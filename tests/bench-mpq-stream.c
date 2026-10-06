/*
 *  bench-mpq-stream.c -- deterministic logical member stream benchmark.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This file is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this file; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "mpq-reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define BENCH_SEEK_COUNT 256u
#define BENCH_SEEK_BYTES 4096u

typedef struct
{
    const char *label;
    mpq_file_options_s options;
} bench_mode_s;

static const bench_mode_s bench_modes[] = {
    { "stored", { 0, 0, 0, 0, 0 } },
    { "zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "encrypted stored", { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "encrypted+zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } }
};

/* Return monotonic elapsed seconds with the existing Windows equivalent. */
static double
elapsed_now(void)
{
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)frequency.QuadPart;
#else
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
#endif
}

/* Give every sector deterministic, compressible, nonconstant contents. */
static void
fill_bytes(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = (uint8_t)(((i / 64u) + (i % 11u)) & 0x7fu);
}

/* Complete fixture creation before any stream timer starts. */
static int
make_archive(const char *path, const uint8_t *data, size_t size, const bench_mode_s *mode)
{
    mpq_archive_create_options_s creation = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0, 0 };
    mpq_archive_s *archive = NULL;
    int32_t result = libmpq__archive_create(&archive, path, &creation);

    if (result != 0)
        return 1;
    result =
        libmpq__archive_add_data(archive, "payload.bin", data, (libmpq__off_t)size, &mode->options);
    if (libmpq__archive_close(archive) != 0)
        return 1;
    return result != 0;
}

/* Confirm that a label describes the actual generated member storage. */
static int
verify_storage(mpq_archive_s *archive, uint32_t number, size_t size, const bench_mode_s *mode)
{
    uint32_t flags = 0;
    uint32_t blocks = 0;
    libmpq__off_t unpacked = 0;
    int failed = 1;

    if (libmpq__file_flags(archive, number, &flags) != 0 ||
        libmpq__file_size_unpacked(archive, number, &unpacked) != 0 ||
        libmpq__file_blocks(archive, number, &blocks) != 0 || blocks == 0 ||
        unpacked != (libmpq__off_t)size ||
        (flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED)) != mode->options.flags)
        return 1;
    if (libmpq__reader_offsets_acquire(archive, number, "payload.bin") != 0)
        return 1;
    for (uint32_t choice = 0; choice < 2; choice++) {
        uint32_t block = choice == 0 ? 0 : blocks - 1u;
        uint32_t method = 0;

        if (libmpq__block_compression(archive, number, block, &method) != 0 ||
            method != ((flags & LIBMPQ_FILE_FLAG_COMPRESS) ? LIBMPQ_COMPRESSION_ZLIB : 0))
            goto done;
    }
    failed = 0;
done:
    if (libmpq__reader_offsets_release(archive, number) != 0)
        failed = 1;
    return failed;
}

/* Measure stream creation separately from read and seek workloads. */
static int
run_open(
    mpq_archive_s *archive, uint32_t number, size_t size, const char *size_label,
    const char *mode_label, int by_name, unsigned runs
)
{
    double best = 1e30;

    for (unsigned run = 0; run < runs; run++) {
        mpq_stream_s *stream = NULL;
        libmpq__off_t stream_size = 0;
        libmpq__off_t position = -1;
        double start = elapsed_now();
        int32_t status = by_name ? libmpq__stream_open_name(archive, "payload.bin", &stream)
                                 : libmpq__stream_open(archive, number, &stream);
        double duration = elapsed_now() - start;

        if (status != 0 || stream == NULL) {
            if (stream != NULL)
                (void)libmpq__stream_close(stream);
            return 1;
        }
        if (libmpq__stream_size(stream, &stream_size) != 0 || stream_size != (libmpq__off_t)size ||
            libmpq__stream_tell(stream, &position) != 0 || position != 0) {
            (void)libmpq__stream_close(stream);
            return 1;
        }
        if (libmpq__stream_close(stream) != 0)
            return 1;
        if (duration < best)
            best = duration;
    }
    printf(
        "%s %s stream open by %s: %.3f ms elapsed (best/%u)\n", size_label, mode_label,
        by_name ? "name" : "number", best * 1000.0, runs
    );
    return 0;
}

/* Time only repeated reads on an already-open logical stream. */
static int
run_sequential(
    mpq_archive_s *archive, const uint8_t *expected, size_t size, uint8_t *actual,
    const char *size_label, const char *mode_label, size_t chunk, const char *chunk_label,
    unsigned runs
)
{
    double best = 1e30;

    for (unsigned run = 0; run < runs; run++) {
        mpq_stream_s *stream = NULL;
        libmpq__off_t position = 0;
        libmpq__off_t stream_size = 0;
        size_t total = 0;
        int32_t status = 0;

        if (libmpq__stream_open_name(archive, "payload.bin", &stream) != 0)
            return 1;
        memset(actual, 0xa5, size);
        double start = elapsed_now();

        while (total < size) {
            libmpq__off_t transferred = 0;
            size_t request = size - total < chunk ? size - total : chunk;

            status =
                libmpq__stream_read(stream, actual + total, (libmpq__off_t)request, &transferred);
            if (status != 0 || transferred != (libmpq__off_t)request)
                break;
            total += (size_t)transferred;
        }
        double duration = elapsed_now() - start;

        if (status != 0 || total != size || memcmp(actual, expected, size) != 0 ||
            libmpq__stream_tell(stream, &position) != 0 || position != (libmpq__off_t)size ||
            libmpq__stream_size(stream, &stream_size) != 0 || stream_size != (libmpq__off_t)size) {
            (void)libmpq__stream_close(stream);
            return 1;
        }
        {
            libmpq__off_t transferred = -1;

            if (libmpq__stream_read(stream, actual, 1, &transferred) != 0 || transferred != 0) {
                (void)libmpq__stream_close(stream);
                return 1;
            }
        }
        if (libmpq__stream_close(stream) != 0)
            return 1;
        if (duration < best)
            best = duration;
    }
    printf(
        "%s %s sequential %s: %.3f ms elapsed (best/%u)\n", size_label, mode_label, chunk_label,
        best * 1000.0, runs
    );
    return 0;
}

/* Build fixed forward, backward, and pseudo-random seek offsets once. */
static void
make_offsets(uint32_t offsets[3][BENCH_SEEK_COUNT], size_t size)
{
    uint32_t state = 0x13579bdfu;
    size_t range = size - BENCH_SEEK_BYTES;

    for (unsigned i = 0; i < BENCH_SEEK_COUNT; i++) {
        size_t step = range * i / (BENCH_SEEK_COUNT - 1u);

        offsets[0][i] = (uint32_t)step;
        offsets[1][i] = (uint32_t)(range - step);
        state = state * 1664525u + 1013904223u;
        offsets[2][i] = state % (uint32_t)(range + 1u);
    }
}

/* Time seek/read pairs; verify every returned slice after stopping the clock. */
static int
run_seeks(
    mpq_archive_s *archive, const uint8_t *expected, size_t size, uint8_t *actual,
    const char *size_label, const char *mode_label, const char *pattern,
    const uint32_t offsets[BENCH_SEEK_COUNT], unsigned runs
)
{
    double best = 1e30;

    for (unsigned run = 0; run < runs; run++) {
        mpq_stream_s *stream = NULL;
        libmpq__off_t position = 0;
        int32_t status = 0;

        if (libmpq__stream_open_name(archive, "payload.bin", &stream) != 0)
            return 1;
        memset(actual, 0xa5, BENCH_SEEK_COUNT * BENCH_SEEK_BYTES);
        double start = elapsed_now();

        for (unsigned i = 0; i < BENCH_SEEK_COUNT; i++) {
            libmpq__off_t transferred = 0;

            status = libmpq__stream_seek(stream, offsets[i], LIBMPQ_SEEK_SET);
            if (status == 0)
                status = libmpq__stream_read(
                    stream, actual + (size_t)i * BENCH_SEEK_BYTES, BENCH_SEEK_BYTES, &transferred
                );
            if (status != 0 || transferred != BENCH_SEEK_BYTES) {
                status = LIBMPQ_ERROR_READ;
                break;
            }
        }
        double duration = elapsed_now() - start;

        if (status != 0 || libmpq__stream_tell(stream, &position) != 0 ||
            position != (libmpq__off_t)offsets[BENCH_SEEK_COUNT - 1] + BENCH_SEEK_BYTES) {
            (void)libmpq__stream_close(stream);
            return 1;
        }
        for (unsigned i = 0; i < BENCH_SEEK_COUNT; i++) {
            if ((size_t)offsets[i] + BENCH_SEEK_BYTES > size ||
                memcmp(
                    actual + (size_t)i * BENCH_SEEK_BYTES, expected + offsets[i], BENCH_SEEK_BYTES
                ) != 0) {
                (void)libmpq__stream_close(stream);
                return 1;
            }
        }
        if (libmpq__stream_close(stream) != 0)
            return 1;
        if (duration < best)
            best = duration;
    }
    printf(
        "%s %s %s seek+read: %.3f ms elapsed (best/%u)\n", size_label, mode_label, pattern,
        best * 1000.0, runs
    );
    return 0;
}

/* Run one stored, compressed, or encrypted fixture through all relevant cases. */
static int
run_case(size_t size, const char *size_label, const bench_mode_s *mode, unsigned runs)
{
    static const size_t chunks[] = { 256u, 1024u, 4096u, 65536u, 1024u * 1024u };
    static const char *chunk_labels[] = { "256 B", "1 KiB", "4 KiB", "64 KiB", "1 MiB" };
    static const char *seek_labels[] = { "forward", "backward", "random" };
    char path[96];
    uint8_t *expected = NULL;
    uint8_t *actual = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number = 0;
    uint32_t offsets[3][BENCH_SEEK_COUNT];
    int failed = 1;

    (void)snprintf(
        path, sizeof(path), "bench-stream-%lu-%u.mpq", (unsigned long)size,
        (unsigned)(mode - bench_modes)
    );
    expected = malloc(size);
    actual = malloc(size);
    if (expected == NULL || actual == NULL)
        goto done;
    fill_bytes(expected, size);
    if (make_archive(path, expected, size, mode) || libmpq__archive_open(&archive, path, 0) != 0 ||
        libmpq__file_number(archive, "payload.bin", &number) != 0 ||
        verify_storage(archive, number, size, mode))
        goto done;

    if (size == 1024u * 1024u) {
        if ((mode->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED) == 0 &&
            run_open(archive, number, size, size_label, mode->label, 0, runs))
            goto done;
        if (run_open(archive, number, size, size_label, mode->label, 1, runs))
            goto done;
    }
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        if ((i < 2 && size != 1024u * 1024u) || chunks[i] > size)
            continue;
        if (run_sequential(
                archive, expected, size, actual, size_label, mode->label, chunks[i],
                chunk_labels[i], runs
            ))
            goto done;
    }
    if (size == 16u * 1024u * 1024u) {
        make_offsets(offsets, size);
        for (unsigned i = 0; i < 3; i++)
            if (run_seeks(
                    archive, expected, size, actual, size_label, mode->label, seek_labels[i],
                    offsets[i], runs
                ))
                goto done;
    }
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != 0)
        failed = 1;
    (void)remove(path);
    free(expected);
    free(actual);
    if (failed)
        fprintf(stderr, "%s %s: stream benchmark failed\n", size_label, mode->label);
    return failed;
}

/* Run deterministic size and storage cases with the common benchmark CLI. */
int
main(int argc, char **argv)
{
    const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };
    const char *size_labels[] = { "64 KiB", "1 MiB", "16 MiB" };
    unsigned runs = 3;

    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (argv[1][0] < '0' || argv[1][0] > '9' || *end != '\0' || parsed == 0 || parsed > 100)
            return 2;
        runs = (unsigned)parsed;
    }
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        for (size_t mode = 0; mode < sizeof(bench_modes) / sizeof(bench_modes[0]); mode++)
            if (run_case(sizes[i], size_labels[i], &bench_modes[mode], runs))
                return 1;
    return 0;
}
