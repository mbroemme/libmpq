/*
 *  bench-mpq-mpqe.c -- deterministic authenticated MPQE transport benchmark.
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

#include "mpq-internal.h"
#include "mpq-reader.h"
#include "mpq-source.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define BENCH_SEEKS 256u
#define BENCH_SEEK_SIZE 4096u

typedef struct
{
    const char *label;
    mpq_file_options_s options;
} bench_mode_s;

static const uint8_t bench_auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
static const bench_mode_s bench_modes[] = {
    { "stored", { 0, 0, 0, 0, 0 } },
    { "zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "encrypted stored", { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "encrypted+zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } }
};

/* Return monotonic elapsed seconds on the current platform. */
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

/* Fill a repeatable, compressible payload with distinct sector contents. */
static void
fill_bytes(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = (uint8_t)(((i / 64u) + (i % 11u)) & 0x7fu);
}

/* Stage a complete archive before timing close/transport encoding. */
static int
stage_archive(
    const char *path, const uint8_t *data, size_t size, const bench_mode_s *mode, int mpqe,
    mpq_archive_s **archive
)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0, 0 };
    int32_t result;

    if (mpqe)
        result = libmpq__archive_create_mpqe(
            archive, path, bench_auth, sizeof(bench_auth) - 1u, &options
        );
    else
        result = libmpq__archive_create(archive, path, &options);
    if (result != LIBMPQ_SUCCESS)
        return 1;
    return libmpq__archive_add_data(
               *archive, "payload.bin", data, (libmpq__off_t)size, &mode->options
           ) != LIBMPQ_SUCCESS;
}

/* Open one already-created archive, with credentials only for MPQE. */
static int32_t
open_archive(mpq_archive_s **archive, const char *path, int mpqe)
{
    if (mpqe)
        return libmpq__archive_open_mpqe(archive, path, 0, bench_auth, sizeof(bench_auth) - 1u);
    return libmpq__archive_open(archive, path, 0);
}

/* Validate stored flags, logical size, first-sector method, and all bytes. */
static int
verify_archive(
    const char *path, const uint8_t *expected, size_t size, const bench_mode_s *mode, int mpqe
)
{
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t *actual = NULL;
    uint32_t number = 0;
    uint32_t flags = 0;
    uint32_t method = 0;
    libmpq__off_t logical_size = 0;
    size_t total = 0;
    int failed = 1;

    if (open_archive(&archive, path, mpqe) != LIBMPQ_SUCCESS)
        goto done;
    if (libmpq__file_number(archive, "payload.bin", &number) != LIBMPQ_SUCCESS ||
        libmpq__file_flags(archive, number, &flags) != LIBMPQ_SUCCESS ||
        libmpq__file_size_unpacked(archive, number, &logical_size) != LIBMPQ_SUCCESS ||
        logical_size != (libmpq__off_t)size ||
        (flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED)) != mode->options.flags)
        goto done;
    if ((flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0) {
        if (libmpq__reader_offsets_acquire(archive, number, "payload.bin") != LIBMPQ_SUCCESS)
            goto done;
        int32_t result = libmpq__block_compression(archive, number, 0, &method);
        if (libmpq__reader_offsets_release(archive, number) != LIBMPQ_SUCCESS ||
            result != LIBMPQ_SUCCESS || method != LIBMPQ_COMPRESSION_ZLIB)
            goto done;
    }
    actual = malloc(size ? size : 1);
    if (actual == NULL ||
        libmpq__stream_open_name(archive, "payload.bin", &stream) != LIBMPQ_SUCCESS)
        goto done;
    while (total < size) {
        libmpq__off_t transferred = 0;

        if (libmpq__stream_read(
                stream, actual + total, (libmpq__off_t)(size - total), &transferred
            ) != LIBMPQ_SUCCESS ||
            transferred <= 0)
            goto done;
        total += (size_t)transferred;
    }
    if (memcmp(actual, expected, size) == 0)
        failed = 0;
done:
    if (stream != NULL && libmpq__stream_close(stream) != LIBMPQ_SUCCESS)
        failed = 1;
    if (archive != NULL && libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        failed = 1;
    free(actual);
    return failed;
}

/* Time authenticated open and full-file extraction as separate operations. */
static int
run_read(
    const char *path, const uint8_t *expected, size_t size, const char *size_label,
    const bench_mode_s *mode, int mpqe, unsigned runs
)
{
    mpq_archive_s *archive = NULL;
    uint8_t *actual = malloc(size);
    uint32_t number = 0;
    double open_best = 1e30;
    double read_best = 1e30;
    int failed = 1;

    if (actual == NULL)
        return 1;
    for (unsigned run = 0; run < runs; run++) {
        double start = elapsed_now();
        int32_t result = open_archive(&archive, path, mpqe);
        double duration = elapsed_now() - start;

        if (result != LIBMPQ_SUCCESS)
            goto done;
        if (duration < open_best)
            open_best = duration;
        result = libmpq__archive_close(archive);
        archive = NULL;
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    if (open_archive(&archive, path, mpqe) != LIBMPQ_SUCCESS ||
        libmpq__file_number(archive, "payload.bin", &number) != LIBMPQ_SUCCESS ||
        libmpq__reader_offsets_acquire(archive, number, "payload.bin") != LIBMPQ_SUCCESS)
        goto done;
    for (unsigned run = 0; run < runs; run++) {
        libmpq__off_t transferred = 0;
        double start;
        double duration;
        int32_t result;

        memset(actual, 0xa5, size);
        start = elapsed_now();
        result = libmpq__file_read(archive, number, actual, (libmpq__off_t)size, &transferred);
        duration = elapsed_now() - start;
        if (result != LIBMPQ_SUCCESS || transferred != (libmpq__off_t)size ||
            memcmp(actual, expected, size) != 0)
            goto done;
        if (duration < read_best)
            read_best = duration;
    }
    if (libmpq__reader_offsets_release(archive, number) != LIBMPQ_SUCCESS)
        goto done;
    printf(
        "%s %s %s open: %.3f ms elapsed (best/%u)\n", size_label, mode->label,
        mpqe ? "MPQE" : "MPQ", open_best * 1000.0, runs
    );
    printf(
        "%s %s %s extract: %.3f ms elapsed (best/%u)\n", size_label, mode->label,
        mpqe ? "MPQE" : "MPQ", read_best * 1000.0, runs
    );
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        failed = 1;
    free(actual);
    return failed;
}

/* Compare ordinary finalization with authenticated MPQE transformation. */
static int
run_encode(const uint8_t *data, size_t size, const char *size_label, unsigned runs)
{
    const char *paths[] = { "bench-mpqe-encode.mpq", "bench-mpqe-encode.mpqe" };
    double best[2] = { 1e30, 1e30 };

    for (int mpqe = 0; mpqe < 2; mpqe++) {
        for (unsigned run = 0; run < runs; run++) {
            mpq_archive_s *archive = NULL;
            double start;
            double duration;
            int32_t result;

            if (stage_archive(paths[mpqe], data, size, &bench_modes[0], mpqe, &archive)) {
                if (archive != NULL)
                    (void)libmpq__archive_close(archive);
                return 1;
            }
            start = elapsed_now();
            result = libmpq__archive_close(archive);
            duration = elapsed_now() - start;
            if (result != LIBMPQ_SUCCESS ||
                verify_archive(paths[mpqe], data, size, &bench_modes[0], mpqe))
                return 1;
            if (duration < best[mpqe])
                best[mpqe] = duration;
            (void)remove(paths[mpqe]);
        }
    }
    printf(
        "%s stored MPQ finalize: %.3f ms elapsed (best/%u)\n", size_label, best[0] * 1000.0, runs
    );
    printf(
        "%s stored MPQE finalize/encode: %.3f ms elapsed (best/%u)\n", size_label, best[1] * 1000.0,
        runs
    );
    return 0;
}

/* Load the ordinary archive bytes for exact low-level transport verification. */
static int
load_file(const char *path, uint8_t **data, size_t *size)
{
    FILE *file = fopen(path, "rb");
    long length;

    if (file == NULL)
        return 1;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        (void)fclose(file);
        return 1;
    }
    *size = (size_t)length;
    *data = malloc(*size ? *size : 1);
    if (*data == NULL) {
        (void)fclose(file);
        return 1;
    }
    int failed = fread(*data, 1, *size, file) != *size;
    if (fclose(file) != 0)
        failed = 1;
    return failed;
}

/* Measure small sequential and fixed seek reads at the private source boundary. */
static int
run_source_reads(const char *raw_path, const char *mpqe_path, unsigned runs)
{
    mpq_source_s *sources[2] = { NULL, NULL };
    uint8_t *expected = NULL;
    uint8_t *actual = NULL;
    uint8_t *sought = NULL;
    size_t size = 0;
    double best[2][3] = { { 1e30, 1e30, 1e30 }, { 1e30, 1e30, 1e30 } };
    const size_t chunks[] = { 4096u, 65536u };
    int failed = 1;

    if (load_file(raw_path, &expected, &size) || size < BENCH_SEEK_SIZE ||
        libmpq__source_open_file(&sources[0], raw_path) != LIBMPQ_SUCCESS ||
        libmpq__source_open_mpqe(&sources[1], mpqe_path, bench_auth, sizeof(bench_auth) - 1u) !=
            LIBMPQ_SUCCESS ||
        libmpq__source_size(sources[0]) != size || libmpq__source_size(sources[1]) != size)
        goto done;
    actual = malloc(size);
    sought = malloc(BENCH_SEEKS * BENCH_SEEK_SIZE);
    if (actual == NULL || sought == NULL)
        goto done;
    for (size_t transport = 0; transport < 2; transport++) {
        mpq_source_s *source = sources[transport];

        for (size_t kind = 0; kind < 3; kind++) {
            for (unsigned run = 0; run < runs; run++) {
                double start;
                double duration;
                int32_t result = LIBMPQ_SUCCESS;

                if (kind < 2) {
                    size_t chunk = chunks[kind];

                    memset(actual, 0xa5, size);
                    start = elapsed_now();
                    for (size_t offset = 0; offset < size; offset += chunk) {
                        size_t take = size - offset < chunk ? size - offset : chunk;
                        result = libmpq__source_read_at(source, offset, actual + offset, take);
                        if (result != LIBMPQ_SUCCESS)
                            break;
                    }
                    duration = elapsed_now() - start;
                    if (result != LIBMPQ_SUCCESS || memcmp(actual, expected, size) != 0)
                        goto done;
                } else {
                    memset(sought, 0xa5, BENCH_SEEKS * BENCH_SEEK_SIZE);
                    start = elapsed_now();
                    for (size_t i = 0; i < BENCH_SEEKS; i++) {
                        size_t offset = ((i * 104729u) % (size - BENCH_SEEK_SIZE + 1u));

                        result = libmpq__source_read_at(
                            source, offset, sought + i * BENCH_SEEK_SIZE, BENCH_SEEK_SIZE
                        );
                        if (result != LIBMPQ_SUCCESS)
                            break;
                    }
                    duration = elapsed_now() - start;
                    if (result != LIBMPQ_SUCCESS)
                        goto done;
                    for (size_t i = 0; i < BENCH_SEEKS; i++) {
                        size_t offset = ((i * 104729u) % (size - BENCH_SEEK_SIZE + 1u));

                        if (memcmp(
                                sought + i * BENCH_SEEK_SIZE, expected + offset, BENCH_SEEK_SIZE
                            ) != 0)
                            goto done;
                    }
                }
                if (duration < best[transport][kind])
                    best[transport][kind] = duration;
            }
        }
        printf(
            "16 MiB %s source read 4 KiB: %.3f ms elapsed (best/%u)\n", transport ? "MPQE" : "MPQ",
            best[transport][0] * 1000.0, runs
        );
        printf(
            "16 MiB %s source read 64 KiB: %.3f ms elapsed (best/%u)\n", transport ? "MPQE" : "MPQ",
            best[transport][1] * 1000.0, runs
        );
        printf(
            "16 MiB %s source seek/read: %.3f ms elapsed (best/%u)\n", transport ? "MPQE" : "MPQ",
            best[transport][2] * 1000.0, runs
        );
    }
    failed = 0;
done:
    for (size_t transport = 0; transport < 2; transport++)
        if (sources[transport] != NULL &&
            libmpq__source_close(sources[transport]) != LIBMPQ_SUCCESS)
            failed = 1;
    free(expected);
    free(actual);
    free(sought);
    return failed;
}

/* Run deterministic transport workloads with the common benchmark CLI. */
int
main(int argc, char **argv)
{
    const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };
    const char *labels[] = { "64 KiB", "1 MiB", "16 MiB" };
    const char *paths[] = { "bench-mpqe-raw.mpq", "bench-mpqe-wrapped.mpqe" };
    unsigned runs = 3;
    int failed = 1;

    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (argv[1][0] < '0' || argv[1][0] > '9' || *end != 0 || parsed == 0 || parsed > 100)
            return 2;
        runs = (unsigned)parsed;
    }
    for (size_t size_index = 0; size_index < 3; size_index++) {
        uint8_t *data = malloc(sizes[size_index]);

        if (data == NULL)
            return 1;
        fill_bytes(data, sizes[size_index]);
        if (run_encode(data, sizes[size_index], labels[size_index], runs)) {
            free(data);
            goto done;
        }
        for (size_t mode = 0; mode < 4; mode++) {
            for (int mpqe = 0; mpqe < 2; mpqe++) {
                mpq_archive_s *archive = NULL;

                if (stage_archive(
                        paths[mpqe], data, sizes[size_index], &bench_modes[mode], mpqe, &archive
                    )) {
                    if (archive != NULL)
                        (void)libmpq__archive_close(archive);
                    free(data);
                    goto done;
                }
                if (libmpq__archive_close(archive) != LIBMPQ_SUCCESS ||
                    verify_archive(
                        paths[mpqe], data, sizes[size_index], &bench_modes[mode], mpqe
                    ) ||
                    run_read(
                        paths[mpqe], data, sizes[size_index], labels[size_index],
                        &bench_modes[mode], mpqe, runs
                    )) {
                    free(data);
                    goto done;
                }
            }
            if (size_index == 2 && mode == 0 && run_source_reads(paths[0], paths[1], runs)) {
                free(data);
                goto done;
            }
            (void)remove(paths[0]);
            (void)remove(paths[1]);
        }
        free(data);
    }
    failed = 0;
done:
    (void)remove(paths[0]);
    (void)remove(paths[1]);
    return failed;
}
