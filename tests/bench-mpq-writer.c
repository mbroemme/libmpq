/*
 *  bench-mpq-writer.c -- deterministic ordinary archive writer benchmark.
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
#include <libmpq/mpq.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define BENCH_SMALL_FILES 512u
#define BENCH_SMALL_SIZE 128u

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

/* Read a monotonic elapsed-time clock on each supported platform. */
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

/* Fill source data with a deterministic, compressible sector pattern. */
static void
fill_bytes(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = (uint8_t)(((i / 64u) + (i % 11u)) & 0x7fu);
}

/* Give each small archive member distinct, repeatable source bytes. */
static void
fill_small(uint8_t data[BENCH_SMALL_SIZE], unsigned file)
{
    for (size_t i = 0; i < BENCH_SMALL_SIZE; i++)
        data[i] = (uint8_t)(file * 31u + i * 17u);
}

/* Create a fresh ordinary MPQ before the measured writer operation. */
static int
create_archive(const char *path, unsigned capacity, mpq_archive_s **archive)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, capacity, 4096, 0, 0 };

    return libmpq__archive_create(archive, path, &options) != 0;
}

/* Check the actual flags, sector method, and complete extracted source bytes. */
static int
verify_member(
    const char *path, const char *name, const uint8_t *expected, size_t size,
    const bench_mode_s *mode
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

    if (libmpq__archive_open(&archive, path, 0) != 0)
        goto done;
    if (libmpq__file_number(archive, name, &number) != 0 ||
        libmpq__file_flags(archive, number, &flags) != 0 ||
        libmpq__file_size_unpacked(archive, number, &logical_size) != 0 ||
        logical_size != (libmpq__off_t)size ||
        (flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED)) != mode->options.flags)
        goto done;
    if ((flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0) {
        if (libmpq__reader_offsets_acquire(archive, number, name) != 0)
            goto done;
        int32_t result = libmpq__block_compression(archive, number, 0, &method);
        if (libmpq__reader_offsets_release(archive, number) != 0 || result != 0 ||
            method != LIBMPQ_COMPRESSION_ZLIB)
            goto done;
    }
    actual = malloc(size ? size : 1);
    if (actual == NULL || libmpq__stream_open_name(archive, name, &stream) != 0)
        goto done;
    while (total < size) {
        libmpq__off_t transferred = 0;

        if (libmpq__stream_read(
                stream, actual + total, (libmpq__off_t)(size - total), &transferred
            ) != 0 ||
            transferred <= 0)
            goto done;
        total += (size_t)transferred;
    }
    if (memcmp(actual, expected, size) == 0)
        failed = 0;
done:
    if (stream != NULL && libmpq__stream_close(stream) != 0)
        failed = 1;
    if (archive != NULL && libmpq__archive_close(archive) != 0)
        failed = 1;
    free(actual);
    return failed;
}

/* Prepare the filesystem source before a path-add timer starts. */
static int
make_source(const char *path, const uint8_t *data, size_t size)
{
    FILE *file = fopen(path, "wb");

    if (file == NULL)
        return 1;
    int failed = fwrite(data, 1, size, file) != size;
    if (fclose(file) != 0)
        failed = 1;
    return failed;
}

/* Time only one-shot insertion and archive finalization, not fixture setup. */
static int
run_one_shot(
    size_t size, const char *size_label, const bench_mode_s *mode, int from_path, unsigned runs
)
{
    const char *archive_path = "bench-writer-one-shot.mpq";
    const char *source_path = "bench-writer-source.bin";
    uint8_t *expected = malloc(size);
    double add_best = 1e30;
    double close_best = 1e30;
    int failed = 1;

    if (expected == NULL)
        return 1;
    fill_bytes(expected, size);
    if (from_path && make_source(source_path, expected, size))
        goto done;
    for (unsigned run = 0; run < runs; run++) {
        mpq_archive_s *archive = NULL;
        double start;
        double duration;
        int32_t result;

        if (create_archive(archive_path, 16, &archive))
            goto done;
        start = elapsed_now();
        if (from_path)
            result = libmpq__archive_add_path(archive, "payload.bin", source_path, &mode->options);
        else
            result = libmpq__archive_add_data(
                archive, "payload.bin", expected, (libmpq__off_t)size, &mode->options
            );
        duration = elapsed_now() - start;
        if (result != 0) {
            (void)libmpq__archive_close(archive);
            goto done;
        }
        if (duration < add_best)
            add_best = duration;
        start = elapsed_now();
        result = libmpq__archive_close(archive);
        duration = elapsed_now() - start;
        if (result != 0)
            goto done;
        if (duration < close_best)
            close_best = duration;
        if (verify_member(archive_path, "payload.bin", expected, size, mode))
            goto done;
        (void)remove(archive_path);
    }
    printf(
        "%s %s add %s: %.3f ms elapsed (best/%u)\n", size_label, mode->label,
        from_path ? "path" : "data", add_best * 1000.0, runs
    );
    printf(
        "%s %s archive close: %.3f ms elapsed (best/%u)\n", size_label, mode->label,
        close_best * 1000.0, runs
    );
    failed = 0;
done:
    (void)remove(archive_path);
    if (from_path)
        (void)remove(source_path);
    free(expected);
    if (failed)
        fprintf(stderr, "%s %s one-shot writer benchmark failed\n", size_label, mode->label);
    return failed;
}

/* Time begin, repeated writes, file finish, and archive close independently. */
static int
run_stream(size_t size, size_t chunk, const bench_mode_s *mode, unsigned runs)
{
    const char *path = "bench-writer-stream.mpq";
    uint8_t *expected = malloc(size);
    double begin_best = 1e30;
    double write_best = 1e30;
    double finish_best = 1e30;
    double close_best = 1e30;
    int failed = 1;

    if (expected == NULL)
        return 1;
    fill_bytes(expected, size);
    for (unsigned run = 0; run < runs; run++) {
        mpq_archive_s *archive = NULL;
        mpq_writer_s *writer = NULL;
        double start;
        double duration;
        int32_t result;

        if (create_archive(path, 16, &archive))
            goto done;
        start = elapsed_now();
        result = libmpq__writer_begin(
            archive, "payload.bin", (libmpq__off_t)size, &mode->options, &writer
        );
        duration = elapsed_now() - start;
        if (result != 0) {
            (void)libmpq__archive_close(archive);
            goto done;
        }
        if (duration < begin_best)
            begin_best = duration;
        start = elapsed_now();
        for (size_t offset = 0; offset < size; offset += chunk) {
            size_t take = size - offset < chunk ? size - offset : chunk;
            result = libmpq__writer_write(writer, expected + offset, (libmpq__off_t)take);
            if (result != 0)
                break;
        }
        duration = elapsed_now() - start;
        if (result != 0) {
            (void)libmpq__archive_close(archive);
            goto done;
        }
        if (duration < write_best)
            write_best = duration;
        start = elapsed_now();
        result = libmpq__writer_finish(writer);
        duration = elapsed_now() - start;
        if (result != 0) {
            (void)libmpq__archive_close(archive);
            goto done;
        }
        if (duration < finish_best)
            finish_best = duration;
        start = elapsed_now();
        result = libmpq__archive_close(archive);
        duration = elapsed_now() - start;
        if (result != 0)
            goto done;
        if (duration < close_best)
            close_best = duration;
        if (verify_member(path, "payload.bin", expected, size, mode))
            goto done;
        (void)remove(path);
    }
    printf(
        "16 MiB %s stream begin: %.3f ms elapsed (best/%u)\n", mode->label, begin_best * 1000.0,
        runs
    );
    printf(
        "16 MiB %s stream write %lu KiB: %.3f ms elapsed (best/%u)\n", mode->label,
        (unsigned long)(chunk / 1024u), write_best * 1000.0, runs
    );
    printf(
        "16 MiB %s stream finish: %.3f ms elapsed (best/%u)\n", mode->label, finish_best * 1000.0,
        runs
    );
    printf(
        "16 MiB %s stream archive close: %.3f ms elapsed (best/%u)\n", mode->label,
        close_best * 1000.0, runs
    );
    failed = 0;
done:
    (void)remove(path);
    free(expected);
    if (failed)
        fprintf(stderr, "16 MiB %s stream writer benchmark failed\n", mode->label);
    return failed;
}

/* Exercise hash insertion and table serialization with small independent files. */
static int
run_many(unsigned runs)
{
    const char *path = "bench-writer-many.mpq";
    uint8_t expected[BENCH_SMALL_SIZE];
    char name[32];
    double add_best = 1e30;
    double close_best = 1e30;

    for (unsigned run = 0; run < runs; run++) {
        mpq_archive_s *archive = NULL;
        double start;
        double duration;
        int32_t result = 0;

        if (create_archive(path, 1024, &archive))
            return 1;
        start = elapsed_now();
        for (unsigned file = 0; file < BENCH_SMALL_FILES; file++) {
            (void)snprintf(name, sizeof(name), "small-%04u.bin", file);
            fill_small(expected, file);
            result = libmpq__archive_add_data(archive, name, expected, sizeof(expected), NULL);
            if (result != 0)
                break;
        }
        duration = elapsed_now() - start;
        if (result != 0) {
            (void)libmpq__archive_close(archive);
            return 1;
        }
        if (duration < add_best)
            add_best = duration;
        start = elapsed_now();
        result = libmpq__archive_close(archive);
        duration = elapsed_now() - start;
        if (result != 0)
            return 1;
        if (duration < close_best)
            close_best = duration;
        for (unsigned file = 0; file < BENCH_SMALL_FILES; file++) {
            (void)snprintf(name, sizeof(name), "small-%04u.bin", file);
            fill_small(expected, file);
            if (verify_member(path, name, expected, sizeof(expected), &bench_modes[0]))
                return 1;
        }
        (void)remove(path);
    }
    printf("512 x 128 B stored add data: %.3f ms elapsed (best/%u)\n", add_best * 1000.0, runs);
    printf("512-file archive close: %.3f ms elapsed (best/%u)\n", close_best * 1000.0, runs);
    return 0;
}

/* Run every ordinary-writer workload using the shared benchmark CLI. */
int
main(int argc, char **argv)
{
    unsigned runs = 3;
    const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };
    const char *labels[] = { "64 KiB", "1 MiB", "16 MiB" };

    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long value = strtoul(argv[1], &end, 10);

        if (argv[1][0] < '0' || argv[1][0] > '9' || *end != 0 || value < 1 || value > 100)
            return 2;
        runs = (unsigned)value;
    }
    for (size_t size_index = 0; size_index < 3; size_index++) {
        for (size_t mode_index = 0; mode_index < 4; mode_index++) {
            if (run_one_shot(
                    sizes[size_index], labels[size_index], &bench_modes[mode_index], 0, runs
                ))
                return 1;
        }
    }
    if (run_one_shot(sizes[2], labels[2], &bench_modes[0], 1, runs) ||
        run_one_shot(sizes[2], labels[2], &bench_modes[1], 1, runs))
        return 1;
    for (size_t mode = 0; mode < 2; mode++) {
        for (size_t chunk = 4096; chunk <= 1024u * 1024u; chunk *= 16) {
            if (run_stream(sizes[2], chunk, &bench_modes[mode], runs))
                return 1;
        }
    }
    if (run_stream(sizes[2], 65536, &bench_modes[3], runs) || run_many(runs))
        return 1;
    return 0;
}
