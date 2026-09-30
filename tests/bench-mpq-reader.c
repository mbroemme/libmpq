/*
 *  bench-mpq-reader.c -- deterministic archive-open and extraction benchmark.
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

/* Return monotonic elapsed seconds on each supported platform. */
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

/* Fill a repeatable, compressible pattern with distinct sector contents. */
static void
fill_bytes(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = (uint8_t)(((i / 64u) + (i % 11u)) & 0x7fu);
}

/* Create one archive before any open or extraction timer starts. */
static int
make_archive(const char *path, const uint8_t *data, size_t size, const bench_mode_s *mode)
{
    mpq_archive_create_options_s creation = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0, 0 };
    mpq_archive_s *archive = NULL;
    int32_t result = libmpq__archive_create(&archive, path, &creation);

    if (result != LIBMPQ_SUCCESS)
        return 1;
    result =
        libmpq__archive_add_data(archive, "payload.bin", data, (libmpq__off_t)size, &mode->options);
    if (libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        return 1;
    return result != LIBMPQ_SUCCESS;
}

/* Verify storage flags, logical size, and actual zlib sectors outside timing. */
static int
verify_storage(mpq_archive_s *archive, uint32_t number, size_t size, const bench_mode_s *mode)
{
    uint32_t flags = 0;
    uint32_t blocks = 0;
    libmpq__off_t unpacked = 0;
    int failed = 1;

    if (libmpq__file_flags(archive, number, &flags) != LIBMPQ_SUCCESS ||
        libmpq__file_size_unpacked(archive, number, &unpacked) != LIBMPQ_SUCCESS ||
        libmpq__file_blocks(archive, number, &blocks) != LIBMPQ_SUCCESS || blocks == 0 ||
        unpacked != (libmpq__off_t)size ||
        (flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED)) != mode->options.flags)
        return 1;
    if (libmpq__reader_offsets_acquire(archive, number, "payload.bin") != LIBMPQ_SUCCESS)
        return 1;
    for (uint32_t choice = 0; choice < 2; choice++) {
        uint32_t block = choice == 0 ? 0 : blocks - 1u;
        uint32_t method = 0;

        if (libmpq__block_compression(archive, number, block, &method) != LIBMPQ_SUCCESS ||
            method != ((flags & LIBMPQ_FILE_FLAG_COMPRESS) ? LIBMPQ_COMPRESSION_ZLIB : 0))
            goto done;
    }
    failed = 0;
done:
    if (libmpq__reader_offsets_release(archive, number) != LIBMPQ_SUCCESS)
        failed = 1;
    return failed;
}

/* Measure minimal archive open and named full-file extraction independently. */
static int
run_case(size_t size, const char *size_label, const bench_mode_s *mode, unsigned runs)
{
    char path[96];
    uint8_t *expected = NULL;
    uint8_t *actual = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number;
    double open_best = 1e30;
    double extract_best = 1e30;
    int failed = 1;

    (void)snprintf(
        path, sizeof(path), "bench-reader-%lu-%u.mpq", (unsigned long)size,
        (unsigned)(mode - bench_modes)
    );
    expected = malloc(size);
    actual = malloc(size);
    if (expected == NULL || actual == NULL)
        goto done;
    fill_bytes(expected, size);
    if (make_archive(path, expected, size, mode))
        goto done;

    if (mode == &bench_modes[0]) {
        for (unsigned i = 0; i < runs; i++) {
            double start = elapsed_now();
            int32_t result = libmpq__archive_open(&archive, path, 0);
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
    }

    if (libmpq__archive_open(&archive, path, 0) != LIBMPQ_SUCCESS ||
        libmpq__file_number(archive, "payload.bin", &number) != LIBMPQ_SUCCESS ||
        verify_storage(archive, number, size, mode))
        goto done;
    for (unsigned i = 0; i < runs; i++) {
        libmpq__off_t transferred = 0;
        memset(actual, 0xa5, size);
        double start = elapsed_now();
        int32_t result = libmpq__reader_offsets_acquire(archive, number, "payload.bin");

        if (result == LIBMPQ_SUCCESS) {
            result = libmpq__file_read(archive, number, actual, (libmpq__off_t)size, &transferred);
            if (libmpq__reader_offsets_release(archive, number) != LIBMPQ_SUCCESS)
                result = LIBMPQ_ERROR_READ;
        }
        double duration = elapsed_now() - start;

        if (result != LIBMPQ_SUCCESS || transferred != (libmpq__off_t)size ||
            memcmp(actual, expected, size) != 0)
            goto done;
        if (duration < extract_best)
            extract_best = duration;
    }
    if (mode == &bench_modes[0])
        printf(
            "%s single-file archive open: %.3f ms elapsed (best/%u)\n", size_label,
            open_best * 1000.0, runs
        );
    printf(
        "%s %s extract: %.3f ms elapsed (best/%u)\n", size_label, mode->label,
        extract_best * 1000.0, runs
    );
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        failed = 1;
    (void)remove(path);
    free(expected);
    free(actual);
    if (failed)
        fprintf(stderr, "%s %s: reader benchmark failed\n", size_label, mode->label);
    return failed;
}

/* Build many deterministic small members without timing archive creation. */
static int
make_small_archive(const char *path)
{
    mpq_archive_create_options_s creation = { LIBMPQ_ARCHIVE_VERSION_ONE, 1024, 4096, 0, 0 };
    mpq_archive_s *archive = NULL;
    uint8_t data[BENCH_SMALL_SIZE];
    char name[32];
    int32_t result = libmpq__archive_create(&archive, path, &creation);

    if (result != LIBMPQ_SUCCESS)
        return 1;
    for (unsigned i = 0; i < BENCH_SMALL_FILES; i++) {
        (void)snprintf(name, sizeof(name), "small-%04u.bin", i);
        for (size_t j = 0; j < sizeof(data); j++)
            data[j] = (uint8_t)(i * 31u + j * 17u);
        result = libmpq__archive_add_data(archive, name, data, sizeof(data), NULL);
        if (result != LIBMPQ_SUCCESS)
            break;
    }
    if (libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        return 1;
    return result != LIBMPQ_SUCCESS;
}

/* Time archive open, then lookups and known-number extractions on one archive. */
static int
run_small_case(unsigned runs)
{
    const char *path = "bench-reader-small.mpq";
    char names[BENCH_SMALL_FILES][32];
    uint32_t numbers[BENCH_SMALL_FILES];
    uint8_t *actual = NULL;
    mpq_archive_s *archive = NULL;
    double open_best = 1e30;
    double lookup_best = 1e30;
    double extract_best = 1e30;
    int failed = 1;

    if (make_small_archive(path))
        goto done;
    for (unsigned run = 0; run < runs; run++) {
        double start = elapsed_now();
        int32_t result = libmpq__archive_open(&archive, path, 0);
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
    if (libmpq__archive_open(&archive, path, 0) != LIBMPQ_SUCCESS)
        goto done;
    actual = malloc((size_t)BENCH_SMALL_FILES * BENCH_SMALL_SIZE);
    if (actual == NULL)
        goto done;
    for (unsigned i = 0; i < BENCH_SMALL_FILES; i++)
        (void)snprintf(names[i], sizeof(names[i]), "small-%04u.bin", i);

    for (unsigned run = 0; run < runs; run++) {
        int32_t result = LIBMPQ_SUCCESS;
        double start = elapsed_now();

        for (unsigned i = 0; i < BENCH_SMALL_FILES; i++) {
            result = libmpq__file_number(archive, names[i], &numbers[i]);
            if (result != LIBMPQ_SUCCESS)
                break;
        }
        double duration = elapsed_now() - start;

        if (result != LIBMPQ_SUCCESS)
            goto done;
        if (duration < lookup_best)
            lookup_best = duration;
    }
    for (unsigned run = 0; run < runs; run++) {
        int32_t result = LIBMPQ_SUCCESS;
        memset(actual, 0xa5, (size_t)BENCH_SMALL_FILES * BENCH_SMALL_SIZE);
        double start = elapsed_now();

        for (unsigned i = 0; i < BENCH_SMALL_FILES; i++) {
            libmpq__off_t transferred = 0;

            result = libmpq__file_read(
                archive, numbers[i], actual + (size_t)i * BENCH_SMALL_SIZE, BENCH_SMALL_SIZE,
                &transferred
            );
            if (result != LIBMPQ_SUCCESS || transferred != BENCH_SMALL_SIZE) {
                result = LIBMPQ_ERROR_READ;
                break;
            }
        }
        double duration = elapsed_now() - start;

        if (result != LIBMPQ_SUCCESS)
            goto done;
        for (unsigned i = 0; i < BENCH_SMALL_FILES; i++)
            for (size_t j = 0; j < BENCH_SMALL_SIZE; j++)
                if (actual[(size_t)i * BENCH_SMALL_SIZE + j] != (uint8_t)(i * 31u + j * 17u))
                    goto done;
        if (duration < extract_best)
            extract_best = duration;
    }
    printf(
        "%u-file archive open: %.3f ms elapsed (best/%u)\n", BENCH_SMALL_FILES, open_best * 1000.0,
        runs
    );
    printf(
        "%u x %u B small lookup: %.3f ms elapsed (best/%u)\n", BENCH_SMALL_FILES, BENCH_SMALL_SIZE,
        lookup_best * 1000.0, runs
    );
    printf(
        "%u x %u B small extract: %.3f ms elapsed (best/%u)\n", BENCH_SMALL_FILES, BENCH_SMALL_SIZE,
        extract_best * 1000.0, runs
    );
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        failed = 1;
    (void)remove(path);
    free(actual);
    if (failed)
        fprintf(stderr, "small-file reader benchmark failed\n");
    return failed;
}

/* Run deterministic small, medium, large, and many-small-file workloads. */
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
    return run_small_case(runs);
}
