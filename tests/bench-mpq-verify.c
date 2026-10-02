/*
 *  bench-mpq-verify.c -- archive file and sector verification benchmark.
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

#include "mpq-archive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

typedef struct
{
    const char *label;
    uint32_t attributes;
    uint32_t storage;
    uint32_t verify;
} integrity_case_s;

static const integrity_case_s file_cases[] = {
    { "stored no attributes", 0, 0, 0 },
    { "stored CRC32", LIBMPQ_ATTRIBUTE_CRC32, 0, LIBMPQ_VERIFY_FILE_CRC32 },
    { "stored MD5", LIBMPQ_ATTRIBUTE_MD5, 0, LIBMPQ_VERIFY_FILE_MD5 },
    { "stored CRC32+MD5", LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5, 0,
      LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5 },
    { "zlib no sector Adler-32", 0, LIBMPQ_FILE_FLAG_COMPRESS, 0 },
    { "zlib sector Adler-32", 0, LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC,
      LIBMPQ_VERIFY_SECTOR_CRC }
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

/* Fill source bytes deterministically, with compressible sector-local variation. */
static void
fill_bytes(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = (uint8_t)(((i / 64u) + (i % 11u)) & 0x7fu);
}

/* Create a real archive variant before any read or verification timing. */
static int
create_file_archive(
    const char *path, const uint8_t *data, size_t size, const integrity_case_s *kind
)
{
    mpq_archive_create_options_s archive_options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0,
                                                     kind->attributes };
    mpq_file_options_s file_options = { kind->storage, LIBMPQ_COMPRESSION_ZLIB,
                                        LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    int32_t result = libmpq__archive_create(&archive, path, &archive_options);

    if (result != 0)
        return 1;
    result =
        libmpq__archive_add_data(archive, "payload.bin", data, (libmpq__off_t)size, &file_options);
    if (result == 0)
        result = libmpq__archive_close(archive);
    else
        (void)libmpq__archive_close(archive);
    return result != 0;
}

/* Measure automatic full-file checks and explicit verification separately. */
static int
run_file_case(
    const uint8_t *data, size_t size, const char *size_label, const integrity_case_s *kind,
    unsigned runs
)
{
    const char *path = "bench-verify-file.mpq";
    mpq_archive_s *archive = NULL;
    uint8_t *actual = NULL;
    uint32_t number = 0;
    uint32_t flags = 0;
    mpq_file_attributes_s attributes;
    double extract_best = 1e30;
    double verify_best = 1e30;
    int failed = 1;

    if (create_file_archive(path, data, size, kind) ||
        libmpq__archive_open(&archive, path, 0) != 0 ||
        libmpq__file_number(archive, "payload.bin", &number) != 0 ||
        libmpq__file_flags(archive, number, &flags) != 0 ||
        (flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC)) != kind->storage)
        goto done;
    if (kind->attributes != 0 &&
        (libmpq__file_attributes(archive, number, &attributes) != 0 ||
         (attributes.flags & (LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5)) != kind->attributes))
        goto done;
    if ((kind->storage & LIBMPQ_FILE_FLAG_SECTOR_CRC) != 0) {
        uint32_t blocks = 0;
        uint32_t checksum = 0;
        uint32_t mismatches = UINT32_MAX;

        if (libmpq__file_blocks(archive, number, &blocks) != 0 || blocks == 0 ||
            libmpq__block_verify(archive, number, 0, &checksum, &mismatches) != 0 ||
            checksum == 0 || mismatches != 0)
            goto done;
        mismatches = UINT32_MAX;
        if (libmpq__block_verify(archive, number, blocks - 1, &checksum, &mismatches) != 0 ||
            checksum == 0 || mismatches != 0)
            goto done;
    }
    actual = malloc(size);
    if (actual == NULL)
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
        if (result != 0 || transferred != (libmpq__off_t)size || memcmp(actual, data, size) != 0)
            goto done;
        if (duration < extract_best)
            extract_best = duration;
        if (kind->verify != 0) {
            uint32_t mismatches = UINT32_MAX;

            start = elapsed_now();
            result = libmpq__file_verify(archive, number, kind->verify, &mismatches);
            duration = elapsed_now() - start;
            if (result != 0 || mismatches != 0)
                goto done;
            if (duration < verify_best)
                verify_best = duration;
        }
    }
    printf(
        "%s %s extract: %.3f ms elapsed (best/%u)\n", size_label, kind->label,
        extract_best * 1000.0, runs
    );
    if (kind->verify != 0)
        printf(
            "%s %s explicit verify: %.3f ms elapsed (best/%u)\n", size_label, kind->label,
            verify_best * 1000.0, runs
        );
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != 0)
        failed = 1;
    free(actual);
    (void)remove(path);
    if (failed)
        fprintf(stderr, "verification benchmark failed: %s %s\n", size_label, kind->label);
    return failed;
}

/* Run real archive workloads with the common bounded benchmark CLI. */
int
main(int argc, char **argv)
{
    const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };
    const char *labels[] = { "64 KiB", "1 MiB", "16 MiB" };
    unsigned runs = 3;

    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (argv[1][0] < '0' || argv[1][0] > '9' || *end != 0 || parsed == 0 || parsed > 100)
            return 2;
        runs = (unsigned)parsed;
    }
    for (size_t index = 0; index < 3; index++) {
        uint8_t *data = malloc(sizes[index]);

        if (data == NULL)
            return 1;
        fill_bytes(data, sizes[index]);
        for (size_t kind = 0; kind < sizeof(file_cases) / sizeof(file_cases[0]); kind++) {
            if (run_file_case(data, sizes[index], labels[index], &file_cases[kind], runs)) {
                free(data);
                return 1;
            }
        }
        free(data);
    }
    return 0;
}
