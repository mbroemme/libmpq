/*
 *  bench-mpq-signature.c -- archive signature verification benchmark.
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

#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

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

/* Create a signed archive using disposable test-only keys, outside timing. */
static int
create_signed_archive(const char *path, const uint8_t *data, size_t size, uint32_t types)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0, 0 };
    mpq_file_options_s file_options = { 0, 0, 0, 0, 0 };
    uint8_t strong_private[512];
    mpq_archive_s *archive = NULL;
    int32_t result = 0;

    test_strong_signature_private_key(strong_private);
    result = libmpq__archive_create(&archive, path, &options);
    if (result != 0)
        return 1;
    if ((types & LIBMPQ_SIGNATURE_WEAK) != 0)
        result = libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        );
    if (result == 0 && (types & LIBMPQ_SIGNATURE_STRONG) != 0)
        result = libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private)
        );
    memset(strong_private, 0, sizeof(strong_private));
    if (result == 0)
        result = libmpq__archive_add_data(
            archive, "payload.bin", data, (libmpq__off_t)size, &file_options
        );
    if (result == 0)
        result = libmpq__archive_close(archive);
    else
        (void)libmpq__archive_close(archive);
    return result != 0;
}

/* Verify each requested signature through the public archive API. */
static int
verify_signatures(mpq_archive_s *archive, uint32_t types)
{
    uint32_t mismatches = UINT32_MAX;

    if ((types & LIBMPQ_SIGNATURE_WEAK) != 0 &&
        (libmpq__archive_verify(
             archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
             sizeof(test_signature_public_key), &mismatches
         ) != 0 ||
         mismatches != 0))
        return 1;
    mismatches = UINT32_MAX;
    if ((types & LIBMPQ_SIGNATURE_STRONG) != 0 &&
        (libmpq__archive_verify(
             archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
             sizeof(test_strong_signature_public_key), &mismatches
         ) != 0 ||
         mismatches != 0))
        return 1;
    return 0;
}

/* Time verification with archive open and structural detection excluded. */
static int
run_signature_case(
    const uint8_t *data, size_t size, const char *size_label, uint32_t types, const char *label,
    unsigned runs
)
{
    const char *path = "bench-signature.mpq";
    mpq_archive_s *archive = NULL;
    uint32_t present = 0;
    double best = 1e30;
    int failed = 1;

    if (create_signed_archive(path, data, size, types) ||
        libmpq__archive_open(&archive, path, 0) != 0 ||
        libmpq__archive_signatures(archive, &present) != 0 || present != types ||
        verify_signatures(archive, types))
        goto done;
    for (unsigned run = 0; run < runs; run++) {
        double start = elapsed_now();
        int invalid = verify_signatures(archive, types);
        double duration = elapsed_now() - start;

        if (invalid)
            goto done;
        if (duration < best)
            best = duration;
    }
    printf(
        "%s %s signature verify: %.3f ms elapsed (best/%u)\n", size_label, label, best * 1000.0,
        runs
    );
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != 0)
        failed = 1;
    (void)remove(path);
    if (failed)
        fprintf(stderr, "signature benchmark failed: %s %s\n", size_label, label);
    return failed;
}

/* Run real signature verification workloads with the common bounded CLI. */
int
main(int argc, char **argv)
{
    const size_t sizes[] = { 1024u * 1024u, 16u * 1024u * 1024u };
    const char *labels[] = { "1 MiB", "16 MiB" };
    const uint32_t types[] = { LIBMPQ_SIGNATURE_WEAK, LIBMPQ_SIGNATURE_STRONG,
                               LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG };
    const char *names[] = { "weak", "strong", "weak+strong" };
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
    for (size_t index = 0; index < 2; index++) {
        uint8_t *data = malloc(sizes[index]);

        if (data == NULL)
            return 1;
        fill_bytes(data, sizes[index]);
        for (size_t kind = 0; kind < 3; kind++) {
            if (run_signature_case(
                    data, sizes[index], labels[index], types[kind], names[kind], runs
                )) {
                free(data);
                return 1;
            }
        }
        free(data);
    }
    return 0;
}
