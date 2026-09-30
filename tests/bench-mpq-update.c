/*
 *  bench-mpq-update.c -- deterministic transactional update benchmark.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define BENCH_COPY_SIZE 65536u
#define BENCH_PREFIX_SIZE 512u

static const uint8_t bench_auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
static const uint8_t bench_magic[4] = { 'H', 'M', '3', 'W' };
static const uint8_t bench_suffix[] = "unrelated container suffix";

typedef enum
{
    BENCH_PLAIN,
    BENCH_EMBEDDED,
    BENCH_MPQE
} bench_kind_e;

typedef enum
{
    BENCH_REPLACE,
    BENCH_RENAME,
    BENCH_REMOVE,
    BENCH_NOOP
} bench_action_e;

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

/* Fill deterministic data that does not depend on the host random source. */
static void
fill_bytes(uint8_t *data, size_t size, uint32_t seed)
{
    for (size_t i = 0; i < size; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        data[i] = (uint8_t)seed;
    }
}

/* Copy fixture bytes outside all timed update sections. */
static int
copy_file(const char *source, const char *destination)
{
    FILE *input = fopen(source, "rb");
    FILE *output = NULL;
    uint8_t buffer[BENCH_COPY_SIZE];
    int failed = 1;

    if (input == NULL)
        return 1;
    output = fopen(destination, "wb");
    if (output == NULL)
        goto done;
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), input);

        if (count != 0 && fwrite(buffer, 1, count, output) != count)
            goto done;
        if (count != sizeof(buffer)) {
            if (ferror(input))
                goto done;
            break;
        }
    }
    failed = 0;

done:
    if (fclose(input) != 0)
        failed = 1;
    if (output != NULL && fclose(output) != 0)
        failed = 1;
    return failed;
}

/* Compare complete files to check that MPQE no-op commits preserve bytes. */
static int
same_file(const char *first, const char *second)
{
    FILE *left = fopen(first, "rb");
    FILE *right = fopen(second, "rb");
    uint8_t left_bytes[BENCH_COPY_SIZE];
    uint8_t right_bytes[BENCH_COPY_SIZE];
    int same = 0;

    if (left == NULL || right == NULL)
        goto done;
    for (;;) {
        size_t left_size = fread(left_bytes, 1, sizeof(left_bytes), left);
        size_t right_size = fread(right_bytes, 1, sizeof(right_bytes), right);

        if (left_size != right_size || memcmp(left_bytes, right_bytes, left_size) != 0)
            goto done;
        if (left_size != sizeof(left_bytes)) {
            if (ferror(left) || ferror(right))
                goto done;
            same = 1;
            break;
        }
    }

done:
    if (left != NULL && fclose(left) != 0)
        same = 0;
    if (right != NULL && fclose(right) != 0)
        same = 0;
    return same;
}

/* Create a one-member ordinary or authenticated archive before timing. */
static int
make_archive(const char *path, const uint8_t *data, size_t size, bench_kind_e kind)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096,
                                             LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_archive_s *archive = NULL;
    int32_t result;

    if (kind == BENCH_MPQE)
        result = libmpq__archive_create_mpqe(
            &archive, path, bench_auth, sizeof(bench_auth) - 1u, &options
        );
    else
        result = libmpq__archive_create(&archive, path, &options);
    if (result != LIBMPQ_SUCCESS)
        return 1;
    result = libmpq__archive_add_data(archive, "payload.bin", data, (libmpq__off_t)size, NULL);
    if (libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        return 1;
    return result != LIBMPQ_SUCCESS;
}

/* Wrap a plain MPQ at an aligned offset with unchanged prefix and suffix. */
static int
make_embedded(const char *source, const char *destination)
{
    FILE *output = fopen(destination, "wb");
    FILE *input = NULL;
    uint8_t prefix[BENCH_PREFIX_SIZE] = { 0 };
    uint8_t buffer[BENCH_COPY_SIZE];
    int failed = 1;

    if (output == NULL)
        return 1;
    input = fopen(source, "rb");
    if (input == NULL)
        goto done;
    memcpy(prefix, bench_magic, sizeof(bench_magic));
    if (fwrite(prefix, 1, sizeof(prefix), output) != sizeof(prefix))
        goto done;
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), input);

        if (count != 0 && fwrite(buffer, 1, count, output) != count)
            goto done;
        if (count != sizeof(buffer)) {
            if (ferror(input))
                goto done;
            break;
        }
    }
    if (fwrite(bench_suffix, 1, sizeof(bench_suffix), output) == sizeof(bench_suffix))
        failed = 0;

done:
    if (input != NULL && fclose(input) != 0)
        failed = 1;
    if (fclose(output) != 0)
        failed = 1;
    return failed;
}

/* Verify the embedded prefix and unrelated suffix outside timed regions. */
static int
check_embedded(const char *path)
{
    FILE *input = fopen(path, "rb");
    uint8_t prefix[BENCH_PREFIX_SIZE];
    uint8_t suffix[sizeof(bench_suffix)];
    int failed = 1;

    if (input == NULL)
        return 1;
    if (fread(prefix, 1, sizeof(prefix), input) != sizeof(prefix) ||
        memcmp(prefix, bench_magic, sizeof(bench_magic)) != 0)
        goto done;
    for (size_t i = 4; i < sizeof(prefix); i++)
        if (prefix[i] != 0)
            goto done;
    if (fseek(input, -(long)sizeof(suffix), SEEK_END) != 0 ||
        fread(suffix, 1, sizeof(suffix), input) != sizeof(suffix) ||
        memcmp(suffix, bench_suffix, sizeof(suffix)) != 0)
        goto done;
    failed = 0;

done:
    if (fclose(input) != 0)
        failed = 1;
    return failed;
}

/* Confirm update output through normal archive APIs after timing stops. */
static int
check_result(
    const char *path, bench_kind_e kind, bench_action_e action, const uint8_t *before,
    const uint8_t *after, size_t size
)
{
    mpq_archive_s *archive = NULL;
    uint8_t *actual = NULL;
    uint32_t number;
    libmpq__off_t offset = 0;
    libmpq__off_t transferred = 0;
    int failed = 1;
    int32_t result;

    if (kind == BENCH_EMBEDDED && check_embedded(path))
        return 1;
    if (kind == BENCH_MPQE)
        result = libmpq__archive_open_mpqe(&archive, path, -1, bench_auth, sizeof(bench_auth) - 1u);
    else
        result = libmpq__archive_open(&archive, path, -1);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    if (kind == BENCH_EMBEDDED &&
        (libmpq__archive_offset(archive, &offset) != LIBMPQ_SUCCESS || offset != BENCH_PREFIX_SIZE))
        goto done;
    if (action == BENCH_REMOVE) {
        if (libmpq__file_number(archive, "payload.bin", &number) == LIBMPQ_ERROR_EXIST)
            failed = 0;
        goto done;
    }
    if (action == BENCH_RENAME &&
        libmpq__file_number(archive, "payload.bin", &number) != LIBMPQ_ERROR_EXIST)
        goto done;
    result = libmpq__file_number(
        archive, action == BENCH_RENAME ? "renamed.bin" : "payload.bin", &number
    );
    if (result != LIBMPQ_SUCCESS)
        goto done;
    actual = malloc(size);
    if (actual == NULL)
        goto done;
    result = libmpq__file_read(archive, number, actual, (libmpq__off_t)size, &transferred);
    if (result == LIBMPQ_SUCCESS && transferred == (libmpq__off_t)size &&
        memcmp(actual, action == BENCH_REPLACE ? after : before, size) == 0)
        failed = 0;

done:
    free(actual);
    if (archive != NULL && libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        failed = 1;
    return failed;
}

/* Time begin, the requested operation, and commit separately. */
static int
run_case(
    const char *fixture, const char *working, bench_kind_e kind, bench_action_e action,
    const uint8_t *before, const uint8_t *after, size_t size, unsigned repeats
)
{
    static const char *kinds[] = { "MPQ", "HM3W", "MPQE" };
    static const char *actions[] = { "replace", "rename", "remove", "no-op" };
    double begin_best = 1e30;
    double operation_best = 1e30;
    double commit_best = 1e30;

    for (unsigned i = 0; i < repeats; i++) {
        mpq_update_s *update = NULL;
        double start;
        double begin_elapsed;
        double operation_elapsed = 0;
        double commit_elapsed;
        int32_t result;

        if (copy_file(fixture, working))
            return 1;
        start = elapsed_now();
        if (kind == BENCH_MPQE)
            result =
                libmpq__update_begin_mpqe(&update, working, bench_auth, sizeof(bench_auth) - 1u);
        else
            result = libmpq__update_begin(&update, working);
        begin_elapsed = elapsed_now() - start;
        if (result != LIBMPQ_SUCCESS)
            goto failed;
        if (action != BENCH_NOOP) {
            start = elapsed_now();
            if (action == BENCH_REPLACE)
                result = libmpq__update_replace_data(
                    update, "payload.bin", after, (libmpq__off_t)size, NULL
                );
            else if (action == BENCH_RENAME)
                result = libmpq__update_rename(update, "payload.bin", "renamed.bin");
            else
                result = libmpq__update_remove(update, "payload.bin");
            operation_elapsed = elapsed_now() - start;
            if (result != LIBMPQ_SUCCESS)
                goto failed;
        }
        start = elapsed_now();
        result = libmpq__update_commit(update);
        update = NULL;
        commit_elapsed = elapsed_now() - start;
        if (result != LIBMPQ_SUCCESS || check_result(working, kind, action, before, after, size) ||
            (action == BENCH_NOOP && !same_file(fixture, working)))
            goto failed;
        if (begin_elapsed < begin_best)
            begin_best = begin_elapsed;
        if (operation_elapsed < operation_best)
            operation_best = operation_elapsed;
        if (commit_elapsed < commit_best)
            commit_best = commit_elapsed;
        continue;

    failed:
        fprintf(
            stderr, "%s %s %lu KiB: benchmark failed (%d)\n", kinds[kind], actions[action],
            (unsigned long)(size / 1024), result
        );
        if (update != NULL)
            (void)libmpq__update_abort(update);
        return 1;
    }
    printf(
        "%s %s %lu KiB: begin %.3f ms, operation %.3f ms, commit %.3f ms (best/%u)\n", kinds[kind],
        actions[action], (unsigned long)(size / 1024), begin_best * 1000.0, operation_best * 1000.0,
        commit_best * 1000.0, repeats
    );
    return 0;
}

/* Generate each archive fixture once and run deterministic size classes. */
int
main(int argc, char **argv)
{
    static const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };
    const char *fixture = "bench-update-fixture.bin";
    const char *working = "bench-update-working.bin";
    const char *source = "bench-update-source.mpq";
    unsigned repeats = 3;
    int failed = 1;

    if (argc > 1) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (end == argv[1] || *end != '\0' || parsed == 0 || parsed > 100)
            return 2;
        repeats = (unsigned)parsed;
    }
    for (size_t index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
        size_t size = sizes[index];
        uint8_t *before = malloc(size);
        uint8_t *after = malloc(size);

        if (before == NULL || after == NULL) {
            free(before);
            free(after);
            goto done;
        }
        fill_bytes(before, size, 0x12345678u);
        fill_bytes(after, size, 0x87654321u);
        for (bench_kind_e kind = BENCH_PLAIN; kind <= BENCH_MPQE; kind++) {
            if ((kind == BENCH_EMBEDDED && (make_archive(source, before, size, BENCH_PLAIN) ||
                                            make_embedded(source, fixture))) ||
                (kind != BENCH_EMBEDDED && make_archive(fixture, before, size, kind))) {
                free(before);
                free(after);
                goto done;
            }
            for (bench_action_e action = BENCH_REPLACE; action <= BENCH_NOOP; action++) {
                if (kind != BENCH_PLAIN && action != BENCH_REPLACE && action != BENCH_NOOP)
                    continue;
                if (run_case(fixture, working, kind, action, before, after, size, repeats)) {
                    free(before);
                    free(after);
                    goto done;
                }
            }
            (void)remove(fixture);
            (void)remove(working);
            (void)remove(source);
        }
        free(before);
        free(after);
    }
    failed = 0;

done:
    (void)remove(fixture);
    (void)remove(working);
    (void)remove(source);
    return failed;
}
