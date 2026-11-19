/*
 *  test-mpq-writer-alloc.c -- libmpq regression tests.
 *
 *  Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
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

/* Only the four replacement modules receive the allocation macros. */
#include "mpq-archive.h"
#include "mpq-writer.h"
#define LIBMPQ_TEST_ALLOC_IMPLEMENTATION
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compile-time call sites in the private core use these ordinary C allocators. */
static void *single_allocations[128];
static unsigned single_live;
static unsigned single_calls;
static int single_fail = -1;
static int single_tracking;
static size_t single_veto;
static size_t single_denied;
static unsigned single_failures;
static unsigned single_reallocations;
static unsigned single_realloc_failures;

static int
single_allocation_fail(size_t size, const char *file, unsigned line)
{
    int fail;

    if (!single_tracking)
        return 0;
    if (single_veto != 0 && size > single_veto) {
        single_denied = size;
        fail = 1;
    } else
        fail = (int)single_calls++ == single_fail;
    if (fail) {
        single_failures++;
        printf("Writer allocation fault: %s:%u, %zu bytes\n", file, line, size);
    }
    return fail;
}

static void *
single_allocation_record(void *pointer)
{
    if (single_tracking && pointer != NULL) {
        for (unsigned i = 0; i < 128; i++)
            if (single_allocations[i] == NULL) {
                single_allocations[i] = pointer;
                single_live++;
                return pointer;
            }
        abort();
    }
    return pointer;
}

/* Apply the selected fault before allocating and recording an ordinary buffer. */
void *
test_writer_malloc(size_t size, const char *file, unsigned line)
{
    return single_allocation_fail(size, file, line) ? NULL : single_allocation_record(malloc(size));
}

/* Check multiplication before applying the allocation fault. */
void *
test_writer_calloc(size_t count, size_t size, const char *file, unsigned line)
{
    size_t total;

    if (count != 0 && size > SIZE_MAX / count)
        return NULL;
    total = count * size;
    if (single_allocation_fail(total, file, line))
        return NULL;

    /* Choose one zeroed byte for C's implementation-defined zero-size case. */
    return single_allocation_record(calloc(total ? total : 1, 1));
}

static void
single_allocation_forget(void *pointer)
{
    for (unsigned i = 0; pointer != NULL && i < 128; i++)
        if (single_allocations[i] == pointer) {
            single_allocations[i] = NULL;
            single_live--;
            break;
        }
}

/* Remove tracked ownership even when failure injection has been disabled. */
void
test_writer_free(void *pointer)
{
    single_allocation_forget(pointer);
    free(pointer);
}

/* Publish a moved owner only after realloc succeeds; failure retains the old one. */
void *
test_writer_realloc(void *pointer, size_t size, const char *file, unsigned line)
{
    if (single_tracking)
        single_reallocations++;
    if (single_allocation_fail(size, file, line)) {
        if (single_tracking)
            single_realloc_failures++;
        return NULL;
    }
    if (size == 0) {
        test_writer_free(pointer);
        return NULL;
    }
    unsigned slot;
    for (slot = 0; slot < 128; slot++)
        if (single_allocations[slot] == pointer)
            break;
    int tracked = pointer != NULL && slot < 128;
    void *result = realloc(pointer, size);
    if (result != NULL) {
        if (tracked) {
            single_allocations[slot] = result;
        } else
            single_allocation_record(result);
    }
    return result;
}

/* Failed realloc preserves its owner; zero-size release is deterministic here. */
static int
test_single_reallocation(void)
{
    uint8_t *original;
    uint8_t *resized;
    void *second;

    TEST_CHECK(single_live == 0);
    single_tracking = 1;
    single_calls = 0;
    single_failures = 0;
    single_fail = -1;
    original = test_writer_malloc(8, __FILE__, __LINE__);
    TEST_CHECK(original != NULL && single_live == 1);
    memset(original, 0x5a, 8);
    resized = test_writer_realloc(original, 16, __FILE__, __LINE__);
    TEST_CHECK(resized != NULL && single_live == 1);
    single_fail = (int)single_calls;
    TEST_CHECK(test_writer_realloc(resized, 32, __FILE__, __LINE__) == NULL);
    TEST_CHECK(single_live == 1 && single_failures == 1);
    for (unsigned i = 0; i < 8; i++)
        TEST_CHECK(resized[i] == 0x5a);
    single_fail = -1;
    single_veto = 16;
    TEST_CHECK(test_writer_realloc(resized, 32, __FILE__, __LINE__) == NULL);
    TEST_CHECK(single_live == 1 && single_failures == 2 && single_denied == 32);
    single_veto = 0;
    second = test_writer_realloc(NULL, 8, __FILE__, __LINE__);
    TEST_CHECK(second != NULL && single_live == 2);
    TEST_CHECK(test_writer_realloc(second, 0, __FILE__, __LINE__) == NULL && single_live == 1);
    second = test_writer_calloc(0, SIZE_MAX, __FILE__, __LINE__);
    TEST_CHECK(second != NULL && *(uint8_t *)second == 0 && single_live == 2);
    test_writer_free(second);
    TEST_CHECK(test_writer_calloc(SIZE_MAX, 2, __FILE__, __LINE__) == NULL && single_live == 1);
    test_writer_free(resized);
    test_writer_free(NULL);
    TEST_CHECK(single_live == 0);
    single_tracking = 0;
    single_denied = 0;
    return 0;
}

/* Begin and encode failures release every tracked allocation without global hooks. */
static int
test_single_allocations(void)
{
    uint8_t payload[9001];
    unsigned reached[5] = { 0 };

    test_payload(payload, sizeof(payload), 43);
    for (unsigned mode = 0; mode < 5; mode++)
        for (int failure = 0; failure < 12; failure++) {
            mpq_archive_s *archive = NULL;
            mpq_writer_s *writer = NULL;
            mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_4, 8, 4096, 0, 0 };
            mpq_file_options_s options = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
            char path[512];
            TEST_CHECK(test_temp_path(path, sizeof(path), "single-alloc") == 0);
            TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
            TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, 0) == 0);
            if (mode == 2 || mode == 4) {
                if (mode == 4)
                    memset(payload, 0, sizeof(payload));
                options.flags |= LIBMPQ_FILE_FLAG_COMPRESS;
                options.compression_first = options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
            } else if (mode == 3)
                options.flags |= LIBMPQ_FILE_FLAG_IMPLODE;
            TEST_CHECK(single_live == 0);
            single_calls = 0;
            single_failures = 0;
            single_fail = failure;
            single_tracking = 1;
            if (mode != 0)
                single_tracking = 0;
            int32_t begun = libmpq__writer_file_begin(
                archive, "single-name", sizeof(payload), &options, &writer
            );
            single_tracking = 0;
            if (mode == 0) {
                TEST_CHECK(single_calls <= 12);
                TEST_CHECK(single_failures == (unsigned)(failure < (int)single_calls));
                TEST_CHECK(begun == 0 || single_failures == 1);
                reached[mode] += single_failures;
            }
            if (mode == 0 && begun != 0) {
                TEST_CHECK(
                    begun == LIBMPQ_ERROR_MALLOC && archive->write_current == NULL &&
                    single_live == 0
                );
                TEST_CHECK(
                    libmpq__writer_file_begin(archive, "recovered", 1, &options, &writer) == 0
                );
                TEST_CHECK(libmpq__writer_file_write(writer, payload, 1) == 0);
                TEST_CHECK(libmpq__writer_file_finish(writer) == 0);
                TEST_CHECK(libmpq__archive_close(archive) == 0);
            } else {
                TEST_CHECK(begun == 0);
                single_calls = 0;
                single_tracking = mode != 0;
                int32_t written = libmpq__writer_file_write(writer, payload, sizeof(payload));
                single_tracking = 0;
                if (mode != 0) {
                    TEST_CHECK(single_calls <= 12);
                    TEST_CHECK(single_failures == (unsigned)(failure < (int)single_calls));
                    reached[mode] += single_failures;
                }
                TEST_CHECK(written == 0 || written == LIBMPQ_ERROR_MALLOC);
                TEST_CHECK(written == 0 || single_failures == 1);
                TEST_CHECK(libmpq__writer_file_finish(writer) == written);

                /* Successful finish transfers the owned name to the archive. */
                if (written == 0 && mode == 0) {
                    TEST_CHECK(single_live == 1 && archive->write_names[0] != NULL);
                    single_allocation_forget(archive->write_names[0]);
                }
                TEST_CHECK(single_live == 0);
                TEST_CHECK(
                    archive->write_current == NULL && archive->write_next_block == (written == 0)
                );
                TEST_CHECK(libmpq__archive_close(archive) == written);
                if (written == 0) {
                    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
                    TEST_CHECK(
                        test_archive_check_name(archive, "single-name", payload, sizeof(payload)) ==
                        0
                    );
                    TEST_CHECK(libmpq__archive_close(archive) == 0);
                }
            }
            TEST_CHECK(remove(path) == 0);
        }
    TEST_CHECK(reached[0] == 3 && reached[1] == 1 && reached[2] >= 3 && reached[3] >= 2);
    TEST_CHECK(reached[4] >= 4 && single_reallocations != 0 && single_realloc_failures != 0);
    printf(
        "Writer allocation faults reached: begin=%u raw=%u zlib-fallback=%u implode=%u "
        "zlib-framing=%u realloc-failures=%u\n",
        reached[0], reached[1], reached[2], reached[3], reached[4], single_realloc_failures
    );
    for (uint32_t version = 0; version < 4; version++) {
        mpq_archive_s *archive = NULL;
        mpq_writer_s *writer = NULL;
        mpq_archive_create_options_s create = { version, 8, 4096, 0, 0 };
        mpq_file_options_s options = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
        const libmpq__off_t sizes[] = { INT32_MAX, (libmpq__off_t)INT32_MAX + 1, UINT32_MAX,
                                        (libmpq__off_t)UINT32_MAX + 1, INT64_MAX };
        char path[512];
        TEST_CHECK(test_temp_path(path, sizeof(path), "single-limits") == 0);
        TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
        for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            single_calls = 0;
            single_failures = 0;
            single_fail = -1;
            single_veto = 1048576;
            single_denied = 0;
            single_tracking = 1;
            int32_t result =
                libmpq__writer_file_begin(archive, "huge", sizes[i], &options, &writer);
            single_tracking = 0;
            TEST_CHECK(result == (i == 0 ? LIBMPQ_ERROR_MALLOC : LIBMPQ_ERROR_SIZE));
            TEST_CHECK(single_denied == (i == 0 ? (size_t)INT32_MAX : 0));
            TEST_CHECK(single_failures == (i == 0));
            TEST_CHECK(single_live == 0 && archive->write_current == NULL);
        }
        archive->write_sector_size = UINT32_C(0x80000000);
        single_calls = 0;
        single_failures = 0;
        single_tracking = 1;
        single_denied = 0;
        int32_t result = libmpq__writer_file_begin(
            archive, "legacy", (libmpq__off_t)INT32_MAX + 1, &options, &writer
        );
        single_tracking = 0;
        single_veto = 0;
        TEST_CHECK(result == LIBMPQ_ERROR_MALLOC && single_denied == UINT32_C(0x80000000));
        TEST_CHECK(single_failures == 1);
        TEST_CHECK(single_live == 0 && archive->write_current == NULL);
        TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    }
    return 0;
}

/* Run only allocation scenarios; the production writer matrix runs separately. */
int
main(void)
{
    TEST_CHECK(test_single_allocations() == 0);
    TEST_CHECK(test_single_reallocation() == 0);
    return 0;
}
