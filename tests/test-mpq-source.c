/*
 *  test-mpq-source.c -- custom random-access source regressions.
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

#include "mpq-internal.h"
#include "mpq-source.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    const uint8_t *data;
    size_t size;
    unsigned reads;
    int32_t failure;
    unsigned fail_after;
} memory_source_s;

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            test_failure(__FILE__, __LINE__, #condition);                                          \
            failed = 1;                                                                            \
            goto done;                                                                             \
        }                                                                                          \
    } while (0)

/* Implement the exact read-at callback contract over caller-owned memory. */
static int32_t
memory_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    memory_source_s *memory = context;

    if (memory == NULL || (buffer == NULL && size != 0) || offset < 0 ||
        (uint64_t)offset > memory->size || size > memory->size - (size_t)offset)
        return LIBMPQ_ERROR_READ;
    ++memory->reads;
    if (memory->failure != 0 && (memory->fail_after == 0 || memory->reads > memory->fail_after))
        return memory->failure;
    if (size != 0)
        memcpy(buffer, memory->data + (size_t)offset, size);
    return LIBMPQ_SUCCESS;
}

/* Check range handling, callback errors, and borrowed-context clone lifetime. */
static int
test_source_calls(void)
{
    const uint8_t bytes[] = "source byte sample";
    memory_source_s memory = { bytes, sizeof(bytes), 0, 0, 0 };
    mpq_source_s *source = NULL;
    mpq_source_s *clone = NULL;
    uint8_t actual[8] = { 0 };
    unsigned reads;
    int failed = 0;

    REQUIRE(libmpq__source_open_io(&source, &memory, memory_read_at, memory.size) == 0);
    REQUIRE(libmpq__source_read_at(source, 2, actual, sizeof(actual)) == 0);
    REQUIRE(memcmp(actual, bytes + 2, sizeof(actual)) == 0);
    reads = memory.reads;
    REQUIRE(
        libmpq__source_read_at(source, memory.size - 1, actual, sizeof(actual)) == LIBMPQ_ERROR_READ
    );
    REQUIRE(libmpq__source_read_at(source, 0, NULL, 0) == 0 && memory.reads == reads);
    memory.failure = 1;
    REQUIRE(libmpq__source_read_at(source, 0, actual, 1) == LIBMPQ_ERROR_READ);
    memory.failure = LIBMPQ_ERROR_SEEK;
    REQUIRE(libmpq__source_read_at(source, 0, actual, 1) == LIBMPQ_ERROR_SEEK);
    memory.failure = 0;
    REQUIRE(libmpq__source_clone(&clone, source, NULL) == 0);
    REQUIRE(libmpq__source_close(source) == 0);
    source = NULL;
    REQUIRE(libmpq__source_read_at(clone, 0, actual, sizeof(actual)) == 0);
    REQUIRE(memcmp(actual, bytes, sizeof(actual)) == 0);
done:
    if (source != NULL && libmpq__source_close(source) != 0)
        failed = 1;
    if (clone != NULL && libmpq__source_close(clone) != 0)
        failed = 1;
    return failed;
}

/* Exercise table and payload failures through the public archive-open path. */
static int
test_archive_calls(void)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s file_options = { 0, 0, 0, 0, 0 };
    uint8_t expected[8192];
    uint8_t actual[sizeof(expected)];
    mpq_archive_s *archive = NULL;
    memory_source_s memory = { 0 };
    uint8_t *backing = NULL;
    size_t backing_size = 0;
    uint32_t number = 0;
    libmpq__off_t transferred = 0;
    char path[256] = { 0 };
    int failed = 0;

    test_payload(expected, sizeof(expected), 53);
    REQUIRE(test_temp_path(path, sizeof(path), "source") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    REQUIRE(
        libmpq__archive_add_data(
            archive, "payload.bin", expected, sizeof(expected), &file_options
        ) == 0
    );
    REQUIRE(libmpq__archive_close(archive) == 0);
    archive = NULL;
    REQUIRE(test_read_path(path, &backing, &backing_size) == 0);
    memory.data = backing;
    memory.size = backing_size;
    REQUIRE(libmpq__archive_open_io(&archive, &memory, memory_read_at, 8, 0, NULL) < 0);
    REQUIRE(archive == NULL);
    memory.failure = LIBMPQ_ERROR_READ;
    REQUIRE(
        libmpq__archive_open_io(
            &archive, &memory, memory_read_at, (libmpq__off_t)memory.size, 0, NULL
        ) == LIBMPQ_ERROR_READ
    );
    REQUIRE(archive == NULL);
    memory.reads = 0;
    memory.fail_after = 1;
    REQUIRE(
        libmpq__archive_open_io(
            &archive, &memory, memory_read_at, (libmpq__off_t)memory.size, 0, NULL
        ) == LIBMPQ_ERROR_READ
    );
    REQUIRE(archive == NULL && memory.reads > 1);
    memory.failure = 0;
    memory.fail_after = 0;
    REQUIRE(
        libmpq__archive_open_io(
            &archive, &memory, memory_read_at, (libmpq__off_t)memory.size, 0, NULL
        ) == 0
    );
    REQUIRE(libmpq__file_number(archive, "payload.bin", &number) == 0);
    memory.failure = LIBMPQ_ERROR_READ;
    REQUIRE(
        libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) ==
        LIBMPQ_ERROR_READ
    );
    memory.failure = 0;
    REQUIRE(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
    REQUIRE(transferred == sizeof(expected) && memcmp(actual, expected, sizeof(expected)) == 0);
done:
    if (archive != NULL && libmpq__archive_close(archive) != 0)
        failed = 1;
    free(backing);
    if (path[0] != 0)
        (void)remove(path);
    return failed;
}

/* Run source-specific range, failure, ownership, and archive regressions. */
int
main(void)
{
    TEST_CHECK(test_source_calls() == 0);
    TEST_CHECK(test_archive_calls() == 0);
    return 0;
}
