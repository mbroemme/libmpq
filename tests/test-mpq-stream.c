/*
 *  test-mpq-stream.c -- logical member stream regression tests.
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

#include "test-mpq-helper.h"

#include <stdio.h>
#include <string.h>

#define STREAM_TEST_SIZE 12289u

typedef struct
{
    const char *name;
    mpq_file_options_s options;
} stream_case_s;

static const stream_case_s stream_cases[] = {
    { "stored", { 0, 0, 0, 0, 0 } },
    { "zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "encrypted", { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "encrypted-zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } }
};

/* Verify incremental reads, sector crossings, backward seeks, and EOF. */
static int
check_stream(mpq_archive_s *archive, const stream_case_s *item, const uint8_t *expected)
{
    mpq_stream_s *stream = NULL;
    uint8_t data[STREAM_TEST_SIZE];
    libmpq__off_t transferred = 0;
    libmpq__off_t position = 0;
    size_t total = 0;
    int failed = 1;

    if (libmpq__stream_open_name(archive, item->name, &stream) != 0)
        return 1;
    memset(data, 0xa5, sizeof(data));
    while (total < sizeof(data)) {
        size_t request = sizeof(data) - total;

        if (request > 257u)
            request = 257u;
        if (libmpq__stream_read(stream, data + total, request, &transferred) != 0 ||
            transferred != (libmpq__off_t)request)
            goto done;
        total += (size_t)transferred;
    }
    if (memcmp(data, expected, sizeof(data)) != 0 || libmpq__stream_tell(stream, &position) != 0 ||
        position != STREAM_TEST_SIZE || libmpq__stream_read(stream, data, 1, &transferred) != 0 ||
        transferred != 0)
        goto done;
    if (libmpq__stream_seek(stream, 4094, LIBMPQ_SEEK_SET) != 0 ||
        libmpq__stream_read(stream, data, 8, &transferred) != 0 || transferred != 8 ||
        memcmp(data, expected + 4094, 8) != 0)
        goto done;
    if (libmpq__stream_seek(stream, -4, LIBMPQ_SEEK_CUR) != 0 ||
        libmpq__stream_read(stream, data, 8, &transferred) != 0 || transferred != 8 ||
        memcmp(data, expected + 4098, 8) != 0)
        goto done;
    if (libmpq__stream_seek(stream, 8190, LIBMPQ_SEEK_SET) != 0 ||
        libmpq__stream_read(stream, data, 8, &transferred) != 0 || transferred != 8 ||
        memcmp(data, expected + 8190, 8) != 0)
        goto done;
    if (libmpq__stream_seek(stream, 4089, LIBMPQ_SEEK_SET) != 0 ||
        libmpq__stream_read(stream, data, 12, &transferred) != 0 || transferred != 12 ||
        memcmp(data, expected + 4089, 12) != 0)
        goto done;
    if (libmpq__stream_seek(stream, 1, LIBMPQ_SEEK_END) != LIBMPQ_ERROR_SEEK ||
        libmpq__stream_tell(stream, &position) != 0 || position != 4101)
        goto done;
    failed = 0;
done:
    if (libmpq__stream_close(stream) != 0)
        failed = 1;
    if (failed)
        fprintf(stderr, "%s: stream regression failed\n", item->name);
    return failed;
}

/* Build one synthetic archive and exercise each supported storage mode. */
int
main(void)
{
    mpq_archive_create_options_s creation = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0, 0 };
    uint8_t expected[STREAM_TEST_SIZE];
    mpq_archive_s *archive = NULL;
    char path[128];
    int failed = 1;

    if (test_temp_path(path, sizeof(path), "stream") != 0)
        return 1;
    for (size_t i = 0; i < sizeof(expected); i++)
        expected[i] = (uint8_t)('A' + ((i / 64u + i % 7u) % 26u));
    if (libmpq__archive_create(&archive, path, &creation) != 0)
        goto done;
    for (size_t i = 0; i < sizeof(stream_cases) / sizeof(stream_cases[0]); i++) {
        if (libmpq__archive_add_data(
                archive, stream_cases[i].name, expected, sizeof(expected), &stream_cases[i].options
            ) != 0)
            goto done;
    }
    if (libmpq__archive_close(archive) != 0) {
        archive = NULL;
        goto done;
    }
    archive = NULL;
    if (libmpq__archive_open(&archive, path, 0) != 0)
        goto done;
    for (size_t i = 0; i < sizeof(stream_cases) / sizeof(stream_cases[0]); i++)
        if (check_stream(archive, &stream_cases[i], expected))
            goto done;
    failed = 0;
done:
    if (archive != NULL && libmpq__archive_close(archive) != 0)
        failed = 1;
    (void)remove(path);
    return failed;
}
