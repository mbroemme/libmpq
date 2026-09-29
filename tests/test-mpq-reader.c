/*
 *  test-mpq-reader.c -- libmpq regression tests.
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

/* Exercise fixture opening, file maps, sector offsets, and block reads. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Validate fixture metadata and extraction through the reader-facing API. */
int
main(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    uint8_t *block_data;
    size_t size;
    char hash[65];
    uint32_t number;
    uint32_t blocks;
    uint32_t flags;
    libmpq__off_t block_size;
    libmpq__off_t transferred;

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(
        strcmp(hash, "722f1acc2acd306abaed0466ffbbfd568e09f5e7da8d63eba86f19c1c2adde73") == 0
    );
    TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &block_size) == 0);
    TEST_CHECK(block_size > 0 && (uint64_t)block_size <= size);
    block_data = malloc((size_t)block_size + 17);
    TEST_CHECK(block_data != NULL);
    TEST_CHECK(libmpq__block_read(archive, number, 0, block_data, block_size, &transferred) == 0);
    TEST_CHECK(transferred == block_size);
    TEST_CHECK(memcmp(block_data, data, (size_t)block_size) == 0);

    /*
     * Raw unencrypted reads share input/output storage and must skip self-copy.
     * Their logical size remains independent of the caller buffer capacity.
     */
    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
    TEST_CHECK(
        (flags &
         (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED)) == 0
    );
    memset(block_data, 0xa5, (size_t)block_size + 17);
    TEST_CHECK(
        libmpq__block_read(archive, number, 0, block_data, block_size + 17, &transferred) == 0
    );
    TEST_CHECK(transferred == block_size);
    TEST_CHECK(memcmp(block_data, data, (size_t)block_size) == 0);
    TEST_CHECK(block_data[block_size] == 0xa5);
    free(block_data);
    free(data);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
