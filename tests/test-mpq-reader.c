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
#include "mpq-archive.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Extra aligned DWORDs before the first compressed sector are not encryption. */
static int
test_extended_sector_offsets(void)
{
    enum
    {
        extra = 108
    };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                   LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    char source_path[512];
    char extended_path[512];
    mpq_archive_s *archive = NULL;
    uint8_t payload[3 * 4096 + 71];
    uint8_t output[sizeof(payload)];
    uint8_t *original = NULL;
    uint8_t *extended = NULL;
    size_t original_size;
    uint32_t number;
    uint32_t blocks;
    uint32_t physical;
    uint32_t block_table_offset;
    uint32_t hash_table_offset;
    uint32_t block_table_count;
    uint32_t member_offset;
    uint32_t insert_at;
    uint32_t first_offset;
    libmpq__off_t transferred;
    FILE *file;

    TEST_CHECK(test_temp_path(source_path, sizeof(source_path), "extended-offset-source") == 0);
    TEST_CHECK(test_temp_path(extended_path, sizeof(extended_path), "extended-offset-table") == 0);
    test_payload(payload, sizeof(payload), 0x12345678u);
    TEST_CHECK(libmpq__archive_create(&archive, source_path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "payload.bin", payload, sizeof(payload), &storage) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_read_path(source_path, &original, &original_size) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, source_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 1);
    physical = archive->mpq_map[number].block_table_indices;
    member_offset = archive->mpq_block[physical].offset;
    first_offset = (blocks + 1u) * 4u;
    insert_at = member_offset + first_offset;
    block_table_offset = archive->mpq_header.block_table_offset;
    hash_table_offset = archive->mpq_header.hash_table_offset;
    block_table_count = archive->mpq_header.block_table_count;
    TEST_CHECK(insert_at < original_size);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    extended = malloc(original_size + extra);
    TEST_CHECK(extended != NULL);
    memcpy(extended, original, insert_at);
    memset(extended + insert_at, 0, extra);
    memcpy(extended + insert_at + extra, original + insert_at, original_size - insert_at);
    for (uint32_t i = 0; i <= blocks; ++i) {
        uint32_t offset = libmpq__load_le32(extended + member_offset + i * 4u);
        libmpq__store_le32(extended + member_offset + i * 4u, offset + extra);
    }
    TEST_CHECK(libmpq__load_le32(extended + member_offset) == first_offset + extra);
    libmpq__store_le32(extended + 8, libmpq__load_le32(extended + 8) + extra);
    if (hash_table_offset >= insert_at)
        libmpq__store_le32(extended + 16, hash_table_offset + extra);
    if (block_table_offset >= insert_at)
        libmpq__store_le32(extended + 20, block_table_offset + extra);
    {
        uint8_t *table =
            extended + block_table_offset + (block_table_offset >= insert_at ? extra : 0);
        uint32_t table_size = block_table_count * 16u;
        uint32_t key = libmpq__crypto_hash_string("(block table)", 0x300);
        uint32_t packed_size;

        TEST_CHECK(libmpq__crypto_decrypt_block(table, table_size, key) == 0);
        packed_size = libmpq__load_le32(table + physical * 16u + 4u);
        libmpq__store_le32(table + physical * 16u + 4u, packed_size + extra);
        TEST_CHECK(libmpq__crypto_encrypt_block(table, table_size, key) == 0);
    }
    file = fopen(extended_path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(extended, 1, original_size + extra, file) == original_size + extra);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, extended_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(original);
    free(extended);
    TEST_CHECK(remove(source_path) == 0);
    TEST_CHECK(remove(extended_path) == 0);
    return 0;
}

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

    TEST_CHECK(test_extended_sector_offsets() == 0);

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
