/*
 *  test-mpq-crypto.c -- libmpq regression tests.
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

/* Exercise encrypted raw payloads and encrypted-file key recovery. */
#include "test-mpq-helper.h"

#include "../src/mpq-crypto.h"
#include "../src/mpq-endian.h"
#include "../src/mpq-file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verify one encrypted file round trip using a recognizable file signature. */
static int
test_encrypted_file(const char *path)
{
    uint8_t payload[20000];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    uint8_t *output = NULL;
    size_t output_size;
    uint32_t number;

    memset(payload, 'E', sizeof(payload));
    memcpy(payload, "RIFF", 4);
    payload[4] = (uint8_t)((sizeof(payload) - 8) & 0xffu);
    payload[5] = (uint8_t)((sizeof(payload) - 8) >> 8);
    payload[6] = (uint8_t)((sizeof(payload) - 8) >> 16);
    payload[7] = (uint8_t)((sizeof(payload) - 8) >> 24);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "encrypted.raw", payload, sizeof(payload), &options) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "encrypted.raw", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/*
 * An anonymous encrypted payload shorter than one cipher word is literal on
 * disk. It must not require impossible filename-based seed recovery.
 */
static int
test_short_anonymous_encrypted_file(const char *path)
{
    static const uint8_t payload[] = { 0x2e };
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    uint8_t *output = NULL;
    size_t output_size;
    uint32_t number;

    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, "anonymous-short.raw", payload, sizeof(payload), &options
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "anonymous-short.raw", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Verify encrypted compressed sectors and the encrypted sector-offset table. */
static int
test_encrypted_compressed_file(const char *path)
{
    uint8_t payload[12000];
    uint8_t *archive_data = NULL;
    uint8_t *table = NULL;
    uint8_t *output = NULL;
    size_t archive_size;
    size_t output_size;
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    libmpq__off_t offset;
    uint32_t number;
    uint32_t key;

    memset(payload, 'C', sizeof(payload));
    memcpy(payload, "compressed-encryption\n", 22);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, "encrypted-compressed.bin", payload, sizeof(payload), &options
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "encrypted-compressed.bin", &number) == 0);
    TEST_CHECK(
        libmpq__file_flags(archive, number, &key) == 0 && (key & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0
    );
    TEST_CHECK((key & LIBMPQ_FILE_FLAG_COMPRESS) != 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &key) == 0 && key == 3);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    free(output);
    output = NULL;
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0);
    TEST_CHECK(test_read_path(path, &archive_data, &archive_size) == 0);
    TEST_CHECK(offset >= 16 && (uint64_t)offset + 16 <= archive_size);
    table = malloc(16);
    TEST_CHECK(table != NULL);
    memcpy(table, archive_data + offset, 16);
    key = libmpq__crypto_hash_string("encrypted-compressed.bin", 0x300);
    {
        int valid = libmpq__load_le32(table) != 16;
        valid = valid && libmpq__crypto_decrypt_block(table, 16, key - 1) == 0;
        valid = valid && libmpq__load_le32(table) == 16;
        valid = valid && libmpq__load_le32(table + 4) > libmpq__load_le32(table);
        valid = valid && libmpq__load_le32(table + 12) > libmpq__load_le32(table + 8);
        free(table);
        free(archive_data);
        table = NULL;
        archive_data = NULL;
        TEST_CHECK(valid);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Fixed unsigned-byte vectors catch EOF confusion and out-of-range crypt-table access. */
static int
test_high_byte_names(void)
{
    static const uint32_t expected[] = { 0x1e50f037, 0x8051beff, 0x22fc45a1, 0x54b3b3b7,
                                         0x1ddf46b7 };
    const char byte[] = { (char)0xff, 0 };
    const char name[] = { 'd', 'i', 'r', '\\', (char)0xff, '.', 'b', 'i', 'n', 0 };
    uint8_t payload[128];
    uint8_t output[128];
    memset(payload, 'H', sizeof(payload));
    for (uint32_t phase = 0; phase < 5; ++phase)
        TEST_CHECK(libmpq__crypto_hash_string(byte, phase * 0x100u) == expected[phase]);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_THREE;
         ++version) {
        mpq_archive_create_options_s create = { version, 4, 512, 0, 0 };
        mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0,
                                       0, 0 };
        mpq_archive_s *archive = NULL;
        mpq_stream_s *stream = NULL;
        libmpq__off_t transferred;
        uint32_t number;
        char path[128];
        TEST_CHECK(test_temp_path(path, sizeof(path), "high-byte") == 0);
        TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
        TEST_CHECK(
            libmpq__archive_add_data(archive, name, payload, sizeof(payload), &storage) == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
        TEST_CHECK(libmpq__stream_open_name(archive, name, &stream) == 0);
        TEST_CHECK(libmpq__stream_read(stream, output, sizeof(output), &transferred) == 0);
        TEST_CHECK(transferred == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(remove(path) == 0);
    }
    return 0;
}

/* Fixed values from an independent crypt-table generator and hash implementation. */
static int
test_basename_keys(void)
{
    static const char *const names[] = { "reference.bin",
                                         "folder/reference.bin",
                                         "folder\\reference.bin",
                                         "folder/subfolder/reference.bin",
                                         "FOLDER\\SUBFOLDER\\REFERENCE.BIN",
                                         "folder\\subfolder/reference.bin" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        TEST_CHECK(libmpq__crypto_file_key(names[i]) == 0xa25af234u);
    TEST_CHECK(libmpq__crypto_file_key("") == 0x7fed7fedu);
    TEST_CHECK(libmpq__crypto_file_key("folder/\\") == 0x7fed7fedu);
    TEST_CHECK(libmpq__crypto_file_key("folder/\xff") == 0x54b3b3b7u);
    TEST_CHECK(((libmpq__crypto_file_key(names[0]) + UINT32_MAX) ^ 32u) == 0xa25af213u);
    return 0;
}

/* Directory members exercise named, numbered and streaming reads through both layers. */
static int
test_directory_members(void)
{
    static const uint8_t auth[] = "libmpq synthetic basename authentication test material";
    static const char *const names[] = { "folder/reference.bin", "folder\\fixed.bin",
                                         "folder/sub/sector.bin", "folder\\sub/fixed-sector.bin" };
    uint8_t payload[1600];
    uint8_t output[1600];
    char path[128];
    memset(payload, 'R', sizeof(payload));
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_THREE;
         ++version) {
        for (unsigned wrapped = 0; wrapped < (version == LIBMPQ_ARCHIVE_VERSION_ONE ? 1u : 2u);
             ++wrapped) {
            mpq_archive_create_options_s create = { version, 8, 512, 0, 0 };
            mpq_archive_s *archive = NULL;
            TEST_CHECK(test_temp_path(path, sizeof(path), "directory-keys") == 0);
            TEST_CHECK(
                (wrapped
                     ? libmpq__archive_create_mpqe(&archive, path, auth, sizeof(auth) - 1, &create)
                     : libmpq__archive_create(&archive, path, &create)) == 0
            );
            for (unsigned i = 0; i < 4; ++i) {
                mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_ENCRYPTED |
                                                   LIBMPQ_FILE_FLAG_COMPRESS,
                                               LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0,
                                               0 };
                if (i < 2)
                    storage.flags = LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED;
                if ((i & 1u) != 0)
                    storage.flags |= 0x00020000u;
                memcpy(payload, "RIFF", 4);
                libmpq__store_le32(payload + 4, (uint32_t)(i < 2 ? 400 : sizeof(payload)) - 8);
                TEST_CHECK(
                    libmpq__archive_add_data(
                        archive, names[i], payload, i < 2 ? 400 : sizeof(payload), &storage
                    ) == 0
                );
            }
            TEST_CHECK(libmpq__archive_close(archive) == 0);
            TEST_CHECK(
                (wrapped ? libmpq__archive_open_mpqe(&archive, path, 0, auth, sizeof(auth) - 1)
                         : libmpq__archive_open(&archive, path, 0)) == 0
            );
            for (unsigned i = 0; i < 4; ++i) {
                mpq_stream_s *stream = NULL;
                uint32_t number;
                size_t length = i < 2 ? 400 : sizeof(payload);
                libmpq__store_le32(payload + 4, (uint32_t)length - 8);
                libmpq__off_t transferred;
                libmpq__off_t packed;
                libmpq__off_t unpacked;
                TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
                TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0);
                TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0);
                TEST_CHECK(packed > 0 && packed <= (libmpq__off_t)length);
                TEST_CHECK(unpacked == (libmpq__off_t)length);
                TEST_CHECK(libmpq__stream_open_name(archive, names[i], &stream) == 0);
                TEST_CHECK(libmpq__stream_read(stream, output, sizeof(output), &transferred) == 0);
                TEST_CHECK(
                    transferred == (libmpq__off_t)length && memcmp(output, payload, length) == 0
                );
                TEST_CHECK(libmpq__stream_seek(stream, 109, LIBMPQ_SEEK_SET) == 0);
                TEST_CHECK(libmpq__stream_read(stream, output, 200, &transferred) == 0);
                TEST_CHECK(transferred == 200 && memcmp(output, payload + 109, 200) == 0);

                /* Numbered reads independently recover the raw signature or sector-table key. */
                TEST_CHECK(
                    libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0
                );
                TEST_CHECK(
                    transferred == (libmpq__off_t)length && memcmp(output, payload, length) == 0
                );
                TEST_CHECK(libmpq__stream_close(stream) == 0);
            }
            TEST_CHECK(libmpq__archive_close(archive) == 0);
            TEST_CHECK(remove(path) == 0);
        }
    }
    return 0;
}

/* Standard basename encryption must survive a named directory read. */
static int
test_reference_directory_member(const char *path)
{
    const char *name = "folder\\reference.bin";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 4, 512, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0,
                                   0 };
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t payload[32];

    /* Independently generated ciphertext for 32 'B' bytes and key 0xa25af234. */
    static const uint8_t encrypted[32] = { 0x2d, 0xba, 0xad, 0xd4, 0xd8, 0xf2, 0xcb, 0x4a,
                                           0xe5, 0xb6, 0xed, 0xb5, 0xa3, 0x4d, 0x5c, 0xfe,
                                           0x95, 0x38, 0xa9, 0x01, 0xb9, 0xf3, 0x8a, 0xc7,
                                           0x37, 0xba, 0xb8, 0xe8, 0x95, 0x24, 0x7d, 0x06 };
    uint8_t output[32];
    libmpq__off_t offset;
    libmpq__off_t transferred;
    uint32_t number;
    FILE *file;
    int matches;
    memset(payload, 'B', sizeof(payload));
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, name, payload, sizeof(payload), &storage) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    /* Keep every table/header byte unchanged; only use the reference basename key. */
    file = fopen(path, "r+b");
    TEST_CHECK(file != NULL);
    TEST_CHECK(libmpq__file_seek(file, offset, SEEK_SET) == 0);
    TEST_CHECK(fwrite(encrypted, 1, sizeof(encrypted), file) == sizeof(encrypted));
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, name, &stream) == 0);
    TEST_CHECK(libmpq__stream_read(stream, output, sizeof(output), &transferred) == 0);
    matches = transferred == sizeof(payload) && memcmp(payload, output, sizeof(payload)) == 0;
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(matches);
    return 0;
}

/* Exercise encrypted payload creation and extraction. */
int
main(int argc, char **argv)
{
    char path[128];
    if (argc == 2 && strcmp(argv[1], "--reference-directory") == 0) {
        int result;
        TEST_CHECK(test_temp_path(path, sizeof(path), "reference-key") == 0);
        result = test_reference_directory_member(path);
        (void)remove(path);
        return result;
    }
    TEST_CHECK(test_high_byte_names() == 0);
    TEST_CHECK(test_basename_keys() == 0);
    TEST_CHECK(test_directory_members() == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "reference-key") == 0);
    TEST_CHECK(test_reference_directory_member(path) == 0);
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "crypto") == 0);
    TEST_CHECK(test_encrypted_file(path) == 0);
    remove(path);
    TEST_CHECK(test_temp_path(path, sizeof(path), "crypto-short") == 0);
    TEST_CHECK(test_short_anonymous_encrypted_file(path) == 0);
    remove(path);
    TEST_CHECK(test_temp_path(path, sizeof(path), "crypto-compressed") == 0);
    TEST_CHECK(test_encrypted_compressed_file(path) == 0);
    remove(path);
    return 0;
}
