/* Exercise encrypted raw payloads and encrypted-file key recovery. */
#include "helper.h"

#include "../src/crypto.h"
#include "../src/endian.h"

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
    TEST_CHECK(libmpq__file_add(archive, "encrypted.raw", payload, sizeof(payload), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "encrypted.raw", &number) == 0);
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
        libmpq__file_add(archive, "encrypted-compressed.bin", payload, sizeof(payload), &options) ==
        0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "encrypted-compressed.bin", &number) == 0);
    TEST_CHECK(libmpq__file_encrypted(archive, number, &key) == 0 && key != 0);
    TEST_CHECK(libmpq__file_compressed(archive, number, &key) == 0 && key != 0);
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

/* Exercise encrypted payload creation and extraction. */
int
main(void)
{
    char path[128];
    TEST_CHECK(test_temp_path(path, sizeof(path), "crypto") == 0);
    TEST_CHECK(test_encrypted_file(path) == 0);
    remove(path);
    TEST_CHECK(test_temp_path(path, sizeof(path), "crypto-compressed") == 0);
    TEST_CHECK(test_encrypted_compressed_file(path) == 0);
    remove(path);
    return 0;
}
