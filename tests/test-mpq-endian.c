/* Exercise the compiled little-endian serialization module. */
#include "test-mpq-helper.h"

#include "../src/mpq-endian.h"
#include "../src/mpq-internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create the smallest deterministic archive used by serialized vectors. */
static int
create_serialized_vector(const char *path, uint32_t version)
{
    static const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s archive_options = { version, 1, 512, 0, 0 };
    mpq_file_options_s file_options = { 0, 0, 0, 0, 0 };

    TEST_CHECK(libmpq__archive_create(&archive, path, &archive_options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "vector.bin", payload, sizeof(payload), &file_options) ==
        0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Verify exact v1/v2 headers and complete deterministic archive bytes. */
static int
test_serialized_vectors(void)
{
    static const uint8_t v1_header[] = {
        0x4d, 0x50, 0x51, 0x1a, 0x20, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    };
    static const uint8_t v2_header[] = {
        0x4d, 0x50, 0x51, 0x1a, 0x2c, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x2c, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const char *hashes[] = {
        "d730dc7f09ac61e27500509f126a5a0e1751ab6d83bee589f433cc6a35bf2413",
        "753f60f41b3d1d489b12f1717c967d1e488842759b7b428534a842c3caa935ed",
    };
    const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
    char paths[2][128];
    uint8_t *data;
    size_t size;
    char hash[65];
    size_t i;
    mpq_archive_s *archive = NULL;
    uint8_t extracted[sizeof(payload)];
    uint32_t file_number;

    for (i = 0; i < 2; ++i) {
        TEST_CHECK(
            test_temp_path(paths[i], sizeof(paths[i]), i == 0 ? "vector-v1" : "vector-v2") == 0
        );
        TEST_CHECK(create_serialized_vector(paths[i], (uint32_t)i) == 0);
        TEST_CHECK(test_read_path(paths[i], &data, &size) == 0);
        TEST_CHECK(size == 516);
        TEST_CHECK(memcmp(data, i == 0 ? v1_header : v2_header, i == 0 ? 32 : 44) == 0);
        TEST_CHECK(memcmp(data + 512, payload, sizeof(payload)) == 0);
        TEST_CHECK(test_sha256(data, size, hash) == 0);
        TEST_CHECK(strcmp(hash, hashes[i]) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, paths[i], 0) == 0);
        TEST_CHECK(libmpq__file_number(archive, "vector.bin", &file_number) == 0);
        TEST_CHECK(
            libmpq__file_read(archive, file_number, extracted, sizeof(extracted), NULL) == 0
        );
        TEST_CHECK(memcmp(extracted, payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        free(data);
        remove(paths[i]);
    }
    return 0;
}

/* The v2 extension occupies exactly 12 wire bytes, including at physical EOF. */
static int
test_header_extension_size(void)
{
    static const uint8_t header[LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE] = {
        0x4d, 0x50, 0x51, 0x1a, 0x2c, 0, 0, 0, 0x2c, 0, 0, 0,
        1,    0,    0,    0,    0x2c, 0, 0, 0, 0x2c, 0, 0, 0,
    };
    static const size_t sizes[] = { sizeof(header), sizeof(header) - 1 };
    char path[128];
    FILE *file;
    mpq_archive_s *archive = NULL;
    uint32_t count;
    size_t size;
    size_t i;

    TEST_CHECK(test_temp_path(path, sizeof(path), "v2-extension-eof") == 0);
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        size = sizes[i];
        file = fopen(path, "wb");
        TEST_CHECK(file != NULL);
        TEST_CHECK(fwrite(header, 1, size, file) == size);
        TEST_CHECK(fclose(file) == 0);
        if (size == sizeof(header)) {
            TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
            TEST_CHECK(libmpq__archive_files(archive, &count) == 0 && count == 0);
            TEST_CHECK(libmpq__archive_close(archive) == 0);
            archive = NULL;
        } else {
            TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_ERROR_FORMAT);
            TEST_CHECK(archive == NULL);
        }
    }
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Verify unaligned-safe little- and big-endian loads and stores for all widths. */
int
main(void)
{
    uint8_t raw[16] = { 0 };

    /* Wire sizes are fixed even when native structures have alignment padding. */
    TEST_CHECK(LIBMPQ_HEADER_WIRE_SIZE == 32u);
    TEST_CHECK(LIBMPQ_HEADER_EX_WIRE_SIZE == 12u);
    TEST_CHECK(LIBMPQ_HASH_ENTRY_WIRE_SIZE == 16u);
    TEST_CHECK(LIBMPQ_BLOCK_ENTRY_WIRE_SIZE == 16u);
    TEST_CHECK(LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE == 2u);
    TEST_CHECK(test_header_extension_size() == 0);

    TEST_CHECK(libmpq__load_le16((const uint8_t[]){ 0x78, 0x56 }) == 0x5678);
    TEST_CHECK(libmpq__load_le32((const uint8_t[]){ 0x78, 0x56, 0x34, 0x12 }) == 0x12345678);
    TEST_CHECK(
        libmpq__load_le64((const uint8_t[]){ 1, 2, 3, 4, 5, 6, 7, 8 }) ==
        UINT64_C(0x0807060504030201)
    );
    TEST_CHECK(libmpq__load_le16(NULL) == 0 && libmpq__load_le32(NULL) == 0);
    TEST_CHECK(libmpq__load_le64(NULL) == 0);
    TEST_CHECK(libmpq__load_be32((const uint8_t[]){ 0x12, 0x34, 0x56, 0x78 }) == 0x12345678);
    libmpq__store_le16(raw, 0x5678);
    libmpq__store_le32(raw + 2, 0x12345678);
    libmpq__store_le64(raw + 6, UINT64_C(0x1122334455667788));
    TEST_CHECK(
        raw[0] == 0x78 && raw[1] == 0x56 && raw[2] == 0x78 && raw[5] == 0x12 && raw[6] == 0x88 &&
        raw[13] == 0x11
    );
    libmpq__store_be32(raw + 1, 0x12345678);
    TEST_CHECK(libmpq__load_be32(raw + 1) == 0x12345678);
    TEST_CHECK(raw[1] == 0x12 && raw[2] == 0x34 && raw[3] == 0x56 && raw[4] == 0x78);
    TEST_CHECK(test_serialized_vectors() == 0);
    return 0;
}
