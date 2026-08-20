/* Exercise the compiled little-endian serialization module. */
#include "helper.h"

#include "../src/endian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create the smallest deterministic archive used by serialized vectors. */
static int
create_serialized_vector(const char *path, uint32_t version)
{
    static const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s archive_options = { version, 1, 512, 0 };
    mpq_file_options_s file_options = { 0, 0, 0, 0, 0 };

    TEST_CHECK(libmpq__archive_create(&archive, path, &archive_options) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "vector.bin", payload, sizeof(payload), &file_options) == 0
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
        free(data);
        remove(paths[i]);
    }
    return 0;
}

/* Verify unaligned-safe little-endian loads and stores for all widths. */
int
main(void)
{
    uint8_t raw[16] = { 0 };

    TEST_CHECK(libmpq__load_le16((const uint8_t[]){ 0x78, 0x56 }) == 0x5678);
    TEST_CHECK(libmpq__load_le32((const uint8_t[]){ 0x78, 0x56, 0x34, 0x12 }) == 0x12345678);
    TEST_CHECK(
        libmpq__load_le64((const uint8_t[]){ 1, 2, 3, 4, 5, 6, 7, 8 }) ==
        UINT64_C(0x0807060504030201)
    );
    TEST_CHECK(libmpq__load_le16(NULL) == 0 && libmpq__load_le32(NULL) == 0);
    TEST_CHECK(libmpq__load_le64(NULL) == 0);
    libmpq__store_le16(raw, 0x5678);
    libmpq__store_le32(raw + 2, 0x12345678);
    libmpq__store_le64(raw + 6, UINT64_C(0x1122334455667788));
    TEST_CHECK(
        raw[0] == 0x78 && raw[1] == 0x56 && raw[2] == 0x78 && raw[5] == 0x12 && raw[6] == 0x88 &&
        raw[13] == 0x11
    );
    TEST_CHECK(test_serialized_vectors() == 0);
    return 0;
}
