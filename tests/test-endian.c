/* Check byte-order helpers and byte-stable archive creation/extraction. */
#include "../src/endian.h"
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verify endian helpers and byte-stable archive creation and extraction. */
int
main(void)
{
    uint8_t raw[16] = { 0 };
    uint8_t *archive_bytes;
    uint8_t *payload;
    char path[128];
    char hash[65];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { 0, 0, 0, 0, 0 };
    uint32_t number;
    size_t archive_size;
    size_t payload_size;
    TEST_CHECK(libmpq__load_le16((uint8_t[]){ 0x78, 0x56 }) == 0x5678);
    TEST_CHECK(libmpq__load_le32((uint8_t[]){ 0x78, 0x56, 0x34, 0x12 }) == 0x12345678);
    TEST_CHECK(
        libmpq__load_le64((uint8_t[]){ 1, 2, 3, 4, 5, 6, 7, 8 }) == UINT64_C(0x0807060504030201)
    );
    libmpq__store_le16(raw, 0x5678);
    libmpq__store_le32(raw + 2, 0x12345678);
    libmpq__store_le64(raw + 6, UINT64_C(0x1122334455667788));
    TEST_CHECK(
        raw[0] == 0x78 && raw[1] == 0x56 && raw[2] == 0x78 && raw[5] == 0x12 && raw[6] == 0x88 &&
        raw[13] == 0x11
    );
    TEST_CHECK(test_temp_path(path, sizeof(path), "endian") == 0);
    TEST_CHECK(test_add_archive(&archive, path, 1, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "bytes", (const uint8_t *)"endian", 6, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_read_path(path, &archive_bytes, &archive_size) == 0);
    TEST_CHECK(test_sha256(archive_bytes, archive_size, hash) == 0 && strlen(hash) == 64);
    free(archive_bytes);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "bytes", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &payload, &payload_size) == 0);
    TEST_CHECK(payload_size == 6 && memcmp(payload, "endian", 6) == 0);
    free(payload);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}
