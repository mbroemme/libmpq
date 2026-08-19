/* Exercise file lookup, metadata, hashing, and complete reads. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
    char path[128];
    const uint8_t data[] = "public file";
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { 0, 0, 0, 0, 0 };
    uint8_t output[sizeof(data)];
    uint32_t file_number;
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    uint32_t value;
    libmpq__off_t offset;
    libmpq__off_t size;
    libmpq__off_t transferred;

    TEST_CHECK(test_temp_path(path, sizeof(path), "files") == 0);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "file.bin", data, sizeof(data) - 1, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);

    TEST_CHECK(libmpq__file_number(archive, "file.bin", &file_number) == 0);
    libmpq__file_hash("file.bin", &hash1, &hash2, &hash3);
    TEST_CHECK(libmpq__file_number_from_hash(archive, hash1, hash2, hash3, &file_number) == 0);
    TEST_CHECK(libmpq__file_size_packed(archive, file_number, &size) == 0 && size > 0);
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, file_number, &size) == 0 && size == sizeof(data) - 1
    );
    TEST_CHECK(libmpq__file_offset(archive, file_number, &offset) == 0 && offset > 0);
    TEST_CHECK(libmpq__file_blocks(archive, file_number, &value) == 0 && value > 0);
    TEST_CHECK(libmpq__file_encrypted(archive, file_number, &value) == 0 && value == 0);
    TEST_CHECK(libmpq__file_compressed(archive, file_number, &value) == 0 && value == 0);
    TEST_CHECK(libmpq__file_imploded(archive, file_number, &value) == 0 && value == 0);
    TEST_CHECK(libmpq__file_read(archive, file_number, output, sizeof(output), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(data) - 1 && memcmp(output, data, transferred) == 0);
    TEST_CHECK(libmpq__file_read(archive, file_number, output, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_read(archive, 99, output, sizeof(output), NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}
