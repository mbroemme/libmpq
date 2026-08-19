/* Round-trip supported compression/encryption paths and reject invalid masks. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
round_trip(
    const char *path, const char *name, const uint8_t *payload, size_t size, uint32_t flags,
    uint32_t first, uint32_t next
)
{
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { flags, first, next, 0, 0 };
    uint8_t *output = NULL;
    size_t output_size;
    uint32_t number;
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, name, payload, size, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == size && memcmp(output, payload, size) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

int
main(void)
{
    char path[128];
    uint8_t data[20000];
    uint8_t encrypted_data[20000];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s invalid = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE, 0, 0, 0,
                                   0 };
    TEST_CHECK(test_temp_path(path, sizeof(path), "codecs") == 0);
    memset(data, 'C', sizeof(data));
    memset(encrypted_data, 'E', sizeof(encrypted_data));
    memcpy(encrypted_data, "RIFF", 4);
    encrypted_data[4] = (uint8_t)((sizeof(encrypted_data) - 8) & 0xff);
    encrypted_data[5] = (uint8_t)((sizeof(encrypted_data) - 8) >> 8);
    encrypted_data[6] = (uint8_t)((sizeof(encrypted_data) - 8) >> 16);
    encrypted_data[7] = (uint8_t)((sizeof(encrypted_data) - 8) >> 24);
    TEST_CHECK(round_trip(path, "raw", data, sizeof(data), 0, 0, 0) == 0);
    remove(path);
    TEST_CHECK(
        round_trip(
            path, "zlib", data, sizeof(data), LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
            LIBMPQ_COMPRESSION_ZLIB
        ) == 0
    );
    remove(path);
    TEST_CHECK(
        round_trip(
            path, "bzip2", data, sizeof(data), LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_BZIP2,
            LIBMPQ_COMPRESSION_BZIP2
        ) == 0
    );
    remove(path);
    TEST_CHECK(
        round_trip(
            path, "encrypted", encrypted_data, sizeof(encrypted_data), LIBMPQ_FILE_FLAG_ENCRYPTED,
            0, 0
        ) == 0
    );
    remove(path);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "invalid", data, sizeof(data), &invalid) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}
