/* Exercise raw, zlib, bzip2, and invalid compression paths. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create one compressed entry and verify its complete round trip. */
static int
test_round_trip(
    const char *path, const char *name, const uint8_t *payload, size_t size, uint32_t compression
)
{
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, compression, compression, 0, 0 };
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

/* Exercise supported compression combinations and rejected codec masks. */
int
main(void)
{
    char path[128];
    uint8_t data[20000];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s invalid = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE, 0, 0, 0,
                                   0 };

    TEST_CHECK(test_temp_path(path, sizeof(path), "compression") == 0);
    memset(data, 'C', sizeof(data));
    TEST_CHECK(test_round_trip(path, "zlib", data, sizeof(data), LIBMPQ_COMPRESSION_ZLIB) == 0);
    remove(path);
    TEST_CHECK(test_round_trip(path, "bzip2", data, sizeof(data), LIBMPQ_COMPRESSION_BZIP2) == 0);
    remove(path);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "invalid", data, sizeof(data), &invalid) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}
