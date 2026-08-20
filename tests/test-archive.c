/* Exercise archive creation, opening, closing, and archive metadata. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>

/* Exercise archive creation, metadata queries, opening, and closing. */
int
main(void)
{
    char path[128];
    const uint8_t data[] = "archive metadata";
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s create_options = { 0, 8, 4096, 0 };
    libmpq__off_t offset;
    libmpq__off_t size;
    uint32_t files;
    uint32_t version;

    TEST_CHECK(test_temp_path(path, sizeof(path), "archive") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create_options) == 0);
    TEST_CHECK(libmpq__file_add(archive, "one", data, sizeof(data) - 1, NULL) == 0);
    TEST_CHECK(libmpq__file_add(archive, "two", data, sizeof(data) - 1, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_offset(archive, &offset) == 0 && offset == 0);
    TEST_CHECK(libmpq__archive_version(archive, &version) == 0 && version == 1);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 2);
    size = 0;
    TEST_CHECK(
        libmpq__archive_size_unpacked(archive, &size) == 0 && size == 2 * (sizeof(data) - 1)
    );
    TEST_CHECK(libmpq__archive_size_packed(archive, &size) == 0 && size > 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}
