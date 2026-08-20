/* Exercise public lifecycle, metadata, lookup, endian, and clone behavior. */
#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exercise the public archive and file facade with a deterministic archive. */
int
main(void)
{
    char path[128];
    const uint8_t payload[] = "public API";
    uint8_t output[sizeof(payload)];
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_archive_create_options_s create = { 1, 8, 4096, 0 };
    libmpq__off_t size;
    libmpq__off_t offset;
    libmpq__off_t transferred;
    uint32_t number;
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    uint32_t value;

    TEST_CHECK(libmpq__version() != NULL && *libmpq__version() != '\0');
    TEST_CHECK(libmpq__strerror(0) != NULL && libmpq__strerror(12345) == NULL);
    TEST_CHECK(libmpq__archive_clone(NULL, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(test_temp_path(path, sizeof(path), "mpq") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__file_add(archive, "payload", payload, sizeof(payload) - 1, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_offset(archive, &offset) == 0 && offset == 0);
    TEST_CHECK(libmpq__archive_files(archive, &value) == 0 && value == 1);
    size = 0;
    TEST_CHECK(libmpq__archive_size_unpacked(archive, &size) == 0 && size == sizeof(payload) - 1);
    TEST_CHECK(libmpq__archive_size_packed(archive, &size) == 0 && size > 0);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    libmpq__file_hash("payload", &hash1, &hash2, &hash3);
    TEST_CHECK(libmpq__file_number_from_hash(archive, hash1, hash2, hash3, &number) == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0 && offset > 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(payload) - 1 && memcmp(output, payload, transferred) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__file_number(clone, "payload", &number) == 0);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    remove(path);
    return 0;
}
