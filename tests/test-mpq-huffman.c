/* Exercise extraction of the checked-in adaptive-Huffman fixture payload. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Resolve and hash the Huffman-compressed fixture entry. */
int
main(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    size_t size;
    char hash[65];
    uint32_t number;

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "huffman.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(
        strcmp(hash, "93c7bdaceb3a5aa3969520c20a63e64d577227f51d2bbb6ee075c43ff8fa5b8e") == 0
    );
    free(data);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
