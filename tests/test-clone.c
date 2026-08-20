/* Verify clone independence and close-order behavior on a real fixture. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verify cloned handles remain usable independently after either close. */
int
main(void)
{
    char path[512];
    mpq_archive_s *source = NULL;
    mpq_archive_s *clone = NULL;
    uint32_t number;
    uint8_t *a;
    uint8_t *b;
    size_t as;
    size_t bs;
    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&source, path, 0) == 0);
    TEST_CHECK(libmpq__archive_clone(&clone, source) == 0);
    TEST_CHECK(libmpq__file_number(source, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(source, number, &a, &as) == 0);
    TEST_CHECK(libmpq__file_number(clone, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(clone, number, &b, &bs) == 0);
    TEST_CHECK(as == bs && memcmp(a, b, as) == 0);
    free(a);
    free(b);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    TEST_CHECK(libmpq__file_number(source, "zlib.txt", &number) == 0);
    TEST_CHECK(test_archive_read(source, number, &a, &as) == 0);
    free(a);
    TEST_CHECK(libmpq__archive_clone(&clone, source) == 0);
    TEST_CHECK(libmpq__archive_close(source) == 0);
    TEST_CHECK(libmpq__file_number(clone, "bzip2.txt", &number) == 0);
    TEST_CHECK(test_archive_read(clone, number, &a, &as) == 0);
    free(a);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    return 0;
}
