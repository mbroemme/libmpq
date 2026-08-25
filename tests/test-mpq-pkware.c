/* Exercise extraction of PKWARE and implode fixture payloads. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>

/* Read both PKWARE-backed fixture entries to exercise the decoder path. */
int
main(void)
{
    char path[512];
    const char *names[] = { "pkware.txt", "implode.txt" };
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    size_t size;
    uint32_t number;
    size_t i;

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
        TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0 && size > 0);
        free(data);
        data = NULL;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
