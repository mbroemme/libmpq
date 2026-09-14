/* Exercise fixture opening, file maps, sector offsets, and block reads. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Validate fixture metadata and extraction through the reader-facing API. */
int
main(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    size_t size;
    char hash[65];
    uint32_t number;
    uint32_t blocks;
    libmpq__off_t block_size;
    libmpq__off_t transferred;

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(
        strcmp(hash, "722f1acc2acd306abaed0466ffbbfd568e09f5e7da8d63eba86f19c1c2adde73") == 0
    );
    free(data);
    TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &block_size) == 0);
    data = malloc((size_t)block_size);
    TEST_CHECK(data != NULL);
    TEST_CHECK(libmpq__block_read(archive, number, 0, data, block_size, &transferred) == 0);
    TEST_CHECK(transferred == block_size);
    free(data);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
