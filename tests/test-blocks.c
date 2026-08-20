/* Exercise sector offset caches, block metadata, and block reads. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>

/* Exercise sector offset handles, block metadata, and block reads. */
int
main(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *block_data;
    uint32_t blocks;
    uint32_t number;
    libmpq__off_t block_size;
    libmpq__off_t transferred;

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 0);
    TEST_CHECK(libmpq__block_open_offset(archive, number) == 0);
    TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &block_size) == 0);
    block_data = malloc((size_t)block_size);
    TEST_CHECK(block_data != NULL);
    TEST_CHECK(libmpq__block_read(archive, number, 0, block_data, block_size, &transferred) == 0);
    TEST_CHECK(transferred == block_size);
    free(block_data);
    TEST_CHECK(libmpq__block_close_offset(archive, number) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
