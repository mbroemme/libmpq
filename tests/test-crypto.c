/* Exercise encrypted raw payloads and encrypted-file key recovery. */
#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verify one encrypted file round trip using a recognizable file signature. */
static int
test_encrypted_file(const char *path)
{
    uint8_t payload[20000];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    uint8_t *output = NULL;
    size_t output_size;
    uint32_t number;

    memset(payload, 'E', sizeof(payload));
    memcpy(payload, "RIFF", 4);
    payload[4] = (uint8_t)((sizeof(payload) - 8) & 0xffu);
    payload[5] = (uint8_t)((sizeof(payload) - 8) >> 8);
    payload[6] = (uint8_t)((sizeof(payload) - 8) >> 16);
    payload[7] = (uint8_t)((sizeof(payload) - 8) >> 24);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "encrypted.raw", payload, sizeof(payload), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "encrypted.raw", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Exercise encrypted payload creation and extraction. */
int
main(void)
{
    char path[128];
    TEST_CHECK(test_temp_path(path, sizeof(path), "crypto") == 0);
    TEST_CHECK(test_encrypted_file(path) == 0);
    remove(path);
    return 0;
}
