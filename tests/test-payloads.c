/* Exercise empty, boundary, binary, XML, WAVE-shaped, and nested payloads. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
    char path[128];
    char inner_path[128];
    char extracted_path[128];
    uint8_t exact[4096];
    uint8_t partial[4097];
    uint8_t wave[44 + 16];
    uint8_t *inner;
    uint8_t *output;
    size_t inner_size;
    size_t output_size;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *inner_archive = NULL;
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };
    uint32_t number;
    TEST_CHECK(test_temp_path(path, sizeof(path), "payload") == 0);
    TEST_CHECK(test_temp_path(inner_path, sizeof(inner_path), "inner") == 0);
    TEST_CHECK(test_temp_path(extracted_path, sizeof(extracted_path), "extracted") == 0);
    test_payload(exact, sizeof(exact), 7);
    test_payload(partial, sizeof(partial), 8);
    memset(wave, 0, sizeof(wave));
    memcpy(wave, "RIFF", 4);
    memcpy(wave + 8, "WAVEfmt ", 8);
    wave[16] = 16;
    wave[20] = 1;
    wave[22] = 1;
    wave[24] = 0x44;
    wave[25] = 0xac;
    wave[32] = 2;
    wave[34] = 16;
    memcpy(wave + 36, "data", 4);
    wave[40] = 16;
    TEST_CHECK(test_add_archive(&inner_archive, inner_path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(inner_archive, "inner.txt", (const uint8_t *)"nested", 6, &raw) == 0
    );
    TEST_CHECK(libmpq__archive_close(inner_archive) == 0);
    TEST_CHECK(test_read_path(inner_path, &inner, &inner_size) == 0);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "empty", NULL, 0, &raw) == 0);
    TEST_CHECK(libmpq__file_add(archive, "exact", exact, sizeof(exact), &raw) == 0);
    TEST_CHECK(libmpq__file_add(archive, "partial", partial, sizeof(partial), &raw) == 0);
    TEST_CHECK(
        libmpq__file_add(
            archive, "xml", (const uint8_t *)"<?xml version=\"1.0\"?><x/>",
            strlen("<?xml version=\"1.0\"?><x/>"), &raw
        ) == 0
    );
    TEST_CHECK(libmpq__file_add(archive, "wave", wave, sizeof(wave), &raw) == 0);
    TEST_CHECK(libmpq__file_add(archive, "nested.mpq", inner, inner_size, &raw) == 0);
    free(inner);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "empty", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0 && output_size == 0);
    free(output);
    TEST_CHECK(libmpq__file_number(archive, "wave", &number) == 0);
    TEST_CHECK(
        test_archive_read(archive, number, &output, &output_size) == 0 &&
        memcmp(output, "RIFF", 4) == 0
    );
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "nested.mpq", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == inner_size);
    {
        FILE *stream = fopen(extracted_path, "wb");
        TEST_CHECK(stream != NULL && fwrite(output, 1, output_size, stream) == output_size);
        TEST_CHECK(fclose(stream) == 0);
    }
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, extracted_path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "inner.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == 6 && memcmp(output, "nested", 6) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    remove(inner_path);
    remove(extracted_path);
    return 0;
}
