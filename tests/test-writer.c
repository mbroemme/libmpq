/* Exercise archive creation, streaming writes, path insertion, and determinism. */
#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create one deterministic archive containing convenience and streamed files. */
static int
test_create_one(const char *path, uint32_t version)
{
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint8_t repetitive[12000];
    uint8_t stream_data[5000];
    char source_path[160];
    FILE *source;

    TEST_CHECK(test_add_archive(&archive, path, version, LIBMPQ_ARCHIVE_CREATE_LISTFILE) == 0);
    memset(repetitive, 'R', sizeof(repetitive));
    test_payload(stream_data, sizeof(stream_data), 42);
    TEST_CHECK(snprintf(source_path, sizeof(source_path), "%s.input", path) > 0);
    source = fopen(source_path, "wb");
    TEST_CHECK(source != NULL && fwrite("path-data", 1, 9, source) == 9);
    TEST_CHECK(fclose(source) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "repeat.bin", repetitive, sizeof(repetitive), &compressed) == 0
    );
    TEST_CHECK(libmpq__file_add_path(archive, "path.bin", source_path, &raw) == 0);
    TEST_CHECK(libmpq__file_begin(archive, "stream.bin", sizeof(stream_data), &raw, &writer) == 0);
    TEST_CHECK(libmpq__file_write(writer, stream_data, 1234) == 0);
    TEST_CHECK(libmpq__file_write(writer, stream_data + 1234, sizeof(stream_data) - 1234) == 0);
    TEST_CHECK(libmpq__file_finish(writer) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(source_path);
    return 0;
}

/* Verify writer output is deterministic for repeated v1 creation and valid for v2. */
int
main(void)
{
    char first_path[128];
    char second_path[128];
    uint8_t *first;
    uint8_t *second;
    size_t first_size;
    size_t second_size;

    TEST_CHECK(test_temp_path(first_path, sizeof(first_path), "writer-a") == 0);
    TEST_CHECK(test_temp_path(second_path, sizeof(second_path), "writer-b") == 0);
    TEST_CHECK(test_create_one(first_path, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_create_one(second_path, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_read_path(first_path, &first, &first_size) == 0);
    TEST_CHECK(test_read_path(second_path, &second, &second_size) == 0);
    TEST_CHECK(first_size == second_size && memcmp(first, second, first_size) == 0);
    free(first);
    free(second);
    remove(first_path);
    remove(second_path);
    TEST_CHECK(test_temp_path(first_path, sizeof(first_path), "writer-v2") == 0);
    TEST_CHECK(test_create_one(first_path, LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    remove(first_path);
    return 0;
}
