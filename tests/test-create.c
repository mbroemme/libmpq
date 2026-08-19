/* Exercise deterministic v1/v2 creation, streaming, lookup, and metadata. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
create_one(const char *path, uint32_t version)
{
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint8_t repetitive[12000];
    uint8_t stream_data[5000];
    uint8_t *stream_output;
    size_t stream_output_size;
    uint32_t number;
    uint32_t files;
    char source_path[160];
    FILE *source;
    libmpq__off_t size;
    libmpq__off_t packed;
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
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 4);
    TEST_CHECK(libmpq__file_number(archive, "repeat.bin", &number) == 0);
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, number, &size) == 0 && size == sizeof(repetitive)
    );
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0 && packed > 0);
    TEST_CHECK(libmpq__file_compressed(archive, number, &files) == 0 && files != 0);
    TEST_CHECK(libmpq__file_number(archive, "stream.bin", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &stream_output, &stream_output_size) == 0);
    TEST_CHECK(
        stream_output_size == sizeof(stream_data) &&
        memcmp(stream_output, stream_data, sizeof(stream_data)) == 0
    );
    free(stream_output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(source_path);
    return 0;
}

int
main(void)
{
    char a[128];
    char b[128];
    uint8_t *first;
    uint8_t *second;
    size_t first_size;
    size_t second_size;
    TEST_CHECK(test_temp_path(a, sizeof(a), "create-a") == 0);
    TEST_CHECK(test_temp_path(b, sizeof(b), "create-b") == 0);
    TEST_CHECK(create_one(a, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(create_one(b, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(
        test_read_path(a, &first, &first_size) == 0 && test_read_path(b, &second, &second_size) == 0
    );
    TEST_CHECK(first_size == second_size && memcmp(first, second, first_size) == 0);
    free(first);
    free(second);
    remove(a);
    remove(b);
    TEST_CHECK(test_temp_path(a, sizeof(a), "create-v2") == 0);
    TEST_CHECK(create_one(a, LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    remove(a);
    return 0;
}
