/* Exercise the complete public archive, file, lookup, and block API. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verify every documented error code has a stable diagnostic. */
static int
test_error_strings(void)
{
    int32_t code;

    TEST_CHECK(libmpq__strerror(0) != NULL);
    for (code = LIBMPQ_ERROR_OPEN; code >= LIBMPQ_ERROR_UNPACK; --code)
        TEST_CHECK(libmpq__strerror(code) != NULL);
    TEST_CHECK(libmpq__strerror(1) == NULL);
    TEST_CHECK(libmpq__strerror(LIBMPQ_ERROR_UNPACK - 1) == NULL);
    return 0;
}

/* Exercise creation validation before creating any filesystem state. */
static int
test_create_errors(void)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0 };
    char path[128];

    TEST_CHECK(test_temp_path(path, sizeof(path), "invalid") == 0);
    TEST_CHECK(libmpq__archive_create(NULL, path, &options) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_create(&archive, NULL, &options) == LIBMPQ_ERROR_EXIST);
    options.version = LIBMPQ_ARCHIVE_VERSION_TWO + 1;
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == LIBMPQ_ERROR_FORMAT);
    options.version = LIBMPQ_ARCHIVE_VERSION_ONE;
    options.sector_size = 1000;
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == LIBMPQ_ERROR_FORMAT);
    options.sector_size = 4096;
    options.max_files = UINT32_MAX;
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_create(&archive, path, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    remove(path);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__archive_open(&archive, "libmpq-test-no-such-file.mpq", 0) == LIBMPQ_ERROR_EXIST
    );
    return 0;
}

/* Reject malformed header fields before they can overflow shifts or allocations. */
static int
test_malformed_headers(void)
{
    char path[128];
    uint8_t header[32] = { 'M',  'P', 'Q', 0x1A, 0x20, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 3, 0,
                           0x20, 0,   0,   0,    0x20, 0, 0, 0, 0,    0, 0, 0, 0, 0, 0, 0 };
    FILE *stream;
    mpq_archive_s *archive = NULL;

    TEST_CHECK(test_temp_path(path, sizeof(path), "malformed-header") == 0);
    stream = fopen(path, "wb");
    TEST_CHECK(stream != NULL);
    TEST_CHECK(fwrite(header, 1, sizeof(header), stream) == sizeof(header));
    TEST_CHECK(fclose(stream) == 0);

    header[14] = 23;
    stream = fopen(path, "wb");
    TEST_CHECK(stream != NULL);
    TEST_CHECK(fwrite(header, 1, sizeof(header), stream) == sizeof(header));
    TEST_CHECK(fclose(stream) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(archive == NULL);

    header[14] = 3;
    memset(header + 24, 0xFF, sizeof(uint32_t));
    stream = fopen(path, "wb");
    TEST_CHECK(stream != NULL);
    TEST_CHECK(fwrite(header, 1, sizeof(header), stream) == sizeof(header));
    TEST_CHECK(fclose(stream) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(archive == NULL);
    remove(path);

    return 0;
}

/* Exercise writer argument validation while an archive is still writable. */
static int
test_writer_errors(mpq_archive_s *archive)
{
    const uint8_t bytes[] = "writer";
    mpq_writer_s *writer = NULL;
    mpq_file_options_s invalid = { LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_COMPRESS, 0, 0, 0,
                                   0 };

    TEST_CHECK(libmpq__file_begin(NULL, "null", 0, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__file_begin(archive, NULL, 0, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__file_begin(archive, "negative", -1, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__file_begin(archive, "invalid-flags", 0, &invalid, &writer) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__file_begin(archive, "null-output", 0, NULL, NULL) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__file_write(NULL, bytes, sizeof(bytes) - 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_write(NULL, NULL, 0) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_finish(NULL) == LIBMPQ_ERROR_EXIST);

    TEST_CHECK(libmpq__file_begin(archive, "active", 2, NULL, &writer) == 0);
    TEST_CHECK(libmpq__file_begin(archive, "second", 0, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__file_write(writer, bytes, 3) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_write(writer, NULL, 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_write(writer, bytes, 2) == 0);
    TEST_CHECK(libmpq__file_finish(writer) == 0);

    TEST_CHECK(libmpq__file_begin(archive, "incomplete", 4, NULL, &writer) == 0);
    TEST_CHECK(libmpq__file_write(writer, bytes, 2) == 0);
    TEST_CHECK(libmpq__file_finish(writer) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_begin(archive, "oversized", 2, NULL, &writer) == 0);
    TEST_CHECK(libmpq__file_write(writer, bytes, 3) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__file_finish(writer) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Exercise metadata, lookups, streaming, convenience writers, and blocks. */
int
main(void)
{
    char archive_path[128];
    char source_path[128];
    const uint8_t payload[] = "public API";
    const uint8_t streamed[] = "streamed";
    const uint8_t source[] = "file_add_path";
    uint8_t *repetitive;
    uint8_t output[sizeof(payload)];
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_writer_s *writer = NULL;
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    libmpq__off_t packed;
    libmpq__off_t unpacked;
    libmpq__off_t offset;
    libmpq__off_t transferred;
    uint32_t number;
    uint32_t files;
    uint32_t blocks;
    uint32_t flag;
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    FILE *source_file;
    size_t i;

    TEST_CHECK(libmpq__version() != NULL && *libmpq__version() != '\0');
    TEST_CHECK(test_error_strings() == 0);
    TEST_CHECK(test_create_errors() == 0);
    TEST_CHECK(test_malformed_headers() == 0);
    TEST_CHECK(libmpq__archive_clone(NULL, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(test_temp_path(archive_path, sizeof(archive_path), "api") == 0);
    TEST_CHECK(test_temp_path(source_path, sizeof(source_path), "source") == 0);
    source_file = fopen(source_path, "wb");
    TEST_CHECK(source_file != NULL);
    TEST_CHECK(fwrite(source, 1, sizeof(source) - 1, source_file) == sizeof(source) - 1);
    TEST_CHECK(fclose(source_file) == 0);

    TEST_CHECK(test_add_archive(&archive, archive_path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(test_writer_errors(archive) == 0);
    TEST_CHECK(libmpq__file_add(archive, "payload", payload, sizeof(payload) - 1, NULL) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "payload", payload, sizeof(payload) - 1, NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    repetitive = malloc(5000);
    TEST_CHECK(repetitive != NULL);
    for (i = 0; i < 5000; ++i)
        repetitive[i] = (uint8_t)('A' + (i % 3));
    TEST_CHECK(libmpq__file_add(archive, "compressed", repetitive, 5000, &compressed) == 0);
    free(repetitive);
    TEST_CHECK(libmpq__file_add(archive, "empty", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__file_add_path(archive, "path", source_path, NULL) == 0);
    TEST_CHECK(
        libmpq__file_add_path(archive, "missing", "libmpq-no-such-source", NULL) ==
        LIBMPQ_ERROR_OPEN
    );
    TEST_CHECK(libmpq__file_begin(archive, "streamed", sizeof(streamed) - 1, NULL, &writer) == 0);
    TEST_CHECK(libmpq__file_write(writer, streamed, 3) == 0);
    TEST_CHECK(libmpq__file_write(writer, streamed + 3, sizeof(streamed) - 4) == 0);
    TEST_CHECK(libmpq__file_finish(writer) == 0);
    TEST_CHECK(libmpq__file_add(archive, "negative", NULL, -1, NULL) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    TEST_CHECK(libmpq__archive_open(&archive, archive_path, -2) == LIBMPQ_ERROR_SEEK);
    TEST_CHECK(libmpq__archive_open(&archive, archive_path, 0) == 0);
    TEST_CHECK(libmpq__archive_version(archive, &flag) == 0 && flag == 1);
    TEST_CHECK(libmpq__archive_offset(archive, &offset) == 0 && offset == 0);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 6);
    unpacked = 0;
    TEST_CHECK(libmpq__archive_size_unpacked(archive, &unpacked) == 0 && unpacked > 0);
    packed = 0;
    TEST_CHECK(libmpq__archive_size_packed(archive, &packed) == 0 && packed > 0);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0 && unpacked == 10);
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0 && packed == unpacked);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 1);
    TEST_CHECK(libmpq__file_encrypted(archive, number, &flag) == 0 && flag == 0);
    TEST_CHECK(libmpq__file_compressed(archive, number, &flag) == 0 && flag == 0);
    TEST_CHECK(libmpq__file_imploded(archive, number, &flag) == 0 && flag == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0 && offset > 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(payload) - 1 && memcmp(output, payload, transferred) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__file_read(archive, files, output, sizeof(output), NULL) == LIBMPQ_ERROR_EXIST
    );

    TEST_CHECK(libmpq__file_number(archive, "missing", &number) == LIBMPQ_ERROR_EXIST);
    libmpq__file_hash("missing", &hash1, &hash2, &hash3);
    TEST_CHECK(
        libmpq__file_number_from_hash(archive, hash1, hash2, hash3, &number) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__file_size_packed(archive, files, &packed) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_size_unpacked(archive, files, &unpacked) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_offset(archive, files, &offset) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_blocks(archive, files, &blocks) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_encrypted(archive, files, &flag) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_compressed(archive, files, &flag) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_imploded(archive, files, &flag) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "compressed", &number) == 0);
    TEST_CHECK(libmpq__file_compressed(archive, number, &flag) == 0 && flag != 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 2);
    TEST_CHECK(libmpq__block_close_offset(archive, number) == LIBMPQ_ERROR_OPEN);
    TEST_CHECK(libmpq__block_open_offset(archive, number) == 0);
    TEST_CHECK(libmpq__block_open_offset(archive, number) == 0);
    TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &unpacked) == 0 && unpacked == 4096);
    TEST_CHECK(
        libmpq__block_size_unpacked(archive, number, blocks, &unpacked) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__block_read(archive, number, 0, output, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__block_read(archive, number, blocks, output, sizeof(output), NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__block_close_offset(archive, number) == 0);
    TEST_CHECK(libmpq__block_close_offset(archive, number) == 0);
    TEST_CHECK(libmpq__block_open_offset(archive, files) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__block_size_unpacked(archive, files, 0, &unpacked) == LIBMPQ_ERROR_EXIST);

    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__file_number(clone, "payload", &number) == 0);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    clone = NULL;
    remove(source_path);
    remove(archive_path);
    return 0;
}
