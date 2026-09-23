/* Exercise the complete public archive, file, lookup, and block API. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    const uint8_t *data;
    size_t size;
    unsigned reads;
    int32_t failure;
    uint8_t out_of_range;
} memory_source_s;

static memory_source_s null_source;

static int32_t
memory_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    memory_source_s *source = context;

    if (source == NULL || offset < 0 || (uint64_t)offset > source->size ||
        size > source->size - (size_t)offset) {
        if (source != NULL)
            source->out_of_range = 1;
        return LIBMPQ_ERROR_READ;
    }
    ++source->reads;
    if (source->failure != 0)
        return source->failure;
    memcpy(buffer, source->data + (size_t)offset, size);
    return 0;
}

static int32_t
null_context_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    (void)context;
    return memory_read_at(&null_source, offset, buffer, size);
}

static int
test_custom_io(const char *path)
{
    uint8_t prefix[512] = { 'n', 'o', 't', '-', 'h', 'm', '3', 'w' };
    memory_source_s source = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_file_stream_s *stream = NULL;
    mpq_file_stream_s *second_stream = NULL;
    uint8_t *embedded = NULL;
    uint8_t *raw = NULL;
    uint8_t output[16];
    libmpq__off_t transferred = 0;
    libmpq__off_t file_size = 0;
    uint32_t files;
    uint32_t number;
    uint32_t version;

    TEST_CHECK(test_read_path(path, &raw, &source.size) == 0);
    source.data = raw;
    TEST_CHECK(source.size <= INT64_MAX);
    TEST_CHECK(
        libmpq__archive_open_io(NULL, &source, memory_read_at, source.size, 0, NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, NULL, source.size, 0, NULL) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(archive == NULL);
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, -1, 0, NULL) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(archive == NULL);
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, source.size, -2, NULL) ==
        LIBMPQ_ERROR_SEEK
    );
    TEST_CHECK(archive == NULL);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, memory_read_at, (libmpq__off_t)source.size,
            (libmpq__off_t)source.size + 1, NULL
        ) == LIBMPQ_ERROR_SEEK
    );
    TEST_CHECK(archive == NULL);

    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, source.size, 0, NULL) == 0
    );
    TEST_CHECK(source.reads != 0);
    TEST_CHECK(libmpq__archive_version(archive, &version) == 0 && version == 1);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 6);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &file_size) == 0 && file_size == 10);
    TEST_CHECK(libmpq__file_read(archive, number, output, 10, &transferred) == 0);
    TEST_CHECK(transferred == 10 && memcmp(output, "public API", 10) == 0);
    TEST_CHECK(libmpq__block_read(archive, number, 0, output, 10, &transferred) == 0);
    TEST_CHECK(transferred == 10 && memcmp(output, "public API", 10) == 0);
    TEST_CHECK(libmpq__file_stream_open(archive, number, &stream) == 0);
    TEST_CHECK(libmpq__file_stream_open_name(archive, "payload", &second_stream) == 0);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(source.out_of_range == 0);
    TEST_CHECK(libmpq__file_stream_read(stream, output, 3, &transferred) == 0);
    TEST_CHECK(transferred == 3 && memcmp(output, "pub", 3) == 0);
    TEST_CHECK(libmpq__file_stream_seek(stream, -1, LIBMPQ_SEEK_CUR) == 0);
    TEST_CHECK(libmpq__file_stream_tell(stream, &transferred) == 0 && transferred == 2);
    TEST_CHECK(libmpq__file_stream_read(stream, output, 16, &transferred) == 0);
    TEST_CHECK(transferred == 8 && memcmp(output, "blic API", 8) == 0);
    TEST_CHECK(libmpq__file_stream_read(stream, output, 1, &transferred) == 0 && transferred == 0);
    TEST_CHECK(libmpq__file_stream_seek(stream, 1, LIBMPQ_SEEK_END) == LIBMPQ_ERROR_SEEK);
    TEST_CHECK(libmpq__file_stream_close(stream) == 0);
    stream = NULL;
    TEST_CHECK(libmpq__file_stream_read(second_stream, output, 1, &transferred) == 0);
    TEST_CHECK(transferred == 1 && output[0] == 'p');
    TEST_CHECK(libmpq__file_stream_close(second_stream) == 0);
    second_stream = NULL;
    TEST_CHECK(libmpq__file_number(clone, "payload", &number) == 0);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    clone = NULL;

    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, source.size, 0, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    clone = NULL;
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    embedded = malloc(sizeof(prefix) + source.size);
    TEST_CHECK(embedded != NULL);
    memcpy(embedded, prefix, sizeof(prefix));
    memcpy(embedded + sizeof(prefix), source.data, source.size);
    source.data = embedded;
    source.size += sizeof(prefix);
    source.reads = 0;
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, source.size, -1, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, memory_read_at, source.size, (libmpq__off_t)sizeof(prefix), NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    source.failure = LIBMPQ_ERROR_READ;
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, source.size, -1, NULL) ==
        LIBMPQ_ERROR_READ
    );
    TEST_CHECK(archive == NULL);
    source.failure = 1;
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, memory_read_at, source.size, -1, NULL) ==
        LIBMPQ_ERROR_READ
    );
    TEST_CHECK(archive == NULL);
    source.failure = 0;

    null_source = source;
    TEST_CHECK(
        libmpq__archive_open_io(&archive, NULL, null_context_read_at, source.size, -1, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(source.out_of_range == 0);
    free(embedded);
    free(raw);
    return 0;
}

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
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
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

    TEST_CHECK(libmpq__writer_begin(NULL, "null", 0, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__writer_begin(archive, NULL, 0, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__writer_begin(archive, "negative", -1, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__writer_begin(archive, "invalid-flags", 0, &invalid, &writer) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__writer_begin(archive, "null-output", 0, NULL, NULL) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__writer_write(NULL, bytes, sizeof(bytes) - 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__writer_write(NULL, NULL, 0) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__writer_finish(NULL) == LIBMPQ_ERROR_EXIST);

    TEST_CHECK(libmpq__writer_begin(archive, "active", 2, NULL, &writer) == 0);
    TEST_CHECK(libmpq__writer_begin(archive, "second", 0, NULL, &writer) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__writer_write(writer, bytes, 3) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__writer_write(writer, NULL, 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__writer_write(writer, bytes, 2) == 0);
    TEST_CHECK(libmpq__writer_finish(writer) == 0);

    TEST_CHECK(libmpq__writer_begin(archive, "incomplete", 4, NULL, &writer) == 0);
    TEST_CHECK(libmpq__writer_write(writer, bytes, 2) == 0);
    TEST_CHECK(libmpq__writer_finish(writer) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__writer_begin(archive, "oversized", 2, NULL, &writer) == 0);
    TEST_CHECK(libmpq__writer_write(writer, bytes, 3) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__writer_finish(writer) == LIBMPQ_ERROR_SIZE);
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
    const uint8_t source[] = "archive_add_path";
    uint8_t *repetitive;
    uint8_t output[sizeof(payload)];
    uint8_t stream_output[17];
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_file_stream_s *file_stream = NULL;
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
    TEST_CHECK(
        libmpq__archive_add_data(archive, "payload", payload, sizeof(payload) - 1, NULL) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, "payload", payload, sizeof(payload) - 1, NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    repetitive = malloc(5000);
    TEST_CHECK(repetitive != NULL);
    for (i = 0; i < 5000; ++i)
        repetitive[i] = (uint8_t)('A' + (i % 3));
    TEST_CHECK(libmpq__archive_add_data(archive, "compressed", repetitive, 5000, &compressed) == 0);
    free(repetitive);
    TEST_CHECK(libmpq__archive_add_data(archive, "empty", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_path(archive, "path", source_path, NULL) == 0);
    TEST_CHECK(
        libmpq__archive_add_path(archive, "missing", "libmpq-no-such-source", NULL) ==
        LIBMPQ_ERROR_OPEN
    );
    TEST_CHECK(libmpq__writer_begin(archive, "streamed", sizeof(streamed) - 1, NULL, &writer) == 0);
    TEST_CHECK(libmpq__writer_write(writer, streamed, 3) == 0);
    TEST_CHECK(libmpq__writer_write(writer, streamed + 3, sizeof(streamed) - 4) == 0);
    TEST_CHECK(libmpq__writer_finish(writer) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "negative", NULL, -1, NULL) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    TEST_CHECK(test_custom_io(archive_path) == 0);

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
    TEST_CHECK(libmpq__file_flags(archive, number, &flag) == 0);
    TEST_CHECK(flag == UINT32_C(0x80000000));
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0 && offset > 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(payload) - 1 && memcmp(output, payload, transferred) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__file_read(archive, files, output, sizeof(output), NULL) == LIBMPQ_ERROR_EXIST
    );

    TEST_CHECK(libmpq__file_number(archive, "missing", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_stream_open_name(archive, "empty", &file_stream) == 0);
    TEST_CHECK(libmpq__file_stream_size(file_stream, &unpacked) == 0 && unpacked == 0);
    TEST_CHECK(
        libmpq__file_stream_read(file_stream, NULL, 0, &transferred) == 0 && transferred == 0
    );
    TEST_CHECK(libmpq__file_stream_seek(file_stream, 0, LIBMPQ_SEEK_END) == 0);
    TEST_CHECK(libmpq__file_stream_close(file_stream) == 0);
    file_stream = NULL;
    libmpq__file_hash("missing", &hash1, &hash2, &hash3);
    TEST_CHECK(
        libmpq__file_number_from_hash(archive, hash1, hash2, hash3, &number) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__file_size_packed(archive, files, &packed) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_size_unpacked(archive, files, &unpacked) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_offset(archive, files, &offset) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_blocks(archive, files, &blocks) == LIBMPQ_ERROR_EXIST);
    flag = UINT32_MAX;
    TEST_CHECK(libmpq__file_flags(archive, files, &flag) == LIBMPQ_ERROR_EXIST && flag == 0);
    flag = UINT32_MAX;
    TEST_CHECK(libmpq__file_flags(NULL, number, &flag) == LIBMPQ_ERROR_EXIST && flag == 0);
    TEST_CHECK(libmpq__file_flags(archive, number, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "compressed", &number) == 0);
    TEST_CHECK(
        libmpq__file_flags(archive, number, &flag) == 0 && (flag & LIBMPQ_FILE_FLAG_COMPRESS) != 0
    );
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 2);
    TEST_CHECK(libmpq__file_stream_open_name(archive, "compressed", &file_stream) == 0);
    for (i = 0; i < 5000;) {
        libmpq__off_t requested = (libmpq__off_t)(5000 - i);

        if (requested > (libmpq__off_t)sizeof(stream_output))
            requested = (libmpq__off_t)sizeof(stream_output);
        TEST_CHECK(
            libmpq__file_stream_read(file_stream, stream_output, requested, &transferred) == 0
        );
        TEST_CHECK(transferred == requested);
        {
            size_t j;

            for (j = 0; j < (size_t)transferred; ++j)
                TEST_CHECK(stream_output[j] == (uint8_t)('A' + ((i + j) % 3)));
        }
        i += (size_t)transferred;
    }
    TEST_CHECK(libmpq__file_stream_read(file_stream, stream_output, 1, &transferred) == 0);
    TEST_CHECK(transferred == 0);
    TEST_CHECK(libmpq__file_stream_tell(file_stream, &offset) == 0 && offset == 5000);
    TEST_CHECK(libmpq__file_stream_seek(file_stream, 0, 3) == LIBMPQ_ERROR_SEEK);
    TEST_CHECK(libmpq__file_stream_tell(file_stream, &offset) == 0 && offset == 5000);
    TEST_CHECK(libmpq__file_stream_seek(file_stream, 1, LIBMPQ_SEEK_END) == LIBMPQ_ERROR_SEEK);
    TEST_CHECK(libmpq__file_stream_seek(file_stream, -1, LIBMPQ_SEEK_SET) == LIBMPQ_ERROR_SEEK);
    TEST_CHECK(libmpq__file_stream_tell(file_stream, &offset) == 0 && offset == 5000);
    TEST_CHECK(libmpq__file_stream_seek(file_stream, 4095, LIBMPQ_SEEK_SET) == 0);
    TEST_CHECK(libmpq__file_stream_read(file_stream, stream_output, 2, &transferred) == 0);
    TEST_CHECK(transferred == 2 && stream_output[0] == 'A' && stream_output[1] == 'B');
    TEST_CHECK(libmpq__file_stream_seek(file_stream, 1, LIBMPQ_SEEK_CUR) == 0);
    TEST_CHECK(libmpq__file_stream_tell(file_stream, &offset) == 0 && offset == 4098);
    TEST_CHECK(libmpq__file_stream_seek(file_stream, -1, LIBMPQ_SEEK_END) == 0);
    TEST_CHECK(libmpq__file_stream_tell(file_stream, &offset) == 0 && offset == 4999);
    TEST_CHECK(
        libmpq__file_stream_seek(file_stream, INT64_MAX, LIBMPQ_SEEK_CUR) == LIBMPQ_ERROR_SEEK
    );
    TEST_CHECK(libmpq__file_stream_tell(file_stream, &offset) == 0 && offset == 4999);
    TEST_CHECK(libmpq__file_stream_close(file_stream) == 0);
    file_stream = NULL;
    TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &unpacked) == 0 && unpacked == 4096);
    TEST_CHECK(
        libmpq__block_size_unpacked(archive, number, blocks, &unpacked) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__block_read(archive, number, 0, output, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__block_read(archive, number, blocks, output, sizeof(output), NULL) ==
        LIBMPQ_ERROR_EXIST
    );
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
