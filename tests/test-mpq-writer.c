/* Exercise deterministic writer output and generated writer/readback properties. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    const char *name;
    mpq_file_options_s options;
} writer_mode_s;

/* Cover lossless raw, PKWARE, multi-codec, encryption, and compatible single units. */
static const writer_mode_s writer_modes[] = {
    { "raw", { 0, 0, 0, 0, 0 } },
    { "raw-encrypted", { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "raw-single", { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 } },
    { "raw-single-encrypted",
      { LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "implode", { LIBMPQ_FILE_FLAG_IMPLODE, 0, 0, 0, 0 } },
    { "implode-encrypted", { LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "huffman",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_HUFFMAN, LIBMPQ_COMPRESSION_HUFFMAN, 0, 0 } },
    { "zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "pkware",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_PKZIP, LIBMPQ_COMPRESSION_PKZIP, 0, 0 } },
    { "bzip2",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_BZIP2, LIBMPQ_COMPRESSION_BZIP2, 0, 0 } },
    { "multi",
      { LIBMPQ_FILE_FLAG_COMPRESS,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        0, 0 } },
    { "mixed-sectors",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_BZIP2, 0, 0 } },
    { "zlib-encrypted",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "multi-encrypted",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        0, 0 } },
    { "zlib-single",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } }
};

/* Make payloads deterministic and compressible while retaining changing bytes. */
static void
fill_property_payload(uint8_t *data, size_t size)
{
    size_t i;

    for (i = 0; i < size; ++i) {
        data[i] = (uint8_t)((i / 97U + i % 5U) & 0xffU);
    }
    if (size >= 8U) {
        data[0] = 'R';
        data[1] = 'I';
        data[2] = 'F';
        data[3] = 'F';
        data[4] = (uint8_t)((size - 8U) & 0xffU);
        data[5] = (uint8_t)(((size - 8U) >> 8) & 0xffU);
        data[6] = (uint8_t)(((size - 8U) >> 16) & 0xffU);
        data[7] = (uint8_t)(((size - 8U) >> 24) & 0xffU);
    }
}

/* Select combinations the MPQ writer can represent for this payload shape. */
static int
property_mode_supported(const writer_mode_s *mode, uint32_t sector_size, size_t payload_size)
{
    if (payload_size == 0 &&
        (mode->options.flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE |
                                LIBMPQ_FILE_FLAG_ENCRYPTED)) != 0) {
        return 0;
    }
    if (payload_size < 8U && (mode->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0)
        return 0;
    if (payload_size > sector_size && (mode->options.flags & LIBMPQ_FILE_FLAG_SINGLE) != 0)
        return 0;
    return 1;
}

/* Verify one generated archive can reopen and reproduce every selected mode. */
static int
test_property_case(uint32_t version, uint32_t sector_size, size_t payload_size)
{
    char path[160] = { 0 };
    uint8_t *payload = NULL;
    uint8_t *output = NULL;
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s archive_options = { version, 32, sector_size, 0 };
    libmpq__off_t transferred;
    int32_t result;
    uint32_t number;
    size_t i;
    int status = 1;

    payload = malloc(payload_size == 0 ? 1U : payload_size);
    if (payload == NULL) {
        test_failure(__FILE__, __LINE__, "payload != NULL");
        goto cleanup;
    }
    output = malloc(payload_size == 0 ? 1U : payload_size);
    if (output == NULL) {
        test_failure(__FILE__, __LINE__, "output != NULL");
        goto cleanup;
    }
    fill_property_payload(payload, payload_size);
    if (test_temp_path(path, sizeof(path), "writer-property") != 0) {
        test_failure(
            __FILE__, __LINE__, "test_temp_path(path, sizeof(path), \"writer-property\") == 0"
        );
        goto cleanup;
    }
    if (libmpq__archive_create(&archive, path, &archive_options) != 0) {
        test_failure(
            __FILE__, __LINE__, "libmpq__archive_create(&archive, path, &archive_options) == 0"
        );
        goto cleanup;
    }
    for (i = 0; i < sizeof(writer_modes) / sizeof(writer_modes[0]); ++i) {
        int32_t add_result;

        if (!property_mode_supported(&writer_modes[i], sector_size, payload_size)) {
            continue;
        }
        add_result = libmpq__file_add(
            archive, writer_modes[i].name, payload, (libmpq__off_t)payload_size,
            &writer_modes[i].options
        );
        if (add_result != 0) {
            fprintf(
                stderr, "writer property add failed: v%u sector %u size %zu mode %s: %d\n", version,
                sector_size, payload_size, writer_modes[i].name, add_result
            );
        }
        if (add_result != 0) {
            test_failure(__FILE__, __LINE__, "add_result == 0");
            goto cleanup;
        }
    }
    if (libmpq__archive_close(archive) != 0) {
        test_failure(__FILE__, __LINE__, "libmpq__archive_close(archive) == 0");
        goto cleanup;
    }
    archive = NULL;
    if (libmpq__archive_open(&archive, path, 0) != 0) {
        test_failure(__FILE__, __LINE__, "libmpq__archive_open(&archive, path, 0) == 0");
        goto cleanup;
    }
    for (i = 0; i < sizeof(writer_modes) / sizeof(writer_modes[0]); ++i) {
        if (!property_mode_supported(&writer_modes[i], sector_size, payload_size)) {
            continue;
        }
        if (libmpq__file_number(archive, writer_modes[i].name, &number) != 0) {
            test_failure(
                __FILE__, __LINE__,
                "libmpq__file_number(archive, writer_modes[i].name, &number) == 0"
            );
            goto cleanup;
        }
        result =
            libmpq__file_read(archive, number, output, (libmpq__off_t)payload_size, &transferred);
        if (result != 0) {
            fprintf(
                stderr, "writer property failed: v%u sector %u size %zu mode %s: %d\n", version,
                sector_size, payload_size, writer_modes[i].name, result
            );
        }
        if (result != 0) {
            test_failure(__FILE__, __LINE__, "result == 0");
            goto cleanup;
        }
        if (transferred != (libmpq__off_t)payload_size) {
            test_failure(__FILE__, __LINE__, "transferred == (libmpq__off_t)payload_size");
            goto cleanup;
        }
        if (memcmp(output, payload, payload_size) != 0) {
            size_t mismatch = 0;

            while (mismatch < payload_size && output[mismatch] == payload[mismatch])
                mismatch++;
            fprintf(
                stderr,
                "writer property mismatch: v%u sector %u size %zu mode %s at %zu (%u != %u)\n",
                version, sector_size, payload_size, writer_modes[i].name, mismatch,
                output[mismatch], payload[mismatch]
            );
        }
        if (memcmp(output, payload, payload_size) != 0) {
            test_failure(__FILE__, __LINE__, "memcmp(output, payload, payload_size) == 0");
            goto cleanup;
        }
    }
    if (libmpq__archive_close(archive) != 0) {
        test_failure(__FILE__, __LINE__, "libmpq__archive_close(archive) == 0");
        goto cleanup;
    }
    archive = NULL;
    status = 0;

cleanup:
    if (archive != NULL)
        libmpq__archive_close(archive);
    free(output);
    free(payload);
    if (path[0] != '\0')
        remove(path);
    return status;
}

/* Cover archive versions, valid sector sizes, and every sector-boundary shape. */
static int
test_writer_properties(void)
{
    static const uint32_t versions[] = { LIBMPQ_ARCHIVE_VERSION_ONE, LIBMPQ_ARCHIVE_VERSION_TWO };
    static const uint32_t sector_sizes[] = { 512, 4096, 16384 };
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i) {
        for (j = 0; j < sizeof(sector_sizes) / sizeof(sector_sizes[0]); ++j) {
            size_t sector_size = sector_sizes[j];
            size_t lengths[] = { 0,
                                 1,
                                 sector_size - 1U,
                                 sector_size,
                                 sector_size + 1U,
                                 sector_size * 2U - 1U,
                                 sector_size * 2U,
                                 sector_size * 2U + 1U };
            size_t k;

            for (k = 0; k < sizeof(lengths) / sizeof(lengths[0]); ++k) {
                TEST_CHECK(test_property_case(versions[i], sector_sizes[j], lengths[k]) == 0);
            }
        }
    }

    return 0;
}

/* Retain convenience-path and streamed-writer coverage in deterministic archives. */
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

/* Retain the byte-for-byte determinism check for repeated v1 output. */
static int
test_writer_determinism(void)
{
    char first_path[160];
    char second_path[160];
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

/* Verify deterministic v1 output, v2 creation, and the generated round-trip matrix. */
int
main(void)
{
    TEST_CHECK(test_writer_determinism() == 0);
    TEST_CHECK(test_writer_properties() == 0);
    return 0;
}
