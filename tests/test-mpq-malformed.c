/* Exercise a deterministic malformed-input corpus and its rejection contract. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
    const char *name;
    const uint8_t *data;
    size_t size;
    int32_t expected;
} malformed_case_s;

/* Use a compact v1 header as the common basis for table-boundary cases. */
static const uint8_t v1_header[] = {
    'M',  'P', 'Q', 0x1a, 0x20, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 3, 0,
    0x20, 0,   0,   0,    0x20, 0, 0, 0, 0,    0, 0, 0, 0, 0, 0, 0
};

/* Reject an invalid block-size shift before it can form an oversized sector. */
static const uint8_t invalid_block_size[] = { 'M', 'P', 'Q', 0x1a, 0x20, 0,    0, 0, 0x20, 0,    0,
                                              0,   0,   0,   23,   0,    0x20, 0, 0, 0,    0x20, 0,
                                              0,   0,   0,   0,    0,    0,    0, 0, 0,    0 };

/* Reject table counts that overflow the serialized allocation bounds. */
static const uint8_t oversized_hash_count[] = { 'M',  'P',  'Q',  0x1a, 0x20, 0, 0, 0,
                                                0x20, 0,    0,    0,    0,    0, 3, 0,
                                                0x20, 0,    0,    0,    0x20, 0, 0, 0,
                                                0xff, 0xff, 0xff, 0xff, 0,    0, 0, 0 };

/* Require a complete hash table when its offset lies exactly at end of file. */
static const uint8_t hash_table_at_eof[] = { 'M', 'P', 'Q', 0x1a, 0x20, 0,    0, 0, 0x20, 0,    0,
                                             0,   0,   0,   3,    0,    0x20, 0, 0, 0,    0x20, 0,
                                             0,   0,   1,   0,    0,    0,    0, 0, 0,    0 };

/* Require a complete block table when its offset lies exactly at end of file. */
static const uint8_t block_table_at_eof[] = { 'M', 'P', 'Q', 0x1a, 0x20, 0,    0, 0, 0x20, 0,    0,
                                              0,   0,   0,   3,    0,    0x20, 0, 0, 0,    0x20, 0,
                                              0,   0,   0,   0,    0,    0,    1, 0, 0,    0 };

/* Reject an archive whose v2 high-offset extension is truncated. */
static const uint8_t truncated_v2_extension[] = { 'M', 'P', 'Q', 0x1a, 0x2c, 0, 0, 0, 0x2c, 0, 0, 0,
                                                  1,   0,   3,   0,    0x2c, 0, 0, 0, 0x2c, 0, 0, 0,
                                                  0,   0,   0,   0,    0,    0, 0, 0 };

/* Preserve format classification for a truncated v2 extended block table. */
static const uint8_t truncated_v2_block_ex_table[] = {
    'M', 'P',  'Q', 0x1a, 0x2c, 0, 0, 0, 0x4c, 0, 0, 0, 1, 0,    3, 0, 0x2c, 0, 0,
    0,   0x3c, 0,   0,    0,    1, 0, 0, 0,    1, 0, 0, 0, 0x4c, 0, 0, 0,    0, 0,
    0,   0,    0,   0,    0,    0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0,    0, 0,
    0,   0,    0,   0,    0,    0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0,    0, 0
};

/* Reject table reads from a far offset even when the encoded count is small. */
static const uint8_t hash_table_far_offset[] = { 'M',  'P',  'Q',  0x1a, 0x20, 0, 0, 0,
                                                 0x20, 0,    0,    0,    0,    0, 3, 0,
                                                 0xf0, 0xff, 0xff, 0x7f, 0x20, 0, 0, 0,
                                                 1,    0,    0,    0,    0,    0, 0, 0 };

/* Keep the byte corpus and the externally visible rejection code together. */
static const malformed_case_s malformed_cases[] = {
    { "truncated-v1-header", v1_header, sizeof(v1_header) - 1U, LIBMPQ_ERROR_FORMAT },
    { "invalid-block-size", invalid_block_size, sizeof(invalid_block_size), LIBMPQ_ERROR_FORMAT },
    { "oversized-hash-count", oversized_hash_count, sizeof(oversized_hash_count),
      LIBMPQ_ERROR_FORMAT },
    { "hash-table-at-eof", hash_table_at_eof, sizeof(hash_table_at_eof), LIBMPQ_ERROR_READ },
    { "block-table-at-eof", block_table_at_eof, sizeof(block_table_at_eof), LIBMPQ_ERROR_READ },
    { "truncated-v2-extension", truncated_v2_extension, sizeof(truncated_v2_extension),
      LIBMPQ_ERROR_FORMAT },
    { "truncated-v2-block-ex-table", truncated_v2_block_ex_table,
      sizeof(truncated_v2_block_ex_table), LIBMPQ_ERROR_FORMAT },
    { "hash-table-far-offset", hash_table_far_offset, sizeof(hash_table_far_offset),
      LIBMPQ_ERROR_READ }
};

/* Write and open each malformed input independently to preserve its error contract. */
static int
test_malformed_corpus(void)
{
    char path[160];
    size_t i;

    for (i = 0; i < sizeof(malformed_cases) / sizeof(malformed_cases[0]); ++i) {
        const malformed_case_s *test_case = &malformed_cases[i];
        mpq_archive_s *archive = NULL;
        FILE *stream;

        TEST_CHECK(snprintf(path, sizeof(path), "libmpq-test-%s.mpq", test_case->name) > 0);
        stream = fopen(path, "wb");
        TEST_CHECK(stream != NULL);
        TEST_CHECK(fwrite(test_case->data, 1, test_case->size, stream) == test_case->size);
        TEST_CHECK(fclose(stream) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == test_case->expected);
        TEST_CHECK(archive == NULL);
        remove(path);
    }

    return 0;
}

/* Corrupt a generated sector table and require a format error before any
 * archive-controlled sector length can be used for allocation. */
static int
test_malformed_sector_offsets(void)
{
    char path[160];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint8_t payload[12000];
    uint8_t output[sizeof(payload)];
    uint8_t invalid_offset[] = { 0xff, 0xff, 0xff, 0x7f };
    libmpq__off_t file_offset;
    libmpq__off_t transferred;
    uint32_t number;
    FILE *stream;

    TEST_CHECK(test_temp_path(path, sizeof(path), "malformed-sector") == 0);
    memset(payload, 'S', sizeof(payload));
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "sector.bin", payload, sizeof(payload), &compressed) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "sector.bin", &number) == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &file_offset) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    stream = fopen(path, "r+b");
    TEST_CHECK(stream != NULL);
    TEST_CHECK(fseek(stream, (long)(file_offset + (libmpq__off_t)sizeof(uint32_t)), SEEK_SET) == 0);
    TEST_CHECK(fwrite(invalid_offset, 1, sizeof(invalid_offset), stream) == sizeof(invalid_offset));
    TEST_CHECK(fclose(stream) == 0);

    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "sector.bin", &number) == 0);
    TEST_CHECK(
        libmpq__file_read(archive, number, output, sizeof(output), &transferred) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}

/* Verify stable format and read failures for all deterministic malformed inputs. */
int
main(void)
{
    TEST_CHECK(test_malformed_corpus() == 0);
    TEST_CHECK(test_malformed_sector_offsets() == 0);
    return 0;
}
