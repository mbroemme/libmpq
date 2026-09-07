/* Exercise MPQ v2+ LZMA creation, readback, and version validation. */
#include "mpq-compression.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fixed StormLib-style MPQ framing with a raw LZMA1 stream without an EOPM. */
static const uint8_t stormlib_no_eopm_packed[] = {
    0x12U, 0,     0x5dU, 0,     0,     0x10U, 0,     52,    0,     0,     0,     0,     0,
    0,     0,     0x00U, 0x29U, 0x9dU, 0x09U, 0xe7U, 0x55U, 0xdfU, 0xddU, 0xfeU, 0x18U, 0x33U,
    0x86U, 0x62U, 0xdfU, 0xb4U, 0x74U, 0x6eU, 0x30U, 0x8fU, 0x58U, 0x21U, 0x49U, 0xdcU, 0xbdU,
    0xbfU, 0xbcU, 0x8bU, 0x90U, 0x76U, 0x90U, 0x5dU, 0x65U, 0x1bU, 0x1aU, 0x4cU, 0x05U, 0x86U,
    0x41U, 0x48U, 0x32U, 0x5fU, 0x92U, 0x14U, 0x77U, 0x8aU, 0x3dU, 0xf8U, 0xa2U, 0x63U, 0x34U,
    0xcbU, 0x7dU, 0xe1U, 0x6bU, 0x37U, 0x26U, 0xbfU, 0xffU, 0xdeU, 0x9cU, 0x60U
};
static const uint8_t stormlib_no_eopm_expected[] =
    "StormLib-compatible no-EOPM LZMA regression vector.\n";

/* Locate the serialized LZMA method, framing prefix, and advisory size. */
static size_t
find_lzma_method(const uint8_t *data, size_t size, uint64_t expected_size)
{
    size_t i;

    for (i = 0; i + 15 <= size; ++i) {
        uint64_t size_field = 0;
        size_t j;

        for (j = 0; j < 8; ++j)
            size_field |= (uint64_t)data[i + 7 + j] << (j * 8U);
        if (data[i] == 0x12U && data[i + 1] == 0 && data[i + 2] == 0x5dU &&
            size_field == expected_size) {
            return i;
        }
    }
    return size;
}

/* Verify the LZMA member in the shared MPQ v2 feature fixture. */
static int
test_feature_fixture(void)
{
    char path[256];
    mpq_archive_s *archive = NULL;
    static const char line[] = "This text uses the exclusive MPQ LZMA compression method.\n";
    uint8_t *stored = NULL;
    uint8_t *output = NULL;
    size_t stored_size;
    size_t output_size;
    size_t i;
    uint32_t number;

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v2-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(test_read_path(path, &stored, &stored_size) == 0);
    TEST_CHECK(find_lzma_method(stored, stored_size, (sizeof(line) - 1U) * 32U) != stored_size);
    free(stored);
    stored = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_version(archive, &number) == 0 && number == 2);
    TEST_CHECK(libmpq__file_number(archive, "lzma.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == (sizeof(line) - 1U) * 32U);
    for (i = 0; i < 32U; ++i)
        TEST_CHECK(memcmp(output + i * (sizeof(line) - 1U), line, sizeof(line) - 1U) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Create a v2 LZMA member, confirm its serialized method, and read it back. */
static int
test_v2_lzma_round_trip(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_LZMA,
                                   LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    uint8_t payload[20000];
    uint8_t *stored = NULL;
    uint8_t *output = NULL;
    size_t stored_size;
    size_t output_size;
    uint32_t number;

    memset(payload, 'L', sizeof(payload));
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_TWO, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "lzma.txt", payload, sizeof(payload), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(test_read_path(path, &stored, &stored_size) == 0);
    TEST_CHECK(find_lzma_method(stored, stored_size, 4096) != stored_size);
    free(stored);
    stored = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "lzma.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Tiny sectors cannot recover the fixed 15-byte MPQ LZMA framing overhead. */
static int
test_lzma_raw_fallback(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_LZMA,
                                   LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    uint8_t payload[15] = { 0 };
    uint8_t *stored = NULL;
    size_t stored_size;

    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_TWO, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "tiny.txt", payload, sizeof(payload), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(test_read_path(path, &stored, &stored_size) == 0);
    TEST_CHECK(find_lzma_method(stored, stored_size, sizeof(payload)) == stored_size);
    free(stored);
    return 0;
}

/* Exercise malformed framing and confirm that the embedded size is advisory. */
static int
test_lzma_framing_validation(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_LZMA,
                                   LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    uint8_t payload[4096];
    uint8_t *stored = NULL;
    uint8_t *output = NULL;
    size_t stored_size;
    size_t output_size;
    size_t offset;
    libmpq__off_t transferred = 0;
    uint32_t number;
    FILE *file;

    memset(payload, 'F', sizeof(payload));
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_TWO, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "framing.txt", payload, sizeof(payload), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(test_read_path(path, &stored, &stored_size) == 0);
    offset = find_lzma_method(stored, stored_size, sizeof(payload));
    TEST_CHECK(offset != stored_size);

    memset(stored + offset + 7, 0, 8);
    file = fopen(path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(stored, 1, stored_size, file) == stored_size);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "framing.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    free(output);
    output = NULL;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    stored[offset + 1] = 1;
    file = fopen(path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(stored, 1, stored_size, file) == stored_size);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "framing.txt", &number) == 0);
    TEST_CHECK(
        libmpq__file_read(archive, number, payload, sizeof(payload), &transferred) ==
        LIBMPQ_ERROR_UNPACK
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(stored);
    return 0;
}

/* Verify a fixed StormLib-style no-EOPM LZMA1 vector. */
static int
test_stormlib_no_eopm(void)
{
    uint8_t output[sizeof(stormlib_no_eopm_expected) - 1U];

    TEST_CHECK(
        libmpq__compression_decompress_multi(
            (uint8_t *)stormlib_no_eopm_packed, sizeof(stormlib_no_eopm_packed), output,
            sizeof(output), LIBMPQ_ARCHIVE_VERSION_TWO
        ) == (int32_t)sizeof(output)
    );
    TEST_CHECK(memcmp(output, stormlib_no_eopm_expected, sizeof(output)) == 0);
    return 0;
}

/* MPQ v1 retains 0x12 as a legacy bzip2-plus-zlib chain, never LZMA. */
static int
test_v1_lzma_rejected(void)
{
    uint8_t output[sizeof(stormlib_no_eopm_expected) - 1U];

    TEST_CHECK(
        libmpq__compression_decompress_multi(
            (uint8_t *)stormlib_no_eopm_packed, sizeof(stormlib_no_eopm_packed), output,
            sizeof(output), LIBMPQ_ARCHIVE_VERSION_ONE
        ) == LIBMPQ_ERROR_UNPACK
    );
    return 0;
}

/* Reject truncated headers, invalid properties, and truncated raw LZMA data. */
static int
test_malformed_lzma(void)
{
    uint8_t output[64];
    uint8_t truncated_header[] = { 0x12U, 0 };
    uint8_t header_only[] = { 0x12U, 0, 0x5dU, 0, 0, 0x10U, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t invalid_properties[] = { 0x12U, 0, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0,
                                     0,     0, 0,     0,     0,     0,     0 };
    uint8_t oversized_decoder[] = { 0x12U, 0, 0x5dU, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0xffU };
    uint8_t truncated_stream[] = { 0x12U, 0, 0x5dU, 0, 0, 0x10U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xffU };

    TEST_CHECK(
        libmpq__compression_decompress_multi(
            truncated_header, sizeof(truncated_header), output, sizeof(output),
            LIBMPQ_ARCHIVE_VERSION_TWO
        ) == LIBMPQ_ERROR_UNPACK
    );
    TEST_CHECK(
        libmpq__compression_decompress_multi(
            header_only, sizeof(header_only), output, sizeof(output), LIBMPQ_ARCHIVE_VERSION_TWO
        ) == LIBMPQ_ERROR_UNPACK
    );
    TEST_CHECK(
        libmpq__compression_decompress_multi(
            invalid_properties, sizeof(invalid_properties), output, sizeof(output),
            LIBMPQ_ARCHIVE_VERSION_TWO
        ) == LIBMPQ_ERROR_UNPACK
    );
    TEST_CHECK(
        libmpq__compression_decompress_multi(
            oversized_decoder, sizeof(oversized_decoder), output, sizeof(output),
            LIBMPQ_ARCHIVE_VERSION_TWO
        ) == LIBMPQ_ERROR_UNPACK
    );
    TEST_CHECK(
        libmpq__compression_decompress_multi(
            truncated_stream, sizeof(truncated_stream), output, sizeof(output),
            LIBMPQ_ARCHIVE_VERSION_TWO
        ) == LIBMPQ_ERROR_UNPACK
    );
    return 0;
}

/* Reject selector combinations that would serialize an ambiguous v2 method byte. */
static int
test_selector_validation(const char *path)
{
    mpq_archive_s *archive = NULL;
    uint8_t payload[128] = { 0 };
    mpq_file_options_s lzma = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_LZMA,
                                LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    mpq_file_options_s ambiguous = {
        LIBMPQ_FILE_FLAG_COMPRESS,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_BZIP2,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_BZIP2, 0, 0
    };

    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "v1-lzma", payload, sizeof(payload), &lzma) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_TWO, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "ambiguous", payload, sizeof(payload), &ambiguous) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

int
main(void)
{
    char path[128];

    TEST_CHECK(test_temp_path(path, sizeof(path), "lzma") == 0);
    TEST_CHECK(test_feature_fixture() == 0);
    TEST_CHECK(test_v2_lzma_round_trip(path) == 0);
    remove(path);
    TEST_CHECK(test_lzma_raw_fallback(path) == 0);
    remove(path);
    TEST_CHECK(test_lzma_framing_validation(path) == 0);
    remove(path);
    TEST_CHECK(test_stormlib_no_eopm() == 0);
    TEST_CHECK(test_v1_lzma_rejected() == 0);
    TEST_CHECK(test_malformed_lzma() == 0);
    TEST_CHECK(test_selector_validation(path) == 0);
    remove(path);
    return 0;
}
