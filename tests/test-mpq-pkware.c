/* Exercise extraction of PKWARE and implode fixture payloads. */
#include "mpq-compression.h"
#include "mpq-internal.h"
#include "mpq-pkware.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bzlib.h>
#include <zlib.h>

/* STANDARD restores raw data if only one stage of an ADPCM pair survives. */
static int
test_partial_chains(void)
{
    static const size_t sizes[] = { 2047, 12 };
    uint8_t input[2047];
    uint8_t *packed = NULL;
    uint8_t emitted;
    size_t packed_size;
    size_t size;
    size_t i;
    size_t j;
    uint32_t mask;
    uint32_t state = 1;
    int matches;

    /* Odd input skips ADPCM; short PCM skips Huffman after lossy encoding. */
    for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); ++j) {
        size = sizes[j];
        memset(input, 'C', sizeof(input));
        if (size == 12) {
            for (i = 0; i < size; ++i) {
                state = state * 1664525U + 1013904223U;
                input[i] = (uint8_t)(state >> 24);
            }
        }
        for (mask = 0x41; mask <= 0x81; mask += 0x40) {
            TEST_CHECK(
                libmpq__compression_encode_sector(
                    input, size, mask, LIBMPQ_ARCHIVE_VERSION_TWO,
                    LIBMPQ_COMPRESSION_POLICY_EXTENDED, &packed, &packed_size, &emitted
                ) == 0
            );
            matches = emitted == (size == 12 ? mask & ~1U : 1U);
            free(packed);
            TEST_CHECK(matches);
            TEST_CHECK(
                libmpq__compression_encode_sector(
                    input, size, mask, LIBMPQ_ARCHIVE_VERSION_TWO,
                    LIBMPQ_COMPRESSION_POLICY_STANDARD, &packed, &packed_size, &emitted
                ) == 0
            );
            matches = emitted == 0 && packed_size == size && memcmp(packed, input, size) == 0;
            free(packed);
            TEST_CHECK(matches);
        }
    }
    return 0;
}

/* Round-trip one bounded payload and optionally require useful compression. */
static int
test_round_trip(const uint8_t *input, uint32_t size, int compressible)
{
    uint8_t *output = malloc(size ? size : 1u);
    uint8_t *packed = NULL;
    uint32_t packed_size = 0;
    int32_t result;

    TEST_CHECK(output != NULL);
    result = libmpq__pkzip_compress(input, size, &packed, &packed_size);
    if (result != 0) {
        free(output);
        TEST_CHECK(result == 0);
    }
    result = libmpq__compression_decompress_pkzip(packed, packed_size, output, size);
    free(packed);
    if (result != (int32_t)size || memcmp(input, output, size) != 0) {
        free(output);
        TEST_CHECK(0);
    }
    free(output);
    if (compressible)
        TEST_CHECK(packed_size < size / 2u);
    return 0;
}

/* The encoder's four-byte empty stream must decode successfully to zero bytes. */
static int
test_empty_stream(void)
{
    uint8_t input = 0;
    uint8_t output = 0xa5;
    uint8_t *packed = NULL;
    uint32_t packed_size = 0;
    int32_t result;

    TEST_CHECK(libmpq__pkzip_compress(&input, 0, &packed, &packed_size) == 0);
    result = libmpq__compression_decompress_pkzip(packed, packed_size, &output, 1);
    free(packed);
    TEST_CHECK(packed_size == 4);
    TEST_CHECK(result == 0);
    TEST_CHECK(output == 0xa5);
    return 0;
}

/* Repeated prose must compress without adding artificial single-byte runs. */
static int
test_general_matches(void)
{
    static const char text[] = "This text uses PKWARE compression as a masked COMPRESS stage.\n";
    uint8_t input[16384];
    size_t i;

    for (i = 0; i < sizeof(input); ++i)
        input[i] = (uint8_t)text[i % (sizeof(text) - 1u)];
    TEST_CHECK(test_round_trip(input, sizeof(input), 1) == 0);

    /* Two- and three-byte overlapping patterns span many maximum-length matches. */
    for (i = 0; i < sizeof(input); ++i)
        input[i] = (uint8_t)('a' + i % 2u);
    TEST_CHECK(test_round_trip(input, sizeof(input), 1) == 0);
    for (i = 0; i < sizeof(input); ++i)
        input[i] = (uint8_t)('a' + i % 3u);
    TEST_CHECK(test_round_trip(input, sizeof(input), 1) == 0);
    return 0;
}

/* Exercise distance suffix transitions, dictionary wrap, and short final matches. */
static int
test_match_boundaries(void)
{
    static const uint32_t distances[] = { 1,   2,    3,    63,   64,   65,   255, 256,
                                          257, 1023, 1024, 2048, 4095, 4096, 4097 };
    static const uint32_t lengths[] = { 0,  1,  2,   3,   8,   10,  14,  22,
                                        38, 70, 134, 262, 515, 516, 517, 1033 };
    uint8_t input[8192];
    size_t i;
    size_t j;
    uint32_t k;

    for (i = 0; i < sizeof(distances) / sizeof(distances[0]); ++i) {
        for (j = 0; j < sizeof(lengths) / sizeof(lengths[0]); ++j) {
            test_payload(input, distances[i], 71);
            for (k = 0; k < lengths[j]; ++k)
                input[distances[i] + k] = input[k];
            TEST_CHECK(test_round_trip(input, distances[i] + lengths[j], 0) == 0);
        }
    }
    TEST_CHECK(test_round_trip(input, 0, 0) == 0);
    return 0;
}

/* Keep the MPQ v1 serialized 0x12 interpretation as bzip2 followed by zlib. */
static int
test_v1_legacy_0x12(void)
{
    uint8_t input[2048];
    uint8_t output[sizeof(input)];
    uint8_t zlib_data[4096];
    uint8_t bzip2_data[8192];
    uint8_t packed[8193];
    unsigned long zlib_size = sizeof(zlib_data);
    unsigned int bzip2_size = sizeof(bzip2_data);
    int32_t unpacked;

    memset(input, 'A', sizeof(input));
    TEST_CHECK(compress2(zlib_data, &zlib_size, input, sizeof(input), Z_BEST_COMPRESSION) == Z_OK);
    TEST_CHECK(
        BZ2_bzBuffToBuffCompress(
            (char *)bzip2_data, &bzip2_size, (char *)zlib_data, (unsigned int)zlib_size, 9, 0, 30
        ) == BZ_OK
    );
    packed[0] = LIBMPQ_COMPRESSION_BZIP2 | LIBMPQ_COMPRESSION_ZLIB;
    memcpy(packed + 1, bzip2_data, bzip2_size);
    unpacked = libmpq__compression_decompress_multi(
        packed, bzip2_size + 1U, output, sizeof(output), LIBMPQ_ARCHIVE_VERSION_ONE
    );
    TEST_CHECK(unpacked == (int32_t)sizeof(output));
    TEST_CHECK(memcmp(output, input, sizeof(input)) == 0);
    return 0;
}

/* Decode enough repeated data to flush and preserve the overlapping history window. */
static int
test_window_flush(void)
{
    uint8_t input[0x3000];
    uint8_t output[sizeof(input)];
    uint8_t *packed = NULL;
    uint32_t packed_size = 0;
    int32_t unpacked;

    memset(input, 'A', sizeof(input));
    TEST_CHECK(libmpq__pkzip_compress(input, sizeof(input), &packed, &packed_size) == 0);
    unpacked = libmpq__compression_decompress_pkzip(packed, packed_size, output, sizeof(output));
    free(packed);
    TEST_CHECK(unpacked == (int32_t)sizeof(output));
    TEST_CHECK(memcmp(output, input, sizeof(input)) == 0);
    return 0;
}

/* Decode mixed literals and runs so the encoder cannot rely on repeated input. */
static int
test_literal_stream(void)
{
    uint8_t input[513];
    uint8_t output[sizeof(input)];
    uint8_t *packed = NULL;
    uint32_t packed_size = 0;
    int32_t unpacked;

    test_payload(input, sizeof(input), 19);
    TEST_CHECK(libmpq__pkzip_compress(input, sizeof(input), &packed, &packed_size) == 0);
    unpacked = libmpq__compression_decompress_pkzip(packed, packed_size, output, sizeof(output));
    free(packed);
    TEST_CHECK(unpacked == (int32_t)sizeof(output));
    TEST_CHECK(memcmp(output, input, sizeof(input)) == 0);
    return 0;
}

/* Preserve a mixed short-run stream found by the writer round-trip fuzzer. */
static int
test_short_runs(void)
{
    static const uint8_t input[] = { 0x26, 0x01, 0x63, 0x62, 0x70, 0x6e, 0x2e, 0xf7, 0xf7,
                                     0xf7, 0xf7, 0xf7, 0xf7, 0x79, 0x70, 0x74, 0x0b, 0x0b,
                                     0x0b, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t output[sizeof(input)];
    uint8_t *packed = NULL;
    uint32_t packed_size = 0;
    int32_t unpacked;

    TEST_CHECK(libmpq__pkzip_compress(input, sizeof(input), &packed, &packed_size) == 0);
    unpacked = libmpq__compression_decompress_pkzip(packed, packed_size, output, sizeof(output));
    free(packed);
    TEST_CHECK(unpacked == (int32_t)sizeof(output));
    TEST_CHECK(memcmp(output, input, sizeof(input)) == 0);
    return 0;
}

/* Decoder status errors must not be mistaken for zero or partial output. */
static int
test_invalid_streams(void)
{
    uint8_t input[512];
    uint8_t output[sizeof(input) + 1];
    uint8_t masked[sizeof(input) * 2];
    uint8_t *packed = NULL;
    uint32_t packed_size = 0;
    uint8_t mode;
    uint8_t dictionary;
    uint32_t size;
    int32_t result;

    memset(input, 'P', sizeof(input));
    TEST_CHECK(libmpq__pkzip_compress(input, sizeof(input), &packed, &packed_size) == 0);
    TEST_CHECK(packed_size > 5 && packed_size + 1 < sizeof(masked));
    mode = packed[0];
    dictionary = packed[1];
    packed[0] = 2;
    result = libmpq__compression_decompress_pkzip(packed, packed_size, output, sizeof(output));
    TEST_CHECK(result == LIBMPQ_ERROR_UNPACK);
    packed[0] = mode;
    packed[1] = 3;
    result = libmpq__compression_decompress_pkzip(packed, packed_size, output, sizeof(output));
    TEST_CHECK(result == LIBMPQ_ERROR_UNPACK);
    packed[1] = dictionary;
    for (size = 0; size <= 4; ++size)
        TEST_CHECK(
            libmpq__compression_decompress_pkzip(packed, size, output, sizeof(output)) ==
            LIBMPQ_ERROR_UNPACK
        );
    TEST_CHECK(
        libmpq__compression_decompress_pkzip(packed, packed_size - 2, output, sizeof(output)) ==
        LIBMPQ_ERROR_UNPACK
    );

    /* Capacity is not an exact size at an intermediate codec stage. */
    TEST_CHECK(
        libmpq__compression_decompress_pkzip(packed, packed_size, output, sizeof(output)) ==
        (int32_t)sizeof(input)
    );
    TEST_CHECK(memcmp(input, output, sizeof(input)) == 0);
    TEST_CHECK(
        libmpq__compression_decompress_block(
            packed, packed_size, output, sizeof(input), LIBMPQ_FLAG_COMPRESS_PKZIP,
            LIBMPQ_ARCHIVE_VERSION_ONE
        ) == (int32_t)sizeof(input)
    );

    /* Complete blocks cannot accept an early end marker as a short success. */
    TEST_CHECK(
        libmpq__compression_decompress_block(
            packed, packed_size, output, sizeof(output), LIBMPQ_FLAG_COMPRESS_PKZIP,
            LIBMPQ_ARCHIVE_VERSION_ONE
        ) == LIBMPQ_ERROR_UNPACK
    );
    masked[0] = LIBMPQ_COMPRESSION_PKZIP;
    memcpy(masked + 1, packed, packed_size);
    free(packed);
    TEST_CHECK(
        libmpq__compression_decompress_block(
            masked, packed_size + 1, output, sizeof(output), LIBMPQ_FLAG_COMPRESS_MULTI,
            LIBMPQ_ARCHIVE_VERSION_ONE
        ) == LIBMPQ_ERROR_UNPACK
    );
    return 0;
}

/* Read both PKWARE-backed fixture entries to exercise the decoder path. */
int
main(void)
{
    char path[512];
    const char *names[] = { "pkware.txt", "implode.txt" };
    const char *lines[] = {
        "This text uses PKWARE compression as a masked COMPRESS stage.\n",
        "This text uses standalone PKWARE implode compression.\n",
    };
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    uint8_t block_data[4096];
    libmpq__off_t transferred;
    libmpq__off_t block_size;
    size_t size;
    uint32_t number;
    uint32_t blocks;
    uint32_t block;
    uint32_t compression;
    size_t i;
    size_t j;
    size_t line_size;

    TEST_CHECK(test_window_flush() == 0);
    TEST_CHECK(test_empty_stream() == 0);
    TEST_CHECK(test_invalid_streams() == 0);
    TEST_CHECK(test_partial_chains() == 0);
    TEST_CHECK(test_general_matches() == 0);
    TEST_CHECK(test_match_boundaries() == 0);
    TEST_CHECK(test_literal_stream() == 0);
    TEST_CHECK(test_short_runs() == 0);
    TEST_CHECK(test_v1_legacy_0x12() == 0);
    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
        TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 0);
        for (block = 0; block < blocks; ++block) {
            TEST_CHECK(libmpq__block_compression(archive, number, block, &compression) == 0);
            TEST_CHECK(compression == LIBMPQ_COMPRESSION_PKZIP);
        }
        TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
        line_size = strlen(lines[i]);
        TEST_CHECK(size == 32 * line_size);
        for (j = 0; j < 32; ++j)
            TEST_CHECK(memcmp(data + j * line_size, lines[i], line_size) == 0);

        /* A larger caller buffer does not change the expected decoded block size. */
        TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &block_size) == 0);
        TEST_CHECK(block_size > 0 && (uint64_t)block_size < sizeof(block_data));
        TEST_CHECK(
            libmpq__block_read(archive, number, 0, block_data, sizeof(block_data), &transferred) ==
            0
        );
        TEST_CHECK(transferred == block_size);
        TEST_CHECK(memcmp(data, block_data, (size_t)block_size) == 0);
        free(data);
        data = NULL;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
