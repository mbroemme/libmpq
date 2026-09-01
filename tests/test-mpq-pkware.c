/* Exercise extraction of PKWARE and implode fixture payloads. */
#include "mpq-compression.h"
#include "mpq-pkware.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Read both PKWARE-backed fixture entries to exercise the decoder path. */
int
main(void)
{
    char path[512];
    const char *names[] = { "pkware.txt", "implode.txt" };
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    size_t size;
    uint32_t number;
    size_t i;

    TEST_CHECK(test_window_flush() == 0);
    TEST_CHECK(test_literal_stream() == 0);
    TEST_CHECK(test_short_runs() == 0);
    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
        TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0 && size > 0);
        free(data);
        data = NULL;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
