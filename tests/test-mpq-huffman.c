/* Exercise extraction of the checked-in adaptive-Huffman fixture payload. */
#include "test-mpq-helper.h"

#include "../src/mpq-huffman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Verify bit lookahead and refill never read beyond a truncated stream tail. */
static int
test_truncated_input(void)
{
    const uint8_t tail[] = { 0 };
    struct huffman_input_stream_s input = { tail, tail + sizeof(tail), 0, 6, 0 };
    struct huffman_input_stream_s truncated = { tail, tail, 0, 0, 0 };
    struct huffman_input_stream_s invalid_type = { tail, tail, 9, 32, 0 };
    struct huffman_tree_s tree;
    uint8_t output;

    TEST_CHECK(libmpq__huffman_peek_seven_bits(&input) == 0);
    TEST_CHECK(input.in_buf == input.in_end && input.bits == 14 && input.failed == 0);
    input.bits = 0;
    TEST_CHECK(libmpq__huffman_read_bit(&input) == 0 && input.failed != 0);

    libmpq__huffman_tree_init(&tree, LIBMPQ_HUFF_DECOMPRESS);
    TEST_CHECK(libmpq__huffman_decode(&tree, &truncated, &output, 1) == LIBMPQ_ERROR_UNPACK);
    libmpq__huffman_tree_init(&tree, LIBMPQ_HUFF_DECOMPRESS);
    TEST_CHECK(libmpq__huffman_decode(&tree, &invalid_type, &output, 1) == LIBMPQ_ERROR_UNPACK);
    return 0;
}

/* Resolve and hash the Huffman-compressed fixture entry. */
int
main(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    size_t size;
    char hash[65];
    uint32_t number;

    TEST_CHECK(test_truncated_input() == 0);
    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "huffman.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(
        strcmp(hash, "93c7bdaceb3a5aa3969520c20a63e64d577227f51d2bbb6ee075c43ff8fa5b8e") == 0
    );
    free(data);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
