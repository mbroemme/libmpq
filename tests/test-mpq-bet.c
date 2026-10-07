/*
 *  test-mpq-bet.c -- Synthetic MPQ BET header regression tests.
 *
 *  Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This file is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this file; if not, see <https://www.gnu.org/licenses/>.
 */

#include "../src/mpq-bet.h"
#include "../src/mpq-endian.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Explicit metadata uses 64-bit positions and unaligned 83-bit records. */
static const uint8_t valid_bet[118] = {
    'B', 'E', 'T', 0x1a, 1,  0, 0, 0, 106, 0, 0,  0, 106, 0, 0,  0, 2, 0, 0,  0, 0x10, 0,
    0,   0,   83,  0,    0,  0, 0, 0, 0,   0, 64, 0, 0,   0, 73, 0, 0, 0, 82, 0, 0,    0,
    83,  0,   0,   0,    64, 0, 0, 0, 9,   0, 0,  0, 9,   0, 0,  0, 1, 0, 0,  0, 0,    0,
    0,   0,   3,   0,    0,  0, 0, 0, 0,   0, 3,  0, 0,   0, 1,  0, 0, 0, 2,  0, 0,    0
};

/* Decode all fields, including reserved metadata, and identify the physical ranges. */
static int
test_valid(void)
{
    mpq_bet_header_s header;
    uint8_t wire[sizeof(valid_bet)];

    TEST_CHECK(libmpq__bet_header_decode(valid_bet, sizeof(valid_bet), &header) == 0);
    TEST_CHECK(header.table_size == 106 && header.entry_count == 2 && header.unknown == 0x10);
    TEST_CHECK(header.table_entry_size == 83 && header.file_position.bit_count == 64);
    TEST_CHECK(header.file_position.bit_index == 0 && header.file_size.bit_index == 64);
    TEST_CHECK(header.file_size.bit_count == 9 && header.compressed_size.bit_index == 73);
    TEST_CHECK(header.compressed_size.bit_count == 9 && header.flag_index.bit_index == 82);
    TEST_CHECK(
        header.flag_index.bit_count == 1 && header.unknown_field.bit_index == 83 &&
        header.unknown_field.bit_count == 0
    );
    TEST_CHECK(
        header.name_hash2_total == 3 && header.name_hash2_extra == 0 &&
        header.name_hash2_size == 3 && header.name_hash_array_size == 1
    );
    TEST_CHECK(header.flag_count == 2 && header.flags.offset == 88 && header.flags.size == 8);
    TEST_CHECK(header.records.offset == 96 && header.records.size == 21);
    TEST_CHECK(header.name_hash2.offset == 117 && header.name_hash2.size == 1);
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 24, 84);
    libmpq__store_le32(wire + 64, 1);
    libmpq__store_le32(wire + 72, 1);
    libmpq__store_le32(wire + 76, 2);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == 0);
    TEST_CHECK(header.unknown_field.bit_count == 1 && header.name_hash2_extra == 1);
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 8, 76);
    libmpq__store_le32(wire + 12, 76);
    libmpq__store_le32(wire + 16, 0);
    libmpq__store_le32(wire + 80, 0);
    libmpq__store_le32(wire + 84, 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, 88, &header) == 0);
    TEST_CHECK(header.flags.size == 0 && header.records.size == 0 && header.name_hash2.size == 0);
    return 0;
}

/* Reject truncated arrays, overlapping fields, impossible widths and huge counts. */
static int
test_invalid(void)
{
    static const struct
    {
        size_t offset;
        uint32_t value;
    } mutations[] = { { 0, LIBMPQ_HET_SIGNATURE },
                      { 4, 2 },
                      { 8, 75 },
                      { 8, UINT32_MAX },
                      { 12, 75 },
                      { 12, 107 },
                      { 24, 0 },
                      { 24, UINT32_MAX },
                      { 28, 84 },
                      { 28, UINT32_MAX },
                      { 32, 63 },
                      { 36, 83 },
                      { 44, 84 },
                      { 48, 65 },
                      { 52, 10 },
                      { 60, 2 },
                      { 64, 1 },
                      { 68, 65 },
                      { 72, 4 },
                      { 76, 4 },
                      { 76, 0 },
                      { 80, 0 },
                      { 80, UINT32_MAX },
                      { 84, 0 },
                      { 84, 3 },
                      { 84, UINT32_MAX },
                      { 16, UINT32_MAX } };
    uint8_t wire[sizeof(valid_bet)];
    mpq_bet_header_s header;
    size_t i;

    for (i = 0; i < sizeof(valid_bet); i++)
        TEST_CHECK(libmpq__bet_header_decode(valid_bet, i, &header) != 0);
    for (i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
        memcpy(wire, valid_bet, sizeof(wire));
        libmpq__store_le32(wire + mutations[i].offset, mutations[i].value);
        TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);
    }
    for (i = 0; i < 5; i++) {
        memcpy(wire, valid_bet, sizeof(wire));
        libmpq__store_le32(wire + 28 + i * 4, UINT32_MAX);
        TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);
        memcpy(wire, valid_bet, sizeof(wire));
        libmpq__store_le32(wire + 48 + i * 4, 65);
        TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);
    }

    /* Wide flag indices reach the array-size guard rather than the width guard. */
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 24, 114);
    libmpq__store_le32(wire + 44, 114);
    libmpq__store_le32(wire + 60, 32);
    libmpq__store_le32(wire + 84, UINT32_MAX);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);

    /* The product is wider than DWORD arithmetic even though neither factor is. */
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 16, UINT32_MAX);
    libmpq__store_le32(wire + 24, UINT32_MAX);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);

    /* Three three-bit hashes exceed the one-byte NameHash2 array by one bit. */
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 16, 3);
    libmpq__store_le32(wire + 8, 117);
    libmpq__store_le32(wire + 12, 117);
    {
        uint8_t expanded[129] = { 0 };

        memcpy(expanded, wire, sizeof(wire));
        TEST_CHECK(libmpq__bet_header_decode(expanded, sizeof(expanded), &header) != 0);
    }
    TEST_CHECK(libmpq__bet_header_decode(NULL, sizeof(valid_bet), &header) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_header_decode(valid_bet, sizeof(valid_bet), NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Reject surplus declared payload and hash padding despite complete buffers. */
static int
test_exact_sizes(void)
{
    uint8_t wire[sizeof(valid_bet) + 1] = { 0 };
    mpq_ext_table_header_s envelope;
    mpq_bet_header_s header;

    memcpy(wire, valid_bet, sizeof(valid_bet));
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == 0);

    /* The extra byte belongs to the envelope, but not to the declared BET table. */
    libmpq__store_le32(wire + 8, 107);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_BET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);

    /* Matching table sizes still cannot pad the one-byte packed NameHash2 array. */
    libmpq__store_le32(wire + 12, 107);
    libmpq__store_le32(wire + 80, 2);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_BET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

/* Run isolated synthetic BET structural tests. */
int
main(void)
{
    TEST_CHECK(test_valid() == 0);
    TEST_CHECK(test_invalid() == 0);
    TEST_CHECK(test_exact_sizes() == 0);
    return 0;
}
