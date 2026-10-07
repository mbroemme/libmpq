/*
 *  test-mpq-het.c -- Synthetic MPQ HET header regression tests.
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

#include "../src/mpq-endian.h"
#include "../src/mpq-het.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Hand-specified header bytes describe three one-byte hashes and nine index bits. */
static const uint8_t valid_het[] = { 'H', 'E', 'T', 0x1a, 1, 0,    0,    0, 37,   0, 0, 0,  37,
                                     0,   0,   0,   2,    0, 0,    0,    3, 0,    0, 0, 64, 0,
                                     0,   0,   3,   0,    0, 0,    0,    0, 0,    0, 3, 0,  0,
                                     0,   2,   0,   0,    0, 0x80, 0x81, 0, 0x08, 0 };

/* Header decoding identifies ranges without reading or interpreting their slots. */
static int
test_valid(void)
{
    uint8_t wire[sizeof(valid_het)];
    mpq_het_header_s header;

    TEST_CHECK(libmpq__het_header_decode(valid_het, sizeof(valid_het), &header) == 0);
    TEST_CHECK(header.table_size == 37 && header.entry_count == 2 && header.total_count == 3);
    TEST_CHECK(header.name_hash_bit_size == 64 && header.index_size == 3);
    TEST_CHECK(header.index_size_total == 3 && header.index_size_extra == 0);
    TEST_CHECK(header.index_table_size == 2 && header.name_hash1.offset == 44);
    TEST_CHECK(
        header.name_hash1.size == 3 && header.indices.offset == 47 && header.indices.size == 2
    );
    memcpy(wire, valid_het, sizeof(wire));
    libmpq__store_le32(wire + 32, 1);
    libmpq__store_le32(wire + 36, 2);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == 0);
    TEST_CHECK(header.index_size_extra == 1 && header.index_size == 2);
    memcpy(wire, valid_het, sizeof(wire));
    libmpq__store_le32(wire + 8, 32);
    libmpq__store_le32(wire + 12, 32);
    libmpq__store_le32(wire + 16, 0);
    libmpq__store_le32(wire + 20, 0);
    libmpq__store_le32(wire + 28, 0);
    libmpq__store_le32(wire + 36, 0);
    libmpq__store_le32(wire + 40, 0);
    TEST_CHECK(libmpq__het_header_decode(wire, 44, &header) == 0);
    TEST_CHECK(header.indices.size == 0 && header.name_hash1.size == 0);
    return 0;
}

/* Mutations exercise truncated headers, invalid relationships, and oversized arrays. */
static int
test_invalid(void)
{
    static const struct
    {
        size_t offset;
        uint32_t value;
    } mutations[] = { { 0, LIBMPQ_BET_SIGNATURE },
                      { 4, 2 },
                      { 8, UINT32_MAX },
                      { 8, 31 },
                      { 12, 31 },
                      { 12, 38 },
                      { 16, 4 },
                      { 24, 0 },
                      { 24, 7 },
                      { 24, 65 },
                      { 28, 2 },
                      { 32, 4 },
                      { 36, 4 },
                      { 36, 0 },
                      { 40, 1 },
                      { 40, UINT32_MAX },
                      { 20, UINT32_MAX },
                      { 28, UINT32_MAX } };
    uint8_t wire[sizeof(valid_het)];
    mpq_het_header_s header;
    size_t i;

    for (i = 0; i < sizeof(valid_het); i++)
        TEST_CHECK(libmpq__het_header_decode(valid_het, i, &header) != 0);
    for (i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
        memcpy(wire, valid_het, sizeof(wire));
        libmpq__store_le32(wire + mutations[i].offset, mutations[i].value);
        TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) != 0);
    }

    /* Three three-bit slots require nine bits, not the declared eight. */
    memcpy(wire, valid_het, sizeof(wire));
    libmpq__store_le32(wire + 8, 36);
    libmpq__store_le32(wire + 12, 36);
    libmpq__store_le32(wire + 40, 1);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire) - 1, &header) != 0);
    TEST_CHECK(libmpq__het_header_decode(NULL, sizeof(valid_het), &header) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__het_header_decode(valid_het, sizeof(valid_het), NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Reject surplus declared payload and index padding despite complete buffers. */
static int
test_exact_sizes(void)
{
    uint8_t wire[sizeof(valid_het) + 1] = { 0 };
    mpq_ext_table_header_s envelope;
    mpq_het_header_s header;

    memcpy(wire, valid_het, sizeof(valid_het));
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == 0);

    /* The extra byte belongs to the envelope, but not to the declared HET table. */
    libmpq__store_le32(wire + 8, 38);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_HET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);

    /* Matching table sizes still cannot pad the two-byte packed index array. */
    libmpq__store_le32(wire + 12, 38);
    libmpq__store_le32(wire + 40, 3);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_HET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

/* Run isolated synthetic HET structural tests. */
int
main(void)
{
    TEST_CHECK(test_valid() == 0);
    TEST_CHECK(test_invalid() == 0);
    TEST_CHECK(test_exact_sizes() == 0);
    return 0;
}
