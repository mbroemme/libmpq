/*
 *  test-mpq-block.c -- MPQ block-table wire-format regression tests.
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

#include "../src/mpq-block.h"
#include "test-mpq-helper.h"

#include <libmpq/mpq.h>
#include <stdint.h>
#include <string.h>

/* Check base fields independently against explicit little-endian bytes. */
static int
test_base_vector(void)
{
    static const uint8_t expected[LIBMPQ_BLOCK_ENTRY_WIRE_SIZE] = {
        0x04, 0x03, 0x02, 0x01, 0x14, 0x13, 0x12, 0x11,
        0x24, 0x23, 0x22, 0x21, 0xd4, 0xc3, 0xb2, 0xa1,
    };
    const mpq_block_s source = { 0x01020304u, 0x11121314u, 0x21222324u, 0xa1b2c3d4u };
    mpq_block_s decoded = { 0 };
    uint8_t wire[sizeof(expected)];

    TEST_CHECK(libmpq__block_table_encode(&source, 1, wire, sizeof(wire)) == 0);
    TEST_CHECK(memcmp(wire, expected, sizeof(expected)) == 0);
    TEST_CHECK(libmpq__block_table_decode(expected, sizeof(expected), &decoded, 1) == 0);
    TEST_CHECK(decoded.offset == source.offset);
    TEST_CHECK(decoded.packed_size == source.packed_size);
    TEST_CHECK(decoded.unpacked_size == source.unpacked_size);
    TEST_CHECK(decoded.flags == source.flags);
    return 0;
}

/* Retain entry order and representative zero and maximum field values. */
static int
test_multiple_base_entries(void)
{
    const mpq_block_s source[3] = {
        { 0, 0, 0, 0 },
        { UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX },
        { 0x01020304u, 7u, 9u, 0x80000200u },
    };
    mpq_block_s decoded[3] = { { 0 } };
    uint8_t wire[3 * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE];
    size_t i;

    TEST_CHECK(libmpq__block_table_encode(source, 3, wire, sizeof(wire)) == 0);
    TEST_CHECK(libmpq__block_table_decode(wire, sizeof(wire), decoded, 3) == 0);
    for (i = 0; i < 3; i++) {
        TEST_CHECK(decoded[i].offset == source[i].offset);
        TEST_CHECK(decoded[i].packed_size == source[i].packed_size);
        TEST_CHECK(decoded[i].unpacked_size == source[i].unpacked_size);
        TEST_CHECK(decoded[i].flags == source[i].flags);
    }
    return 0;
}

/* v2 high-offset words have their own exact two-byte wire layout. */
static int
test_extended_vector(void)
{
    static const uint8_t expected[3 * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE] = {
        0x34, 0x12, 0x00, 0x00, 0xff, 0xff,
    };
    const mpq_block_ex_s source[3] = { { 0x1234u }, { 0 }, { UINT16_MAX } };
    mpq_block_ex_s decoded[3] = { { 0 } };
    uint8_t wire[sizeof(expected)];

    TEST_CHECK(libmpq__block_ex_table_encode(source, 3, wire, sizeof(wire)) == 0);
    TEST_CHECK(memcmp(wire, expected, sizeof(expected)) == 0);
    TEST_CHECK(libmpq__block_ex_table_decode(expected, sizeof(expected), decoded, 3) == 0);
    TEST_CHECK(decoded[0].offset_high == source[0].offset_high);
    TEST_CHECK(decoded[1].offset_high == source[1].offset_high);
    TEST_CHECK(decoded[2].offset_high == source[2].offset_high);
    return 0;
}

/* Reject truncated, undersized, and overflowing table requests before access. */
static int
test_invalid_buffers(void)
{
    mpq_block_s base = { 0 };
    mpq_block_ex_s extension = { 0 };
    uint8_t wire[LIBMPQ_BLOCK_ENTRY_WIRE_SIZE];
    size_t base_overflow = SIZE_MAX / LIBMPQ_BLOCK_ENTRY_WIRE_SIZE + 1u;
    size_t ex_overflow = SIZE_MAX / LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE + 1u;
    size_t i;

    memset(wire, 0xa5, sizeof(wire));
    TEST_CHECK(libmpq__block_table_decode(wire, sizeof(wire) - 1u, &base, 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__block_ex_table_decode(wire, LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE - 1u, &extension, 1) ==
        LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(libmpq__block_table_encode(&base, 1, wire, sizeof(wire) - 1u) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__block_ex_table_encode(&extension, 1, wire, LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE - 1u) ==
        LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__block_table_decode(wire, SIZE_MAX, &base, base_overflow) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__block_table_encode(&base, base_overflow, wire, SIZE_MAX) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__block_ex_table_decode(wire, SIZE_MAX, &extension, ex_overflow) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__block_ex_table_encode(&extension, ex_overflow, wire, SIZE_MAX) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(base.offset == 0 && base.flags == 0);
    TEST_CHECK(extension.offset_high == 0);
    for (i = 0; i < sizeof(wire); i++)
        TEST_CHECK(wire[i] == 0xa5);
    TEST_CHECK(libmpq__block_table_decode(NULL, 0, NULL, 0) == 0);
    TEST_CHECK(libmpq__block_table_encode(NULL, 0, NULL, 0) == 0);
    TEST_CHECK(libmpq__block_ex_table_decode(NULL, 0, NULL, 0) == 0);
    TEST_CHECK(libmpq__block_ex_table_encode(NULL, 0, NULL, 0) == 0);
    return 0;
}

int
main(void)
{
    if (test_base_vector() != 0 || test_multiple_base_entries() != 0 ||
        test_extended_vector() != 0 || test_invalid_buffers() != 0)
        return 1;
    return 0;
}
