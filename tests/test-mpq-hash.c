/*
 *  test-mpq-hash.c -- MPQ hash-table wire-format regression tests.
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

#include "../src/mpq-hash.h"
#include "test-mpq-helper.h"

#include <libmpq/mpq.h>
#include <stdint.h>
#include <string.h>

/* Check each field against independently specified little-endian wire bytes. */
static int
test_single_entry(void)
{
    static const uint8_t expected[LIBMPQ_HASH_ENTRY_WIRE_SIZE] = {
        0x04, 0x03, 0x02, 0x01, 0x14, 0x13, 0x12, 0x11,
        0x22, 0x21, 0x32, 0x31, 0x44, 0x43, 0x42, 0x41,
    };
    const mpq_hash_s source = { 0x01020304u, 0x11121314u, 0x2122u, 0x3132u, 0x41424344u };
    mpq_hash_s decoded = { 0 };
    uint8_t wire[sizeof(expected)];

    TEST_CHECK(libmpq__hash_table_encode(&source, 1, wire, sizeof(wire)) == 0);
    TEST_CHECK(memcmp(wire, expected, sizeof(expected)) == 0);
    TEST_CHECK(libmpq__hash_table_decode(expected, sizeof(expected), &decoded, 1) == 0);
    TEST_CHECK(decoded.hash_a == source.hash_a);
    TEST_CHECK(decoded.hash_b == source.hash_b);
    TEST_CHECK(decoded.locale == source.locale);
    TEST_CHECK(decoded.platform == source.platform);
    TEST_CHECK(decoded.block_table_index == source.block_table_index);
    return 0;
}

/* FREE and DELETED are serialized unchanged, including their block-index words. */
static int
test_slot_markers(void)
{
    static const uint8_t expected[2 * LIBMPQ_HASH_ENTRY_WIRE_SIZE] = {
        0xa4, 0xa3, 0xa2, 0xa1, 0xb4, 0xb3, 0xb2, 0xb1, 0xc2, 0xc1, 0xd2,
        0xd1, 0xff, 0xff, 0xff, 0xff, 0xe4, 0xe3, 0xe2, 0xe1, 0xf4, 0xf3,
        0xf2, 0xf1, 0x02, 0x01, 0x04, 0x03, 0xfe, 0xff, 0xff, 0xff,
    };
    const mpq_hash_s source[2] = {
        { 0xa1a2a3a4u, 0xb1b2b3b4u, 0xc1c2u, 0xd1d2u, LIBMPQ_HASH_FREE },
        { 0xe1e2e3e4u, 0xf1f2f3f4u, 0x0102u, 0x0304u, LIBMPQ_HASH_DELETED },
    };
    mpq_hash_s decoded[2] = { { 0 } };
    uint8_t wire[sizeof(expected)];

    TEST_CHECK(LIBMPQ_HASH_FREE == UINT32_MAX);
    TEST_CHECK(LIBMPQ_HASH_DELETED == UINT32_MAX - 1u);
    TEST_CHECK(libmpq__hash_table_encode(source, 2, wire, sizeof(wire)) == 0);
    TEST_CHECK(memcmp(wire, expected, sizeof(expected)) == 0);
    TEST_CHECK(libmpq__hash_table_decode(expected, sizeof(expected), decoded, 2) == 0);
    TEST_CHECK(decoded[0].block_table_index == LIBMPQ_HASH_FREE);
    TEST_CHECK(decoded[1].block_table_index == LIBMPQ_HASH_DELETED);
    TEST_CHECK(decoded[0].hash_a == source[0].hash_a);
    TEST_CHECK(decoded[0].hash_b == source[0].hash_b);
    TEST_CHECK(decoded[0].locale == source[0].locale);
    TEST_CHECK(decoded[0].platform == source[0].platform);
    TEST_CHECK(decoded[1].hash_a == source[1].hash_a);
    TEST_CHECK(decoded[1].hash_b == source[1].hash_b);
    TEST_CHECK(decoded[1].locale == source[1].locale);
    TEST_CHECK(decoded[1].platform == source[1].platform);
    return 0;
}

/* A table round trip retains ordering, locale, platform, and slot markers. */
static int
test_multiple_entries(void)
{
    const mpq_hash_s source[3] = {
        { 0x01020304u, 0x11121314u, 0x2122u, 0x3132u, 7u },
        { 0, 0, 0, 0, LIBMPQ_HASH_FREE },
        { 0, 0, 0, 0, LIBMPQ_HASH_DELETED },
    };
    mpq_hash_s decoded[3] = { { 0 } };
    uint8_t wire[3 * LIBMPQ_HASH_ENTRY_WIRE_SIZE];
    size_t i;

    TEST_CHECK(libmpq__hash_table_encode(source, 3, wire, sizeof(wire)) == 0);
    TEST_CHECK(libmpq__hash_table_decode(wire, sizeof(wire), decoded, 3) == 0);
    for (i = 0; i < 3; i++) {
        TEST_CHECK(decoded[i].hash_a == source[i].hash_a);
        TEST_CHECK(decoded[i].hash_b == source[i].hash_b);
        TEST_CHECK(decoded[i].locale == source[i].locale);
        TEST_CHECK(decoded[i].platform == source[i].platform);
        TEST_CHECK(decoded[i].block_table_index == source[i].block_table_index);
    }
    return 0;
}

/* Reject short, missing, or arithmetically impossible buffers before conversion. */
static int
test_invalid_buffers(void)
{
    mpq_hash_s entry = { 0 };
    uint8_t wire[LIBMPQ_HASH_ENTRY_WIRE_SIZE];
    size_t overflow_count = SIZE_MAX / LIBMPQ_HASH_ENTRY_WIRE_SIZE + 1u;
    size_t i;

    memset(wire, 0xa5, sizeof(wire));
    TEST_CHECK(libmpq__hash_table_decode(wire, sizeof(wire) - 1u, &entry, 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__hash_table_encode(&entry, 1, wire, sizeof(wire) - 1u) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__hash_table_decode(NULL, sizeof(wire), &entry, 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__hash_table_encode(&entry, 1, NULL, sizeof(wire)) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__hash_table_decode(wire, SIZE_MAX, &entry, overflow_count) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__hash_table_encode(&entry, overflow_count, wire, SIZE_MAX) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(entry.block_table_index == 0);
    for (i = 0; i < sizeof(wire); i++)
        TEST_CHECK(wire[i] == 0xa5);
    TEST_CHECK(libmpq__hash_table_decode(NULL, 0, NULL, 0) == 0);
    TEST_CHECK(libmpq__hash_table_encode(NULL, 0, NULL, 0) == 0);
    return 0;
}

int
main(void)
{
    if (test_single_entry() != 0 || test_slot_markers() != 0 || test_multiple_entries() != 0 ||
        test_invalid_buffers() != 0)
        return 1;
    return 0;
}
