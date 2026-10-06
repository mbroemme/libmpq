/*
 *  test-mpq-header.c -- MPQ header wire-format regression tests.
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

#include "../src/mpq-header.h"
#include "test-mpq-helper.h"

#include <libmpq/mpq.h>
#include <stdint.h>
#include <string.h>

/* Check both directions against independent v1 and v2 wire vectors. */
static int
test_header_vectors(void)
{
    static const uint8_t v1[] = {
        0x4d, 0x50, 0x51, 0x1a, 0x20, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34,
        0x12, 0x00, 0x00, 0x03, 0x00, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07,
        0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e, 0x0d,
    };
    static const uint8_t v2[] = {
        0x4d, 0x50, 0x51, 0x1a, 0x2c, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x03,
        0x00, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f,
        0x0e, 0x0d, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x1a, 0x19, 0x1c, 0x1b,
    };
    mpq_header_s base = { LIBMPQ_HEADER,
                          LIBMPQ_HEADER_WIRE_SIZE,
                          0x12345678u,
                          0,
                          3,
                          0x01020304u,
                          0x05060708u,
                          0x090a0b0cu,
                          0x0d0e0f10u };
    mpq_header_ex_s extension = { UINT64_C(0x1112131415161718), 0x191au, 0x1b1cu };
    mpq_header_s decoded;
    mpq_header_ex_s decoded_ex;
    uint8_t wire[sizeof(v2)];

    TEST_CHECK(libmpq__header_encode(&base, wire, sizeof(v1)) == 0);
    TEST_CHECK(memcmp(wire, v1, sizeof(v1)) == 0);
    memset(&decoded, 0, sizeof(decoded));
    TEST_CHECK(libmpq__header_decode(&decoded, v1, sizeof(v1)) == 0);
    TEST_CHECK(decoded.mpq_magic == base.mpq_magic);
    TEST_CHECK(decoded.header_size == base.header_size);
    TEST_CHECK(decoded.archive_size == base.archive_size);
    TEST_CHECK(decoded.version == base.version);
    TEST_CHECK(decoded.block_size == base.block_size);
    TEST_CHECK(decoded.hash_table_offset == base.hash_table_offset);
    TEST_CHECK(decoded.block_table_offset == base.block_table_offset);
    TEST_CHECK(decoded.hash_table_count == base.hash_table_count);
    TEST_CHECK(decoded.block_table_count == base.block_table_count);

    base.header_size = sizeof(v2);
    base.version = LIBMPQ_ARCHIVE_VERSION_TWO;
    TEST_CHECK(libmpq__header_encode(&base, wire, sizeof(wire)) == 0);
    TEST_CHECK(
        libmpq__header_ex_encode(
            &extension, wire + LIBMPQ_HEADER_WIRE_SIZE, LIBMPQ_HEADER_EX_WIRE_SIZE
        ) == 0
    );
    TEST_CHECK(memcmp(wire, v2, sizeof(v2)) == 0);
    TEST_CHECK(libmpq__header_decode(&decoded, v2, sizeof(v2)) == 0);
    TEST_CHECK(
        libmpq__header_ex_decode(
            &decoded_ex, v2 + LIBMPQ_HEADER_WIRE_SIZE, LIBMPQ_HEADER_EX_WIRE_SIZE
        ) == 0
    );
    TEST_CHECK(decoded.header_size == sizeof(v2));
    TEST_CHECK(decoded.version == LIBMPQ_ARCHIVE_VERSION_TWO);
    TEST_CHECK(decoded_ex.extended_offset == extension.extended_offset);
    TEST_CHECK(decoded_ex.hash_table_offset_high == extension.hash_table_offset_high);
    TEST_CHECK(decoded_ex.block_table_offset_high == extension.block_table_offset_high);
    return 0;
}

/* Reject short buffers without modifying native fields or available wire bytes. */
static int
test_truncated_headers(void)
{
    mpq_header_s base = { 0 };
    mpq_header_ex_s extension = { 0 };
    uint8_t wire[LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE];

    memset(wire, 0xa5, sizeof(wire));
    TEST_CHECK(
        libmpq__header_decode(&base, wire, LIBMPQ_HEADER_WIRE_SIZE - 1) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_ex_decode(&extension, wire, LIBMPQ_HEADER_EX_WIRE_SIZE - 1) ==
        LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(base.mpq_magic == 0);
    TEST_CHECK(extension.extended_offset == 0);
    TEST_CHECK(
        libmpq__header_encode(&base, wire, LIBMPQ_HEADER_WIRE_SIZE - 1) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_ex_encode(&extension, wire, LIBMPQ_HEADER_EX_WIRE_SIZE - 1) ==
        LIBMPQ_ERROR_SIZE
    );
    for (size_t i = 0; i < sizeof(wire); i++)
        TEST_CHECK(wire[i] == 0xa5);
    return 0;
}

int
main(void)
{
    if (test_header_vectors() != 0 || test_truncated_headers() != 0)
        return 1;
    return 0;
}
