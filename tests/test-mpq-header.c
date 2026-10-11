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

#include "../src/mpq-archive.h"
#include "../src/mpq-crypto.h"
#include "../src/mpq-endian.h"
#include "../src/mpq-header.h"
#include "test-mpq-helper.h"

#include <libmpq/mpq.h>
#include <stdint.h>
#include <stdlib.h>
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

/* Independent little-endian v3 extension vector, including a >32-bit size. */
static int
test_v3_vector(void)
{
    static const uint8_t expected[24] = { 8,  7,  6,  5,  4,  3,  2,  1,  24, 23, 22, 21,
                                          20, 19, 18, 17, 40, 39, 38, 37, 36, 35, 34, 33 };
    mpq_header_v3_s extension = { UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718),
                                  UINT64_C(0x2122232425262728) };
    mpq_header_v3_s decoded = { 0 };
    mpq_header_s base = { 0 };
    uint8_t wire[24];

    TEST_CHECK(libmpq__header_v3_encode(&extension, wire, sizeof(wire)) == 0);
    TEST_CHECK(memcmp(wire, expected, sizeof(wire)) == 0);
    TEST_CHECK(libmpq__header_v3_decode(&decoded, expected, sizeof(expected)) == 0);
    TEST_CHECK(decoded.archive_size == extension.archive_size);
    TEST_CHECK(decoded.bet_table_offset == extension.bet_table_offset);
    TEST_CHECK(decoded.het_table_offset == extension.het_table_offset);
    base.version = LIBMPQ_ARCHIVE_VERSION_THREE;
    base.header_size = LIBMPQ_HEADER_V3_WIRE_SIZE;
    base.archive_size = 123;
    TEST_CHECK(libmpq__header_archive_size(&base, &decoded) == extension.archive_size);
    base.header_size = 44;
    TEST_CHECK(libmpq__header_archive_size(&base, &decoded) == 123);
    memset(wire, 0xa5, sizeof(wire));
    TEST_CHECK(libmpq__header_v3_encode(&extension, wire, 23) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__header_v3_decode(&decoded, wire, 23) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(decoded.archive_size == extension.archive_size);
    for (size_t i = 0; i < sizeof(wire); ++i)
        TEST_CHECK(wire[i] == 0xa5);
    return 0;
}

/* Independent complete v4 wire vector; digest bytes are synthetic, not computed. */
static const uint8_t test_v4_wire[208] = {
    0x4d, 0x50, 0x51, 0x1a, 0xd0, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x03, 0x00, 0x03, 0x00,
    0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0c, 0x0b, 0x0a, 0x09, 0x10, 0x0f, 0x0e, 0x0d,
    0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x1a, 0x19, 0x1c, 0x1b, 0x28, 0x27, 0x26, 0x25,
    0x24, 0x23, 0x22, 0x21, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x48, 0x47, 0x46, 0x45,
    0x44, 0x43, 0x42, 0x41, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x68, 0x67, 0x66, 0x65,
    0x64, 0x63, 0x62, 0x61, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x88, 0x87, 0x86, 0x85,
    0x84, 0x83, 0x82, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x03, 0x02, 0x01,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
};

/* Check all layers, large sizes, unaligned storage and digest boundaries. */
static int
test_v4_vectors(void)
{
    mpq_header_s base = {
        LIBMPQ_HEADER, 208,         0x12345678u, LIBMPQ_ARCHIVE_VERSION_FOUR, 3, 0x01020304u,
        0x05060708u,   0x090a0b0cu, 0x0d0e0f10u
    };
    mpq_header_ex_s ex = { UINT64_C(0x1112131415161718), 0x191au, 0x1b1cu };
    mpq_header_v3_s v3 = { UINT64_C(0x2122232425262728), UINT64_C(0x3132333435363738),
                           UINT64_C(0x4142434445464748) };
    mpq_header_v4_s v4 = { 0 };
    mpq_header_s decoded;
    mpq_header_ex_s decoded_ex;
    mpq_header_v3_s decoded_v3;
    mpq_header_v4_s decoded_v4;
    uint8_t output[210];
    uint8_t repeated[208];

    v4.hash_table_size = UINT64_C(0x5152535455565758);
    v4.block_table_size = UINT64_C(0x6162636465666768);
    v4.hi_block_table_size = UINT64_C(0x7172737475767778);
    v4.het_table_size = UINT64_C(0x8182838485868788);
    v4.bet_table_size = UINT64_MAX;
    v4.raw_chunk_size = 0x01020304u;
    for (size_t i = 0; i < 16; ++i) {
        v4.block_table_md5[i] = (uint8_t)i;
        v4.hash_table_md5[i] = (uint8_t)(i + 16);
        v4.hi_block_table_md5[i] = (uint8_t)(i + 32);
        v4.bet_table_md5[i] = (uint8_t)(i + 48);
        v4.het_table_md5[i] = (uint8_t)(i + 64);
        v4.header_md5[i] = (uint8_t)(i + 80);
    }
    TEST_CHECK(LIBMPQ_HEADER_V4_WIRE_SIZE == 0xd0u);
    TEST_CHECK(LIBMPQ_HEADER_V4_EX_WIRE_SIZE == 0x8cu);
    TEST_CHECK(LIBMPQ_HEADER_V3_WIRE_SIZE + LIBMPQ_HEADER_V4_EX_WIRE_SIZE == 208u);
    TEST_CHECK(LIBMPQ_HEADER_V4_MD5_INPUT_SIZE == 0xc0u);
    TEST_CHECK(LIBMPQ_HEADER_V4_MD5_OFFSET + LIBMPQ_HEADER_V4_MD5_SIZE == 208u);
    memset(output, 0xa5, sizeof(output));
    TEST_CHECK(libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, output + 1, 208) == 0);
    TEST_CHECK(output[0] == 0xa5 && output[209] == 0xa5);
    TEST_CHECK(memcmp(output + 1, test_v4_wire, 208) == 0);
    TEST_CHECK(
        libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, repeated, sizeof(repeated)) == 0
    );
    TEST_CHECK(memcmp(repeated, test_v4_wire, 208) == 0);
    TEST_CHECK(
        libmpq__header_v4_full_decode(
            &decoded, &decoded_ex, &decoded_v3, &decoded_v4, output + 1, 208
        ) == 0
    );
    TEST_CHECK(decoded.mpq_magic == LIBMPQ_HEADER && decoded.header_size == 208u);
    TEST_CHECK(decoded.version == 3 && decoded.block_size == 3);
    TEST_CHECK(decoded.archive_size == 0x12345678u);
    TEST_CHECK(
        decoded.hash_table_offset == 0x01020304u && decoded.block_table_offset == 0x05060708u
    );
    TEST_CHECK(decoded.hash_table_count == 0x090a0b0cu && decoded.block_table_count == 0x0d0e0f10u);
    TEST_CHECK(decoded_ex.extended_offset == ex.extended_offset);
    TEST_CHECK(decoded_ex.hash_table_offset_high == ex.hash_table_offset_high);
    TEST_CHECK(decoded_ex.block_table_offset_high == ex.block_table_offset_high);
    TEST_CHECK(decoded_v3.archive_size == v3.archive_size);
    TEST_CHECK(decoded_v3.bet_table_offset == v3.bet_table_offset);
    TEST_CHECK(decoded_v3.het_table_offset == v3.het_table_offset);
    TEST_CHECK(decoded_v4.hash_table_size == v4.hash_table_size);
    TEST_CHECK(decoded_v4.block_table_size == v4.block_table_size);
    TEST_CHECK(decoded_v4.hi_block_table_size == v4.hi_block_table_size);
    TEST_CHECK(decoded_v4.het_table_size == v4.het_table_size);
    TEST_CHECK(decoded_v4.bet_table_size == UINT64_MAX);
    TEST_CHECK(decoded_v4.raw_chunk_size == v4.raw_chunk_size);
    TEST_CHECK(memcmp(decoded_v4.block_table_md5, v4.block_table_md5, 16) == 0);
    TEST_CHECK(memcmp(decoded_v4.hash_table_md5, v4.hash_table_md5, 16) == 0);
    TEST_CHECK(memcmp(decoded_v4.hi_block_table_md5, v4.hi_block_table_md5, 16) == 0);
    TEST_CHECK(memcmp(decoded_v4.bet_table_md5, v4.bet_table_md5, 16) == 0);
    TEST_CHECK(memcmp(decoded_v4.het_table_md5, v4.het_table_md5, 16) == 0);
    TEST_CHECK(memcmp(decoded_v4.header_md5, v4.header_md5, 16) == 0);
    TEST_CHECK(
        libmpq__header_v4_full_encode(
            &decoded, &decoded_ex, &decoded_v3, &decoded_v4, repeated, sizeof(repeated)
        ) == 0
    );
    TEST_CHECK(memcmp(repeated, test_v4_wire, 208) == 0);

    /* Extension-only helpers start at byte 0x44, not at the archive signature. */
    TEST_CHECK(libmpq__header_v4_encode(&v4, output + 1, 140) == 0);
    TEST_CHECK(memcmp(output + 1, test_v4_wire + 68, 140) == 0);
    TEST_CHECK(libmpq__header_v4_decode(&decoded_v4, output + 1, 140) == 0);
    TEST_CHECK(decoded_v4.bet_table_size == UINT64_MAX);

    /* A supplied header digest is outside the defined MD5 input range. */
    memset(v4.header_md5, 0xff, sizeof(v4.header_md5));
    TEST_CHECK(libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, repeated, 208) == 0);
    TEST_CHECK(memcmp(repeated, test_v4_wire, LIBMPQ_HEADER_V4_MD5_INPUT_SIZE) == 0);
    for (size_t i = LIBMPQ_HEADER_V4_MD5_OFFSET; i < 208; ++i)
        TEST_CHECK(repeated[i] == 0xff);

    /* No default chunk size or nonzero digest requirement is imposed. */
    memset(&v4, 0, sizeof(v4));
    TEST_CHECK(libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, repeated, 208) == 0);
    TEST_CHECK(
        libmpq__header_v4_full_decode(
            &decoded, &decoded_ex, &decoded_v3, &decoded_v4, repeated, 208
        ) == 0
    );
    TEST_CHECK(decoded_v4.raw_chunk_size == 0);
    for (size_t i = 68; i < 208; ++i)
        TEST_CHECK(repeated[i] == 0);
    return 0;
}

/* Short or malformed headers preserve every output; overlong buffers keep their tail. */
static int
test_v4_errors(void)
{
    mpq_header_s base;
    mpq_header_ex_s ex;
    mpq_header_v3_s v3;
    mpq_header_v4_s v4;
    uint8_t output[209];
    uint8_t changed[208];

    memset(&base, 0xa5, sizeof(base));
    memset(&ex, 0xa5, sizeof(ex));
    memset(&v3, 0xa5, sizeof(v3));
    memset(&v4, 0xa5, sizeof(v4));
    for (size_t size = 0; size < 208; ++size) {
        TEST_CHECK(
            libmpq__header_v4_full_decode(&base, &ex, &v3, &v4, test_v4_wire, size) ==
            LIBMPQ_ERROR_SIZE
        );
        memset(output, 0xa5, sizeof(output));
        TEST_CHECK(
            libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, output, size) == LIBMPQ_ERROR_SIZE
        );
        for (size_t i = 0; i < sizeof(output); ++i)
            TEST_CHECK(output[i] == 0xa5);
    }
    TEST_CHECK(base.mpq_magic == 0xa5a5a5a5u);
    TEST_CHECK(ex.extended_offset == UINT64_C(0xa5a5a5a5a5a5a5a5));
    TEST_CHECK(v3.archive_size == UINT64_C(0xa5a5a5a5a5a5a5a5));
    TEST_CHECK(v4.hash_table_size == UINT64_C(0xa5a5a5a5a5a5a5a5));
    for (size_t size = 0; size < 140; ++size) {
        TEST_CHECK(libmpq__header_v4_decode(&v4, test_v4_wire + 68, size) == LIBMPQ_ERROR_SIZE);
        TEST_CHECK(libmpq__header_v4_encode(&v4, output, size) == LIBMPQ_ERROR_SIZE);
    }
    TEST_CHECK(v4.hash_table_size == UINT64_C(0xa5a5a5a5a5a5a5a5));
    for (size_t i = 0; i < sizeof(output); ++i)
        TEST_CHECK(output[i] == 0xa5);

    TEST_CHECK(
        libmpq__header_v4_full_decode(NULL, &ex, &v3, &v4, test_v4_wire, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_v4_full_decode(&base, NULL, &v3, &v4, test_v4_wire, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_v4_full_decode(&base, &ex, NULL, &v4, test_v4_wire, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_v4_full_decode(&base, &ex, &v3, NULL, test_v4_wire, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(libmpq__header_v4_full_decode(&base, &ex, &v3, &v4, NULL, 208) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(
        libmpq__header_v4_full_encode(NULL, &ex, &v3, &v4, output, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_v4_full_encode(&base, NULL, &v3, &v4, output, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_v4_full_encode(&base, &ex, NULL, &v4, output, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__header_v4_full_encode(&base, &ex, &v3, NULL, output, 208) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, NULL, 208) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__header_v4_decode(NULL, test_v4_wire + 68, 140) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__header_v4_decode(&v4, NULL, 140) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__header_v4_encode(NULL, output, 140) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__header_v4_encode(&v4, NULL, 140) == LIBMPQ_ERROR_SIZE);

    /* Wrong version, wrong declared size and wrong magic are structural errors. */
    for (unsigned int field = 0; field < 3; ++field) {
        memcpy(changed, test_v4_wire, 208);
        changed[field == 0 ? 12 : field == 1 ? 4 : 0] ^= 1;
        TEST_CHECK(
            libmpq__header_v4_full_decode(&base, &ex, &v3, &v4, changed, 208) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(base.mpq_magic == 0xa5a5a5a5u);
        TEST_CHECK(ex.extended_offset == UINT64_C(0xa5a5a5a5a5a5a5a5));
        TEST_CHECK(v3.archive_size == UINT64_C(0xa5a5a5a5a5a5a5a5));
        TEST_CHECK(v4.hash_table_size == UINT64_C(0xa5a5a5a5a5a5a5a5));
    }
    TEST_CHECK(libmpq__header_v4_full_decode(&base, &ex, &v3, &v4, test_v4_wire, 208) == 0);
    for (unsigned int field = 0; field < 3; ++field) {
        mpq_header_s invalid = base;
        if (field == 0)
            invalid.version = LIBMPQ_ARCHIVE_VERSION_THREE;
        else if (field == 1)
            invalid.header_size = 207;
        else
            invalid.mpq_magic = 0;
        TEST_CHECK(
            libmpq__header_v4_full_encode(&invalid, &ex, &v3, &v4, output, 208) ==
            LIBMPQ_ERROR_FORMAT
        );
        for (size_t i = 0; i < sizeof(output); ++i)
            TEST_CHECK(output[i] == 0xa5);
    }
    TEST_CHECK(libmpq__header_v4_full_encode(&base, &ex, &v3, &v4, output, sizeof(output)) == 0);
    TEST_CHECK(output[208] == 0xa5 && memcmp(output, test_v4_wire, 208) == 0);
    return 0;
}

/* A compact synthetic archive can be placed beyond 4 GiB by sparse read_at. */
typedef struct
{
    uint8_t bytes[10000];
    size_t length;
    uint32_t header_size;
    uint64_t shift;
    uint64_t base;
    uint64_t source_size;
    uint64_t highest_read;
} v3_source_s;

/* Supply exact requested ranges, with zero-filled gaps between header and tables. */
static int32_t
v3_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    v3_source_s *source = context;
    uint64_t start;
    uint64_t positions[2] = { source->base, source->base + source->shift + source->header_size };
    size_t lengths[2] = { source->header_size, source->length - source->header_size };
    size_t indices[2] = { 0, source->header_size };

    if (offset < 0 || (uint64_t)offset > source->source_size ||
        size > source->source_size - (uint64_t)offset)
        return LIBMPQ_ERROR_READ;
    start = (uint64_t)offset;
    if (start > source->highest_read)
        source->highest_read = start;
    memset(buffer, 0, size);
    for (unsigned int i = 0; i < 2; ++i) {
        uint64_t left = start > positions[i] ? start : positions[i];
        uint64_t right =
            start + size < positions[i] + lengths[i] ? start + size : positions[i] + lengths[i];
        if (left < right)
            memcpy(
                buffer + (size_t)(left - start),
                source->bytes + indices[i] + (size_t)(left - positions[i]), (size_t)(right - left)
            );
    }
    return 0;
}

/* Build encrypted classic tables and one deterministic, multi-sector stored member. */
static int
v3_fixture(v3_source_s *source, uint32_t header_size, uint64_t shift, uint64_t base)
{
    mpq_header_s header = {
        LIBMPQ_HEADER,    header_size, 0, LIBMPQ_ARCHIVE_VERSION_THREE, 3, header_size,
        header_size + 64, 4,           1
    };
    mpq_header_ex_s ex = { shift + header_size + 80, (uint16_t)(shift >> 32),
                           (uint16_t)(shift >> 32) };
    mpq_header_v3_s v3 = { shift + header_size + 82 + 9000, 0, 0 };
    mpq_hash_s hashes[4];
    mpq_block_s block = { header_size + 82, 9000, 9000, LIBMPQ_FLAG_EXISTS };
    mpq_block_ex_s high = { (uint16_t)(shift >> 32) };
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;

    memset(source, 0, sizeof(*source));
    source->header_size = header_size;
    source->shift = shift;
    source->base = base;
    source->length = header_size + 82 + 9000;
    source->source_size = base + shift + source->length;
    header.archive_size = header_size == 68 ? 1 : (uint32_t)v3.archive_size;
    memset(hashes, 0xff, sizeof(hashes));
    libmpq__file_hash("payload.bin", &h1, &h2, &h3);
    hashes[h1 & 3u] = (mpq_hash_s){ h2, h3, 0, 0, 0 };
    TEST_CHECK(libmpq__header_encode(&header, source->bytes, header_size) == 0);
    TEST_CHECK(libmpq__header_ex_encode(&ex, source->bytes + 32, 12) == 0);
    if (header_size == 68)
        TEST_CHECK(libmpq__header_v3_encode(&v3, source->bytes + 44, 24) == 0);
    TEST_CHECK(libmpq__hash_table_encode(hashes, 4, source->bytes + header_size, 64) == 0);
    TEST_CHECK(libmpq__block_table_encode(&block, 1, source->bytes + header_size + 64, 16) == 0);
    TEST_CHECK(libmpq__block_ex_table_encode(&high, 1, source->bytes + header_size + 80, 2) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source->bytes + header_size, 64, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source->bytes + header_size + 64, 16, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    for (size_t i = 0; i < 9000; ++i)
        source->bytes[header_size + 82 + i] = (uint8_t)(i * 37u + i / 13u);
    return 0;
}

/* Exercise public lookup, extraction and streaming with full or short v3 headers. */
static int
test_v3_classic(uint32_t header_size, uint64_t shift, uint64_t base, int adjusted)
{
    v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t actual[9000];
    uint8_t expected[9000];
    uint32_t number;
    uint32_t version;
    uint32_t files;
    libmpq__off_t transferred;
    libmpq__off_t size;

    TEST_CHECK(v3_fixture(&source, header_size, shift, base) == 0);
    memcpy(expected, source.bytes + header_size + 82, sizeof(expected));
    if (adjusted) {
        uint8_t *raw = source.bytes + header_size + 64;
        uint32_t table_key = libmpq__crypto_hash_string("(block table)", 0x300);
        uint32_t key =
            (libmpq__crypto_hash_string("payload.bin", 0x300) + header_size + 82) ^ 9000u;
        TEST_CHECK(libmpq__crypto_decrypt_block(raw, 16, table_key) == 0);
        libmpq__store_le32(raw + 12, LIBMPQ_FLAG_EXISTS | LIBMPQ_FLAG_ENCRYPTED | 0x00020000u);
        TEST_CHECK(libmpq__crypto_encrypt_block(raw, 16, table_key) == 0);
        for (uint32_t i = 0, position = 0; position < sizeof(expected); ++i) {
            uint32_t size = sizeof(expected) - position;
            if (size > 4096)
                size = 4096;
            TEST_CHECK(
                libmpq__crypto_encrypt_block(
                    source.bytes + header_size + 82 + position, size, key + i
                ) == 0
            );
            position += size;
        }
    }
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, base != 0 ? -1 : 0,
            NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_offset(archive, &size) == 0 && size == (libmpq__off_t)base);
    TEST_CHECK(libmpq__archive_version(archive, &version) == 0 && version == 3);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 1);
    TEST_CHECK(
        libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3) ==
        source.source_size - base
    );
    TEST_CHECK(archive->mpq_header_v3.bet_table_offset == 0);
    TEST_CHECK(archive->mpq_header_v3.het_table_offset == 0);

    /* Consumption needs canonical metadata, not decoded classic block storage. */
    free(archive->mpq_block);
    free(archive->mpq_block_ex);
    archive->mpq_block = NULL;
    archive->mpq_block_ex = NULL;
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == 0 && size == 9000);
    TEST_CHECK(
        libmpq__file_offset(archive, number, &size) == 0 &&
        (uint64_t)size == shift + header_size + 82
    );
    memset(actual, 0xa5, sizeof(actual));
    if (adjusted) {
        TEST_CHECK(libmpq__stream_open_name(archive, "payload.bin", &stream) == 0);
        TEST_CHECK(
            libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0 &&
            transferred == 9000
        );
        TEST_CHECK(libmpq__stream_close(stream) == 0);
    } else {
        TEST_CHECK(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
        TEST_CHECK(transferred == 9000);
    }
    TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, "payload.bin", &stream) == 0);
    memset(actual, 0xa5, sizeof(actual));
    TEST_CHECK(libmpq__stream_read(stream, actual, 4300, &transferred) == 0 && transferred == 4300);
    TEST_CHECK(
        libmpq__stream_read(stream, actual + 4300, 4700, &transferred) == 0 && transferred == 4700
    );
    TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__stream_read(stream, actual, 1, &transferred) == 0 && transferred == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (shift != 0)
        TEST_CHECK(source.highest_read > UINT32_MAX);
    return 0;
}

/* Reject truncated extensions, unsupported versions, oversized extents and HET/BET-only input. */
static int
test_v3_rejection(void)
{
    v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_header_s header;
    mpq_header_v3_s v3;

    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    for (libmpq__off_t available = 44; available < 68; ++available) {
        source.source_size = (uint64_t)available;
        TEST_CHECK(
            libmpq__archive_open_io(&archive, &source, v3_read_at, available, 0, NULL) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(archive == NULL);
    }
    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    TEST_CHECK(libmpq__header_decode(&header, source.bytes, 32) == 0);
    header.header_size = 40; /* An incomplete v2 extension is not a short v3 header. */
    TEST_CHECK(libmpq__header_encode(&header, source.bytes, 32) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    TEST_CHECK(libmpq__header_decode(&header, source.bytes, 32) == 0);
    header.version = LIBMPQ_ARCHIVE_VERSION_FOUR; /* MPQ v4 opening is still unsupported. */
    TEST_CHECK(libmpq__header_encode(&header, source.bytes, 32) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    TEST_CHECK(libmpq__header_v3_decode(&v3, source.bytes + 44, 24) == 0);
    v3.archive_size = UINT64_MAX;
    TEST_CHECK(libmpq__header_v3_encode(&v3, source.bytes + 44, 24) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    TEST_CHECK(libmpq__header_decode(&header, source.bytes, 32) == 0);
    header.hash_table_count = 0;
    header.block_table_count = 0;
    TEST_CHECK(libmpq__header_encode(&header, source.bytes, 32) == 0);
    TEST_CHECK(libmpq__header_v3_decode(&v3, source.bytes + 44, 24) == 0);
    v3.het_table_offset = 150;
    v3.bet_table_offset = 160;
    TEST_CHECK(libmpq__header_v3_encode(&v3, source.bytes + 44, 24) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    return 0;
}

/* Structural wire support must not enable public archive opening or creation. */
static int
test_v4_disabled(void)
{
    v3_source_s source = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { 0 };

    memcpy(source.bytes, test_v4_wire, sizeof(test_v4_wire));
    source.header_size = sizeof(test_v4_wire);
    source.length = sizeof(test_v4_wire);
    source.source_size = sizeof(test_v4_wire);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    options.version = LIBMPQ_ARCHIVE_VERSION_FOUR;
    TEST_CHECK(
        libmpq__archive_create(&archive, "unsupported-v4.mpq", &options) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    return 0;
}

/* Declared malformed extended tables must not disappear behind classic fallback. */
static int
test_v3_optional_tables(void)
{
    v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_header_v3_s v3;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    mpq_hash_s hashes[4];
    mpq_block_s block = { 150, 9000, 9000, 0 };

    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    v3.archive_size = source.length + 16;
    v3.bet_table_offset = source.length;
    v3.het_table_offset = source.length + 8;
    source.length += 16;
    source.source_size += 16;
    TEST_CHECK(libmpq__header_v3_encode(&v3, source.bytes + 44, 24) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);

    /* With no reachable live blocks, name lookup would require HET/BET. */
    memset(hashes, 0xff, sizeof(hashes));
    TEST_CHECK(libmpq__hash_table_encode(hashes, 4, source.bytes + 68, 64) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 68, 64, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);

    /* Empty classic stubs must not masquerade as an empty HET/BET-backed archive. */
    TEST_CHECK(libmpq__block_table_encode(&block, 1, source.bytes + 132, 16) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 132, 16, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    block.flags = LIBMPQ_FLAG_EXISTS;
    TEST_CHECK(libmpq__block_table_encode(&block, 1, source.bytes + 132, 16) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 132, 16, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );

    /* Restore the classic mapping, then reject an out-of-extent HET position. */
    libmpq__file_hash("payload.bin", &h1, &h2, &h3);
    hashes[h1 & 3u] = (mpq_hash_s){ h2, h3, 0, 0, 0 };
    TEST_CHECK(libmpq__hash_table_encode(hashes, 4, source.bytes + 68, 64) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 68, 64, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    v3.het_table_offset = UINT64_MAX;
    TEST_CHECK(libmpq__header_v3_encode(&v3, source.bytes + 44, 24) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);

    /* Physical trailing bytes must not hide a payload outside the declared archive. */
    v3.het_table_offset = 0;
    v3.bet_table_offset = 0;
    v3.archive_size = source.length - 17;
    TEST_CHECK(libmpq__header_v3_encode(&v3, source.bytes + 44, 24) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    return 0;
}

/* Unreferenced live blocks must not prevent reading classic-reachable members. */
static int
test_v3_mixed_tables(void)
{
    v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    mpq_header_s header;
    mpq_header_ex_s ex;
    mpq_header_v3_s v3;
    mpq_block_s blocks[2] = { { 150, 9000, 9000, LIBMPQ_FLAG_EXISTS },
                              { 9186, 8, 8, LIBMPQ_FLAG_EXISTS } };
    mpq_block_ex_s high[2] = { { 0 }, { 0 } };
    uint8_t actual[9000];
    uint32_t number;
    libmpq__off_t transferred;

    TEST_CHECK(v3_fixture(&source, 68, 0, 0) == 0);
    TEST_CHECK(libmpq__header_decode(&header, source.bytes, 32) == 0);
    TEST_CHECK(libmpq__header_ex_decode(&ex, source.bytes + 32, 12) == 0);
    header.block_table_offset = 9150;
    header.block_table_count = 2;
    ex.extended_offset = 9182;
    source.length = 9210;
    source.source_size = source.length;
    v3 = (mpq_header_v3_s){ source.length, 0, 0 };
    TEST_CHECK(libmpq__header_encode(&header, source.bytes, 32) == 0);
    TEST_CHECK(libmpq__header_ex_encode(&ex, source.bytes + 32, 12) == 0);
    TEST_CHECK(libmpq__header_v3_encode(&v3, source.bytes + 44, 24) == 0);
    TEST_CHECK(libmpq__block_table_encode(blocks, 2, source.bytes + 9150, 32) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 9150, 32, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    TEST_CHECK(libmpq__block_ex_table_encode(high, 2, source.bytes + 9182, 4) == 0);
    memcpy(source.bytes + 9186, "unmapped", 8);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, v3_read_at, (libmpq__off_t)source.source_size, 0, NULL
        ) == 0
    );
    TEST_CHECK(archive->mpq_header_v3.bet_table_offset == v3.bet_table_offset);
    TEST_CHECK(archive->mpq_header_v3.het_table_offset == v3.het_table_offset);
    TEST_CHECK((archive->mpq_block[1].flags & LIBMPQ_FLAG_EXISTS) != 0);
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; ++i)
        TEST_CHECK(archive->mpq_hash[i].block_table_index != 1);
    TEST_CHECK(libmpq__file_number(archive, "unmapped.bin", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    memset(actual, 0xa5, sizeof(actual));
    TEST_CHECK(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
    TEST_CHECK(transferred == 9000);
    TEST_CHECK(memcmp(actual, source.bytes + 150, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, "payload.bin", &stream) == 0);
    memset(actual, 0xa5, sizeof(actual));
    TEST_CHECK(libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0);
    TEST_CHECK(transferred == 9000);
    TEST_CHECK(memcmp(actual, source.bytes + 150, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

int
main(void)
{
    if (test_header_vectors() != 0 || test_truncated_headers() != 0 || test_v3_vector() != 0 ||
        test_v3_classic(68, 0, 0, 0) != 0 || test_v3_classic(32, 0, 0, 0) != 0 ||
        test_v3_classic(44, 0, 0, 0) != 0 || test_v3_classic(60, 0, 512, 0) != 0 ||
        test_v3_classic(68, UINT64_C(0x100000000), 512, 0) != 0 ||
        test_v3_classic(68, UINT64_C(0x100000000), 512, 1) != 0 || test_v3_rejection() != 0 ||
        test_v3_optional_tables() != 0 || test_v3_mixed_tables() != 0 || test_v4_vectors() != 0 ||
        test_v4_errors() != 0 || test_v4_disabled() != 0)
        return 1;
    return 0;
}
