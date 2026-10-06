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
    header.version = 3; /* MPQ v4 is still unsupported. */
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

/* Nonzero HET/BET positions do not force their use when classic lookup is usable. */
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
        ) == 0
    );
    TEST_CHECK(archive->mpq_header_v3.bet_table_offset == v3.bet_table_offset);
    TEST_CHECK(archive->mpq_header_v3.het_table_offset == v3.het_table_offset);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

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
    v3 = (mpq_header_v3_s){ source.length, 9194, 9202 };
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
        test_v3_optional_tables() != 0 || test_v3_mixed_tables() != 0)
        return 1;
    return 0;
}
