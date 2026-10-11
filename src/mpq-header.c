/*
 *  mpq-header.c -- MPQ archive header wire-format encoding and decoding.
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

#include "mpq-header.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Decode only wire fields; archive validation remains with the reader. */
int32_t
libmpq__header_decode(mpq_header_s *header, const uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    header->mpq_magic = libmpq__load_le32(wire);
    header->header_size = libmpq__load_le32(wire + 4);
    header->archive_size = libmpq__load_le32(wire + 8);
    header->version = libmpq__load_le16(wire + 12);
    header->block_size = libmpq__load_le16(wire + 14);
    header->hash_table_offset = libmpq__load_le32(wire + 16);
    header->block_table_offset = libmpq__load_le32(wire + 20);
    header->hash_table_count = libmpq__load_le32(wire + 24);
    header->block_table_count = libmpq__load_le32(wire + 28);
    return 0;
}

/* Decode the optional version 2 extension from its 12 wire bytes. */
int32_t
libmpq__header_ex_decode(mpq_header_ex_s *header, const uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_EX_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    header->extended_offset = libmpq__load_le64(wire);
    header->hash_table_offset_high = libmpq__load_le16(wire + 8);
    header->block_table_offset_high = libmpq__load_le16(wire + 10);
    return 0;
}

/* Decode only the 24-byte v3 extension; short-header fallback belongs to the reader. */
int32_t
libmpq__header_v3_decode(mpq_header_v3_s *header, const uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_V3_EX_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    header->archive_size = libmpq__load_le64(wire);
    header->bet_table_offset = libmpq__load_le64(wire + 8);
    header->het_table_offset = libmpq__load_le64(wire + 16);
    return 0;
}

/* Encode fixed native fields into the exact 32-byte little-endian base header. */
int32_t
libmpq__header_encode(const mpq_header_s *header, uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    libmpq__store_le32(wire, header->mpq_magic);
    libmpq__store_le32(wire + 4, header->header_size);
    libmpq__store_le32(wire + 8, header->archive_size);
    libmpq__store_le16(wire + 12, header->version);
    libmpq__store_le16(wire + 14, header->block_size);
    libmpq__store_le32(wire + 16, header->hash_table_offset);
    libmpq__store_le32(wire + 20, header->block_table_offset);
    libmpq__store_le32(wire + 24, header->hash_table_count);
    libmpq__store_le32(wire + 28, header->block_table_count);
    return 0;
}

/* Encode the optional version 2 extension into exactly 12 wire bytes. */
int32_t
libmpq__header_ex_encode(const mpq_header_ex_s *header, uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_EX_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    libmpq__store_le64(wire, header->extended_offset);
    libmpq__store_le16(wire + 8, header->hash_table_offset_high);
    libmpq__store_le16(wire + 10, header->block_table_offset_high);
    return 0;
}

/* Encode the v3 extension independently of native structure alignment. */
int32_t
libmpq__header_v3_encode(const mpq_header_v3_s *header, uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_V3_EX_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    libmpq__store_le64(wire, header->archive_size);
    libmpq__store_le64(wire + 8, header->bet_table_offset);
    libmpq__store_le64(wire + 16, header->het_table_offset);
    return 0;
}

/* Decode only the 140-byte v4 extension, preserving arbitrary digest bytes. */
int32_t
libmpq__header_v4_decode(mpq_header_v4_s *header, const uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_V4_EX_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    header->hash_table_size = libmpq__load_le64(wire);
    header->block_table_size = libmpq__load_le64(wire + 8);
    header->hi_block_table_size = libmpq__load_le64(wire + 16);
    header->het_table_size = libmpq__load_le64(wire + 24);
    header->bet_table_size = libmpq__load_le64(wire + 32);
    header->raw_chunk_size = libmpq__load_le32(wire + 40);
    memcpy(header->block_table_md5, wire + 44, 16);
    memcpy(header->hash_table_md5, wire + 60, 16);
    memcpy(header->hi_block_table_md5, wire + 76, 16);
    memcpy(header->bet_table_md5, wire + 92, 16);
    memcpy(header->het_table_md5, wire + 108, 16);
    memcpy(header->header_md5, wire + 124, 16);
    return 0;
}

/* Encode the extension alone without hashing or interpreting table metadata. */
int32_t
libmpq__header_v4_encode(const mpq_header_v4_s *header, uint8_t *wire, size_t size)
{
    if (header == NULL || wire == NULL || size < LIBMPQ_HEADER_V4_EX_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;

    libmpq__store_le64(wire, header->hash_table_size);
    libmpq__store_le64(wire + 8, header->block_table_size);
    libmpq__store_le64(wire + 16, header->hi_block_table_size);
    libmpq__store_le64(wire + 24, header->het_table_size);
    libmpq__store_le64(wire + 32, header->bet_table_size);
    libmpq__store_le32(wire + 40, header->raw_chunk_size);
    memcpy(wire + 44, header->block_table_md5, 16);
    memcpy(wire + 60, header->hash_table_md5, 16);
    memcpy(wire + 76, header->hi_block_table_md5, 16);
    memcpy(wire + 92, header->bet_table_md5, 16);
    memcpy(wire + 108, header->het_table_md5, 16);
    memcpy(wire + 124, header->header_md5, 16);
    return 0;
}

/* Validate all declarations before publishing any decoded layer. */
int32_t
libmpq__header_v4_full_decode(
    mpq_header_s *header, mpq_header_ex_s *ex, mpq_header_v3_s *v3, mpq_header_v4_s *v4,
    const uint8_t *wire, size_t size
)
{
    mpq_header_s base;

    if (header == NULL || ex == NULL || v3 == NULL || v4 == NULL || wire == NULL ||
        size < LIBMPQ_HEADER_V4_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    libmpq__header_decode(&base, wire, LIBMPQ_HEADER_WIRE_SIZE);
    if (base.mpq_magic != LIBMPQ_HEADER || base.version != LIBMPQ_ARCHIVE_VERSION_FOUR ||
        base.header_size != LIBMPQ_HEADER_V4_WIRE_SIZE)
        return LIBMPQ_ERROR_FORMAT;

    /* Fixed layer extents fit the already validated complete buffer. */
    libmpq__header_ex_decode(ex, wire + LIBMPQ_HEADER_WIRE_SIZE, LIBMPQ_HEADER_EX_WIRE_SIZE);
    libmpq__header_v3_decode(
        v3, wire + LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE,
        LIBMPQ_HEADER_V3_EX_WIRE_SIZE
    );
    libmpq__header_v4_decode(v4, wire + LIBMPQ_HEADER_V3_WIRE_SIZE, LIBMPQ_HEADER_V4_EX_WIRE_SIZE);
    *header = base;
    return 0;
}

/* Validate before writing; each layer emits only its defined wire bytes. */
int32_t
libmpq__header_v4_full_encode(
    const mpq_header_s *header, const mpq_header_ex_s *ex, const mpq_header_v3_s *v3,
    const mpq_header_v4_s *v4, uint8_t *wire, size_t size
)
{
    if (header == NULL || ex == NULL || v3 == NULL || v4 == NULL || wire == NULL ||
        size < LIBMPQ_HEADER_V4_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    if (header->mpq_magic != LIBMPQ_HEADER || header->version != LIBMPQ_ARCHIVE_VERSION_FOUR ||
        header->header_size != LIBMPQ_HEADER_V4_WIRE_SIZE)
        return LIBMPQ_ERROR_FORMAT;

    libmpq__header_encode(header, wire, LIBMPQ_HEADER_WIRE_SIZE);
    libmpq__header_ex_encode(ex, wire + LIBMPQ_HEADER_WIRE_SIZE, LIBMPQ_HEADER_EX_WIRE_SIZE);
    libmpq__header_v3_encode(
        v3, wire + LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE,
        LIBMPQ_HEADER_V3_EX_WIRE_SIZE
    );
    libmpq__header_v4_encode(v4, wire + LIBMPQ_HEADER_V3_WIRE_SIZE, LIBMPQ_HEADER_V4_EX_WIRE_SIZE);
    return 0;
}

/* Select the declared size without truncating the full v3 archive extent. */
uint64_t
libmpq__header_archive_size(const mpq_header_s *header, const mpq_header_v3_s *v3)
{
    if (header == NULL)
        return 0;
    if (header->version == LIBMPQ_ARCHIVE_VERSION_THREE &&
        header->header_size >= LIBMPQ_HEADER_V3_WIRE_SIZE)
        return v3 == NULL ? 0 : v3->archive_size;
    return header->archive_size;
}
