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
