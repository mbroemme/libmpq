/*
 *  mpq-het.c -- MPQ HET header decoding and validation.
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

#include "mpq-het.h"
#include "mpq-bit.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>

/* Decode and validate the HET layout without interpreting hashes or BET indices. */
int32_t
libmpq__het_header_decode(const uint8_t *input, size_t size, mpq_het_header_s *header)
{
    mpq_het_header_s decoded = { 0 };
    const uint8_t *wire;
    size_t index_bytes;
    size_t remaining;
    int32_t result;

    if (header == NULL)
        return LIBMPQ_ERROR_SIZE;
    result = libmpq__ext_table_decode(input, size, LIBMPQ_HET_SIGNATURE, &decoded.envelope);
    if (result != 0)
        return result;
    if (decoded.envelope.data_size < LIBMPQ_HET_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    wire = input + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
    decoded.table_size = libmpq__load_le32(wire);
    decoded.entry_count = libmpq__load_le32(wire + 4);
    decoded.total_count = libmpq__load_le32(wire + 8);
    decoded.name_hash_bit_size = libmpq__load_le32(wire + 12);
    decoded.index_size_total = libmpq__load_le32(wire + 16);
    decoded.index_size_extra = libmpq__load_le32(wire + 20);
    decoded.index_size = libmpq__load_le32(wire + 24);
    decoded.index_table_size = libmpq__load_le32(wire + 28);
    if (decoded.table_size < LIBMPQ_HET_HEADER_WIRE_SIZE ||
        decoded.table_size != decoded.envelope.data_size ||
        decoded.entry_count > decoded.total_count || decoded.name_hash_bit_size < 8 ||
        decoded.name_hash_bit_size > 64 || decoded.index_size_total > 64 ||
        decoded.index_size > decoded.index_size_total ||
        decoded.index_size_extra > decoded.index_size_total - decoded.index_size ||
        (decoded.total_count != 0 && decoded.index_size == 0))
        return LIBMPQ_ERROR_FORMAT;
    if (libmpq__bit_bytes(decoded.total_count, decoded.index_size_total, &index_bytes) != 0)
        return LIBMPQ_ERROR_SIZE;
    remaining = decoded.table_size - LIBMPQ_HET_HEADER_WIRE_SIZE;
    if (decoded.total_count > remaining)
        return LIBMPQ_ERROR_FORMAT;
    remaining -= decoded.total_count;
    if (decoded.index_table_size != remaining || index_bytes != decoded.index_table_size)
        return LIBMPQ_ERROR_FORMAT;
    decoded.name_hash1.offset = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + LIBMPQ_HET_HEADER_WIRE_SIZE;
    decoded.name_hash1.size = decoded.total_count;
    decoded.indices.offset = decoded.name_hash1.offset + decoded.name_hash1.size;
    decoded.indices.size = decoded.index_table_size;
    *header = decoded;
    return 0;
}
