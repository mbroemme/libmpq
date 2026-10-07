/*
 *  mpq-ext-table.c -- MPQ extended-table envelope decoding.
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

#include "mpq-ext-table.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>

/* Validate an already-decoded envelope; crypto/compression belong to its loader. */
int32_t
libmpq__ext_table_decode(
    const uint8_t *input, size_t size, uint32_t signature, mpq_ext_table_header_s *header
)
{
    mpq_ext_table_header_s decoded;

    if (input == NULL || header == NULL || size < LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    decoded.signature = libmpq__load_le32(input);
    decoded.version = libmpq__load_le32(input + 4);
    decoded.data_size = libmpq__load_le32(input + 8);
    if ((signature != LIBMPQ_HET_SIGNATURE && signature != LIBMPQ_BET_SIGNATURE) ||
        decoded.signature != signature || decoded.version != LIBMPQ_EXT_TABLE_VERSION)
        return LIBMPQ_ERROR_FORMAT;
    if (decoded.data_size > size - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    *header = decoded;
    return 0;
}
