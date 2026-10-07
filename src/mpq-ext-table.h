/*
 *  mpq-ext-table.h -- Private MPQ extended-table envelope and ranges.
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

#ifndef LIBMPQ_MPQ_EXT_TABLE_H
#define LIBMPQ_MPQ_EXT_TABLE_H

#include <stddef.h>
#include <stdint.h>

#define LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE 12u
#define LIBMPQ_EXT_TABLE_VERSION 1u
#define LIBMPQ_HET_SIGNATURE 0x1a544548u
#define LIBMPQ_BET_SIGNATURE 0x1a544542u

/*
 * Private, decoded common envelope. data_size excludes these twelve bytes,
 * includes the table-specific header, and describes decrypted/decompressed data.
 */
typedef struct
{
    uint32_t signature;
    uint32_t version;
    uint32_t data_size;
} mpq_ext_table_header_s;

/*
 * Validated byte range relative to the start of the complete decoded envelope.
 * Offsets/sizes carry no borrowed pointers and do not decode array contents.
 */
typedef struct
{
    size_t offset;
    size_t size;
} mpq_ext_table_range_s;

int32_t libmpq__ext_table_decode(
    const uint8_t *input, size_t size, uint32_t signature, mpq_ext_table_header_s *header
);

#endif
