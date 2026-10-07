/*
 *  mpq-bet.h -- Private MPQ BET header and payload ranges.
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

#ifndef LIBMPQ_MPQ_BET_H
#define LIBMPQ_MPQ_BET_H

#include "mpq-ext-table.h"

#define LIBMPQ_BET_HEADER_WIRE_SIZE 76u

/* Bit coordinates within one packed BET file record; not C bitfields. */
typedef struct
{
    uint32_t bit_index;
    uint32_t bit_count;
} mpq_bet_field_s;

/*
 * Private decoded BET header. Flags precede packed records and NameHash2.
 * Reserved metadata is preserved, not interpreted. table_size excludes the
 * common envelope. No flag values, file records, or hashes are decoded here.
 */
typedef struct
{
    mpq_ext_table_header_s envelope;
    uint32_t table_size;
    uint32_t entry_count;
    uint32_t unknown;
    uint32_t table_entry_size;
    mpq_bet_field_s file_position;
    mpq_bet_field_s file_size;
    mpq_bet_field_s compressed_size;
    mpq_bet_field_s flag_index;
    mpq_bet_field_s unknown_field;
    uint32_t name_hash2_total;
    uint32_t name_hash2_extra;
    uint32_t name_hash2_size;
    uint32_t name_hash_array_size;
    uint32_t flag_count;
    mpq_ext_table_range_s flags;
    mpq_ext_table_range_s records;
    mpq_ext_table_range_s name_hash2;
} mpq_bet_header_s;

/* Decode header/ranges from already-decrypted/decompressed table bytes. */
int32_t libmpq__bet_header_decode(const uint8_t *input, size_t size, mpq_bet_header_s *header);

#endif
