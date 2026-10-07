/*
 *  mpq-het.h -- Private MPQ HET header and payload ranges.
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

#ifndef LIBMPQ_MPQ_HET_H
#define LIBMPQ_MPQ_HET_H

#include "mpq-ext-table.h"

#define LIBMPQ_HET_HEADER_WIRE_SIZE 32u

/*
 * Private HET header; table_size includes this header but not the envelope.
 * NameHash1 occupies one byte per slot regardless of name_hash_bit_size.
 */
typedef struct
{
    mpq_ext_table_header_s envelope;
    uint32_t table_size;
    uint32_t entry_count;
    uint32_t total_count;
    uint32_t name_hash_bit_size;
    uint32_t index_size_total;
    uint32_t index_size_extra;
    uint32_t index_size;
    uint32_t index_table_size;
    mpq_ext_table_range_s name_hash1;
    mpq_ext_table_range_s indices;
} mpq_het_header_s;

/* Decode header/ranges only from already-decrypted/decompressed table bytes. */
int32_t libmpq__het_header_decode(const uint8_t *input, size_t size, mpq_het_header_s *header);

#endif
