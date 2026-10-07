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
#define LIBMPQ_HET_FILENAME_LIMIT 0x108u
#define LIBMPQ_HET_SLOT_FREE 0u

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

/* Borrowed decoded-table view. The caller keeps input bytes alive and immutable. */
typedef struct
{
    mpq_het_header_s header;
    const uint8_t *name_hash1;
    size_t name_hash1_size;
    const uint8_t *index_bits;
    size_t index_bits_size;
} mpq_het_s;

/* Masked/forced HET hash, its high eight bits, low remaining bits, and probe start. */
typedef struct
{
    uint64_t hash;
    uint64_t name_hash2;
    uint32_t initial_slot;
    uint8_t name_hash1;
} mpq_het_hash_s;

/*
 * Jenkins hashlittle2 with Storm seeds and ASCII lowercase/backslash normalization.
 * Only the first 264 filename bytes are hashed. NULL is invalid; empty is valid.
 */
int32_t libmpq__het_hash_filename(const char *filename, uint64_t *hash);
int32_t libmpq__het_hash_partition(
    uint64_t hash, uint32_t hash_bits, uint32_t total_count, mpq_het_hash_s *parts
);
int32_t libmpq__het_view_init(const uint8_t *input, size_t size, mpq_het_s *table);
int32_t libmpq__het_slot_index(const mpq_het_s *table, uint32_t slot, uint64_t *index);

/*
 * NameHash1 alone cannot confirm a filename. The caller must match NameHash2
 * for a candidate BET index and may reject deleted entries. No BET record is
 * decoded here. Return an error or set matches to zero/nonzero; no state is kept.
 */
typedef int32_t (*mpq_het_match_fn)(
    void *context, uint64_t index, uint64_t name_hash2, int *matches
);

/* Bound probing by total_count, validate indices against count, then confirm them. */
int32_t libmpq__het_lookup(
    const mpq_het_s *table, const char *filename, uint64_t bet_entry_count, mpq_het_match_fn match,
    void *context, uint64_t *index
);

#endif
