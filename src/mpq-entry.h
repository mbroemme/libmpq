/*
 *  mpq-entry.h -- private logical MPQ archive-entry state.
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

#ifndef LIBMPQ_MPQ_ENTRY_H
#define LIBMPQ_MPQ_ENTRY_H

#include <stdint.h>

/* Per-member reader/cache state for decryption and packed sector offsets. */
typedef struct
{
    uint32_t seed;                /* Per-file decryption seed. */
    uint8_t seed_known;           /* Whether seed was recovered successfully. */
    uint32_t *packed_offset;      /* Packed sector offsets for multi-sector files. */
    uint32_t packed_offset_count; /* Number of packed_offset entries. */
    uint32_t open_count;          /* Reference count for the cached sector table. */
} mpq_file_s;

/*
 * Map a compact public file number, resolved through the archive hash table,
 * to its physical block-table entry. Unused or invalid blocks may be skipped;
 * block_table_diff records how many were skipped before this entry.
 */
typedef struct
{
    uint32_t block_table_indices; /* Block-table index for this public file number. */
    uint32_t block_table_diff;    /* Number of skipped invalid block entries before this file. */
} mpq_map_s;

#endif /* LIBMPQ_MPQ_ENTRY_H */
