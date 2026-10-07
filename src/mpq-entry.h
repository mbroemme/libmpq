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

#include "mpq-block.h"

#include <stdint.h>

/* Provenance flags can coexist; zero never identifies a valid source. */
#define LIBMPQ_ENTRY_SOURCE_NONE 0u
#define LIBMPQ_ENTRY_SOURCE_CLASSIC 1u
#define LIBMPQ_ENTRY_SOURCE_BET 2u

/* Logical member metadata owned by the archive, independent of classic wire widths. */
typedef struct
{
    uint64_t offset;               /* Complete archive-relative payload position. */
    uint64_t packed_size;          /* Stored payload length. */
    uint64_t unpacked_size;        /* Logical decoded length (target length for patch members). */
    uint32_t flags;                /* Storage flags, including reader-discovered encryption. */
    uint32_t classic_source_index; /* Classic row, or UINT32_MAX when absent. */
    uint32_t bet_source_index;     /* BET row, or UINT32_MAX when absent. */
    uint32_t file_number;          /* Compact public number, or UINT32_MAX for unused entries. */
    uint8_t source_mask;           /* Sources present; logical reads do not require either index. */
} mpq_entry_s;

/* Convert classic wire metadata once; format writers still own the original tables. */
static inline void
libmpq__entry_from_classic(
    mpq_entry_s *entry, const mpq_block_s *block, const mpq_block_ex_s *high, uint32_t index
)
{
    entry->offset = block->offset | ((uint64_t)high->offset_high << 32);
    entry->packed_size = block->packed_size;
    entry->unpacked_size = block->unpacked_size;
    entry->flags = block->flags;
    entry->classic_source_index = index;
    entry->bet_source_index = UINT32_MAX;
    entry->source_mask = LIBMPQ_ENTRY_SOURCE_CLASSIC;
    entry->file_number = UINT32_MAX;
}

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
 * Map a compact public file number to canonical member metadata. Unused
 * entries are skipped without changing public numbering or source identity.
 */
typedef struct
{
    uint32_t entry_index; /* Canonical entry index for this public file number. */
} mpq_map_s;

#endif /* LIBMPQ_MPQ_ENTRY_H */
