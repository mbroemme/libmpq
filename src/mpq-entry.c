/*
 *  mpq-entry.c -- private logical MPQ archive-entry initialization.
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

#include "mpq-entry.h"

/* Convert classic wire metadata once; format writers still own the original tables. */
void
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
