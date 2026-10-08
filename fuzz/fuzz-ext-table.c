/*
 *  fuzz-ext-table.c -- Fuzz decoded HET/BET structures and consumers.
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

#include "mpq-bet.h"
#include "mpq-het.h"
#include <stddef.h>
#include <stdint.h>

/* Exercise every HET candidate without confirming a hash or requiring a BET. */
static int32_t
match_candidate(void *context, uint64_t index, uint64_t hash, int *matches)
{
    (void)context;
    (void)index;
    (void)hash;
    *matches = 0;
    return 0;
}

/* Already-decoded bytes reach parsers even when archive table crypto would fail. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mpq_het_s het;
    mpq_bet_s bet;
    uint64_t index;
    if (size > LIBMPQ_EXT_TABLE_MAX_SIZE)
        return 0;
    if (libmpq__het_view_init(data, size, &het) == 0) {
        (void)libmpq__het_lookup(&het, "overview.txt", UINT32_MAX, match_candidate, NULL, &index);
        (void)libmpq__het_slot_index(&het, het.header.total_count - 1, &index);
    }
    if (libmpq__bet_view_init(data, size, &bet) == 0) {
        uint64_t indices[3] = { 0, bet.header.entry_count == 0 ? 0 : bet.header.entry_count - 1,
                                bet.header.entry_count };
        for (size_t i = 0; i < 3; i++) {
            mpq_bet_entry_s record;
            mpq_entry_s entry;
            uint64_t hash;
            (void)libmpq__bet_record_decode(&bet, indices[i], &record);
            if (libmpq__bet_name_hash2(&bet, indices[i], &hash) == 0)
                (void)libmpq__bet_entry_decode(&bet, indices[i], hash, &entry);
        }
    }
    return 0;
}
