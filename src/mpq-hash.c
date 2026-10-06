/*
 *  mpq-hash.c -- MPQ hash-table wire-format encoding and decoding.
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

#include "mpq-hash.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>

/* Decode fixed-size entries without interpreting slot or block-index semantics. */
int32_t
libmpq__hash_table_decode(
    const uint8_t *input, size_t input_size, mpq_hash_s *entries, size_t entry_count
)
{
    size_t i;

    if (entry_count > SIZE_MAX / LIBMPQ_HASH_ENTRY_WIRE_SIZE ||
        input_size < entry_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE ||
        (entry_count != 0 && (input == NULL || entries == NULL)))
        return LIBMPQ_ERROR_SIZE;

    for (i = 0; i < entry_count; i++) {
        const uint8_t *wire = input + i * LIBMPQ_HASH_ENTRY_WIRE_SIZE;

        entries[i].hash_a = libmpq__load_le32(wire);
        entries[i].hash_b = libmpq__load_le32(wire + 4);
        entries[i].locale = libmpq__load_le16(wire + 8);
        entries[i].platform = libmpq__load_le16(wire + 10);
        entries[i].block_table_index = libmpq__load_le32(wire + 12);
    }
    return 0;
}

/* Encode native entries into caller-owned wire bytes before table encryption. */
int32_t
libmpq__hash_table_encode(
    const mpq_hash_s *entries, size_t entry_count, uint8_t *output, size_t output_size
)
{
    size_t i;

    if (entry_count > SIZE_MAX / LIBMPQ_HASH_ENTRY_WIRE_SIZE ||
        output_size < entry_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE ||
        (entry_count != 0 && (entries == NULL || output == NULL)))
        return LIBMPQ_ERROR_SIZE;

    for (i = 0; i < entry_count; i++) {
        uint8_t *wire = output + i * LIBMPQ_HASH_ENTRY_WIRE_SIZE;

        libmpq__store_le32(wire, entries[i].hash_a);
        libmpq__store_le32(wire + 4, entries[i].hash_b);
        libmpq__store_le16(wire + 8, entries[i].locale);
        libmpq__store_le16(wire + 10, entries[i].platform);
        libmpq__store_le32(wire + 12, entries[i].block_table_index);
    }
    return 0;
}
