/*
 *  mpq-block.c -- MPQ block-table wire-format encoding and decoding.
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

#include "mpq-block.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>

/* Decode base entries without interpreting flags or file positions. */
int32_t
libmpq__block_table_decode(
    const uint8_t *input, size_t input_size, mpq_block_s *entries, size_t entry_count
)
{
    size_t i;

    if (entry_count > SIZE_MAX / LIBMPQ_BLOCK_ENTRY_WIRE_SIZE ||
        input_size < entry_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE ||
        (entry_count != 0 && (input == NULL || entries == NULL)))
        return LIBMPQ_ERROR_SIZE;

    for (i = 0; i < entry_count; i++) {
        const uint8_t *wire = input + i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;

        entries[i].offset = libmpq__load_le32(wire);
        entries[i].packed_size = libmpq__load_le32(wire + 4);
        entries[i].unpacked_size = libmpq__load_le32(wire + 8);
        entries[i].flags = libmpq__load_le32(wire + 12);
    }
    return 0;
}

/* Encode base entries into caller-owned bytes before table encryption. */
int32_t
libmpq__block_table_encode(
    const mpq_block_s *entries, size_t entry_count, uint8_t *output, size_t output_size
)
{
    size_t i;

    if (entry_count > SIZE_MAX / LIBMPQ_BLOCK_ENTRY_WIRE_SIZE ||
        output_size < entry_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE ||
        (entry_count != 0 && (entries == NULL || output == NULL)))
        return LIBMPQ_ERROR_SIZE;

    for (i = 0; i < entry_count; i++) {
        uint8_t *wire = output + i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;

        libmpq__store_le32(wire, entries[i].offset);
        libmpq__store_le32(wire + 4, entries[i].packed_size);
        libmpq__store_le32(wire + 8, entries[i].unpacked_size);
        libmpq__store_le32(wire + 12, entries[i].flags);
    }
    return 0;
}

/* Decode the optional v2 high-offset words without changing their values. */
int32_t
libmpq__block_ex_table_decode(
    const uint8_t *input, size_t input_size, mpq_block_ex_s *entries, size_t entry_count
)
{
    size_t i;

    if (entry_count > SIZE_MAX / LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE ||
        input_size < entry_count * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE ||
        (entry_count != 0 && (input == NULL || entries == NULL)))
        return LIBMPQ_ERROR_SIZE;

    for (i = 0; i < entry_count; i++)
        entries[i].offset_high = libmpq__load_le16(input + i * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE);
    return 0;
}

/* Encode the optional v2 high-offset words in little-endian order. */
int32_t
libmpq__block_ex_table_encode(
    const mpq_block_ex_s *entries, size_t entry_count, uint8_t *output, size_t output_size
)
{
    size_t i;

    if (entry_count > SIZE_MAX / LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE ||
        output_size < entry_count * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE ||
        (entry_count != 0 && (entries == NULL || output == NULL)))
        return LIBMPQ_ERROR_SIZE;

    for (i = 0; i < entry_count; i++)
        libmpq__store_le16(output + i * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE, entries[i].offset_high);
    return 0;
}
