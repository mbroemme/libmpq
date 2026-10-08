/*
 *  mpq-ext-table-builder.c -- Deterministic in-memory HET/BET construction.
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

#include "mpq-ext-table-builder.h"
#include "mpq-bit.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>
#include <stdlib.h>
#include <string.h>

static uint32_t
value_bits(uint64_t value)
{
    uint32_t width = 0;
    while (value != 0) {
        ++width;
        value >>= 1;
    }
    return width;
}

static int
compare_flags(const void *left, const void *right)
{
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;
    return (a > b) - (a < b);
}

static uint32_t
find_flag(const uint32_t *flags, uint32_t count, uint32_t value)
{
    uint32_t low = 0;
    uint32_t high = count;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2;
        if (flags[middle] < value)
            low = middle + 1;
        else
            high = middle;
    }
    return low;
}

void
libmpq__het_builder_free(mpq_het_builder_s *builder)
{
    if (builder != NULL) {
        free(builder->name_hash1);
        free(builder->index_bits);
        memset(builder, 0, sizeof(*builder));
    }
}

void
libmpq__bet_builder_free(mpq_bet_builder_s *builder)
{
    if (builder != NULL) {
        free(builder->flags);
        free(builder->records);
        free(builder->name_hash2);
        memset(builder, 0, sizeof(*builder));
    }
}

int32_t
libmpq__ext_tables_build(
    const mpq_ext_table_file_s *files, size_t count, mpq_het_builder_s *het, mpq_bet_builder_s *bet
)
{
    mpq_het_builder_s h = { 0 };
    mpq_bet_builder_s b = { 0 };
    mpq_bet_field_s *fields[5] = { &b.header.file_position, &b.header.file_size,
                                   &b.header.compressed_size, &b.header.flag_index,
                                   &b.header.unknown_field };
    uint64_t maximum[3] = { 0 };
    uint64_t *hashes = NULL;
    uint32_t *flags = NULL;
    uint32_t unique = 0;
    uint32_t record_bits = 0;
    uint64_t slots;
    uint64_t size;
    size_t i;
    int32_t result = LIBMPQ_ERROR_SIZE;

    /* NameHash2 alone needs seven bytes per row. Bound all work before input access. */
    if (het == NULL || bet == NULL || (count != 0 && files == NULL))
        return LIBMPQ_ERROR_EXIST;
    if (count > (LIBMPQ_EXT_TABLE_MAX_SIZE - 12u - 76u) / 7u)
        return LIBMPQ_ERROR_SIZE;

    /* Odd capacities, minimum three, with at most 75 percent occupancy. */
    slots = count + (count + 2u) / 3u;
    if (slots < 3)
        slots = 3;
    if ((slots & 1) == 0)
        ++slots;
    if (count != 0) {
        hashes = malloc(count * sizeof(*hashes));
        flags = malloc(count * sizeof(*flags));
        if (hashes == NULL || flags == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
    }
    for (i = 0; i < count; ++i) {
        uint64_t hash;
        mpq_het_hash_s parts;
        if (files[i].filename == NULL) {
            result = LIBMPQ_ERROR_EXIST;
            goto done;
        }
        if (files[i].packed_size > UINT64_MAX - files[i].offset) {
            result = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        result = libmpq__het_hash_filename(files[i].filename, &hash);
        if (result != 0)
            goto done;
        result = libmpq__het_hash_partition(hash, 64, (uint32_t)slots, &parts);
        if (result != 0)
            goto done;
        hashes[i] = parts.hash;
        flags[i] = files[i].flags;
        if (files[i].offset > maximum[0])
            maximum[0] = files[i].offset;
        if (files[i].unpacked_size > maximum[1])
            maximum[1] = files[i].unpacked_size;
        if (files[i].packed_size > maximum[2])
            maximum[2] = files[i].packed_size;
    }
    if (count != 0)
        qsort(flags, count, sizeof(*flags), compare_flags);
    for (i = 0; i < count; ++i)
        if (unique == 0 || flags[i] != flags[unique - 1])
            flags[unique++] = flags[i];
    for (i = 0; i < 5; ++i) {
        fields[i]->bit_index = record_bits;
        fields[i]->bit_count =
            i < 3 ? value_bits(maximum[i]) : (i == 3 && unique != 0 ? value_bits(unique - 1u) : 0);
        record_bits += fields[i]->bit_count;
    }
    b.header.table_entry_size = record_bits != 0 ? record_bits : 1;
    b.header.entry_count = (uint32_t)count;
    b.header.flag_count = unique;
    b.header.name_hash2_total = b.header.name_hash2_size = 56;
    b.header.flags.offset = 12u + LIBMPQ_BET_HEADER_WIRE_SIZE;
    b.header.flags.size = (size_t)unique * 4u;
    result = libmpq__bit_bytes(count, b.header.table_entry_size, &b.header.records.size);
    if (result != 0)
        goto done;
    result = libmpq__bit_bytes(count, 56, &b.header.name_hash2.size);
    if (result != 0)
        goto done;
    b.header.records.offset = b.header.flags.offset + b.header.flags.size;
    b.header.name_hash2.offset = b.header.records.offset + b.header.records.size;
    size = b.header.name_hash2.offset + (uint64_t)b.header.name_hash2.size;
    if (size > LIBMPQ_EXT_TABLE_MAX_SIZE) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    b.header.table_size = (uint32_t)(size - 12u);
    b.header.name_hash_array_size = (uint32_t)b.header.name_hash2.size;
    b.header.envelope.signature = LIBMPQ_BET_SIGNATURE;
    b.header.envelope.version = LIBMPQ_EXT_TABLE_VERSION;
    b.header.envelope.data_size = b.header.table_size;

    h.header.entry_count = (uint32_t)count;
    h.header.total_count = (uint32_t)slots;
    h.header.name_hash_bit_size = 64;
    h.header.index_size = count > 1 ? value_bits(count - 1) : 1;
    h.header.index_size_total = h.header.index_size;
    h.header.name_hash1.offset = 12u + LIBMPQ_HET_HEADER_WIRE_SIZE;
    h.header.name_hash1.size = (size_t)slots;
    h.header.indices.offset = h.header.name_hash1.offset + h.header.name_hash1.size;
    result = libmpq__bit_bytes(slots, h.header.index_size, &h.header.indices.size);
    if (result != 0)
        goto done;
    size = h.header.indices.offset + (uint64_t)h.header.indices.size;
    if (size > LIBMPQ_EXT_TABLE_MAX_SIZE) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    h.header.index_table_size = (uint32_t)h.header.indices.size;
    h.header.table_size = (uint32_t)(size - 12u);
    h.header.envelope.signature = LIBMPQ_HET_SIGNATURE;
    h.header.envelope.version = LIBMPQ_EXT_TABLE_VERSION;
    h.header.envelope.data_size = h.header.table_size;

    h.name_hash1 = calloc(h.header.name_hash1.size, 1);
    h.index_bits = calloc(h.header.indices.size, 1);
    if (unique != 0)
        b.flags = malloc(b.header.flags.size);
    if (count != 0) {
        b.records = calloc(b.header.records.size, 1);
        b.name_hash2 = calloc(b.header.name_hash2.size, 1);
    }
    if (h.name_hash1 == NULL || h.index_bits == NULL ||
        (count != 0 && (b.flags == NULL || b.records == NULL || b.name_hash2 == NULL))) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    for (i = 0; i < unique; ++i)
        libmpq__store_le32(b.flags + i * 4u, flags[i]);
    for (i = 0; i < count; ++i) {
        uint64_t values[5] = { files[i].offset, files[i].unpacked_size, files[i].packed_size,
                               find_flag(flags, unique, files[i].flags), 0 };
        size_t field;
        for (field = 0; field < 5; ++field) {
            result = libmpq__bit_set(
                b.records, b.header.records.size,
                (uint64_t)i * b.header.table_entry_size + fields[field]->bit_index,
                fields[field]->bit_count, values[field]
            );
            if (result != 0)
                goto done;
        }
        result = libmpq__bit_set(
            b.name_hash2, b.header.name_hash2.size, (uint64_t)i * 56, 56,
            hashes[i] & UINT64_C(0x00ffffffffffffff)
        );
        if (result != 0)
            goto done;
    }

    /* Reject indistinguishable full normalized hashes, including collisions and aliases. */
    for (i = 0; i < count; ++i) {
        uint32_t slot = (uint32_t)(hashes[i] % slots);
        uint32_t probes;
        for (probes = 0; probes < h.header.total_count; ++probes) {
            if (h.name_hash1[slot] == LIBMPQ_HET_SLOT_FREE)
                break;
            {
                uint64_t previous;
                result = libmpq__bit_get(
                    h.index_bits, h.header.indices.size, (uint64_t)slot * h.header.index_size_total,
                    h.header.index_size, &previous
                );
                if (result != 0)
                    goto done;
                if (previous >= count || hashes[previous] == hashes[i]) {
                    result = LIBMPQ_ERROR_EXIST;
                    goto done;
                }
            }
            slot = slot + 1 == h.header.total_count ? 0 : slot + 1;
        }
        if (probes == h.header.total_count) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        h.name_hash1[slot] = (uint8_t)(hashes[i] >> 56);
        result = libmpq__bit_set(
            h.index_bits, h.header.indices.size, (uint64_t)slot * h.header.index_size_total,
            h.header.index_size, i
        );
        if (result != 0)
            goto done;
    }
    libmpq__het_builder_free(het);
    libmpq__bet_builder_free(bet);
    *het = h;
    *bet = b;
    memset(&h, 0, sizeof(h));
    memset(&b, 0, sizeof(b));
    result = 0;
done:
    free(hashes);
    free(flags);
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    return result;
}
