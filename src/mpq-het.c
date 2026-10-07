/*
 *  mpq-het.c -- MPQ HET header decoding and validation.
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

#include "mpq-het.h"
#include "mpq-bit.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>

/* Decode and validate the HET layout without interpreting hashes or BET indices. */
int32_t
libmpq__het_header_decode(const uint8_t *input, size_t size, mpq_het_header_s *header)
{
    mpq_het_header_s decoded = { 0 };
    const uint8_t *wire;
    size_t index_bytes;
    size_t remaining;
    int32_t result;

    if (header == NULL)
        return LIBMPQ_ERROR_SIZE;
    result = libmpq__ext_table_decode(input, size, LIBMPQ_HET_SIGNATURE, &decoded.envelope);
    if (result != 0)
        return result;
    if (decoded.envelope.data_size < LIBMPQ_HET_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    wire = input + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
    decoded.table_size = libmpq__load_le32(wire);
    decoded.entry_count = libmpq__load_le32(wire + 4);
    decoded.total_count = libmpq__load_le32(wire + 8);
    decoded.name_hash_bit_size = libmpq__load_le32(wire + 12);
    decoded.index_size_total = libmpq__load_le32(wire + 16);
    decoded.index_size_extra = libmpq__load_le32(wire + 20);
    decoded.index_size = libmpq__load_le32(wire + 24);
    decoded.index_table_size = libmpq__load_le32(wire + 28);
    if (decoded.table_size < LIBMPQ_HET_HEADER_WIRE_SIZE ||
        decoded.table_size != decoded.envelope.data_size ||
        decoded.entry_count > decoded.total_count || decoded.name_hash_bit_size < 8 ||
        decoded.name_hash_bit_size > 64 || decoded.index_size_total > 64 ||
        decoded.index_size > decoded.index_size_total ||
        decoded.index_size_extra > decoded.index_size_total - decoded.index_size ||
        (decoded.total_count != 0 && decoded.index_size == 0))
        return LIBMPQ_ERROR_FORMAT;
    if (libmpq__bit_bytes(decoded.total_count, decoded.index_size_total, &index_bytes) != 0)
        return LIBMPQ_ERROR_SIZE;
    remaining = decoded.table_size - LIBMPQ_HET_HEADER_WIRE_SIZE;
    if (decoded.total_count > remaining)
        return LIBMPQ_ERROR_FORMAT;
    remaining -= decoded.total_count;
    if (decoded.index_table_size != remaining || index_bytes != decoded.index_table_size)
        return LIBMPQ_ERROR_FORMAT;
    decoded.name_hash1.offset = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + LIBMPQ_HET_HEADER_WIRE_SIZE;
    decoded.name_hash1.size = decoded.total_count;
    decoded.indices.offset = decoded.name_hash1.offset + decoded.name_hash1.size;
    decoded.indices.size = decoded.index_table_size;
    *header = decoded;
    return 0;
}

/* Rotate the fixed, nonzero lookup3 mixing distances in an unsigned word. */
static uint32_t
het_rotate(uint32_t value, uint32_t distance)
{
    return (value << distance) | (value >> (32 - distance));
}

/* Jenkins lookup3 reversible block mix (Bob Jenkins, public domain, May 2006). */
static void
het_mix(uint32_t state[3])
{
    state[0] -= state[2];
    state[0] ^= het_rotate(state[2], 4);
    state[2] += state[1];
    state[1] -= state[0];
    state[1] ^= het_rotate(state[0], 6);
    state[0] += state[2];
    state[2] -= state[1];
    state[2] ^= het_rotate(state[1], 8);
    state[1] += state[0];
    state[0] -= state[2];
    state[0] ^= het_rotate(state[2], 16);
    state[2] += state[1];
    state[1] -= state[0];
    state[1] ^= het_rotate(state[0], 19);
    state[0] += state[2];
    state[2] -= state[1];
    state[2] ^= het_rotate(state[1], 4);
    state[1] += state[0];
}

/* Jenkins lookup3 final avalanche; intentional unsigned wrap matches the format. */
static void
het_final(uint32_t state[3])
{
    state[2] ^= state[1];
    state[2] -= het_rotate(state[1], 14);
    state[0] ^= state[2];
    state[0] -= het_rotate(state[2], 11);
    state[1] ^= state[0];
    state[1] -= het_rotate(state[0], 25);
    state[2] ^= state[1];
    state[2] -= het_rotate(state[1], 16);
    state[0] ^= state[2];
    state[0] -= het_rotate(state[2], 4);
    state[1] ^= state[0];
    state[1] -= het_rotate(state[0], 14);
    state[2] ^= state[1];
    state[2] -= het_rotate(state[1], 24);
}

/* Hash exactly the locale-independent normalized byte prefix used by Storm. */
int32_t
libmpq__het_hash_filename(const char *filename, uint64_t *hash)
{
    uint8_t normalized[LIBMPQ_HET_FILENAME_LIMIT];
    uint32_t state[3];
    size_t length = 0;
    size_t remaining;
    size_t offset = 0;
    size_t i;

    if (hash == NULL)
        return LIBMPQ_ERROR_SIZE;
    *hash = 0;
    if (filename == NULL)
        return LIBMPQ_ERROR_EXIST;
    while (length < sizeof(normalized) && filename[length] != '\0') {
        uint8_t byte = (uint8_t)filename[length];

        if (byte >= 'A' && byte <= 'Z')
            byte = (uint8_t)(byte + ('a' - 'A'));
        if (byte == '/')
            byte = '\\';
        normalized[length++] = byte;
    }
    state[0] = 0xdeadbeefu + (uint32_t)length + 2u;
    state[1] = state[0];
    state[2] = state[0] + 1u;
    remaining = length;
    while (remaining > 12) {
        for (i = 0; i < 3; i++)
            state[i] += libmpq__load_le32(normalized + offset + i * 4);
        het_mix(state);
        offset += 12;
        remaining -= 12;
    }
    for (i = 0; i < remaining; i++)
        state[i / 4] += (uint32_t)normalized[offset + i] << ((i % 4) * 8);
    if (remaining != 0)
        het_final(state);
    *hash = ((uint64_t)state[1] << 32) | state[2];
    return 0;
}

/* Apply HET's declared hash width and forced high bit before splitting/probing. */
int32_t
libmpq__het_hash_partition(
    uint64_t hash, uint32_t hash_bits, uint32_t total_count, mpq_het_hash_s *parts
)
{
    uint64_t mask;

    if (parts == NULL)
        return LIBMPQ_ERROR_SIZE;
    *parts = (mpq_het_hash_s){ 0 };
    if (hash_bits < 8 || hash_bits > 64 || total_count == 0)
        return LIBMPQ_ERROR_FORMAT;
    mask = hash_bits == 64 ? UINT64_MAX : (UINT64_C(1) << hash_bits) - 1;
    parts->hash = (hash & mask) | (UINT64_C(1) << (hash_bits - 1));
    parts->name_hash1 = (uint8_t)(parts->hash >> (hash_bits - 8));
    parts->name_hash2 = parts->hash & ((UINT64_C(1) << (hash_bits - 8)) - 1);
    parts->initial_slot = (uint32_t)(parts->hash % total_count);
    return 0;
}

/* Validate view geometry before touching borrowed arrays, including mutated views. */
static int32_t
het_view_validate(const mpq_het_s *table)
{
    size_t bytes;
    const mpq_het_header_s *header;

    if (table == NULL)
        return LIBMPQ_ERROR_FORMAT;
    header = &table->header;
    if (header->total_count == 0 || header->entry_count > header->total_count ||
        header->name_hash_bit_size < 8 || header->name_hash_bit_size > 64 ||
        header->index_size == 0 || header->index_size_total > 64 ||
        header->index_size > header->index_size_total ||
        header->index_size_extra > header->index_size_total - header->index_size ||
        table->name_hash1 == NULL || table->name_hash1_size != header->total_count ||
        libmpq__bit_bytes(header->total_count, header->index_size_total, &bytes) != 0 ||
        table->index_bits == NULL || table->index_bits_size != bytes ||
        header->index_table_size != bytes)
        return LIBMPQ_ERROR_FORMAT;
    return 0;
}

/* Borrow only the ranges established by structural decoding; zero-slot views fail. */
int32_t
libmpq__het_view_init(const uint8_t *input, size_t size, mpq_het_s *table)
{
    mpq_het_s decoded = { 0 };
    int32_t result;

    if (table == NULL)
        return LIBMPQ_ERROR_SIZE;
    *table = decoded;
    result = libmpq__het_header_decode(input, size, &decoded.header);
    if (result != 0)
        return result;
    decoded.name_hash1 = input + decoded.header.name_hash1.offset;
    decoded.name_hash1_size = decoded.header.name_hash1.size;
    decoded.index_bits = input + decoded.header.indices.offset;
    decoded.index_bits_size = decoded.header.indices.size;
    result = het_view_validate(&decoded);
    if (result != 0)
        return result;
    *table = decoded;
    return 0;
}

/* Read the low effective bits at slot * total width; extra bits occupy the stride. */
int32_t
libmpq__het_slot_index(const mpq_het_s *table, uint32_t slot, uint64_t *index)
{
    uint64_t offset;

    if (index == NULL)
        return LIBMPQ_ERROR_SIZE;
    *index = 0;
    if (het_view_validate(table) != 0 || slot >= table->header.total_count)
        return LIBMPQ_ERROR_FORMAT;
    if (table->name_hash1[slot] == LIBMPQ_HET_SLOT_FREE)
        return LIBMPQ_ERROR_EXIST;
    if ((table->name_hash1[slot] & 0x80u) == 0)
        return LIBMPQ_ERROR_FORMAT;

    /* Both factors are bounded uint32_t values, with width at most 64. */
    offset = (uint64_t)slot * table->header.index_size_total;
    return libmpq__bit_get(
        table->index_bits, table->index_bits_size, offset, table->header.index_size, index
    );
}

/* Probe HET candidates and require lower-hash confirmation, without reading BET. */
int32_t
libmpq__het_lookup(
    const mpq_het_s *table, const char *filename, uint64_t bet_entry_count, mpq_het_match_fn match,
    void *context, uint64_t *index
)
{
    mpq_het_hash_s parts;
    uint64_t hash;
    uint32_t slot;
    uint32_t probes;
    int32_t result;

    if (index == NULL)
        return LIBMPQ_ERROR_SIZE;
    *index = 0;
    if (het_view_validate(table) != 0 || match == NULL)
        return LIBMPQ_ERROR_FORMAT;
    result = libmpq__het_hash_filename(filename, &hash);
    if (result != 0)
        return result;
    result = libmpq__het_hash_partition(
        hash, table->header.name_hash_bit_size, table->header.total_count, &parts
    );
    if (result != 0)
        return result;
    if (table->header.entry_count == 0)
        return LIBMPQ_ERROR_EXIST;
    slot = parts.initial_slot;
    for (probes = 0; probes < table->header.total_count; probes++) {
        uint8_t name_hash1 = table->name_hash1[slot];

        if (name_hash1 == LIBMPQ_HET_SLOT_FREE)
            return LIBMPQ_ERROR_EXIST;
        if ((name_hash1 & 0x80u) == 0)
            return LIBMPQ_ERROR_FORMAT;
        if (name_hash1 == parts.name_hash1) {
            uint64_t candidate;
            int matches = 0;

            result = libmpq__het_slot_index(table, slot, &candidate);
            if (result != 0)
                return result;
            if (candidate >= bet_entry_count)
                return LIBMPQ_ERROR_FORMAT;
            result = match(context, candidate, parts.name_hash2, &matches);
            if (result != 0)
                return result;
            if (matches != 0) {
                *index = candidate;
                return 0;
            }
        }
        slot = slot == table->header.total_count - 1 ? 0 : slot + 1;
    }
    return LIBMPQ_ERROR_EXIST;
}
