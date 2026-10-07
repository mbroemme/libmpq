/*
 *  mpq-bet.c -- MPQ BET header decoding and validation.
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
#include "mpq-bit.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Check individual fields and reject overlapping nonempty record domains. */
static int32_t
bet_fields_validate(const mpq_bet_field_s *fields, uint32_t record_size)
{
    size_t i;
    size_t j;

    for (i = 0; i < 5; i++) {
        if (fields[i].bit_count > 64 || fields[i].bit_index > record_size ||
            fields[i].bit_count > record_size - fields[i].bit_index)
            return LIBMPQ_ERROR_FORMAT;
        for (j = 0; j < i; j++) {
            if (fields[i].bit_count != 0 && fields[j].bit_count != 0 &&
                fields[i].bit_index < fields[j].bit_index + fields[j].bit_count &&
                fields[j].bit_index < fields[i].bit_index + fields[i].bit_count)
                return LIBMPQ_ERROR_FORMAT;
        }
    }
    return 0;
}

/* Recheck geometry for defensive use of caller-owned views, without reading payload. */
static int32_t
bet_view_validate(const mpq_bet_s *table)
{
    size_t bytes;
    mpq_bet_field_s fields[5];

    if (table == NULL)
        return LIBMPQ_ERROR_SIZE;
    fields[0] = table->header.file_position;
    fields[1] = table->header.file_size;
    fields[2] = table->header.compressed_size;
    fields[3] = table->header.flag_index;
    fields[4] = table->header.unknown_field;
    if (table->header.table_entry_size == 0 ||
        bet_fields_validate(fields, table->header.table_entry_size) != 0 ||
        table->header.name_hash2_total > 64 ||
        table->header.name_hash2_size > table->header.name_hash2_total ||
        table->header.name_hash2_extra >
            table->header.name_hash2_total - table->header.name_hash2_size ||
        (table->header.entry_count != 0 &&
         (table->header.flag_count == 0 || table->header.name_hash2_size == 0)) ||
        table->header.flag_index.bit_count > 32)
        return LIBMPQ_ERROR_FORMAT;
    if (libmpq__bit_bytes(table->header.entry_count, table->header.table_entry_size, &bytes) != 0 ||
        bytes != table->records_size || (bytes != 0 && table->records == NULL))
        return LIBMPQ_ERROR_SIZE;
    if (libmpq__bit_bytes(table->header.entry_count, table->header.name_hash2_total, &bytes) != 0 ||
        bytes != table->name_hash2_size || (bytes != 0 && table->name_hash2 == NULL))
        return LIBMPQ_ERROR_SIZE;
    if (libmpq__bit_bytes(table->header.flag_count, 32, &bytes) != 0 ||
        bytes != table->flags_size || (bytes != 0 && table->flags == NULL))
        return LIBMPQ_ERROR_SIZE;
    return 0;
}

int32_t
libmpq__bet_view_init(const uint8_t *input, size_t size, mpq_bet_s *table)
{
    mpq_bet_s decoded = { 0 };
    int32_t result;

    if (table == NULL)
        return LIBMPQ_ERROR_SIZE;
    memset(table, 0, sizeof(*table));
    result = libmpq__bet_header_decode(input, size, &decoded.header);
    if (result != 0)
        return result;
    decoded.flags = input + decoded.header.flags.offset;
    decoded.flags_size = decoded.header.flags.size;
    decoded.records = input + decoded.header.records.offset;
    decoded.records_size = decoded.header.records.size;
    decoded.name_hash2 = input + decoded.header.name_hash2.offset;
    decoded.name_hash2_size = decoded.header.name_hash2.size;
    *table = decoded;
    return 0;
}

int32_t
libmpq__bet_name_hash2(const mpq_bet_s *table, uint64_t index, uint64_t *hash)
{
    int32_t result;

    if (hash == NULL)
        return LIBMPQ_ERROR_SIZE;
    *hash = 0;
    result = bet_view_validate(table);
    if (result != 0)
        return result;
    if (index >= table->header.entry_count)
        return LIBMPQ_ERROR_EXIST;

    /* Both factors are bounded by uint32_t (stride additionally by 64). */
    return libmpq__bit_get(
        table->name_hash2, table->name_hash2_size, index * table->header.name_hash2_total,
        table->header.name_hash2_size, hash
    );
}

int32_t
libmpq__bet_record_decode(const mpq_bet_s *table, uint64_t index, mpq_bet_entry_s *entry)
{
    mpq_bet_entry_s decoded = { 0 };
    mpq_bet_field_s fields[5];
    uint64_t values[5];
    uint64_t base;
    size_t i;
    int32_t result;

    if (entry == NULL)
        return LIBMPQ_ERROR_SIZE;
    memset(entry, 0, sizeof(*entry));
    result = bet_view_validate(table);
    if (result != 0)
        return result;
    if (index >= table->header.entry_count)
        return LIBMPQ_ERROR_EXIST;
    fields[0] = table->header.file_position;
    fields[1] = table->header.file_size;
    fields[2] = table->header.compressed_size;
    fields[3] = table->header.flag_index;
    fields[4] = table->header.unknown_field;

    /* uint32_t index/count and record width bound the product and field sums. */
    base = index * table->header.table_entry_size;
    for (i = 0; i < 5; i++) {
        result = libmpq__bit_get(
            table->records, table->records_size, base + fields[i].bit_index, fields[i].bit_count,
            &values[i]
        );
        if (result != 0)
            return result;
    }
    if (values[3] >= table->header.flag_count)
        return LIBMPQ_ERROR_FORMAT;
    decoded.offset = values[0];
    decoded.unpacked_size = values[1];
    decoded.packed_size = values[2];
    decoded.flag_index = values[3];
    decoded.unknown = values[4];
    decoded.flags = libmpq__load_le32(table->flags + (size_t)values[3] * 4);
    result = libmpq__bet_name_hash2(table, index, &decoded.name_hash2);
    if (result != 0)
        return result;
    *entry = decoded;
    return 0;
}

int32_t
libmpq__bet_match(void *context, uint64_t index, uint64_t expected, int *matches)
{
    const mpq_bet_s *table = context;
    uint64_t actual;
    uint64_t mask;
    int32_t result;

    if (matches == NULL)
        return LIBMPQ_ERROR_SIZE;
    *matches = 0;
    result = libmpq__bet_name_hash2(table, index, &actual);
    if (result != 0)
        return result;
    mask = table->header.name_hash2_size == 64 ? UINT64_MAX
                                               : (UINT64_C(1) << table->header.name_hash2_size) - 1;
    *matches = actual == (expected & mask);
    return 0;
}

int32_t
libmpq__bet_entry_decode(
    const mpq_bet_s *table, uint64_t index, uint64_t expected, mpq_entry_s *entry
)
{
    mpq_bet_entry_s decoded;
    int matches;
    int32_t result;

    if (entry == NULL)
        return LIBMPQ_ERROR_SIZE;
    memset(entry, 0, sizeof(*entry));
    entry->classic_source_index = UINT32_MAX;
    entry->bet_source_index = UINT32_MAX;
    result = libmpq__bet_match((void *)table, index, expected, &matches);
    if (result != 0)
        return result;
    if (!matches)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__bet_record_decode(table, index, &decoded);
    if (result != 0)
        return result;
    entry->offset = decoded.offset;
    entry->unpacked_size = decoded.unpacked_size;
    entry->packed_size = decoded.packed_size;
    entry->flags = decoded.flags;
    entry->source_mask = LIBMPQ_ENTRY_SOURCE_BET;
    entry->bet_source_index = (uint32_t)index;
    entry->file_number = UINT32_MAX;
    return 0;
}

/* Decode complete BET metadata and bound all arrays without interpreting entries. */
int32_t
libmpq__bet_header_decode(const uint8_t *input, size_t size, mpq_bet_header_s *header)
{
    mpq_bet_header_s decoded = { 0 };
    mpq_bet_field_s fields[5];
    const uint8_t *wire;
    size_t record_bytes;
    size_t hash_bytes;
    size_t flag_bytes;
    size_t remaining;
    size_t i;
    int32_t result;

    if (header == NULL)
        return LIBMPQ_ERROR_SIZE;
    result = libmpq__ext_table_decode(input, size, LIBMPQ_BET_SIGNATURE, &decoded.envelope);
    if (result != 0)
        return result;
    if (decoded.envelope.data_size < LIBMPQ_BET_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    wire = input + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
    decoded.table_size = libmpq__load_le32(wire);
    decoded.entry_count = libmpq__load_le32(wire + 4);
    decoded.unknown = libmpq__load_le32(wire + 8);
    decoded.table_entry_size = libmpq__load_le32(wire + 12);
    for (i = 0; i < 5; i++) {
        fields[i].bit_index = libmpq__load_le32(wire + 16 + i * 4);
        fields[i].bit_count = libmpq__load_le32(wire + 36 + i * 4);
    }
    decoded.file_position = fields[0];
    decoded.file_size = fields[1];
    decoded.compressed_size = fields[2];
    decoded.flag_index = fields[3];
    decoded.unknown_field = fields[4];
    decoded.name_hash2_total = libmpq__load_le32(wire + 56);
    decoded.name_hash2_extra = libmpq__load_le32(wire + 60);
    decoded.name_hash2_size = libmpq__load_le32(wire + 64);
    decoded.name_hash_array_size = libmpq__load_le32(wire + 68);
    decoded.flag_count = libmpq__load_le32(wire + 72);
    if (decoded.table_size < LIBMPQ_BET_HEADER_WIRE_SIZE ||
        decoded.table_size != decoded.envelope.data_size || decoded.table_entry_size == 0 ||
        bet_fields_validate(fields, decoded.table_entry_size) != 0 ||
        decoded.name_hash2_total > 64 || decoded.name_hash2_size > decoded.name_hash2_total ||
        decoded.name_hash2_extra > decoded.name_hash2_total - decoded.name_hash2_size ||
        (decoded.entry_count != 0 && (decoded.flag_count == 0 || decoded.name_hash2_size == 0)) ||
        decoded.flag_index.bit_count > 32 ||
        (decoded.flag_index.bit_count < 32 &&
         (uint64_t)decoded.flag_count > (UINT64_C(1) << decoded.flag_index.bit_count)))
        return LIBMPQ_ERROR_FORMAT;
    if (libmpq__bit_bytes(decoded.entry_count, decoded.table_entry_size, &record_bytes) != 0 ||
        libmpq__bit_bytes(decoded.entry_count, decoded.name_hash2_total, &hash_bytes) != 0 ||
        libmpq__bit_bytes(decoded.flag_count, 32, &flag_bytes) != 0)
        return LIBMPQ_ERROR_SIZE;
    remaining = decoded.table_size - LIBMPQ_BET_HEADER_WIRE_SIZE;
    if (flag_bytes > remaining)
        return LIBMPQ_ERROR_FORMAT;
    remaining -= flag_bytes;
    if (record_bytes > remaining)
        return LIBMPQ_ERROR_FORMAT;
    remaining -= record_bytes;
    if (decoded.name_hash_array_size != remaining || hash_bytes != remaining)
        return LIBMPQ_ERROR_FORMAT;
    decoded.flags.offset = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + LIBMPQ_BET_HEADER_WIRE_SIZE;
    decoded.flags.size = flag_bytes;
    decoded.records.offset = decoded.flags.offset + flag_bytes;
    decoded.records.size = record_bytes;
    decoded.name_hash2.offset = decoded.records.offset + record_bytes;
    decoded.name_hash2.size = decoded.name_hash_array_size;
    *header = decoded;
    return 0;
}
