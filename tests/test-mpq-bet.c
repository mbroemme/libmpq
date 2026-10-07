/*
 *  test-mpq-bet.c -- Synthetic MPQ BET header regression tests.
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

#include "../src/mpq-bet.h"
#include "../src/mpq-bit.h"
#include "../src/mpq-endian.h"
#include "../src/mpq-het.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Explicit metadata uses 64-bit positions and unaligned 83-bit records. */
static const uint8_t valid_bet[118] = {
    'B', 'E', 'T', 0x1a, 1,  0, 0, 0, 106, 0, 0,  0, 106, 0, 0,  0, 2, 0, 0,  0, 0x10, 0,
    0,   0,   83,  0,    0,  0, 0, 0, 0,   0, 64, 0, 0,   0, 73, 0, 0, 0, 82, 0, 0,    0,
    83,  0,   0,   0,    64, 0, 0, 0, 9,   0, 0,  0, 9,   0, 0,  0, 1, 0, 0,  0, 0,    0,
    0,   0,   3,   0,    0,  0, 0, 0, 0,   0, 3,  0, 0,   0, 1,  0, 0, 0, 2,  0, 0,    0
};

/* Decode all fields, including reserved metadata, and identify the physical ranges. */
static int
test_valid(void)
{
    mpq_bet_header_s header;
    uint8_t wire[sizeof(valid_bet)];

    TEST_CHECK(libmpq__bet_header_decode(valid_bet, sizeof(valid_bet), &header) == 0);
    TEST_CHECK(header.table_size == 106 && header.entry_count == 2 && header.unknown == 0x10);
    TEST_CHECK(header.table_entry_size == 83 && header.file_position.bit_count == 64);
    TEST_CHECK(header.file_position.bit_index == 0 && header.file_size.bit_index == 64);
    TEST_CHECK(header.file_size.bit_count == 9 && header.compressed_size.bit_index == 73);
    TEST_CHECK(header.compressed_size.bit_count == 9 && header.flag_index.bit_index == 82);
    TEST_CHECK(
        header.flag_index.bit_count == 1 && header.unknown_field.bit_index == 83 &&
        header.unknown_field.bit_count == 0
    );
    TEST_CHECK(
        header.name_hash2_total == 3 && header.name_hash2_extra == 0 &&
        header.name_hash2_size == 3 && header.name_hash_array_size == 1
    );
    TEST_CHECK(header.flag_count == 2 && header.flags.offset == 88 && header.flags.size == 8);
    TEST_CHECK(header.records.offset == 96 && header.records.size == 21);
    TEST_CHECK(header.name_hash2.offset == 117 && header.name_hash2.size == 1);
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 24, 84);
    libmpq__store_le32(wire + 64, 1);
    libmpq__store_le32(wire + 72, 1);
    libmpq__store_le32(wire + 76, 2);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == 0);
    TEST_CHECK(header.unknown_field.bit_count == 1 && header.name_hash2_extra == 1);
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 8, 76);
    libmpq__store_le32(wire + 12, 76);
    libmpq__store_le32(wire + 16, 0);
    libmpq__store_le32(wire + 80, 0);
    libmpq__store_le32(wire + 84, 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, 88, &header) == 0);
    TEST_CHECK(header.flags.size == 0 && header.records.size == 0 && header.name_hash2.size == 0);
    return 0;
}

/* Reject truncated arrays, overlapping fields, impossible widths and huge counts. */
static int
test_invalid(void)
{
    static const struct
    {
        size_t offset;
        uint32_t value;
    } mutations[] = { { 0, LIBMPQ_HET_SIGNATURE },
                      { 4, 2 },
                      { 8, 75 },
                      { 8, UINT32_MAX },
                      { 12, 75 },
                      { 12, 107 },
                      { 24, 0 },
                      { 24, UINT32_MAX },
                      { 28, 84 },
                      { 28, UINT32_MAX },
                      { 32, 63 },
                      { 36, 83 },
                      { 44, 84 },
                      { 48, 65 },
                      { 52, 10 },
                      { 60, 2 },
                      { 64, 1 },
                      { 68, 65 },
                      { 72, 4 },
                      { 76, 4 },
                      { 76, 0 },
                      { 80, 0 },
                      { 80, UINT32_MAX },
                      { 84, 0 },
                      { 84, 3 },
                      { 84, UINT32_MAX },
                      { 16, UINT32_MAX } };
    uint8_t wire[sizeof(valid_bet)];
    mpq_bet_header_s header;
    size_t i;

    for (i = 0; i < sizeof(valid_bet); i++)
        TEST_CHECK(libmpq__bet_header_decode(valid_bet, i, &header) != 0);
    for (i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
        memcpy(wire, valid_bet, sizeof(wire));
        libmpq__store_le32(wire + mutations[i].offset, mutations[i].value);
        TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);
    }
    for (i = 0; i < 5; i++) {
        memcpy(wire, valid_bet, sizeof(wire));
        libmpq__store_le32(wire + 28 + i * 4, UINT32_MAX);
        TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);
        memcpy(wire, valid_bet, sizeof(wire));
        libmpq__store_le32(wire + 48 + i * 4, 65);
        TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);
    }

    /* Wide flag indices reach the array-size guard rather than the width guard. */
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 24, 114);
    libmpq__store_le32(wire + 44, 114);
    libmpq__store_le32(wire + 60, 32);
    libmpq__store_le32(wire + 84, UINT32_MAX);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);

    /* The product is wider than DWORD arithmetic even though neither factor is. */
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 16, UINT32_MAX);
    libmpq__store_le32(wire + 24, UINT32_MAX);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) != 0);

    /* Three three-bit hashes exceed the one-byte NameHash2 array by one bit. */
    memcpy(wire, valid_bet, sizeof(wire));
    libmpq__store_le32(wire + 16, 3);
    libmpq__store_le32(wire + 8, 117);
    libmpq__store_le32(wire + 12, 117);
    {
        uint8_t expanded[129] = { 0 };

        memcpy(expanded, wire, sizeof(wire));
        TEST_CHECK(libmpq__bet_header_decode(expanded, sizeof(expanded), &header) != 0);
    }
    TEST_CHECK(libmpq__bet_header_decode(NULL, sizeof(valid_bet), &header) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_header_decode(valid_bet, sizeof(valid_bet), NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Reject surplus declared payload and hash padding despite complete buffers. */
static int
test_exact_sizes(void)
{
    uint8_t wire[sizeof(valid_bet) + 1] = { 0 };
    mpq_ext_table_header_s envelope;
    mpq_bet_header_s header;

    memcpy(wire, valid_bet, sizeof(valid_bet));
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == 0);

    /* The extra byte belongs to the envelope, but not to the declared BET table. */
    libmpq__store_le32(wire + 8, 107);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_BET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);

    /* Matching table sizes still cannot pad the one-byte packed NameHash2 array. */
    libmpq__store_le32(wire + 12, 107);
    libmpq__store_le32(wire + 80, 2);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_BET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

/* Three unaligned, deliberately reordered records, with full-width metadata. */
static int
make_records(uint8_t *wire, size_t capacity, uint32_t hash_width, mpq_bet_s *table)
{
    static const uint32_t positions[5] = { 3, 67, 131, 0, 195 };
    static const uint32_t widths[5] = { 64, 64, 64, 2, 3 };
    size_t hash_bytes;
    size_t size;
    size_t i;
    size_t j;

    TEST_CHECK(libmpq__bit_bytes(3, hash_width == 64 ? 64 : 9, &hash_bytes) == 0);
    size = 88 + 12 + 75 + hash_bytes;
    TEST_CHECK(size <= capacity);
    memset(wire, 0, capacity);
    libmpq__store_le32(wire, LIBMPQ_BET_SIGNATURE);
    libmpq__store_le32(wire + 4, 1);
    libmpq__store_le32(wire + 8, (uint32_t)size - 12);
    libmpq__store_le32(wire + 12, (uint32_t)size - 12);
    libmpq__store_le32(wire + 16, 3);
    libmpq__store_le32(wire + 24, 198);
    for (i = 0; i < 5; i++) {
        libmpq__store_le32(wire + 28 + i * 4, positions[i]);
        libmpq__store_le32(wire + 48 + i * 4, widths[i]);
    }
    libmpq__store_le32(wire + 68, hash_width == 64 ? 64 : 9);
    libmpq__store_le32(wire + 72, hash_width == 64 ? 0 : 2);
    libmpq__store_le32(wire + 76, hash_width);
    libmpq__store_le32(wire + 80, (uint32_t)hash_bytes);
    libmpq__store_le32(wire + 84, 3);
    for (i = 0; i < 3; i++) {
        uint64_t values[5] = { UINT64_MAX - i, UINT64_C(0x123456789abcdef0) + i,
                               UINT64_C(0xfedcba9876543210) - i, i, i + 1 };

        libmpq__store_le32(wire + 88 + i * 4, UINT32_C(0x80000200) + (uint32_t)i);
        for (j = 0; j < 5; j++)
            TEST_CHECK(
                libmpq__bit_set(wire + 100, 75, i * 198 + positions[j], widths[j], values[j]) == 0
            );
        TEST_CHECK(
            libmpq__bit_set(
                wire + 175, hash_bytes, i * (hash_width == 64 ? 64 : 9), hash_width,
                hash_width == 64 ? UINT64_MAX - i : 0x51 + i
            ) == 0
        );
        if (hash_width != 64)
            TEST_CHECK(libmpq__bit_set(wire + 175, hash_bytes, i * 9 + 7, 2, 3) == 0);
    }
    TEST_CHECK(libmpq__bet_view_init(wire, size, table) == 0);
    return 0;
}

/* Decode exact values without archive state or classic-table storage. */
static int
test_records(void)
{
    static const uint8_t explicit_record[11] = { 8, 7, 6, 5, 4, 3, 2, 1, 1, 5, 6 };
    uint8_t wire[256];
    mpq_bet_s table;
    mpq_bet_entry_s record;
    mpq_entry_s entry;
    uint64_t hash;
    uint64_t i;
    int matches;

    /* Independent packed vector, not produced by the bit writer under test. */
    memcpy(wire, valid_bet, sizeof(valid_bet));
    memcpy(wire + 96, explicit_record, sizeof(explicit_record));
    libmpq__store_le32(wire + 92, UINT32_C(0x89abcdef));
    TEST_CHECK(libmpq__bet_view_init(wire, sizeof(valid_bet), &table) == 0);
    TEST_CHECK(libmpq__bet_record_decode(&table, 0, &record) == 0);
    TEST_CHECK(record.offset == UINT64_C(0x0102030405060708));
    TEST_CHECK(record.unpacked_size == 257 && record.packed_size == 258);
    TEST_CHECK(record.flag_index == 1 && record.flags == UINT32_C(0x89abcdef));
    TEST_CHECK(record.unknown == 0 && record.name_hash2 == 0);

    TEST_CHECK(make_records(wire, sizeof(wire), 7, &table) == 0);
    TEST_CHECK(table.flags == wire + 88 && table.records == wire + 100);
    for (i = 0; i < 3; i++) {
        TEST_CHECK(libmpq__bet_record_decode(&table, i, &record) == 0);
        TEST_CHECK(record.offset == UINT64_MAX - i);
        TEST_CHECK(record.unpacked_size == UINT64_C(0x123456789abcdef0) + i);
        TEST_CHECK(record.packed_size == UINT64_C(0xfedcba9876543210) - i);
        TEST_CHECK(record.flag_index == i && record.unknown == i + 1);
        TEST_CHECK(record.flags == UINT32_C(0x80000200) + i);
        TEST_CHECK(record.name_hash2 == 0x51 + i);
        TEST_CHECK(libmpq__bet_name_hash2(&table, i, &hash) == 0 && hash == 0x51 + i);
        TEST_CHECK(libmpq__bet_match(&table, i, 0x51 + i + 0x100, &matches) == 0 && matches);
        TEST_CHECK(libmpq__bet_entry_decode(&table, i, 0x51 + i, &entry) == 0);
        TEST_CHECK(entry.offset == record.offset && entry.packed_size == record.packed_size);
        TEST_CHECK(entry.unpacked_size == record.unpacked_size && entry.flags == record.flags);
        TEST_CHECK(entry.source_mask == LIBMPQ_ENTRY_SOURCE_BET && entry.bet_source_index == i);
        TEST_CHECK(entry.classic_source_index == UINT32_MAX);
        TEST_CHECK(entry.file_number == UINT32_MAX);
        TEST_CHECK(libmpq__bet_entry_decode(&table, i, 0x50 + i, &entry) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(entry.source_mask == LIBMPQ_ENTRY_SOURCE_NONE && entry.offset == 0);
    }
    libmpq__store_le32(wire + 64, 0);
    TEST_CHECK(libmpq__bet_view_init(wire, 179, &table) == 0);
    TEST_CHECK(libmpq__bet_record_decode(&table, 2, &record) == 0 && record.unknown == 0);
    TEST_CHECK(make_records(wire, sizeof(wire), 64, &table) == 0);
    TEST_CHECK(libmpq__bet_name_hash2(&table, 2, &hash) == 0 && hash == UINT64_MAX - 2);
    TEST_CHECK(libmpq__bet_entry_decode(&table, 2, hash, &entry) == 0);
    return 0;
}

/* Damaged borrowed views and impossible indices never access payload bytes. */
static int
test_record_errors(void)
{
    uint8_t wire[256];
    mpq_bet_s table;
    mpq_bet_s damaged;
    mpq_bet_entry_s record;
    mpq_entry_s entry;
    uint64_t hash = 1;
    int matches = 1;

    TEST_CHECK(make_records(wire, sizeof(wire), 7, &table) == 0);
    TEST_CHECK(libmpq__bet_record_decode(&table, 3, &record) == LIBMPQ_ERROR_EXIST);

    /* Reject huge indices before any record/hash offset multiplication. */
    TEST_CHECK(libmpq__bet_record_decode(&table, UINT64_MAX, &record) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__bet_name_hash2(&table, UINT64_MAX, &hash) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(hash == 0);
    TEST_CHECK(libmpq__bit_set(wire + 100, 75, 198, 2, 3) == 0);
    TEST_CHECK(libmpq__bet_record_decode(&table, 1, &record) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(record.offset == 0 && record.flags == 0);
    damaged = table;
    damaged.records_size--;
    TEST_CHECK(libmpq__bet_record_decode(&damaged, 0, &record) == LIBMPQ_ERROR_SIZE);
    damaged = table;
    damaged.name_hash2_size--;
    TEST_CHECK(libmpq__bet_name_hash2(&damaged, 0, &hash) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_record_decode(&damaged, 0, &record) == LIBMPQ_ERROR_SIZE);
    damaged = table;
    damaged.flags_size--;
    TEST_CHECK(libmpq__bet_record_decode(&damaged, 0, &record) == LIBMPQ_ERROR_SIZE);
    damaged = table;
    damaged.records = NULL;
    TEST_CHECK(libmpq__bet_record_decode(&damaged, 0, &record) != 0);
    damaged = table;
    damaged.header.file_position.bit_count = 65;
    TEST_CHECK(libmpq__bet_record_decode(&damaged, 0, &record) == LIBMPQ_ERROR_FORMAT);
    damaged = table;
    damaged.header.name_hash2_total = 65;
    TEST_CHECK(libmpq__bet_name_hash2(&damaged, 0, &hash) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__bet_record_decode(NULL, 0, &record) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_record_decode(&table, 0, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_name_hash2(&table, 0, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_match(NULL, 0, 0, &matches) == LIBMPQ_ERROR_SIZE && !matches);
    TEST_CHECK(libmpq__bet_match(&table, 0, 0, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_entry_decode(NULL, 0, 0, &entry) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_entry_decode(&table, 0, 0, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bet_view_init(NULL, 0, &table) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(table.records == NULL);
    TEST_CHECK(libmpq__bet_view_init(wire, sizeof(wire), NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Entire filename-to-entry pipeline stays in decoded memory, not archive opening. */
static int
test_het_bet(void)
{
    uint8_t wire[256];
    uint8_t het_wire[47] = { 0 };
    mpq_bet_s bet;
    mpq_het_s het;
    mpq_het_hash_s parts;
    mpq_entry_s entry;
    uint64_t hash;
    uint64_t index;

    TEST_CHECK(make_records(wire, sizeof(wire), 7, &bet) == 0);
    TEST_CHECK(libmpq__het_hash_filename("synthetic/path.bin", &hash) == 0);
    TEST_CHECK(libmpq__het_hash_partition(hash, 15, 2, &parts) == 0);
    TEST_CHECK(libmpq__bit_set(wire + 175, 4, 9, 7, parts.name_hash2) == 0);
    libmpq__store_le32(het_wire, LIBMPQ_HET_SIGNATURE);
    libmpq__store_le32(het_wire + 4, 1);
    libmpq__store_le32(het_wire + 8, 35);
    libmpq__store_le32(het_wire + 12, 35);
    libmpq__store_le32(het_wire + 16, 1);
    libmpq__store_le32(het_wire + 20, 2);
    libmpq__store_le32(het_wire + 24, 15);
    libmpq__store_le32(het_wire + 28, 2);
    libmpq__store_le32(het_wire + 36, 2);
    libmpq__store_le32(het_wire + 40, 1);
    het_wire[44 + parts.initial_slot] = parts.name_hash1;
    TEST_CHECK(libmpq__bit_set(het_wire + 46, 1, parts.initial_slot * 2, 2, 1) == 0);
    TEST_CHECK(libmpq__het_view_init(het_wire, sizeof(het_wire), &het) == 0);
    TEST_CHECK(
        libmpq__het_lookup(&het, "SYNTHETIC\\PATH.BIN", 3, libmpq__bet_match, &bet, &index) == 0
    );
    TEST_CHECK(index == 1);
    TEST_CHECK(libmpq__bet_entry_decode(&bet, index, parts.name_hash2, &entry) == 0);
    TEST_CHECK(entry.source_mask == LIBMPQ_ENTRY_SOURCE_BET && entry.bet_source_index == 1);
    TEST_CHECK(entry.offset == UINT64_MAX - 1 && entry.file_number == UINT32_MAX);
    return 0;
}

/* Run isolated synthetic BET structural tests. */
int
main(void)
{
    TEST_CHECK(test_valid() == 0);
    TEST_CHECK(test_invalid() == 0);
    TEST_CHECK(test_exact_sizes() == 0);
    TEST_CHECK(test_records() == 0);
    TEST_CHECK(test_record_errors() == 0);
    TEST_CHECK(test_het_bet() == 0);
    return 0;
}
