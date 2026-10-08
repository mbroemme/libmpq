/*
 *  test-mpq-ext-table-builder.c -- Synthetic owned HET/BET builder tests.
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

#include "../src/mpq-bit.h"
#include "../src/mpq-endian.h"
#include "../src/mpq-ext-table-builder.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* HET emission remains test-only; production HET serialization is not enabled. */
static uint8_t *
het_wire(const mpq_het_builder_s *h)
{
    uint8_t *wire = calloc(12u + h->header.table_size, 1);
    uint32_t values[11] = { LIBMPQ_HET_SIGNATURE,         1,
                            h->header.table_size,         h->header.table_size,
                            h->header.entry_count,        h->header.total_count,
                            h->header.name_hash_bit_size, h->header.index_size_total,
                            h->header.index_size_extra,   h->header.index_size,
                            h->header.index_table_size };
    size_t i;
    if (wire == NULL)
        return NULL;
    for (i = 0; i < 11; ++i)
        libmpq__store_le32(wire + i * 4, values[i]);
    memcpy(wire + h->header.name_hash1.offset, h->name_hash1, h->header.name_hash1.size);
    memcpy(wire + h->header.indices.offset, h->index_bits, h->header.indices.size);
    return wire;
}

static uint8_t *
bet_wire(const mpq_bet_builder_s *b)
{
    uint8_t *wire = NULL;
    size_t size;
    if (libmpq__bet_serialize(b, &wire, &size) != 0 ||
        size != LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + b->header.table_size) {
        free(wire);
        return NULL;
    }
    return wire;
}

static int
roundtrip(const mpq_ext_table_file_s *files, size_t count, uint32_t capacity)
{
    mpq_het_builder_s h = { 0 };
    mpq_het_builder_s again_h = { 0 };
    mpq_bet_builder_s b = { 0 };
    mpq_bet_builder_s again_b = { 0 };
    mpq_het_s view_h;
    mpq_bet_s view_b;
    uint8_t *wire_h;
    uint8_t *wire_b;
    uint8_t *again_wire_h;
    uint8_t *again_wire_b;
    size_t i;
    TEST_CHECK(libmpq__ext_tables_build(files, count, &h, &b) == 0);
    TEST_CHECK(h.header.total_count == capacity);
    TEST_CHECK(h.header.entry_count == count && b.header.entry_count == count);
    TEST_CHECK(libmpq__ext_tables_build(files, count, &again_h, &again_b) == 0);
    wire_h = het_wire(&h);
    wire_b = bet_wire(&b);
    again_wire_h = het_wire(&again_h);
    again_wire_b = bet_wire(&again_b);
    TEST_CHECK(wire_h && wire_b && again_wire_h && again_wire_b);
    TEST_CHECK(memcmp(wire_h, again_wire_h, 12u + h.header.table_size) == 0);
    TEST_CHECK(memcmp(wire_b, again_wire_b, 12u + b.header.table_size) == 0);
    TEST_CHECK(libmpq__het_view_init(wire_h, 12u + h.header.table_size, &view_h) == 0);
    TEST_CHECK(libmpq__bet_view_init(wire_b, 12u + b.header.table_size, &view_b) == 0);
    for (i = 0; i < count; ++i) {
        uint64_t index;
        uint64_t hash;
        uint64_t name_hash2;
        mpq_het_hash_s parts;
        mpq_bet_entry_s record;
        mpq_entry_s entry;
        TEST_CHECK(
            libmpq__het_lookup(
                &view_h, files[i].filename, count, libmpq__bet_match, &view_b, &index
            ) == 0
        );
        TEST_CHECK(index == i);
        TEST_CHECK(libmpq__het_hash_filename(files[i].filename, &hash) == 0);
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, capacity, &parts) == 0);
        TEST_CHECK(libmpq__bet_record_decode(&view_b, index, &record) == 0);
        TEST_CHECK(record.offset == files[i].offset && record.packed_size == files[i].packed_size);
        TEST_CHECK(
            record.unpacked_size == files[i].unpacked_size && record.flags == files[i].flags
        );
        TEST_CHECK(record.unknown == 0 && record.name_hash2 == parts.name_hash2);
        TEST_CHECK(libmpq__bet_name_hash2(&view_b, index, &name_hash2) == 0);
        TEST_CHECK(name_hash2 == parts.name_hash2);
        TEST_CHECK(libmpq__bet_entry_decode(&view_b, index, parts.name_hash2, &entry) == 0);
        TEST_CHECK(entry.source_mask == LIBMPQ_ENTRY_SOURCE_BET && entry.bet_source_index == i);
    }
    {
        uint64_t index;
        TEST_CHECK(
            libmpq__het_lookup(&view_h, "absent", count, libmpq__bet_match, &view_b, &index) ==
            LIBMPQ_ERROR_EXIST
        );
    }
    free(wire_h);
    free(wire_b);
    free(again_wire_h);
    free(again_wire_b);
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    libmpq__het_builder_free(&again_h);
    libmpq__bet_builder_free(&again_b);
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    return 0;
}

static int
test_widths(void)
{
    mpq_ext_table_file_s files[65];
    char names[65][32];
    mpq_het_builder_s h = { 0 };
    mpq_bet_builder_s b = { 0 };
    mpq_ext_table_file_s single = { "one", 1, 3, 2, 0x01020304 };
    size_t i;
    TEST_CHECK(roundtrip(NULL, 0, 3) == 0);
    TEST_CHECK(roundtrip(&single, 1, 3) == 0);
    TEST_CHECK(libmpq__ext_tables_build(&single, 1, &h, &b) == 0);
    TEST_CHECK(b.header.table_entry_size == 5 && b.records[0] == 0x1d);
    TEST_CHECK(b.header.flag_index.bit_count == 0 && b.header.flag_count == 1);
    TEST_CHECK(b.flags[0] == 4 && b.flags[1] == 3 && b.flags[2] == 2 && b.flags[3] == 1);
    single.offset = 255;
    single.unpacked_size = UINT32_MAX;
    single.packed_size = 256;
    TEST_CHECK(libmpq__ext_tables_build(&single, 1, &h, &b) == 0);
    TEST_CHECK(b.header.file_position.bit_count == 8);
    TEST_CHECK(b.header.file_size.bit_count == 32 && b.header.compressed_size.bit_count == 9);
    TEST_CHECK(roundtrip(&single, 1, 3) == 0);
    single.offset = 256;
    TEST_CHECK(libmpq__ext_tables_build(&single, 1, &h, &b) == 0);
    TEST_CHECK(b.header.file_position.bit_count == 9);
    for (i = 0; i < 65; ++i) {
        snprintf(names[i], sizeof(names[i]), "generated-%zu.bin", i);
        files[i].filename = names[i];
        files[i].offset = i == 0 ? UINT64_MAX : UINT64_C(0x100000000) + i;
        files[i].packed_size = i == 0 ? 0 : i;
        files[i].unpacked_size = i == 0 ? UINT64_MAX : i * 256;
        files[i].flags = i % 3 == 0 ? UINT32_MAX : (uint32_t)(i % 3);
    }
    files[1].filename = "prefix-0088.bin";
    files[2].offset = 0;
    files[2].packed_size = UINT64_MAX;
    TEST_CHECK(roundtrip(files, 2, 3) == 0);
    TEST_CHECK(roundtrip(files, 3, 5) == 0);
    TEST_CHECK(roundtrip(files, 5, 7) == 0);
    TEST_CHECK(roundtrip(files, 6, 9) == 0);
    TEST_CHECK(roundtrip(files, 65, 87) == 0);
    TEST_CHECK(libmpq__ext_tables_build(files, 65, &h, &b) == 0);
    TEST_CHECK(b.header.file_position.bit_count == 64 && b.header.file_size.bit_count == 64);
    TEST_CHECK(b.header.compressed_size.bit_count == 64);
    TEST_CHECK(b.header.flag_count == 3 && b.header.flag_index.bit_count == 2);
    TEST_CHECK(libmpq__load_le32(b.flags) == 1 && libmpq__load_le32(b.flags + 4) == 2);
    TEST_CHECK(libmpq__load_le32(b.flags + 8) == UINT32_MAX);
    {
        uint64_t hash;
        mpq_het_hash_s parts;
        TEST_CHECK(libmpq__het_hash_filename(files[1].filename, &hash) == 0);
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, h.header.total_count, &parts) == 0);
        TEST_CHECK(parts.name_hash1 == 0x80);
    }
    single.offset = single.packed_size = single.unpacked_size = 0;
    TEST_CHECK(libmpq__ext_tables_build(&single, 1, &h, &b) == 0);
    TEST_CHECK(b.header.table_entry_size == 1 && b.records[0] == 0);
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    return 0;
}

static int
test_collisions_and_errors(void)
{
    char names[4][32];
    mpq_ext_table_file_s files[2] = { { 0 } };
    mpq_het_builder_s h = { 0 };
    mpq_bet_builder_s b = { 0 };
    uint32_t first = UINT32_MAX;
    size_t i;
    for (i = 0; i < 100; ++i) {
        uint64_t hash;
        mpq_het_hash_s parts;
        snprintf(names[1], sizeof(names[1]), "collision-%zu", i);
        TEST_CHECK(libmpq__het_hash_filename(names[1], &hash) == 0);
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, 3, &parts) == 0);
        if (first == UINT32_MAX) {
            first = parts.initial_slot;
            memcpy(names[0], names[1], sizeof(names[0]));
        } else if (parts.initial_slot == first)
            break;
    }
    TEST_CHECK(i < 100);
    files[0].filename = names[0];
    files[1].filename = names[1];
    TEST_CHECK(roundtrip(files, 2, 3) == 0);
    TEST_CHECK(libmpq__ext_tables_build(files, 2, &h, &b) == 0);
    {
        uint64_t index;
        uint32_t next = (first + 1) % 3;
        TEST_CHECK(
            libmpq__bit_get(
                h.index_bits, h.header.indices.size, (uint64_t)next * h.header.index_size,
                h.header.index_size, &index
            ) == 0
        );
        TEST_CHECK(index == 1 && h.name_hash1[next] != 0);
    }
    files[0].filename = "dir/file";
    files[1].filename = "DIR\\FILE";
    {
        uint8_t *saved = h.name_hash1;
        TEST_CHECK(libmpq__ext_tables_build(files, 2, &h, &b) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(h.name_hash1 == saved && h.header.entry_count == 2);
    }
    files[1].filename = "";
    TEST_CHECK(roundtrip(files, 2, 3) == 0);
    files[1].filename = NULL;
    TEST_CHECK(libmpq__ext_tables_build(files, 2, &h, &b) == LIBMPQ_ERROR_EXIST);
    files[1].filename = "different";
    files[1].offset = UINT64_MAX;
    files[1].packed_size = 1;
    TEST_CHECK(libmpq__ext_tables_build(files, 2, &h, &b) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__ext_tables_build(files, SIZE_MAX, &h, &b) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__ext_tables_build(NULL, 1, &h, &b) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__ext_tables_build(files, 1, NULL, &b) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__ext_tables_build(files, 1, &h, NULL) == LIBMPQ_ERROR_EXIST);
    {
        char long_names[2][LIBMPQ_HET_FILENAME_LIMIT + 2];
        memset(long_names, 'x', sizeof(long_names));
        long_names[0][LIBMPQ_HET_FILENAME_LIMIT] = 'a';
        long_names[1][LIBMPQ_HET_FILENAME_LIMIT] = 'b';
        long_names[0][LIBMPQ_HET_FILENAME_LIMIT + 1] = '\0';
        long_names[1][LIBMPQ_HET_FILENAME_LIMIT + 1] = '\0';
        files[0].filename = long_names[0];
        files[1].filename = long_names[1];
        files[1].offset = files[1].packed_size = 0;
        TEST_CHECK(libmpq__ext_tables_build(files, 2, &h, &b) == LIBMPQ_ERROR_EXIST);
    }
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    libmpq__het_builder_free(NULL);
    libmpq__bet_builder_free(NULL);
    return 0;
}

/* Independent full wire vector: five-bit record and a fixed reference HET hash. */
static int
test_serialization_vector(void)
{
    static const uint8_t expected[100] = {
        0x42, 0x45, 0x54, 0x1a, 1, 0, 0, 0,    0x58, 0,    0,    0,    0x58, 0,    0,   0, 1,
        0,    0,    0,    0,    0, 0, 0, 5,    0,    0,    0,    0,    0,    0,    0,   1, 0,
        0,    0,    3,    0,    0, 0, 5, 0,    0,    0,    5,    0,    0,    0,    1,   0, 0,
        0,    2,    0,    0,    0, 2, 0, 0,    0,    0,    0,    0,    0,    0,    0,   0, 0,
        56,   0,    0,    0,    0, 0, 0, 0,    56,   0,    0,    0,    7,    0,    0,   0, 1,
        0,    0,    0,    4,    3, 2, 1, 0x1d, 0xda, 0xf6, 0xb0, 0xc8, 0x19, 0x16, 0x42
    };
    mpq_ext_table_file_s file = { "prefix-0088.bin", 1, 3, 2, 0x01020304 };
    mpq_het_builder_s h = { 0 };
    mpq_bet_builder_s b = { 0 };
    mpq_bet_header_s header;
    uint8_t *wire;
    uint8_t *again;
    size_t size;
    size_t again_size;

    TEST_CHECK(libmpq__ext_tables_build(&file, 1, &h, &b) == 0);
    TEST_CHECK(libmpq__bet_serialize(&b, &wire, &size) == 0);
    TEST_CHECK(size == sizeof(expected) && memcmp(wire, expected, size) == 0);
    TEST_CHECK(libmpq__bet_header_decode(wire, size, &header) == 0);
    TEST_CHECK(header.table_size == 88 && header.envelope.data_size == 88);
    TEST_CHECK(header.records.offset == 92 && header.name_hash2.offset == 93);
    TEST_CHECK(libmpq__bet_serialize(&b, &again, &again_size) == 0);
    TEST_CHECK(again_size == size && memcmp(wire, again, size) == 0);
    free(again);
    free(wire);

    /* Only meaningful fields are emitted; poisoned input padding is not copied. */
    b.records[0] |= 0xe0;
    TEST_CHECK(libmpq__bet_serialize(&b, &wire, &size) == 0);
    TEST_CHECK(memcmp(wire, expected, size) == 0 && b.records[0] == 0xfd);
    free(wire);
    file.offset = file.unpacked_size = file.packed_size = 0;
    TEST_CHECK(libmpq__ext_tables_build(&file, 1, &h, &b) == 0);
    b.records[0] = 0xff;
    TEST_CHECK(libmpq__bet_serialize(&b, &wire, &size) == 0);
    TEST_CHECK(wire[b.header.records.offset] == 0 && b.records[0] == 0xff);
    free(wire);
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    return 0;
}

static int
test_serialization_stride(void)
{
    mpq_ext_table_file_s files[2] = { { "first", 1, 2, 3, 1 }, { "second", 4, 5, 6, 1 } };
    mpq_het_builder_s h = { 0 };
    mpq_bet_builder_s b = { 0 };
    mpq_bet_s view;
    uint64_t hashes[2];
    uint8_t *wire;
    size_t size;
    size_t hash_bytes;
    size_t i;

    TEST_CHECK(libmpq__ext_tables_build(files, 2, &h, &b) == 0);
    for (i = 0; i < 2; ++i)
        TEST_CHECK(
            libmpq__bit_get(b.name_hash2, b.header.name_hash2.size, i * 56, 56, &hashes[i]) == 0
        );
    TEST_CHECK(libmpq__bit_bytes(2, 59, &hash_bytes) == 0);
    free(b.name_hash2);
    b.name_hash2 = malloc(hash_bytes);
    TEST_CHECK(b.name_hash2 != NULL);
    memset(b.name_hash2, 0xff, hash_bytes);
    b.header.table_size += (uint32_t)(hash_bytes - b.header.name_hash2.size);
    b.header.envelope.data_size = b.header.table_size;
    b.header.name_hash2.size = hash_bytes;
    b.header.name_hash_array_size = (uint32_t)hash_bytes;
    b.header.name_hash2_total = 59;
    b.header.name_hash2_extra = 3;
    for (i = 0; i < 2; ++i)
        TEST_CHECK(libmpq__bit_set(b.name_hash2, hash_bytes, i * 59, 56, hashes[i]) == 0);
    TEST_CHECK(libmpq__bet_serialize(&b, &wire, &size) == 0);
    TEST_CHECK(libmpq__bet_view_init(wire, size, &view) == 0);
    for (i = 0; i < 2; ++i) {
        uint64_t hash;
        uint64_t padding;
        mpq_bet_entry_s record;
        TEST_CHECK(libmpq__bet_name_hash2(&view, i, &hash) == 0 && hash == hashes[i]);
        TEST_CHECK(
            libmpq__bit_get(view.name_hash2, view.name_hash2_size, i * 59 + 56, 3, &padding) == 0
        );
        TEST_CHECK(padding == 0);
        TEST_CHECK(libmpq__bet_record_decode(&view, i, &record) == 0);
        TEST_CHECK(record.offset == files[i].offset && record.flags == 1);
    }
    TEST_CHECK((view.name_hash2[hash_bytes - 1] & 0xc0) == 0);
    free(wire);
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    return 0;
}

/* A malformed private state must reset both outputs and never expose partial bytes. */
static int
serialize_failure(const mpq_bet_builder_s *b, int32_t error)
{
    uint8_t sentinel = 0;
    uint8_t *wire = &sentinel;
    size_t size = SIZE_MAX;
    TEST_CHECK(libmpq__bet_serialize(b, &wire, &size) == error);
    TEST_CHECK(wire == NULL && size == 0);
    return 0;
}

static int
test_serialization_errors(void)
{
    mpq_ext_table_file_s file = { "errors", 1, 2, 3, 1 };
    mpq_het_builder_s h = { 0 };
    mpq_bet_builder_s b = { 0 };
    mpq_bet_builder_s bad;
    uint8_t *wire = NULL;
    size_t size = 1;

    TEST_CHECK(serialize_failure(NULL, LIBMPQ_ERROR_SIZE) == 0);
    TEST_CHECK(libmpq__ext_tables_build(&file, 1, &h, &b) == 0);
    TEST_CHECK(libmpq__bet_serialize(&b, NULL, &size) == LIBMPQ_ERROR_SIZE && size == 0);
    TEST_CHECK(libmpq__bet_serialize(&b, &wire, NULL) == LIBMPQ_ERROR_SIZE && wire == NULL);
    bad = b;
    bad.header.entry_count = UINT32_MAX;
    bad.header.table_entry_size = UINT32_MAX;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    bad.header.flag_count = UINT32_MAX;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    bad.header.name_hash2_total = UINT32_MAX;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    ++bad.header.table_size;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    ++bad.header.envelope.data_size;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    bad.header.envelope.signature = LIBMPQ_HET_SIGNATURE;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    ++bad.header.envelope.version;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    bad.header.records.offset = SIZE_MAX;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    --bad.header.records.size;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    --bad.header.name_hash2.size;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    bad.records = NULL;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    bad.flags = NULL;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    bad.name_hash2 = NULL;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_SIZE) == 0);
    bad = b;
    bad.header.file_position.bit_count = 65;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    bad.header.file_position.bit_index = UINT32_MAX;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    bad.header.file_position = b.header.file_size;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    bad = b;
    bad.header.name_hash2_extra = 1;
    TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    {
        mpq_ext_table_file_s pair[2] = { { "left", 1, 2, 3, 1 }, { "right", 4, 5, 6, 2 } };
        TEST_CHECK(libmpq__ext_tables_build(pair, 2, &h, &b) == 0);
        bad = b;
        bad.header.flag_count = 1;
        bad.header.flags.size -= 4;
        bad.header.records.offset -= 4;
        bad.header.name_hash2.offset -= 4;
        bad.header.table_size -= 4;
        bad.header.envelope.data_size -= 4;
        TEST_CHECK(serialize_failure(&bad, LIBMPQ_ERROR_FORMAT) == 0);
    }
    libmpq__het_builder_free(&h);
    libmpq__bet_builder_free(&b);
    return 0;
}

int
main(void)
{
    TEST_CHECK(test_widths() == 0);
    TEST_CHECK(test_collisions_and_errors() == 0);
    TEST_CHECK(test_serialization_vector() == 0);
    TEST_CHECK(test_serialization_stride() == 0);
    TEST_CHECK(test_serialization_errors() == 0);
    return 0;
}
