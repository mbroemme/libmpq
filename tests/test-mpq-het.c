/*
 *  test-mpq-het.c -- Synthetic MPQ HET header regression tests.
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
#include "../src/mpq-het.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <stdio.h>
#include <string.h>

/* Hand-specified header bytes describe three one-byte hashes and nine index bits. */
static const uint8_t valid_het[] = { 'H', 'E', 'T', 0x1a, 1, 0,    0,    0, 37,   0, 0, 0,  37,
                                     0,   0,   0,   2,    0, 0,    0,    3, 0,    0, 0, 64, 0,
                                     0,   0,   3,   0,    0, 0,    0,    0, 0,    0, 3, 0,  0,
                                     0,   2,   0,   0,    0, 0x80, 0x81, 0, 0x08, 0 };

/* Header decoding identifies ranges without reading or interpreting their slots. */
static int
test_valid(void)
{
    uint8_t wire[sizeof(valid_het)];
    mpq_het_header_s header;

    TEST_CHECK(libmpq__het_header_decode(valid_het, sizeof(valid_het), &header) == 0);
    TEST_CHECK(header.table_size == 37 && header.entry_count == 2 && header.total_count == 3);
    TEST_CHECK(header.name_hash_bit_size == 64 && header.index_size == 3);
    TEST_CHECK(header.index_size_total == 3 && header.index_size_extra == 0);
    TEST_CHECK(header.index_table_size == 2 && header.name_hash1.offset == 44);
    TEST_CHECK(
        header.name_hash1.size == 3 && header.indices.offset == 47 && header.indices.size == 2
    );
    memcpy(wire, valid_het, sizeof(wire));
    libmpq__store_le32(wire + 32, 1);
    libmpq__store_le32(wire + 36, 2);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == 0);
    TEST_CHECK(header.index_size_extra == 1 && header.index_size == 2);
    memcpy(wire, valid_het, sizeof(wire));
    libmpq__store_le32(wire + 8, 32);
    libmpq__store_le32(wire + 12, 32);
    libmpq__store_le32(wire + 16, 0);
    libmpq__store_le32(wire + 20, 0);
    libmpq__store_le32(wire + 28, 0);
    libmpq__store_le32(wire + 36, 0);
    libmpq__store_le32(wire + 40, 0);
    TEST_CHECK(libmpq__het_header_decode(wire, 44, &header) == 0);
    TEST_CHECK(header.indices.size == 0 && header.name_hash1.size == 0);
    return 0;
}

/* Mutations exercise truncated headers, invalid relationships, and oversized arrays. */
static int
test_invalid(void)
{
    static const struct
    {
        size_t offset;
        uint32_t value;
    } mutations[] = { { 0, LIBMPQ_BET_SIGNATURE },
                      { 4, 2 },
                      { 8, UINT32_MAX },
                      { 8, 31 },
                      { 12, 31 },
                      { 12, 38 },
                      { 16, 4 },
                      { 24, 0 },
                      { 24, 7 },
                      { 24, 65 },
                      { 28, 2 },
                      { 32, 4 },
                      { 36, 4 },
                      { 36, 0 },
                      { 40, 1 },
                      { 40, UINT32_MAX },
                      { 20, UINT32_MAX },
                      { 28, UINT32_MAX } };
    uint8_t wire[sizeof(valid_het)];
    mpq_het_header_s header;
    size_t i;

    for (i = 0; i < sizeof(valid_het); i++)
        TEST_CHECK(libmpq__het_header_decode(valid_het, i, &header) != 0);
    for (i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
        memcpy(wire, valid_het, sizeof(wire));
        libmpq__store_le32(wire + mutations[i].offset, mutations[i].value);
        TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) != 0);
    }

    /* Three three-bit slots require nine bits, not the declared eight. */
    memcpy(wire, valid_het, sizeof(wire));
    libmpq__store_le32(wire + 8, 36);
    libmpq__store_le32(wire + 12, 36);
    libmpq__store_le32(wire + 40, 1);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire) - 1, &header) != 0);
    TEST_CHECK(libmpq__het_header_decode(NULL, sizeof(valid_het), &header) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__het_header_decode(valid_het, sizeof(valid_het), NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Reject surplus declared payload and index padding despite complete buffers. */
static int
test_exact_sizes(void)
{
    uint8_t wire[sizeof(valid_het) + 1] = { 0 };
    mpq_ext_table_header_s envelope;
    mpq_het_header_s header;

    memcpy(wire, valid_het, sizeof(valid_het));
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == 0);

    /* The extra byte belongs to the envelope, but not to the declared HET table. */
    libmpq__store_le32(wire + 8, 38);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_HET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);

    /* Matching table sizes still cannot pad the two-byte packed index array. */
    libmpq__store_le32(wire + 12, 38);
    libmpq__store_le32(wire + 40, 3);
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_HET_SIGNATURE, &envelope) == 0);
    TEST_CHECK(libmpq__het_header_decode(wire, sizeof(wire), &header) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

/* Independent lookup3 vectors use Storm's seed order, not the classic MPQ hash. */
static int
test_hashes(void)
{
    static const struct
    {
        const char *name;
        uint64_t hash;
    } vectors[] = { { "", UINT64_C(0xdeadbef1deadbef2) },
                    { "file.bin", UINT64_C(0x9266c442bd53f116) },
                    { "FILE.BIN", UINT64_C(0x9266c442bd53f116) },
                    { "Dir/File.bin", UINT64_C(0x1b6b317ba6ead78a) },
                    { "dir\\file.bin", UINT64_C(0x1b6b317ba6ead78a) },
                    { "a", UINT64_C(0x6dacec851cd637bb) },
                    { "123456789012", UINT64_C(0xfc3630b9ea0934dd) },
                    { "1234567890123", UINT64_C(0x26a15ad5e7e87190) },
                    { "Synthetic/Long/Path/With/Several/Components/And/A/File.Name",
                      UINT64_C(0xe3ace21891e3eb9e) },
                    { "\x80\xc0\xff.bin", UINT64_C(0x6392b1aafe7b80b6) } };
    char long_name[300];
    uint64_t hash;
    size_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        TEST_CHECK(libmpq__het_hash_filename(vectors[i].name, &hash) == 0);
        TEST_CHECK(hash == vectors[i].hash);
    }
    for (i = 0; i < sizeof(long_name) - 1; i++)
        long_name[i] = (char)('A' + i % 26);
    long_name[sizeof(long_name) - 1] = '\0';
    TEST_CHECK(libmpq__het_hash_filename(long_name, &hash) == 0);
    TEST_CHECK(hash == UINT64_C(0x983f7c33c2bc79fc));
    long_name[LIBMPQ_HET_FILENAME_LIMIT] = '\0';
    TEST_CHECK(libmpq__het_hash_filename(long_name, &hash) == 0);
    TEST_CHECK(hash == UINT64_C(0x983f7c33c2bc79fc));
    TEST_CHECK(libmpq__het_hash_filename(NULL, &hash) == LIBMPQ_ERROR_EXIST && hash == 0);
    TEST_CHECK(libmpq__het_hash_filename("file.bin", NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Masking and high-bit forcing happen before modulo, for every declared width. */
static int
test_partition(void)
{
    mpq_het_hash_s parts;

    TEST_CHECK(libmpq__het_hash_partition(UINT64_C(0x0123456789abcdef), 64, 7, &parts) == 0);
    TEST_CHECK(parts.hash == UINT64_C(0x8123456789abcdef));
    TEST_CHECK(parts.name_hash1 == 0x81 && parts.name_hash2 == UINT64_C(0x23456789abcdef));
    TEST_CHECK(parts.initial_slot == 0);
    TEST_CHECK(libmpq__het_hash_partition(UINT64_C(0x0123456789abcdef), 40, 7, &parts) == 0);
    TEST_CHECK(parts.hash == UINT64_C(0xe789abcdef));
    TEST_CHECK(parts.name_hash1 == 0xe7 && parts.name_hash2 == UINT64_C(0x89abcdef));
    TEST_CHECK(parts.initial_slot == 5);
    TEST_CHECK(libmpq__het_hash_partition(UINT64_C(0x0123456789abcdef), 8, 7, &parts) == 0);
    TEST_CHECK(parts.hash == 0xef && parts.name_hash1 == 0xef && parts.name_hash2 == 0);
    TEST_CHECK(parts.initial_slot == 1);
    TEST_CHECK(libmpq__het_hash_partition(UINT64_C(0x9266c442bd53f116), 64, 8, &parts) == 0);
    TEST_CHECK(parts.name_hash1 == 0x92 && parts.name_hash2 == UINT64_C(0x66c442bd53f116));
    TEST_CHECK(parts.initial_slot == 6);
    TEST_CHECK(libmpq__het_hash_partition(0, 7, 1, &parts) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__het_hash_partition(0, 65, 1, &parts) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__het_hash_partition(0, 64, 0, &parts) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__het_hash_partition(0, 64, 1, NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Create only decoded synthetic HET bytes, with optional high stride bits. */
static int
make_lookup_table(
    uint8_t *wire, size_t capacity, uint32_t slots, uint32_t entries, uint32_t stride,
    uint32_t width, mpq_het_s *table
)
{
    size_t index_bytes;
    size_t total;

    TEST_CHECK(libmpq__bit_bytes(slots, stride, &index_bytes) == 0);
    total = 44 + slots + index_bytes;
    TEST_CHECK(total <= capacity);
    memset(wire, 0, capacity);
    libmpq__store_le32(wire, LIBMPQ_HET_SIGNATURE);
    libmpq__store_le32(wire + 4, LIBMPQ_EXT_TABLE_VERSION);
    libmpq__store_le32(wire + 8, (uint32_t)(total - 12));
    libmpq__store_le32(wire + 12, (uint32_t)(total - 12));
    libmpq__store_le32(wire + 16, entries);
    libmpq__store_le32(wire + 20, slots);
    libmpq__store_le32(wire + 24, 64);
    libmpq__store_le32(wire + 28, stride);
    libmpq__store_le32(wire + 32, stride - width);
    libmpq__store_le32(wire + 36, width);
    libmpq__store_le32(wire + 40, (uint32_t)index_bytes);
    memset(wire + 44 + slots, 0xff, index_bytes);
    TEST_CHECK(libmpq__het_view_init(wire, total, table) == 0);
    return 0;
}

/* Populate a slot without altering the extra high bits within its packed stride. */
static int
place_lookup_slot(
    uint8_t *wire, const mpq_het_s *table, uint32_t slot, uint8_t name_hash1, uint64_t index
)
{
    wire[table->header.name_hash1.offset + slot] = name_hash1;
    TEST_CHECK(
        libmpq__bit_set(
            wire + table->header.indices.offset, table->index_bits_size,
            (uint64_t)slot * table->header.index_size_total, table->header.index_size, index
        ) == 0
    );
    return 0;
}

/* Synthetic reference hashes replace BET content, which is deliberately not parsed. */
typedef struct
{
    uint64_t index;
    uint64_t name_hash2;
    uint32_t calls;
    int32_t error;
} lookup_match_s;

/* Confirm only a caller-owned synthetic hash and index, recording candidate visits. */
static int32_t
match_lookup(void *context, uint64_t index, uint64_t name_hash2, int *matches)
{
    lookup_match_s *expected = context;

    expected->calls++;
    *matches = expected->index == index && expected->name_hash2 == name_hash2;
    return expected->error;
}

/* Direct hits, wraparound collisions, empty termination and full-table bounds. */
static int
test_lookup(void)
{
    uint8_t wire[160];
    mpq_het_s table;
    mpq_het_hash_s parts;
    lookup_match_s expected = { 3, UINT64_C(0x66c442bd53f116), 0, 0 };
    uint64_t index;
    uint32_t i;

    TEST_CHECK(libmpq__het_hash_partition(UINT64_C(0x9266c442bd53f116), 64, 8, &parts) == 0);
    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 1, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 6, parts.name_hash1, 3) == 0);
    TEST_CHECK(libmpq__het_lookup(&table, "FILE.BIN", 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 1);
    TEST_CHECK(libmpq__het_slot_index(&table, 6, &index) == 0 && index == 3);

    /* Lookup must use the declared width, not a hard-coded top-byte split. */
    libmpq__store_le32(wire + 24, 40);
    TEST_CHECK(libmpq__het_view_init(wire, sizeof(wire), &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 6, 0xc2, 3) == 0);
    expected.name_hash2 = UINT64_C(0xbd53f116);
    expected.calls = 0;
    TEST_CHECK(libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 1);
    expected.name_hash2 = UINT64_C(0x66c442bd53f116);

    /* A non-power-of-two slot count uses modulo, not classic hash-table masking. */
    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 7, 2, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 2, 0x91, 0) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 3, parts.name_hash1, 3) == 0);
    expected.calls = 0;
    TEST_CHECK(libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 1);

    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 2, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 6, 0x91, 0) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 7, parts.name_hash1, 3) == 0);
    expected.calls = 0;
    TEST_CHECK(libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 1);

    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 3, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 6, 0x91, 0) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 7, 0x80, 1) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 0, parts.name_hash1, 3) == 0);
    expected.calls = 0;
    TEST_CHECK(libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 1);
    TEST_CHECK(libmpq__het_slot_index(&table, 7, &index) == 0 && index == 1);

    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 1, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 7, parts.name_hash1, 3) == 0);
    expected.calls = 0;
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(index == 0 && expected.calls == 0);

    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 8, 5, 3, &table) == 0);
    for (i = 0; i < 8; i++)
        TEST_CHECK(place_lookup_slot(wire, &table, i, parts.name_hash1, i) == 0);
    expected.name_hash2 ^= 1;
    expected.calls = 0;
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(index == 0 && expected.calls == 8);
    return 0;
}

/* Real synthetic names with the same prefix/start must still match lower hash bits. */
static int
test_hash_collision(void)
{
    uint8_t wire[160];
    char other_name[40];
    mpq_het_s table;
    mpq_het_hash_s target;
    mpq_het_hash_s other;
    lookup_match_s expected = { 3, UINT64_C(0x66c442bd53f116), 0, 0 };
    uint64_t hash;
    uint64_t index;
    uint32_t i;

    TEST_CHECK(libmpq__het_hash_partition(UINT64_C(0x9266c442bd53f116), 64, 8, &target) == 0);
    for (i = 0; i < 8192; i++) {
        snprintf(other_name, sizeof(other_name), "collision-%04u.bin", i);
        TEST_CHECK(libmpq__het_hash_filename(other_name, &hash) == 0);
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, 8, &other) == 0);
        if (other.name_hash1 == target.name_hash1 && other.initial_slot == target.initial_slot &&
            other.hash != target.hash)
            break;
    }
    TEST_CHECK(i < 8192 && other.name_hash2 != target.name_hash2);
    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 2, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 6, other.name_hash1, 1) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 7, target.name_hash1, 3) == 0);
    TEST_CHECK(libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 2);
    expected.calls = 0;
    TEST_CHECK(
        libmpq__het_lookup(&table, other_name, 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(index == 0 && expected.calls == 2);
    expected.index = 1;
    expected.name_hash2 = other.name_hash2;
    TEST_CHECK(libmpq__het_lookup(&table, other_name, 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 1);
    expected.error = LIBMPQ_ERROR_FORMAT;
    TEST_CHECK(
        libmpq__het_lookup(&table, other_name, 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(index == 0);
    return 0;
}

/* The deleted-marker byte is also a valid prefix and cannot suppress live matches. */
static int
test_prefix_eighty(void)
{
    uint8_t wire[160];
    char name[40];
    mpq_het_s table;
    mpq_het_hash_s parts;
    lookup_match_s expected = { 3, 0, 0, 0 };
    uint64_t hash;
    uint64_t index;
    uint32_t i;

    for (i = 0; i < 8192; i++) {
        snprintf(name, sizeof(name), "prefix-%04u.bin", i);
        TEST_CHECK(libmpq__het_hash_filename(name, &hash) == 0);
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, 8, &parts) == 0);
        if (parts.name_hash1 == 0x80)
            break;
    }
    TEST_CHECK(i < 8192);
    expected.name_hash2 = parts.name_hash2;
    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 2, 5, 3, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, parts.initial_slot, 0x80, 1) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, (parts.initial_slot + 1) % 8, 0x80, 3) == 0);
    TEST_CHECK(libmpq__het_lookup(&table, name, 8, match_lookup, &expected, &index) == 0);
    TEST_CHECK(index == 3 && expected.calls == 2);
    return 0;
}

/* Maximum widths remain unsigned; malformed views cannot reach borrowed buffers. */
static int
test_lookup_bounds(void)
{
    uint8_t wire[160];
    mpq_het_s table;
    mpq_het_s invalid;
    lookup_match_s expected = { UINT64_MAX - 1, UINT64_C(0x66c442bd53f116), 0, 0 };
    uint64_t index = 99;

    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 1, 1, 64, 64, &table) == 0);
    TEST_CHECK(place_lookup_slot(wire, &table, 0, 0x92, UINT64_MAX - 1) == 0);
    TEST_CHECK(libmpq__het_slot_index(&table, 0, &index) == 0 && index == UINT64_MAX - 1);
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", UINT64_MAX, match_lookup, &expected, &index) == 0
    );
    TEST_CHECK(index == UINT64_MAX - 1);
    TEST_CHECK(place_lookup_slot(wire, &table, 0, 0x92, UINT64_MAX) == 0);
    TEST_CHECK(libmpq__het_slot_index(&table, 0, &index) == 0 && index == UINT64_MAX);
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", UINT64_MAX, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(index == 0);
    TEST_CHECK(libmpq__het_slot_index(&table, 1, &index) == LIBMPQ_ERROR_FORMAT && index == 0);
    TEST_CHECK(libmpq__het_slot_index(&table, UINT32_MAX, &index) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__het_slot_index(&table, 0, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(place_lookup_slot(wire, &table, 0, 1, 0) == 0);
    TEST_CHECK(libmpq__het_slot_index(&table, 0, &index) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(place_lookup_slot(wire, &table, 0, 0x92, 0) == 0);
    invalid = table;
    invalid.index_bits_size--;
    TEST_CHECK(libmpq__het_slot_index(&invalid, 0, &index) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__het_lookup(&invalid, "file.bin", 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_FORMAT
    );
    invalid = table;
    invalid.name_hash1_size = 0;
    TEST_CHECK(libmpq__het_slot_index(&invalid, 0, &index) == LIBMPQ_ERROR_FORMAT);
    invalid = table;
    invalid.header.total_count = 0;
    TEST_CHECK(
        libmpq__het_lookup(&invalid, "file.bin", 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_FORMAT
    );
    invalid = table;
    invalid.index_bits = NULL;
    TEST_CHECK(libmpq__het_slot_index(&invalid, 0, &index) == LIBMPQ_ERROR_FORMAT);
    invalid = table;
    invalid.name_hash1 = NULL;
    TEST_CHECK(libmpq__het_slot_index(&invalid, 0, &index) == LIBMPQ_ERROR_FORMAT);
    invalid = table;
    invalid.header.index_size_total = UINT32_MAX;
    TEST_CHECK(libmpq__het_slot_index(&invalid, 0, &index) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__het_lookup(NULL, "file.bin", 8, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", 8, NULL, &expected, &index) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", 8, match_lookup, &expected, NULL) ==
        LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__het_lookup(&table, NULL, 8, match_lookup, &expected, &index) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__het_view_init(valid_het, sizeof(valid_het) - 1, &table) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(libmpq__het_view_init(valid_het, sizeof(valid_het), NULL) == LIBMPQ_ERROR_SIZE);

    TEST_CHECK(make_lookup_table(wire, sizeof(wire), 8, 0, 5, 3, &table) == 0);
    TEST_CHECK(libmpq__het_slot_index(&table, 0, &index) == LIBMPQ_ERROR_EXIST && index == 0);
    TEST_CHECK(
        libmpq__het_lookup(&table, "file.bin", 0, match_lookup, &expected, &index) ==
        LIBMPQ_ERROR_EXIST
    );
    libmpq__store_le32(wire + 8, 32);
    libmpq__store_le32(wire + 12, 32);
    libmpq__store_le32(wire + 20, 0);
    libmpq__store_le32(wire + 28, 0);
    libmpq__store_le32(wire + 32, 0);
    libmpq__store_le32(wire + 36, 0);
    libmpq__store_le32(wire + 40, 0);
    TEST_CHECK(libmpq__het_view_init(wire, 44, &table) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(table.name_hash1 == NULL && table.index_bits == NULL);
    return 0;
}

/* Run isolated synthetic HET structural and filename-lookup tests. */
int
main(void)
{
    TEST_CHECK(test_valid() == 0);
    TEST_CHECK(test_invalid() == 0);
    TEST_CHECK(test_exact_sizes() == 0);
    TEST_CHECK(test_hashes() == 0);
    TEST_CHECK(test_partition() == 0);
    TEST_CHECK(test_lookup() == 0);
    TEST_CHECK(test_hash_collision() == 0);
    TEST_CHECK(test_prefix_eighty() == 0);
    TEST_CHECK(test_lookup_bounds() == 0);
    return 0;
}
