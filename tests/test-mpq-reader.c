/*
 *  test-mpq-reader.c -- libmpq regression tests.
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

/* Exercise fixture opening, file maps, sector offsets, and block reads. */
#include "mpq-archive.h"
#include "mpq-bit.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-ext-table.h"
#include "mpq-file.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Synthetic v3 image; sparse source reads can place its body above 4 GiB. */
typedef struct
{
    uint8_t bytes[16384];
    size_t size;
    uint64_t shift;
    uint64_t base;
    uint64_t fail_at;
    uint64_t het_offset;
    uint64_t bet_offset;
} reader_v3_source_s;

static int32_t
reader_v3_read_at(void *context, libmpq__off_t offset, uint8_t *output, size_t size)
{
    reader_v3_source_s *source = context;
    uint64_t start;
    uint64_t extent = source->base + source->shift + source->size;
    uint64_t positions[2] = { source->base, source->base + source->shift + 68 };
    size_t lengths[2] = { 68, source->size - 68 };
    size_t indices[2] = { 0, 68 };
    size_t i;
    if (offset < 0 || (uint64_t)offset > extent || size > extent - (uint64_t)offset)
        return LIBMPQ_ERROR_READ;
    start = (uint64_t)offset;
    if (source->fail_at != 0 && start <= source->fail_at && source->fail_at - start < size)
        return LIBMPQ_ERROR_READ;
    memset(output, 0, size);
    for (i = 0; i < 2; i++) {
        uint64_t left = start > positions[i] ? start : positions[i];
        uint64_t right =
            start + size < positions[i] + lengths[i] ? start + size : positions[i] + lengths[i];
        if (left < right)
            memcpy(
                output + (size_t)(left - start),
                source->bytes + indices[i] + (size_t)(left - positions[i]), (size_t)(right - left)
            );
    }
    return 0;
}

/* The plaintext envelope is followed by compressed-then-ciphered contained data. */
static int
reader_v3_store_table(
    reader_v3_source_s *source, const uint8_t *decoded, size_t size, int compressed,
    const char *key_name
)
{
    uint8_t stored[1024];
    size_t stored_size = size;
    if (compressed >= 2) {
        uint8_t *encoded = NULL;
        TEST_CHECK(
            libmpq__ext_table_encode(decoded, size, compressed == 2, &encoded, &stored_size) == 0
        );
        TEST_CHECK(source->size + stored_size <= sizeof(source->bytes));
        memcpy(source->bytes + source->size, encoded, stored_size);
        source->size += stored_size;
        free(encoded);
        return 0;
    }
    if (compressed) {
        unsigned long capacity = sizeof(stored) - 13;
        memcpy(stored, decoded, 12);
        stored[12] = LIBMPQ_COMPRESSION_ZLIB;
        TEST_CHECK(compress2(stored + 13, &capacity, decoded + 12, size - 12, 9) == Z_OK);
        stored_size = (size_t)capacity + 13;
        TEST_CHECK(stored_size < size);
    } else {
        memcpy(stored, decoded, size);
    }
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            stored + 12, (uint32_t)stored_size - 12, libmpq__crypto_hash_string(key_name, 0x300)
        ) == 0
    );
    TEST_CHECK(source->size + stored_size <= sizeof(source->bytes));
    memcpy(source->bytes + source->size, stored, stored_size);
    source->size += stored_size;
    return 0;
}

/* No production HET/BET writer is used or introduced for this test fixture. */
static int
reader_v3_fixture(
    reader_v3_source_s *source, int compress_het, int compress_bet, int classic, int high,
    int encrypted, int empty, uint64_t shift, uint64_t base
)
{
    const char *names[2] = { "payload.bin", (encrypted & 4) ? "(signature)" : "(listfile)" };
    static const char listfile[] = "payload.bin\r\n";
    mpq_header_s header = { LIBMPQ_HEADER, 68, 0, LIBMPQ_ARCHIVE_VERSION_THREE, 3, 0, 0, 0, 0 };
    mpq_header_ex_s ex = { 0 };
    mpq_header_v3_s v3;
    uint8_t het_wire[124] = { 0 };
    uint8_t bet_wire[152] = { 0 };
    uint32_t count = empty ? 0 : 2;
    size_t record_bytes;
    size_t hash_bytes;
    size_t bet_size;
    uint32_t flags = LIBMPQ_FLAG_EXISTS;
    size_t payload_size = 9000;
    uint32_t i;
    memset(source, 0, sizeof(*source));
    source->size = 68;
    source->shift = shift;
    source->base = base;
    if ((encrypted & 1) != 0)
        flags |= LIBMPQ_FLAG_ENCRYPTED | 0x00020000u;
    if (!empty) {
        for (i = 0; i < 9000; i++)
            source->bytes[68 + i] = (uint8_t)(i * 17u + i / 31u);
        if ((encrypted & 2) != 0) {
            uint8_t compressed[10000];
            unsigned long length = sizeof(compressed) - 1;
            compressed[0] = LIBMPQ_COMPRESSION_ZLIB;
            TEST_CHECK(compress2(compressed + 1, &length, source->bytes + 68, 9000, 9) == Z_OK);
            payload_size = (size_t)length + 1;
            TEST_CHECK(payload_size < 9000);
            memcpy(source->bytes + 68, compressed, payload_size);
            flags |= LIBMPQ_FLAG_COMPRESS_MULTI | LIBMPQ_FLAG_SINGLE;
        }
        source->size += payload_size;
        if ((encrypted & 4) != 0) {
            memset(source->bytes + source->size, 0, 72);
            source->size += 72;
        } else {
            memcpy(source->bytes + source->size, listfile, sizeof(listfile) - 1);
            source->size += sizeof(listfile) - 1;
        }
    }
    TEST_CHECK(libmpq__bit_bytes(count, 130, &record_bytes) == 0);
    TEST_CHECK(libmpq__bit_bytes(count, 58, &hash_bytes) == 0);
    bet_size = 88 + 8 + record_bytes + hash_bytes;
    libmpq__store_le32(bet_wire, LIBMPQ_BET_SIGNATURE);
    libmpq__store_le32(bet_wire + 4, 1);
    libmpq__store_le32(bet_wire + 8, (uint32_t)bet_size - 12);
    libmpq__store_le32(bet_wire + 12, (uint32_t)bet_size - 12);
    libmpq__store_le32(bet_wire + 16, count);
    libmpq__store_le32(bet_wire + 24, 130);
    libmpq__store_le32(bet_wire + 32, 64);
    libmpq__store_le32(bet_wire + 36, 96);
    libmpq__store_le32(bet_wire + 40, 128);
    libmpq__store_le32(bet_wire + 44, 129);
    libmpq__store_le32(bet_wire + 48, 64);
    libmpq__store_le32(bet_wire + 52, 32);
    libmpq__store_le32(bet_wire + 56, 32);
    libmpq__store_le32(bet_wire + 60, 1);
    libmpq__store_le32(bet_wire + 64, 1);
    libmpq__store_le32(bet_wire + 68, 58);
    libmpq__store_le32(bet_wire + 72, 2);
    libmpq__store_le32(bet_wire + 76, 56);
    libmpq__store_le32(bet_wire + 80, (uint32_t)hash_bytes);
    libmpq__store_le32(bet_wire + 84, 2);
    libmpq__store_le32(bet_wire + 88, flags);
    libmpq__store_le32(bet_wire + 92, LIBMPQ_FLAG_EXISTS);
    libmpq__store_le32(het_wire, LIBMPQ_HET_SIGNATURE);
    libmpq__store_le32(het_wire + 4, 1);
    libmpq__store_le32(het_wire + 8, 112);
    libmpq__store_le32(het_wire + 12, 112);
    libmpq__store_le32(het_wire + 16, count);
    libmpq__store_le32(het_wire + 20, 64);
    libmpq__store_le32(het_wire + 24, 64);
    libmpq__store_le32(het_wire + 28, 2);
    libmpq__store_le32(het_wire + 36, 2);
    libmpq__store_le32(het_wire + 40, 16);
    for (i = 0; i < count; i++) {
        uint64_t hash;
        mpq_het_hash_s parts;
        uint32_t slot;
        uint64_t offset = shift + (i == 0 ? 68 : 68 + payload_size);
        uint32_t size = i == 0 ? 9000 : (encrypted & 4) ? 72 : sizeof(listfile) - 1;
        TEST_CHECK(libmpq__het_hash_filename(names[i], &hash) == 0);
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, 64, &parts) == 0);
        slot = parts.initial_slot;
        while (het_wire[44 + slot] != 0)
            slot = (slot + 1) % 64;
        het_wire[44 + slot] = parts.name_hash1;
        TEST_CHECK(libmpq__bit_set(het_wire + 108, 16, slot * 2, 2, i) == 0);
        TEST_CHECK(libmpq__bit_set(bet_wire + 96, record_bytes, i * 130, 64, offset) == 0);
        TEST_CHECK(libmpq__bit_set(bet_wire + 96, record_bytes, i * 130 + 64, 32, size) == 0);
        TEST_CHECK(
            libmpq__bit_set(
                bet_wire + 96, record_bytes, i * 130 + 96, 32, i == 0 ? payload_size : size
            ) == 0
        );
        TEST_CHECK(libmpq__bit_set(bet_wire + 96, record_bytes, i * 130 + 128, 1, i) == 0);
        TEST_CHECK(
            libmpq__bit_set(
                bet_wire + 96 + record_bytes, hash_bytes, i * 58, 56, parts.name_hash2
            ) == 0
        );
        TEST_CHECK(
            libmpq__bit_set(bet_wire + 96 + record_bytes, hash_bytes, i * 58 + 56, 2, 3) == 0
        );
    }
    source->het_offset = shift + source->size;
    TEST_CHECK(
        reader_v3_store_table(source, het_wire, sizeof(het_wire), compress_het, "(hash table)") == 0
    );
    source->bet_offset = shift + source->size;
    TEST_CHECK(
        reader_v3_store_table(source, bet_wire, bet_size, compress_bet, "(block table)") == 0
    );
    if (classic != 0) {
        mpq_block_s block[2] = { { 68, (uint32_t)payload_size, 9000, flags },
                                 { (uint32_t)(68 + payload_size), 72, 72, LIBMPQ_FLAG_EXISTS } };
        mpq_hash_s hashes[8];
        header.block_table_count = classic == 3 ? 2 : 1;
        if (classic == 1) {
            memset(hashes, 0xff, sizeof(hashes));
            header.hash_table_count = 8;
            header.hash_table_offset = (uint32_t)(shift + source->size);
            ex.hash_table_offset_high = (uint16_t)(shift >> 32);
            for (i = 0; i < 2; i++) {
                uint32_t h1;
                uint32_t h2;
                uint32_t h3;
                uint32_t slot;
                libmpq__file_hash(i == 0 ? "payload.bin" : "fallback.bin", &h1, &h2, &h3);
                slot = h1 & 7;
                while (hashes[slot].block_table_index != LIBMPQ_HASH_FREE)
                    slot = (slot + 1) & 7;
                hashes[slot] = (mpq_hash_s){ h2, h3, 0, 0, 0 };
            }
            TEST_CHECK(
                libmpq__hash_table_encode(hashes, 8, source->bytes + source->size, 128) == 0
            );
            TEST_CHECK(
                libmpq__crypto_encrypt_block(
                    source->bytes + source->size, 128,
                    libmpq__crypto_hash_string("(hash table)", 0x300)
                ) == 0
            );
            source->size += 128;
        }
        header.block_table_offset = (uint32_t)(shift + source->size);
        ex.block_table_offset_high = (uint16_t)(shift >> 32);
        TEST_CHECK(
            libmpq__block_table_encode(
                block, header.block_table_count, source->bytes + source->size,
                16 * header.block_table_count
            ) == 0
        );
        TEST_CHECK(
            libmpq__crypto_encrypt_block(
                source->bytes + source->size, 16 * header.block_table_count,
                libmpq__crypto_hash_string("(block table)", 0x300)
            ) == 0
        );
        source->size += 16 * header.block_table_count;
        if (high) {
            ex.extended_offset = shift + source->size;
            libmpq__store_le16(source->bytes + source->size, (uint16_t)(shift >> 32));
            source->size += 2;
        }
    }
    v3 = (mpq_header_v3_s){ shift + source->size, source->bet_offset, source->het_offset };
    TEST_CHECK(libmpq__header_encode(&header, source->bytes, 32) == 0);
    TEST_CHECK(libmpq__header_ex_encode(&ex, source->bytes + 32, 12) == 0);
    TEST_CHECK(libmpq__header_v3_encode(&v3, source->bytes + 44, 24) == 0);
    if ((encrypted & 1) != 0 && !empty) {
        uint32_t seed =
            (libmpq__crypto_hash_string("payload.bin", 0x300) + (uint32_t)(shift + 68)) ^ 9000u;
        if ((encrypted & 2) != 0) {
            TEST_CHECK(
                libmpq__crypto_encrypt_block(source->bytes + 68, (uint32_t)payload_size, seed) == 0
            );
        } else
            for (i = 0; i < 9000; i += 4096) {
                uint32_t size = 9000 - i < 4096 ? 9000 - i : 4096;
                TEST_CHECK(
                    libmpq__crypto_encrypt_block(source->bytes + 68 + i, size, seed + i / 4096) == 0
                );
            }
    }
    return 0;
}

/* Same-index rows merge even when metadata differs; other rows never alias. */
static int
reader_v3_mixed_fixture(
    reader_v3_source_s *source, uint32_t classic_count, uint32_t bet_count, int live_sources,
    int attributes
)
{
    uint32_t capacity = classic_count > bet_count ? classic_count : bet_count;
    mpq_header_s header = { LIBMPQ_HEADER, 68, 0, LIBMPQ_ARCHIVE_VERSION_THREE, 3, 0, 0, 16,
                            classic_count };
    mpq_header_ex_s ex = { 0 };
    mpq_header_v3_s v3;
    mpq_block_s blocks[4];
    mpq_hash_s hashes[16];
    uint8_t het[132] = { 0 };
    uint8_t bet[256] = { 0 };
    size_t record_bytes;
    size_t hash_bytes;
    size_t bet_size;
    uint32_t i;
    TEST_CHECK(capacity <= 4 && classic_count >= 2 && bet_count >= 2);
    memset(source, 0, sizeof(*source));
    source->size = 68 + capacity * 64;
    memset(hashes, 0xff, sizeof(hashes));
    for (i = 0; i < capacity; i++) {
        char name[32];
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        uint32_t slot;
        for (uint32_t j = 0; j < 64; j++)
            source->bytes[68 + i * 64 + j] = (uint8_t)(i * 71 + j);
        blocks[i] = (mpq_block_s){ 68 + i * 64, 64, 64, LIBMPQ_FLAG_EXISTS };
        if ((live_sources == 1 && i == 1) || (live_sources == 2 && i == 0))
            blocks[i].flags = 0;
        if (attributes && i == 1) {
            blocks[i].packed_size = blocks[i].unpacked_size = 8 + classic_count * 4;
            libmpq__store_le32(source->bytes + blocks[i].offset, 100);
            libmpq__store_le32(source->bytes + blocks[i].offset + 4, LIBMPQ_ATTRIBUTE_CRC32);
        }
        if (i >= classic_count)
            continue;
        for (uint32_t alias = 0; alias < 2; alias++) {
            if (attributes && i == 1 && alias != 0)
                continue;
            TEST_CHECK(
                snprintf(name, sizeof(name), alias ? "bet-%u.bin" : "classic-%u.bin", i) > 0
            );
            libmpq__file_hash(attributes && i == 1 ? "(attributes)" : name, &h1, &h2, &h3);
            slot = h1 & 15;
            while (hashes[slot].block_table_index != LIBMPQ_HASH_FREE)
                slot = (slot + 1) & 15;
            hashes[slot] = (mpq_hash_s){ h2, h3, 0, 0, i };
        }
    }
    if (attributes)
        for (i = 0; i < classic_count; i++)
            libmpq__store_le32(
                source->bytes + blocks[1].offset + 8 + i * 4,
                i == 1 ? 0 : (uint32_t)crc32(0, source->bytes + 68 + i * 64, 64)
            );
    TEST_CHECK(libmpq__bit_bytes(bet_count, 130, &record_bytes) == 0);
    TEST_CHECK(libmpq__bit_bytes(bet_count, 56, &hash_bytes) == 0);
    bet_size = 100 + record_bytes + hash_bytes;
    libmpq__store_le32(bet, LIBMPQ_BET_SIGNATURE);
    libmpq__store_le32(bet + 4, 1);
    libmpq__store_le32(bet + 8, (uint32_t)bet_size - 12);
    libmpq__store_le32(bet + 12, (uint32_t)bet_size - 12);
    libmpq__store_le32(bet + 16, bet_count);
    libmpq__store_le32(bet + 24, 130);
    libmpq__store_le32(bet + 32, 64);
    libmpq__store_le32(bet + 36, 96);
    libmpq__store_le32(bet + 40, 128);
    libmpq__store_le32(bet + 44, 130);
    libmpq__store_le32(bet + 48, 64);
    libmpq__store_le32(bet + 52, 32);
    libmpq__store_le32(bet + 56, 32);
    libmpq__store_le32(bet + 60, 2);
    libmpq__store_le32(bet + 68, 56);
    libmpq__store_le32(bet + 76, 56);
    libmpq__store_le32(bet + 80, (uint32_t)hash_bytes);
    libmpq__store_le32(bet + 84, 3);
    libmpq__store_le32(bet + 88, LIBMPQ_FLAG_EXISTS);
    libmpq__store_le32(bet + 92, LIBMPQ_FLAG_EXISTS | LIBMPQ_FLAG_SINGLE);
    libmpq__store_le32(het, LIBMPQ_HET_SIGNATURE);
    libmpq__store_le32(het + 4, 1);
    libmpq__store_le32(het + 8, 120);
    libmpq__store_le32(het + 12, 120);
    libmpq__store_le32(het + 16, bet_count);
    libmpq__store_le32(het + 20, 64);
    libmpq__store_le32(het + 24, 64);
    libmpq__store_le32(het + 28, 3);
    libmpq__store_le32(het + 36, 3);
    libmpq__store_le32(het + 40, 24);
    for (i = 0; i < bet_count; i++) {
        char name[32];
        uint64_t hash;
        mpq_het_hash_s parts;
        uint32_t slot;
        uint32_t flag_index = live_sources && i == 0 ? 2 : i == 0 ? 1 : 0;
        uint64_t offset = blocks[i].offset;
        uint32_t packed = blocks[i].packed_size;
        uint32_t unpacked = blocks[i].unpacked_size;
        if (i == 0) {
            offset++;
            packed = 16;
            unpacked = 16;
        }

        /* Equal metadata on distinct rows must not cause heuristic deduplication. */
        if (i == 3) {
            offset = blocks[0].offset;
            packed = unpacked = 64;
        }
        TEST_CHECK(snprintf(name, sizeof(name), "bet-%u.bin", i) > 0);
        TEST_CHECK(
            libmpq__het_hash_filename(attributes && i == 1 ? "(attributes)" : name, &hash) == 0
        );
        TEST_CHECK(libmpq__het_hash_partition(hash, 64, 64, &parts) == 0);
        slot = parts.initial_slot;
        while (het[44 + slot] != 0)
            slot = (slot + 1) % 64;
        het[44 + slot] = parts.name_hash1;
        TEST_CHECK(libmpq__bit_set(het + 108, 24, slot * 3, 3, i) == 0);
        TEST_CHECK(libmpq__bit_set(bet + 100, record_bytes, i * 130, 64, offset) == 0);
        TEST_CHECK(libmpq__bit_set(bet + 100, record_bytes, i * 130 + 64, 32, unpacked) == 0);
        TEST_CHECK(libmpq__bit_set(bet + 100, record_bytes, i * 130 + 96, 32, packed) == 0);
        TEST_CHECK(libmpq__bit_set(bet + 100, record_bytes, i * 130 + 128, 2, flag_index) == 0);
        TEST_CHECK(
            libmpq__bit_set(bet + 100 + record_bytes, hash_bytes, i * 56, 56, parts.name_hash2) == 0
        );
    }
    source->het_offset = source->size;
    TEST_CHECK(reader_v3_store_table(source, het, sizeof(het), 0, "(hash table)") == 0);
    source->bet_offset = source->size;
    TEST_CHECK(reader_v3_store_table(source, bet, bet_size, 0, "(block table)") == 0);
    header.hash_table_offset = (uint32_t)source->size;
    TEST_CHECK(libmpq__hash_table_encode(hashes, 16, source->bytes + source->size, 256) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source->bytes + source->size, 256, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    source->size += 256;
    header.block_table_offset = (uint32_t)source->size;
    TEST_CHECK(
        libmpq__block_table_encode(
            blocks, classic_count, source->bytes + source->size, classic_count * 16
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source->bytes + source->size, classic_count * 16,
            libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    source->size += classic_count * 16;
    v3 = (mpq_header_v3_s){ source->size, source->bet_offset, source->het_offset };
    TEST_CHECK(libmpq__header_encode(&header, source->bytes, 32) == 0);
    TEST_CHECK(libmpq__header_ex_encode(&ex, source->bytes + 32, 12) == 0);
    TEST_CHECK(libmpq__header_v3_encode(&v3, source->bytes + 44, 24) == 0);
    return 0;
}

static int
test_v3_mixed_rows(uint32_t classic_count, uint32_t bet_count, int live_sources, int attributes)
{
    reader_v3_source_s source;
    mpq_archive_s *archive = NULL;
    uint32_t capacity = classic_count > bet_count ? classic_count : bet_count;
    uint32_t files;
    TEST_CHECK(
        reader_v3_mixed_fixture(&source, classic_count, bet_count, live_sources, attributes) == 0
    );
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == 0
    );
    TEST_CHECK(archive->entry_count == capacity);
    if (attributes) {
        mpq_entry_s saved = archive->mpq_entry[0];
        archive->mpq_entry[0] = archive->mpq_entry[2];
        archive->mpq_entry[2] = saved;
        for (uint32_t i = 0; i < capacity; i++) {
            const mpq_entry_s *entry = &archive->mpq_entry[i];
            if ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0)
                archive->classic_entry_indices[entry->classic_source_index] = i;
            if ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) != 0)
                archive->bet_entry_indices[entry->bet_source_index] = i;
            archive->mpq_map[entry->file_number].entry_index = i;
        }
    }
    TEST_CHECK(
        libmpq__archive_files(archive, &files) == 0 && files == capacity - (live_sources == 2)
    );
    for (uint32_t i = 0; i < capacity; i++) {
        char name[32];
        uint32_t index;
        uint32_t classic_index = UINT32_MAX;
        uint32_t bet_index = UINT32_MAX;
        uint32_t number;
        uint32_t classic_number;
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        uint32_t flags;
        libmpq__off_t value;
        libmpq__off_t transferred;
        uint8_t data[64];
        mpq_stream_s *stream = NULL;
        mpq_entry_s saved;
        if (i < classic_count)
            TEST_CHECK(libmpq__entry_index_from_classic(archive, i, &classic_index) == 0);
        if (i < bet_count)
            TEST_CHECK(libmpq__entry_index_from_bet(archive, i, &bet_index) == 0);
        if (i < classic_count && i < bet_count)
            TEST_CHECK(classic_index == bet_index);
        index = i < bet_count ? bet_index : classic_index;
        saved = archive->mpq_entry[index];
        if (i == 0 && live_sources == 0) {
            mpq_bet_entry_s raw;
            TEST_CHECK(libmpq__bet_record_decode(&archive->mpq_bet, 0, &raw) == 0);
            TEST_CHECK(
                raw.offset != saved.offset && raw.packed_size != saved.packed_size &&
                raw.unpacked_size != saved.unpacked_size && raw.flags != saved.flags
            );
        }
        TEST_CHECK(
            saved.source_mask == ((i < classic_count ? LIBMPQ_ENTRY_SOURCE_CLASSIC : 0) |
                                  (i < bet_count ? LIBMPQ_ENTRY_SOURCE_BET : 0))
        );
        TEST_CHECK(saved.classic_source_index == (i < classic_count ? i : UINT32_MAX));
        TEST_CHECK(saved.bet_source_index == (i < bet_count ? i : UINT32_MAX));
        if (i == 3 && i >= classic_count) {
            const mpq_entry_s *first = &archive->mpq_entry[archive->bet_entry_indices[0]];
            TEST_CHECK(saved.offset == first->offset);
            TEST_CHECK(saved.packed_size == first->packed_size);
            TEST_CHECK(saved.unpacked_size == first->unpacked_size);
            TEST_CHECK(saved.flags == first->flags);
            TEST_CHECK(index != archive->bet_entry_indices[0]);
        }
        if (live_sources == 2 && i == 0) {
            TEST_CHECK((saved.flags & LIBMPQ_FLAG_EXISTS) == 0 && saved.file_number == UINT32_MAX);
            continue;
        }
        TEST_CHECK(
            snprintf(name, sizeof(name), i < bet_count ? "bet-%u.bin" : "classic-%u.bin", i) > 0
        );
        TEST_CHECK(
            libmpq__file_number(archive, attributes && i == 1 ? "(attributes)" : name, &number) == 0
        );
        TEST_CHECK(archive->mpq_map[number].entry_index == index);
        if (i < classic_count && !(live_sources && i == 1)) {
            TEST_CHECK(snprintf(name, sizeof(name), "classic-%u.bin", i) > 0);
            libmpq__file_hash(attributes && i == 1 ? "(attributes)" : name, &h1, &h2, &h3);
            TEST_CHECK(libmpq__file_number_from_hash(archive, h1, h2, h3, &classic_number) == 0);
            TEST_CHECK(classic_number == number);
            if (i < bet_count) {
                TEST_CHECK(snprintf(name, sizeof(name), "bet-%u.bin", i) > 0);
                libmpq__file_hash(attributes && i == 1 ? "(attributes)" : name, &h1, &h2, &h3);
                TEST_CHECK(
                    libmpq__file_number_from_hash(archive, h1, h2, h3, &classic_number) == 0
                );
                TEST_CHECK(classic_number == number);
            }
            TEST_CHECK(saved.offset == archive->mpq_block[i].offset);
            TEST_CHECK(saved.packed_size == archive->mpq_block[i].packed_size);
            TEST_CHECK(saved.unpacked_size == archive->mpq_block[i].unpacked_size);
            TEST_CHECK(saved.flags == archive->mpq_block[i].flags);
        }
        TEST_CHECK(
            libmpq__file_offset(archive, number, &value) == 0 && (uint64_t)value == saved.offset
        );
        TEST_CHECK(
            libmpq__file_size_packed(archive, number, &value) == 0 &&
            (uint64_t)value == saved.packed_size
        );
        TEST_CHECK(
            libmpq__file_size_unpacked(archive, number, &value) == 0 &&
            (uint64_t)value == saved.unpacked_size
        );
        TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0 && flags == saved.flags);
        TEST_CHECK(
            libmpq__file_read(archive, number, data, sizeof(data), &transferred) == 0 &&
            (uint64_t)transferred == saved.unpacked_size
        );
        TEST_CHECK(memcmp(data, source.bytes + saved.offset, (size_t)transferred) == 0);
        TEST_CHECK(libmpq__stream_open(archive, number, &stream) == 0);
        TEST_CHECK(
            libmpq__stream_read(stream, data, sizeof(data), &transferred) == 0 &&
            (uint64_t)transferred == saved.unpacked_size
        );
        TEST_CHECK(memcmp(data, source.bytes + saved.offset, (size_t)transferred) == 0);
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        if (attributes && i != 1) {
            mpq_file_attributes_s info;
            int32_t result = libmpq__file_attributes(archive, number, &info);
            if (i < classic_count)
                TEST_CHECK(
                    result == 0 && info.crc32 == (uint32_t)crc32(0, source.bytes + saved.offset, 64)
                );
            else
                TEST_CHECK(result == LIBMPQ_ERROR_FORMAT);
        }
        if (i < classic_count) {
            archive->mpq_entry[index].source_mask &= (uint8_t)~LIBMPQ_ENTRY_SOURCE_CLASSIC;
            TEST_CHECK(
                libmpq__entry_index_from_classic(archive, i, &classic_index) == LIBMPQ_ERROR_FORMAT
            );
            archive->mpq_entry[index] = saved;
            archive->mpq_entry[index].classic_source_index = UINT32_MAX;
            TEST_CHECK(
                libmpq__entry_index_from_classic(archive, i, &classic_index) == LIBMPQ_ERROR_FORMAT
            );
            archive->mpq_entry[index] = saved;
            archive->classic_entry_indices[i] = capacity;
            TEST_CHECK(
                libmpq__entry_index_from_classic(archive, i, &classic_index) == LIBMPQ_ERROR_FORMAT
            );
            archive->classic_entry_indices[i] = index;
        }
        if (i < bet_count) {
            archive->mpq_entry[index].source_mask &= (uint8_t)~LIBMPQ_ENTRY_SOURCE_BET;
            TEST_CHECK(libmpq__entry_index_from_bet(archive, i, &bet_index) == LIBMPQ_ERROR_FORMAT);
            archive->mpq_entry[index] = saved;
            archive->mpq_entry[index].bet_source_index = UINT32_MAX;
            TEST_CHECK(libmpq__entry_index_from_bet(archive, i, &bet_index) == LIBMPQ_ERROR_FORMAT);
            archive->mpq_entry[index] = saved;
            archive->bet_entry_indices[i] = capacity;
            TEST_CHECK(libmpq__entry_index_from_bet(archive, i, &bet_index) == LIBMPQ_ERROR_FORMAT);
            archive->bet_entry_indices[i] = index;
        }
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

static int
test_v3_bet_read(
    int compressed_het, int compressed_bet, int classic, int high, int encrypted, int empty,
    uint64_t shift, uint64_t base
)
{
    reader_v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t actual[9000];
    uint8_t *list = NULL;
    size_t list_size;
    uint32_t number;
    uint32_t files;
    uint32_t flags;
    uint32_t index;
    uint64_t het_size;
    uint64_t bet_size;
    libmpq__off_t size;
    libmpq__off_t transferred;
    TEST_CHECK(
        reader_v3_fixture(
            &source, compressed_het, compressed_bet, classic, high, encrypted, empty, shift, base
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v3_read_at, (libmpq__off_t)(shift + base + source.size),
            base ? -1 : 0, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == (empty ? 0u : 2u));
    TEST_CHECK(libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size) == 0);
    TEST_CHECK(het_size == source.bet_offset - source.het_offset);
    TEST_CHECK(
        bet_size == (classic == 1   ? shift + archive->mpq_header.hash_table_offset
                     : classic == 2 ? shift + archive->mpq_header.block_table_offset
                                    : shift + source.size) -
                        source.bet_offset
    );
    if (!empty) {
        TEST_CHECK(libmpq__file_number(archive, "PAYLOAD.BIN", &number) == 0);
        TEST_CHECK(libmpq__entry_index_from_bet(archive, 0, &index) == 0);
        TEST_CHECK(archive->mpq_map[number].entry_index == index);
        if (classic != 0) {
            uint32_t classic_index;
            TEST_CHECK(libmpq__entry_index_from_classic(archive, 0, &classic_index) == 0);
            TEST_CHECK(classic_index == index);
        }
        TEST_CHECK(
            libmpq__file_offset(archive, number, &size) == 0 && (uint64_t)size == shift + 68
        );
        TEST_CHECK(
            libmpq__file_size_packed(archive, number, &size) == 0 &&
            ((encrypted & 2) ? size < 9000 : size == 9000)
        );
        TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == 0 && size == 9000);
        TEST_CHECK(
            libmpq__file_flags(archive, number, &flags) == 0 && (flags & LIBMPQ_FLAG_EXISTS)
        );
        TEST_CHECK(
            (flags & LIBMPQ_FLAG_COMPRESS_MULTI) ==
            ((encrypted & 2) ? LIBMPQ_FLAG_COMPRESS_MULTI : 0u)
        );
        if ((encrypted & 1) == 0) {
            memset(actual, 0xa5, sizeof(actual));
            TEST_CHECK(
                libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0 &&
                transferred == 9000
            );
            for (uint32_t i = 0; i < 9000; i++)
                TEST_CHECK(actual[i] == (uint8_t)(i * 17u + i / 31u));
        }
        TEST_CHECK(libmpq__stream_open_name(archive, "payload.bin", &stream) == 0);
        TEST_CHECK(libmpq__stream_size(stream, &size) == 0 && size == 9000);
        memset(actual, 0xa5, sizeof(actual));
        TEST_CHECK(
            libmpq__stream_read(stream, actual, 4501, &transferred) == 0 && transferred == 4501
        );
        TEST_CHECK(
            libmpq__stream_read(stream, actual + 4501, 4499, &transferred) == 0 &&
            transferred == 4499
        );
        for (uint32_t i = 0; i < 9000; i++)
            TEST_CHECK(actual[i] == (uint8_t)(i * 17u + i / 31u));
        TEST_CHECK(libmpq__stream_tell(stream, &size) == 0 && size == 9000);
        TEST_CHECK(libmpq__stream_read(stream, actual, 1, &transferred) == 0 && transferred == 0);
        TEST_CHECK(libmpq__stream_seek(stream, -17, LIBMPQ_SEEK_END) == 0);
        TEST_CHECK(libmpq__stream_read(stream, actual, 17, &transferred) == 0 && transferred == 17);
        for (uint32_t i = 0; i < 17; i++)
            TEST_CHECK(actual[i] == (uint8_t)((8983 + i) * 17u + (8983 + i) / 31u));
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == 0);
        TEST_CHECK(test_archive_read(archive, number, &list, &list_size) == 0);
        TEST_CHECK(list_size == 13 && memcmp(list, "payload.bin\r\n", 13) == 0);
        free(list);
        if (classic == 1) {
            TEST_CHECK(libmpq__file_number(archive, "fallback.bin", &number) == 0);
            TEST_CHECK(
                archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask ==
                (LIBMPQ_ENTRY_SOURCE_CLASSIC | LIBMPQ_ENTRY_SOURCE_BET)
            );
        }
        archive->bet_entry_indices[0] = UINT32_MAX;
        TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == LIBMPQ_ERROR_FORMAT);
        archive->bet_entry_indices[0] = index;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

static int
reader_v3_expect_failure(reader_v3_source_s *source)
{
    mpq_archive_s *archive = NULL;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, source, reader_v3_read_at,
            (libmpq__off_t)(source->base + source->shift + source->size), 0, NULL
        ) != 0
    );
    TEST_CHECK(archive == NULL);
    return 0;
}

/* Present one table at a virtual extent without allocating that extent. */
typedef struct
{
    reader_v3_source_s source;
    const uint8_t *table;
    size_t available;
    size_t stored_size;
    size_t offset;
    size_t original_size;
    size_t extent;
    unsigned int envelope_reads;
    unsigned int payload_reads;
} reader_v3_limit_source_s;

static int32_t
reader_v3_limit_read_at(void *context, libmpq__off_t offset, uint8_t *output, size_t size)
{
    reader_v3_limit_source_s *source = context;
    size_t start;
    size_t copied = 0;
    if (offset < 0 || (uint64_t)offset > source->extent || size > source->extent - (uint64_t)offset)
        return LIBMPQ_ERROR_READ;
    start = (size_t)offset;
    while (copied < size) {
        size_t position = start + copied;
        size_t count;
        const uint8_t *input;
        if (position < source->offset) {
            count = source->offset - position;
            input = source->source.bytes + position;
        } else if (position < source->offset + source->stored_size) {
            size_t index = position - source->offset;
            if (index < LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE)
                source->envelope_reads++;
            else
                source->payload_reads++;
            if (index >= source->available || size - copied > source->available - index)
                return LIBMPQ_ERROR_READ;
            count = source->available - index;
            input = source->table + index;
        } else {
            size_t index = position - source->stored_size + source->original_size;
            count = source->source.size - index;
            input = source->source.bytes + index;
        }
        if (count > size - copied)
            count = size - copied;
        memcpy(output + copied, input, count);
        copied += count;
    }
    return 0;
}

static int
reader_v3_limit_fixture(reader_v3_limit_source_s *source, int bet, size_t stored_size)
{
    memset(source, 0, sizeof(*source));
    TEST_CHECK(reader_v3_fixture(&source->source, 0, 0, 0, 0, 0, 1, 0, 0) == 0);
    source->offset = (size_t)(bet ? source->source.bet_offset : source->source.het_offset);
    source->original_size =
        (bet ? source->source.size : (size_t)source->source.bet_offset) - source->offset;
    source->table = source->source.bytes + source->offset;
    source->available = source->original_size;
    source->stored_size = stored_size;
    source->extent = source->source.size - source->original_size + stored_size;
    libmpq__store_le64(source->source.bytes + 44, source->extent);
    if (!bet)
        libmpq__store_le64(source->source.bytes + 52, source->offset + stored_size);
    return 0;
}

/* Both mismatches have individually valid headers and unchanged array geometry. */
static int
test_v3_table_counts(void)
{
    for (uint32_t count = 1; count <= 3; count += 2) {
        reader_v3_source_s source;
        mpq_archive_s *archive = NULL;
        mpq_het_s het;
        mpq_bet_s bet;
        uint32_t key;
        TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
        key = libmpq__crypto_hash_string("(hash table)", 0x300);
        TEST_CHECK(
            libmpq__crypto_decrypt_block(source.bytes + source.het_offset + 12, 112, key) == 0
        );
        libmpq__store_le32(source.bytes + source.het_offset + 16, count);
        TEST_CHECK(libmpq__het_view_init(source.bytes + source.het_offset, 124, &het) == 0);
        TEST_CHECK(het.header.entry_count == count);
        TEST_CHECK(
            libmpq__crypto_encrypt_block(source.bytes + source.het_offset + 12, 112, key) == 0
        );
        key = libmpq__crypto_hash_string("(block table)", 0x300);
        TEST_CHECK(
            libmpq__crypto_decrypt_block(
                source.bytes + source.bet_offset + 12,
                (uint32_t)(source.size - source.bet_offset - 12), key
            ) == 0
        );
        TEST_CHECK(
            libmpq__bet_view_init(
                source.bytes + source.bet_offset, source.size - source.bet_offset, &bet
            ) == 0
        );
        TEST_CHECK(bet.header.entry_count == 2);
        TEST_CHECK(
            libmpq__crypto_encrypt_block(
                source.bytes + source.bet_offset + 12,
                (uint32_t)(source.size - source.bet_offset - 12), key
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(archive == NULL);
    }
    return 0;
}

/* Rejected extents need no large backing buffer and must never reach payload I/O. */
static int
test_v3_table_limits(void)
{
    for (int bet = 0; bet < 2; bet++) {
        for (int decoded = 0; decoded < 2; decoded++) {
            reader_v3_limit_source_s source;
            mpq_archive_s *archive = NULL;
            size_t normal_size = bet ? 96 : 124;
            TEST_CHECK(
                reader_v3_limit_fixture(
                    &source, bet, decoded ? normal_size : LIBMPQ_EXT_TABLE_MAX_SIZE + 1
                ) == 0
            );
            if (decoded)
                libmpq__store_le32(
                    source.source.bytes + source.offset + 8,
                    LIBMPQ_EXT_TABLE_MAX_SIZE + 1 - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE
                );
            TEST_CHECK(
                libmpq__archive_open_io(
                    &archive, &source, reader_v3_limit_read_at, (libmpq__off_t)source.extent, 0,
                    NULL
                ) == LIBMPQ_ERROR_FORMAT
            );
            TEST_CHECK(archive == NULL);
            TEST_CHECK(source.envelope_reads == (unsigned int)decoded);
            TEST_CHECK(source.payload_reads == 0);
        }
    }
    return 0;
}

/* A real limit-sized decoded table is needed only for the valid inclusive boundary. */
static int
test_v3_table_limit_boundary(void)
{
    uint8_t *table = calloc(1, LIBMPQ_EXT_TABLE_MAX_SIZE);
    uint8_t compressed[16384];
    TEST_CHECK(table != NULL);
    for (int bet = 0; bet < 2; bet++) {
        uint32_t payload_size = LIBMPQ_EXT_TABLE_MAX_SIZE - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
        uint32_t key = libmpq__crypto_hash_string(bet ? "(block table)" : "(hash table)", 0x300);
        memset(table, 0, LIBMPQ_EXT_TABLE_MAX_SIZE);
        libmpq__store_le32(table, bet ? LIBMPQ_BET_SIGNATURE : LIBMPQ_HET_SIGNATURE);
        libmpq__store_le32(table + 4, LIBMPQ_EXT_TABLE_VERSION);
        libmpq__store_le32(table + 8, payload_size);
        libmpq__store_le32(table + 12, payload_size);
        if (bet) {
            mpq_bet_s view;
            libmpq__store_le32(table + 24, 18);
            libmpq__store_le32(table + 60, 18);
            libmpq__store_le32(table + 68, 56);
            libmpq__store_le32(table + 76, 56);
            libmpq__store_le32(table + 84, (payload_size - LIBMPQ_BET_HEADER_WIRE_SIZE) / 4);
            TEST_CHECK(libmpq__bet_view_init(table, LIBMPQ_EXT_TABLE_MAX_SIZE, &view) == 0);
        } else {
            mpq_het_s view;
            uint32_t slots = (payload_size - LIBMPQ_HET_HEADER_WIRE_SIZE) / 2;
            libmpq__store_le32(table + 20, slots);
            libmpq__store_le32(table + 24, 64);
            libmpq__store_le32(table + 28, 8);
            libmpq__store_le32(table + 36, 8);
            libmpq__store_le32(table + 40, slots);
            TEST_CHECK(libmpq__het_view_init(table, LIBMPQ_EXT_TABLE_MAX_SIZE, &view) == 0);
        }

        /* Test decoded-at-limit with compression, then stored-at-limit without it. */
        for (int packed = 1; packed >= 0; packed--) {
            reader_v3_limit_source_s source;
            mpq_archive_s *archive = NULL;
            unsigned long length = sizeof(compressed) - 13;
            size_t stored_size = LIBMPQ_EXT_TABLE_MAX_SIZE;
            uint8_t *stored = table;
            uint32_t files;
            if (packed) {
                memcpy(compressed, table, 12);
                compressed[12] = LIBMPQ_COMPRESSION_ZLIB;
                TEST_CHECK(
                    compress2(compressed + 13, &length, table + 12, payload_size, 9) == Z_OK
                );
                stored = compressed;
                stored_size = (size_t)length + 13;
            }
            TEST_CHECK(
                libmpq__crypto_encrypt_block(stored + 12, (uint32_t)stored_size - 12, key) == 0
            );
            TEST_CHECK(reader_v3_limit_fixture(&source, bet, stored_size) == 0);
            source.table = stored;
            source.available = stored_size;
            TEST_CHECK(
                libmpq__archive_open_io(
                    &archive, &source, reader_v3_limit_read_at, (libmpq__off_t)source.extent, 0,
                    NULL
                ) == 0
            );
            TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 0);
            TEST_CHECK(source.envelope_reads == 1 && source.payload_reads == 1);
            TEST_CHECK(libmpq__archive_close(archive) == 0);
        }
    }
    free(table);
    return 0;
}

/* Malformed extents, compressed streams and packed indices must not fall back. */
static int
test_v3_bet_errors(void)
{
    reader_v3_source_s source;
    reader_v3_source_s original;
    mpq_archive_s *archive = NULL;
    uint32_t number;
    uint64_t hash;
    mpq_het_hash_s parts;
    uint8_t *het;
    uint8_t *bet;
    mpq_bet_s bet_view;
    uint32_t key;
    TEST_CHECK(reader_v3_fixture(&original, 0, 0, 1, 1, 0, 0, 0, 0) == 0);
    source = original;
    libmpq__store_le64(source.bytes + 60, source.bet_offset); /* overlapping HET/BET */
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    libmpq__store_le64(source.bytes + 60, source.bet_offset + 1); /* out of order */
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    libmpq__store_le64(source.bytes + 52, source.het_offset + 11); /* short HET extent */
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    libmpq__store_le64(source.bytes + 52, source.size); /* BET past archive end */
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    libmpq__store_le64(source.bytes + 52, 0); /* incomplete pair */
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    libmpq__store_le32(source.bytes + source.het_offset + 8, UINT32_MAX);
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    source.fail_at = source.bet_offset + 12;
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    source = original;
    key = libmpq__crypto_hash_string("(hash table)", 0x300);
    het = source.bytes + source.het_offset;
    TEST_CHECK(libmpq__crypto_decrypt_block(het + 12, 112, key) == 0);
    TEST_CHECK(libmpq__het_hash_filename("payload.bin", &hash) == 0);
    TEST_CHECK(libmpq__het_hash_partition(hash, 64, 64, &parts) == 0);
    TEST_CHECK(libmpq__bit_set(het + 108, 16, parts.initial_slot * 2, 2, 3) == 0);
    TEST_CHECK(libmpq__crypto_encrypt_block(het + 12, 112, key) == 0);
    TEST_CHECK(reader_v3_expect_failure(&source) == 0);

    /* A valid hash mismatch is a miss, unlike a malformed table/index. */
    TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
    bet = source.bytes + source.bet_offset;
    key = libmpq__crypto_hash_string("(block table)", 0x300);
    TEST_CHECK(
        libmpq__crypto_decrypt_block(
            bet + 12, (uint32_t)(source.size - source.bet_offset - 12), key
        ) == 0
    );
    TEST_CHECK(libmpq__bet_view_init(bet, source.size - source.bet_offset, &bet_view) == 0);
    TEST_CHECK(
        libmpq__bit_set(
            (uint8_t *)bet_view.name_hash2, bet_view.name_hash2_size, 0, 56, parts.name_hash2 ^ 1
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            bet + 12, (uint32_t)(source.size - source.bet_offset - 12), key
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    /* Invalid flag indices and payload ranges fail during BET population. */
    for (uint32_t i = 0; i < 3; i++) {
        TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
        bet = source.bytes + source.bet_offset;
        TEST_CHECK(
            libmpq__crypto_decrypt_block(
                bet + 12, (uint32_t)(source.size - source.bet_offset - 12), key
            ) == 0
        );
        TEST_CHECK(libmpq__bet_view_init(bet, source.size - source.bet_offset, &bet_view) == 0);
        if (i < 2) {
            TEST_CHECK(
                libmpq__bit_set(
                    (uint8_t *)bet_view.records, bet_view.records_size, 0, 64,
                    i == 0 ? UINT64_MAX : source.size - 1
                ) == 0
            );
        } else {

            /* Keep layout valid but leave record one's flag index outside the array. */
            memmove(bet + 92, bet + 96, source.size - source.bet_offset - 96);
            source.size -= 4;
            libmpq__store_le32(bet + 8, (uint32_t)(source.size - source.bet_offset - 12));
            libmpq__store_le32(bet + 12, (uint32_t)(source.size - source.bet_offset - 12));
            libmpq__store_le32(bet + 84, 1);
            libmpq__store_le64(source.bytes + 44, source.size);
        }
        TEST_CHECK(
            libmpq__crypto_encrypt_block(
                bet + 12, (uint32_t)(source.size - source.bet_offset - 12), key
            ) == 0
        );
        TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    }
    for (uint32_t i = 0; i < 3; i++) {
        TEST_CHECK(reader_v3_fixture(&source, i == 0, i != 0, 0, 0, 0, 0, 0, 0) == 0);
        uint64_t position = i == 0 ? source.het_offset : source.bet_offset;
        key = libmpq__crypto_hash_string(i == 0 ? "(hash table)" : "(block table)", 0x300);
        uint32_t stored = (uint32_t)((i == 0 ? source.bet_offset : source.size) - position - 12);
        TEST_CHECK(libmpq__crypto_decrypt_block(source.bytes + position + 12, stored, key) == 0);
        if (i < 2) {
            source.bytes[position + 12] = 0xff;
        } else {

            /* BET is final here: a ciphered trailing byte must not be ignored. */
            source.bytes[source.size++] = 0x53;
            stored++;
            libmpq__store_le64(source.bytes + 44, source.size);
        }
        TEST_CHECK(libmpq__crypto_encrypt_block(source.bytes + position + 12, stored, key) == 0);
        TEST_CHECK(reader_v3_expect_failure(&source) == 0);
    }
    for (int which = 0; which < 2; which++)
        for (int delta = -1; delta <= 1; delta += 2) {
            TEST_CHECK(reader_v3_fixture(&source, 1, 1, 0, 0, 0, 0, 0, 0) == 0);
            uint8_t *envelope = source.bytes + (which ? source.bet_offset : source.het_offset);
            uint32_t expected = libmpq__load_le32(envelope + 8);
            libmpq__store_le32(envelope + 8, delta < 0 ? expected - 1 : expected + 1);
            TEST_CHECK(reader_v3_expect_failure(&source) == 0);
        }
    return 0;
}

/* Extent inference is ordered, bounded and independent of optional classic tables. */
static int
test_v3_extent_geometry(void)
{
    mpq_archive_s archive = { 0 };
    uint64_t het;
    uint64_t bet;
    archive.mpq_header =
        (mpq_header_s){ LIBMPQ_HEADER, 68, 0, LIBMPQ_ARCHIVE_VERSION_THREE, 3, 160, 192, 2, 2 };
    archive.mpq_header_ex.extended_offset = 224;
    archive.mpq_header_v3 = (mpq_header_v3_s){ 228, 112, 68 };
    for (uint32_t mask = 0; mask < 8; mask++) {
        archive.mpq_header.hash_table_count = (mask & 1) ? 2 : 0;
        archive.mpq_header.block_table_count = (mask & 2) ? 2 : 0;
        archive.mpq_header_ex.extended_offset = (mask & 4) ? 224 : 0;
        TEST_CHECK(libmpq__reader_ext_table_sizes(&archive, &het, &bet) == 0);
        TEST_CHECK(het == 44);
        TEST_CHECK(bet == ((mask & 1) ? 160u : (mask & 2) ? 192u : (mask & 4) ? 224u : 228u) - 112);
    }
    archive.mpq_header.hash_table_count = archive.mpq_header.block_table_count = 2;
    archive.mpq_header_ex.extended_offset = 224;
    archive.mpq_header.block_table_offset = 191; /* one-byte overlap */
    TEST_CHECK(libmpq__reader_ext_table_sizes(&archive, &het, &bet) == LIBMPQ_ERROR_FORMAT);
    archive.mpq_header.block_table_offset = 159; /* reversed classic ordering */
    TEST_CHECK(libmpq__reader_ext_table_sizes(&archive, &het, &bet) == LIBMPQ_ERROR_FORMAT);
    archive.mpq_header.block_table_offset = 192;
    for (uint64_t offset = 228; offset <= 229; offset++) {
        archive.mpq_header_ex.extended_offset = offset;
        TEST_CHECK(libmpq__reader_ext_table_sizes(&archive, &het, &bet) == LIBMPQ_ERROR_FORMAT);
    }
    return 0;
}

/* Fixed format keys are independent of the loader's string-key derivation. */
static int
test_v3_table_keys(void)
{
    reader_v3_source_s source;
    for (int which = 0; which < 2; which++) {
        const uint32_t right = which ? 0xec83b3a3u : 0xc3af3770u;
        const uint32_t wrong = which ? 0xc3af3770u : 0xec83b3a3u;
        TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
        size_t offset = (size_t)(which ? source.bet_offset : source.het_offset);
        uint32_t size = (uint32_t)((which ? source.size : source.bet_offset) - offset - 12);
        uint8_t *table = source.bytes + offset;
        TEST_CHECK(libmpq__crypto_decrypt_block(table + 12, size, right) == 0);
        TEST_CHECK(libmpq__load_le32(table + 12) == libmpq__load_le32(table + 8));
        TEST_CHECK(libmpq__crypto_encrypt_block(table + 12, size, wrong) == 0);
        TEST_CHECK(reader_v3_expect_failure(&source) == 0);
        for (uint32_t field = 0; field < 2; field++) {
            TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
            table = source.bytes + offset;
            libmpq__store_le32(table + field * 4, field == 0 ? 0 : 2);
            TEST_CHECK(reader_v3_expect_failure(&source) == 0);
        }
    }
    return 0;
}

static int
test_v3_signature_discovery(void)
{
    reader_v3_source_s source;
    mpq_archive_s *archive = NULL;
    uint32_t signatures;
    for (int classic = 0; classic <= 3; classic += 3) {
        TEST_CHECK(reader_v3_fixture(&source, 1, 1, classic, 0, 4, 0, 0, 0) == 0);
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_signatures(archive, &signatures) == 0 &&
            signatures == LIBMPQ_SIGNATURE_WEAK
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    return 0;
}

/* BET provenance must not affect decoding the plaintext prefix and PTCH body. */
static int
test_v3_patch_payload(void)
{
    reader_v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_bet_s bet;
    mpq_md5_s digest;
    uint8_t output[68];
    uint8_t *prefix;
    uint8_t *patch;
    uint8_t *table;
    uint32_t number;
    uint32_t flags;
    libmpq__off_t size;
    libmpq__off_t transferred;
    TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
    prefix = source.bytes + 68;
    memset(prefix, 0, 96);
    patch = prefix + 28;
    libmpq__store_le32(prefix, 28);
    libmpq__store_le32(prefix + 4, 0x80000000u);
    libmpq__store_le32(prefix + 8, 68);
    memcpy(patch, "PTCH", 4);
    libmpq__store_le32(patch + 4, 68);
    memcpy(patch + 16, "MD5_", 4);
    libmpq__store_le32(patch + 20, 40);
    libmpq__md5_init(&digest);
    libmpq__md5_final(&digest, patch + 24);
    memcpy(patch + 40, patch + 24, 16);
    memcpy(patch + 56, "XFRM", 4);
    libmpq__store_le32(patch + 60, 12);
    memcpy(patch + 64, "COPY", 4);
    libmpq__md5_init(&digest);
    libmpq__md5_update(&digest, patch, 68);
    libmpq__md5_final(&digest, prefix + 12);
    table = source.bytes + source.bet_offset;
    uint32_t stored = (uint32_t)(source.size - source.bet_offset - 12);
    TEST_CHECK(libmpq__crypto_decrypt_block(table + 12, stored, 0xec83b3a3u) == 0);
    TEST_CHECK(libmpq__bet_view_init(table, stored + 12, &bet) == 0);
    libmpq__store_le32(
        (uint8_t *)bet.flags, LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FLAG_SINGLE
    );
    TEST_CHECK(libmpq__bit_set((uint8_t *)bet.records, bet.records_size, 64, 32, 0) == 0);
    TEST_CHECK(libmpq__bit_set((uint8_t *)bet.records, bet.records_size, 96, 32, 96) == 0);
    TEST_CHECK(libmpq__crypto_encrypt_block(table + 12, stored, 0xec83b3a3u) == 0);
    for (int damaged = 0; damaged < 2; damaged++) {
        if (damaged)
            prefix[12] ^= 1;
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == 0
        );
        TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
        TEST_CHECK(
            libmpq__file_flags(archive, number, &flags) == 0 &&
            (flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0
        );
        TEST_CHECK(libmpq__patch_payload_size(archive, number, &size) == 0 && size == 68);
        memset(output, 0xa5, sizeof(output));
        int32_t result = libmpq__patch_payload_read(
            archive, number, "payload.bin", output, sizeof(output), &transferred
        );
        TEST_CHECK(result == (damaged ? LIBMPQ_ERROR_FORMAT : 0));
        if (!damaged)
            TEST_CHECK(transferred == 68 && memcmp(output, patch, sizeof(output)) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    return 0;
}

/* Additive metadata queries must not wrap full-width values or alter failed accumulators. */
static int
test_size_accumulators(void)
{
    mpq_archive_s archive = { 0 };
    mpq_entry_s entries[2] = { { 0 }, { 0 } };
    mpq_map_s map[2] = { { 1 }, { 0 } };
    int32_t (*queries[])(mpq_archive_s *, libmpq__off_t *) = { libmpq__archive_size_packed,
                                                               libmpq__archive_size_unpacked };
    archive.mpq_header.version = LIBMPQ_ARCHIVE_VERSION_THREE;
    archive.mpq_entry = entries;
    archive.mpq_map = map;
    archive.files = archive.entry_count = 2;
    for (size_t query = 0; query < 2; ++query) {
        libmpq__off_t total = 0;
        entries[0].packed_size = entries[0].unpacked_size = INT64_MAX - 1;
        entries[1].packed_size = entries[1].unpacked_size = 1;
        TEST_CHECK(queries[query](&archive, &total) == 0 && total == INT64_MAX);
        total = 1;
        TEST_CHECK(queries[query](&archive, &total) == LIBMPQ_ERROR_SIZE && total == 1);
        total = -1;
        TEST_CHECK(queries[query](&archive, &total) == 0 && total == INT64_MAX - 1);
        entries[0].packed_size = entries[0].unpacked_size = INT64_MAX;
        total = 0;
        TEST_CHECK(queries[query](&archive, &total) == LIBMPQ_ERROR_SIZE && total == 0);
        entries[0].packed_size = entries[0].unpacked_size = UINT64_MAX;
        TEST_CHECK(queries[query](&archive, &total) == LIBMPQ_ERROR_SIZE && total == 0);
        TEST_CHECK(queries[query](NULL, &total) == LIBMPQ_ERROR_EXIST && total == 0);
        TEST_CHECK(queries[query](&archive, NULL) == LIBMPQ_ERROR_EXIST);
        map[1].entry_index = 2;
        TEST_CHECK(queries[query](&archive, &total) == LIBMPQ_ERROR_EXIST && total == 0);
        map[1].entry_index = 0;
        archive.files = 0;
        total = 17;
        TEST_CHECK(queries[query](&archive, &total) == 0 && total == 17);
        archive.files = 2;
    }
    return 0;
}

/* Large metadata stays full-width; sector counts must not wrap at UINT32_MAX. */
static int
test_v3_size_conversions(void)
{
    reader_v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint32_t number;
    uint32_t blocks;
    libmpq__off_t size;
    TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    entry->unpacked_size = UINT32_MAX;
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0);
    TEST_CHECK(blocks == 1048576);
    entry->unpacked_size = (uint64_t)UINT32_MAX + 1;
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, number, &size) == 0 &&
        (uint64_t)size == (uint64_t)UINT32_MAX + 1
    );
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == LIBMPQ_ERROR_SIZE && blocks == 0);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    /* Encode the large size on disk too, so a stream's fresh clone sees it. */
    uint8_t table[200] = { 0 };
    mpq_bet_s bet;
    size_t stored = source.size - (size_t)source.bet_offset;
    uint8_t *original = source.bytes + source.bet_offset;
    TEST_CHECK(
        libmpq__crypto_decrypt_block(original + 12, (uint32_t)stored - 12, 0xec83b3a3u) == 0
    );
    TEST_CHECK(libmpq__bet_view_init(original, stored, &bet) == 0);
    memcpy(table, original, 96);
    libmpq__store_le32(table + 8, 140);
    libmpq__store_le32(table + 12, 140);
    libmpq__store_le32(table + 24, 162);
    libmpq__store_le32(table + 36, 128);
    libmpq__store_le32(table + 40, 160);
    libmpq__store_le32(table + 44, 161);
    libmpq__store_le32(table + 52, 64);
    for (uint32_t i = 0; i < 2; i++) {
        mpq_bet_entry_s record;
        TEST_CHECK(libmpq__bet_record_decode(&bet, i, &record) == 0);
        TEST_CHECK(libmpq__bit_set(table + 96, 41, i * 162, 64, record.offset) == 0);
        TEST_CHECK(
            libmpq__bit_set(
                table + 96, 41, i * 162 + 64, 64,
                i == 0 ? (uint64_t)UINT32_MAX + 1 : record.unpacked_size
            ) == 0
        );
        TEST_CHECK(libmpq__bit_set(table + 96, 41, i * 162 + 128, 32, record.packed_size) == 0);
        TEST_CHECK(libmpq__bit_set(table + 96, 41, i * 162 + 160, 1, i) == 0);
    }
    memcpy(table + 137, bet.name_hash2, 15);
    TEST_CHECK(libmpq__crypto_encrypt_block(table + 12, 140, 0xec83b3a3u) == 0);
    memcpy(original, table, 152);
    source.size = (size_t)source.bet_offset + 152;
    libmpq__store_le64(source.bytes + 44, source.size);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v3_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == LIBMPQ_ERROR_SIZE && blocks == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, "payload.bin", &stream) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(stream == NULL);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Transaction setup accepts readable v3 inputs without performing a reconstruction. */
static int
test_v3_transaction_setup(void)
{
    reader_v3_source_s source;
    reader_v3_source_s cipher;
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    FILE *file;
    uint8_t auth[32];
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    uint8_t actual[9000];
    uint32_t number;
    libmpq__off_t transferred;
    memset(auth, 0x53, sizeof(auth));
    TEST_CHECK(reader_v3_fixture(&source, 1, 1, 0, 0, 0, 0, 0, 0) == 0);
    cipher = source;
    file = fopen("reader-v3.mpq", "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(source.bytes, 1, source.size, file) == source.size);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "reader-v3.mpq", 0) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "reader-v3.mpq") == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(libmpq__mpqe_key(key, auth, sizeof(auth)) == 0);
    file = fopen("reader-v3.mpqe", "wb");
    TEST_CHECK(file != NULL);
    for (size_t offset = 0; offset < source.size; offset += LIBMPQ_MPQE_CHUNK_SIZE) {
        uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE] = { 0 };
        size_t size = source.size - offset < sizeof(chunk) ? source.size - offset : sizeof(chunk);
        memcpy(chunk, source.bytes + offset, size);
        libmpq__mpqe_transform_chunk(chunk, key, offset);
        memcpy(cipher.bytes + offset, chunk, size);
        TEST_CHECK(fwrite(chunk, 1, size, file) == size);
    }
    libmpq__mpqe_clear(key, sizeof(key));
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open_mpqe(&archive, "reader-v3.mpqe", 0, auth, sizeof(auth)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    memset(actual, 0xa5, sizeof(actual));
    TEST_CHECK(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(actual));
    TEST_CHECK(memcmp(actual, source.bytes + LIBMPQ_HEADER_V3_WIRE_SIZE, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        libmpq__archive_open_mpqe_io(
            &archive, &cipher, reader_v3_read_at, (libmpq__off_t)cipher.size, 0, auth, sizeof(auth),
            NULL
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    memset(actual, 0xa5, sizeof(actual));
    TEST_CHECK(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(actual));
    TEST_CHECK(memcmp(actual, source.bytes + LIBMPQ_HEADER_V3_WIRE_SIZE, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin_mpqe(&update, "reader-v3.mpqe", auth, sizeof(auth)) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(remove("reader-v3.mpq") == 0);
    TEST_CHECK(remove("reader-v3.mpqe") == 0);
    return 0;
}

/* Extra aligned uint32_t entries before the first compressed sector are not encryption. */
static int
test_extended_sector_offsets(void)
{
    enum
    {
        extra = 108
    };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                   LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    char source_path[512];
    char extended_path[512];
    mpq_archive_s *archive = NULL;
    uint8_t payload[3 * 4096 + 71];
    uint8_t output[sizeof(payload)];
    uint8_t *original = NULL;
    uint8_t *extended = NULL;
    size_t original_size;
    uint32_t number;
    uint32_t blocks;
    uint32_t physical;
    uint32_t block_table_offset;
    uint32_t hash_table_offset;
    uint32_t block_table_count;
    uint32_t member_offset;
    uint32_t insert_at;
    uint32_t first_offset;
    libmpq__off_t transferred;
    FILE *file;

    TEST_CHECK(test_temp_path(source_path, sizeof(source_path), "extended-offset-source") == 0);
    TEST_CHECK(test_temp_path(extended_path, sizeof(extended_path), "extended-offset-table") == 0);
    test_payload(payload, sizeof(payload), 0x12345678u);
    TEST_CHECK(libmpq__archive_create(&archive, source_path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "payload.bin", payload, sizeof(payload), &storage) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_read_path(source_path, &original, &original_size) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, source_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 1);
    TEST_CHECK(
        archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask ==
        LIBMPQ_ENTRY_SOURCE_CLASSIC
    );
    physical = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    member_offset = archive->mpq_block[physical].offset;
    first_offset = (blocks + 1u) * 4u;
    insert_at = member_offset + first_offset;
    block_table_offset = archive->mpq_header.block_table_offset;
    hash_table_offset = archive->mpq_header.hash_table_offset;
    block_table_count = archive->mpq_header.block_table_count;
    TEST_CHECK(insert_at < original_size);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    extended = malloc(original_size + extra);
    TEST_CHECK(extended != NULL);
    memcpy(extended, original, insert_at);
    memset(extended + insert_at, 0, extra);
    memcpy(extended + insert_at + extra, original + insert_at, original_size - insert_at);
    for (uint32_t i = 0; i <= blocks; ++i) {
        uint32_t offset = libmpq__load_le32(extended + member_offset + i * 4u);
        libmpq__store_le32(extended + member_offset + i * 4u, offset + extra);
    }
    TEST_CHECK(libmpq__load_le32(extended + member_offset) == first_offset + extra);
    libmpq__store_le32(extended + 8, libmpq__load_le32(extended + 8) + extra);
    if (hash_table_offset >= insert_at)
        libmpq__store_le32(extended + 16, hash_table_offset + extra);
    if (block_table_offset >= insert_at)
        libmpq__store_le32(extended + 20, block_table_offset + extra);
    {
        uint8_t *table =
            extended + block_table_offset + (block_table_offset >= insert_at ? extra : 0);
        uint32_t table_size = block_table_count * 16u;
        uint32_t key = libmpq__crypto_hash_string("(block table)", 0x300);
        uint32_t packed_size;

        TEST_CHECK(libmpq__crypto_decrypt_block(table, table_size, key) == 0);
        packed_size = libmpq__load_le32(table + physical * 16u + 4u);
        libmpq__store_le32(table + physical * 16u + 4u, packed_size + extra);
        TEST_CHECK(libmpq__crypto_encrypt_block(table, table_size, key) == 0);
    }
    file = fopen(extended_path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(extended, 1, original_size + extra, file) == original_size + extra);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, extended_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(original);
    free(extended);
    TEST_CHECK(remove(source_path) == 0);
    TEST_CHECK(remove(extended_path) == 0);
    return 0;
}

/* Canonical metadata remains sufficient after classic wire tables are discarded. */
static int
test_canonical_entries(uint32_t version)
{
    mpq_archive_create_options_s options = { version, 8, 4096, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    char path[512];
    uint8_t source[9000];
    uint8_t actual[sizeof(source)];
    uint32_t number;
    uint32_t flags;
    uint32_t mismatches;
    uint32_t index;
    uint32_t classic;
    mpq_file_attributes_s attributes;
    mpq_file_attributes_s expected_attributes;
    libmpq__off_t offset;
    libmpq__off_t packed;
    libmpq__off_t unpacked;
    libmpq__off_t transferred;
    TEST_CHECK(test_temp_path(path, sizeof(path), "canonical-entries") == 0);
    test_payload(source, sizeof(source), 42);
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "payload.bin", source, sizeof(source), &storage) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &expected_attributes) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    index = archive->mpq_map[number].entry_index;
    TEST_CHECK(archive->mpq_entry[index].source_mask == LIBMPQ_ENTRY_SOURCE_CLASSIC);
    classic = archive->mpq_entry[index].classic_source_index;

    /* Move the payload to another entry without changing public file numbers. */
    {
        uint32_t other = index == 0 ? 1 : 0;
        mpq_entry_s saved = archive->mpq_entry[index];
        archive->mpq_entry[index] = archive->mpq_entry[other];
        archive->mpq_entry[other] = saved;
        for (uint32_t i = 0; i < archive->entry_count; ++i) {
            mpq_entry_s *entry = &archive->mpq_entry[i];
            archive->classic_entry_indices[entry->classic_source_index] = i;
            if (entry->file_number != UINT32_MAX)
                archive->mpq_map[entry->file_number].entry_index = i;
        }
        index = other;
    }
    TEST_CHECK(index != classic);
    TEST_CHECK(libmpq__entry_index_from_classic(archive, classic, &flags) == 0 && flags == index);

    /* An extra canonical slot must not change classic attributes row sizing. */
    {
        uint32_t count = archive->entry_count;
        mpq_entry_s *entries = calloc((size_t)count + 1, sizeof(*entries));
        mpq_file_s **files = calloc((size_t)count + 1, sizeof(*files));
        mpq_map_s *map = calloc((size_t)count + 1, sizeof(*map));
        if (entries == NULL || files == NULL || map == NULL) {
            free(entries);
            free(files);
            free(map);
            TEST_CHECK(0);
        }
        memcpy(entries, archive->mpq_entry, count * sizeof(*entries));
        memcpy(files, archive->mpq_file, count * sizeof(*files));
        memcpy(map, archive->mpq_map, count * sizeof(*map));
        free(archive->mpq_entry);
        free(archive->mpq_file);
        free(archive->mpq_map);
        archive->mpq_entry = entries;
        archive->mpq_file = files;
        archive->mpq_map = map;
        archive->entry_count = count + 1;
    }
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(attributes.crc32 == expected_attributes.crc32);
    TEST_CHECK(memcmp(attributes.md5, expected_attributes.md5, sizeof(attributes.md5)) == 0);
    archive->classic_entry_indices[classic] = archive->entry_count;
    TEST_CHECK(libmpq__entry_index_from_classic(archive, classic, &flags) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(flags == UINT32_MAX);
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == LIBMPQ_ERROR_FORMAT);
    archive->classic_entry_indices[classic] = index;
    TEST_CHECK(libmpq__entry_index_from_classic(NULL, classic, &flags) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(flags == UINT32_MAX);
    TEST_CHECK(libmpq__entry_index_from_classic(archive, classic, NULL) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__entry_index_from_classic(archive, archive->mpq_header.block_table_count, &flags) ==
        LIBMPQ_ERROR_FORMAT
    );
    {
        uint32_t *mapping = archive->classic_entry_indices;
        archive->classic_entry_indices = NULL;
        TEST_CHECK(
            libmpq__entry_index_from_classic(archive, classic, &flags) == LIBMPQ_ERROR_FORMAT
        );
        archive->classic_entry_indices = mapping;
    }
    archive->mpq_entry[index].source_mask = LIBMPQ_ENTRY_SOURCE_NONE;
    TEST_CHECK(
        libmpq__file_attributes(archive, archive->mpq_entry[index].file_number, &attributes) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__entry_index_from_classic(archive, classic, &flags) == LIBMPQ_ERROR_FORMAT);
    archive->mpq_entry[index].source_mask = LIBMPQ_ENTRY_SOURCE_BET;
    TEST_CHECK(
        libmpq__file_attributes(archive, archive->mpq_entry[index].file_number, &attributes) ==
        LIBMPQ_ERROR_FORMAT
    );
    archive->mpq_entry[index].source_mask = LIBMPQ_ENTRY_SOURCE_CLASSIC;
    archive->mpq_entry[index].classic_source_index = archive->mpq_header.block_table_count;
    TEST_CHECK(
        libmpq__file_attributes(archive, archive->mpq_entry[index].file_number, &attributes) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__entry_index_from_classic(archive, classic, &flags) == LIBMPQ_ERROR_FORMAT);
    archive->mpq_entry[index].classic_source_index = classic;
    TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0);
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0);
    TEST_CHECK(unpacked == sizeof(source));
    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
    TEST_CHECK(flags == archive->mpq_block[classic].flags);
    TEST_CHECK((uint64_t)offset == archive->mpq_entry[index].offset);
    TEST_CHECK((uint64_t)packed == archive->mpq_entry[index].packed_size);
    free(archive->mpq_block);
    free(archive->mpq_block_ex);
    archive->mpq_block = NULL;
    archive->mpq_block_ex = NULL;
    TEST_CHECK(libmpq__file_number(archive, "PAYLOAD.BIN", &number) == 0);
    TEST_CHECK(
        libmpq__file_flags(archive, number, &flags) == 0 && flags == archive->mpq_entry[index].flags
    );
    TEST_CHECK(
        libmpq__file_size_packed(archive, number, &transferred) == 0 && transferred == packed
    );
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, number, &transferred) == 0 && transferred == unpacked
    );
    TEST_CHECK(libmpq__file_offset(archive, number, &transferred) == 0 && transferred == offset);
    TEST_CHECK(libmpq__stream_open_name(archive, "payload.bin", &stream) == 0);
    TEST_CHECK(libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(source) && memcmp(actual, source, sizeof(source)) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "payload.bin") == 0);
    TEST_CHECK(
        libmpq__file_verify(
            archive, number, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &mismatches
        ) == 0 &&
        mismatches == 0
    );
    TEST_CHECK(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
    TEST_CHECK(transferred == sizeof(source) && memcmp(actual, source, sizeof(source)) == 0);
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    for (uint32_t slot = 0; slot < archive->mpq_header.hash_table_count; ++slot) {
        mpq_hash_s *hash = &archive->mpq_hash[slot];
        if (hash->block_table_index != classic)
            continue;
        hash->block_table_index = archive->entry_count;
        TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == LIBMPQ_ERROR_FORMAT);
        hash->block_table_index = classic;
        TEST_CHECK(libmpq__file_number(archive, "payload.bin", &number) == 0);
        break;
    }
    archive->mpq_map[number].entry_index = archive->entry_count;
    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) ==
        LIBMPQ_ERROR_EXIST
    );
    archive->mpq_map[number].entry_index = index;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);

    options.attributes = 0;
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->files == 0);
    TEST_CHECK(libmpq__file_flags(archive, 0, &flags) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);

    /* A zero-row base header also exercises NULL entry storage on close. */
    {
        uint8_t wire[32];
        mpq_header_s header = {
            LIBMPQ_HEADER, 32, 32, LIBMPQ_ARCHIVE_VERSION_ONE, 3, 32, 32, 0, 0
        };
        FILE *file;
        size_t written;
        int closed;
        TEST_CHECK(libmpq__header_encode(&header, wire, sizeof(wire)) == 0);
        file = fopen(path, "wb");
        TEST_CHECK(file != NULL);
        written = fwrite(wire, 1, sizeof(wire), file);
        closed = fclose(file);
        TEST_CHECK(written == sizeof(wire) && closed == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(archive->entry_count == 0 && archive->mpq_entry == NULL && archive->files == 0);
        TEST_CHECK(archive->classic_entry_indices == NULL);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(remove(path) == 0);
    }
    return 0;
}

/* Reserved BET values are readable but cannot be reproduced by the current writer. */
static int
test_v3_reserved_update(void)
{
    reader_v3_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_bet_entry_s record;
    FILE *file;
    uint8_t *table;
    uint32_t key = libmpq__crypto_hash_string("(block table)", 0x300);
    TEST_CHECK(reader_v3_fixture(&source, 0, 0, 0, 0, 0, 0, 0, 0) == 0);
    table = source.bytes + source.bet_offset;
    TEST_CHECK(
        libmpq__crypto_decrypt_block(
            table + 12, (uint32_t)(source.size - source.bet_offset - 12), key
        ) == 0
    );
    TEST_CHECK(libmpq__bit_set(table + 96, 33, 129, 1, 1) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            table + 12, (uint32_t)(source.size - source.bet_offset - 12), key
        ) == 0
    );
    file = fopen("reader-v3-reserved.mpq", "wb");
    TEST_CHECK(
        file != NULL && fwrite(source.bytes, 1, source.size, file) == source.size &&
        fclose(file) == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, "reader-v3-reserved.mpq", 0) == 0);
    TEST_CHECK(
        libmpq__bet_record_decode(&archive->mpq_bet, 0, &record) == 0 && record.unknown == 1
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "reader-v3-reserved.mpq") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "payload.bin", (const uint8_t *)"new", 3, NULL) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(remove("reader-v3-reserved.mpq") == 0);
    return 0;
}

/* Runtime v4 image shared by hand-built and writer-derived tests. */
typedef struct
{
    uint8_t bytes[32768];
    size_t size;
    uint64_t base;
    uint64_t fail_at;
    unsigned int reads;
    size_t max_read;
    mpq_header_s header;
    mpq_header_ex_s ex;
    mpq_header_v3_s v3;
    mpq_header_v4_s v4;
} reader_v4_source_s;

static int32_t
reader_v4_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    reader_v4_source_s *source = context;
    uint64_t start;
    uint64_t end = source->base + source->size;
    ++source->reads;
    if (size > source->max_read)
        source->max_read = size;
    if (offset < 0 || (uint64_t)offset > end || size > end - (uint64_t)offset)
        return LIBMPQ_ERROR_READ;
    start = (uint64_t)offset;
    if (source->fail_at != 0 && start <= source->fail_at && source->fail_at - start < size)
        return LIBMPQ_ERROR_READ;
    memset(buffer, 0, size);
    if (start >= source->base) {
        memcpy(buffer, source->bytes + (size_t)(start - source->base), size);
    } else if (start == 0 && size >= 16 && source->base == 512) {
        libmpq__store_le32(buffer, 0x1b51504du);
        libmpq__store_le32(buffer + 4, 16);
        libmpq__store_le32(buffer + 8, 512);
        libmpq__store_le32(buffer + 12, 16);
    }
    return 0;
}

static int
reader_v4_header(reader_v4_source_s *source)
{
    TEST_CHECK(
        libmpq__header_v4_full_encode(
            &source->header, &source->ex, &source->v3, &source->v4, source->bytes,
            sizeof(source->bytes)
        ) == 0
    );
    return 0;
}

/* Hand-place classic tables around a payload without invoking an archive writer. */
static int
test_v4_independent_layout(void)
{

    /* Fixed Python hashlib.md5 vectors: hash, block, hi-block, then header. */
    static const uint8_t digests[4][16] = { { 0xd6, 0xaf, 0x60, 0x70, 0x22, 0x46, 0xc6, 0x9f, 0x30,
                                              0x9c, 0x44, 0xe7, 0x4e, 0x14, 0x5c, 0x36 },
                                            { 0x5c, 0x00, 0x66, 0xcc, 0x66, 0x2e, 0x35, 0xf2, 0xa1,
                                              0xe5, 0x7c, 0x81, 0x59, 0x2c, 0xfb, 0xa2 },
                                            { 0xc4, 0x10, 0x3f, 0x12, 0x2d, 0x27, 0x67, 0x7c, 0x9d,
                                              0xb1, 0x44, 0xca, 0xe1, 0x39, 0x4a, 0x66 },
                                            { 0x88, 0x7a, 0xf8, 0x3a, 0xcd, 0x64, 0x2b, 0xd9, 0x08,
                                              0xe6, 0x7e, 0xda, 0x9e, 0x12, 0xa1, 0x2a } };
    reader_v4_source_s source = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_hash_s hashes[4];
    mpq_block_s block = { 288, 5, 5, LIBMPQ_FLAG_EXISTS };
    mpq_block_ex_s high = { 0 };
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t number;
    uint32_t files;
    uint8_t actual[5];
    libmpq__off_t transferred;
    libmpq__off_t offset;
    libmpq__off_t packed;
    libmpq__off_t unpacked;
    source.header = (mpq_header_s){
        LIBMPQ_HEADER, LIBMPQ_HEADER_V4_WIRE_SIZE, 1, LIBMPQ_ARCHIVE_VERSION_FOUR, 3, 352, 240, 4, 1
    };
    source.ex.extended_offset = 224;
    source.size = 416;
    source.v3.archive_size = source.size;
    source.v4.hash_table_size = 64;
    source.v4.block_table_size = 16;
    source.v4.hi_block_table_size = 2;
    TEST_CHECK(reader_v4_header(&source) == 0);
    memset(hashes, 0xff, sizeof(hashes));
    libmpq__file_hash("independent.bin", &h1, &h2, &h3);
    hashes[h1 & 3u] = (mpq_hash_s){ h2, h3, 0, 0, 0 };
    TEST_CHECK(libmpq__hash_table_encode(hashes, 4, source.bytes + 352, 64) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 352, 64, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    TEST_CHECK(libmpq__block_table_encode(&block, 1, source.bytes + 240, 16) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source.bytes + 240, 16, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    TEST_CHECK(libmpq__block_ex_table_encode(&high, 1, source.bytes + 224, 2) == 0);
    memcpy(source.bytes + 288, "hello", sizeof(actual));
    for (unsigned int variant = 0; variant < 4; ++variant) {
        if (variant == 2) {
            memcpy(source.v4.hash_table_md5, digests[0], 16);
            memcpy(source.v4.block_table_md5, digests[1], 16);
            memcpy(source.v4.hi_block_table_md5, digests[2], 16);
            memcpy(source.v4.header_md5, digests[3], 16);
            TEST_CHECK(reader_v4_header(&source) == 0);
        }
        source.base = (variant & 1u) ? 512 : 0;
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v4_read_at, (libmpq__off_t)(source.base + source.size),
                (libmpq__off_t)source.base, NULL
            ) == 0
        );
        TEST_CHECK(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR);
        TEST_CHECK(archive->mpq_header_v4.hash_table_size == 64);
        TEST_CHECK(archive->mpq_header_v4.block_table_size == 16);
        TEST_CHECK(archive->mpq_header_v4.hi_block_table_size == 2);
        TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 1);
        TEST_CHECK(libmpq__file_number(archive, "independent.bin", &number) == 0);
        TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0 && offset == 288);
        TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0 && packed == 5);
        TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0 && unpacked == 5);
        TEST_CHECK(libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0);
        TEST_CHECK(transferred == sizeof(actual) && memcmp(actual, "hello", sizeof(actual)) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    return 0;
}

/* Sparse cases contain long zero runs; other cases retain the fixed byte pattern. */
static uint8_t
reader_v4_payload_byte(size_t position, uint32_t method)
{
    return (method & LIBMPQ_COMPRESSION_SPARSE) != 0 && position % 256 < 240
               ? 0
               : (uint8_t)(position % 17);
}

/* Keep payload offsets final, then reorder/gap the stored tables independently. */
static int
reader_v4_fixture(
    reader_v4_source_s *source, int representation, int compressed, int encrypted, int single,
    int attributes, uint32_t method
)
{
    mpq_archive_s *writer = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_THREE, 8, 4096,
                                             LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s file_options = { 0 };
    uint8_t payload[9000];
    uint8_t *original = NULL;
    size_t original_size;
    size_t positions[5];
    size_t sizes[5];
    size_t length = single ? 256 : sizeof(payload);
    memset(source, 0, sizeof(*source));
    if (attributes)
        options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5;
    if (method != 0)
        options.flags |= LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED;
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = reader_v4_payload_byte(i, method);
    file_options.flags = compressed ? LIBMPQ_FILE_FLAG_COMPRESS : 0;
    if (encrypted)
        file_options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
    if (encrypted == 2)
        file_options.flags |= 0x00020000u;
    if (single)
        file_options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
    if (attributes && compressed && !single)
        file_options.flags |= LIBMPQ_FILE_FLAG_SECTOR_CRC;
    file_options.compression_first = method != 0 ? method : LIBMPQ_COMPRESSION_ZLIB;
    file_options.compression_next = file_options.compression_first;
    TEST_CHECK(libmpq__archive_create(&writer, "reader-v4-input.mpq", &options) == 0);
    writer->write_ext_compress = compressed;
    TEST_CHECK(libmpq__file_seek(writer->fp, LIBMPQ_HEADER_V4_WIRE_SIZE, SEEK_SET) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(writer, "folder/payload.bin", payload, length, &file_options) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(writer, "zero.bin", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(test_read_path("reader-v4-input.mpq", &original, &original_size) == 0);
    TEST_CHECK(original_size + 2048 < sizeof(source->bytes));
    memcpy(source->bytes, original, original_size);
    TEST_CHECK(libmpq__header_decode(&source->header, original, original_size) == 0);
    TEST_CHECK(libmpq__header_ex_decode(&source->ex, original + 32, 12) == 0);
    TEST_CHECK(libmpq__header_v3_decode(&source->v3, original + 44, 24) == 0);
    positions[0] = source->header.block_table_offset;
    positions[1] = 0;
    positions[2] = (size_t)source->v3.bet_table_offset;
    positions[3] = source->header.hash_table_offset;
    positions[4] = (size_t)source->v3.het_table_offset;
    sizes[0] = source->header.block_table_count * 16u;
    sizes[1] = source->header.block_table_count * 2u;
    sizes[2] = source->header.hash_table_offset - positions[2];
    sizes[3] = source->header.hash_table_count * 16u;
    sizes[4] = positions[2] - positions[4];
    source->size = original_size;
    for (size_t i = 0; i < 5; ++i) {
        size_t next = source->size + 9;
        if (i == 1)
            memset(source->bytes + next, 0, sizes[i]);
        else
            memcpy(source->bytes + next, original + positions[i], sizes[i]);
        positions[i] = next;
        source->size = next + sizes[i];
    }
    free(original);
    TEST_CHECK(remove("reader-v4-input.mpq") == 0);
    source->header.version = LIBMPQ_ARCHIVE_VERSION_FOUR;
    source->header.header_size = LIBMPQ_HEADER_V4_WIRE_SIZE;
    source->header.archive_size = 1; /* The inherited 64-bit size is authoritative. */
    source->header.block_table_offset = (uint32_t)positions[0];
    source->ex.extended_offset = positions[1];
    source->v3.bet_table_offset = positions[2];
    source->header.hash_table_offset = (uint32_t)positions[3];
    source->v3.het_table_offset = positions[4];
    source->v3.archive_size = source->size;
    memset(&source->v4, 0, sizeof(source->v4));
    source->v4.block_table_size = sizes[0];
    source->v4.hi_block_table_size = sizes[1];
    source->v4.bet_table_size = sizes[2];
    source->v4.hash_table_size = sizes[3];
    source->v4.het_table_size = sizes[4];
    source->v4.raw_chunk_size = 0;
    if (representation == 0) {
        source->header.hash_table_count = source->header.block_table_count = 0;
        source->header.hash_table_offset = source->header.block_table_offset = 0;
        source->ex.extended_offset = 0;
        source->v4.hash_table_size = source->v4.block_table_size = 0;
        source->v4.hi_block_table_size = 0;
    } else if (representation == 1) {
        source->v3.het_table_offset = source->v3.bet_table_offset = 0;
        source->v4.het_table_size = source->v4.bet_table_size = 0;
        if (single) {
            source->ex.extended_offset = 0;
            source->v4.hi_block_table_size = 0;
        }
    }
    return reader_v4_header(source);
}

/* Test-side digest construction; fixed independent vectors are checked above. */
static void
reader_v4_digest(const uint8_t *data, size_t size, uint8_t digest[16])
{
    mpq_md5_s context;
    libmpq__md5_init(&context);
    libmpq__md5_update(&context, data, size);
    libmpq__md5_final(&context, digest);
}

/* Re-sign only the header so table-specific failures remain isolated. */
static int
reader_v4_header_md5(reader_v4_source_s *source)
{
    TEST_CHECK(reader_v4_header(source) == 0);
    reader_v4_digest(source->bytes, 192, source->v4.header_md5);
    return reader_v4_header(source);
}

/* Hash exact declared stored extents, including plaintext extended-table envelopes. */
static int
reader_v4_table_md5(reader_v4_source_s *source)
{
    uint64_t positions[5] = { source->header.hash_table_offset, source->header.block_table_offset,
                              source->ex.extended_offset, source->v3.het_table_offset,
                              source->v3.bet_table_offset };
    uint64_t sizes[5] = { source->v4.hash_table_size, source->v4.block_table_size,
                          source->v4.hi_block_table_size, source->v4.het_table_size,
                          source->v4.bet_table_size };
    uint8_t *digests[5] = { source->v4.hash_table_md5, source->v4.block_table_md5,
                            source->v4.hi_block_table_md5, source->v4.het_table_md5,
                            source->v4.bet_table_md5 };
    for (size_t i = 0; i < 5; ++i) {
        memset(digests[i], 0, 16);
        if (positions[i] == 0)
            continue;
        TEST_CHECK(positions[i] <= source->size && sizes[i] <= source->size - positions[i]);
        reader_v4_digest(source->bytes + (size_t)positions[i], (size_t)sizes[i], digests[i]);
    }
    return reader_v4_header_md5(source);
}

/* Failed opens expose no handle; valid metadata must still permit exact member reads. */
static int
reader_v4_expect(reader_v4_source_s *source, int32_t expected)
{
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t actual[9000];
    uint32_t files;
    libmpq__off_t transferred;
    source->reads = 0;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, source, reader_v4_read_at, (libmpq__off_t)(source->base + source->size),
            source->base == 512 ? -1 : (libmpq__off_t)source->base, NULL
        ) == expected
    );
    if (expected != 0) {
        TEST_CHECK(archive == NULL);
        return 0;
    }
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 3);
    TEST_CHECK(libmpq__stream_open_name(archive, "folder/payload.bin", &stream) == 0);
    TEST_CHECK(
        libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0 &&
        transferred == sizeof(actual)
    );
    for (size_t i = 0; i < sizeof(actual); ++i)
        TEST_CHECK(actual[i] == (uint8_t)(i % 17));
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Verify stored-byte integrity independently for every present or absent table. */
static int
test_v4_md5(int representation, int compressed)
{
    reader_v4_source_s original;
    reader_v4_source_s source;
    mpq_archive_s *archive = NULL;
    uint64_t positions[5];
    uint64_t sizes[5];
    uint8_t *digests[6] = { source.v4.hash_table_md5,     source.v4.block_table_md5,
                            source.v4.hi_block_table_md5, source.v4.het_table_md5,
                            source.v4.bet_table_md5,      source.v4.header_md5 };
    TEST_CHECK(reader_v4_fixture(&original, representation, compressed, 2, 0, 0, 0) == 0);
    TEST_CHECK(reader_v4_table_md5(&original) == 0);
    positions[0] = original.header.hash_table_offset;
    positions[1] = original.header.block_table_offset;
    positions[2] = original.ex.extended_offset;
    positions[3] = original.v3.het_table_offset;
    positions[4] = original.v3.bet_table_offset;
    sizes[0] = original.v4.hash_table_size;
    sizes[1] = original.v4.block_table_size;
    sizes[2] = original.v4.hi_block_table_size;
    sizes[3] = original.v4.het_table_size;
    sizes[4] = original.v4.bet_table_size;
    for (unsigned int embedded = 0; embedded < 3; ++embedded) {
        source = original;
        source.base = embedded == 0 ? 0 : embedded == 1 ? 512 : UINT64_C(0x100000000);
        TEST_CHECK(reader_v4_expect(&source, 0) == 0);
    }
    source = original;
    for (size_t i = 0; i < 5; ++i)
        memset(digests[i], 0, 16);
    TEST_CHECK(reader_v4_header_md5(&source) == 0);
    TEST_CHECK(reader_v4_expect(&source, 0) == 0);
    for (size_t i = 0; i < 6; ++i) {
        source = original;
        digests[i][0] ^= 1;
        TEST_CHECK((i == 5 ? reader_v4_header(&source) : reader_v4_header_md5(&source)) == 0);
        TEST_CHECK(reader_v4_expect(&source, LIBMPQ_ERROR_FORMAT) == 0);
        if (i == 5 || positions[i] == 0)
            TEST_CHECK(source.reads == 2);

        /* A missing digest is allowed even when other fields provide digests. */
        source = original;
        memset(digests[i], 0, 16);
        TEST_CHECK((i == 5 ? reader_v4_header(&source) : reader_v4_header_md5(&source)) == 0);
        TEST_CHECK(reader_v4_expect(&source, 0) == 0);
        if (i == 5 || positions[i] == 0)
            continue;
        source = original;
        source.bytes[(size_t)(positions[i] + sizes[i] - 1)] ^= 0x80;
        TEST_CHECK(reader_v4_expect(&source, LIBMPQ_ERROR_FORMAT) == 0);
        source = original;
        source.fail_at = positions[i] + sizes[i] - 1;
        TEST_CHECK(
            reader_v4_expect(&source, i == 2 ? LIBMPQ_ERROR_FORMAT : LIBMPQ_ERROR_READ) == 0
        );
    }

    /* Header verification precedes trusting new counts or allocating their tables. */
    source = original;
    source.header.block_table_count = UINT32_MAX;
    TEST_CHECK(reader_v4_header(&source) == 0);
    TEST_CHECK(reader_v4_expect(&source, LIBMPQ_ERROR_FORMAT) == 0 && source.reads == 2);
    source = original;
    reader_v4_digest(source.bytes, LIBMPQ_HEADER_V4_WIRE_SIZE, source.v4.header_md5);
    TEST_CHECK(reader_v4_header(&source) == 0);
    TEST_CHECK(reader_v4_expect(&source, LIBMPQ_ERROR_FORMAT) == 0 && source.reads == 2);
    source = original;
    source.fail_at = LIBMPQ_HEADER_V4_MD5_OFFSET;
    TEST_CHECK(reader_v4_expect(&source, LIBMPQ_ERROR_READ) == 0);

    /* Digests over decrypted or decompressed representations must not match. */
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &original, reader_v4_read_at, (libmpq__off_t)original.size, 0, NULL
        ) == 0
    );
    for (size_t i = 0; i < 5; ++i) {
        uint8_t plain[256];
        if (i == 2 || positions[i] == 0)
            continue;
        source = original;
        if (i < 2) {
            TEST_CHECK(sizes[i] <= sizeof(plain));
            memcpy(plain, source.bytes + (size_t)positions[i], (size_t)sizes[i]);
            TEST_CHECK(
                libmpq__crypto_decrypt_block(
                    plain, (uint32_t)sizes[i],
                    libmpq__crypto_hash_string(i == 0 ? "(hash table)" : "(block table)", 0x300)
                ) == 0
            );
            reader_v4_digest(plain, (size_t)sizes[i], digests[i]);
        } else {
            const uint8_t *decoded = i == 3 ? archive->het_data : archive->bet_data;
            reader_v4_digest(decoded, 12u + libmpq__load_le32(decoded + 8), digests[i]);
        }
        TEST_CHECK(reader_v4_header_md5(&source) == 0);
        TEST_CHECK(reader_v4_expect(&source, LIBMPQ_ERROR_FORMAT) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Add raw arrays to a classic-only image; ordinary encrypted bytes can move unchanged. */
static int
reader_v4_raw_fixture(
    reader_v4_source_s *source, uint32_t chunk_size, int compressed, int encrypted, int single
)
{
    reader_v4_source_s original;
    mpq_block_s blocks[8];
    uint8_t wire[8 * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE];
    size_t table_size;
    TEST_CHECK(reader_v4_fixture(source, 1, compressed, encrypted, single, 1, 0) == 0);
    original = *source;
    table_size = (size_t)source->v4.block_table_size;
    TEST_CHECK(table_size <= sizeof(wire));
    memcpy(wire, source->bytes + source->header.block_table_offset, table_size);
    TEST_CHECK(
        libmpq__crypto_decrypt_block(
            wire, (uint32_t)table_size, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    TEST_CHECK(
        libmpq__block_table_decode(wire, table_size, blocks, source->header.block_table_count) == 0
    );
    for (uint32_t i = 0; i < source->header.block_table_count; ++i) {
        uint32_t offset = blocks[i].offset;
        uint32_t size = blocks[i].packed_size;
        uint32_t position = 0;
        if (size == 0)
            continue;
        TEST_CHECK((blocks[i].flags & 0x00020000u) == 0);
        TEST_CHECK(offset <= original.size && size <= original.size - offset);
        TEST_CHECK(size <= sizeof(source->bytes) - source->size);
        blocks[i].offset = (uint32_t)source->size;
        memcpy(source->bytes + source->size, original.bytes + offset, size);
        source->size += size;
        while (chunk_size != 0 && position < size) {
            uint32_t take = size - position < chunk_size ? size - position : chunk_size;
            TEST_CHECK(16 <= sizeof(source->bytes) - source->size);
            reader_v4_digest(
                original.bytes + offset + position, take, source->bytes + source->size
            );
            source->size += 16;
            position += take;
        }
    }
    TEST_CHECK(
        libmpq__block_table_encode(
            blocks, source->header.block_table_count,
            source->bytes + source->header.block_table_offset, table_size
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            source->bytes + source->header.block_table_offset, (uint32_t)table_size,
            libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    source->v4.raw_chunk_size = chunk_size;
    source->v3.archive_size = source->size;
    return reader_v4_table_md5(source);
}

/* Raw verification uses stored bytes, requires no filename key and combines with attributes. */
static int
test_v4_raw_md5(uint32_t chunk_size, int compressed, int encrypted, int single, uint64_t base)
{
    reader_v4_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_entry_s saved;
    mpq_entry_s *entry;
    mpq_stream_s *stream = NULL;
    uint8_t actual[9000];
    libmpq__off_t transferred;
    uint32_t number;
    uint32_t empty;
    uint32_t bits;
    uint64_t chunks;
    uint64_t digest_offset;
    TEST_CHECK(reader_v4_raw_fixture(&source, chunk_size, compressed, encrypted, single) == 0);
    source.base = base;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v4_read_at, (libmpq__off_t)(base + source.size),
            (libmpq__off_t)base, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "folder/payload.bin", &number) == 0);
    entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    saved = *entry;
    digest_offset = entry->offset + entry->packed_size;

    /* Independent hashlib.md5 vectors over the fixed i % 17 plaintext pattern. */
    if (!compressed && !encrypted && single && chunk_size == 256) {
        static const uint8_t expected[16] = { 0x9b, 0x50, 0x46, 0x47, 0x18, 0x63, 0x54, 0xd9,
                                              0x4e, 0xd0, 0x2f, 0xfa, 0xd1, 0x77, 0xb5, 0x7e };
        memcpy(source.bytes + (size_t)digest_offset, expected, sizeof(expected));
    }
    if (!compressed && !encrypted && !single && chunk_size == 4096) {
        static const uint8_t expected[16] = { 0xdb, 0xc9, 0x89, 0x29, 0x27, 0x97, 0x26, 0x94,
                                              0x0f, 0xb7, 0x3f, 0xe4, 0xa3, 0xc5, 0xf8, 0xc7 };
        memcpy(source.bytes + (size_t)digest_offset + 32, expected, sizeof(expected));
    }
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 && bits == 0
    );
    TEST_CHECK(libmpq__stream_open_name(archive, "folder/payload.bin", &stream) == 0);

    /* Named streams own independent clones; logical checks need this archive's key cache. */
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "folder/payload.bin") == 0);
    TEST_CHECK(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits) == 0 && bits == 0);
    if (chunk_size != 0) {
        source.bytes[(size_t)digest_offset] ^= 1;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits) == 0 &&
            bits == LIBMPQ_VERIFY_RAW_MD5
        );
        source.bytes[(size_t)digest_offset] ^= 1;
    }
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(
        libmpq__stream_read(stream, actual, (libmpq__off_t)entry->unpacked_size, &transferred) ==
            0 &&
        transferred == (libmpq__off_t)entry->unpacked_size
    );
    for (size_t i = 0; i < (size_t)transferred; ++i)
        TEST_CHECK(actual[i] == (uint8_t)(i % 17));
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__file_number(archive, "zero.bin", &empty) == 0);
    {
        unsigned int reads = source.reads;
        TEST_CHECK(
            libmpq__file_verify(archive, empty, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 && bits == 0
        );
        TEST_CHECK(source.reads == reads);
    }
    if (chunk_size == 0) {
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        return 0;
    }
    chunks = (entry->packed_size - 1) / chunk_size + 1;
    digest_offset = entry->offset + entry->packed_size;
    {
        uint8_t stored[16];
        memcpy(stored, source.bytes + (size_t)digest_offset, sizeof(stored));
        memset(source.bytes + (size_t)digest_offset, 0, sizeof(stored));
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 &&
            bits == LIBMPQ_VERIFY_RAW_MD5
        );
        memcpy(source.bytes + (size_t)digest_offset, stored, sizeof(stored));
    }
    for (unsigned int i = 0; i < 4; ++i) {
        size_t position = (size_t)(i == 0   ? entry->offset
                                   : i == 1 ? entry->offset + entry->packed_size / 2
                                   : i == 2 ? digest_offset - 1
                                            : digest_offset + (chunks - 1) * 16);
        source.bytes[position] ^= 1;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 &&
            bits == LIBMPQ_VERIFY_RAW_MD5
        );
        if (i == 3)
            TEST_CHECK(
                libmpq__file_verify(
                    archive, number, LIBMPQ_VERIFY_RAW_MD5 | LIBMPQ_VERIFY_SECTOR_CRC, &bits
                ) == 0 &&
                bits == LIBMPQ_VERIFY_RAW_MD5
            );
        source.bytes[position] ^= 1;
    }
    source.fail_at = base + digest_offset;
    bits = UINT32_MAX;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == LIBMPQ_ERROR_READ &&
        bits == 0
    );
    source.fail_at = base + entry->offset;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == LIBMPQ_ERROR_READ &&
        bits == 0
    );
    source.fail_at = 0;
    if (chunks > 1) {
        source.bytes[(size_t)digest_offset] ^= 1;
        source.fail_at = base + digest_offset + (chunks - 1) * 16;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) ==
                LIBMPQ_ERROR_READ &&
            bits == 0
        );
        source.fail_at = 0;
        source.bytes[(size_t)digest_offset] ^= 1;
    }
    {
        uint64_t extent = archive->mpq_header_v3.archive_size;
        uint64_t physical = archive->file_size;
        archive->mpq_header_v3.archive_size = digest_offset + chunks * 16 - 1;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) ==
                LIBMPQ_ERROR_FORMAT &&
            bits == 0
        );
        archive->mpq_header_v3.archive_size = extent;
        archive->file_size = base + digest_offset + chunks * 16 - 1;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) ==
                LIBMPQ_ERROR_READ &&
            bits == 0
        );
        archive->file_size = physical;
    }
    {
        uint64_t extent = archive->mpq_header_v3.archive_size;
        uint64_t physical = archive->file_size;
        archive->mpq_header_v3.archive_size = UINT64_MAX;
        archive->file_size = UINT64_MAX;
        entry->offset = 0;
        if (base == 0) {
            unsigned int reads = source.reads;
            entry->packed_size = UINT64_MAX;
            archive->mpq_header_v4.raw_chunk_size = 1;
            TEST_CHECK(
                libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) ==
                    LIBMPQ_ERROR_FORMAT &&
                bits == 0
            );
            TEST_CHECK(source.reads == reads);
        }
        if (source.size >= 16384) {
            entry->packed_size = UINT32_MAX;
            archive->mpq_header_v4.raw_chunk_size = UINT32_MAX;
            source.fail_at = base + 1;
            source.max_read = 0;
            TEST_CHECK(
                libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) ==
                    LIBMPQ_ERROR_READ &&
                bits == 0
            );
            TEST_CHECK(source.max_read == 16384);
            source.fail_at = 0;
        }
        *entry = saved;
        archive->mpq_header_v4.raw_chunk_size = chunk_size;
        archive->mpq_header_v3.archive_size = extent;
        archive->file_size = physical;
    }
    entry->unpacked_size = 0;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 && bits == 0
    );
    *entry = saved;
    entry->offset = UINT64_MAX;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == LIBMPQ_ERROR_FORMAT &&
        bits == 0
    );
    *entry = saved;
    entry->packed_size = UINT64_MAX;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == LIBMPQ_ERROR_FORMAT &&
        bits == 0
    );
    *entry = saved;
    entry->flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 && bits == 0
    );
    *entry = saved;
    entry->flags |= LIBMPQ_FILE_FLAG_PATCH_FILE;
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 && bits == 0
    );
    *entry = saved;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Real APIs must agree on rows and bytes regardless of table order or archive base. */
static int
test_v4_read(
    int representation, int compressed, int encrypted, int single, uint64_t base, uint32_t method
)
{
    reader_v4_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_stream_s *stream = NULL;
    uint32_t number;
    uint32_t classic;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t files;
    uint32_t version;
    uint32_t flags;
    uint8_t actual[9000];
    libmpq__off_t transferred;
    libmpq__off_t unpacked;
    libmpq__off_t packed;
    libmpq__off_t offset;
    size_t length = single ? 256 : sizeof(actual);
    TEST_CHECK(
        reader_v4_fixture(&source, representation, compressed, encrypted, single, 0, method) == 0
    );
    if (method != 0)
        TEST_CHECK(reader_v4_table_md5(&source) == 0);
    source.base = base;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v4_read_at, (libmpq__off_t)(source.base + source.size),
            base == 512 ? -1 : (libmpq__off_t)base, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_version(archive, &version) == 0 && version == 4);
    TEST_CHECK(
        archive->mpq_header.header_size == 208 && archive->mpq_header_v3.archive_size == source.size
    );
    TEST_CHECK(memcmp(archive->mpq_header_v4.header_md5, source.v4.header_md5, 16) == 0);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 3);
    TEST_CHECK(libmpq__file_number(archive, "folder/payload.bin", &number) == 0);
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, number, &unpacked) == 0 &&
        unpacked == (libmpq__off_t)length
    );
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0 && packed > 0);
    if ((method & LIBMPQ_COMPRESSION_SPARSE) != 0) {
        uint32_t emitted;
        TEST_CHECK(packed < (libmpq__off_t)length);
        TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "folder/payload.bin") == 0);
        TEST_CHECK(
            libmpq__block_compression(archive, number, 0, &emitted) == 0 &&
            (emitted & LIBMPQ_COMPRESSION_SPARSE) != 0
        );
        TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    }
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0 && offset == 208);
    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
    TEST_CHECK(((flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0) == (encrypted != 0));
    TEST_CHECK(libmpq__stream_open_name(archive, "folder/payload.bin", &stream) == 0);
    TEST_CHECK(
        libmpq__stream_read(stream, actual, length, &transferred) == 0 &&
        transferred == (libmpq__off_t)length
    );
    for (size_t i = 0; i < length; ++i)
        TEST_CHECK(actual[i] == reader_v4_payload_byte(i, method));
    TEST_CHECK(libmpq__stream_seek(stream, 17, LIBMPQ_SEEK_SET) == 0);
    TEST_CHECK(libmpq__stream_read(stream, actual, 20, &transferred) == 0 && transferred == 20);
    for (size_t i = 0; i < 20; ++i)
        TEST_CHECK(actual[i] == reader_v4_payload_byte(i + 17, method));
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    if (!encrypted) {
        TEST_CHECK(libmpq__file_read(archive, number, actual, length, &transferred) == 0);
        TEST_CHECK(transferred == (libmpq__off_t)length);
        for (size_t i = 0; i < length; ++i)
            TEST_CHECK(actual[i] == reader_v4_payload_byte(i, method));
    }
    if (representation == 2) {
        libmpq__file_hash("folder/payload.bin", &h1, &h2, &h3);
        TEST_CHECK(
            libmpq__file_number_from_hash(archive, h1, h2, h3, &classic) == 0 && classic == number
        );
        TEST_CHECK(
            archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask ==
            (LIBMPQ_ENTRY_SOURCE_CLASSIC | LIBMPQ_ENTRY_SOURCE_BET)
        );
    } else if (representation == 0) {
        TEST_CHECK(
            archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index ==
            UINT32_MAX
        );
    }
    if (representation != 1) {
        uint64_t het_size;
        uint64_t bet_size;
        TEST_CHECK(libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size) == 0);
        TEST_CHECK(het_size == source.v4.het_table_size && bet_size == source.v4.bet_table_size);
        if (compressed) {
            uint32_t decoded = libmpq__load_le32(source.bytes + source.v3.het_table_offset + 8);
            TEST_CHECK(het_size < (uint64_t)decoded + 12);
        }
    }
    TEST_CHECK(libmpq__file_number(archive, "zero.bin", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0 && unpacked == 0);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(clone->mpq_header_v4.bet_table_size == source.v4.bet_table_size);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* User-data offsets may target a header that a 512-byte scan cannot discover. */
static int
test_v4_user_data(void)
{
    reader_v4_source_s original;
    reader_v4_source_s source;
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t actual[9000];
    libmpq__off_t transferred;
    TEST_CHECK(reader_v4_fixture(&original, 2, 1, 2, 0, 1, 0) == 0);
    TEST_CHECK(reader_v4_table_md5(&original) == 0);
    TEST_CHECK(original.size + 96 <= sizeof(original.bytes));
    memmove(original.bytes + 96, original.bytes, original.size);
    memset(original.bytes, 0, 96);
    libmpq__store_le32(original.bytes, 0x1b51504du);
    libmpq__store_le32(original.bytes + 4, 32);
    libmpq__store_le32(original.bytes + 8, 96);
    libmpq__store_le32(original.bytes + 12, 16);
    original.size += 96;
    for (unsigned int which = 0; which < 7; ++which) {
        source = original;
        if (which == 1)
            libmpq__store_le32(source.bytes + 8, UINT32_MAX);
        if (which == 2)
            libmpq__store_le32(source.bytes + 8, 8);
        if (which == 3)
            libmpq__store_le32(source.bytes + 4, 97);
        if (which == 4)
            libmpq__store_le32(source.bytes + 12, 33);
        if (which == 5)
            source.bytes[96] = 0;
        if (which == 6)
            source.fail_at = 96;
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, -1, NULL
            ) == (which == 0   ? 0
                  : which == 6 ? LIBMPQ_ERROR_READ
                               : LIBMPQ_ERROR_FORMAT)
        );
        if (which != 0) {
            TEST_CHECK(archive == NULL);
            continue;
        }
        TEST_CHECK(
            archive->archive_offset == 96 &&
            archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR
        );
        TEST_CHECK(libmpq__stream_open_name(archive, "folder/payload.bin", &stream) == 0);
        TEST_CHECK(
            libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0 &&
            transferred == sizeof(actual)
        );
        for (size_t i = 0; i < sizeof(actual); ++i)
            TEST_CHECK(actual[i] == (uint8_t)(i % 17));
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    return 0;
}

/* Short classic extents return UNPACK without identifying their encoding. */
static int
test_v4_extents(void)
{
    reader_v4_source_s original;
    reader_v4_source_s source;
    mpq_archive_s *archive = NULL;
    TEST_CHECK(reader_v4_fixture(&original, 2, 0, 0, 0, 0, 0) == 0);
    for (unsigned int which = 0; which < 21; ++which) {
        int32_t expected = LIBMPQ_ERROR_FORMAT;
        source = original;
        switch (which) {
        case 0:
            source.v3.archive_size = UINT64_MAX;
            break;
        case 1:
            source.v3.bet_table_offset = UINT64_MAX - 3;
            break;
        case 2:
            source.v4.het_table_size = UINT64_MAX;
            break;
        case 3:
            source.v4.hash_table_size = UINT64_MAX;
            break;
        case 4:
            source.header.hash_table_count = UINT32_MAX;
            break;
        case 5:
            source.header.block_table_count = UINT32_MAX;
            break;
        case 6:
            source.v4.het_table_size = LIBMPQ_EXT_TABLE_MAX_SIZE + 1u;
            break;
        case 7:
            source.v3.het_table_offset = 0;
            break;
        case 8:
            source.v4.bet_table_size = 0;
            break;
        case 9:
            source.header.block_table_offset = 100;
            break;
        case 10:
            source.ex.extended_offset = source.size + 1;
            break;
        case 11:
            source.v4.hi_block_table_size = 0;
            break;
        case 12:
            source.v4.hash_table_size--;
            expected = LIBMPQ_ERROR_UNPACK;
            break;
        case 13:
            source.v4.block_table_size--;
            expected = LIBMPQ_ERROR_UNPACK;
            break;
        case 14:
            source.v4.hi_block_table_size--;
            expected = LIBMPQ_ERROR_UNPACK;
            break;
        case 15:
            source.v4.hash_table_size++;
            break;
        case 16:
            source.header.hash_table_offset = 0;
            break;
        case 17:
            source.v3.archive_size = source.size - 1;
            break;
        case 18:
            source.header.hash_table_offset = UINT32_MAX;
            source.ex.hash_table_offset_high = UINT16_MAX;
            break;
        case 19:
            source.v4.het_table_size = 12;
            break;
        default:
            source.v3.bet_table_offset = source.size - 12;
            break;
        }
        TEST_CHECK(reader_v4_header(&source) == 0);
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == expected
        );
        TEST_CHECK(archive == NULL && source.reads == 2);
    }

    /* A correctly framed compressed classic table is explicitly unsupported. */
    {
        uint8_t plain[256];
        uint8_t packed[256];
        unsigned long capacity = sizeof(packed) - 1;
        uint32_t key = libmpq__crypto_hash_string("(hash table)", 0x300);
        source = original;
        TEST_CHECK(source.v4.hash_table_size <= sizeof(plain));
        memcpy(
            plain, source.bytes + source.header.hash_table_offset, (size_t)source.v4.hash_table_size
        );
        TEST_CHECK(
            libmpq__crypto_decrypt_block(plain, (uint32_t)source.v4.hash_table_size, key) == 0
        );
        packed[0] = LIBMPQ_COMPRESSION_ZLIB;
        TEST_CHECK(
            compress2(packed + 1, &capacity, plain, (unsigned long)source.v4.hash_table_size, 9) ==
            Z_OK
        );
        TEST_CHECK(capacity + 1 < source.v4.hash_table_size);
        source.v4.hash_table_size = capacity + 1;
        TEST_CHECK(
            libmpq__crypto_encrypt_block(packed, (uint32_t)source.v4.hash_table_size, key) == 0
        );
        memcpy(
            source.bytes + source.header.hash_table_offset, packed,
            (size_t)source.v4.hash_table_size
        );
        TEST_CHECK(reader_v4_header(&source) == 0);
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == LIBMPQ_ERROR_UNPACK
        );
        TEST_CHECK(archive == NULL && source.reads == 2);
    }
    source = original;
    source.fail_at = source.v3.bet_table_offset;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == LIBMPQ_ERROR_READ
    );
    TEST_CHECK(archive == NULL);
    source = original;
    source.bytes[source.v3.het_table_offset] ^= 1;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    source = original;
    source.bytes[source.v3.het_table_offset + 12] ^= 0x40;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
        ) != 0
    );
    TEST_CHECK(archive == NULL);
    for (size_t available = 32; available < 208; ++available) {
        source = original;
        source.size = available;
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(archive == NULL && source.reads == 1);
    }
    for (unsigned int which = 0; which < 2; ++which) {
        source = original;
        if (which == 0)
            libmpq__store_le32(source.bytes + 4, 207);
        else
            libmpq__store_le16(source.bytes + 12, 4);
        TEST_CHECK(
            libmpq__archive_open_io(
                &archive, &source, reader_v4_read_at, (libmpq__off_t)source.size, 0, NULL
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(archive == NULL);
    }

    /* An empty archive needs no tables; a live block still needs a lookup representation. */
    memset(&source, 0, sizeof(source));
    source.header =
        (mpq_header_s){ LIBMPQ_HEADER, 208, 1, LIBMPQ_ARCHIVE_VERSION_FOUR, 3, 0, 0, 0, 0 };
    source.size = 208;
    source.v3.archive_size = 208;
    TEST_CHECK(reader_v4_header(&source) == 0);
    TEST_CHECK(libmpq__archive_open_io(&archive, &source, reader_v4_read_at, 208, 0, NULL) == 0);
    TEST_CHECK(archive->files == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    source.header.block_table_count = 1;
    source.header.block_table_offset = 208;
    source.v4.block_table_size = 16;
    source.size = 224;
    source.v3.archive_size = 224;
    TEST_CHECK(reader_v4_header(&source) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(&archive, &source, reader_v4_read_at, 224, 0, NULL) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    return 0;
}

/* Plain/MPQE path opening remains read-only and rejected transactions preserve sources. */
static int
test_v4_mpqe_read_only(int raw, int embedded)
{
    reader_v4_source_s source;
    reader_v4_source_s cipher;
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    mpq_update_s *update = NULL;
    mpq_patch_s *patch = NULL;
    mpq_archive_create_options_s options = { 0 };
    uint8_t auth[32];
    uint8_t key[64];
    uint8_t actual[9000];
    uint32_t number;
    libmpq__off_t transferred;
    FILE *file;
    if (raw)
        TEST_CHECK(reader_v4_raw_fixture(&source, 31, 1, 1, 0) == 0);
    else
        TEST_CHECK(reader_v4_fixture(&source, 2, 1, 2, 0, 0, 0) == 0);
    TEST_CHECK(reader_v4_table_md5(&source) == 0);
    if (embedded) {
        TEST_CHECK(source.size + 96 <= sizeof(source.bytes));
        memmove(source.bytes + 96, source.bytes, source.size);
        memset(source.bytes, 0, 96);
        libmpq__store_le32(source.bytes, LIBMPQ_USER_DATA_HEADER);
        libmpq__store_le32(source.bytes + 4, 32);
        libmpq__store_le32(source.bytes + 8, 96);
        libmpq__store_le32(source.bytes + 12, 16);
        source.size += 96;
    }
    file = fopen("reader-v4.mpq", "wb");
    TEST_CHECK(
        file != NULL && fwrite(source.bytes, 1, source.size, file) == source.size &&
        fclose(file) == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, "reader-v4.mpq", -1) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        libmpq__update_begin(&update, "reader-v4.mpq") == LIBMPQ_ERROR_FORMAT && update == NULL
    );
    TEST_CHECK(
        libmpq__patch_begin(&patch, "reader-v4.mpq", "reader-v4-patch.mpq") ==
            LIBMPQ_ERROR_FORMAT &&
        patch == NULL
    );
    options.version = LIBMPQ_ARCHIVE_VERSION_FOUR + 1;
    TEST_CHECK(
        libmpq__archive_create(&archive, "reader-v4-output.mpq", &options) == LIBMPQ_ERROR_FORMAT &&
        archive == NULL
    );
    memset(auth, 0x53, sizeof(auth));
    TEST_CHECK(libmpq__mpqe_key(key, auth, sizeof(auth)) == 0);
    cipher = source;
    for (size_t offset = 0; offset < source.size; offset += sizeof(key)) {
        uint8_t chunk[64] = { 0 };
        size_t size = source.size - offset < sizeof(chunk) ? source.size - offset : sizeof(chunk);
        memcpy(chunk, source.bytes + offset, size);
        libmpq__mpqe_transform_chunk(chunk, key, offset);
        memcpy(cipher.bytes + offset, chunk, size);
    }
    libmpq__mpqe_clear(key, sizeof(key));
    file = fopen("reader-v4.mpqe", "wb");
    TEST_CHECK(
        file != NULL && fwrite(cipher.bytes, 1, cipher.size, file) == cipher.size &&
        fclose(file) == 0
    );
    TEST_CHECK(
        libmpq__archive_open_mpqe_io(
            &archive, &cipher, reader_v4_read_at, (libmpq__off_t)cipher.size, -1, auth,
            sizeof(auth), NULL
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "folder/payload.bin", &number) == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, "folder/payload.bin", &stream) == 0);
    if (raw) {
        uint32_t bits = UINT32_MAX;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &bits) == 0 && bits == 0
        );
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits) == 0 && bits == 0
        );
    }
    TEST_CHECK(
        libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0 &&
        transferred == sizeof(actual)
    );
    for (size_t i = 0; i < sizeof(actual); ++i)
        TEST_CHECK(actual[i] == (uint8_t)(i % 17));
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open_mpqe(&archive, "reader-v4.mpqe", -1, auth, sizeof(auth)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        libmpq__update_begin_mpqe(&update, "reader-v4.mpqe", auth, sizeof(auth)) ==
            LIBMPQ_ERROR_FORMAT &&
        update == NULL
    );
    if (!raw) {
        cipher.bytes[(size_t)source.v3.het_table_offset + (embedded ? 96 : 0) + 12] ^= 1;
        TEST_CHECK(
            libmpq__archive_open_mpqe_io(
                &archive, &cipher, reader_v4_read_at, (libmpq__off_t)cipher.size, -1, auth,
                sizeof(auth), NULL
            ) == LIBMPQ_ERROR_FORMAT &&
            archive == NULL
        );
        cipher.bytes[(size_t)source.v3.het_table_offset + (embedded ? 96 : 0) + 12] ^= 1;
    }
    auth[0] ^= 1;
    TEST_CHECK(
        libmpq__archive_open_mpqe_io(
            &archive, &cipher, reader_v4_read_at, (libmpq__off_t)cipher.size, -1, auth,
            sizeof(auth), NULL
        ) != 0 &&
        archive == NULL
    );
    {
        uint8_t *bytes;
        size_t size;
        TEST_CHECK(test_read_path("reader-v4.mpq", &bytes, &size) == 0);
        TEST_CHECK(size == source.size && memcmp(bytes, source.bytes, size) == 0);
        free(bytes);
        TEST_CHECK(test_read_path("reader-v4.mpqe", &bytes, &size) == 0);
        TEST_CHECK(size == cipher.size && memcmp(bytes, cipher.bytes, size) == 0);
        free(bytes);
    }
    TEST_CHECK(remove("reader-v4.mpq") == 0);
    TEST_CHECK(remove("reader-v4.mpqe") == 0);
    return 0;
}

/* Validate fixture metadata and extraction through the reader-facing API. */
int
main(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    uint8_t *block_data;
    size_t size;
    char hash[65];
    uint32_t number;
    uint32_t blocks;
    uint32_t flags;
    libmpq__off_t block_size;
    libmpq__off_t transferred;

    TEST_CHECK(test_extended_sector_offsets() == 0);
    TEST_CHECK(test_v4_user_data() == 0);
    TEST_CHECK(test_v3_mixed_rows(2, 2, 0, 0) == 0);
    TEST_CHECK(test_v3_mixed_rows(2, 4, 0, 0) == 0);
    TEST_CHECK(test_v3_mixed_rows(4, 2, 0, 0) == 0);
    TEST_CHECK(test_v3_mixed_rows(2, 2, 1, 0) == 0);
    TEST_CHECK(test_v3_mixed_rows(2, 2, 2, 0) == 0);
    TEST_CHECK(test_v3_mixed_rows(2, 4, 0, 1) == 0);
    for (int het = 0; het < 2; het++)
        for (int bet = 0; bet < 2; bet++)
            TEST_CHECK(test_v3_bet_read(het, bet, 0, 0, 0, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(0, 0, 1, 0, 0, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(1, 1, 1, 1, 0, 0, 0, 512) == 0);
    TEST_CHECK(test_v3_bet_read(0, 0, 2, 0, 0, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(0, 0, 1, 0, 1, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(1, 1, 1, 0, 3, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(0, 0, 0, 0, 1, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(1, 1, 0, 0, 2, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(1, 1, 0, 0, 3, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(1, 1, 0, 0, 0, 0, UINT64_C(0x100000000), 0) == 0);
    TEST_CHECK(test_v3_bet_read(0, 0, 0, 0, 0, 1, 0, 0) == 0);

    /* Production encoder bytes must pass the existing generic-I/O table loader. */
    TEST_CHECK(test_v3_bet_read(2, 2, 0, 0, 0, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_read(3, 3, 0, 0, 1, 0, 0, 0) == 0);
    TEST_CHECK(test_v3_bet_errors() == 0);
    TEST_CHECK(test_v3_extent_geometry() == 0);
    TEST_CHECK(test_v3_table_keys() == 0);
    TEST_CHECK(test_v3_table_counts() == 0);
    TEST_CHECK(test_v3_table_limits() == 0);
    TEST_CHECK(test_v3_table_limit_boundary() == 0);
    TEST_CHECK(test_v3_signature_discovery() == 0);
    TEST_CHECK(test_v3_size_conversions() == 0);
    TEST_CHECK(test_size_accumulators() == 0);
    TEST_CHECK(test_v3_patch_payload() == 0);
    TEST_CHECK(test_v3_transaction_setup() == 0);
    TEST_CHECK(test_v3_reserved_update() == 0);
    TEST_CHECK(test_v4_independent_layout() == 0);
    {
        static const uint32_t methods[] = { LIBMPQ_COMPRESSION_ZLIB,
                                            LIBMPQ_COMPRESSION_BZIP2,
                                            LIBMPQ_COMPRESSION_PKZIP,
                                            LIBMPQ_COMPRESSION_HUFFMAN,
                                            LIBMPQ_COMPRESSION_LZMA,
                                            LIBMPQ_COMPRESSION_SPARSE,
                                            LIBMPQ_COMPRESSION_SPARSE | LIBMPQ_COMPRESSION_ZLIB,
                                            LIBMPQ_COMPRESSION_SPARSE | LIBMPQ_COMPRESSION_BZIP2 };
        for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i) {
            TEST_CHECK(test_v4_read(2, 1, 2, 0, 0, methods[i]) == 0);
            TEST_CHECK(test_v4_read(0, 1, 1, 1, 512, methods[i]) == 0);
        }
    }
    TEST_CHECK(test_v4_raw_md5(0, 0, 0, 1, 0) == 0);
    TEST_CHECK(test_v4_raw_md5(256, 0, 0, 1, 0) == 0);
    TEST_CHECK(test_v4_raw_md5(64, 0, 0, 1, 512) == 0);
    TEST_CHECK(test_v4_raw_md5(100, 0, 1, 1, 0) == 0);
    TEST_CHECK(test_v4_raw_md5(4096, 0, 0, 0, UINT64_C(0x100000000)) == 0);
    TEST_CHECK(test_v4_raw_md5(31, 1, 0, 0, 0) == 0);
    TEST_CHECK(test_v4_raw_md5(31, 1, 1, 0, 512) == 0);
    TEST_CHECK(test_v4_raw_md5(1, 1, 1, 1, 0) == 0);
    TEST_CHECK(test_v4_raw_md5(UINT32_MAX, 1, 0, 0, 0) == 0);
    for (int representation = 0; representation < 3; ++representation) {
        TEST_CHECK(test_v4_md5(representation, 0) == 0);
        TEST_CHECK(test_v4_md5(representation, 1) == 0);
        TEST_CHECK(test_v4_read(representation, 0, 0, 0, 0, 0) == 0);
        TEST_CHECK(test_v4_read(representation, 0, 1, 0, 0, 0) == 0);
        TEST_CHECK(test_v4_read(representation, 1, 1, 0, 512, 0) == 0);
        TEST_CHECK(test_v4_read(representation, 1, 2, 0, 0, 0) == 0);
        TEST_CHECK(test_v4_read(representation, 1, 2, 1, UINT64_C(0x100000000), 0) == 0);
    }
    TEST_CHECK(test_v4_extents() == 0);
    TEST_CHECK(test_v4_mpqe_read_only(0, 0) == 0);
    TEST_CHECK(test_v4_mpqe_read_only(1, 0) == 0);
    TEST_CHECK(test_v4_mpqe_read_only(0, 1) == 0);
    TEST_CHECK(test_v4_mpqe_read_only(1, 1) == 0);
    TEST_CHECK(test_canonical_entries(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_canonical_entries(LIBMPQ_ARCHIVE_VERSION_TWO) == 0);

    TEST_CHECK(snprintf(path, sizeof(path), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(
        strcmp(hash, "722f1acc2acd306abaed0466ffbbfd568e09f5e7da8d63eba86f19c1c2adde73") == 0
    );
    TEST_CHECK(libmpq__block_size_unpacked(archive, number, 0, &block_size) == 0);
    TEST_CHECK(block_size > 0 && (uint64_t)block_size <= size);
    block_data = malloc((size_t)block_size + 17);
    TEST_CHECK(block_data != NULL);
    TEST_CHECK(libmpq__block_read(archive, number, 0, block_data, block_size, &transferred) == 0);
    TEST_CHECK(transferred == block_size);
    TEST_CHECK(memcmp(block_data, data, (size_t)block_size) == 0);

    /*
     * Raw unencrypted reads share input/output storage and must skip self-copy.
     * Their logical size remains independent of the caller buffer capacity.
     */
    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
    TEST_CHECK(
        (flags &
         (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED)) == 0
    );
    memset(block_data, 0xa5, (size_t)block_size + 17);
    TEST_CHECK(
        libmpq__block_read(archive, number, 0, block_data, block_size + 17, &transferred) == 0
    );
    TEST_CHECK(transferred == block_size);
    TEST_CHECK(memcmp(block_data, data, (size_t)block_size) == 0);
    TEST_CHECK(block_data[block_size] == 0xa5);
    free(block_data);
    free(data);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}
