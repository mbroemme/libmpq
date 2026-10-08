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

/* Read-only boundaries include ordinary and authenticated transaction setup. */
static int
test_v3_read_only(void)
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
    TEST_CHECK(libmpq__update_begin(&update, "reader-v3.mpq") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(update == NULL);
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
    TEST_CHECK(
        libmpq__update_begin_mpqe(&update, "reader-v3.mpqe", auth, sizeof(auth)) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(update == NULL);
    TEST_CHECK(remove("reader-v3.mpq") == 0);
    TEST_CHECK(remove("reader-v3.mpqe") == 0);
    return 0;
}

/* Extra aligned DWORDs before the first compressed sector are not encryption. */
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
    TEST_CHECK(test_v3_bet_errors() == 0);
    TEST_CHECK(test_v3_extent_geometry() == 0);
    TEST_CHECK(test_v3_table_keys() == 0);
    TEST_CHECK(test_v3_table_counts() == 0);
    TEST_CHECK(test_v3_table_limits() == 0);
    TEST_CHECK(test_v3_table_limit_boundary() == 0);
    TEST_CHECK(test_v3_signature_discovery() == 0);
    TEST_CHECK(test_v3_size_conversions() == 0);
    TEST_CHECK(test_v3_patch_payload() == 0);
    TEST_CHECK(test_v3_read_only() == 0);
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
