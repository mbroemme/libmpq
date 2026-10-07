/*
 *  mpq-reader.c -- internal archive reader implementation.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpq-archive.h"
#include "mpq-attributes.h"
#include "mpq-block.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-reader.h"
#include "mpq-source.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/*
 * Accumulate a serialized range without wrapping.
 * Callers decide whether zero-length ranges are meaningful.
 */
static int32_t
extend_extent(uint64_t offset, uint64_t length, uint64_t *extent)
{
    uint64_t end;
    if (offset > UINT64_MAX - length)
        return LIBMPQ_ERROR_FORMAT;
    end = offset + length;
    if (end > *extent)
        *extent = end;
    return 0;
}

/* Classic rows have explicit provenance; consumers never assume entry order. */
int32_t
libmpq__entry_index_from_classic(
    const mpq_archive_s *archive, uint32_t block_index, uint32_t *entry_index
)
{
    uint32_t index;
    if (entry_index != NULL)
        *entry_index = UINT32_MAX;
    if (archive == NULL || entry_index == NULL || archive->classic_entry_indices == NULL ||
        archive->mpq_entry == NULL || block_index >= archive->mpq_header.block_table_count)
        return LIBMPQ_ERROR_FORMAT;
    index = archive->classic_entry_indices[block_index];
    if (index >= archive->entry_count ||
        (archive->mpq_entry[index].source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) == 0 ||
        archive->mpq_entry[index].classic_source_index != block_index)
        return LIBMPQ_ERROR_FORMAT;
    *entry_index = index;
    return 0;
}

int32_t
libmpq__entry_index_from_bet(
    const mpq_archive_s *archive, uint64_t bet_index, uint32_t *entry_index
)
{
    uint32_t index;
    if (entry_index != NULL)
        *entry_index = UINT32_MAX;
    if (archive == NULL || entry_index == NULL || archive->bet_entry_indices == NULL ||
        archive->mpq_entry == NULL || bet_index >= archive->mpq_bet.header.entry_count)
        return LIBMPQ_ERROR_FORMAT;
    index = archive->bet_entry_indices[bet_index];
    if (index >= archive->entry_count ||
        (archive->mpq_entry[index].source_mask & LIBMPQ_ENTRY_SOURCE_BET) == 0 ||
        archive->mpq_entry[index].bet_source_index != bet_index)
        return LIBMPQ_ERROR_FORMAT;
    *entry_index = index;
    return 0;
}

/* Absent structures are skipped, not used as zero boundaries. Classic sizes stay fixed. */
int32_t
libmpq__reader_ext_table_sizes(const mpq_archive_s *archive, uint64_t *het_size, uint64_t *bet_size)
{
    uint64_t positions[6];
    uint64_t lengths[5];
    size_t i;
    size_t j;
    if (het_size == NULL || bet_size == NULL || archive == NULL)
        return LIBMPQ_ERROR_FORMAT;
    *het_size = *bet_size = 0;
    positions[0] = archive->mpq_header_v3.het_table_offset;
    positions[1] = archive->mpq_header_v3.bet_table_offset;
    positions[2] = archive->mpq_header.hash_table_count == 0
                       ? 0
                       : archive->mpq_header.hash_table_offset |
                             ((uint64_t)archive->mpq_header_ex.hash_table_offset_high << 32);
    positions[3] = archive->mpq_header.block_table_count == 0
                       ? 0
                       : archive->mpq_header.block_table_offset |
                             ((uint64_t)archive->mpq_header_ex.block_table_offset_high << 32);
    positions[4] = archive->mpq_header_ex.extended_offset;
    positions[5] = libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    lengths[0] = lengths[1] = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
    lengths[2] = (uint64_t)archive->mpq_header.hash_table_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    lengths[3] = (uint64_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    lengths[4] = (uint64_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE;
    for (i = 0; i < 5; i++) {
        if (positions[i] == 0)
            continue;
        if (positions[i] < archive->mpq_header.header_size)
            return LIBMPQ_ERROR_FORMAT;
        for (j = i + 1; j < 5 && positions[j] == 0; j++) {
        }
        if (positions[i] >= positions[j] || lengths[i] > positions[j] - positions[i])
            return LIBMPQ_ERROR_FORMAT;
        if (i == 0)
            *het_size = positions[j] - positions[i];
        if (i == 1)
            *bet_size = positions[j] - positions[i];
    }
    return 0;
}

/* Bound every known v3 table range by its authoritative archive extent. */
static int32_t
validate_v3_header(const mpq_archive_s *archive)
{
    uint64_t size = libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    uint64_t hash = archive->mpq_header.hash_table_offset |
                    ((uint64_t)archive->mpq_header_ex.hash_table_offset_high << 32);
    uint64_t block = archive->mpq_header.block_table_offset |
                     ((uint64_t)archive->mpq_header_ex.block_table_offset_high << 32);
    uint64_t high = archive->mpq_header_ex.extended_offset;
    uint64_t bet = archive->mpq_header_v3.bet_table_offset;
    uint64_t het = archive->mpq_header_v3.het_table_offset;
    uint32_t hashes = archive->mpq_header.hash_table_count;
    uint32_t blocks = archive->mpq_header.block_table_count;

    if (archive->archive_offset < 0 || size < archive->mpq_header.header_size ||
        size > (uint64_t)INT64_MAX - (uint64_t)archive->archive_offset ||
        (uint64_t)archive->archive_offset > archive->file_size ||
        size > archive->file_size - (uint64_t)archive->archive_offset)
        return LIBMPQ_ERROR_FORMAT;
    if ((blocks != 0 && hashes == 0 && het == 0) || ((bet == 0) != (het == 0)))
        return LIBMPQ_ERROR_FORMAT;
    if (hashes != 0 &&
        ((hashes & (hashes - 1u)) != 0 || hash < archive->mpq_header.header_size || hash > size ||
         (uint64_t)hashes * LIBMPQ_HASH_ENTRY_WIRE_SIZE > size - hash))
        return LIBMPQ_ERROR_FORMAT;
    if (blocks != 0 && (block < archive->mpq_header.header_size || block > size ||
                        (uint64_t)blocks * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE > size - block))
        return LIBMPQ_ERROR_FORMAT;
    if (high != 0 && (high < archive->mpq_header.header_size || high > size ||
                      (uint64_t)blocks * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE > size - high))
        return LIBMPQ_ERROR_FORMAT;
    if ((bet != 0 && (bet < archive->mpq_header.header_size || bet >= size)) ||
        (het != 0 && (het < archive->mpq_header.header_size || het >= size)))
        return LIBMPQ_ERROR_FORMAT;
    if (het != 0) {
        uint64_t het_size;
        uint64_t bet_size;
        return libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size);
    }
    return 0;
}

/* The envelope is plaintext; only its contained data is ciphered, then decompressed. */
static int32_t
ext_table_load(
    mpq_archive_s *archive, uint64_t offset, uint64_t stored_size, uint32_t signature, uint32_t key,
    uint8_t **output, size_t *output_size
)
{
    uint8_t envelope[LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE];
    uint8_t *stored = NULL;
    uint8_t *decoded = NULL;
    uint32_t data_size;
    uint64_t decoded_size;
    size_t payload_size;
    int32_t result;
    *output = NULL;
    *output_size = 0;
    if (stored_size < sizeof(envelope) || stored_size > LIBMPQ_EXT_TABLE_MAX_SIZE ||
        stored_size - sizeof(envelope) > INT32_MAX)
        return LIBMPQ_ERROR_FORMAT;
    result = libmpq__source_read_at(
        archive->source, (uint64_t)archive->archive_offset + offset, envelope, sizeof(envelope)
    );
    if (result != 0)
        return result;
    data_size = libmpq__load_le32(envelope + 8);
    decoded_size = (uint64_t)data_size + sizeof(envelope);
    if (libmpq__load_le32(envelope) != signature ||
        libmpq__load_le32(envelope + 4) != LIBMPQ_EXT_TABLE_VERSION || data_size == 0 ||
        data_size > INT32_MAX || decoded_size > LIBMPQ_EXT_TABLE_MAX_SIZE ||
        decoded_size > SIZE_MAX)
        return LIBMPQ_ERROR_FORMAT;
    payload_size = (size_t)(stored_size - sizeof(envelope));
    if (payload_size == 0 || payload_size > data_size)
        return LIBMPQ_ERROR_FORMAT;
    stored = malloc(payload_size);
    decoded = malloc(sizeof(envelope) + data_size);
    if (stored == NULL || decoded == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    memcpy(decoded, envelope, sizeof(envelope));
    result = libmpq__source_read_at(
        archive->source, (uint64_t)archive->archive_offset + offset + sizeof(envelope), stored,
        payload_size
    );
    if (result != 0)
        goto done;
    libmpq__crypto_decrypt_block(stored, (uint32_t)payload_size, key);
    if (payload_size < data_size) {
        result = libmpq__compression_decompress_table(
            stored, (uint32_t)payload_size, decoded + sizeof(envelope), data_size,
            LIBMPQ_ARCHIVE_VERSION_THREE
        );
        if (result != (int32_t)data_size) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    } else {
        memcpy(decoded + sizeof(envelope), stored, payload_size);
    }
    *output = decoded;
    *output_size = sizeof(envelope) + data_size;
    decoded = NULL;
    result = 0;
done:
    free(stored);
    free(decoded);
    return result;
}

/* BET establishes rows; live classic metadata overlays shared source rows. */
static int32_t
load_het_bet(mpq_archive_s *archive)
{
    uint64_t het_size;
    uint64_t bet_size;
    size_t size;
    uint32_t classic_count = archive->mpq_header.block_table_count;
    uint32_t count;
    uint32_t capacity;
    uint32_t i;
    int32_t result;
    if (archive->mpq_header_v3.het_table_offset == 0)
        return 0;
    result = libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size);
    if (result != 0)
        return result;
    result = ext_table_load(
        archive, archive->mpq_header_v3.het_table_offset, het_size, LIBMPQ_HET_SIGNATURE,
        libmpq__crypto_hash_string("(hash table)", 0x300), &archive->het_data, &size
    );
    if (result != 0)
        return result;
    result = libmpq__het_view_init(archive->het_data, size, &archive->mpq_het);
    if (result != 0)
        return result;
    result = ext_table_load(
        archive, archive->mpq_header_v3.bet_table_offset, bet_size, LIBMPQ_BET_SIGNATURE,
        libmpq__crypto_hash_string("(block table)", 0x300), &archive->bet_data, &size
    );
    if (result != 0)
        return result;
    result = libmpq__bet_view_init(archive->bet_data, size, &archive->mpq_bet);
    if (result != 0)
        return result;
    count = archive->mpq_bet.header.entry_count;
    if (archive->mpq_het.header.entry_count != count ||
        archive->mpq_het.header.name_hash_bit_size - 8 != archive->mpq_bet.header.name_hash2_size)
        return LIBMPQ_ERROR_FORMAT;
    capacity = count > classic_count ? count : classic_count;
    if (capacity != 0 && SIZE_MAX / capacity < sizeof(mpq_entry_s))
        return LIBMPQ_ERROR_FORMAT;
    if (count != 0) {
        mpq_entry_s *entries = realloc(archive->mpq_entry, (size_t)capacity * sizeof(*entries));
        if (entries == NULL)
            return LIBMPQ_ERROR_MALLOC;
        archive->mpq_entry = entries;
        archive->bet_entry_indices = calloc(count, sizeof(uint32_t));
        if (archive->bet_entry_indices == NULL)
            return LIBMPQ_ERROR_MALLOC;
    }
    archive->entry_count = capacity;
    for (i = 0; i < count; i++) {
        uint64_t hash;
        mpq_entry_s decoded;
        mpq_entry_s *entry = &decoded;
        result = libmpq__bet_name_hash2(&archive->mpq_bet, i, &hash);
        if (result == 0)
            result = libmpq__bet_entry_decode(&archive->mpq_bet, i, hash, entry);
        if (result != 0)
            return result;
        archive->bet_entry_indices[i] = i;
        if (entry->offset > INT64_MAX || entry->packed_size > INT64_MAX ||
            entry->unpacked_size > INT64_MAX ||
            ((entry->flags & LIBMPQ_FLAG_EXISTS) != 0 &&
             (entry->offset < archive->mpq_header.header_size ||
              entry->offset >
                  libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3) ||
              entry->packed_size >
                  libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3) -
                      entry->offset)))
            return LIBMPQ_ERROR_FORMAT;
        if (i < classic_count) {
            const mpq_entry_s *classic = &archive->mpq_entry[i];
            if ((classic->flags & LIBMPQ_FLAG_EXISTS) != 0) {
                entry->offset = classic->offset;
                entry->packed_size = classic->packed_size;
                entry->unpacked_size = classic->unpacked_size;
                entry->flags = classic->flags;
            }
            entry->source_mask |= LIBMPQ_ENTRY_SOURCE_CLASSIC;
            entry->classic_source_index = i;
        }
        archive->mpq_entry[i] = decoded;
    }

    /* Reject malformed live slots at open, even if later lookup would miss them. */
    for (i = 0; i < archive->mpq_het.header.total_count; i++) {
        uint64_t index;
        uint8_t prefix = archive->mpq_het.name_hash1[i];
        if (prefix == LIBMPQ_HET_SLOT_FREE)
            continue;
        if ((prefix & 0x80) == 0 || libmpq__het_slot_index(&archive->mpq_het, i, &index) != 0 ||
            index >= count)
            return LIBMPQ_ERROR_FORMAT;
    }
    return 0;
}

int32_t
libmpq__archive_required_extent(const mpq_archive_s *archive, uint64_t *size)
{
    uint64_t extent;
    uint64_t hash;
    uint64_t block;
    uint32_t i;
    if (size != NULL)
        *size = 0;
    if (archive == NULL || size == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->archive_offset < 0 || archive->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_THREE ||
        (archive->entry_count != 0 && archive->mpq_entry == NULL))
        return LIBMPQ_ERROR_FORMAT;
    extent = archive->mpq_header.header_size;
    if (extent < LIBMPQ_HEADER_WIRE_SIZE ||
        (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO &&
         extent < LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE) ||
        (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE &&
         extent != LIBMPQ_HEADER_WIRE_SIZE &&
         extent < LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE))
        return LIBMPQ_ERROR_FORMAT;
    hash = archive->mpq_header.hash_table_offset |
           ((uint64_t)archive->mpq_header_ex.hash_table_offset_high << 32);
    block = archive->mpq_header.block_table_offset |
            ((uint64_t)archive->mpq_header_ex.block_table_offset_high << 32);
    if (extend_extent(
            hash, (uint64_t)archive->mpq_header.hash_table_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE,
            &extent
        ) != 0 ||
        extend_extent(
            block, (uint64_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE,
            &extent
        ) != 0)
        return LIBMPQ_ERROR_FORMAT;
    if (archive->mpq_header_ex.extended_offset != 0 &&
        extend_extent(
            archive->mpq_header_ex.extended_offset,
            (uint64_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE,
            &extent
        ) != 0)
        return LIBMPQ_ERROR_FORMAT;
    for (i = 0; i < archive->entry_count; ++i) {
        if ((archive->mpq_entry[i].flags & LIBMPQ_FLAG_EXISTS) &&
            archive->mpq_entry[i].packed_size != 0 &&
            extend_extent(
                archive->mpq_entry[i].offset, archive->mpq_entry[i].packed_size, &extent
            ) != 0)
            return LIBMPQ_ERROR_FORMAT;
    }
    if (archive->het_data != NULL) {
        uint64_t het_size;
        uint64_t bet_size;
        if (libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size) != 0 ||
            extend_extent(archive->mpq_header_v3.het_table_offset, het_size, &extent) != 0 ||
            extend_extent(archive->mpq_header_v3.bet_table_offset, bet_size, &extent) != 0)
            return LIBMPQ_ERROR_FORMAT;
    }
    *size = extent;
    return 0;
}

int32_t
libmpq__archive_signature_extent(const mpq_archive_s *archive, uint64_t *size)
{
    uint64_t required;
    uint64_t extent;
    int32_t result;
    if (size != NULL)
        *size = 0;
    if (archive == NULL || size == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_required_extent(archive, &required);
    if (result != 0)
        return result;
    extent = archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO
                 ? required
                 : libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    if (extent < required || (uint64_t)archive->archive_offset > archive->file_size ||
        extent > archive->file_size - (uint64_t)archive->archive_offset)
        return LIBMPQ_ERROR_FORMAT;
    *size = extent;
    return 0;
}

/*
 * Release a cached block offset table when the last user closes it.
 * Reference counting permits nested block operations while ensuring the cache
 * is freed only after the final matching close.
 */
int32_t
libmpq__reader_offsets_release(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    mpq_archive->mpq_file[file_number]->open_count--;

    if (mpq_archive->mpq_file[file_number]->open_count != 0) {

        /* Keep the cache alive until every matching open operation closes. */
        return 0;
    }

    free(mpq_archive->mpq_file[file_number]->packed_offset);
    free(mpq_archive->mpq_file[file_number]);

    mpq_archive->mpq_file[file_number] = NULL;

    return 0;
}

/*
 * Read a complete file by opening its block offset table and copying each block.
 * The output buffer must hold the complete unpacked file, and cached offset
 * state is closed on both successful and failed block reads.
 */
int32_t
libmpq__reader_file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
)
{

    /* Block loop state and total bytes transferred to the caller. */
    uint32_t i;
    uint32_t blocks = 0;
    int32_t result = 0;
    libmpq__off_t file_offset = 0;
    libmpq__off_t expected_size = 0;
    libmpq__off_t unpacked_size = 0;
    libmpq__off_t transferred_block = 0;
    libmpq__off_t transferred_total = 0;
    uint32_t *checksums = NULL;
    uint32_t mismatches = 0;
    uint32_t sector_mismatches = 0;
    int lossy = 0;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    libmpq__file_size_unpacked(mpq_archive, file_number, &expected_size);

    if (expected_size > out_size) {
        return LIBMPQ_ERROR_SIZE;
    }

    libmpq__file_offset(mpq_archive, file_number, &file_offset);
    libmpq__file_blocks(mpq_archive, file_number, &blocks);

    if ((result = libmpq__reader_offsets_acquire(mpq_archive, file_number, NULL)) < 0) {
        return result;
    }

    /*
     * Sector tables are optional metadata. Explicit verification reports
     * malformed tables, while complete reads skip unusable tables and retain
     * normal extraction behavior.
     */
    if (libmpq__reader_sector_checksums(mpq_archive, file_number, &checksums) < 0)
        checksums = NULL;

    /* Read each block into its exact destination slice and maintain one total. */
    for (i = 0; i < blocks; i++) {
        int block_lossy = 0;

        unpacked_size = 0;

        libmpq__block_size_unpacked(mpq_archive, file_number, i, &unpacked_size);

        /* Offset state is already held for the complete file read. */
        if ((result = libmpq__reader_block_read_acquired(
                 mpq_archive, file_number, i, out_buf + transferred_total, unpacked_size,
                 &transferred_block, checksums != NULL ? checksums + i : NULL, &sector_mismatches,
                 &block_lossy
             )) < 0) {
            free(checksums);
            libmpq__reader_offsets_release(mpq_archive, file_number);
            return result;
        }

        if (block_lossy)
            lossy = 1;
        transferred_total += transferred_block;
    }

    if (transferred_total != expected_size) {
        free(checksums);
        (void)libmpq__reader_offsets_release(mpq_archive, file_number);
        return LIBMPQ_ERROR_READ;
    }
    result = libmpq__reader_offsets_release(mpq_archive, file_number);
    free(checksums);
    if (result < 0)
        return result;

    if (sector_mismatches != 0)
        return LIBMPQ_ERROR_READ;

    /*
     * file_read always decodes the complete logical member. Compare lossless
     * output against attributes without reopening or rereading the member.
     */
    if (!lossy) {
        result = libmpq__attributes_verify_data(
            mpq_archive, file_number, out_buf, (size_t)transferred_total, &mismatches
        );
        if (result < 0)
            return result;
        if (mismatches != 0)
            return LIBMPQ_ERROR_READ;
    }

    if (transferred != NULL) {
        *transferred = transferred_total;
    }

    return 0;
}

/*
 * Metadata-only sizes need no decryption key. For sectorized codec files,
 * reuse the reader's parsed offsets and exclude the checksum-table extent.
 */
int32_t
libmpq__reader_block_size_packed(
    mpq_archive_s *archive, uint32_t number, uint32_t block, libmpq__off_t *packed_size
)
{
    uint32_t index;
    uint32_t flags;
    uint64_t start = 0;
    uint64_t length;
    int32_t status;

    if (packed_size != NULL)
        *packed_size = 0;
    if (archive == NULL || packed_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (libmpq__reader_validate_file_number(archive, number) < 0 ||
        libmpq__reader_validate_block_number(archive, number, block) < 0)
        return LIBMPQ_ERROR_EXIST;
    index = archive->mpq_map[number].entry_index;
    flags = archive->mpq_entry[index].flags;
    if ((flags & LIBMPQ_FLAG_SINGLE) != 0) {
        length = archive->mpq_entry[index].packed_size;
    } else if ((flags & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0) {
        libmpq__off_t unpacked;
        status = libmpq__block_size_unpacked(archive, number, block, &unpacked);
        if (status < 0)
            return status;
        start = (uint64_t)block * archive->block_size;
        length = (uint64_t)unpacked;
    } else {
        uint32_t end;
        status = libmpq__reader_offsets_acquire(archive, number, NULL);
        if (status < 0)
            return status;
        start = archive->mpq_file[number]->packed_offset[block];
        end = archive->mpq_file[number]->packed_offset[block + 1U];
        status = libmpq__reader_offsets_release(archive, number);
        if (status < 0)
            return status;
        if (end < start)
            return LIBMPQ_ERROR_FORMAT;
        length = end - start;
    }
    if (start > archive->mpq_entry[index].packed_size ||
        length > archive->mpq_entry[index].packed_size - start)
        return LIBMPQ_ERROR_FORMAT;
    status = libmpq__reader_validate_payload_range(archive, index, start, length);
    if (status < 0)
        return status;
    *packed_size = (libmpq__off_t)length;
    return 0;
}

/*
 * Read all or a prefix of an already bounded packed sector. Encryption uses
 * complete words; a short final word remains literal as in the full reader.
 */
static int32_t
read_packed(mpq_archive_s *archive, uint32_t number, uint32_t block, uint8_t *buffer, size_t size)
{
    uint32_t index = archive->mpq_map[number].entry_index;
    uint32_t seed;
    uint64_t offset = (uint64_t)archive->archive_offset + archive->mpq_entry[index].offset +
                      archive->mpq_file[number]->packed_offset[block];
    int32_t status = libmpq__source_read_at(archive->source, offset, buffer, size);
    if (status < 0)
        return status;
    if ((archive->mpq_entry[index].flags & LIBMPQ_FLAG_ENCRYPTED) != 0 &&
        size >= sizeof(uint32_t)) {
        if (libmpq__reader_get_block_seed(archive, number, block, &seed) < 0 ||
            libmpq__crypto_decrypt_block(buffer, (uint32_t)size, seed) < 0)
            return LIBMPQ_ERROR_DECRYPT;
    }
    return 0;
}

/* Inspect the stored method without a sector-sized buffer or decompression. */
int32_t
libmpq__reader_block_compression(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint32_t *compression
)
{
    libmpq__off_t packed;
    libmpq__off_t unpacked;
    uint32_t flags;
    uint8_t prefix[4];
    size_t prefix_size;
    int32_t status;

    if (compression != NULL)
        *compression = 0;
    if (compression == NULL)
        return LIBMPQ_ERROR_EXIST;
    status = libmpq__reader_block_size_packed(archive, number, block, &packed);
    if (status < 0)
        return status;
    status = libmpq__block_size_unpacked(archive, number, block, &unpacked);
    if (status < 0)
        return status;
    flags = archive->mpq_entry[archive->mpq_map[number].entry_index].flags;
    if (packed >= unpacked ||
        (flags & (LIBMPQ_FLAG_COMPRESS_MULTI | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        return 0;
    if (packed == 0)
        return LIBMPQ_ERROR_FORMAT;
    if ((flags & LIBMPQ_FLAG_COMPRESS_MULTI) == 0) {
        *compression = LIBMPQ_COMPRESSION_PKZIP;
        return 0;
    }
    status = libmpq__reader_offsets_acquire(archive, number, NULL);
    if (status < 0)
        return status;
    prefix_size = (flags & LIBMPQ_FLAG_ENCRYPTED) ? sizeof(prefix) : 1U;
    if (packed < (libmpq__off_t)prefix_size)
        prefix_size = (size_t)packed;
    status = read_packed(archive, number, block, prefix, prefix_size);
    (void)libmpq__reader_offsets_release(archive, number);
    if (status < 0)
        return status;
    *compression = prefix[0];
    return 0;
}

/*
 * Sector checksums follow packed sectors and are not encrypted, even when
 * file data is encrypted. Reuse the offset table loaded by open_named().
 */
static int32_t sector_checksums(mpq_archive_s *archive, uint32_t number, uint32_t **checksums);

int32_t
libmpq__reader_sector_checksums(mpq_archive_s *archive, uint32_t number, uint32_t **checksums)
{
    int32_t result = libmpq__reader_offsets_acquire(archive, number, NULL);
    *checksums = NULL;
    if (result < 0)
        return result;
    result = sector_checksums(archive, number, checksums);
    (void)libmpq__reader_offsets_release(archive, number);
    return result;
}

static int32_t
sector_checksums(mpq_archive_s *archive, uint32_t number, uint32_t **checksums)
{
    uint32_t index = archive->mpq_map[number].entry_index;
    uint32_t flags = archive->mpq_entry[index].flags;
    uint32_t blocks = libmpq__reader_count_file_blocks(archive, number);
    uint32_t start;
    uint32_t end;
    uint32_t packed_size;
    size_t size;
    uint64_t offset;
    uint8_t *packed = NULL;
    uint32_t *table = NULL;
    int32_t status;

    *checksums = NULL;
    if (blocks == 0 || (flags & LIBMPQ_FLAG_CRC) == 0 || (flags & LIBMPQ_FLAG_SINGLE) != 0 ||
        (flags & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        return 0;
    if (archive->mpq_file[number] == NULL ||
        archive->mpq_file[number]->packed_offset_count != blocks + 1)
        return LIBMPQ_ERROR_OPEN;

    /* The existing parser allocates and decodes one extra offset for CRC files. */
    start = archive->mpq_file[number]->packed_offset[blocks];
    end = archive->mpq_file[number]->packed_offset[blocks + 1];
    if (end == 0 || end == start)
        return 0;
    if (end < start || end > archive->mpq_entry[index].packed_size)
        return LIBMPQ_ERROR_FORMAT;
    if ((uint64_t)blocks * sizeof(uint32_t) > INT32_MAX ||
        (uint64_t)blocks * sizeof(uint32_t) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    size = (size_t)blocks * sizeof(uint32_t);
    packed_size = end - start;
    if (packed_size > size)
        return LIBMPQ_ERROR_FORMAT;
    status = libmpq__reader_validate_payload_range(archive, index, start, packed_size);
    if (status < 0)
        return status;
    offset = (uint64_t)archive->archive_offset + archive->mpq_entry[index].offset + start;
    packed = malloc(packed_size);
    table = malloc(size);
    if (packed == NULL || table == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto cleanup;
    }
    status = libmpq__source_read_at(archive->source, offset, packed, packed_size);
    if (status < 0)
        goto cleanup;
    status = libmpq__compression_decompress_block(
        packed, packed_size, (uint8_t *)table, size, LIBMPQ_FLAG_COMPRESS_MULTI,
        archive->mpq_header.version
    );
    if (status < 0 || (uint64_t)status != size) {
        status = LIBMPQ_ERROR_FORMAT;
        goto cleanup;
    }
    libmpq__reader_decode_uint32_table(table, (const uint8_t *)table, blocks);
    *checksums = table;
    table = NULL;
    status = 0;
cleanup:
    free(table);
    free(packed);
    return status;
}

/*
 * Read, decrypt and decompress one block from an opened file entry.
 * The routine computes packed bounds, applies per-block encryption, selects
 * raw or codec output, and reports the exact unpacked byte count.
 */
int32_t libmpq__reader_block_read_acquired(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint8_t *buffer, libmpq__off_t size,
    libmpq__off_t *transferred, const uint32_t *checksum, uint32_t *mismatches, int *lossy
);

int32_t
libmpq__reader_block_read(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint8_t *buffer, libmpq__off_t size,
    libmpq__off_t *transferred, const uint32_t *checksum, uint32_t *mismatches, int *lossy
)
{
    int32_t result;
    if (lossy != NULL)
        *lossy = 0;
    if (libmpq__reader_validate_block_number(archive, number, block) < 0)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__reader_offsets_acquire(archive, number, NULL);
    if (result < 0)
        return result;
    result = libmpq__reader_block_read_acquired(
        archive, number, block, buffer, size, transferred, checksum, mismatches, lossy
    );
    (void)libmpq__reader_offsets_release(archive, number);
    return result;
}

int32_t
libmpq__reader_block_read_acquired(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred, const uint32_t *checksum,
    uint32_t *mismatches, int *lossy
)
{

    /* Packed input buffer, size bookkeeping and block decryption state. */
    uint8_t *in_buf;
    uint32_t flags = 0;
    uint32_t encrypted = 0;
    uint32_t compressed = 0;
    uint32_t imploded = 0;
    int32_t tb = 0;
    uint8_t use_out_buf = 0;
    libmpq__off_t in_size = 0;
    libmpq__off_t unpacked_size = 0;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (libmpq__reader_validate_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    libmpq__block_size_unpacked(mpq_archive, file_number, block_number, &unpacked_size);

    if (unpacked_size > out_size) {
        return LIBMPQ_ERROR_SIZE;
    }

    /*
     * Compute the absolute payload position from archive, file, and block offsets.
     * The stored block offset is relative to the file payload start, not the
     * beginning of the archive file.
     */
    if (mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] <
            mpq_archive->mpq_file[file_number]->packed_offset[block_number] ||
        mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] >
            mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].packed_size) {
        return LIBMPQ_ERROR_FORMAT;
    }
    in_size = mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] -
              mpq_archive->mpq_file[file_number]->packed_offset[block_number];
    if (libmpq__reader_validate_payload_range(
            mpq_archive, mpq_archive->mpq_map[file_number].entry_index,
            mpq_archive->mpq_file[file_number]->packed_offset[block_number], (uint64_t)in_size
        ) < 0) {
        return LIBMPQ_ERROR_READ;
    }

    libmpq__file_flags(mpq_archive, file_number, &flags);
    encrypted = flags & LIBMPQ_FILE_FLAG_ENCRYPTED;
    compressed = flags & LIBMPQ_FILE_FLAG_COMPRESS;
    imploded = flags & LIBMPQ_FILE_FLAG_IMPLODE;

    /* Raw unencrypted blocks can be read directly into the caller's buffer. */
    use_out_buf = !encrypted && !compressed && !imploded && in_size <= out_size;

    if (use_out_buf) {

        /* Raw data can bypass a temporary allocation when no transform is needed. */
        in_buf = out_buf;
    } else {
        if ((in_buf = calloc(1, in_size)) == NULL) {
            return LIBMPQ_ERROR_MALLOC;
        }
    }

    if ((tb = read_packed(mpq_archive, file_number, block_number, in_buf, (size_t)in_size)) < 0) {
        if (!use_out_buf) {
            free(in_buf);
        }
        return tb;
    }

    /*
     * A multi-compression sector only carries a codec mask when it was
     * actually compressed. MPQ WAVE ADPCM is lossy, so its decoded PCM cannot
     * be compared with source-byte (attributes) CRC32/MD5 metadata.
     */
    if (lossy != NULL && compressed && in_size < unpacked_size && in_size != 0 &&
        (in_buf[0] & (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO)) != 0)
        *lossy = 1;

    /*
     * MPQ sector CRCs are Adler-32 over decrypted packed bytes, not CRC32.
     * Zero and all-ones entries are unavailable legacy checksum values.
     */
    if (checksum != NULL && *checksum != 0 && *checksum != UINT32_MAX &&
        (uint32_t)adler32(0, in_buf, (uInt)in_size) != *checksum)
        *mismatches |= LIBMPQ_VERIFY_SECTOR_CRC;

    /* Blizzard multi-compression blocks declare their exact backend chain in the payload. */
    if (compressed) {

        /* The payload's leading mask selects and orders its decompression stages. */
        if ((tb = libmpq__compression_decompress_block(
                 in_buf, in_size, out_buf, unpacked_size, LIBMPQ_FLAG_COMPRESS_MULTI,
                 mpq_archive->mpq_header.version
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    /* PKWARE-imploded blocks use the legacy explode decoder. */
    if (imploded) {

        /* Standalone PKWARE payloads use the legacy decoder without a mask byte. */
        if ((tb = libmpq__compression_decompress_block(
                 in_buf, in_size, out_buf, unpacked_size, LIBMPQ_FLAG_COMPRESS_PKZIP,
                 mpq_archive->mpq_header.version
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    if (compressed && imploded) {
        if (!use_out_buf) {
            free(in_buf);
        }
        return LIBMPQ_ERROR_UNPACK;
    }

    if (!compressed && !imploded) {

        /* A raw block is copied only after encrypted and compressed paths are excluded. */
        if ((tb = libmpq__compression_decompress_block(
                 in_buf, in_size, out_buf, unpacked_size, LIBMPQ_FLAG_COMPRESS_NONE,
                 mpq_archive->mpq_header.version
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    if (!use_out_buf) {
        free(in_buf);
    }

    if (transferred != NULL) {
        *transferred = tb;
    }

    return 0;
}

/*
 * Verify that a file payload subrange is both internally consistent and
 * contained in the physical backing file captured when the archive opened.
 * Sector offsets and block-table sizes are archive-controlled, so this check
 * must happen before using either value for allocation or source reads.
 */
int32_t
libmpq__reader_validate_payload_range(
    const mpq_archive_s *mpq_archive, uint32_t entry_index, uint64_t relative_offset, uint64_t size
)
{
    uint64_t payload_offset;
    uint64_t absolute_offset;

    if (mpq_archive == NULL || mpq_archive->mpq_entry == NULL ||
        entry_index >= mpq_archive->entry_count)
        return LIBMPQ_ERROR_EXIST;
    if (mpq_archive->archive_offset < 0) {
        return LIBMPQ_ERROR_FORMAT;
    }

    payload_offset = mpq_archive->mpq_entry[entry_index].offset;
    if (mpq_archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE) {
        uint64_t extent =
            libmpq__header_archive_size(&mpq_archive->mpq_header, &mpq_archive->mpq_header_v3);

        if (payload_offset > extent || relative_offset > extent - payload_offset ||
            size > extent - payload_offset - relative_offset)
            return LIBMPQ_ERROR_FORMAT;
    }
    absolute_offset = (uint64_t)mpq_archive->archive_offset;
    if (payload_offset > UINT64_MAX - absolute_offset) {
        return LIBMPQ_ERROR_FORMAT;
    }
    absolute_offset += payload_offset;
    if (relative_offset > UINT64_MAX - absolute_offset) {
        return LIBMPQ_ERROR_FORMAT;
    }
    absolute_offset += relative_offset;
    if (absolute_offset > mpq_archive->file_size ||
        size > mpq_archive->file_size - absolute_offset) {
        return LIBMPQ_ERROR_READ;
    }

    return 0;
}

/*
 * Open a file entry and cache its packed block offset table for block operations.
 * Compressed entries load and decrypt their serialized offsets, while raw or
 * single-unit entries receive synthesized offsets from block metadata.
 */
int32_t
libmpq__reader_offsets_acquire(mpq_archive_s *mpq_archive, uint32_t file_number, const char *name)
{

    /* Packed block table state, file seed and read status. */
    uint32_t blocks;
    uint32_t i;
    uint32_t entry_index;
    uint32_t packed_offset_count;
    uint32_t packed_size;
    uint32_t stored_table_size;
    int32_t result = 0;
    uint8_t *packed_data = NULL;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* Sector offsets and codec lengths still require representable 32-bit sizes. */
    if (mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].packed_size >
            UINT32_MAX ||
        mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].unpacked_size >
            UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;

    if (mpq_archive->mpq_file[file_number]) {

        /* A named internal read can supply a key to an anonymous cached open. */
        if (name != NULL && !mpq_archive->mpq_file[file_number]->seed_known) {
            uint32_t index = mpq_archive->mpq_map[file_number].entry_index;
            uint32_t seed = libmpq__crypto_hash_string(name, 0x300);
            if (mpq_archive->mpq_entry[index].flags & 0x00020000u)
                seed = (seed + (uint32_t)mpq_archive->mpq_entry[index].offset) ^
                       (uint32_t)mpq_archive->mpq_entry[index].unpacked_size;
            mpq_archive->mpq_file[file_number]->seed = seed;
            mpq_archive->mpq_file[file_number]->seed_known = 1;
        }

        /* Nested callers share the cached offsets through a reference count. */
        mpq_archive->mpq_file[file_number]->open_count++;
        return 0;
    }

    entry_index = mpq_archive->mpq_map[file_number].entry_index;
    blocks = libmpq__reader_count_file_blocks(mpq_archive, file_number);
    if (blocks > UINT32_MAX / sizeof(uint32_t) - 2U) {
        return LIBMPQ_ERROR_FORMAT;
    }
    packed_offset_count = blocks + 1;
    packed_size = sizeof(uint32_t) * packed_offset_count;

    if ((mpq_archive->mpq_entry[entry_index].flags & LIBMPQ_FLAG_CRC) != 0) {
        packed_size += sizeof(uint32_t);
    }
    stored_table_size = packed_size;

    if ((mpq_archive->mpq_file[file_number] = calloc(1, sizeof(mpq_file_s))) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    if ((mpq_archive->mpq_file[file_number]->packed_offset = calloc(1, packed_size)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    mpq_archive->mpq_file[file_number]->packed_offset_count = packed_offset_count;
    mpq_archive->mpq_file[file_number]->open_count = 1;

    if (name != NULL) {
        uint32_t seed = libmpq__crypto_hash_string(name, 0x300);
        if (mpq_archive->mpq_entry[entry_index].flags & 0x00020000u)
            seed = (seed + (uint32_t)mpq_archive->mpq_entry[entry_index].offset) ^
                   (uint32_t)mpq_archive->mpq_entry[entry_index].unpacked_size;
        mpq_archive->mpq_file[file_number]->seed = seed;
        mpq_archive->mpq_file[file_number]->seed_known = 1;
    }

    /*
     * Compressed multi-sector files carry serialized offsets before their first
     * payload, so load that table before any block can be read.
     */
    if ((mpq_archive->mpq_entry[entry_index].flags &
         (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) != 0 &&
        (mpq_archive->mpq_entry[entry_index].flags & LIBMPQ_FLAG_SINGLE) == 0) {
        if (mpq_archive->mpq_entry[entry_index].packed_size < packed_size ||
            libmpq__reader_validate_payload_range(mpq_archive, entry_index, 0, packed_size) < 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((packed_data = malloc(packed_size)) == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }
        if ((result = libmpq__source_read_at(
                 mpq_archive->source,
                 mpq_archive->mpq_entry[entry_index].offset + (uint64_t)mpq_archive->archive_offset,
                 packed_data, packed_size
             )) < 0) {
            goto error;
        }

        /* WoW MPQs may contain bounded extra DWORDs before the first sector. */
        if ((mpq_archive->mpq_entry[entry_index].flags & LIBMPQ_FLAG_ENCRYPTED) == 0) {
            uint32_t first_offset = libmpq__load_le32(packed_data);

            if (first_offset >= packed_size && first_offset - packed_size <= 0x400u &&
                (first_offset & 3u) == 0 &&
                first_offset <= mpq_archive->mpq_entry[entry_index].packed_size) {
                if (first_offset > packed_size) {
                    uint8_t *expanded = realloc(packed_data, first_offset);

                    if (expanded == NULL) {
                        result = LIBMPQ_ERROR_MALLOC;
                        goto error;
                    }
                    packed_data = expanded;
                    result = libmpq__source_read_at(
                        mpq_archive->source,
                        mpq_archive->mpq_entry[entry_index].offset +
                            (uint64_t)mpq_archive->archive_offset + packed_size,
                        packed_data + packed_size, first_offset - packed_size
                    );
                    if (result != 0)
                        goto error;
                }
                stored_table_size = first_offset;
            } else {

                /* Some protected archives omit the encrypted flag. */
                mpq_archive->mpq_entry[entry_index].flags |= LIBMPQ_FLAG_ENCRYPTED;

                /* Preserve discovered flags for classic rebuilds, when that storage exists. */
                if ((mpq_archive->mpq_entry[entry_index].source_mask &
                     LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0 &&
                    mpq_archive->mpq_entry[entry_index].classic_source_index <
                        mpq_archive->mpq_header.block_table_count &&
                    mpq_archive->mpq_block != NULL)
                    mpq_archive->mpq_block[mpq_archive->mpq_entry[entry_index].classic_source_index]
                        .flags |= LIBMPQ_FLAG_ENCRYPTED;
            }
        }

        /* The packed offset table uses seed - 1, so recover the file seed first. */
        if (mpq_archive->mpq_entry[entry_index].flags & LIBMPQ_FLAG_ENCRYPTED) {
            uint32_t seed = mpq_archive->mpq_file[file_number]->seed;

            if (!mpq_archive->mpq_file[file_number]->seed_known &&
                libmpq__crypto_derive_block_table_seed(
                    packed_data, packed_size, mpq_archive->block_size, &seed
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
            mpq_archive->mpq_file[file_number]->seed = seed;
            mpq_archive->mpq_file[file_number]->seed_known = 1;

            if (libmpq__crypto_decrypt_block(
                    packed_data, packed_size, mpq_archive->mpq_file[file_number]->seed - 1
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }

            /* A valid decrypted table starts with its own byte size. */
            if (libmpq__load_le32(packed_data) != packed_size) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
        }

        libmpq__reader_decode_uint32_table(
            mpq_archive->mpq_file[file_number]->packed_offset, packed_data,
            packed_size / sizeof(uint32_t)
        );
        if (mpq_archive->mpq_file[file_number]->packed_offset[0] != stored_table_size) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        for (i = 1; i < packed_offset_count; i++) {
            if (mpq_archive->mpq_file[file_number]->packed_offset[i] <
                    mpq_archive->mpq_file[file_number]->packed_offset[i - 1] ||
                mpq_archive->mpq_file[file_number]->packed_offset[i] >
                    mpq_archive->mpq_entry[entry_index].packed_size) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }
        }
        free(packed_data);
        packed_data = NULL;
    } else {

        /* Raw sectorized files derive offsets directly from their fixed sector size. */
        if ((mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].flags &
             LIBMPQ_FLAG_SINGLE) == 0) {

            /* Synthesize offsets for uncompressed multi-sector files. */
            for (i = 0; i < packed_offset_count; i++) {
                if (i == blocks) {
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index]
                            .unpacked_size;
                } else {
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        i * mpq_archive->block_size;
                }
            }
        } else {
            mpq_archive->mpq_file[file_number]->packed_offset[0] = 0;
            mpq_archive->mpq_file[file_number]->packed_offset[1] =
                mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].packed_size;
        }
    }

    /*
     * Raw encrypted files have no encrypted offset table from which to derive a seed.
     * The MPQ cipher leaves a trailing partial word unchanged, so an anonymous
     * payload shorter than one word needs no seed and remains readable.
     */
    if ((mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].flags &
         (LIBMPQ_FLAG_ENCRYPTED | LIBMPQ_FLAG_COMPRESSED)) == LIBMPQ_FLAG_ENCRYPTED &&
        !mpq_archive->mpq_file[file_number]->seed_known &&
        mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].packed_size >=
            sizeof(uint32_t)) {
        uint8_t first_block[8];
        uint32_t first_offset;
        uint32_t second_offset;
        uint32_t first_size;
        uint32_t seed;

        if (packed_offset_count < 2) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        first_offset = mpq_archive->mpq_file[file_number]->packed_offset[0];
        second_offset = mpq_archive->mpq_file[file_number]->packed_offset[1];
        if (second_offset < first_offset) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        first_size = second_offset - first_offset;
        if (first_size < sizeof(first_block)) {
            result = LIBMPQ_ERROR_DECRYPT;
            goto error;
        }

        if ((result = libmpq__source_read_at(
                 mpq_archive->source,
                 mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].offset +
                     (uint64_t)mpq_archive->archive_offset,
                 first_block, sizeof(first_block)
             )) < 0) {
            goto error;
        }

        /* Raw encrypted payloads require signature-based key recovery instead. */
        if (libmpq__crypto_detect_file_key(
                first_block, sizeof(first_block),
                mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].unpacked_size,
                &seed
            ) < 0) {
            result = LIBMPQ_ERROR_DECRYPT;
            goto error;
        }

        mpq_archive->mpq_file[file_number]->seed = seed;
        mpq_archive->mpq_file[file_number]->seed_known = 1;
    }

    return 0;

error:

    free(packed_data);

    if (mpq_archive->mpq_file[file_number] != NULL) {
        free(mpq_archive->mpq_file[file_number]->packed_offset);
        free(mpq_archive->mpq_file[file_number]);
        mpq_archive->mpq_file[file_number] = NULL;
    }

    return result;
}

/*
 * Calculate a serialized table size while rejecting arithmetic overflow.
 * MPQ table lengths are stored in 32-bit fields, so both native allocation
 * size and on-disk representation must fit before the caller proceeds.
 */
static int32_t
table_size(uint32_t count, size_t item_size, size_t *size)
{
    if (item_size == 0 || count > SIZE_MAX / item_size || (size_t)count * item_size > UINT32_MAX) {
        return LIBMPQ_ERROR_FORMAT;
    }

    *size = (size_t)count * item_size;
    return 0;
}

/*
 * Decode a packed array of little-endian 32-bit values in place.
 * This is used for sector offset tables whose serialized representation is
 * independent of the host CPU's byte order.
 */
void
libmpq__reader_decode_uint32_table(uint32_t *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        table[i] = libmpq__load_le32(raw + i * sizeof(uint32_t));
    }
}

/*
 * Open an MPQ archive path and prepare decoded metadata for later operations.
 * The routine locates the header, loads and decrypts all metadata tables, and
 * builds the compact file map used by the public archive and block APIs.
 */
static int32_t
libmpq__reader_archive_open_source(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    mpq_source_s *source
)
{

    /* Archive table counters and status used while building the file map. */
    uint32_t i = 0;
    uint32_t count = 0;
    int32_t result = 0;
    uint32_t header_search = 0;
    uint8_t header_data[LIBMPQ_HEADER_WIRE_SIZE];
    uint8_t header_ex_data[LIBMPQ_HEADER_EX_WIRE_SIZE];
    uint8_t header_v3_data[LIBMPQ_HEADER_V3_EX_WIRE_SIZE];
    uint8_t *table_data = NULL;
    size_t table_bytes = 0;

    if (mpq_archive == NULL) {
        libmpq__source_discard(source);
        return LIBMPQ_ERROR_EXIST;
    }
    *mpq_archive = NULL;

    /* A sentinel offset requests the embedded-archive scan used by readers. */
    if (archive_offset == -1) {
        archive_offset = 0;
        header_search = 1;
    } else if (archive_offset < 0) {
        libmpq__source_discard(source);
        return LIBMPQ_ERROR_SEEK;
    }

    if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {
        libmpq__source_discard(source);
        return LIBMPQ_ERROR_MALLOC;
    }

    /* Transfer source ownership before any later archive initialization can fail. */
    (*mpq_archive)->source = source;

    if (mpq_filename != NULL) {
        (*mpq_archive)->filename = malloc(strlen(mpq_filename) + 1);
        if ((*mpq_archive)->filename == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }
        memcpy((*mpq_archive)->filename, mpq_filename, strlen(mpq_filename) + 1);
    }

    (*mpq_archive)->file_identity_valid =
        libmpq__source_file_identity(
            source, &(*mpq_archive)->file_device, &(*mpq_archive)->file_inode
        ) == 0;

    (*mpq_archive)->file_size = libmpq__source_size(source);

    (*mpq_archive)->mpq_header.mpq_magic = 0;
    (*mpq_archive)->files = 0;

    /* Probe the requested location, or advance in 512-byte steps for embedded archives. */
    while (1) {
        (*mpq_archive)->mpq_header.mpq_magic = 0;

        if ((uint64_t)archive_offset > (*mpq_archive)->file_size ||
            sizeof(header_data) > (*mpq_archive)->file_size - (uint64_t)archive_offset) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((result = libmpq__source_read_at(
                 (*mpq_archive)->source, (uint64_t)archive_offset, header_data, sizeof(header_data)
             )) < 0)
            goto error;

        if ((result = libmpq__header_decode(
                 &(*mpq_archive)->mpq_header, header_data, sizeof(header_data)
             )) < 0)
            goto error;

        if ((*mpq_archive)->mpq_header.mpq_magic == LIBMPQ_HEADER) {
            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {

                /* Protected archives may store a bogus header size; normalize it locally. */
                if ((*mpq_archive)->mpq_header.header_size != LIBMPQ_HEADER_WIRE_SIZE) {
                    (*mpq_archive)->mpq_header.header_size = LIBMPQ_HEADER_WIRE_SIZE;
                }
            }

            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
                if ((*mpq_archive)->mpq_header.header_size !=
                    LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE) {
                    (*mpq_archive)->mpq_header.header_size =
                        LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE;
                }
            }

            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE &&
                ((*mpq_archive)->mpq_header.header_size < LIBMPQ_HEADER_WIRE_SIZE ||
                 ((*mpq_archive)->mpq_header.header_size != LIBMPQ_HEADER_WIRE_SIZE &&
                  (*mpq_archive)->mpq_header.header_size <
                      LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE) ||
                 (*mpq_archive)->mpq_header.header_size > LIBMPQ_HEADER_V3_WIRE_SIZE ||
                 (*mpq_archive)->mpq_header.header_size >
                     (*mpq_archive)->file_size - (uint64_t)archive_offset)) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }

            if ((*mpq_archive)->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_THREE) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }

            break;
        }

        if (!header_search) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if (archive_offset > INT64_MAX - 512) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        archive_offset += 512;
    }

    if ((*mpq_archive)->mpq_header.block_size > 22) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }

    (*mpq_archive)->block_size = 512U << (*mpq_archive)->mpq_header.block_size;
    (*mpq_archive)->archive_offset = archive_offset;

    if (table_size(
            (*mpq_archive)->mpq_header.hash_table_count, LIBMPQ_HASH_ENTRY_WIRE_SIZE, &table_bytes
        ) < 0 ||
        (uint64_t)table_bytes > (*mpq_archive)->file_size ||
        table_size(
            (*mpq_archive)->mpq_header.block_table_count, LIBMPQ_BLOCK_ENTRY_WIRE_SIZE, &table_bytes
        ) < 0 ||
        (uint64_t)table_bytes > (*mpq_archive)->file_size) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }

    /* MPQ v2 and v3 store high table offsets immediately after the base header. */
    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO ||
        ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE &&
         (*mpq_archive)->mpq_header.header_size >=
             LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE)) {
        if ((uint64_t)archive_offset > UINT64_MAX - LIBMPQ_HEADER_WIRE_SIZE ||
            (uint64_t)archive_offset + LIBMPQ_HEADER_WIRE_SIZE > (*mpq_archive)->file_size ||
            sizeof(header_ex_data) >
                (*mpq_archive)->file_size - ((uint64_t)archive_offset + LIBMPQ_HEADER_WIRE_SIZE)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((result = libmpq__source_read_at(
                 (*mpq_archive)->source, (uint64_t)archive_offset + LIBMPQ_HEADER_WIRE_SIZE,
                 header_ex_data, sizeof(header_ex_data)
             )) < 0)
            goto error;

        if ((result = libmpq__header_ex_decode(
                 &(*mpq_archive)->mpq_header_ex, header_ex_data, sizeof(header_ex_data)
             )) < 0)
            goto error;
    }

    /* A short v3 header has no v3 extension; its zeroed fields remain absent. */
    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE) {
        if ((*mpq_archive)->mpq_header.header_size == LIBMPQ_HEADER_V3_WIRE_SIZE) {
            result = libmpq__source_read_at(
                source,
                (uint64_t)archive_offset + LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE,
                header_v3_data, sizeof(header_v3_data)
            );
            if (result != 0)
                goto error;
            result = libmpq__header_v3_decode(
                &(*mpq_archive)->mpq_header_v3, header_v3_data, sizeof(header_v3_data)
            );
            if (result != 0)
                goto error;
        }
        result = validate_v3_header(*mpq_archive);
        if (result != 0)
            goto error;
    }

    /* Metadata tables are decoded once and kept with the archive handle for later lookups. */
    if (((*mpq_archive)->mpq_header.block_table_count != 0 &&
         (((*mpq_archive)->mpq_block =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s))) == NULL ||
          ((*mpq_archive)->mpq_block_ex =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s))) ==
              NULL ||
          ((*mpq_archive)->mpq_entry =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_entry_s))) == NULL ||
          ((*mpq_archive)->classic_entry_indices =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(uint32_t))) == NULL)) ||
        ((*mpq_archive)->mpq_header.hash_table_count != 0 &&
         ((*mpq_archive)->mpq_hash =
              calloc((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s))) == NULL)) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    if (table_size(
            (*mpq_archive)->mpq_header.hash_table_count, LIBMPQ_HASH_ENTRY_WIRE_SIZE, &table_bytes
        ) < 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }
    if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* Locate, read, decrypt, and decode the hash table before file lookup begins. */
    if ((result = libmpq__source_read_at(
             (*mpq_archive)->source,
             (*mpq_archive)->mpq_header.hash_table_offset +
                 ((uint64_t)(*mpq_archive)->mpq_header_ex.hash_table_offset_high << 32) +
                 (uint64_t)(*mpq_archive)->archive_offset,
             table_data, table_bytes
         )) < 0) {
        goto error;
    }

    /* MPQ stores the hash table encrypted with the fixed "(hash table)" key. */
    libmpq__crypto_decrypt_block(
        table_data, (uint32_t)table_bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    result = libmpq__hash_table_decode(
        table_data, table_bytes, (*mpq_archive)->mpq_hash,
        (*mpq_archive)->mpq_header.hash_table_count
    );
    if (result < 0)
        goto error;
    free(table_data);
    table_data = NULL;

    if (table_size(
            (*mpq_archive)->mpq_header.block_table_count, LIBMPQ_BLOCK_ENTRY_WIRE_SIZE, &table_bytes
        ) < 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }
    if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* The block table uses the same fixed key pattern as the hash table. */
    if ((result = libmpq__source_read_at(
             (*mpq_archive)->source,
             (*mpq_archive)->mpq_header.block_table_offset +
                 ((uint64_t)(*mpq_archive)->mpq_header_ex.block_table_offset_high << 32) +
                 (uint64_t)(*mpq_archive)->archive_offset,
             table_data, table_bytes
         )) < 0) {
        goto error;
    }

    /* MPQ stores the block table encrypted with the fixed "(block table)" key. */
    libmpq__crypto_decrypt_block(
        table_data, (uint32_t)table_bytes, libmpq__crypto_hash_string("(block table)", 0x300)
    );
    result = libmpq__block_table_decode(
        table_data, table_bytes, (*mpq_archive)->mpq_block,
        (*mpq_archive)->mpq_header.block_table_count
    );
    if (result < 0)
        goto error;
    free(table_data);
    table_data = NULL;

    /* v2 block high words are optional and are loaded only when present. */
    if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {
        if (table_size(
                (*mpq_archive)->mpq_header.block_table_count, LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE,
                &table_bytes
            ) < 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }

        if ((result = libmpq__source_read_at(
                 (*mpq_archive)->source,
                 (*mpq_archive)->mpq_header_ex.extended_offset + (uint64_t)archive_offset,
                 table_data, table_bytes
             )) < 0) {
            if (result == LIBMPQ_ERROR_READ)
                result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        result = libmpq__block_ex_table_decode(
            table_data, table_bytes, (*mpq_archive)->mpq_block_ex,
            (*mpq_archive)->mpq_header.block_table_count
        );
        if (result < 0)
            goto error;
        free(table_data);
        table_data = NULL;
    }

    /* Classic rows retain their indices; only public numbering skips unused entries. */
    (*mpq_archive)->entry_count = (*mpq_archive)->mpq_header.block_table_count;
    for (i = 0; i < (*mpq_archive)->entry_count; ++i) {
        (*mpq_archive)->classic_entry_indices[i] = i;
        libmpq__entry_from_classic(
            &(*mpq_archive)->mpq_entry[i], &(*mpq_archive)->mpq_block[i],
            &(*mpq_archive)->mpq_block_ex[i], i
        );
    }

    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE) {
        uint64_t extent;

        result = load_het_bet(*mpq_archive);
        if (result != 0)
            goto error;
        result = libmpq__archive_signature_extent(*mpq_archive, &extent);
        if (result != 0)
            goto error;
    }

    if ((*mpq_archive)->entry_count != 0) {
        (*mpq_archive)->mpq_map = calloc((*mpq_archive)->entry_count, sizeof(mpq_map_s));
        (*mpq_archive)->mpq_file = calloc((*mpq_archive)->entry_count, sizeof(mpq_file_s *));
        if ((*mpq_archive)->mpq_map == NULL || (*mpq_archive)->mpq_file == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }
    }

    /* Build public numbering from canonical entries, independent of table provenance. */
    for (i = 0; i < (*mpq_archive)->entry_count; i++) {
        if (((*mpq_archive)->mpq_entry[i].flags & LIBMPQ_FLAG_EXISTS) == 0) {
            continue;
        }

        (*mpq_archive)->mpq_map[count].entry_index = i;
        (*mpq_archive)->mpq_entry[i].file_number = count;
        count++;
    }

    (*mpq_archive)->files = count;

    free(table_data);
    return 0;

error:

    /* All partially allocated reader state is released through one failure path. */
    free(table_data);
    if ((*mpq_archive)->source)
        libmpq__source_discard((*mpq_archive)->source);

    free((*mpq_archive)->mpq_map);
    free((*mpq_archive)->mpq_entry);
    free((*mpq_archive)->classic_entry_indices);
    free((*mpq_archive)->bet_entry_indices);
    free((*mpq_archive)->het_data);
    free((*mpq_archive)->bet_data);
    free((*mpq_archive)->mpq_file);
    free((*mpq_archive)->mpq_hash);
    free((*mpq_archive)->mpq_block);
    free((*mpq_archive)->mpq_block_ex);
    free((*mpq_archive)->filename);
    free(*mpq_archive);

    *mpq_archive = NULL;

    return result;
}

int32_t
libmpq__reader_archive_open_path(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{
    mpq_source_s *source = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    result = libmpq__source_open_file(&source, mpq_filename);

    return result == 0 ? libmpq__reader_archive_open_source(
                             mpq_archive, mpq_filename, archive_offset, source
                         )
                       : result;
}

int32_t
libmpq__reader_archive_open_mpqe(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    mpq_source_s *source = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    result = libmpq__source_open_mpqe(&source, mpq_filename, auth_code, auth_code_size);

    return result == 0 ? libmpq__reader_archive_open_source(
                             mpq_archive, mpq_filename, archive_offset, source
                         )
                       : result;
}

int32_t
libmpq__reader_archive_open_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const char *source_name
)
{
    mpq_source_s *source = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    if (read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (source_size < 0)
        return LIBMPQ_ERROR_SIZE;
    if (archive_offset < -1)
        return LIBMPQ_ERROR_SEEK;
    if (archive_offset >= 0 && (uint64_t)archive_offset > (uint64_t)source_size)
        return LIBMPQ_ERROR_SEEK;
    result = libmpq__source_open_io(&source, context, read_at, (uint64_t)source_size);
    return result == 0 ? libmpq__reader_archive_open_source(
                             mpq_archive, source_name, archive_offset, source
                         )
                       : result;
}

int32_t
libmpq__reader_archive_open_mpqe_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const uint8_t *auth_code,
    size_t auth_code_size, const char *source_name
)
{
    mpq_source_s *source = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    if (read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (source_size < 0)
        return LIBMPQ_ERROR_SIZE;
    if (archive_offset < -1)
        return LIBMPQ_ERROR_SEEK;
    if (archive_offset >= 0 && (uint64_t)archive_offset > (uint64_t)source_size)
        return LIBMPQ_ERROR_SEEK;
    result = libmpq__source_open_mpqe_io(
        &source, context, read_at, (uint64_t)source_size, auth_code, auth_code_size
    );
    return result == 0 ? libmpq__reader_archive_open_source(
                             mpq_archive, source_name, archive_offset, source
                         )
                       : result;
}

int32_t
libmpq__reader_archive_clone(mpq_archive_s **clone, const mpq_archive_s *source)
{
    mpq_source_s *clone_source = NULL;
    int32_t result;

    if (clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    *clone = NULL;
    if (source == NULL || source->source == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__source_clone(&clone_source, source->source, source->filename);
    if (result == 0 && source->file_identity_valid) {
        uint64_t device;
        uint64_t inode;

        result = libmpq__source_file_identity(clone_source, &device, &inode);
        if (result == 0 && (device != source->file_device || inode != source->file_inode))
            result = LIBMPQ_ERROR_EXIST;
        if (result != 0)
            libmpq__source_discard(clone_source);
    }

    return result == 0 ? libmpq__reader_archive_open_source(
                             clone, source->filename, source->archive_offset, clone_source
                         )
                       : result;
}

/*
 * Validate that a public file number maps to an extractable archive entry.
 * Public numbering excludes unused entries, so this check protects all later
 * map and canonical-metadata accesses from an invalid compact index.
 */
int32_t
libmpq__reader_validate_file_number(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (mpq_archive == NULL || file_number >= mpq_archive->files || mpq_archive->mpq_map == NULL ||
        mpq_archive->mpq_entry == NULL ||
        mpq_archive->mpq_map[file_number].entry_index >= mpq_archive->entry_count) {
        return LIBMPQ_ERROR_EXIST;
    }

    return 0;
}

/*
 * Return the number of sectors needed to represent a file entry.
 * Single-unit files always have one payload block; sectorized files use the
 * archive block size and round the unpacked length up to a complete sector.
 */
uint32_t
libmpq__reader_count_file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    uint32_t entry_index = mpq_archive->mpq_map[file_number].entry_index;
    uint32_t unpacked_size = (uint32_t)mpq_archive->mpq_entry[entry_index].unpacked_size;

    if ((mpq_archive->mpq_entry[entry_index].flags & LIBMPQ_FLAG_SINGLE) != 0) {
        return 1;
    }

    return (unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
}

/*
 * Validate that a block number exists for the selected file entry.
 * The file's storage mode determines the valid range, including the special
 * one-block case for single-unit entries.
 */
int32_t
libmpq__reader_validate_block_number(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number
)
{
    if (block_number >= libmpq__reader_count_file_blocks(mpq_archive, file_number)) {
        return LIBMPQ_ERROR_EXIST;
    }

    return 0;
}

/*
 * Return the per-block decryption seed derived from the file seed and block number.
 * The helper validates file and block ownership, ensures offset metadata is
 * available, and refuses to guess a key when anonymous decryption failed.
 */
int32_t
libmpq__reader_get_block_seed(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed
)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (libmpq__reader_validate_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (!mpq_archive->mpq_file[file_number]->seed_known) {
        return LIBMPQ_ERROR_DECRYPT;
    }

    *seed = mpq_archive->mpq_file[file_number]->seed + block_number;

    return 0;
}
