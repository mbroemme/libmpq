/*
 *  mpq-verify.c -- explicit file checksum verification.
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

#include "mpq-verify.h"
#include "mpq-archive.h"
#include "mpq-attributes.h"
#include "mpq-block.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "mpq-signature.h"
#include "mpq-source.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Sort only the copied layout; canonical rows and hash/probe identities stay unchanged. */
static int
raw_interval_compare(const void *left, const void *right)
{
    const mpq_raw_interval_s *a = left;
    const mpq_raw_interval_s *b = right;

    return a->start < b->start ? -1 : a->start > b->start;
}

/* Zero-sized and unused records reserve no storage; all sums are checked. */
static int32_t
raw_interval_add(struct mpq_raw_index *index, uint64_t start, uint64_t length)
{
    mpq_raw_interval_s *interval;

    if (length == 0)
        return 0;
    if (length > UINT64_MAX - start)
        return LIBMPQ_ERROR_FORMAT;
    interval = &index->intervals[index->count++];
    interval->start = start;
    interval->end = start + length;
    interval->maximum = 0;
    return 0;
}

/* Publish only a complete index. Failed allocation/build leaves the reader retryable. */
static int32_t
raw_index_prepare(mpq_archive_s *archive, void *(*allocate)(size_t))
{
    struct mpq_raw_index *index;
    uint64_t capacity;
    uint64_t positions[6];
    uint64_t sizes[6];
    uint64_t maximum = 0;
    int32_t status = 0;

    if (archive == NULL || allocate == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (archive->raw_index != NULL)
        return 0;
    capacity = (uint64_t)archive->entry_count + 6;
    if (capacity > (SIZE_MAX - sizeof(*index)) / sizeof(mpq_raw_interval_s))
        return LIBMPQ_ERROR_SIZE;
    index = allocate(sizeof(*index) + (size_t)capacity * sizeof(mpq_raw_interval_s));
    if (index == NULL)
        return LIBMPQ_ERROR_MALLOC;
    index->references = 1;
    index->count = 0;
    positions[0] = 0;
    positions[1] = archive->mpq_header.hash_table_offset |
                   ((uint64_t)archive->mpq_header_ex.hash_table_offset_high << 32);
    positions[2] = archive->mpq_header.block_table_offset |
                   ((uint64_t)archive->mpq_header_ex.block_table_offset_high << 32);
    positions[3] = archive->mpq_header_ex.extended_offset;
    positions[4] = archive->mpq_header_v3.het_table_offset;
    positions[5] = archive->mpq_header_v3.bet_table_offset;
    sizes[0] = archive->mpq_header.header_size;
    sizes[1] = archive->mpq_header_v4.hash_table_size;
    sizes[2] = archive->mpq_header_v4.block_table_size;
    sizes[3] = archive->mpq_header_v4.hi_block_table_size;
    sizes[4] = archive->mpq_header_v4.het_table_size;
    sizes[5] = archive->mpq_header_v4.bet_table_size;
    for (size_t i = 0; status == 0 && i < 6; ++i)
        status = raw_interval_add(index, positions[i], sizes[i]);
    for (uint32_t i = 0; status == 0 && i < archive->entry_count; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[i];

        if ((entry->flags & LIBMPQ_FLAG_EXISTS) != 0)
            status = raw_interval_add(index, entry->offset, entry->packed_size);
    }
    if (status != 0) {
        free(index);
        return status;
    }
    qsort(index->intervals, index->count, sizeof(mpq_raw_interval_s), raw_interval_compare);
    for (size_t i = 0; i < index->count; ++i) {
        if (index->intervals[i].end > maximum)
            maximum = index->intervals[i].end;
        index->intervals[i].maximum = maximum;
    }
    archive->raw_index = index;
    return 0;
}

/* Share immutable ranges only after normal clone opening and source identity checks. */
int32_t
libmpq__raw_index_share(mpq_archive_s *destination, const mpq_archive_s *source)
{
    if (source->raw_index == NULL)
        return 0;
    if (source->raw_index->references == SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    source->raw_index->references++;
    destination->raw_index = source->raw_index;
    return 0;
}

/* A clone may outlive its parent; the final owner frees the copied ranges. */
void
libmpq__raw_index_release(mpq_archive_s *archive)
{
    struct mpq_raw_index *index = archive->raw_index;

    archive->raw_index = NULL;
    if (index != NULL && --index->references == 0)
        free(index);
}

/* Find all starts below end; their prefix maximum detects any intersecting range. */
static int
raw_index_overlap(const struct mpq_raw_index *index, uint64_t start, uint64_t end)
{
    size_t low = 0;
    size_t high = index->count;

    while (low < high) {
        size_t middle = low + (high - low) / 2;

        if (index->intervals[middle].start < end)
            low = middle + 1;
        else
            high = middle;
    }
    return low != 0 && index->intervals[low - 1].maximum > start;
}

/*
 * Reuse the same table loader and packed/decrypted checksum check as file
 * verification. Do not publish outputs until reading and decoding succeed.
 */
int32_t
libmpq__verify_block(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint32_t *checksum,
    uint32_t *mismatches
)
{
    uint32_t *checksums = NULL;
    uint8_t *buffer = NULL;
    uint32_t mismatch_mask = 0;
    uint32_t stored = 0;
    uint32_t storage;
    libmpq__off_t size = 0;
    libmpq__off_t transferred = 0;
    int32_t status;

    if (checksum != NULL)
        *checksum = 0;
    if (mismatches != NULL)
        *mismatches = 0;
    if (archive == NULL || checksum == NULL || mismatches == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (libmpq__reader_validate_file_number(archive, file_number) < 0 ||
        libmpq__reader_validate_block_number(archive, file_number, block_number) < 0)
        return LIBMPQ_ERROR_EXIST;
    storage = archive->mpq_entry[archive->mpq_map[file_number].entry_index].flags;
    if ((storage & LIBMPQ_FLAG_CRC) == 0 || (storage & LIBMPQ_FLAG_SINGLE) != 0 ||
        (storage & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        return LIBMPQ_ERROR_EXIST;
    status = libmpq__reader_offsets_acquire(archive, file_number, NULL);
    if (status < 0)
        return status;
    status = libmpq__reader_sector_checksums(archive, file_number, &checksums);
    if (status < 0)
        goto cleanup;
    if (checksums == NULL || checksums[block_number] == 0 ||
        checksums[block_number] == UINT32_MAX) {
        status = LIBMPQ_ERROR_EXIST;
        goto cleanup;
    }
    stored = checksums[block_number];
    status = libmpq__block_size_unpacked(archive, file_number, block_number, &size);
    if (status < 0)
        goto cleanup;
    if (size < 0 || (uint64_t)size > SIZE_MAX || (uint64_t)size > UINT_MAX) {
        status = LIBMPQ_ERROR_SIZE;
        goto cleanup;
    }
    buffer = malloc(size == 0 ? 1 : (size_t)size);
    if (buffer == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto cleanup;
    }
    status = libmpq__reader_block_read(
        archive, file_number, block_number, buffer, size, &transferred, &stored, &mismatch_mask,
        NULL
    );
    if (status == 0 && transferred != size)
        status = LIBMPQ_ERROR_READ;
cleanup:
    free(buffer);
    free(checksums);
    {
        int32_t close_status = libmpq__reader_offsets_release(archive, file_number);
        if (status == 0)
            status = close_status;
    }
    if (status == 0) {
        *checksum = stored;
        *mismatches = mismatch_mask;
    }
    return status;
}

/* Verify raw chunks with fixed memory, independent of file encryption or codecs. */
static int32_t
verify_raw_md5(
    mpq_archive_s *archive, uint32_t entry_index, uint32_t *mismatches, uint32_t *checked,
    void *(*allocate)(size_t)
)
{
    const mpq_entry_s *entry = &archive->mpq_entry[entry_index];
    uint32_t chunk_size = archive->mpq_header_v4.raw_chunk_size;
    uint64_t chunks;
    uint64_t digest_size;
    uint64_t extent;
    uint64_t base;
    uint64_t position;
    uint64_t digest_position;
    uint64_t remaining = entry->packed_size;
    uint8_t buffer[16384];
    uint8_t actual[LIBMPQ_MD5_SIZE];
    uint8_t expected[LIBMPQ_MD5_SIZE];
    mpq_md5_s md5;
    int32_t status;
    if (archive->mpq_header.version != LIBMPQ_ARCHIVE_VERSION_FOUR || chunk_size == 0 ||
        remaining == 0 || (entry->flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0)
        return 0;
    status = libmpq__reader_validate_payload_range(archive, entry_index, 0, remaining);
    if (status != 0)
        return status;
    chunks = (remaining - 1) / chunk_size + 1;
    if (chunks > UINT64_MAX / LIBMPQ_MD5_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    digest_size = chunks * LIBMPQ_MD5_SIZE;
    extent = libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    base = (uint64_t)archive->archive_offset;

    /* Payload validation bounds the sum; the trailing digest array is separate. */
    position = entry->offset;
    digest_position = position + remaining;
    if (digest_size > extent - digest_position || base > (uint64_t)INT64_MAX ||
        digest_position > (uint64_t)INT64_MAX - base ||
        digest_size > (uint64_t)INT64_MAX - base - digest_position)
        return LIBMPQ_ERROR_FORMAT;
    if (base > archive->file_size || digest_position > archive->file_size - base ||
        digest_size > archive->file_size - base - digest_position)
        return LIBMPQ_ERROR_READ;
    if (checked != NULL) {
        status = raw_index_prepare(archive, allocate);
        if (status != 0)
            return status;
        if (raw_index_overlap(archive->raw_index, digest_position, digest_position + digest_size))
            return LIBMPQ_ERROR_FORMAT;
    }
    position += base;
    digest_position += base;
    while (remaining != 0) {
        uint64_t in_chunk = remaining < chunk_size ? remaining : chunk_size;
        remaining -= in_chunk;
        libmpq__md5_init(&md5);
        while (in_chunk != 0) {
            size_t take = in_chunk < sizeof(buffer) ? (size_t)in_chunk : sizeof(buffer);
            status = libmpq__source_read_at(archive->source, position, buffer, take);
            if (status != 0)
                return status;
            libmpq__md5_update(&md5, buffer, take);
            position += take;
            in_chunk -= take;
        }
        libmpq__md5_final(&md5, actual);
        status =
            libmpq__source_read_at(archive->source, digest_position, expected, sizeof(expected));
        if (status != 0)
            return status;
        if (memcmp(actual, expected, sizeof(actual)) != 0)
            *mismatches |= LIBMPQ_VERIFY_RAW_MD5;
        digest_position += sizeof(expected);
    }
    if (checked != NULL)
        *checked |= LIBMPQ_VERIFY_RAW_MD5;
    return 0;
}

/*
 * Hash requested physical chunks and logical blocks without changing extraction.
 * Publish mismatch bits only after the entire verification operation succeeds.
 */
static int32_t
verify_file(
    mpq_archive_s *archive, uint32_t file_number, const char *filename, uint32_t verify_flags,
    uint32_t *checked, uint32_t *unavailable, uint32_t *mismatches, void *(*allocate)(size_t)
)
{
    mpq_file_attributes_s attributes;
    mpq_md5_s md5;
    uint8_t digest[16];
    uint8_t *buffer = NULL;
    size_t buffer_capacity = 0;
    uint32_t *checksums = NULL;
    uint32_t crc = 0;
    uint32_t blocks = 0;
    uint32_t i;
    uint32_t mismatch_mask = 0;
    uint32_t checked_mask = 0;
    uint32_t requested = verify_flags;
    uint32_t sector_missing = 0;
    uint32_t lossy = 0;
    int extended = checked != NULL;
    uint32_t storage;
    libmpq__off_t expected = 0;
    libmpq__off_t total = 0;
    int32_t status;

    if (mismatches != NULL)
        *mismatches = 0;
    if (archive == NULL || mismatches == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (libmpq__reader_validate_file_number(archive, file_number) < 0)
        return LIBMPQ_ERROR_EXIST;
    if ((verify_flags & ~LIBMPQ_VERIFY_ALL) != 0)
        return LIBMPQ_ERROR_FORMAT;
    if (verify_flags == 0)
        return 0;
    if ((verify_flags & LIBMPQ_VERIFY_RAW_MD5) != 0) {
        status = verify_raw_md5(
            archive, archive->mpq_map[file_number].entry_index, &mismatch_mask,
            extended ? &checked_mask : NULL, allocate
        );
        if (status != 0)
            return status;
        verify_flags &= ~LIBMPQ_VERIFY_RAW_MD5;
        if (verify_flags == 0) {
            goto publish;
        }
    }
    memset(&attributes, 0, sizeof(attributes));
    if ((verify_flags & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)) != 0) {
        if (extended) {
            const mpq_entry_s *entry =
                &archive->mpq_entry[archive->mpq_map[file_number].entry_index];

            status = libmpq__attributes_load(archive);
            if (status != 0 && status != LIBMPQ_ERROR_EXIST)
                return status;
            if (status == 0 && (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0) {
                uint32_t signature_number;
                uint32_t signatures;

                status = libmpq__file_attributes(archive, file_number, &attributes);
                if (status != 0)
                    return status;

                /* Only recognized circular zero placeholders, never arbitrary CRC zero. */
                if (attributes.crc32 == 0 &&
                    (entry->classic_source_index == archive->attributes->self ||
                     (libmpq__file_number(archive, LIBMPQ_SIGNATURE_NAME, &signature_number) == 0 &&
                      signature_number == file_number &&
                      libmpq__signature_detect(archive, &signatures) == 0 &&
                      (signatures & LIBMPQ_SIGNATURE_WEAK) != 0)))
                    attributes.flags &= ~LIBMPQ_ATTRIBUTE_CRC32;
            }
        } else {
            status = libmpq__file_attributes(archive, file_number, &attributes);
            if (status < 0)
                return status;
        }
    }
    if ((attributes.flags & LIBMPQ_ATTRIBUTE_CRC32) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_FILE_CRC32;
    if ((attributes.flags & LIBMPQ_ATTRIBUTE_MD5) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_FILE_MD5;
    storage = archive->mpq_entry[archive->mpq_map[file_number].entry_index].flags;
    if ((storage & LIBMPQ_FLAG_CRC) == 0 || (storage & LIBMPQ_FLAG_SINGLE) != 0 ||
        (storage & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_SECTOR_CRC;
    if (verify_flags == 0)
        goto publish;
    status = libmpq__file_size_unpacked(archive, file_number, &expected);
    if (status < 0)
        return status;
    status = libmpq__file_blocks(archive, file_number, &blocks);
    if (status < 0)
        return status;
    status = libmpq__reader_offsets_acquire(archive, file_number, filename);
    if (status < 0)
        return status;
    if ((verify_flags & LIBMPQ_VERIFY_SECTOR_CRC) != 0) {
        status = libmpq__reader_sector_checksums(archive, file_number, &checksums);
        if (status < 0)
            goto cleanup;
    }
    if (checksums == NULL &&
        (verify_flags & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)) == 0)
        goto cleanup;
    if ((verify_flags & LIBMPQ_VERIFY_FILE_MD5) != 0)
        libmpq__md5_init(&md5);
    for (i = 0; i < blocks; ++i) {
        libmpq__off_t size = 0;
        libmpq__off_t transferred = 0;
        int block_lossy = 0;
        status = libmpq__block_size_unpacked(archive, file_number, i, &size);
        if (status < 0)
            goto cleanup;
        if (size < 0 || (uint64_t)size > SIZE_MAX || (uint64_t)size > UINT_MAX ||
            size > expected - total) {
            status = LIBMPQ_ERROR_SIZE;
            goto cleanup;
        }

        /* The operation owns one decoded-sector buffer and already holds offsets. */
        if ((size_t)size > buffer_capacity || buffer == NULL) {
            size_t needed = size == 0 ? 1 : (size_t)size;
            uint8_t *resized = realloc(buffer, needed);

            if (resized == NULL) {
                status = LIBMPQ_ERROR_MALLOC;
                goto cleanup;
            }
            buffer = resized;
            buffer_capacity = needed;
        }
        status = libmpq__reader_block_read_acquired(
            archive, file_number, i, buffer, size, &transferred,
            checksums != NULL ? checksums + i : NULL, &mismatch_mask, extended ? &block_lossy : NULL
        );
        if (status < 0)
            goto cleanup;
        if (transferred != size) {
            status = LIBMPQ_ERROR_READ;
            goto cleanup;
        }
        lossy |= block_lossy != 0;
        if ((verify_flags & LIBMPQ_VERIFY_SECTOR_CRC) != 0) {
            if (checksums != NULL && checksums[i] != 0 && checksums[i] != UINT32_MAX)
                checked_mask |= LIBMPQ_VERIFY_SECTOR_CRC;
            else
                sector_missing = LIBMPQ_VERIFY_SECTOR_CRC;
        }
        if ((verify_flags & LIBMPQ_VERIFY_FILE_CRC32) != 0)
            crc = (uint32_t)crc32(crc, buffer, (uInt)size);
        if ((verify_flags & LIBMPQ_VERIFY_FILE_MD5) != 0)
            libmpq__md5_update(&md5, buffer, (size_t)size);
        total += size;
    }
    if (total != expected) {
        status = LIBMPQ_ERROR_READ;
        goto cleanup;
    }
    if ((verify_flags & LIBMPQ_VERIFY_FILE_MD5) != 0) {
        libmpq__md5_final(&md5, digest);
    }

    /* Attributes carry no decoded-byte provenance for lossy ADPCM output. */
    if (extended && lossy)
        verify_flags &= ~(LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5);
    checked_mask |= verify_flags & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5);
    libmpq__attributes_compare_file(&attributes, verify_flags, crc, digest, &mismatch_mask);
cleanup:
    free(checksums);
    free(buffer);
    {
        int32_t close_status = libmpq__reader_offsets_release(archive, file_number);
        if (status == 0)
            status = close_status;
    }
    if (status != 0)
        return status;
publish:
    if (extended) {
        *checked = checked_mask;
        *unavailable = (requested & ~checked_mask) | sector_missing;
    }
    *mismatches = mismatch_mask;
    return 0;
}

/* Keep the published mismatch-only contract, including literal lossy comparisons. */
int32_t
libmpq__verify_file(
    mpq_archive_s *archive, uint32_t file_number, uint32_t flags, uint32_t *mismatches
)
{
    return verify_file(archive, file_number, NULL, flags, NULL, NULL, mismatches, NULL);
}

/* Isolate caller key context and its cache from the parent archive. */
int32_t
libmpq__verify_file_ex(
    mpq_archive_s *archive, uint32_t file_number, const char *filename, uint32_t flags,
    uint32_t *checked, uint32_t *unavailable, uint32_t *mismatches, void *(*allocate)(size_t)
)
{
    mpq_archive_s *clone = NULL;
    int32_t status;

    if (checked != NULL)
        *checked = 0;
    if (unavailable != NULL)
        *unavailable = 0;
    if (mismatches != NULL)
        *mismatches = 0;
    if (archive == NULL || checked == NULL || unavailable == NULL || mismatches == NULL ||
        allocate == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (libmpq__reader_validate_file_number(archive, file_number) != 0)
        return LIBMPQ_ERROR_EXIST;
    if ((flags & ~LIBMPQ_VERIFY_ALL) != 0)
        return LIBMPQ_ERROR_FORMAT;
    if (flags == 0)
        return 0;
    if (filename != NULL) {
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[file_number].entry_index];

        if (*filename == '\0')
            return LIBMPQ_ERROR_EXIST;

        /* Full stored identities can disprove a hint without reselecting a member. */
        if ((archive->het_data == NULL &&
             (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0) ||
            (archive->het_data != NULL && archive->mpq_het.header.name_hash_bit_size == 64 &&
             archive->mpq_bet.header.name_hash2_size == 56)) {
            mpq_file_identity_s identity;
            uint32_t ordinal = 0;

            do {
                status = libmpq__file_identity(archive, filename, ordinal++, &identity);
                if (status != 0)
                    return status;
            } while (identity.file_number != file_number);
        }
        if ((flags & LIBMPQ_VERIFY_RAW_MD5) != 0 &&
            archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR &&
            archive->mpq_header_v4.raw_chunk_size != 0 && entry->packed_size != 0 &&
            (entry->flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) == 0) {
            status = raw_index_prepare(archive, allocate);
            if (status != 0)
                return status;
        }
        status = libmpq__reader_archive_clone(&clone, archive);
        if (status != 0)
            return status;
    }
    status = verify_file(
        clone != NULL ? clone : archive, file_number, filename, flags, checked, unavailable,
        mismatches, allocate
    );
    if (clone != NULL) {
        int32_t close_status = libmpq__archive_close(clone);
        if (status == 0)
            status = close_status;
    }
    if (status != 0) {
        *checked = 0;
        *unavailable = 0;
        *mismatches = 0;
    }
    return status;
}
