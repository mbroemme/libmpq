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
#include "mpq-source.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

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
verify_raw_md5(mpq_archive_s *archive, uint32_t entry_index, uint32_t *mismatches)
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
    return 0;
}

/*
 * Hash requested physical chunks and logical blocks without changing extraction.
 * Publish mismatch bits only after the entire verification operation succeeds.
 */
int32_t
libmpq__verify_file(
    mpq_archive_s *archive, uint32_t file_number, uint32_t verify_flags, uint32_t *mismatches
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
        status = verify_raw_md5(archive, archive->mpq_map[file_number].entry_index, &mismatch_mask);
        if (status != 0)
            return status;
        verify_flags &= ~LIBMPQ_VERIFY_RAW_MD5;
        if (verify_flags == 0) {
            *mismatches = mismatch_mask;
            return 0;
        }
    }
    memset(&attributes, 0, sizeof(attributes));
    if ((verify_flags & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)) != 0) {
        status = libmpq__file_attributes(archive, file_number, &attributes);
        if (status < 0)
            return status;
    }
    if ((attributes.flags & LIBMPQ_ATTRIBUTE_CRC32) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_FILE_CRC32;
    if ((attributes.flags & LIBMPQ_ATTRIBUTE_MD5) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_FILE_MD5;
    storage = archive->mpq_entry[archive->mpq_map[file_number].entry_index].flags;
    if ((storage & LIBMPQ_FLAG_CRC) == 0 || (storage & LIBMPQ_FLAG_SINGLE) != 0 ||
        (storage & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_SECTOR_CRC;
    if (verify_flags == 0) {
        *mismatches = mismatch_mask;
        return 0;
    }
    status = libmpq__file_size_unpacked(archive, file_number, &expected);
    if (status < 0)
        return status;
    status = libmpq__file_blocks(archive, file_number, &blocks);
    if (status < 0)
        return status;
    status = libmpq__reader_offsets_acquire(archive, file_number, NULL);
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
            checksums != NULL ? checksums + i : NULL, &mismatch_mask, NULL
        );
        if (status < 0)
            goto cleanup;
        if (transferred != size) {
            status = LIBMPQ_ERROR_READ;
            goto cleanup;
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
    libmpq__attributes_compare_file(&attributes, verify_flags, crc, digest, &mismatch_mask);
cleanup:
    free(checksums);
    free(buffer);
    {
        int32_t close_status = libmpq__reader_offsets_release(archive, file_number);
        if (status == 0)
            status = close_status;
    }
    if (status == 0)
        *mismatches = mismatch_mask;
    return status;
}
