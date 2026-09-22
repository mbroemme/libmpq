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
#include "mpq-attributes.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-reader.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Reuse the same table loader and packed/decrypted checksum check as file
 * verification. Do not publish outputs until reading and decoding succeed. */
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
    storage = archive->mpq_block[archive->mpq_map[file_number].block_table_indices].flags;
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
    if (status == LIBMPQ_SUCCESS && transferred != size)
        status = LIBMPQ_ERROR_READ;
cleanup:
    free(buffer);
    free(checksums);
    {
        int32_t close_status = libmpq__reader_offsets_release(archive, file_number);
        if (status == LIBMPQ_SUCCESS)
            status = close_status;
    }
    if (status == LIBMPQ_SUCCESS) {
        *checksum = stored;
        *mismatches = mismatch_mask;
    }
    return status;
}

/* Hash logical blocks through the existing reader without changing extraction.
 * Publish mismatch bits only after the entire verification operation succeeds. */
int32_t
libmpq__verify_file(
    mpq_archive_s *archive, uint32_t file_number, uint32_t verify_flags, uint32_t *mismatches
)
{
    mpq_file_attributes_s attributes;
    mpq_md5_s md5;
    uint8_t digest[16];
    uint8_t *buffer = NULL;
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
        return LIBMPQ_SUCCESS;
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
    storage = archive->mpq_block[archive->mpq_map[file_number].block_table_indices].flags;
    if ((storage & LIBMPQ_FLAG_CRC) == 0 || (storage & LIBMPQ_FLAG_SINGLE) != 0 ||
        (storage & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        verify_flags &= ~LIBMPQ_VERIFY_SECTOR_CRC;
    if (verify_flags == 0)
        return LIBMPQ_SUCCESS;
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
        buffer = malloc(size == 0 ? 1 : (size_t)size);
        if (buffer == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto cleanup;
        }
        status = libmpq__reader_block_read(
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
        free(buffer);
        buffer = NULL;
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
        if (status == LIBMPQ_SUCCESS)
            status = close_status;
    }
    if (status == LIBMPQ_SUCCESS)
        *mismatches = mismatch_mask;
    return status;
}
