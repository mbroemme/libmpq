/*
 *  reader.c -- internal archive reader implementation.
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

#include "common.h"
#include "endian.h"
#include "mpq-internal.h"
#include "platform.h"
#include "reader.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Calculate a serialized table size while rejecting arithmetic overflow.
 * MPQ table lengths are stored in 32-bit fields, so both native allocation
 * size and on-disk representation must fit before the caller proceeds. */
static int32_t
table_size(uint32_t count, size_t item_size, size_t *size)
{
    if (item_size == 0 || count > SIZE_MAX / item_size || (size_t)count * item_size > UINT32_MAX) {
        return LIBMPQ_ERROR_FORMAT;
    }

    *size = (size_t)count * item_size;
    return LIBMPQ_SUCCESS;
}

/* Decode the fixed MPQ v1 header from its little-endian byte representation.
 * The helper performs no validation; callers validate version, offsets, and
 * counts after all header fields have been loaded. */
static void
decode_mpq_header(mpq_header_s *header, const uint8_t *raw)
{
    header->mpq_magic = libmpq__load_le32(raw + 0);
    header->header_size = libmpq__load_le32(raw + 4);
    header->archive_size = libmpq__load_le32(raw + 8);
    header->version = libmpq__load_le16(raw + 12);
    header->block_size = libmpq__load_le16(raw + 14);
    header->hash_table_offset = libmpq__load_le32(raw + 16);
    header->block_table_offset = libmpq__load_le32(raw + 20);
    header->hash_table_count = libmpq__load_le32(raw + 24);
    header->block_table_count = libmpq__load_le32(raw + 28);
}

/* Decode the optional MPQ v2 high-offset header extension.
 * Its fields extend table and archive offsets without changing the v1 header
 * layout, so they are loaded separately when the archive version requires it. */
static void
decode_mpq_header_ex(mpq_header_ex_s *header, const uint8_t *raw)
{
    header->extended_offset = libmpq__load_le64(raw + 0);
    header->hash_table_offset_high = libmpq__load_le16(raw + 8);
    header->block_table_offset_high = libmpq__load_le16(raw + 10);
}

/* Decode the encrypted hash-table entries into native archive structures.
 * Each entry is read field-by-field to avoid alignment and host-endian
 * assumptions when the library runs on a different architecture. */
static void
decode_mpq_hash_table(mpq_hash_s *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    if (table == 0 || raw == 0)
        return;
    for (i = 0; i < count; i++) {
        const uint8_t *entry = raw + i * sizeof(mpq_hash_s);

        table[i].hash_a = libmpq__load_le32(entry + 0);
        table[i].hash_b = libmpq__load_le32(entry + 4);
        table[i].locale = libmpq__load_le16(entry + 8);
        table[i].platform = libmpq__load_le16(entry + 10);
        table[i].block_table_index = libmpq__load_le32(entry + 12);
    }
}

/* Decode the fixed-width block table used by MPQ v1 and v2 archives.
 * The high offset words are handled separately by the extended-table helper. */
static void
decode_mpq_block_table(mpq_block_s *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    if (table == 0 || raw == 0)
        return;
    for (i = 0; i < count; i++) {
        const uint8_t *entry = raw + i * sizeof(mpq_block_s);

        table[i].offset = libmpq__load_le32(entry + 0);
        table[i].packed_size = libmpq__load_le32(entry + 4);
        table[i].unpacked_size = libmpq__load_le32(entry + 8);
        table[i].flags = libmpq__load_le32(entry + 12);
    }
}

/* Decode the optional high 16-bit offset table for MPQ v2 block entries.
 * The caller has already positioned the input at the extension table and
 * supplies storage sized for the block-table entry count. */
static void
decode_mpq_block_ex_table(mpq_block_ex_s *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    if (table == 0 || raw == 0)
        return;
    for (i = 0; i < count; i++) {
        table[i].offset_high = libmpq__load_le16(raw + i * sizeof(mpq_block_ex_s));
    }
}

/* Decode a packed array of little-endian 32-bit values in place.
 * This is used for sector offset tables whose serialized representation is
 * independent of the host CPU's byte order. */
void
libmpq__reader_decode_uint32_table(uint32_t *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        table[i] = libmpq__load_le32(raw + i * sizeof(uint32_t));
    }
}

/* Open an MPQ archive path and prepare decoded metadata for later operations.
 * The routine locates the header, loads and decrypts all metadata tables, and
 * builds the compact file map used by the public archive and block APIs. */
int32_t
libmpq__reader_archive_open_path(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{

    /* Archive table counters and status used while building the file map. */
    uint32_t i = 0;
    uint32_t count = 0;
    int32_t result = 0;
    uint32_t header_search = FALSE;
    uint8_t header_data[sizeof(mpq_header_s)];
    uint8_t header_ex_data[sizeof(mpq_header_ex_s)];
    uint8_t *table_data = NULL;
    size_t table_bytes = 0;

    /* A sentinel offset requests the embedded-archive scan used by readers. */
    if (archive_offset == -1) {
        archive_offset = 0;
        header_search = TRUE;
    }

    if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {
        return LIBMPQ_ERROR_MALLOC;
    }

    (*mpq_archive)->filename = malloc(strlen(mpq_filename) + 1);
    if ((*mpq_archive)->filename == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }
    memcpy((*mpq_archive)->filename, mpq_filename, strlen(mpq_filename) + 1);

#if !defined(_WIN32) && !defined(_WIN64)
    {
        struct stat file_status;

        if (stat(mpq_filename, &file_status) == 0) {
            (*mpq_archive)->file_device = (uint64_t)file_status.st_dev;
            (*mpq_archive)->file_inode = (uint64_t)file_status.st_ino;
            (*mpq_archive)->file_identity_valid = TRUE;
        }
    }
#endif

    /* Open the archive file for binary reads. */
    errno = 0;
    if (((*mpq_archive)->fp = fopen(mpq_filename, "rb")) == NULL) {
        result = errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
        goto error;
    }

    (*mpq_archive)->mpq_header.mpq_magic = 0;
    (*mpq_archive)->files = 0;

    /* Probe the requested location, or advance in 512-byte steps for embedded archives. */
    while (TRUE) {
        (*mpq_archive)->mpq_header.mpq_magic = 0;

        if (fseeko((*mpq_archive)->fp, archive_offset, SEEK_SET) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (fread(header_data, 1, sizeof(header_data), (*mpq_archive)->fp) != sizeof(header_data)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        decode_mpq_header(&(*mpq_archive)->mpq_header, header_data);

        if ((*mpq_archive)->mpq_header.mpq_magic == LIBMPQ_HEADER) {
            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {

                /* Protected archives may store a bogus header size; normalize it locally. */
                if ((*mpq_archive)->mpq_header.header_size != sizeof(mpq_header_s)) {
                    (*mpq_archive)->mpq_header.header_size = sizeof(mpq_header_s);
                }
            }

            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
                if ((*mpq_archive)->mpq_header.header_size !=
                    sizeof(mpq_header_s) + sizeof(mpq_header_ex_s)) {
                    (*mpq_archive)->mpq_header.header_size =
                        sizeof(mpq_header_s) + sizeof(mpq_header_ex_s);
                }
            }

            break;
        }

        if (!header_search) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        archive_offset += 512;
    }

    (*mpq_archive)->block_size = 512 << (*mpq_archive)->mpq_header.block_size;
    (*mpq_archive)->archive_offset = archive_offset;

    /* MPQ v2 stores high table offsets in a separate extension immediately after v1. */
    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        if (fseeko((*mpq_archive)->fp, sizeof(mpq_header_s) + archive_offset, SEEK_SET) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (fread(header_ex_data, 1, sizeof(header_ex_data), (*mpq_archive)->fp) !=
            sizeof(header_ex_data)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        decode_mpq_header_ex(&(*mpq_archive)->mpq_header_ex, header_ex_data);
    }

    /* Metadata tables are decoded once and kept with the archive handle for later lookups. */
    if (((*mpq_archive)->mpq_block =
             calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s))) == NULL ||
        ((*mpq_archive)->mpq_block_ex =
             calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s))) ==
            NULL ||
        ((*mpq_archive)->mpq_hash =
             calloc((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s))) == NULL ||
        ((*mpq_archive)->mpq_file =
             calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_file_s *))) == NULL ||
        ((*mpq_archive)->mpq_map =
             calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_map_s))) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    if (table_size((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s), &table_bytes) <
        0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }
    if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* Locate, read, decrypt, and decode the hash table before file lookup begins. */
    if (fseeko(
            (*mpq_archive)->fp,
            (*mpq_archive)->mpq_header.hash_table_offset +
                (((long long)((*mpq_archive)->mpq_header_ex.hash_table_offset_high)) << 32) +
                (*mpq_archive)->archive_offset,
            SEEK_SET
        ) < 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto error;
    }

    if (fread(table_data, 1, table_bytes, (*mpq_archive)->fp) != table_bytes) {
        result = LIBMPQ_ERROR_READ;
        goto error;
    }

    /* MPQ stores the hash table encrypted with the fixed "(hash table)" key. */
    libmpq__common_decrypt_block(
        table_data, (uint32_t)table_bytes, libmpq__common_hash_string("(hash table)", 0x300)
    );
    decode_mpq_hash_table(
        (*mpq_archive)->mpq_hash, table_data, (*mpq_archive)->mpq_header.hash_table_count
    );
    free(table_data);
    table_data = NULL;

    if (table_size(
            (*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s), &table_bytes
        ) < 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }
    if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* The block table uses the same fixed key pattern as the hash table. */
    if (fseeko(
            (*mpq_archive)->fp,
            (*mpq_archive)->mpq_header.block_table_offset +
                (((long long)((*mpq_archive)->mpq_header_ex.block_table_offset_high)) << 32) +
                (*mpq_archive)->archive_offset,
            SEEK_SET
        ) < 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto error;
    }

    if (fread(table_data, 1, table_bytes, (*mpq_archive)->fp) != table_bytes) {
        result = LIBMPQ_ERROR_READ;
        goto error;
    }

    /* MPQ stores the block table encrypted with the fixed "(block table)" key. */
    libmpq__common_decrypt_block(
        table_data, (uint32_t)table_bytes, libmpq__common_hash_string("(block table)", 0x300)
    );
    decode_mpq_block_table(
        (*mpq_archive)->mpq_block, table_data, (*mpq_archive)->mpq_header.block_table_count
    );
    free(table_data);
    table_data = NULL;

    /* v2 block high words are optional and are loaded only when present. */
    if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {
        if (fseeko(
                (*mpq_archive)->fp, (*mpq_archive)->mpq_header_ex.extended_offset + archive_offset,
                SEEK_SET
            ) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (table_size(
                (*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s), &table_bytes
            ) < 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }

        if (fread(table_data, 1, table_bytes, (*mpq_archive)->fp) != table_bytes) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        decode_mpq_block_ex_table(
            (*mpq_archive)->mpq_block_ex, table_data, (*mpq_archive)->mpq_header.block_table_count
        );
        free(table_data);
        table_data = NULL;
    }

    /* Build the compact public file-number map from existing block-table entries. */
    for (i = 0; i < (*mpq_archive)->mpq_header.block_table_count; i++) {
        (*mpq_archive)->mpq_map[i].block_table_diff = i - count;

        if (((*mpq_archive)->mpq_block[i].flags & LIBMPQ_FLAG_EXISTS) == 0) {
            continue;
        }

        (*mpq_archive)->mpq_map[count].block_table_indices = i;
        count++;
    }

    (*mpq_archive)->files = count;

    free(table_data);
    return LIBMPQ_SUCCESS;

error:

    /* All partially allocated reader state is released through one failure path. */
    free(table_data);
    if ((*mpq_archive)->fp)
        fclose((*mpq_archive)->fp);

    free((*mpq_archive)->mpq_map);
    free((*mpq_archive)->mpq_file);
    free((*mpq_archive)->mpq_hash);
    free((*mpq_archive)->mpq_block);
    free((*mpq_archive)->mpq_block_ex);
    free((*mpq_archive)->filename);
    free(*mpq_archive);

    *mpq_archive = NULL;

    return result;
}

/* Validate that a public file number maps to an extractable archive entry.
 * Public numbering excludes unused block-table slots, so this check protects
 * all later map and block-table accesses from an invalid compact index. */
int32_t
libmpq__reader_validate_file_number(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (file_number >= mpq_archive->files) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the number of sectors needed to represent a file entry.
 * Single-unit files always have one payload block; sectorized files use the
 * archive block size and round the unpacked length up to a complete sector. */
uint32_t
libmpq__reader_count_file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    uint32_t block_table_index = mpq_archive->mpq_map[file_number].block_table_indices;
    uint32_t unpacked_size = mpq_archive->mpq_block[block_table_index].unpacked_size;

    if ((mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_SINGLE) != 0) {
        return 1;
    }

    return (unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
}

/* Validate that a block number exists for the selected file entry.
 * The file's storage mode determines the valid range, including the special
 * one-block case for single-unit entries. */
int32_t
libmpq__reader_validate_block_number(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number
)
{
    if (block_number >= libmpq__reader_count_file_blocks(mpq_archive, file_number)) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the per-block decryption seed derived from the file seed and block number.
 * The helper validates file and block ownership, ensures offset metadata is
 * available, and refuses to guess a key when anonymous decryption failed. */
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

    return LIBMPQ_SUCCESS;
}
