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

#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-platform.h"
#include "mpq-reader.h"
#include "mpq-stream.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Verify that a file payload subrange is both internally consistent and
 * contained in the physical backing file captured when the archive opened.
 * Sector offsets and block-table sizes are archive-controlled, so this check
 * must happen before using either value for allocation or stream reads. */
int32_t
libmpq__reader_validate_payload_range(
    const mpq_archive_s *mpq_archive, uint32_t block_table_index, uint64_t relative_offset,
    uint64_t size
)
{
    uint64_t payload_offset;
    uint64_t absolute_offset;

    if (mpq_archive->archive_offset < 0) {
        return LIBMPQ_ERROR_FORMAT;
    }

    payload_offset = ((uint64_t)mpq_archive->mpq_block_ex[block_table_index].offset_high << 32) |
                     mpq_archive->mpq_block[block_table_index].offset;
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

    return LIBMPQ_SUCCESS;
}

/* Open a file entry and cache its packed block offset table for block operations.
 * Compressed entries load and decrypt their serialized offsets, while raw or
 * single-unit entries receive synthesized offsets from block metadata. */
int32_t
libmpq__reader_open_named(mpq_archive_s *mpq_archive, uint32_t file_number, const char *name)
{

    /* Packed block table state, file seed and read status. */
    uint32_t blocks;
    uint32_t i;
    uint32_t block_table_index;
    uint32_t packed_offset_count;
    uint32_t packed_size;
    int32_t result = 0;
    uint8_t *packed_data = NULL;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number]) {

        /* A named internal read can supply a key to an anonymous cached open. */
        if (name != NULL && !mpq_archive->mpq_file[file_number]->seed_known) {
            uint32_t index = mpq_archive->mpq_map[file_number].block_table_indices;
            uint32_t seed = libmpq__crypto_hash_string(name, 0x300);
            if (mpq_archive->mpq_block[index].flags & 0x00020000u)
                seed = (seed + mpq_archive->mpq_block[index].offset) ^
                       mpq_archive->mpq_block[index].unpacked_size;
            mpq_archive->mpq_file[file_number]->seed = seed;
            mpq_archive->mpq_file[file_number]->seed_known = TRUE;
        }

        /* Nested callers share the cached offsets through a reference count. */
        mpq_archive->mpq_file[file_number]->open_count++;
        return LIBMPQ_SUCCESS;
    }

    block_table_index = mpq_archive->mpq_map[file_number].block_table_indices;
    blocks = libmpq__reader_count_file_blocks(mpq_archive, file_number);
    if (blocks > UINT32_MAX / sizeof(uint32_t) - 2U) {
        return LIBMPQ_ERROR_FORMAT;
    }
    packed_offset_count = blocks + 1;
    packed_size = sizeof(uint32_t) * packed_offset_count;

    if ((mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_CRC) != 0) {
        packed_size += sizeof(uint32_t);
    }

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
        if (mpq_archive->mpq_block[block_table_index].flags & 0x00020000u)
            seed = (seed + mpq_archive->mpq_block[block_table_index].offset) ^
                   mpq_archive->mpq_block[block_table_index].unpacked_size;
        mpq_archive->mpq_file[file_number]->seed = seed;
        mpq_archive->mpq_file[file_number]->seed_known = TRUE;
    }

    /* Compressed multi-sector files carry serialized offsets before their first
     * payload, so load that table before any block can be read. */
    if ((mpq_archive->mpq_block[block_table_index].flags &
         (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) != 0 &&
        (mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_SINGLE) == 0) {
        if (mpq_archive->mpq_block[block_table_index].packed_size < packed_size ||
            libmpq__reader_validate_payload_range(mpq_archive, block_table_index, 0, packed_size) <
                0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((packed_data = malloc(packed_size)) == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }
        if ((result = libmpq__stream_read_at(
                 mpq_archive->stream,
                 mpq_archive->mpq_block[block_table_index].offset +
                     ((uint64_t)mpq_archive->mpq_block_ex[block_table_index].offset_high << 32) +
                     (uint64_t)mpq_archive->archive_offset,
                 packed_data, packed_size
             )) < 0) {
            goto error;
        }

        /* Some protected archives omit the encrypted flag; a wrong first offset exposes that. */
        if (libmpq__load_le32(packed_data) != packed_size &&
            libmpq__load_le32(packed_data) != packed_size + 4) {
            mpq_archive->mpq_block[block_table_index].flags |= LIBMPQ_FLAG_ENCRYPTED;
        }

        /* The packed offset table uses seed - 1, so recover the file seed first. */
        if (mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_ENCRYPTED) {
            uint32_t seed = mpq_archive->mpq_file[file_number]->seed;

            if (!mpq_archive->mpq_file[file_number]->seed_known &&
                libmpq__crypto_derive_block_table_seed(
                    packed_data, packed_size, mpq_archive->block_size, &seed
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
            mpq_archive->mpq_file[file_number]->seed = seed;
            mpq_archive->mpq_file[file_number]->seed_known = TRUE;

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
        if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        for (i = 1; i < packed_offset_count; i++) {
            if (mpq_archive->mpq_file[file_number]->packed_offset[i] <
                    mpq_archive->mpq_file[file_number]->packed_offset[i - 1] ||
                mpq_archive->mpq_file[file_number]->packed_offset[i] >
                    mpq_archive->mpq_block[block_table_index].packed_size) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }
        }
        free(packed_data);
        packed_data = NULL;
    } else {

        /* Raw sectorized files derive offsets directly from their fixed sector size. */
        if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
             LIBMPQ_FLAG_SINGLE) == 0) {

            /* Synthesize offsets for uncompressed multi-sector files. */
            for (i = 0; i < packed_offset_count; i++) {
                if (i == blocks) {
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        mpq_archive
                            ->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                            .unpacked_size;
                } else {
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        i * mpq_archive->block_size;
                }
            }
        } else {
            mpq_archive->mpq_file[file_number]->packed_offset[0] = 0;
            mpq_archive->mpq_file[file_number]->packed_offset[1] =
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .packed_size;
        }
    }

    /* Raw encrypted files have no encrypted offset table from which to derive a seed. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         (LIBMPQ_FLAG_ENCRYPTED | LIBMPQ_FLAG_COMPRESSED)) == LIBMPQ_FLAG_ENCRYPTED &&
        !mpq_archive->mpq_file[file_number]->seed_known) {
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

        if ((result = libmpq__stream_read_at(
                 mpq_archive->stream,
                 mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                         .offset +
                     ((uint64_t)mpq_archive
                          ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
                          .offset_high
                      << 32) +
                     (uint64_t)mpq_archive->archive_offset,
                 first_block, sizeof(first_block)
             )) < 0) {
            goto error;
        }

        /* Raw encrypted payloads require signature-based key recovery instead. */
        if (libmpq__crypto_detect_file_key(
                first_block, sizeof(first_block),
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .unpacked_size,
                &seed
            ) < 0) {
            result = LIBMPQ_ERROR_DECRYPT;
            goto error;
        }

        mpq_archive->mpq_file[file_number]->seed = seed;
        mpq_archive->mpq_file[file_number]->seed_known = TRUE;
    }

    return LIBMPQ_SUCCESS;

error:

    free(packed_data);

    if (mpq_archive->mpq_file[file_number] != NULL) {
        free(mpq_archive->mpq_file[file_number]->packed_offset);
        free(mpq_archive->mpq_file[file_number]);
        mpq_archive->mpq_file[file_number] = NULL;
    }

    return result;
}

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
static int32_t
libmpq__reader_archive_open_stream(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    mpq_stream_s *stream
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

    if (mpq_archive == NULL) {
        libmpq__stream_discard(stream);
        return LIBMPQ_ERROR_EXIST;
    }
    *mpq_archive = NULL;

    /* A sentinel offset requests the embedded-archive scan used by readers. */
    if (archive_offset == -1) {
        archive_offset = 0;
        header_search = TRUE;
    } else if (archive_offset < 0) {
        libmpq__stream_discard(stream);
        return LIBMPQ_ERROR_SEEK;
    }

    if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {
        libmpq__stream_discard(stream);
        return LIBMPQ_ERROR_MALLOC;
    }

    /* Transfer stream ownership before any later archive initialization can fail. */
    (*mpq_archive)->stream = stream;

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

    (*mpq_archive)->file_size = libmpq__stream_size(stream);

    (*mpq_archive)->mpq_header.mpq_magic = 0;
    (*mpq_archive)->files = 0;

    /* Probe the requested location, or advance in 512-byte steps for embedded archives. */
    while (TRUE) {
        (*mpq_archive)->mpq_header.mpq_magic = 0;

        if ((uint64_t)archive_offset > (*mpq_archive)->file_size ||
            sizeof(header_data) > (*mpq_archive)->file_size - (uint64_t)archive_offset) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((result = libmpq__stream_read_at(
                 (*mpq_archive)->stream, (uint64_t)archive_offset, header_data, sizeof(header_data)
             )) < 0)
            goto error;

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

            if ((*mpq_archive)->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_TWO) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }

            break;
        }

        if (!header_search) {
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

    if (table_size((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s), &table_bytes) <
            0 ||
        (uint64_t)table_bytes > (*mpq_archive)->file_size ||
        table_size(
            (*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s), &table_bytes
        ) < 0 ||
        (uint64_t)table_bytes > (*mpq_archive)->file_size) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }

    /* MPQ v2 stores high table offsets in a separate extension immediately after v1. */
    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        if ((uint64_t)archive_offset > UINT64_MAX - sizeof(mpq_header_s) ||
            (uint64_t)archive_offset + sizeof(mpq_header_s) > (*mpq_archive)->file_size ||
            sizeof(header_ex_data) >
                (*mpq_archive)->file_size - ((uint64_t)archive_offset + sizeof(mpq_header_s))) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((result = libmpq__stream_read_at(
                 (*mpq_archive)->stream, (uint64_t)archive_offset + sizeof(mpq_header_s),
                 header_ex_data, sizeof(header_ex_data)
             )) < 0)
            goto error;

        decode_mpq_header_ex(&(*mpq_archive)->mpq_header_ex, header_ex_data);
    }

    /* Metadata tables are decoded once and kept with the archive handle for later lookups. */
    if (((*mpq_archive)->mpq_header.block_table_count != 0 &&
         (((*mpq_archive)->mpq_block =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s))) == NULL ||
          ((*mpq_archive)->mpq_block_ex =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s))) ==
              NULL ||
          ((*mpq_archive)->mpq_file =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_file_s *))) ==
              NULL ||
          ((*mpq_archive)->mpq_map =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_map_s))) == NULL)) ||
        ((*mpq_archive)->mpq_header.hash_table_count != 0 &&
         ((*mpq_archive)->mpq_hash =
              calloc((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s))) == NULL)) {
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
    if ((result = libmpq__stream_read_at(
             (*mpq_archive)->stream,
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
    if ((result = libmpq__stream_read_at(
             (*mpq_archive)->stream,
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
    decode_mpq_block_table(
        (*mpq_archive)->mpq_block, table_data, (*mpq_archive)->mpq_header.block_table_count
    );
    free(table_data);
    table_data = NULL;

    /* v2 block high words are optional and are loaded only when present. */
    if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {
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

        if ((result = libmpq__stream_read_at(
                 (*mpq_archive)->stream,
                 (*mpq_archive)->mpq_header_ex.extended_offset + (uint64_t)archive_offset,
                 table_data, table_bytes
             )) < 0) {
            if (result == LIBMPQ_ERROR_READ)
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
    if ((*mpq_archive)->stream)
        libmpq__stream_discard((*mpq_archive)->stream);

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

int32_t
libmpq__reader_archive_open_path(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{
    mpq_stream_s *stream = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    result = libmpq__stream_open_file(&stream, mpq_filename);

    return result == LIBMPQ_SUCCESS ? libmpq__reader_archive_open_stream(
                                          mpq_archive, mpq_filename, archive_offset, stream
                                      )
                                    : result;
}

int32_t
libmpq__reader_archive_open_mpqe(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    mpq_stream_s *stream = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    result = libmpq__stream_open_mpqe(&stream, mpq_filename, auth_code, auth_code_size);

    return result == LIBMPQ_SUCCESS ? libmpq__reader_archive_open_stream(
                                          mpq_archive, mpq_filename, archive_offset, stream
                                      )
                                    : result;
}

int32_t
libmpq__reader_archive_clone(mpq_archive_s **clone, const mpq_archive_s *source)
{
    mpq_stream_s *stream = NULL;
    int32_t result;

    if (clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    *clone = NULL;
    if (source == NULL || source->stream == NULL || source->filename == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__stream_clone(&stream, source->stream, source->filename);

    return result == LIBMPQ_SUCCESS ? libmpq__reader_archive_open_stream(
                                          clone, source->filename, source->archive_offset, stream
                                      )
                                    : result;
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
