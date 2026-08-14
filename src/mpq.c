/*
 *  mpq.c -- public archive, file and block operations.
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
#include "mpq-internal.h"
#include "platform.h"
#include <libmpq/mpq.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Error strings indexed by the negated libmpq error code. */
static const char *libmpq_error_strings[] = { "success",
                                              "open error on file",
                                              "close error on file",
                                              "lseek error on file",
                                              "read error on file",
                                              "write error on file",
                                              "memory allocation error",
                                              "format error",
                                              "init() wasn't called",
                                              "buffer size is too small",
                                              "archive, file, or block does not exist",
                                              "we don't know the decryption seed",
                                              "error on unpacking file" };

/* Return the configured libmpq package version. */
const char *
libmpq__version(void)
{
    return VERSION;
}

/* Translate a libmpq return code into a static diagnostic string. */
const char *
libmpq__strerror(int32_t return_code)
{

    /* Only negative libmpq error codes and zero are valid table indexes. */
    if (-return_code < 0 ||
        (size_t)-return_code >= sizeof(libmpq_error_strings) / sizeof(libmpq_error_strings[0]))
        return NULL;

    /* Return the static string owned by the library. */
    return libmpq_error_strings[-return_code];
}

/* Open an MPQ archive and prepare decoded metadata for later file and block operations. */
int32_t
libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{

    /* Archive table counters and status used while building the file map. */
    uint32_t i = 0;
    uint32_t count = 0;
    int32_t result = 0;
    uint32_t header_search = FALSE;

    if (archive_offset == -1) {
        archive_offset = 0;
        header_search = TRUE;
    }

    if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {
        return LIBMPQ_ERROR_MALLOC;
    }

    /* Open the archive file for binary reads. */
    errno = 0;
    if (((*mpq_archive)->fp = fopen(mpq_filename, "rb")) == NULL) {
        result = errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
        goto error;
    }

    (*mpq_archive)->mpq_header.mpq_magic = 0;
    (*mpq_archive)->files = 0;

    /* Without an explicit offset, scan every 512 bytes for an embedded MPQ header. */
    while (TRUE) {
        (*mpq_archive)->mpq_header.mpq_magic = 0;

        if (fseeko((*mpq_archive)->fp, archive_offset, SEEK_SET) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (fread(&(*mpq_archive)->mpq_header, 1, sizeof(mpq_header_s), (*mpq_archive)->fp) !=
            sizeof(mpq_header_s)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

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

    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        if (fseeko((*mpq_archive)->fp, sizeof(mpq_header_s) + archive_offset, SEEK_SET) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (fread(&(*mpq_archive)->mpq_header_ex, 1, sizeof(mpq_header_ex_s), (*mpq_archive)->fp) !=
            sizeof(mpq_header_ex_s)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
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

    if (fread(
            (*mpq_archive)->mpq_hash, 1,
            (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s), (*mpq_archive)->fp
        ) != (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s)) {
        result = LIBMPQ_ERROR_READ;
        goto error;
    }

    /* MPQ stores the hash table encrypted with the fixed "(hash table)" key. */
    libmpq__decrypt_block(
        (uint32_t *)((*mpq_archive)->mpq_hash),
        (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s),
        libmpq__hash_string("(hash table)", 0x300)
    );

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

    if (fread(
            (*mpq_archive)->mpq_block, 1,
            (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s), (*mpq_archive)->fp
        ) != (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s)) {
        result = LIBMPQ_ERROR_READ;
        goto error;
    }

    /* MPQ stores the block table encrypted with the fixed "(block table)" key. */
    libmpq__decrypt_block(
        (uint32_t *)((*mpq_archive)->mpq_block),
        (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s),
        libmpq__hash_string("(block table)", 0x300)
    );

    /* Extended block tables are optional and only needed when payload offsets exceed 4 GiB. */
    if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {
        if (fseeko(
                (*mpq_archive)->fp, (*mpq_archive)->mpq_header_ex.extended_offset + archive_offset,
                SEEK_SET
            ) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (fread(
                (*mpq_archive)->mpq_block_ex, 1,
                (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_ex_s),
                (*mpq_archive)->fp
            ) != (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_ex_s)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
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

    return LIBMPQ_SUCCESS;

error:
    if ((*mpq_archive)->fp)
        fclose((*mpq_archive)->fp);

    free((*mpq_archive)->mpq_map);
    free((*mpq_archive)->mpq_file);
    free((*mpq_archive)->mpq_hash);
    free((*mpq_archive)->mpq_block);
    free((*mpq_archive)->mpq_block_ex);
    free(*mpq_archive);

    *mpq_archive = NULL;

    return result;
}

/* Close the archive file and release all metadata tables allocated during archive open. */
int32_t
libmpq__archive_close(mpq_archive_s *mpq_archive)
{
    if ((fclose(mpq_archive->fp)) < 0) {

        /* Keep the handle intact so the caller may retry closing it. */
        return LIBMPQ_ERROR_CLOSE;
    }

    free(mpq_archive->mpq_map);
    free(mpq_archive->mpq_file);
    free(mpq_archive->mpq_hash);
    free(mpq_archive->mpq_block);
    free(mpq_archive->mpq_block_ex);
    free(mpq_archive);

    return LIBMPQ_SUCCESS;
}

/* Return the sum of packed sizes for all files in the archive block table. */
int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size)
{

    /* Running total across all block-table entries. */
    uint32_t i;

    for (i = 0; i < mpq_archive->files; i++) {
        *packed_size +=
            mpq_archive->mpq_block[mpq_archive->mpq_map[i].block_table_indices].packed_size;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the sum of unpacked sizes for all files in the archive block table. */
int32_t
libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, libmpq__off_t *unpacked_size)
{

    /* Running total across all block-table entries. */
    uint32_t i;

    for (i = 0; i < mpq_archive->files; i++) {
        *unpacked_size +=
            mpq_archive->mpq_block[mpq_archive->mpq_map[i].block_table_indices].unpacked_size;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the byte offset where the MPQ archive starts in the backing file. */
int32_t
libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset)
{
    *offset = mpq_archive->archive_offset;

    return LIBMPQ_SUCCESS;
}

/* Return the MPQ archive format version stored in the header. */
int32_t
libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version)
{
    *version = mpq_archive->mpq_header.version + 1;

    return LIBMPQ_SUCCESS;
}

/* Return the number of valid file entries discovered while opening the archive. */
int32_t
libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files)
{
    *files = mpq_archive->files;

    return LIBMPQ_SUCCESS;
}

/* Validate that a public file number maps to an extractable archive entry. */
static int32_t
validate_file_number(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (file_number >= mpq_archive->files) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the number of sectors needed to represent a file entry. */
static uint32_t
count_file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    uint32_t block_table_index = mpq_archive->mpq_map[file_number].block_table_indices;
    uint32_t unpacked_size = mpq_archive->mpq_block[block_table_index].unpacked_size;

    if ((mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_SINGLE) != 0) {
        return 1;
    }

    return (unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
}

/* Validate that a block number exists for the selected file entry. */
static int32_t
validate_block_number(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number)
{
    if (block_number >= count_file_blocks(mpq_archive, file_number)) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the packed size of a file entry by block-table number. */
int32_t
libmpq__file_size_packed(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *packed_size
)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *packed_size =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].packed_size;

    return LIBMPQ_SUCCESS;
}

/* Return the unpacked size of a file entry by block-table number. */
int32_t
libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *unpacked_size =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].unpacked_size;

    return LIBMPQ_SUCCESS;
}

/* Return the file data offset relative to the start of the archive. */
int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *offset = mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].offset +
              (((long long)mpq_archive
                    ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
                    .offset_high)
               << 32);

    return LIBMPQ_SUCCESS;
}

/* Return the number of blocks needed to store the selected file. */
int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *blocks = count_file_blocks(mpq_archive, file_number);

    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry has the MPQ encrypted flag set. */
int32_t
libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *encrypted =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_ENCRYPTED) != 0
            ? TRUE
            : FALSE;

    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry has any MPQ compression flags set. */
int32_t
libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *compressed =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESS_MULTI) != 0
            ? TRUE
            : FALSE;

    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry uses PKWARE implosion. */
int32_t
libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *imploded =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESS_PKZIP) != 0
            ? TRUE
            : FALSE;

    return LIBMPQ_SUCCESS;
}

/* Calculate the three Storm hashes used to identify an MPQ file name. */
void
libmpq__file_hash(const char *filename, uint32_t *hash1, uint32_t *hash2, uint32_t *hash3)
{
    *hash1 = libmpq__hash_string(filename, 0x0);
    *hash2 = libmpq__hash_string(filename, 0x100);
    *hash3 = libmpq__hash_string(filename, 0x200);
}

/* Resolve a precomputed MPQ file-name hash to a public file number. */
int32_t
libmpq__file_number_from_hash(
    mpq_archive_s *mpq_archive, uint32_t hash1, uint32_t hash2, uint32_t hash3, uint32_t *number
)
{

    /* Hash table probe state and archive hash-table size. */
    uint32_t i, ht_count;

    ht_count = mpq_archive->mpq_header.hash_table_count;

    hash1 &= (ht_count - 1);

    /* The first hash selects the initial probe slot; collisions use linear probing. */
    for (i = hash1; mpq_archive->mpq_hash[i].block_table_index != LIBMPQ_HASH_FREE;
         i = (i + 1) & (ht_count - 1)) {
        if (mpq_archive->mpq_hash[i].hash_a == hash2 && mpq_archive->mpq_hash[i].hash_b == hash3) {
            *number =
                mpq_archive->mpq_hash[i].block_table_index -
                mpq_archive->mpq_map[mpq_archive->mpq_hash[i].block_table_index].block_table_diff;

            return LIBMPQ_SUCCESS;
        }

        if (((i + 1) & (ht_count - 1)) == hash1) {
            break;
        }
    }

    return LIBMPQ_ERROR_EXIST;
}

/* Resolve an MPQ file name to its block-table number through the hash table. */
int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number)
{
    uint32_t hash1, hash2, hash3;

    libmpq__file_hash(filename, &hash1, &hash2, &hash3);
    return libmpq__file_number_from_hash(mpq_archive, hash1, hash2, hash3, number);
}

/* Read a complete file by opening its block offset table and copying each block. */
int32_t
libmpq__file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
)
{

    /* Block loop state and total bytes transferred to the caller. */
    uint32_t i;
    uint32_t blocks = 0;
    int32_t result = 0;
    libmpq__off_t file_offset = 0;
    libmpq__off_t unpacked_size = 0;
    libmpq__off_t transferred_block = 0;
    libmpq__off_t transferred_total = 0;

    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    libmpq__file_size_unpacked(mpq_archive, file_number, &unpacked_size);

    if (unpacked_size > out_size) {
        return LIBMPQ_ERROR_SIZE;
    }

    libmpq__file_offset(mpq_archive, file_number, &file_offset);
    libmpq__file_blocks(mpq_archive, file_number, &blocks);

    if ((result = libmpq__block_open_offset(mpq_archive, file_number)) < 0) {
        return result;
    }

    for (i = 0; i < blocks; i++) {
        unpacked_size = 0;

        libmpq__block_size_unpacked(mpq_archive, file_number, i, &unpacked_size);

        if ((result = libmpq__block_read(
                 mpq_archive, file_number, i, out_buf + transferred_total, unpacked_size,
                 &transferred_block
             )) < 0) {
            libmpq__block_close_offset(mpq_archive, file_number);
            return result;
        }

        transferred_total += transferred_block;
    }

    libmpq__block_close_offset(mpq_archive, file_number);

    if (transferred != NULL) {
        *transferred = transferred_total;
    }

    return LIBMPQ_SUCCESS;
}

/* Open a file entry and cache its packed block offset table for block operations. */
int32_t
libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number)
{

    /* Packed block table state, file seed and read status. */
    uint32_t blocks;
    uint32_t i;
    uint32_t packed_offset_count;
    uint32_t packed_size;
    int32_t result = 0;

    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number]) {
        mpq_archive->mpq_file[file_number]->open_count++;
        return LIBMPQ_SUCCESS;
    }

    blocks = count_file_blocks(mpq_archive, file_number);
    packed_offset_count = blocks + 1;
    packed_size = sizeof(uint32_t) * packed_offset_count;

    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_CRC) != 0) {
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

    /* Compressed multi-sector files store a packed sector offset table in the archive. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESSED) != 0 &&
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) == 0) {
        if (fseeko(
                mpq_archive->fp,
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                        .offset +
                    (((long long)mpq_archive
                          ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
                          .offset_high)
                     << 32) +
                    mpq_archive->archive_offset,
                SEEK_SET
            ) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        if (fread(
                mpq_archive->mpq_file[file_number]->packed_offset, 1, packed_size, mpq_archive->fp
            ) != packed_size) {
            result = LIBMPQ_ERROR_READ;
            goto error;
        }

        /* Some protected archives omit the encrypted flag; a wrong first offset exposes that. */
        if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size &&
            mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size + 4) {
            mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags |=
                LIBMPQ_FLAG_ENCRYPTED;
        }

        /* The packed offset table uses seed - 1, so recover the file seed first. */
        if (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
            LIBMPQ_FLAG_ENCRYPTED) {
            uint32_t seed;

            if (libmpq__derive_block_table_seed(
                    (uint8_t *)mpq_archive->mpq_file[file_number]->packed_offset, packed_size,
                    mpq_archive->block_size, &seed
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
            mpq_archive->mpq_file[file_number]->seed = seed;

            if (libmpq__decrypt_block(
                    mpq_archive->mpq_file[file_number]->packed_offset, packed_size,
                    mpq_archive->mpq_file[file_number]->seed - 1
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }

            /* A valid decrypted table starts with its own byte size. */
            if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
        }
    } else {
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

    return LIBMPQ_SUCCESS;

error:

    if (mpq_archive->mpq_file[file_number] != NULL) {
        free(mpq_archive->mpq_file[file_number]->packed_offset);
        free(mpq_archive->mpq_file[file_number]);
        mpq_archive->mpq_file[file_number] = NULL;
    }

    return result;
}

/* Release a cached block offset table when the last user closes it. */
int32_t
libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    mpq_archive->mpq_file[file_number]->open_count--;

    if (mpq_archive->mpq_file[file_number]->open_count != 0) {
        return LIBMPQ_SUCCESS;
    }

    free(mpq_archive->mpq_file[file_number]->packed_offset);
    free(mpq_archive->mpq_file[file_number]);

    mpq_archive->mpq_file[file_number] = NULL;

    return LIBMPQ_SUCCESS;
}

/* Return the unpacked size for one block of an opened file entry. */
int32_t
libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (validate_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) != 0) {
        *unpacked_size =
            mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                .unpacked_size;
    }

    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) == 0) {
        if (block_number < count_file_blocks(mpq_archive, file_number) - 1) {
            *unpacked_size = mpq_archive->block_size;
        } else {
            *unpacked_size =
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .unpacked_size -
                mpq_archive->block_size * block_number;
        }
    }

    return LIBMPQ_SUCCESS;
}

/* Return the per-block decryption seed derived from the file seed and block number. */
int32_t
libmpq__get_block_seed(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed
)
{
    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (validate_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    *seed = mpq_archive->mpq_file[file_number]->seed + block_number;

    return LIBMPQ_SUCCESS;
}

/* Read, decrypt and decompress one block from an opened file entry. */
int32_t
libmpq__block_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
)
{

    /* Packed input buffer, size bookkeeping and block decryption state. */
    uint8_t *in_buf;
    uint32_t seed = 0;
    uint32_t encrypted = 0;
    uint32_t compressed = 0;
    uint32_t imploded = 0;
    int32_t tb = 0;
    uint8_t use_out_buf = FALSE;
    libmpq__off_t block_offset = 0;
    libmpq__off_t in_size = 0;
    libmpq__off_t unpacked_size = 0;

    if (validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (validate_block_number(mpq_archive, file_number, block_number) < 0) {
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

    /* Packed offsets are relative to the file payload start, not the archive start. */
    block_offset =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].offset +
        (((long long)mpq_archive
              ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
              .offset_high)
         << 32) +
        mpq_archive->mpq_file[file_number]->packed_offset[block_number];
    in_size = mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] -
              mpq_archive->mpq_file[file_number]->packed_offset[block_number];

    libmpq__file_encrypted(mpq_archive, file_number, &encrypted);
    libmpq__file_compressed(mpq_archive, file_number, &compressed);
    libmpq__file_imploded(mpq_archive, file_number, &imploded);

    /* Raw unencrypted blocks can be read directly into the caller's buffer. */
    use_out_buf = !encrypted && !compressed && !imploded && in_size <= out_size;

    if (fseeko(mpq_archive->fp, block_offset + mpq_archive->archive_offset, SEEK_SET) < 0) {
        return LIBMPQ_ERROR_SEEK;
    }

    if (use_out_buf) {
        in_buf = out_buf;
    } else {
        if ((in_buf = calloc(1, in_size)) == NULL) {
            return LIBMPQ_ERROR_MALLOC;
        }
    }

    if (fread(in_buf, 1, (size_t)in_size, mpq_archive->fp) != (size_t)in_size) {
        if (!use_out_buf) {
            free(in_buf);
        }
        return LIBMPQ_ERROR_READ;
    }

    if (encrypted) {
        libmpq__get_block_seed(mpq_archive, file_number, block_number, &seed);

        if (libmpq__decrypt_block((uint32_t *)in_buf, in_size, seed) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_DECRYPT;
        }
    }

    /* Blizzard multi-compression blocks declare their exact backend chain in the payload. */
    if (compressed) {
        if ((tb = libmpq__decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    /* PKWARE-imploded blocks use the legacy explode decoder. */
    if (imploded) {
        if ((tb = libmpq__decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKZIP
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
        if ((tb = libmpq__decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE
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

    return LIBMPQ_SUCCESS;
}
