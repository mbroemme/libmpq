/*
 *  mpq.c -- functions for developers using libmpq.
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

/* configuration includes. */
#include "config.h"

/* public and internal api includes. */
#include "mpq-internal.h"
#include "mpq.h"

/* internal hash, crypt and decompression includes. */
#include "common.h"

/* system includes. */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* platform compatibility includes. */
#include "platform.h"

/* Error strings indexed by the negated libmpq error code. */
static const char *__libmpq_error_strings[] = { "success",
                                                "open error on file",
                                                "close error on file",
                                                "lseek error on file",
                                                "read error on file",
                                                "write error on file",
                                                "memory allocation error",
                                                "format errror",
                                                "init() wasn't called",
                                                "buffer size is to small",
                                                "file or block does not exist in archive",
                                                "we don't know the decryption seed",
                                                "error on unpacking file" };

/* Return the configured libmpq package version. */
const char *
libmpq__version(void)
{

    /* return version information. */
    return VERSION;
}

/* Translate a libmpq return code into a static diagnostic string. */
const char *
libmpq__strerror(int32_t return_code)
{

    /* Only negative libmpq error codes and zero are valid table indexes. */
    if (-return_code < 0 || -return_code > sizeof(__libmpq_error_strings) / sizeof(char *))
        return NULL;

    /* Return the static string owned by the library. */
    return __libmpq_error_strings[-return_code];
}

/* Open an MPQ archive, locate its header, read metadata tables, decrypt them and
 * build the in-memory file map used by later file and block operations. */
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

        /* Archive state could not be allocated. */
        return LIBMPQ_ERROR_MALLOC;
    }

    /* Open the archive file for binary reads. */
    if (((*mpq_archive)->fp = fopen(mpq_filename, "rb")) == NULL) {

        /* file could not be opened. */
        result = LIBMPQ_ERROR_OPEN;
        goto error;
    }

    /* assign some default values. */
    (*mpq_archive)->mpq_header.mpq_magic = 0;
    (*mpq_archive)->files = 0;

    /* loop through file and search for mpq signature. */
    while (TRUE) {

        /* reset header values. */
        (*mpq_archive)->mpq_header.mpq_magic = 0;

        /* seek in file. */
        if (fseeko((*mpq_archive)->fp, archive_offset, SEEK_SET) < 0) {

            /* seek in file failed. */
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        /* read header from file. */
        if (fread(&(*mpq_archive)->mpq_header, 1, sizeof(mpq_header_s), (*mpq_archive)->fp) !=
            sizeof(mpq_header_s)) {

            /* no valid mpq archive. */
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        /* check if we found a valid mpq header. */
        if ((*mpq_archive)->mpq_header.mpq_magic == LIBMPQ_HEADER) {

            /* check if we process old mpq archive version. */
            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {

                /* check if the archive is protected. */
                if ((*mpq_archive)->mpq_header.header_size != sizeof(mpq_header_s)) {

                    /* correct header size. */
                    (*mpq_archive)->mpq_header.header_size = sizeof(mpq_header_s);
                }
            }

            /* check if we process new mpq archive version. */
            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {

                /* check if the archive is protected. */
                if ((*mpq_archive)->mpq_header.header_size !=
                    sizeof(mpq_header_s) + sizeof(mpq_header_ex_s)) {

                    /* correct header size. */
                    (*mpq_archive)->mpq_header.header_size =
                        sizeof(mpq_header_s) + sizeof(mpq_header_ex_s);
                }
            }

            /* break the loop, because header was found. */
            break;
        }

        /* move to the next possible offset. */
        if (!header_search) {

            /* no valid mpq archive. */
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        archive_offset += 512;
    }

    /* store block size for later use. */
    (*mpq_archive)->block_size = 512 << (*mpq_archive)->mpq_header.block_size;

    /* store archive offset and size for later use. */
    (*mpq_archive)->archive_offset = archive_offset;

    /* check if we process new mpq archive version. */
    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {

        /* seek in file. */
        if (fseeko((*mpq_archive)->fp, sizeof(mpq_header_s) + archive_offset, SEEK_SET) < 0) {

            /* seek in file failed. */
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        /* read header from file. */
        if (fread(&(*mpq_archive)->mpq_header_ex, 1, sizeof(mpq_header_ex_s), (*mpq_archive)->fp) !=
            sizeof(mpq_header_ex_s)) {

            /* no valid mpq archive. */
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
    }

    /* allocate memory for the block table, hash table, file and block table to file mapping. */
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

        /* memory allocation problem. */
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* seek in file. */
    if (fseeko(
            (*mpq_archive)->fp,
            (*mpq_archive)->mpq_header.hash_table_offset +
                (((long long)((*mpq_archive)->mpq_header_ex.hash_table_offset_high)) << 32) +
                (*mpq_archive)->archive_offset,
            SEEK_SET
        ) < 0) {

        /* seek in file failed. */
        result = LIBMPQ_ERROR_SEEK;
        goto error;
    }

    /* read the hash table into the buffer. */
    if (fread(
            (*mpq_archive)->mpq_hash, 1,
            (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s), (*mpq_archive)->fp
        ) != (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s)) {

        /* something on read failed. */
        result = LIBMPQ_ERROR_READ;
        goto error;
    }

    /* decrypt the hashtable. */
    libmpq__decrypt_block(
        (uint32_t *)((*mpq_archive)->mpq_hash),
        (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s),
        libmpq__hash_string("(hash table)", 0x300)
    );

    /* seek in file. */
    if (fseeko(
            (*mpq_archive)->fp,
            (*mpq_archive)->mpq_header.block_table_offset +
                (((long long)((*mpq_archive)->mpq_header_ex.block_table_offset_high)) << 32) +
                (*mpq_archive)->archive_offset,
            SEEK_SET
        ) < 0) {

        /* seek in file failed. */
        result = LIBMPQ_ERROR_SEEK;
        goto error;
    }

    /* read the block table into the buffer. */
    if (fread(
            (*mpq_archive)->mpq_block, 1,
            (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s), (*mpq_archive)->fp
        ) != (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s)) {

        /* something on read failed. */
        result = LIBMPQ_ERROR_READ;
        goto error;
    }

    /* decrypt block table. */
    libmpq__decrypt_block(
        (uint32_t *)((*mpq_archive)->mpq_block),
        (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s),
        libmpq__hash_string("(block table)", 0x300)
    );

    /* check if extended block table is present, regardless of version 2 it is only present in
     * archives > 4GB. */
    if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {

        /* seek in file. */
        if (fseeko(
                (*mpq_archive)->fp, (*mpq_archive)->mpq_header_ex.extended_offset + archive_offset,
                SEEK_SET
            ) < 0) {

            /* seek in file failed. */
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        /* read header from file. */
        if (fread(
                (*mpq_archive)->mpq_block_ex, 1,
                (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_ex_s),
                (*mpq_archive)->fp
            ) != (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_ex_s)) {

            /* no valid mpq archive. */
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
    }

    /* loop through all files in mpq archive and check if they are valid. */
    for (i = 0; i < (*mpq_archive)->mpq_header.block_table_count; i++) {

        /* save block difference between valid and invalid blocks. */
        (*mpq_archive)->mpq_map[i].block_table_diff = i - count;

        /* check if file exists, sizes and offsets are correct. */
        if (((*mpq_archive)->mpq_block[i].flags & LIBMPQ_FLAG_EXISTS) == 0) {

            /* file does not exist, so nothing to do with that block. */
            continue;
        }

        /* create final indices tables. */
        (*mpq_archive)->mpq_map[count].block_table_indices = i;

        /* increase file counter. */
        count++;
    }

    /* save the number of files. */
    (*mpq_archive)->files = count;

    /* if no error was found, return zero. */
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

    /* try to close the file */
    if ((fclose(mpq_archive->fp)) < 0) {

        /* don't free anything here, so the caller can try calling us
         * again.
         */
        return LIBMPQ_ERROR_CLOSE;
    }

    /* free header, tables and list. */
    free(mpq_archive->mpq_map);
    free(mpq_archive->mpq_file);
    free(mpq_archive->mpq_hash);
    free(mpq_archive->mpq_block);
    free(mpq_archive->mpq_block_ex);
    free(mpq_archive);

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the sum of packed sizes for all files in the archive block table. */
int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size)
{

    /* Running total across all block-table entries. */
    uint32_t i;

    /* loop through all files in archive and count packed size. */
    for (i = 0; i < mpq_archive->files; i++) {
        *packed_size +=
            mpq_archive->mpq_block[mpq_archive->mpq_map[i].block_table_indices].packed_size;
    }

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the sum of unpacked sizes for all files in the archive block table. */
int32_t
libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, libmpq__off_t *unpacked_size)
{

    /* Running total across all block-table entries. */
    uint32_t i;

    /* loop through all files in archive and count unpacked size. */
    for (i = 0; i < mpq_archive->files; i++) {
        *unpacked_size +=
            mpq_archive->mpq_block[mpq_archive->mpq_map[i].block_table_indices].unpacked_size;
    }

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the byte offset where the MPQ archive starts in the backing file. */
int32_t
libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset)
{

    /* return archive offset. */
    *offset = mpq_archive->archive_offset;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the MPQ archive format version stored in the header. */
int32_t
libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version)
{

    /* return archive version. */
    *version = mpq_archive->mpq_header.version + 1;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the number of valid file entries discovered while opening the archive. */
int32_t
libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files)
{

    /* return archive version. */
    *files = mpq_archive->files;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

static int32_t
libmpq__check_file_number(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (file_number >= mpq_archive->files) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

static uint32_t
libmpq__file_block_count(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    uint32_t block_table_index = mpq_archive->mpq_map[file_number].block_table_indices;
    uint32_t unpacked_size = mpq_archive->mpq_block[block_table_index].unpacked_size;

    if ((mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_SINGLE) != 0) {
        return 1;
    }

    return (unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
}

static int32_t
libmpq__check_block_number(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number)
{
    if (block_number >= libmpq__file_block_count(mpq_archive, file_number)) {
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

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* get the packed size of file. */
    *packed_size =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].packed_size;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the unpacked size of a file entry by block-table number. */
int32_t
libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* get the unpacked size of file. */
    *unpacked_size =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].unpacked_size;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the file data offset relative to the start of the archive. */
int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* return file offset relative to archive start. */
    *offset = mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].offset +
              (((long long)mpq_archive
                    ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
                    .offset_high)
               << 32);

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the number of blocks needed to store the selected file. */
int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* return the number of blocks for the given file. */
    *blocks = libmpq__file_block_count(mpq_archive, file_number);

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry has the MPQ encrypted flag set. */
int32_t
libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* return the encryption status of file. */
    *encrypted =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_ENCRYPTED) != 0
            ? TRUE
            : FALSE;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry has any MPQ compression flags set. */
int32_t
libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* return the compression status of file. */
    *compressed =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESS_MULTI) != 0
            ? TRUE
            : FALSE;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry uses PKWARE implosion. */
int32_t
libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* return the implosion status of file. */
    *imploded =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESS_PKZIP) != 0
            ? TRUE
            : FALSE;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Resolve an MPQ file name to its block-table number through the hash table. */
int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number)
{

    /* Hash table probe values for the three Storm hash variants. */
    uint32_t i, hash1, hash2, hash3, ht_count;

    /* if the list of file names doesn't include this one, we'll have
     * to figure out the file number the "hard" way.
     */
    ht_count = mpq_archive->mpq_header.hash_table_count;

    hash1 = libmpq__hash_string(filename, 0x0) & (ht_count - 1);
    hash2 = libmpq__hash_string(filename, 0x100);
    hash3 = libmpq__hash_string(filename, 0x200);

    /* loop through all files in mpq archive.
     * hash1 gives us a clue about the starting position of this
     * search.
     */
    for (i = hash1; mpq_archive->mpq_hash[i].block_table_index != LIBMPQ_HASH_FREE;
         i = (i + 1) & (ht_count - 1)) {

        /* if the other two hashes match, we found our file number. */
        if (mpq_archive->mpq_hash[i].hash_a == hash2 && mpq_archive->mpq_hash[i].hash_b == hash3) {

            /* return the file number. */
            *number =
                mpq_archive->mpq_hash[i].block_table_index -
                mpq_archive->mpq_map[mpq_archive->mpq_hash[i].block_table_index].block_table_diff;

            /* we found our file, return zero. */
            return LIBMPQ_SUCCESS;
        }

        /* check if we have cycled through the whole hash table */
        if (((i + 1) & (ht_count - 1)) == hash1) {
            break;
        }
    }

    /* if no matching entry found, so return error. */
    return LIBMPQ_ERROR_EXIST;
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

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* get target size of block. */
    libmpq__file_size_unpacked(mpq_archive, file_number, &unpacked_size);

    /* Check if the target buffer is too small. */
    if (unpacked_size > out_size) {

        /* Output buffer size is too small or block size is unknown. */
        return LIBMPQ_ERROR_SIZE;
    }

    /* fetch file offset. */
    libmpq__file_offset(mpq_archive, file_number, &file_offset);

    /* get block count for file. */
    libmpq__file_blocks(mpq_archive, file_number, &blocks);

    /* open the packed block offset table. */
    if ((result = libmpq__block_open_offset(mpq_archive, file_number)) < 0) {

        /* something on opening packed block offset table failed. */
        return result;
    }

    /* loop through all blocks. */
    for (i = 0; i < blocks; i++) {

        /* cleanup size variable. */
        unpacked_size = 0;

        /* get unpacked block size. */
        libmpq__block_size_unpacked(mpq_archive, file_number, i, &unpacked_size);

        /* read block. */
        if ((result = libmpq__block_read(
                 mpq_archive, file_number, i, out_buf + transferred_total, unpacked_size,
                 &transferred_block
             )) < 0) {

            /* close the packed block offset table. */
            libmpq__block_close_offset(mpq_archive, file_number);

            /* something on reading block failed. */
            return result;
        }

        transferred_total += transferred_block;
    }

    /* close the packed block offset table. */
    libmpq__block_close_offset(mpq_archive, file_number);

    /* check for null pointer. */
    if (transferred != NULL) {

        /* store transferred bytes. */
        *transferred = transferred_total;
    }

    /* if no error was found, return zero. */
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

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number]) {

        /* file already opened, so increment counter */
        mpq_archive->mpq_file[file_number]->open_count++;
        return LIBMPQ_SUCCESS;
    }

    /* get packed offset table size based on block count. */
    blocks = libmpq__file_block_count(mpq_archive, file_number);
    packed_offset_count = blocks + 1;
    packed_size = sizeof(uint32_t) * packed_offset_count;

    /* check if data has one extra entry. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_CRC) != 0) {

        /* add one uint32_t. */
        packed_size += sizeof(uint32_t);
    }

    /* allocate memory for the file. */
    if ((mpq_archive->mpq_file[file_number] = calloc(1, sizeof(mpq_file_s))) == NULL) {

        /* memory allocation problem. */
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* allocate memory for the packed block offset table. */
    if ((mpq_archive->mpq_file[file_number]->packed_offset = calloc(1, packed_size)) == NULL) {

        /* memory allocation problem. */
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* initialize counter to one opening */
    mpq_archive->mpq_file[file_number]->packed_offset_count = packed_offset_count;
    mpq_archive->mpq_file[file_number]->open_count = 1;

    /* check if we need to load the packed block offset table, we will maintain this table for
     * unpacked files too. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESSED) != 0 &&
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) == 0) {

        /* seek to block position. */
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

            /* seek in file failed. */
            result = LIBMPQ_ERROR_SEEK;
            goto error;
        }

        /* read block positions from begin of file. */
        if (fread(
                mpq_archive->mpq_file[file_number]->packed_offset, 1, packed_size, mpq_archive->fp
            ) != packed_size) {

            /* something on read from archive failed. */
            result = LIBMPQ_ERROR_READ;
            goto error;
        }

        /* check if the archive is protected some way, sometimes the file appears not to be
         * encrypted, but it is. a special case are files with an additional sector but
         * LIBMPQ_FLAG_CRC not set. we don't want to handle them as encrypted. */
        if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size &&
            mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size + 4) {

            /* file is encrypted. */
            mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags |=
                LIBMPQ_FLAG_ENCRYPTED;
        }

        /* check if packed offset block is encrypted, we have to decrypt it. */
        if (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
            LIBMPQ_FLAG_ENCRYPTED) {

            /* check if we don't know the file seed, try to find it. */
            if (libmpq__decrypt_key(
                    (uint8_t *)mpq_archive->mpq_file[file_number]->packed_offset, packed_size,
                    mpq_archive->block_size, &mpq_archive->mpq_file[file_number]->seed
                ) < 0) {

                /* sorry without seed, we cannot extract file. */
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }

            /* decrypt block in input buffer. */
            if (libmpq__decrypt_block(
                    mpq_archive->mpq_file[file_number]->packed_offset, packed_size,
                    mpq_archive->mpq_file[file_number]->seed - 1
                ) < 0) {

                /* something on decrypt failed. */
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }

            /* check if the block positions are correctly decrypted. */
            if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size) {

                /* sorry without seed, we cannot extract file. */
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
        }
    } else {

        /* check if file is not stored in a single sector. */
        if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
             LIBMPQ_FLAG_SINGLE) == 0) {

            /* loop through all blocks and create packed block offset table based on block size. */
            for (i = 0; i < packed_offset_count; i++) {

                /* check if we process the last block. */
                if (i == blocks) {

                    /* store size of last block. */
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        mpq_archive
                            ->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                            .unpacked_size;
                } else {

                    /* store default block size. */
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        i * mpq_archive->block_size;
                }
            }
        } else {

            /* store offsets. */
            mpq_archive->mpq_file[file_number]->packed_offset[0] = 0;
            mpq_archive->mpq_file[file_number]->packed_offset[1] =
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .packed_size;
        }
    }

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;

error:

    /* free packed block offset table and file pointer. */
    if (mpq_archive->mpq_file[file_number] != NULL) {
        free(mpq_archive->mpq_file[file_number]->packed_offset);
        free(mpq_archive->mpq_file[file_number]);
        mpq_archive->mpq_file[file_number] = NULL;
    }

    /* return error constant. */
    return result;
}

/* Release a cached block offset table when the last user closes it. */
int32_t
libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL) {

        /* packed block offset table is not opened. */
        return LIBMPQ_ERROR_OPEN;
    }

    mpq_archive->mpq_file[file_number]->open_count--;

    if (mpq_archive->mpq_file[file_number]->open_count != 0) {

        /* still in use */
        return LIBMPQ_SUCCESS;
    }

    /* free packed block offset table and file pointer. */
    free(mpq_archive->mpq_file[file_number]->packed_offset);
    free(mpq_archive->mpq_file[file_number]);

    /* mark it as unopened - libmpq__block_open_offset checks for this to decide whether to
     * increment the counter */
    mpq_archive->mpq_file[file_number] = NULL;

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the unpacked size for one block of an opened file entry. */
int32_t
libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if given block number is not out of range. */
    if (libmpq__check_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if packed block offset table is opened. */
    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {

        /* packed block offset table is not opened. */
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if block is stored as single sector. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) != 0) {

        /* return the unpacked size of the block in the mpq archive. */
        *unpacked_size =
            mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                .unpacked_size;
    }

    /* check if block is not stored as single sector. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) == 0) {

        /* check if we not process the last block. */
        if (block_number < libmpq__file_block_count(mpq_archive, file_number) - 1) {

            /* return the block size as unpacked size. */
            *unpacked_size = mpq_archive->block_size;
        } else {

            /* return the unpacked size of the last block in the mpq archive. */
            *unpacked_size =
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .unpacked_size -
                mpq_archive->block_size * block_number;
        }
    }

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}

/* Return the per-block decryption seed derived from the file seed and block number. */
int32_t
libmpq__block_seed(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed
)
{

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if given block number is not out of range. */
    if (libmpq__check_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if packed block offset table is opened. */
    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {

        /* packed block offset table is not opened. */
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* return the decryption key. */
    *seed = mpq_archive->mpq_file[file_number]->seed + block_number;

    /* if no error was found, return zero. */
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
    libmpq__off_t block_offset = 0;
    libmpq__off_t in_size = 0;
    libmpq__off_t unpacked_size = 0;

    /* check if given file number is not out of range. */
    if (libmpq__check_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if given block number is not out of range. */
    if (libmpq__check_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* check if packed block offset table is opened. */
    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {

        /* packed block offset table is not opened. */
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* get target size of block. */
    libmpq__block_size_unpacked(mpq_archive, file_number, block_number, &unpacked_size);

    /* Check if the target buffer is too small. */
    if (unpacked_size > out_size) {

        /* Output buffer size is too small or block size is unknown. */
        return LIBMPQ_ERROR_SIZE;
    }

    /* fetch some required values like input buffer size and block offset. */
    block_offset =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].offset +
        (((long long)mpq_archive
              ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
              .offset_high)
         << 32) +
        mpq_archive->mpq_file[file_number]->packed_offset[block_number];
    in_size = mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] -
              mpq_archive->mpq_file[file_number]->packed_offset[block_number];

    /* seek in file. */
    if (fseeko(mpq_archive->fp, block_offset + mpq_archive->archive_offset, SEEK_SET) < 0) {

        /* something with seek in file failed. */
        return LIBMPQ_ERROR_SEEK;
    }

    /* allocate memory for the read buffer. */
    if ((in_buf = calloc(1, in_size)) == NULL) {

        /* memory allocation problem. */
        return LIBMPQ_ERROR_MALLOC;
    }

    /* read block from file. */
    if (fread(in_buf, 1, in_size, mpq_archive->fp) != in_size) {

        /* free buffers. */
        free(in_buf);

        /* something on reading block failed. */
        return LIBMPQ_ERROR_READ;
    }

    /* get encryption status. */
    libmpq__file_encrypted(mpq_archive, file_number, &encrypted);

    /* check if file is encrypted. */
    if (encrypted) {

        /* get decryption key. */
        libmpq__block_seed(mpq_archive, file_number, block_number, &seed);

        /* decrypt block. */
        if (libmpq__decrypt_block((uint32_t *)in_buf, in_size, seed) < 0) {

            /* free buffers. */
            free(in_buf);

            /* something on decrypting block failed. */
            return LIBMPQ_ERROR_DECRYPT;
        }
    }

    /* get compression status. */
    libmpq__file_compressed(mpq_archive, file_number, &compressed);

    /* check if file is compressed. */
    if (compressed) {

        /* decompress block. */
        if ((tb = libmpq__decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI
             )) < 0) {

            /* free temporary buffer. */
            free(in_buf);

            /* something on decompressing block failed. */
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    /* get implosion status. */
    libmpq__file_imploded(mpq_archive, file_number, &imploded);

    /* check if file is imploded. */
    if (imploded) {

        /* explode block. */
        if ((tb = libmpq__decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKZIP
             )) < 0) {

            /* free temporary buffer. */
            free(in_buf);

            /* something on decompressing block failed. */
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    /* files should not be compressed and imploded */
    if (compressed && imploded) {

        /* free temporary buffer. */
        free(in_buf);

        /* something on decompressing block failed. */
        return LIBMPQ_ERROR_UNPACK;
    }

    /* check if file is neither compressed nor imploded. */
    if (!compressed && !imploded) {

        /* copy block. */
        if ((tb = libmpq__decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE
             )) < 0) {

            /* free temporary buffer. */
            free(in_buf);

            /* something on decompressing block failed. */
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    /* free read buffer. */
    free(in_buf);

    /* check for null pointer. */
    if (transferred != NULL) {

        /* store transferred bytes. */
        *transferred = tb;
    }

    /* if no error was found, return zero. */
    return LIBMPQ_SUCCESS;
}
