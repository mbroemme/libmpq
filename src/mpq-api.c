/*
 *  mpq-api.c -- public archive, file and block operations.
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

#include "mpq-attributes.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-platform.h"
#include "mpq-reader.h"
#include "mpq-stream.h"
#include "mpq-verify.h"
#include "mpq-writer.h"
#include <libmpq/mpq.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* C99-compatible compile-time checks of native public value layouts.
 * These describe host-side structs, not the little-endian disk format. */
#define LIBMPQ_ABI_SIZE(type, bytes)                                                               \
    typedef char type##_size_check[sizeof(type) == (bytes) ? 1 : -1]
#define LIBMPQ_ABI_FIELD(type, field, offset, bytes)                                               \
    typedef char type##_##field##_layout_check                                                     \
        [offsetof(type, field) == (offset) && sizeof(((type *)0)->field) == (bytes) ? 1 : -1]

LIBMPQ_ABI_SIZE(mpq_archive_create_options_s, 20);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, version, 0, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, max_files, 4, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, sector_size, 8, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, flags, 12, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, attributes, 16, 4);

LIBMPQ_ABI_SIZE(mpq_file_options_s, 16);
LIBMPQ_ABI_FIELD(mpq_file_options_s, flags, 0, 4);
LIBMPQ_ABI_FIELD(mpq_file_options_s, compression_first, 4, 4);
LIBMPQ_ABI_FIELD(mpq_file_options_s, compression_next, 8, 4);
LIBMPQ_ABI_FIELD(mpq_file_options_s, locale, 12, 2);
LIBMPQ_ABI_FIELD(mpq_file_options_s, platform, 14, 2);

LIBMPQ_ABI_SIZE(mpq_file_attributes_s, 40);
LIBMPQ_ABI_FIELD(mpq_file_attributes_s, flags, 0, 4);
LIBMPQ_ABI_FIELD(mpq_file_attributes_s, crc32, 4, 4);
LIBMPQ_ABI_FIELD(mpq_file_attributes_s, filetime, 8, 8);
LIBMPQ_ABI_FIELD(mpq_file_attributes_s, md5, 16, 16);
LIBMPQ_ABI_FIELD(mpq_file_attributes_s, patch_bit, 32, 4);
LIBMPQ_ABI_FIELD(mpq_file_attributes_s, reserved, 36, 4);

#undef LIBMPQ_ABI_FIELD
#undef LIBMPQ_ABI_SIZE

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

/* Return the configured libmpq package version.
 * The returned pointer refers to immutable library storage and remains valid
 * for the lifetime of the process. */
const char *
libmpq__version(void)
{
    return VERSION;
}

/* Query whether writer compression is allowed without restricting archive decoding. */
int32_t
libmpq__archive_compression_allowed(
    uint32_t archive_version, uint32_t compression_mask, libmpq_compression_policy_t policy
)
{
    return libmpq__compression_allowed(archive_version, compression_mask, policy);
}

/* Return the optional attributes header flags without affecting normal reads.
 * Absence and malformed metadata are distinct negative results. */
int32_t
libmpq__archive_attributes_flags(mpq_archive_s *archive, uint32_t *flags)
{
    int32_t result;
    if (flags != NULL)
        *flags = 0;
    if (archive == NULL || flags == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    result = libmpq__attributes_load(archive);
    if (result == LIBMPQ_SUCCESS)
        *flags = archive->attributes->flags;
    return result;
}

/* Translate a public file number before reading stored per-block attributes.
 * Availability flags distinguish absent legacy values from legitimate zeroes. */
int32_t
libmpq__file_attributes(mpq_archive_s *archive, uint32_t number, mpq_file_attributes_s *attributes)
{
    uint32_t flags;
    int32_t result;
    if (attributes != NULL)
        memset(attributes, 0, sizeof(*attributes));
    if (archive == NULL || attributes == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (libmpq__reader_validate_file_number(archive, number) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_attributes_flags(archive, &flags);
    if (result == LIBMPQ_SUCCESS)
        libmpq__attributes_get(
            archive->attributes, archive->mpq_map[number].block_table_indices, attributes
        );
    return result;
}

/* Explicit verification is implemented separately from the public API facade. */
int32_t
libmpq__file_verify(
    mpq_archive_s *archive, uint32_t file_number, uint32_t verify_flags, uint32_t *mismatches
)
{
    return libmpq__verify_file(archive, file_number, verify_flags, mismatches);
}

/* Supply an explicit timestamp for an unfinished source file.
 * The writer owns the value; no filesystem timestamp is consulted. */
int32_t
libmpq__file_timestamp(mpq_writer_s *writer, uint64_t filetime)
{
    return libmpq__writer_file_timestamp(writer, filetime);
}

/* Translate a libmpq return code into a static diagnostic string.
 * Valid codes index an internal immutable table; invalid positive or out-of-
 * range negative values return NULL instead of reading outside that table. */
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

/* Create an MPQ archive through the internal writer implementation.
 * This public facade preserves the stable API while keeping archive layout
 * and file-table construction in the writer module. */
int32_t
libmpq__archive_create(
    mpq_archive_s **out, const char *path, const mpq_archive_create_options_s *options
)
{
    return libmpq__writer_archive_create(out, path, options);
}

/* Create an MPQE-wrapped archive through the normal writer and private final transform. */
int32_t
libmpq__archive_create_mpqe(
    mpq_archive_s **out, const char *path, const uint8_t *auth_code, size_t auth_code_size,
    const mpq_archive_create_options_s *options
)
{
    return libmpq__writer_archive_create_mpqe(out, path, auth_code, auth_code_size, options);
}

/* Begin a streamed file through the internal writer implementation.
 * The returned opaque writer owns the in-progress file state until finish or
 * an error closes the stream. */
int32_t
libmpq__file_begin(
    mpq_archive_s *archive, const char *name, libmpq__off_t size, const mpq_file_options_s *options,
    mpq_writer_s **out
)
{
    return libmpq__writer_file_begin(archive, name, size, options, out);
}

/* Write one input range through the internal writer implementation.
 * The writer validates the declared file size and buffers or flushes sectors
 * according to the selected storage and compression options. */
int32_t
libmpq__file_write(mpq_writer_s *writer, const uint8_t *buffer, libmpq__off_t size)
{
    return libmpq__writer_file_write(writer, buffer, size);
}

/* Finish a streamed file through the internal writer implementation.
 * Finalization verifies that all declared bytes were supplied and publishes
 * the completed file entry in the archive tables. */
int32_t
libmpq__file_finish(mpq_writer_s *writer)
{
    return libmpq__writer_file_finish(writer);
}

/* Add an in-memory file through the internal writer implementation.
 * The convenience call performs begin, write, and finish operations while
 * retaining the same validation and compression behavior as streaming. */
int32_t
libmpq__file_add(
    mpq_archive_s *archive, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    return libmpq__writer_file_add(archive, name, data, size, options);
}

/* Add a filesystem file through the internal writer implementation.
 * The source is read in bounded chunks, so callers need not load the complete
 * file into memory before archive creation begins. */
int32_t
libmpq__file_add_path(
    mpq_archive_s *archive, const char *name, const char *source, const mpq_file_options_s *options
)
{
    return libmpq__writer_file_add_path(archive, name, source, options);
}

/* Open an MPQ archive from a path and optional embedded archive offset.
 * A sentinel offset enables embedded-header scanning, while an explicit offset
 * restricts parsing to the requested archive location. */
int32_t
libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{
    return libmpq__reader_archive_open_path(mpq_archive, mpq_filename, archive_offset);
}

/* Open a caller-authenticated MPQE stream before parsing the contained MPQ. */
int32_t
libmpq__archive_open_mpqe(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    return libmpq__reader_archive_open_mpqe(
        mpq_archive, mpq_filename, archive_offset, auth_code, auth_code_size
    );
}

/* Reopen an archive with independent file I/O, metadata, and lazy caches.
 * Cloning rejects writer handles and verifies the source path still identifies
 * the same file before reparsing it into a separate archive object. */
int32_t
libmpq__archive_clone(mpq_archive_s **clone, mpq_archive_s *source)
{
    struct stat file_status;

    if (clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    *clone = NULL;

    if (source == NULL || source->filename == NULL || source->write_mode)
        return LIBMPQ_ERROR_EXIST;

#if !defined(_WIN32) && !defined(_WIN64)

    /* Reject cloning after the backing path has been replaced or removed. */
    if (source->file_identity_valid) {
        if (stat(source->filename, &file_status) < 0)
            return errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
        if ((uint64_t)file_status.st_dev != source->file_device ||
            (uint64_t)file_status.st_ino != source->file_inode)
            return LIBMPQ_ERROR_EXIST;
    }
#endif

    return libmpq__reader_archive_clone(clone, source);
}

/* Close the archive file and release all metadata tables allocated during archive open.
 * Writer handles are finalized before their archive storage is freed, while
 * reader-side cached block offsets are released entry by entry. */
int32_t
libmpq__archive_close(mpq_archive_s *mpq_archive)
{
    uint32_t i;
    int32_t result = LIBMPQ_SUCCESS;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;

    if (mpq_archive->write_mode) {

        /* Writer closure must serialize tables before releasing writer storage. */
        result = libmpq__writer_finalize(mpq_archive);
        if (result == LIBMPQ_SUCCESS && mpq_archive->write_mpqe)
            result = libmpq__writer_finalize_mpqe(mpq_archive);
        if (mpq_archive->fp != NULL && fclose(mpq_archive->fp) < 0 && result == LIBMPQ_SUCCESS)
            result = LIBMPQ_ERROR_CLOSE;
        libmpq__writer_mpqe_cleanup(mpq_archive);
        for (i = 0; i < mpq_archive->write_capacity; i++)
            free(mpq_archive->write_names ? mpq_archive->write_names[i] : NULL);
        free(mpq_archive->write_names);
        free(mpq_archive->write_locales);
        free(mpq_archive->write_platforms);
        libmpq__attributes_free(mpq_archive);
        free(mpq_archive->mpq_hash);
        free(mpq_archive->mpq_block);
        free(mpq_archive->mpq_block_ex);
        free(mpq_archive->filename);
        free(mpq_archive->write_mpqe_destination);
        free(mpq_archive->write_mpqe_output_path);
        free(mpq_archive);
        return result;
    }

    result = libmpq__stream_close(mpq_archive->stream);
    if (result != LIBMPQ_SUCCESS)
        return result;

    for (i = 0; i < mpq_archive->mpq_header.block_table_count; i++) {
        if (mpq_archive->mpq_file[i] != NULL) {
            free(mpq_archive->mpq_file[i]->packed_offset);
            free(mpq_archive->mpq_file[i]);
        }
    }

    free(mpq_archive->mpq_map);
    libmpq__attributes_free(mpq_archive);
    free(mpq_archive->mpq_file);
    free(mpq_archive->mpq_hash);
    free(mpq_archive->mpq_block);
    free(mpq_archive->mpq_block_ex);
    free(mpq_archive->filename);
    free(mpq_archive);

    return result;
}

/* Return the sum of packed sizes for all files in the archive block table.
 * The caller supplies an accumulator, allowing this query to preserve the
 * library's existing additive API behavior. */
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

/* Return the sum of unpacked sizes for all files in the archive block table.
 * Only live public file-map entries are counted; unused block-table capacity
 * does not contribute to the reported total. */
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

/* Return the byte offset where the MPQ archive starts in the backing file.
 * Embedded archives therefore report their discovered start rather than zero. */
int32_t
libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset)
{
    *offset = mpq_archive->archive_offset;

    return LIBMPQ_SUCCESS;
}

/* Return the MPQ archive format version stored in the header.
 * The internal zero-based version is converted to the public one-based API
 * value before being written to the caller's output. */
int32_t
libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version)
{
    *version = mpq_archive->mpq_header.version + 1;

    return LIBMPQ_SUCCESS;
}

/* Return the number of valid file entries discovered while opening the archive.
 * This is the compact public count, not the reserved block-table capacity. */
int32_t
libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files)
{
    *files = mpq_archive->files;

    return LIBMPQ_SUCCESS;
}

/* Return the packed size of a file entry by block-table number.
 * The public file number is validated and translated through the compact map
 * before reading the corresponding block-table entry. */
int32_t
libmpq__file_size_packed(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *packed_size
)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *packed_size =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].packed_size;

    return LIBMPQ_SUCCESS;
}

/* Return the unpacked size of a file entry by block-table number.
 * Invalid compact file numbers are rejected before any archive metadata is
 * accessed. */
int32_t
libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *unpacked_size =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].unpacked_size;

    return LIBMPQ_SUCCESS;
}

/* Return the file data offset relative to the start of the archive.
 * MPQ v2 high offset words are combined with the legacy low word to produce
 * the complete offset visible through the public API. */
int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *offset = mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].offset +
              (((long long)mpq_archive
                    ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
                    .offset_high)
               << 32);

    return LIBMPQ_SUCCESS;
}

/* Return the number of blocks needed to store the selected file.
 * The reader distinguishes single-unit files from sectorized entries and
 * applies the archive sector size for the latter. */
int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *blocks = libmpq__reader_count_file_blocks(mpq_archive, file_number);

    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry has the MPQ encrypted flag set.
 * The result is normalized to the library's boolean convention after lookup. */
int32_t
libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *encrypted =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_ENCRYPTED) != 0
            ? TRUE
            : FALSE;

    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry has any MPQ compression flags set.
 * This reports Blizzard multi-compression metadata, including its per-sector
 * codec mask, rather than treating standalone PKWARE as multi-compressed. */
int32_t
libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *compressed =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESS_MULTI) != 0
            ? TRUE
            : FALSE;

    return LIBMPQ_SUCCESS;
}

/* Report whether the selected file entry uses PKWARE implosion.
 * The flag query covers standalone implode storage as represented in the MPQ
 * block entry and returns a normalized boolean result. */
int32_t
libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *imploded =
        (mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_COMPRESS_PKZIP) != 0
            ? TRUE
            : FALSE;

    return LIBMPQ_SUCCESS;
}

/* Calculate the three Storm hashes used to identify an MPQ file name.
 * Each output corresponds to a distinct hash-table phase used during MPQ
 * name lookup and collision probing. */
void
libmpq__file_hash(const char *filename, uint32_t *hash1, uint32_t *hash2, uint32_t *hash3)
{
    *hash1 = libmpq__crypto_hash_string(filename, 0x0);
    *hash2 = libmpq__crypto_hash_string(filename, 0x100);
    *hash3 = libmpq__crypto_hash_string(filename, 0x200);
}

/* Resolve a precomputed MPQ file-name hash to a public file number.
 * The first hash selects a slot and linear probing continues until the stored
 * pair matches or the table wraps without finding the file. */
int32_t
libmpq__file_number_from_hash(
    mpq_archive_s *mpq_archive, uint32_t hash1, uint32_t hash2, uint32_t hash3, uint32_t *number
)
{

    /* Hash table probe state and archive hash-table size. */
    uint32_t i;
    uint32_t ht_count;
    uint32_t block_table_index;

    ht_count = mpq_archive->mpq_header.hash_table_count;
    if (ht_count == 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    hash1 %= ht_count;

    /* The first hash selects the initial probe slot; collisions use linear probing. */
    for (i = hash1; mpq_archive->mpq_hash[i].block_table_index != LIBMPQ_HASH_FREE;
         i = (i + 1) % ht_count) {
        if (mpq_archive->mpq_hash[i].hash_a == hash2 && mpq_archive->mpq_hash[i].hash_b == hash3) {
            block_table_index = mpq_archive->mpq_hash[i].block_table_index;
            if (block_table_index >= mpq_archive->mpq_header.block_table_count ||
                (mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_EXISTS) == 0) {
                return LIBMPQ_ERROR_FORMAT;
            }
            *number = block_table_index - mpq_archive->mpq_map[block_table_index].block_table_diff;
            if (*number >= mpq_archive->files) {
                return LIBMPQ_ERROR_FORMAT;
            }

            return LIBMPQ_SUCCESS;
        }

        if ((i + 1) % ht_count == hash1) {
            break;
        }
    }

    return LIBMPQ_ERROR_EXIST;
}

/* Resolve an MPQ file name to its block-table number through the hash table.
 * The name is hashed with all three Storm phases before the collision-aware
 * lookup is delegated to the precomputed-hash helper. */
int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number)
{
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;

    libmpq__file_hash(filename, &hash1, &hash2, &hash3);
    return libmpq__file_number_from_hash(mpq_archive, hash1, hash2, hash3, number);
}

/* Read a complete file by opening its block offset table and copying each block.
 * The output buffer must hold the complete unpacked file, and cached offset
 * state is closed on both successful and failed block reads. */
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

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
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

    /* Read each block into its exact destination slice and maintain one total. */
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

/* Open a file's offset cache using the normal anonymous reader path.
 * Internal named reads share the same implementation and reference counting. */
int32_t
libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    return libmpq__reader_open_named(mpq_archive, file_number, NULL);
}

/* Release a cached block offset table when the last user closes it.
 * Reference counting permits nested block operations while ensuring the cache
 * is freed only after the final matching close. */
int32_t
libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number)
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
        return LIBMPQ_SUCCESS;
    }

    free(mpq_archive->mpq_file[file_number]->packed_offset);
    free(mpq_archive->mpq_file[file_number]);

    mpq_archive->mpq_file[file_number] = NULL;

    return LIBMPQ_SUCCESS;
}

/* Return the unpacked size for one block of an opened file entry.
 * Full sectors use the archive sector size, while the final sector is reduced
 * to the remaining file bytes and single-unit files use their full size. */
int32_t
libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
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

    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) != 0) {

        /* A single-unit entry has one logical block containing the whole file. */
        *unpacked_size =
            mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                .unpacked_size;
    }

    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         LIBMPQ_FLAG_SINGLE) == 0) {

        /* Every non-final sector is full-sized; only the tail uses a remainder. */
        if (block_number < libmpq__reader_count_file_blocks(mpq_archive, file_number) - 1) {
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

/* Normal block reads never enable explicit checksum verification. */
int32_t
libmpq__block_read(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
)
{
    return libmpq__reader_block_read(
        archive, file_number, block_number, out_buf, out_size, transferred, NULL, NULL
    );
}
