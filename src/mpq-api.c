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

/* Export only public wrappers when building a Windows DLL. */
#if defined(_WIN32) && defined(DLL_EXPORT)
#define LIBMPQ_API __declspec(dllexport)
#endif

#include <libmpq/mpq.h>

#include "mpq-archive.h"
#include "mpq-attributes.h"
#include "mpq-block.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-patch-reader.h"
#include "mpq-patch-writer.h"
#include "mpq-reader.h"
#include "mpq-rsa.h"
#include "mpq-signature.h"
#include "mpq-source.h"
#include "mpq-stream.h"
#include "mpq-update.h"
#include "mpq-verify.h"
#include "mpq-writer.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * C99-compatible compile-time checks of native public value layouts.
 * These describe host-side structs, not the little-endian disk format.
 */
#define LIBMPQ_ABI_SIZE(type, bytes) \
    typedef char type##_size_check[sizeof(type) == (bytes) ? 1 : -1]
#define LIBMPQ_ABI_FIELD(type, field, offset, bytes) \
    typedef char type##_##field##_layout_check       \
        [offsetof(type, field) == (offset) && sizeof(((type *)0)->field) == (bytes) ? 1 : -1]

LIBMPQ_ABI_SIZE(mpq_archive_create_options_s, 20);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, version, 0, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, max_files, 4, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, sector_size, 8, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, flags, 12, 4);
LIBMPQ_ABI_FIELD(mpq_archive_create_options_s, attributes, 16, 4);

LIBMPQ_ABI_SIZE(mpq_file_identity_s, 16);
LIBMPQ_ABI_FIELD(mpq_file_identity_s, file_number, 0, 4);
LIBMPQ_ABI_FIELD(mpq_file_identity_s, flags, 4, 4);
LIBMPQ_ABI_FIELD(mpq_file_identity_s, locale, 8, 2);
LIBMPQ_ABI_FIELD(mpq_file_identity_s, platform, 10, 2);
LIBMPQ_ABI_FIELD(mpq_file_identity_s, reserved, 12, 4);

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

/*
 * Return the configured libmpq package version.
 * The returned pointer refers to immutable library storage and remains valid
 * for the lifetime of the process.
 */
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

/* Signature queries and verification are explicit and do not affect reads. */
int32_t
libmpq__archive_signatures(mpq_archive_s *archive, uint32_t *signatures)
{
    return libmpq__signature_detect(archive, signatures);
}

int32_t
libmpq__archive_verify(
    mpq_archive_s *archive, uint32_t flags, const uint8_t *key, size_t key_size,
    uint32_t *mismatches
)
{
    return libmpq__signature_verify(archive, flags, key, key_size, mismatches);
}

int32_t
libmpq__archive_sign(mpq_archive_s *archive, uint32_t type, const uint8_t *key, size_t key_size)
{
    return libmpq__signature_configure(archive, type, key, key_size);
}

/*
 * Return the optional attributes header flags without affecting normal reads.
 * Absence and malformed metadata are distinct negative results.
 */
int32_t
libmpq__archive_attributes(mpq_archive_s *archive, uint32_t *flags)
{
    int32_t result;
    if (flags != NULL)
        *flags = 0;
    if (archive == NULL || flags == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    result = libmpq__attributes_load(archive);
    if (result == 0)
        *flags = archive->attributes->flags;
    return result;
}

/*
 * Translate a public file number before reading stored per-block attributes.
 * Availability flags distinguish absent legacy values from legitimate zeroes.
 */
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
    if (libmpq__reader_validate_file_number(archive, number) != 0)
        return LIBMPQ_ERROR_EXIST;
    if ((archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask &
         LIBMPQ_ENTRY_SOURCE_CLASSIC) == 0 ||
        archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index >=
            archive->mpq_header.block_table_count)
        return LIBMPQ_ERROR_FORMAT;
    result = libmpq__archive_attributes(archive, &flags);
    if (result == 0)
        libmpq__attributes_get(
            archive->attributes,
            archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index,
            attributes
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

/* Explicitly verify one sector and return its stored checksum. */
int32_t
libmpq__block_verify(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint32_t *checksum,
    uint32_t *mismatches
)
{
    return libmpq__verify_block(archive, file_number, block_number, checksum, mismatches);
}

/*
 * Supply an explicit timestamp for an unfinished source file.
 * The writer owns the value; no filesystem timestamp is consulted.
 */
int32_t
libmpq__writer_timestamp(mpq_writer_s *writer, uint64_t filetime)
{
    return libmpq__writer_file_timestamp(writer, filetime);
}

/*
 * Translate a libmpq return code into a static diagnostic string.
 * Valid codes index an internal immutable table; invalid positive or out-of-
 * range negative values return NULL instead of reading outside that table.
 */
const char *
libmpq__strerror(int32_t return_code)
{
    uint32_t index = 0u - (uint32_t)return_code;

    /* Only negative libmpq error codes and zero are valid table indexes. */
    if (return_code > 0 || index >= sizeof(libmpq_error_strings) / sizeof(libmpq_error_strings[0]))
        return NULL;

    /* Return the static string owned by the library. */
    return libmpq_error_strings[index];
}

/*
 * Create an MPQ archive through the internal writer implementation.
 * This public facade preserves the stable API while keeping archive layout
 * and file-table construction in the writer module.
 */
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

int32_t
libmpq__update_begin(mpq_update_s **update, const char *path)
{
    mpq_archive_s *archive = NULL;
    int32_t result = libmpq__update_transaction_begin(update, path);

    if (result != 0)
        return result;
    result = libmpq__archive_open(&archive, libmpq__update_path(*update), -1);
    if (archive != NULL) {
        int32_t close_result = libmpq__archive_close(archive);

        if (result == 0)
            result = close_result;
    }
    if (result != 0) {
        (void)libmpq__update_transaction_abort(*update);
        *update = NULL;
    }
    return result;
}

/* Begin an MPQE transaction with explicit caller authentication. */
int32_t
libmpq__update_begin_mpqe(
    mpq_update_s **update, const char *path, const uint8_t *auth_code, size_t auth_code_size
)
{
    return libmpq__update_transaction_begin_mpqe(update, path, auth_code, auth_code_size);
}

int32_t
libmpq__update_add_data(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    return libmpq__update_transaction_add(update, filename, data, size, NULL, options);
}

int32_t
libmpq__update_add_path(
    mpq_update_s *update, const char *filename, const char *source_path,
    const mpq_file_options_s *options
)
{
    if (source_path == NULL)
        return LIBMPQ_ERROR_EXIST;
    return libmpq__update_transaction_add(update, filename, NULL, 0, source_path, options);
}

int32_t
libmpq__update_replace_data(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    return libmpq__update_transaction_replace(update, filename, data, size, NULL, options);
}

int32_t
libmpq__update_replace_path(
    mpq_update_s *update, const char *filename, const char *source_path,
    const mpq_file_options_s *options
)
{
    return libmpq__update_transaction_replace(update, filename, NULL, 0, source_path, options);
}

int32_t
libmpq__update_remove(mpq_update_s *update, const char *filename)
{
    return libmpq__update_transaction_remove(update, filename);
}

int32_t
libmpq__update_rename(mpq_update_s *update, const char *old_filename, const char *new_filename)
{
    return libmpq__update_transaction_rename(update, old_filename, new_filename);
}

/* Exact update wrappers reuse the staged transaction engine. */
int32_t
libmpq__update_replace_data_identity(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform, const uint8_t *data,
    libmpq__off_t size, const mpq_file_options_s *options
)
{
    return libmpq__update_transaction_replace_identity(
        update, name, locale, platform, data, size, NULL, options
    );
}

/* Borrow a replacement path only for this synchronous staging call. */
int32_t
libmpq__update_replace_path_identity(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform, const char *path,
    const mpq_file_options_s *options
)
{
    if (path == NULL)
        return LIBMPQ_ERROR_EXIST;
    return libmpq__update_transaction_replace_identity(
        update, name, locale, platform, NULL, 0, path, options
    );
}

/* Remove a single exact identity, retaining any shared payload aliases. */
int32_t
libmpq__update_remove_identity(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform
)
{
    return libmpq__update_transaction_remove_identity(update, name, locale, platform);
}

/* Preserve the selected locale/platform while renaming one exact identity. */
int32_t
libmpq__update_rename_identity(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform, const char *new_name
)
{
    return libmpq__update_transaction_rename_identity(update, name, locale, platform, new_name);
}

int32_t
libmpq__update_commit(mpq_update_s *update)
{
    mpq_archive_s *archive = NULL;
    int32_t result;

    if (update == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_open(&archive, libmpq__update_path(update), -1);
    if (archive != NULL) {
        int32_t close_result = libmpq__archive_close(archive);

        if (result == 0)
            result = close_result;
    }
    if (result != 0) {
        (void)libmpq__update_transaction_abort(update);
        return result;
    }
    return libmpq__update_transaction_commit(update);
}

int32_t
libmpq__update_abort(mpq_update_s *update)
{
    return libmpq__update_transaction_abort(update);
}

int32_t
libmpq__patch_begin(mpq_patch_s **patch, const char *base_archive, const char *output_patch)
{
    return libmpq__patch_writer_begin(patch, base_archive, output_patch);
}

/* Keep public payload entry points in the Windows DLL-exporting translation unit. */
int32_t
libmpq__patch_payload_size(mpq_archive_s *archive, uint32_t file_number, libmpq__off_t *size)
{
    return libmpq__patch_reader_payload_size(archive, file_number, size);
}

int32_t
libmpq__patch_payload_read(
    mpq_archive_s *archive, uint32_t file_number, const char *filename, uint8_t *buffer,
    libmpq__off_t capacity, libmpq__off_t *transferred
)
{
    return libmpq__patch_reader_payload_read(
        archive, file_number, filename, buffer, capacity, transferred
    );
}

int32_t
libmpq__patch_begin_mpqe(
    mpq_patch_s **patch, const char *base_archive, const char *output_patch,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    return libmpq__patch_writer_begin_mpqe(
        patch, base_archive, output_patch, auth_code, auth_code_size
    );
}

/* Query the patch's owned writer without exposing its private archive. */
int32_t
libmpq__patch_raw_chunk_size_get(mpq_patch_s *patch, uint32_t *raw_chunk_size)
{
    return libmpq__patch_writer_get_raw_chunk_size(patch, raw_chunk_size);
}

int32_t
libmpq__patch_raw_chunk_size_set(mpq_patch_s *patch, uint32_t raw_chunk_size)
{
    return libmpq__patch_writer_set_raw_chunk_size(patch, raw_chunk_size);
}

int32_t
libmpq__patch_sign(
    mpq_patch_s *patch, uint32_t signature_type, const uint8_t *private_key, size_t private_key_size
)
{
    return libmpq__patch_writer_sign(patch, signature_type, private_key, private_key_size);
}

int32_t
libmpq__patch_add_data(
    mpq_patch_s *patch, const char *filename, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    return libmpq__patch_writer_add(patch, filename, data, size, options);
}

int32_t
libmpq__patch_add_path(
    mpq_patch_s *patch, const char *filename, const char *source_path,
    const mpq_file_options_s *options
)
{
    return libmpq__patch_writer_add_path(patch, filename, source_path, options);
}

int32_t
libmpq__patch_replace_data(
    mpq_patch_s *patch, const char *filename, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    return libmpq__patch_writer_replace(patch, filename, data, size, options);
}

int32_t
libmpq__patch_replace_path(
    mpq_patch_s *patch, const char *filename, const char *source_path,
    const mpq_file_options_s *options
)
{
    return libmpq__patch_writer_replace_path(patch, filename, source_path, options);
}

int32_t
libmpq__patch_remove(mpq_patch_s *patch, const char *filename)
{
    return libmpq__patch_writer_remove(patch, filename);
}

int32_t
libmpq__patch_finish(mpq_patch_s *patch)
{
    return libmpq__patch_writer_finish(patch);
}

int32_t
libmpq__patch_abort(mpq_patch_s *patch)
{
    return libmpq__patch_writer_abort(patch);
}

/*
 * Begin a streamed file through the internal writer implementation.
 * The returned opaque writer owns the in-progress file state until finish or
 * an error closes the stream.
 */
int32_t
libmpq__writer_begin(
    mpq_archive_s *archive, const char *name, libmpq__off_t size, const mpq_file_options_s *options,
    mpq_writer_s **out
)
{
    return libmpq__writer_file_begin(archive, name, size, options, out);
}

/*
 * Write one input range through the internal writer implementation.
 * The writer validates the declared file size and buffers or flushes sectors
 * according to the selected storage and compression options.
 */
int32_t
libmpq__writer_write(mpq_writer_s *writer, const uint8_t *buffer, libmpq__off_t size)
{
    return libmpq__writer_file_write(writer, buffer, size);
}

/*
 * Finish a streamed file through the internal writer implementation.
 * Finalization verifies that all declared bytes were supplied and publishes
 * the completed file entry in the archive tables.
 */
int32_t
libmpq__writer_finish(mpq_writer_s *writer)
{
    return libmpq__writer_file_finish(writer);
}

/*
 * Add an in-memory file through the internal writer implementation.
 * The convenience call performs begin, write, and finish operations while
 * retaining the same validation and compression behavior as streaming.
 */
int32_t
libmpq__archive_add_data(
    mpq_archive_s *archive, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    return libmpq__writer_file_add(archive, name, data, size, options);
}

/*
 * Add a filesystem file through the internal writer implementation.
 * The source is read in bounded chunks, so callers need not load the complete
 * file into memory before archive creation begins.
 */
int32_t
libmpq__archive_add_path(
    mpq_archive_s *archive, const char *name, const char *source, const mpq_file_options_s *options
)
{
    return libmpq__writer_file_add_path(archive, name, source, options);
}

/*
 * Open an MPQ archive from a path and optional embedded archive offset.
 * A sentinel offset enables embedded-header scanning, while an explicit offset
 * restricts parsing to the requested archive location.
 */
int32_t
libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{
    return libmpq__reader_archive_open_path(mpq_archive, mpq_filename, archive_offset);
}

int32_t
libmpq__archive_open_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const char *source_name
)
{
    return libmpq__reader_archive_open_io(
        mpq_archive, context, read_at, source_size, archive_offset, source_name
    );
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

int32_t
libmpq__archive_open_mpqe_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const uint8_t *auth_code,
    size_t auth_code_size, const char *source_name
)
{
    return libmpq__reader_archive_open_mpqe_io(
        mpq_archive, context, read_at, source_size, archive_offset, auth_code, auth_code_size,
        source_name
    );
}

/* Share the same private policy for ordinary and patch archive creation. */
int32_t
libmpq__archive_raw_chunk_size_set(mpq_archive_s *archive, uint32_t raw_chunk_size)
{
    return libmpq__writer_set_raw_chunk_size(archive, raw_chunk_size);
}

int32_t
libmpq__archive_raw_chunk_size_get(mpq_archive_s *archive, uint32_t *raw_chunk_size)
{
    if (raw_chunk_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    *raw_chunk_size = 0;
    if (archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_FOUR)
        return LIBMPQ_ERROR_FORMAT;
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR)
        *raw_chunk_size = archive->mpq_header_v4.raw_chunk_size;
    return 0;
}

/* Compose already-open inputs without extending their source lifetimes. */
int32_t
libmpq__archive_open_patch(
    mpq_archive_s **archive, mpq_archive_s *base, mpq_archive_s *const *patch_archives,
    const char *const *patch_prefixes, size_t patch_count
)
{
    return libmpq__patch_reader_open_archives(
        archive, base, patch_archives, patch_prefixes, patch_count
    );
}

/*
 * Reopen an archive with independent file I/O, metadata, and lazy caches.
 * Cloning rejects writer handles and verifies a path-backed source still
 * identifies the same file before reparsing it into a separate archive object.
 */
int32_t
libmpq__archive_clone(mpq_archive_s **clone, mpq_archive_s *source)
{
    if (clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    *clone = NULL;

    if (source == NULL || source->write_mode)
        return LIBMPQ_ERROR_EXIST;

    return libmpq__reader_archive_clone(clone, source);
}

/*
 * Close the archive file and release all metadata tables allocated during archive open.
 * Writer handles are finalized before their archive storage is freed, while
 * reader-side cached block offsets are released entry by entry.
 */
int32_t
libmpq__archive_close(mpq_archive_s *mpq_archive)
{
    uint32_t i;
    int32_t result = 0;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;

    if (mpq_archive->write_mode) {

        /* Writer closure must serialize tables before releasing writer storage. */
        result = libmpq__writer_finalize(mpq_archive);
        libmpq__writer_file_abort(mpq_archive->write_current);
        if (result == 0 && mpq_archive->write_mpqe)
            result = libmpq__writer_finalize_mpqe(mpq_archive);
        if (mpq_archive->fp != NULL && fclose(mpq_archive->fp) < 0 && result == 0)
            result = LIBMPQ_ERROR_CLOSE;
        libmpq__writer_mpqe_cleanup(mpq_archive);
        libmpq__rsa_clear(
            mpq_archive->write_signature_key, sizeof(mpq_archive->write_signature_key)
        );
        libmpq__rsa_clear(
            mpq_archive->write_strong_signature_key, sizeof(mpq_archive->write_strong_signature_key)
        );
        for (i = 0; i < mpq_archive->write_capacity; i++)
            free(mpq_archive->write_names ? mpq_archive->write_names[i] : NULL);
        libmpq__writer_identity_free(mpq_archive);
        free(mpq_archive->write_names);
        free(mpq_archive->write_locales);
        free(mpq_archive->write_platforms);
        libmpq__attributes_free(mpq_archive);
        free(mpq_archive->mpq_hash);
        free(mpq_archive->mpq_entry);
        free(mpq_archive->classic_entry_indices);
        free(mpq_archive->mpq_block);
        free(mpq_archive->mpq_block_ex);
        free(mpq_archive->filename);
        free(mpq_archive->write_mpqe_destination);
        free(mpq_archive->write_mpqe_output_path);
        free(mpq_archive);
        return result;
    }

    result = libmpq__source_close(mpq_archive->source);

    for (i = 0; i < mpq_archive->entry_count; i++) {
        if (mpq_archive->mpq_file[i] != NULL) {
            free(mpq_archive->mpq_file[i]->packed_offset);
            free(mpq_archive->mpq_file[i]);
        }
    }

    free(mpq_archive->mpq_map);
    libmpq__attributes_free(mpq_archive);
    free(mpq_archive->mpq_file);
    free(mpq_archive->mpq_hash);
    free(mpq_archive->mpq_entry);
    free(mpq_archive->classic_entry_indices);
    free(mpq_archive->bet_entry_indices);
    free(mpq_archive->het_data);
    free(mpq_archive->bet_data);
    free(mpq_archive->mpq_block);
    free(mpq_archive->mpq_block_ex);
    free(mpq_archive->filename);
    free(mpq_archive);

    return result;
}

/*
 * Return the sum of packed sizes for all files in the archive block table.
 * The caller supplies an accumulator, allowing this query to preserve the
 * library's existing additive API behavior.
 */
int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size)
{

    /* Running total across all block-table entries. */
    uint32_t i;
    libmpq__off_t total;

    if (mpq_archive == NULL || packed_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    total = *packed_size;
    for (i = 0; i < mpq_archive->files; i++) {
        uint64_t amount;
        if (libmpq__reader_validate_file_number(mpq_archive, i) != 0)
            return LIBMPQ_ERROR_EXIST;
        amount = mpq_archive->mpq_entry[mpq_archive->mpq_map[i].entry_index].packed_size;
        if (amount > INT64_MAX || total > INT64_MAX - (libmpq__off_t)amount)
            return LIBMPQ_ERROR_SIZE;
        total += (libmpq__off_t)amount;
    }
    *packed_size = total;

    return 0;
}

/*
 * Return the sum of unpacked sizes for all files in the archive block table.
 * Only live public file-map entries are counted; unused block-table capacity
 * does not contribute to the reported total.
 */
int32_t
libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, libmpq__off_t *unpacked_size)
{

    /* Running total across all block-table entries. */
    uint32_t i;
    libmpq__off_t total;

    if (mpq_archive == NULL || unpacked_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    total = *unpacked_size;
    for (i = 0; i < mpq_archive->files; i++) {
        uint64_t amount;
        if (libmpq__reader_validate_file_number(mpq_archive, i) != 0)
            return LIBMPQ_ERROR_EXIST;
        amount = mpq_archive->mpq_entry[mpq_archive->mpq_map[i].entry_index].unpacked_size;
        if (amount > INT64_MAX || total > INT64_MAX - (libmpq__off_t)amount)
            return LIBMPQ_ERROR_SIZE;
        total += (libmpq__off_t)amount;
    }
    *unpacked_size = total;

    return 0;
}

/*
 * Return the byte offset where the MPQ archive starts in the backing file.
 * Embedded archives therefore report their discovered start rather than zero.
 */
int32_t
libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset)
{
    *offset = mpq_archive->archive_offset;

    return 0;
}

/*
 * Return the MPQ archive format version stored in the header.
 * The internal zero-based version is converted to the public one-based API
 * value before being written to the caller's output.
 */
int32_t
libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version)
{
    *version = mpq_archive->mpq_header.version + 1;

    return 0;
}

/*
 * Return the number of valid file entries discovered while opening the archive.
 * This is the compact public count, not the reserved block-table capacity.
 */
int32_t
libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files)
{
    *files = mpq_archive->files;

    return 0;
}

/*
 * Return the packed size of a canonical entry by public file number.
 * The public file number is validated and translated through the compact map
 * before reading the corresponding canonical entry.
 */
int32_t
libmpq__file_size_packed(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *packed_size
)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *packed_size =
        mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].packed_size;

    return 0;
}

/*
 * Return the unpacked size of a canonical entry by public file number.
 * Invalid compact file numbers are rejected before any archive metadata is
 * accessed.
 */
int32_t
libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *unpacked_size =
        mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].unpacked_size;

    return 0;
}

/*
 * Return the file data offset relative to the start of the archive.
 * MPQ v2 high offset words are combined with the legacy low word to produce
 * the complete offset visible through the public API.
 */
int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    *offset = mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].offset;

    return 0;
}

/*
 * Return the number of blocks needed to store the selected file.
 * The reader distinguishes single-unit files from sectorized entries and
 * applies the archive sector size for the latter.
 */
int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks)
{
    if (blocks != NULL)
        *blocks = 0;
    if (mpq_archive == NULL || blocks == NULL ||
        libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    /* The sector reader cannot consume lengths beyond its 32-bit offset domain. */
    const mpq_entry_s *entry =
        &mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index];
    if (entry->packed_size > UINT32_MAX || entry->unpacked_size > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;

    *blocks = libmpq__reader_count_file_blocks(mpq_archive, file_number);

    return 0;
}

/* Return canonical entry flags without reading or modifying payload data. */
int32_t
libmpq__file_flags(mpq_archive_s *archive, uint32_t file_number, uint32_t *flags)
{
    if (flags == NULL)
        return LIBMPQ_ERROR_EXIST;
    *flags = 0;
    if (archive == NULL || libmpq__reader_validate_file_number(archive, file_number) < 0)
        return LIBMPQ_ERROR_EXIST;

    *flags = archive->mpq_entry[archive->mpq_map[file_number].entry_index].flags;
    return 0;
}

/*
 * Calculate the three Storm hashes used to identify an MPQ file name.
 * Each output corresponds to a distinct hash-table phase used during MPQ
 * name lookup and collision probing.
 */
void
libmpq__file_hash(const char *filename, uint32_t *hash1, uint32_t *hash2, uint32_t *hash3)
{
    *hash1 = libmpq__crypto_hash_string(filename, 0x0);
    *hash2 = libmpq__crypto_hash_string(filename, 0x100);
    *hash3 = libmpq__crypto_hash_string(filename, 0x200);
}

/*
 * Resolve a precomputed MPQ file-name hash to a public file number.
 * The first hash selects a slot and linear probing continues until the stored
 * pair matches or the table wraps without finding the file.
 */
int32_t
libmpq__file_number_from_hash(
    mpq_archive_s *mpq_archive, uint32_t hash1, uint32_t hash2, uint32_t hash3, uint32_t *number
)
{

    /* Hash table probe state and archive hash-table size. */
    uint32_t i;
    uint32_t ht_count;
    uint32_t block_table_index;
    uint32_t entry_index;

    ht_count = mpq_archive->mpq_header.hash_table_count;
    if (ht_count == 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    hash1 %= ht_count;

    /* The first hash selects the initial probe slot; collisions use linear probing. */
    for (i = hash1; mpq_archive->mpq_hash[i].block_table_index != LIBMPQ_HASH_FREE;
         i = (i + 1) % ht_count) {
        if (mpq_archive->mpq_hash[i].block_table_index != LIBMPQ_HASH_DELETED &&
            mpq_archive->mpq_hash[i].hash_a == hash2 && mpq_archive->mpq_hash[i].hash_b == hash3) {
            block_table_index = mpq_archive->mpq_hash[i].block_table_index;
            if (libmpq__entry_index_from_classic(mpq_archive, block_table_index, &entry_index) !=
                    0 ||
                (mpq_archive->mpq_entry[entry_index].flags & LIBMPQ_FLAG_EXISTS) == 0) {
                return LIBMPQ_ERROR_FORMAT;
            }
            *number = mpq_archive->mpq_entry[entry_index].file_number;
            if (*number >= mpq_archive->files ||
                mpq_archive->mpq_map[*number].entry_index != entry_index) {
                return LIBMPQ_ERROR_FORMAT;
            }

            return 0;
        }

        if ((i + 1) % ht_count == hash1) {
            break;
        }
    }

    return LIBMPQ_ERROR_EXIST;
}

/* Confirm the hash and skip non-live BET rows without masking malformed mappings. */
static int32_t
api_bet_match(void *context, uint64_t bet_index, uint64_t hash, int *matches)
{
    mpq_archive_s *archive = context;
    uint32_t index;
    int32_t result = libmpq__bet_match(&archive->mpq_bet, bet_index, hash, matches);
    if (result != 0 || !*matches)
        return result;
    result = libmpq__entry_index_from_bet(archive, bet_index, &index);
    if (result != 0)
        return result;
    *matches = (archive->mpq_entry[index].flags & LIBMPQ_FLAG_EXISTS) != 0;
    return 0;
}

/* Validate canonical mappings without inferring filename-specific provenance. */
static int32_t
api_identity_entry(mpq_archive_s *a, uint32_t index, mpq_file_identity_s *out)
{
    const mpq_entry_s *entry;
    uint32_t mapped;

    if (a->mpq_entry == NULL || index >= a->entry_count)
        return LIBMPQ_ERROR_FORMAT;
    entry = &a->mpq_entry[index];
    if (!(entry->flags & LIBMPQ_FLAG_EXISTS))
        return LIBMPQ_ERROR_EXIST;
    if (!entry->source_mask || (entry->source_mask & ~3u) || entry->file_number >= a->files ||
        entry->file_number >= a->entry_count || a->mpq_map == NULL ||
        a->mpq_map[entry->file_number].entry_index != index)
        return LIBMPQ_ERROR_FORMAT;
    if ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) &&
        (libmpq__entry_index_from_classic(a, entry->classic_source_index, &mapped) != 0 ||
         mapped != index))
        return LIBMPQ_ERROR_FORMAT;
    if ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) &&
        (libmpq__entry_index_from_bet(a, entry->bet_source_index, &mapped) != 0 || mapped != index))
        return LIBMPQ_ERROR_FORMAT;
    out->file_number = entry->file_number;
    return 0;
}

typedef struct
{
    mpq_archive_s *archive;
    uint32_t index;
    uint8_t found;
} api_identity_bet_s;

/* Inspect all reachable candidates using the existing validated HET probe loop. */
static int32_t
api_identity_bet_match(void *context, uint64_t row, uint64_t hash, int *matches)
{
    api_identity_bet_s *state = context;
    int32_t result = api_bet_match(state->archive, row, hash, matches);

    if (result != 0 || !*matches)
        return result;
    if (state->found)
        return LIBMPQ_ERROR_FORMAT;
    result = libmpq__entry_index_from_bet(state->archive, row, &state->index);
    if (result != 0)
        return result;
    state->found = 1;
    *matches = 0;
    return 0;
}

/* Sort a temporary list only to detect duplicate locale/platform identities. */
static int
api_identity_compare(const void *left, const void *right)
{
    const mpq_file_identity_s *a = left;
    const mpq_file_identity_s *b = right;

    if (a->locale != b->locale)
        return a->locale < b->locale ? -1 : 1;
    return a->platform < b->platform ? -1 : a->platform != b->platform;
}

/* Share strict resolution without altering the existing first-hit lookup. */
static int32_t
api_identity_lookup(
    mpq_archive_s *a, const char *name, uint32_t ordinal, uint16_t locale, uint16_t platform,
    uint8_t exact, mpq_file_identity_s *out
)
{
    api_identity_bet_s bet = { a, 0, 0 };
    mpq_file_identity_s *rows = NULL;
    mpq_file_identity_s selected = { 0 };
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    uint32_t count;
    uint32_t start = 0;
    uint32_t probes = 0;
    uint32_t capacity = 0;
    uint32_t used = 0;
    uint8_t found = 0;
    int32_t result = LIBMPQ_ERROR_EXIST;

    if (a == NULL || name == NULL || *name == '\0')
        return LIBMPQ_ERROR_EXIST;
    if (a->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    count = a->mpq_header.hash_table_count;
    if ((a->het_data == NULL) != (a->bet_data == NULL))
        return LIBMPQ_ERROR_FORMAT;
    if (count && a->mpq_hash == NULL)
        return LIBMPQ_ERROR_FORMAT;
    libmpq__file_hash(name, &hash1, &hash2, &hash3);
    if (count) {
        uint32_t slot = start = hash1 % count;

        while (probes < count) {
            const mpq_hash_s *row = &a->mpq_hash[slot];

            if (row->block_table_index == LIBMPQ_HASH_FREE)
                break;
            if (row->block_table_index != LIBMPQ_HASH_DELETED && row->hash_a == hash2 &&
                row->hash_b == hash3)
                capacity++;
            probes++;
            slot = slot == count - 1 ? 0 : slot + 1;
        }
    }
    if (capacity) {
        if ((uint64_t)capacity * sizeof(*rows) > SIZE_MAX)
            return LIBMPQ_ERROR_SIZE;
        rows = calloc(capacity, sizeof(*rows));
        if (rows == NULL)
            return LIBMPQ_ERROR_MALLOC;
    }

    /* Reachability follows the probe chain, but enumeration uses original slot order. */
    for (uint32_t slot = 0; slot < count; slot++) {
        const mpq_hash_s *row = &a->mpq_hash[slot];
        uint32_t distance = slot >= start ? slot - start : count - start + slot;
        uint32_t index;

        if (distance >= probes || row->block_table_index == LIBMPQ_HASH_DELETED ||
            row->hash_a != hash2 || row->hash_b != hash3)
            continue;
        if (rows == NULL || used >= capacity) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (libmpq__entry_index_from_classic(a, row->block_table_index, &index) != 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        result = api_identity_entry(a, index, &rows[used]);
        if (result == LIBMPQ_ERROR_EXIST)
            continue;
        if (result != 0)
            goto done;
        rows[used].flags = LIBMPQ_IDENTITY_CLASSIC;
        rows[used].locale = row->locale;
        rows[used].platform = row->platform;
        used++;
    }
    if (a->het_data != NULL) {
        uint64_t ignored;

        if (a->bet_data == NULL || a->mpq_het.header.name_hash_bit_size != 64 ||
            a->mpq_bet.header.name_hash2_size != 56 || strlen(name) > LIBMPQ_HET_FILENAME_LIMIT) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        result = libmpq__het_lookup(
            &a->mpq_het, name, a->mpq_bet.header.entry_count, api_identity_bet_match, &bet, &ignored
        );
        if (result != LIBMPQ_ERROR_EXIST) {
            if (result == 0)
                result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (bet.found) {
            mpq_file_identity_s checked = { 0 };

            result = api_identity_entry(a, bet.index, &checked);
            if (result != 0)
                goto done;
        }
    }
    if (used) {
        uint8_t reconciled = !bet.found;

        for (uint32_t i = 0; i < used; i++) {
            if (bet.found && a->mpq_map[rows[i].file_number].entry_index == bet.index) {
                rows[i].flags |= LIBMPQ_IDENTITY_BET;
                reconciled = 1;
            }
            if ((!exact && i == ordinal) ||
                (exact && rows[i].locale == locale && rows[i].platform == platform)) {
                selected = rows[i];
                found = 1;
            }
        }
        if (!reconciled) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        qsort(rows, used, sizeof(*rows), api_identity_compare);
        for (uint32_t i = 1; i < used; i++) {
            if (api_identity_compare(&rows[i - 1], &rows[i]) == 0) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
    } else if (bet.found) {
        result = api_identity_entry(a, bet.index, &selected);
        if (result != 0)
            goto done;

        /* This name has only a BET identity, even if its payload has classic aliases. */
        selected.flags = LIBMPQ_IDENTITY_BET;
        found = exact ? locale == 0 && platform == 0 : ordinal == 0;
    }
    result = found ? 0 : LIBMPQ_ERROR_EXIST;
    if (result == 0)
        *out = selected;
done:
    free(rows);
    return result;
}

/* Return one indexed identity without changing ordinary name lookup. */
int32_t
libmpq__file_identity(
    mpq_archive_s *archive, const char *filename, uint32_t identity_index,
    mpq_file_identity_s *identity
)
{
    if (identity == NULL)
        return LIBMPQ_ERROR_EXIST;
    memset(identity, 0, sizeof(*identity));
    return api_identity_lookup(archive, filename, identity_index, 0, 0, 0, identity);
}

/* Select only an explicitly stored identity, without locale-neutral fallback. */
int32_t
libmpq__file_number_identity(
    mpq_archive_s *archive, const char *filename, uint16_t locale, uint16_t platform,
    uint32_t *number
)
{
    mpq_file_identity_s identity = { 0 };
    int32_t result;

    if (number == NULL)
        return LIBMPQ_ERROR_EXIST;
    *number = 0;
    result = api_identity_lookup(archive, filename, 0, locale, platform, 1, &identity);
    if (result == 0)
        *number = identity.file_number;
    return result;
}

/* Resolve on the owned clone while retaining the supplied physical encryption name. */
int32_t
libmpq__stream_open_name_identity(
    mpq_archive_s *archive, const char *filename, uint16_t locale, uint16_t platform,
    mpq_stream_s **stream
)
{
    return libmpq__reader_stream_open_name_identity(archive, filename, locale, platform, stream);
}

/*
 * Resolve a name through validated HET/BET first, with classic fallback on a miss.
 * The name is hashed with all three Storm phases before the collision-aware
 * lookup is delegated to the precomputed-hash helper.
 */
int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number)
{
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    int32_t result;
    if (mpq_archive == NULL || filename == NULL || number == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (mpq_archive->het_data != NULL) {
        uint64_t bet_index;
        uint32_t index;
        result = libmpq__het_lookup(
            &mpq_archive->mpq_het, filename, mpq_archive->mpq_bet.header.entry_count, api_bet_match,
            mpq_archive, &bet_index
        );
        if (result == 0) {
            result = libmpq__entry_index_from_bet(mpq_archive, bet_index, &index);
            if (result != 0)
                return result;
            *number = mpq_archive->mpq_entry[index].file_number;
            if (*number >= mpq_archive->files || mpq_archive->mpq_map[*number].entry_index != index)
                return LIBMPQ_ERROR_FORMAT;
            return 0;
        }
        if (result != LIBMPQ_ERROR_EXIST)
            return result;
    }

    libmpq__file_hash(filename, &hash1, &hash2, &hash3);
    return libmpq__file_number_from_hash(mpq_archive, hash1, hash2, hash3, number);
}

/* Complete reads scope their offset cache inside the reader. */
int32_t
libmpq__file_read(
    mpq_archive_s *archive, uint32_t number, uint8_t *buffer, libmpq__off_t size,
    libmpq__off_t *transferred
)
{
    return libmpq__reader_file_read(archive, number, buffer, size, transferred);
}

int32_t
libmpq__stream_open(mpq_archive_s *archive, uint32_t file_number, mpq_stream_s **stream)
{
    return libmpq__reader_stream_open(archive, file_number, stream);
}

int32_t
libmpq__stream_open_name(mpq_archive_s *archive, const char *filename, mpq_stream_s **stream)
{
    return libmpq__reader_stream_open_name(archive, filename, stream);
}

int32_t
libmpq__stream_read(
    mpq_stream_s *stream, uint8_t *buffer, libmpq__off_t size, libmpq__off_t *transferred
)
{
    return libmpq__reader_stream_read(stream, buffer, size, transferred);
}

int32_t
libmpq__stream_seek(mpq_stream_s *stream, libmpq__off_t offset, int32_t origin)
{
    return libmpq__reader_stream_seek(stream, offset, origin);
}

int32_t
libmpq__stream_tell(mpq_stream_s *stream, libmpq__off_t *position)
{
    return libmpq__reader_stream_tell(stream, position);
}

int32_t
libmpq__stream_size(mpq_stream_s *stream, libmpq__off_t *size)
{
    return libmpq__reader_stream_size(stream, size);
}

int32_t
libmpq__stream_close(mpq_stream_s *stream)
{
    return libmpq__reader_stream_close(stream);
}

/*
 * Return one block's unpacked size directly from archive metadata.
 * Full sectors use the archive sector size, while the final sector is reduced
 * to the remaining file bytes and single-unit files use their full size.
 */
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

    if ((mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].flags &
         LIBMPQ_FLAG_SINGLE) != 0) {

        /* A single-unit entry has one logical block containing the whole file. */
        *unpacked_size =
            mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].unpacked_size;
    }

    if ((mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index].flags &
         LIBMPQ_FLAG_SINGLE) == 0) {

        /* Every non-final sector is full-sized; only the tail uses a remainder. */
        if (block_number < libmpq__reader_count_file_blocks(mpq_archive, file_number) - 1) {
            *unpacked_size = mpq_archive->block_size;
        } else {
            *unpacked_size = mpq_archive->mpq_entry[mpq_archive->mpq_map[file_number].entry_index]
                                 .unpacked_size -
                             mpq_archive->block_size * block_number;
        }
    }

    return 0;
}

/* Query stored sector bytes through the reader's offset-table lifecycle. */
int32_t
libmpq__block_size_packed(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, libmpq__off_t *packed_size
)
{
    return libmpq__reader_block_size_packed(archive, file_number, block_number, packed_size);
}

/* Report the serialized method through the reader's packed-sector inspection. */
int32_t
libmpq__block_compression(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint32_t *compression
)
{
    return libmpq__reader_block_compression(archive, file_number, block_number, compression);
}

/* Normal block reads never enable explicit checksum verification. */
int32_t
libmpq__block_read(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
)
{
    return libmpq__reader_block_read(
        archive, file_number, block_number, out_buf, out_size, transferred, NULL, NULL, NULL
    );
}
