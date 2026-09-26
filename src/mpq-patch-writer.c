/*
 *  mpq-patch-writer.c -- private MPQ whole-file patch archive creation.
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

#include "mpq-patch-writer.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-patch-bsd0.h"
#include "mpq-patch.h"
#include "mpq-reader.h"
#include "mpq-writer.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LIBMPQ_PATCH_COPY_HEADER_SIZE 68u
#define LIBMPQ_PATCH_WRITER_CAPACITY 1024u

struct mpq_patch
{
    mpq_archive_s *base;
    mpq_archive_s *archive;
    mpq_directory_s *directory;
    char *destination;
    char *temporary;
};

/* The patch archive itself owns no references to the source archive. */
static int32_t
patch_writer_cleanup(mpq_patch_writer_s *state, uint8_t publish)
{
    int32_t result = LIBMPQ_SUCCESS;
    int32_t cleanup;

    if (state->archive != NULL) {
        result = libmpq__archive_close(state->archive);
        state->archive = NULL;
    }
    if (state->base != NULL) {
        cleanup = libmpq__archive_close(state->base);
        if (result == LIBMPQ_SUCCESS)
            result = cleanup;
    }
    if (publish && result == LIBMPQ_SUCCESS) {
        result = libmpq__directory_replace(state->directory, state->temporary, state->destination);
    }
    if (!publish || result != LIBMPQ_SUCCESS) {
        cleanup = libmpq__directory_remove(state->directory, state->temporary);
        if (result == LIBMPQ_SUCCESS)
            result = cleanup;
    }
    if (state->directory != NULL)
        libmpq__directory_close(state->directory);
    free(state->destination);
    free(state->temporary);
    free(state);
    return result;
}

/* Resolve a unique named base identity, retaining its locale and platform. */
static int32_t
patch_writer_member(
    mpq_patch_writer_s *state, const char *name, uint32_t *number, uint16_t *locale,
    uint16_t *platform
)
{
    uint32_t hash1;
    uint32_t hash_a;
    uint32_t hash_b;
    uint32_t block;
    uint32_t found = UINT32_MAX;
    int32_t result;

    if (name == NULL || name[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__file_number(state->base, name, number);
    if (result != LIBMPQ_SUCCESS)
        return result;
    block = state->base->mpq_map[*number].block_table_indices;
    libmpq__file_hash(name, &hash1, &hash_a, &hash_b);
    for (uint32_t i = 0; i < state->base->mpq_header.hash_table_count; i++) {
        const mpq_hash_s *entry = &state->base->mpq_hash[i];

        if (entry->block_table_index == block && entry->hash_a == hash_a &&
            entry->hash_b == hash_b) {
            if (found != UINT32_MAX)
                return LIBMPQ_ERROR_FORMAT;
            found = i;
        }
    }
    if (found == UINT32_MAX)
        return LIBMPQ_ERROR_FORMAT;
    *locale = state->base->mpq_hash[found].locale;
    *platform = state->base->mpq_hash[found].platform;
    return LIBMPQ_SUCCESS;
}

/* Read a named base member with its filename-derived decryption key. */
static int32_t
patch_writer_read_base(
    mpq_patch_writer_s *state, const char *name, uint32_t number, uint8_t **data, size_t *size
)
{
    libmpq__off_t length = 0;
    libmpq__off_t transferred = 0;
    uint8_t *bytes = NULL;
    int32_t result;

    *data = NULL;
    *size = 0;
    result = libmpq__file_size_unpacked(state->base, number, &length);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (length < 0 || (uint64_t)length > UINT32_MAX || (uint64_t)length > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    bytes = malloc(length == 0 ? 1 : (size_t)length);
    if (bytes == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__reader_offsets_acquire(state->base, number, name);
    if (result == LIBMPQ_SUCCESS) {
        result = libmpq__file_read(state->base, number, bytes, length, &transferred);
        if (result == LIBMPQ_SUCCESS && transferred != length)
            result = LIBMPQ_ERROR_READ;
        {
            int32_t release = libmpq__reader_offsets_release(state->base, number);

            if (result == LIBMPQ_SUCCESS)
                result = release;
        }
    }
    if (result == LIBMPQ_SUCCESS) {
        *data = bytes;
        *size = (size_t)length;
        bytes = NULL;
    }
    free(bytes);
    return result;
}

/* Build one complete PTCH candidate without changing its transform afterward. */
static int32_t
patch_writer_build_payload(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    const uint8_t *transform, size_t transform_size, size_t patch_stream_size, uint8_t use_bsd0,
    uint8_t **payload, size_t *payload_size
)
{
    static const uint8_t ptch_tag[4] = { 'P', 'T', 'C', 'H' };
    static const uint8_t md5_tag[4] = { 'M', 'D', '5', '_' };
    static const uint8_t xfrm_tag[4] = { 'X', 'F', 'R', 'M' };
    static const uint8_t copy_tag[4] = { 'C', 'O', 'P', 'Y' };
    static const uint8_t bsd0_tag[4] = { 'B', 'S', 'D', '0' };
    size_t encoded_size;
    uint8_t *raw;
    uint8_t *patch;
    mpq_md5_s md5;

    *payload = NULL;
    *payload_size = 0;
    if (transform_size > UINT32_MAX - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
        patch_stream_size > UINT32_MAX - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
        transform_size > SIZE_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE)
        return LIBMPQ_ERROR_SIZE;
    encoded_size = LIBMPQ_PATCH_COPY_HEADER_SIZE + transform_size;
    raw = calloc(1, LIBMPQ_PATCH_INFO_SIZE + encoded_size);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    patch = raw + LIBMPQ_PATCH_INFO_SIZE;
    libmpq__store_le32(raw, LIBMPQ_PATCH_INFO_SIZE);
    libmpq__store_le32(raw + 4, 0x80000000u);
    libmpq__store_le32(raw + 8, (uint32_t)encoded_size);
    memcpy(patch, ptch_tag, sizeof(ptch_tag));
    libmpq__store_le32(patch + 4, (uint32_t)(LIBMPQ_PATCH_COPY_HEADER_SIZE + patch_stream_size));
    libmpq__store_le32(patch + 8, (uint32_t)before_size);
    libmpq__store_le32(patch + 12, (uint32_t)after_size);
    memcpy(patch + 16, md5_tag, sizeof(md5_tag));
    libmpq__store_le32(patch + 20, 40);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, before, before_size);
    libmpq__md5_final(&md5, patch + 24);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, after, after_size);
    libmpq__md5_final(&md5, patch + 40);
    memcpy(patch + 56, xfrm_tag, sizeof(xfrm_tag));
    libmpq__store_le32(patch + 60, (uint32_t)transform_size + 12);
    memcpy(patch + 64, use_bsd0 ? bsd0_tag : copy_tag, sizeof(copy_tag));
    if (transform_size != 0)
        memcpy(patch + LIBMPQ_PATCH_COPY_HEADER_SIZE, transform, transform_size);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, patch, encoded_size);
    libmpq__md5_final(&md5, raw + 12);

    *payload = raw;
    *payload_size = LIBMPQ_PATCH_INFO_SIZE + encoded_size;
    return LIBMPQ_SUCCESS;
}

/* Select BSD0 only when its complete candidate is smaller and decodes correctly. */
static int32_t
patch_writer_payload(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    uint8_t **payload, size_t *payload_size
)
{
    size_t transform_size = 0;
    size_t patch_stream_size = 0;
    size_t verified_size = 0;
    uint8_t *transform = NULL;
    uint8_t *candidate = NULL;
    uint8_t *best = NULL;
    uint8_t *verified = NULL;
    size_t candidate_size = 0;
    size_t best_size;
    int32_t result;

    *payload = NULL;
    *payload_size = 0;
    if (before_size > UINT32_MAX ||
        after_size > UINT32_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
        after_size > SIZE_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE)
        return LIBMPQ_ERROR_SIZE;
    best_size = LIBMPQ_PATCH_INFO_SIZE + LIBMPQ_PATCH_COPY_HEADER_SIZE + after_size;
    if (after_size != 0) {
        for (uint8_t splice = 0; splice < 2; splice++) {
            result = libmpq__patch_bsd0_encode(
                before, before_size, after, after_size, splice, &transform, &transform_size,
                &patch_stream_size
            );
            if (result != LIBMPQ_SUCCESS) {
                free(best);
                return result;
            }
            if (transform == NULL)
                continue;
            if (patch_stream_size > UINT32_MAX - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
                transform_size > UINT32_MAX - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
                transform_size >
                    SIZE_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE) {
                free(transform);
                transform = NULL;
                continue;
            }
            result = patch_writer_build_payload(
                before, before_size, after, after_size, transform, transform_size,
                patch_stream_size, 1, &candidate, &candidate_size
            );
            free(transform);
            transform = NULL;
            if (result != LIBMPQ_SUCCESS) {
                free(best);
                return result;
            }
            result = libmpq__patch_apply(
                before, before_size, candidate + LIBMPQ_PATCH_INFO_SIZE,
                candidate_size - LIBMPQ_PATCH_INFO_SIZE, &verified, &verified_size
            );
            if (result == LIBMPQ_SUCCESS && verified_size == after_size && verified != NULL &&
                memcmp(verified, after, after_size) == 0 && candidate_size < best_size) {
                free(best);
                best = candidate;
                best_size = candidate_size;
                candidate = NULL;
            }
            free(verified);
            verified = NULL;
            free(candidate);
            candidate = NULL;
        }
    }
    if (best != NULL) {
        *payload = best;
        *payload_size = best_size;
        return LIBMPQ_SUCCESS;
    }
    return patch_writer_build_payload(
        before, before_size, after, after_size, after, after_size, after_size, 0, payload,
        payload_size
    );
}

/* Refuse to publish a patch over its own base archive. */
static int32_t
patch_writer_check_destination(mpq_patch_writer_s *state)
{
    FILE *existing = libmpq__directory_file_open(state->directory, state->destination, "rb");
    uint64_t device;
    uint64_t inode;
    int32_t result = LIBMPQ_SUCCESS;

    if (existing == NULL)
        return LIBMPQ_SUCCESS;
    if (state->base->file_identity_valid) {
        result = libmpq__file_identity(existing, &device, &inode);
        if (result == LIBMPQ_SUCCESS && device == state->base->file_device &&
            inode == state->base->file_inode)
            result = LIBMPQ_ERROR_FORMAT;
    }
    if (fclose(existing) != 0 && result == LIBMPQ_SUCCESS)
        result = LIBMPQ_ERROR_CLOSE;
    return result;
}

/* Create a same-directory temporary patch archive without touching its target. */
int32_t
libmpq__patch_writer_begin(
    mpq_patch_writer_s **patch_writer, const char *base_path, const char *patch_path
)
{
    mpq_patch_writer_s *state = NULL;
    mpq_archive_create_options_s options;
    FILE *temporary_file = NULL;
    char *absolute = NULL;
    int32_t result;

    if (patch_writer == NULL)
        return LIBMPQ_ERROR_EXIST;
    *patch_writer = NULL;
    if (base_path == NULL || patch_path == NULL)
        return LIBMPQ_ERROR_EXIST;
    state = calloc(1, sizeof(*state));
    if (state == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__archive_open(&state->base, base_path, 0);
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    if (state->base->archive_offset != 0 ||
        state->base->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_TWO) {
        result = LIBMPQ_ERROR_FORMAT;
        goto fail;
    }
    absolute = libmpq__file_absolute_path(patch_path);
    if (absolute == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto fail;
    }
    result = libmpq__directory_open(absolute, &state->directory, &state->destination);
    free(absolute);
    absolute = NULL;
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    result = patch_writer_check_destination(state);
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    result = libmpq__directory_temporary(
        state->directory, ".libmpq-patch-write-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1,
        &state->temporary, &temporary_file
    );
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    options.version = state->base->mpq_header.version;
    options.max_files = LIBMPQ_PATCH_WRITER_CAPACITY;
    options.sector_size = state->base->block_size;
    options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_PATCH_BIT;
    result = libmpq__writer_archive_create_file(
        &state->archive, state->temporary, temporary_file, &options
    );
    temporary_file = NULL;
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    state->archive->write_patch_mode = 1;
    *patch_writer = state;
    return LIBMPQ_SUCCESS;

fail:
    free(absolute);
    if (temporary_file != NULL)
        (void)fclose(temporary_file);
    if (state->temporary != NULL)
        (void)patch_writer_cleanup(state, 0);
    else {
        if (state->base != NULL)
            (void)libmpq__archive_close(state->base);
        if (state->directory != NULL)
            libmpq__directory_close(state->directory);
        free(state->destination);
        free(state);
    }
    return result;
}

/* Stage a named replacement, falling back to COPY unless BSD0 is smaller. */
int32_t
libmpq__patch_writer_replace(
    mpq_patch_writer_s *state, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    uint8_t *before = NULL;
    uint8_t *payload = NULL;
    size_t before_size = 0;
    size_t payload_size = 0;
    uint32_t number;
    uint32_t block;
    uint16_t locale;
    uint16_t platform;
    int32_t result;

    if (state == NULL || (data == NULL && size != 0))
        return LIBMPQ_ERROR_EXIST;
    if (size < 0 ||
        (uint64_t)size > UINT32_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
        (uint64_t)size > SIZE_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE)
        return LIBMPQ_ERROR_SIZE;
    result = patch_writer_member(state, name, &number, &locale, &platform);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (options != NULL) {
        if (options->locale != locale || options->platform != platform ||
            (options->flags &
             ~(LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
               LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_SECTOR_CRC)) != 0)
            return LIBMPQ_ERROR_FORMAT;
        storage = *options;
    } else {
        storage.locale = locale;
        storage.platform = platform;
    }
    result = patch_writer_read_base(state, name, number, &before, &before_size);
    if (result == LIBMPQ_SUCCESS)
        result =
            patch_writer_payload(before, before_size, data, (size_t)size, &payload, &payload_size);
    if (result == LIBMPQ_SUCCESS && options == NULL &&
        payload_size > state->archive->write_sector_size)
        storage.flags = 0;

    if (result == LIBMPQ_SUCCESS)
        result = libmpq__writer_patch_file_add(
            state->archive, name, payload, LIBMPQ_PATCH_INFO_SIZE, payload + LIBMPQ_PATCH_INFO_SIZE,
            (libmpq__off_t)(payload_size - LIBMPQ_PATCH_INFO_SIZE), size, &storage
        );
    if (result == LIBMPQ_SUCCESS) {
        mpq_md5_s md5;

        block = state->archive->write_next_block - 1;
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, data, (size_t)size);
        libmpq__md5_final(&md5, state->archive->write_attributes[block].md5);
    }
    free(payload);
    free(before);
    return result;
}

/* Read one filesystem replacement and reuse the same staged data path. */
int32_t
libmpq__patch_writer_replace_path(
    mpq_patch_writer_s *state, const char *name, const char *source_path,
    const mpq_file_options_s *options
)
{
    FILE *input;
    libmpq__off_t size;
    uint8_t *data = NULL;
    int32_t result;

    if (state == NULL || source_path == NULL || source_path[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    input = libmpq__file_open(source_path, "rb");
    if (input == NULL)
        return LIBMPQ_ERROR_OPEN;
    result = libmpq__file_seek(input, 0, SEEK_END);
    if (result == LIBMPQ_SUCCESS) {
        size = libmpq__file_tell(input);
        if (size < 0 ||
            (uint64_t)size > UINT32_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
            (uint64_t)size > SIZE_MAX)
            result = LIBMPQ_ERROR_SIZE;
    }
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__file_seek(input, 0, SEEK_SET);
    if (result == LIBMPQ_SUCCESS) {
        data = malloc(size == 0 ? 1 : (size_t)size);
        if (data == NULL)
            result = LIBMPQ_ERROR_MALLOC;
    }
    if (result == LIBMPQ_SUCCESS && size != 0 &&
        fread(data, 1, (size_t)size, input) != (size_t)size)
        result = LIBMPQ_ERROR_READ;
    if (fclose(input) != 0 && result == LIBMPQ_SUCCESS)
        result = LIBMPQ_ERROR_CLOSE;
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__patch_writer_replace(state, name, data, size, options);
    free(data);
    return result;
}

/* Stage a named delete marker without touching the base archive. */
int32_t
libmpq__patch_writer_remove(mpq_patch_writer_s *state, const char *name)
{
    uint16_t locale;
    uint16_t platform;
    uint32_t number;
    int32_t result;

    if (state == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = patch_writer_member(state, name, &number, &locale, &platform);
    if (result != LIBMPQ_SUCCESS)
        return result;
    return libmpq__writer_patch_delete_marker(state->archive, name, locale, platform);
}

/* Publish the finalized patch only after its writer has closed successfully. */
int32_t
libmpq__patch_writer_finish(mpq_patch_writer_s *state)
{
    if (state == NULL)
        return LIBMPQ_ERROR_EXIST;
    return patch_writer_cleanup(state, 1);
}

/* Discard a private patch writer and its unpublished same-directory file. */
int32_t
libmpq__patch_writer_abort(mpq_patch_writer_s *state)
{
    if (state == NULL)
        return LIBMPQ_ERROR_EXIST;
    return patch_writer_cleanup(state, 0);
}
