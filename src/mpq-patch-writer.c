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
#include "mpq-archive.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-md5.h"
#include "mpq-patch-reader.h"
#include "mpq-reader.h"
#include "mpq-writer.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LIBMPQ_PATCH_COPY_HEADER_SIZE 68u
#define LIBMPQ_PATCH_WRITER_CAPACITY 1024u

#define LIBMPQ_BSD0_HEADER_SIZE 32u
#define LIBMPQ_BSD0_CONTROL_SIZE 12u

/* Encode zero runs and literal runs using the reader's bounded RLE format. */
static size_t
patch_bsd0_rle(const uint8_t *raw, size_t size, uint8_t *output)
{
    size_t input = 0;
    size_t used = 4;

    memset(output, 0, 4);
    while (input < size) {
        size_t count = 0;
        uint8_t zero = raw[input] == 0;

        while (count < size - input && count < 128 && (raw[input + count] == 0) == zero)
            count++;
        output[used++] = (uint8_t)(count - 1) | (zero ? 0 : 0x80u);
        if (!zero) {
            memcpy(output + used, raw + input, count);
            used += count;
        }
        input += count;
    }
    return used;
}

/* Successful BSD0 output always uses the reader's RLE wrapper. */
static int32_t
patch_bsd0_pack(uint8_t *raw, size_t raw_size, uint8_t **encoded, size_t *encoded_size)
{
    size_t rle_capacity;
    size_t rle_size;
    uint8_t *rle;

    if (raw_size > (SIZE_MAX - 4) / 2) {
        free(raw);
        return LIBMPQ_ERROR_SIZE;
    }
    rle_capacity = raw_size * 2 + 4;
    rle = malloc(rle_capacity);
    if (rle == NULL) {
        free(raw);
        return LIBMPQ_ERROR_MALLOC;
    }
    rle_size = patch_bsd0_rle(raw, raw_size, rle);
    free(raw);
    *encoded = rle;
    *encoded_size = rle_size;
    return 0;
}

/* Build the aligned candidate, where unchanged bytes become zero differences. */
static uint8_t *
patch_bsd0_aligned(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    size_t *raw_size
)
{
    size_t overlap = before_size < after_size ? before_size : after_size;
    uint8_t *raw;

    *raw_size = LIBMPQ_BSD0_HEADER_SIZE + LIBMPQ_BSD0_CONTROL_SIZE + after_size;
    raw = calloc(1, *raw_size);
    if (raw == NULL)
        return NULL;
    memcpy(raw, "BSDIFF40", 8);
    libmpq__store_le64(raw + 8, LIBMPQ_BSD0_CONTROL_SIZE);
    libmpq__store_le64(raw + 16, overlap);
    libmpq__store_le64(raw + 24, after_size);
    libmpq__store_le32(raw + 32, (uint32_t)overlap);
    libmpq__store_le32(raw + 36, (uint32_t)(after_size - overlap));
    for (size_t i = 0; i < overlap; i++)
        raw[LIBMPQ_BSD0_HEADER_SIZE + LIBMPQ_BSD0_CONTROL_SIZE + i] =
            (uint8_t)(after[i] - before[i]);
    if (after_size != overlap)
        memcpy(
            raw + LIBMPQ_BSD0_HEADER_SIZE + LIBMPQ_BSD0_CONTROL_SIZE + overlap, after + overlap,
            after_size - overlap
        );
    return raw;
}

/*
 * A BSD0 tuple's add count combines base bytes with diff bytes. Its copy count
 * consumes literal extra-block bytes, not bytes from the base. The first
 * tuple copies the unchanged prefix literally and seeks to the old middle.
 * The second diffs overlapping middle bytes, copies inserted bytes from the
 * extra block, then skips any removed old-middle bytes. The final tuple
 * copies the unchanged suffix literally. Empty ranges omit their tuple.
 * This matches libmpq's BSD0 decoder, not a generic bsdiff copy operation.
 */
static uint8_t *
patch_bsd0_splice(
    const uint8_t *before, const uint8_t *after, size_t after_size, size_t prefix, size_t suffix,
    size_t old_middle, size_t *raw_size
)
{
    size_t new_middle = after_size - prefix - suffix;
    size_t overlap = old_middle < new_middle ? old_middle : new_middle;
    size_t inserted = new_middle - overlap;
    size_t control_count = (prefix != 0) + (overlap + inserted != 0) + (suffix != 0);
    size_t control_size = control_count * LIBMPQ_BSD0_CONTROL_SIZE;
    size_t delta_offset = LIBMPQ_BSD0_HEADER_SIZE + control_size;
    size_t extra_offset = delta_offset + overlap;
    size_t control_offset = LIBMPQ_BSD0_HEADER_SIZE;
    uint8_t *raw;

    *raw_size = LIBMPQ_BSD0_HEADER_SIZE + control_size + after_size;
    raw = calloc(1, *raw_size);
    if (raw == NULL)
        return NULL;
    memcpy(raw, "BSDIFF40", 8);
    libmpq__store_le64(raw + 8, control_size);
    libmpq__store_le64(raw + 16, overlap);
    libmpq__store_le64(raw + 24, after_size);
    if (prefix != 0) {
        libmpq__store_le32(raw + control_offset + 4, (uint32_t)prefix);
        libmpq__store_le32(raw + control_offset + 8, (uint32_t)prefix);
        control_offset += LIBMPQ_BSD0_CONTROL_SIZE;
        memcpy(raw + extra_offset, after, prefix);
    }
    if (overlap + inserted != 0) {
        libmpq__store_le32(raw + control_offset, (uint32_t)overlap);
        libmpq__store_le32(raw + control_offset + 4, (uint32_t)inserted);
        libmpq__store_le32(raw + control_offset + 8, (uint32_t)(old_middle - overlap));
        control_offset += LIBMPQ_BSD0_CONTROL_SIZE;
    }
    for (size_t i = 0; i < overlap; i++)
        raw[delta_offset + i] = (uint8_t)(after[prefix + i] - before[prefix + i]);
    if (inserted != 0)
        memcpy(raw + extra_offset + prefix, after + prefix + overlap, inserted);
    if (suffix != 0) {
        libmpq__store_le32(raw + control_offset + 4, (uint32_t)suffix);
        memcpy(raw + extra_offset + prefix + inserted, after + prefix + new_middle, suffix);
    }
    return raw;
}

/*
 * PTCH BSD0 uses libmpq's existing RLE-wrapped BSDIFF40-compatible layout.
 * The splice tuples above retain that decoder contract; the output is not a
 * generic bsdiff patch file.
 */
int32_t
libmpq__patch_bsd0_encode(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    uint8_t splice, uint8_t **encoded, size_t *encoded_size, size_t *patch_stream_size
)
{
    size_t prefix = 0;
    size_t suffix = 0;
    size_t raw_size;
    uint8_t *raw;

    if (encoded == NULL || encoded_size == NULL || patch_stream_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    *encoded = NULL;
    *encoded_size = 0;
    *patch_stream_size = 0;
    if ((before == NULL && before_size != 0) || (after == NULL && after_size != 0))
        return LIBMPQ_ERROR_EXIST;
    if (before_size > UINT32_MAX || after_size > UINT32_MAX ||
        after_size > SIZE_MAX - LIBMPQ_BSD0_HEADER_SIZE - 3 * LIBMPQ_BSD0_CONTROL_SIZE ||
        after_size == 0)
        return LIBMPQ_ERROR_SIZE;
    if (splice == 0) {
        raw = patch_bsd0_aligned(before, before_size, after, after_size, &raw_size);
    } else {
        while (prefix < before_size && prefix < after_size && before[prefix] == after[prefix])
            prefix++;
        while (suffix < before_size - prefix && suffix < after_size - prefix &&
               before[before_size - suffix - 1] == after[after_size - suffix - 1])
            suffix++;
        if (suffix < 16 || (prefix == 0 && prefix + suffix == after_size) ||
            before_size - prefix - suffix > INT32_MAX)
            return 0;
        raw = patch_bsd0_splice(
            before, after, after_size, prefix, suffix, before_size - prefix - suffix, &raw_size
        );
    }
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    *patch_stream_size = raw_size;
    return patch_bsd0_pack(raw, raw_size, encoded, encoded_size);
}

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
    int32_t result = 0;
    int32_t cleanup;

    if (state->archive != NULL) {
        result = libmpq__archive_close(state->archive);
        state->archive = NULL;
    }
    if (state->base != NULL) {
        cleanup = libmpq__archive_close(state->base);
        if (result == 0)
            result = cleanup;
    }
    if (publish && result == 0) {
        result = libmpq__directory_replace(state->directory, state->temporary, state->destination);
    }
    if (!publish || result != 0) {
        cleanup = libmpq__directory_remove(state->directory, state->temporary);
        if (result == 0)
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
    if (result != 0)
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
    return 0;
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
    if (result != 0)
        return result;
    if (length < 0 || (uint64_t)length > UINT32_MAX || (uint64_t)length > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    bytes = malloc(length == 0 ? 1 : (size_t)length);
    if (bytes == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__reader_offsets_acquire(state->base, number, name);
    if (result == 0) {
        result = libmpq__file_read(state->base, number, bytes, length, &transferred);
        if (result == 0 && transferred != length)
            result = LIBMPQ_ERROR_READ;
        {
            int32_t release = libmpq__reader_offsets_release(state->base, number);

            if (result == 0)
                result = release;
        }
    }
    if (result == 0) {
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
    size_t before_size, size_t after_size, const uint8_t *transform, size_t transform_size,
    size_t patch_stream_size, uint8_t use_bsd0, const uint8_t before_md5[LIBMPQ_MD5_SIZE],
    const uint8_t after_md5[LIBMPQ_MD5_SIZE], uint8_t **payload, size_t *payload_size
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
    memcpy(patch + 24, before_md5, LIBMPQ_MD5_SIZE);
    memcpy(patch + 40, after_md5, LIBMPQ_MD5_SIZE);
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
    return 0;
}

/* Select BSD0 only when its complete candidate is smaller and decodes correctly. */
static int32_t
patch_writer_payload(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    uint8_t after_md5[LIBMPQ_MD5_SIZE], uint8_t **payload, size_t *payload_size
)
{
    uint8_t before_md5[LIBMPQ_MD5_SIZE];
    mpq_md5_s md5;
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
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, before, before_size);
    libmpq__md5_final(&md5, before_md5);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, after, after_size);
    libmpq__md5_final(&md5, after_md5);
    if (after_size != 0) {
        for (uint8_t splice = 0; splice < 2; splice++) {
            result = libmpq__patch_bsd0_encode(
                before, before_size, after, after_size, splice, &transform, &transform_size,
                &patch_stream_size
            );
            if (result != 0) {
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

            /* Equal or larger candidates cannot win; only contenders need validation. */
            if (LIBMPQ_PATCH_INFO_SIZE + LIBMPQ_PATCH_COPY_HEADER_SIZE + transform_size >=
                best_size) {
                free(transform);
                transform = NULL;
                continue;
            }
            result = patch_writer_build_payload(
                before_size, after_size, transform, transform_size, patch_stream_size, 1,
                before_md5, after_md5, &candidate, &candidate_size
            );
            free(transform);
            transform = NULL;
            if (result != 0) {
                free(best);
                return result;
            }
            result = libmpq__patch_apply(
                before, before_size, candidate + LIBMPQ_PATCH_INFO_SIZE,
                candidate_size - LIBMPQ_PATCH_INFO_SIZE, &verified, &verified_size
            );
            if (result == 0 && verified_size == after_size && verified != NULL &&
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
        return 0;
    }
    return patch_writer_build_payload(
        before_size, after_size, after, after_size, after_size, 0, before_md5, after_md5, payload,
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
    int32_t result = 0;

    if (existing == NULL)
        return 0;
    if (state->base->file_identity_valid) {
        result = libmpq__file_identity(existing, &device, &inode);
        if (result == 0 && device == state->base->file_device && inode == state->base->file_inode)
            result = LIBMPQ_ERROR_FORMAT;
    }
    if (fclose(existing) != 0 && result == 0)
        result = LIBMPQ_ERROR_CLOSE;
    return result;
}

/* Resolve the sibling temporary path for the existing MPQE archive writer. */
static char *
patch_writer_staged_path(const char *absolute, const char *temporary)
{
    const char *slash = strrchr(absolute, '/');
    size_t directory_size;
    size_t name_size = strlen(temporary);
    char *path;

#ifdef _WIN32
    {
        const char *backslash = strrchr(absolute, '\\');

        if (backslash != NULL && (slash == NULL || backslash > slash))
            slash = backslash;
    }
#endif
    if (slash == NULL)
        return NULL;
    directory_size = (size_t)(slash - absolute) + 1;
    if (directory_size > SIZE_MAX - name_size - 1)
        return NULL;
    path = malloc(directory_size + name_size + 1);
    if (path != NULL) {
        memcpy(path, absolute, directory_size);
        memcpy(path + directory_size, temporary, name_size + 1);
    }
    return path;
}

/* Stage a same-directory patch; MPQE output delegates to the existing writer. */
static int32_t
patch_writer_begin_internal(
    mpq_patch_writer_s **patch_writer, const char *base_path, const char *patch_path,
    const uint8_t *auth_code, size_t auth_code_size, uint8_t mpqe
)
{
    mpq_patch_writer_s *state = NULL;
    mpq_archive_create_options_s options;
    FILE *temporary_file = NULL;
    char *absolute = NULL;
    char *staged_path = NULL;
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
    if (result != 0)
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
    if (result != 0)
        goto fail;
    result = patch_writer_check_destination(state);
    if (result != 0)
        goto fail;
    result = libmpq__directory_temporary(
        state->directory, ".libmpq-patch-write-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1,
        &state->temporary, &temporary_file
    );
    if (result != 0)
        goto fail;
    options.version = state->base->mpq_header.version;
    options.max_files = LIBMPQ_PATCH_WRITER_CAPACITY;
    options.sector_size = state->base->block_size;
    options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_PATCH_BIT;
    if (mpqe) {
        if (fclose(temporary_file) != 0) {
            temporary_file = NULL;
            result = LIBMPQ_ERROR_CLOSE;
            goto fail;
        }
        temporary_file = NULL;
        staged_path = patch_writer_staged_path(absolute, state->temporary);
        if (staged_path == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto fail;
        }
        result = libmpq__writer_archive_create_mpqe(
            &state->archive, staged_path, auth_code, auth_code_size, &options
        );
    } else {
        result = libmpq__writer_archive_create_file(
            &state->archive, state->temporary, temporary_file, &options
        );
        temporary_file = NULL;
    }
    if (result != 0)
        goto fail;
    state->archive->write_patch_mode = 1;
    free(staged_path);
    free(absolute);
    *patch_writer = state;
    return 0;

fail:
    free(staged_path);
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

/* Preserve ordinary MPQ patch creation and its existing lifecycle. */
int32_t
libmpq__patch_writer_begin(
    mpq_patch_writer_s **patch_writer, const char *base_path, const char *patch_path
)
{
    return patch_writer_begin_internal(patch_writer, base_path, patch_path, NULL, 0, 0);
}

/* Stage an MPQE patch using the archive writer's authentication and encryption. */
int32_t
libmpq__patch_writer_begin_mpqe(
    mpq_patch_writer_s **patch_writer, const char *base_path, const char *patch_path,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    return patch_writer_begin_internal(
        patch_writer, base_path, patch_path, auth_code, auth_code_size, 1
    );
}

/* Let archive finalization generate the configured weak or strong signature. */
int32_t
libmpq__patch_writer_sign(
    mpq_patch_writer_s *state, uint32_t signature_type, const uint8_t *private_key,
    size_t private_key_size
)
{
    if (state == NULL)
        return LIBMPQ_ERROR_EXIST;
    return libmpq__archive_sign(state->archive, signature_type, private_key, private_key_size);
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
    uint8_t after_md5[LIBMPQ_MD5_SIZE];
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
    if (result != 0)
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
    if (result == 0)
        result = patch_writer_payload(
            before, before_size, data, (size_t)size, after_md5, &payload, &payload_size
        );
    if (result == 0 && options == NULL && payload_size > state->archive->write_sector_size)
        storage.flags = 0;

    if (result == 0)
        result = libmpq__writer_patch_file_add(
            state->archive, name, payload, LIBMPQ_PATCH_INFO_SIZE, payload + LIBMPQ_PATCH_INFO_SIZE,
            (libmpq__off_t)(payload_size - LIBMPQ_PATCH_INFO_SIZE), size, &storage
        );
    if (result == 0) {
        block = state->archive->write_next_block - 1;
        memcpy(state->archive->write_attributes[block].md5, after_md5, LIBMPQ_MD5_SIZE);
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
    if (result == 0) {
        size = libmpq__file_tell(input);
        if (size < 0 ||
            (uint64_t)size > UINT32_MAX - LIBMPQ_PATCH_INFO_SIZE - LIBMPQ_PATCH_COPY_HEADER_SIZE ||
            (uint64_t)size > SIZE_MAX)
            result = LIBMPQ_ERROR_SIZE;
    }
    if (result == 0)
        result = libmpq__file_seek(input, 0, SEEK_SET);
    if (result == 0) {
        data = malloc(size == 0 ? 1 : (size_t)size);
        if (data == NULL)
            result = LIBMPQ_ERROR_MALLOC;
    }
    if (result == 0 && size != 0 && fread(data, 1, (size_t)size, input) != (size_t)size)
        result = LIBMPQ_ERROR_READ;
    if (fclose(input) != 0 && result == 0)
        result = LIBMPQ_ERROR_CLOSE;
    if (result == 0)
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
    if (result != 0)
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
