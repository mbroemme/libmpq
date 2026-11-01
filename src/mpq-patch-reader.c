/*
 *  mpq-patch-reader.c -- private MPQ incremental patch decoding.
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

/* Export public patch-payload entry points when building a Windows DLL. */
#if defined(_WIN32) && defined(DLL_EXPORT)
#define LIBMPQ_API __declspec(dllexport)
#endif

#include "mpq-archive.h"
#include "mpq-attributes.h"
#include "mpq-block.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-md5.h"
#include "mpq-patch-reader.h"
#include "mpq-reader.h"
#include "mpq-signature.h"
#include "mpq-source.h"
#include "mpq-stream.h"
#include "mpq-verify.h"
#include "mpq-writer.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define LIBMPQ_PATCH_HEADER_SIZE 68u
#define LIBMPQ_PATCH_BSDIFF_HEADER_SIZE 32u
#define LIBMPQ_PATCH_COPY_SIZE 65536u

struct mpq_patch_view
{
    mpq_directory_s *directory;
    char *temporary;
    char *path;
    mpq_archive_s *archive;
    libmpq__off_t archive_offset;
    uint8_t changed;
};

/*
 * A live patch hash entry is authoritative; a listfile may add its plaintext
 * name for decryption or insertion, but never determines whether it exists.
 */
typedef struct
{
    uint32_t hash_a;
    uint32_t hash_b;
    uint32_t physical_hash_a;
    uint32_t physical_hash_b;
    uint16_t locale;
    uint16_t platform;
    uint32_t block_index;
    uint32_t number;
    char *name;
    char *physical_name;
    uint8_t live;
    uint8_t internal;
} mpq_patch_entry_s;

/* Compare one buffer with a serialized MD5 digest. */
static int32_t
patch_check_md5(const uint8_t *data, size_t size, const uint8_t expected[16])
{
    mpq_md5_s context;
    uint8_t actual[16];

    libmpq__md5_init(&context);
    libmpq__md5_update(&context, data, size);
    libmpq__md5_final(&context, actual);
    return memcmp(actual, expected, sizeof(actual)) == 0 ? 0 : LIBMPQ_ERROR_FORMAT;
}

/* Only the fixed header has fields; extension bytes need not be allocated. */
static int32_t
patch_info_parse_header(
    const uint8_t *data, size_t header_size, uint64_t available_size, mpq_patch_info_s *info
)
{
    if (info == NULL)
        return LIBMPQ_ERROR_EXIST;
    memset(info, 0, sizeof(*info));
    if (data == NULL || header_size < LIBMPQ_PATCH_INFO_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    info->length = libmpq__load_le32(data);
    info->flags = libmpq__load_le32(data + 4);
    info->data_size = libmpq__load_le32(data + 8);
    memcpy(info->md5, data + 12, sizeof(info->md5));
    if (info->length < LIBMPQ_PATCH_INFO_SIZE || info->length > available_size ||
        (info->flags & 0x80000000u) == 0)
        return LIBMPQ_ERROR_FORMAT;
    return 0;
}

int32_t
libmpq__patch_info_parse(const uint8_t *data, size_t size, mpq_patch_info_s *info)
{
    return patch_info_parse_header(data, size, size, info);
}

/* Expand Blizzard's zero-skipping RLE wrapper around a BSD0 transform. */
static int32_t
patch_expand_rle(const uint8_t *encoded, size_t encoded_size, uint8_t *decoded, size_t decoded_size)
{
    size_t input = 4;
    size_t output = 0;

    if (encoded_size < 4)
        return LIBMPQ_ERROR_FORMAT;
    memset(decoded, 0, decoded_size);
    while (input < encoded_size && output < decoded_size) {
        uint8_t command = encoded[input++];
        size_t count = (size_t)(command & 0x7fu) + 1;

        if (count > decoded_size - output)
            return LIBMPQ_ERROR_FORMAT;
        if ((command & 0x80u) != 0) {
            if (count > encoded_size - input)
                return LIBMPQ_ERROR_FORMAT;
            memcpy(decoded + output, encoded + input, count);
            input += count;
        }
        output += count;
    }
    return input == encoded_size && output == decoded_size ? 0 : LIBMPQ_ERROR_FORMAT;
}

typedef int32_t (*patch_read_at_fn)(void *context, uint64_t offset, uint8_t *data, size_t size);
typedef int32_t (*patch_bsd_span_fn)(
    void *context, uint64_t offset, uint64_t source, uint64_t target, uint32_t size, uint8_t add
);

/* Walk the same bounded BSD0 regions for memory and file-backed transforms. */
static int32_t
patch_walk_bsd0(
    void *context, patch_read_at_fn read_at, patch_bsd_span_fn span, uint64_t data_size,
    uint64_t output_size
)
{
    uint8_t header[LIBMPQ_PATCH_BSDIFF_HEADER_SIZE];
    if (data_size < sizeof(header))
        return LIBMPQ_ERROR_FORMAT;
    int32_t status = read_at(context, 0, header, sizeof(header));
    if (status != 0)
        return status;
    uint64_t control_end = libmpq__load_le64(header + 8);
    uint64_t delta_end = libmpq__load_le64(header + 16);
    if (memcmp(header, "BSDIFF40", 8) != 0 || libmpq__load_le64(header + 24) != output_size ||
        control_end > data_size - sizeof(header) ||
        delta_end > data_size - sizeof(header) - control_end)
        return LIBMPQ_ERROR_FORMAT;
    uint64_t control = sizeof(header);
    control_end += control;
    uint64_t delta = control_end;
    delta_end += delta;
    uint64_t extra = delta_end;
    uint64_t target = 0;
    int64_t source = 0;
    while (target < output_size) {
        uint8_t triple[12];
        if (control_end - control < sizeof(triple))
            return LIBMPQ_ERROR_FORMAT;
        status = read_at(context, control, triple, sizeof(triple));
        if (status != 0)
            return status;
        uint32_t add = libmpq__load_le32(triple);
        uint32_t copy = libmpq__load_le32(triple + 4);
        uint32_t raw_move = libmpq__load_le32(triple + 8);
        int64_t move =
            (raw_move & 0x80000000u) != 0 ? -(int64_t)(raw_move & 0x7fffffffu) : (int64_t)raw_move;
        control += sizeof(triple);
        if (add > output_size - target || add > delta_end - delta || source < 0 ||
            source > INT64_MAX - (int64_t)add)
            return LIBMPQ_ERROR_FORMAT;
        if (add != 0) {
            status = span(context, delta, (uint64_t)source, target, add, 1);
            if (status != 0)
                return status;
        }
        target += add;
        delta += add;
        source += (int64_t)add;
        if (copy > output_size - target || copy > data_size - extra)
            return LIBMPQ_ERROR_FORMAT;
        if (copy != 0) {
            status = span(context, extra, 0, target, copy, 0);
            if (status != 0)
                return status;
        }
        target += copy;
        extra += copy;
        if ((move > 0 && source > INT64_MAX - move) || (move < 0 && source < INT64_MIN - move))
            return LIBMPQ_ERROR_FORMAT;
        source += move;
        if (add == 0 && copy == 0)
            return LIBMPQ_ERROR_FORMAT;
    }
    return target == output_size && control == control_end && delta == delta_end &&
                   extra == data_size
               ? 0
               : LIBMPQ_ERROR_FORMAT;
}

typedef struct
{
    const uint8_t *base;
    size_t base_size;
    const uint8_t *data;
    uint8_t *output;
} patch_bsd_memory_s;

/* The walker has already bounded reads within the transform. */
static int32_t
patch_bsd_memory_read(void *context, uint64_t offset, uint8_t *data, size_t size)
{
    const patch_bsd_memory_s *memory = context;
    memcpy(data, memory->data + (size_t)offset, size);
    return 0;
}

/* Apply one validated span into the materializer's existing memory result. */
static int32_t
patch_bsd_memory_span(
    void *context, uint64_t offset, uint64_t source, uint64_t target, uint32_t size, uint8_t add
)
{
    const patch_bsd_memory_s *memory = context;
    const uint8_t *input = memory->data + (size_t)offset;
    uint8_t *output = memory->output + (size_t)target;
    if (!add)
        memcpy(output, input, size);
    else
        for (uint32_t i = 0; i < size; ++i) {
            uint64_t old_offset = source + i;
            uint8_t old_byte = old_offset < memory->base_size ? memory->base[old_offset] : 0;
            output[i] = (uint8_t)(input[i] + old_byte);
        }
    return 0;
}

typedef struct
{
    uint32_t after;
    size_t encoded;
    size_t decoded;
} patch_transform_s;

/* Parse the common PTCH envelope before either backend trusts transform sizes. */
static int32_t
patch_transform_parse(
    const uint8_t *header, size_t patch_size, uint64_t base_size, patch_transform_s *transform
)
{
    if (patch_size < LIBMPQ_PATCH_HEADER_SIZE || memcmp(header, "PTCH", 4) != 0 ||
        memcmp(header + 16, "MD5_", 4) != 0 || memcmp(header + 56, "XFRM", 4) != 0)
        return LIBMPQ_ERROR_FORMAT;
    uint32_t complete = libmpq__load_le32(header + 4);
    uint32_t length = libmpq__load_le32(header + 60);
    if (libmpq__load_le32(header + 8) != base_size || libmpq__load_le32(header + 20) != 40 ||
        complete < LIBMPQ_PATCH_HEADER_SIZE || length < 12 ||
        length - 12 != patch_size - LIBMPQ_PATCH_HEADER_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    transform->after = libmpq__load_le32(header + 12);
    transform->encoded = patch_size - LIBMPQ_PATCH_HEADER_SIZE;
    transform->decoded = complete - LIBMPQ_PATCH_HEADER_SIZE;
    return 0;
}

/* Apply and verify a PTCH payload, optionally borrowing COPY output. */
static int32_t
patch_apply_internal(
    const uint8_t *base, size_t base_size, const uint8_t *patch, size_t patch_size,
    uint8_t **output, size_t *output_size, uint8_t borrow_copy
)
{
    patch_transform_s transform;
    uint32_t after_size;
    const uint8_t *encoded;
    size_t encoded_size;
    size_t decoded_size;
    uint8_t *decoded = NULL;
    uint8_t *result = NULL;
    int32_t status;

    if (output == NULL || output_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    *output = NULL;
    *output_size = 0;
    if ((base == NULL && base_size != 0) || patch == NULL)
        return LIBMPQ_ERROR_FORMAT;
    status = patch_transform_parse(patch, patch_size, base_size, &transform);
    if (status != 0)
        return status;
    after_size = transform.after;
    status = patch_check_md5(base, base_size, patch + 24);
    if (status != 0)
        return status;
    encoded = patch + LIBMPQ_PATCH_HEADER_SIZE;
    encoded_size = transform.encoded;
    decoded_size = transform.decoded;
    if (memcmp(patch + 64, "COPY", 4) == 0) {
        if (decoded_size != encoded_size || decoded_size != after_size)
            return LIBMPQ_ERROR_FORMAT;
        decoded = (uint8_t *)encoded;
    } else if (memcmp(patch + 64, "BSD0", 4) == 0) {
        if (decoded_size < LIBMPQ_PATCH_BSDIFF_HEADER_SIZE)
            return LIBMPQ_ERROR_FORMAT;
        if (decoded_size != encoded_size) {
            decoded = malloc(decoded_size == 0 ? 1 : decoded_size);
            if (decoded == NULL)
                return LIBMPQ_ERROR_MALLOC;
            status = patch_expand_rle(encoded, encoded_size, decoded, decoded_size);
            if (status != 0)
                goto done;
        } else {
            decoded = (uint8_t *)encoded;
        }
    } else {
        return LIBMPQ_ERROR_FORMAT;
    }
    if (memcmp(patch + 64, "COPY", 4) == 0) {
        if (borrow_copy)
            result = decoded;
        else {
            result = malloc(after_size == 0 ? 1 : after_size);
            if (result == NULL) {
                status = LIBMPQ_ERROR_MALLOC;
                goto done;
            }
            memcpy(result, decoded, after_size);
        }
        status = 0;
    } else {
        result = malloc(after_size == 0 ? 1 : after_size);
        if (result == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        patch_bsd_memory_s memory = { base, base_size, decoded, result };
        status = patch_walk_bsd0(
            &memory, patch_bsd_memory_read, patch_bsd_memory_span, decoded_size, after_size
        );
    }
    if (status == 0)
        status = patch_check_md5(result, after_size, patch + 40);
    if (status == 0) {
        *output = result;
        *output_size = after_size;
        result = NULL;
    }

done:
    if (decoded != encoded)
        free(decoded);
    if (result != encoded)
        free(result);
    return status;
}

/* Preserve the owning output contract for tests, fuzzers, and other callers. */
int32_t
libmpq__patch_apply(
    const uint8_t *base, size_t base_size, const uint8_t *patch, size_t patch_size,
    uint8_t **output, size_t *output_size
)
{
    return patch_apply_internal(base, base_size, patch, patch_size, output, output_size, 0);
}

/* Construct the stable path of a sibling temporary file. */
static char *
patch_temporary_path(const char *absolute, const char *temporary)
{

    /* Call libc functions directly to avoid C11-only generic macros in C99. */
    const char *slash = (strrchr)(absolute, '/');
    size_t directory_size;
    size_t name_size = strlen(temporary);
    char *path;

#ifdef _WIN32
    {
        const char *backslash = (strrchr)(absolute, '\\');

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
    if (path == NULL)
        return NULL;
    memcpy(path, absolute, directory_size);
    memcpy(path + directory_size, temporary, name_size + 1);
    return path;
}

/* Copy a bounded physical container range without interpreting its contents. */
static int32_t
patch_copy_range(mpq_archive_s *base, FILE *output, uint64_t offset, uint64_t remaining)
{
    uint8_t buffer[LIBMPQ_PATCH_COPY_SIZE];

    if (offset > base->file_size || remaining > base->file_size - offset)
        return LIBMPQ_ERROR_SIZE;

    while (remaining != 0) {
        size_t count = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        int32_t status = libmpq__source_read_at(base->source, offset, buffer, count);

        if (status != 0)
            return status;
        if (fwrite(buffer, 1, count, output) != count)
            return LIBMPQ_ERROR_WRITE;
        offset += count;
        remaining -= count;
    }
    return 0;
}

/* Read a member through current archive metadata, including adjusted patch blocks. */
static int32_t
patch_read_adjusted(
    mpq_archive_s *archive, const char *name, uint32_t number, const uint32_t *seed, uint8_t **data,
    size_t *size
)
{
    libmpq__off_t transferred = 0;
    libmpq__off_t logical_size = 0;
    uint8_t *bytes = NULL;
    int32_t status;

    status = libmpq__reader_offsets_acquire_key(archive, number, name, seed);
    if (status != 0)
        return status;
    status = libmpq__file_size_unpacked(archive, number, &logical_size);
    if (status != 0 || logical_size < 0 || (uint64_t)logical_size > SIZE_MAX) {
        if (status == 0)
            status = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    bytes = malloc(logical_size == 0 ? 1 : (size_t)logical_size);
    if (bytes == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    status = libmpq__file_read(archive, number, bytes, logical_size, &transferred);
    if (status == 0 && transferred != logical_size)
        status = LIBMPQ_ERROR_READ;
    if (status == 0) {
        *data = bytes;
        *size = (size_t)logical_size;
        bytes = NULL;
    }

done:
    free(bytes);
    {
        int32_t release_status = libmpq__reader_offsets_release(archive, number);

        if (status == 0)
            status = release_status;
    }
    return status;
}

/* Use complete-file verification when reading an ordinary named member. */
static int32_t
patch_read_named(mpq_archive_s *archive, const char *name, uint8_t **data, size_t *size)
{
    uint32_t number;
    int32_t status = libmpq__file_number(archive, name, &number);

    if (status != 0)
        return status;
    return patch_read_adjusted(archive, name, number, NULL, data, size);
}

static int32_t
patch_member_info(mpq_archive_s *archive, uint32_t number, mpq_patch_info_s *info)
{
    mpq_entry_s *block;
    uint8_t fixed[LIBMPQ_PATCH_INFO_SIZE];
    uint64_t offset;
    uint32_t physical;
    int32_t status;

    if (archive == NULL || info == NULL ||
        libmpq__reader_validate_file_number(archive, number) != 0)
        return LIBMPQ_ERROR_EXIST;
    physical = archive->mpq_map[number].entry_index;
    block = &archive->mpq_entry[physical];
    if ((block->flags & LIBMPQ_FILE_FLAG_PATCH_FILE) == 0)
        return LIBMPQ_ERROR_EXIST;
    if (block->packed_size < LIBMPQ_PATCH_INFO_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    offset = (uint64_t)archive->archive_offset + block->offset;
    status = libmpq__source_read_at(archive->source, offset, fixed, sizeof(fixed));
    if (status != 0)
        return status;
    status = patch_info_parse_header(fixed, sizeof(fixed), block->packed_size, info);
    return status;
}

int32_t
libmpq__patch_reader_payload_size(mpq_archive_s *archive, uint32_t number, libmpq__off_t *size)
{
    mpq_patch_info_s info;
    int32_t status;

    if (size == NULL)
        return LIBMPQ_ERROR_EXIST;
    *size = 0;
    status = patch_member_info(archive, number, &info);
    if (status == 0)
        *size = info.data_size;
    return status;
}

/* Adjust the private reader to the body while retaining the original KEY seed. */
static int32_t
patch_body_view(
    mpq_archive_s *archive, uint32_t number, const char *name, const mpq_patch_info_s *info,
    uint32_t *key, const uint32_t **seed
)
{
    uint32_t index = archive->mpq_map[number].entry_index;
    mpq_entry_s *block = &archive->mpq_entry[index];
    if (info->length > block->packed_size || info->length > UINT64_MAX - block->offset)
        return LIBMPQ_ERROR_FORMAT;
    uint64_t shifted = block->offset + info->length;
    if (shifted > UINT32_MAX && archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE)
        return LIBMPQ_ERROR_FORMAT;
    *seed = NULL;
    if (name != NULL && (block->flags & (LIBMPQ_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY)) ==
                            (LIBMPQ_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY)) {

        /* KEY still describes the original member, including its result size. */
        *key = (libmpq__crypto_file_key(name) + (uint32_t)block->offset) ^
               (uint32_t)block->unpacked_size;
        *seed = key;
    }
    block->offset = shifted;
    block->packed_size -= info->length;
    block->unpacked_size = info->data_size;
    block->flags &= ~LIBMPQ_FILE_FLAG_PATCH_FILE;
    archive->attributes_error = LIBMPQ_ERROR_EXIST;
    return 0;
}

/*
 * Parse the plaintext patch prefix before using its body size, then
 * decode the stored body through normal MPQ reader semantics. Patch-file
 * blocks describe the resulting file size rather than the decoded body size.
 */
static int32_t
patch_read_incremental(
    mpq_archive_s *archive, const char *name, uint32_t number, uint8_t **data, size_t *size
)
{
    mpq_archive_s *clone = NULL;
    uint8_t *body = NULL;
    mpq_patch_info_s info;
    size_t body_size = 0;
    uint32_t key = 0;
    const uint32_t *seed = NULL;
    int32_t status;

    *data = NULL;
    *size = 0;
    status = patch_member_info(archive, number, &info);
    if (status != 0)
        return status;

    /* Reopen from wire metadata with empty member caches, even if the caller has live reads. */
    status = libmpq__archive_clone(&clone, archive);
    if (status != 0)
        goto done;
    status = libmpq__reader_validate_file_number(clone, number);
    if (status != 0)
        goto done;
    status = patch_body_view(clone, number, name, &info, &key, &seed);
    if (status != 0)
        goto done;
    status = patch_read_adjusted(clone, name, number, seed, &body, &body_size);
    if (status != 0)
        goto done;
    if (body_size != info.data_size) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    status = patch_check_md5(body, body_size, info.md5);
    if (status == 0) {
        *data = body;
        *size = body_size;
        body = NULL;
    }

done:
    if (clone != NULL) {
        int32_t close_status = libmpq__archive_close(clone);

        if (status == 0)
            status = close_status;
    }
    if (status != 0) {
        free(*data);
        *data = NULL;
        *size = 0;
    }
    free(body);
    return status;
}

int32_t
libmpq__patch_reader_payload_read(
    mpq_archive_s *archive, uint32_t number, const char *name, uint8_t *buffer,
    libmpq__off_t capacity, libmpq__off_t *transferred
)
{
    libmpq__off_t expected;
    uint8_t *body = NULL;
    size_t body_size = 0;
    int32_t status;

    if (transferred == NULL)
        return LIBMPQ_ERROR_EXIST;
    *transferred = 0;
    status = libmpq__patch_reader_payload_size(archive, number, &expected);
    if (status != 0)
        return status;
    if (capacity < 0 || capacity < expected || (expected != 0 && buffer == NULL))
        return LIBMPQ_ERROR_SIZE;
    status = patch_read_incremental(archive, name, number, &body, &body_size);
    if (status == 0) {
        if ((uint64_t)body_size != (uint64_t)expected)
            status = LIBMPQ_ERROR_FORMAT;
        else {
            if (body_size != 0)
                memcpy(buffer, body, body_size);
            *transferred = expected;
        }
    }
    free(body);
    return status;
}

/* Live hash identity is enough to match an existing member without its name. */
static uint8_t
patch_live_hash(const mpq_archive_s *archive, const mpq_hash_s *hash)
{
    uint32_t index;
    return libmpq__entry_index_from_classic(archive, hash->block_table_index, &index) == 0 &&
           (archive->mpq_entry[index].flags & LIBMPQ_FLAG_EXISTS) != 0;
}

static uint32_t
patch_hash_slot(
    const mpq_archive_s *archive, uint32_t hash_a, uint32_t hash_b, uint16_t locale,
    uint16_t platform
)
{
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; i++) {
        const mpq_hash_s *candidate = &archive->mpq_hash[i];

        if (patch_live_hash(archive, candidate) && candidate->hash_a == hash_a &&
            candidate->hash_b == hash_b && candidate->locale == locale &&
            candidate->platform == platform)
            return i;
    }
    return UINT32_MAX;
}

static uint32_t
patch_matching_hash(const mpq_archive_s *archive, const mpq_patch_entry_s *needle)
{
    return patch_hash_slot(
        archive, needle->hash_a, needle->hash_b, needle->locale, needle->platform
    );
}

static uint32_t
patch_number_for_block(const mpq_archive_s *archive, uint32_t block)
{
    uint32_t index;
    uint32_t number;
    if (libmpq__entry_index_from_classic(archive, block, &index) != 0)
        return UINT32_MAX;
    number = archive->mpq_entry[index].file_number;
    return number < archive->files && archive->mpq_map[number].entry_index == index ? number
                                                                                    : UINT32_MAX;
}

/* Resolve identity first; the source's block index only decodes its wire row. */
static int32_t
patch_attribute_for_identity(
    const mpq_archive_s *archive, uint32_t hash_a, uint32_t hash_b, uint16_t locale,
    uint16_t platform, mpq_file_attributes_s *attributes
)
{
    uint32_t slot;
    uint32_t index;

    memset(attributes, 0, sizeof(*attributes));
    if (archive->attributes == NULL)
        return LIBMPQ_ERROR_EXIST;
    slot = patch_hash_slot(archive, hash_a, hash_b, locale, platform);
    if (slot == UINT32_MAX)
        return LIBMPQ_ERROR_EXIST;
    if (libmpq__entry_index_from_classic(
            archive, archive->mpq_hash[slot].block_table_index, &index
        ) != 0)
        return LIBMPQ_ERROR_FORMAT;
    libmpq__attributes_get(
        archive->attributes, archive->mpq_entry[index].classic_source_index, attributes
    );
    return 0;
}

static uint8_t
patch_known_internal(uint32_t hash_a, uint32_t hash_b)
{
    static const char *const names[] = { LIBMPQ_LISTFILE_NAME, LIBMPQ_ATTRIBUTES_NAME,
                                         LIBMPQ_SIGNATURE_NAME, "(patch_metadata)" };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (hash_a == libmpq__crypto_hash_string(names[i], 0x100) &&
            hash_b == libmpq__crypto_hash_string(names[i], 0x200))
            return 1;
    return 0;
}

static uint32_t
patch_internal_slot(const mpq_archive_s *archive, const char *name)
{
    uint32_t hash_a = libmpq__crypto_hash_string(name, 0x100);
    uint32_t hash_b = libmpq__crypto_hash_string(name, 0x200);

    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; i++)
        if (patch_live_hash(archive, &archive->mpq_hash[i]) &&
            archive->mpq_hash[i].hash_a == hash_a && archive->mpq_hash[i].hash_b == hash_b)
            return i;
    return UINT32_MAX;
}

static uint8_t
patch_hash_present(const mpq_archive_s *archive, uint32_t hash_a, uint32_t hash_b)
{
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; i++)
        if (patch_live_hash(archive, &archive->mpq_hash[i]) &&
            archive->mpq_hash[i].hash_a == hash_a && archive->mpq_hash[i].hash_b == hash_b)
            return 1;
    return 0;
}

static void
patch_delete_hash(mpq_hash_s *hash)
{
    memset(hash, 0, sizeof(*hash));
    hash->block_table_index = LIBMPQ_HASH_DELETED;
}

/* Build authoritative entries from live hashes and optionally enrich their names. */
static int32_t
patch_entries(mpq_archive_s *patch, mpq_patch_entry_s **entries, uint32_t *entry_count)
{
    uint8_t *list = NULL;
    size_t size = 0;
    size_t position = 0;
    int32_t status;

    *entries = NULL;
    if (patch->het_data != NULL)
        return LIBMPQ_ERROR_FORMAT;
    *entry_count = patch->mpq_header.hash_table_count;
    if (*entry_count == 0)
        return LIBMPQ_ERROR_FORMAT;
    *entries = calloc(*entry_count, sizeof(**entries));
    if (*entries == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (uint32_t i = 0; i < *entry_count; i++) {
        const mpq_hash_s *hash = &patch->mpq_hash[i];
        mpq_patch_entry_s *entry = &(*entries)[i];

        if (!patch_live_hash(patch, hash))
            continue;
        entry->hash_a = hash->hash_a;
        entry->hash_b = hash->hash_b;
        entry->physical_hash_a = hash->hash_a;
        entry->physical_hash_b = hash->hash_b;
        entry->locale = hash->locale;
        entry->platform = hash->platform;
        entry->block_index = hash->block_table_index;
        entry->number = patch_number_for_block(patch, hash->block_table_index);
        entry->live = 1;
    }
    status = patch_read_named(patch, LIBMPQ_LISTFILE_NAME, &list, &size);
    if (status != 0) {
        free(list);
        return status == LIBMPQ_ERROR_MALLOC ? status : 0;
    }
    while (position < size) {
        size_t start = position;
        size_t length;
        uint32_t first;
        uint32_t second;

        while (position < size && list[position] != '\n')
            position++;
        length = position - start;
        if (position < size)
            position++;
        if (length != 0 && list[start + length - 1] == '\r')
            length--;
        if (length == 0)
            continue;
        if ((memchr)(list + start, 0, length) != NULL)
            continue;
        {
            char *name = malloc(length + 1);

            if (name == NULL) {
                status = LIBMPQ_ERROR_MALLOC;
                break;
            }
            memcpy(name, list + start, length);
            name[length] = '\0';
            first = libmpq__crypto_hash_string(name, 0x100);
            second = libmpq__crypto_hash_string(name, 0x200);
            for (uint32_t i = 0; i < *entry_count; i++) {
                mpq_patch_entry_s *entry = &(*entries)[i];

                if (!entry->live || entry->hash_a != first || entry->hash_b != second ||
                    entry->name != NULL)
                    continue;
                entry->name = malloc(length + 1);
                if (entry->name == NULL) {
                    status = LIBMPQ_ERROR_MALLOC;
                    break;
                }
                memcpy(entry->name, name, length + 1);
            }
            free(name);
            if (status != 0)
                break;
        }
    }
    free(list);
    return status;
}

/* Compare names using the same byte-wise uppercase folding as MPQ hashing. */
static uint8_t
patch_name_equal(const char *left, const char *right, size_t length)
{
    for (size_t i = 0; i < length; i++)
        if (toupper((unsigned char)left[i]) != toupper((unsigned char)right[i]))
            return 0;
    return 1;
}

/* Identify only a complete metadata path component, not a similar basename. */
static uint8_t
patch_metadata_path(const char *name, size_t *prefix_length)
{
    const char *separator = (strrchr)(name, '\\');
    const char *basename = separator == NULL ? name : separator + 1;
    static const char marker[] = "(patch_metadata)";

    if (strlen(basename) != sizeof(marker) - 1 ||
        !patch_name_equal(basename, marker, sizeof(marker) - 1))
        return 0;
    *prefix_length = separator == NULL ? 0 : (size_t)(separator - name) + 1;
    return 1;
}

/* Normalize an explicit prefix to either empty or one trailing backslash. */
static int32_t
patch_normalize_prefix(const char *input, char **result)
{
    size_t length = strlen(input);

    while (length != 0 && input[length - 1] == '\\')
        length--;
    if (length > SIZE_MAX - 2)
        return LIBMPQ_ERROR_SIZE;
    *result = malloc(length + (length != 0) + 1);
    if (*result == NULL)
        return LIBMPQ_ERROR_MALLOC;
    memcpy(*result, input, length);
    if (length != 0)
        (*result)[length++] = '\\';
    (*result)[length] = '\0';
    return 0;
}

/* Accept one live namespace marker using the materializer's metadata rules. */
static int32_t
patch_discover_marker(
    mpq_archive_s *archive, const char *name, size_t length, uint32_t number, char **discovered
)
{
    libmpq__off_t size;
    if (length == SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    if (*discovered == NULL) {
        *discovered = malloc(length + 1);
        if (*discovered == NULL)
            return LIBMPQ_ERROR_MALLOC;
        memcpy(*discovered, name, length);
        (*discovered)[length] = '\0';
    } else if (strlen(*discovered) != length || !patch_name_equal(*discovered, name, length))
        return LIBMPQ_ERROR_FORMAT;
    if (number == UINT32_MAX || libmpq__file_size_unpacked(archive, number, &size) != 0 ||
        size <= 0 || size >= 64)
        return LIBMPQ_ERROR_FORMAT;
    return 0;
}

/* A caller prefix and a discovered marker must name the same namespace. */
static int
patch_prefix_conflicts(const char *explicit_prefix, const char *discovered)
{
    return explicit_prefix != NULL && discovered != NULL &&
           (strlen(explicit_prefix) != strlen(discovered) ||
            !patch_name_equal(explicit_prefix, discovered, strlen(discovered)));
}

/* Keep physical member lookup separate from logical lower-layer identity. */
static int32_t
patch_prepare_entries(
    mpq_archive_s *patch, mpq_patch_entry_s *entries, uint32_t entry_count,
    const mpq_patch_source_s *source, uint8_t *detected
)
{
    char *discovered = NULL;
    char *explicit_prefix = NULL;
    char *marker_name = NULL;
    const char *prefix;
    size_t prefix_length;
    int32_t status = 0;

    if (source->prefix != NULL) {
        status = patch_normalize_prefix(source->prefix, &explicit_prefix);
        if (status != 0)
            goto done;
    }
    for (uint32_t i = 0; i < entry_count; i++) {
        mpq_patch_entry_s *entry = &entries[i];
        size_t length;

        if (!entry->live || entry->name == NULL || !patch_metadata_path(entry->name, &length))
            continue;
        *detected = 1;
        status = patch_discover_marker(patch, entry->name, length, entry->number, &discovered);
        if (status != 0)
            goto done;
    }
    if (patch_prefix_conflicts(explicit_prefix, discovered)) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    prefix = explicit_prefix != NULL ? explicit_prefix : discovered;
    if (prefix == NULL)
        prefix = "";
    prefix_length = strlen(prefix);
    if (prefix_length != 0) {
        static const char marker[] = "(patch_metadata)";

        if (prefix_length > SIZE_MAX - sizeof(marker)) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        marker_name = malloc(prefix_length + sizeof(marker));
        if (marker_name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        memcpy(marker_name, prefix, prefix_length);
        memcpy(marker_name + prefix_length, marker, sizeof(marker));
    }
    for (uint32_t i = 0; i < entry_count; i++) {
        mpq_patch_entry_s *entry = &entries[i];
        size_t ignored;

        if (!entry->live)
            continue;
        if (patch_known_internal(entry->physical_hash_a, entry->physical_hash_b) ||
            (marker_name != NULL &&
             entry->physical_hash_a == libmpq__crypto_hash_string(marker_name, 0x100) &&
             entry->physical_hash_b == libmpq__crypto_hash_string(marker_name, 0x200)) ||
            (entry->name != NULL && patch_metadata_path(entry->name, &ignored))) {
            entry->internal = 1;
            continue;
        }
        if (prefix_length == 0)
            continue;
        if (entry->name == NULL) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (strlen(entry->name) < prefix_length ||
            !patch_name_equal(entry->name, prefix, prefix_length)) {
            entry->live = 0;
            continue;
        }
        if (entry->name[prefix_length] == '\0') {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        entry->physical_name = entry->name;
        {
            const char *logical = entry->physical_name + prefix_length;
            size_t length = strlen(logical);

            entry->name = malloc(length + 1);
            if (entry->name != NULL)
                memcpy(entry->name, logical, length + 1);
        }
        if (entry->name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        entry->hash_a = libmpq__crypto_hash_string(entry->name, 0x100);
        entry->hash_b = libmpq__crypto_hash_string(entry->name, 0x200);
    }

done:
    free(marker_name);
    free(explicit_prefix);
    free(discovered);
    return status;
}

/* Grow every reader-owned block array before changing the serialized count. */
static int32_t
patch_new_block(mpq_archive_s *archive, uint32_t *index)
{
    uint32_t block = archive->mpq_header.block_table_count;
    size_t count = (size_t)block + 1;
    uint32_t entry_index = archive->entry_count;
    size_t entries = (size_t)entry_index + 1;
    void *grown;

    if (block == UINT32_MAX || entry_index == UINT32_MAX ||
        count > SIZE_MAX / sizeof(*archive->classic_entry_indices) ||
        count > SIZE_MAX / sizeof(*archive->mpq_block) ||
        count > SIZE_MAX / sizeof(*archive->mpq_block_ex) ||
        entries > SIZE_MAX / sizeof(*archive->mpq_entry) ||
        entries > SIZE_MAX / sizeof(*archive->mpq_file) ||
        entries > SIZE_MAX / sizeof(*archive->mpq_map))
        return LIBMPQ_ERROR_SIZE;
    grown = realloc(archive->mpq_block, count * sizeof(*archive->mpq_block));
    if (grown == NULL)
        return LIBMPQ_ERROR_MALLOC;
    archive->mpq_block = grown;
    grown = realloc(archive->mpq_block_ex, count * sizeof(*archive->mpq_block_ex));
    if (grown == NULL)
        return LIBMPQ_ERROR_MALLOC;
    archive->mpq_block_ex = grown;
    grown =
        realloc(archive->classic_entry_indices, count * sizeof(*archive->classic_entry_indices));
    if (grown == NULL)
        return LIBMPQ_ERROR_MALLOC;
    archive->classic_entry_indices = grown;
    grown = realloc(archive->mpq_file, entries * sizeof(*archive->mpq_file));
    if (grown == NULL)
        return LIBMPQ_ERROR_MALLOC;
    archive->mpq_file = grown;
    grown = realloc(archive->mpq_map, entries * sizeof(*archive->mpq_map));
    if (grown == NULL)
        return LIBMPQ_ERROR_MALLOC;
    archive->mpq_map = grown;
    grown = realloc(archive->mpq_entry, entries * sizeof(*archive->mpq_entry));
    if (grown == NULL)
        return LIBMPQ_ERROR_MALLOC;
    archive->mpq_entry = grown;
    memset(&archive->mpq_block[block], 0, sizeof(*archive->mpq_block));
    memset(&archive->mpq_block_ex[block], 0, sizeof(*archive->mpq_block_ex));
    archive->mpq_file[entry_index] = NULL;
    memset(&archive->mpq_map[entry_index], 0, sizeof(*archive->mpq_map));
    archive->classic_entry_indices[block] = entry_index;
    libmpq__entry_from_classic(
        &archive->mpq_entry[entry_index], &archive->mpq_block[block], &archive->mpq_block_ex[block],
        block
    );
    archive->entry_count++;
    archive->mpq_header.block_table_count++;
    *index = block;
    return 0;
}

static int32_t
patch_insert_hash(mpq_archive_s *archive, const char *name, const mpq_hash_s *entry)
{
    uint32_t count = archive->mpq_header.hash_table_count;
    uint32_t start;
    uint32_t candidate = UINT32_MAX;

    if (count == 0)
        return LIBMPQ_ERROR_FORMAT;
    start = libmpq__crypto_hash_string(name, 0) % count;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t slot = (start + i) % count;
        uint32_t index = archive->mpq_hash[slot].block_table_index;

        if (index == UINT32_MAX - 1u && candidate == UINT32_MAX)
            candidate = slot;
        if (index == UINT32_MAX) {
            if (candidate == UINT32_MAX)
                candidate = slot;
            break;
        }
    }
    if (candidate == UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    archive->mpq_hash[candidate] = *entry;
    return 0;
}

/* Changed files use a private raw single-unit payload; old physical data stays intact. */
static int32_t
patch_append_member(
    mpq_archive_s *archive, FILE *output, const uint8_t *data, size_t size, uint32_t *block
)
{
    libmpq__off_t absolute = libmpq__file_tell(output);
    uint64_t offset;
    uint32_t index;
    int32_t status;

    if (absolute < archive->archive_offset)
        return LIBMPQ_ERROR_SEEK;
    offset = (uint64_t)(absolute - archive->archive_offset);
    if (offset > UINT32_MAX || size > UINT32_MAX || size > UINT32_MAX - offset)
        return LIBMPQ_ERROR_SIZE;
    status = patch_new_block(archive, block);
    if (status != 0)
        return status;
    status = libmpq__entry_index_from_classic(archive, *block, &index);
    if (status != 0)
        return status;
    if (size != 0 && fwrite(data, 1, size, output) != size)
        return LIBMPQ_ERROR_WRITE;
    archive->mpq_block[*block].offset = (uint32_t)offset;
    archive->mpq_block[*block].packed_size = (uint32_t)size;
    archive->mpq_block[*block].unpacked_size = (uint32_t)size;
    archive->mpq_block[*block].flags = LIBMPQ_FLAG_EXISTS | LIBMPQ_FLAG_SINGLE;
    libmpq__entry_from_classic(
        &archive->mpq_entry[index], &archive->mpq_block[*block], &archive->mpq_block_ex[*block],
        *block
    );
    return 0;
}

static uint8_t
patch_list_contains(const uint8_t *list, size_t size, const char *name)
{
    size_t length = strlen(name);
    size_t at = 0;

    while (at < size) {
        size_t start = at;

        while (at < size && list[at] != '\n')
            at++;
        if (at - start == length && memcmp(list + start, name, length) == 0)
            return 1;
        if (at < size)
            at++;
    }
    return 0;
}

static void
patch_set_attributes(
    mpq_file_attributes_s *attributes, uint32_t flags, const uint8_t *data, size_t size,
    int32_t patch_bit
)
{
    mpq_md5_s md5;
    size_t at = 0;
    uint32_t crc = (uint32_t)crc32(0, Z_NULL, 0);

    memset(attributes, 0, sizeof(*attributes));
    attributes->flags = flags;
    attributes->patch_bit = patch_bit;
    while (at < size) {
        uInt count = size - at > UINT_MAX ? UINT_MAX : (uInt)(size - at);

        crc = (uint32_t)crc32(crc, data + at, count);
        at += count;
    }
    attributes->crc32 = crc;
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, data, size);
    libmpq__md5_final(&md5, attributes->md5);
}

/* Keep known live names, remove deleted names, and enrich new named entries. */
static int32_t
patch_rewrite_listfile(
    mpq_archive_s *lower, mpq_archive_s *target, const mpq_patch_entry_s *entries,
    uint32_t entry_count, FILE *output, mpq_file_attributes_s *list_row, uint32_t attribute_flags,
    uint8_t add_attributes_name
)
{
    uint8_t *original = NULL;
    uint8_t *updated = NULL;
    size_t original_size = 0;
    size_t capacity;
    size_t used = 0;
    size_t at = 0;
    uint32_t slot = patch_internal_slot(target, LIBMPQ_LISTFILE_NAME);
    int32_t status;

    if (slot == UINT32_MAX)
        return 0;
    status = patch_read_named(lower, LIBMPQ_LISTFILE_NAME, &original, &original_size);
    if (status != 0)
        return status;
    if (original_size == SIZE_MAX) {
        status = LIBMPQ_ERROR_SIZE;
        goto done;
    }

    /* A final line without a newline gains one byte when rewritten. */
    capacity = original_size + 1;
    if (add_attributes_name) {
        if (capacity > SIZE_MAX - sizeof(LIBMPQ_ATTRIBUTES_NAME)) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        capacity += sizeof(LIBMPQ_ATTRIBUTES_NAME);
    }
    for (uint32_t i = 0; i < entry_count; i++) {
        size_t length;

        if (entries[i].name == NULL)
            continue;
        length = strlen(entries[i].name);
        if (capacity == SIZE_MAX || length > SIZE_MAX - capacity - 1) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        capacity += length + 1;
    }
    updated = malloc(capacity == 0 ? 1 : capacity);
    if (updated == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    while (at < original_size) {
        size_t start = at;
        size_t length;
        char *name;

        while (at < original_size && original[at] != '\n' && original[at] != '\r')
            at++;
        length = at - start;
        while (at < original_size && (original[at] == '\n' || original[at] == '\r'))
            at++;
        if (length == 0)
            continue;
        if ((memchr)(original + start, 0, length) != NULL) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        name = malloc(length + 1);
        if (name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        memcpy(name, original + start, length);
        name[length] = '\0';
        if (strcmp(name, LIBMPQ_SIGNATURE_NAME) != 0 && strcmp(name, "(patch_metadata)") != 0 &&
            patch_hash_present(
                target, libmpq__crypto_hash_string(name, 0x100),
                libmpq__crypto_hash_string(name, 0x200)
            )) {
            if (used > capacity || length >= capacity - used) {
                free(name);
                status = LIBMPQ_ERROR_SIZE;
                goto done;
            }
            memcpy(updated + used, name, length);
            used += length;
            updated[used++] = '\n';
        }
        free(name);
    }
    for (uint32_t i = 0; i < entry_count; i++) {
        size_t length;

        if (!entries[i].live || entries[i].internal || entries[i].name == NULL ||
            patch_known_internal(entries[i].hash_a, entries[i].hash_b) ||
            !patch_hash_present(target, entries[i].hash_a, entries[i].hash_b) ||
            patch_list_contains(updated, used, entries[i].name))
            continue;
        length = strlen(entries[i].name);
        if (used > capacity || length >= capacity - used) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        memcpy(updated + used, entries[i].name, length);
        used += length;
        updated[used++] = '\n';
    }
    if (add_attributes_name && !patch_list_contains(updated, used, LIBMPQ_ATTRIBUTES_NAME)) {
        static const uint8_t attributes_line[] = LIBMPQ_ATTRIBUTES_NAME "\n";
        size_t length = sizeof(attributes_line) - 1;

        if (used > capacity || length > capacity - used) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        memcpy(updated + used, attributes_line, length);
        used += length;
    }
    {
        uint32_t block;

        status = patch_append_member(target, output, updated, used, &block);
        if (status == 0) {
            target->mpq_hash[slot].block_table_index = block;
            if (list_row != NULL)
                patch_set_attributes(list_row, attribute_flags, updated, used, 0);
        }
    }

done:
    free(original);
    free(updated);
    return status;
}

/* Map source and changed hash identities onto the result's serialized rows. */
static int32_t
patch_remap_attributes(
    const mpq_archive_s *lower, const mpq_archive_s *target, const mpq_patch_entry_s *entries,
    const mpq_file_attributes_s *changed_rows, const uint8_t *changed, uint32_t entry_count,
    const mpq_file_attributes_s *list_row, mpq_file_attributes_s *result_rows
)
{
    uint32_t list_a = libmpq__crypto_hash_string(LIBMPQ_LISTFILE_NAME, 0x100);
    uint32_t list_b = libmpq__crypto_hash_string(LIBMPQ_LISTFILE_NAME, 0x200);
    uint32_t attributes_a = libmpq__crypto_hash_string(LIBMPQ_ATTRIBUTES_NAME, 0x100);
    uint32_t attributes_b = libmpq__crypto_hash_string(LIBMPQ_ATTRIBUTES_NAME, 0x200);
    uint8_t *assigned;
    int32_t status = 0;

    assigned = calloc(target->mpq_header.block_table_count, 1);
    if (assigned == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (uint32_t i = 0; i < target->mpq_header.hash_table_count; i++) {
        const mpq_hash_s *hash = &target->mpq_hash[i];
        mpq_file_attributes_s row = { 0 };
        uint32_t block;
        uint8_t resolved = 0;

        if (!patch_live_hash(target, hash) ||
            (hash->hash_a == attributes_a && hash->hash_b == attributes_b))
            continue;
        block = hash->block_table_index;
        if (hash->hash_a == list_a && hash->hash_b == list_b && list_row != NULL) {
            row = *list_row;
            resolved = 1;
        }
        for (uint32_t j = entry_count; j > 0 && !resolved; j--) {
            const mpq_patch_entry_s *entry = &entries[j - 1];

            if (changed[j - 1] && entry->hash_a == hash->hash_a && entry->hash_b == hash->hash_b &&
                entry->locale == hash->locale && entry->platform == hash->platform) {
                row = changed_rows[j - 1];
                resolved = 1;
            }
        }
        if (!resolved && lower->attributes != NULL) {
            status = patch_attribute_for_identity(
                lower, hash->hash_a, hash->hash_b, hash->locale, hash->platform, &row
            );
            if (status != 0)
                goto done;
        }
        if (assigned[block] && memcmp(&result_rows[block], &row, sizeof(row)) != 0) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        result_rows[block] = row;
        assigned[block] = 1;
    }

done:
    free(assigned);
    return status;
}

static int32_t
patch_rewrite_attributes(
    mpq_archive_s *target, FILE *output, mpq_file_attributes_s *attributes, uint32_t flags
)
{
    uint32_t slot = patch_internal_slot(target, LIBMPQ_ATTRIBUTES_NAME);
    uint32_t self;
    uint32_t block;
    uint8_t *data = NULL;
    size_t size = 0;
    int32_t status;

    if (attributes == NULL)
        return 0;
    if (target->mpq_header.block_table_count == UINT32_MAX)
        return LIBMPQ_ERROR_FORMAT;
    self = target->mpq_header.block_table_count;
    status =
        libmpq__attributes_serialize_patch_bits(attributes, self + 1, self, flags, &data, &size);
    if (status != 0)
        return status;
    status = patch_append_member(target, output, data, size, &block);
    if (status == 0) {
        if (block != self)
            status = LIBMPQ_ERROR_FORMAT;
        else if (slot != UINT32_MAX)
            target->mpq_hash[slot].block_table_index = block;
        else {
            mpq_hash_s inserted = { libmpq__crypto_hash_string(LIBMPQ_ATTRIBUTES_NAME, 0x100),
                                    libmpq__crypto_hash_string(LIBMPQ_ATTRIBUTES_NAME, 0x200), 0, 0,
                                    block };

            status = patch_insert_hash(target, LIBMPQ_ATTRIBUTES_NAME, &inserted);
        }
    }
    free(data);
    return status;
}

/* Serialize the private view's updated tables without using update semantics. */
static int32_t
patch_write_tables(mpq_archive_s *archive, FILE *output)
{
    uint8_t header[LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE] = { 0 };
    mpq_header_s wire_header;
    mpq_header_ex_s wire_ex;
    int32_t result;
    uint8_t *raw;
    uint64_t hash_offset;
    uint64_t block_offset;
    uint64_t extended_offset = 0;
    uint64_t end;
    size_t bytes;

    if (libmpq__file_tell(output) < 0)
        return LIBMPQ_ERROR_SEEK;
    if (libmpq__file_tell(output) < archive->archive_offset)
        return LIBMPQ_ERROR_SEEK;
    hash_offset = (uint64_t)(libmpq__file_tell(output) - archive->archive_offset);
    if (hash_offset > UINT32_MAX ||
        archive->mpq_header.hash_table_count > UINT32_MAX / LIBMPQ_HASH_ENTRY_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    bytes = (size_t)archive->mpq_header.hash_table_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    raw = malloc(bytes == 0 ? 1 : bytes);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__hash_table_encode(
        archive->mpq_hash, archive->mpq_header.hash_table_count, raw, bytes
    );
    if (result < 0) {
        free(raw);
        return result;
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    if (fwrite(raw, 1, bytes, output) != bytes) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);
    block_offset = (uint64_t)(libmpq__file_tell(output) - archive->archive_offset);
    if (archive->mpq_header.block_table_count > UINT32_MAX / LIBMPQ_BLOCK_ENTRY_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    bytes = (size_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    raw = malloc(bytes == 0 ? 1 : bytes);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__block_table_encode(
        archive->mpq_block, archive->mpq_header.block_table_count, raw, bytes
    );
    if (result < 0) {
        free(raw);
        return result;
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(block table)", 0x300)
    );
    if (fwrite(raw, 1, bytes, output) != bytes) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        extended_offset = (uint64_t)(libmpq__file_tell(output) - archive->archive_offset);
        for (uint32_t i = 0; i < archive->mpq_header.block_table_count; i++) {
            uint8_t word[2];

            result =
                libmpq__block_ex_table_encode(&archive->mpq_block_ex[i], 1, word, sizeof(word));
            if (result < 0)
                return result;
            if (fwrite(word, 1, sizeof(word), output) != sizeof(word))
                return LIBMPQ_ERROR_WRITE;
        }
    }
    end = (uint64_t)(libmpq__file_tell(output) - archive->archive_offset);
    if (end > UINT32_MAX || archive->mpq_header.header_size > sizeof(header))
        return LIBMPQ_ERROR_SIZE;
    wire_header = archive->mpq_header;
    wire_header.mpq_magic = LIBMPQ_HEADER;
    wire_header.archive_size = (uint32_t)end;
    wire_header.hash_table_offset = (uint32_t)hash_offset;
    wire_header.block_table_offset = (uint32_t)block_offset;
    result = libmpq__header_encode(&wire_header, header, sizeof(header));
    if (result < 0)
        return result;
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        wire_ex.extended_offset = extended_offset;
        wire_ex.hash_table_offset_high = 0;
        wire_ex.block_table_offset_high = 0;
        result = libmpq__header_ex_encode(
            &wire_ex, header + LIBMPQ_HEADER_WIRE_SIZE, LIBMPQ_HEADER_EX_WIRE_SIZE
        );
        if (result < 0)
            return result;
    }
    if (libmpq__file_seek(output, (uint64_t)archive->archive_offset, SEEK_SET) != 0 ||
        fwrite(header, 1, archive->mpq_header.header_size, output) !=
            archive->mpq_header.header_size)
        return LIBMPQ_ERROR_WRITE;
    return fflush(output) == 0 ? 0 : LIBMPQ_ERROR_WRITE;
}

/* Apply one hash entry, using its name only when needed for decoding or insertion. */
static int32_t
patch_stage_hash(
    mpq_archive_s *lower, mpq_archive_s *target, mpq_archive_s *patch,
    const mpq_patch_entry_s *entry, FILE *output, mpq_file_attributes_s *changed_row,
    uint32_t attribute_flags
)
{
    uint32_t slot = patch_matching_hash(lower, entry);
    uint32_t patch_number = patch_number_for_block(patch, entry->block_index);
    uint32_t lower_number = UINT32_MAX;
    uint32_t flags;
    uint8_t *payload = NULL;
    uint8_t *base = NULL;
    uint8_t *result = NULL;
    uint8_t borrowed_result = 0;
    size_t payload_size = 0;
    size_t base_size = 0;
    size_t result_size = 0;
    uint32_t block;
    int32_t status;

    if (patch_number == UINT32_MAX)
        return LIBMPQ_ERROR_FORMAT;
    flags = patch->mpq_entry[patch->mpq_map[patch_number].entry_index].flags;
    if (slot != UINT32_MAX)
        lower_number = patch_number_for_block(lower, lower->mpq_hash[slot].block_table_index);
    if ((flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0) {
        if (slot != UINT32_MAX)
            patch_delete_hash(&target->mpq_hash[slot]);
        return 0;
    }
    if (slot == UINT32_MAX && entry->name == NULL)
        return LIBMPQ_ERROR_FORMAT;
    if ((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0)
        status = patch_read_incremental(
            patch, entry->physical_name == NULL ? entry->name : entry->physical_name, patch_number,
            &payload, &payload_size
        );
    else
        status = patch_read_adjusted(
            patch, entry->physical_name == NULL ? entry->name : entry->physical_name, patch_number,
            NULL, &payload, &payload_size
        );
    if (status != 0)
        goto done;
    if ((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0) {
        if (lower_number == UINT32_MAX) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        status = patch_read_adjusted(lower, entry->name, lower_number, NULL, &base, &base_size);
        if (status == 0) {
            borrowed_result =
                payload_size > LIBMPQ_PATCH_HEADER_SIZE && memcmp(payload + 64, "COPY", 4) == 0;
            status = patch_apply_internal(
                base, base_size, payload, payload_size, &result, &result_size, borrowed_result
            );
        }
    } else {
        result = payload;
        result_size = payload_size;
        payload = NULL;
    }
    if (status != 0)
        goto done;
    status = patch_append_member(target, output, result, result_size, &block);
    if (status != 0)
        goto done;
    if (changed_row != NULL) {
        mpq_file_attributes_s inherited = { 0 };
        mpq_file_attributes_s patch_row = { 0 };

        if (lower->attributes != NULL) {
            status = patch_attribute_for_identity(
                lower, entry->hash_a, entry->hash_b, entry->locale, entry->platform, &inherited
            );
            if (status != 0 && status != LIBMPQ_ERROR_EXIST)
                goto done;
        }
        if (patch->attributes != NULL) {
            status = patch_attribute_for_identity(
                patch, entry->physical_hash_a, entry->physical_hash_b, entry->locale,
                entry->platform, &patch_row
            );
            if (status != 0)
                goto done;
            if ((patch_row.flags & LIBMPQ_ATTRIBUTE_FILETIME) != 0)
                inherited.filetime = patch_row.filetime;
        }
        patch_set_attributes(
            changed_row, attribute_flags, result, result_size, inherited.patch_bit
        );
        changed_row->filetime = inherited.filetime;
    }
    if (slot != UINT32_MAX)
        target->mpq_hash[slot].block_table_index = block;
    else {
        mpq_hash_s inserted = { entry->hash_a, entry->hash_b, entry->locale, entry->platform,
                                block };

        status = patch_insert_hash(target, entry->name, &inserted);
    }

done:
    free(base);
    free(payload);
    if (!borrowed_result)
        free(result);
    return status;
}

/* Open an ordinary MPQ or authenticate an MPQE source through the existing reader. */
static int32_t
patch_source_open(mpq_archive_s **archive, const mpq_patch_source_s *source)
{
    int32_t result;
    if (archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *archive = NULL;
    if (source == NULL || source->path == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = source->auth_code == NULL
                 ? libmpq__archive_open(archive, source->path, -1)
                 : libmpq__archive_open_mpqe(
                       archive, source->path, -1, source->auth_code, source->auth_code_size
                   );
    if (result == 0 && (*archive)->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_FOUR) {
        (void)libmpq__archive_close(*archive);
        *archive = NULL;
        return LIBMPQ_ERROR_FORMAT;
    }
    return result;
}

/* Compare full names, not possibly truncated filename hashes. */
static uint8_t
patch_named_equal(const char *left, const char *right)
{
    for (;;) {
        uint8_t a = (uint8_t)*left++;
        uint8_t b = (uint8_t)*right++;
        if (a >= 'A' && a <= 'Z')
            a = (uint8_t)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z')
            b = (uint8_t)(b + ('a' - 'A'));
        if (a == '/')
            a = '\\';
        if (b == '/')
            b = '\\';
        if (a != b)
            return 0;
        if (a == 0)
            return 1;
    }
}

/* Record caller-known/listed spellings only after validating their public mapping. */
static int32_t
patch_record_named(mpq_archive_s *archive, mpq_patch_entry_s *entries, const char *name)
{
    uint32_t number;
    int32_t status = libmpq__file_number(archive, name, &number);
    mpq_patch_entry_s *entry;

    if (status != 0)
        return status;
    if (libmpq__reader_validate_file_number(archive, number) != 0)
        return LIBMPQ_ERROR_FORMAT;
    entry = &entries[number];
    if (entry->name != NULL)
        return patch_named_equal(entry->name, name) ? 0 : LIBMPQ_ERROR_FORMAT;
    entry->name = malloc(strlen(name) + 1);
    if (entry->name == NULL)
        return LIBMPQ_ERROR_MALLOC;
    memcpy(entry->name, name, strlen(name) + 1);
    entry->hash_a = entry->physical_hash_a = libmpq__crypto_hash_string(name, 0x100);
    entry->hash_b = entry->physical_hash_b = libmpq__crypto_hash_string(name, 0x200);
    return 0;
}

/* Enumerate canonical rows; never assume that a public number is a source index. */
static int32_t
patch_named_entries(mpq_archive_s *archive, mpq_patch_entry_s **out)
{
    static const char *const special[] = { LIBMPQ_LISTFILE_NAME, LIBMPQ_ATTRIBUTES_NAME,
                                           LIBMPQ_SIGNATURE_NAME, "(patch_metadata)" };
    mpq_patch_entry_s *entries;
    uint8_t *list = NULL;
    size_t size = 0;
    size_t position = 0;
    int32_t status = 0;

    *out = NULL;
    if ((uint64_t)archive->files * sizeof(*entries) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    entries = calloc(archive->files == 0 ? 1 : archive->files, sizeof(*entries));
    if (entries == NULL)
        return LIBMPQ_ERROR_MALLOC;

    /* The caller owns partial names as well as the successful result. */
    *out = entries;
    for (uint32_t i = 0; i < archive->files; i++) {
        const mpq_entry_s *canonical;
        uint32_t translated;

        if (libmpq__reader_validate_file_number(archive, i) != 0)
            return LIBMPQ_ERROR_FORMAT;
        canonical = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        if (canonical->source_mask == LIBMPQ_ENTRY_SOURCE_NONE)
            return LIBMPQ_ERROR_FORMAT;
        if ((canonical->source_mask & LIBMPQ_ENTRY_SOURCE_BET) != 0) {
            mpq_bet_entry_s record;
            status =
                libmpq__entry_index_from_bet(archive, canonical->bet_source_index, &translated);
            if (status != 0 || translated != archive->mpq_map[i].entry_index)
                return LIBMPQ_ERROR_FORMAT;
            status =
                libmpq__bet_record_decode(&archive->mpq_bet, canonical->bet_source_index, &record);
            if (status != 0)
                return status;
            if (record.unknown != 0)
                return LIBMPQ_ERROR_FORMAT;
        }
        entries[i].number = i;
        entries[i].block_index = canonical->classic_source_index;
        entries[i].live = 1;
    }
    for (size_t i = 0; i < sizeof(special) / sizeof(special[0]); i++) {
        status = patch_record_named(archive, entries, special[i]);
        if (status != 0 && status != LIBMPQ_ERROR_EXIST)
            return status;
    }
    status = patch_read_named(archive, LIBMPQ_LISTFILE_NAME, &list, &size);
    if (status == LIBMPQ_ERROR_EXIST)
        return 0;
    while (status == 0 && position < size) {
        size_t start = position;
        char *name;

        while (position < size && list[position] != '\r' && list[position] != '\n')
            position++;
        if (position == start) {
            position++;
            continue;
        }
        if ((memchr)(list + start, 0, position - start) != NULL) {
            status = LIBMPQ_ERROR_FORMAT;
            break;
        }
        name = malloc(position - start + 1);
        if (name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            break;
        }
        memcpy(name, list + start, position - start);
        name[position - start] = '\0';
        status = patch_record_named(archive, entries, name);
        if (status == LIBMPQ_ERROR_EXIST)
            status = LIBMPQ_ERROR_FORMAT;
        free(name);
    }
    free(list);
    return status;
}

/* A rebuild can represent one classic identity per canonical row, not aliases. */
static int32_t
patch_named_identity(mpq_archive_s *archive, mpq_patch_entry_s *entry)
{
    const mpq_entry_s *canonical = &archive->mpq_entry[archive->mpq_map[entry->number].entry_index];
    uint32_t references = 0;
    uint32_t translated;

    if (entry->name == NULL)
        return LIBMPQ_ERROR_FORMAT;
    if ((canonical->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) == 0)
        return 0;
    if (libmpq__entry_index_from_classic(archive, canonical->classic_source_index, &translated) !=
            0 ||
        translated != archive->mpq_map[entry->number].entry_index)
        return LIBMPQ_ERROR_FORMAT;
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; i++) {
        const mpq_hash_s *hash = &archive->mpq_hash[i];
        if (hash->block_table_index != canonical->classic_source_index)
            continue;
        if (++references > 1 || hash->hash_a != entry->physical_hash_a ||
            hash->hash_b != entry->physical_hash_b)
            return LIBMPQ_ERROR_FORMAT;
        entry->locale = hash->locale;
        entry->platform = hash->platform;
    }
    return references == 1 ? 0 : LIBMPQ_ERROR_FORMAT;
}

static void
patch_free_entries(mpq_patch_entry_s *entries, uint32_t count)
{
    if (entries != NULL)
        for (uint32_t i = 0; i < count; i++) {
            free(entries[i].name);
            free(entries[i].physical_name);
        }
    free(entries);
}

/* BET-only rows do not own classic attributes; new output checksums are generated. */
static int32_t
patch_named_attributes(mpq_archive_s *archive, uint32_t number, mpq_file_attributes_s *attributes)
{
    memset(attributes, 0, sizeof(*attributes));
    if ((archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask &
         LIBMPQ_ENTRY_SOURCE_CLASSIC) == 0)
        return LIBMPQ_ERROR_EXIST;
    return libmpq__file_attributes(archive, number, attributes);
}

/* Keep storage selection for modified files, rejecting unrepresentable sector policies. */
static int32_t
patch_named_storage(
    mpq_archive_s *archive, const mpq_patch_entry_s *entry, mpq_file_options_s *options
)
{
    const mpq_entry_s *canonical = &archive->mpq_entry[archive->mpq_map[entry->number].entry_index];
    uint32_t blocks;
    int32_t status;

    options->flags = canonical->flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE |
                                         LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_COMPRESS |
                                         LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_KEY);
    options->locale = entry->locale;
    options->platform = entry->platform;
    if ((options->flags & LIBMPQ_FILE_FLAG_COMPRESS) == 0)
        return 0;
    status = libmpq__reader_offsets_acquire(archive, entry->number, entry->name);
    if (status != 0)
        return status;
    status = libmpq__file_blocks(archive, entry->number, &blocks);
    for (uint32_t i = 0; status == 0 && i < blocks; i++) {
        uint32_t mask;
        status = libmpq__block_compression(archive, entry->number, i, &mask);
        if (status != 0)
            break;
        if (mask == 0)
            continue;
        if (mask == LIBMPQ_COMPRESSION_LZMA_METHOD)
            mask = LIBMPQ_COMPRESSION_LZMA;

        /* Reapplying a lossy stage cannot preserve the validated target bytes. */
        if ((mask & (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO)) != 0) {
            status = LIBMPQ_ERROR_FORMAT;
            break;
        }
        if (i == 0)
            options->compression_first = mask;
        else if (options->compression_next != 0 && options->compression_next != mask)
            status = LIBMPQ_ERROR_FORMAT;
        else
            options->compression_next = mask;
    }
    if (status == 0) {
        if (options->compression_first == 0)
            options->compression_first = options->compression_next;
        if (options->compression_first == 0)
            options->compression_first = LIBMPQ_COMPRESSION_ZLIB;
        if (options->compression_next == 0)
            options->compression_next = options->compression_first;
    }
    {
        int32_t released = libmpq__reader_offsets_release(archive, entry->number);
        if (status == 0)
            status = released;
    }
    return status;
}

/* Rebuild a named view with the ordinary v3 writer and publish only validated output. */
static int32_t
patch_materialize_named(
    mpq_patch_view_s *view, mpq_archive_s **lower_handle, mpq_archive_s *patch,
    const mpq_patch_source_s *source, uint8_t explicit_layer
)
{
    mpq_archive_s *lower = *lower_handle;
    uint32_t base_count = lower->files;
    mpq_patch_entry_s *base_entries = NULL;
    mpq_patch_entry_s *entries = NULL;
    mpq_archive_s *writer = NULL;
    mpq_archive_s *check = NULL;
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 0, 0,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE |
                                                LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                            0 };
    FILE *output = NULL;
    char *temporary = NULL;
    char *candidate = NULL;
    uint64_t extent;
    uint8_t detected = explicit_layer;
    uint8_t mutated = 0;
    int32_t status = patch_named_entries(patch, &entries);

    if (status != 0)
        goto done;
    for (uint32_t i = 0; i < patch->files; i++) {
        status = patch_named_identity(patch, &entries[i]);
        if (status != 0)
            goto done;
        if ((patch->mpq_entry[patch->mpq_map[i].entry_index].flags &
             (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) != 0)
            detected = 1;
    }
    status = patch_prepare_entries(patch, entries, patch->files, source, &detected);
    if (status != 0)
        goto done;
    if (!detected) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    for (uint32_t i = 0; i < patch->files; i++) {
        if (!entries[i].live || entries[i].internal)
            continue;
        for (uint32_t j = 0; j < i; j++)
            if (entries[j].live && !entries[j].internal &&
                patch_named_equal(entries[i].name, entries[j].name)) {
                status = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        if ((patch->mpq_entry[patch->mpq_map[i].entry_index].flags &
             LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0) {
            uint32_t number;
            status = libmpq__file_number(lower, entries[i].name, &number);
            if (status == LIBMPQ_ERROR_EXIST) {
                status = 0;
                continue;
            }
            if (status != 0)
                goto done;
        }
        mutated = 1;
    }
    if (!mutated)
        goto done;
    status = patch_named_entries(lower, &base_entries);
    if (status != 0)
        goto done;

    /* Logical patch names also provide known names for unlisted base members. */
    for (uint32_t i = 0; i < patch->files; i++) {
        if (!entries[i].live || entries[i].internal)
            continue;
        status = patch_record_named(lower, base_entries, entries[i].name);
        if (status != 0 && status != LIBMPQ_ERROR_EXIST)
            goto done;
    }
    for (uint32_t i = 0; i < lower->files; i++) {
        status = patch_named_identity(lower, &base_entries[i]);
        if (status != 0)
            goto done;
        base_entries[i].internal =
            patch_known_internal(base_entries[i].hash_a, base_entries[i].hash_b);
    }
    status = libmpq__attributes_load(lower);
    if (status == 0)
        create.attributes = lower->attributes->flags;
    else if (status != LIBMPQ_ERROR_EXIST)
        goto done;
    status = libmpq__attributes_load(patch);
    if (status == 0)
        create.attributes |= patch->attributes->flags;
    else if (status != LIBMPQ_ERROR_EXIST)
        goto done;
    if ((uint64_t)lower->files + patch->files + 2 > UINT32_MAX) {
        status = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    create.max_files = lower->files + patch->files + 2;
    create.sector_size = lower->block_size;
    status = libmpq__archive_signature_extent(lower, &extent);
    if (status != 0)
        goto done;
    status = libmpq__directory_temporary_reopenable(
        view->directory, ".libmpq-patch-view-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary,
        &output
    );
    if (status != 0)
        goto done;
    candidate = patch_temporary_path(view->path, temporary);
    if (candidate == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    status = libmpq__writer_archive_create_file(&writer, candidate, output, &create);
    output = NULL;
    if (status != 0)
        goto done;

    /* Imported encrypted members keep their original relative offsets and keys. */
    if (extent < writer->mpq_header.header_size)
        extent = writer->mpq_header.header_size;
    if (extent > INT64_MAX ||
        libmpq__file_seek(writer->fp, (libmpq__off_t)(extent - 1), SEEK_SET) != 0 ||
        fputc(0, writer->fp) == EOF) {
        status = LIBMPQ_ERROR_WRITE;
        goto done;
    }
    for (uint32_t pass = 0; pass < 2; pass++) {
        uint32_t count = pass == 0 ? lower->files : patch->files;
        for (uint32_t i = 0; i < count; i++) {
            const mpq_patch_entry_s *base_entry = pass == 0 ? &base_entries[i] : NULL;
            const mpq_patch_entry_s *change = pass == 1 ? &entries[i] : NULL;
            mpq_archive_s *storage_archive;
            const mpq_patch_entry_s *storage_entry;
            mpq_file_options_s options = { 0 };
            mpq_file_attributes_s attributes = { 0 };
            uint8_t *before = NULL;
            uint8_t *payload = NULL;
            uint8_t *result = NULL;
            size_t before_size = 0;
            size_t payload_size = 0;
            size_t result_size = 0;
            const char *name;
            uint32_t flags;

            if (pass == 0) {
                if (base_entry->internal)
                    continue;
                for (uint32_t j = 0; j < patch->files; j++) {
                    if (!entries[j].live || entries[j].internal ||
                        !patch_named_equal(base_entry->name, entries[j].name))
                        continue;
                    if (change != NULL || base_entry->locale != entries[j].locale ||
                        base_entry->platform != entries[j].platform) {
                        status = LIBMPQ_ERROR_FORMAT;
                        goto done;
                    }
                    change = &entries[j];
                }
            } else {
                uint32_t number;
                if (!change->live || change->internal)
                    continue;
                status = libmpq__file_number(lower, change->name, &number);
                if (status == 0)
                    continue;
                if (status != LIBMPQ_ERROR_EXIST)
                    goto done;
            }
            name = base_entry != NULL ? base_entry->name : change->name;
            flags = change == NULL
                        ? 0
                        : patch->mpq_entry[patch->mpq_map[change->number].entry_index].flags;
            if ((flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0)
                continue;
            storage_archive = base_entry == NULL ? patch : lower;
            storage_entry = base_entry == NULL ? change : base_entry;
            status = patch_named_attributes(storage_archive, storage_entry->number, &attributes);
            if (status != 0 && status != LIBMPQ_ERROR_EXIST)
                goto done;
            if (change != NULL) {
                mpq_file_attributes_s patch_attributes = { 0 };
                status = patch_named_attributes(patch, change->number, &patch_attributes);
                if (status != 0 && status != LIBMPQ_ERROR_EXIST)
                    goto done;
                if ((patch_attributes.flags & LIBMPQ_ATTRIBUTE_FILETIME) != 0)
                    attributes.filetime = patch_attributes.filetime;
            }
            if (change == NULL &&
                (lower->mpq_entry[lower->mpq_map[i].entry_index].flags &
                 (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) != 0) {
                status = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            if (change == NULL && lower->mpq_entry[lower->mpq_map[i].entry_index].offset >=
                                      writer->mpq_header.header_size) {
                const mpq_entry_s *canonical = &lower->mpq_entry[lower->mpq_map[i].entry_index];
                if (canonical->offset > extent ||
                    canonical->packed_size > extent - canonical->offset ||
                    canonical->offset > INT64_MAX) {
                    status = LIBMPQ_ERROR_FORMAT;
                    goto done;
                }
                if (create.attributes != 0 && attributes.flags == 0) {
                    status = patch_read_adjusted(lower, name, i, NULL, &result, &result_size);
                    if (status == 0)
                        patch_set_attributes(
                            &attributes, create.attributes, result, result_size, 0
                        );
                    free(result);
                    if (status != 0)
                        goto done;
                }
                if (libmpq__file_seek(writer->fp, (libmpq__off_t)canonical->offset, SEEK_SET) !=
                    0) {
                    status = LIBMPQ_ERROR_SEEK;
                    goto done;
                }
                status = patch_copy_range(
                    lower, writer->fp, (uint64_t)lower->archive_offset + canonical->offset,
                    canonical->packed_size
                );
                if (status == 0)
                    status = libmpq__writer_import_member(
                        writer, name, canonical, base_entry->locale, base_entry->platform,
                        create.attributes != 0 ? &attributes : NULL
                    );
                if (status != 0)
                    goto done;
                continue;
            }
            if (change == NULL) {
                status = patch_read_adjusted(
                    lower, name, base_entry->number, NULL, &result, &result_size
                );
            } else if ((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0) {
                if (base_entry == NULL) {
                    status = LIBMPQ_ERROR_FORMAT;
                    goto done;
                }
                status = patch_read_incremental(
                    patch, change->physical_name == NULL ? change->name : change->physical_name,
                    change->number, &payload, &payload_size
                );
                if (status == 0)
                    status = patch_read_adjusted(
                        lower, name, base_entry->number, NULL, &before, &before_size
                    );
                if (status == 0)
                    status = libmpq__patch_apply(
                        before, before_size, payload, payload_size, &result, &result_size
                    );
            } else {
                status = patch_read_adjusted(
                    patch, change->physical_name == NULL ? change->name : change->physical_name,
                    change->number, NULL, &result, &result_size
                );
            }
            free(before);
            free(payload);
            if (status == 0) {
                status = patch_named_storage(storage_archive, storage_entry, &options);
#if SIZE_MAX > INT64_MAX
                if (status == 0 && result_size > INT64_MAX)
                    status = LIBMPQ_ERROR_SIZE;
#endif
                if (status == 0 && libmpq__file_seek(writer->fp, 0, SEEK_END) != 0)
                    status = LIBMPQ_ERROR_SEEK;
                if (status == 0)
                    status = libmpq__archive_add_data(
                        writer, name, result, (libmpq__off_t)result_size, &options
                    );
                if (status == 0 && writer->write_attributes != NULL)
                    writer->write_attributes[writer->write_next_block - 1].filetime =
                        attributes.filetime;
            }
            free(result);
            if (status != 0)
                goto done;
        }
    }

    /* Packed imports can leave the cursor before a rewritten member's end. */
    if (libmpq__file_seek(writer->fp, 0, SEEK_END) != 0) {
        status = LIBMPQ_ERROR_SEEK;
        goto done;
    }
    status = libmpq__archive_close(writer);
    writer = NULL;
    if (status != 0)
        goto done;
    status = libmpq__archive_open(&check, candidate, 0);
    if (status != 0)
        goto done;
    status = libmpq__archive_close(check);
    check = NULL;
    if (status != 0)
        goto done;

    /* Close the old view before unlinking it, including on platforms denying open-file removal. */
    status = libmpq__archive_close(lower);
    *lower_handle = NULL;
    if (status != 0)
        goto done;
    status = libmpq__directory_remove(view->directory, view->temporary);
    if (status != 0)
        goto done;
    free(view->temporary);
    free(view->path);
    view->temporary = temporary;
    view->path = candidate;
    view->archive_offset = 0;
    view->changed = 1;
    temporary = NULL;
    candidate = NULL;

done:
    if (writer != NULL) {
        writer->write_finalized = 1;
        (void)libmpq__archive_close(writer);
    }
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (output != NULL)
        (void)fclose(output);
    if (temporary != NULL)
        (void)libmpq__directory_remove(view->directory, temporary);
    patch_free_entries(base_entries, base_count);
    patch_free_entries(entries, patch->files);
    free(candidate);
    free(temporary);
    return status;
}

/* Apply a complete layer in a separate private materialization, never via updates. */
static int32_t
patch_apply_layer(
    mpq_patch_view_s *view, mpq_archive_s *patch, const mpq_patch_source_s *source,
    uint8_t explicit_layer
)
{
    mpq_archive_s *lower = NULL;
    mpq_archive_s *target = NULL;
    mpq_archive_s *check = NULL;
    FILE *output = NULL;
    char *temporary = NULL;
    char *candidate = NULL;
    mpq_patch_entry_s *entries = NULL;
    mpq_file_attributes_s *attributes = NULL;
    mpq_file_attributes_s *changed_rows = NULL;
    mpq_file_attributes_s list_row = { 0 };
    uint8_t *changed = NULL;
    uint32_t attribute_flags = 0;
    uint32_t metadata_number;
    uint32_t entry_count = 0;
    uint8_t detected = explicit_layer;
    uint8_t mutated = 0;
    uint8_t has_attributes = 0;
    int32_t status;

    status = libmpq__archive_open(&lower, view->path, view->archive_offset);
    if (status != 0)
        goto done;
    if (lower->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE ||
        patch->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR || patch->het_data != NULL) {
        status = patch_materialize_named(view, &lower, patch, source, explicit_layer);
        goto done;
    }
    if (libmpq__file_number(patch, "(patch_metadata)", &metadata_number) == 0) {
        libmpq__off_t metadata_size = 0;

        status = libmpq__file_size_unpacked(patch, metadata_number, &metadata_size);
        if (status != 0)
            goto done;
        if (metadata_size <= 0 || metadata_size >= 64) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        detected = 1;
    }
    for (uint32_t i = 0; i < patch->mpq_header.hash_table_count; i++) {
        uint32_t index;
        if (patch_live_hash(patch, &patch->mpq_hash[i]) &&
            libmpq__entry_index_from_classic(patch, patch->mpq_hash[i].block_table_index, &index) ==
                0 &&
            (patch->mpq_entry[index].flags &
             (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) != 0)
            detected = 1;
    }
    status = patch_entries(patch, &entries, &entry_count);
    if (status != 0)
        goto done;
    status = patch_prepare_entries(patch, entries, entry_count, source, &detected);
    if (status != 0)
        goto done;
    if (!detected) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }

    /* Legacy table rewriting applies only to v1/v2 archive headers. */
    if (lower->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_TWO) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    status = libmpq__archive_open(&target, view->path, view->archive_offset);
    if (status != 0)
        goto done;
    status = libmpq__attributes_load(lower);
    if (status == 0) {
        has_attributes = 1;
        attribute_flags = lower->attributes->flags;
    } else if (status != LIBMPQ_ERROR_EXIST) {
        goto done;
    }
    status = libmpq__attributes_load(patch);
    if (status == 0) {
        if (!has_attributes && (patch->attributes->flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0) {
            has_attributes = 1;
            attribute_flags = LIBMPQ_ATTRIBUTE_PATCH_BIT;
        } else if (has_attributes) {
            attribute_flags |= patch->attributes->flags & LIBMPQ_ATTRIBUTE_PATCH_BIT;
        }
    } else if (status != LIBMPQ_ERROR_EXIST) {
        goto done;
    }
    if (has_attributes) {
        changed_rows = calloc(entry_count, sizeof(*changed_rows));
        changed = calloc(entry_count, 1);
        if (changed_rows == NULL || changed == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
    }
    status = libmpq__directory_temporary_reopenable(
        view->directory, ".libmpq-patch-view-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary,
        &output
    );
    if (status != 0)
        goto done;
    candidate = patch_temporary_path(view->path, temporary);
    if (candidate == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    {
        uint64_t extent;

        status = libmpq__archive_signature_extent(lower, &extent);
        if (status != 0)
            goto done;
        status = patch_copy_range(lower, output, 0, (uint64_t)view->archive_offset + extent);
    }
    if (status != 0)
        goto done;
    for (uint32_t i = 0; i < entry_count; i++) {
        const mpq_patch_entry_s *entry = &entries[i];
        uint32_t index;

        if (!entry->live || entry->internal)
            continue;
        status = libmpq__entry_index_from_classic(patch, entry->block_index, &index);
        if (status != 0)
            goto done;
        if ((patch->mpq_entry[index].flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0 &&
            patch_matching_hash(target, entry) == UINT32_MAX)
            continue;
        status = patch_stage_hash(
            lower, target, patch, entry, output, has_attributes ? &changed_rows[i] : NULL,
            attribute_flags
        );
        if (status != 0)
            goto done;
        if (has_attributes && (patch->mpq_entry[index].flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) == 0)
            changed[i] = 1;
        mutated = 1;
    }
    if (!mutated)
        goto done;
    for (uint32_t i = 0; i < target->mpq_header.hash_table_count; i++) {
        mpq_hash_s *hash = &target->mpq_hash[i];

        if (patch_live_hash(target, hash) &&
            ((hash->hash_a == libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x100) &&
              hash->hash_b == libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x200)) ||
             (hash->hash_a == libmpq__crypto_hash_string("(patch_metadata)", 0x100) &&
              hash->hash_b == libmpq__crypto_hash_string("(patch_metadata)", 0x200))))
            patch_delete_hash(hash);
    }
    status = patch_rewrite_listfile(
        lower, target, entries, entry_count, output, has_attributes ? &list_row : NULL,
        attribute_flags,
        (uint8_t)(has_attributes &&
                  patch_internal_slot(target, LIBMPQ_ATTRIBUTES_NAME) == UINT32_MAX)
    );
    if (status != 0)
        goto done;
    if (has_attributes) {
        uint32_t count = target->mpq_header.block_table_count;

        if (count == UINT32_MAX || (size_t)count + 1 > SIZE_MAX / sizeof(*attributes)) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        attributes = calloc((size_t)count + 1, sizeof(*attributes));
        if (attributes == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        status = patch_remap_attributes(
            lower, target, entries, changed_rows, changed, entry_count,
            patch_internal_slot(target, LIBMPQ_LISTFILE_NAME) == UINT32_MAX ? NULL : &list_row,
            attributes
        );
        if (status != 0)
            goto done;
    }
    status = patch_rewrite_attributes(target, output, attributes, attribute_flags);
    if (status != 0)
        goto done;
    status = patch_write_tables(target, output);
    if (status != 0)
        goto done;
    {
        uint64_t extent;
        uint64_t suffix;
        uint8_t marker[4];

        status = libmpq__archive_signature_extent(lower, &extent);
        if (status != 0)
            goto done;
        suffix = (uint64_t)view->archive_offset + extent;
        if (lower->file_size - suffix >= LIBMPQ_STRONG_TRAILER_SIZE) {
            status = libmpq__source_read_at(lower->source, suffix, marker, sizeof(marker));
            if (status != 0)
                goto done;
            if (memcmp(marker, "NGIS", sizeof(marker)) == 0)
                suffix += LIBMPQ_STRONG_TRAILER_SIZE;
        }
        if (libmpq__file_seek(output, 0, SEEK_END) != 0) {
            status = LIBMPQ_ERROR_SEEK;
            goto done;
        }
        status = patch_copy_range(lower, output, suffix, lower->file_size - suffix);
        if (status != 0)
            goto done;
    }
    if (fclose(output) != 0) {
        output = NULL;
        status = LIBMPQ_ERROR_CLOSE;
        goto done;
    }
    output = NULL;
    status = libmpq__archive_open(&check, candidate, view->archive_offset);
    if (status != 0)
        goto done;
    status = libmpq__archive_close(check);
    check = NULL;
    if (status != 0)
        goto done;
    status = libmpq__archive_close(target);
    target = NULL;
    if (status != 0)
        goto done;
    status = libmpq__archive_close(lower);
    lower = NULL;
    if (status != 0)
        goto done;
    status = libmpq__directory_remove(view->directory, view->temporary);
    if (status != 0)
        goto done;
    free(view->temporary);
    free(view->path);
    view->temporary = temporary;
    view->path = candidate;
    view->changed = 1;
    temporary = NULL;
    candidate = NULL;

done:
    if (output != NULL)
        (void)fclose(output);
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (target != NULL)
        (void)libmpq__archive_close(target);
    if (lower != NULL)
        (void)libmpq__archive_close(lower);
    if (temporary != NULL)
        (void)libmpq__directory_remove(view->directory, temporary);
    if (entries != NULL) {
        for (uint32_t i = 0; i < entry_count; i++) {
            free(entries[i].name);
            free(entries[i].physical_name);
        }
    }
    free(entries);
    free(attributes);
    free(changed_rows);
    free(changed);
    free(temporary);
    free(candidate);
    return status;
}

/* Consume the private view and remove its temporary materialization. */
int32_t
libmpq__patch_view_close(mpq_patch_view_s *view)
{
    int32_t status = 0;

    if (view == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (view->archive != NULL)
        status = libmpq__archive_close(view->archive);
    if (view->directory != NULL && view->temporary != NULL) {
        int32_t remove_status = libmpq__directory_remove(view->directory, view->temporary);

        if (status == 0)
            status = remove_status;
    }
    if (view->directory != NULL)
        libmpq__directory_close(view->directory);
    free(view->temporary);
    free(view->path);
    free(view);
    return status;
}

/* Expose the private materialized view to the existing read-only archive APIs. */
mpq_archive_s *
libmpq__patch_view_archive(mpq_patch_view_s *view)
{
    return view == NULL ? NULL : view->archive;
}

/* Clone opened inputs only during the call; path callers retain auto-recognition. */
static int32_t
patch_layer_open(
    mpq_archive_s **archive, mpq_patch_source_s *layer, const mpq_patch_source_s *sources,
    mpq_archive_s *const *archives, const char *const *prefixes, size_t index
)
{
    if (archives == NULL) {
        *layer = sources[index];
        return patch_source_open(archive, layer);
    }
    memset(layer, 0, sizeof(*layer));
    layer->prefix = prefixes != NULL ? prefixes[index] : NULL;
    return libmpq__archive_clone(archive, archives[index]);
}

/* Consume the private base reader; all output sources adopt their temporary. */
static int32_t
patch_view_compose(
    mpq_patch_view_s **view, mpq_archive_s *base, const mpq_patch_source_s *patch_sources,
    mpq_archive_s *const *patch_archives, const char *const *prefixes, size_t patch_count
)
{
    mpq_patch_view_s *state = NULL;
    mpq_archive_s *patch = NULL;
    FILE *temporary = NULL;
    char *absolute = NULL;
    char *destination = NULL;
    char *logical_name = NULL;
    mpq_patch_source_s layer;
    uint8_t explicit_layer = patch_archives != NULL;
    uint8_t materialized = 0;
    int32_t status;

    *view = NULL;
    state = calloc(1, sizeof(*state));
    if (state == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto error;
    }
    if (base->filename != NULL) {
        logical_name = libmpq__string_duplicate(base->filename);
        if (logical_name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            goto error;
        }
    }
    absolute = libmpq__file_temporary_anchor();
    if (absolute == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto error;
    }
    status = libmpq__directory_open(absolute, &state->directory, &destination);
    if (status != 0)
        goto error;
    status = libmpq__directory_temporary_reopenable(
        state->directory, ".libmpq-patch-view-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1,
        &state->temporary, &temporary
    );
    if (status != 0)
        goto error;
    state->path = patch_temporary_path(absolute, state->temporary);
    if (state->path == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto error;
    }
    state->archive_offset = base->archive_offset;
    if (base->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE) {

        /* Rebuild directly from the opened sources, without a full intermediate base copy. */
        if (fclose(temporary) != 0) {
            temporary = NULL;
            status = LIBMPQ_ERROR_CLOSE;
            goto error;
        }
        temporary = NULL;
        for (size_t i = 0; i < patch_count; i++) {

            /* Adoption consumes the lower handle; no-op layers leave it available. */
            if (base == NULL) {
                status = libmpq__archive_open(&base, state->path, state->archive_offset);
                if (status != 0)
                    goto error;
            }
            status = patch_layer_open(&patch, &layer, patch_sources, patch_archives, prefixes, i);
            if (status == 0)
                status = patch_materialize_named(state, &base, patch, &layer, explicit_layer);
            if (status != 0)
                goto error;
            if (base == NULL)
                materialized = 1;
            status = libmpq__archive_close(patch);
            patch = NULL;
            if (status != 0)
                goto error;
        }
        if (base != NULL) {
            if (materialized) {
                status = libmpq__archive_close(base);
                base = NULL;
                if (status != 0)
                    goto error;
                goto expose;
            }

            /* No-op layers keep every original byte, including signatures and wrappers. */
            temporary = libmpq__directory_file_open(state->directory, state->temporary, "r+b");
            if (temporary == NULL) {
                status = LIBMPQ_ERROR_OPEN;
                goto error;
            }
            status = patch_copy_range(base, temporary, 0, base->file_size);
            if (status != 0)
                goto error;
            if (fclose(temporary) != 0) {
                temporary = NULL;
                status = LIBMPQ_ERROR_CLOSE;
                goto error;
            }
            temporary = NULL;
            status = libmpq__archive_close(base);
            base = NULL;
            if (status != 0)
                goto error;
        }
        goto expose;
    }
    status = patch_copy_range(base, temporary, 0, base->file_size);
    if (status != 0)
        goto error;
    if (fclose(temporary) != 0) {
        temporary = NULL;
        status = LIBMPQ_ERROR_CLOSE;
        goto error;
    }
    temporary = NULL;
    status = libmpq__archive_close(base);
    base = NULL;
    if (status != 0)
        goto error;
    for (size_t i = 0; i < patch_count; i++) {
        status = patch_layer_open(&patch, &layer, patch_sources, patch_archives, prefixes, i);
        if (status == 0)
            status = patch_apply_layer(state, patch, &layer, explicit_layer);
        if (status != 0)
            goto error;
        status = libmpq__archive_close(patch);
        patch = NULL;
        if (status != 0)
            goto error;
    }
expose:
    status = libmpq__archive_open(&state->archive, state->path, state->archive_offset);
    if (status != 0)
        goto error;
    status = libmpq__source_adopt_temporary(
        state->archive->source, state->directory, state->temporary, state->path
    );
    if (status != 0)
        goto error;
    state->directory = NULL;
    if (!state->changed) {
        free(state->archive->filename);
        state->archive->filename = logical_name;
        logical_name = NULL;
    }
    free(logical_name);
    free(destination);
    free(absolute);
    *view = state;
    return 0;

error:
    if (temporary != NULL)
        (void)fclose(temporary);
    if (base != NULL)
        (void)libmpq__archive_close(base);
    if (patch != NULL)
        (void)libmpq__archive_close(patch);
    free(logical_name);
    free(destination);
    free(absolute);
    (void)libmpq__patch_view_close(state);
    return status;
}

/* Preserve path-based private recognition, ownership and nonempty-layer rules. */
int32_t
libmpq__patch_view_open_sources(
    mpq_patch_view_s **view, const mpq_patch_source_s *base_source,
    const mpq_patch_source_s *patch_sources, size_t patch_count
)
{
    mpq_archive_s *base = NULL;
    int32_t status;

    if (view == NULL)
        return LIBMPQ_ERROR_EXIST;
    *view = NULL;
    if (base_source == NULL || base_source->path == NULL || patch_sources == NULL ||
        patch_count == 0)
        return LIBMPQ_ERROR_EXIST;
    if (patch_count > SIZE_MAX / sizeof(*patch_sources))
        return LIBMPQ_ERROR_SIZE;
    status = patch_source_open(&base, base_source);
    return status == 0 ? patch_view_compose(view, base, patch_sources, NULL, NULL, patch_count)
                       : status;
}

/* Borrow opened layers synchronously and return an independently owned reader. */
int32_t
libmpq__patch_reader_open_archives(
    mpq_archive_s **archive, mpq_archive_s *base, mpq_archive_s *const *patches,
    const char *const *prefixes, size_t patch_count
)
{
    mpq_patch_view_s *view = NULL;
    mpq_archive_s *lower = NULL;
    int32_t status;

    if (archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *archive = NULL;
    if (base == NULL || base->write_mode || (patch_count != 0 && patches == NULL))
        return LIBMPQ_ERROR_EXIST;
    if (patch_count > SIZE_MAX / sizeof(*patches))
        return LIBMPQ_ERROR_SIZE;
    for (size_t i = 0; i < patch_count; i++)
        if (patches[i] == NULL || patches[i]->write_mode)
            return LIBMPQ_ERROR_EXIST;
    status = libmpq__archive_clone(&lower, base);
    if (status != 0)
        return status;
    status = patch_view_compose(&view, lower, NULL, patches, prefixes, patch_count);
    if (status != 0)
        return status;
    *archive = view->archive;
    view->archive = NULL;
    return libmpq__patch_view_close(view);
}

/* Adapt path-only patch callers to independent ordinary source descriptors. */
static int32_t
patch_view_open_paths(
    mpq_patch_view_s **view, const mpq_patch_source_s *base_source, const char *const *patch_paths,
    size_t patch_count
)
{
    mpq_patch_source_s *sources;
    int32_t status;

    if (view == NULL)
        return LIBMPQ_ERROR_EXIST;
    *view = NULL;
    if (patch_paths == NULL || patch_count == 0)
        return LIBMPQ_ERROR_EXIST;
    if (patch_count > SIZE_MAX / sizeof(*sources))
        return LIBMPQ_ERROR_SIZE;
    sources = calloc(patch_count, sizeof(*sources));
    if (sources == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (size_t i = 0; i < patch_count; i++)
        sources[i].path = patch_paths[i];
    status = libmpq__patch_view_open_sources(view, base_source, sources, patch_count);
    free(sources);
    return status;
}

/* Build a private view from an ordinary MPQ base. */
int32_t
libmpq__patch_view_open(
    mpq_patch_view_s **view, const char *base_path, const char *const *patch_paths,
    size_t patch_count
)
{
    mpq_patch_source_s base_source = { base_path, NULL, 0, NULL };

    return patch_view_open_paths(view, &base_source, patch_paths, patch_count);
}

/* Decode an authenticated MPQE base before composing ordinary MPQ patches. */
int32_t
libmpq__patch_view_open_mpqe_base(
    mpq_patch_view_s **view, const char *base_path, const uint8_t *auth_code, size_t auth_code_size,
    const char *const *patch_paths, size_t patch_count
)
{
    mpq_patch_source_s base_source = { base_path, auth_code, auth_code_size, NULL };

    if (auth_code == NULL) {
        if (view != NULL)
            *view = NULL;
        return view == NULL ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_DECRYPT;
    }
    return patch_view_open_paths(view, &base_source, patch_paths, patch_count);
}

/* Release the plan without touching any of its original archive handles. */
void
libmpq__patch_selection_free(mpq_patch_selection_s *selection)
{
    if (selection != NULL) {
        for (size_t i = 0; i < selection->count; ++i)
            free(selection->operations[i].physical_name);
        free(selection->operations);
        memset(selection, 0, sizeof(*selection));
    }
}

/* Join a normalized prefix and a logical member name. */
static int32_t
patch_join_name(const char *prefix, const char *name, char **physical)
{
    size_t head = strlen(prefix);
    size_t tail = strlen(name);
    if (tail == SIZE_MAX || head > SIZE_MAX - tail - 1)
        return LIBMPQ_ERROR_SIZE;
    *physical = malloc(head + tail + 1);
    if (*physical == NULL)
        return LIBMPQ_ERROR_MALLOC;
    memcpy(*physical, prefix, head);
    memcpy(*physical + head, name, tail + 1);
    return 0;
}

/* Ignore stale marker spellings. Live candidates must qualify as real members. */
static int32_t
patch_selected_marker(mpq_archive_s *archive, const char *name, char **discovered)
{
    mpq_named_identity_s *rows;
    uint32_t count;
    size_t prefix;
    if (!patch_metadata_path(name, &prefix))
        return 0;
    int32_t status = libmpq__reader_name_identities(archive, name, &rows, &count);
    if (status == LIBMPQ_ERROR_EXIST)
        return 0;
    if (status != 0)
        return status;
    for (uint32_t i = 0; status == 0 && i < count; ++i) {
        const uint32_t number = rows[i].identity.file_number;
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        if ((entry->flags & (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) != 0)
            status = LIBMPQ_ERROR_FORMAT;
        else
            status = patch_discover_marker(archive, name, prefix, number, discovered);
    }
    free(rows);
    return status;
}

/* Only namespace markers need spellings from the patch listfile. */
static int32_t
patch_selected_prefix(mpq_archive_s *archive, const char *supplied, char **prefix)
{
    static const char marker[] = "(patch_metadata)";
    uint8_t *list = NULL;
    char *explicit_prefix = NULL;
    char *discovered = NULL;
    char *qualified = NULL;
    size_t size = 0;
    int32_t status = supplied == NULL ? 0 : patch_normalize_prefix(supplied, &explicit_prefix);
    *prefix = NULL;
    if (status == 0)
        status = patch_selected_marker(archive, marker, &discovered);
    if (status == 0 && explicit_prefix != NULL && *explicit_prefix != '\0') {
        status = patch_join_name(explicit_prefix, marker, &qualified);
        if (status == 0)
            status = patch_selected_marker(archive, qualified, &discovered);
    }
    if (status == 0) {
        status = patch_read_named(archive, LIBMPQ_LISTFILE_NAME, &list, &size);
        if (status == LIBMPQ_ERROR_EXIST)
            status = 0;
    }
    for (size_t i = 0; status == 0 && i < size;) {
        size_t start = i;
        while (i < size && list[i] != '\r' && list[i] != '\n')
            i++;
        size_t length = i - start;
        if (i < size)
            i++;
        if (length < sizeof(marker) - 1)
            continue;
        const char *end = (const char *)list + start + length - (sizeof(marker) - 1);
        if (!patch_name_equal(end, marker, sizeof(marker) - 1) ||
            (length != sizeof(marker) - 1 && end[-1] != '\\'))
            continue;
        if ((memchr)(list + start, 0, length) != NULL || length == SIZE_MAX) {
            status = LIBMPQ_ERROR_FORMAT;
            break;
        }
        char *name = malloc(length + 1);
        if (name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            break;
        }
        memcpy(name, list + start, length);
        name[length] = '\0';
        status = patch_selected_marker(archive, name, &discovered);
        free(name);
    }
    if (status == 0 && patch_prefix_conflicts(explicit_prefix, discovered))
        status = LIBMPQ_ERROR_FORMAT;
    if (status == 0) {
        const char *value = explicit_prefix != NULL ? explicit_prefix : discovered;
        *prefix = libmpq__string_duplicate(value != NULL ? value : "");
        if (*prefix == NULL)
            status = LIBMPQ_ERROR_MALLOC;
    }
    free(qualified);
    free(discovered);
    free(explicit_prefix);
    free(list);
    return status;
}

/* Flag extra names sharing encrypted storage without assuming they have this key. */
static uint8_t
patch_alias_key_evidence(
    const mpq_archive_s *archive, const mpq_entry_s *entry, const mpq_named_identity_s *id,
    uint32_t a, uint32_t b
)
{
    if ((entry->flags & LIBMPQ_FILE_FLAG_ENCRYPTED) == 0 ||
        (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) == 0)
        return 0;
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; ++i) {
        const mpq_hash_s *slot = &archive->mpq_hash[i];
        if (slot->block_table_index == entry->classic_source_index &&
            (slot->hash_a != a || slot->hash_b != b || id->slot == UINT32_MAX))
            return 1;
    }
    return 0;
}

/* Scan the matching classic hash family for hidden rows past a free slot. */
static int32_t
patch_selected_reachability(
    mpq_archive_s *archive, uint32_t hash, uint32_t a, uint32_t b, uint8_t exact, uint16_t locale,
    uint16_t platform
)
{
    uint32_t count = archive->mpq_header.hash_table_count;
    uint32_t limit = 0;
    if (count == 0)
        return 0;
    uint32_t start = hash % count;
    for (uint32_t slot = start; limit < count; slot = slot == count - 1 ? 0 : slot + 1) {
        if (archive->mpq_hash[slot].block_table_index == LIBMPQ_HASH_FREE)
            break;
        limit++;
    }
    for (uint32_t slot = 0; slot < count; ++slot) {
        const mpq_hash_s *row = &archive->mpq_hash[slot];
        uint32_t distance = slot >= start ? slot - start : count - start + slot;
        if (distance >= limit && row->block_table_index < LIBMPQ_HASH_DELETED && row->hash_a == a &&
            row->hash_b == b && (!exact || (row->locale == locale && row->platform == platform)))
            return LIBMPQ_ERROR_FORMAT;
    }
    return 0;
}

/* Record only rows of the requested physical spelling. */
static int32_t
patch_select_collect(
    mpq_patch_selection_s *plan, size_t *capacity, mpq_archive_s *archive, size_t source,
    const char *physical, uint8_t exact, uint16_t locale, uint16_t platform
)
{
    mpq_named_identity_s *rows;
    uint32_t count;
    uint32_t hash;
    uint32_t a;
    uint32_t b;
    libmpq__file_hash(physical, &hash, &a, &b);
    int32_t status = patch_selected_reachability(archive, hash, a, b, exact, locale, platform);
    if (status != 0)
        return status;
    status = libmpq__reader_name_identities(archive, physical, &rows, &count);
    if (status != 0)
        return status == LIBMPQ_ERROR_EXIST ? 0 : status;
    for (uint32_t i = 0; status == 0 && i < count; ++i) {
        const mpq_file_identity_s *id = &rows[i].identity;
        if (exact && (id->locale != locale || id->platform != platform))
            continue;
        const mpq_entry_s *entry =
            &archive->mpq_entry[archive->mpq_map[id->file_number].entry_index];
        if ((id->flags & LIBMPQ_IDENTITY_BET) != 0) {
            mpq_bet_entry_s record;
            status = libmpq__bet_record_decode(&archive->mpq_bet, entry->bet_source_index, &record);
            if (status != 0)
                break;
            if (record.unknown != 0) {
                status = LIBMPQ_ERROR_FORMAT;
                break;
            }
        }
        if (plan->count == *capacity) {
            size_t limit = SIZE_MAX / sizeof(*plan->operations);
            size_t next = *capacity == 0 ? 8 : (*capacity <= limit / 2 ? *capacity * 2 : limit);
            if (next <= *capacity || next > limit) {
                status = LIBMPQ_ERROR_SIZE;
                break;
            }
            mpq_patch_selection_operation_s *grown =
                realloc(plan->operations, next * sizeof(*grown));
            if (grown == NULL) {
                status = LIBMPQ_ERROR_MALLOC;
                break;
            }
            plan->operations = grown;
            *capacity = next;
        }
        char *name = libmpq__string_duplicate(physical);
        if (name == NULL) {
            status = LIBMPQ_ERROR_MALLOC;
            break;
        }
        mpq_patch_selection_operation_s *op = &plan->operations[plan->count++];
        *op = (mpq_patch_selection_operation_s){
            .source = source,
            .number = id->file_number,
            .flags = entry->flags,
            .provenance = id->flags,
            .classic_slot = rows[i].slot,
            .locale = id->locale,
            .platform = id->platform,
            .offset = entry->offset,
            .packed_size = entry->packed_size,
            .unpacked_size = entry->unpacked_size,
            .physical_name = name,
            .needs_key_evidence = patch_alias_key_evidence(archive, entry, &rows[i], a, b),
            .kind =
                (entry->flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0 ? LIBMPQ_PATCH_SELECT_DELETE
                : (entry->flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0  ? LIBMPQ_PATCH_SELECT_DELTA
                                                                     : LIBMPQ_PATCH_SELECT_ORDINARY
        };
    }
    free(rows);
    return status;
}

/* Match the legacy linear-table mutation without keeping physical block rows. */
static uint32_t
patch_shadow_slot(
    const mpq_hash_s *hashes, uint32_t count, uint32_t a, uint32_t b, uint16_t locale,
    uint16_t platform, uint8_t exact
)
{
    for (uint32_t i = 0; i < count; ++i) {
        const mpq_hash_s *row = &hashes[i];
        if (row->block_table_index == 0 && row->hash_a == a && row->hash_b == b &&
            (!exact || (row->locale == locale && row->platform == platform)))
            return i;
    }
    return UINT32_MAX;
}

/* Reproduce only slot occupancy, layer order and generated-attribute placement. */
static int32_t
patch_shadow_layer(
    mpq_archive_s *table, const mpq_hash_s *lower, mpq_archive_s *layer, const char *prefix,
    const char *name, uint8_t *attributes
)
{
    const uint32_t attr_a = libmpq__crypto_hash_string(LIBMPQ_ATTRIBUTES_NAME, 0x100);
    const uint32_t attr_b = libmpq__crypto_hash_string(LIBMPQ_ATTRIBUTES_NAME, 0x200);
    mpq_patch_entry_s *entries = NULL;
    char *normalized = NULL;
    char *physical = NULL;
    uint32_t slots = table->mpq_header.hash_table_count;
    uint32_t count = 0;
    uint8_t detected = 1;
    uint8_t mutated = 0;
    int32_t status = patch_selected_prefix(layer, prefix, &normalized);
    if (status == 0)
        status = patch_join_name(normalized, name, &physical);
    if (status == 0)
        status = patch_entries(layer, &entries, &count);
    if (status == 0) {
        const uint32_t a = libmpq__crypto_hash_string(physical, 0x100);
        const uint32_t b = libmpq__crypto_hash_string(physical, 0x200);
        for (uint32_t i = 0; status == 0 && i < count; ++i) {
            if (entries[i].live && entries[i].name == NULL && entries[i].hash_a == a &&
                entries[i].hash_b == b) {
                entries[i].name = libmpq__string_duplicate(physical);
                if (entries[i].name == NULL)
                    status = LIBMPQ_ERROR_MALLOC;
            }
        }
    }
    if (status == 0) {
        mpq_patch_source_s source = { .prefix = normalized };
        status = patch_prepare_entries(layer, entries, count, &source, &detected);
    }
    for (uint32_t i = 0; status == 0 && i < count; ++i) {
        const mpq_patch_entry_s *entry = &entries[i];
        if (!entry->live || entry->internal)
            continue;
        if (entry->number >= layer->files) {
            status = LIBMPQ_ERROR_FORMAT;
            break;
        }
        uint32_t slot = patch_shadow_slot(
            lower, slots, entry->hash_a, entry->hash_b, entry->locale, entry->platform, 1
        );
        uint32_t flags = layer->mpq_entry[layer->mpq_map[entry->number].entry_index].flags;
        if ((flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0) {
            if (patch_shadow_slot(
                    table->mpq_hash, slots, entry->hash_a, entry->hash_b, entry->locale,
                    entry->platform, 1
                ) != UINT32_MAX &&
                slot != UINT32_MAX) {
                patch_delete_hash(&table->mpq_hash[slot]);
                mutated = 1;
            }
        } else if (slot != UINT32_MAX) {
            mutated = 1;
        } else if ((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) == 0) {
            if (entry->name == NULL) {
                status = LIBMPQ_ERROR_FORMAT;
                break;
            }
            mpq_hash_s inserted = { entry->hash_a, entry->hash_b, entry->locale, entry->platform,
                                    0 };
            status = patch_insert_hash(table, entry->name, &inserted);
            mutated = 1;
        }
    }
    if (status == 0 && mutated) {
        status = libmpq__attributes_load(layer);
        if (status == 0) {
            *attributes |= (layer->attributes->flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0;
        } else if (status == LIBMPQ_ERROR_EXIST)
            status = 0;
        for (uint32_t i = 0; i < table->mpq_header.hash_table_count; ++i) {
            mpq_hash_s *row = &table->mpq_hash[i];
            if (row->block_table_index == 0 &&
                ((row->hash_a == libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x100) &&
                  row->hash_b == libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x200)) ||
                 (row->hash_a == libmpq__crypto_hash_string("(patch_metadata)", 0x100) &&
                  row->hash_b == libmpq__crypto_hash_string("(patch_metadata)", 0x200))))
                patch_delete_hash(row);
        }
        if (status == 0 && *attributes &&
            patch_shadow_slot(table->mpq_hash, slots, attr_a, attr_b, 0, 0, 0) == UINT32_MAX) {
            mpq_hash_s inserted = { attr_a, attr_b, 0, 0, 0 };
            status = patch_insert_hash(table, LIBMPQ_ATTRIBUTES_NAME, &inserted);
        }
    }
    patch_free_entries(entries, count);
    free(physical);
    free(normalized);
    return status;
}

/* Resolve the ordinary winner after replaying only classic metadata. */
static int32_t
patch_shadow_winner(
    mpq_archive_s *base, mpq_archive_s *const *patches, const char *const *prefixes, size_t count,
    const char *filename, uint16_t *locale, uint16_t *platform
)
{
    mpq_archive_s table = { 0 };
    uint32_t slots = base->mpq_header.hash_table_count;
    mpq_hash_s *lower;
    size_t bytes;
    uint8_t attributes = 0;
    int32_t status;
    if (slots == 0)
        return LIBMPQ_ERROR_FORMAT;
    if ((uint64_t)slots * sizeof(*table.mpq_hash) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    bytes = (size_t)slots * sizeof(*table.mpq_hash);
    table.mpq_hash = malloc(bytes);
    lower = malloc(bytes);
    if (table.mpq_hash == NULL || lower == NULL) {
        free(lower);
        free(table.mpq_hash);
        return LIBMPQ_ERROR_MALLOC;
    }
    table.mpq_header.hash_table_count = slots;
    memcpy(table.mpq_hash, base->mpq_hash, bytes);
    for (uint32_t i = 0; i < slots; ++i) {
        if (table.mpq_hash[i].block_table_index < LIBMPQ_HASH_DELETED)
            table.mpq_hash[i].block_table_index = patch_live_hash(base, &base->mpq_hash[i]) ? 0 : 1;
    }
    status = libmpq__attributes_load(base);
    if (status == 0)
        attributes = 1;
    else if (status == LIBMPQ_ERROR_EXIST)
        status = 0;
    for (size_t i = 0; status == 0 && i < count; ++i) {
        mpq_archive_s *layer = NULL;
        status = libmpq__archive_clone(&layer, patches[i]);
        if (status == 0) {

            /* Every entry in a layer targets the same pre-layer table. */
            memcpy(lower, table.mpq_hash, bytes);
            status = patch_shadow_layer(
                &table, lower, layer, prefixes != NULL ? prefixes[i] : NULL, filename, &attributes
            );
            int32_t close_status = libmpq__archive_close(layer);
            if (status == 0)
                status = close_status;
        }
    }
    if (status == 0) {
        uint32_t hash;
        uint32_t a;
        uint32_t b;
        libmpq__file_hash(filename, &hash, &a, &b);
        uint32_t slot = hash % slots;
        status = LIBMPQ_ERROR_FORMAT;
        for (uint32_t i = 0; i < slots; ++i, slot = slot == slots - 1 ? 0 : slot + 1) {
            const mpq_hash_s *row = &table.mpq_hash[slot];
            if (row->block_table_index == LIBMPQ_HASH_FREE)
                break;
            if (row->block_table_index < LIBMPQ_HASH_DELETED && row->hash_a == a &&
                row->hash_b == b) {
                if (row->block_table_index == 0) {
                    *locale = row->locale;
                    *platform = row->platform;
                    status = 0;
                }
                break;
            }
        }
    }
    free(lower);
    free(table.mpq_hash);
    return status;
}

/* Group operations by tuple while maintaining layer order within each group. */
static int
patch_select_compare(const void *first, const void *second)
{
    const mpq_patch_selection_operation_s *a = first;
    const mpq_patch_selection_operation_s *b = second;
    if (a->locale != b->locale)
        return a->locale < b->locale ? -1 : 1;
    if (a->platform != b->platform)
        return a->platform < b->platform ? -1 : 1;
    return a->source < b->source ? -1 : a->source != b->source;
}

/* Rank retained base tuples by HET precedence and then classic probe distance. */
static int32_t
patch_select_regular(
    const mpq_patch_selection_s *plan, mpq_archive_s *base, mpq_archive_s *const *patches,
    const char *const *prefixes, size_t count, const char *filename, uint16_t *locale,
    uint16_t *platform
)
{
    size_t best = SIZE_MAX;
    size_t live = 0;
    uint32_t bet = 0;
    uint32_t distance = UINT32_MAX;
    uint32_t slots = base->mpq_header.hash_table_count;
    uint32_t start = slots == 0 ? 0 : libmpq__crypto_hash_string(filename, 0) % slots;
    uint8_t named =
        base->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE || base->het_data != NULL;
    uint8_t inserted = 0;
    uint8_t changed = 0;
    uint8_t orphan = 0;

    /*
     * Match patch_apply_layer(): a v3 layer with only classic tables can
     * apply to a v1/v2 lower archive without rebuilding it as a named view.
     */
    for (size_t i = 0; i < count; ++i)
        named |= patches[i]->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR ||
                 patches[i]->het_data != NULL;

    for (size_t i = 0; i < plan->count;) {
        const mpq_patch_selection_operation_s *first = &plan->operations[i];
        uint8_t present = 0;
        uint8_t new_slot = 0;
        do {
            const mpq_patch_selection_operation_s *op = &plan->operations[i++];
            if (op->kind == LIBMPQ_PATCH_SELECT_DELETE) {
                changed |= present;
                present = 0;
            } else if (op->kind == LIBMPQ_PATCH_SELECT_ORDINARY) {
                changed |= op->source != 0;
                if (!present)
                    new_slot = op->source != 0;
                present = 1;
            } else if (!present) {
                orphan = 1;
            } else {
                changed = 1;
            }
        } while (i < plan->count && plan->operations[i].locale == first->locale &&
                 plan->operations[i].platform == first->platform);
        if (!present)
            continue;
        live++;
        inserted |= new_slot;
        uint32_t slot = first->classic_slot;
        uint32_t rank = first->source != 0 || slot >= slots
                            ? UINT32_MAX
                            : (slot >= start ? slot - start : slots - start + slot);
        uint8_t has_bet = first->source == 0 && (first->provenance & LIBMPQ_IDENTITY_BET) != 0;
        if (has_bet)
            bet++;
        if (best == SIZE_MAX || has_bet || (bet == 0 && rank < distance)) {
            best = (size_t)(first - plan->operations);
            distance = rank;
        }
    }
    if (live == 0)
        return orphan ? LIBMPQ_ERROR_FORMAT : LIBMPQ_ERROR_EXIST;
    if (live > 1) {
        if (named && changed)
            return LIBMPQ_ERROR_FORMAT;
        if (inserted)
            return patch_shadow_winner(base, patches, prefixes, count, filename, locale, platform);
        if (bet > 1)
            return LIBMPQ_ERROR_FORMAT;
    }
    *locale = plan->operations[best].locale;
    *platform = plan->operations[best].platform;
    return 0;
}

/* Check all applicable physical geometry, including operations before a reset. */
static int32_t
patch_select_validate(
    mpq_patch_selection_s *plan, mpq_archive_s *base, mpq_archive_s *const *patches,
    uint16_t locale, uint16_t platform
)
{
    const uint32_t storage = LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_COMPRESS |
                             LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED |
                             LIBMPQ_FILE_FLAG_KEY | LIBMPQ_FILE_FLAG_SINGLE |
                             LIBMPQ_FILE_FLAG_SECTOR_CRC;
    uint8_t present = 0;
    size_t kept = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        mpq_patch_selection_operation_s *op = &plan->operations[i];
        if (op->locale != locale || op->platform != platform)
            continue;
        if (op->source == 0 && op->kind != LIBMPQ_PATCH_SELECT_ORDINARY)
            return LIBMPQ_ERROR_FORMAT;
        mpq_archive_s *archive = op->source == 0 ? base : patches[op->source - 1];
        uint32_t index = archive->mpq_map[op->number].entry_index;
        int32_t status = libmpq__reader_validate_payload_range(archive, index, 0, op->packed_size);
        if (status != 0)
            return status;
        if (op->kind == LIBMPQ_PATCH_SELECT_DELETE) {
            if (op->flags != (LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_DELETE_MARKER) ||
                op->packed_size != 0 || op->unpacked_size != 0)
                return LIBMPQ_ERROR_FORMAT;
            present = 0;
        } else {
            if ((op->flags & ~(storage | LIBMPQ_FILE_FLAG_PATCH_FILE)) != 0 ||
                (op->flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE)) ==
                    (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE) ||
                (op->packed_size == 0 && op->unpacked_size != 0))
                return LIBMPQ_ERROR_FORMAT;
            if (op->kind == LIBMPQ_PATCH_SELECT_DELTA) {
                if (!present)
                    return LIBMPQ_ERROR_FORMAT;
                status = patch_member_info(archive, op->number, &op->patch_info);
                if (status != 0)
                    return status;
                if (op->patch_info.data_size < LIBMPQ_PATCH_HEADER_SIZE ||
                    op->patch_info.length == op->packed_size)
                    return LIBMPQ_ERROR_FORMAT;
            }
            present = 1;
        }
        kept++;
    }
    if (!present)
        return LIBMPQ_ERROR_EXIST;
    if (kept == 0)
        return LIBMPQ_ERROR_FORMAT;

    /* Compact in place only after the full applicable chain passes. */
    size_t next = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        mpq_patch_selection_operation_s *op = &plan->operations[i];
        if (op->locale == locale && op->platform == platform)
            plan->operations[next++] = *op;
        else
            free(op->physical_name);
    }
    plan->count = kept;
    plan->locale = locale;
    plan->platform = platform;
    return 0;
}

/* Plan an exact or ordinary selected chain without opening any payload decoder. */
int32_t
libmpq__patch_select(
    mpq_patch_selection_s *selection, mpq_archive_s *base, mpq_archive_s *const *patches,
    const char *const *prefixes, size_t count, const char *filename, uint8_t exact, uint16_t locale,
    uint16_t platform
)
{
    mpq_archive_s *lower = NULL;
    mpq_patch_selection_s plan = { 0 };
    size_t capacity = 0;
    size_t prefix_len;
    uint32_t hash;
    uint32_t a;
    uint32_t b;
    int32_t status;
    if (selection == NULL)
        return LIBMPQ_ERROR_EXIST;
    memset(selection, 0, sizeof(*selection));
    if (base == NULL || base->write_mode || filename == NULL || *filename == '\0' ||
        (count != 0 && patches == NULL))
        return LIBMPQ_ERROR_EXIST;
    if (count > SIZE_MAX / sizeof(*patches) || count > SIZE_MAX / sizeof(*prefixes))
        return LIBMPQ_ERROR_SIZE;
    for (size_t i = 0; i < count; ++i)
        if (patches[i] == NULL || patches[i]->write_mode)
            return LIBMPQ_ERROR_EXIST;
    libmpq__file_hash(filename, &hash, &a, &b);
    if (patch_known_internal(a, b) || patch_metadata_path(filename, &prefix_len))
        return LIBMPQ_ERROR_FORMAT;

    status = libmpq__archive_clone(&lower, base);
    if (status == 0)
        status =
            patch_select_collect(&plan, &capacity, lower, 0, filename, exact, locale, platform);
    for (size_t i = 0; status == 0 && i < count; ++i) {
        mpq_archive_s *layer = NULL;
        char *prefix = NULL;
        char *physical = NULL;
        status = libmpq__archive_clone(&layer, patches[i]);
        if (status == 0)
            status = patch_selected_prefix(layer, prefixes != NULL ? prefixes[i] : NULL, &prefix);
        if (status == 0)
            status = patch_join_name(prefix, filename, &physical);
        if (status == 0)
            status = patch_select_collect(
                &plan, &capacity, layer, i + 1, physical, exact, locale, platform
            );
        free(physical);
        free(prefix);
        if (layer != NULL) {
            int32_t close_status = libmpq__archive_close(layer);
            if (status == 0)
                status = close_status;
        }
    }
    if (status == 0 && !exact) {
        if (plan.count > 1)
            qsort(plan.operations, plan.count, sizeof(*plan.operations), patch_select_compare);
        status = patch_select_regular(
            &plan, lower, patches, prefixes, count, filename, &locale, &platform
        );
    }
    if (status == 0)
        status = patch_select_validate(&plan, lower, patches, locale, platform);
    if (lower != NULL) {
        int32_t close_status = libmpq__archive_close(lower);
        if (status == 0)
            status = close_status;
    }
    if (status == 0)
        *selection = plan;
    else
        libmpq__patch_selection_free(&plan);
    return status;
}

#define LIBMPQ_PATCH_TRANSFER_SIZE 16384u

typedef struct
{
    FILE *file;
    char *name;
    uint64_t size;
    mpq_md5_s md5;
    uint8_t digest[16];
    uint8_t needs_key_evidence;
} patch_spool_s;

/* Only private spools are closed and removed here. Keep the first failure. */
static int32_t
patch_spool_close(mpq_directory_s *directory, patch_spool_s *spool, int32_t status)
{
    if (spool->file != NULL && fclose(spool->file) != 0 && status == 0)
        status = LIBMPQ_ERROR_CLOSE;
    if (spool->name != NULL && libmpq__directory_remove(directory, spool->name) != 0 && status == 0)
        status = LIBMPQ_ERROR_CLOSE;
    free(spool->name);
    memset(spool, 0, sizeof(*spool));
    return status;
}

/* Allocate storage lazily as bytes are written. */
static int32_t
patch_spool_open(mpq_directory_s *directory, patch_spool_s *spool)
{
    libmpq__md5_init(&spool->md5);
    return libmpq__directory_temporary(
        directory, ".libmpq-selected-patch-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &spool->name,
        &spool->file
    );
}

/* Report short writes and keep an exact logical extent. */
static int32_t
patch_spool_write(patch_spool_s *spool, const uint8_t *data, size_t size)
{
    if (size > (uint64_t)INT64_MAX - spool->size)
        return LIBMPQ_ERROR_SIZE;
    if (fwrite(data, 1, size, spool->file) != size)
        return LIBMPQ_ERROR_WRITE;
    spool->size += size;
    return 0;
}

/* Hash logical result bytes in the order written. */
static int32_t
patch_result_write(patch_spool_s *spool, const uint8_t *data, size_t size)
{
    int32_t status = patch_spool_write(spool, data, size);
    if (status == 0)
        libmpq__md5_update(&spool->md5, data, size);
    return status;
}

/* Read only a finalized range, with explicit errors for seek and short input. */
static int32_t
patch_spool_read(patch_spool_s *spool, uint64_t offset, uint8_t *data, size_t size)
{
    if (offset > spool->size || size > spool->size - offset)
        return LIBMPQ_ERROR_READ;
    if (libmpq__file_seek(spool->file, offset, SEEK_SET) != 0)
        return LIBMPQ_ERROR_SEEK;
    return fread(data, 1, size, spool->file) == size ? 0 : LIBMPQ_ERROR_READ;
}

typedef struct
{
    mpq_archive_s *archive;
    uint32_t number;
    uint32_t blocks;
    uint32_t next;
    uint32_t *checksums;
    uint8_t *data;
    size_t capacity;
    size_t size;
    size_t position;
    uint64_t remaining;
    mpq_md5_s body_md5;
    uint8_t hash_body;
    uint8_t single;
    uint8_t lossy;
    uint8_t covered;
} patch_payload_s;

/* Decode one whole MPQ sector, or one SINGLE unit, using the archive reader. */
static int32_t
patch_payload_fill(patch_payload_s *payload)
{
    libmpq__off_t size;
    libmpq__off_t transferred;
    uint32_t mismatches = 0;
    int lossy = 0;
    uint32_t block = payload->next;
    if (block >= payload->blocks)
        return LIBMPQ_ERROR_READ;
    int32_t status = libmpq__block_size_unpacked(payload->archive, payload->number, block, &size);
    if (status != 0)
        return status;
    if (size < 0 || size > INT32_MAX || (uint64_t)size > SIZE_MAX ||
        (uint64_t)size > payload->remaining)
        return LIBMPQ_ERROR_SIZE;
    libmpq__off_t packed;
    status = libmpq__reader_block_size_packed(payload->archive, payload->number, block, &packed);
    if (status != 0)
        return status;
    if (packed < 0 || (uint64_t)packed > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    if (!payload->single && (uint64_t)packed > payload->archive->block_size)
        return LIBMPQ_ERROR_FORMAT;
    if (payload->data == NULL || (size_t)size > payload->capacity) {
        uint8_t *data = realloc(payload->data, size == 0 ? 1 : (size_t)size);
        if (data == NULL)
            return LIBMPQ_ERROR_MALLOC;
        payload->data = data;
        payload->capacity = (size_t)size;
    }
    const uint32_t *checksum = payload->checksums == NULL ? NULL : payload->checksums + block;
    status = libmpq__reader_block_read_acquired(
        payload->archive, payload->number, block, payload->data, size, &transferred, checksum,
        &mismatches, &lossy
    );
    if (status != 0)
        return status;
    if (mismatches != 0 || transferred != size)
        return LIBMPQ_ERROR_READ;
    payload->covered &= checksum != NULL && *checksum != 0 && *checksum != UINT32_MAX;
    payload->lossy |= lossy != 0;
    payload->position = 0;
    payload->size = (size_t)size;
    payload->next++;
    return 0;
}

/* Pull exact decoded bytes while tracking the physical PTCH body digest. */
static int32_t
patch_payload_read(patch_payload_s *payload, uint8_t *data, size_t size)
{
    if (size > payload->remaining)
        return LIBMPQ_ERROR_FORMAT;
    while (size != 0) {
        if (payload->position == payload->size) {
            int32_t status = patch_payload_fill(payload);
            if (status != 0)
                return status;
        }
        size_t take = payload->size - payload->position;
        if (take == 0)
            return LIBMPQ_ERROR_READ;
        if (take > size)
            take = size;
        memcpy(data, payload->data + payload->position, take);
        if (payload->hash_body)
            libmpq__md5_update(&payload->body_md5, data, take);
        data += take;
        size -= take;
        payload->position += take;
        payload->remaining -= take;
    }
    return 0;
}

/* Reuse the reader's CRC/MD5 availability rules for ordinary source members. */
static int32_t
patch_spool_member(
    patch_payload_s *payload, const mpq_file_attributes_s *attributes, patch_spool_s *next
)
{
    uint8_t buffer[LIBMPQ_PATCH_TRANSFER_SIZE];
    uint32_t crc = 0;
    if (payload->remaining == 0 && payload->blocks != 0) {
        int32_t status = patch_payload_fill(payload);
        if (status != 0)
            return status;
    }
    while (payload->remaining != 0) {
        size_t take =
            payload->remaining < sizeof(buffer) ? (size_t)payload->remaining : sizeof(buffer);
        int32_t status = patch_payload_read(payload, buffer, take);
        if (status == 0)
            status = patch_result_write(next, buffer, take);
        if (status != 0)
            return status;
        if ((attributes->flags & LIBMPQ_ATTRIBUTE_CRC32) != 0)
            crc = (uint32_t)crc32(crc, buffer, (uInt)take);
    }
    libmpq__md5_final(&next->md5, next->digest);
    uint32_t mismatches = 0;
    if (!payload->lossy)
        libmpq__attributes_compare_file(
            attributes, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, crc, next->digest,
            &mismatches
        );
    if (mismatches != 0)
        return LIBMPQ_ERROR_FORMAT;
    if ((!payload->lossy && (attributes->flags & LIBMPQ_ATTRIBUTE_MD5) != 0) ||
        (payload->covered && payload->blocks != 0))
        next->needs_key_evidence = 0;
    return 0;
}

/* Stream COPY output, or stage an unwrapped BSD0 transform. */
static int32_t
patch_transfer(patch_payload_s *payload, patch_spool_s *spool, size_t remaining, uint8_t logical)
{
    uint8_t buffer[LIBMPQ_PATCH_TRANSFER_SIZE];
    while (remaining != 0) {
        size_t take = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        int32_t status = patch_payload_read(payload, buffer, take);
        if (status == 0)
            status = logical ? patch_result_write(spool, buffer, take)
                             : patch_spool_write(spool, buffer, take);
        if (status != 0)
            return status;
        remaining -= take;
    }
    return 0;
}

/* Expand the same zero/literal runs incrementally, with no size-based preallocation. */
static int32_t
patch_spool_rle(patch_payload_s *payload, patch_spool_s *transform, size_t remaining)
{
    uint8_t bytes[128];
    int32_t status = patch_payload_read(payload, bytes, 4);
    if (status != 0)
        return status;
    while (payload->remaining != 0 && remaining != 0) {
        uint8_t command;
        status = patch_payload_read(payload, &command, 1);
        if (status != 0)
            return status;
        size_t count = (size_t)(command & 0x7fu) + 1;
        if (count > remaining)
            return LIBMPQ_ERROR_FORMAT;
        if ((command & 0x80u) != 0)
            status = patch_payload_read(payload, bytes, count);
        else
            memset(bytes, 0, count);
        if (status == 0)
            status = patch_spool_write(transform, bytes, count);
        if (status != 0)
            return status;
        remaining -= count;
    }
    return payload->remaining == 0 && remaining == 0 ? 0 : LIBMPQ_ERROR_FORMAT;
}

typedef struct
{
    patch_spool_s *transform;
    patch_spool_s *lower;
    patch_spool_s *next;
} patch_bsd_files_s;

/* Read a fixed BSD0 header or control triple from the transform spool. */
static int32_t
patch_bsd_file_read(void *context, uint64_t offset, uint8_t *data, size_t size)
{
    const patch_bsd_files_s *files = context;
    return patch_spool_read(files->transform, offset, data, size);
}

/* Stream one validated delta or extra range into the new logical result. */
static int32_t
patch_bsd_file_span(
    void *context, uint64_t offset, uint64_t source, uint64_t target, uint32_t size, uint8_t add
)
{
    const patch_bsd_files_s *files = context;
    uint8_t data[LIBMPQ_PATCH_TRANSFER_SIZE];
    uint8_t old[LIBMPQ_PATCH_TRANSFER_SIZE];
    if (files->next->size != target)
        return LIBMPQ_ERROR_FORMAT;
    while (size != 0) {
        size_t take = size < sizeof(data) ? (size_t)size : sizeof(data);
        int32_t status = patch_spool_read(files->transform, offset, data, take);
        if (status != 0)
            return status;
        if (add && source < files->lower->size) {
            uint64_t available = files->lower->size - source;
            size_t covered = available < take ? (size_t)available : take;
            status = patch_spool_read(files->lower, source, old, covered);
            if (status != 0)
                return status;
            for (size_t i = 0; i < covered; ++i)
                data[i] = (uint8_t)(data[i] + old[i]);
        }
        status = patch_result_write(files->next, data, take);
        if (status != 0)
            return status;
        offset += take;
        source += take;
        size -= (uint32_t)take;
    }
    return 0;
}

/* Verify and apply one physical patch before allowing the caller to adopt it. */
static int32_t
patch_spool_delta(
    patch_payload_s *payload, const mpq_patch_selection_operation_s *op, mpq_directory_s *directory,
    patch_spool_s *lower, patch_spool_s *next
)
{
    patch_spool_s decoded = { 0 };
    patch_transform_s transform;
    uint8_t header[LIBMPQ_PATCH_HEADER_SIZE];
    uint8_t digest[16];
    if (lower->file == NULL)
        return LIBMPQ_ERROR_FORMAT;
    libmpq__md5_init(&payload->body_md5);
    payload->hash_body = 1;
    int32_t status = patch_payload_read(payload, header, sizeof(header));
    if (status != 0)
        return status;
    status = patch_transform_parse(header, op->patch_info.data_size, lower->size, &transform);
    if (status != 0)
        return status;
    if (transform.after != op->unpacked_size || memcmp(lower->digest, header + 24, 16) != 0)
        return LIBMPQ_ERROR_FORMAT;

    uint8_t copy = memcmp(header + 64, "COPY", 4) == 0;
    if (copy) {
        if (transform.encoded != transform.decoded || transform.decoded != transform.after)
            return LIBMPQ_ERROR_FORMAT;
        status = patch_transfer(payload, next, transform.encoded, 1);
    } else {
        if (memcmp(header + 64, "BSD0", 4) != 0 ||
            transform.decoded < LIBMPQ_PATCH_BSDIFF_HEADER_SIZE ||
            transform.decoded > LIBMPQ_PATCH_BSDIFF_HEADER_SIZE + UINT64_C(13) * transform.after)
            return LIBMPQ_ERROR_FORMAT;
        if (transform.decoded != transform.encoded &&
            (transform.encoded < 4 || transform.decoded > UINT64_C(128) * (transform.encoded - 4)))
            return LIBMPQ_ERROR_FORMAT;
        status = patch_spool_open(directory, &decoded);
        if (status == 0)
            status = transform.decoded == transform.encoded
                         ? patch_transfer(payload, &decoded, transform.encoded, 0)
                         : patch_spool_rle(payload, &decoded, transform.decoded);
    }
    libmpq__md5_final(&payload->body_md5, digest);
    if (status == 0 &&
        (payload->remaining != 0 || memcmp(digest, op->patch_info.md5, sizeof(digest)) != 0))
        status = LIBMPQ_ERROR_FORMAT;
    if (status == 0 && !copy) {
        if (fflush(decoded.file) != 0)
            status = LIBMPQ_ERROR_WRITE;
        else {
            patch_bsd_files_s files = { &decoded, lower, next };
            status = patch_walk_bsd0(
                &files, patch_bsd_file_read, patch_bsd_file_span, decoded.size, transform.after
            );
        }
    }
    if (status == 0) {
        libmpq__md5_final(&next->md5, next->digest);
        if (next->size != transform.after || memcmp(next->digest, header + 40, 16) != 0)
            status = LIBMPQ_ERROR_FORMAT;
    }
    return patch_spool_close(directory, &decoded, status);
}

/* Read the selected canonical member with the plan's exact spelling and geometry. */
static int32_t
patch_spool_operation(
    mpq_archive_s *input, const mpq_patch_selection_operation_s *op, mpq_directory_s *directory,
    patch_spool_s *lower, patch_spool_s *next
)
{
    patch_payload_s payload = { .number = op->number, .covered = 1 };
    mpq_file_attributes_s attributes;
    int32_t status = libmpq__archive_clone(&payload.archive, input);
    if (status != 0)
        return status;
    status = libmpq__reader_validate_file_number(payload.archive, op->number);
    if (status != 0)
        goto done;
    mpq_archive_s *archive = payload.archive;
    uint32_t index = archive->mpq_map[op->number].entry_index;
    const mpq_entry_s *entry = &archive->mpq_entry[index];
    if (entry->offset != op->offset || entry->packed_size != op->packed_size ||
        entry->unpacked_size != op->unpacked_size || entry->flags != op->flags) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    uint8_t delta = op->kind == LIBMPQ_PATCH_SELECT_DELTA;
    uint64_t prefix = delta ? op->patch_info.length : 0;
    payload.single = (op->flags & LIBMPQ_FILE_FLAG_SINGLE) != 0;
    payload.remaining = delta ? op->patch_info.data_size : op->unpacked_size;
    if (prefix > op->packed_size) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (op->packed_size - prefix > UINT32_MAX || payload.remaining > UINT32_MAX ||
        (payload.single &&
         (payload.remaining > INT32_MAX || op->packed_size - prefix > INT32_MAX)) ||
        (delta && op->unpacked_size > UINT32_MAX)) {
        status = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    status = libmpq__reader_validate_payload_range(archive, index, 0, entry->packed_size);
    if (status != 0)
        goto done;
    uint32_t checked;
    uint32_t unavailable;
    uint32_t mismatches;
    status = libmpq__verify_file_ex(
        archive, op->number, NULL, LIBMPQ_VERIFY_RAW_MD5, &checked, &unavailable, &mismatches,
        malloc
    );
    if (status != 0 || mismatches != 0) {
        if (status == 0)
            status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }

    uint32_t key;
    const uint32_t *seed = NULL;
    if (delta) {
        status =
            patch_body_view(archive, op->number, op->physical_name, &op->patch_info, &key, &seed);
    } else {
        status = libmpq__verify_attributes(archive, op->number, &attributes);
        next->needs_key_evidence = op->needs_key_evidence;
    }
    if (status != 0)
        goto done;
    status = libmpq__reader_offsets_acquire_key(archive, op->number, op->physical_name, seed);
    if (status != 0)
        goto done;
    status = libmpq__file_blocks(archive, op->number, &payload.blocks);
    if (status == 0)
        status = libmpq__reader_sector_checksums(archive, op->number, &payload.checksums);
    if (status == 0)
        status = patch_spool_open(directory, next);
    if (status == 0)
        status = delta ? patch_spool_delta(&payload, op, directory, lower, next)
                       : patch_spool_member(&payload, &attributes, next);
    if (status == 0 && (next->size != op->unpacked_size || payload.next != payload.blocks))
        status = LIBMPQ_ERROR_FORMAT;
    if (status == 0 && fflush(next->file) != 0)
        status = LIBMPQ_ERROR_WRITE;

done:
    free(payload.data);
    free(payload.checksums);
    {
        int32_t cleanup = libmpq__archive_close(payload.archive);
        return status != 0 ? status : cleanup;
    }
}

/* Execute synchronously, then transfer only the final logical spool to the stream. */
int32_t
libmpq__patch_execute(
    const mpq_patch_selection_s *selection, mpq_archive_s *base, mpq_archive_s *const *patches,
    size_t count, mpq_stream_s **stream
)
{
    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (selection == NULL || selection->operations == NULL || selection->count == 0 ||
        base == NULL || (count != 0 && patches == NULL))
        return LIBMPQ_ERROR_EXIST;

    patch_spool_s lower = { 0 };
    patch_spool_s next = { 0 };
    mpq_directory_s *directory = NULL;
    char *name = NULL;
    char *anchor = libmpq__file_temporary_anchor();
    if (anchor == NULL)
        return LIBMPQ_ERROR_MALLOC;
    int32_t status = libmpq__directory_open(anchor, &directory, &name);
    free(anchor);
    free(name);
    if (status != 0)
        return status;

    for (size_t i = 0; status == 0 && i < selection->count; ++i) {
        const mpq_patch_selection_operation_s *op = &selection->operations[i];
        if (op->source > count) {
            status = LIBMPQ_ERROR_EXIST;
            break;
        }
        mpq_archive_s *input = op->source == 0 ? base : patches[op->source - 1];
        if (input == NULL) {
            status = LIBMPQ_ERROR_EXIST;
            break;
        }
        if (lower.needs_key_evidence && op->kind != LIBMPQ_PATCH_SELECT_DELTA) {
            status = LIBMPQ_ERROR_DECRYPT;
            break;
        }
        if (op->kind != LIBMPQ_PATCH_SELECT_DELETE)
            status = patch_spool_operation(input, op, directory, &lower, &next);
        if (status == 0) {
            status = patch_spool_close(directory, &lower, 0);
            lower = next;
            memset(&next, 0, sizeof(next));
        }
    }
    if (status == 0 && lower.file == NULL)
        status = LIBMPQ_ERROR_EXIST;
    if (status == 0 && lower.needs_key_evidence)
        status = LIBMPQ_ERROR_DECRYPT;
    if (status == 0) {
        mpq_source_s *source;
        status = libmpq__source_adopt_spool(&source, lower.file, lower.size, directory, lower.name);
        if (status == 0) {
            directory = NULL;
            memset(&lower, 0, sizeof(lower));
            status = libmpq__reader_stream_adopt_source(stream, source);
            if (status != 0)
                libmpq__source_discard(source);
        }
    }
    status = patch_spool_close(directory, &next, status);
    status = patch_spool_close(directory, &lower, status);
    libmpq__directory_close(directory);
    return status;
}
