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
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-md5.h"
#include "mpq-patch-reader.h"
#include "mpq-reader.h"
#include "mpq-signature.h"
#include "mpq-source.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifdef _WIN32
#include <windows.h>
#endif

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
    const uint8_t *data, size_t header_size, size_t available_size, mpq_patch_info_s *info
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

/* Apply the BSD0 control, delta, and extra blocks using bounded offsets. */
static int32_t
patch_apply_bsd0(
    const uint8_t *base, size_t base_size, const uint8_t *data, size_t data_size, uint8_t *output,
    size_t output_size
)
{
    size_t control_size;
    size_t delta_size;
    size_t extra_size;
    size_t control = 0;
    size_t delta = 0;
    size_t extra = 0;
    size_t target = 0;
    int64_t source = 0;
    const uint8_t *controls;
    const uint8_t *deltas;
    const uint8_t *extras;

    if (data_size < LIBMPQ_PATCH_BSDIFF_HEADER_SIZE || memcmp(data, "BSDIFF40", 8) != 0 ||
        libmpq__load_le64(data + 24) != output_size || libmpq__load_le64(data + 8) > SIZE_MAX ||
        libmpq__load_le64(data + 16) > SIZE_MAX)
        return LIBMPQ_ERROR_FORMAT;
    control_size = (size_t)libmpq__load_le64(data + 8);
    delta_size = (size_t)libmpq__load_le64(data + 16);
    if (control_size > data_size - LIBMPQ_PATCH_BSDIFF_HEADER_SIZE ||
        delta_size > data_size - LIBMPQ_PATCH_BSDIFF_HEADER_SIZE - control_size)
        return LIBMPQ_ERROR_FORMAT;
    controls = data + LIBMPQ_PATCH_BSDIFF_HEADER_SIZE;
    deltas = controls + control_size;
    extras = deltas + delta_size;
    extra_size = data_size - LIBMPQ_PATCH_BSDIFF_HEADER_SIZE - control_size - delta_size;
    while (target < output_size) {
        size_t add;
        size_t copy;
        uint32_t raw_move;
        int64_t move;
        size_t i;

        if (control_size - control < 12)
            return LIBMPQ_ERROR_FORMAT;
        add = libmpq__load_le32(controls + control);
        copy = libmpq__load_le32(controls + control + 4);
        raw_move = libmpq__load_le32(controls + control + 8);
        move =
            (raw_move & 0x80000000u) != 0 ? -(int64_t)(raw_move & 0x7fffffffu) : (int64_t)raw_move;
        control += 12;
        if (add > output_size - target || add > delta_size - delta || source < 0 ||
            source > INT64_MAX - (int64_t)add)
            return LIBMPQ_ERROR_FORMAT;
        for (i = 0; i < add; i++) {
            uint64_t old_offset = (uint64_t)source + i;
            uint8_t old_byte = old_offset < base_size ? base[old_offset] : 0;

            output[target + i] = (uint8_t)(deltas[delta + i] + old_byte);
        }
        target += add;
        delta += add;
        source += (int64_t)add;
        if (copy > output_size - target || copy > extra_size - extra)
            return LIBMPQ_ERROR_FORMAT;
        memcpy(output + target, extras + extra, copy);
        target += copy;
        extra += copy;
        if ((move > 0 && source > INT64_MAX - move) || (move < 0 && source < INT64_MIN - move))
            return LIBMPQ_ERROR_FORMAT;
        source += move;
        if (add == 0 && copy == 0)
            return LIBMPQ_ERROR_FORMAT;
    }
    return target == output_size && control == control_size && delta == delta_size &&
                   extra == extra_size
               ? 0
               : LIBMPQ_ERROR_FORMAT;
}

/* Apply and verify a PTCH payload, optionally borrowing COPY output. */
static int32_t
patch_apply_internal(
    const uint8_t *base, size_t base_size, const uint8_t *patch, size_t patch_size,
    uint8_t **output, size_t *output_size, uint8_t borrow_copy
)
{
    uint32_t complete_size;
    uint32_t before_size;
    uint32_t after_size;
    uint32_t md5_block_size;
    uint32_t transform_size;
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
    if ((base == NULL && base_size != 0) || patch == NULL ||
        patch_size < LIBMPQ_PATCH_HEADER_SIZE || memcmp(patch, "PTCH", 4) != 0 ||
        memcmp(patch + 16, "MD5_", 4) != 0 || memcmp(patch + 56, "XFRM", 4) != 0)
        return LIBMPQ_ERROR_FORMAT;
    complete_size = libmpq__load_le32(patch + 4);
    before_size = libmpq__load_le32(patch + 8);
    after_size = libmpq__load_le32(patch + 12);
    md5_block_size = libmpq__load_le32(patch + 20);
    transform_size = libmpq__load_le32(patch + 60);
    if (before_size != base_size || md5_block_size != 40 ||
        complete_size < LIBMPQ_PATCH_HEADER_SIZE || transform_size < 12 ||
        transform_size - 12 != patch_size - LIBMPQ_PATCH_HEADER_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    status = patch_check_md5(base, base_size, patch + 24);
    if (status != 0)
        return status;
    encoded = patch + LIBMPQ_PATCH_HEADER_SIZE;
    encoded_size = patch_size - LIBMPQ_PATCH_HEADER_SIZE;
    decoded_size = complete_size - LIBMPQ_PATCH_HEADER_SIZE;
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
        status = patch_apply_bsd0(base, base_size, decoded, decoded_size, result, after_size);
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
    if (path == NULL)
        return NULL;
    memcpy(path, absolute, directory_size);
    memcpy(path + directory_size, temporary, name_size + 1);
    return path;
}

/* Select a process temporary directory, separate from the read-only base. */
static char *
patch_temporary_anchor(void)
{
#ifdef _WIN32
    DWORD capacity = GetTempPathW(0, NULL);
    wchar_t *wide;
    char *directory;
    DWORD length;
    int bytes;

    if (capacity == 0)
        return NULL;
    wide = malloc((size_t)capacity * sizeof(*wide));
    if (wide == NULL)
        return NULL;
    length = GetTempPathW(capacity, wide);
    if (length == 0 || length >= capacity) {
        free(wide);
        return NULL;
    }
    bytes = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    directory = bytes > 0 ? malloc((size_t)bytes + sizeof("libmpq-patch-view-anchor")) : NULL;
    if (directory != NULL) {
        if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, directory, bytes, NULL, NULL) == 0) {
            free(directory);
            directory = NULL;
        } else {
            strcat(directory, "libmpq-patch-view-anchor");
        }
    }
    free(wide);
    return directory;
#else
    const char *directory = getenv("TMPDIR");
    size_t length;
    char *anchor;

    if (directory == NULL || directory[0] != '/')
        directory = "/tmp";
    length = strlen(directory);
    if (length > SIZE_MAX - sizeof("/libmpq-patch-view-anchor"))
        return NULL;
    anchor = malloc(length + sizeof("/libmpq-patch-view-anchor"));
    if (anchor != NULL) {
        memcpy(anchor, directory, length);
        memcpy(anchor + length, "/libmpq-patch-view-anchor", sizeof("/libmpq-patch-view-anchor"));
    }
    return anchor;
#endif
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
    mpq_archive_s *archive, const char *name, uint32_t number, uint8_t **data, size_t *size
)
{
    libmpq__off_t transferred = 0;
    libmpq__off_t logical_size = 0;
    uint8_t *bytes = NULL;
    int32_t status;

    status = libmpq__reader_offsets_acquire(archive, number, name);
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
    return patch_read_adjusted(archive, name, number, data, size);
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
libmpq__patch_payload_size(mpq_archive_s *archive, uint32_t number, libmpq__off_t *size)
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
    mpq_entry_s *block;
    uint8_t *body = NULL;
    mpq_patch_info_s info;
    uint64_t shifted;
    uint32_t prefix_size;
    uint32_t physical;
    size_t body_size = 0;
    int32_t status;

    *data = NULL;
    *size = 0;
    status = patch_member_info(archive, number, &info);
    if (status != 0)
        return status;
    prefix_size = info.length;
    status = libmpq__archive_clone(&clone, archive);
    if (status != 0)
        goto done;
    status = libmpq__reader_validate_file_number(clone, number);
    if (status != 0)
        goto done;
    physical = clone->mpq_map[number].entry_index;
    block = &clone->mpq_entry[physical];
    shifted = block->offset + prefix_size;
    if (shifted > UINT32_MAX && clone->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {
        status = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    block->offset = shifted;
    block->packed_size -= prefix_size;
    block->unpacked_size = info.data_size;
    block->flags &= ~LIBMPQ_FILE_FLAG_PATCH_FILE;
    clone->attributes_error = LIBMPQ_ERROR_EXIST;
    status = patch_read_adjusted(clone, name, number, &body, &body_size);
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
libmpq__patch_payload_read(
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
    status = libmpq__patch_payload_size(archive, number, &expected);
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
    libmpq__attributes_get(archive->attributes, archive->mpq_entry[index].source_index, attributes);
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
        if (memchr(list + start, 0, length) != NULL)
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
    const char *separator = strrchr(name, '\\');
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
        if (length > SIZE_MAX - 1) {
            status = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        if (discovered == NULL) {
            discovered = malloc(length + 1);
            if (discovered == NULL) {
                status = LIBMPQ_ERROR_MALLOC;
                goto done;
            }
            memcpy(discovered, entry->name, length);
            discovered[length] = '\0';
        } else if (strlen(discovered) != length ||
                   !patch_name_equal(discovered, entry->name, length)) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        {
            uint32_t number = patch_number_for_block(patch, entry->block_index);
            libmpq__off_t size;

            if (number == UINT32_MAX || libmpq__file_size_unpacked(patch, number, &size) != 0 ||
                size <= 0 || size >= 64) {
                status = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
    }
    if (explicit_prefix != NULL && discovered != NULL &&
        (strlen(explicit_prefix) != strlen(discovered) ||
         !patch_name_equal(explicit_prefix, discovered, strlen(discovered)))) {
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
        if (memchr(original + start, 0, length) != NULL) {
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
            &payload, &payload_size
        );
    if (status != 0)
        goto done;
    if ((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0) {
        if (lower_number == UINT32_MAX) {
            status = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        status = patch_read_adjusted(lower, entry->name, lower_number, &base, &base_size);
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
    if (archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *archive = NULL;
    if (source == NULL || source->path == NULL)
        return LIBMPQ_ERROR_EXIST;
    return source->auth_code == NULL
               ? libmpq__archive_open(archive, source->path, -1)
               : libmpq__archive_open_mpqe(
                     archive, source->path, -1, source->auth_code, source->auth_code_size
                 );
}

/* Apply a complete layer in a separate private materialization, never via updates. */
static int32_t
patch_apply_layer(mpq_patch_view_s *view, const mpq_patch_source_s *source)
{
    mpq_archive_s *patch = NULL;
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
    uint8_t detected = 0;
    uint8_t mutated = 0;
    uint8_t has_attributes = 0;
    int32_t status;

    status = patch_source_open(&patch, source);
    if (status != 0)
        return status;
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
    status = libmpq__archive_open(&lower, view->path, view->archive_offset);
    if (status != 0)
        goto done;

    /* Materialization currently rebuilds only v1/v2 archive headers. */
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
    if (patch != NULL)
        (void)libmpq__archive_close(patch);
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

/* Materialize independently opened sources without changing any input archive. */
int32_t
libmpq__patch_view_open_sources(
    mpq_patch_view_s **view, const mpq_patch_source_s *base_source,
    const mpq_patch_source_s *patch_sources, size_t patch_count
)
{
    mpq_patch_view_s *state = NULL;
    mpq_archive_s *base = NULL;
    FILE *temporary = NULL;
    char *absolute = NULL;
    char *destination = NULL;
    int32_t status;

    if (view == NULL)
        return LIBMPQ_ERROR_EXIST;
    *view = NULL;
    if (base_source == NULL || base_source->path == NULL || patch_sources == NULL ||
        patch_count == 0)
        return LIBMPQ_ERROR_EXIST;
    state = calloc(1, sizeof(*state));
    if (state == NULL)
        return LIBMPQ_ERROR_MALLOC;
    status = patch_source_open(&base, base_source);
    if (status != 0)
        goto error;
    absolute = patch_temporary_anchor();
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
        if (patch_sources[i].path == NULL) {
            status = LIBMPQ_ERROR_EXIST;
            goto error;
        }
        status = patch_apply_layer(state, &patch_sources[i]);
        if (status != 0)
            goto error;
    }
    status = libmpq__archive_open(&state->archive, state->path, state->archive_offset);
    if (status != 0)
        goto error;
    free(destination);
    free(absolute);
    *view = state;
    return 0;

error:
    if (temporary != NULL)
        (void)fclose(temporary);
    if (base != NULL)
        (void)libmpq__archive_close(base);
    free(destination);
    free(absolute);
    (void)libmpq__patch_view_close(state);
    return status;
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
