/*
 *  mpq-attributes.c -- optional MPQ attributes parsing and serialization.
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

#include "mpq-attributes.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-reader.h"

#include <stdlib.h>
#include <string.h>

/* Calculate numeric-array offsets without narrowing unchecked file sizes.
 * The same helper handles full tables and the known one-entry-short layout. */
static uint64_t
array_layout(uint32_t count, uint32_t flags, mpq_attributes_s *view)
{
    static const uint32_t widths[] = { 4, 8, 16 };
    uint64_t size = 8;
    uint32_t i;

    for (i = 0; i < 3; ++i) {
        if (size <= SIZE_MAX)
            view->offsets[i] = (size_t)size;
        if (flags & (1u << i))
            size += (uint64_t)count * widths[i];
    }
    if (size <= SIZE_MAX)
        view->offsets[3] = (size_t)size;
    return size;
}

/* Recognize an exact layout, including documented Storm-style exceptions.
 * Unknown DWORD patch contents are not interpreted as a bit array. */
static int
match_layout(
    const uint8_t *data, size_t size, uint32_t count, uint32_t entries, mpq_attributes_s *view,
    int legacy
)
{
    uint64_t base = array_layout(entries, view->flags, view);
    uint64_t bits = ((uint64_t)entries + 7) / 8;
    uint64_t short_bits = ((uint64_t)count + 6) / 8;
    size_t i;

    if (base > size)
        return 0;
    view->entries = entries;
    if (!(view->flags & LIBMPQ_ATTRIBUTE_PATCH_BIT))
        return base == size;
    if (base + bits == size) {
        view->patch_bits = (uint64_t)entries;
        return 1;
    }
    if (base + short_bits == size) {
        view->patch_bits = short_bits * 8;
        view->patch_self_omitted = 1;
        return 1;
    }
    if (!legacy)
        return 0;
    if (base == size)
        return 1;
    if (base + (uint64_t)count * 4 != size)
        return 0;
    for (i = (size_t)base; i < size; ++i) {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}

/* Parse an immutable payload against its physical block-table count.
 * Only recognized exact layouts are accepted; no partial result escapes on error. */
int32_t
libmpq__attributes_parse(
    const uint8_t *data, size_t size, uint32_t count, uint32_t self, mpq_attributes_s *view
)
{
    mpq_attributes_s candidate = { 0 };

    memset(view, 0, sizeof(*view));
    if (data == NULL || size < 8 || count == 0 || self >= count ||
        libmpq__load_le32(data) != LIBMPQ_ATTRIBUTES_VERSION)
        return LIBMPQ_ERROR_FORMAT;
    candidate.flags = libmpq__load_le32(data + 4);
    if (candidate.flags & ~LIBMPQ_ATTRIBUTES_ALL)
        return LIBMPQ_ERROR_FORMAT;
    candidate.data = data;
    candidate.self = self;
    if (!match_layout(data, size, count, count, &candidate, 0) &&
        !match_layout(data, size, count, count - 1, &candidate, 0) &&
        !match_layout(data, size, count, count, &candidate, 1))
        return LIBMPQ_ERROR_FORMAT;
    *view = candidate;
    return LIBMPQ_SUCCESS;
}

/* Decode one physical block-table entry without changing its availability.
 * Omitted legacy rows and opaque patch arrays remain explicitly unavailable. */
void
libmpq__attributes_get(const mpq_attributes_s *view, uint32_t index, mpq_file_attributes_s *result)
{
    memset(result, 0, sizeof(*result));
    if (index >= view->entries)
        return;
    result->flags = view->flags & ~LIBMPQ_ATTRIBUTE_PATCH_BIT;
    if (result->flags & LIBMPQ_ATTRIBUTE_CRC32)
        result->crc32 = libmpq__load_le32(view->data + view->offsets[0] + (size_t)index * 4);
    if (result->flags & LIBMPQ_ATTRIBUTE_FILETIME)
        result->filetime = libmpq__load_le64(view->data + view->offsets[1] + (size_t)index * 8);
    if (result->flags & LIBMPQ_ATTRIBUTE_MD5)
        memcpy(result->md5, view->data + view->offsets[2] + (size_t)index * 16, 16);
    if (view->flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) {
        if (index < view->patch_bits) {
            result->flags |= LIBMPQ_ATTRIBUTE_PATCH_BIT;
            result->patch_bit =
                (view->data[view->offsets[3] + index / 8] & (0x80u >> (index % 8))) != 0;
        } else if (index == view->self && view->patch_self_omitted) {
            result->flags |= LIBMPQ_ATTRIBUTE_PATCH_BIT;
        }
    }
}

/* Load optional metadata only when requested, using normal MPQ file I/O.
 * Structural errors and absence are cached; transient resource errors can be retried. */
int32_t
libmpq__attributes_load(mpq_archive_s *archive)
{
    uint32_t number;
    libmpq__off_t size = 0;
    libmpq__off_t transferred = 0;
    mpq_attributes_s *view;
    uint8_t *data;
    int32_t result;

    if (archive->attributes != NULL)
        return LIBMPQ_SUCCESS;
    if (archive->attributes_error != LIBMPQ_SUCCESS)
        return archive->attributes_error;
    result = libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &number);
    if (result != LIBMPQ_SUCCESS) {
        if (result == LIBMPQ_ERROR_EXIST || result == LIBMPQ_ERROR_FORMAT)
            archive->attributes_error = result;
        return result;
    }
    result = libmpq__file_size_unpacked(archive, number, &size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (size < 8 || (uint64_t)size > SIZE_MAX ||
        (uint64_t)size > 8 + (uint64_t)archive->mpq_header.block_table_count * 32) {
        archive->attributes_error = LIBMPQ_ERROR_FORMAT;
        return LIBMPQ_ERROR_FORMAT;
    }
    data = malloc((size_t)size);
    view = calloc(1, sizeof(*view));
    if (data == NULL || view == NULL) {
        free(data);
        free(view);
        return LIBMPQ_ERROR_MALLOC;
    }
    result = libmpq__reader_open_named(archive, number, LIBMPQ_ATTRIBUTES_NAME);
    if (result == LIBMPQ_SUCCESS) {
        result = libmpq__file_read(archive, number, data, size, &transferred);
        (void)libmpq__block_close_offset(archive, number);
        if (result == LIBMPQ_SUCCESS && transferred != size)
            result = LIBMPQ_ERROR_READ;
    }
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__attributes_parse(
            data, (size_t)size, archive->mpq_header.block_table_count,
            archive->mpq_map[number].block_table_indices, view
        );
    if (result != LIBMPQ_SUCCESS) {
        free(data);
        free(view);
        if (result == LIBMPQ_ERROR_FORMAT)
            archive->attributes_error = result;
        return result;
    }
    archive->attributes = view;
    return LIBMPQ_SUCCESS;
}

/* Release both reader-owned payloads and writer-owned metadata records.
 * Reader callers invoke this only after a successful public close. */
void
libmpq__attributes_free(mpq_archive_s *archive)
{
    if (archive->attributes != NULL) {
        free((void *)archive->attributes->data);
        free(archive->attributes);
        archive->attributes = NULL;
    }
    free(archive->write_attributes);
    archive->write_attributes = NULL;
}

/* Return the dedicated attribute mask, independent of creation flags and policy. */
uint32_t
libmpq__attributes_write_flags(const mpq_archive_s *archive)
{
    return archive->write_attributes_flags;
}

/* Serialize complete numeric arrays and Storm-compatible zero patch bits.
 * Self and unused records are zero, and true patch bits are never silently discarded. */
int32_t
libmpq__attributes_serialize(
    const mpq_file_attributes_s *entries, uint32_t count, uint32_t self, uint32_t flags,
    uint8_t **data, size_t *size
)
{
    mpq_attributes_s layout = { 0 };
    uint64_t length;
    uint8_t *raw;
    uint32_t i;

    *data = NULL;
    *size = 0;
    if (count == 0 || self >= count || (flags & ~LIBMPQ_ATTRIBUTES_ALL))
        return LIBMPQ_ERROR_FORMAT;
    length = array_layout(count, flags, &layout);
    if (flags & LIBMPQ_ATTRIBUTE_PATCH_BIT)
        length += ((uint64_t)count + 6) / 8;
    if (length > SIZE_MAX || length > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    for (i = 0; i < count; ++i) {
        if (entries[i].patch_bit != 0)
            return LIBMPQ_ERROR_FORMAT;
    }
    raw = calloc(1, (size_t)length);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    libmpq__store_le32(raw, LIBMPQ_ATTRIBUTES_VERSION);
    libmpq__store_le32(raw + 4, flags);
    for (i = 0; i < count; ++i) {
        if (i == self)
            continue;
        if (flags & LIBMPQ_ATTRIBUTE_CRC32)
            libmpq__store_le32(raw + layout.offsets[0] + (size_t)i * 4, entries[i].crc32);
        if (flags & LIBMPQ_ATTRIBUTE_FILETIME)
            libmpq__store_le64(raw + layout.offsets[1] + (size_t)i * 8, entries[i].filetime);
        if (flags & LIBMPQ_ATTRIBUTE_MD5)
            memcpy(raw + layout.offsets[2] + (size_t)i * 16, entries[i].md5, 16);
    }
    *data = raw;
    *size = (size_t)length;
    return LIBMPQ_SUCCESS;
}
