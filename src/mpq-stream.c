/*
 *  mpq-stream.c -- incremental logical MPQ member stream.
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

#include "mpq-stream.h"
#include "mpq-internal.h"
#include "mpq-reader.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct mpq_stream
{
    mpq_archive_s *archive;
    uint32_t file_number;
    uint32_t blocks;
    uint32_t cached_block;
    uint32_t *checksums;
    uint8_t *buffer;
    uint8_t offsets_acquired;
    uint8_t block_valid;
    libmpq__off_t size;
    libmpq__off_t position;
    libmpq__off_t buffer_size;
    libmpq__off_t block_size;
};

static int32_t
stream_load_block(mpq_stream_s *stream, uint32_t block)
{
    libmpq__off_t size = 0;
    libmpq__off_t transferred = 0;
    uint32_t mismatches = 0;
    int32_t result;

    if (stream->block_valid && stream->cached_block == block)
        return LIBMPQ_SUCCESS;
    result = libmpq__block_size_unpacked(stream->archive, stream->file_number, block, &size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (size < 0 || (uint64_t)size > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    if (size > stream->buffer_size) {
        uint8_t *buffer = realloc(stream->buffer, (size_t)size);
        if (buffer == NULL && size != 0)
            return LIBMPQ_ERROR_MALLOC;
        stream->buffer = buffer;
        stream->buffer_size = size;
    }
    result = libmpq__reader_block_read_acquired(
        stream->archive, stream->file_number, block, stream->buffer, stream->buffer_size,
        &transferred, stream->checksums != NULL ? stream->checksums + block : NULL, &mismatches,
        NULL
    );
    if (mismatches != 0)
        return LIBMPQ_ERROR_READ;
    if (result != LIBMPQ_SUCCESS)
        return result;
    stream->cached_block = block;
    stream->block_size = transferred;
    stream->block_valid = 1;
    return LIBMPQ_SUCCESS;
}

/* Take ownership of a private archive clone and initialize one logical stream. */
static int32_t
stream_adopt(mpq_archive_s *archive, uint32_t file_number, const char *name, mpq_stream_s **stream)
{
    mpq_stream_s *result = NULL;
    uint32_t *checksums = NULL;
    int32_t status;

    if (stream == NULL) {
        if (archive != NULL)
            (void)libmpq__archive_close(archive);
        return LIBMPQ_ERROR_EXIST;
    }
    *stream = NULL;
    if (archive == NULL || archive->write_mode ||
        libmpq__reader_validate_file_number(archive, file_number) != LIBMPQ_SUCCESS) {
        if (archive != NULL)
            (void)libmpq__archive_close(archive);
        return LIBMPQ_ERROR_EXIST;
    }
    result = calloc(1, sizeof(*result));
    if (result == NULL) {
        (void)libmpq__archive_close(archive);
        return LIBMPQ_ERROR_MALLOC;
    }
    result->archive = archive;
    result->file_number = file_number;
    status = libmpq__reader_offsets_acquire(result->archive, file_number, name);
    if (status != LIBMPQ_SUCCESS)
        goto error;
    result->offsets_acquired = 1;
    status = libmpq__file_size_unpacked(result->archive, file_number, &result->size);
    if (status != LIBMPQ_SUCCESS)
        goto error;
    status = libmpq__file_blocks(result->archive, file_number, &result->blocks);
    if (status != LIBMPQ_SUCCESS)
        goto error;
    if (result->blocks != 0) {
        mpq_file_s *file;
        uint32_t flags;
        uint32_t start;
        uint32_t end;

        status = libmpq__file_flags(result->archive, file_number, &flags);
        if (status != LIBMPQ_SUCCESS)
            goto error;
        if ((flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0) {
            file = result->archive->mpq_file[file_number];
            if (file == NULL || file->packed_offset == NULL || file->packed_offset_count < 2) {
                status = LIBMPQ_ERROR_FORMAT;
                goto error;
            }
            start = file->packed_offset[0];
            end = file->packed_offset[1];
            if (end < start) {
                status = LIBMPQ_ERROR_FORMAT;
                goto error;
            }
            if (end - start >= sizeof(uint32_t)) {
                uint32_t seed;

                status = libmpq__reader_get_block_seed(result->archive, file_number, 0, &seed);
                if (status != LIBMPQ_SUCCESS)
                    goto error;
            }
        }
    }
    if (libmpq__reader_sector_checksums(result->archive, file_number, &checksums) == LIBMPQ_SUCCESS)
        result->checksums = checksums;
    result->cached_block = UINT32_MAX;
    *stream = result;
    return LIBMPQ_SUCCESS;

error:
    free(checksums);
    if (result->offsets_acquired)
        (void)libmpq__reader_offsets_release(result->archive, file_number);
    if (result->archive != NULL)
        (void)libmpq__archive_close(result->archive);
    free(result);
    return status;
}

int32_t
libmpq__reader_stream_open(mpq_archive_s *archive, uint32_t file_number, mpq_stream_s **stream)
{
    mpq_archive_s *clone = NULL;
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (archive == NULL || archive->write_mode ||
        libmpq__reader_validate_file_number(archive, file_number) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_clone(&clone, archive);
    if (result != LIBMPQ_SUCCESS)
        return result;
    return stream_adopt(clone, file_number, NULL, stream);
}

int32_t
libmpq__reader_stream_open_name(mpq_archive_s *archive, const char *filename, mpq_stream_s **stream)
{
    mpq_archive_s *clone = NULL;
    uint32_t file_number;
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (archive == NULL || filename == NULL || archive->write_mode)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_clone(&clone, archive);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__file_number(clone, filename, &file_number);
    if (result != LIBMPQ_SUCCESS) {
        (void)libmpq__archive_close(clone);
        return result;
    }
    return stream_adopt(clone, file_number, filename, stream);
}

int32_t
libmpq__reader_stream_read(
    mpq_stream_s *stream, uint8_t *buffer, libmpq__off_t size, libmpq__off_t *transferred
)
{
    libmpq__off_t total = 0;

    if (transferred != NULL)
        *transferred = 0;
    if (size < 0 || (uint64_t)size > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    if (stream == NULL || (buffer == NULL && size != 0))
        return LIBMPQ_ERROR_EXIST;
    while (total < size && stream->position < stream->size) {
        libmpq__off_t base;
        libmpq__off_t offset;
        libmpq__off_t available;
        libmpq__off_t count;
        uint32_t block;
        int32_t result;

        block =
            stream->blocks == 1 ? 0 : (uint32_t)(stream->position / stream->archive->block_size);
        base = stream->blocks == 1 ? 0 : (libmpq__off_t)block * stream->archive->block_size;
        result = stream_load_block(stream, block);
        if (result != LIBMPQ_SUCCESS) {
            if (transferred != NULL)
                *transferred = total;
            return result;
        }
        offset = stream->position - base;
        if (offset < 0 || offset > stream->block_size) {
            if (transferred != NULL)
                *transferred = total;
            return LIBMPQ_ERROR_READ;
        }
        available = stream->block_size - offset;
        if (available == 0) {
            if (transferred != NULL)
                *transferred = total;
            return LIBMPQ_ERROR_READ;
        }
        count = size - total;
        if (count > available)
            count = available;
        if (count > stream->size - stream->position)
            count = stream->size - stream->position;
        memcpy(buffer + total, stream->buffer + offset, (size_t)count);
        total += count;
        stream->position += count;
    }
    if (transferred != NULL)
        *transferred = total;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__reader_stream_seek(mpq_stream_s *stream, libmpq__off_t offset, int32_t origin)
{
    libmpq__off_t base;
    libmpq__off_t position;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (origin == LIBMPQ_SEEK_SET)
        base = 0;
    else if (origin == LIBMPQ_SEEK_CUR)
        base = stream->position;
    else if (origin == LIBMPQ_SEEK_END)
        base = stream->size;
    else
        return LIBMPQ_ERROR_SEEK;
    if ((offset > 0 && base > INT64_MAX - offset) || (offset < 0 && base < INT64_MIN - offset))
        return LIBMPQ_ERROR_SEEK;
    position = base + offset;
    if (position < 0 || position > stream->size)
        return LIBMPQ_ERROR_SEEK;
    stream->position = position;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__reader_stream_tell(mpq_stream_s *stream, libmpq__off_t *position)
{
    if (position != NULL)
        *position = 0;
    if (stream == NULL || position == NULL)
        return LIBMPQ_ERROR_EXIST;
    *position = stream->position;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__reader_stream_size(mpq_stream_s *stream, libmpq__off_t *size)
{
    if (size != NULL)
        *size = 0;
    if (stream == NULL || size == NULL)
        return LIBMPQ_ERROR_EXIST;
    *size = stream->size;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__reader_stream_close(mpq_stream_s *stream)
{
    int32_t result = LIBMPQ_SUCCESS;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    free(stream->buffer);
    free(stream->checksums);
    if (stream->offsets_acquired) {
        int32_t cleanup = libmpq__reader_offsets_release(stream->archive, stream->file_number);
        if (cleanup != LIBMPQ_SUCCESS)
            result = cleanup;
    }
    if (stream->archive != NULL) {
        int32_t cleanup = libmpq__archive_close(stream->archive);
        if (result == LIBMPQ_SUCCESS && cleanup != LIBMPQ_SUCCESS)
            result = cleanup;
    }
    free(stream);
    return result;
}
