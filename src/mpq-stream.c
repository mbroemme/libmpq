/*
 *  mpq-stream.c -- private random-access archive stream implementations.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpq-file.h"
#include "mpq-internal.h"
#include "mpq-mpqe.h"
#include "mpq-stream.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define LIBMPQ_MPQE_READ_BUFFER_SIZE (LIBMPQ_MPQE_CHUNK_SIZE * 64U)

static int32_t read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size);

/* Seek through the project offset type without narrowing large file positions. */
static int32_t
libmpq__stream_file_seek(mpq_stream_s *stream, uint64_t offset)
{
    return libmpq__file_seek(stream->file, offset, SEEK_SET);
}

/* Read an exact physical byte range from the underlying ordinary file. */
static int32_t
libmpq__stream_file_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (offset > stream->size || size > stream->size - offset)
        return LIBMPQ_ERROR_READ;
    if (size == 0)
        return LIBMPQ_SUCCESS;
    if (libmpq__stream_file_seek(stream, offset) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_SEEK;
    if (fread(buffer, 1, size, stream->file) != size)
        return LIBMPQ_ERROR_READ;
    return LIBMPQ_SUCCESS;
}

/* Open a backing file and capture its immutable size for range validation. */
static int32_t
libmpq__stream_open_common(mpq_stream_s **stream, const char *path)
{
    libmpq__off_t end;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (path == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = calloc(1, sizeof(**stream));
    if (*stream == NULL)
        return LIBMPQ_ERROR_MALLOC;
    (*stream)->file = libmpq__file_open(path, "rb");
    if ((*stream)->file == NULL) {
        free(*stream);
        *stream = NULL;
        return errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
    }
    if (libmpq__file_seek((*stream)->file, (libmpq__off_t)0, SEEK_END) < 0 ||
        (end = (libmpq__off_t)libmpq__file_tell((*stream)->file)) < 0) {
        fclose((*stream)->file);
        free(*stream);
        *stream = NULL;
        return LIBMPQ_ERROR_SEEK;
    }
    (*stream)->size = (uint64_t)end;
    (*stream)->read_at = read_at;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__stream_open_file(mpq_stream_s **stream, const char *path)
{
    int32_t result = libmpq__stream_open_common(stream, path);

    if (result == LIBMPQ_SUCCESS)
        (*stream)->provider = LIBMPQ_STREAM_FILE;
    return result;
}

int32_t
libmpq__stream_open_mpqe(
    mpq_stream_s **stream, const char *path, const uint8_t *auth_code, size_t auth_code_size
)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    result = libmpq__mpqe_key(key, auth_code, auth_code_size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__stream_open_common(stream, path);
    if (result != LIBMPQ_SUCCESS) {
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    (*stream)->provider = LIBMPQ_STREAM_MPQE;
    memcpy((*stream)->key, key, sizeof(key));
    libmpq__mpqe_clear(key, sizeof(key));
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__stream_clone(mpq_stream_s **stream, const mpq_stream_s *source, const char *path)
{
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__stream_open_common(stream, path);

    if (result != LIBMPQ_SUCCESS)
        return result;
    (*stream)->provider = source->provider;
    if (source->provider == LIBMPQ_STREAM_MPQE)
        memcpy((*stream)->key, source->key, sizeof((*stream)->key));
    return LIBMPQ_SUCCESS;
}

static int32_t
read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    size_t copied = 0;

    if (stream == NULL || (buffer == NULL && size != 0))
        return LIBMPQ_ERROR_EXIST;
    if (offset > stream->size || size > stream->size - offset)
        return LIBMPQ_ERROR_READ;
    if (stream->provider == LIBMPQ_STREAM_FILE)
        return libmpq__stream_file_read_at(stream, offset, buffer, size);
    while (copied < size) {
        uint64_t request_offset = offset + copied;
        uint64_t chunk_offset = request_offset & ~(uint64_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);
        uint8_t chunks[LIBMPQ_MPQE_READ_BUFFER_SIZE] = { 0 };
        uint64_t remaining = stream->size - chunk_offset;
        uint64_t request_end = offset + size;
        uint64_t required = request_end - chunk_offset;
        uint64_t rounded_required;
        uint64_t physical_u64;
        size_t physical;
        size_t decrypt_size;
        size_t batch_start = (size_t)(request_offset - chunk_offset);
        size_t available;
        size_t chunk;
        int32_t result;

        if (required > UINT64_MAX - (LIBMPQ_MPQE_CHUNK_SIZE - 1U)) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_SIZE;
        }
        rounded_required =
            (required + (LIBMPQ_MPQE_CHUNK_SIZE - 1U)) & ~(uint64_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);
        if (rounded_required > sizeof(chunks))
            rounded_required = sizeof(chunks);
        physical_u64 = remaining < rounded_required ? remaining : rounded_required;
        if (physical_u64 > sizeof(chunks)) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_SIZE;
        }
        physical = (size_t)physical_u64;
        decrypt_size =
            (physical + (LIBMPQ_MPQE_CHUNK_SIZE - 1U)) & ~(size_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);

        if (chunk_offset >= stream->size || physical <= batch_start) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_READ;
        }
        result = libmpq__stream_file_read_at(stream, chunk_offset, chunks, physical);
        if (result != LIBMPQ_SUCCESS) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return result;
        }
        for (chunk = 0; chunk < decrypt_size; chunk += LIBMPQ_MPQE_CHUNK_SIZE) {
            libmpq__mpqe_transform_chunk(
                chunks + chunk, stream->key, chunk_offset + (uint64_t)chunk
            );
        }
        available = physical - batch_start;
        if (available > size - copied)
            available = size - copied;
        memcpy(buffer + copied, chunks + batch_start, available);
        copied += available;
        libmpq__mpqe_clear(chunks, sizeof(chunks));
    }
    return LIBMPQ_SUCCESS;
}

/* Dispatch through the private stream operation; no global fault state. */
int32_t
libmpq__stream_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    return stream->read_at(stream, offset, buffer, size);
}

uint64_t
libmpq__stream_size(const mpq_stream_s *stream)
{
    return stream == NULL ? 0 : stream->size;
}

int32_t
libmpq__stream_close(mpq_stream_s *stream)
{
    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (stream->file != NULL && fclose(stream->file) != 0)
        return LIBMPQ_ERROR_CLOSE;
    libmpq__mpqe_clear(stream->key, sizeof(stream->key));
    free(stream);
    return LIBMPQ_SUCCESS;
}

void
libmpq__stream_discard(mpq_stream_s *stream)
{
    if (stream == NULL)
        return;
    if (stream->file != NULL)
        (void)fclose(stream->file);
    libmpq__mpqe_clear(stream->key, sizeof(stream->key));
    free(stream);
}
