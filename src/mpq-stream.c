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

typedef struct
{
    FILE *file;
    uint64_t size;
    uint8_t owned;
} mpq_file_backend_s;

typedef struct
{
    void *context;
    libmpq_io_read_at_fn read_at;
    uint64_t size;
} mpq_custom_backend_s;

/* Seek through the project offset type without narrowing large file positions. */
static int32_t
file_backend_seek(mpq_file_backend_s *backend, uint64_t offset)
{
    return libmpq__file_seek(backend->file, offset, SEEK_SET);
}

/* Read an exact physical byte range from an ordinary filesystem backend. */
static int32_t
file_backend_read_at(void *context, uint64_t offset, uint8_t *buffer, size_t size)
{
    mpq_file_backend_s *backend = context;

    if (backend == NULL || (buffer == NULL && size != 0))
        return LIBMPQ_ERROR_EXIST;
    if (offset > backend->size || size > backend->size - offset)
        return LIBMPQ_ERROR_READ;
    if (size == 0)
        return LIBMPQ_SUCCESS;
    if (file_backend_seek(backend, offset) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_SEEK;
    if (fread(buffer, 1, size, backend->file) != size)
        return LIBMPQ_ERROR_READ;
    return LIBMPQ_SUCCESS;
}

static int32_t
file_backend_close(void *context)
{
    mpq_file_backend_s *backend = context;
    int32_t result = LIBMPQ_SUCCESS;

    if (backend == NULL)
        return LIBMPQ_SUCCESS;
    if (backend->owned && backend->file != NULL && fclose(backend->file) != 0)
        result = LIBMPQ_ERROR_CLOSE;
    free(backend);
    return result;
}

static void
file_backend_discard(void *context)
{
    mpq_file_backend_s *backend = context;

    if (backend == NULL)
        return;
    if (backend->owned && backend->file != NULL)
        (void)fclose(backend->file);
    free(backend);
}

static int32_t
file_backend_identity(void *context, uint64_t *device, uint64_t *inode)
{
    mpq_file_backend_s *backend = context;

    if (backend == NULL)
        return LIBMPQ_ERROR_EXIST;
    return libmpq__file_identity(backend->file, device, inode);
}

static int32_t
custom_backend_read_at(void *context, uint64_t offset, uint8_t *buffer, size_t size)
{
    mpq_custom_backend_s *backend = context;
    int32_t result;

    if (backend == NULL || backend->read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (offset > INT64_MAX)
        return LIBMPQ_ERROR_READ;
    result = backend->read_at(backend->context, (libmpq__off_t)offset, buffer, size);
    return result > 0 ? LIBMPQ_ERROR_READ : result;
}

static int32_t
custom_backend_close(void *context)
{
    free(context);
    return LIBMPQ_SUCCESS;
}

static void
custom_backend_discard(void *context)
{
    free(context);
}

static int32_t
custom_backend_clone(void *context, mpq_io_backend_s *clone)
{
    mpq_custom_backend_s *source = context;
    mpq_custom_backend_s *backend;

    if (source == NULL || clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    backend = malloc(sizeof(*backend));
    if (backend == NULL)
        return LIBMPQ_ERROR_MALLOC;
    *backend = *source;
    memset(clone, 0, sizeof(*clone));
    clone->context = backend;
    clone->size = backend->size;
    clone->read_at = custom_backend_read_at;
    clone->close = custom_backend_close;
    clone->discard = custom_backend_discard;
    clone->clone = custom_backend_clone;
    return LIBMPQ_SUCCESS;
}

static int32_t
stream_set_file_backend(mpq_stream_s *stream, FILE *file, uint64_t size, uint8_t owned)
{
    mpq_file_backend_s *backend;

    if (stream == NULL || file == NULL)
        return LIBMPQ_ERROR_EXIST;
    backend = calloc(1, sizeof(*backend));
    if (backend == NULL)
        return LIBMPQ_ERROR_MALLOC;
    backend->file = file;
    backend->size = size;
    backend->owned = owned;
    stream->backend.context = backend;
    stream->backend.size = size;
    stream->backend.read_at = file_backend_read_at;
    stream->backend.identity = file_backend_identity;
    stream->backend.close = file_backend_close;
    stream->backend.discard = file_backend_discard;
    stream->size = size;
    return LIBMPQ_SUCCESS;
}

static int32_t
stream_set_custom_backend(
    mpq_stream_s *stream, void *context, libmpq_io_read_at_fn read_at, uint64_t size
)
{
    mpq_custom_backend_s *backend;

    if (stream == NULL || read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    backend = malloc(sizeof(*backend));
    if (backend == NULL)
        return LIBMPQ_ERROR_MALLOC;
    backend->context = context;
    backend->read_at = read_at;
    backend->size = size;
    stream->backend.context = backend;
    stream->backend.size = size;
    stream->backend.read_at = custom_backend_read_at;
    stream->backend.close = custom_backend_close;
    stream->backend.discard = custom_backend_discard;
    stream->backend.clone = custom_backend_clone;
    stream->size = size;
    return LIBMPQ_SUCCESS;
}

static int32_t
backend_read_at(const mpq_io_backend_s *backend, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (backend == NULL || (buffer == NULL && size != 0) || backend->read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (offset > backend->size || size > backend->size - offset)
        return LIBMPQ_ERROR_READ;
    if (size == 0)
        return LIBMPQ_SUCCESS;
    return backend->read_at(backend->context, offset, buffer, size);
}

/* Open a filesystem backend and capture its immutable size for range validation. */
static int32_t
libmpq__stream_open_common(mpq_stream_s **stream, const char *path)
{
    libmpq__off_t end;
    FILE *file;
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (path == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = calloc(1, sizeof(**stream));
    if (*stream == NULL)
        return LIBMPQ_ERROR_MALLOC;
    (*stream)->allocated = 1;
    file = libmpq__file_open(path, "rb");
    if (file == NULL) {
        free(*stream);
        *stream = NULL;
        return errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
    }
    if (libmpq__file_seek(file, (libmpq__off_t)0, SEEK_END) < 0 ||
        (end = (libmpq__off_t)libmpq__file_tell(file)) < 0) {
        fclose(file);
        free(*stream);
        *stream = NULL;
        return LIBMPQ_ERROR_SEEK;
    }
    result = stream_set_file_backend(*stream, file, (uint64_t)end, 1);
    if (result != LIBMPQ_SUCCESS) {
        fclose(file);
        free(*stream);
        *stream = NULL;
    }
    return result;
}

/* Adapt a writer's flushed FILE without taking ownership or reopening its path. */
int32_t
libmpq__stream_borrow_file(mpq_stream_s *stream, FILE *file, uint64_t size)
{
    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    memset(stream, 0, sizeof(*stream));
    return stream_set_file_backend(stream, file, size, 0);
}

int32_t
libmpq__stream_open_file(mpq_stream_s **stream, const char *path)
{
    return libmpq__stream_open_common(stream, path);
}

int32_t
libmpq__stream_open_io(
    mpq_stream_s **stream, void *context, libmpq_io_read_at_fn read_at, uint64_t size
)
{
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = calloc(1, sizeof(**stream));
    if (*stream == NULL)
        return LIBMPQ_ERROR_MALLOC;
    (*stream)->allocated = 1;
    result = stream_set_custom_backend(*stream, context, read_at, size);
    if (result != LIBMPQ_SUCCESS) {
        free(*stream);
        *stream = NULL;
    }
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
    (*stream)->mpqe = 1;
    memcpy((*stream)->key, key, sizeof(key));
    libmpq__mpqe_clear(key, sizeof(key));
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__stream_open_mpqe_io(
    mpq_stream_s **stream, void *context, libmpq_io_read_at_fn read_at, uint64_t size,
    const uint8_t *auth_code, size_t auth_code_size
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
    result = libmpq__stream_open_io(stream, context, read_at, size);
    if (result != LIBMPQ_SUCCESS) {
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    (*stream)->mpqe = 1;
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
    if (source->backend.clone != NULL) {
        *stream = calloc(1, sizeof(**stream));
        if (*stream == NULL)
            return LIBMPQ_ERROR_MALLOC;
        (*stream)->allocated = 1;
        result = source->backend.clone(source->backend.context, &(*stream)->backend);
    } else {
        if (path == NULL)
            return LIBMPQ_ERROR_EXIST;
        result = libmpq__stream_open_common(stream, path);
    }

    if (result != LIBMPQ_SUCCESS) {
        libmpq__stream_discard(*stream);
        *stream = NULL;
        return result;
    }
    if (source->backend.clone != NULL)
        (*stream)->size = (*stream)->backend.size;
    (*stream)->mpqe = source->mpqe;
    if (source->mpqe)
        memcpy((*stream)->key, source->key, sizeof((*stream)->key));
    return LIBMPQ_SUCCESS;
}

static int32_t
mpqe_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    size_t copied = 0;

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
        result = backend_read_at(&stream->backend, chunk_offset, chunks, physical);
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

int32_t
libmpq__stream_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (stream == NULL || (buffer == NULL && size != 0) || stream->backend.read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (offset > stream->size || size > stream->size - offset)
        return LIBMPQ_ERROR_READ;
    if (size == 0)
        return LIBMPQ_SUCCESS;
    if (stream->mpqe)
        return mpqe_read_at(stream, offset, buffer, size);
    return backend_read_at(&stream->backend, offset, buffer, size);
}

uint64_t
libmpq__stream_size(const mpq_stream_s *stream)
{
    return stream == NULL ? 0 : stream->size;
}

int32_t
libmpq__stream_is_mpqe(const mpq_stream_s *stream)
{
    return stream != NULL && stream->mpqe;
}

int32_t
libmpq__stream_file_identity(const mpq_stream_s *stream, uint64_t *device, uint64_t *inode)
{
    if (device != NULL)
        *device = 0;
    if (inode != NULL)
        *inode = 0;
    if (stream == NULL || device == NULL || inode == NULL || stream->backend.identity == NULL ||
        stream->backend.context == NULL)
        return LIBMPQ_ERROR_EXIST;
    return stream->backend.identity(stream->backend.context, device, inode);
}

int32_t
libmpq__stream_close(mpq_stream_s *stream)
{
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = stream->backend.close == NULL ? LIBMPQ_SUCCESS
                                           : stream->backend.close(stream->backend.context);
    libmpq__mpqe_clear(stream->key, sizeof(stream->key));
    if (stream->allocated)
        free(stream);
    return result;
}

void
libmpq__stream_discard(mpq_stream_s *stream)
{
    if (stream == NULL)
        return;
    if (stream->backend.discard != NULL)
        stream->backend.discard(stream->backend.context);
    else if (stream->backend.close != NULL)
        (void)stream->backend.close(stream->backend.context);
    libmpq__mpqe_clear(stream->key, sizeof(stream->key));
    if (stream->allocated)
        free(stream);
}
