/*
 *  mpq-source.c -- private random-access archive source implementations.
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
#include "mpq-source.h"

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
source_set_file_backend(mpq_source_s *source, FILE *file, uint64_t size, uint8_t owned)
{
    mpq_file_backend_s *backend;

    if (source == NULL || file == NULL)
        return LIBMPQ_ERROR_EXIST;
    backend = calloc(1, sizeof(*backend));
    if (backend == NULL)
        return LIBMPQ_ERROR_MALLOC;
    backend->file = file;
    backend->size = size;
    backend->owned = owned;
    source->backend.context = backend;
    source->backend.size = size;
    source->backend.read_at = file_backend_read_at;
    source->backend.identity = file_backend_identity;
    source->backend.close = file_backend_close;
    source->backend.discard = file_backend_discard;
    source->size = size;
    return LIBMPQ_SUCCESS;
}

static int32_t
source_set_custom_backend(
    mpq_source_s *source, void *context, libmpq_io_read_at_fn read_at, uint64_t size
)
{
    mpq_custom_backend_s *backend;

    if (source == NULL || read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    backend = malloc(sizeof(*backend));
    if (backend == NULL)
        return LIBMPQ_ERROR_MALLOC;
    backend->context = context;
    backend->read_at = read_at;
    backend->size = size;
    source->backend.context = backend;
    source->backend.size = size;
    source->backend.read_at = custom_backend_read_at;
    source->backend.close = custom_backend_close;
    source->backend.discard = custom_backend_discard;
    source->backend.clone = custom_backend_clone;
    source->size = size;
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
libmpq__source_open_common(mpq_source_s **source, const char *path)
{
    libmpq__off_t end;
    FILE *file;
    int32_t result;

    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    *source = NULL;
    if (path == NULL)
        return LIBMPQ_ERROR_EXIST;
    *source = calloc(1, sizeof(**source));
    if (*source == NULL)
        return LIBMPQ_ERROR_MALLOC;
    (*source)->allocated = 1;
    file = libmpq__file_open(path, "rb");
    if (file == NULL) {
        free(*source);
        *source = NULL;
        return errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
    }
    if (libmpq__file_seek(file, (libmpq__off_t)0, SEEK_END) < 0 ||
        (end = (libmpq__off_t)libmpq__file_tell(file)) < 0) {
        fclose(file);
        free(*source);
        *source = NULL;
        return LIBMPQ_ERROR_SEEK;
    }
    result = source_set_file_backend(*source, file, (uint64_t)end, 1);
    if (result != LIBMPQ_SUCCESS) {
        fclose(file);
        free(*source);
        *source = NULL;
    }
    return result;
}

/* Adapt a writer's flushed FILE without taking ownership or reopening its path. */
int32_t
libmpq__source_borrow_file(mpq_source_s *source, FILE *file, uint64_t size)
{
    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    memset(source, 0, sizeof(*source));
    return source_set_file_backend(source, file, size, 0);
}

int32_t
libmpq__source_open_file(mpq_source_s **source, const char *path)
{
    return libmpq__source_open_common(source, path);
}

int32_t
libmpq__source_open_io(
    mpq_source_s **source, void *context, libmpq_io_read_at_fn read_at, uint64_t size
)
{
    int32_t result;

    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    *source = NULL;
    if (read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    *source = calloc(1, sizeof(**source));
    if (*source == NULL)
        return LIBMPQ_ERROR_MALLOC;
    (*source)->allocated = 1;
    result = source_set_custom_backend(*source, context, read_at, size);
    if (result != LIBMPQ_SUCCESS) {
        free(*source);
        *source = NULL;
    }
    return result;
}

int32_t
libmpq__source_open_mpqe(
    mpq_source_s **source, const char *path, const uint8_t *auth_code, size_t auth_code_size
)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    int32_t result;

    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    *source = NULL;
    result = libmpq__mpqe_key(key, auth_code, auth_code_size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__source_open_common(source, path);
    if (result != LIBMPQ_SUCCESS) {
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    (*source)->mpqe = 1;
    memcpy((*source)->key, key, sizeof(key));
    libmpq__mpqe_clear(key, sizeof(key));
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__source_open_mpqe_io(
    mpq_source_s **source, void *context, libmpq_io_read_at_fn read_at, uint64_t size,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    int32_t result;

    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    *source = NULL;
    result = libmpq__mpqe_key(key, auth_code, auth_code_size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__source_open_io(source, context, read_at, size);
    if (result != LIBMPQ_SUCCESS) {
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    (*source)->mpqe = 1;
    memcpy((*source)->key, key, sizeof(key));
    libmpq__mpqe_clear(key, sizeof(key));
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__source_clone(mpq_source_s **clone, const mpq_source_s *source, const char *path)
{
    int32_t result;

    if (clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    *clone = NULL;
    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (source->backend.clone != NULL) {
        *clone = calloc(1, sizeof(**clone));
        if (*clone == NULL)
            return LIBMPQ_ERROR_MALLOC;
        (*clone)->allocated = 1;
        result = source->backend.clone(source->backend.context, &(*clone)->backend);
    } else {
        if (path == NULL)
            return LIBMPQ_ERROR_EXIST;
        result = libmpq__source_open_common(clone, path);
    }

    if (result != LIBMPQ_SUCCESS) {
        libmpq__source_discard(*clone);
        *clone = NULL;
        return result;
    }
    if (source->backend.clone != NULL)
        (*clone)->size = (*clone)->backend.size;
    (*clone)->mpqe = source->mpqe;
    if (source->mpqe)
        memcpy((*clone)->key, source->key, sizeof((*clone)->key));
    return LIBMPQ_SUCCESS;
}

static int32_t
source_mpqe_read_at(mpq_source_s *source, uint64_t offset, uint8_t *buffer, size_t size)
{
    size_t copied = 0;

    while (copied < size) {
        uint64_t request_offset = offset + copied;
        uint64_t chunk_offset = request_offset & ~(uint64_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);
        uint8_t chunks[LIBMPQ_MPQE_READ_BUFFER_SIZE] = { 0 };
        uint64_t remaining = source->size - chunk_offset;
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

        if (chunk_offset >= source->size || physical <= batch_start) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_READ;
        }
        result = backend_read_at(&source->backend, chunk_offset, chunks, physical);
        if (result != LIBMPQ_SUCCESS) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return result;
        }
        for (chunk = 0; chunk < decrypt_size; chunk += LIBMPQ_MPQE_CHUNK_SIZE) {
            libmpq__mpqe_transform_chunk(
                chunks + chunk, source->key, chunk_offset + (uint64_t)chunk
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
libmpq__source_read_at(mpq_source_s *source, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (source == NULL || (buffer == NULL && size != 0) || source->backend.read_at == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (offset > source->size || size > source->size - offset)
        return LIBMPQ_ERROR_READ;
    if (size == 0)
        return LIBMPQ_SUCCESS;
    if (source->mpqe)
        return source_mpqe_read_at(source, offset, buffer, size);
    return backend_read_at(&source->backend, offset, buffer, size);
}

uint64_t
libmpq__source_size(const mpq_source_s *source)
{
    return source == NULL ? 0 : source->size;
}

int32_t
libmpq__source_is_mpqe(const mpq_source_s *source)
{
    return source != NULL && source->mpqe;
}

int32_t
libmpq__source_file_identity(const mpq_source_s *source, uint64_t *device, uint64_t *inode)
{
    if (device != NULL)
        *device = 0;
    if (inode != NULL)
        *inode = 0;
    if (source == NULL || device == NULL || inode == NULL || source->backend.identity == NULL ||
        source->backend.context == NULL)
        return LIBMPQ_ERROR_EXIST;
    return source->backend.identity(source->backend.context, device, inode);
}

int32_t
libmpq__source_close(mpq_source_s *source)
{
    int32_t result;

    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = source->backend.close == NULL ? LIBMPQ_SUCCESS
                                           : source->backend.close(source->backend.context);
    libmpq__mpqe_clear(source->key, sizeof(source->key));
    if (source->allocated)
        free(source);
    return result;
}

void
libmpq__source_discard(mpq_source_s *source)
{
    if (source == NULL)
        return;
    if (source->backend.discard != NULL)
        source->backend.discard(source->backend.context);
    else if (source->backend.close != NULL)
        (void)source->backend.close(source->backend.context);
    libmpq__mpqe_clear(source->key, sizeof(source->key));
    if (source->allocated)
        free(source);
}
