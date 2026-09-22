/*
 *  mpq-stream.h -- private random-access archive stream declarations.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#ifndef LIBMPQ_STREAM_H
#define LIBMPQ_STREAM_H

#include <libmpq/mpq.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "mpq-mpqe.h"

typedef struct mpq_stream mpq_stream_s;

typedef int32_t (*mpq_io_read_at_fn)(void *, uint64_t, uint8_t *, size_t);
typedef int32_t (*mpq_io_identity_fn)(void *, uint64_t *, uint64_t *);
typedef int32_t (*mpq_io_close_fn)(void *);
typedef void (*mpq_io_discard_fn)(void *);

/*
 * A private random-access byte source with explicit context ownership.
 * close and discard both consume context; close reports finalization errors,
 * while discard ignores them.
 */
typedef struct mpq_io_backend
{
    void *context;
    uint64_t size;
    mpq_io_read_at_fn read_at;
    mpq_io_identity_fn identity;
    mpq_io_close_fn close;
    mpq_io_discard_fn discard;
} mpq_io_backend_s;

/* Logical archive bytes optionally transformed from an underlying backend. */
struct mpq_stream
{
    mpq_io_backend_s backend;
    uint64_t size;
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    uint8_t mpqe;
    uint8_t allocated;
};

int32_t libmpq__stream_open_file(mpq_stream_s **stream, const char *path);

/* Borrow a finalized writer FILE for bounded read-at operations; do not close. */
int32_t libmpq__stream_borrow_file(mpq_stream_s *stream, FILE *file, uint64_t size);
int32_t libmpq__stream_open_mpqe(
    mpq_stream_s **stream, const char *path, const uint8_t *auth_code, size_t auth_code_size
);
int32_t libmpq__stream_clone(mpq_stream_s **stream, const mpq_stream_s *source, const char *path);
int32_t libmpq__stream_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size);
uint64_t libmpq__stream_size(const mpq_stream_s *stream);
int32_t libmpq__stream_is_mpqe(const mpq_stream_s *stream);
int32_t libmpq__stream_file_identity(const mpq_stream_s *stream, uint64_t *device, uint64_t *inode);

/* Close consumes stream even when it returns an error. */
int32_t libmpq__stream_close(mpq_stream_s *stream);

/* Discard consumes stream and ignores backend finalization errors. */
void libmpq__stream_discard(mpq_stream_s *stream);

#endif /* LIBMPQ_STREAM_H */
