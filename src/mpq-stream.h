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

typedef enum
{
    LIBMPQ_STREAM_FILE,
    LIBMPQ_STREAM_MPQE
} libmpq_stream_provider_e;

typedef int32_t (*mpq_stream_read_at_fn)(mpq_stream_s *, uint64_t, uint8_t *, size_t);

/*
 * Private per-stream dispatch. The context is borrowed, not copied to clones.
 * Normal streams use the built-in reader and no context.
 */
struct mpq_stream
{
    FILE *file;
    uint64_t size;
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    libmpq_stream_provider_e provider;
    mpq_stream_read_at_fn read_at;
    void *read_context;
};

int32_t libmpq__stream_open_file(mpq_stream_s **stream, const char *path);

/* Borrow a finalized writer FILE for bounded read-at operations; do not close. */
void libmpq__stream_borrow_file(mpq_stream_s *stream, FILE *file, uint64_t size);
int32_t libmpq__stream_open_mpqe(
    mpq_stream_s **stream, const char *path, const uint8_t *auth_code, size_t auth_code_size
);
int32_t libmpq__stream_clone(mpq_stream_s **stream, const mpq_stream_s *source, const char *path);
int32_t libmpq__stream_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size);
uint64_t libmpq__stream_size(const mpq_stream_s *stream);
int32_t libmpq__stream_close(mpq_stream_s *stream);
void libmpq__stream_discard(mpq_stream_s *stream);

#endif /* LIBMPQ_STREAM_H */
