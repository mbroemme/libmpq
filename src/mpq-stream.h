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

typedef struct mpq_stream mpq_stream_s;

#define LIBMPQ_MPQE_CHUNK_SIZE 64U
#define LIBMPQ_MPQE_AUTH_CODE_MINIMUM 32U

int32_t libmpq__stream_open_file(mpq_stream_s **stream, const char *path);
int32_t libmpq__stream_open_mpqe(
    mpq_stream_s **stream, const char *path, const uint8_t *authentication_code,
    size_t authentication_code_size
);
int32_t libmpq__stream_clone(mpq_stream_s **stream, const mpq_stream_s *source, const char *path);
int32_t libmpq__stream_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size);
uint64_t libmpq__stream_size(const mpq_stream_s *stream);
int32_t libmpq__stream_close(mpq_stream_s *stream);
void libmpq__stream_discard(mpq_stream_s *stream);

int32_t libmpq__mpqe_key(
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t *authentication_code,
    size_t authentication_code_size
);
void libmpq__mpqe_transform_chunk(
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE],
    uint64_t offset
);
void libmpq__mpqe_clear(void *buffer, size_t size);

#ifdef LIBMPQ_TESTING
void libmpq__stream_mpqe_test_transform_chunk(
    uint8_t chunk[64], const uint8_t *authentication_code, uint64_t offset
);
#endif

#endif /* LIBMPQ_STREAM_H */
