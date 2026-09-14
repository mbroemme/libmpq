/*
 *  mpq-mpqe.h -- private MPQE cryptographic helper declarations.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#ifndef LIBMPQ_MPQE_H
#define LIBMPQ_MPQE_H

#include <libmpq/mpq.h>

#include <stddef.h>
#include <stdint.h>

#define LIBMPQ_MPQE_CHUNK_SIZE 64U
#define LIBMPQ_MPQE_AUTH_CODE_MINIMUM 32U

int32_t libmpq__mpqe_key(
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t *auth_code, size_t auth_code_size
);
void libmpq__mpqe_transform_chunk(
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE],
    uint64_t offset
);
void libmpq__mpqe_clear(void *buffer, size_t size);

#endif /* LIBMPQ_MPQE_H */
