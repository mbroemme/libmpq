/*
 *  mpq-endian.h -- little-endian serialization helpers for MPQ data.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 */

#ifndef LIBMPQ_ENDIAN_H
#define LIBMPQ_ENDIAN_H

#include <stdint.h>

/*
 * MPQ stores all multi-byte integers in little-endian byte order. The
 * implementations operate on byte arrays rather than host objects, so
 * serialized archive data remains correct on little- and big-endian machines.
 * A NULL input buffer is rejected by the load helpers and yields zero; store
 * helpers require a valid writable buffer supplied by the caller.
 */

/* Load a 16-bit little-endian value from an unaligned byte buffer. */
uint16_t libmpq__load_le16(const uint8_t *buffer);

/* Load a 32-bit little-endian value from an unaligned byte buffer. */
uint32_t libmpq__load_le32(const uint8_t *buffer);

/* Load a 64-bit little-endian value from two serialized 32-bit halves. */
uint64_t libmpq__load_le64(const uint8_t *buffer);

/* Store a 16-bit value in little-endian byte order. */
void libmpq__store_le16(uint8_t *buffer, uint16_t value);

/* Store a 32-bit value in little-endian byte order. */
void libmpq__store_le32(uint8_t *buffer, uint32_t value);

/* Store a 64-bit value as two little-endian 32-bit halves. */
void libmpq__store_le64(uint8_t *buffer, uint64_t value);

#endif /* LIBMPQ_ENDIAN_H */
