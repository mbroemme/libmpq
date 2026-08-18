/*
 *  endian.h -- little-endian serialization helpers for MPQ data.
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

/* MPQ stores all multi-byte integers in little-endian byte order. */
static inline uint16_t
libmpq__load_le16(const uint8_t *buffer)
{
    return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

static inline uint32_t
libmpq__load_le32(const uint8_t *buffer)
{
    return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

static inline uint64_t
libmpq__load_le64(const uint8_t *buffer)
{
    return (uint64_t)libmpq__load_le32(buffer) | ((uint64_t)libmpq__load_le32(buffer + 4) << 32);
}

static inline void
libmpq__store_le16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
}

static inline void
libmpq__store_le32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
    buffer[2] = (uint8_t)(value >> 16);
    buffer[3] = (uint8_t)(value >> 24);
}

static inline void
libmpq__store_le64(uint8_t *buffer, uint64_t value)
{
    libmpq__store_le32(buffer, (uint32_t)value);
    libmpq__store_le32(buffer + 4, (uint32_t)(value >> 32));
}

#endif /* LIBMPQ_ENDIAN_H */
