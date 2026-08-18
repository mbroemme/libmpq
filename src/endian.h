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

/* MPQ stores all multi-byte integers in little-endian byte order.
 * These helpers operate on byte arrays rather than host objects so serialized
 * archive data remains correct on both little- and big-endian machines. */

/* Load a 16-bit little-endian value from an unaligned byte buffer.
 * The result is assembled explicitly and therefore does not depend on host
 * alignment or native byte order. */
static inline uint16_t
libmpq__load_le16(const uint8_t *buffer)
{
    if (buffer == 0)
        return 0;
    return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

/* Load a 32-bit little-endian value from an unaligned byte buffer.
 * Each byte is widened before shifting so the operation has defined width. */
static inline uint32_t
libmpq__load_le32(const uint8_t *buffer)
{
    if (buffer == 0)
        return 0;
    return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

/* Load a 64-bit little-endian value from two serialized 32-bit halves.
 * The low half is read first and the high half is shifted into its final
 * position without relying on a native 64-bit object layout. */
static inline uint64_t
libmpq__load_le64(const uint8_t *buffer)
{
    if (buffer == 0)
        return 0;
    return (uint64_t)libmpq__load_le32(buffer) | ((uint64_t)libmpq__load_le32(buffer + 4) << 32);
}

/* Store a 16-bit value in little-endian byte order.
 * Writing individual bytes makes the helper safe for packed and unaligned
 * archive fields. */
static inline void
libmpq__store_le16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
}

/* Store a 32-bit value in little-endian byte order.
 * The output is always four serialized bytes regardless of host endianness. */
static inline void
libmpq__store_le32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
    buffer[2] = (uint8_t)(value >> 16);
    buffer[3] = (uint8_t)(value >> 24);
}

/* Store a 64-bit value as two little-endian 32-bit halves.
 * This matches the MPQ v2 high-offset representation and avoids struct
 * padding or native byte-order assumptions. */
static inline void
libmpq__store_le64(uint8_t *buffer, uint64_t value)
{
    libmpq__store_le32(buffer, (uint32_t)value);
    libmpq__store_le32(buffer + 4, (uint32_t)(value >> 32));
}

#endif /* LIBMPQ_ENDIAN_H */
