/*
 *  mpq-endian.c -- little-endian serialization helpers for MPQ data.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#include "mpq-endian.h"

#include <stddef.h>

/* Load a 16-bit little-endian value without alignment or host-byte-order assumptions. */
uint16_t
libmpq__load_le16(const uint8_t *buffer)
{
    if (buffer == NULL)
        return 0;
    return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

/* Load a 32-bit little-endian value from four serialized bytes. */
uint32_t
libmpq__load_le32(const uint8_t *buffer)
{
    if (buffer == NULL)
        return 0;
    return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

/* Load a 64-bit value from two serialized little-endian 32-bit halves. */
uint64_t
libmpq__load_le64(const uint8_t *buffer)
{
    if (buffer == NULL)
        return 0;
    return (uint64_t)libmpq__load_le32(buffer) | ((uint64_t)libmpq__load_le32(buffer + 4) << 32);
}

/* Store a 16-bit value as two little-endian bytes. */
void
libmpq__store_le16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
}

/* Store a 32-bit value as four little-endian bytes. */
void
libmpq__store_le32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
    buffer[2] = (uint8_t)(value >> 16);
    buffer[3] = (uint8_t)(value >> 24);
}

/* Store a 64-bit value as two little-endian 32-bit halves. */
void
libmpq__store_le64(uint8_t *buffer, uint64_t value)
{
    libmpq__store_le32(buffer, (uint32_t)value);
    libmpq__store_le32(buffer + 4, (uint32_t)(value >> 32));
}
