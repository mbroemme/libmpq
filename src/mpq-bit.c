/*
 *  mpq-bit.c -- Checked little-endian MPQ bit access.
 *
 *  Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This file is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this file; if not, see <https://www.gnu.org/licenses/>.
 */

#include "mpq-bit.h"
#include <libmpq/mpq.h>

/* Check a bit range without multiplying the supplied byte capacity by eight. */
static int32_t
bit_range(size_t size, uint64_t offset, uint32_t width)
{
    if (width > 64 || offset > UINT64_MAX - width)
        return LIBMPQ_ERROR_SIZE;
    if (width == 0)
        return offset / 8 > size || (offset / 8 == size && offset % 8 != 0) ? LIBMPQ_ERROR_SIZE : 0;
    return (offset + width - 1) / 8 < size ? 0 : LIBMPQ_ERROR_SIZE;
}

/* Read checked fields without unaligned access or host byte-order assumptions. */
int32_t
libmpq__bit_get(
    const uint8_t *buffer, size_t size, uint64_t offset, uint32_t width, uint64_t *value
)
{
    uint32_t i;

    if (value == NULL)
        return LIBMPQ_ERROR_SIZE;
    *value = 0;
    if (bit_range(size, offset, width) != 0 || (width != 0 && buffer == NULL))
        return LIBMPQ_ERROR_SIZE;
    for (i = 0; i < width; i++) {
        uint64_t bit = offset + i;

        *value |= (uint64_t)((buffer[(size_t)(bit / 8)] >> (bit % 8)) & 1u) << i;
    }
    return 0;
}

/* Update only the requested bits and reject values that would be truncated. */
int32_t
libmpq__bit_set(uint8_t *buffer, size_t size, uint64_t offset, uint32_t width, uint64_t value)
{
    uint32_t i;

    if (bit_range(size, offset, width) != 0 || (width != 0 && buffer == NULL) ||
        (width < 64 && (value >> width) != 0))
        return LIBMPQ_ERROR_SIZE;
    for (i = 0; i < width; i++) {
        uint64_t bit = offset + i;
        uint8_t mask = (uint8_t)(1u << (bit % 8));
        size_t byte = (size_t)(bit / 8);

        buffer[byte] =
            (uint8_t)((buffer[byte] & (uint8_t)~mask) | (((value >> i) & 1u) != 0 ? mask : 0));
    }
    return 0;
}

/* Calculate packed-array storage without overflowing multiplication or rounding. */
int32_t
libmpq__bit_bytes(uint64_t count, uint64_t width, size_t *size)
{
    uint64_t bits;
    uint64_t bytes;

    if (size == NULL)
        return LIBMPQ_ERROR_SIZE;
    *size = 0;
    if (width != 0 && count > UINT64_MAX / width)
        return LIBMPQ_ERROR_SIZE;
    bits = count * width;
    bytes = bits / 8 + (bits % 8 != 0);
    if (bytes > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    *size = (size_t)bytes;
    return 0;
}
