/*
 *  mpq-bit.h -- Private checked MPQ bit-access declarations.
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

#ifndef LIBMPQ_MPQ_BIT_H
#define LIBMPQ_MPQ_BIT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Private little-endian bit access: bit zero is the low bit of byte zero.
 * Widths are 0..64; zero-width writes require value zero. No allocation or
 * aliasing is retained. Failed reads reset value to zero.
 */
int32_t libmpq__bit_get(
    const uint8_t *buffer, size_t size, uint64_t offset, uint32_t width, uint64_t *value
);
int32_t
libmpq__bit_set(uint8_t *buffer, size_t size, uint64_t offset, uint32_t width, uint64_t value);

/* Checked ceil(count * width / 8), including conversion to size_t. */
int32_t libmpq__bit_bytes(uint64_t count, uint64_t width, size_t *size);

#endif
