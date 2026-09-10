/*
 *  mpq-md5.h -- internal MD5 checksum declarations.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
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

#ifndef LIBMPQ_MD5_H
#define LIBMPQ_MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t state[4];
    uint64_t size;
    uint8_t buffer[64];
} mpq_md5_s;

void libmpq__md5_init(mpq_md5_s *context);
void libmpq__md5_update(mpq_md5_s *context, const uint8_t *data, size_t size);
void libmpq__md5_final(mpq_md5_s *context, uint8_t digest[16]);

#endif /* LIBMPQ_MD5_H */
