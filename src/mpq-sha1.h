/*
 *  mpq-sha1.h -- private portable SHA-1 declarations.
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
#ifndef LIBMPQ_SHA1_H
#define LIBMPQ_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define LIBMPQ_SHA1_SIZE 20u

typedef struct mpq_sha1
{
    uint32_t state[5];
    uint64_t bits;
    uint8_t buffer[64];
    size_t used;
} mpq_sha1_s;

void libmpq__sha1_init(mpq_sha1_s *context);
void libmpq__sha1_update(mpq_sha1_s *context, const uint8_t *data, size_t size);
void libmpq__sha1_final(mpq_sha1_s *context, uint8_t digest[LIBMPQ_SHA1_SIZE]);

#endif /* LIBMPQ_SHA1_H */
