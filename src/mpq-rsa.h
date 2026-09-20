/*
 *  mpq-rsa.h -- private fixed-width legacy RSA declarations.
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

#ifndef LIBMPQ_RSA_H
#define LIBMPQ_RSA_H

#include "mpq-md5.h"
#include <stddef.h>
#include <stdint.h>

#define LIBMPQ_RSA_SIZE 64u
#define LIBMPQ_RSA_KEY_SIZE (2u * LIBMPQ_RSA_SIZE)

int32_t libmpq__rsa_key_validate(const uint8_t *key, size_t size);
int32_t libmpq__rsa_operation(
    const uint8_t key[LIBMPQ_RSA_KEY_SIZE], const uint8_t input[LIBMPQ_RSA_SIZE],
    uint8_t output[LIBMPQ_RSA_SIZE]
);
void
libmpq__rsa_md5_encode(const uint8_t digest[LIBMPQ_MD5_SIZE], uint8_t encoded[LIBMPQ_RSA_SIZE]);
void libmpq__rsa_clear(void *data, size_t size);
#endif /* LIBMPQ_RSA_H */
