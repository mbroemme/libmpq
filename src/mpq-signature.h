/*
 *  mpq-signature.h -- private weak archive signature declarations.
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

#ifndef LIBMPQ_SIGNATURE_H
#define LIBMPQ_SIGNATURE_H

#include <libmpq/mpq.h>

#include "mpq-rsa.h"

#define LIBMPQ_SIGNATURE_PREFIX_SIZE 8u
#define LIBMPQ_SIGNATURE_SIZE (LIBMPQ_SIGNATURE_PREFIX_SIZE + LIBMPQ_RSA_SIZE)
int32_t libmpq__signature_detect(mpq_archive_s *archive, uint32_t *signatures);
int32_t libmpq__signature_verify(
    mpq_archive_s *archive, uint32_t flags, const uint8_t *key, size_t key_size,
    uint32_t *mismatches
);
int32_t libmpq__signature_configure(
    mpq_archive_s *archive, uint32_t type, const uint8_t *key, size_t key_size
);
int32_t libmpq__signature_finish(mpq_archive_s *archive, uint64_t size);
#endif /* LIBMPQ_SIGNATURE_H */
