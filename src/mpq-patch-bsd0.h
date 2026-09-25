/*
 *  mpq-patch-bsd0.h -- private BSD0 patch generation declarations.
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

#ifndef LIBMPQ_MPQ_PATCH_BSD0_H
#define LIBMPQ_MPQ_PATCH_BSD0_H

#include <libmpq/mpq.h>

int32_t libmpq__patch_bsd0_encode(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    uint8_t splice, uint8_t **encoded, size_t *encoded_size, size_t *patch_stream_size
);

#endif /* LIBMPQ_MPQ_PATCH_BSD0_H */
