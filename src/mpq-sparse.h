/*
 *  mpq-sparse.h -- Private MPQ SPARSE codec declarations.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#ifndef LIBMPQ_SPARSE_H
#define LIBMPQ_SPARSE_H

#include <stdint.h>

/*
 * Encode into caller-owned storage; return bytes written or a negative error.
 * Insufficient space returns UNPACK so the writer can retain the raw stage.
 */
int32_t libmpq__sparse_compress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/*
 * Decode the big-endian length and bounded token stream without allocating.
 * Return the declared byte count only after it has been fully reconstructed.
 */
int32_t libmpq__sparse_decompress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

#endif /* LIBMPQ_SPARSE_H */
