/*
 *  fuzz-sector-decode.c -- Fuzz target for compressed MPQ sectors.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#include "mpq-compression.h"
#include "mpq-internal.h"

#include <stdint.h>
#include <stdlib.h>

#define LIBMPQ_FUZZ_SECTOR_HEADER_SIZE 3U
#define LIBMPQ_FUZZ_MAX_OUTPUT 65536U

/* Decode a framed sector: mode byte, little-endian output length, then payload. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint32_t output_size;
    uint32_t compression_type;
    uint8_t *output;

    if (size < LIBMPQ_FUZZ_SECTOR_HEADER_SIZE) {
        return 0;
    }

    output_size = 1U + (uint32_t)data[1] + ((uint32_t)data[2] << 8);
    if (output_size > LIBMPQ_FUZZ_MAX_OUTPUT) {
        return 0;
    }
    compression_type =
        (data[0] & 1U) != 0U ? LIBMPQ_FLAG_COMPRESS_PKZIP : LIBMPQ_FLAG_COMPRESS_MULTI;
    output = malloc(output_size);
    if (output == NULL) {
        return 0;
    }

    (void)libmpq__compression_decompress_block(
        (uint8_t *)(data + LIBMPQ_FUZZ_SECTOR_HEADER_SIZE),
        (uint32_t)(size - LIBMPQ_FUZZ_SECTOR_HEADER_SIZE), output, output_size, compression_type
    );
    free(output);

    return 0;
}
