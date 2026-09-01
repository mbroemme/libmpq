/*
 *  fuzz-codec-decode.c -- Focused bounded decoder target for one MPQ codec.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#include "mpq-compression.h"

#include <stdint.h>
#include <stdlib.h>

#define LIBMPQ_FUZZ_CODEC_FRAME_SIZE 2U
#define LIBMPQ_FUZZ_CODEC_MAX_OUTPUT 65536U

#ifndef LIBMPQ_FUZZ_CODEC
#error "LIBMPQ_FUZZ_CODEC must select one focused decoder"
#endif

/* Decode one codec-specific framed payload with a bounded output allocation. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint32_t output_size;
    uint8_t *output;

    if (size < LIBMPQ_FUZZ_CODEC_FRAME_SIZE) {
        return 0;
    }

    output_size = 1U + (uint32_t)data[0] + ((uint32_t)data[1] << 8);
    if (output_size > LIBMPQ_FUZZ_CODEC_MAX_OUTPUT) {
        return 0;
    }

    output = malloc(output_size);
    if (output == NULL) {
        return 0;
    }

#if LIBMPQ_FUZZ_CODEC == LIBMPQ_COMPRESSION_PKZIP
    (void)libmpq__compression_decompress_pkzip(
        (uint8_t *)(data + LIBMPQ_FUZZ_CODEC_FRAME_SIZE),
        (uint32_t)(size - LIBMPQ_FUZZ_CODEC_FRAME_SIZE), output, output_size
    );
#elif LIBMPQ_FUZZ_CODEC == LIBMPQ_COMPRESSION_HUFFMAN
    (void)libmpq__compression_decompress_huffman(
        (uint8_t *)(data + LIBMPQ_FUZZ_CODEC_FRAME_SIZE),
        (uint32_t)(size - LIBMPQ_FUZZ_CODEC_FRAME_SIZE), output, output_size
    );
#elif LIBMPQ_FUZZ_CODEC == LIBMPQ_COMPRESSION_ZLIB
    (void)libmpq__compression_decompress_zlib(
        (uint8_t *)(data + LIBMPQ_FUZZ_CODEC_FRAME_SIZE),
        (uint32_t)(size - LIBMPQ_FUZZ_CODEC_FRAME_SIZE), output, output_size
    );
#elif LIBMPQ_FUZZ_CODEC == LIBMPQ_COMPRESSION_BZIP2
    (void)libmpq__compression_decompress_bzip2(
        (uint8_t *)(data + LIBMPQ_FUZZ_CODEC_FRAME_SIZE),
        (uint32_t)(size - LIBMPQ_FUZZ_CODEC_FRAME_SIZE), output, output_size
    );
#else
#error "Unsupported focused codec"
#endif

    free(output);
    return 0;
}
