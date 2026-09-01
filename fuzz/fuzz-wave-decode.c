/*
 *  fuzz-wave-decode.c -- Focused bounded target for MPQ ADPCM WAVE decoding.
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

#define LIBMPQ_FUZZ_WAVE_FRAME_SIZE 3U
#define LIBMPQ_FUZZ_WAVE_MAX_OUTPUT 65536U

/* Decode a mono or stereo framed ADPCM payload with a bounded output buffer. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint32_t output_size;
    uint8_t *output;

    if (size < LIBMPQ_FUZZ_WAVE_FRAME_SIZE) {
        return 0;
    }

    output_size = 1U + (uint32_t)data[1] + ((uint32_t)data[2] << 8);
    if (output_size > LIBMPQ_FUZZ_WAVE_MAX_OUTPUT) {
        return 0;
    }

    output = malloc(output_size);
    if (output == NULL) {
        return 0;
    }

    if ((data[0] & 1U) == 0U) {
        (void)libmpq__compression_decompress_wave_mono(
            (uint8_t *)(data + LIBMPQ_FUZZ_WAVE_FRAME_SIZE),
            (uint32_t)(size - LIBMPQ_FUZZ_WAVE_FRAME_SIZE), output, output_size
        );
    } else {
        (void)libmpq__compression_decompress_wave_stereo(
            (uint8_t *)(data + LIBMPQ_FUZZ_WAVE_FRAME_SIZE),
            (uint32_t)(size - LIBMPQ_FUZZ_WAVE_FRAME_SIZE), output, output_size
        );
    }

    free(output);
    return 0;
}
