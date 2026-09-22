/*
 *  mpq-sparse.c -- Bounded MPQ zero-run compression and decompression.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#include "mpq-sparse.h"
#include "mpq-endian.h"
#include <libmpq/mpq.h>

#include <string.h>

/* SPARSE lengths are big-endian, unlike MPQ header and table fields. */
int32_t
libmpq__sparse_compress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
{
    uint32_t input = 0;
    uint32_t output = 4;

    if (in_buf == NULL || out_buf == NULL || in_size == 0 || in_size > INT32_MAX || out_size < 4)
        return LIBMPQ_ERROR_UNPACK;
    if (out_size > INT32_MAX)
        out_size = INT32_MAX;
    libmpq__store_be32(out_buf, in_size);
    while (input < in_size) {
        uint32_t count = 0;
        uint32_t start = input;

        /* A token represents 3..130 zeros; shorter runs remain literal data. */
        while (count < 130 && count < in_size - input && in_buf[input + count] == 0)
            count++;
        if (count >= 3) {
            if (output == out_size)
                return LIBMPQ_ERROR_UNPACK;
            out_buf[output++] = (uint8_t)(count - 3);
            input += count;
        } else {

            /* Stop literals before the next zero run or after 128 bytes. */
            do {
                input++;
                if (in_size - input >= 3 && in_buf[input] == 0 && in_buf[input + 1] == 0 &&
                    in_buf[input + 2] == 0)
                    break;
            } while (input < in_size && input - start < 128);
            count = input - start;
            if (output == out_size || count > out_size - output - 1)
                return LIBMPQ_ERROR_UNPACK;
            out_buf[output++] = (uint8_t)(0x80U | (count - 1));
            memcpy(out_buf + output, in_buf + start, count);
            output += count;
        }
    }
    return (int32_t)output;
}

/* Accept clipped terminal runs, but never accept missing output or input bytes. */
int32_t
libmpq__sparse_decompress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
{
    uint32_t input = 4;
    uint32_t output = 0;
    uint32_t length;

    if (in_buf == NULL || out_buf == NULL || in_size < 5)
        return LIBMPQ_ERROR_UNPACK;
    length = libmpq__load_be32(in_buf);
    if (length == 0 || length > out_size || length > INT32_MAX)
        return LIBMPQ_ERROR_UNPACK;
    while (input < in_size && output < length) {
        uint8_t token = in_buf[input++];
        uint32_t count = (uint32_t)(token & 0x7fU) + ((token & 0x80U) ? 1U : 3U);

        /*
         * Accept the short terminal literal form emitted by Storm-style compressors,
         * even when the token nominally describes more bytes than remain in the
         * declared output. The required literal bytes must be physically present.
         */
        if (count > length - output)
            count = length - output;
        if (token & 0x80U) {
            if (count > in_size - input)
                return LIBMPQ_ERROR_UNPACK;
            memcpy(out_buf + output, in_buf + input, count);
            input += count;
        } else {
            memset(out_buf + output, 0, count);
        }
        output += count;
    }
    if (input != in_size || output != length)
        return LIBMPQ_ERROR_UNPACK;
    return (int32_t)output;
}
