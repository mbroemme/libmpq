/*
 *  mpq-sha1.c -- private portable SHA-1 implementation.
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

#include "mpq-sha1.h"
#include <string.h>

static uint32_t
rotate_left(uint32_t value, unsigned int count)
{
    return (value << count) | (value >> (32u - count));
}

static void
transform(mpq_sha1_s *context, const uint8_t block[64])
{
    uint32_t words[80];
    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t e = context->state[4];
    size_t i;
    for (i = 0; i < 16; ++i)
        words[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (; i < 80; ++i)
        words[i] = rotate_left(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    for (i = 0; i < 80; ++i) {
        uint32_t f;
        uint32_t k;
        uint32_t next;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        next = rotate_left(a, 5) + f + e + k + words[i];
        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = next;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    memset(words, 0, sizeof(words));
}

void
libmpq__sha1_init(mpq_sha1_s *context)
{
    context->state[0] = 0x67452301u;
    context->state[1] = 0xefcdab89u;
    context->state[2] = 0x98badcfeu;
    context->state[3] = 0x10325476u;
    context->state[4] = 0xc3d2e1f0u;
    context->bits = 0;
    context->used = 0;
}

void
libmpq__sha1_update(mpq_sha1_s *context, const uint8_t *data, size_t size)
{
    context->bits += (uint64_t)size * UINT64_C(8);
    while (size != 0) {
        size_t count = sizeof(context->buffer) - context->used;
        if (count > size)
            count = size;
        memcpy(context->buffer + context->used, data, count);
        context->used += count;
        data += count;
        size -= count;
        if (context->used == sizeof(context->buffer)) {
            transform(context, context->buffer);
            context->used = 0;
        }
    }
}

void
libmpq__sha1_final(mpq_sha1_s *context, uint8_t digest[LIBMPQ_SHA1_SIZE])
{
    uint8_t padding[64] = { 0x80 };
    uint8_t length[8];
    uint64_t bits = context->bits;
    size_t i;
    for (i = 0; i < sizeof(length); ++i)
        length[sizeof(length) - 1 - i] = (uint8_t)(bits >> (i * 8u));
    libmpq__sha1_update(
        context, padding, context->used < 56 ? 56 - context->used : 120 - context->used
    );
    libmpq__sha1_update(context, length, sizeof(length));
    for (i = 0; i < 5; ++i) {
        digest[i * 4] = (uint8_t)(context->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(context->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(context->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)context->state[i];
    }
    memset(context, 0, sizeof(*context));
}
