/*
 *  mpq-md5.c -- MD5 checksums for MPQ format compatibility.
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

#include "mpq-md5.h"
#include "mpq-endian.h"

#include <string.h>

/* Transform one complete block using fixed-width unsigned arithmetic.
 * Explicit little-endian loads make the result independent of host byte order. */
static void
transform(mpq_md5_s *context, const uint8_t block[64])
{
    static const uint32_t constants[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391
    };
    static const uint8_t shifts[16] = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };
    uint32_t words[16];
    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t i;

    for (i = 0; i < 16; ++i)
        words[i] = libmpq__load_le32(block + 4 * i);
    for (i = 0; i < 64; ++i) {
        uint32_t f;
        uint32_t index;
        uint32_t value;
        uint32_t previous = d;
        uint8_t shift = shifts[(i / 16) * 4 + i % 4];
        if (i < 16) {
            f = (b & c) | (~b & d);
            index = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            index = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            index = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            index = (7 * i) % 16;
        }
        value = a + f + constants[i] + words[index];
        d = c;
        c = b;
        b += (value << shift) | (value >> (32 - shift));
        a = previous;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
}

/* Initialize a caller-owned incremental checksum context.
 * No allocation or external cryptographic provider is needed. */
void
libmpq__md5_init(mpq_md5_s *context)
{
    memset(context, 0, sizeof(*context));
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* Add bytes to the checksum, buffering at most one incomplete block.
 * The byte count wraps modulo 2^64 as required for the encoded bit length. */
void
libmpq__md5_update(mpq_md5_s *context, const uint8_t *data, size_t size)
{
    while (size != 0) {
        size_t used = (size_t)(context->size % 64);
        size_t take = size < 64 - used ? size : 64 - used;
        memcpy(context->buffer + used, data, take);
        context->size += take;
        data += take;
        size -= take;
        if (context->size % 64 == 0)
            transform(context, context->buffer);
    }
}

/* Append RFC padding and return the canonical sixteen-byte digest.
 * Finalization consumes the context and clears its buffered input. */
void
libmpq__md5_final(mpq_md5_s *context, uint8_t digest[LIBMPQ_MD5_SIZE])
{
    uint8_t padding[64] = { 0x80 };
    uint8_t length[8];
    size_t used = (size_t)(context->size % 64);
    uint32_t i;

    libmpq__store_le64(length, context->size * 8);
    libmpq__md5_update(context, padding, used < 56 ? 56 - used : 120 - used);
    libmpq__md5_update(context, length, sizeof(length));
    for (i = 0; i < 4; ++i)
        libmpq__store_le32(digest + i * 4, context->state[i]);
    memset(context, 0, sizeof(*context));
}
