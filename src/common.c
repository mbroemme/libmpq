/*
 *  common.c -- internal hash, crypt and decompression helpers.
 *
 *  Copyright (c) 2003-2011 Maik Broemme <mbroemme@libmpq.org>
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

/* system includes. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* public api includes. */
#include "mpq-internal.h"
#include "mpq.h"

/* internal decompression includes. */
#include "extract.h"

#include "common.h"

/* Shared Storm/MPQ encryption table. It is compiled into the library and can be
 * regenerated with tools/crypt_buf_gen when the table generator changes. */
#include "crypt_buf.h"

/* Hash an MPQ table name or file name with one of the Storm hash table offsets. */
uint32_t
libmpq__hash_string(const char *key, uint32_t offset)
{

    /* Storm hashing starts with fixed seed values for every input string. */
    uint32_t seed1 = 0x7FED7FED;
    uint32_t seed2 = 0xEEEEEEEE;

    /* one key character. */
    uint32_t ch;

    /* prepare seeds. */
    while (*key != 0) {
        ch = toupper(*key++);
        seed1 = crypt_buf[offset + ch] ^ (seed1 + seed2);
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
    }

    return seed1;
}

/* Encrypt a block in place using the MPQ block cipher and the supplied seed. */
int32_t
libmpq__encrypt_block(uint32_t *in_buf, uint32_t in_size, uint32_t seed)
{

    /* The cipher updates both seeds for every 32-bit word. */
    uint32_t seed2 = 0xEEEEEEEE;
    uint32_t ch;

    /* we're processing the data 4 bytes at a time. */
    for (; in_size >= 4; in_size -= 4) {
        seed2 += crypt_buf[0x400 + (seed & 0xFF)];
        ch = *in_buf ^ (seed + seed2);
        seed = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
        seed2 = *in_buf + seed2 + (seed2 << 5) + 3;
        *in_buf++ = ch;
    }

    /* Block encryption has no recoverable per-word error state. */
    return LIBMPQ_SUCCESS;
}

/* Decrypt a block in place using the MPQ block cipher and the supplied seed. */
int32_t
libmpq__decrypt_block(uint32_t *in_buf, uint32_t in_size, uint32_t seed)
{

    /* The cipher updates both seeds for every 32-bit word. */
    uint32_t seed2 = 0xEEEEEEEE;
    uint32_t ch;

    /* we're processing the data 4 bytes at a time. */
    for (; in_size >= 4; in_size -= 4) {
        seed2 += crypt_buf[0x400 + (seed & 0xFF)];
        ch = *in_buf ^ (seed + seed2);
        seed = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
        seed2 = ch + seed2 + (seed2 << 5) + 3;
        *in_buf++ = ch;
    }

    /* Block decryption has no recoverable per-word error state. */
    return LIBMPQ_SUCCESS;
}

/* Recover the per-file block-table seed from the first encrypted block offsets. */
int32_t
libmpq__decrypt_key(uint8_t *in_buf, uint32_t in_size, uint32_t block_size, uint32_t *key)
{

    /* Candidate seed saved after matching the first known block offset. */
    uint32_t saveseed1;

    /* Intermediate value matching seed1 + seed2 for the first encrypted word. */
    uint32_t temp;
    uint32_t i = 0;

    /* Derive the first seed candidate from the known block-table size. */
    temp = (*(uint32_t *)in_buf ^ in_size) - 0xEEEEEEEE;

    /* Try every possible low byte used to index the encryption table. */
    for (i = 0; i < 0x100; i++) {

        /* Candidate seeds and decrypted block offsets for this low byte. */
        uint32_t seed1;
        uint32_t seed2 = 0xEEEEEEEE;
        uint32_t ch;
        uint32_t ch2;

        /* The first encrypted value must decrypt to the block table size. */
        seed1 = temp - crypt_buf[0x400 + i];
        seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
        ch = ((uint32_t *)in_buf)[0] ^ (seed1 + seed2);

        if (ch != in_size) {
            continue;
        }

        /* add one because we are decrypting block positions. */
        saveseed1 = seed1 + 1;
        ch2 = ch;

        /*
         *  if ok, continue and test the second value. we don't know exactly the value,
         *  but we know that the second one has lower 16 bits set to zero (no compressed
         *  block is larger than 0xFFFF bytes)
         */
        seed1 = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
        seed2 = ch + seed2 + (seed2 << 5) + 3;
        seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
        ch = ((uint32_t *)in_buf)[1] ^ (seed1 + seed2);

        /* check if we found the file seed. */
        if ((ch - ch2) <= block_size) {

            /* file seed found, so return it. */
            *key = saveseed1;
            return LIBMPQ_SUCCESS;
        }
    }

    /* No candidate produced a plausible block offset sequence. */
    return LIBMPQ_ERROR_DECRYPT;
}

/* Decompress one archive block according to its MPQ compression flags. */
int32_t
libmpq__decompress_block(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size,
    uint32_t compression_type
)
{

    /* Number of bytes transferred by the selected decompressor. */
    int32_t tb = 0;

    /* check if buffer is not compressed. */
    if (compression_type == LIBMPQ_FLAG_COMPRESS_NONE) {

        /* no compressed data, so copy input buffer to output buffer. */
        memcpy(out_buf, in_buf, out_size);

        /* store number of bytes copied. */
        tb = out_size;
    }

    /* Dispatch single PKZIP compression or Blizzard's chained compression mode. */
    else if (compression_type == LIBMPQ_FLAG_COMPRESS_PKZIP ||
             compression_type == LIBMPQ_FLAG_COMPRESS_MULTI) {

        /* check if block is really compressed, some blocks have set the compression flag, but are
         * not compressed. */
        if (in_size < out_size) {

            /* check if we are using pkzip compression algorithm. */
            if (compression_type == LIBMPQ_FLAG_COMPRESS_PKZIP) {

                /* decompress using pkzip. */
                if ((tb = libmpq__decompress_pkzip(in_buf, in_size, out_buf, out_size)) < 0) {

                    /* something on decompression failed. */
                    return tb;
                }
            }

            /* Run the chained MPQ decompressor selected by the block header byte. */
            else if (compression_type == LIBMPQ_FLAG_COMPRESS_MULTI) {

                /*
                 *  check if it is a file compressed by blizzard's multiple compression, note that
                 * storm.dll version 1.0.9 distributed with warcraft 3 passes the full path name of
                 * the opened archive as the new last parameter.
                 */
                if ((tb = libmpq__decompress_multi(in_buf, in_size, out_buf, out_size)) < 0) {

                    /* Propagate the decompressor-specific failure code. */
                    return tb;
                }
            }
        } else {

            /* block has set compression flag, but is not compressed, so copy data to output buffer.
             */
            memcpy(out_buf, in_buf, out_size);

            /* save the number of transferred bytes. */
            tb = in_size;
        }
    }

    /* Return the number of bytes written to the output buffer. */
    return tb;
}
