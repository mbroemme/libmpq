/*
 *  extract.h -- decompression backend declarations for MPQ block payloads.
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

#ifndef LIBMPQ_EXTRACT_H
#define LIBMPQ_EXTRACT_H

#include <stdint.h>

/* Compression flags stored in the first byte of a Blizzard multi-compression block. */
#define LIBMPQ_COMPRESSION_HUFFMAN 0x01 /* Huffman compression used for WAVE payloads. */
#define LIBMPQ_COMPRESSION_ZLIB 0x02    /* Zlib compression introduced in Warcraft III. */
#define LIBMPQ_COMPRESSION_PKZIP 0x08   /* PKWARE Data Compression Library compression. */
#define LIBMPQ_COMPRESSION_BZIP2                                                                   \
    0x10 /* Bzip2 compression introduced in Warcraft III: The Frozen Throne. */
#define LIBMPQ_COMPRESSION_WAVE_MONO 0x40   /* Mono ADPCM 4:1 WAVE compression. */
#define LIBMPQ_COMPRESSION_WAVE_STEREO 0x80 /* Stereo ADPCM 4:1 WAVE compression. */

/* Decompression backend signature; returns transferred bytes or a libmpq error code. */
typedef int32_t (*DECOMPRESS)(uint8_t *, uint32_t, uint8_t *, uint32_t);

/* Maps one MPQ compression flag to the backend that can decode it. */
typedef struct
{
    uint32_t mask;         /* Compression flag handled by this entry. */
    DECOMPRESS decompress; /* Backend implementation. */
} decompress_table_s;

/* Decompress a Huffman-coded MPQ stream; in_size is kept for backend ABI parity. */
extern int32_t libmpq__extract_decompress_huffman(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decompress a zlib-coded MPQ stream. */
extern int32_t libmpq__extract_decompress_zlib(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decompress a PKWARE DCL-coded MPQ stream. */
extern int32_t libmpq__extract_decompress_pkzip(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decompress a bzip2-coded MPQ stream. */
extern int32_t libmpq__extract_decompress_bzip2(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decompress a mono ADPCM WAVE stream. */
extern int32_t libmpq__extract_decompress_wave_mono(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decompress a stereo ADPCM WAVE stream. */
extern int32_t libmpq__extract_decompress_wave_stereo(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decode a Blizzard multi-compression stream by applying each flagged backend in order. */
extern int32_t libmpq__extract_decompress_multi(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

#endif /* LIBMPQ_EXTRACT_H */
