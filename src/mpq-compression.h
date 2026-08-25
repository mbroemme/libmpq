/*
 *  mpq-compression.h -- MPQ compression and decompression declarations.
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

#ifndef LIBMPQ_COMPRESSION_H
#define LIBMPQ_COMPRESSION_H

#include <stddef.h>
#include <stdint.h>

/*
 * Compression masks stored in the first byte of a Blizzard
 * multi-compression block. The values are bit flags rather than an
 * enumeration: a block may pass through several codecs, and the decoder
 * applies the selected stages in the format's canonical order. Bits 0x04,
 * 0x20, and all bits above 0x80 are reserved and must be rejected when they
 * are not implemented locally.
 */

/* Adaptive Huffman compression; bit 0, value 0x01. */
#define LIBMPQ_COMPRESSION_HUFFMAN 0x01

/* zlib/Deflate compression; bit 1, value 0x02. */
#define LIBMPQ_COMPRESSION_ZLIB 0x02

/* PKWARE Data Compression Library compression; bit 3, value 0x08. */
#define LIBMPQ_COMPRESSION_PKZIP 0x08

/* bzip2 compression; bit 4, value 0x10. */
#define LIBMPQ_COMPRESSION_BZIP2 0x10

/* Mono 4:1 ADPCM WAVE compression; bit 6, value 0x40. */
#define LIBMPQ_COMPRESSION_WAVE_MONO 0x40

/* Stereo 4:1 ADPCM WAVE compression; bit 7, value 0x80. */
#define LIBMPQ_COMPRESSION_WAVE_STEREO 0x80

/*
 * Codec callback signature used by the multi-compression dispatcher. The
 * input and output buffers are owned by the caller; a successful codec
 * returns the number of bytes written, while a negative result is a libmpq
 * error code. Implementations must not write beyond out_size bytes.
 */
typedef int32_t (*DECOMPRESS)(uint8_t *, uint32_t, uint8_t *, uint32_t);

/*
 * Associates one serialized MPQ compression flag with its decoder. The table
 * is ordered independently from the mask bits because chained streams are
 * decoded in the reverse of their encoding order.
 */
typedef struct
{
    uint32_t mask;         /* Compression flag handled by this entry. */
    DECOMPRESS decompress; /* Backend implementation. */
} decompress_table_s;

/*
 * Decode an adaptive-Huffman MPQ stream.
 *
 * The input and output storage remain caller-owned. The decoder consumes the
 * format's four-byte bit-buffer prefix and returns the number of bytes placed
 * in out_buf, or a negative libmpq error when the stream is invalid or memory
 * cannot be allocated.
 */
extern int32_t libmpq__compression_decompress_huffman(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decode a zlib stream into out_buf, returning bytes written or a codec error. */
extern int32_t libmpq__compression_decompress_zlib(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decode a PKWARE DCL stream into out_buf, returning bytes written or a codec error. */
extern int32_t libmpq__compression_decompress_pkzip(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decode a bzip2 stream into out_buf, returning bytes written or a codec error. */
extern int32_t libmpq__compression_decompress_bzip2(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decode a mono MPQ ADPCM stream into PCM bytes in out_buf. */
extern int32_t libmpq__compression_decompress_wave_mono(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/* Decode a stereo MPQ ADPCM stream into interleaved PCM bytes in out_buf. */
extern int32_t libmpq__compression_decompress_wave_stereo(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/*
 * Decode a Blizzard multi-compression block. The leading mask selects the
 * stages; each stage receives the previous stage's complete output, and the
 * final result is copied to out_buf. Unknown combinations and undersized
 * output buffers are rejected with a negative libmpq error.
 */
extern int32_t libmpq__compression_decompress_multi(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
);

/*
 * Report whether mask contains only codec bits implemented by this build.
 * Zero is accepted because it describes an uncompressed sector; reserved or
 * unsupported bits return false.
 */
int libmpq__compression_supported_mask(uint32_t mask);

/*
 * Encode one sector through the requested codec chain.
 *
 * On success, output receives newly allocated storage owned by the caller and
 * output_size receives its length. emitted_mask reports the stages actually
 * used, allowing the writer to fall back to raw storage when compression
 * expands the sector. The input remains untouched on every return path.
 */
int32_t libmpq__compression_encode_sector(
    const uint8_t *input, size_t input_size, uint32_t requested, uint8_t **output,
    size_t *output_size, uint8_t *emitted_mask
);

/*
 * Decode one archive block according to compression_type. Raw blocks are
 * copied directly; compressed blocks are dispatched through the multi-stage
 * decoder. The return value is the number of unpacked bytes or a negative
 * libmpq error, and neither caller-provided buffer is released here.
 */
int32_t libmpq__compression_decompress_block(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size,
    uint32_t compression_type
);

#endif /* LIBMPQ_COMPRESSION_H */
