/*
 *  extract.c -- decompression backends for MPQ block payloads.
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

#include "extract.h"
#include "endian.h"
#include "pkware.h"
#include "huffman.h"
#include "wave.h"
#include <libmpq/mpq.h>

#include <stdlib.h>
#include <string.h>

#include <bzlib.h>
#include <zlib.h>

/* Map MPQ compression flags to the backend that can decode that payload. */
static decompress_table_s dcmp_table[] = {

    /* Inverse of the canonical writer order: WAVE, Huffman, zlib, PKWARE, bzip2. */
    { LIBMPQ_COMPRESSION_WAVE_STEREO, libmpq__decompress_wave_stereo },
    { LIBMPQ_COMPRESSION_WAVE_MONO, libmpq__decompress_wave_mono },
    { LIBMPQ_COMPRESSION_HUFFMAN, libmpq__decompress_huffman },
    { LIBMPQ_COMPRESSION_PKZIP, libmpq__decompress_pkzip },
    { LIBMPQ_COMPRESSION_ZLIB, libmpq__decompress_zlib },
    { LIBMPQ_COMPRESSION_BZIP2, libmpq__decompress_bzip2 }
};

/* Decompress an MPQ Huffman-compressed stream into the caller-provided buffer. */
int32_t
libmpq__decompress_huffman(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* Huffman state and transferred-byte count for this stream. */
    int32_t tb = 0;
    struct huffman_tree_s *ht;
    struct huffman_input_stream_s *is;

    if (in_buf == NULL || out_buf == NULL || in_size < sizeof(uint32_t)) {
        return LIBMPQ_ERROR_FORMAT;
    }

    if ((ht = malloc(sizeof(struct huffman_tree_s))) == NULL) {
        return LIBMPQ_ERROR_MALLOC;
    }

    if ((is = malloc(sizeof(struct huffman_input_stream_s))) == NULL) {
        free(ht);
        return LIBMPQ_ERROR_MALLOC;
    }

    /* Start from a clean tree and input stream because both keep adaptive state. */
    memset(ht, 0, sizeof(struct huffman_tree_s));
    memset(is, 0, sizeof(struct huffman_input_stream_s));

    /* The first four bytes seed the bit buffer; remaining bytes form the stream. */
    is->bit_buf = libmpq__load_le32(in_buf);
    in_buf += sizeof(int32_t);
    is->in_buf = (uint8_t *)in_buf;
    is->bits = 32;

    libmpq__huffman_tree_init(ht, LIBMPQ_HUFF_DECOMPRESS);

    tb = libmpq__huffman_decode(ht, is, out_buf, out_size);

    free(is);
    free(ht);

    return tb;
}

/* Decompress an MPQ zlib-compressed stream into the caller-provided buffer. */
int32_t
libmpq__decompress_zlib(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* Zlib stream state and transferred-byte count for this stream. */
    int32_t result = 0;
    int32_t tb = 0;
    z_stream z;

    /* Zlib consumes the complete MPQ block and writes directly to the caller buffer. */
    z.next_in = (Bytef *)in_buf;
    z.avail_in = (uInt)in_size;
    z.total_in = in_size;
    z.next_out = (Bytef *)out_buf;
    z.avail_out = (uInt)out_size;
    z.total_out = 0;
    z.zalloc = NULL;
    z.zfree = NULL;

    /* Use zlib's default window handling; MPQ streams are standard zlib payloads. */
    if ((result = inflateInit(&z)) != Z_OK) {
        return result;
    }

    if ((result = inflate(&z, Z_FINISH)) != Z_STREAM_END) {
        return result;
    }

    tb = z.total_out;

    if ((result = inflateEnd(&z)) != Z_OK) {
        return result;
    }

    return tb;
}

/* Decompress an MPQ PKWARE Data Compression Library stream. */
int32_t
libmpq__decompress_pkzip(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* PKZIP work buffer, callback state and transferred-byte count. */
    int32_t tb = 0;
    pkzip_cmp_s *work_buf;
    pkzip_data_s info;

    if ((work_buf = malloc(sizeof(*work_buf))) == NULL) {
        return LIBMPQ_ERROR_MALLOC;
    }

    /* The PKWARE decoder uses caller-provided scratch memory as its full state. */
    memset(work_buf, 0, sizeof(*work_buf));

    /* Callback state tracks input and output positions for the decoder. */
    info.in_buf = in_buf;
    info.in_pos = 0;
    info.in_bytes = in_size;
    info.out_buf = out_buf;
    info.out_pos = 0;
    info.max_out = out_size;

    if ((tb = libmpq__do_decompress_pkzip((uint8_t *)work_buf, &info)) < 0) {
        free(work_buf);
        return tb;
    }

    tb = info.out_pos;

    free(work_buf);

    return tb;
}

/* Decompress an MPQ bzip2-compressed stream into the caller-provided buffer. */
int32_t
libmpq__decompress_bzip2(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* Bzip2 stream state and transferred-byte count for this stream. */
    int32_t result = 0;
    int32_t tb = 0;
    bz_stream strm;

    /* Default bzip2 allocators are sufficient for MPQ block decompression. */
    strm.bzalloc = NULL;
    strm.bzfree = NULL;

    if ((result = BZ2_bzDecompressInit(&strm, 0, 0)) != BZ_OK) {
        return result;
    }

    /* Bzip2 consumes the complete MPQ block and writes directly to the caller buffer. */
    strm.next_in = (char *)in_buf;
    strm.avail_in = in_size;
    strm.next_out = (char *)out_buf;
    strm.avail_out = out_size;

    while (BZ2_bzDecompress(&strm) != BZ_STREAM_END)
        ;

    tb = strm.total_out_lo32;

    BZ2_bzDecompressEnd(&strm);

    return tb;
}

/* Decompress an MPQ mono WAVE-compressed stream. */
int32_t
libmpq__decompress_wave_mono(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* Transferred-byte count reported by the shared WAVE decoder. */
    int32_t tb = 0;

    if ((tb = libmpq__do_decompress_wave(out_buf, out_size, in_buf, in_size, 1)) < 0) {
        return tb;
    }

    return tb;
}

/* Decompress an MPQ stereo WAVE-compressed stream. */
int32_t
libmpq__decompress_wave_stereo(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
{

    /* Transferred-byte count reported by the shared WAVE decoder. */
    int32_t tb = 0;

    if ((tb = libmpq__do_decompress_wave(out_buf, out_size, in_buf, in_size, 2)) < 0) {
        return tb;
    }

    return tb;
}

/* Decode a Blizzard multi-compression stream by applying each flagged backend in order. */
int32_t
libmpq__decompress_multi(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* Compression mask state, temporary buffers and transferred-byte count. */
    int32_t tb = 0;
    uint32_t count = 0;
    uint32_t entries = (sizeof(dcmp_table) / sizeof(decompress_table_s));
    uint8_t *temp_buf = NULL;
    uint8_t *work_buf = 0;
    uint8_t decompress_flag, decompress_unsupp;
    uint32_t i;

    /* First byte selects the chained decompression backends for this block. */
    decompress_flag = decompress_unsupp = *in_buf++;

    in_size--;

    /* Count supported algorithms and remember flags that have no local backend. */
    for (i = 0; i < entries; i++) {
        if (decompress_flag & dcmp_table[i].mask) {
            count++;
            decompress_unsupp &= ~dcmp_table[i].mask;
        }
    }

    /* Refuse streams that use a compression method from a newer unsupported format. */
    if (decompress_unsupp) {
        return LIBMPQ_ERROR_UNPACK;
    }

    /* Multiple backends need a temporary buffer between decompression stages. */
    if (count > 1) {
        if ((temp_buf = malloc(out_size)) == NULL) {
            return LIBMPQ_ERROR_MALLOC;
        }

        memset(temp_buf, 0, out_size);
    }

    /* Apply selected backends in table order, alternating buffers between stages. */
    for (i = 0, count = 0; i < entries; i++) {

        /* Apply this decompressor if its bit is present in the stream header. */
        if (decompress_flag & dcmp_table[i].mask) {

            /* Chained stages ping-pong between output and temporary storage. */
            if (count == 0) {
                work_buf = out_buf;
            } else {
                work_buf = temp_buf;
            }

            /* Decompress the current stage with the mapped backend. */
            if ((tb = dcmp_table[i].decompress(in_buf, in_size, work_buf, out_size)) < 0) {
                free(temp_buf);
                return tb;
            }

            /* Feed this stage's output into the next decompression stage. */
            in_size = out_size;
            in_buf = work_buf;

            count++;
        }
    }

    /* Copy the final stage back if it ended in the temporary buffer. */
    if (work_buf != out_buf) {
        memcpy(out_buf, in_buf, out_size);
    }

    free(temp_buf);

    return tb;
}
