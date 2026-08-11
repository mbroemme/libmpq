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

/* system includes. */
#include <stdlib.h>
#include <string.h>

/* zlib includes. */
#include <bzlib.h>
#include <zlib.h>

/* public api includes. */
#include "mpq.h"

/* internal decompression includes. */
#include "explode.h"
#include "extract.h"
#include "huffman.h"
#include "wave.h"

/* Map MPQ compression flags to the backend that can decode that payload. */
static decompress_table_s dcmp_table[] = {
    { LIBMPQ_COMPRESSION_HUFFMAN,
      libmpq__decompress_huffman },                       /* decompression using Huffman trees. */
    { LIBMPQ_COMPRESSION_ZLIB, libmpq__decompress_zlib }, /* decompression with the zlib library. */
    { LIBMPQ_COMPRESSION_PKZIP,
      libmpq__decompress_pkzip }, /* decompression with PKWARE Data Compression Library. */
    { LIBMPQ_COMPRESSION_BZIP2, libmpq__decompress_bzip2 }, /* decompression with bzip2 library. */
    { LIBMPQ_COMPRESSION_WAVE_MONO,
      libmpq__decompress_wave_mono }, /* decompression for mono waves. */
    { LIBMPQ_COMPRESSION_WAVE_STEREO,
      libmpq__decompress_wave_stereo } /* decompression for stereo waves. */
};

/* Decompress an MPQ Huffman-compressed stream into the caller-provided buffer. */
int32_t
libmpq__decompress_huffman(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* TODO: make typdefs of this structs? */

    /* Huffman state and transferred-byte count for this stream. */
    int32_t tb = 0;
    struct huffman_tree_s *ht;
    struct huffman_input_stream_s *is;

    /* allocate memory for the huffman tree. */
    if ((ht = malloc(sizeof(struct huffman_tree_s))) == NULL) {

        /* memory allocation problem. */
        return LIBMPQ_ERROR_MALLOC;
    }

    if ((is = malloc(sizeof(struct huffman_input_stream_s))) == NULL) {

        /* memory allocation problem. */
        free(ht);
        return LIBMPQ_ERROR_MALLOC;
    }

    /* cleanup structures. */
    memset(ht, 0, sizeof(struct huffman_tree_s));
    memset(is, 0, sizeof(struct huffman_input_stream_s));

    /* initialize input stream. */
    is->bit_buf = *(uint32_t *)in_buf;
    in_buf += sizeof(int32_t);
    is->in_buf = (uint8_t *)in_buf;
    is->bits = 32;

    /* initialize the huffman tree for decompression. */
    libmpq__huffman_tree_init(ht, LIBMPQ_HUFF_DECOMPRESS);

    /* save the number of copied bytes. */
    tb = libmpq__do_decompress_huffman(ht, is, out_buf, out_size);

    /* free structures. */
    free(is);
    free(ht);

    /* return transferred bytes. */
    return tb;
}

/* Decompress an MPQ zlib-compressed stream into the caller-provided buffer. */
int32_t
libmpq__decompress_zlib(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* zlib stream state and transferred-byte count for this stream. */
    int32_t result = 0;
    int32_t tb = 0;
    z_stream z;

    /* fill the stream structure for zlib. */
    z.next_in = (Bytef *)in_buf;
    z.avail_in = (uInt)in_size;
    z.total_in = in_size;
    z.next_out = (Bytef *)out_buf;
    z.avail_out = (uInt)out_size;
    z.total_out = 0;
    z.zalloc = NULL;
    z.zfree = NULL;

    /* initialize the decompression structure, storm.dll uses zlib version 1.1.3. */
    if ((result = inflateInit(&z)) != Z_OK) {

        /* something on zlib initialization failed. */
        return result;
    }

    /* call zlib to decompress the data. */
    if ((result = inflate(&z, Z_FINISH)) != Z_STREAM_END) {

        /* something on zlib decompression failed. */
        return result;
    }

    /* save transferred bytes. */
    tb = z.total_out;

    /* cleanup zlib. */
    if ((result = inflateEnd(&z)) != Z_OK) {

        /* something on zlib finalization failed. */
        return result;
    }

    /* return transferred bytes. */
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

    /* allocate memory for pkzip data structure. */
    if ((work_buf = malloc(sizeof(*work_buf))) == NULL) {

        /* memory allocation problem. */
        return LIBMPQ_ERROR_MALLOC;
    }

    /* cleanup. */
    memset(work_buf, 0, sizeof(*work_buf));

    /* fill data information structure. */
    info.in_buf = in_buf;
    info.in_pos = 0;
    info.in_bytes = in_size;
    info.out_buf = out_buf;
    info.out_pos = 0;
    info.max_out = out_size;

    /* do the decompression. */
    if ((tb = libmpq__do_decompress_pkzip((uint8_t *)work_buf, &info)) < 0) {

        /* free working buffer. */
        free(work_buf);

        /* something failed on pkzip decompression. */
        return tb;
    }

    /* save transferred bytes. */
    tb = info.out_pos;

    /* free working buffer. */
    free(work_buf);

    /* return transferred bytes. */
    return tb;
}

/* Decompress an MPQ bzip2-compressed stream into the caller-provided buffer. */
int32_t
libmpq__decompress_bzip2(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* bzip2 stream state and transferred-byte count for this stream. */
    int32_t result = 0;
    int32_t tb = 0;
    bz_stream strm;

    /* initialize the bzlib decompression. */
    strm.bzalloc = NULL;
    strm.bzfree = NULL;

    /* initialize the structure. */
    if ((result = BZ2_bzDecompressInit(&strm, 0, 0)) != BZ_OK) {

        /* something on bzlib initialization failed. */
        return result;
    }

    /* fill the stream structure for bzlib. */
    strm.next_in = (char *)in_buf;
    strm.avail_in = in_size;
    strm.next_out = (char *)out_buf;
    strm.avail_out = out_size;

    /* do the decompression. */
    while (BZ2_bzDecompress(&strm) != BZ_STREAM_END)
        ;

    /* save transferred bytes. */
    tb = strm.total_out_lo32;

    /* cleanup of bzip stream. */
    BZ2_bzDecompressEnd(&strm);

    /* return transferred bytes. */
    return tb;
}

/* Decompress an MPQ mono WAVE-compressed stream. */
int32_t
libmpq__decompress_wave_mono(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{

    /* Transferred-byte count reported by the shared WAVE decoder. */
    int32_t tb = 0;

    /* save the number of copied bytes. */
    if ((tb = libmpq__do_decompress_wave(out_buf, out_size, in_buf, in_size, 1)) < 0) {

        /* something on wave decompression failed. */
        return tb;
    }

    /* return transferred bytes. */
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

    /* save the number of copied bytes. */
    if ((tb = libmpq__do_decompress_wave(out_buf, out_size, in_buf, in_size, 2)) < 0) {

        /* something on wave decompression failed. */
        return tb;
    }

    /* return transferred bytes. */
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

    /* get applied compression types. */
    decompress_flag = decompress_unsupp = *in_buf++;

    /* decrement data size. */
    in_size--;

    /* Count supported algorithms and remember flags that have no local backend. */
    for (i = 0; i < entries; i++) {

        /* check if have to apply this decompression. */
        if (decompress_flag & dcmp_table[i].mask) {

            /* increase counter for used compression algorithms. */
            count++;

            /* This algorithm is supported, so remove it from the unsupported mask. */
            decompress_unsupp &= ~dcmp_table[i].mask;
        }
    }

    /* Refuse streams that use a compression method from a newer unsupported format. */
    if (decompress_unsupp) {

        /* Compression type is unknown to this version of libmpq. */
        return LIBMPQ_ERROR_UNPACK;
    }

    /* Multiple backends need a temporary buffer between decompression stages. */
    if (count > 1) {

        /* allocate memory for temporary buffer. */
        if ((temp_buf = malloc(out_size)) == NULL) {

            /* memory allocation problem. */
            return LIBMPQ_ERROR_MALLOC;
        }

        /* cleanup. */
        memset(temp_buf, 0, out_size);
    }

    /* apply all decompressions. */
    for (i = 0, count = 0; i < entries; i++) {

        /* Apply this decompressor if its bit is present in the stream header. */
        if (decompress_flag & dcmp_table[i].mask) {

            /* First stage can write directly to the output buffer. Later stages
             * alternate buffers. */
            if (count == 0) {

                /* use output buffer as working buffer. */
                work_buf = out_buf;
            } else {

                /* use temporary buffer as working buffer. */
                work_buf = temp_buf;
            }

            /* Decompress the current stage with the mapped backend. */
            if ((tb = dcmp_table[i].decompress(in_buf, in_size, work_buf, out_size)) < 0) {

                /* free temporary buffer. */
                free(temp_buf);

                /* something on decompression failed. */
                return tb;
            }

            /* Feed this stage's output into the next decompression stage. */
            in_size = out_size;
            in_buf = work_buf;

            /* increase counter. */
            count++;
        }
    }

    /* Copy the final stage back if it ended in the temporary buffer. */
    if (work_buf != out_buf) {

        /* copy buffer. */
        memcpy(out_buf, in_buf, out_size);
    }

    /* free temporary buffer. */
    free(temp_buf);

    /* return transferred bytes. */
    return tb;
}
