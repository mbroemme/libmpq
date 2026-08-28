/*
 *  mpq-compression.c -- MPQ compression and decompression orchestration.
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

#include "mpq-compression.h"
#include "mpq-endian.h"
#include "mpq-huffman.h"
#include "mpq-internal.h"
#include "mpq-pkware.h"
#include "mpq-wave.h"
#include <libmpq/mpq.h>

#include <stdlib.h>
#include <string.h>

#include <bzlib.h>
#include <zlib.h>

/* Map MPQ compression flags to the backend that can decode that payload. */
static decompress_table_s dcmp_table[] = {

    /* Reverse of the canonical writer order. */
    { LIBMPQ_COMPRESSION_BZIP2, libmpq__compression_decompress_bzip2 },
    { LIBMPQ_COMPRESSION_PKZIP, libmpq__compression_decompress_pkzip },
    { LIBMPQ_COMPRESSION_ZLIB, libmpq__compression_decompress_zlib },
    { LIBMPQ_COMPRESSION_HUFFMAN, libmpq__compression_decompress_huffman },
    { LIBMPQ_COMPRESSION_WAVE_STEREO, libmpq__compression_decompress_wave_stereo },
    { LIBMPQ_COMPRESSION_WAVE_MONO, libmpq__compression_decompress_wave_mono }
};

/* Decompress an MPQ Huffman-compressed stream into the caller-provided buffer.
 * The stream owns adaptive tree state, so the function initializes and frees
 * a separate tree and bit reader for each archive block. */
int32_t
libmpq__compression_decompress_huffman(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
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
    is->in_buf = in_buf;
    is->in_end = in_buf + in_size - sizeof(uint32_t);
    is->bits = 32;

    libmpq__huffman_tree_init(ht, LIBMPQ_HUFF_DECOMPRESS);

    tb = libmpq__huffman_decode(ht, is, out_buf, out_size);

    free(is);
    free(ht);

    return tb;
}

/* Decompress an MPQ zlib-compressed stream into the caller-provided buffer.
 * The output count returned by zlib is converted to the libmpq block API's
 * signed transfer convention, while zlib failures are propagated unchanged. */
int32_t
libmpq__compression_decompress_zlib(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
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

/* Decompress an MPQ PKWARE Data Compression Library stream.
 * A scratch codec object and callback state isolate the decoder from the
 * caller's buffers while preserving the exact number of produced bytes. */
int32_t
libmpq__compression_decompress_pkzip(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
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

    if ((tb = libmpq__pkzip_decompress((uint8_t *)work_buf, &info)) < 0) {
        free(work_buf);
        return tb;
    }

    tb = info.out_pos;

    free(work_buf);

    return tb;
}

/* Decompress an MPQ bzip2-compressed stream into the caller-provided buffer.
 * The bzip2 state consumes the compressed block and writes decoded bytes
 * directly to the destination supplied by the archive reader. */
int32_t
libmpq__compression_decompress_bzip2(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
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

/* Decompress an MPQ mono WAVE-compressed stream.
 * The channel count is fixed to one so the shared WAVE decoder can validate
 * the payload format and reconstruct the original PCM byte stream. */
int32_t
libmpq__compression_decompress_wave_mono(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
{

    /* Transferred-byte count reported by the shared WAVE decoder. */
    int32_t tb = 0;

    if ((tb = libmpq__wave_decompress(out_buf, out_size, in_buf, in_size, 1)) < 0) {
        return tb;
    }

    return tb;
}

/* Decompress an MPQ stereo WAVE-compressed stream.
 * The channel count is fixed to two, matching the stereo ADPCM framing and
 * predictor state expected by the shared WAVE decoder. */
int32_t
libmpq__compression_decompress_wave_stereo(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
{

    /* Transferred-byte count reported by the shared WAVE decoder. */
    int32_t tb = 0;

    if ((tb = libmpq__wave_decompress(out_buf, out_size, in_buf, in_size, 2)) < 0) {
        return tb;
    }

    return tb;
}

/* Decode a Blizzard multi-compression stream by applying each flagged backend in order.
 * The leading mask selects supported codecs, and intermediate buffers preserve
 * each stage's output while the next stage consumes it. */
int32_t
libmpq__compression_decompress_multi(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size
)
{

    /* Compression mask state, temporary buffers and transferred-byte count. */
    int32_t tb = 0;
    uint32_t count = 0;
    uint32_t entries = (sizeof(dcmp_table) / sizeof(decompress_table_s));
    uint8_t *temp_buf = NULL;
    uint8_t *work_buf = 0;
    uint8_t decompress_flag;
    uint8_t decompress_unsupp;
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
            if (count == 0)
                work_buf = temp_buf != NULL ? temp_buf : out_buf;
            else
                work_buf = (in_buf == out_buf) ? temp_buf : out_buf;

            /* Decompress the current stage with the mapped backend. */
            if ((tb = dcmp_table[i].decompress(in_buf, in_size, work_buf, out_size)) < 0) {
                free(temp_buf);
                return tb;
            }

            /* Feed this stage's output into the next decompression stage. */
            if (tb < 0) {
                free(temp_buf);
                return tb;
            }
            in_size = (uint32_t)tb;
            in_buf = work_buf;

            count++;
        }
    }

    /* Copy the final stage back if it ended in the temporary buffer. */
    if (work_buf != out_buf) {
        memcpy(out_buf, in_buf, (size_t)tb);
    }

    free(temp_buf);

    return tb;
}

/* Return whether every requested compression bit has a local implementation.
 * Unknown bits are rejected before any codec or archive state is modified. */
int
libmpq__compression_supported_mask(uint32_t mask)
{
    return (mask & ~(LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB |
                     LIBMPQ_COMPRESSION_PKZIP | LIBMPQ_COMPRESSION_BZIP2 |
                     LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO)) == 0;
}

/* Apply one selected compression backend and replace the current buffer.
 * Each backend receives the current stage output and returns a newly owned
 * buffer, allowing the caller to retain the previous stage on fallback. */
static int32_t
compression_stage(uint8_t **data, size_t *size, uint32_t mask)
{
    uint8_t *out;
    size_t out_size = *size + (*size / 100) + 1024;
    z_stream z;
    bz_stream b;
    int result;

    if (mask == LIBMPQ_COMPRESSION_HUFFMAN)
        out_size = *size * 2 + 64;
    out = malloc(out_size ? out_size : 1);
    if (out == NULL)
        return LIBMPQ_ERROR_MALLOC;
    if (mask == LIBMPQ_COMPRESSION_PKZIP) {
        uint8_t *candidate = NULL;
        uint32_t candidate_size = 0;
        int32_t status;
        free(out);
        status = libmpq__pkzip_compress(*data, (uint32_t)*size, &candidate, &candidate_size);
        if (status < 0)
            return status;
        free(*data);
        *data = candidate;
        *size = candidate_size;
        return LIBMPQ_SUCCESS;
    } else if (mask == LIBMPQ_COMPRESSION_HUFFMAN) {
        struct huffman_tree_s *tree = calloc(1, sizeof(*tree));
        struct huffman_output_stream_s stream;
        int32_t encoded;
        if (tree == NULL) {
            free(out);
            return LIBMPQ_ERROR_MALLOC;
        }
        stream.out_buf = out;
        stream.capacity = (uint32_t)out_size;
        encoded = libmpq__huffman_encode(tree, &stream, *data, (uint32_t)*size);
        free(tree);
        if (encoded < 0) {
            free(out);
            return encoded;
        }
        free(*data);
        *data = out;
        *size = (size_t)encoded;
        return LIBMPQ_SUCCESS;
    } else if (mask == LIBMPQ_COMPRESSION_WAVE_MONO || mask == LIBMPQ_COMPRESSION_WAVE_STEREO) {
        uint8_t *candidate = NULL;
        uint32_t candidate_size = 0;
        int32_t status = libmpq__wave_compress(
            *data, (uint32_t)*size, &candidate, &candidate_size,
            mask == LIBMPQ_COMPRESSION_WAVE_MONO ? 1 : 2
        );
        free(out);
        if (status < 0)
            return status;
        free(*data);
        *data = candidate;
        *size = candidate_size;
        return LIBMPQ_SUCCESS;
    } else if (mask == LIBMPQ_COMPRESSION_ZLIB) {
        memset(&z, 0, sizeof(z));
        z.next_in = *data;
        z.avail_in = (uInt)*size;
        z.next_out = out;
        z.avail_out = (uInt)out_size;
        result = deflateInit(&z, Z_DEFAULT_COMPRESSION);
        if (result == Z_OK)
            result = deflate(&z, Z_FINISH);
        if (result == Z_STREAM_END)
            result = deflateEnd(&z);
        else
            deflateEnd(&z);
        if (result != Z_OK) {
            free(out);
            return LIBMPQ_ERROR_UNPACK;
        }
        out_size = z.total_out;
    } else {
        memset(&b, 0, sizeof(b));
        b.next_in = (char *)*data;
        b.avail_in = (unsigned int)*size;
        b.next_out = (char *)out;
        b.avail_out = (unsigned int)out_size;
        result = BZ2_bzCompressInit(&b, 9, 0, 30);
        if (result == BZ_OK) {
            do {
                result = BZ2_bzCompress(&b, BZ_FINISH);
            } while (result == BZ_FINISH_OK);
        }
        if (result == BZ_STREAM_END)
            result = BZ2_bzCompressEnd(&b);
        else
            BZ2_bzCompressEnd(&b);
        if (result != BZ_OK) {
            free(out);
            return LIBMPQ_ERROR_UNPACK;
        }
        out_size = b.total_out_lo32;
    }
    free(*data);
    *data = out;
    *size = out_size;
    return LIBMPQ_SUCCESS;
}

/* Apply the selected compression chain and return its actual successful mask.
 * Stages run in canonical Storm order, and a stage is kept only when it saves
 * at least two bytes; the emitted mask therefore describes actual reductions. */
int32_t
libmpq__compression_encode_sector(
    const uint8_t *input, size_t input_size, uint32_t requested, uint8_t **output,
    size_t *output_size, uint8_t *emitted_mask
)
{
    uint8_t *data;
    size_t size;
    uint32_t masks[] = { LIBMPQ_COMPRESSION_WAVE_MONO, LIBMPQ_COMPRESSION_WAVE_STEREO,
                         LIBMPQ_COMPRESSION_HUFFMAN,   LIBMPQ_COMPRESSION_ZLIB,
                         LIBMPQ_COMPRESSION_PKZIP,     LIBMPQ_COMPRESSION_BZIP2 };
    size_t i;

    if (!libmpq__compression_supported_mask(requested))
        return LIBMPQ_ERROR_FORMAT;
    data = malloc(input_size ? input_size : 1);
    if (data == NULL)
        return LIBMPQ_ERROR_MALLOC;
    memcpy(data, input, input_size);
    size = input_size;
    *emitted_mask = 0;

    /* Try each requested codec independently so expansion does not poison later stages. */
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        if (requested & masks[i]) {
            size_t before = size;
            uint8_t *saved = malloc(before ? before : 1);
            int32_t result;
            if (saved == NULL) {
                free(data);
                return LIBMPQ_ERROR_MALLOC;
            }
            memcpy(saved, data, before);
            result = compression_stage(&data, &size, masks[i]);
            if (result < 0) {
                free(saved);
                continue;
            }
            if (size <= before - (before >= 2 ? 2 : before))
                *emitted_mask |= (uint8_t)masks[i];
            else {
                free(data);
                data = saved;
                size = before;
                saved = NULL;
            }
            free(saved);
        }
    }
    if (*emitted_mask == 0 || size + 1 >= input_size) {
        *emitted_mask = 0;
        *output = data;
        *output_size = size;
    } else {
        uint8_t *packed = realloc(data, size + 1);
        if (packed == NULL) {
            free(data);
            return LIBMPQ_ERROR_MALLOC;
        }
        memmove(packed + 1, packed, size);
        packed[0] = *emitted_mask;
        *output = packed;
        *output_size = size + 1;
    }
    return LIBMPQ_SUCCESS;
}

/* Decompress one archive block according to its MPQ compression flags.
 * Raw data is copied directly, while PKWARE and multi-compression payloads
 * are dispatched to the codec layer with MPQ-compatible expansion semantics. */
int32_t
libmpq__compression_decompress_block(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size,
    uint32_t compression_type
)
{
    int32_t tb = 0;

    if (compression_type == LIBMPQ_FLAG_COMPRESS_NONE) {
        if (in_size < out_size)
            return LIBMPQ_ERROR_SIZE;
        memcpy(out_buf, in_buf, out_size);
        tb = out_size;
    } else if (compression_type == LIBMPQ_FLAG_COMPRESS_PKZIP ||
               compression_type == LIBMPQ_FLAG_COMPRESS_MULTI) {
        if (compression_type == LIBMPQ_FLAG_COMPRESS_PKZIP) {
            if (in_size >= out_size) {
                memcpy(out_buf, in_buf, out_size);
                tb = out_size;
            } else if ((tb = libmpq__compression_decompress_pkzip(
                            in_buf, in_size, out_buf, out_size
                        )) < 0) {
                return tb;
            }
        } else if (in_size < out_size) {
            if ((tb = libmpq__compression_decompress_multi(in_buf, in_size, out_buf, out_size)) < 0)
                return tb;
        } else {
            memcpy(out_buf, in_buf, out_size);
            tb = out_size;
        }
    }
    return tb;
}
