/*
 *  pkware.h -- PKWARE Data Compression Library declarations.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This source was adapted from the C++ version of pklib.h included
 *  in stormlib. The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
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

#ifndef LIBMPQ_PKWARE_H
#define LIBMPQ_PKWARE_H

#include <stdint.h>

/*
 * Literal coding modes stored in the two-byte PKWARE DCL stream header.
 * Binary mode treats literals as arbitrary bytes and is the mode emitted by
 * the libmpq compressor. ASCII mode applies the legacy text-oriented literal
 * coding rules accepted by the decoder for compatibility with existing MPQ
 * archives.
 */

/* Encode and decode literals as arbitrary binary byte values. */
#define LIBMPQ_PKZIP_CMP_BINARY 0

/* Encode and decode literals using the legacy ASCII text mode. */
#define LIBMPQ_PKZIP_CMP_ASCII 1

/*
 * Decoder status values returned by libmpq__pkzip_decompress(). Zero means
 * that the stream reached its end marker successfully. Positive values
 * identify malformed stream metadata, malformed compressed data, or an
 * aborted callback transfer; callers must not interpret them as byte counts.
 */

/* The compressed stream was decoded successfully. */
#define LIBMPQ_PKZIP_CMP_NO_ERROR 0

/* The dictionary-size field is outside the supported 4-, 5-, or 6-bit range. */
#define LIBMPQ_PKZIP_CMP_INV_DICTSIZE 1

/* The literal coding mode is neither binary nor ASCII. */
#define LIBMPQ_PKZIP_CMP_INV_MODE 2

/* The compressed stream contains invalid or truncated data. */
#define LIBMPQ_PKZIP_CMP_BAD_DATA 3

/* A decoder input/output callback stopped the expansion before completion. */
#define LIBMPQ_PKZIP_CMP_ABORT 4

#include "pack_begin.h"

/* PKWARE explode decoder state; field offsets match the original workspace layout. */
typedef struct
{
    uint32_t offs0000;   /* 0000 - compatibility field from the original layout. */
    uint32_t cmp_type;   /* 0004 - literal coding mode. */
    uint32_t out_pos;    /* 0008 - current position in the output ring buffer. */
    uint32_t dsize_bits; /* 000C - dictionary size exponent: 4, 5 or 6. */
    uint32_t dsize_mask; /* 0010 - dictionary distance bitmask. */
    uint32_t bit_buf;    /* 0014 - low bits waiting to be consumed. */
    uint32_t extra_bits; /* 0018 - valid bits above the low byte in bit_buf. */
    uint32_t in_pos;     /* 001C - current position in in_buf. */
    uint32_t in_bytes;   /* 0020 - available bytes in in_buf. */
    void *param;         /* 0024 - caller callback state. */
    uint32_t (*read_buf)(char *buf, uint32_t *size, void *param); /* 0028 - input callback. */
    void (*write_buf)(char *buf, uint32_t *size, void *param);    /* 002C - output callback. */
    uint8_t out_buf[0x2000];  /* 0030 - output circle buffer, starting position is 0x1000. */
    uint8_t offs_2030[0x204]; /* 2030 - compatibility workspace from the original layout. */
    uint8_t in_buf[0x800];    /* 2234 - compressed input staging buffer. */
    uint8_t pos1[0x100];      /* 2A34 - decoded distance prefixes. */
    uint8_t pos2[0x100];      /* 2B34 - decoded length/literal prefixes. */
    uint8_t offs_2c34[0x100]; /* 2C34 - first-level ASCII literal lookup. */
    uint8_t offs_2d34[0x100]; /* 2D34 - second-level ASCII literal lookup. */
    uint8_t offs_2e34[0x80];  /* 2EB4 - third-level ASCII literal lookup. */
    uint8_t offs_2eb4[0x100]; /* 2EB4 - zero-prefix ASCII literal lookup. */
    uint8_t bits_asc[0x100];  /* 2FB4 - bit length per ASCII literal. */
    uint8_t dist_bits[0x40];  /* 30B4 - bit length per distance prefix. */
    uint8_t slen_bits[0x10];  /* 30F4 - bit length per length prefix. */
    uint8_t clen_bits[0x10];  /* 3104 - extra bit count per length prefix. */
    uint16_t len_base[0x10];  /* 3114 - base copy length per prefix. */
} PACK_STRUCT pkzip_cmp_s;
#include "pack_end.h"

/* Callback state that connects the PKWARE decoder to libmpq input and output buffers. */
typedef struct
{
    uint8_t *in_buf;  /* Caller-provided compressed input buffer. */
    uint32_t in_pos;  /* Current offset in input data buffer. */
    int32_t in_bytes; /* Number of bytes in the input buffer. */
    uint8_t *out_buf; /* Caller-provided output buffer. */
    uint32_t out_pos; /* Current offset in the output buffer. */
    int32_t max_out;  /* Maximum writable bytes in the output buffer. */
} pkzip_data_s;

/*
 * Initialize the caller-provided decoder workspace and expand its callback
 * stream. param supplies input/output callbacks and remains caller-owned;
 * the result is a PKWARE status constant, not a byte count.
 */
uint32_t libmpq__pkzip_decompress(uint8_t *work_buf, void *param);

/*
 * Encode binary input as a newly allocated DCL stream using literal and
 * distance-one run forms. out_buf is returned to the caller for release and
 * out_size reports its serialized length; invalid arguments or allocation
 * failure return a negative libmpq error.
 */
int32_t libmpq__pkzip_compress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t **out_buf, uint32_t *out_size
);

#endif /* LIBMPQ_PKWARE_H */
