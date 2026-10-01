/*
 *  mpq-internal.h -- internal MPQ archive structures and constants.
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

#ifndef LIBMPQ_MPQ_INTERNAL_H
#define LIBMPQ_MPQ_INTERNAL_H

#include <libmpq/mpq.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "mpq-archive.h"
#include "mpq-file.h"
#include "mpq-writer.h"

/* Common success return code used by libmpq functions. */
#define LIBMPQ_SUCCESS 0

/* File entry exists in the block table and has not been deleted. */
#define LIBMPQ_FLAG_EXISTS 0x80000000

/* File payload is encrypted and must be decrypted before decompression. */
#define LIBMPQ_FLAG_ENCRYPTED 0x00010000

/* Mask covering all MPQ compression mode bits. */
#define LIBMPQ_FLAG_COMPRESSED 0x0000FF00

/* File payload uses the PKWARE Data Compression Library algorithm. */
#define LIBMPQ_FLAG_COMPRESS_PKZIP 0x00000100

/* File payload uses Blizzard's chained multi-compression format. */
#define LIBMPQ_FLAG_COMPRESS_MULTI 0x00000200

/* Internal libmpq marker for an uncompressed block. */
#define LIBMPQ_FLAG_COMPRESS_NONE 0x00000300

/* File is stored as a single sector without a packed block offset table. */
#define LIBMPQ_FLAG_SINGLE 0x01000000

/* Packed block offset table has an additional CRC checksum entry. */
#define LIBMPQ_FLAG_CRC 0x04000000

/* Keep boolean-like constants available for old C environments. */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#endif /* LIBMPQ_MPQ_INTERNAL_H */
