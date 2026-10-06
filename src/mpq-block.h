/*
 *  mpq-block.h -- private MPQ block-table wire-format definitions.
 *
 *  Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
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

#ifndef LIBMPQ_MPQ_BLOCK_H
#define LIBMPQ_MPQ_BLOCK_H

#include <stddef.h>
#include <stdint.h>

/* Serialized MPQ block-table entry sizes, independent of native alignment. */
#define LIBMPQ_BLOCK_ENTRY_WIRE_SIZE 16u
#define LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE 2u

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

/* File is stored as a single sector without a packed block offset table. */
#define LIBMPQ_FLAG_SINGLE 0x01000000

/* Packed block offset table has an additional CRC checksum entry. */
#define LIBMPQ_FLAG_CRC 0x04000000

/*
 * Native representation of one stored file payload. Offset and packed size
 * locate its bytes, while unpacked size describes the decoded result. Patch
 * entries record the reconstructed result size; flags select storage,
 * encryption, and compression behavior.
 */
typedef struct
{
    uint32_t offset;        /* Payload offset from the archive start. */
    uint32_t packed_size;   /* Stored payload size. */
    uint32_t unpacked_size; /* Size after decryption and decompression. */
    uint32_t flags;         /* MPQ file flags. */
} mpq_block_s;

/*
 * Optional v2 high offset word paired with the low offset in mpq_block_s.
 * Version 1 archives do not use this extension.
 */
typedef struct
{
    uint16_t offset_high; /* Upper 16 bits of the file payload offset. */
} mpq_block_ex_s;

/*
 * Convert caller-owned native entries and little-endian wire bytes.
 * These helpers check sizes only; table semantics and encryption remain with
 * the caller. Zero entries require no buffers.
 */
int32_t libmpq__block_table_decode(
    const uint8_t *input, size_t input_size, mpq_block_s *entries, size_t entry_count
);
int32_t libmpq__block_table_encode(
    const mpq_block_s *entries, size_t entry_count, uint8_t *output, size_t output_size
);
int32_t libmpq__block_ex_table_decode(
    const uint8_t *input, size_t input_size, mpq_block_ex_s *entries, size_t entry_count
);
int32_t libmpq__block_ex_table_encode(
    const mpq_block_ex_s *entries, size_t entry_count, uint8_t *output, size_t output_size
);

#endif /* LIBMPQ_MPQ_BLOCK_H */
