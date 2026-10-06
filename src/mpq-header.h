/*
 *  mpq-header.h -- private MPQ archive header wire-format definitions.
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

#ifndef LIBMPQ_MPQ_HEADER_H
#define LIBMPQ_MPQ_HEADER_H

#include <stddef.h>
#include <stdint.h>

/* MPQ archive signature stored as the little-endian bytes "MPQ\x1A". */
#define LIBMPQ_HEADER 0x1A51504D

/* Serialized MPQ header sizes, independent of native structure alignment. */
#define LIBMPQ_HEADER_WIRE_SIZE 32u
#define LIBMPQ_HEADER_EX_WIRE_SIZE 12u
#define LIBMPQ_HEADER_V3_EX_WIRE_SIZE 24u
#define LIBMPQ_HEADER_V3_WIRE_SIZE 68u

/* Native representation of the fixed MPQ archive header. */
typedef struct
{
    uint32_t mpq_magic;          /* MPQ signature. */
    uint32_t header_size;        /* Serialized header size in bytes. */
    uint32_t archive_size;       /* Legacy size; a full v3 header supplies the effective size. */
    uint16_t version;            /* Archive format version. */
    uint16_t block_size;         /* File sector size exponent: 512 * 2 ^ block_size. */
    uint32_t hash_table_offset;  /* Offset of the hash table from the archive start. */
    uint32_t block_table_offset; /* Offset of the block table from the archive start. */
    uint32_t hash_table_count;   /* Number of entries in the hash table. */
    uint32_t block_table_count;  /* Number of entries in the block table. */
} mpq_header_s;

/* Version 2 extension carrying high table-offset words. */
typedef struct
{
    uint64_t extended_offset;         /* Extended block-table offset from the archive start. */
    uint16_t hash_table_offset_high;  /* High 16 bits of the hash-table offset. */
    uint16_t block_table_offset_high; /* High 16 bits of the block-table offset. */
} mpq_header_ex_s;

/* Version 3 extension following the version 2 high-offset fields. */
typedef struct
{
    uint64_t archive_size;     /* Authoritative archive size for a full v3 header. */
    uint64_t bet_table_offset; /* Archive-relative BET table offset, or zero if absent. */
    uint64_t het_table_offset; /* Archive-relative HET table offset, or zero if absent. */
} mpq_header_v3_s;

/*
 * Convert one fixed-size little-endian wire header to or from native fields.
 * Callers own both buffers and perform archive-level semantic validation.
 * A short buffer is rejected without reading or writing beyond its extent.
 */
int32_t libmpq__header_decode(mpq_header_s *header, const uint8_t *wire, size_t size);
int32_t libmpq__header_ex_decode(mpq_header_ex_s *header, const uint8_t *wire, size_t size);
int32_t libmpq__header_v3_decode(mpq_header_v3_s *header, const uint8_t *wire, size_t size);
int32_t libmpq__header_encode(const mpq_header_s *header, uint8_t *wire, size_t size);
int32_t libmpq__header_ex_encode(const mpq_header_ex_s *header, uint8_t *wire, size_t size);
int32_t libmpq__header_v3_encode(const mpq_header_v3_s *header, uint8_t *wire, size_t size);

/* Full v3 headers use the 64-bit size; short v3 headers retain the legacy size. */
uint64_t libmpq__header_archive_size(const mpq_header_s *header, const mpq_header_v3_s *v3);

#endif /* LIBMPQ_MPQ_HEADER_H */
