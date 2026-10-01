/*
 *  mpq-hash.h -- private MPQ hash-table wire-format definitions.
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

#ifndef LIBMPQ_MPQ_HASH_H
#define LIBMPQ_MPQ_HASH_H

#include <stddef.h>
#include <stdint.h>

/* Hash-table slot markers and fixed serialized entry size. */
#define LIBMPQ_HASH_FREE 0xFFFFFFFFu
#define LIBMPQ_HASH_DELETED 0xFFFFFFFEu
#define LIBMPQ_HASH_ENTRY_WIRE_SIZE 16u

/*
 * Native representation of one decrypted MPQ hash-table entry. The filename
 * hashes, locale, and platform identify a block-table index; FREE and DELETED
 * indices mark unused slots without changing the other wire fields.
 */
typedef struct
{
    uint32_t hash_a;            /* First filename hash. */
    uint32_t hash_b;            /* Second filename hash. */
    uint16_t locale;            /* File locale identifier. */
    uint16_t platform;          /* File platform identifier; zero means default. */
    uint32_t block_table_index; /* Block index, or a FREE/DELETED slot marker. */
} mpq_hash_s;

/*
 * Convert caller-owned native entries and little-endian wire bytes.
 * Both helpers check buffer sizes but leave table semantics and encryption
 * to the reader or writer. Zero entries require no buffers.
 */
int32_t libmpq__hash_table_decode(
    const uint8_t *input, size_t input_size, mpq_hash_s *entries, size_t entry_count
);
int32_t libmpq__hash_table_encode(
    const mpq_hash_s *entries, size_t entry_count, uint8_t *output, size_t output_size
);

#endif /* LIBMPQ_MPQ_HASH_H */
