/*
 *  mpq-ext-table-builder.h -- Private owned HET/BET builders.
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

#ifndef LIBMPQ_MPQ_EXT_TABLE_BUILDER_H
#define LIBMPQ_MPQ_EXT_TABLE_BUILDER_H

#include "mpq-bet.h"
#include "mpq-het.h"

/* Full-width completed writer metadata. Filenames are borrowed only during build. */
typedef struct
{
    const char *filename;
    uint64_t offset;
    uint64_t packed_size;
    uint64_t unpacked_size;
    uint32_t flags;
} mpq_ext_table_file_s;

/* Owned packed regions, separate from the read-side borrowed views. */
typedef struct
{
    mpq_het_header_s header;
    uint8_t *name_hash1;
    uint8_t *index_bits;
} mpq_het_builder_s;

typedef struct
{
    mpq_bet_header_s header;
    uint8_t *flags;
    uint8_t *records;
    uint8_t *name_hash2;
} mpq_bet_builder_s;

/*
 * Zero-initialize outputs first. Failure preserves them; success replaces them.
 * No envelopes or archive bytes are serialized, and no input aliases are retained.
 */
int32_t libmpq__ext_tables_build(
    const mpq_ext_table_file_s *files, size_t count, mpq_het_builder_s *het, mpq_bet_builder_s *bet
);
void libmpq__het_builder_free(mpq_het_builder_s *builder);
void libmpq__bet_builder_free(mpq_bet_builder_s *builder);

/*
 * Serialize a complete plaintext, uncompressed BET table. The caller owns the
 * returned buffer and frees it with free(). Failure resets buffer/size to NULL/0.
 * Builders remain unchanged; no filenames are hashed and no archive is written.
 */
int32_t libmpq__bet_serialize(const mpq_bet_builder_s *builder, uint8_t **buffer, size_t *size);

#endif
