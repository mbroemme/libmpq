/*
 *  mpq-verify.h -- private file verification declarations.
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

#ifndef LIBMPQ_VERIFY_H
#define LIBMPQ_VERIFY_H

#include <libmpq/mpq.h>

/* Immutable copied ranges. Only externally serialized lifetime operations change refs. */
typedef struct
{
    uint64_t start;
    uint64_t end;
    uint64_t maximum;
} mpq_raw_interval_s;

struct mpq_raw_index
{
    size_t references;
    size_t count;
    mpq_raw_interval_s intervals[];
};

/* Share only completed indexes; the final externally serialized owner releases them. */
int32_t libmpq__raw_index_share(mpq_archive_s *destination, const mpq_archive_s *source);
void libmpq__raw_index_release(mpq_archive_s *archive);

/* Bounded stored-byte comparisons; callers validate geometry and absolute ranges. */
int32_t libmpq__verify_raw_chunks(
    mpq_archive_s *archive, uint64_t position, uint64_t size, uint64_t digest_position,
    uint32_t chunk_size, int stop_on_mismatch, uint32_t *mismatch
);

int32_t libmpq__verify_archive_ex(
    mpq_archive_s *archive, uint32_t flags, uint32_t *checked, uint32_t *unavailable,
    uint32_t *mismatches
);

int32_t libmpq__verify_file(
    mpq_archive_s *archive, uint32_t file_number, uint32_t verify_flags, uint32_t *mismatches
);

int32_t libmpq__verify_file_ex(
    mpq_archive_s *archive, uint32_t file_number, const char *filename, uint32_t verify_flags,
    uint32_t *checked, uint32_t *unavailable, uint32_t *mismatches, void *(*allocate)(size_t)
);

int32_t libmpq__verify_block(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint32_t *checksum,
    uint32_t *mismatches
);

#endif /* LIBMPQ_VERIFY_H */
