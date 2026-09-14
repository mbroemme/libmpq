/*
 *  mpq-attributes.h -- internal MPQ attributes declarations.
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

#ifndef LIBMPQ_ATTRIBUTES_H
#define LIBMPQ_ATTRIBUTES_H

#include <libmpq/mpq.h>
#include <stddef.h>

#define LIBMPQ_ATTRIBUTES_VERSION 100u
#define LIBMPQ_ATTRIBUTES_ALL 0x0fu

/* A validated view borrows the payload; only the archive cache owns its data. */
typedef struct
{
    const uint8_t *data;
    uint32_t flags;
    uint32_t entries;
    uint32_t self;
    uint64_t patch_bits;
    uint8_t patch_self_omitted;
    size_t offsets[4];
} mpq_attributes_s;

int32_t libmpq__attributes_parse(
    const uint8_t *data, size_t size, uint32_t count, uint32_t self, mpq_attributes_s *view
);
void
libmpq__attributes_get(const mpq_attributes_s *view, uint32_t index, mpq_file_attributes_s *result);
int32_t libmpq__attributes_load(mpq_archive_s *archive);
void libmpq__attributes_free(mpq_archive_s *archive);
uint32_t libmpq__attributes_write_flags(const mpq_archive_s *archive);
int32_t libmpq__attributes_serialize(
    const mpq_file_attributes_s *entries, uint32_t count, uint32_t self, uint32_t flags,
    uint8_t **data, size_t *size
);

#endif /* LIBMPQ_ATTRIBUTES_H */
