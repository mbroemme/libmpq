/*
 *  reader.h -- internal archive reader declarations.
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

#ifndef LIBMPQ_READER_H
#define LIBMPQ_READER_H

#include <libmpq/mpq.h>
#include <stdint.h>

int32_t libmpq__reader_archive_open_path(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
);
void libmpq__reader_decode_uint32_table(uint32_t *table, const uint8_t *raw, uint32_t count);
int32_t libmpq__reader_validate_file_number(mpq_archive_s *mpq_archive, uint32_t file_number);
uint32_t libmpq__reader_count_file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number);
int32_t libmpq__reader_validate_block_number(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number
);
int32_t libmpq__reader_get_block_seed(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed
);

#endif /* LIBMPQ_READER_H */
