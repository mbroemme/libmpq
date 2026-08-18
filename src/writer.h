/*
 *  writer.h -- internal archive writer declarations.
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

#ifndef LIBMPQ_WRITER_H
#define LIBMPQ_WRITER_H

#include <libmpq/mpq.h>

int32_t libmpq__writer_archive_create(
    mpq_archive_s **out, const char *path, const mpq_archive_create_options_s *options
);
int32_t libmpq__writer_file_begin(
    mpq_archive_s *archive, const char *name, libmpq__off_t size,
    const mpq_file_create_options_s *options, mpq_writer_s **out
);
int32_t libmpq__writer_file_write(mpq_writer_s *writer, const uint8_t *buffer, libmpq__off_t size);
int32_t libmpq__writer_file_finish(mpq_writer_s *writer);
int32_t libmpq__writer_file_add(
    mpq_archive_s *archive, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_create_options_s *options
);
int32_t libmpq__writer_file_add_path(
    mpq_archive_s *archive, const char *name, const char *source,
    const mpq_file_create_options_s *options
);
int32_t libmpq__writer_finalize(mpq_archive_s *archive);

#endif /* LIBMPQ_WRITER_H */
