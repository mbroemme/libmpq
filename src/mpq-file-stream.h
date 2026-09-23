/*
 *  mpq-file-stream.h -- internal logical file streaming declarations.
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

#ifndef LIBMPQ_FILE_STREAM_H
#define LIBMPQ_FILE_STREAM_H

#include <libmpq/mpq.h>

int32_t libmpq__reader_file_stream_open(
    mpq_archive_s *archive, uint32_t file_number, mpq_file_stream_s **stream
);
int32_t libmpq__reader_file_stream_open_name(
    mpq_archive_s *archive, const char *filename, mpq_file_stream_s **stream
);
int32_t libmpq__reader_file_stream_read(
    mpq_file_stream_s *stream, uint8_t *buffer, libmpq__off_t size, libmpq__off_t *transferred
);
int32_t
libmpq__reader_file_stream_seek(mpq_file_stream_s *stream, libmpq__off_t offset, int32_t origin);
int32_t libmpq__reader_file_stream_tell(mpq_file_stream_s *stream, libmpq__off_t *position);
int32_t libmpq__reader_file_stream_size(mpq_file_stream_s *stream, libmpq__off_t *size);
int32_t libmpq__reader_file_stream_close(mpq_file_stream_s *stream);

#endif /* LIBMPQ_FILE_STREAM_H */
