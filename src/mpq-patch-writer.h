/*
 *  mpq-patch-writer.h -- private MPQ patch archive writer declarations.
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

#ifndef LIBMPQ_MPQ_PATCH_WRITER_H
#define LIBMPQ_MPQ_PATCH_WRITER_H

#include <libmpq/mpq.h>

typedef mpq_patch_s mpq_patch_writer_s;

/* Retain direct splice-tuple regression access without exporting a public API. */
int32_t libmpq__patch_bsd0_encode(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    uint8_t splice, uint8_t **encoded, size_t *encoded_size, size_t *patch_stream_size
);

/* Begin a private libmpq-compatible whole-file patch for a path-backed MPQ. */
int32_t libmpq__patch_writer_begin(
    mpq_patch_writer_s **patch_writer, const char *base_path, const char *patch_path
);

/* Add a PTCH replacement, selecting BSD0 only when smaller than COPY. */
int32_t libmpq__patch_writer_replace(
    mpq_patch_writer_s *patch_writer, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
);

int32_t libmpq__patch_writer_replace_path(
    mpq_patch_writer_s *patch_writer, const char *name, const char *source_path,
    const mpq_file_options_s *options
);

/* Add a delete marker for an existing named base member. */
int32_t libmpq__patch_writer_remove(mpq_patch_writer_s *patch_writer, const char *name);

/* Consume the writer, publishing its completed same-directory temporary file. */
int32_t libmpq__patch_writer_finish(mpq_patch_writer_s *patch_writer);

/* Consume the writer and discard any unpublished temporary file. */
int32_t libmpq__patch_writer_abort(mpq_patch_writer_s *patch_writer);

#endif /* LIBMPQ_MPQ_PATCH_WRITER_H */
