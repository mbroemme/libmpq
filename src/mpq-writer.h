/*
 *  mpq-writer.h -- internal archive writer declarations.
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

/* Create a seekable archive and initialize its writer metadata from options. */
int32_t libmpq__writer_archive_create(
    mpq_archive_s **out, const char *path, const mpq_archive_create_options_s *options
);
int32_t libmpq__writer_archive_create_mpqe(
    mpq_archive_s **out, const char *path, const uint8_t *authentication_code,
    size_t authentication_code_size, const mpq_archive_create_options_s *options
);

/* Begin one named file and return a stateful streaming writer for its payload. */
int32_t libmpq__writer_file_begin(
    mpq_archive_s *archive, const char *name, libmpq__off_t size, const mpq_file_options_s *options,
    mpq_writer_s **out
);

/* Append bytes to the current file, buffering and flushing complete sectors. */
int32_t libmpq__writer_file_write(mpq_writer_s *writer, const uint8_t *buffer, libmpq__off_t size);

/* Finish the current file, write its sector offsets, and publish its block entry. */
int32_t libmpq__writer_file_finish(mpq_writer_s *writer);

/* Add a complete in-memory file using begin, write, and finish semantics. */
int32_t libmpq__writer_file_add(
    mpq_archive_s *archive, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
);

/* Read source from disk and add it as a named archive file. */
int32_t libmpq__writer_file_add_path(
    mpq_archive_s *archive, const char *name, const char *source, const mpq_file_options_s *options
);

/* Write final tables, optional listfile, and the completed archive header. */
int32_t libmpq__writer_finalize(mpq_archive_s *archive);
int32_t libmpq__writer_finalize_mpqe(mpq_archive_s *archive);
void libmpq__writer_mpqe_cleanup(mpq_archive_s *archive);

#ifdef LIBMPQ_TESTING
typedef enum
{
    LIBMPQ_WRITER_TEST_FAULT_NONE,
    LIBMPQ_WRITER_TEST_FAULT_FINALIZE,
    LIBMPQ_WRITER_TEST_FAULT_TRANSFORM,
    LIBMPQ_WRITER_TEST_FAULT_OUTPUT_CLOSE,
    LIBMPQ_WRITER_TEST_FAULT_PUBLISH
} libmpq_writer_test_fault_e;

/* Test-only deterministic failure injection for MPQE writer cleanup coverage. */
void libmpq__writer_test_fault_set(libmpq_writer_test_fault_e fault);
#endif

#endif /* LIBMPQ_WRITER_H */
