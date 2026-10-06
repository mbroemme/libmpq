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

#include "mpq-file.h"
#include "mpq-md5.h"
#include "mpq-mpqe.h"
#include <libmpq/mpq.h>
#include <stdio.h>

/*
 * A live writer owns the state for one file being streamed into an archive.
 * It buffers at most one archive sector, applies the selected compression and
 * encryption options when that sector is flushed, and records packed offsets
 * for compressed files. The archive owns the active writer through
 * mpq_archive.write_current; the writer is released after file finish or an
 * aborted write, and must not outlive its parent archive.
 */
struct mpq_writer
{
    mpq_archive_s *archive;           /* Parent archive that owns the output stream. */
    char *name;                       /* File name used for hashing and encryption keys. */
    uint8_t *data;                    /* Buffer for the current uncompressed input sector. */
    uint32_t data_size;               /* Number of valid bytes currently buffered in data. */
    uint32_t sector_index;            /* Index of the next sector to flush. */
    uint32_t block_count;             /* Number of sectors expected for this file. */
    uint64_t payload_offset;          /* Archive offset where this file's payload begins. */
    uint32_t prefix_size;             /* Plaintext patch prefix before stored member data. */
    uint32_t patch_result_size;       /* Reconstructed size recorded for a patch-file block. */
    uint8_t patch_file;               /* This writer emits a private patch-file entry. */
    uint64_t packed_total;            /* Bytes written for packed sectors, excluding the table. */
    uint32_t *offsets;                /* Relative sector offsets for compressed files. */
    uint32_t *checksums;              /* Optional slice owned by the offsets allocation. */
    libmpq__off_t expected;           /* File size declared when the writer was opened. */
    libmpq__off_t written;            /* Number of source bytes accepted by the writer. */
    mpq_file_options_s options;       /* Storage, compression, encryption, and identity options. */
    mpq_file_attributes_s attributes; /* Metadata accumulated for this source file. */
    mpq_md5_s md5;                    /* Incremental source-byte digest when requested. */
};

/* Set caller-controlled FILETIME on an active writer with generation enabled. */
int32_t libmpq__writer_file_timestamp(mpq_writer_s *writer, uint64_t filetime);

/* Private backend operations used during MPQE writer finalization. */
typedef struct mpq_writer_mpqe_ops
{
    int32_t (*finalize)(mpq_archive_s *archive);
    int32_t (*transform)(mpq_archive_s *archive);
    int (*close_output)(FILE *output);
    int32_t (*publish)(mpq_directory_s *directory, const char *temporary, const char *destination);
} mpq_writer_mpqe_ops_s;

/* Create a seekable archive and initialize its writer metadata from options. */
int32_t libmpq__writer_archive_create(
    mpq_archive_s **out, const char *path, const mpq_archive_create_options_s *options
);
int32_t libmpq__writer_archive_create_file(
    mpq_archive_s **out, const char *path, FILE *file, const mpq_archive_create_options_s *options
);
int32_t libmpq__writer_archive_create_mpqe(
    mpq_archive_s **out, const char *path, const uint8_t *auth_code, size_t auth_code_size,
    const mpq_archive_create_options_s *options
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

/* Discard an unfinished writer and release its private stream state. */
void libmpq__writer_file_abort(mpq_writer_s *writer);

/* Add a complete in-memory file using begin, write, and finish semantics. */
int32_t libmpq__writer_file_add(
    mpq_archive_s *archive, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
);

/* Store a plaintext patch prefix and encoded body as one patch member. */
int32_t libmpq__writer_patch_file_add(
    mpq_archive_s *archive, const char *name, const uint8_t *prefix, uint32_t prefix_size,
    const uint8_t *body, libmpq__off_t body_size, libmpq__off_t result_size,
    const mpq_file_options_s *options
);

/* Write a zero-byte delete marker only for a private patch-mode archive. */
int32_t libmpq__writer_patch_delete_marker(
    mpq_archive_s *archive, const char *name, uint16_t locale, uint16_t platform
);

/* Read source from disk and add it as a named archive file. */
int32_t libmpq__writer_file_add_path(
    mpq_archive_s *archive, const char *name, const char *source, const mpq_file_options_s *options
);

/* Write final tables, optional listfile, and the completed archive header. */
int32_t libmpq__writer_finalize(mpq_archive_s *archive);
int32_t libmpq__writer_finalize_mpqe(mpq_archive_s *archive);
int32_t libmpq__writer_mpqe_transform_file(
    FILE *input, FILE *output, const uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE]
);
void libmpq__writer_mpqe_cleanup(mpq_archive_s *archive);

#endif /* LIBMPQ_WRITER_H */
