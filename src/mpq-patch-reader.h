/*
 *  mpq-patch-reader.h -- private MPQ patch archive and payload interfaces.
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

#ifndef LIBMPQ_MPQ_PATCH_READER_H
#define LIBMPQ_MPQ_PATCH_READER_H

#include <libmpq/mpq.h>
#include <stddef.h>
#include <stdint.h>

#define LIBMPQ_FILE_FLAG_PATCH_FILE 0x00100000u
#define LIBMPQ_FILE_FLAG_DELETE_MARKER 0x02000000u
#define LIBMPQ_PATCH_INFO_SIZE 28u

typedef struct
{
    uint32_t length;
    uint32_t flags;
    uint32_t data_size;
    uint8_t md5[16];
} mpq_patch_info_s;

typedef struct mpq_patch_view mpq_patch_view_s;

/* Credentials are borrowed only while each source is opened. */
typedef struct
{
    const char *path;
    const uint8_t *auth_code;
    size_t auth_code_size;
} mpq_patch_source_s;

/* Compose independently authenticated base and patch sources. */
int32_t libmpq__patch_view_open_sources(
    mpq_patch_view_s **view, const mpq_patch_source_s *base, const mpq_patch_source_s *patches,
    size_t patch_count
);

/* Compose path-backed MPQ layers into a private, read-only archive view. */
int32_t libmpq__patch_view_open(
    mpq_patch_view_s **view, const char *base_path, const char *const *patch_paths,
    size_t patch_count
);

/* Authenticate the base container while keeping patch paths ordinary MPQs. */
int32_t libmpq__patch_view_open_mpqe_base(
    mpq_patch_view_s **view, const char *base_path, const uint8_t *auth_code, size_t auth_code_size,
    const char *const *patch_paths, size_t patch_count
);
mpq_archive_s *libmpq__patch_view_archive(mpq_patch_view_s *view);
int32_t libmpq__patch_view_close(mpq_patch_view_s *view);

/* Decode the prefix preceding a stored MPQ patch member. */
int32_t libmpq__patch_info_parse(const uint8_t *data, size_t size, mpq_patch_info_s *info);

/* Apply a decoded PTCH payload and return a newly allocated logical file. */
int32_t libmpq__patch_apply(
    const uint8_t *base, size_t base_size, const uint8_t *patch, size_t patch_size,
    uint8_t **output, size_t *output_size
);

#endif /* LIBMPQ_MPQ_PATCH_READER_H */
