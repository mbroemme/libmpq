/*
 *  mpq-file.h -- private file and directory operations.
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

#ifndef LIBMPQ_FILE_H
#define LIBMPQ_FILE_H

#include <libmpq/mpq.h>
#include <stdio.h>

typedef struct mpq_directory mpq_directory_s;

/* Paths use UTF-8 on Windows. All streams are opened in binary mode. */
FILE *libmpq__file_open(const char *path, const char *mode);
int32_t libmpq__file_seek(FILE *file, uint64_t offset, int origin);
libmpq__off_t libmpq__file_tell(FILE *file);
int32_t libmpq__file_identity(FILE *file, uint64_t *device, uint64_t *inode);
char *libmpq__string_duplicate(const char *text);

/* Retain the destination directory until publication and cleanup finish. */
int32_t libmpq__directory_open(const char *path, mpq_directory_s **directory, char **name);
int32_t libmpq__directory_temporary(
    mpq_directory_s *directory, const char *suffix, int private_file, char **name, FILE **file
);
int32_t libmpq__directory_remove(mpq_directory_s *directory, const char *name);
int32_t libmpq__directory_replace(
    mpq_directory_s *directory, const char *temporary, const char *destination
);
void libmpq__directory_close(mpq_directory_s *directory);

#endif /* LIBMPQ_FILE_H */
