/*
 *  mpq-update.h -- private filesystem update transactions.
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

#ifndef LIBMPQ_UPDATE_H
#define LIBMPQ_UPDATE_H

#include "mpq-file.h"

/* Private operations permit deterministic transaction finalization tests. */
typedef struct mpq_update_ops
{
    int (*flush)(FILE *file);
    int (*close)(FILE *file);
    int32_t (*publish)(mpq_directory_s *directory, const char *temporary, const char *destination);
} mpq_update_ops_s;

int32_t libmpq__update_transaction_begin(mpq_update_s **update, const char *path);
const char *libmpq__update_path(const mpq_update_s *update);
int32_t libmpq__update_transaction_commit(mpq_update_s *update);
int32_t libmpq__update_transaction_abort(mpq_update_s *update);
int32_t libmpq__update_transaction_replace(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const char *source_path, const mpq_file_options_s *options
);
int32_t libmpq__update_transaction_remove(mpq_update_s *update, const char *filename);
int32_t libmpq__update_transaction_rename(
    mpq_update_s *update, const char *old_filename, const char *new_filename
);
const mpq_update_ops_s *libmpq__update_ops(const mpq_update_s *update);
void libmpq__update_set_ops(mpq_update_s *update, const mpq_update_ops_s *ops);

#endif /* LIBMPQ_UPDATE_H */
