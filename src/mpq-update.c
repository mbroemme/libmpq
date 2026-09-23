/*
 *  mpq-update.c -- private filesystem update transactions.
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

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "mpq-update.h"
#include "mpq-internal.h"
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#define LIBMPQ_UPDATE_COPY_SIZE 65536u

struct mpq_update
{
    mpq_directory_s *directory;
    FILE *working;
    char *destination;
    char *temporary;
    char *working_path;
    uint64_t device;
    uint64_t inode;
    const mpq_update_ops_s *ops;
#ifndef _WIN32
    uint32_t mode;
#endif
};

static const mpq_update_ops_s default_update_ops = { fflush, fclose, libmpq__directory_replace };

static void
update_result(int32_t *result, int32_t next)
{
    if (*result == LIBMPQ_SUCCESS && next != LIBMPQ_SUCCESS)
        *result = next;
}

static char *
update_working_path(const char *path, const char *temporary)
{
    const char *slash;
    size_t directory_size;
    size_t temporary_size;
    char *working_path;

    slash = strrchr(path, '/');
#ifdef _WIN32
    {
        const char *backslash = strrchr(path, '\\');

        if (backslash != NULL && (slash == NULL || backslash > slash))
            slash = backslash;
    }
#endif
    directory_size = slash == NULL ? 2 : (size_t)(slash - path) + 1;
    temporary_size = strlen(temporary);
    if (directory_size > SIZE_MAX - temporary_size - 1)
        return NULL;
    working_path = malloc(directory_size + temporary_size + 1);
    if (working_path == NULL)
        return NULL;
    if (slash == NULL) {
        working_path[0] = '.';
        working_path[1] = '/';
    } else {
        memcpy(working_path, path, directory_size);
    }
    memcpy(working_path + directory_size, temporary, temporary_size + 1);
    return working_path;
}

static int32_t
update_copy(FILE *input, FILE *output)
{
    uint8_t buffer[LIBMPQ_UPDATE_COPY_SIZE];

    for (;;) {
        size_t size = fread(buffer, 1, sizeof(buffer), input);

        if (size != 0 && fwrite(buffer, 1, size, output) != size)
            return LIBMPQ_ERROR_WRITE;
        if (size != sizeof(buffer)) {
            if (ferror(input))
                return LIBMPQ_ERROR_READ;
            break;
        }
    }
    return fflush(output) == 0 ? LIBMPQ_SUCCESS : LIBMPQ_ERROR_WRITE;
}

static int32_t
update_identity(const mpq_update_s *update)
{
    FILE *file;
    uint64_t device;
    uint64_t inode;
    int32_t result;

    /*
     * This is a best-effort identity recheck immediately before publication.
     * It does not make the subsequent replacement conditional on that identity.
     */
    file = libmpq__directory_file_open(update->directory, update->destination, "rb");
    if (file == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__file_identity(file, &device, &inode);
    if (result == LIBMPQ_SUCCESS && (device != update->device || inode != update->inode))
        result = LIBMPQ_ERROR_EXIST;
    if (fclose(file) != 0)
        update_result(&result, LIBMPQ_ERROR_CLOSE);
    return result;
}

static int32_t
update_cleanup(mpq_update_s *update, uint8_t remove_temporary)
{
    int32_t result = LIBMPQ_SUCCESS;

    if (update->working != NULL) {
        if (update->ops->close(update->working) != 0)
            update_result(&result, LIBMPQ_ERROR_CLOSE);
        update->working = NULL;
    }
    if (remove_temporary && update->temporary != NULL) {
        update_result(&result, libmpq__directory_remove(update->directory, update->temporary));
    }
    free(update->working_path);
    free(update->temporary);
    free(update->destination);
    libmpq__directory_close(update->directory);
    free(update);
    return result;
}

int32_t
libmpq__update_begin(mpq_update_s **update, const char *path)
{
    mpq_update_s *state;
    FILE *input = NULL;
    char *absolute = NULL;
    int32_t result;

    if (update != NULL)
        *update = NULL;
    if (update == NULL || path == NULL)
        return LIBMPQ_ERROR_EXIST;
    state = calloc(1, sizeof(*state));
    if (state == NULL)
        return LIBMPQ_ERROR_MALLOC;
    state->ops = &default_update_ops;
    absolute = libmpq__file_absolute_path(path);
    if (absolute == NULL) {
        result = LIBMPQ_ERROR_OPEN;
        goto fail;
    }
    result = libmpq__directory_open(absolute, &state->directory, &state->destination);
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    result = libmpq__directory_file_validate(state->directory, state->destination);
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    input = libmpq__directory_file_open(state->directory, state->destination, "rb");
    if (input == NULL) {
        result = LIBMPQ_ERROR_EXIST;
        goto fail;
    }
    result = libmpq__file_identity(input, &state->device, &state->inode);
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    result = libmpq__directory_temporary_reopenable(
        state->directory, ".libmpq-update-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &state->temporary,
        &state->working
    );
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    state->working_path = update_working_path(absolute, state->temporary);
    if (state->working_path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto fail;
    }
#ifndef _WIN32
    {
        struct stat status;

        if (fstat(fileno(input), &status) != 0) {
            result = LIBMPQ_ERROR_OPEN;
            goto fail;
        }
        if (!S_ISREG(status.st_mode)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto fail;
        }
        state->mode = (uint32_t)(status.st_mode & 07777);
    }
#endif
    result = update_copy(input, state->working);
    if (result != LIBMPQ_SUCCESS)
        goto fail;
    if (fclose(input) != 0) {
        input = NULL;
        result = LIBMPQ_ERROR_CLOSE;
        goto fail;
    }
    free(absolute);
    *update = state;
    return LIBMPQ_SUCCESS;

fail:
    free(absolute);
    if (input != NULL && fclose(input) != 0)
        update_result(&result, LIBMPQ_ERROR_CLOSE);
    (void)update_cleanup(state, 1);
    return result;
}

const char *
libmpq__update_path(const mpq_update_s *update)
{
    return update == NULL ? NULL : update->working_path;
}

const mpq_update_ops_s *
libmpq__update_ops(const mpq_update_s *update)
{
    return update == NULL ? NULL : update->ops;
}

void
libmpq__update_set_ops(mpq_update_s *update, const mpq_update_ops_s *ops)
{
    if (update != NULL && ops != NULL && ops->flush != NULL && ops->close != NULL &&
        ops->publish != NULL)
        update->ops = ops;
}

int32_t
libmpq__update_commit(mpq_update_s *update)
{
    int32_t result = LIBMPQ_SUCCESS;
    int32_t cleanup_result;
    uint8_t published = 0;

    if (update == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (update->working == NULL) {
        result = LIBMPQ_ERROR_EXIST;
    } else if (update->ops->flush(update->working) != 0) {
        result = LIBMPQ_ERROR_WRITE;
    }
#ifndef _WIN32
    if (result == LIBMPQ_SUCCESS && fchmod(fileno(update->working), (mode_t)update->mode) != 0)
        result = LIBMPQ_ERROR_WRITE;
    if (update->working != NULL) {
        if (update->ops->close(update->working) != 0)
            update_result(&result, LIBMPQ_ERROR_CLOSE);
        update->working = NULL;
    }
    if (result == LIBMPQ_SUCCESS)
        result = update_identity(update);
#else
    if (result == LIBMPQ_SUCCESS)
        result = update_identity(update);
    if (result == LIBMPQ_SUCCESS) {
        result = libmpq__directory_copy_security(
            update->directory, update->destination, update->temporary
        );
    }
    if (update->working != NULL) {
        if (update->ops->close(update->working) != 0)
            update_result(&result, LIBMPQ_ERROR_CLOSE);
        update->working = NULL;
    }
#endif
    if (result == LIBMPQ_SUCCESS) {
        result = update->ops->publish(update->directory, update->temporary, update->destination);
        published = result == LIBMPQ_SUCCESS;
    }
    cleanup_result = update_cleanup(update, (uint8_t)!published);
    update_result(&result, cleanup_result);
    return result;
}

int32_t
libmpq__update_abort(mpq_update_s *update)
{
    if (update == NULL)
        return LIBMPQ_ERROR_EXIST;
    return update_cleanup(update, 1);
}
