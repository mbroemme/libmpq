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
#include "mpq-archive.h"
#include "mpq-attributes.h"
#include "mpq-bet.h"
#include "mpq-block.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-mpqe.h"
#include "mpq-reader.h"
#include "mpq-signature.h"
#include "mpq-source.h"
#include "mpq-stream.h"
#include "mpq-writer.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#define LIBMPQ_UPDATE_COPY_SIZE 65536u

typedef enum
{
    LIBMPQ_UPDATE_ADD,
    LIBMPQ_UPDATE_REPLACE,
    LIBMPQ_UPDATE_REMOVE,
    LIBMPQ_UPDATE_RENAME,
    LIBMPQ_UPDATE_CHANGE_IDENTITY,
    LIBMPQ_UPDATE_TIMESTAMP
} mpq_update_action_e;

/* A selector is resolved afresh against each successfully adopted stage. */
typedef struct
{
    uint16_t locale;
    uint16_t platform;
    uint32_t number;
    uint32_t slot;
    uint8_t shared;
    uint8_t keep_name;
    uint16_t new_locale;
    uint16_t new_platform;
    uint64_t filetime;
    uint8_t timestamp_exact;
} mpq_update_identity_s;

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
    uint8_t mpqe_auth[LIBMPQ_MPQE_AUTH_CODE_MINIMUM];
    uint8_t mpqe;
    uint8_t dirty;
    char **known_names;
    uint32_t known_count;
#ifndef _WIN32
    uint32_t mode;
#endif
};

static const mpq_update_ops_s default_update_ops = { fflush, fclose, libmpq__directory_replace,
                                                     malloc };

static void
update_result(int32_t *result, int32_t next)
{
    if (*result == 0 && next != 0)
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
    return fflush(output) == 0 ? 0 : LIBMPQ_ERROR_WRITE;
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
    result = libmpq__file_handle_identity(file, &device, &inode);
    if (result == 0 && (device != update->device || inode != update->inode))
        result = LIBMPQ_ERROR_EXIST;
    if (fclose(file) != 0)
        update_result(&result, LIBMPQ_ERROR_CLOSE);
    return result;
}

static int32_t
update_cleanup(mpq_update_s *update, uint8_t remove_temporary)
{
    int32_t result = 0;

    if (update->working != NULL) {
        if (update->ops->close(update->working) != 0)
            update_result(&result, LIBMPQ_ERROR_CLOSE);
        update->working = NULL;
    }
    if (remove_temporary && update->temporary != NULL) {
        update_result(&result, libmpq__directory_remove(update->directory, update->temporary));
    }
    free(update->working_path);
    for (uint32_t i = 0; i < update->known_count; ++i)
        free(update->known_names[i]);
    free(update->known_names);
    free(update->temporary);
    free(update->destination);
    libmpq__mpqe_clear(update->mpqe_auth, sizeof(update->mpqe_auth));
    libmpq__directory_close(update->directory);
    free(update);
    return result;
}

static int32_t
update_copy_range(mpq_archive_s *archive, FILE *output, uint64_t offset, uint64_t size);

/* Prepare a private working file; MPQE decoding fills it directly. */
static int32_t
update_transaction_begin_source(mpq_update_s **update, const char *path, uint8_t copy_source)
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
    if (result != 0)
        goto fail;
    result = libmpq__directory_file_validate(state->directory, state->destination);
    if (result != 0)
        goto fail;
    input = libmpq__directory_file_open(state->directory, state->destination, "rb");
    if (input == NULL) {
        result = LIBMPQ_ERROR_EXIST;
        goto fail;
    }
    result = libmpq__file_handle_identity(input, &state->device, &state->inode);
    if (result != 0)
        goto fail;
    result = libmpq__directory_temporary_reopenable(
        state->directory, ".libmpq-update-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &state->temporary,
        &state->working
    );
    if (result != 0)
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
    if (copy_source) {
        result = update_copy(input, state->working);
        if (result != 0)
            goto fail;
    }
    if (fclose(input) != 0) {
        input = NULL;
        result = LIBMPQ_ERROR_CLOSE;
        goto fail;
    }
    free(absolute);
    *update = state;
    return 0;

fail:
    free(absolute);
    if (input != NULL && fclose(input) != 0)
        update_result(&result, LIBMPQ_ERROR_CLOSE);
    (void)update_cleanup(state, 1);
    return result;
}

/* Begin an ordinary or embedded update with a byte-for-byte working copy. */
int32_t
libmpq__update_transaction_begin(mpq_update_s **update, const char *path)
{
    mpq_archive_s *check = NULL;
    int32_t result = update_transaction_begin_source(update, path, 1);
    if (result != 0)
        return result;

    /* Generic transaction setup historically accepts nonarchives; keep that contract. */
    if (libmpq__reader_archive_open_path(&check, (*update)->working_path, -1) == 0) {
        uint8_t unsupported = check->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_FOUR;
        (void)libmpq__archive_close(check);
        if (unsupported) {
            (void)update_cleanup(*update, 1);
            *update = NULL;
            return LIBMPQ_ERROR_FORMAT;
        }
    }
    return 0;
}

/* Decode an authenticated MPQE source directly into its private working file. */
int32_t
libmpq__update_transaction_begin_mpqe(
    mpq_update_s **update, const char *path, const uint8_t *auth_code, size_t auth_code_size
)
{
    mpq_archive_s *source = NULL;
    mpq_archive_s *check = NULL;
    mpq_update_s *state;
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    uint64_t device;
    uint64_t inode;
    int32_t result;

    if (update != NULL)
        *update = NULL;
    if (update == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__mpqe_key(key, auth_code, auth_code_size);
    if (result != 0)
        return result;
    libmpq__mpqe_clear(key, sizeof(key));
    result = update_transaction_begin_source(update, path, 0);
    if (result != 0)
        return result;
    state = *update;
    result = libmpq__reader_archive_open_mpqe(&source, path, -1, auth_code, auth_code_size);
    if (result != 0)
        goto fail;
    if (source->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_FOUR) {
        result = LIBMPQ_ERROR_FORMAT;
        goto fail;
    }
    result = libmpq__source_file_identity(source->source, &device, &inode);
    if (result != 0)
        goto fail;
    if (device != state->device || inode != state->inode) {
        result = LIBMPQ_ERROR_EXIST;
        goto fail;
    }
    result = update_copy_range(source, state->working, 0, source->file_size);
    if (result != 0)
        goto fail;
    if (fflush(state->working) != 0) {
        result = LIBMPQ_ERROR_WRITE;
        goto fail;
    }
    result = libmpq__reader_archive_open_path(&check, state->working_path, -1);
    if (result != 0)
        goto fail;
    result = libmpq__archive_close(check);
    check = NULL;
    if (result != 0)
        goto fail;
    result = libmpq__archive_close(source);
    source = NULL;
    if (result != 0)
        goto fail;
    state->mpqe = 1;
    memcpy(state->mpqe_auth, auth_code, sizeof(state->mpqe_auth));
    return 0;

fail:
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (source != NULL)
        (void)libmpq__archive_close(source);
    (void)update_cleanup(state, 1);
    *update = NULL;
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

/* Rewrap a staged plaintext MPQ before publishing the encrypted sibling file. */
static int32_t
update_commit_mpqe(mpq_update_s *update)
{
    mpq_archive_s *check = NULL;
    FILE *encrypted = NULL;
    char *encrypted_name = NULL;
    char *encrypted_path = NULL;
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    uint8_t plaintext_removed = 0;
    uint8_t published = 0;
    int32_t result;

    if (update->working == NULL)
        result = LIBMPQ_ERROR_EXIST;
    else if (update->ops->flush(update->working) != 0)
        result = LIBMPQ_ERROR_WRITE;
    else
        result = 0;
    if (result != 0)
        goto done;
    if (!update->dirty) {
        if (update->ops->close(update->working) != 0)
            result = LIBMPQ_ERROR_CLOSE;
        update->working = NULL;
        if (result == 0)
            result = update_identity(update);
        goto done;
    }
    result = libmpq__mpqe_key(key, update->mpqe_auth, sizeof(update->mpqe_auth));
    if (result != 0)
        goto done;
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-update-mpqe-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1,
        &encrypted_name, &encrypted
    );
    if (result != 0)
        goto clear_key;
    encrypted_path = update_working_path(update->working_path, encrypted_name);
    if (encrypted_path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto clear_key;
    }
    result = libmpq__writer_mpqe_transform_file(update->working, encrypted, key);
    libmpq__mpqe_clear(key, sizeof(key));
    if (result != 0)
        goto done;
    result = libmpq__reader_archive_open_mpqe(
        &check, encrypted_path, -1, update->mpqe_auth, sizeof(update->mpqe_auth)
    );
    if (result != 0)
        goto done;
    result = libmpq__archive_close(check);
    check = NULL;
    if (result != 0)
        goto done;
#ifndef _WIN32
    if (fchmod(fileno(encrypted), (mode_t)update->mode) != 0) {
        result = LIBMPQ_ERROR_WRITE;
        goto done;
    }
#else
    result =
        libmpq__directory_copy_security(update->directory, update->destination, encrypted_name);
    if (result != 0)
        goto done;
#endif
    if (fclose(encrypted) != 0) {
        encrypted = NULL;
        result = LIBMPQ_ERROR_CLOSE;
        goto done;
    }
    encrypted = NULL;
    if (update->ops->close(update->working) != 0) {
        update->working = NULL;
        result = LIBMPQ_ERROR_CLOSE;
        goto done;
    }
    update->working = NULL;
    result = libmpq__directory_remove(update->directory, update->temporary);
    if (result != 0)
        goto done;
    plaintext_removed = 1;
    result = update_identity(update);
    if (result == 0) {
        result = update->ops->publish(update->directory, encrypted_name, update->destination);
        published = result == 0;
    }
    goto done;

clear_key:
    libmpq__mpqe_clear(key, sizeof(key));
done:
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (encrypted != NULL && fclose(encrypted) != 0)
        update_result(&result, LIBMPQ_ERROR_CLOSE);
    if (encrypted_name != NULL && !published)
        update_result(&result, libmpq__directory_remove(update->directory, encrypted_name));
    free(encrypted_name);
    free(encrypted_path);
    update_result(&result, update_cleanup(update, (uint8_t)!plaintext_removed));
    return result;
}

int32_t
libmpq__update_transaction_commit(mpq_update_s *update)
{
    int32_t result = 0;
    int32_t cleanup_result;
    uint8_t published = 0;

    if (update == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (update->mpqe)
        return update_commit_mpqe(update);
    if (update->working == NULL) {
        result = LIBMPQ_ERROR_EXIST;
    } else if (update->ops->flush(update->working) != 0) {
        result = LIBMPQ_ERROR_WRITE;
    }
#ifndef _WIN32
    if (result == 0 && fchmod(fileno(update->working), (mode_t)update->mode) != 0)
        result = LIBMPQ_ERROR_WRITE;
    if (update->working != NULL) {
        if (update->ops->close(update->working) != 0)
            update_result(&result, LIBMPQ_ERROR_CLOSE);
        update->working = NULL;
    }
    if (result == 0)
        result = update_identity(update);
#else
    if (result == 0)
        result = update_identity(update);
    if (result == 0) {
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
    if (result == 0) {
        result = update->ops->publish(update->directory, update->temporary, update->destination);
        published = result == 0;
    }
    cleanup_result = update_cleanup(update, (uint8_t)!published);
    update_result(&result, cleanup_result);
    return result;
}

int32_t
libmpq__update_transaction_abort(mpq_update_s *update)
{
    if (update == NULL)
        return LIBMPQ_ERROR_EXIST;
    return update_cleanup(update, 1);
}

static int32_t
update_copy_range(mpq_archive_s *archive, FILE *output, uint64_t offset, uint64_t size)
{
    uint8_t buffer[LIBMPQ_UPDATE_COPY_SIZE];

    while (size != 0) {
        size_t chunk = size < sizeof(buffer) ? (size_t)size : sizeof(buffer);
        int32_t result = libmpq__source_read_at(archive->source, offset, buffer, chunk);

        if (result != 0)
            return result;
        if (fwrite(buffer, 1, chunk, output) != chunk)
            return LIBMPQ_ERROR_WRITE;
        offset += chunk;
        size -= chunk;
    }
    return 0;
}

static int32_t
update_read_named(mpq_archive_s *archive, const char *name, uint8_t **data, size_t *size)
{
    mpq_stream_s *stream = NULL;
    libmpq__off_t length = 0;
    libmpq__off_t transferred = 0;
    uint8_t *bytes;
    int32_t result;

    *data = NULL;
    *size = 0;
    result = libmpq__stream_open_name(archive, name, &stream);
    if (result != 0)
        return result;
    result = libmpq__stream_size(stream, &length);
    if (result != 0 || length < 0 || (uint64_t)length > SIZE_MAX) {
        (void)libmpq__stream_close(stream);
        return result == 0 ? LIBMPQ_ERROR_SIZE : result;
    }
    bytes = malloc(length == 0 ? 1u : (size_t)length);
    if (bytes == NULL) {
        (void)libmpq__stream_close(stream);
        return LIBMPQ_ERROR_MALLOC;
    }
    result = libmpq__stream_read(stream, bytes, length, &transferred);
    if (result == 0 && transferred != length)
        result = LIBMPQ_ERROR_READ;
    if (libmpq__stream_close(stream) != 0 && result == 0)
        result = LIBMPQ_ERROR_CLOSE;
    if (result != 0) {
        free(bytes);
        return result;
    }
    *data = bytes;
    *size = (size_t)length;
    return 0;
}

static int32_t
update_listfile(
    mpq_archive_s *archive, const char *old_name, const char *new_name, uint8_t **data,
    size_t *size, uint32_t *index
)
{
    uint8_t *original = NULL;
    uint8_t *updated;
    size_t original_size = 0;
    size_t used = 0;
    size_t pos = 0;
    int32_t result;

    result = libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, index);
    if (result != 0)
        return result;
    result = update_read_named(archive, LIBMPQ_LISTFILE_NAME, &original, &original_size);
    if (result != 0)
        return result;
    if (original_size > SIZE_MAX - strlen(new_name == NULL ? "" : new_name) - 2u) {
        free(original);
        return LIBMPQ_ERROR_SIZE;
    }
    updated = malloc(original_size + strlen(new_name == NULL ? "" : new_name) + 2u);
    if (updated == NULL) {
        free(original);
        return LIBMPQ_ERROR_MALLOC;
    }
    while (pos < original_size) {
        size_t begin = pos;
        size_t length;
        char *name;
        uint8_t skip = 0;

        while (pos < original_size && original[pos] != '\n' && original[pos] != '\r')
            pos++;
        length = pos - begin;
        while (pos < original_size && (original[pos] == '\n' || original[pos] == '\r'))
            pos++;
        if (length == 0)
            continue;
        if (memchr(original + begin, 0, length) != NULL) {
            free(updated);
            free(original);
            return LIBMPQ_ERROR_FORMAT;
        }
        name = malloc(length + 1u);
        if (name == NULL) {
            free(updated);
            free(original);
            return LIBMPQ_ERROR_MALLOC;
        }
        memcpy(name, original + begin, length);
        name[length] = '\0';
        if (libmpq__crypto_hash_string(name, 0x100) ==
                libmpq__crypto_hash_string(old_name, 0x100) &&
            libmpq__crypto_hash_string(name, 0x200) == libmpq__crypto_hash_string(old_name, 0x200))
            skip = 1;
        if (libmpq__crypto_hash_string(name, 0x100) ==
                libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x100) &&
            libmpq__crypto_hash_string(name, 0x200) ==
                libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x200))
            skip = 1;
        free(name);
        if (!skip) {
            memcpy(updated + used, original + begin, length);
            used += length;
            updated[used++] = '\n';
        }
    }
    if (new_name != NULL) {
        size_t length = strlen(new_name);

        memcpy(updated + used, new_name, length + 1u);
        updated[used + length] = '\n';
        used += length + 1u;
    }
    free(original);
    *data = updated;
    *size = used;
    return 0;
}

static uint32_t
update_hash_slot(const mpq_archive_s *archive, const char *name, uint32_t block)
{
    uint32_t a = libmpq__crypto_hash_string(name, 0x100);
    uint32_t b = libmpq__crypto_hash_string(name, 0x200);
    uint32_t i;

    for (i = 0; i < archive->mpq_header.hash_table_count; i++) {
        const mpq_hash_s *entry = &archive->mpq_hash[i];

        if (entry->block_table_index == block && entry->hash_a == a && entry->hash_b == b)
            return i;
    }
    return UINT32_MAX;
}

/* Count live aliases without treating empty and deleted hash slots as references. */
static uint32_t
update_block_references(const mpq_archive_s *archive, uint32_t block)
{
    uint32_t references = 0;
    uint32_t i;

    for (i = 0; i < archive->mpq_header.hash_table_count; i++) {
        uint32_t index = archive->mpq_hash[i].block_table_index;

        if (index < archive->mpq_header.block_table_count && index == block)
            references++;
    }
    return references;
}

static uint8_t
update_reserved_name(const char *name)
{
    static const char *reserved[] = { LIBMPQ_ATTRIBUTES_NAME, LIBMPQ_LISTFILE_NAME,
                                      LIBMPQ_SIGNATURE_NAME };
    uint32_t a = libmpq__crypto_hash_string(name, 0x100);
    uint32_t b = libmpq__crypto_hash_string(name, 0x200);
    size_t i;

    for (i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++)
        if (a == libmpq__crypto_hash_string(reserved[i], 0x100) &&
            b == libmpq__crypto_hash_string(reserved[i], 0x200))
            return 1;
    return 0;
}

static void
update_delete_hash(mpq_hash_s *entry)
{
    entry->hash_a = 0;
    entry->hash_b = 0;
    entry->locale = 0;
    entry->platform = 0;
    entry->block_table_index = LIBMPQ_HASH_DELETED;
}

static int32_t
update_insert_hash(mpq_archive_s *archive, const char *name, const mpq_hash_s *original)
{
    uint32_t count = archive->mpq_header.hash_table_count;
    uint32_t start;
    uint32_t candidate = UINT32_MAX;
    uint32_t i;

    if (count == 0)
        return LIBMPQ_ERROR_FORMAT;
    start = libmpq__crypto_hash_string(name, 0) % count;
    for (i = 0; i < count; i++) {
        uint32_t slot = (start + i) % count;
        uint32_t index = archive->mpq_hash[slot].block_table_index;

        if (index == UINT32_MAX - 1u && candidate == UINT32_MAX)
            candidate = slot;
        if (index == UINT32_MAX) {
            if (candidate == UINT32_MAX)
                candidate = slot;
            break;
        }
    }
    if (candidate == UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    archive->mpq_hash[candidate] = *original;
    archive->mpq_hash[candidate].hash_a = libmpq__crypto_hash_string(name, 0x100);
    archive->mpq_hash[candidate].hash_b = libmpq__crypto_hash_string(name, 0x200);
    return 0;
}

static int32_t
update_encode(
    mpq_update_s *update, mpq_archive_s *archive, FILE *output, const char *name,
    const uint8_t *data, uint64_t size, const char *source_path, const char *old_name,
    const mpq_file_options_s *file_options, mpq_block_s *block, mpq_block_ex_s *block_ex,
    mpq_file_attributes_s *attributes, uint8_t *expected_md5, uint64_t *expected_size
)
{
    mpq_archive_create_options_s options = { 0, 1, 0, LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                             0 };
    mpq_archive_s *writer = NULL;
    mpq_archive_s *packed = NULL;
    mpq_writer_s *file_writer = NULL;
    mpq_stream_s *old_stream = NULL;
    mpq_stream_s *expected_stream = NULL;
    FILE *input = NULL;
    FILE *temporary_file = NULL;
    char *temporary = NULL;
    char *temporary_path = NULL;
    libmpq__off_t measured;
    uint8_t buffer[LIBMPQ_UPDATE_COPY_SIZE];
    uint64_t remaining;
    uint64_t position;
    mpq_md5_s md5;
    uint32_t crc = 0;
    uint8_t relocate_tables = 0;
    int32_t result;

    options.version = archive->mpq_header.version;
    options.sector_size = archive->block_size;
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-packed-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary,
        &temporary_file
    );
    if (result != 0)
        return result;
    temporary_path = update_working_path(update->working_path, temporary);
    if (temporary_path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    if (source_path != NULL) {
        input = libmpq__file_open(source_path, "rb");
        if (input == NULL) {
            result = LIBMPQ_ERROR_OPEN;
            goto done;
        }
        if (libmpq__file_seek(input, 0, SEEK_END) != 0 ||
            (measured = libmpq__file_tell(input)) < 0 ||
            libmpq__file_seek(input, 0, SEEK_SET) != 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto done;
        }
        size = (uint64_t)measured;
    } else if (old_name != NULL) {
        libmpq__off_t old_size = 0;

        result = libmpq__stream_open_name(archive, old_name, &old_stream);
        if (result != 0)
            goto done;
        result = libmpq__stream_size(old_stream, &old_size);
        if (result != 0 || old_size < 0) {
            result = result == 0 ? LIBMPQ_ERROR_SIZE : result;
            goto done;
        }
        size = (uint64_t)old_size;
    }
    if (size > UINT32_MAX || size > INT64_MAX || (data != NULL && size > SIZE_MAX)) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    result = libmpq__writer_archive_create_file(&writer, temporary_path, temporary_file, &options);
    temporary_file = NULL;
    if (result != 0)
        goto done;

    /*
     * output is plaintext (also for MPQE). Its current position is the copy
     * destination; the standalone staging archive starts at zero, so subtract
     * only the source archive's prefix. KEY must use this final relative
     * position, not the staging writer's independently reserved payload start.
     */
    if ((file_options->flags & LIBMPQ_FILE_FLAG_KEY) != 0) {
        libmpq__off_t staging = libmpq__file_tell(writer->fp);
        measured = libmpq__file_tell(output);
        if (staging < 0 || measured < 0 || measured < archive->archive_offset ||
            libmpq__file_seek(writer->fp, measured - archive->archive_offset, SEEK_SET) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto done;
        }
        relocate_tables = measured - archive->archive_offset < staging;
    }
    result =
        libmpq__writer_file_begin(writer, name, (libmpq__off_t)size, file_options, &file_writer);
    if (result != 0)
        goto done;
    if (expected_md5 != NULL ||
        (attributes != NULL && (attributes->flags & LIBMPQ_ATTRIBUTE_MD5) != 0))
        libmpq__md5_init(&md5);
    remaining = size;
    position = 0;
    while (remaining != 0) {
        size_t chunk = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        const uint8_t *bytes = buffer;

        if (input != NULL) {
            if (fread(buffer, 1, chunk, input) != chunk) {
                result = LIBMPQ_ERROR_READ;
                break;
            }
        } else if (old_stream != NULL) {
            libmpq__off_t transferred = 0;

            result = libmpq__stream_read(old_stream, buffer, (libmpq__off_t)chunk, &transferred);
            if (result != 0 || transferred != (libmpq__off_t)chunk) {
                if (result == 0)
                    result = LIBMPQ_ERROR_READ;
                break;
            }
        } else if (data != NULL) {
            bytes = data + position;
        } else {
            result = LIBMPQ_ERROR_EXIST;
            break;
        }
        result = libmpq__writer_file_write(file_writer, bytes, (libmpq__off_t)chunk);
        if (result != 0)
            break;
        if (attributes != NULL) {
            if ((attributes->flags & LIBMPQ_ATTRIBUTE_CRC32) != 0)
                crc = (uint32_t)crc32(crc, bytes, (uInt)chunk);
        }
        if (expected_md5 != NULL ||
            (attributes != NULL && (attributes->flags & LIBMPQ_ATTRIBUTE_MD5) != 0))
            libmpq__md5_update(&md5, bytes, chunk);
        remaining -= chunk;
        position += chunk;
    }
    if (result != 0)
        goto done;
    result = libmpq__writer_file_finish(file_writer);
    file_writer = NULL;
    if (result != 0)
        goto done;
    if (attributes != NULL) {
        attributes->crc32 = crc;
        attributes->patch_bit = 0;
    }
    if (expected_md5 != NULL ||
        (attributes != NULL && (attributes->flags & LIBMPQ_ATTRIBUTE_MD5) != 0)) {
        uint8_t digest[16];

        libmpq__md5_final(&md5, digest);
        if (attributes != NULL && (attributes->flags & LIBMPQ_ATTRIBUTE_MD5) != 0)
            memcpy(attributes->md5, digest, sizeof(digest));
        if (expected_md5 != NULL)
            memcpy(expected_md5, digest, sizeof(digest));
    }
    if (expected_size != NULL)
        *expected_size = size;

    /* Compact inputs can put that payload inside the staging writer's reserved tables. */
    if (relocate_tables) {
        uint64_t hash_bytes = (uint64_t)writer->write_hash_capacity * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
        uint64_t block_bytes = (uint64_t)writer->write_capacity * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
        uint64_t extra_bytes =
            writer->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO
                ? (uint64_t)writer->write_capacity * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE
                : 0;
        if (libmpq__file_seek(writer->fp, 0, SEEK_END) < 0 ||
            (measured = libmpq__file_tell(writer->fp)) < 0) {
            result = LIBMPQ_ERROR_SEEK;
            goto done;
        }
        if (hash_bytes + block_bytes + extra_bytes > UINT32_MAX ||
            (uint64_t)measured > UINT32_MAX - (hash_bytes + block_bytes + extra_bytes)) {
            result = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        writer->mpq_header.hash_table_offset = (uint32_t)measured;
        writer->mpq_header.block_table_offset = (uint32_t)((uint64_t)measured + hash_bytes);
        if (extra_bytes != 0)
            writer->mpq_header_ex.extended_offset = (uint64_t)measured + hash_bytes + block_bytes;
    }
    result = libmpq__archive_close(writer);
    writer = NULL;
    if (result != 0)
        goto done;
    result = libmpq__archive_open(&packed, temporary_path, 0);
    if (result != 0)
        goto done;
    if (expected_md5 != NULL &&
        ((file_options->compression_first | file_options->compression_next) &
         (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO)) != 0) {
        result = libmpq__stream_open_name(packed, name, &expected_stream);
        if (result != 0)
            goto done;
        libmpq__md5_init(&md5);
        remaining = size;
        while (remaining != 0) {
            size_t chunk = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
            libmpq__off_t transferred = 0;

            result =
                libmpq__stream_read(expected_stream, buffer, (libmpq__off_t)chunk, &transferred);
            if (result != 0 || transferred != (libmpq__off_t)chunk) {
                if (result == 0)
                    result = LIBMPQ_ERROR_READ;
                goto done;
            }
            libmpq__md5_update(&md5, buffer, chunk);
            remaining -= chunk;
        }
        libmpq__md5_final(&md5, expected_md5);
        result = libmpq__stream_close(expected_stream);
        expected_stream = NULL;
        if (result != 0)
            goto done;
    }
    measured = libmpq__file_tell(output);
    if (measured < 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto done;
    }
    if ((uint64_t)measured < (uint64_t)archive->archive_offset) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    position = (uint64_t)measured - (uint64_t)archive->archive_offset;
    if (position > UINT32_MAX && archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    *block = packed->mpq_block[0];
    block->offset = (uint32_t)position;
    block_ex->offset_high = (uint16_t)(position >> 32);
    result = update_copy_range(
        packed, output, packed->mpq_block[0].offset, packed->mpq_block[0].packed_size
    );

done:
    if (file_writer != NULL)
        libmpq__writer_file_abort(file_writer);
    if (writer != NULL)
        (void)libmpq__archive_close(writer);
    if (packed != NULL)
        (void)libmpq__archive_close(packed);
    if (old_stream != NULL)
        (void)libmpq__stream_close(old_stream);
    if (expected_stream != NULL)
        (void)libmpq__stream_close(expected_stream);
    if (input != NULL)
        (void)fclose(input);
    if (temporary_file != NULL)
        (void)fclose(temporary_file);
    if (temporary != NULL)
        (void)libmpq__directory_remove(update->directory, temporary);
    free(temporary_path);
    free(temporary);
    return result;
}

static int32_t
update_write_tables(mpq_archive_s *archive, FILE *output, uint64_t *extent)
{
    uint8_t header[LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE] = { 0 };
    mpq_header_s wire_header;
    mpq_header_ex_s wire_ex;
    int32_t result;
    uint8_t *raw;
    uint64_t hash_offset;
    uint64_t block_offset;
    uint64_t block_ex_offset = 0;
    uint64_t end;
    uint64_t archive_offset = (uint64_t)archive->archive_offset;
    libmpq__off_t measured;
    size_t bytes;
    uint32_t i;

    measured = libmpq__file_tell(output);
    if (measured < 0 || (uint64_t)measured < archive_offset)
        return LIBMPQ_ERROR_SEEK;
    end = (uint64_t)measured - archive_offset;
    if (end > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    hash_offset = end;
    bytes = (size_t)archive->mpq_header.hash_table_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    raw = malloc(bytes == 0 ? 1u : bytes);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__hash_table_encode(
        archive->mpq_hash, archive->mpq_header.hash_table_count, raw, bytes
    );
    if (result < 0) {
        free(raw);
        return result;
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    if (fwrite(raw, 1, bytes, output) != bytes) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);
    measured = libmpq__file_tell(output);
    if (measured < 0 || (uint64_t)measured < archive_offset)
        return LIBMPQ_ERROR_SEEK;
    block_offset = (uint64_t)measured - archive_offset;
    bytes = (size_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    raw = malloc(bytes == 0 ? 1u : bytes);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = libmpq__block_table_encode(
        archive->mpq_block, archive->mpq_header.block_table_count, raw, bytes
    );
    if (result < 0) {
        free(raw);
        return result;
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(block table)", 0x300)
    );
    if (fwrite(raw, 1, bytes, output) != bytes) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        measured = libmpq__file_tell(output);
        if (measured < 0 || (uint64_t)measured < archive_offset)
            return LIBMPQ_ERROR_SEEK;
        block_ex_offset = (uint64_t)measured - archive_offset;
        for (i = 0; i < archive->mpq_header.block_table_count; i++) {
            uint8_t word[2];

            result =
                libmpq__block_ex_table_encode(&archive->mpq_block_ex[i], 1, word, sizeof(word));
            if (result < 0)
                return result;
            if (fwrite(word, 1, sizeof(word), output) != sizeof(word))
                return LIBMPQ_ERROR_WRITE;
        }
    }
    measured = libmpq__file_tell(output);
    if (measured < 0 || (uint64_t)measured < archive_offset)
        return LIBMPQ_ERROR_SEEK;
    end = (uint64_t)measured - archive_offset;
    if (end > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    wire_header = archive->mpq_header;
    wire_header.mpq_magic = LIBMPQ_HEADER;
    wire_header.archive_size = (uint32_t)end;
    wire_header.hash_table_offset = (uint32_t)hash_offset;
    wire_header.block_table_offset = (uint32_t)block_offset;
    result = libmpq__header_encode(&wire_header, header, sizeof(header));
    if (result < 0)
        return result;
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        wire_ex.extended_offset = block_ex_offset;
        wire_ex.hash_table_offset_high = (uint16_t)(hash_offset >> 32);
        wire_ex.block_table_offset_high = (uint16_t)(block_offset >> 32);
        result = libmpq__header_ex_encode(
            &wire_ex, header + LIBMPQ_HEADER_WIRE_SIZE, LIBMPQ_HEADER_EX_WIRE_SIZE
        );
        if (result < 0)
            return result;
    }
    if (libmpq__file_seek(output, archive_offset, SEEK_SET) != 0 ||
        fwrite(header, 1, archive->mpq_header.header_size, output) !=
            archive->mpq_header.header_size ||
        libmpq__file_seek(output, archive_offset + end, SEEK_SET) != 0)
        return LIBMPQ_ERROR_WRITE;
    *extent = end;
    return 0;
}

/* Decode a complete member for pre-rename capture or rebuilt-copy validation. */
static int32_t
update_validate_member(
    mpq_archive_s *archive, const char *name, const uint8_t *expected_md5, uint64_t expected_size,
    uint8_t compare_contents, uint8_t *actual_md5, uint64_t *actual_size
)
{
    mpq_md5_s md5;
    uint8_t digest[16];
    uint8_t *data = NULL;
    libmpq__off_t size = 0;
    libmpq__off_t transferred = 0;
    uint32_t number;
    int32_t result;

    result = libmpq__file_number(archive, name, &number);
    if (result != 0)
        return result;
    result = libmpq__file_size_unpacked(archive, number, &size);
    if (result != 0)
        return result;
    if (size < 0 || (uint64_t)size > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    if (compare_contents && (uint64_t)size != expected_size)
        return LIBMPQ_ERROR_READ;
    data = malloc(size == 0 ? 1u : (size_t)size);
    if (data == NULL)
        return LIBMPQ_ERROR_MALLOC;

    if ((archive->mpq_entry[archive->mpq_map[number].entry_index].flags & LIBMPQ_FLAG_ENCRYPTED) !=
        0) {
        result = libmpq__reader_offsets_acquire(archive, number, name);
        if (result == 0) {
            result = libmpq__file_read(archive, number, data, size, &transferred);
            update_result(&result, libmpq__reader_offsets_release(archive, number));
        }
    } else {
        result = libmpq__file_read(archive, number, data, size, &transferred);
    }
    if (result == 0 && transferred != size)
        result = LIBMPQ_ERROR_READ;
    if (result == 0 && (compare_contents || actual_md5 != NULL)) {
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, data, (size_t)size);
        libmpq__md5_final(&md5, digest);
        if (compare_contents && memcmp(digest, expected_md5, sizeof(digest)) != 0)
            result = LIBMPQ_ERROR_READ;
        if (result == 0 && actual_md5 != NULL)
            memcpy(actual_md5, digest, sizeof(digest));
    }
    if (result == 0 && actual_size != NULL)
        *actual_size = (uint64_t)size;
    free(data);
    return result;
}

/* Compare complete names using HET's locale-independent case/separator rules. */
static int
update_names_equal(const char *first, const char *second)
{
    do {
        uint8_t a = (uint8_t)*first++;
        uint8_t b = (uint8_t)*second++;
        if (a >= 'A' && a <= 'Z')
            a = (uint8_t)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z')
            b = (uint8_t)(b + ('a' - 'A'));
        if (a == '/')
            a = '\\';
        if (b == '/')
            b = '\\';
        if (a != b)
            return 0;
        if (a == 0)
            return 1;
    } while (1);
}

/* Release a private list of owned spellings, independent of canonical row numbers. */
static void
update_free_names(char **names, uint32_t count)
{
    if (names == NULL)
        return;
    for (uint32_t i = 0; i < count; ++i)
        free(names[i]);
    free(names);
}

/*
 * Revalidate strings against the candidate before consuming the previous stage.
 * Existence does not certify alias/key compatibility: compaction still performs
 * its full identity/provenance checks. Exact bytes distinguish classic slashes.
 */
static int32_t
update_prepare_names(
    mpq_update_s *update, mpq_archive_s *candidate, char *const *supplied, uint32_t supplied_count,
    const char *const *filenames, uint32_t filename_count, const char *first, const char *second,
    char ***out, uint32_t *out_count
)
{
    uint64_t collected_end = (uint64_t)update->known_count + supplied_count;
    uint64_t filenames_end = collected_end + filename_count;
    uint64_t capacity = filenames_end + 2;
    uint32_t count = 0;
    char **names;
    void *(*allocate)(size_t) = update->ops->allocate_names;
    int32_t result = 0;

    *out = NULL;
    *out_count = 0;
    if (capacity > UINT32_MAX || capacity > SIZE_MAX / sizeof(*names))
        return LIBMPQ_ERROR_SIZE;
    if (allocate == NULL)
        allocate = malloc;
    names = allocate((size_t)capacity * sizeof(*names));
    if (names == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (uint64_t i = 0; i < capacity; ++i) {
        const char *name = i < update->known_count ? update->known_names[i]
                           : i < collected_end     ? supplied[i - update->known_count]
                           : i < filenames_end     ? filenames[i - collected_end]
                           : i == filenames_end    ? first
                                                   : second;
        uint32_t number;
        uint32_t existing;
        if (name == NULL)
            continue;
        if (i >= collected_end && i < filenames_end) {
            mpq_file_identity_s identity;
            result = libmpq__file_identity(candidate, name, 0, &identity);
        } else
            result = libmpq__file_number(candidate, name, &number);
        if (result == LIBMPQ_ERROR_EXIST) {
            result = 0;
            continue;
        }
        if (result != 0)
            break;
        for (existing = 0; existing < count; ++existing)
            if (strcmp(names[existing], name) == 0)
                break;
        if (existing != count)
            continue;
        size_t size = strlen(name);
        if (size == SIZE_MAX) {
            result = LIBMPQ_ERROR_SIZE;
            break;
        }
        names[count] = allocate(size + 1);
        if (names[count] == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            break;
        }
        memcpy(names[count++], name, size + 1);
    }
    if (result != 0) {
        update_free_names(names, count);
        return result;
    }
    *out = names;
    *out_count = count;
    return 0;
}

/* Install only after successful candidate adoption; ownership transfers exactly once. */
static void
update_adopt_names(mpq_update_s *update, char ***names, uint32_t count)
{
    update_free_names(update->known_names, update->known_count);
    update->known_names = *names;
    update->known_count = count;
    *names = NULL;
}

/* Resolve names to public file numbers; never derive names from table hashes. */
static int32_t
update_record_name(mpq_archive_s *archive, char **names, const char *name)
{
    uint32_t number;
    int32_t result = libmpq__file_number(archive, name, &number);
    if (result == LIBMPQ_ERROR_EXIST)
        return 0;
    if (result != 0)
        return result;
    if (number >= archive->files)
        return LIBMPQ_ERROR_FORMAT;
    if (names[number] != NULL && !update_names_equal(names[number], name))
        return LIBMPQ_ERROR_FORMAT;
    if (names[number] == NULL) {
        names[number] = malloc(strlen(name) + 1);
        if (names[number] == NULL)
            return LIBMPQ_ERROR_MALLOC;
        memcpy(names[number], name, strlen(name) + 1);
    }
    return 0;
}

static int32_t
update_collect_names(mpq_update_s *update, mpq_archive_s *archive, const char *target, char ***out)
{
    static const char *special[] = { LIBMPQ_LISTFILE_NAME, LIBMPQ_ATTRIBUTES_NAME,
                                     LIBMPQ_SIGNATURE_NAME };
    char **names;
    uint8_t *list = NULL;
    size_t size = 0;
    size_t pos = 0;
    uint32_t number;
    int32_t result;
    *out = NULL;
    if (archive->files == UINT32_MAX || ((uint64_t)archive->files + 1) * sizeof(*names) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    names = calloc((size_t)archive->files + 1, sizeof(*names));
    if (names == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = 0;
    for (size_t i = 0; result == 0 && i < sizeof(special) / sizeof(special[0]); ++i)
        result = update_record_name(archive, names, special[i]);
    for (uint32_t i = 0; result == 0 && i < update->known_count; ++i)
        if (update->known_names[i] != NULL)
            result = update_record_name(archive, names, update->known_names[i]);
    if (result == 0 && libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0)
        result = update_read_named(archive, LIBMPQ_LISTFILE_NAME, &list, &size);
    while (result == 0 && pos < size) {
        size_t begin = pos;
        char *name;
        while (pos < size && list[pos] != '\r' && list[pos] != '\n')
            ++pos;
        if (pos == begin) {
            ++pos;
            continue;
        }
        if (memchr(list + begin, 0, pos - begin) != NULL) {
            result = LIBMPQ_ERROR_FORMAT;
            break;
        }
        name = malloc(pos - begin + 1);
        if (name == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            break;
        }
        memcpy(name, list + begin, pos - begin);
        name[pos - begin] = '\0';
        result = libmpq__file_number(archive, name, &number);
        if (result == LIBMPQ_ERROR_EXIST)
            result = LIBMPQ_ERROR_FORMAT;
        if (result == 0)
            result = update_record_name(archive, names, name);
        free(name);
    }

    /* Known source spellings win over a caller's equivalent slash/case spelling. */
    if (result == 0)
        result = update_record_name(archive, names, target);
    free(list);
    if (result != 0) {
        for (uint32_t i = 0; i < archive->files; ++i)
            free(names[i]);
        free(names);
    } else {
        *out = names;
    }
    return result;
}

/* Resolve the exact hash row, then constrain extended mutations to one-to-one names. */
static int32_t
update_resolve_identity(
    mpq_archive_s *archive, mpq_update_action_e action, const char *name, const char *new_name,
    const mpq_file_options_s *options, mpq_update_identity_s *target
)
{
    mpq_file_identity_s identity;
    const mpq_entry_s *entry;
    uint32_t hashes[3];
    uint32_t unused;
    int32_t result = libmpq__file_number_from_identity(
        archive, name, target->locale, target->platform, &target->number
    );
    if (result != 0)
        return result;
    entry = &archive->mpq_entry[archive->mpq_map[target->number].entry_index];
    target->slot = UINT32_MAX;
    libmpq__file_hash(name, &hashes[0], &hashes[1], &hashes[2]);
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; ++i) {
        const mpq_hash_s *hash = &archive->mpq_hash[i];
        if (hash->block_table_index < LIBMPQ_HASH_DELETED && hash->hash_a == hashes[1] &&
            hash->hash_b == hashes[2] && hash->locale == target->locale &&
            hash->platform == target->platform) {
            if (target->slot != UINT32_MAX ||
                hash->block_table_index != entry->classic_source_index)
                return LIBMPQ_ERROR_FORMAT;
            target->slot = i;
        }
    }
    if (options != NULL &&
        (options->locale != target->locale || options->platform != target->platform))
        return LIBMPQ_ERROR_FORMAT;
    if (action == LIBMPQ_UPDATE_RENAME && update_names_equal(name, new_name))
        return 0;
    if (action == LIBMPQ_UPDATE_CHANGE_IDENTITY) {
        if (target->locale == target->new_locale && target->platform == target->new_platform)
            return 0;
        result = libmpq__file_number_from_identity(
            archive, name, target->new_locale, target->new_platform, &unused
        );
        if (result != LIBMPQ_ERROR_EXIST)
            return result == 0 ? LIBMPQ_ERROR_EXIST : result;
        if (target->slot == UINT32_MAX || update_reserved_name(name))
            return LIBMPQ_ERROR_FORMAT;

        /* A matching opaque row beyond the probe chain cannot be assumed absent. */
        for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; ++i) {
            const mpq_hash_s *hash = &archive->mpq_hash[i];
            if (hash->block_table_index < LIBMPQ_HASH_DELETED && hash->hash_a == hashes[1] &&
                hash->hash_b == hashes[2] && hash->locale == target->new_locale &&
                hash->platform == target->new_platform)
                return LIBMPQ_ERROR_FORMAT;
        }
    }

    result = libmpq__file_identity(archive, name, 1, &identity);
    if (result != 0 && result != LIBMPQ_ERROR_EXIST)
        return result;
    target->keep_name = result == 0;
    if (archive->het_data != NULL) {
        if (target->keep_name)
            return LIBMPQ_ERROR_FORMAT;
        result = libmpq__file_identity(archive, name, 0, &identity);
        if (result != 0)
            return result;
        if (!(identity.flags & LIBMPQ_IDENTITY_BET) ||
            ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0 &&
             (target->slot == UINT32_MAX ||
              update_block_references(archive, entry->classic_source_index) != 1)))
            return LIBMPQ_ERROR_FORMAT;
    }
    if (target->slot != UINT32_MAX)
        target->shared = update_block_references(archive, entry->classic_source_index) > 1;
    if (action != LIBMPQ_UPDATE_RENAME)
        return 0;
    result = libmpq__file_number_from_identity(
        archive, new_name, target->locale, target->platform, &unused
    );
    if (result != LIBMPQ_ERROR_EXIST)
        return result == 0 ? LIBMPQ_ERROR_EXIST : result;
    if (archive->het_data != NULL) {
        result = libmpq__file_identity(archive, new_name, 0, &identity);
        if (result != LIBMPQ_ERROR_EXIST)
            return result == 0 ? LIBMPQ_ERROR_EXIST : result;
    }
    libmpq__file_hash(new_name, &hashes[0], &hashes[1], &hashes[2]);
    for (uint32_t i = 0; i < archive->mpq_header.hash_table_count; ++i) {
        const mpq_hash_s *hash = &archive->mpq_hash[i];
        if (hash->block_table_index < LIBMPQ_HASH_DELETED && hash->hash_a == hashes[1] &&
            hash->hash_b == hashes[2] && hash->locale == target->locale &&
            hash->platform == target->platform)
            return LIBMPQ_ERROR_FORMAT;
    }
    return 0;
}

/* Validate available row metadata before deciding whether a timestamp is a no-op. */
static int32_t
update_resolve_timestamp(
    mpq_archive_s *archive, const char *name, mpq_update_identity_s *target, uint8_t *unchanged
)
{
    mpq_file_attributes_s attributes;
    mpq_file_identity_s identity;
    const mpq_entry_s *entry;
    uint32_t selected;
    int32_t result;

    *unchanged = 0;
    result = target->timestamp_exact
                 ? libmpq__file_number_from_identity(
                       archive, name, target->locale, target->platform, &selected
                   )
                 : libmpq__file_number(archive, name, &selected);
    if (result != 0)
        return result;

    /* Enumeration validates contradictory tuples and filename-specific provenance. */
    for (uint32_t ordinal = 0;; ++ordinal) {
        result = libmpq__file_identity(archive, name, ordinal, &identity);
        if (result != 0)
            return result == LIBMPQ_ERROR_EXIST ? LIBMPQ_ERROR_FORMAT : result;
        if (identity.file_number == selected &&
            (!target->timestamp_exact ||
             (identity.locale == target->locale && identity.platform == target->platform)))
            break;
        if (ordinal == UINT32_MAX)
            return LIBMPQ_ERROR_FORMAT;
    }
    entry = &archive->mpq_entry[archive->mpq_map[selected].entry_index];
    target->slot = UINT32_MAX;
    uint32_t hashes[3];
    libmpq__file_hash(name, &hashes[0], &hashes[1], &hashes[2]);
    for (uint32_t slot = 0; (identity.flags & LIBMPQ_IDENTITY_CLASSIC) != 0 &&
                            slot < archive->mpq_header.hash_table_count;
         ++slot) {
        const mpq_hash_s *row = &archive->mpq_hash[slot];
        if (row->block_table_index < LIBMPQ_HASH_DELETED && row->hash_a == hashes[1] &&
            row->hash_b == hashes[2] && row->locale == identity.locale &&
            row->platform == identity.platform) {
            if (target->slot != UINT32_MAX || row->block_table_index != entry->classic_source_index)
                return LIBMPQ_ERROR_FORMAT;
            target->slot = slot;
        }
    }
    if ((identity.flags & LIBMPQ_IDENTITY_CLASSIC) != 0 && target->slot == UINT32_MAX)
        return LIBMPQ_ERROR_FORMAT;
    result = libmpq__file_attributes(archive, selected, &attributes);
    if (result != 0)
        return result == LIBMPQ_ERROR_EXIST ? LIBMPQ_ERROR_FORMAT : result;
    if (!(attributes.flags & LIBMPQ_ATTRIBUTE_FILETIME))
        return LIBMPQ_ERROR_FORMAT;
    target->number = selected;
    target->locale = identity.locale;
    target->platform = identity.platform;
    if (attributes.filetime == target->filetime) {
        *unchanged = 1;
        return 0;
    }
    if (update_block_references(archive, entry->classic_source_index) != 1)
        return LIBMPQ_ERROR_FORMAT;
    return update_resolve_identity(archive, LIBMPQ_UPDATE_TIMESTAMP, name, NULL, NULL, target);
}

/* Hash an exact logical member with bounded storage, never first-hit name lookup. */
static int32_t
update_exact_digest(
    mpq_archive_s *archive, const char *name, const mpq_update_identity_s *target,
    uint8_t digest[16], uint64_t *size
)
{
    mpq_stream_s *stream = NULL;
    uint8_t buffer[LIBMPQ_UPDATE_COPY_SIZE];
    mpq_md5_s md5;
    int32_t result =
        libmpq__stream_open_name_identity(archive, name, target->locale, target->platform, &stream);
    *size = 0;
    libmpq__md5_init(&md5);
    while (result == 0) {
        libmpq__off_t received = 0;
        result = libmpq__stream_read(stream, buffer, sizeof(buffer), &received);
        if (result != 0 || received == 0)
            break;
        if ((uint64_t)received > UINT64_MAX - *size) {
            result = LIBMPQ_ERROR_SIZE;
            break;
        }
        *size += (uint64_t)received;
        libmpq__md5_update(&md5, buffer, (size_t)received);
    }
    if (stream != NULL)
        update_result(&result, libmpq__stream_close(stream));
    if (result == 0)
        libmpq__md5_final(&md5, digest);
    return result;
}

/* Capture a replacement path's expected content before any candidate serialization. */
static int32_t
update_path_digest(const char *path, uint8_t digest[16], uint64_t *size)
{
    FILE *file = libmpq__file_open(path, "rb");
    uint8_t buffer[LIBMPQ_UPDATE_COPY_SIZE];
    mpq_md5_s md5;
    int32_t result = 0;
    if (file == NULL)
        return LIBMPQ_ERROR_OPEN;
    *size = 0;
    libmpq__md5_init(&md5);
    for (;;) {
        size_t received = fread(buffer, 1, sizeof(buffer), file);
        if (*size > UINT64_MAX - received) {
            result = LIBMPQ_ERROR_SIZE;
            break;
        }
        *size += received;
        libmpq__md5_update(&md5, buffer, received);
        if (received != sizeof(buffer)) {
            if (ferror(file))
                result = LIBMPQ_ERROR_READ;
            break;
        }
    }
    if (fclose(file) != 0)
        update_result(&result, LIBMPQ_ERROR_CLOSE);
    if (result == 0)
        libmpq__md5_final(&md5, digest);
    return result;
}

/* Redirect just one classic identity to a completed output row, preserving all aliases. */
static int32_t
update_detach_identity(
    mpq_archive_s *writer, const mpq_update_identity_s *target, mpq_update_action_e action,
    const char *new_name
)
{
    mpq_writer_identity_s *identity = writer->write_identity;
    mpq_hash_s hash;
    uint32_t *rows;
    if (target->slot == UINT32_MAX)
        return 0;
    if (action == LIBMPQ_UPDATE_CHANGE_IDENTITY) {
        identity->classic[target->slot].locale = target->new_locale;
        identity->classic[target->slot].platform = target->new_platform;
        return 0;
    }
    hash = identity->classic[target->slot];
    update_delete_hash(&identity->classic[target->slot]);
    if (action == LIBMPQ_UPDATE_REMOVE)
        return 0;
    if (identity->block_count == UINT32_MAX ||
        ((uint64_t)identity->block_count + 1) * sizeof(*rows) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    rows = realloc(identity->classic_rows, ((size_t)identity->block_count + 1) * sizeof(*rows));
    if (rows == NULL)
        return LIBMPQ_ERROR_MALLOC;
    identity->classic_rows = rows;
    rows[identity->block_count] = writer->write_next_block - 1;
    hash.block_table_index = identity->block_count++;
    if (action == LIBMPQ_UPDATE_RENAME) {
        mpq_archive_s table = { 0 };
        table.mpq_header.hash_table_count = identity->classic_count;
        table.mpq_hash = identity->classic;
        return update_insert_hash(&table, new_name, &hash);
    }
    identity->classic[target->slot] = hash;
    return 0;
}

/* Reopen validation checks identities and exact stored bytes, without naming opaque entries. */
static int32_t
update_check_unknowns(
    mpq_archive_s *source, mpq_archive_s *check, char **names, const uint32_t *rows,
    uint64_t *hashes, uint32_t attribute_flags, uint32_t ignored_slot,
    const mpq_update_identity_s *timestamp
)
{
    uint8_t before[LIBMPQ_UPDATE_COPY_SIZE];
    uint8_t after[LIBMPQ_UPDATE_COPY_SIZE];
    uint32_t *unknown_by_row = NULL;
    const uint8_t extended = check->het_data != NULL;
    int32_t result = LIBMPQ_ERROR_FORMAT;
    if (extended) {
        uint32_t count = check->mpq_bet.header.entry_count;
        if ((uint64_t)count * sizeof(*unknown_by_row) > SIZE_MAX)
            return LIBMPQ_ERROR_SIZE;
        unknown_by_row = malloc((size_t)count * sizeof(*unknown_by_row));
        if (unknown_by_row == NULL)
            return LIBMPQ_ERROR_MALLOC;
        for (uint32_t i = 0; i < count; ++i)
            unknown_by_row[i] = UINT32_MAX;
    }
    for (uint32_t i = 0; i < source->files; ++i) {
        const mpq_entry_s *old = &source->mpq_entry[source->mpq_map[i].entry_index];
        const mpq_entry_s *entry;
        uint32_t index;
        uint32_t mismatch;
        if (names[i] != NULL)
            continue;
        if (extended) {
            if (rows[i] >= check->mpq_bet.header.entry_count ||
                libmpq__entry_index_from_bet(check, rows[i], &index) != 0)
                goto done;
            unknown_by_row[rows[i]] = i;
        } else if (libmpq__entry_index_from_classic(check, rows[i], &index) != 0)
            goto done;
        entry = &check->mpq_entry[index];
        if (entry->source_mask != old->source_mask || entry->offset != old->offset ||
            entry->packed_size != old->packed_size || entry->unpacked_size != old->unpacked_size ||
            entry->flags != old->flags || entry->file_number >= check->files ||
            libmpq__reader_validate_payload_range(check, index, 0, entry->packed_size) != 0)
            goto done;
        result = libmpq__reader_validate_payload_range(
            source, source->mpq_map[i].entry_index, 0, old->packed_size
        );
        if (result != 0)
            goto done;
        if (source->archive_offset < 0 || check->archive_offset < 0 ||
            old->offset > (uint64_t)INT64_MAX - (uint64_t)source->archive_offset ||
            entry->offset > (uint64_t)INT64_MAX - (uint64_t)check->archive_offset ||
            old->packed_size >
                (uint64_t)INT64_MAX - (uint64_t)source->archive_offset - old->offset ||
            entry->packed_size >
                (uint64_t)INT64_MAX - (uint64_t)check->archive_offset - entry->offset) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        uint64_t source_position = (uint64_t)source->archive_offset + old->offset;
        uint64_t candidate_position = (uint64_t)check->archive_offset + entry->offset;
        result = LIBMPQ_ERROR_FORMAT;
        for (uint64_t offset = 0; offset < old->packed_size;) {
            size_t size = old->packed_size - offset < sizeof(before)
                              ? (size_t)(old->packed_size - offset)
                              : sizeof(before);
            if (libmpq__source_read_at(source->source, source_position + offset, before, size) !=
                    0 ||
                libmpq__source_read_at(check->source, candidate_position + offset, after, size) !=
                    0 ||
                memcmp(before, after, size) != 0) {
                result = LIBMPQ_ERROR_READ;
                goto done;
            }
            offset += size;
        }
        if (libmpq__file_verify(check, entry->file_number, LIBMPQ_VERIFY_RAW_MD5, &mismatch) != 0 ||
            mismatch != 0) {
            result = LIBMPQ_ERROR_READ;
            goto done;
        }
        if (attribute_flags != 0) {
            mpq_file_attributes_s a;
            mpq_file_attributes_s b;
            if (libmpq__file_attributes(source, i, &a) != 0 ||
                libmpq__file_attributes(check, entry->file_number, &b) != 0)
                goto done;
            if (timestamp != NULL && i == timestamp->number)
                a.filetime = timestamp->filetime;
            if (a.flags != b.flags || a.crc32 != b.crc32 || a.filetime != b.filetime ||
                a.patch_bit != b.patch_bit || memcmp(a.md5, b.md5, sizeof(a.md5)) != 0)
                goto done;
        }
    }
    for (uint32_t slot = 0; slot < source->mpq_header.hash_table_count; ++slot) {
        const mpq_hash_s *old = &source->mpq_hash[slot];
        const mpq_hash_s *hash;
        uint32_t index;
        uint32_t number;
        if (slot == ignored_slot || old->block_table_index >= LIBMPQ_HASH_DELETED)
            continue;
        if (libmpq__entry_index_from_classic(source, old->block_table_index, &index) != 0)
            goto done;
        number = source->mpq_entry[index].file_number;
        if (number >= source->files || names[number] != NULL)
            continue;
        if (slot >= check->mpq_header.hash_table_count)
            goto done;
        hash = &check->mpq_hash[slot];
        if (hash->hash_a != old->hash_a || hash->hash_b != old->hash_b ||
            hash->locale != old->locale || hash->platform != old->platform ||
            hash->block_table_index != rows[number])
            goto done;
    }
    if (extended) {
        for (uint32_t slot = 0; slot < check->mpq_het.header.total_count; ++slot) {
            uint64_t row;
            uint64_t low;
            uint32_t number;
            if (check->mpq_het.name_hash1[slot] == LIBMPQ_HET_SLOT_FREE)
                continue;
            if (libmpq__het_slot_index(&check->mpq_het, slot, &row) != 0 ||
                row >= check->mpq_bet.header.entry_count)
                goto done;
            number = unknown_by_row[row];
            if (number == UINT32_MAX)
                continue;
            if (libmpq__bet_name_hash2(&check->mpq_bet, row, &low) != 0 ||
                hashes[number] != (((uint64_t)check->mpq_het.name_hash1[slot] << 56) | low))
                goto done;
            hashes[number] = 0;
        }
        for (uint32_t i = 0; i < source->files; ++i)
            if (names[i] == NULL && hashes[i] != 0)
                goto done;
    }
    result = 0;
done:
    free(unknown_by_row);
    return result;
}

/* Shared completed-MPQ assembly preserves origins without changing writer coordinates. */
static int32_t update_open_candidate(
    mpq_update_s *update, mpq_archive_s *source, const mpq_prefix_info_s *prefix, char **name,
    char **path, mpq_archive_s **candidate
);

/* Rebuild named logical entries using the ordinary writer and transaction publication. */
static int32_t
update_rebuild_named(
    mpq_update_s *update, mpq_archive_s **source, mpq_update_action_e action, const char *old_name,
    const char *new_name, const uint8_t *data, libmpq__off_t size, const char *source_path,
    const mpq_file_options_s *replacement_options, const mpq_update_identity_s *exact
)
{
    mpq_archive_s *archive = *source;
    mpq_archive_s *writer = NULL;
    mpq_archive_s *check = NULL;
    mpq_archive_create_options_s create = { archive->mpq_header.version, 0, 0, 0, 0 };
    char **names = NULL;
    uint32_t *preserved_rows = NULL;
    uint64_t *preserved_hashes = NULL;
    uint8_t incomplete = 0;
    uint8_t preserve_listfile = 0;
    char *temporary = NULL;
    char *path = NULL;
    FILE *file = NULL;
    uint32_t target = UINT32_MAX;
    uint32_t count = archive->files;
    uint32_t attribute_flags = 0;
    uint32_t unused;
    uint32_t special_numbers[3] = { UINT32_MAX, UINT32_MAX, UINT32_MAX };
    static const char *special_names[] = { LIBMPQ_LISTFILE_NAME, LIBMPQ_ATTRIBUTES_NAME,
                                           LIBMPQ_SIGNATURE_NAME };
    uint8_t expected_digest[16] = { 0 };
    uint64_t expected_size = 0;
    uint8_t *list_data = NULL;
    size_t list_size = 0;
    char **prepared_names = NULL;
    uint32_t prepared_count = 0;
    int32_t result;
    uint64_t extent = libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);

    mpq_prefix_info_s prefix;
    result = libmpq__reader_archive_prefix_info(archive, &prefix);
    if (result != 0)
        return result;

    /* Preserve supported prefixes; unrelated trailers must not be silently discarded. */
    if (prefix.origin > archive->file_size || extent > archive->file_size - prefix.origin ||
        extent > (uint64_t)INT64_MAX - prefix.origin ||
        archive->mpq_header.header_size >
            (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR
                 ? LIBMPQ_HEADER_V4_WIRE_SIZE
                 : LIBMPQ_HEADER_V3_WIRE_SIZE))
        return LIBMPQ_ERROR_FORMAT;
    uint64_t end = prefix.origin + extent;
    if (archive->file_size != end) {
        uint32_t signatures;
        result = libmpq__archive_signatures(archive, &signatures);
        if (result != 0)
            return result;
        if (archive->file_size - end != LIBMPQ_STRONG_TRAILER_SIZE ||
            (signatures & LIBMPQ_SIGNATURE_STRONG) == 0)
            return LIBMPQ_ERROR_FORMAT;
    }
    result = exact != NULL ? 0 : libmpq__file_number(archive, old_name, &target);
    if (exact != NULL)
        target = exact->number;
    if (action == LIBMPQ_UPDATE_ADD) {
        if (result != LIBMPQ_ERROR_EXIST)
            return result == 0 ? LIBMPQ_ERROR_EXIST : result;
        target = UINT32_MAX;
    } else if (result != 0) {
        return result;
    }
    if (exact == NULL && action == LIBMPQ_UPDATE_RENAME) {
        result = libmpq__file_number(archive, new_name, &unused);
        if (result != LIBMPQ_ERROR_EXIST)
            return result == 0 ? LIBMPQ_ERROR_EXIST : result;
    }
    if (exact != NULL) {
        if (count == UINT32_MAX || ((uint64_t)count + 1) * sizeof(*names) > SIZE_MAX)
            return LIBMPQ_ERROR_SIZE;
        names = calloc((size_t)count + 1, sizeof(*names));
        result = names != NULL ? 0 : LIBMPQ_ERROR_MALLOC;
        for (uint32_t i = 0; result == 0 && i < 3; ++i) {
            result = libmpq__file_number(archive, special_names[i], &special_numbers[i]);
            if (result == LIBMPQ_ERROR_EXIST) {
                special_numbers[i] = UINT32_MAX;
                result = 0;
                continue;
            }
            if (result != 0)
                break;
            if (special_numbers[i] == target) {
                result = LIBMPQ_ERROR_FORMAT;
                break;
            }
            mpq_file_identity_s identity;
            result = libmpq__file_identity(archive, special_names[i], 0, &identity);
            if (result == 0 &&
                (identity.locale != 0 || identity.platform != 0 ||
                 (archive->het_data != NULL && !(identity.flags & LIBMPQ_IDENTITY_BET)) ||
                 libmpq__file_identity(archive, special_names[i], 1, &identity) !=
                     LIBMPQ_ERROR_EXIST))
                result = LIBMPQ_ERROR_FORMAT;
            const mpq_entry_s *entry =
                &archive->mpq_entry[archive->mpq_map[special_numbers[i]].entry_index];
            if (result == 0 && (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) &&
                update_block_references(archive, entry->classic_source_index) != 1)
                result = LIBMPQ_ERROR_FORMAT;
            if (result == 0) {
                names[special_numbers[i]] = libmpq__string_duplicate(special_names[i]);
                if (names[special_numbers[i]] == NULL)
                    result = LIBMPQ_ERROR_MALLOC;
            }
        }
        if (result == 0 && !exact->shared && action != LIBMPQ_UPDATE_CHANGE_IDENTITY &&
            action != LIBMPQ_UPDATE_TIMESTAMP) {
            names[target] = libmpq__string_duplicate(old_name);
            if (names[target] == NULL)
                result = LIBMPQ_ERROR_MALLOC;
        }

        /* Metadata edits preserve listfiles unless an internal signature must be removed. */
        if (result == 0 &&
            (action == LIBMPQ_UPDATE_CHANGE_IDENTITY || action == LIBMPQ_UPDATE_TIMESTAMP) &&
            special_numbers[0] != UINT32_MAX && special_numbers[2] == UINT32_MAX) {
            preserve_listfile = 1;
            free(names[special_numbers[0]]);
            names[special_numbers[0]] = NULL;
        }
    } else
        result = update_collect_names(update, archive, old_name, &names);
    if (result != 0)
        goto done;
    for (uint32_t i = 0; i < count; ++i)
        incomplete |= names[i] == NULL;
    incomplete |= exact != NULL;
    if (incomplete) {
        if (count == 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if ((uint64_t)count * sizeof(*preserved_rows) > SIZE_MAX ||
            (uint64_t)count * sizeof(*preserved_hashes) > SIZE_MAX) {
            result = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        preserved_rows = malloc((size_t)count * sizeof(*preserved_rows));
        preserved_hashes = calloc(count, sizeof(*preserved_hashes));
        if (preserved_rows == NULL || preserved_hashes == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        for (uint32_t i = 0; i < count; ++i)
            preserved_rows[i] = UINT32_MAX;
        if (exact == NULL && (action == LIBMPQ_UPDATE_ADD || action == LIBMPQ_UPDATE_RENAME)) {
            uint32_t hashes[3];
            libmpq__file_hash(
                action == LIBMPQ_UPDATE_ADD ? old_name : new_name, &hashes[0], &hashes[1],
                &hashes[2]
            );
            for (uint32_t slot = 0; slot < archive->mpq_header.hash_table_count; ++slot)
                if (archive->mpq_hash[slot].block_table_index < LIBMPQ_HASH_DELETED &&
                    archive->mpq_hash[slot].hash_a == hashes[1] &&
                    archive->mpq_hash[slot].hash_b == hashes[2]) {
                    result = LIBMPQ_ERROR_EXIST;
                    goto done;
                }
        }
    }
    result = libmpq__attributes_load(archive);
    if (result == 0)
        attribute_flags = archive->attributes->flags;
    else if (result != LIBMPQ_ERROR_EXIST)
        goto done;
    if ((attribute_flags & ~LIBMPQ_ATTRIBUTES_ALL) != 0 ||
        (archive->mpq_header.version != LIBMPQ_ARCHIVE_VERSION_FOUR &&
         (attribute_flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0)) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    create.max_files = count + 1;
    create.sector_size = 512u << archive->mpq_header.block_size;
    create.attributes = attribute_flags;
    create.flags = LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED;
    if (exact == NULL && libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &unused) == 0)
        create.flags |= LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    if (exact != NULL) {
        if (action == LIBMPQ_UPDATE_RENAME)
            result = update_exact_digest(archive, old_name, exact, expected_digest, &expected_size);
        else if (action == LIBMPQ_UPDATE_REPLACE) {
            if (source_path != NULL)
                result = update_path_digest(source_path, expected_digest, &expected_size);
            else if ((uint64_t)size > UINT32_MAX || (uint64_t)size > SIZE_MAX)
                result = LIBMPQ_ERROR_SIZE;
            else {
                mpq_md5_s md5;
                libmpq__md5_init(&md5);
                if (size != 0)
                    libmpq__md5_update(&md5, data, (size_t)size);
                libmpq__md5_final(&md5, expected_digest);
                expected_size = (uint64_t)size;
                result = 0;
            }
        } else
            result = 0;
        if (result == 0 && special_numbers[0] != UINT32_MAX && !preserve_listfile)
            result = update_listfile(
                archive,
                action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_CHANGE_IDENTITY ||
                        action == LIBMPQ_UPDATE_TIMESTAMP || exact->keep_name
                    ? LIBMPQ_SIGNATURE_NAME
                    : old_name,
                action == LIBMPQ_UPDATE_RENAME ? new_name : NULL, &list_data, &list_size, &unused
            );
        if (result != 0)
            goto done;
    }
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-rebuild-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary, &file
    );
    if (result != 0)
        goto done;
    path = update_working_path(update->working_path, temporary);
    if (path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    result = archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR
                 ? libmpq__writer_archive_create_v4(
                       &writer, path, file, &create, archive->mpq_header_v4.raw_chunk_size
                   )
                 : libmpq__writer_archive_create_file(&writer, path, file, &create);
    file = NULL;
    if (result != 0)
        goto done;

    if (incomplete) {
        result = libmpq__writer_identity_init(writer, archive);
        if (result != 0)
            goto done;
    }

    /* Reserve the source extent so rewritten payloads cannot overlap retained members. */
    if ((incomplete || archive->mpq_header.version != LIBMPQ_ARCHIVE_VERSION_FOUR ||
         archive->mpq_header_v4.raw_chunk_size == 0) &&
        (extent > INT64_MAX || extent == 0 ||
         libmpq__file_seek(writer->fp, (libmpq__off_t)(extent - 1), SEEK_SET) < 0 ||
         fputc(0, writer->fp) == EOF)) {
        result = LIBMPQ_ERROR_WRITE;
        goto done;
    }
    for (uint32_t i = 0; i < count; ++i) {
        mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        mpq_file_attributes_s attributes = { 0 };
        mpq_file_options_s options = { 0 };
        uint32_t references = 0;
        const char *name = i == target && action == LIBMPQ_UPDATE_RENAME ? new_name : names[i];
        if (names[i] != NULL && update_reserved_name(names[i]))
            continue;
        if ((entry->flags & (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) != 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) {
            mpq_bet_entry_s record;
            result = libmpq__bet_record_decode(&archive->mpq_bet, entry->bet_source_index, &record);
            if (result != 0)
                goto done;
            if (record.unknown != 0) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
        if (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) {
            uint32_t hashes[3];
            if (names[i] != NULL)
                libmpq__file_hash(names[i], &hashes[0], &hashes[1], &hashes[2]);
            for (uint32_t slot = 0; slot < archive->mpq_header.hash_table_count; ++slot) {
                mpq_hash_s *hash = &archive->mpq_hash[slot];
                if (hash->block_table_index != entry->classic_source_index)
                    continue;
                ++references;
                if (exact == NULL && names[i] != NULL &&
                    (references > 1 || hash->hash_a != hashes[1] || hash->hash_b != hashes[2])) {
                    result = LIBMPQ_ERROR_FORMAT;
                    goto done;
                }
                options.locale = hash->locale;
                options.platform = hash->platform;
            }
            if (incomplete && references == 0) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            if (attribute_flags != 0) {
                if (entry->classic_source_index >= archive->mpq_header.block_table_count) {
                    result = LIBMPQ_ERROR_FORMAT;
                    goto done;
                }
                libmpq__attributes_get(
                    archive->attributes, entry->classic_source_index, &attributes
                );
            }
        } else if (attribute_flags != 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (action == LIBMPQ_UPDATE_TIMESTAMP) {
            if (!(attributes.flags & LIBMPQ_ATTRIBUTE_FILETIME)) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            if (i == target)
                attributes.filetime = exact->filetime;
        }
        if (attributes.patch_bit) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (exact != NULL && i == target && !exact->shared &&
            action != LIBMPQ_UPDATE_CHANGE_IDENTITY && action != LIBMPQ_UPDATE_TIMESTAMP)
            continue;
        if (exact == NULL && i == target && action == LIBMPQ_UPDATE_REMOVE)
            continue;
        if (exact == NULL && i == target && action == LIBMPQ_UPDATE_REPLACE)
            continue;
        if (names[i] == NULL) {
            result = libmpq__writer_preserve_member(
                writer, archive, i, attribute_flags != 0 ? &attributes : NULL
            );
            if (result != 0)
                goto done;
            preserved_rows[i] = writer->write_next_block - 1;
            preserved_hashes[i] =
                writer->write_identity->source_hashes[archive->mpq_map[i].entry_index];
        } else if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR &&
                   (archive->mpq_header_v4.raw_chunk_size != 0 ||
                    (i == target && action == LIBMPQ_UPDATE_RENAME &&
                     (entry->flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0))) {
            result = libmpq__writer_copy_member(
                writer, archive, i, names[i], name, options.locale, options.platform,
                attribute_flags != 0 ? &attributes : NULL
            );
            if (result != 0)
                goto done;
            if (writer->write_attributes != NULL)
                writer->write_attributes[writer->write_next_block - 1].filetime =
                    attributes.filetime;
        } else if (i == target && action == LIBMPQ_UPDATE_RENAME &&
                   (entry->flags & LIBMPQ_FILE_FLAG_ENCRYPTED)) {
            uint8_t *decoded = NULL;
            size_t decoded_size;
            options.flags = entry->flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE |
                                            LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_KEY);
            if (entry->flags & LIBMPQ_FLAG_COMPRESS_MULTI) {
                options.flags |= LIBMPQ_FILE_FLAG_COMPRESS;
                options.compression_first = options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
            } else if (entry->flags & LIBMPQ_FLAG_COMPRESS_PKZIP) {
                options.flags |= LIBMPQ_FILE_FLAG_IMPLODE;
            }
            result = update_read_named(archive, names[i], &decoded, &decoded_size);
            if (result == 0 && libmpq__file_seek(writer->fp, 0, SEEK_END) < 0)
                result = LIBMPQ_ERROR_SEEK;
            if (result == 0)
                result = libmpq__archive_add_data(
                    writer, name, decoded, (libmpq__off_t)decoded_size, &options
                );
            free(decoded);
            if (result != 0)
                goto done;
            if (writer->write_attributes != NULL)
                writer->write_attributes[writer->write_next_block - 1].filetime =
                    attributes.filetime;
        } else {
            if (entry->offset < writer->mpq_header.header_size || entry->offset > INT64_MAX ||
                entry->packed_size > UINT32_MAX || entry->unpacked_size > UINT32_MAX ||
                entry->offset > extent || entry->packed_size > extent - entry->offset) {
                result = LIBMPQ_ERROR_SIZE;
                goto done;
            }
            if (libmpq__file_seek(writer->fp, (libmpq__off_t)entry->offset, SEEK_SET) < 0) {
                result = LIBMPQ_ERROR_SEEK;
                goto done;
            }
            result = libmpq__reader_validate_payload_range(
                archive, archive->mpq_map[i].entry_index, 0, entry->packed_size
            );
            if (result == 0)
                result = update_copy_range(
                    archive, writer->fp, prefix.origin + entry->offset, entry->packed_size
                );
            if (result == 0)
                result = libmpq__writer_import_member(
                    writer, name, entry, options.locale, options.platform,
                    attribute_flags != 0 ? &attributes : NULL
                );
            if (result != 0)
                goto done;
        }
        if (incomplete && names[i] != NULL && !(i == target && action == LIBMPQ_UPDATE_RENAME)) {
            result = libmpq__writer_identity_bind(writer, archive, i);
            if (result != 0)
                goto done;
        }
    }
    if (libmpq__file_seek(writer->fp, 0, SEEK_END) < 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto done;
    }
    if (exact != NULL) {
        mpq_file_attributes_s attributes = { 0 };
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[target].entry_index];
        if (attribute_flags != 0) {
            if (!(entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC)) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            libmpq__attributes_get(archive->attributes, entry->classic_source_index, &attributes);
        }
        if (action == LIBMPQ_UPDATE_REPLACE) {
            mpq_file_options_s options =
                replacement_options != NULL ? *replacement_options : (mpq_file_options_s){ 0 };
            options.locale = exact->locale;
            options.platform = exact->platform;
            result = source_path != NULL
                         ? libmpq__archive_add_path(writer, old_name, source_path, &options)
                         : libmpq__archive_add_data(writer, old_name, data, size, &options);
            if (result == 0 && writer->write_attributes != NULL)
                writer->write_attributes[writer->write_next_block - 1].filetime =
                    attributes.filetime;
        } else if (action == LIBMPQ_UPDATE_RENAME)
            result = libmpq__writer_copy_member(
                writer, archive, target, old_name, new_name, exact->locale, exact->platform,
                attribute_flags != 0 ? &attributes : NULL
            );
        else
            result = 0;
        if (result == 0 && action != LIBMPQ_UPDATE_TIMESTAMP)
            result = update_detach_identity(writer, exact, action, new_name);
        if (result != 0)
            goto done;
        if (special_numbers[0] != UINT32_MAX && !preserve_listfile) {
            mpq_file_options_s options = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
            result = libmpq__archive_add_data(
                writer, LIBMPQ_LISTFILE_NAME, list_data, (libmpq__off_t)list_size, &options
            );
            if (result == 0)
                result = libmpq__writer_identity_bind(writer, archive, special_numbers[0]);
            if (result != 0)
                goto done;
        }
    }
    if (exact == NULL && (action == LIBMPQ_UPDATE_ADD || action == LIBMPQ_UPDATE_REPLACE)) {
        const char *member_name = action == LIBMPQ_UPDATE_REPLACE ? names[target] : old_name;
        mpq_file_options_s options =
            replacement_options != NULL ? *replacement_options : (mpq_file_options_s){ 0 };
        if (action == LIBMPQ_UPDATE_REPLACE && target < count) {
            mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[target].entry_index];
            if (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) {
                for (uint32_t slot = 0; slot < archive->mpq_header.hash_table_count; ++slot) {
                    mpq_hash_s *hash = &archive->mpq_hash[slot];
                    if (hash->block_table_index == entry->classic_source_index) {
                        if (replacement_options != NULL && (options.locale != hash->locale ||
                                                            options.platform != hash->platform)) {
                            result = LIBMPQ_ERROR_FORMAT;
                            goto done;
                        }
                        options.locale = hash->locale;
                        options.platform = hash->platform;
                        break;
                    }
                }
            }
        }
        result = source_path != NULL
                     ? libmpq__archive_add_path(writer, member_name, source_path, &options)
                     : libmpq__archive_add_data(writer, member_name, data, size, &options);
        if (result != 0)
            goto done;
        if (incomplete && action == LIBMPQ_UPDATE_REPLACE) {
            result = libmpq__writer_identity_bind(writer, archive, target);
            if (result != 0)
                goto done;
        }
    }
    result = libmpq__archive_close(writer);
    writer = NULL;
    if (result != 0)
        goto done;
    result = update_open_candidate(update, archive, &prefix, &temporary, &path, &check);
    if (result != 0)
        goto done;
    if (check->mpq_header.version != archive->mpq_header.version) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    {
        uint32_t expected =
            (action == LIBMPQ_UPDATE_CHANGE_IDENTITY || action == LIBMPQ_UPDATE_TIMESTAMP) ? count
            : exact != NULL
                ? count - !exact->shared + (action != LIBMPQ_UPDATE_REMOVE)
                : count + (action == LIBMPQ_UPDATE_ADD) - (action == LIBMPQ_UPDATE_REMOVE);
        if (libmpq__file_number(archive, LIBMPQ_SIGNATURE_NAME, &unused) == 0)
            --expected;
        if (check->files != expected) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        for (uint32_t i = 0; i < count; ++i) {
            if (exact != NULL || i == target || names[i] == NULL || update_reserved_name(names[i]))
                continue;
            result = libmpq__file_number(check, names[i], &unused);
            if (result != 0)
                goto done;
        }
    }
    if (incomplete) {
        result = update_check_unknowns(
            archive, check, names, preserved_rows, preserved_hashes, attribute_flags,
            exact != NULL && action != LIBMPQ_UPDATE_TIMESTAMP ? exact->slot : UINT32_MAX,
            action == LIBMPQ_UPDATE_TIMESTAMP ? exact : NULL
        );
        if (result != 0)
            goto done;
    }
    if (exact == NULL && action != LIBMPQ_UPDATE_ADD && action != LIBMPQ_UPDATE_REPLACE &&
        libmpq__file_number(check, old_name, &unused) != LIBMPQ_ERROR_EXIST) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (exact != NULL) {
        uint8_t digest[16];
        uint64_t length;
        if (action == LIBMPQ_UPDATE_TIMESTAMP) {
            mpq_file_attributes_s attributes;
            uint32_t number;
            result = libmpq__file_number_from_identity(
                check, old_name, exact->locale, exact->platform, &number
            );
            if (result == 0)
                result = libmpq__file_attributes(check, number, &attributes);
            if (result == 0 && (!(attributes.flags & LIBMPQ_ATTRIBUTE_FILETIME) ||
                                attributes.filetime != exact->filetime))
                result = LIBMPQ_ERROR_FORMAT;
        } else if (action == LIBMPQ_UPDATE_CHANGE_IDENTITY) {
            uint32_t number;
            const mpq_hash_s *before = &archive->mpq_hash[exact->slot];
            const mpq_hash_s *after = &check->mpq_hash[exact->slot];
            result = libmpq__file_number_from_identity(
                check, old_name, exact->new_locale, exact->new_platform, &number
            );
            if (result == 0 &&
                (after->hash_a != before->hash_a || after->hash_b != before->hash_b ||
                 after->locale != exact->new_locale || after->platform != exact->new_platform ||
                 after->block_table_index != preserved_rows[target] ||
                 check->mpq_entry[check->mpq_map[number].entry_index].classic_source_index !=
                     preserved_rows[target]))
                result = LIBMPQ_ERROR_FORMAT;
            if (result == 0) {
                result = libmpq__file_number_from_identity(
                    check, old_name, exact->locale, exact->platform, &number
                );
                result = result == LIBMPQ_ERROR_EXIST ? 0
                         : result == 0                ? LIBMPQ_ERROR_FORMAT
                                                      : result;
            }
        } else if (action != LIBMPQ_UPDATE_REMOVE) {
            result = update_exact_digest(
                check, action == LIBMPQ_UPDATE_RENAME ? new_name : old_name, exact, digest, &length
            );
            if (result == 0 &&
                (length != expected_size || memcmp(digest, expected_digest, 16) != 0))
                result = LIBMPQ_ERROR_READ;
        } else {
            uint32_t ignored;
            result = libmpq__file_number_from_identity(
                check, old_name, exact->locale, exact->platform, &ignored
            );
            result = result == LIBMPQ_ERROR_EXIST ? 0 : result == 0 ? LIBMPQ_ERROR_FORMAT : result;
        }
        for (uint32_t i = 0; result == 0 && i < check->files; ++i) {
            uint32_t mismatches;
            result = libmpq__file_verify(check, i, LIBMPQ_VERIFY_RAW_MD5, &mismatches);
            if (result == 0 && mismatches != 0)
                result = LIBMPQ_ERROR_READ;
        }
        if (result != 0)
            goto done;
    }
    if (exact == NULL && action != LIBMPQ_UPDATE_REMOVE) {
        result = update_validate_member(
            check, action == LIBMPQ_UPDATE_RENAME ? new_name : old_name, NULL, 0, 0, NULL, NULL
        );
        if (result != 0)
            goto done;
    }
    result = update_prepare_names(
        update, check, names, count, NULL, 0, old_name,
        action == LIBMPQ_UPDATE_RENAME ? new_name : NULL, &prepared_names, &prepared_count
    );
    if (result != 0)
        goto done;
    result = libmpq__archive_close(check);
    check = NULL;
    if (result != 0)
        goto done;
    file = libmpq__directory_file_open(update->directory, temporary, "r+b");
    if (file == NULL) {
        result = LIBMPQ_ERROR_OPEN;
        goto done;
    }
    result = libmpq__archive_close(archive);
    *source = NULL;
    if (result != 0)
        goto done;
    if (update->ops->flush(update->working) != 0) {
        result = LIBMPQ_ERROR_WRITE;
        goto done;
    }
    {
        FILE *previous = update->working;

        /* Close consumes the stream even on failure; abort must not close it twice. */
        update->working = NULL;
        if (update->ops->close(previous) != 0) {
            result = LIBMPQ_ERROR_CLOSE;
            goto done;
        }
    }
    result = libmpq__directory_remove(update->directory, update->temporary);
    if (result != 0)
        goto done;
    free(update->temporary);
    free(update->working_path);
    update->working = file;
    update->temporary = temporary;
    update->working_path = path;
    update_adopt_names(update, &prepared_names, prepared_count);
    update->dirty = 1;
    temporary = NULL;
    path = NULL;
    file = NULL;
done:
    update_free_names(prepared_names, prepared_count);
    if (writer != NULL) {
        libmpq__writer_file_abort(writer->write_current);
        writer->write_current = NULL;
        (void)libmpq__archive_close(writer);
    }
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (file != NULL)
        (void)fclose(file);
    if (temporary != NULL)
        (void)libmpq__directory_remove(update->directory, temporary);
    free(temporary);
    free(path);
    free(list_data);
    free(preserved_rows);
    free(preserved_hashes);
    if (names != NULL) {
        for (uint32_t i = 0; i <= count; ++i)
            free(names[i]);
        free(names);
    }
    return result;
}

static int32_t
update_apply(
    mpq_update_s *update, mpq_update_action_e action, const char *old_name, const char *new_name,
    const uint8_t *data, libmpq__off_t size, const char *source_path,
    const mpq_file_options_s *replacement_options, const mpq_update_identity_s *selector
)
{
    static const uint8_t marker[4] = { 'N', 'G', 'I', 'S' };
    mpq_archive_s *archive = NULL;
    mpq_archive_s *check = NULL;
    mpq_file_attributes_s *attributes = NULL;
    mpq_file_options_s options = { 0 };
    mpq_hash_s hash = { 0 };
    FILE *rebuilt = NULL;
    char *temporary = NULL;
    char *rebuilt_path = NULL;
    uint8_t *list = NULL;
    uint8_t *attribute_data = NULL;
    uint64_t extent = 0;
    uint64_t suffix = 0;
    uint64_t rebuilt_extent = 0;
    uint32_t number;
    uint32_t block;
    uint32_t slot;
    uint32_t list_number = 0;
    uint32_t attributes_number = 0;
    uint32_t signature_number = 0;
    uint32_t i;
    uint32_t attribute_flags = 0;
    size_t list_size = 0;
    size_t attribute_size = 0;
    char **prepared_names = NULL;
    uint32_t prepared_count = 0;
    int32_t result;
    uint8_t has_list = 0;
    uint8_t has_attributes = 0;
    uint8_t has_signature = 0;
    uint8_t append_block = 0;
    uint8_t expected_md5[16] = { 0 };
    uint64_t expected_size = 0;

    if (update == NULL || update->working == NULL || old_name == NULL || old_name[0] == '\0' ||
        (action == LIBMPQ_UPDATE_RENAME && (new_name == NULL || new_name[0] == '\0')) ||
        ((action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_ADD) &&
         (size < 0 || (size != 0 && data == NULL && source_path == NULL))) ||
        ((action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_ADD) && source_path != NULL &&
         source_path[0] == '\0'))
        return LIBMPQ_ERROR_EXIST;
    if ((action != LIBMPQ_UPDATE_CHANGE_IDENTITY && update_reserved_name(old_name)) ||
        (action == LIBMPQ_UPDATE_RENAME && update_reserved_name(new_name)))
        return LIBMPQ_ERROR_FORMAT;
    if (fflush(update->working) != 0)
        return LIBMPQ_ERROR_WRITE;
    result = libmpq__archive_open(&archive, update->working_path, -1);
    if (result != 0)
        return result;

    if (archive->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_FOUR) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }

    mpq_update_identity_s exact = { 0 };
    if (selector != NULL) {
        exact = *selector;
        if (action == LIBMPQ_UPDATE_TIMESTAMP) {
            uint8_t unchanged;
            result = update_resolve_timestamp(archive, old_name, &exact, &unchanged);
            if (result != 0 || unchanged)
                goto done;
        } else
            result = update_resolve_identity(
                archive, action, old_name, new_name, replacement_options, &exact
            );
        if (result != 0 ||
            (action == LIBMPQ_UPDATE_RENAME && update_names_equal(old_name, new_name)) ||
            (action == LIBMPQ_UPDATE_CHANGE_IDENTITY && exact.locale == exact.new_locale &&
             exact.platform == exact.new_platform))
            goto done;
    }

    /* Extended-table actions exit here; update_encode() below remains legacy-only. */
    if (selector != NULL || archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE ||
        (action == LIBMPQ_UPDATE_ADD && archive->files == 0)) {
        result = update_rebuild_named(
            update, &archive, action, old_name, new_name, data, size, source_path,
            replacement_options, selector != NULL ? &exact : NULL
        );
        goto done;
    }
    result = libmpq__file_number(archive, old_name, &number);
    if (action == LIBMPQ_UPDATE_ADD) {
        if (result != LIBMPQ_ERROR_EXIST) {
            result = result == 0 ? LIBMPQ_ERROR_EXIST : result;
            goto done;
        }
        for (block = 0; block < archive->mpq_header.block_table_count; ++block)
            if ((archive->mpq_block[block].flags & LIBMPQ_FLAG_EXISTS) == 0 &&
                update_block_references(archive, block) == 0)
                break;
        if (block == archive->mpq_header.block_table_count) {
            if ((uint64_t)block + 1 > UINT32_MAX / LIBMPQ_BLOCK_ENTRY_WIRE_SIZE ||
                ((uint64_t)block + 1) * sizeof(*archive->mpq_block) > SIZE_MAX ||
                ((uint64_t)block + 1) * sizeof(*archive->mpq_block_ex) > SIZE_MAX ||
                ((uint64_t)block + 1) * sizeof(*attributes) > SIZE_MAX) {
                result = LIBMPQ_ERROR_SIZE;
                goto done;
            }
            append_block = 1;
        }
        hash.block_table_index = block;
        if (replacement_options != NULL) {
            hash.locale = replacement_options->locale;
            hash.platform = replacement_options->platform;
        }
        result = update_insert_hash(archive, old_name, &hash);
        if (result != 0)
            goto done;
    } else {
        if (result != 0)
            goto done;
        block = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    }
    slot = update_hash_slot(archive, old_name, block);
    if (slot == UINT32_MAX) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    hash = archive->mpq_hash[slot];
    if ((action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_ADD) &&
        replacement_options != NULL &&
        (replacement_options->locale != hash.locale ||
         replacement_options->platform != hash.platform)) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if ((action == LIBMPQ_UPDATE_REPLACE ||
         (action == LIBMPQ_UPDATE_RENAME &&
          (archive->mpq_block[block].flags & LIBMPQ_FLAG_ENCRYPTED) != 0)) &&
        update_block_references(archive, block) > 1) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (action == LIBMPQ_UPDATE_RENAME) {
        uint32_t collision;

        result = libmpq__file_number(archive, new_name, &collision);
        if (result == 0) {
            result = LIBMPQ_ERROR_EXIST;
            goto done;
        }
        if (result != LIBMPQ_ERROR_EXIST)
            goto done;
    }
    result = libmpq__archive_signature_extent(archive, &extent);
    if (result != 0)
        goto done;
    if ((uint64_t)archive->archive_offset > UINT64_MAX - extent) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    suffix = (uint64_t)archive->archive_offset + extent;
    if (suffix <= archive->file_size && archive->file_size - suffix >= LIBMPQ_STRONG_TRAILER_SIZE) {
        uint8_t actual[4];

        result = libmpq__source_read_at(archive->source, suffix, actual, sizeof(actual));
        if (result != 0)
            goto done;
        if (memcmp(actual, marker, sizeof(marker)) == 0)
            suffix += LIBMPQ_STRONG_TRAILER_SIZE;
    }
    if (libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &list_number) == 0) {
        has_list = 1;
        if (update_block_references(
                archive,
                archive->mpq_entry[archive->mpq_map[list_number].entry_index].classic_source_index
            ) != 1) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        result = update_listfile(
            archive, old_name,
            action == LIBMPQ_UPDATE_REMOVE   ? NULL
            : action == LIBMPQ_UPDATE_RENAME ? new_name
                                             : old_name,
            &list, &list_size, &list_number
        );
        if (result != 0)
            goto done;
    }
    result = libmpq__attributes_load(archive);
    if (result == 0) {
        has_attributes = 1;
        attribute_flags = archive->attributes->flags;
        if (libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &attributes_number) != 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (update_block_references(
                archive, archive->mpq_entry[archive->mpq_map[attributes_number].entry_index]
                             .classic_source_index
            ) != 1) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        attributes = calloc(archive->mpq_header.block_table_count, sizeof(*attributes));
        if (attributes == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        for (i = 0; i < archive->mpq_header.block_table_count; i++) {
            libmpq__attributes_get(archive->attributes, i, &attributes[i]);
            if (attributes[i].patch_bit != 0) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
    } else if (result != LIBMPQ_ERROR_EXIST) {
        goto done;
    }
    if (libmpq__file_number(archive, LIBMPQ_SIGNATURE_NAME, &signature_number) == 0) {
        has_signature = 1;
        if (update_block_references(
                archive, archive->mpq_entry[archive->mpq_map[signature_number].entry_index]
                             .classic_source_index
            ) != 1) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    }
    if (action == LIBMPQ_UPDATE_RENAME) {
        result =
            update_validate_member(archive, old_name, NULL, 0, 0, expected_md5, &expected_size);
        if (result != 0)
            goto done;
    }
    if (append_block) {
        size_t rows = (size_t)block + 1;
        void *grown = realloc(archive->mpq_block, rows * sizeof(*archive->mpq_block));
        if (grown == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        archive->mpq_block = grown;
        memset(&archive->mpq_block[block], 0, sizeof(*archive->mpq_block));
        grown = realloc(archive->mpq_block_ex, rows * sizeof(*archive->mpq_block_ex));
        if (grown == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        archive->mpq_block_ex = grown;
        memset(&archive->mpq_block_ex[block], 0, sizeof(*archive->mpq_block_ex));
        if (has_attributes) {
            grown = realloc(attributes, rows * sizeof(*attributes));
            if (grown == NULL) {
                result = LIBMPQ_ERROR_MALLOC;
                goto done;
            }
            attributes = grown;
            memset(&attributes[block], 0, sizeof(*attributes));
        }
        archive->mpq_header.block_table_count = (uint32_t)rows;
    }
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-rebuild-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary,
        &rebuilt
    );
    if (result != 0)
        goto done;
    rebuilt_path = update_working_path(update->working_path, temporary);
    if (rebuilt_path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    result = update_copy_range(archive, rebuilt, 0, (uint64_t)archive->archive_offset + extent);
    if (result != 0)
        goto done;
    if (action == LIBMPQ_UPDATE_REMOVE) {
        update_delete_hash(&archive->mpq_hash[slot]);
        if (update_block_references(archive, block) == 0) {
            memset(&archive->mpq_block[block], 0, sizeof(archive->mpq_block[block]));
            archive->mpq_block_ex[block].offset_high = 0;
            if (has_attributes)
                memset(&attributes[block], 0, sizeof(attributes[block]));
        }
    } else if (action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_ADD ||
               (archive->mpq_block[block].flags & LIBMPQ_FLAG_ENCRYPTED) != 0) {
        if (action == LIBMPQ_UPDATE_RENAME) {
            uint32_t original_flags = archive->mpq_block[block].flags;

            options.flags = original_flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE |
                                              LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_KEY);
            if ((original_flags & LIBMPQ_FLAG_COMPRESS_MULTI) != 0) {
                options.flags |= LIBMPQ_FILE_FLAG_COMPRESS;
                options.compression_first = LIBMPQ_COMPRESSION_ZLIB;
                options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
            } else if ((original_flags & LIBMPQ_FLAG_COMPRESS_PKZIP) != 0) {
                options.flags |= LIBMPQ_FILE_FLAG_IMPLODE;
            }
        } else {
            if (replacement_options != NULL)
                options = *replacement_options;
        }
        options.locale = hash.locale;
        options.platform = hash.platform;
        if (has_attributes) {
            attributes[block].flags = attribute_flags;
            if (action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_ADD)
                attributes[block].filetime = 0;
        }
        result = update_encode(
            update, archive, rebuilt, action == LIBMPQ_UPDATE_RENAME ? new_name : old_name, data,
            (uint64_t)size, source_path, action == LIBMPQ_UPDATE_RENAME ? old_name : NULL, &options,
            &archive->mpq_block[block], &archive->mpq_block_ex[block],
            has_attributes ? &attributes[block] : NULL,
            action != LIBMPQ_UPDATE_RENAME ? expected_md5 : NULL,
            action != LIBMPQ_UPDATE_RENAME ? &expected_size : NULL
        );
        if (result != 0)
            goto done;
    }
    if (action == LIBMPQ_UPDATE_RENAME) {
        update_delete_hash(&archive->mpq_hash[slot]);
        result = update_insert_hash(archive, new_name, &hash);
        if (result != 0)
            goto done;
    }
    if (has_signature) {
        uint32_t signature_block =
            archive->mpq_entry[archive->mpq_map[signature_number].entry_index].classic_source_index;

        for (i = 0; i < archive->mpq_header.hash_table_count; i++)
            if (archive->mpq_hash[i].block_table_index == signature_block)
                update_delete_hash(&archive->mpq_hash[i]);
        memset(
            &archive->mpq_block[signature_block], 0, sizeof(archive->mpq_block[signature_block])
        );
        archive->mpq_block_ex[signature_block].offset_high = 0;
        if (has_attributes)
            memset(&attributes[signature_block], 0, sizeof(attributes[signature_block]));
    }
    if (has_list) {
        uint32_t list_block =
            archive->mpq_entry[archive->mpq_map[list_number].entry_index].classic_source_index;

        options.flags = LIBMPQ_FILE_FLAG_SINGLE;
        options.compression_first = 0;
        options.compression_next = 0;
        options.locale = 0;
        options.platform = 0;
        if (has_attributes)
            attributes[list_block].flags = attribute_flags;
        result = update_encode(
            update, archive, rebuilt, LIBMPQ_LISTFILE_NAME, list, list_size, NULL, NULL, &options,
            &archive->mpq_block[list_block], &archive->mpq_block_ex[list_block],
            has_attributes ? &attributes[list_block] : NULL, NULL, NULL
        );
        if (result != 0)
            goto done;
    }
    if (has_attributes) {
        uint32_t attributes_block =
            archive->mpq_entry[archive->mpq_map[attributes_number].entry_index]
                .classic_source_index;

        result = libmpq__attributes_serialize(
            attributes, archive->mpq_header.block_table_count, attributes_block, attribute_flags,
            &attribute_data, &attribute_size
        );
        if (result != 0)
            goto done;
        options.flags = LIBMPQ_FILE_FLAG_SINGLE;
        options.compression_first = 0;
        options.compression_next = 0;
        result = update_encode(
            update, archive, rebuilt, LIBMPQ_ATTRIBUTES_NAME, attribute_data, attribute_size, NULL,
            NULL, &options, &archive->mpq_block[attributes_block],
            &archive->mpq_block_ex[attributes_block], NULL, NULL, NULL
        );
        if (result != 0)
            goto done;
    }
    result = update_write_tables(archive, rebuilt, &rebuilt_extent);
    if (result != 0)
        goto done;
    if (suffix < archive->file_size) {
        result = update_copy_range(archive, rebuilt, suffix, archive->file_size - suffix);
        if (result != 0)
            goto done;
    }
    if (fflush(rebuilt) != 0) {
        result = LIBMPQ_ERROR_WRITE;
        goto done;
    }
    result = libmpq__archive_open(&check, rebuilt_path, -1);
    if (result != 0)
        goto done;
    if (check->archive_offset != archive->archive_offset ||
        check->mpq_header.archive_size != rebuilt_extent) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (action == LIBMPQ_UPDATE_REMOVE || action == LIBMPQ_UPDATE_RENAME) {
        result = libmpq__file_number(check, old_name, &number);
        if (result != LIBMPQ_ERROR_EXIST) {
            result = result == 0 ? LIBMPQ_ERROR_FORMAT : result;
            goto done;
        }
    }
    result = 0;
    if (action != LIBMPQ_UPDATE_REMOVE)
        result = update_validate_member(
            check, action == LIBMPQ_UPDATE_RENAME ? new_name : old_name, expected_md5,
            expected_size, 1, NULL, NULL
        );
    if (result != 0)
        goto done;
    result = update_prepare_names(
        update, check, NULL, 0, NULL, 0, old_name, action == LIBMPQ_UPDATE_RENAME ? new_name : NULL,
        &prepared_names, &prepared_count
    );
    if (result != 0)
        goto done;
    result = libmpq__archive_close(check);
    check = NULL;
    if (result != 0)
        goto done;
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != 0)
        goto done;

    /*
     * Adopt the validated rebuild without replacing a still-open working file.
     * This avoids sharing-sensitive replacement of an open destination on
     * Windows. Final publication still uses same-directory atomic replacement
     * after the working file is closed.
     */
    {
        FILE *previous_working = update->working;
        char *previous_temporary = update->temporary;
        char *previous_path = update->working_path;

        if (update->ops->flush(previous_working) != 0) {
            result = LIBMPQ_ERROR_WRITE;
            goto done;
        }
        update->working = NULL;
        if (update->ops->close(previous_working) != 0) {
            result = LIBMPQ_ERROR_CLOSE;
            goto done;
        }
        result = libmpq__directory_remove(update->directory, previous_temporary);
        if (result != 0)
            goto done;
        update->working = rebuilt;
        update->temporary = temporary;
        update->working_path = rebuilt_path;
        rebuilt = NULL;
        temporary = NULL;
        rebuilt_path = NULL;
        free(previous_temporary);
        free(previous_path);
        update_adopt_names(update, &prepared_names, prepared_count);
        update->dirty = 1;
    }

done:
    update_free_names(prepared_names, prepared_count);
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (rebuilt != NULL)
        (void)fclose(rebuilt);
    if (temporary != NULL)
        (void)libmpq__directory_remove(update->directory, temporary);
    free(temporary);
    free(rebuilt_path);
    free(list);
    free(attribute_data);
    free(attributes);
    return result;
}

int32_t
libmpq__update_transaction_add(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const char *source_path, const mpq_file_options_s *options
)
{
    return update_apply(
        update, LIBMPQ_UPDATE_ADD, filename, NULL, data, size, source_path, options, NULL
    );
}

int32_t
libmpq__update_transaction_replace(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const char *source_path, const mpq_file_options_s *options
)
{
    return update_apply(
        update, LIBMPQ_UPDATE_REPLACE, filename, NULL, data, size, source_path, options, NULL
    );
}

int32_t
libmpq__update_transaction_remove(mpq_update_s *update, const char *filename)
{
    return update_apply(update, LIBMPQ_UPDATE_REMOVE, filename, NULL, NULL, 0, NULL, NULL, NULL);
}

int32_t
libmpq__update_transaction_rename(
    mpq_update_s *update, const char *old_filename, const char *new_filename
)
{
    return update_apply(
        update, LIBMPQ_UPDATE_RENAME, old_filename, new_filename, NULL, 0, NULL, NULL, NULL
    );
}

/* Exact wrappers share the existing stage/rebuild/adoption engine. */
int32_t
libmpq__update_transaction_replace_identity(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform, const uint8_t *data,
    libmpq__off_t size, const char *path, const mpq_file_options_s *options
)
{
    mpq_update_identity_s selector = { .locale = locale, .platform = platform, .slot = UINT32_MAX };
    return update_apply(
        update, LIBMPQ_UPDATE_REPLACE, name, NULL, data, size, path, options, &selector
    );
}

/* Remove exactly one staged identity without consuming the transaction. */
int32_t
libmpq__update_transaction_remove_identity(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform
)
{
    mpq_update_identity_s selector = { .locale = locale, .platform = platform, .slot = UINT32_MAX };
    return update_apply(update, LIBMPQ_UPDATE_REMOVE, name, NULL, NULL, 0, NULL, NULL, &selector);
}

/* Rename the selected staged identity, leaving other aliases untouched. */
int32_t
libmpq__update_transaction_rename_identity(
    mpq_update_s *update, const char *name, const char *new_name, uint16_t locale, uint16_t platform
)
{
    mpq_update_identity_s selector = { .locale = locale, .platform = platform, .slot = UINT32_MAX };
    return update_apply(
        update, LIBMPQ_UPDATE_RENAME, name, new_name, NULL, 0, NULL, NULL, &selector
    );
}

/* Change one tuple in the existing identity-preserving reconstruction path. */
int32_t
libmpq__update_transaction_change_identity(
    mpq_update_s *update, const char *filename, uint16_t old_locale, uint16_t old_platform,
    uint16_t new_locale, uint16_t new_platform
)
{
    mpq_update_identity_s selector = { .locale = old_locale,
                                       .platform = old_platform,
                                       .slot = UINT32_MAX,
                                       .new_locale = new_locale,
                                       .new_platform = new_platform };
    return update_apply(
        update, LIBMPQ_UPDATE_CHANGE_IDENTITY, filename, NULL, NULL, 0, NULL, NULL, &selector
    );
}

/* Copy timestamp and selection values into the synchronous staging request. */
int32_t
libmpq__update_transaction_timestamp(
    mpq_update_s *update, const char *name, uint64_t filetime, uint8_t exact, uint16_t locale,
    uint16_t platform
)
{
    mpq_update_identity_s target = { .locale = locale,
                                     .platform = platform,
                                     .slot = UINT32_MAX,
                                     .filetime = filetime,
                                     .timestamp_exact = exact };
    return update_apply(update, LIBMPQ_UPDATE_TIMESTAMP, name, NULL, NULL, 0, NULL, NULL, &target);
}

/* Duplicate exact tuples cannot be normalized safely during physical reconstruction. */
static int
update_compact_hash_compare(const void *first, const void *second)
{
    const mpq_hash_s *a = first;
    const mpq_hash_s *b = second;
    if (a->hash_a != b->hash_a)
        return a->hash_a < b->hash_a ? -1 : 1;
    if (a->hash_b != b->hash_b)
        return a->hash_b < b->hash_b ? -1 : 1;
    if (a->locale != b->locale)
        return a->locale < b->locale ? -1 : 1;
    return a->platform < b->platform ? -1 : a->platform != b->platform;
}

static int32_t
update_compact_hashes(mpq_archive_s *archive)
{
    uint32_t count = archive->mpq_header.hash_table_count;
    size_t live = 0;
    mpq_hash_s *hashes;
    if ((uint64_t)count * sizeof(*hashes) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    hashes = malloc(count ? (size_t)count * sizeof(*hashes) : 1);
    if (hashes == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (uint32_t slot = 0; slot < count; ++slot) {
        const mpq_hash_s *hash = &archive->mpq_hash[slot];
        uint32_t index;
        if (hash->block_table_index >= LIBMPQ_HASH_DELETED)
            continue;
        if (libmpq__entry_index_from_classic(archive, hash->block_table_index, &index) != 0 ||
            archive->mpq_entry[index].file_number >= archive->files ||
            archive->mpq_entry[index].classic_source_index != hash->block_table_index) {
            free(hashes);
            return LIBMPQ_ERROR_FORMAT;
        }
        hashes[live++] = *hash;
    }
    qsort(hashes, live, sizeof(*hashes), update_compact_hash_compare);
    for (size_t i = 1; i < live; ++i)
        if (update_compact_hash_compare(&hashes[i - 1], &hashes[i]) == 0) {
            free(hashes);
            return LIBMPQ_ERROR_FORMAT;
        }
    free(hashes);
    return 0;
}

/* Stored extents are sorted independently of canonical row order. */
typedef struct
{
    uint64_t offset;
    uint64_t size;
} mpq_compact_range_s;

static int
update_compact_range_compare(const void *first, const void *second)
{
    const mpq_compact_range_s *a = first;
    const mpq_compact_range_s *b = second;
    return a->offset < b->offset ? -1 : a->offset != b->offset;
}

/* Account for raw arrays without allocating a chunk-sized buffer. */
static int32_t
update_compact_size(mpq_archive_s *archive, uint64_t stored, uint8_t raw, uint64_t *physical)
{
    uint32_t chunk = archive->mpq_header_v4.raw_chunk_size;
    uint64_t digests = 0;
    if (raw && archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR && chunk && stored)
        digests = (stored - 1) / chunk + 1;
    if (digests > (UINT64_MAX - stored) / LIBMPQ_MD5_SIZE)
        return LIBMPQ_ERROR_SIZE;
    *physical = stored + digests * LIBMPQ_MD5_SIZE;
    return 0;
}

/* Prove coverage, reject overlap, and distinguish holes from required legacy alignment. */
static int32_t
update_compact_layout(mpq_archive_s *archive, uint8_t *dense)
{
    uint64_t extent = libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    mpq_compact_range_s *ranges;
    uint64_t sizes[2];
    uint64_t cursor = 0;
    uint64_t first_payload = UINT64_MAX;
    size_t count = 1;
    int32_t result = LIBMPQ_ERROR_FORMAT;
    *dense = 1;
    if (archive->archive_offset < 0 || (uint64_t)archive->archive_offset > archive->file_size ||
        extent > archive->file_size - (uint64_t)archive->archive_offset ||
        extent > (uint64_t)INT64_MAX - (uint64_t)archive->archive_offset ||
        ((uint64_t)archive->files + 6) * sizeof(*ranges) > SIZE_MAX)
        return LIBMPQ_ERROR_FORMAT;
    ranges = calloc((size_t)archive->files + 6, sizeof(*ranges));
    if (ranges == NULL)
        return LIBMPQ_ERROR_MALLOC;
    ranges[0] = (mpq_compact_range_s){ 0, archive->mpq_header.header_size };
    result = libmpq__reader_classic_table_sizes(archive, sizes);
    if (result != 0)
        goto done;
    if (sizes[0])
        ranges[count++] =
            (mpq_compact_range_s){ archive->mpq_header.hash_table_offset |
                                       ((uint64_t)archive->mpq_header_ex.hash_table_offset_high
                                        << 32),
                                   sizes[0] };
    if (sizes[1])
        ranges[count++] =
            (mpq_compact_range_s){ archive->mpq_header.block_table_offset |
                                       ((uint64_t)archive->mpq_header_ex.block_table_offset_high
                                        << 32),
                                   sizes[1] };
    if (archive->mpq_header_ex.extended_offset != 0)
        ranges[count++] =
            (mpq_compact_range_s){ archive->mpq_header_ex.extended_offset,
                                   archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR
                                       ? archive->mpq_header_v4.hi_block_table_size
                                       : (uint64_t)archive->mpq_header.block_table_count * 2 };
    if (archive->het_data != NULL) {
        result = libmpq__reader_ext_table_sizes(archive, &sizes[0], &sizes[1]);
        if (result != 0)
            goto done;
        for (unsigned i = 0; i < 2; ++i) {
            uint64_t physical;
            result = update_compact_size(archive, sizes[i], 1, &physical);
            if (result != 0)
                goto done;
            ranges[count++] = (mpq_compact_range_s){ i ? archive->mpq_header_v3.bet_table_offset
                                                       : archive->mpq_header_v3.het_table_offset,
                                                     physical };
        }
    }
    for (uint32_t i = 0; i < archive->files; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        uint64_t physical;
        result = update_compact_size(archive, entry->packed_size, 1, &physical);
        if (result != 0)
            goto done;
        if (physical && entry->offset < first_payload)
            first_payload = entry->offset;
        if (physical)
            ranges[count++] = (mpq_compact_range_s){ entry->offset, physical };
    }
    qsort(ranges, count, sizeof(*ranges), update_compact_range_compare);
    result = LIBMPQ_ERROR_FORMAT;
    for (size_t i = 0; i < count; ++i) {
        if (ranges[i].offset < cursor || ranges[i].offset > extent ||
            ranges[i].size > extent - ranges[i].offset)
            goto done;
        if (ranges[i].offset != cursor) {

            /* Only pre-payload legacy alignment is an allowed physical reservation. */
            if (archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE ||
                ranges[i].offset != first_payload ||
                ranges[i].offset != ((cursor + 511) & ~UINT64_C(511)))
                if (!(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE && i == 1 &&
                      ranges[i].offset == cursor + 16 && archive->attributes != NULL &&
                      archive->attributes->flags != 0))
                    *dense = 0;
        }
        cursor = ranges[i].offset + ranges[i].size;
    }
    if (cursor != extent)
        *dense = 0;
    result = 0;
done:
    free(ranges);
    return result;
}

/* One supplied spelling can identify multiple qualified physical rows. */
static int32_t
update_compact_name(
    mpq_archive_s *archive, char **names, uint8_t *known_slots, uint32_t slot_count,
    const char *name, void *(*allocate)(size_t)
)
{
    uint32_t hashes[3];
    libmpq__file_hash(name, &hashes[0], &hashes[1], &hashes[2]);
    for (uint32_t ordinal = 0;; ++ordinal) {
        mpq_file_identity_s identity;
        int32_t result = libmpq__file_identity(archive, name, ordinal, &identity);
        if (result != 0)
            return result == LIBMPQ_ERROR_EXIST && ordinal != 0 ? 0 : result;
        uint32_t number = identity.file_number;
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        if (names[number] != NULL && (entry->flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0 &&
            libmpq__crypto_file_key(names[number]) != libmpq__crypto_file_key(name))
            return LIBMPQ_ERROR_FORMAT;
        if (names[number] == NULL) {
            if (allocate == NULL)
                names[number] = libmpq__string_duplicate(name);
            else {
                size_t length = strlen(name);
                if (length == SIZE_MAX)
                    return LIBMPQ_ERROR_SIZE;
                names[number] = allocate(length + 1);
                if (names[number] != NULL)
                    memcpy(names[number], name, length + 1);
            }
            if (names[number] == NULL)
                return LIBMPQ_ERROR_MALLOC;
        }
        if (identity.flags & LIBMPQ_IDENTITY_CLASSIC)
            for (uint32_t slot = 0; slot < slot_count; ++slot) {
                const mpq_hash_s *row = &archive->mpq_hash[slot];
                if (row->block_table_index == entry->classic_source_index &&
                    row->hash_a == hashes[1] && row->hash_b == hashes[2])
                    known_slots[slot] = 1;
            }
        if (ordinal == UINT32_MAX)
            return LIBMPQ_ERROR_SIZE;
    }
}

/* Learn key spellings without inventing names; retain proof for each encrypted alias. */
static int32_t
update_compact_names(
    mpq_update_s *update, mpq_archive_s *archive, char **names, uint8_t *known_slots,
    uint32_t slot_count
)
{
    uint8_t *list = NULL;
    size_t size = 0;
    size_t position = 0;
    uint32_t number;
    int32_t result = 0;
    if (libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0)
        result = update_read_named(archive, LIBMPQ_LISTFILE_NAME, &list, &size);
    for (uint32_t i = 0; result == 0 && i < update->known_count; ++i)
        if (update->known_names[i] != NULL) {
            result = update_compact_name(
                archive, names, known_slots, slot_count, update->known_names[i], NULL
            );
            if (result == LIBMPQ_ERROR_EXIST)
                result = 0;
        }
    while (result == 0 && position < size) {
        size_t start = position;
        char *name;
        while (position < size && list[position] != '\r' && list[position] != '\n')
            ++position;
        if (position == start) {
            ++position;
            continue;
        }
        if (memchr(list + start, 0, position - start) != NULL) {
            result = LIBMPQ_ERROR_FORMAT;
            break;
        }
        name = malloc(position - start + 1);
        if (name == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            break;
        }
        memcpy(name, list + start, position - start);
        name[position - start] = 0;
        result = update_compact_name(archive, names, known_slots, slot_count, name, NULL);
        if (result == LIBMPQ_ERROR_EXIST)
            result = LIBMPQ_ERROR_FORMAT;
        free(name);
    }
    free(list);
    return result;
}

/* Compare stored bytes, including the exact expected KEY ciphertext transformation. */
static int32_t
update_compact_bytes(
    mpq_archive_s *source, mpq_archive_s *check, uint32_t number, uint32_t output, const char *name
)
{
    const mpq_entry_s *a = &source->mpq_entry[source->mpq_map[number].entry_index];
    const mpq_entry_s *b = &check->mpq_entry[check->mpq_map[output].entry_index];
    uint8_t before[16384];
    uint8_t after[16384];
    uint64_t offset = 0;
    uint8_t rekey = (a->flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY)) ==
                        (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY) &&
                    (uint32_t)a->offset != (uint32_t)b->offset && a->packed_size != 0;
    mpq_file_s *file = NULL;
    uint32_t key = 0;
    int32_t result = 0;
    if (a->packed_size != b->packed_size || a->unpacked_size != b->unpacked_size ||
        a->flags != b->flags || a->source_mask != b->source_mask)
        return LIBMPQ_ERROR_FORMAT;
    result = libmpq__reader_validate_payload_range(
        source, source->mpq_map[number].entry_index, 0, a->packed_size
    );
    if (result == 0)
        result = libmpq__reader_validate_payload_range(
            check, check->mpq_map[output].entry_index, 0, b->packed_size
        );
    if (result != 0)
        return result;
    if (a->offset > INT64_MAX || b->offset > INT64_MAX ||
        (uint64_t)source->archive_offset > (uint64_t)INT64_MAX - a->offset ||
        (uint64_t)check->archive_offset > (uint64_t)INT64_MAX - b->offset)
        return LIBMPQ_ERROR_FORMAT;
    uint64_t source_position = (uint64_t)source->archive_offset + a->offset;
    uint64_t candidate_position = (uint64_t)check->archive_offset + b->offset;
    if (rekey) {
        result = libmpq__reader_offsets_acquire(source, number, name);
        if (result != 0)
            return result;
        file = source->mpq_file[number];
        key = (libmpq__crypto_file_key(name) + (uint32_t)b->offset) ^ (uint32_t)a->unpacked_size;
    }

    /* Each cipher block restarts its state; the residual CRC storage is opaque. */
    uint32_t blocks = rekey ? libmpq__reader_count_file_blocks(source, number) : 0;
    if (rekey && (a->flags & LIBMPQ_FILE_FLAG_SINGLE) != 0)
        blocks = 1;
    for (uint64_t part = 0; offset < a->packed_size; ++part) {
        uint64_t end = a->packed_size;
        uint32_t old_key = 0;
        uint32_t new_key = 0;
        uint8_t table = rekey && (a->flags & LIBMPQ_FILE_FLAG_SINGLE) == 0 &&
                        (a->flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE)) != 0;
        if (rekey && table && part == 0) {
            end = file->packed_offset[0];
            old_key = file->seed - 1;
            new_key = key - 1;
        } else if (rekey && part - table < blocks) {
            uint32_t sector = (uint32_t)(part - table);
            end = file->packed_offset[sector + 1];
            old_key = file->seed + sector;
            new_key = key + sector;
        }
        if (end < offset || end > a->packed_size) {
            result = LIBMPQ_ERROR_FORMAT;
            break;
        }
        uint32_t state[4] = { old_key, 0xeeeeeeee, new_key, 0xeeeeeeee };
        while (offset < end) {
            uint32_t take =
                end - offset < sizeof(before) ? (uint32_t)(end - offset) : sizeof(before);
            result = libmpq__source_read_at(source->source, source_position + offset, before, take);
            if (result == 0)
                result =
                    libmpq__source_read_at(check->source, candidate_position + offset, after, take);
            if (result != 0)
                break;
            if (old_key != new_key)
                libmpq__crypto_reencrypt_block(before, take, state);
            if (memcmp(before, after, take) != 0) {
                result = LIBMPQ_ERROR_READ;
                break;
            }
            offset += take;
        }
        if (result != 0)
            break;
    }
    if (rekey)
        update_result(&result, libmpq__reader_offsets_release(source, number));
    return result;
}

/* Reproduce an internal member's observable storage policy through the existing writer. */
static int32_t
update_internal_options(
    mpq_archive_s *archive, uint32_t number, const char *name, size_t size,
    mpq_file_options_s *options
)
{
    int32_t result;
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    options->flags = entry->flags & ~LIBMPQ_FLAG_EXISTS;
    mpq_file_identity_s identity;
    result = libmpq__file_identity(archive, name, 0, &identity);
    if (result != 0)
        return result;
    options->locale = identity.locale;
    options->platform = identity.platform;
    if (entry->flags & LIBMPQ_FILE_FLAG_COMPRESS) {
        result = libmpq__reader_offsets_acquire(archive, number, name);
        if (result != 0)
            return result;
        for (uint32_t block = 0; block < libmpq__reader_count_file_blocks(archive, number);
             ++block) {
            uint32_t method;
            result = libmpq__reader_block_compression(archive, number, block, &method);
            if (result != 0)
                break;
            if (method == 0)
                continue; /* A raw fallback sector does not identify a codec. */
            if (!libmpq__compression_allowed(
                    archive->mpq_header.version, method, LIBMPQ_COMPRESSION_POLICY_EXTENDED
                ) ||
                (method & (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO))) {
                result = LIBMPQ_ERROR_FORMAT;
                break;
            }
            uint32_t *policy =
                block == 0 ? &options->compression_first : &options->compression_next;
            if (*policy != 0 && *policy != method) {
                result = LIBMPQ_ERROR_FORMAT;
                break;
            }
            *policy = method;
        }
        update_result(&result, libmpq__reader_offsets_release(archive, number));
        if (result != 0)
            return result;
        if (libmpq__reader_count_file_blocks(archive, number) == 1)
            options->compression_next = options->compression_first;
        if (options->compression_next == 0) {
            result = LIBMPQ_ERROR_FORMAT;
            return result;
        }
    }
    if ((options->flags & LIBMPQ_FILE_FLAG_SECTOR_CRC) &&
        (size == 0 || (options->flags & LIBMPQ_FILE_FLAG_SINGLE) ||
         !(options->flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE)))) {
        result = LIBMPQ_ERROR_FORMAT;
        return result;
    }
    return 0;
}

/* Add/remove signature lines while retaining unrelated bytes and separators. */
static int32_t
update_signature_listfile(
    mpq_archive_s *archive, uint32_t number, uint8_t add, uint8_t **data, size_t *size,
    mpq_file_options_s *options
)
{
    uint8_t *original = NULL;
    size_t length = 0;
    size_t used = 0;
    uint8_t changed = 0;
    uint8_t found = 0;
    int32_t result = update_read_named(archive, LIBMPQ_LISTFILE_NAME, &original, &length);
    if (result != 0)
        return result;
    if (length == SIZE_MAX) {
        free(original);
        return LIBMPQ_ERROR_SIZE;
    }
    uint8_t *terminated = realloc(original, length + 1);
    if (terminated == NULL) {
        free(original);
        return LIBMPQ_ERROR_MALLOC;
    }
    original = terminated;
    original[length] = 0;
    for (size_t pos = 0; pos < length;) {
        size_t begin = pos;
        while (pos < length && original[pos] != '\r' && original[pos] != '\n')
            ++pos;
        size_t end = pos;
        if (pos < length && original[pos++] == '\r' && pos < length && original[pos] == '\n')
            ++pos;
        if (memchr(original + begin, 0, end - begin) != NULL) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        uint8_t saved = original[end];
        original[end] = 0;
        int remove = libmpq__crypto_hash_string((char *)original + begin, 0x100) ==
                         libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x100) &&
                     libmpq__crypto_hash_string((char *)original + begin, 0x200) ==
                         libmpq__crypto_hash_string(LIBMPQ_SIGNATURE_NAME, 0x200);
        original[end] = saved;
        found |= remove != 0;
        if (remove && !add)
            changed = 1;
        else {
            memmove(original + used, original + begin, pos - begin);
            used += pos - begin;
        }
    }
    if (add && !found) {
        size_t extra = sizeof(LIBMPQ_SIGNATURE_NAME) + 1;
        if (used > SIZE_MAX - extra - 1) {
            result = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        uint8_t *expanded = realloc(original, used + extra + 1);
        if (expanded == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        original = expanded;
        if (used != 0 && original[used - 1] != '\n' && original[used - 1] != '\r')
            original[used++] = '\n';
        memcpy(original + used, LIBMPQ_SIGNATURE_NAME "\n", sizeof(LIBMPQ_SIGNATURE_NAME));
        used += sizeof(LIBMPQ_SIGNATURE_NAME);
        changed = 1;
    }
    if (!changed)
        goto done;
    result = update_internal_options(archive, number, LIBMPQ_LISTFILE_NAME, used, options);
    if (result != 0)
        goto done;
    *data = original;
    *size = used;
    original = NULL;
done:
    free(original);
    return result;
}

/* Wrap completed zero-origin output without changing its serialized offsets or keys. */
static int32_t
update_assemble_prefix(mpq_update_s *update, mpq_archive_s *source, char **name, char **path)
{
    FILE *input = NULL;
    FILE *output = NULL;
    char *assembled = NULL;
    char *assembled_path = NULL;
    libmpq__off_t size;
    uint64_t origin = (uint64_t)source->archive_offset;
    int32_t result = 0;
    if (origin == 0)
        return 0;
    input = libmpq__file_open(*path, "rb");
    if (input == NULL)
        return LIBMPQ_ERROR_OPEN;
    if (libmpq__file_seek(input, 0, SEEK_END) != 0 || (size = libmpq__file_tell(input)) < 0 ||
        libmpq__file_seek(input, 0, SEEK_SET) != 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto done;
    }
    if ((uint64_t)size > (uint64_t)INT64_MAX - origin) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-embedded-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &assembled,
        &output
    );
    if (result != 0)
        goto done;
    assembled_path = update_working_path(update->working_path, assembled);
    if (assembled_path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    result = update_copy_range(source, output, 0, origin);
    if (result == 0)
        result = update_copy(input, output);
    if (result == 0) {
        libmpq__off_t written = libmpq__file_tell(output);
        if (written < 0)
            result = LIBMPQ_ERROR_SEEK;
        else if ((uint64_t)written != origin + (uint64_t)size)
            result = LIBMPQ_ERROR_READ;
    }
done:
    if (input != NULL)
        update_result(&result, fclose(input) == 0 ? 0 : LIBMPQ_ERROR_CLOSE);
    if (output != NULL) {
        if (result == 0 && fflush(output) != 0)
            result = LIBMPQ_ERROR_WRITE;
        update_result(&result, fclose(output) == 0 ? 0 : LIBMPQ_ERROR_CLOSE);
    }
    if (result == 0)
        result = libmpq__directory_remove(update->directory, *name);
    if (result == 0) {
        free(*name);
        free(*path);
        *name = assembled;
        *path = assembled_path;
        assembled = assembled_path = NULL;
    }
    if (assembled != NULL)
        update_result(&result, libmpq__directory_remove(update->directory, assembled));
    free(assembled);
    free(assembled_path);
    return result;
}

/* Validate both discovery provenance and every immutable prefix byte before adoption. */
static int32_t
update_validate_prefix(
    mpq_archive_s *source, mpq_archive_s *candidate, const mpq_prefix_info_s *expected
)
{
    mpq_prefix_info_s actual;
    uint8_t before[16384];
    uint8_t after[16384];
    int32_t result = libmpq__reader_archive_prefix_info(candidate, &actual);
    if (result != 0)
        return result;
    if (actual.origin != expected->origin || actual.has_user_data != expected->has_user_data ||
        actual.user_data_position != expected->user_data_position ||
        actual.user_data_size != expected->user_data_size ||
        actual.user_data_header_size != expected->user_data_header_size ||
        actual.header_offset != expected->header_offset)
        return LIBMPQ_ERROR_FORMAT;
    for (uint64_t position = 0; position < actual.origin;) {
        size_t take = actual.origin - position < sizeof(before) ? (size_t)(actual.origin - position)
                                                                : sizeof(before);
        result = libmpq__source_read_at(source->source, position, before, take);
        if (result == 0)
            result = libmpq__source_read_at(candidate->source, position, after, take);
        if (result != 0)
            return result;
        if (memcmp(before, after, take) != 0)
            return LIBMPQ_ERROR_FORMAT;
        position += take;
    }
    return 0;
}

/* Reopen assembled output through normal discovery before operation-specific validation. */
static int32_t
update_open_candidate(
    mpq_update_s *update, mpq_archive_s *source, const mpq_prefix_info_s *prefix, char **name,
    char **path, mpq_archive_s **candidate
)
{
    *candidate = NULL;
    int32_t result = update_assemble_prefix(update, source, name, path);
    if (result == 0)
        result = libmpq__archive_open(candidate, *path, -1);
    if (result == 0)
        result = update_validate_prefix(source, *candidate, prefix);
    if (result == 0) {
        uint64_t extent =
            libmpq__header_archive_size(&(*candidate)->mpq_header, &(*candidate)->mpq_header_v3);
        if (prefix->origin > (*candidate)->file_size ||
            extent != (*candidate)->file_size - prefix->origin)
            result = LIBMPQ_ERROR_FORMAT;
    }
    if (result != 0 && *candidate != NULL) {
        (void)libmpq__archive_close(*candidate);
        *candidate = NULL;
    }
    return result;
}

/* Adopt a validated sibling without publishing or retaining operation-specific state. */
static int32_t
update_adopt_candidate(mpq_update_s *update, FILE **file, char **temporary, char **path)
{
    if (update->ops->flush(update->working) != 0)
        return LIBMPQ_ERROR_WRITE;
    FILE *previous = update->working;
    update->working = NULL;
    if (update->ops->close(previous) != 0)
        return LIBMPQ_ERROR_CLOSE;
    int32_t result = libmpq__directory_remove(update->directory, update->temporary);
    if (result != 0)
        return result;
    free(update->temporary);
    free(update->working_path);
    update->working = *file;
    update->temporary = *temporary;
    update->working_path = *path;
    update->dirty = 1;
    *file = NULL;
    *temporary = *path = NULL;
    return 0;
}

/* Compact the current stage through the shared writer, then adopt only a validated candidate. */
int32_t
libmpq__update_transaction_compact(
    mpq_update_s *update, const char *const *filenames, size_t filename_count
)
{
    const uint32_t supported = LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                               LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_SECTOR_CRC |
                               LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE |
                               LIBMPQ_FILE_FLAG_KEY;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *writer = NULL;
    mpq_archive_s *check = NULL;
    mpq_archive_s identity_check = { 0 };
    mpq_file_attributes_s *attributes = NULL;
    uint64_t *positions = NULL;
    uint32_t *rows = NULL;
    char **names = NULL;
    uint8_t *known_slots = NULL;
    FILE *file = NULL;
    char *temporary = NULL;
    char *path = NULL;
    uint8_t *list = NULL;
    size_t list_size = 0;
    mpq_file_options_s list_options = { 0 };
    mpq_entry_s encoded_list = { 0 };
    mpq_prefix_info_s prefix;
    uint32_t signature = UINT32_MAX;
    uint32_t attribute = UINT32_MAX;
    uint32_t listfile = UINT32_MAX;
    uint32_t flags = 0;
    uint32_t count = 0;
    uint32_t classic_count = 0;
    uint32_t retained = 0;
    uint8_t dense = 0;
    uint64_t next;
    char **prepared_names = NULL;
    uint32_t prepared_count = 0;
    int32_t result;
    if (update == NULL || update->working == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (filename_count != 0) {
        if (filenames == NULL)
            return LIBMPQ_ERROR_EXIST;
        if (filename_count > UINT32_MAX || filename_count > SIZE_MAX / sizeof(*filenames))
            return LIBMPQ_ERROR_SIZE;
        uint64_t capacity = (uint64_t)update->known_count + filename_count + 2;
        if (capacity > UINT32_MAX || capacity > SIZE_MAX / sizeof(*filenames))
            return LIBMPQ_ERROR_SIZE;
        for (size_t i = 0; i < filename_count; ++i)
            if (filenames[i] == NULL || filenames[i][0] == '\0')
                return LIBMPQ_ERROR_EXIST;
    }
    if (fflush(update->working) != 0)
        return LIBMPQ_ERROR_WRITE;
    result = libmpq__archive_open(&archive, update->working_path, -1);
    if (result != 0)
        return result;
    result = libmpq__reader_archive_prefix_info(archive, &prefix);
    if (result != 0)
        goto done;
    uint64_t extent = libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    if (prefix.origin > archive->file_size || extent > archive->file_size - prefix.origin ||
        extent > (uint64_t)INT64_MAX - prefix.origin) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    uint64_t end = prefix.origin + extent;
    if (archive->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_FOUR ||
        archive->mpq_header.header_size !=
            (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE ? LIBMPQ_HEADER_WIRE_SIZE
             : archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO
                 ? LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE
             : archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE
                 ? LIBMPQ_HEADER_V3_WIRE_SIZE
                 : LIBMPQ_HEADER_V4_WIRE_SIZE)) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (archive->file_size != end) {
        uint32_t signatures;
        result = libmpq__archive_signatures(archive, &signatures);
        if (result != 0)
            goto done;
        if (archive->file_size < end || archive->file_size - end != LIBMPQ_STRONG_TRAILER_SIZE ||
            !(signatures & LIBMPQ_SIGNATURE_STRONG)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    }
    count = archive->files;
    classic_count = archive->mpq_header.hash_table_count;
    if (count == UINT32_MAX || ((uint64_t)count + 1) * sizeof(*attributes) > SIZE_MAX) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    if (filename_count != 0) {
        uint64_t capacity = (uint64_t)update->known_count + count + filename_count + 2;
        if (capacity > UINT32_MAX || capacity > SIZE_MAX / sizeof(*names)) {
            result = LIBMPQ_ERROR_SIZE;
            goto done;
        }
    }
    names = calloc((size_t)count + 1, sizeof(*names));
    known_slots = calloc(classic_count ? classic_count : 1, 1);
    rows = malloc(((size_t)count + 1) * sizeof(*rows));
    positions = calloc((size_t)count + 1, sizeof(*positions));
    attributes = calloc((size_t)count + 1, sizeof(*attributes));
    if (names == NULL || known_slots == NULL || rows == NULL || positions == NULL ||
        attributes == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    for (uint32_t i = 0; i < count; ++i)
        rows[i] = UINT32_MAX;
    result = update_compact_names(update, archive, names, known_slots, classic_count);
    if (result != 0)
        goto done;
    for (size_t i = 0; i < filename_count; ++i) {
        result = update_compact_name(
            archive, names, known_slots, classic_count, filenames[i], update->ops->allocate_names
        );
        if (result != 0)
            goto done;
    }
    (void)libmpq__file_number(archive, LIBMPQ_SIGNATURE_NAME, &signature);
    (void)libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &attribute);
    (void)libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &listfile);
    const char *special[] = { LIBMPQ_SIGNATURE_NAME, LIBMPQ_ATTRIBUTES_NAME, LIBMPQ_LISTFILE_NAME };
    for (unsigned i = 0; i < 3; ++i) {
        mpq_file_identity_s identity;
        result = libmpq__file_identity(archive, special[i], 1, &identity);
        if (result != LIBMPQ_ERROR_EXIST) {
            result = result != 0 ? result : LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    }
    if (listfile != UINT32_MAX) {
        result = update_compact_name(
            archive, names, known_slots, classic_count, LIBMPQ_LISTFILE_NAME, NULL
        );
        if (result != 0)
            goto done;
    }
    result = libmpq__attributes_load(archive);
    if (result == 0)
        flags = archive->attributes->flags;
    else if (result != LIBMPQ_ERROR_EXIST)
        goto done;
    if ((flags & ~LIBMPQ_ATTRIBUTES_ALL) != 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    identity_check.write_capacity = count + 1;
    result = libmpq__writer_identity_init(&identity_check, archive);
    if (result != 0)
        goto done;
    result = update_compact_hashes(archive);
    if (result != 0)
        goto done;
    if (archive->het_data != NULL && archive->mpq_header_v4.raw_chunk_size != 0) {
        result = libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE);
        if (result == 0)
            result = libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE);
        if (result != 0)
            goto done;
    }
    for (uint32_t i = 0; i < count; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        if ((entry->flags & ~supported) != 0 || entry->packed_size > UINT32_MAX ||
            entry->unpacked_size > UINT32_MAX || entry->offset >> 32 > UINT16_MAX ||
            libmpq__reader_validate_payload_range(
                archive, archive->mpq_map[i].entry_index, 0, entry->packed_size
            ) != 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) {
            mpq_bet_entry_s record;
            result = libmpq__bet_record_decode(&archive->mpq_bet, entry->bet_source_index, &record);
            if (result != 0 || record.unknown != 0) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
        if (flags) {
            result = libmpq__file_attributes(archive, i, &attributes[i]);
            if (result != 0 || attributes[i].patch_bit ||
                (i != attribute &&
                 archive->mpq_entry[archive->mpq_map[i].entry_index].classic_source_index >=
                     archive->attributes->entries)) {
                result = result != 0 ? result : LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
        uint32_t references = (entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0
                                  ? update_block_references(archive, entry->classic_source_index)
                                  : 0;
        if ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0 && references == 0) {

            /* Only a classic-only row with no live identity is safely obsolete. */
            if (entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            continue;
        }
        if ((i == signature || i == attribute || i == listfile) && references > 1) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if ((entry->flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0 && references > 1) {
            if (names[i] == NULL) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto done;
            }
            for (uint32_t slot = 0; slot < classic_count; ++slot) {
                const mpq_hash_s *hash = &archive->mpq_hash[slot];
                if (hash->block_table_index == entry->classic_source_index && !known_slots[slot]) {
                    result = LIBMPQ_ERROR_FORMAT;
                    goto done;
                }
            }
        }
        uint32_t mismatches;
        result = libmpq__file_verify(archive, i, LIBMPQ_VERIFY_RAW_MD5, &mismatches);
        if (result != 0 || mismatches != 0) {
            result = result != 0 ? result : LIBMPQ_ERROR_READ;
            goto done;
        }
        rows[i] = 0;
    }
    result = update_compact_layout(archive, &dense);
    if (result != 0)
        goto done;
    for (uint32_t i = 0; i < count; ++i)
        if (rows[i] == UINT32_MAX)
            dense = 0;
    if (dense)
        goto done;
    if (signature != UINT32_MAX && listfile != UINT32_MAX) {
        result = update_signature_listfile(archive, listfile, 0, &list, &list_size, &list_options);
        if (result != 0)
            goto done;
    }
    if (list != NULL && flags != 0) {
        if (flags & LIBMPQ_ATTRIBUTE_CRC32)
            attributes[listfile].crc32 = (uint32_t)crc32(0, list, (uInt)list_size);
        if (flags & LIBMPQ_ATTRIBUTE_MD5) {
            mpq_md5_s md5;
            libmpq__md5_init(&md5);
            libmpq__md5_update(&md5, list, list_size);
            libmpq__md5_final(&md5, attributes[listfile].md5);
            const uint8_t unavailable[16] = { 0 };
            if (memcmp(attributes[listfile].md5, unavailable, 16) != 0)
                attributes[listfile].flags |= LIBMPQ_ATTRIBUTE_MD5;
            else
                attributes[listfile].flags &= ~LIBMPQ_ATTRIBUTE_MD5;
        }
    }

    /* Plan ordinary packed rows first; generated metadata follows without source holes. */
    next = archive->mpq_header.header_size;
    for (uint32_t i = 0; i < count; ++i) {
        if (rows[i] == UINT32_MAX || i == signature || i == attribute ||
            (i == listfile && list != NULL))
            continue;
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        positions[i] = next;
        if ((entry->flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY)) ==
                (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY) &&
            entry->packed_size != 0 && (uint32_t)next != (uint32_t)entry->offset &&
            names[i] == NULL) {
            result = LIBMPQ_ERROR_DECRYPT;
            goto done;
        }
        uint64_t physical;
        result = update_compact_size(archive, entry->packed_size, 1, &physical);
        if (result != 0 || next > INT64_MAX || physical > (uint64_t)INT64_MAX - next) {
            result = LIBMPQ_ERROR_SIZE;
            goto done;
        }
        next += physical;
    }
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-compact-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary, &file
    );
    if (result != 0)
        goto done;
    path = update_working_path(update->working_path, temporary);
    if (path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    mpq_archive_create_options_s create = { archive->mpq_header.version, count + 1,
                                            512u << archive->mpq_header.block_size,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED, 0 };
    result = libmpq__writer_archive_create_compact(
        &writer, path, file, &create, archive->mpq_header_v4.raw_chunk_size
    );
    file = NULL;
    if (result != 0)
        goto done;
    result = libmpq__writer_identity_init(writer, archive);
    if (result != 0)
        goto done;

    /* Source identity state is separate from names, so aliases never duplicate payloads. */
    for (uint32_t i = 0; i < count; ++i) {
        if (rows[i] == UINT32_MAX || i == signature || i == attribute ||
            (i == listfile && list != NULL))
            continue;
        if (libmpq__file_seek(writer->fp, 0, SEEK_END) != 0 ||
            (uint64_t)libmpq__file_tell(writer->fp) != positions[i]) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        rows[i] = writer->write_next_block;
        result = libmpq__writer_relocate_member(
            writer, archive, i, names[i], flags ? &attributes[i] : NULL
        );
        if (result != 0)
            goto done;
    }

    /* Encode changed metadata last, letting the writer account for its actual extent. */
    if (list != NULL) {
        rows[listfile] = writer->write_next_block;
        positions[listfile] = next;
        writer->write_internal = 1;
        result =
            libmpq__writer_file_add(writer, LIBMPQ_LISTFILE_NAME, list, list_size, &list_options);
        writer->write_internal = 0;
        if (result == 0)
            result = libmpq__writer_identity_bind(writer, archive, listfile);
        if (result != 0)
            goto done;
        const mpq_block_s *block = &writer->mpq_block[rows[listfile]];
        encoded_list.offset = positions[listfile];
        encoded_list.packed_size = block->packed_size;
        encoded_list.unpacked_size = block->unpacked_size;
        encoded_list.flags = block->flags;
        if (encoded_list.flags != (list_options.flags | LIBMPQ_FLAG_EXISTS)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    }
    if (attribute != UINT32_MAX) {
        uint32_t row = writer->write_next_block;
        mpq_file_attributes_s *mapped = calloc(writer->write_capacity, sizeof(*mapped));
        uint8_t *data = NULL;
        size_t size = 0;
        if (mapped == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        for (uint32_t i = 0; i < count; ++i)
            if (i != signature && i != attribute && rows[i] != UINT32_MAX)
                mapped[rows[i]] = attributes[i];
        mapped[row] = attributes[attribute];
        result = libmpq__attributes_serialize(
            mapped,
            archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE ? row + 1
                                                                        : writer->write_capacity,
            row, flags, &data, &size
        );
        free(mapped);
        if (result == 0) {
            mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                           LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
            rows[attribute] = row;
            writer->write_internal = 1;
            result = libmpq__writer_file_add(writer, LIBMPQ_ATTRIBUTES_NAME, data, size, &options);
            writer->write_internal = 0;
            if (result == 0)
                result = libmpq__writer_identity_bind(writer, archive, attribute);
        }
        free(data);
        if (result != 0)
            goto done;
    }
    retained = writer->write_next_block;
    result = libmpq__archive_close(writer);
    writer = NULL;
    if (result != 0)
        goto done;
    result = update_open_candidate(update, archive, &prefix, &temporary, &path, &check);
    if (result != 0)
        goto done;
    result = update_compact_layout(check, &dense);
    if (result != 0 || !dense || check->files != retained ||
        check->mpq_header.version != archive->mpq_header.version ||
        check->mpq_header_v4.raw_chunk_size != archive->mpq_header_v4.raw_chunk_size ||
        check->mpq_header.hash_table_count != archive->mpq_header.hash_table_count) {
        result = result != 0 ? result : LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (check->het_data != NULL && check->mpq_header_v4.raw_chunk_size != 0) {
        result = libmpq__reader_verify_ext_raw_md5(check, LIBMPQ_HET_SIGNATURE);
        if (result == 0)
            result = libmpq__reader_verify_ext_raw_md5(check, LIBMPQ_BET_SIGNATURE);
        if (result != 0)
            goto done;
    }
    for (uint32_t slot = 0; slot < classic_count; ++slot) {
        mpq_hash_s expected = archive->mpq_hash[slot];
        if (expected.block_table_index < LIBMPQ_HASH_DELETED) {
            uint32_t index;
            result = libmpq__entry_index_from_classic(archive, expected.block_table_index, &index);
            if (result != 0)
                goto done;
            uint32_t number = archive->mpq_entry[index].file_number;
            expected.block_table_index = number == signature ? LIBMPQ_HASH_DELETED : rows[number];
        }
        const mpq_hash_s *actual = &check->mpq_hash[slot];
        if (expected.hash_a != actual->hash_a || expected.hash_b != actual->hash_b ||
            expected.locale != actual->locale || expected.platform != actual->platform ||
            expected.block_table_index != actual->block_table_index) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    }
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t index;
        uint32_t number;
        if (i == signature || rows[i] == UINT32_MAX)
            continue;
        result = check->het_data != NULL ? libmpq__entry_index_from_bet(check, rows[i], &index)
                                         : libmpq__entry_index_from_classic(check, rows[i], &index);
        if (result != 0)
            goto done;
        number = check->mpq_entry[index].file_number;
        if (i != attribute && !(i == listfile && list != NULL)) {
            if (check->mpq_entry[index].offset != positions[i]) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            result = update_compact_bytes(archive, check, i, number, names[i]);
            if (result != 0)
                goto done;
        }
        if (i == listfile && list != NULL) {
            const mpq_entry_s *actual = &check->mpq_entry[index];
            uint8_t *decoded = NULL;
            size_t decoded_size = 0;
            if (actual->offset != encoded_list.offset || actual->flags != encoded_list.flags ||
                actual->packed_size != encoded_list.packed_size ||
                actual->unpacked_size != list_size) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
            result = update_read_named(check, LIBMPQ_LISTFILE_NAME, &decoded, &decoded_size);
            if (result == 0 && (decoded_size != list_size || memcmp(decoded, list, list_size) != 0))
                result = LIBMPQ_ERROR_FORMAT;
            free(decoded);
            if (result != 0)
                goto done;
            result = libmpq__reader_offsets_acquire(check, number, LIBMPQ_LISTFILE_NAME);
            if (result != 0)
                goto done;
            for (uint32_t block = 0; block < libmpq__reader_count_file_blocks(check, number);
                 ++block) {
                uint32_t method;
                result = libmpq__reader_block_compression(check, number, block, &method);
                if (result != 0 || ((actual->flags & LIBMPQ_FILE_FLAG_COMPRESS) && method != 0 &&
                                    method != (block == 0 ? list_options.compression_first
                                                          : list_options.compression_next))) {
                    result = result != 0 ? result : LIBMPQ_ERROR_FORMAT;
                    break;
                }
            }
            update_result(&result, libmpq__reader_offsets_release(check, number));
            if (result != 0)
                goto done;
        }
        uint32_t mismatches;
        result = libmpq__file_verify(check, number, LIBMPQ_VERIFY_RAW_MD5, &mismatches);
        if (result != 0 || mismatches != 0) {
            result = result != 0 ? result : LIBMPQ_ERROR_READ;
            goto done;
        }
        if (flags && i != attribute) {
            mpq_file_attributes_s actual;
            result = libmpq__file_attributes(check, number, &actual);
            if (result != 0 || actual.flags != attributes[i].flags ||
                actual.filetime != attributes[i].filetime || actual.crc32 != attributes[i].crc32 ||
                actual.patch_bit != attributes[i].patch_bit ||
                memcmp(actual.md5, attributes[i].md5, 16) != 0) {
                result = result != 0 ? result : LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
        if (check->het_data != NULL) {
            uint64_t low;
            uint64_t full = 0;
            unsigned references = 0;
            for (uint32_t slot = 0; slot < check->mpq_het.header.total_count; ++slot) {
                uint64_t row;
                if (check->mpq_het.name_hash1[slot] == LIBMPQ_HET_SLOT_FREE)
                    continue;
                if (libmpq__het_slot_index(&check->mpq_het, slot, &row) != 0) {
                    result = LIBMPQ_ERROR_FORMAT;
                    goto done;
                }
                if (row == rows[i]) {
                    ++references;
                    full = (uint64_t)check->mpq_het.name_hash1[slot] << 56;
                }
            }
            result = libmpq__bet_name_hash2(&check->mpq_bet, rows[i], &low);
            if (result != 0 || references != 1 ||
                (full | low) !=
                    identity_check.write_identity->source_hashes[archive->mpq_map[i].entry_index]) {
                result = LIBMPQ_ERROR_FORMAT;
                goto done;
            }
        }
    }
    result = update_prepare_names(
        update, check, names, count, filenames, (uint32_t)filename_count, NULL, NULL,
        &prepared_names, &prepared_count
    );
    if (result != 0)
        goto done;
    result = libmpq__archive_close(check);
    check = NULL;
    if (result != 0)
        goto done;
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != 0)
        goto done;
    file = libmpq__file_open(path, "r+b");
    if (file == NULL) {
        result = LIBMPQ_ERROR_OPEN;
        goto done;
    }
    result = update_adopt_candidate(update, &file, &temporary, &path);
    if (result != 0)
        goto done;
    update_adopt_names(update, &prepared_names, prepared_count);
done:
    update_free_names(prepared_names, prepared_count);
    libmpq__writer_identity_free(&identity_check);
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (writer != NULL)
        (void)libmpq__archive_close(writer);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (file != NULL)
        (void)fclose(file);
    if (temporary != NULL)
        (void)libmpq__directory_remove(update->directory, temporary);
    if (names != NULL) {
        for (uint32_t i = 0; i < count; ++i)
            free(names[i]);
        free(names);
    }
    free(known_slots);
    free(rows);
    free(positions);
    free(attributes);
    free(list);
    free(temporary);
    free(path);
    return result;
}

/* Internal members must have one neutral identity and an exclusive physical association. */
static int32_t
update_sign_special(mpq_archive_s *archive, const char *name, uint32_t *number)
{
    mpq_file_identity_s identity;
    int32_t result = libmpq__file_identity(archive, name, 0, &identity);
    if (result != 0)
        return result;
    *number = identity.file_number;
    if (identity.locale != 0 || identity.platform != 0 ||
        (archive->het_data != NULL && !(identity.flags & LIBMPQ_IDENTITY_BET)) ||
        libmpq__file_identity(archive, name, 1, &identity) != LIBMPQ_ERROR_EXIST)
        return LIBMPQ_ERROR_FORMAT;
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[*number].entry_index];
    if ((entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0 &&
        update_block_references(archive, entry->classic_source_index) != 1)
        return LIBMPQ_ERROR_FORMAT;
    return 0;
}

/* Physical signing validates layout/integrity without recovering opaque member names or keys. */
static int32_t
update_sign_source(mpq_archive_s *archive, uint64_t *extent, uint32_t *signatures)
{
    uint8_t dense;
    int32_t result = libmpq__archive_signature_extent(archive, extent);
    if (result == 0)
        result = libmpq__archive_signatures(archive, signatures);
    if (result != 0)
        return result;
    if (archive->archive_offset < 0 ||
        *extent > (uint64_t)INT64_MAX - (uint64_t)archive->archive_offset ||
        *extent != libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3))
        return LIBMPQ_ERROR_FORMAT;
    uint64_t end = (uint64_t)archive->archive_offset + *extent;
    if (end > archive->file_size ||
        archive->file_size - end !=
            ((*signatures & LIBMPQ_SIGNATURE_STRONG) ? LIBMPQ_STRONG_TRAILER_SIZE : 0))
        return LIBMPQ_ERROR_FORMAT;
    result = update_compact_layout(archive, &dense);
    if (result == 0)
        result = update_compact_hashes(archive);
    if (result != 0)
        return result;
    result = libmpq__attributes_load(archive);
    if (result != 0 && result != LIBMPQ_ERROR_EXIST)
        return result;
    if (archive->attributes != NULL && (archive->attributes->flags & ~LIBMPQ_ATTRIBUTES_ALL) != 0)
        return LIBMPQ_ERROR_FORMAT;
    for (uint32_t i = 0; i < archive->files; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        uint32_t mismatch;
        if ((entry->flags & (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) != 0)
            return LIBMPQ_ERROR_FORMAT;
        if (entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) {
            mpq_bet_entry_s record;
            result = libmpq__bet_record_decode(&archive->mpq_bet, entry->bet_source_index, &record);
            if (result != 0 || record.unknown != 0)
                return result != 0 ? result : LIBMPQ_ERROR_FORMAT;
        }
        if (archive->attributes != NULL) {
            mpq_file_attributes_s attributes;
            result = libmpq__file_attributes(archive, i, &attributes);
            if (result != 0 || attributes.patch_bit)
                return result != 0 ? result : LIBMPQ_ERROR_FORMAT;
        }
        result = libmpq__file_verify(archive, i, LIBMPQ_VERIFY_RAW_MD5, &mismatch);
        if (result != 0 || mismatch != 0)
            return result != 0 ? result : LIBMPQ_ERROR_READ;
    }
    if (archive->het_data != NULL && archive->mpq_header_v4.raw_chunk_size != 0) {
        result = libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE);
        if (result == 0)
            result = libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE);
        if (result != 0)
            return result;
    }
    if (*signatures & LIBMPQ_SIGNATURE_WEAK) {
        uint32_t number;
        result = update_sign_special(archive, LIBMPQ_SIGNATURE_NAME, &number);
        if (result != 0)
            return result;
        if (archive->attributes != NULL) {
            mpq_file_attributes_s attributes;
            const uint8_t zero[16] = { 0 };
            result = libmpq__file_attributes(archive, number, &attributes);
            if (result != 0 || attributes.crc32 != 0 || attributes.filetime != 0 ||
                memcmp(attributes.md5, zero, sizeof(zero)) != 0)
                return result != 0 ? result : LIBMPQ_ERROR_FORMAT;
        }
    }
    return 0;
}

/* Compare stored physical ranges with bounded memory; no plaintext trust is implied. */
static int32_t
update_sign_bytes(mpq_archive_s *source, mpq_archive_s *candidate, uint64_t offset, uint64_t size)
{
    uint8_t before[16384];
    uint8_t after[16384];
    if (offset > source->file_size || size > source->file_size - offset ||
        offset > candidate->file_size || size > candidate->file_size - offset)
        return LIBMPQ_ERROR_FORMAT;
    while (size != 0) {
        size_t take = size < sizeof(before) ? (size_t)size : sizeof(before);
        int32_t result = libmpq__source_read_at(source->source, offset, before, take);
        if (result == 0)
            result = libmpq__source_read_at(candidate->source, offset, after, take);
        if (result != 0)
            return result;
        if (memcmp(before, after, take) != 0)
            return LIBMPQ_ERROR_READ;
        offset += take;
        size -= take;
    }
    return 0;
}

/* Add only the absent weak member, preserving physical payloads through the shared writer. */
static int32_t
update_sign_rebuild(
    mpq_update_s *update, mpq_archive_s *source, const mpq_prefix_info_s *prefix, char **temporary,
    char **path, mpq_archive_s **candidate
)
{
    mpq_archive_s *writer = NULL;
    FILE *file = NULL;
    uint32_t count = source->files;
    uint32_t attribute = UINT32_MAX;
    uint32_t listfile = UINT32_MAX;
    uint32_t flags = source->attributes != NULL ? source->attributes->flags : 0;
    uint32_t *rows = NULL;
    uint64_t *hashes = NULL;
    char **names = NULL;
    mpq_file_attributes_s *mapped = NULL;
    uint8_t *list = NULL;
    size_t list_size = 0;
    mpq_file_options_s list_options = { 0 };
    mpq_file_options_s attribute_options = { 0 };
    int32_t result;
    if (count == UINT32_MAX || ((uint64_t)count + 1) * sizeof(*mapped) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    result = update_sign_special(source, LIBMPQ_ATTRIBUTES_NAME, &attribute);
    if (result != 0 && result != LIBMPQ_ERROR_EXIST)
        return result;
    result = update_sign_special(source, LIBMPQ_LISTFILE_NAME, &listfile);
    if (result != 0 && result != LIBMPQ_ERROR_EXIST)
        return result;
    if (listfile != UINT32_MAX) {
        result = update_signature_listfile(source, listfile, 1, &list, &list_size, &list_options);
        if (result != 0)
            return result;
    }
    rows = calloc((size_t)count + 1, sizeof(*rows));
    hashes = calloc((size_t)count + 1, sizeof(*hashes));
    names = calloc((size_t)count + 1, sizeof(*names));
    mapped = calloc((size_t)count + 1, sizeof(*mapped));
    if (rows == NULL || hashes == NULL || names == NULL || mapped == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-sign-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, temporary, &file
    );
    if (result != 0)
        goto done;
    *path = update_working_path(update->working_path, *temporary);
    if (*path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    mpq_archive_create_options_s create = { source->mpq_header.version, count + 1,
                                            source->block_size,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED, 0 };
    result = source->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR
                 ? libmpq__writer_archive_create_v4(&writer, *path, file, &create, 0)
                 : libmpq__writer_archive_create_file(&writer, *path, file, &create);
    file = NULL;
    if (result != 0)
        goto done;
    result = libmpq__writer_identity_init(writer, source);
    if (result != 0)
        goto done;
    uint64_t extent = libmpq__header_archive_size(&source->mpq_header, &source->mpq_header_v3);
    if (extent == 0 || extent > INT64_MAX ||
        libmpq__file_seek(writer->fp, (libmpq__off_t)(extent - 1), SEEK_SET) != 0 ||
        fputc(0, writer->fp) == EOF) {
        result = LIBMPQ_ERROR_WRITE;
        goto done;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (i == attribute || (i == listfile && list != NULL))
            continue;
        mpq_file_attributes_s attributes = { 0 };
        if (flags != 0) {
            result = libmpq__file_attributes(source, i, &attributes);
            if (result != 0)
                goto done;
        }
        rows[i] = writer->write_next_block;
        mapped[rows[i]] = attributes;
        result = libmpq__writer_preserve_member(writer, source, i, flags ? &attributes : NULL);
        if (result != 0)
            goto done;
        hashes[i] = writer->write_identity->source_hashes[source->mpq_map[i].entry_index];
    }
    if (libmpq__file_seek(writer->fp, 0, SEEK_END) != 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto done;
    }
    const uint8_t zero[LIBMPQ_SIGNATURE_SIZE] = { 0 };
    const mpq_file_options_s raw = { 0 };
    writer->write_internal = 1;
    result = libmpq__writer_file_add(writer, LIBMPQ_SIGNATURE_NAME, zero, sizeof(zero), &raw);
    if (result != 0)
        goto done;
    if (list != NULL) {
        rows[listfile] = writer->write_next_block;
        names[listfile] = (char *)LIBMPQ_LISTFILE_NAME;
        if (flags != 0) {
            result = libmpq__file_attributes(source, listfile, &mapped[rows[listfile]]);
            if (result != 0)
                goto done;
            if (flags & LIBMPQ_ATTRIBUTE_CRC32)
                mapped[rows[listfile]].crc32 = (uint32_t)crc32(0, list, (uInt)list_size);
            if (flags & LIBMPQ_ATTRIBUTE_MD5) {
                mpq_md5_s md5;
                libmpq__md5_init(&md5);
                libmpq__md5_update(&md5, list, list_size);
                libmpq__md5_final(&md5, mapped[rows[listfile]].md5);
            }
        }
        result =
            libmpq__writer_file_add(writer, LIBMPQ_LISTFILE_NAME, list, list_size, &list_options);
        if (result == 0)
            result = libmpq__writer_identity_bind(writer, source, listfile);
        if (result != 0)
            goto done;
    }
    if (attribute != UINT32_MAX) {
        uint8_t *data = NULL;
        size_t size;
        uint32_t row = writer->write_next_block;
        rows[attribute] = row;
        names[attribute] = (char *)LIBMPQ_ATTRIBUTES_NAME;
        result = libmpq__attributes_serialize(
            mapped,
            source->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_THREE ? row + 1
                                                                       : writer->write_capacity,
            row, flags, &data, &size
        );
        if (result == 0)
            result = update_internal_options(
                source, attribute, LIBMPQ_ATTRIBUTES_NAME, size, &attribute_options
            );
        if (result == 0)
            result = libmpq__writer_file_add(
                writer, LIBMPQ_ATTRIBUTES_NAME, data, size, &attribute_options
            );
        free(data);
        if (result == 0)
            result = libmpq__writer_identity_bind(writer, source, attribute);
        if (result != 0)
            goto done;
    }
    writer->write_internal = 0;
    result = libmpq__archive_close(writer);
    writer = NULL;
    if (result == 0)
        result = update_open_candidate(update, source, prefix, temporary, path, candidate);
    if (result != 0)
        goto done;
    if ((*candidate)->files != count + 1) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    result =
        update_check_unknowns(source, *candidate, names, rows, hashes, flags, UINT32_MAX, NULL);
    if (result != 0)
        goto done;
    for (uint32_t i = 0; i < count; ++i) {
        if (names[i] == NULL)
            continue;
        uint32_t number;
        result = update_sign_special(*candidate, names[i], &number);
        if (result != 0)
            goto done;
        const mpq_entry_s *entry =
            &(*candidate)->mpq_entry[(*candidate)->mpq_map[number].entry_index];
        if (!(entry->source_mask & LIBMPQ_ENTRY_SOURCE_CLASSIC) ||
            entry->classic_source_index != rows[i]) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        const mpq_file_options_s *storage = i == listfile ? &list_options : &attribute_options;
        if (entry->flags != (storage->flags | LIBMPQ_FLAG_EXISTS)) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        result = libmpq__reader_offsets_acquire(*candidate, number, names[i]);
        if (result != 0)
            goto done;
        for (uint32_t block = 0; block < libmpq__reader_count_file_blocks(*candidate, number);
             ++block) {
            uint32_t method;
            result = libmpq__reader_block_compression(*candidate, number, block, &method);
            if (result != 0 ||
                ((entry->flags & LIBMPQ_FILE_FLAG_COMPRESS) && method != 0 &&
                 method != (block == 0 ? storage->compression_first : storage->compression_next))) {
                result = result != 0 ? result : LIBMPQ_ERROR_FORMAT;
                break;
            }
        }
        update_result(&result, libmpq__reader_offsets_release(*candidate, number));
        if (result != 0)
            goto done;
        if (i == listfile) {
            uint8_t *decoded = NULL;
            size_t size;
            result = update_read_named(*candidate, LIBMPQ_LISTFILE_NAME, &decoded, &size);
            if (result == 0 && (size != list_size || memcmp(decoded, list, size) != 0 ||
                                entry->flags != (list_options.flags | LIBMPQ_FLAG_EXISTS)))
                result = LIBMPQ_ERROR_FORMAT;
            free(decoded);
            if (result != 0)
                goto done;
            if (flags != 0) {
                mpq_file_attributes_s actual;
                const mpq_file_attributes_s *expected = &mapped[rows[i]];
                result = libmpq__file_attributes(*candidate, number, &actual);
                if (result == 0 &&
                    (actual.flags != expected->flags || actual.patch_bit != expected->patch_bit ||
                     actual.filetime != expected->filetime || actual.crc32 != expected->crc32 ||
                     memcmp(actual.md5, expected->md5, 16) != 0))
                    result = LIBMPQ_ERROR_FORMAT;
                if (result != 0)
                    goto done;
            }
        }
    }
done:
    if (writer != NULL) {
        libmpq__writer_file_abort(writer->write_current);
        writer->write_current = NULL;
        (void)libmpq__archive_close(writer);
    }
    if (file != NULL)
        update_result(&result, fclose(file) == 0 ? 0 : LIBMPQ_ERROR_CLOSE);
    free(rows);
    free(hashes);
    free(names);
    free(mapped);
    free(list);
    return result;
}

/*
 * Generate now, validate storage/preservation, then adopt.
 * Private keys never enter update state.
 */
int32_t
libmpq__update_transaction_sign(
    mpq_update_s *update, uint32_t type, const uint8_t *key, size_t key_size
)
{
    mpq_archive_s *source = NULL;
    mpq_archive_s *candidate = NULL;
    mpq_prefix_info_s prefix;
    FILE *file = NULL;
    char *temporary = NULL;
    char *path = NULL;
    uint64_t extent;
    uint32_t signatures;
    uint32_t expected;
    uint64_t changed = UINT64_MAX;
    char **prepared_names = NULL;
    uint32_t prepared_count = 0;
    int32_t result;
    uint8_t rebuilt = 0;
    if (update == NULL || update->working == NULL)
        return LIBMPQ_ERROR_EXIST;
    if ((type == LIBMPQ_SIGNATURE_WEAK     ? libmpq__rsa_weak_key_validate(key, key_size)
         : type == LIBMPQ_SIGNATURE_STRONG ? libmpq__rsa_strong_key_validate(key, key_size)
                                           : LIBMPQ_ERROR_FORMAT) != 0 ||
        (type == LIBMPQ_SIGNATURE_STRONG && update->mpqe))
        return LIBMPQ_ERROR_FORMAT;
    if (fflush(update->working) != 0)
        return LIBMPQ_ERROR_WRITE;
    result = libmpq__archive_open(&source, update->working_path, -1);
    if (result != 0)
        return result;
    result = libmpq__reader_archive_prefix_info(source, &prefix);
    if (result == 0)
        result = update_sign_source(source, &extent, &signatures);
    if (result != 0)
        goto done;
    if (type == LIBMPQ_SIGNATURE_WEAK && source->mpq_header_v4.raw_chunk_size != 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    expected = type == LIBMPQ_SIGNATURE_WEAK ? LIBMPQ_SIGNATURE_WEAK
                                             : signatures | LIBMPQ_SIGNATURE_STRONG;
    rebuilt = type == LIBMPQ_SIGNATURE_WEAK && !(signatures & LIBMPQ_SIGNATURE_WEAK);
    if (rebuilt) {
        result = update_sign_rebuild(update, source, &prefix, &temporary, &path, &candidate);
        if (result != 0)
            goto done;
    } else {
        result = libmpq__directory_temporary_reopenable(
            update->directory, ".libmpq-sign-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary, &file
        );
        if (result != 0)
            goto done;
        path = update_working_path(update->working_path, temporary);
        if (path == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto done;
        }
        result = update_copy_range(source, file, 0, prefix.origin + extent);
        if (result == 0 && fflush(file) != 0)
            result = LIBMPQ_ERROR_WRITE;
        update_result(&result, fclose(file) == 0 ? 0 : LIBMPQ_ERROR_CLOSE);
        file = NULL;
        if (result == 0)
            result = libmpq__archive_open(&candidate, path, -1);
        if (result != 0)
            goto done;
    }
    if (type == LIBMPQ_SIGNATURE_WEAK) {
        uint32_t number;
        result = update_sign_special(candidate, LIBMPQ_SIGNATURE_NAME, &number);
        if (result != 0)
            goto done;
        changed = prefix.origin +
                  candidate->mpq_entry[candidate->mpq_map[number].entry_index].offset +
                  LIBMPQ_SIGNATURE_PREFIX_SIZE;
    }
    file = libmpq__file_open(path, "r+b");
    if (file == NULL) {
        result = LIBMPQ_ERROR_OPEN;
        goto done;
    }
    result = libmpq__signature_sign_file(candidate, file, type, key, key_size);
    update_result(&result, fclose(file) == 0 ? 0 : LIBMPQ_ERROR_CLOSE);
    file = NULL;
    if (result != 0)
        goto done;
    result = libmpq__archive_close(candidate);
    candidate = NULL;
    if (result == 0)
        result = libmpq__archive_open(&candidate, path, -1);
    if (result == 0)
        result = update_validate_prefix(source, candidate, &prefix);
    uint64_t candidate_extent;
    uint32_t candidate_signatures;
    if (result == 0)
        result = update_sign_source(candidate, &candidate_extent, &candidate_signatures);
    if (result == 0 && candidate_signatures != expected)
        result = LIBMPQ_ERROR_FORMAT;
    if (result == 0 && !rebuilt) {
        uint64_t core = prefix.origin + extent;
        if (candidate_extent != extent || candidate->files != source->files)
            result = LIBMPQ_ERROR_FORMAT;
        else if (type == LIBMPQ_SIGNATURE_STRONG)
            result = update_sign_bytes(source, candidate, 0, core);
        else {
            result = update_sign_bytes(source, candidate, 0, changed);
            if (result == 0)
                result = update_sign_bytes(
                    source, candidate, changed + LIBMPQ_RSA_SIZE, core - changed - LIBMPQ_RSA_SIZE
                );
        }
    }
    if (result != 0)
        goto done;
    result = update_prepare_names(
        update, candidate, NULL, 0, NULL, 0, NULL, NULL, &prepared_names, &prepared_count
    );
    if (result != 0)
        goto done;
    result = libmpq__archive_close(candidate);
    candidate = NULL;
    if (result == 0) {
        result = libmpq__archive_close(source);
        source = NULL;
    }
    if (result != 0)
        goto done;
    file = libmpq__file_open(path, "r+b");
    if (file == NULL) {
        result = LIBMPQ_ERROR_OPEN;
        goto done;
    }
    result = update_adopt_candidate(update, &file, &temporary, &path);
    if (result == 0)
        update_adopt_names(update, &prepared_names, prepared_count);
done:
    update_free_names(prepared_names, prepared_count);
    if (candidate != NULL)
        (void)libmpq__archive_close(candidate);
    if (source != NULL)
        (void)libmpq__archive_close(source);
    if (file != NULL)
        update_result(&result, fclose(file) == 0 ? 0 : LIBMPQ_ERROR_CLOSE);
    if (temporary != NULL)
        update_result(&result, libmpq__directory_remove(update->directory, temporary));
    free(temporary);
    free(path);
    return result;
}
