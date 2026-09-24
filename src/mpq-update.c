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
#include "mpq-attributes.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
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
    LIBMPQ_UPDATE_REPLACE,
    LIBMPQ_UPDATE_REMOVE,
    LIBMPQ_UPDATE_RENAME
} mpq_update_action_e;

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
libmpq__update_transaction_begin(mpq_update_s **update, const char *path)
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
libmpq__update_transaction_commit(mpq_update_s *update)
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

        if (result != LIBMPQ_SUCCESS)
            return result;
        if (fwrite(buffer, 1, chunk, output) != chunk)
            return LIBMPQ_ERROR_WRITE;
        offset += chunk;
        size -= chunk;
    }
    return LIBMPQ_SUCCESS;
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
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__stream_size(stream, &length);
    if (result != LIBMPQ_SUCCESS || length < 0 || (uint64_t)length > SIZE_MAX) {
        (void)libmpq__stream_close(stream);
        return result == LIBMPQ_SUCCESS ? LIBMPQ_ERROR_SIZE : result;
    }
    bytes = malloc(length == 0 ? 1u : (size_t)length);
    if (bytes == NULL) {
        (void)libmpq__stream_close(stream);
        return LIBMPQ_ERROR_MALLOC;
    }
    result = libmpq__stream_read(stream, bytes, length, &transferred);
    if (result == LIBMPQ_SUCCESS && transferred != length)
        result = LIBMPQ_ERROR_READ;
    if (libmpq__stream_close(stream) != LIBMPQ_SUCCESS && result == LIBMPQ_SUCCESS)
        result = LIBMPQ_ERROR_CLOSE;
    if (result != LIBMPQ_SUCCESS) {
        free(bytes);
        return result;
    }
    *data = bytes;
    *size = (size_t)length;
    return LIBMPQ_SUCCESS;
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
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = update_read_named(archive, LIBMPQ_LISTFILE_NAME, &original, &original_size);
    if (result != LIBMPQ_SUCCESS)
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
    return LIBMPQ_SUCCESS;
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
    entry->block_table_index = UINT32_MAX - 1u;
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
    return LIBMPQ_SUCCESS;
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
    int32_t result;

    options.version = archive->mpq_header.version;
    options.sector_size = archive->block_size;
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-packed-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary,
        &temporary_file
    );
    if (result != LIBMPQ_SUCCESS)
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
        if (libmpq__file_seek(input, 0, SEEK_END) != LIBMPQ_SUCCESS ||
            (measured = libmpq__file_tell(input)) < 0 ||
            libmpq__file_seek(input, 0, SEEK_SET) != LIBMPQ_SUCCESS) {
            result = LIBMPQ_ERROR_SEEK;
            goto done;
        }
        size = (uint64_t)measured;
    } else if (old_name != NULL) {
        libmpq__off_t old_size = 0;

        result = libmpq__stream_open_name(archive, old_name, &old_stream);
        if (result != LIBMPQ_SUCCESS)
            goto done;
        result = libmpq__stream_size(old_stream, &old_size);
        if (result != LIBMPQ_SUCCESS || old_size < 0) {
            result = result == LIBMPQ_SUCCESS ? LIBMPQ_ERROR_SIZE : result;
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
    if (result != LIBMPQ_SUCCESS)
        goto done;
    result =
        libmpq__writer_file_begin(writer, name, (libmpq__off_t)size, file_options, &file_writer);
    if (result != LIBMPQ_SUCCESS)
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
            if (result != LIBMPQ_SUCCESS || transferred != (libmpq__off_t)chunk) {
                if (result == LIBMPQ_SUCCESS)
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
        if (result != LIBMPQ_SUCCESS)
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
    if (result != LIBMPQ_SUCCESS)
        goto done;
    result = libmpq__writer_file_finish(file_writer);
    file_writer = NULL;
    if (result != LIBMPQ_SUCCESS)
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
    result = libmpq__archive_close(writer);
    writer = NULL;
    if (result != LIBMPQ_SUCCESS)
        goto done;
    result = libmpq__archive_open(&packed, temporary_path, 0);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    if (expected_md5 != NULL &&
        ((file_options->compression_first | file_options->compression_next) &
         (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO)) != 0) {
        result = libmpq__stream_open_name(packed, name, &expected_stream);
        if (result != LIBMPQ_SUCCESS)
            goto done;
        libmpq__md5_init(&md5);
        remaining = size;
        while (remaining != 0) {
            size_t chunk = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
            libmpq__off_t transferred = 0;

            result =
                libmpq__stream_read(expected_stream, buffer, (libmpq__off_t)chunk, &transferred);
            if (result != LIBMPQ_SUCCESS || transferred != (libmpq__off_t)chunk) {
                if (result == LIBMPQ_SUCCESS)
                    result = LIBMPQ_ERROR_READ;
                goto done;
            }
            libmpq__md5_update(&md5, buffer, chunk);
            remaining -= chunk;
        }
        libmpq__md5_final(&md5, expected_md5);
        result = libmpq__stream_close(expected_stream);
        expected_stream = NULL;
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    measured = libmpq__file_tell(output);
    if (measured < 0) {
        result = LIBMPQ_ERROR_SEEK;
        goto done;
    }
    position = (uint64_t)measured;
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
    uint8_t *raw;
    uint64_t hash_offset;
    uint64_t block_offset;
    uint64_t block_ex_offset = 0;
    uint64_t end;
    size_t bytes;
    uint32_t i;

    end = (uint64_t)libmpq__file_tell(output);
    if (end > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    hash_offset = end;
    bytes = (size_t)archive->mpq_header.hash_table_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    raw = malloc(bytes == 0 ? 1u : bytes);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < archive->mpq_header.hash_table_count; i++) {
        size_t at = (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
        const mpq_hash_s *entry = &archive->mpq_hash[i];

        libmpq__store_le32(raw + at, entry->hash_a);
        libmpq__store_le32(raw + at + 4u, entry->hash_b);
        libmpq__store_le16(raw + at + 8u, entry->locale);
        libmpq__store_le16(raw + at + 10u, entry->platform);
        libmpq__store_le32(raw + at + 12u, entry->block_table_index);
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    if (fwrite(raw, 1, bytes, output) != bytes) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);
    block_offset = (uint64_t)libmpq__file_tell(output);
    bytes = (size_t)archive->mpq_header.block_table_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    raw = malloc(bytes == 0 ? 1u : bytes);
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < archive->mpq_header.block_table_count; i++) {
        size_t at = (size_t)i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
        const mpq_block_s *entry = &archive->mpq_block[i];

        libmpq__store_le32(raw + at, entry->offset);
        libmpq__store_le32(raw + at + 4u, entry->packed_size);
        libmpq__store_le32(raw + at + 8u, entry->unpacked_size);
        libmpq__store_le32(raw + at + 12u, entry->flags);
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
        block_ex_offset = (uint64_t)libmpq__file_tell(output);
        for (i = 0; i < archive->mpq_header.block_table_count; i++) {
            uint8_t word[2];

            libmpq__store_le16(word, archive->mpq_block_ex[i].offset_high);
            if (fwrite(word, 1, sizeof(word), output) != sizeof(word))
                return LIBMPQ_ERROR_WRITE;
        }
    }
    end = (uint64_t)libmpq__file_tell(output);
    if (end > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    libmpq__store_le32(header, LIBMPQ_HEADER);
    libmpq__store_le32(header + 4u, archive->mpq_header.header_size);
    libmpq__store_le32(header + 8u, (uint32_t)end);
    libmpq__store_le16(header + 12u, archive->mpq_header.version);
    libmpq__store_le16(header + 14u, archive->mpq_header.block_size);
    libmpq__store_le32(header + 16u, (uint32_t)hash_offset);
    libmpq__store_le32(header + 20u, (uint32_t)block_offset);
    libmpq__store_le32(header + 24u, archive->mpq_header.hash_table_count);
    libmpq__store_le32(header + 28u, archive->mpq_header.block_table_count);
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        libmpq__store_le64(header + 32u, block_ex_offset);
        libmpq__store_le16(header + 40u, (uint16_t)(hash_offset >> 32));
        libmpq__store_le16(header + 42u, (uint16_t)(block_offset >> 32));
    }
    if (libmpq__file_seek(output, 0, SEEK_SET) != LIBMPQ_SUCCESS ||
        fwrite(header, 1, archive->mpq_header.header_size, output) !=
            archive->mpq_header.header_size ||
        libmpq__file_seek(output, end, SEEK_SET) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_WRITE;
    *extent = end;
    return LIBMPQ_SUCCESS;
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
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__file_size_unpacked(archive, number, &size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (size < 0 || (uint64_t)size > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    if (compare_contents && (uint64_t)size != expected_size)
        return LIBMPQ_ERROR_READ;
    data = malloc(size == 0 ? 1u : (size_t)size);
    if (data == NULL)
        return LIBMPQ_ERROR_MALLOC;

    if ((archive->mpq_block[archive->mpq_map[number].block_table_indices].flags &
         LIBMPQ_FLAG_ENCRYPTED) != 0) {
        result = libmpq__reader_offsets_acquire(archive, number, name);
        if (result == LIBMPQ_SUCCESS) {
            result = libmpq__file_read(archive, number, data, size, &transferred);
            update_result(&result, libmpq__reader_offsets_release(archive, number));
        }
    } else {
        result = libmpq__file_read(archive, number, data, size, &transferred);
    }
    if (result == LIBMPQ_SUCCESS && transferred != size)
        result = LIBMPQ_ERROR_READ;
    if (result == LIBMPQ_SUCCESS && (compare_contents || actual_md5 != NULL)) {
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, data, (size_t)size);
        libmpq__md5_final(&md5, digest);
        if (compare_contents && memcmp(digest, expected_md5, sizeof(digest)) != 0)
            result = LIBMPQ_ERROR_READ;
        if (result == LIBMPQ_SUCCESS && actual_md5 != NULL)
            memcpy(actual_md5, digest, sizeof(digest));
    }
    if (result == LIBMPQ_SUCCESS && actual_size != NULL)
        *actual_size = (uint64_t)size;
    free(data);
    return result;
}

static int32_t
update_apply(
    mpq_update_s *update, mpq_update_action_e action, const char *old_name, const char *new_name,
    const uint8_t *data, libmpq__off_t size, const char *source_path,
    const mpq_file_options_s *replacement_options
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
    int32_t result;
    uint8_t has_list = 0;
    uint8_t has_attributes = 0;
    uint8_t has_signature = 0;
    uint8_t rebuilt_installed = 0;
    uint8_t expected_md5[16] = { 0 };
    uint64_t expected_size = 0;

    if (update == NULL || update->working == NULL || old_name == NULL || old_name[0] == '\0' ||
        (action == LIBMPQ_UPDATE_RENAME && (new_name == NULL || new_name[0] == '\0')) ||
        (action == LIBMPQ_UPDATE_REPLACE &&
         (size < 0 || (size != 0 && data == NULL && source_path == NULL))) ||
        (action == LIBMPQ_UPDATE_REPLACE && source_path != NULL && source_path[0] == '\0'))
        return LIBMPQ_ERROR_EXIST;
    if (update_reserved_name(old_name) ||
        (action == LIBMPQ_UPDATE_RENAME && update_reserved_name(new_name)))
        return LIBMPQ_ERROR_FORMAT;
    if (fflush(update->working) != 0)
        return LIBMPQ_ERROR_WRITE;
    result = libmpq__archive_open(&archive, update->working_path, 0);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (archive->archive_offset != 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    result = libmpq__file_number(archive, old_name, &number);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    block = archive->mpq_map[number].block_table_indices;
    slot = update_hash_slot(archive, old_name, block);
    if (slot == UINT32_MAX) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    hash = archive->mpq_hash[slot];
    if (action == LIBMPQ_UPDATE_REPLACE && replacement_options != NULL &&
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
        if (result == LIBMPQ_SUCCESS) {
            result = LIBMPQ_ERROR_EXIST;
            goto done;
        }
        if (result != LIBMPQ_ERROR_EXIST)
            goto done;
    }
    result = libmpq__archive_signature_extent(archive, &extent);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    suffix = extent;
    if (extent <= archive->file_size && archive->file_size - extent >= LIBMPQ_STRONG_TRAILER_SIZE) {
        uint8_t actual[4];

        result = libmpq__source_read_at(archive->source, extent, actual, sizeof(actual));
        if (result != LIBMPQ_SUCCESS)
            goto done;
        if (memcmp(actual, marker, sizeof(marker)) == 0)
            suffix += LIBMPQ_STRONG_TRAILER_SIZE;
    }
    if (libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &list_number) == LIBMPQ_SUCCESS) {
        has_list = 1;
        if (update_block_references(archive, archive->mpq_map[list_number].block_table_indices) !=
            1) {
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
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    result = libmpq__attributes_load(archive);
    if (result == LIBMPQ_SUCCESS) {
        has_attributes = 1;
        attribute_flags = archive->attributes->flags;
        if (libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &attributes_number) !=
            LIBMPQ_SUCCESS) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
        if (update_block_references(
                archive, archive->mpq_map[attributes_number].block_table_indices
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
    if (libmpq__file_number(archive, LIBMPQ_SIGNATURE_NAME, &signature_number) == LIBMPQ_SUCCESS) {
        has_signature = 1;
        if (update_block_references(
                archive, archive->mpq_map[signature_number].block_table_indices
            ) != 1) {
            result = LIBMPQ_ERROR_FORMAT;
            goto done;
        }
    }
    if (action == LIBMPQ_UPDATE_RENAME) {
        result =
            update_validate_member(archive, old_name, NULL, 0, 0, expected_md5, &expected_size);
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    result = libmpq__directory_temporary_reopenable(
        update->directory, ".libmpq-rebuild-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary,
        &rebuilt
    );
    if (result != LIBMPQ_SUCCESS)
        goto done;
    rebuilt_path = update_working_path(update->working_path, temporary);
    if (rebuilt_path == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    result = update_copy_range(archive, rebuilt, 0, extent);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    if (action == LIBMPQ_UPDATE_REMOVE) {
        update_delete_hash(&archive->mpq_hash[slot]);
        if (update_block_references(archive, block) == 0) {
            memset(&archive->mpq_block[block], 0, sizeof(archive->mpq_block[block]));
            archive->mpq_block_ex[block].offset_high = 0;
            if (has_attributes)
                memset(&attributes[block], 0, sizeof(attributes[block]));
        }
    } else if (action == LIBMPQ_UPDATE_REPLACE ||
               (archive->mpq_block[block].flags & LIBMPQ_FLAG_ENCRYPTED) != 0) {
        if (action == LIBMPQ_UPDATE_RENAME) {
            uint32_t original_flags = archive->mpq_block[block].flags;

            options.flags = original_flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE |
                                              LIBMPQ_FILE_FLAG_SECTOR_CRC);
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
            if (action == LIBMPQ_UPDATE_REPLACE)
                attributes[block].filetime = 0;
        }
        result = update_encode(
            update, archive, rebuilt, action == LIBMPQ_UPDATE_RENAME ? new_name : old_name, data,
            (uint64_t)size, source_path, action == LIBMPQ_UPDATE_RENAME ? old_name : NULL, &options,
            &archive->mpq_block[block], &archive->mpq_block_ex[block],
            has_attributes ? &attributes[block] : NULL,
            action == LIBMPQ_UPDATE_REPLACE ? expected_md5 : NULL,
            action == LIBMPQ_UPDATE_REPLACE ? &expected_size : NULL
        );
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    if (action == LIBMPQ_UPDATE_RENAME) {
        update_delete_hash(&archive->mpq_hash[slot]);
        result = update_insert_hash(archive, new_name, &hash);
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    if (has_signature) {
        uint32_t signature_block = archive->mpq_map[signature_number].block_table_indices;

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
        uint32_t list_block = archive->mpq_map[list_number].block_table_indices;

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
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    if (has_attributes) {
        uint32_t attributes_block = archive->mpq_map[attributes_number].block_table_indices;

        result = libmpq__attributes_serialize(
            attributes, archive->mpq_header.block_table_count, attributes_block, attribute_flags,
            &attribute_data, &attribute_size
        );
        if (result != LIBMPQ_SUCCESS)
            goto done;
        options.flags = LIBMPQ_FILE_FLAG_SINGLE;
        options.compression_first = 0;
        options.compression_next = 0;
        result = update_encode(
            update, archive, rebuilt, LIBMPQ_ATTRIBUTES_NAME, attribute_data, attribute_size, NULL,
            NULL, &options, &archive->mpq_block[attributes_block],
            &archive->mpq_block_ex[attributes_block], NULL, NULL, NULL
        );
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    result = update_write_tables(archive, rebuilt, &rebuilt_extent);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    if (suffix < archive->file_size) {
        result = update_copy_range(archive, rebuilt, suffix, archive->file_size - suffix);
        if (result != LIBMPQ_SUCCESS)
            goto done;
    }
    if (fflush(rebuilt) != 0) {
        result = LIBMPQ_ERROR_WRITE;
        goto done;
    }
    result = libmpq__archive_open(&check, rebuilt_path, 0);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    if (check->archive_offset != 0 || check->mpq_header.archive_size != rebuilt_extent) {
        result = LIBMPQ_ERROR_FORMAT;
        goto done;
    }
    if (action != LIBMPQ_UPDATE_REPLACE) {
        result = libmpq__file_number(check, old_name, &number);
        if (result != LIBMPQ_ERROR_EXIST) {
            result = result == LIBMPQ_SUCCESS ? LIBMPQ_ERROR_FORMAT : result;
            goto done;
        }
    }
    result = LIBMPQ_SUCCESS;
    if (action == LIBMPQ_UPDATE_REPLACE || action == LIBMPQ_UPDATE_RENAME)
        result = update_validate_member(
            check, action == LIBMPQ_UPDATE_RENAME ? new_name : old_name, expected_md5,
            expected_size, 1, NULL, NULL
        );
    if (result != LIBMPQ_SUCCESS)
        goto done;
    result = libmpq__archive_close(check);
    check = NULL;
    if (result != LIBMPQ_SUCCESS)
        goto done;
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != LIBMPQ_SUCCESS)
        goto done;
    result = libmpq__directory_replace(update->directory, temporary, update->temporary);
    if (result != LIBMPQ_SUCCESS)
        goto done;
    rebuilt_installed = 1;
    (void)fclose(update->working);
    update->working = rebuilt;
    rebuilt = NULL;

done:
    if (check != NULL)
        (void)libmpq__archive_close(check);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (rebuilt != NULL)
        (void)fclose(rebuilt);
    if (temporary != NULL && !rebuilt_installed)
        (void)libmpq__directory_remove(update->directory, temporary);
    free(temporary);
    free(rebuilt_path);
    free(list);
    free(attribute_data);
    free(attributes);
    return result;
}

int32_t
libmpq__update_transaction_replace(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const char *source_path, const mpq_file_options_s *options
)
{
    return update_apply(
        update, LIBMPQ_UPDATE_REPLACE, filename, NULL, data, size, source_path, options
    );
}

int32_t
libmpq__update_transaction_remove(mpq_update_s *update, const char *filename)
{
    return update_apply(update, LIBMPQ_UPDATE_REMOVE, filename, NULL, NULL, 0, NULL, NULL);
}

int32_t
libmpq__update_transaction_rename(
    mpq_update_s *update, const char *old_filename, const char *new_filename
)
{
    return update_apply(
        update, LIBMPQ_UPDATE_RENAME, old_filename, new_filename, NULL, 0, NULL, NULL
    );
}
