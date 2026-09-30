/*
 *  test-mpq-update.c -- private update transaction regression tests.
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

#define _POSIX_C_SOURCE 200809L

#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-internal.h"
#include "mpq-mpqe.h"
#include "mpq-signature.h"
#include "mpq-source.h"
#include "mpq-update.h"
#include "test-mpq-helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

static const uint8_t auth_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";

#define UPDATE_CHECK(condition)                                                                    \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            test_failure(__FILE__, __LINE__, #condition);                                          \
            goto fail;                                                                             \
        }                                                                                          \
    } while (0)

static int
check_named(mpq_archive_s *archive, const char *name, const uint8_t *expected, size_t size);

typedef enum
{
    UPDATE_FAULT_FLUSH,
    UPDATE_FAULT_CLOSE,
    UPDATE_FAULT_PUBLISH
} update_fault_e;

static int
fail_flush(FILE *file)
{
    (void)file;
    return EOF;
}

static int
fail_close(FILE *file)
{
    (void)fclose(file);
    return EOF;
}

static int32_t
fail_publish(mpq_directory_s *directory, const char *temporary, const char *destination)
{
    (void)directory;
    (void)temporary;
    (void)destination;
    return LIBMPQ_ERROR_WRITE;
}

static int
write_bytes(const char *path, const uint8_t *bytes, size_t size)
{
    FILE *file = fopen(path, "wb");
    int result = 0;

    if (file == NULL)
        return -1;
    if (size != 0 && fwrite(bytes, 1, size, file) != size)
        result = -1;
    if (fclose(file) != 0)
        result = -1;
    return result;
}

static int
read_bytes(const char *path, uint8_t **bytes, size_t *size)
{
    FILE *file;
    long length;
    uint8_t *data;
    int result = 0;

    *bytes = NULL;
    *size = 0;
    file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        if (file != NULL)
            (void)fclose(file);
        return -1;
    }
    data = malloc((size_t)length == 0 ? 1 : (size_t)length);
    if (data == NULL) {
        (void)fclose(file);
        return -1;
    }
    if ((size_t)length != 0 && fread(data, 1, (size_t)length, file) != (size_t)length)
        result = -1;
    if (fclose(file) != 0)
        result = -1;
    if (result != 0) {
        free(data);
        return -1;
    }
    *bytes = data;
    *size = (size_t)length;
    return 0;
}

static int
copy_file(const char *source, const char *destination)
{
    uint8_t *bytes;
    size_t size;
    int result;

    if (read_bytes(source, &bytes, &size) != 0)
        return -1;
    result = write_bytes(destination, bytes, size);
    free(bytes);
    return result;
}

static int
same_file(const char *first, const char *second)
{
    uint8_t *first_bytes = NULL;
    uint8_t *second_bytes = NULL;
    size_t first_size;
    size_t second_size;
    int equal;

    if (read_bytes(first, &first_bytes, &first_size) != 0 ||
        read_bytes(second, &second_bytes, &second_size) != 0) {
        free(first_bytes);
        free(second_bytes);
        return 0;
    }
    equal = first_size == second_size && memcmp(first_bytes, second_bytes, first_size) == 0;
    free(first_bytes);
    free(second_bytes);
    return equal;
}

static int
create_archive(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { 0, 4, 4096, 0, 0 };
    const uint8_t payload[] = "update payload";
    int32_t result;

    result = libmpq__archive_create(&archive, path, &options);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(archive, "payload", payload, sizeof(payload) - 1U, NULL);
    if (archive != NULL) {
        int32_t close_result = libmpq__archive_close(archive);

        if (result == LIBMPQ_SUCCESS)
            result = close_result;
    }
    return result == LIBMPQ_SUCCESS ? 0 : -1;
}

static int
test_abort(const char *path)
{
    mpq_update_s *update = NULL;
    char *temporary;

    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(update != NULL && libmpq__update_path(update) != NULL);
    temporary = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(temporary != NULL);
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
#ifndef _WIN32
    TEST_CHECK(access(temporary, F_OK) != 0);
#endif
    free(temporary);
    return 0;
}

static int
test_noop_commit(const char *path, const char *reference)
{
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number;
    uint8_t payload[sizeof("update payload") - 1U];

    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_ops(update)->publish == libmpq__directory_replace);
    TEST_CHECK(libmpq__update_transaction_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__file_read(archive, number, payload, sizeof(payload), NULL) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(memcmp(payload, "update payload", sizeof(payload)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_public_replace(const char *source)
{
    static const uint8_t changed[] = "replacement payload";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint8_t bytes[sizeof(changed) - 1u];
    uint32_t number;
    char *previous_path;
    FILE *orphan;
    int32_t replace_result;
    int path_changed;
    int old_removed;

    TEST_CHECK(copy_file(source, "update-public.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-public.mpq") == LIBMPQ_SUCCESS);
    previous_path = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(previous_path != NULL);
    replace_result =
        libmpq__update_replace_data(update, "payload", changed, sizeof(changed) - 1u, NULL);
    path_changed =
        replace_result == LIBMPQ_SUCCESS && strcmp(previous_path, libmpq__update_path(update)) != 0;
    orphan = fopen(previous_path, "rb");
    old_removed = orphan == NULL;
    if (orphan != NULL)
        (void)fclose(orphan);
    free(previous_path);
    if (replace_result != LIBMPQ_SUCCESS)
        fprintf(stderr, "update replacement returned %d\n", replace_result);
    TEST_CHECK(replace_result == LIBMPQ_SUCCESS);
    TEST_CHECK(path_changed);
    TEST_CHECK(old_removed);
    TEST_CHECK(libmpq__archive_open(&archive, "update-public.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == LIBMPQ_SUCCESS);
    {
        uint8_t original[sizeof("update payload") - 1u];

        TEST_CHECK(
            libmpq__file_read(archive, number, original, sizeof(original), NULL) == LIBMPQ_SUCCESS
        );
        TEST_CHECK(memcmp(original, "update payload", sizeof(original)) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-public.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_read(archive, number, bytes, sizeof(bytes), NULL) == LIBMPQ_SUCCESS);
    TEST_CHECK(memcmp(bytes, changed, sizeof(bytes)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
create_edit_archive(const char *path, uint32_t options_flags)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { 0, 16, 512, options_flags,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s encrypted = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE |
                                         LIBMPQ_FILE_FLAG_ENCRYPTED,
                                     LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    static const uint8_t plain[] = "ordinary file";
    static const uint8_t secret[] = "secret compressed and encrypted payload";
    static const uint8_t unknown[] = "unlisted physical entry";
    int32_t result;

    result = libmpq__archive_create(&archive, path, &options);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(archive, "plain", plain, sizeof(plain) - 1u, NULL);
    if (result == LIBMPQ_SUCCESS)
        result =
            libmpq__archive_add_data(archive, "secret", secret, sizeof(secret) - 1u, &encrypted);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(archive, "unknown", unknown, sizeof(unknown) - 1u, NULL);
    if (archive != NULL) {
        int32_t closed = libmpq__archive_close(archive);

        if (result == LIBMPQ_SUCCESS)
            result = closed;
    }
    return result == LIBMPQ_SUCCESS ? 0 : -1;
}

/* Build a normal MPQ inside MPQE for authenticated update coverage. */
static int
create_mpqe_edit_archive(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { 0, 16, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s encrypted = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE |
                                         LIBMPQ_FILE_FLAG_ENCRYPTED,
                                     LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    static const uint8_t plain[] = "ordinary file";
    static const uint8_t secret[] = "secret compressed and encrypted payload";
    static const uint8_t removed[] = "remove this member";
    int32_t result =
        libmpq__archive_create_mpqe(&archive, path, auth_code, sizeof(auth_code) - 1u, &options);

    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(archive, "plain", plain, sizeof(plain) - 1u, NULL);
    if (result == LIBMPQ_SUCCESS)
        result =
            libmpq__archive_add_data(archive, "secret", secret, sizeof(secret) - 1u, &encrypted);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(archive, "removed", removed, sizeof(removed) - 1u, NULL);
    if (archive != NULL) {
        int32_t closed = libmpq__archive_close(archive);

        if (result == LIBMPQ_SUCCESS)
            result = closed;
    }
    return result == LIBMPQ_SUCCESS ? 0 : -1;
}

/* Make an existing hash name reference another existing physical block. */
static int
share_archive_block(const char *path, const char *source_name, const char *alias_name)
{
    mpq_archive_s *archive = NULL;
    uint8_t *raw = NULL;
    FILE *file = NULL;
    uint32_t first;
    uint32_t second;
    uint32_t block;
    uint32_t count;
    uint32_t i;
    size_t bytes;

    if (libmpq__archive_open(&archive, path, 0) != LIBMPQ_SUCCESS)
        return -1;
    if (libmpq__file_number(archive, source_name, &first) != LIBMPQ_SUCCESS ||
        libmpq__file_number(archive, alias_name, &second) != LIBMPQ_SUCCESS)
        goto fail;
    block = archive->mpq_map[first].block_table_indices;
    count = archive->mpq_header.hash_table_count;
    bytes = (size_t)count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    raw = malloc(bytes);
    if (raw == NULL)
        goto fail;
    for (i = 0; i < count; i++) {
        mpq_hash_s *entry = &archive->mpq_hash[i];
        size_t at = (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE;

        if (entry->block_table_index == archive->mpq_map[second].block_table_indices)
            entry->block_table_index = block;
        libmpq__store_le32(raw + at, entry->hash_a);
        libmpq__store_le32(raw + at + 4u, entry->hash_b);
        libmpq__store_le16(raw + at + 8u, entry->locale);
        libmpq__store_le16(raw + at + 10u, entry->platform);
        libmpq__store_le32(raw + at + 12u, entry->block_table_index);
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    file = fopen(path, "r+b");
    if (file == NULL ||
        libmpq__file_seek(file, archive->mpq_header.hash_table_offset, SEEK_SET) !=
            LIBMPQ_SUCCESS ||
        fwrite(raw, 1, bytes, file) != bytes)
        goto fail;
    if (fclose(file) != 0) {
        file = NULL;
        goto fail;
    }
    free(raw);
    return libmpq__archive_close(archive) == LIBMPQ_SUCCESS ? 0 : -1;

fail:
    if (file != NULL)
        (void)fclose(file);
    free(raw);
    (void)libmpq__archive_close(archive);
    return -1;
}

/* Construct a two-name fixture whose hash entries intentionally share one block. */
static int
create_shared_archive(const char *path, uint8_t encrypted)
{
    static const uint8_t payload[] = "shared physical payload";
    mpq_archive_create_options_s options = { 0, 8, 4096, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s file_options = { 0 };
    mpq_archive_s *archive = NULL;
    int32_t result;

    if (encrypted)
        file_options.flags = LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE;
    result = libmpq__archive_create(&archive, path, &options);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(
            archive, "alias-a", payload, sizeof(payload) - 1u, encrypted ? &file_options : NULL
        );
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__archive_add_data(
            archive, "alias-b", payload, sizeof(payload) - 1u, encrypted ? &file_options : NULL
        );
    if (archive != NULL) {
        int32_t close_result = libmpq__archive_close(archive);

        if (result == LIBMPQ_SUCCESS)
            result = close_result;
    }
    if (result != LIBMPQ_SUCCESS)
        return -1;
    return share_archive_block(path, "alias-a", "alias-b");
}

static int
test_shared_blocks(void)
{
    static const uint8_t payload[] = "shared physical payload";
    static const uint8_t changed[] = "replacement";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number;

    TEST_CHECK(create_shared_archive("update-shared-remove.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-remove.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_remove(update, "alias-a") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-remove.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "alias-a", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "alias-b", &number) == LIBMPQ_SUCCESS);
    {
        uint8_t bytes[sizeof(payload) - 1u];

        TEST_CHECK(
            libmpq__file_read(archive, number, bytes, sizeof(bytes), NULL) == LIBMPQ_SUCCESS
        );
        TEST_CHECK(memcmp(bytes, payload, sizeof(bytes)) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_shared_archive("update-shared-staged.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-staged.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "alias-a", "renamed-a") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(update, "alias-b", changed, sizeof(changed) - 1u, NULL) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-staged.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "renamed-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_shared_archive("update-shared-replace.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-replace.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(update, "alias-a", changed, sizeof(changed) - 1u, NULL) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-replace.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "alias-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_shared_archive("update-shared-rename.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-rename.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "alias-a", "renamed-a") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-rename.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "alias-a", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(check_named(archive, "renamed-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_shared_archive("update-shared-encrypted.mpq", 1) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-encrypted.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "alias-a", "renamed-a") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-encrypted.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "alias-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "alias-b", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "renamed-a", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

/* A shared internal block must reject an unrelated mutation before staging. */
static int
test_shared_metadata(void)
{
    static const char *metadata[] = { "(listfile)", "(attributes)", "(signature)" };
    static const char *paths[] = { "update-shared-list.mpq", "update-shared-attributes.mpq",
                                   "update-shared-signature.mpq" };
    static const uint8_t changed[] = "unrelated replacement";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number;
    size_t i;

    for (i = 0; i < sizeof(metadata) / sizeof(metadata[0]); i++) {
        const char *working;
        const char *target = "overview.txt";

        TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpq", paths[i]) == 0);
        TEST_CHECK(libmpq__update_begin(&update, paths[i]) == LIBMPQ_SUCCESS);
        if (i != 2) {
            TEST_CHECK(
                libmpq__update_rename(update, "overview.txt", "renamed-overview.txt") ==
                LIBMPQ_SUCCESS
            );
            target = "renamed-overview.txt";
        }
        working = libmpq__update_path(update);
        TEST_CHECK(working != NULL);
        TEST_CHECK(share_archive_block(working, metadata[i], "wave-mono.wav") == 0);
        TEST_CHECK(copy_file(working, "update-shared-metadata-before.mpq") == 0);
        TEST_CHECK(
            libmpq__update_replace_data(update, target, changed, sizeof(changed) - 1u, NULL) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(working, "update-shared-metadata-before.mpq"));
        TEST_CHECK(libmpq__archive_open(&archive, working, 0) == LIBMPQ_SUCCESS);
        TEST_CHECK(libmpq__file_number(archive, target, &number) == LIBMPQ_SUCCESS);
        if (i != 2)
            TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
        archive = NULL;
        TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
        update = NULL;
        TEST_CHECK(same_file(paths[i], FIXTURE_DIR "/mpq-v1-features.mpq"));
    }
    return 0;
}

static int
check_named(mpq_archive_s *archive, const char *name, const uint8_t *expected, size_t size)
{
    uint32_t number;
    uint8_t *buffer = malloc(size == 0 ? 1u : size);
    mpq_stream_s *stream = NULL;
    libmpq__off_t transferred = 0;
    int32_t result;
    int32_t close_result = LIBMPQ_SUCCESS;
    int matches;

    TEST_CHECK(buffer != NULL);
    result = libmpq__file_number(archive, name, &number);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__stream_open_name(archive, name, &stream);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__stream_read(stream, buffer, (libmpq__off_t)size, &transferred);
    matches = result == LIBMPQ_SUCCESS && transferred == (libmpq__off_t)size &&
              memcmp(buffer, expected, size) == 0;
    if (stream != NULL)
        close_result = libmpq__stream_close(stream);
    free(buffer);
    TEST_CHECK(matches);
    TEST_CHECK(close_result == LIBMPQ_SUCCESS);
    return 0;
}

static int
check_listfile(mpq_archive_s *archive)
{
    uint32_t number;
    libmpq__off_t size = 0;
    uint8_t *bytes;

    TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == LIBMPQ_SUCCESS);
    TEST_CHECK(size > 0 && (uint64_t)size < SIZE_MAX);
    bytes = malloc((size_t)size + 1u);
    TEST_CHECK(bytes != NULL);
    TEST_CHECK(libmpq__file_read(archive, number, bytes, size, NULL) == LIBMPQ_SUCCESS);
    bytes[size] = 0;
    TEST_CHECK(strstr((const char *)bytes, "renamed-secret\n") != NULL);
    TEST_CHECK(strstr((const char *)bytes, "plain\n") != NULL);
    TEST_CHECK(strstr((const char *)bytes, "\nsecret\n") == NULL);
    TEST_CHECK(strncmp((const char *)bytes, "secret\n", 7u) != 0);
    TEST_CHECK(strstr((const char *)bytes, "\nunknown\n") == NULL);
    free(bytes);
    return 0;
}

static int
test_public_edit(void)
{
    static const uint8_t replacement[] = "new compressed data";
    static const uint8_t secret[] = "secret compressed and encrypted payload";
    static const uint8_t unknown[] = "unlisted physical entry";
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    mpq_file_attributes_s original_secret;
    mpq_file_attributes_s renamed_secret;
    uint32_t number;
    uint32_t mismatches;

    TEST_CHECK(create_edit_archive("update-edit.mpq", LIBMPQ_ARCHIVE_CREATE_LISTFILE) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-edit.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_attributes(archive, number, &original_secret) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    TEST_CHECK(libmpq__update_begin(&update, "update-edit.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "secret", "renamed-secret") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_remove(update, "unknown") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(
            update, "plain", replacement, sizeof(replacement) - 1u, &compressed
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-edit.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(check_named(archive, "renamed-secret", secret, sizeof(secret) - 1u) == 0);
    TEST_CHECK(check_listfile(archive) == 0);
    TEST_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "unknown", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__file_verify(
            archive, number, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &mismatches
        ) == LIBMPQ_SUCCESS &&
        mismatches == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "renamed-secret", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_attributes(archive, number, &renamed_secret) == LIBMPQ_SUCCESS);
    TEST_CHECK(renamed_secret.crc32 == original_secret.crc32);
    TEST_CHECK(memcmp(renamed_secret.md5, original_secret.md5, sizeof(renamed_secret.md5)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_edit_archive("update-unknown.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-unknown.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-unknown.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(check_named(archive, "secret", secret, sizeof(secret) - 1u) == 0);
    TEST_CHECK(check_named(archive, "unknown", unknown, sizeof(unknown) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_public_abort_and_path(void)
{
    static const uint8_t replacement[] = "replacement from path";
    static const uint8_t original[] = "ordinary file";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number;

    TEST_CHECK(create_edit_archive("update-abort.mpq", LIBMPQ_ARCHIVE_CREATE_LISTFILE) == 0);
    TEST_CHECK(copy_file("update-abort.mpq", "update-abort-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_remove(update, "plain") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file("update-abort.mpq", "update-abort-reference.mpq"));

    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "plain", "renamed") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file("update-abort.mpq", "update-abort-reference.mpq"));

    TEST_CHECK(write_bytes("update-replacement.bin", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_path(update, "plain", "update-replacement.bin", NULL) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file("update-abort.mpq", "update-abort-reference.mpq"));

    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_path(update, "plain", "update-replacement.bin", NULL) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-abort.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "renamed", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_edit_archive("update-normal-rename.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-normal-rename.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "plain", "renamed") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-normal-rename.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "renamed", original, sizeof(original) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_public_signatures(void)
{
    static const uint8_t replacement[] = "updated overview";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint8_t *packed = NULL;
    uint8_t *after = NULL;
    uint32_t wave_number;
    uint32_t wave_block;
    uint32_t packed_size;
    uint64_t packed_offset;
    uint32_t signatures = UINT32_MAX;
    mpq_file_attributes_s attributes;
    int32_t result;

    UPDATE_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpq", "update-signatures.mpq") == 0);
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-signatures.mpq", 0) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(libmpq__file_number(archive, "wave-mono.wav", &wave_number) == LIBMPQ_SUCCESS);
    wave_block = archive->mpq_map[wave_number].block_table_indices;
    packed_size = archive->mpq_block[wave_block].packed_size;
    packed_offset = archive->mpq_block[wave_block].offset;
    packed = malloc(packed_size);
    after = malloc(packed_size);
    UPDATE_CHECK(packed != NULL && after != NULL);
    UPDATE_CHECK(
        libmpq__source_read_at(archive->source, packed_offset, packed, packed_size) ==
        LIBMPQ_SUCCESS
    );
    result = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(result == LIBMPQ_SUCCESS);
    UPDATE_CHECK(libmpq__update_begin(&update, "update-signatures.mpq") == LIBMPQ_SUCCESS);
    UPDATE_CHECK(
        libmpq__update_replace_data(
            update, "overview.txt", replacement, sizeof(replacement) - 1u, NULL
        ) == LIBMPQ_SUCCESS
    );
    result = libmpq__update_commit(update);
    update = NULL;
    UPDATE_CHECK(result == LIBMPQ_SUCCESS);
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-signatures.mpq", 0) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(check_named(archive, "overview.txt", replacement, sizeof(replacement) - 1u) == 0);
    {
        uint32_t overview;

        UPDATE_CHECK(libmpq__file_number(archive, "overview.txt", &overview) == LIBMPQ_SUCCESS);
        UPDATE_CHECK(libmpq__file_attributes(archive, overview, &attributes) == LIBMPQ_SUCCESS);
        UPDATE_CHECK(attributes.filetime == 0);
    }
    UPDATE_CHECK(libmpq__file_number(archive, "wave-mono.wav", &wave_number) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(archive->mpq_map[wave_number].block_table_indices == wave_block);
    UPDATE_CHECK(archive->mpq_block[wave_block].packed_size == packed_size);
    UPDATE_CHECK(archive->mpq_block[wave_block].offset == packed_offset);
    UPDATE_CHECK(
        libmpq__source_read_at(archive->source, packed_offset, after, packed_size) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(memcmp(after, packed, packed_size) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(signatures == 0);
    result = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(result == LIBMPQ_SUCCESS);
    free(packed);
    free(after);
    return 0;

fail:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (update != NULL)
        (void)libmpq__update_abort(update);
    free(packed);
    free(after);
    return 1;
}

static int
test_public_limits(void)
{
    mpq_update_s *update = NULL;

    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpq", "update-noop.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-noop.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(FIXTURE_DIR "/mpq-v1-features.mpq", "update-noop.mpq"));
    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpqe", "update-mpqe.mpqe") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-mpqe.mpqe") != LIBMPQ_SUCCESS);
    TEST_CHECK(update == NULL);
    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.w3x", "update-embedded.w3x") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-embedded.w3x") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(create_edit_archive("update-collision.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-collision.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_rename(update, "plain", "secret") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_rename(update, "plain", "(attributes)") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_remove(update, "missing") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_public_trailing_bytes(void)
{
    static const uint8_t suffix[] = "unrelated container suffix";
    static const uint8_t changed[] = "changed";
    mpq_update_s *update = NULL;
    uint8_t *bytes = NULL;
    size_t size = 0;
    FILE *file;
    int valid_size;
    int valid_suffix;

    TEST_CHECK(create_archive("update-trailing.mpq") == 0);
    file = fopen("update-trailing.mpq", "ab");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(suffix, 1, sizeof(suffix) - 1u, file) == sizeof(suffix) - 1u);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-trailing.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(update, "payload", changed, sizeof(changed) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(read_bytes("update-trailing.mpq", &bytes, &size) == 0);
    valid_size = size >= sizeof(suffix) - 1u;
    valid_suffix = valid_size &&
                   memcmp(bytes + size - (sizeof(suffix) - 1u), suffix, sizeof(suffix) - 1u) == 0;
    free(bytes);
    TEST_CHECK(valid_size);
    TEST_CHECK(valid_suffix);
    return 0;
}

static int
test_public_v2(void)
{
    static const uint8_t changed[] = "v2 replacement";
    uint8_t lzma[2048];
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_LZMA,
                                      LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t signatures = UINT32_MAX;

    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v2-features.mpq", "update-v2.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-v2.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(update, "overview.txt", changed, sizeof(changed) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-v2.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "overview.txt", changed, sizeof(changed) - 1u) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
    TEST_CHECK(signatures == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    memset(lzma, 'L', sizeof(lzma));
    TEST_CHECK(libmpq__update_begin(&update, "update-v2.mpq") == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__update_replace_data(update, "overview.txt", lzma, sizeof(lzma), &compressed) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-v2.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "overview.txt", lzma, sizeof(lzma)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_public_replace_options(void)
{
    uint8_t replacement[2048];
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                   LIBMPQ_COMPRESSION_BZIP2, 0, 0 };
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint32_t number;
    uint32_t method;
    uint32_t block;

    memset(replacement, 'Q', sizeof(replacement));
    TEST_CHECK(create_edit_archive("update-options-data.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-options-data.mpq") == LIBMPQ_SUCCESS);
    options.locale = 1;
    TEST_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement), &options) ==
        LIBMPQ_ERROR_FORMAT
    );
    options.locale = 0;
    options.platform = 1;
    TEST_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement), &options) ==
        LIBMPQ_ERROR_FORMAT
    );
    options.platform = 0;
    TEST_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement), &options) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-options-data.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_SUCCESS);
    block = archive->mpq_map[number].block_table_indices;
    TEST_CHECK((archive->mpq_block[block].flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0);
    TEST_CHECK(libmpq__block_compression(archive, number, 0, &method) == LIBMPQ_SUCCESS);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_ZLIB);
    TEST_CHECK(libmpq__block_compression(archive, number, 1, &method) == LIBMPQ_SUCCESS);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_BZIP2);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);

    TEST_CHECK(create_edit_archive("update-options-path.mpq", 0) == 0);
    TEST_CHECK(write_bytes("update-options.bin", replacement, sizeof(replacement)) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-options-path.mpq") == LIBMPQ_SUCCESS);
    options.locale = 1;
    TEST_CHECK(
        libmpq__update_replace_path(update, "plain", "update-options.bin", &options) ==
        LIBMPQ_ERROR_FORMAT
    );
    options.locale = 0;
    TEST_CHECK(
        libmpq__update_replace_path(update, "plain", "update-options.bin", &options) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_open(&archive, "update-options-path.mpq", 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__block_compression(archive, number, 0, &method) == LIBMPQ_SUCCESS);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_ZLIB);
    TEST_CHECK(libmpq__block_compression(archive, number, 1, &method) == LIBMPQ_SUCCESS);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_BZIP2);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_working_copy_isolation(const char *path, const char *reference)
{
    mpq_update_s *update = NULL;
    FILE *working;

    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);

    /* The transaction path must be reopenable while the transaction is active. */
    working = fopen(libmpq__update_path(update), "r+b");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite("X", 1, 1, working) == 1);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(path, reference));
    return 0;
}

#ifndef _WIN32
static int
test_stable_working_path(void)
{
    static const uint8_t contents[] = "relative update container";
    char current[4096];
    mpq_update_s *update = NULL;
    char *working_path;
    FILE *working;

    TEST_CHECK(getcwd(current, sizeof(current)) != NULL);
    TEST_CHECK(mkdir("update-relative", 0700) == 0);
    TEST_CHECK(chdir("update-relative") == 0);
    TEST_CHECK(write_bytes("source.bin", contents, sizeof(contents) - 1U) == 0);
    TEST_CHECK(libmpq__update_transaction_begin(&update, "source.bin") == LIBMPQ_SUCCESS);
    working_path = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(working_path != NULL);
    TEST_CHECK(chdir(current) == 0);
    working = fopen(working_path, "r+b");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite("X", 1, 1, working) == 1);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    free(working_path);
    TEST_CHECK(unlink("update-relative/source.bin") == 0);
    TEST_CHECK(rmdir("update-relative") == 0);
    return 0;
}
#endif

static int
test_publication(const char *path)
{
    static const uint8_t original[] = "original container";
    static const uint8_t changed[] = "changed container";
    mpq_update_s *update = NULL;
    FILE *working;
    uint8_t *bytes;
    size_t size;

    TEST_CHECK(write_bytes(path, original, sizeof(original) - 1U) == 0);
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    working = fopen(libmpq__update_path(update), "wb");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite(changed, 1, sizeof(changed) - 1U, working) == sizeof(changed) - 1U);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(original) - 1U && memcmp(bytes, original, size) == 0);
    free(bytes);
    TEST_CHECK(libmpq__update_transaction_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(changed) - 1U && memcmp(bytes, changed, size) == 0);
    free(bytes);
    return 0;
}

static int
test_failure_cleanup(const char *path, update_fault_e fault)
{
    static const uint8_t original[] = "unmodified destination";
    mpq_update_s *update = NULL;
    mpq_update_ops_s ops;
    char *temporary;
    uint8_t *bytes;
    size_t size;

    TEST_CHECK(write_bytes(path, original, sizeof(original) - 1U) == 0);
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_ops(update) != NULL);
    ops = *libmpq__update_ops(update);
    if (fault == UPDATE_FAULT_FLUSH)
        ops.flush = fail_flush;
    else if (fault == UPDATE_FAULT_CLOSE)
        ops.close = fail_close;
    else
        ops.publish = fail_publish;
    libmpq__update_set_ops(update, &ops);
    temporary = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(temporary != NULL);
    TEST_CHECK(libmpq__update_transaction_commit(update) != LIBMPQ_SUCCESS);
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(original) - 1U && memcmp(bytes, original, size) == 0);
    free(bytes);
#ifndef _WIN32
    TEST_CHECK(access(temporary, F_OK) != 0);
#endif
    free(temporary);
    return 0;
}

static int
test_embedded_preservation(const char *archive_path, const char *path)
{
    static const uint8_t prefix[] = "container prefix";
    static const uint8_t suffix[] = "container suffix";
    mpq_update_s *update = NULL;
    uint8_t *archive_bytes = NULL;
    uint8_t *container = NULL;
    size_t archive_size;
    size_t container_size;

    UPDATE_CHECK(read_bytes(archive_path, &archive_bytes, &archive_size) == 0);
    container_size = sizeof(prefix) - 1U + archive_size + sizeof(suffix) - 1U;
    container = malloc(container_size);
    UPDATE_CHECK(container != NULL);
    memcpy(container, prefix, sizeof(prefix) - 1U);
    memcpy(container + sizeof(prefix) - 1U, archive_bytes, archive_size);
    memcpy(container + sizeof(prefix) - 1U + archive_size, suffix, sizeof(suffix) - 1U);
    UPDATE_CHECK(write_bytes(path, container, container_size) == 0);
    UPDATE_CHECK(write_bytes("update-embedded-reference.bin", container, container_size) == 0);
    free(container);
    free(archive_bytes);
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_transaction_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(path, "update-embedded-reference.bin"));
    return 0;

fail:
    free(container);
    free(archive_bytes);
    return 1;
}

/* Wrap an ordinary archive in an aligned HM3W-style container with a suffix. */
static int
create_embedded_update_container(const char *source, const char *path, uint8_t strong)
{
    static const uint8_t suffix[] = "unrelated trailing container bytes";
    static const uint8_t marker[4] = { 'N', 'G', 'I', 'S' };
    uint8_t *archive_bytes = NULL;
    uint8_t *container = NULL;
    size_t archive_size;
    size_t trailer_size = strong ? LIBMPQ_STRONG_TRAILER_SIZE : 0;
    size_t container_size;
    int result = -1;

    if (read_bytes(source, &archive_bytes, &archive_size) != 0 ||
        archive_size > SIZE_MAX - 512u - trailer_size - sizeof(suffix) + 1u)
        goto done;
    container_size = 512u + archive_size + trailer_size + sizeof(suffix) - 1u;
    container = calloc(container_size, 1);
    if (container == NULL)
        goto done;
    memcpy(container, "HM3W", 4);
    memcpy(container + 512u, archive_bytes, archive_size);
    if (strong)
        memcpy(container + 512u + archive_size, marker, sizeof(marker));
    memcpy(container + 512u + archive_size + trailer_size, suffix, sizeof(suffix) - 1u);
    result = write_bytes(path, container, container_size);

done:
    free(container);
    free(archive_bytes);
    return result;
}

static int
test_public_embedded_updates(void)
{
    static const char *paths[] = { "update-embedded-data.w3x", "update-embedded-path.w3m",
                                   "update-embedded-remove.bin", "update-embedded-rename.bin" };
    static const uint8_t replacement[] = "replacement large enough to move the suffix";
    static const uint8_t secret[] = "secret compressed and encrypted payload";
    static const uint8_t suffix[] = "unrelated trailing container bytes";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    uint8_t *before = NULL;
    uint8_t *after = NULL;
    size_t before_size = 0;
    size_t after_size = 0;
    uint32_t number;
    uint32_t signatures;
    uint32_t i;
    FILE *working = NULL;

    UPDATE_CHECK(
        create_edit_archive("update-embedded-source.mpq", LIBMPQ_ARCHIVE_CREATE_LISTFILE) == 0
    );
    UPDATE_CHECK(
        write_bytes("update-embedded-input.bin", replacement, sizeof(replacement) - 1u) == 0
    );
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        UPDATE_CHECK(
            create_embedded_update_container("update-embedded-source.mpq", paths[i], i == 0) == 0
        );
        UPDATE_CHECK(read_bytes(paths[i], &before, &before_size) == 0);
        if (i == 0) {
            UPDATE_CHECK(libmpq__archive_open(&archive, paths[i], -1) == LIBMPQ_SUCCESS);
            UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
            UPDATE_CHECK((signatures & LIBMPQ_SIGNATURE_STRONG) != 0);
            UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
            archive = NULL;
        }
        UPDATE_CHECK(libmpq__update_begin(&update, paths[i]) == LIBMPQ_SUCCESS);
        if (i == 0)
            UPDATE_CHECK(
                libmpq__update_replace_data(
                    update, "plain", replacement, sizeof(replacement) - 1u, NULL
                ) == LIBMPQ_SUCCESS
            );
        else if (i == 1)
            UPDATE_CHECK(
                libmpq__update_replace_path(update, "plain", "update-embedded-input.bin", NULL) ==
                LIBMPQ_SUCCESS
            );
        else if (i == 2)
            UPDATE_CHECK(libmpq__update_remove(update, "plain") == LIBMPQ_SUCCESS);
        else
            UPDATE_CHECK(
                libmpq__update_rename(update, "secret", "renamed-secret") == LIBMPQ_SUCCESS
            );
        UPDATE_CHECK(read_bytes(paths[i], &after, &after_size) == 0);
        UPDATE_CHECK(before_size == after_size && memcmp(before, after, before_size) == 0);
        free(after);
        after = NULL;
        UPDATE_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
        update = NULL;
        UPDATE_CHECK(libmpq__archive_open(&archive, paths[i], -1) == LIBMPQ_SUCCESS);
        UPDATE_CHECK(archive->archive_offset == 512);
        if (i < 2)
            UPDATE_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
        else if (i == 2)
            UPDATE_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_ERROR_EXIST);
        else {
            UPDATE_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_ERROR_EXIST);
            UPDATE_CHECK(check_named(archive, "renamed-secret", secret, sizeof(secret) - 1u) == 0);
        }
        UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
        UPDATE_CHECK(signatures == 0);
        UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
        archive = NULL;
        UPDATE_CHECK(read_bytes(paths[i], &after, &after_size) == 0);
        UPDATE_CHECK(after_size >= 512u + sizeof(suffix) - 1u);
        UPDATE_CHECK(memcmp(before, after, 512u) == 0);
        UPDATE_CHECK(
            memcmp(after + after_size - sizeof(suffix) + 1u, suffix, sizeof(suffix) - 1u) == 0
        );
        if (i == 0)
            UPDATE_CHECK(after_size != before_size);
        free(before);
        free(after);
        before = NULL;
        after = NULL;
    }
    UPDATE_CHECK(
        create_embedded_update_container(
            "update-embedded-source.mpq", "update-embedded-abort.w3x", 0
        ) == 0
    );
    UPDATE_CHECK(copy_file("update-embedded-abort.w3x", "update-embedded-before.bin") == 0);
    UPDATE_CHECK(libmpq__update_begin(&update, "update-embedded-abort.w3x") == LIBMPQ_SUCCESS);
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-embedded-abort.w3x", "update-embedded-before.bin"));
    UPDATE_CHECK(libmpq__update_begin(&update, "update-embedded-abort.w3x") == LIBMPQ_SUCCESS);
    UPDATE_CHECK(libmpq__update_remove(update, "missing") == LIBMPQ_ERROR_EXIST);
    UPDATE_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-embedded-abort.w3x", "update-embedded-before.bin"));
    UPDATE_CHECK(libmpq__update_begin(&update, "update-embedded-abort.w3x") == LIBMPQ_SUCCESS);
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    working = fopen(libmpq__update_path(update), "wb");
    UPDATE_CHECK(working != NULL);
    UPDATE_CHECK(fwrite("X", 1, 1, working) == 1);
    UPDATE_CHECK(fclose(working) == 0);
    working = NULL;
    UPDATE_CHECK(libmpq__update_commit(update) != LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-embedded-abort.w3x", "update-embedded-before.bin"));
    UPDATE_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.w3x", "update-fixture.w3x") == 0);
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-fixture.w3x", -1) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG));
    UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    UPDATE_CHECK(libmpq__update_begin(&update, "update-fixture.w3x") == LIBMPQ_SUCCESS);
    UPDATE_CHECK(
        libmpq__update_replace_data(
            update, "overview.txt", replacement, sizeof(replacement) - 1u, NULL
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-fixture.w3x", -1) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(archive->archive_offset > 0);
    UPDATE_CHECK(check_named(archive, "overview.txt", replacement, sizeof(replacement) - 1u) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(signatures == 0);
    UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    return 0;

fail:
    if (working != NULL)
        (void)fclose(working);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (update != NULL)
        (void)libmpq__update_abort(update);
    free(before);
    free(after);
    return 1;
}

#ifndef _WIN32
static int
test_identity_mismatch(const char *path)
{
    static const uint8_t replacement[] = "external replacement";
    mpq_update_s *update = NULL;
    char *temporary;
    uint8_t *bytes;
    size_t size;

    TEST_CHECK(write_bytes(path, (const uint8_t *)"original", 8) == 0);
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    temporary = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(temporary != NULL);
    TEST_CHECK(write_bytes("update-replacement.bin", replacement, sizeof(replacement) - 1U) == 0);
    TEST_CHECK(rename("update-replacement.bin", path) == 0);
    TEST_CHECK(libmpq__update_transaction_commit(update) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(access(temporary, F_OK) != 0);
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(replacement) - 1U && memcmp(bytes, replacement, size) == 0);
    free(bytes);
    free(temporary);
    return 0;
}

static int
test_symlink_destination(void)
{
    static const uint8_t contents[] = "real destination";
    struct stat status;
    mpq_update_s *update = NULL;
    uint8_t *bytes;
    size_t size;

    TEST_CHECK(write_bytes("update-real.bin", contents, sizeof(contents) - 1U) == 0);
    if (symlink("update-real.bin", "update-link.bin") != 0) {
        TEST_CHECK(unlink("update-real.bin") == 0);
        return 0;
    }
    TEST_CHECK(libmpq__update_transaction_begin(&update, "update-link.bin") != LIBMPQ_SUCCESS);
    TEST_CHECK(update == NULL);
    TEST_CHECK(lstat("update-link.bin", &status) == 0);
    TEST_CHECK(S_ISLNK(status.st_mode));
    TEST_CHECK(read_bytes("update-real.bin", &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(contents) - 1U && memcmp(bytes, contents, size) == 0);
    free(bytes);
    TEST_CHECK(unlink("update-link.bin") == 0);
    TEST_CHECK(unlink("update-real.bin") == 0);
    return 0;
}
#endif

#ifndef _WIN32
static int
test_permissions(const char *path)
{
    mpq_update_s *update = NULL;
    struct stat status;

    TEST_CHECK(write_bytes(path, (const uint8_t *)"permissions", 11) == 0);
    TEST_CHECK(chmod(path, 0640) == 0);
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_transaction_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(stat(path, &status) == 0);
    TEST_CHECK((status.st_mode & 0777) == 0640);
    return 0;
}
#endif

static int
test_mpqe_noop(void)
{
    char source[512];
    const char *path = "update.mpqe";
    const char *reference = "update.mpqe.reference";
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;

    TEST_CHECK(snprintf(source, sizeof(source), "%s/%s", FIXTURE_DIR, "mpq-v1-features.mpqe") > 0);
    TEST_CHECK(copy_file(source, path) == 0);
    TEST_CHECK(copy_file(source, reference) == 0);
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_transaction_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(
        libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1U) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

static int
test_public_mpqe_updates(void)
{
    static const char *paths[] = { "update-mpqe-data.mpqe", "update-mpqe-path.mpqe",
                                   "update-mpqe-remove.mpqe", "update-mpqe-rename.mpqe",
                                   "update-mpqe-multiple.mpqe" };
    static const uint8_t replacement[] = "authenticated replacement contents";
    static const uint8_t original_plain[] = "ordinary file";
    static const uint8_t secret[] = "secret compressed and encrypted payload";
    uint8_t borrowed_code[LIBMPQ_MPQE_AUTH_CODE_MINIMUM];
    uint8_t wrong_code[LIBMPQ_MPQE_AUTH_CODE_MINIMUM] = { 0 };
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    FILE *working = NULL;
    uint32_t number;
    uint32_t signatures;
    uint32_t i;
#ifndef _WIN32
    struct stat mode_status;
#endif

    UPDATE_CHECK(write_bytes("update-mpqe-input.bin", replacement, sizeof(replacement) - 1u) == 0);
    memcpy(borrowed_code, auth_code, sizeof(borrowed_code));
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        UPDATE_CHECK(create_mpqe_edit_archive(paths[i]) == 0);
#ifndef _WIN32
        if (i == 0)
            UPDATE_CHECK(chmod(paths[i], 0640) == 0);
#endif
        UPDATE_CHECK(
            libmpq__update_begin_mpqe(
                &update, paths[i], i == 0 ? borrowed_code : auth_code,
                i == 0 ? sizeof(borrowed_code) : sizeof(auth_code) - 1u
            ) == LIBMPQ_SUCCESS
        );
        if (i == 0) {
            UPDATE_CHECK(
                libmpq__archive_open(&archive, libmpq__update_path(update), -1) == LIBMPQ_SUCCESS
            );
            UPDATE_CHECK(
                check_named(archive, "plain", original_plain, sizeof(original_plain) - 1u) == 0
            );
            UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
            archive = NULL;
        }
        if (i == 0)
            memset(borrowed_code, 0, sizeof(borrowed_code));
        if (i == 0 || i == 4)
            UPDATE_CHECK(
                libmpq__update_replace_data(
                    update, "plain", replacement, sizeof(replacement) - 1u, NULL
                ) == LIBMPQ_SUCCESS
            );
        if (i == 1)
            UPDATE_CHECK(
                libmpq__update_replace_path(update, "plain", "update-mpqe-input.bin", NULL) ==
                LIBMPQ_SUCCESS
            );
        if (i == 2 || i == 4)
            UPDATE_CHECK(libmpq__update_remove(update, "removed") == LIBMPQ_SUCCESS);
        if (i == 3 || i == 4)
            UPDATE_CHECK(
                libmpq__update_rename(update, "secret", "renamed-secret") == LIBMPQ_SUCCESS
            );
        UPDATE_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
        update = NULL;
#ifndef _WIN32
        if (i == 0) {
            UPDATE_CHECK(stat(paths[i], &mode_status) == 0);
            UPDATE_CHECK((mode_status.st_mode & 0777) == 0640);
        }
#endif
        UPDATE_CHECK(
            libmpq__archive_open_mpqe(&archive, paths[i], -1, auth_code, sizeof(auth_code) - 1u) ==
            LIBMPQ_SUCCESS
        );
        if (i == 0 || i == 1 || i == 4)
            UPDATE_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
        if (i == 2 || i == 4)
            UPDATE_CHECK(libmpq__file_number(archive, "removed", &number) == LIBMPQ_ERROR_EXIST);
        if (i == 3 || i == 4) {
            UPDATE_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_ERROR_EXIST);
            UPDATE_CHECK(check_named(archive, "renamed-secret", secret, sizeof(secret) - 1u) == 0);
        }
        UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
        archive = NULL;
    }
    UPDATE_CHECK(create_mpqe_edit_archive("update-mpqe-rollback.mpqe") == 0);
    UPDATE_CHECK(copy_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin") == 0);
    UPDATE_CHECK(libmpq__update_begin(&update, "update-mpqe-rollback.mpqe") != LIBMPQ_SUCCESS);
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(&update, "update-mpqe-rollback.mpqe", NULL, 0) ==
        LIBMPQ_ERROR_DECRYPT
    );
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, LIBMPQ_MPQE_AUTH_CODE_MINIMUM - 1u
        ) == LIBMPQ_ERROR_DECRYPT
    );
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", wrong_code, sizeof(wrong_code)
        ) != LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(create_archive("update-not-mpqe.mpq") == 0);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-not-mpqe.mpq", auth_code, sizeof(auth_code) - 1u
        ) != LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__update_remove(update, "missing") == LIBMPQ_ERROR_EXIST);
    UPDATE_CHECK(libmpq__update_abort(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        LIBMPQ_SUCCESS
    );
    working = fopen(libmpq__update_path(update), "wb");
    UPDATE_CHECK(working != NULL);
    UPDATE_CHECK(fwrite("X", 1, 1, working) == 1);
    UPDATE_CHECK(fclose(working) == 0);
    working = NULL;
    UPDATE_CHECK(libmpq__update_commit(update) != LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpqe", "update-mpqe-signed.mpqe") == 0);
    UPDATE_CHECK(
        libmpq__archive_open_mpqe(
            &archive, "update-mpqe-signed.mpqe", -1, auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
    UPDATE_CHECK((signatures & LIBMPQ_SIGNATURE_WEAK) != 0);
    UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-signed.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(
        libmpq__update_replace_data(
            update, "overview.txt", replacement, sizeof(replacement) - 1u, NULL
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    update = NULL;
    UPDATE_CHECK(
        libmpq__archive_open_mpqe(
            &archive, "update-mpqe-signed.mpqe", -1, auth_code, sizeof(auth_code) - 1u
        ) == LIBMPQ_SUCCESS
    );
    UPDATE_CHECK(check_named(archive, "overview.txt", replacement, sizeof(replacement) - 1u) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == LIBMPQ_SUCCESS);
    UPDATE_CHECK(signatures == 0);
    UPDATE_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;

fail:
    if (working != NULL)
        (void)fclose(working);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (update != NULL)
        (void)libmpq__update_abort(update);
    return 1;
}

int
main(void)
{
    const char *archive_path = "update.mpq";
    mpq_update_s *update = NULL;

    TEST_CHECK(libmpq__update_transaction_begin(NULL, archive_path) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__update_transaction_begin(&update, NULL) == LIBMPQ_ERROR_EXIST && update == NULL
    );
    TEST_CHECK(libmpq__update_commit(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_abort(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(create_archive(archive_path) == 0);
    TEST_CHECK(copy_file(archive_path, "update-reference.mpq") == 0);
    TEST_CHECK(test_abort(archive_path) == 0);
    TEST_CHECK(test_working_copy_isolation(archive_path, "update-reference.mpq") == 0);
    TEST_CHECK(test_noop_commit(archive_path, "update-reference.mpq") == 0);
    TEST_CHECK(test_public_replace(archive_path) == 0);
    TEST_CHECK(test_public_edit() == 0);
    TEST_CHECK(test_public_abort_and_path() == 0);
    TEST_CHECK(test_public_signatures() == 0);
    TEST_CHECK(test_public_limits() == 0);
    TEST_CHECK(test_public_trailing_bytes() == 0);
    TEST_CHECK(test_public_v2() == 0);
    TEST_CHECK(test_public_replace_options() == 0);
    TEST_CHECK(test_shared_blocks() == 0);
    TEST_CHECK(test_shared_metadata() == 0);
    TEST_CHECK(test_publication("update-container.bin") == 0);
    TEST_CHECK(test_failure_cleanup("update-flush.bin", UPDATE_FAULT_FLUSH) == 0);
    TEST_CHECK(test_failure_cleanup("update-close.bin", UPDATE_FAULT_CLOSE) == 0);
    TEST_CHECK(test_failure_cleanup("update-publish.bin", UPDATE_FAULT_PUBLISH) == 0);
    TEST_CHECK(test_embedded_preservation(archive_path, "update-embedded.bin") == 0);
    TEST_CHECK(test_public_embedded_updates() == 0);
#ifndef _WIN32
    TEST_CHECK(test_stable_working_path() == 0);
    TEST_CHECK(test_identity_mismatch("update-identity.bin") == 0);
    TEST_CHECK(test_symlink_destination() == 0);
    TEST_CHECK(test_permissions("update-permissions.bin") == 0);
#endif
    TEST_CHECK(test_mpqe_noop() == 0);
    TEST_CHECK(test_public_mpqe_updates() == 0);
    return 0;
}
