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

#include "mpq-archive.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-md5.h"
#include "mpq-mpqe.h"
#include "mpq-patch-reader.h"
#include "mpq-reader.h"
#include "mpq-signature.h"
#include "mpq-source.h"
#include "mpq-update.h"
#include "mpq-writer.h"
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
    if (result == 0)
        result = libmpq__archive_add_data(archive, "payload", payload, sizeof(payload) - 1U, NULL);
    if (archive != NULL) {
        int32_t close_result = libmpq__archive_close(archive);

        if (result == 0)
            result = close_result;
    }
    return result == 0 ? 0 : -1;
}

static int
test_abort(const char *path)
{
    mpq_update_s *update = NULL;
    char *temporary;

    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
    TEST_CHECK(update != NULL && libmpq__update_path(update) != NULL);
    temporary = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(temporary != NULL);
    TEST_CHECK(libmpq__update_abort(update) == 0);
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

    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_ops(update)->publish == libmpq__directory_replace);
    TEST_CHECK(libmpq__update_transaction_commit(update) == 0);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, payload, sizeof(payload), NULL) == 0);
    TEST_CHECK(memcmp(payload, "update payload", sizeof(payload)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
    TEST_CHECK(libmpq__update_begin(&update, "update-public.mpq") == 0);
    previous_path = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(previous_path != NULL);
    replace_result =
        libmpq__update_replace_data(update, "payload", changed, sizeof(changed) - 1u, NULL);
    path_changed = replace_result == 0 && strcmp(previous_path, libmpq__update_path(update)) != 0;
    orphan = fopen(previous_path, "rb");
    old_removed = orphan == NULL;
    if (orphan != NULL)
        (void)fclose(orphan);
    free(previous_path);
    if (replace_result != 0)
        fprintf(stderr, "update replacement returned %d\n", replace_result);
    TEST_CHECK(replace_result == 0);
    TEST_CHECK(path_changed);
    TEST_CHECK(old_removed);
    TEST_CHECK(libmpq__archive_open(&archive, "update-public.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    {
        uint8_t original[sizeof("update payload") - 1u];

        TEST_CHECK(libmpq__file_read(archive, number, original, sizeof(original), NULL) == 0);
        TEST_CHECK(memcmp(original, "update payload", sizeof(original)) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-public.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, bytes, sizeof(bytes), NULL) == 0);
    TEST_CHECK(memcmp(bytes, changed, sizeof(bytes)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
    if (result == 0)
        result = libmpq__archive_add_data(archive, "plain", plain, sizeof(plain) - 1u, NULL);
    if (result == 0)
        result =
            libmpq__archive_add_data(archive, "secret", secret, sizeof(secret) - 1u, &encrypted);
    if (result == 0)
        result = libmpq__archive_add_data(archive, "unknown", unknown, sizeof(unknown) - 1u, NULL);
    if (archive != NULL) {
        int32_t closed = libmpq__archive_close(archive);

        if (result == 0)
            result = closed;
    }
    return result == 0 ? 0 : -1;
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

    if (result == 0)
        result = libmpq__archive_add_data(archive, "plain", plain, sizeof(plain) - 1u, NULL);
    if (result == 0)
        result =
            libmpq__archive_add_data(archive, "secret", secret, sizeof(secret) - 1u, &encrypted);
    if (result == 0)
        result = libmpq__archive_add_data(archive, "removed", removed, sizeof(removed) - 1u, NULL);
    if (archive != NULL) {
        int32_t closed = libmpq__archive_close(archive);

        if (result == 0)
            result = closed;
    }
    return result == 0 ? 0 : -1;
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

    if (libmpq__archive_open(&archive, path, 0) != 0)
        return -1;
    if (libmpq__file_number(archive, source_name, &first) != 0 ||
        libmpq__file_number(archive, alias_name, &second) != 0)
        goto fail;
    if (archive->mpq_entry[archive->mpq_map[first].entry_index].source_mask !=
            LIBMPQ_ENTRY_SOURCE_CLASSIC ||
        archive->mpq_entry[archive->mpq_map[second].entry_index].source_mask !=
            LIBMPQ_ENTRY_SOURCE_CLASSIC)
        goto fail;
    block = archive->mpq_entry[archive->mpq_map[first].entry_index].classic_source_index;
    count = archive->mpq_header.hash_table_count;
    bytes = (size_t)count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    raw = malloc(bytes);
    if (raw == NULL)
        goto fail;
    for (i = 0; i < count; i++) {
        mpq_hash_s *entry = &archive->mpq_hash[i];
        size_t at = (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE;

        if (entry->block_table_index ==
            archive->mpq_entry[archive->mpq_map[second].entry_index].classic_source_index)
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
        libmpq__file_seek(file, archive->mpq_header.hash_table_offset, SEEK_SET) != 0 ||
        fwrite(raw, 1, bytes, file) != bytes)
        goto fail;
    if (fclose(file) != 0) {
        file = NULL;
        goto fail;
    }
    free(raw);
    return libmpq__archive_close(archive) == 0 ? 0 : -1;

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
    if (result == 0)
        result = libmpq__archive_add_data(
            archive, "alias-a", payload, sizeof(payload) - 1u, encrypted ? &file_options : NULL
        );
    if (result == 0)
        result = libmpq__archive_add_data(
            archive, "alias-b", payload, sizeof(payload) - 1u, encrypted ? &file_options : NULL
        );
    if (archive != NULL) {
        int32_t close_result = libmpq__archive_close(archive);

        if (result == 0)
            result = close_result;
    }
    if (result != 0)
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
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-remove.mpq") == 0);
    TEST_CHECK(libmpq__update_remove(update, "alias-a") == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-remove.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "alias-a", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "alias-b", &number) == 0);
    {
        uint8_t bytes[sizeof(payload) - 1u];

        TEST_CHECK(libmpq__file_read(archive, number, bytes, sizeof(bytes), NULL) == 0);
        TEST_CHECK(memcmp(bytes, payload, sizeof(bytes)) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_shared_archive("update-shared-staged.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-staged.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "alias-a", "renamed-a") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "alias-b", changed, sizeof(changed) - 1u, NULL) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-staged.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "renamed-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_shared_archive("update-shared-replace.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-replace.mpq") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "alias-a", changed, sizeof(changed) - 1u, NULL) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-replace.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "alias-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_shared_archive("update-shared-rename.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-rename.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "alias-a", "renamed-a") == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-rename.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "alias-a", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(check_named(archive, "renamed-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(check_named(archive, "alias-b", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_shared_archive("update-shared-encrypted.mpq", 1) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-shared-encrypted.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "alias-a", "renamed-a") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-shared-encrypted.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "alias-a", payload, sizeof(payload) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "alias-b", &number) == 0);
    TEST_CHECK(libmpq__file_number(archive, "renamed-a", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
        TEST_CHECK(libmpq__update_begin(&update, paths[i]) == 0);
        if (i != 2) {
            TEST_CHECK(libmpq__update_rename(update, "overview.txt", "renamed-overview.txt") == 0);
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
        TEST_CHECK(libmpq__archive_open(&archive, working, 0) == 0);
        TEST_CHECK(libmpq__file_number(archive, target, &number) == 0);
        if (i != 2)
            TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        TEST_CHECK(libmpq__update_abort(update) == 0);
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
    int32_t close_result = 0;
    int matches;

    TEST_CHECK(buffer != NULL);
    result = libmpq__file_number(archive, name, &number);
    if (result == 0)
        result = libmpq__stream_open_name(archive, name, &stream);
    if (result == 0)
        result = libmpq__stream_read(stream, buffer, (libmpq__off_t)size, &transferred);
    matches =
        result == 0 && transferred == (libmpq__off_t)size && memcmp(buffer, expected, size) == 0;
    if (stream != NULL)
        close_result = libmpq__stream_close(stream);
    free(buffer);
    TEST_CHECK(matches);
    TEST_CHECK(close_result == 0);
    return 0;
}

static int
check_listfile(mpq_archive_s *archive)
{
    uint32_t number;
    libmpq__off_t size = 0;
    uint8_t *bytes;

    TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == 0);
    TEST_CHECK(size > 0 && (uint64_t)size < SIZE_MAX);
    bytes = malloc((size_t)size + 1u);
    TEST_CHECK(bytes != NULL);
    TEST_CHECK(libmpq__file_read(archive, number, bytes, size, NULL) == 0);
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
    TEST_CHECK(libmpq__archive_open(&archive, "update-edit.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "secret", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &original_secret) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__update_begin(&update, "update-edit.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "secret", "renamed-secret") == 0);
    TEST_CHECK(libmpq__update_remove(update, "unknown") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(
            update, "plain", replacement, sizeof(replacement) - 1u, &compressed
        ) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-edit.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(check_named(archive, "renamed-secret", secret, sizeof(secret) - 1u) == 0);
    TEST_CHECK(check_listfile(archive) == 0);
    TEST_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "unknown", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == 0);
    TEST_CHECK(
        libmpq__file_verify(
            archive, number, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &mismatches
        ) == 0 &&
        mismatches == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "renamed-secret", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &renamed_secret) == 0);
    TEST_CHECK(renamed_secret.crc32 == original_secret.crc32);
    TEST_CHECK(memcmp(renamed_secret.md5, original_secret.md5, sizeof(renamed_secret.md5)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_edit_archive("update-unknown.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-unknown.mpq") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-unknown.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(check_named(archive, "secret", secret, sizeof(secret) - 1u) == 0);
    TEST_CHECK(check_named(archive, "unknown", unknown, sizeof(unknown) - 1u) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == 0);
    TEST_CHECK(libmpq__update_remove(update, "plain") == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file("update-abort.mpq", "update-abort-reference.mpq"));

    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "plain", "renamed") == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file("update-abort.mpq", "update-abort-reference.mpq"));

    TEST_CHECK(write_bytes("update-replacement.bin", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == 0);
    TEST_CHECK(libmpq__update_replace_path(update, "plain", "update-replacement.bin", NULL) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file("update-abort.mpq", "update-abort-reference.mpq"));

    TEST_CHECK(libmpq__update_begin(&update, "update-abort.mpq") == 0);
    TEST_CHECK(libmpq__update_replace_path(update, "plain", "update-replacement.bin", NULL) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-abort.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "renamed", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_edit_archive("update-normal-rename.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-normal-rename.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "plain", "renamed") == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-normal-rename.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "renamed", original, sizeof(original) - 1u) == 0);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
    uint32_t wave_entry;
    uint32_t packed_size;
    uint64_t packed_offset;
    uint32_t signatures = UINT32_MAX;
    mpq_file_attributes_s attributes;
    int32_t result;

    UPDATE_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpq", "update-signatures.mpq") == 0);
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-signatures.mpq", 0) == 0);
    UPDATE_CHECK(libmpq__file_number(archive, "wave-mono.wav", &wave_number) == 0);
    wave_entry = archive->mpq_map[wave_number].entry_index;
    packed_size = archive->mpq_entry[wave_entry].packed_size;
    packed_offset = archive->mpq_entry[wave_entry].offset;
    packed = malloc(packed_size);
    after = malloc(packed_size);
    UPDATE_CHECK(packed != NULL && after != NULL);
    UPDATE_CHECK(libmpq__source_read_at(archive->source, packed_offset, packed, packed_size) == 0);
    result = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(result == 0);
    UPDATE_CHECK(libmpq__update_begin(&update, "update-signatures.mpq") == 0);
    UPDATE_CHECK(
        libmpq__update_replace_data(
            update, "overview.txt", replacement, sizeof(replacement) - 1u, NULL
        ) == 0
    );
    result = libmpq__update_commit(update);
    update = NULL;
    UPDATE_CHECK(result == 0);
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-signatures.mpq", 0) == 0);
    UPDATE_CHECK(check_named(archive, "overview.txt", replacement, sizeof(replacement) - 1u) == 0);
    {
        uint32_t overview;

        UPDATE_CHECK(libmpq__file_number(archive, "overview.txt", &overview) == 0);
        UPDATE_CHECK(libmpq__file_attributes(archive, overview, &attributes) == 0);
        UPDATE_CHECK(attributes.filetime == 0);
    }
    UPDATE_CHECK(libmpq__file_number(archive, "wave-mono.wav", &wave_number) == 0);
    UPDATE_CHECK(archive->mpq_map[wave_number].entry_index == wave_entry);
    UPDATE_CHECK(archive->mpq_entry[wave_entry].packed_size == packed_size);
    UPDATE_CHECK(archive->mpq_entry[wave_entry].offset == packed_offset);
    UPDATE_CHECK(libmpq__source_read_at(archive->source, packed_offset, after, packed_size) == 0);
    UPDATE_CHECK(memcmp(after, packed, packed_size) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    UPDATE_CHECK(signatures == 0);
    result = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(result == 0);
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
    TEST_CHECK(libmpq__update_begin(&update, "update-noop.mpq") == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(same_file(FIXTURE_DIR "/mpq-v1-features.mpq", "update-noop.mpq"));
    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpqe", "update-mpqe.mpqe") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-mpqe.mpqe") != 0);
    TEST_CHECK(update == NULL);
    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.w3x", "update-embedded.w3x") == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-embedded.w3x") == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(create_edit_archive("update-collision.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-collision.mpq") == 0);
    TEST_CHECK(libmpq__update_rename(update, "plain", "secret") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_rename(update, "plain", "(attributes)") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_remove(update, "missing") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_abort(update) == 0);
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
    TEST_CHECK(libmpq__update_begin(&update, "update-trailing.mpq") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "payload", changed, sizeof(changed) - 1u, NULL) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
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
    TEST_CHECK(libmpq__update_begin(&update, "update-v2.mpq") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "overview.txt", changed, sizeof(changed) - 1u, NULL) ==
        0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-v2.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "overview.txt", changed, sizeof(changed) - 1u) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    TEST_CHECK(signatures == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    memset(lzma, 'L', sizeof(lzma));
    TEST_CHECK(libmpq__update_begin(&update, "update-v2.mpq") == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "overview.txt", lzma, sizeof(lzma), &compressed) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-v2.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "overview.txt", lzma, sizeof(lzma)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
    uint32_t entry_index;

    memset(replacement, 'Q', sizeof(replacement));
    TEST_CHECK(create_edit_archive("update-options-data.mpq", 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-options-data.mpq") == 0);
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
        0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-options-data.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == 0);
    entry_index = archive->mpq_map[number].entry_index;
    TEST_CHECK((archive->mpq_entry[entry_index].flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0);
    TEST_CHECK(libmpq__block_compression(archive, number, 0, &method) == 0);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_ZLIB);
    TEST_CHECK(libmpq__block_compression(archive, number, 1, &method) == 0);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_BZIP2);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    TEST_CHECK(create_edit_archive("update-options-path.mpq", 0) == 0);
    TEST_CHECK(write_bytes("update-options.bin", replacement, sizeof(replacement)) == 0);
    TEST_CHECK(libmpq__update_begin(&update, "update-options-path.mpq") == 0);
    options.locale = 1;
    TEST_CHECK(
        libmpq__update_replace_path(update, "plain", "update-options.bin", &options) ==
        LIBMPQ_ERROR_FORMAT
    );
    options.locale = 0;
    TEST_CHECK(libmpq__update_replace_path(update, "plain", "update-options.bin", &options) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, "update-options-path.mpq", 0) == 0);
    TEST_CHECK(check_named(archive, "plain", replacement, sizeof(replacement)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "plain", &number) == 0);
    TEST_CHECK(libmpq__block_compression(archive, number, 0, &method) == 0);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_ZLIB);
    TEST_CHECK(libmpq__block_compression(archive, number, 1, &method) == 0);
    TEST_CHECK(method == LIBMPQ_COMPRESSION_BZIP2);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

static int
test_working_copy_isolation(const char *path, const char *reference)
{
    mpq_update_s *update = NULL;
    FILE *working;

    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);

    /* The transaction path must be reopenable while the transaction is active. */
    working = fopen(libmpq__update_path(update), "r+b");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite("X", 1, 1, working) == 1);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(libmpq__update_abort(update) == 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, "source.bin") == 0);
    working_path = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(working_path != NULL);
    TEST_CHECK(chdir(current) == 0);
    working = fopen(working_path, "r+b");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite("X", 1, 1, working) == 1);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
    working = fopen(libmpq__update_path(update), "wb");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite(changed, 1, sizeof(changed) - 1U, working) == sizeof(changed) - 1U);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(original) - 1U && memcmp(bytes, original, size) == 0);
    free(bytes);
    TEST_CHECK(libmpq__update_transaction_commit(update) == 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
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
    TEST_CHECK(libmpq__update_transaction_commit(update) != 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_transaction_commit(update) == 0);
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
            UPDATE_CHECK(libmpq__archive_open(&archive, paths[i], -1) == 0);
            UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
            UPDATE_CHECK((signatures & LIBMPQ_SIGNATURE_STRONG) != 0);
            UPDATE_CHECK(libmpq__archive_close(archive) == 0);
            archive = NULL;
        }
        UPDATE_CHECK(libmpq__update_begin(&update, paths[i]) == 0);
        if (i == 0)
            UPDATE_CHECK(
                libmpq__update_replace_data(
                    update, "plain", replacement, sizeof(replacement) - 1u, NULL
                ) == 0
            );
        else if (i == 1)
            UPDATE_CHECK(
                libmpq__update_replace_path(update, "plain", "update-embedded-input.bin", NULL) == 0
            );
        else if (i == 2)
            UPDATE_CHECK(libmpq__update_remove(update, "plain") == 0);
        else
            UPDATE_CHECK(libmpq__update_rename(update, "secret", "renamed-secret") == 0);
        UPDATE_CHECK(read_bytes(paths[i], &after, &after_size) == 0);
        UPDATE_CHECK(before_size == after_size && memcmp(before, after, before_size) == 0);
        free(after);
        after = NULL;
        UPDATE_CHECK(libmpq__update_commit(update) == 0);
        update = NULL;
        UPDATE_CHECK(libmpq__archive_open(&archive, paths[i], -1) == 0);
        UPDATE_CHECK(archive->archive_offset == 512);
        if (i < 2)
            UPDATE_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
        else if (i == 2)
            UPDATE_CHECK(libmpq__file_number(archive, "plain", &number) == LIBMPQ_ERROR_EXIST);
        else {
            UPDATE_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_ERROR_EXIST);
            UPDATE_CHECK(check_named(archive, "renamed-secret", secret, sizeof(secret) - 1u) == 0);
        }
        UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
        UPDATE_CHECK(signatures == 0);
        UPDATE_CHECK(libmpq__archive_close(archive) == 0);
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
    UPDATE_CHECK(libmpq__update_begin(&update, "update-embedded-abort.w3x") == 0);
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        0
    );
    UPDATE_CHECK(libmpq__update_abort(update) == 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-embedded-abort.w3x", "update-embedded-before.bin"));
    UPDATE_CHECK(libmpq__update_begin(&update, "update-embedded-abort.w3x") == 0);
    UPDATE_CHECK(libmpq__update_remove(update, "missing") == LIBMPQ_ERROR_EXIST);
    UPDATE_CHECK(libmpq__update_abort(update) == 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-embedded-abort.w3x", "update-embedded-before.bin"));
    UPDATE_CHECK(libmpq__update_begin(&update, "update-embedded-abort.w3x") == 0);
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        0
    );
    working = fopen(libmpq__update_path(update), "wb");
    UPDATE_CHECK(working != NULL);
    UPDATE_CHECK(fwrite("X", 1, 1, working) == 1);
    UPDATE_CHECK(fclose(working) == 0);
    working = NULL;
    UPDATE_CHECK(libmpq__update_commit(update) != 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-embedded-abort.w3x", "update-embedded-before.bin"));
    UPDATE_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.w3x", "update-fixture.w3x") == 0);
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-fixture.w3x", -1) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    UPDATE_CHECK(signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG));
    UPDATE_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    UPDATE_CHECK(libmpq__update_begin(&update, "update-fixture.w3x") == 0);
    UPDATE_CHECK(
        libmpq__update_replace_data(
            update, "overview.txt", replacement, sizeof(replacement) - 1u, NULL
        ) == 0
    );
    UPDATE_CHECK(libmpq__update_commit(update) == 0);
    update = NULL;
    UPDATE_CHECK(libmpq__archive_open(&archive, "update-fixture.w3x", -1) == 0);
    UPDATE_CHECK(archive->archive_offset > 0);
    UPDATE_CHECK(check_named(archive, "overview.txt", replacement, sizeof(replacement) - 1u) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    UPDATE_CHECK(signatures == 0);
    UPDATE_CHECK(libmpq__archive_close(archive) == 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, "update-link.bin") != 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_transaction_commit(update) == 0);
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
    TEST_CHECK(libmpq__update_transaction_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_transaction_commit(update) == 0);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(
        libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1U) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
            ) == 0
        );
        if (i == 0) {
            UPDATE_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
            UPDATE_CHECK(
                check_named(archive, "plain", original_plain, sizeof(original_plain) - 1u) == 0
            );
            UPDATE_CHECK(libmpq__archive_close(archive) == 0);
            archive = NULL;
        }
        if (i == 0)
            memset(borrowed_code, 0, sizeof(borrowed_code));
        if (i == 0 || i == 4)
            UPDATE_CHECK(
                libmpq__update_replace_data(
                    update, "plain", replacement, sizeof(replacement) - 1u, NULL
                ) == 0
            );
        if (i == 1)
            UPDATE_CHECK(
                libmpq__update_replace_path(update, "plain", "update-mpqe-input.bin", NULL) == 0
            );
        if (i == 2 || i == 4)
            UPDATE_CHECK(libmpq__update_remove(update, "removed") == 0);
        if (i == 3 || i == 4)
            UPDATE_CHECK(libmpq__update_rename(update, "secret", "renamed-secret") == 0);
        UPDATE_CHECK(libmpq__update_commit(update) == 0);
        update = NULL;
#ifndef _WIN32
        if (i == 0) {
            UPDATE_CHECK(stat(paths[i], &mode_status) == 0);
            UPDATE_CHECK((mode_status.st_mode & 0777) == 0640);
        }
#endif
        UPDATE_CHECK(
            libmpq__archive_open_mpqe(&archive, paths[i], -1, auth_code, sizeof(auth_code) - 1u) ==
            0
        );
        if (i == 0 || i == 1 || i == 4)
            UPDATE_CHECK(check_named(archive, "plain", replacement, sizeof(replacement) - 1u) == 0);
        if (i == 2 || i == 4)
            UPDATE_CHECK(libmpq__file_number(archive, "removed", &number) == LIBMPQ_ERROR_EXIST);
        if (i == 3 || i == 4) {
            UPDATE_CHECK(libmpq__file_number(archive, "secret", &number) == LIBMPQ_ERROR_EXIST);
            UPDATE_CHECK(check_named(archive, "renamed-secret", secret, sizeof(secret) - 1u) == 0);
        }
        UPDATE_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
    }
    UPDATE_CHECK(create_mpqe_edit_archive("update-mpqe-rollback.mpqe") == 0);
    UPDATE_CHECK(copy_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin") == 0);
    UPDATE_CHECK(libmpq__update_begin(&update, "update-mpqe-rollback.mpqe") != 0);
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
        ) != 0
    );
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(create_archive("update-not-mpqe.mpq") == 0);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-not-mpqe.mpq", auth_code, sizeof(auth_code) - 1u
        ) != 0
    );
    UPDATE_CHECK(update == NULL);
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(libmpq__update_commit(update) == 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        0
    );
    UPDATE_CHECK(libmpq__update_abort(update) == 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(libmpq__update_remove(update, "missing") == LIBMPQ_ERROR_EXIST);
    UPDATE_CHECK(libmpq__update_abort(update) == 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-rollback.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(
        libmpq__update_replace_data(update, "plain", replacement, sizeof(replacement) - 1u, NULL) ==
        0
    );
    working = fopen(libmpq__update_path(update), "wb");
    UPDATE_CHECK(working != NULL);
    UPDATE_CHECK(fwrite("X", 1, 1, working) == 1);
    UPDATE_CHECK(fclose(working) == 0);
    working = NULL;
    UPDATE_CHECK(libmpq__update_commit(update) != 0);
    update = NULL;
    UPDATE_CHECK(same_file("update-mpqe-rollback.mpqe", "update-mpqe-rollback-before.bin"));
    UPDATE_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpqe", "update-mpqe-signed.mpqe") == 0);
    UPDATE_CHECK(
        libmpq__archive_open_mpqe(
            &archive, "update-mpqe-signed.mpqe", -1, auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    UPDATE_CHECK((signatures & LIBMPQ_SIGNATURE_WEAK) != 0);
    UPDATE_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    UPDATE_CHECK(
        libmpq__update_begin_mpqe(
            &update, "update-mpqe-signed.mpqe", auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(
        libmpq__update_replace_data(
            update, "overview.txt", replacement, sizeof(replacement) - 1u, NULL
        ) == 0
    );
    UPDATE_CHECK(libmpq__update_commit(update) == 0);
    update = NULL;
    UPDATE_CHECK(
        libmpq__archive_open_mpqe(
            &archive, "update-mpqe-signed.mpqe", -1, auth_code, sizeof(auth_code) - 1u
        ) == 0
    );
    UPDATE_CHECK(check_named(archive, "overview.txt", replacement, sizeof(replacement) - 1u) == 0);
    UPDATE_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    UPDATE_CHECK(signatures == 0);
    UPDATE_CHECK(libmpq__archive_close(archive) == 0);
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

/* The same staged namespace and publication rules apply to every supported version. */
static int
test_generic_add(uint32_t version, int mpqe, int metadata)
{
    mpq_archive_create_options_s create = { version, 16, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[2000];
    uint32_t number;
    uint32_t generation;
    int32_t result;
    char path[128];
    FILE *input;
    memset(payload, 'X', sizeof(payload));
    if (!metadata) {
        create.flags = 0;
        create.attributes = 0;
    }
    if (version == LIBMPQ_ARCHIVE_VERSION_THREE)
        storage.flags |= 0x00020000u;
    TEST_CHECK(test_temp_path(path, sizeof(path), "generic-add") == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_create_mpqe(
                    &archive, path, auth_code, sizeof(auth_code) - 1, &create
                )
              : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_data(update, "missing", payload, sizeof(payload), NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    result = libmpq__update_add_data(update, "folder/secret", payload, sizeof(payload), &storage);
    if (result != 0)
        fprintf(stderr, "add version=%u mpqe=%d error=%d\n", version, mpqe, result);
    TEST_CHECK(result == 0);
    TEST_CHECK(
        libmpq__update_add_data(update, "FOLDER/SECRET", payload, sizeof(payload), NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    input = fopen("update-add-input.bin", "wb");
    TEST_CHECK(input != NULL && fwrite("path", 1, 4, input) == 4 && fclose(input) == 0);
    TEST_CHECK(libmpq__update_add_path(update, "from-path", "update-add-input.bin", NULL) == 0);
    TEST_CHECK(libmpq__update_add_data(update, "zero", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__update_rename(update, "folder/secret", "folder/renamed-secret") == 0);
    TEST_CHECK(libmpq__update_remove(update, "from-path") == 0);
    TEST_CHECK(libmpq__update_remove(update, "from-path") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_add_data(update, "from-path", (const uint8_t *)"new", 3, NULL) == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "from-path", (const uint8_t *)"replaced", 8, NULL) == 0
    );
    TEST_CHECK(
        libmpq__update_add_path(update, "failed", "does-not-exist", NULL) == LIBMPQ_ERROR_OPEN
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
              : libmpq__archive_open(&archive, path, 0)) == 0
    );
    TEST_CHECK(libmpq__archive_version(archive, &generation) == 0 && generation == version + 1);
    TEST_CHECK(check_named(archive, "folder/renamed-secret", payload, sizeof(payload)) == 0);
    TEST_CHECK(check_named(archive, "from-path", (const uint8_t *)"replaced", 8) == 0);
    TEST_CHECK(check_named(archive, "zero", (const uint8_t *)"", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "folder/secret", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "failed", &number) == LIBMPQ_ERROR_EXIST);
    for (uint32_t i = 0; version == LIBMPQ_ARCHIVE_VERSION_THREE && i < archive->files; ++i) {
        mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        TEST_CHECK(entry->source_mask == (LIBMPQ_ENTRY_SOURCE_CLASSIC | LIBMPQ_ENTRY_SOURCE_BET));
        TEST_CHECK(
            archive->classic_entry_indices[entry->classic_source_index] ==
            archive->bet_entry_indices[entry->bet_source_index]
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove("update-add-input.bin") == 0);
    return 0;
}

/* A dense legacy block table grows without needing names for retained payloads. */
static int
test_add_dense(uint32_t version)
{
    mpq_archive_create_options_s create = { version, 1, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    const char *path = "update-dense-add.mpq";
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "first", (const uint8_t *)"first", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_add_path(update, "bad", NULL, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_add_data(update, "second", (const uint8_t *)"second", 6, NULL) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.block_table_count == 2);
    TEST_CHECK(check_named(archive, "first", (const uint8_t *)"first", 5) == 0);
    TEST_CHECK(check_named(archive, "second", (const uint8_t *)"second", 6) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Strip only synthetic classic tables, retaining the independently decoded HET/BET bytes. */
static int
strip_classic_tables(const char *path)
{
    uint8_t *bytes;
    size_t size;
    uint32_t end;
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size >= LIBMPQ_HEADER_V3_WIRE_SIZE);
    end = libmpq__load_le32(bytes + 16);
    TEST_CHECK(end >= LIBMPQ_HEADER_V3_WIRE_SIZE && end < size);
    memset(bytes + 16, 0, 16);
    memset(bytes + 32, 0, 12);
    libmpq__store_le32(bytes + 8, end);
    libmpq__store_le64(bytes + 44, end);
    TEST_CHECK(write_bytes(path, bytes, end) == 0);
    free(bytes);
    return 0;
}

static int
test_v3_reconstruction(int complete)
{
    const char *path = "update-v3-bet-only.mpq";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 8, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint32_t count;
    create.flags = complete ? LIBMPQ_ARCHIVE_CREATE_LISTFILE : 0;
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "known", (const uint8_t *)"known", 5, NULL) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "unknown", (const uint8_t *)"unknown", 7, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(strip_classic_tables(path) == 0);
    TEST_CHECK(copy_file(path, "update-v3-bet-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    if (complete) {
        TEST_CHECK(libmpq__update_remove(update, "known") == 0);
        TEST_CHECK(libmpq__update_add_data(update, "new", (const uint8_t *)"new", 3, NULL) == 0);
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(check_named(archive, "unknown", (const uint8_t *)"unknown", 7) == 0);
        TEST_CHECK(check_named(archive, "new", (const uint8_t *)"new", 3) == 0);
        TEST_CHECK(libmpq__archive_files(archive, &count) == 0 && count == 3);
        TEST_CHECK(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE);
        TEST_CHECK(archive->mpq_header.block_table_count == archive->mpq_bet.header.entry_count);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    } else {
        TEST_CHECK(libmpq__update_remove(update, "known") == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(
            libmpq__update_add_data(update, "new", (const uint8_t *)"new", 3, NULL) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(libmpq__update_abort(update) == 0);
        TEST_CHECK(same_file(path, "update-v3-bet-reference.mpq"));
    }
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove("update-v3-bet-reference.mpq") == 0);
    return 0;
}

/* Retained codec/cipher bytes and timestamps survive; signatures and failed publication do not. */
static int
test_v3_metadata_rollback(void)
{
    const char *path = "update-v3-metadata.mpq";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       0x00020000u,
                                   LIBMPQ_COMPRESSION_LZMA, LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    mpq_update_ops_s ops = { fflush, fclose, fail_publish };
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_update_s *update = NULL;
    mpq_file_attributes_s attributes;
    uint8_t strong_key[sizeof(test_strong_signature_public_key)];
    uint8_t payload[1500];
    uint8_t *before;
    uint8_t *after;
    size_t before_size;
    size_t after_size;
    uint32_t number;
    uint32_t signatures;
    libmpq__off_t offset;
    libmpq__off_t packed;
    memset(payload, 'M', sizeof(payload));
    test_strong_signature_private_key(strong_key);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, strong_key, sizeof(strong_key)) == 0
    );
    TEST_CHECK(libmpq__writer_begin(archive, "keep", sizeof(payload), &storage, &writer) == 0);
    TEST_CHECK(libmpq__writer_timestamp(writer, 77) == 0);
    TEST_CHECK(libmpq__writer_write(writer, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__writer_finish(writer) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(read_bytes(path, &before, &before_size) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "keep", &number) == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0);
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_add_data(update, "fresh", (const uint8_t *)"fresh", 5, NULL) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(read_bytes(path, &after, &after_size) == 0);
    TEST_CHECK(
        (uint64_t)offset + (uint64_t)packed <= before_size &&
        (uint64_t)offset + (uint64_t)packed <= after_size
    );
    TEST_CHECK(memcmp(before + (size_t)offset, after + (size_t)offset, (size_t)packed) == 0);
    free(before);
    free(after);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(check_named(archive, "keep", payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "keep", &number) == 0);
    TEST_CHECK(
        libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 77
    );
    TEST_CHECK(
        libmpq__file_verify(
            archive, number, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &signatures
        ) == 0 &&
        signatures == 0
    );
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0 && signatures == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, "update-v3-metadata-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_add_data(update, "unpublished", payload, sizeof(payload), NULL) == 0);
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(same_file(path, "update-v3-metadata-reference.mpq"));
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove("update-v3-metadata-reference.mpq") == 0);
    return 0;
}

/* Each operation must preserve unrelated codec/cipher members, not just their names. */
static int
test_v3_retained_operations(void)
{
    const char *path = "update-v3-retained.mpq";
    const char *keep[] = { "single", "encrypted", "fixed-sector" };
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 16, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                   LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[1800];
    size_t lengths[] = { 512, 512, sizeof(payload) };
    libmpq__off_t packed[3];
    uint32_t flags[3];
    uint32_t counts[] = { 6, 6, 5, 5, 5 };
    uint32_t number;
    uint32_t count;
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i % 19);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    for (size_t i = 0; i < 3; ++i) {
        options.flags = LIBMPQ_FILE_FLAG_COMPRESS;
        if (i < 2)
            options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
        if (i != 0)
            options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
        if (i == 2)
            options.flags |= 0x00020000u;
        TEST_CHECK(
            libmpq__archive_add_data(
                archive, keep[i], payload, (libmpq__off_t)lengths[i], &options
            ) == 0
        );
    }
    TEST_CHECK(libmpq__archive_add_data(archive, "edit", (const uint8_t *)"old", 3, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    for (size_t i = 0; i < 3; ++i) {
        TEST_CHECK(libmpq__file_number(archive, keep[i], &number) == 0);
        TEST_CHECK(libmpq__file_size_packed(archive, number, &packed[i]) == 0);
        TEST_CHECK(libmpq__file_flags(archive, number, &flags[i]) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    for (unsigned operation = 0; operation < 5; ++operation) {
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        if (operation == 0)
            TEST_CHECK(
                libmpq__update_add_data(update, "added", payload, sizeof(payload), NULL) == 0
            );
        else if (operation == 1)
            TEST_CHECK(
                libmpq__update_replace_data(update, "edit", payload, sizeof(payload), NULL) == 0
            );
        else if (operation == 2)
            TEST_CHECK(libmpq__update_remove(update, "added") == 0);
        else if (operation == 3)
            TEST_CHECK(libmpq__update_rename(update, "edit", "renamed") == 0);
        else {
            TEST_CHECK(libmpq__update_remove(update, "renamed") == 0);
            TEST_CHECK(
                libmpq__update_add_data(update, "renamed", payload, sizeof(payload), NULL) == 0
            );
            TEST_CHECK(
                libmpq__update_replace_data(update, "renamed", (const uint8_t *)"new", 3, NULL) == 0
            );
            TEST_CHECK(libmpq__update_rename(update, "renamed", "final") == 0);
        }
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(libmpq__archive_files(archive, &count) == 0 && count == counts[operation]);
        for (size_t i = 0; i < 3; ++i) {
            uint8_t *het = archive->het_data;
            uint32_t classic_number;
            uint32_t actual_flags;
            libmpq__off_t actual_packed;
            libmpq__off_t unpacked;
            TEST_CHECK(check_named(archive, keep[i], payload, lengths[i]) == 0);
            TEST_CHECK(libmpq__file_number(archive, keep[i], &number) == 0);
            archive->het_data = NULL;
            TEST_CHECK(libmpq__file_number(archive, keep[i], &classic_number) == 0);
            archive->het_data = het;
            TEST_CHECK(number == classic_number);
            TEST_CHECK(
                libmpq__file_flags(archive, number, &actual_flags) == 0 && actual_flags == flags[i]
            );
            TEST_CHECK(
                libmpq__file_size_packed(archive, number, &actual_packed) == 0 &&
                actual_packed == packed[i]
            );
            TEST_CHECK(
                libmpq__file_size_unpacked(archive, number, &unpacked) == 0 &&
                unpacked == (libmpq__off_t)lengths[i]
            );
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Hand-written listfiles exercise reconstruction independently of writer-generated lists. */
static int
test_v3_list_names(unsigned variant)
{
    const char *path = "update-v3-list-names.mpq";
    static const char equivalent_names[] = "\r\nfolder/name\n"
                                           "FOLDER/NAME\r\nfolder\\name\nfolder/name\nother\r\n";
    static const char *lists[] = { equivalent_names, "folder/name\nother\nmissing\n",
                                   "folder/name\n", "folder/name\nother\ninvalid\0name\n" };
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 8, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char long_name[267];
    char list[600];
    const char *name = "folder/name";
    const char *bytes = variant < 4 ? lists[variant] : list;
    size_t length = variant == 3 ? sizeof("folder/name\nother\ninvalid\0name\n") - 1
                                 : (variant < 4 ? strlen(bytes) : 0);
    if (variant == 4) {
        memset(long_name, 'a', 264);
        long_name[264] = 'x';
        long_name[265] = '\0';
        name = long_name;
        length = (size_t)snprintf(list, sizeof(list), "%s\n", name);
        long_name[264] = 'y';
        length += (size_t)snprintf(list + length, sizeof(list) - length, "%s\nother\n", name);
        long_name[264] = 'x';
    }
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, name, (const uint8_t *)"first", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"second", 6, NULL) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, "(listfile)", (const uint8_t *)bytes, (libmpq__off_t)length, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(strip_classic_tables(path) == 0);
    TEST_CHECK(copy_file(path, "update-v3-list-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    if (variant == 0) {
        TEST_CHECK(
            libmpq__update_add_data(update, "added", (const uint8_t *)"third", 5, NULL) == 0
        );
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(check_named(archive, "folder\\name", (const uint8_t *)"first", 5) == 0);
        TEST_CHECK(check_named(archive, "other", (const uint8_t *)"second", 6) == 0);
        TEST_CHECK(check_named(archive, "added", (const uint8_t *)"third", 5) == 0);
        TEST_CHECK(archive->mpq_header.block_table_count == archive->mpq_bet.header.entry_count);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    } else {
        TEST_CHECK(
            libmpq__update_add_data(update, "added", (const uint8_t *)"third", 5, NULL) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(libmpq__update_abort(update) == 0);
        TEST_CHECK(same_file(path, "update-v3-list-reference.mpq"));
    }
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove("update-v3-list-reference.mpq") == 0);
    return 0;
}

/* Faults after validation must not publish a rebuild or leave a consumed stream owned. */
static int
test_adoption_failure(update_fault_e fault, int commit, int mpqe, uint32_t version)
{
    const char *path = "update-v3-adoption.mpq";
    mpq_archive_create_options_s create = { version, 8, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_update_ops_s ops = { fflush, fclose, fail_publish };
    char *previous;
    FILE *probe;
    int missing;
    TEST_CHECK(
        (mpqe ? libmpq__archive_create_mpqe(
                    &archive, path, auth_code, sizeof(auth_code) - 1, &create
                )
              : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "keep", (const uint8_t *)"keep", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, "update-v3-adoption-reference.mpq") == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    previous = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(previous != NULL);
    if (fault == UPDATE_FAULT_FLUSH)
        ops.flush = fail_flush;
    else if (fault == UPDATE_FAULT_CLOSE)
        ops.close = fail_close;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(
        libmpq__update_add_data(update, "added", (const uint8_t *)"added", 5, NULL) ==
        (fault == UPDATE_FAULT_FLUSH ? LIBMPQ_ERROR_WRITE : LIBMPQ_ERROR_CLOSE)
    );
    TEST_CHECK(strcmp(previous, libmpq__update_path(update)) == 0);
    if (fault == UPDATE_FAULT_CLOSE)
        TEST_CHECK(libmpq__update_remove(update, "keep") == LIBMPQ_ERROR_EXIST);
    else {
        TEST_CHECK(libmpq__archive_open(&archive, previous, 0) == 0);
        TEST_CHECK(check_named(archive, "keep", (const uint8_t *)"keep", 4) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    if (commit)
        TEST_CHECK(
            libmpq__update_commit(update) ==
            (fault == UPDATE_FAULT_FLUSH ? LIBMPQ_ERROR_WRITE : LIBMPQ_ERROR_EXIST)
        );
    else {
        libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish });
        if (fault == UPDATE_FAULT_FLUSH)
            TEST_CHECK(
                libmpq__update_add_data(update, "added", (const uint8_t *)"added", 5, NULL) == 0
            );
        TEST_CHECK(libmpq__update_abort(update) == 0);
    }
    TEST_CHECK(same_file(path, "update-v3-adoption-reference.mpq"));
    probe = fopen(previous, "rb");
    missing = probe == NULL;
    if (probe != NULL)
        (void)fclose(probe);
    TEST_CHECK(missing);
    free(previous);
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove("update-v3-adoption-reference.mpq") == 0);
    return 0;
}

/* Normalized HET requests retain the stored classic spelling during replacement. */
static int
test_v3_normalized_update(int mpqe)
{
    const char *path = "update-v3-normalized.mpq";
    const char *input = "update-v3-normalized.bin";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       0x00020000u,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[1300];
    uint32_t hashes[3];
    uint32_t het_number;
    uint32_t classic_number;
    memset(payload, 'N', sizeof(payload));
    TEST_CHECK(write_bytes(input, payload, sizeof(payload)) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_create_mpqe(
                    &archive, path, auth_code, sizeof(auth_code) - 1, &create
                )
              : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, "folder/item", payload, sizeof(payload), &storage) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "keep", (const uint8_t *)"keep", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    for (unsigned pass = 0; pass < 2; ++pass) {
        TEST_CHECK(
            (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                  : libmpq__update_begin(&update, path)) == 0
        );
        TEST_CHECK(
            (pass == 0 ? libmpq__update_replace_data(
                             update, "FOLDER\\ITEM", payload, sizeof(payload), &storage
                         )
                       : libmpq__update_replace_path(update, "folder\\item", input, &storage)) == 0
        );
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            (mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
                  : libmpq__archive_open(&archive, path, 0)) == 0
        );
        TEST_CHECK(check_named(archive, "folder\\item", payload, sizeof(payload)) == 0);
        TEST_CHECK(check_named(archive, "keep", (const uint8_t *)"keep", 4) == 0);
        TEST_CHECK(libmpq__file_number(archive, "folder\\item", &het_number) == 0);
        libmpq__file_hash("folder/item", &hashes[0], &hashes[1], &hashes[2]);
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, hashes[0], hashes[1], hashes[2], &classic_number
            ) == 0
        );
        TEST_CHECK(het_number == classic_number);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_rename(update, "folder\\item", "folder/renamed") == 0);
    TEST_CHECK(libmpq__update_remove(update, "folder\\renamed") == 0);
    TEST_CHECK(
        libmpq__update_add_data(update, "folder/renamed", payload, sizeof(payload), &storage) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
              : libmpq__archive_open(&archive, path, 0)) == 0
    );
    TEST_CHECK(check_named(archive, "folder\\renamed", payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "folder/item", &het_number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(input) == 0);
    return 0;
}

/* Check the cipher against positions decoded from wire tables, not writer bookkeeping. */
static int
check_serialized_member_key(
    mpq_archive_s *archive, const char *name, uint32_t base_key, const uint8_t *expected,
    size_t size
)
{
    uint8_t header[68];
    uint8_t blocks[256];
    uint8_t packed[2048];
    uint8_t decoded[1600];
    uint32_t number;
    uint32_t row;
    uint32_t count;
    uint32_t flags;
    uint32_t packed_size;
    uint64_t block_offset;
    uint64_t position;
    uint32_t key = base_key;
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(
        (archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask &
         LIBMPQ_ENTRY_SOURCE_CLASSIC) != 0
    );
    row = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    TEST_CHECK(
        libmpq__source_read_at(archive->source, archive->archive_offset, header, sizeof(header)) ==
        0
    );
    count = libmpq__load_le32(header + 28);
    TEST_CHECK(count <= sizeof(blocks) / 16 && row < count);
    block_offset = libmpq__load_le32(header + 20);
    if (archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_TWO)
        block_offset |= (uint64_t)libmpq__load_le16(header + 42) << 32;
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, archive->archive_offset + block_offset, blocks, count * 16
        ) == 0
    );
    TEST_CHECK(libmpq__crypto_decrypt_block(blocks, count * 16, 0xec83b3a3u) == 0);
    position = libmpq__load_le32(blocks + row * 16);
    packed_size = libmpq__load_le32(blocks + row * 16 + 4);
    TEST_CHECK(libmpq__load_le32(blocks + row * 16 + 8) == size);
    flags = libmpq__load_le32(blocks + row * 16 + 12);
    if (archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_TWO &&
        libmpq__load_le64(header + 32) != 0) {
        uint8_t high[2];
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, archive->archive_offset + libmpq__load_le64(header + 32) + row * 2,
                high, sizeof(high)
            ) == 0
        );
        position |= (uint64_t)libmpq__load_le16(high) << 32;
    }
    if (archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE) {
        mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        mpq_bet_entry_s record;
        uint64_t het_offset = libmpq__load_le64(header + 60);
        uint64_t bet_offset = libmpq__load_le64(header + 52);
        uint64_t hash_offset =
            libmpq__load_le32(header + 16) | ((uint64_t)libmpq__load_le16(header + 40) << 32);
        TEST_CHECK(libmpq__load_le32(header + 4) == 68 && libmpq__load_le16(header + 12) == 2);
        TEST_CHECK(het_offset >= 68 && het_offset < bet_offset && bet_offset < hash_offset);
        TEST_CHECK(hash_offset + (uint64_t)libmpq__load_le32(header + 24) * 16 == block_offset);
        TEST_CHECK((entry->source_mask & LIBMPQ_ENTRY_SOURCE_BET) != 0);
        TEST_CHECK(
            libmpq__bet_record_decode(&archive->mpq_bet, entry->bet_source_index, &record) == 0
        );
        TEST_CHECK(
            record.offset == position && record.packed_size == packed_size &&
            record.unpacked_size == size && record.flags == flags
        );
        TEST_CHECK(
            archive->mpq_bet.header.entry_count == count &&
            archive->mpq_het.header.entry_count == count
        );
    }
    if ((flags & 0x00020000u) != 0)
        key = (base_key + (uint32_t)position) ^ (uint32_t)size;
    TEST_CHECK(packed_size <= sizeof(packed) && size <= sizeof(decoded));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, archive->archive_offset + position, packed, packed_size
        ) == 0
    );
    if ((flags & LIBMPQ_FILE_FLAG_SINGLE) != 0) {
        TEST_CHECK(libmpq__crypto_decrypt_block(packed, packed_size, key) == 0);
        TEST_CHECK(packed_size == size && memcmp(packed, expected, size) == 0);
    } else {
        uint32_t sectors = (uint32_t)((size + 511) / 512);
        uint32_t table_size = (sectors + 1) * 4;
        TEST_CHECK(table_size <= packed_size);
        TEST_CHECK(libmpq__crypto_decrypt_block(packed, table_size, key - 1) == 0);
        TEST_CHECK(libmpq__load_le32(packed) == table_size);
        TEST_CHECK(libmpq__load_le32(packed + sectors * 4) == packed_size);
        for (uint32_t i = 0; i < sectors; ++i) {
            uint32_t start = libmpq__load_le32(packed + i * 4);
            uint32_t end = libmpq__load_le32(packed + (i + 1) * 4);
            uint32_t bytes = (uint32_t)(size - i * 512);
            if (bytes > 512)
                bytes = 512;
            TEST_CHECK(start >= table_size && start <= end && end <= packed_size);
            TEST_CHECK(libmpq__crypto_decrypt_block(packed + start, end - start, key + i) == 0);
            TEST_CHECK(
                libmpq__compression_decompress_block(
                    packed + start, end - start, decoded + i * 512, bytes,
                    LIBMPQ_FLAG_COMPRESS_MULTI, archive->mpq_header.version
                ) == (int32_t)bytes
            );
        }
        TEST_CHECK(memcmp(decoded, expected, size) == 0);
    }
    return 0;
}

/* Embed the logical MPQ at offset 512, then optionally use the existing MPQE transform. */
static int
prepend_update_archive(const char *path, int mpqe)
{
    mpq_archive_s *archive = NULL;
    uint8_t *bytes = NULL;
    FILE *input = NULL;
    FILE *output = NULL;
    int result = 1;
    int close_result;
    uint64_t size;
    UPDATE_CHECK(
        (mpqe ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
              : libmpq__archive_open(&archive, path, -1)) == 0
    );
    size = archive->file_size;
    UPDATE_CHECK(size <= SIZE_MAX - 512);
    bytes = calloc((size_t)size + 512, 1);
    UPDATE_CHECK(bytes != NULL);
    memcpy(bytes, "HM3W", 4);
    UPDATE_CHECK(libmpq__source_read_at(archive->source, 0, bytes + 512, (size_t)size) == 0);
    close_result = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(close_result == 0);
    if (mpqe) {
        uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
        input = tmpfile();
        output = fopen(path, "wb");
        UPDATE_CHECK(input != NULL && output != NULL);
        UPDATE_CHECK(fwrite(bytes, 1, (size_t)size + 512, input) == size + 512);
        UPDATE_CHECK(libmpq__mpqe_key(key, auth_code, sizeof(auth_code) - 1) == 0);
        UPDATE_CHECK(libmpq__writer_mpqe_transform_file(input, output, key) == 0);
        close_result = fclose(input);
        input = NULL;
        UPDATE_CHECK(close_result == 0);
        close_result = fclose(output);
        output = NULL;
        UPDATE_CHECK(close_result == 0);
    } else
        UPDATE_CHECK(write_bytes(path, bytes, (size_t)size + 512) == 0);
    result = 0;

fail:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (input != NULL)
        (void)fclose(input);
    if (output != NULL)
        (void)fclose(output);
    free(bytes);
    return result;
}

/* Basename and directory-only renames must both rebuild encrypted members correctly. */
static int
test_directory_encrypted_updates(uint32_t version, int mpqe, int embedded, uint32_t storage_flags)
{
    const char *path = "update-directory-key.mpq";
    const char *names[] = { "folder\\reference.bin", "folder\\renamed.bin", "other\\renamed.bin" };
    mpq_archive_create_options_s create = { version, 8, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       0x00020000u,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[1300];
    size_t size = (storage_flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ? 256 : sizeof(payload);
    const char *current = names[0];
    storage.flags = storage_flags;
    memset(payload, 'A', sizeof(payload));
    TEST_CHECK(
        (mpqe ? libmpq__archive_create_mpqe(
                    &archive, path, auth_code, sizeof(auth_code) - 1, &create
                )
              : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (embedded) {
        TEST_CHECK(prepend_update_archive(path, mpqe) == 0);
        if (version == LIBMPQ_ARCHIVE_VERSION_THREE) {

            /* Named v3 rebuilds conservatively reject wrappers, rather than dropping them. */
            TEST_CHECK(copy_file(path, "update-directory-key-reference.mpq") == 0);
            TEST_CHECK(
                (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                      : libmpq__update_begin(&update, path)) == 0
            );
            TEST_CHECK(
                libmpq__update_add_data(update, current, payload, size, &storage) ==
                LIBMPQ_ERROR_FORMAT
            );
            TEST_CHECK(libmpq__update_abort(update) == 0);
            TEST_CHECK(same_file(path, "update-directory-key-reference.mpq"));
            TEST_CHECK(remove(path) == 0 && remove("update-directory-key-reference.mpq") == 0);
            return 0;
        }
    }
    for (unsigned pass = 0; pass < 5; ++pass) {
        TEST_CHECK(
            (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                  : libmpq__update_begin(&update, path)) == 0
        );
        if (pass == 0)
            TEST_CHECK(libmpq__update_add_data(update, current, payload, size, &storage) == 0);
        else if (pass == 1) {
            memset(payload, 'B', sizeof(payload));
            TEST_CHECK(libmpq__update_replace_data(update, current, payload, size, &storage) == 0);
        } else if (pass < 4) {
            TEST_CHECK(libmpq__update_rename(update, current, names[pass - 1]) == 0);
            current = names[pass - 1];
        } else {
            TEST_CHECK(libmpq__update_remove(update, current) == 0);
            TEST_CHECK(libmpq__update_add_data(update, current, payload, size, &storage) == 0);
        }
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            (mpqe ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                  : libmpq__archive_open(&archive, path, -1)) == 0
        );
        TEST_CHECK(archive->archive_offset == (embedded ? 512 : 0));
        TEST_CHECK(check_named(archive, current, payload, size) == 0);
        TEST_CHECK(
            check_serialized_member_key(
                archive, current, pass < 2 ? 0xa25af234u : 0xc74b33e7u, payload, size
            ) == 0
        );
        {
            uint32_t number;
            uint32_t flags;
            uint32_t hashes[3];
            uint32_t classic_number;
            TEST_CHECK(libmpq__file_number(archive, current, &number) == 0);
            libmpq__file_hash(current, &hashes[0], &hashes[1], &hashes[2]);
            TEST_CHECK(
                libmpq__file_number_from_hash(
                    archive, hashes[0], hashes[1], hashes[2], &classic_number
                ) == 0
            );
            TEST_CHECK(number == classic_number);
            TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
            TEST_CHECK(
                (flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u)) ==
                (storage_flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u))
            );
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(copy_file(path, "update-directory-key-reference.mpq") == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_rename(update, current, "abort\\different.bin") == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file(path, "update-directory-key-reference.mpq"));
    TEST_CHECK(remove(path) == 0 && remove("update-directory-key-reference.mpq") == 0);
    return 0;
}

/* A compact external-style archive has no writer-reserved 512-byte payload gap. */
static int
test_compact_fix_key_update(uint32_t version)
{
    const char *path = "update-compact-fix-key.mpq";
    const char *name = "folder\\reference.bin";
    uint8_t wire[108] = { 0 };
    uint32_t header_size = version == LIBMPQ_ARCHIVE_VERSION_ONE ? 32 : 44;
    uint32_t end = header_size + 48;
    uint32_t hashes[3];
    uint8_t payload[16];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_file_options_s storage = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0, 0
    };
    memset(payload, 'C', sizeof(payload));
    libmpq__store_le32(wire, 0x1a51504du);
    libmpq__store_le32(wire + 4, header_size);
    libmpq__store_le32(wire + 8, end);
    libmpq__store_le16(wire + 12, (uint16_t)version);
    libmpq__store_le32(wire + 16, header_size);
    libmpq__store_le32(wire + 20, header_size + 16);
    libmpq__store_le32(wire + 24, 1);
    libmpq__store_le32(wire + 28, 1);
    libmpq__file_hash(name, &hashes[0], &hashes[1], &hashes[2]);
    libmpq__store_le32(wire + header_size, hashes[1]);
    libmpq__store_le32(wire + header_size + 4, hashes[2]);
    libmpq__store_le32(wire + header_size + 16, header_size + 32);
    libmpq__store_le32(wire + header_size + 20, sizeof(payload));
    libmpq__store_le32(wire + header_size + 24, sizeof(payload));
    libmpq__store_le32(wire + header_size + 28, LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_SINGLE);
    memcpy(wire + header_size + 32, payload, sizeof(payload));
    TEST_CHECK(libmpq__crypto_encrypt_block(wire + header_size, 16, 0xc3af3770u) == 0);
    TEST_CHECK(libmpq__crypto_encrypt_block(wire + header_size + 16, 16, 0xec83b3a3u) == 0);
    TEST_CHECK(write_bytes(path, wire, end) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(check_named(archive, name, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, "update-compact-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_replace_data(update, name, payload, sizeof(payload), &storage) == 0);
    libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish });
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(same_file(path, "update-compact-reference.mpq"));
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_replace_data(update, name, payload, sizeof(payload), &storage) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(check_named(archive, name, payload, sizeof(payload)) == 0);
    TEST_CHECK(
        check_serialized_member_key(archive, name, 0xa25af234u, payload, sizeof(payload)) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove("update-compact-reference.mpq") == 0);
    return 0;
}

/* A patch prefix is plaintext; FIX_KEY uses the member start and reconstructed size. */
static int
test_fix_key_patch_prefix(int single)
{
    const char *path = "update-fix-key-prefix.mpq";
    const char *name = "folder\\reference.bin";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 4, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0, 0
    };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_md5_s md5;
    uint8_t prefix[LIBMPQ_PATCH_INFO_SIZE] = { 0 };
    uint8_t payload[132] = { 0 };
    uint8_t output[132];
    uint8_t on_disk_prefix[LIBMPQ_PATCH_INFO_SIZE];
    libmpq__off_t offset;
    libmpq__off_t transferred;
    uint32_t number;
    memcpy(payload, "PTCH", 4);
    libmpq__store_le32(payload + 4, sizeof(payload));
    libmpq__store_le32(payload + 12, 64);
    memcpy(payload + 16, "MD5_", 4);
    libmpq__store_le32(payload + 20, 40);
    libmpq__md5_init(&md5);
    libmpq__md5_final(&md5, payload + 24);
    memset(payload + 68, 'P', 64);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, payload + 68, 64);
    libmpq__md5_final(&md5, payload + 40);
    memcpy(payload + 56, "XFRM", 4);
    libmpq__store_le32(payload + 60, 76);
    memcpy(payload + 64, "COPY", 4);
    libmpq__store_le32(prefix, sizeof(prefix));
    libmpq__store_le32(prefix + 4, 0x80000000u);
    libmpq__store_le32(prefix + 8, sizeof(payload));
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, payload, sizeof(payload));
    libmpq__md5_final(&md5, prefix + 12);
    if (!single) {
        storage.flags &= ~LIBMPQ_FILE_FLAG_SINGLE;
        storage.flags |= LIBMPQ_FILE_FLAG_COMPRESS;
        storage.compression_first = storage.compression_next = LIBMPQ_COMPRESSION_ZLIB;
    }
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    archive->write_patch_mode = 1;
    TEST_CHECK(
        libmpq__writer_patch_file_add(
            archive, name, prefix, sizeof(prefix), payload, sizeof(payload), 64, &storage
        ) == 0
    );
    {
        mpq_file_options_s cache_storage = {
            LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0, 0
        };
        TEST_CHECK(
            libmpq__archive_add_data(
                archive, "cache\\reference.bin", payload, 32, &cache_storage
            ) == 0
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0);
    TEST_CHECK(
        libmpq__source_read_at(archive->source, offset, on_disk_prefix, sizeof(on_disk_prefix)) == 0
    );
    TEST_CHECK(memcmp(prefix, on_disk_prefix, sizeof(prefix)) == 0);
    if (single) {
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, offset + sizeof(prefix), output, sizeof(output)
            ) == 0
        );
        TEST_CHECK(
            libmpq__crypto_decrypt_block(
                output, sizeof(output), (0xa25af234u + (uint32_t)offset) ^ 64u
            ) == 0
        );
        TEST_CHECK(memcmp(output, payload, sizeof(payload)) == 0);
    } else {
        TEST_CHECK(
            libmpq__source_read_at(archive->source, offset + sizeof(prefix), output, 8) == 0
        );
        TEST_CHECK(
            libmpq__crypto_decrypt_block(output, 8, ((0xa25af234u + (uint32_t)offset) ^ 64u) - 1) ==
            0
        );
        TEST_CHECK(libmpq__load_le32(output) == 8);
    }
    TEST_CHECK(
        libmpq__patch_payload_read(archive, number, name, output, sizeof(output), &transferred) == 0
    );
    TEST_CHECK(transferred == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    TEST_CHECK(archive->mpq_file[number] == NULL);
    {
        mpq_archive_s *clone = NULL;
        uint32_t cached_number = number;
        const char *cached_name = name;
        mpq_file_s *cached;
        uint32_t cached_seed;
        uint32_t cached_count;
        if (!single) {

            /* A compressed patch's unadjusted prefix is not a sector table. */
            cached_name = "cache\\reference.bin";
            TEST_CHECK(libmpq__file_number(archive, cached_name, &cached_number) == 0);
        }
        TEST_CHECK(libmpq__reader_offsets_acquire(archive, cached_number, cached_name) == 0);
        cached = archive->mpq_file[cached_number];
        TEST_CHECK(cached != NULL && cached->seed_known);
        cached_seed = cached->seed;
        cached_count = cached->open_count;
        {
            const mpq_entry_s *entry =
                &archive->mpq_entry[archive->mpq_map[cached_number].entry_index];
            TEST_CHECK(
                cached_seed ==
                ((0xa25af234u + (uint32_t)entry->offset) ^ (uint32_t)entry->unpacked_size)
            );
        }
        TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
        TEST_CHECK(clone->mpq_file != archive->mpq_file && clone->mpq_entry != archive->mpq_entry);
        for (uint32_t i = 0; i < clone->entry_count; ++i)
            TEST_CHECK(clone->mpq_file[i] == NULL);
        TEST_CHECK(libmpq__archive_close(clone) == 0);
        for (unsigned read = 0; read < 2; ++read) {
            TEST_CHECK(
                libmpq__patch_payload_read(
                    archive, number, name, output, sizeof(output), &transferred
                ) == 0
            );
            TEST_CHECK(
                transferred == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0
            );
            TEST_CHECK(
                archive->mpq_file[cached_number] == cached && cached->seed == cached_seed &&
                cached->seed_known && cached->open_count == cached_count
            );
        }
        TEST_CHECK(libmpq__reader_offsets_release(archive, cached_number) == 0);
        TEST_CHECK(archive->mpq_file[cached_number] == NULL);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, "update-fix-key-prefix-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_rename(update, name, "other\\reference.bin") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file(path, "update-fix-key-prefix-reference.mpq"));
    TEST_CHECK(remove(path) == 0 && remove("update-fix-key-prefix-reference.mpq") == 0);
    return 0;
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
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_THREE;
         ++version) {
        TEST_CHECK(test_generic_add(version, 0, 1) == 0);
        TEST_CHECK(test_generic_add(version, 1, 1) == 0);
    }
    TEST_CHECK(test_generic_add(LIBMPQ_ARCHIVE_VERSION_THREE, 0, 0) == 0);
    TEST_CHECK(test_generic_add(LIBMPQ_ARCHIVE_VERSION_THREE, 1, 0) == 0);
    TEST_CHECK(test_v3_reconstruction(0) == 0);
    TEST_CHECK(test_v3_reconstruction(1) == 0);
    TEST_CHECK(test_v3_metadata_rollback() == 0);
    TEST_CHECK(test_v3_normalized_update(0) == 0);
    TEST_CHECK(test_v3_normalized_update(1) == 0);
    TEST_CHECK(test_compact_fix_key_update(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_compact_fix_key_update(LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    TEST_CHECK(test_fix_key_patch_prefix(0) == 0);
    TEST_CHECK(test_fix_key_patch_prefix(1) == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_THREE;
         ++version) {
        for (int mpqe = 0; mpqe < 2; ++mpqe) {
            for (int embedded = 0; embedded < 2; ++embedded) {
                for (unsigned flags = 0; flags < 4; ++flags) {
                    uint32_t storage = LIBMPQ_FILE_FLAG_ENCRYPTED;
                    storage |= (flags & 1) != 0 ? 0x00020000u : 0;
                    storage |=
                        (flags & 2) != 0 ? LIBMPQ_FILE_FLAG_SINGLE : LIBMPQ_FILE_FLAG_COMPRESS;
                    TEST_CHECK(
                        test_directory_encrypted_updates(version, mpqe, embedded, storage) == 0
                    );
                }
            }
        }
    }
    TEST_CHECK(test_v3_retained_operations() == 0);
    for (unsigned variant = 0; variant < 5; ++variant)
        TEST_CHECK(test_v3_list_names(variant) == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_THREE;
         ++version)
        for (int mpqe = 0; mpqe < 2; ++mpqe)
            for (int commit = 0; commit < 2; ++commit) {
                TEST_CHECK(test_adoption_failure(UPDATE_FAULT_FLUSH, commit, mpqe, version) == 0);
                TEST_CHECK(test_adoption_failure(UPDATE_FAULT_CLOSE, commit, mpqe, version) == 0);
            }
    TEST_CHECK(test_add_dense(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_add_dense(LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    return 0;
}
