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
#include "mpq-bit.h"
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
#include <zlib.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

static const uint8_t auth_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";

#define UPDATE_CHECK(condition)                           \
    do {                                                  \
        if (!(condition)) {                               \
            test_failure(__FILE__, __LINE__, #condition); \
            goto fail;                                    \
        }                                                 \
    } while (0)

static int
check_named(mpq_archive_s *archive, const char *name, const uint8_t *expected, size_t size);

static int test_v4_source_layout(const char *path, unsigned layout);

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
    *bytes = NULL;
    *size = 0;
    return test_read_path(path, bytes, size);
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
    if (version >= LIBMPQ_ARCHIVE_VERSION_3)
        storage.flags |= LIBMPQ_FILE_FLAG_KEY;
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
    const char *invalid_names[] = { NULL, "" };
    for (size_t i = 0; i < sizeof(invalid_names) / sizeof(invalid_names[0]); ++i) {
        const char *name = invalid_names[i];
        TEST_CHECK(libmpq__update_add_data(update, name, payload, 1, NULL) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(
            libmpq__update_add_path(update, name, "update-add-input.bin", NULL) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(libmpq__update_rename(update, "folder/secret", name) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(
            libmpq__update_rename_identity(update, "folder/secret", name, 0, 0) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(libmpq__update_change_identity(update, name, 0, 0, 1, 0) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(
            libmpq__update_replace_data(update, name, payload, 1, NULL) == LIBMPQ_ERROR_EXIST
        );
    }
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
    for (uint32_t i = 0; version >= LIBMPQ_ARCHIVE_VERSION_3 && i < archive->files; ++i) {
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
    uint32_t capacity;
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
    capacity = archive->mpq_header.hash_table_count;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version >= LIBMPQ_ARCHIVE_VERSION_3) {
        TEST_CHECK(copy_file(path, "update-dense-reference.mpq") == 0);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        for (uint32_t i = 2; i < capacity; ++i) {
            char name[32];
            (void)snprintf(name, sizeof(name), "fill-%u", i);
            TEST_CHECK(
                libmpq__update_add_data(update, name, (const uint8_t *)"fill", 4, NULL) == 0
            );
        }
        TEST_CHECK(
            libmpq__update_add_data(update, "overflow", (const uint8_t *)"new", 3, NULL) ==
            LIBMPQ_ERROR_SIZE
        );
        TEST_CHECK(libmpq__update_abort(update) == 0);
        TEST_CHECK(same_file(path, "update-dense-reference.mpq"));
        TEST_CHECK(remove("update-dense-reference.mpq") == 0);
    }
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
test_named_reconstruction(int complete, uint32_t version)
{
    const char *path = "update-v3-bet-only.mpq";
    mpq_archive_create_options_s create = { version, 8, 512, 0, 0 };
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
    TEST_CHECK(
        (version == LIBMPQ_ARCHIVE_VERSION_4 ? test_v4_source_layout(path, 2)
                                             : strip_classic_tables(path)) == 0
    );
    TEST_CHECK(copy_file(path, "update-v3-bet-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_remove(update, "known") == 0);
    TEST_CHECK(libmpq__update_add_data(update, "new", (const uint8_t *)"new", 3, NULL) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(check_named(archive, "unknown", (const uint8_t *)"unknown", 7) == 0);
    TEST_CHECK(check_named(archive, "new", (const uint8_t *)"new", 3) == 0);
    TEST_CHECK(libmpq__archive_files(archive, &count) == 0 && count == (complete ? 3u : 2u));
    TEST_CHECK(archive->mpq_header.version == version);
    TEST_CHECK(
        archive->mpq_header.block_table_count ==
        (complete ? archive->mpq_bet.header.entry_count : 0)
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove("update-v3-bet-reference.mpq") == 0);
    return 0;
}

/* Retained codec/cipher bytes and timestamps survive; signatures and failed publication do not. */
static int
test_v3_metadata_rollback(void)
{
    const char *path = "update-v3-metadata.mpq";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_LZMA, LIBMPQ_COMPRESSION_LZMA, 0, 0 };
    mpq_update_ops_s ops = { fflush, fclose, fail_publish, malloc };
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
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 16, 512,
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
            options.flags |= LIBMPQ_FILE_FLAG_KEY;
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
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 8, 512, 0, 0 };
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
    if (variant == 0 || variant == 2) {
        TEST_CHECK(
            libmpq__update_add_data(update, "added", (const uint8_t *)"third", 5, NULL) == 0
        );
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(check_named(archive, "folder\\name", (const uint8_t *)"first", 5) == 0);
        TEST_CHECK(check_named(archive, "other", (const uint8_t *)"second", 6) == 0);
        TEST_CHECK(check_named(archive, "added", (const uint8_t *)"third", 5) == 0);
        TEST_CHECK(
            archive->mpq_header.block_table_count ==
            (variant == 0 ? archive->mpq_bet.header.entry_count : 0)
        );
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
    mpq_update_ops_s ops = { fflush, fclose, fail_publish, malloc };
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
        libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc });
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
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_KEY,
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
    uint8_t decoded[1600] = { 0 };
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
    if (archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_2)
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
    if (archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_2 &&
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
    if (archive->mpq_header.version >= LIBMPQ_ARCHIVE_VERSION_3) {
        mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        mpq_bet_entry_s record;
        uint64_t het_offset = libmpq__load_le64(header + 60);
        uint64_t bet_offset = libmpq__load_le64(header + 52);
        uint64_t hash_offset =
            libmpq__load_le32(header + 16) | ((uint64_t)libmpq__load_le16(header + 40) << 32);
        TEST_CHECK(
            libmpq__load_le32(header + 4) == archive->mpq_header.header_size &&
            libmpq__load_le16(header + 12) == archive->mpq_header.version
        );
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
    if ((flags & LIBMPQ_FILE_FLAG_KEY) != 0)
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
        uint32_t table_size = (sectors + 1 + ((flags & LIBMPQ_FILE_FLAG_SECTOR_CRC) != 0)) * 4;
        TEST_CHECK(table_size <= packed_size);
        TEST_CHECK(libmpq__crypto_decrypt_block(packed, table_size, key - 1) == 0);
        TEST_CHECK(libmpq__load_le32(packed) == table_size);
        TEST_CHECK(libmpq__load_le32(packed + sectors * 4) <= packed_size);
        if ((flags & LIBMPQ_FILE_FLAG_SECTOR_CRC) == 0)
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
                                       LIBMPQ_FILE_FLAG_KEY,
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
    if (embedded)
        TEST_CHECK(prepend_update_archive(path, mpqe) == 0);
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
                (flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY)) ==
                (storage_flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY))
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
test_compact_key_update(uint32_t version)
{
    const char *path = "update-compact-key.mpq";
    const char *name = "folder\\reference.bin";
    uint8_t wire[108] = { 0 };
    uint32_t header_size = version == LIBMPQ_ARCHIVE_VERSION_1 ? 32 : 44;
    uint32_t end = header_size + 48;
    uint32_t hashes[3];
    uint8_t payload[16];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_file_options_s storage = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0, 0
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
    libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc });
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

/* A patch prefix is plaintext; KEY uses the member start and reconstructed size. */
static int
test_key_patch_prefix(int single)
{
    const char *path = "update-key-prefix.mpq";
    const char *name = "folder\\reference.bin";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 4, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0, 0
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
            LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0, 0
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
    TEST_CHECK(copy_file(path, "update-key-prefix-reference.mpq") == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_rename(update, name, "other\\reference.bin") == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file(path, "update-key-prefix-reference.mpq"));
    TEST_CHECK(remove(path) == 0 && remove("update-key-prefix-reference.mpq") == 0);
    return 0;
}

/* Change only explicit table presence, retaining writer-produced stored bytes. */
static int
test_v4_source_layout(const char *path, unsigned layout)
{
    mpq_archive_s *archive = NULL;
    uint8_t wire[208];
    mpq_md5_s md5;
    FILE *file;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    if (layout == 1) {
        archive->mpq_header_v3.het_table_offset = archive->mpq_header_v3.bet_table_offset = 0;
        archive->mpq_header_v4.het_table_size = archive->mpq_header_v4.bet_table_size = 0;
        memset(archive->mpq_header_v4.het_table_md5, 0, 16);
        memset(archive->mpq_header_v4.bet_table_md5, 0, 16);
    } else if (layout == 2) {
        archive->mpq_header.hash_table_offset = archive->mpq_header.block_table_offset = 0;
        archive->mpq_header.hash_table_count = archive->mpq_header.block_table_count = 0;
        archive->mpq_header_ex.hash_table_offset_high =
            archive->mpq_header_ex.block_table_offset_high = 0;
        archive->mpq_header_v4.hash_table_size = archive->mpq_header_v4.block_table_size = 0;
        memset(archive->mpq_header_v4.hash_table_md5, 0, 16);
        memset(archive->mpq_header_v4.block_table_md5, 0, 16);
    } else if (layout == 3) {
        uint8_t high[32] = { 0 };
        uint32_t bytes = archive->mpq_header.block_table_count * 2;
        TEST_CHECK(bytes <= sizeof(high));
        archive->mpq_header_ex.extended_offset = archive->mpq_header_v3.archive_size;
        archive->mpq_header_v4.hi_block_table_size = bytes;
        archive->mpq_header_v3.archive_size += bytes;
        archive->mpq_header.archive_size = (uint32_t)archive->mpq_header_v3.archive_size;
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, high, bytes);
        libmpq__md5_final(&md5, archive->mpq_header_v4.hi_block_table_md5);
        file = libmpq__file_open(path, "ab");
        TEST_CHECK(file != NULL && fwrite(high, 1, bytes, file) == bytes && fclose(file) == 0);
    }
    TEST_CHECK(
        libmpq__header_v4_full_encode(
            &archive->mpq_header, &archive->mpq_header_ex, &archive->mpq_header_v3,
            &archive->mpq_header_v4, wire, sizeof(wire)
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, wire, 192);
    libmpq__md5_final(&md5, wire + 192);
    file = libmpq__file_open(path, "r+b");
    TEST_CHECK(
        file != NULL && fwrite(wire, 1, sizeof(wire), file) == sizeof(wire) && fclose(file) == 0
    );
    return 0;
}

/* Preserve raw policy and exact contents across rebuilds, aborts and publication failures. */
static int
test_v4_updates(uint32_t chunk, unsigned layout, int mpqe)
{
    mpq_archive_create_options_s create = {
        LIBMPQ_ARCHIVE_VERSION_4, 16, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
        layout == 2 ? 0
                    : LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME |
                          LIBMPQ_ATTRIBUTE_PATCH_BIT
    };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[1280];
    uint8_t big[32769];
    uint8_t header[208];
    uint8_t expected[16];
    uint8_t cipher[16];
    char path[512];
    char plain[512];
    char snapshot[512];
    const char *name = "folder/reference.bin";
    uint64_t old_offset;
    uint32_t number;
    uint32_t mask;
    mpq_update_ops_s ops = { fflush, fclose, fail_publish, malloc };
    TEST_CHECK(test_temp_path(plain, sizeof(plain), "v4-update-source") == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "v4-update") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "v4-update-before") == 0);
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i % 251);
    memset(big, 'B', sizeof(big));
    TEST_CHECK(libmpq__writer_archive_create_v4(&archive, plain, NULL, &create, chunk) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "padding", big, sizeof(big), NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, name, payload, sizeof(payload), &storage) == 0);
    if (create.attributes != 0)
        archive->write_attributes[1].filetime = UINT64_C(0xfedcba9876543210);
    TEST_CHECK(libmpq__archive_add_data(archive, "empty", NULL, 0, NULL) == 0);
    if (layout == 0 && !mpqe && chunk == 17) {
        uint8_t key[512];
        test_strong_signature_private_key(key);
        TEST_CHECK(libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, key, sizeof(key)) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_v4_source_layout(plain, layout) == 0);
    if (mpqe) {
        uint8_t key[64];
        FILE *input = libmpq__file_open(plain, "rb");
        FILE *output = libmpq__file_open(path, "wb");
        TEST_CHECK(input != NULL && output != NULL);
        TEST_CHECK(libmpq__mpqe_key(key, auth_code, sizeof(auth_code) - 1) == 0);
        TEST_CHECK(libmpq__writer_mpqe_transform_file(input, output, key) == 0);
        libmpq__mpqe_clear(key, sizeof(key));
        TEST_CHECK(fclose(input) == 0 && fclose(output) == 0);
    } else
        TEST_CHECK(copy_file(plain, path) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_add_data(update, "aborted", payload, sizeof(payload), NULL) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(
        (mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
              : libmpq__archive_open(&archive, path, 0)) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    old_offset = archive->mpq_entry[archive->mpq_map[number].entry_index].offset;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_remove(update, "padding") == 0);
    TEST_CHECK(libmpq__update_add_data(update, "added", big, sizeof(big), NULL) == 0);
    TEST_CHECK(libmpq__update_add_data(update, "ADDED", NULL, 0, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_replace_data(update, "absent", NULL, 0, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_rename(update, name, "other/reference.bin") == 0);
    TEST_CHECK(libmpq__update_rename(update, "other/reference.bin", "other/renamed.bin") == 0);
    TEST_CHECK(libmpq__update_remove(update, "added") == 0);
    TEST_CHECK(libmpq__update_add_data(update, "added", payload, sizeof(payload), NULL) == 0);
    TEST_CHECK(libmpq__update_replace_path(update, "added", plain, NULL) == 0);
    TEST_CHECK(libmpq__update_replace_data(update, "added", (const uint8_t *)"abc", 3, NULL) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
              : libmpq__archive_open(&archive, path, 0)) == 0
    );
    TEST_CHECK(
        archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_4 &&
        archive->mpq_header.header_size == 208 && archive->mpq_header_v4.raw_chunk_size == chunk
    );
    {
        uint32_t configured;
        TEST_CHECK(
            libmpq__archive_raw_chunk_size_get(archive, &configured) == 0 && configured == chunk
        );
        TEST_CHECK(
            libmpq__archive_raw_chunk_size_set(archive, chunk ^ 1) == LIBMPQ_ERROR_NOT_INITIALIZED
        );
    }
    TEST_CHECK(archive->het_data != NULL && archive->bet_data != NULL);
    TEST_CHECK(libmpq__archive_signatures(archive, &mask) == 0 && mask == 0);
    TEST_CHECK(check_named(archive, "other/renamed.bin", payload, sizeof(payload)) == 0);
    TEST_CHECK(check_named(archive, "added", (const uint8_t *)"abc", 3) == 0);
    TEST_CHECK(
        libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) ==
        (chunk != 0 ? 0 : LIBMPQ_ERROR_EXIST)
    );
    TEST_CHECK(
        libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) ==
        (chunk != 0 ? 0 : LIBMPQ_ERROR_EXIST)
    );
    TEST_CHECK(libmpq__file_number(archive, "padding", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "other/renamed.bin", &number) == 0);
    if (create.attributes != 0) {
        mpq_file_attributes_s attributes;
        TEST_CHECK(
            libmpq__file_attributes(archive, number, &attributes) == 0 &&
            attributes.filetime == UINT64_C(0xfedcba9876543210)
        );
    }
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "other/renamed.bin") == 0);
    TEST_CHECK(
        libmpq__file_verify(
            archive, number,
            create.attributes != 0 ? LIBMPQ_VERIFY_ALL
                                   : LIBMPQ_VERIFY_RAW_MD5 | LIBMPQ_VERIFY_SECTOR_CRC,
            &mask
        ) == 0 &&
        mask == 0
    );
    if (create.attributes == 0)
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mask) == LIBMPQ_ERROR_EXIST
        );
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);

    TEST_CHECK(
        (archive->mpq_entry[archive->mpq_map[number].entry_index].flags & storage.flags) ==
        storage.flags
    );
    TEST_CHECK(archive->mpq_entry[archive->mpq_map[number].entry_index].offset != old_offset);

    /* Fixed basename hash is independently known; inspect ciphertext at the serialized offset. */
    TEST_CHECK(
        check_serialized_member_key(
            archive, "other/renamed.bin", 0xc74b33e7u, payload, sizeof(payload)
        ) == 0
    );
    TEST_CHECK(libmpq__source_read_at(archive->source, 0, header, sizeof(header)) == 0);
    TEST_CHECK(libmpq__load_le32(header + 4) == 208 && libmpq__load_le16(header + 12) == 3);
    for (uint32_t i = 0; i < archive->files; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        uint64_t end = entry->offset + entry->packed_size;
        if (chunk && entry->packed_size)
            end += ((entry->packed_size - 1) / chunk + 1) * 16;
        TEST_CHECK(end <= archive->mpq_header_v3.het_table_offset);
        TEST_CHECK(entry->classic_source_index == entry->bet_source_index);
        TEST_CHECK(libmpq__file_verify(archive, i, LIBMPQ_VERIFY_RAW_MD5, &mask) == 0 && mask == 0);
    }
    TEST_CHECK(libmpq__file_number(archive, "added", &number) == 0);
    if (chunk >= 3) {
        static const uint8_t abc_md5[16] = { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                                             0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 };
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(libmpq__source_read_at(archive->source, entry->offset + 3, cipher, 16) == 0);
        memcpy(expected, abc_md5, 16);
        TEST_CHECK(memcmp(expected, cipher, 16) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
              : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_replace_data(update, "added", payload, sizeof(payload), NULL) == 0);
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(plain) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Retain ADPCM, mixed masks and large single units without changing their packed codecs. */
static int
test_v4_preserved_packed(uint32_t chunk, uint32_t encryption, unsigned kind)
{
    mpq_archive_create_options_s create = {
        LIBMPQ_ARCHIVE_VERSION_4, 8, kind == 2 ? 65536 : 4096,
        LIBMPQ_ARCHIVE_CREATE_LISTFILE | LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
        LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5
    };
    mpq_file_options_s storage = {
        encryption | (kind == 2 ? LIBMPQ_FILE_FLAG_SINGLE
                                : LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC),
        LIBMPQ_COMPRESSION_ZLIB,
        kind == 0 ? LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_WAVE_MONO
                  : LIBMPQ_COMPRESSION_SPARSE | LIBMPQ_COMPRESSION_ZLIB,
        0, 0
    };
    const char *name = "folder/reference.bin";
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_update_ops_s ops = { fflush, fclose, fail_publish, malloc };
    mpq_entry_s before;
    mpq_entry_s after;
    uint8_t input[32771];
    uint8_t *decoded;
    uint8_t *packed;
    uint8_t *actual;
    size_t decoded_size;
    size_t input_size = kind == 0 ? 12844 : kind == 1 ? 8212 : sizeof(input);
    uint32_t number;
    uint32_t mask;
    uint32_t original_mismatches;
    mpq_file_attributes_s original_attributes;
    uint32_t offsets[8];
    uint32_t count;
    uint32_t random = 0x12345678;
    char path[512];
    char snapshot[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "v4-retained-packed") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "v4-packed-original") == 0);
    for (size_t i = 0; i < sizeof(input); ++i) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        input[i] = kind == 2                    ? (uint8_t)random
                   : i >= 8192 || (i / 128) % 4 ? 0
                                                : (uint8_t)(i * 13 + i / 127);
    }
    if (kind == 0) {
        memset(input, 0, 44);
        memcpy(input, "RIFF", 4);
        libmpq__store_le32(input + 4, (uint32_t)input_size - 8);
        memcpy(input + 8, "WAVEfmt ", 8);
        libmpq__store_le32(input + 16, 16);
        libmpq__store_le16(input + 20, 1);
        libmpq__store_le16(input + 22, 1);
        libmpq__store_le32(input + 24, 22050);
        libmpq__store_le32(input + 28, 44100);
        libmpq__store_le16(input + 32, 2);
        libmpq__store_le16(input + 34, 16);
        memcpy(input + 36, "data", 4);
        libmpq__store_le32(input + 40, (uint32_t)input_size - 44);
        for (size_t i = 0; i < 6400; ++i)
            libmpq__store_le16(input + 44 + i * 2, (uint16_t)(((int)(i % 101) - 50) * 317));
    }
    TEST_CHECK(libmpq__writer_archive_create_v4(&archive, path, NULL, &create, chunk) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "padding", input, 512, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, name, input, input_size, &storage) == 0);
    archive->write_attributes[1].filetime = UINT64_C(0x123456789abcdef0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    before = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, name) == 0);
    count = archive->mpq_file[number]->packed_offset_count;
    TEST_CHECK(count <= sizeof(offsets) / sizeof(offsets[0]));
    memcpy(offsets, archive->mpq_file[number]->packed_offset, count * sizeof(offsets[0]));
    if (kind != 2) {
        TEST_CHECK(libmpq__block_compression(archive, number, 0, &mask) == 0 && mask == 2);
        TEST_CHECK(
            libmpq__block_compression(archive, number, 1, &mask) == 0 &&
            mask == (kind == 0 ? 65 : 34)
        );
        if (kind == 1)
            TEST_CHECK(libmpq__block_compression(archive, number, 2, &mask) == 0 && mask == 32);
    }
    TEST_CHECK(libmpq__file_attributes(archive, number, &original_attributes) == 0);
    TEST_CHECK(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &original_mismatches) == 0);
    TEST_CHECK((original_mismatches & (LIBMPQ_VERIFY_RAW_MD5 | LIBMPQ_VERIFY_SECTOR_CRC)) == 0);
    if (kind == 0)
        TEST_CHECK((original_mismatches & LIBMPQ_VERIFY_FILE_MD5) != 0);
    else
        TEST_CHECK(original_mismatches == 0);
    TEST_CHECK(test_archive_read(archive, number, &decoded, &decoded_size) == 0);
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    packed = malloc((size_t)before.packed_size);
    actual = malloc((size_t)before.packed_size);
    TEST_CHECK(packed != NULL && actual != NULL);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, before.offset, packed, (size_t)before.packed_size
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_remove(update, "padding") == 0);
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, snapshot));
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_remove(update, "padding") == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_4);
    TEST_CHECK(archive->mpq_header_v4.raw_chunk_size == chunk);
    TEST_CHECK(check_named(archive, name, decoded, decoded_size) == 0);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    after = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        after.flags == before.flags && after.packed_size == before.packed_size &&
        after.unpacked_size == before.unpacked_size
    );
    if (chunk != 0)
        TEST_CHECK(after.offset != before.offset);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, name) == 0);
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mask) == 0 &&
        mask == original_mismatches
    );
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    {
        mpq_file_attributes_s attributes;
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.filetime == UINT64_C(0x123456789abcdef0));
        TEST_CHECK(
            attributes.flags == original_attributes.flags &&
            attributes.crc32 == original_attributes.crc32 &&
            memcmp(attributes.md5, original_attributes.md5, sizeof(attributes.md5)) == 0
        );
    }
    TEST_CHECK(
        libmpq__source_read_at(archive->source, after.offset, actual, (size_t)after.packed_size) ==
        0
    );
    if ((encryption & LIBMPQ_FILE_FLAG_KEY) != 0 && before.offset != after.offset) {
        uint32_t old_key = (0xa25af234u + (uint32_t)before.offset) ^ (uint32_t)before.unpacked_size;
        uint32_t new_key = (0xa25af234u + (uint32_t)after.offset) ^ (uint32_t)after.unpacked_size;
        uint32_t blocks = kind == 2 ? 1 : count - 1;
        if (kind != 2) {
            TEST_CHECK(libmpq__crypto_decrypt_block(packed, offsets[0], old_key - 1) == 0);
            TEST_CHECK(libmpq__crypto_encrypt_block(packed, offsets[0], new_key - 1) == 0);
        }
        for (uint32_t i = 0; i < blocks; ++i) {
            uint32_t size = offsets[i + 1] - offsets[i];
            TEST_CHECK(libmpq__crypto_decrypt_block(packed + offsets[i], size, old_key + i) == 0);
            TEST_CHECK(libmpq__crypto_encrypt_block(packed + offsets[i], size, new_key + i) == 0);
        }
    }
    TEST_CHECK(memcmp(packed, actual, (size_t)after.packed_size) == 0);
    TEST_CHECK(
        libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) ==
        (chunk ? 0 : LIBMPQ_ERROR_EXIST)
    );
    TEST_CHECK(
        libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) ==
        (chunk ? 0 : LIBMPQ_ERROR_EXIST)
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(decoded);
    free(packed);
    free(actual);
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Reject damaged raw digests and BET-only classic attributes without changing the source. */
static int
test_v4_rejected_source(int corrupt)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_4, 8, 512,
                                             LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             LIBMPQ_ATTRIBUTE_PATCH_BIT };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char snapshot[512];
    uint64_t digest;
    uint32_t number;
    TEST_CHECK(test_temp_path(path, sizeof(path), "v4-reject-source") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "v4-reject-before") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "keep", (const uint8_t *)"abc", 3, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (!corrupt)
        TEST_CHECK(test_v4_source_layout(path, 2) == 0);
    if (corrupt) {
        FILE *file;
        int value;
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(libmpq__file_number(archive, "keep", &number) == 0);
        digest = archive->mpq_entry[archive->mpq_map[number].entry_index].offset + 3;
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        file = libmpq__file_open(path, "r+b");
        TEST_CHECK(file != NULL && libmpq__file_seek(file, (libmpq__off_t)digest, SEEK_SET) == 0);
        value = fgetc(file);
        TEST_CHECK(value != EOF && libmpq__file_seek(file, (libmpq__off_t)digest, SEEK_SET) == 0);
        TEST_CHECK(fputc(value ^ 1, file) != EOF && fclose(file) == 0);
    }
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_add_data(update, "added", (const uint8_t *)"new", 3, NULL) ==
        (corrupt ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Unnamed ciphertext keeps its offset and probe identity while known names change. */
static int
test_unknown_members(uint32_t version, unsigned layout, uint32_t chunk, int mpqe)
{
    const char *opaque[] = { "lost/sector.bin", "lost/single.bin", "lost/empty" };
    mpq_archive_create_options_s create = { version, 16, 512, 0,
                                            layout == 2 ? 0 : LIBMPQ_ATTRIBUTES_ALL & 7 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_update_ops_s ops = { fflush, fclose, fail_publish, malloc };
    mpq_entry_s entries[3];
    mpq_hash_s hashes[32];
    uint8_t payload[9007];
    uint8_t *before;
    size_t before_size;
    char plain[512];
    char path[512];
    char snapshot[512];
    uint32_t number;
    uint32_t mask;
    uint32_t hash_count;
    TEST_CHECK(test_temp_path(plain, sizeof(plain), "unknown-source") == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "unknown-update") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "unknown-snapshot") == 0);
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i * 13 + i / 127);
    TEST_CHECK(
        (version == LIBMPQ_ARCHIVE_VERSION_4
             ? libmpq__writer_archive_create_v4(&archive, plain, NULL, &create, chunk)
             : libmpq__archive_create(&archive, plain, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "target", (const uint8_t *)"old", 3, NULL) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, opaque[0], payload, sizeof(payload), &storage) == 0
    );
    if (create.attributes != 0)
        archive->write_attributes[1].filetime = UINT64_C(0xfedcba9876543210);
    storage = (mpq_file_options_s){ LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0,
                                    layout == 2 ? 0 : 0x409, layout == 2 ? 0 : 1 };
    TEST_CHECK(libmpq__archive_add_data(archive, opaque[1], payload, 37, &storage) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, opaque[2], NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(test_v4_source_layout(plain, layout) == 0);
    else if (layout == 2)
        TEST_CHECK(strip_classic_tables(plain) == 0);
    else if (layout == 1) {
        FILE *file = libmpq__file_open(plain, "r+b");
        uint8_t absent[16] = { 0 };
        TEST_CHECK(file != NULL && libmpq__file_seek(file, 52, SEEK_SET) == 0);
        TEST_CHECK(fwrite(absent, 1, sizeof(absent), file) == sizeof(absent) && fclose(file) == 0);
    }
    TEST_CHECK(read_bytes(plain, &before, &before_size) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, plain, 0) == 0);
    hash_count = archive->mpq_header.hash_table_count;
    TEST_CHECK(hash_count <= sizeof(hashes) / sizeof(hashes[0]));
    if (hash_count != 0)
        memcpy(hashes, archive->mpq_hash, hash_count * sizeof(*hashes));
    for (unsigned i = 0; i < 3; ++i) {
        TEST_CHECK(libmpq__file_number(archive, opaque[i], &number) == 0);
        entries[i] = archive->mpq_entry[archive->mpq_map[number].entry_index];
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (mpqe) {
        uint8_t key[64];
        FILE *input = libmpq__file_open(plain, "rb");
        FILE *output = libmpq__file_open(path, "wb");
        TEST_CHECK(input != NULL && output != NULL);
        TEST_CHECK(libmpq__mpqe_key(key, auth_code, sizeof(auth_code) - 1) == 0);
        TEST_CHECK(libmpq__writer_mpqe_transform_file(input, output, key) == 0);
        libmpq__mpqe_clear(key, sizeof(key));
        TEST_CHECK(fclose(input) == 0 && fclose(output) == 0);
    } else
        TEST_CHECK(copy_file(plain, path) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    for (unsigned operation = 0; operation < 9; ++operation) {
        TEST_CHECK(
            (mpqe ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                  : libmpq__update_begin(&update, path)) == 0
        );
        if (operation == 0) {
            TEST_CHECK(libmpq__update_commit(update) == 0 && same_file(path, snapshot));
            continue;
        }
        if (operation == 1)
            TEST_CHECK(libmpq__update_replace_data(update, "target", payload, 31, NULL) == 0);
        else if (operation == 2)
            TEST_CHECK(libmpq__update_add_data(update, "added", payload, 9, NULL) == 0);
        else if (operation == 3)
            TEST_CHECK(libmpq__update_rename(update, "target", "renamed") == 0);
        else if (operation == 4)
            TEST_CHECK(libmpq__update_remove(update, "renamed") == 0);
        else if (operation == 5) {
            TEST_CHECK(libmpq__update_remove(update, "added") == 0);
            TEST_CHECK(libmpq__update_add_data(update, "added", payload, 19, NULL) == 0);
        } else
            TEST_CHECK(libmpq__update_add_data(update, "transient", payload, 7, NULL) == 0);
        if (operation == 6) {
            TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
            continue;
        }
        if (operation == 7) {
            libmpq__update_set_ops(update, &ops);
            TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
            TEST_CHECK(same_file(path, snapshot));
            continue;
        }
        if (operation == 8) {
            TEST_CHECK(
                libmpq__update_add_data(update, "transient", payload, 7, NULL) == LIBMPQ_ERROR_EXIST
            );
            TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
            continue;
        }
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            (mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
                  : libmpq__archive_open(&archive, path, 0)) == 0
        );
        TEST_CHECK(archive->mpq_header.version == version);
        TEST_CHECK(archive->mpq_header_v4.raw_chunk_size == chunk);
        TEST_CHECK((archive->het_data != NULL) == (layout != 1));
        TEST_CHECK(archive->mpq_header.hash_table_count == hash_count);
        TEST_CHECK(
            libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == LIBMPQ_ERROR_EXIST
        );
        if (operation == 1)
            TEST_CHECK(check_named(archive, "target", payload, 31) == 0);
        if (operation == 3) {
            TEST_CHECK(check_named(archive, "renamed", payload, 31) == 0);
            TEST_CHECK(libmpq__file_number(archive, "target", &number) == LIBMPQ_ERROR_EXIST);
        }
        if (operation >= 4)
            TEST_CHECK(libmpq__file_number(archive, "renamed", &number) == LIBMPQ_ERROR_EXIST);
        if (operation == 2 || operation == 5)
            TEST_CHECK(check_named(archive, "added", payload, operation == 2 ? 9 : 19) == 0);
        for (unsigned i = 0; i < 3; ++i) {
            mpq_entry_s *entry;
            uint8_t stored[9007];
            mpq_file_attributes_s attributes;
            TEST_CHECK(libmpq__file_number(archive, opaque[i], &number) == 0);
            entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
            TEST_CHECK(entry->offset == entries[i].offset && entry->flags == entries[i].flags);
            TEST_CHECK(
                entry->packed_size == entries[i].packed_size &&
                entry->unpacked_size == entries[i].unpacked_size &&
                entry->source_mask == entries[i].source_mask
            );
            TEST_CHECK(
                entry->packed_size <= sizeof(stored) && entry->offset <= before_size &&
                entry->packed_size <= before_size - entry->offset
            );
            TEST_CHECK(
                libmpq__source_read_at(
                    archive->source, entry->offset, stored, (size_t)entry->packed_size
                ) == 0
            );
            TEST_CHECK(
                memcmp(stored, before + (size_t)entry->offset, (size_t)entry->packed_size) == 0
            );
            TEST_CHECK(
                check_named(
                    archive, opaque[i], payload,
                    i == 0   ? sizeof(payload)
                    : i == 1 ? 37
                             : 0
                ) == 0
            );
            TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, opaque[i]) == 0);
            TEST_CHECK(
                libmpq__file_verify(
                    archive, number,
                    layout == 2 ? LIBMPQ_VERIFY_RAW_MD5 | LIBMPQ_VERIFY_SECTOR_CRC
                                : LIBMPQ_VERIFY_ALL,
                    &mask
                ) == 0 &&
                mask == 0
            );
            libmpq__reader_offsets_release(archive, number);
            if (i == 0 && create.attributes != 0) {
                TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
                TEST_CHECK(attributes.filetime == UINT64_C(0xfedcba9876543210));
            }
            for (uint32_t slot = 0; slot < hash_count; ++slot)
                if (hashes[slot].block_table_index == entries[i].classic_source_index) {
                    const mpq_hash_s *hash = &archive->mpq_hash[slot];
                    TEST_CHECK(
                        hash->hash_a == hashes[slot].hash_a && hash->hash_b == hashes[slot].hash_b
                    );
                    TEST_CHECK(
                        hash->locale == hashes[slot].locale &&
                        hash->platform == hashes[slot].platform
                    );
                    TEST_CHECK(hash->block_table_index == entry->classic_source_index);
                }
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(copy_file(path, snapshot) == 0);
    }
    if (!mpqe && chunk != 0) {
        for (unsigned digest = 0; digest < 2; ++digest) {
            uint64_t position = entries[0].offset + (digest ? entries[0].packed_size : 0);
            FILE *file = libmpq__file_open(path, "r+b");
            int value;
            TEST_CHECK(
                file != NULL && libmpq__file_seek(file, (libmpq__off_t)position, SEEK_SET) == 0
            );
            value = fgetc(file);
            TEST_CHECK(
                value != EOF && libmpq__file_seek(file, (libmpq__off_t)position, SEEK_SET) == 0
            );
            TEST_CHECK(fputc(value ^ 1, file) != EOF && fclose(file) == 0);
            TEST_CHECK(copy_file(path, snapshot) == 0);
            TEST_CHECK(libmpq__update_begin(&update, path) == 0);
            TEST_CHECK(
                libmpq__update_add_data(update, "transient", payload, 7, NULL) == LIBMPQ_ERROR_READ
            );
            TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
        }
    }
    free(before);
    TEST_CHECK(remove(plain) == 0 && remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Reduced or ambiguous identities cannot be promoted into complete filename hashes. */
static int
test_unknown_identity_limits(void)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_4, 4, 512, 0, 0 };
    mpq_archive_s *source = NULL;
    mpq_archive_s *writer = NULL;
    mpq_entry_s *entry;
    uint32_t saved;
    char path[512];
    char output[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "unknown-limits") == 0);
    TEST_CHECK(test_temp_path(output, sizeof(output), "unknown-output") == 0);
    TEST_CHECK(libmpq__archive_create(&source, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(source, "known", (const uint8_t *)"known", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(source) == 0);
    TEST_CHECK(libmpq__archive_open(&source, path, 0) == 0);
    TEST_CHECK(libmpq__archive_create(&writer, output, &create) == 0);
    saved = source->mpq_het.header.name_hash_bit_size;
    source->mpq_het.header.name_hash_bit_size = 63;
    TEST_CHECK(libmpq__writer_identity_init(writer, source) == LIBMPQ_ERROR_FORMAT);
    source->mpq_het.header.name_hash_bit_size = saved;
    source->mpq_bet.header.name_hash2_extra = 1;
    TEST_CHECK(libmpq__writer_identity_init(writer, source) == LIBMPQ_ERROR_FORMAT);
    source->mpq_bet.header.name_hash2_extra = 0;
    source->mpq_het.header.index_size_extra = 1;
    TEST_CHECK(libmpq__writer_identity_init(writer, source) == LIBMPQ_ERROR_FORMAT);
    source->mpq_het.header.index_size_extra = 0;
    entry = &source->mpq_entry[source->mpq_map[0].entry_index];
    saved = entry->source_mask;
    entry->source_mask = LIBMPQ_ENTRY_SOURCE_BET;
    TEST_CHECK(libmpq__writer_identity_init(writer, source) == LIBMPQ_ERROR_FORMAT);
    entry->source_mask = saved;
    TEST_CHECK(libmpq__writer_identity_init(writer, source) == 0);
    TEST_CHECK(libmpq__writer_preserve_member(writer, source, 0, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(writer->write_error == 0);
    libmpq__writer_identity_free(writer);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__archive_close(source) == 0);
    TEST_CHECK(remove(path) == 0 && remove(output) == 0);
    return 0;
}

/* A hash identity outside the candidate's probe chain must not be overwritten. */
static int
test_unknown_collision(void)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 8, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t wire[16 * 16];
    uint8_t absent[16] = { 0 };
    char candidate[32];
    char path[512];
    char snapshot[512];
    uint32_t hashes[3];
    uint32_t number;
    uint32_t slot;
    uint32_t row;
    uint32_t position;
    FILE *file;
    TEST_CHECK(test_temp_path(path, sizeof(path), "unknown-collision") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "unknown-collision-before") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "hidden", (const uint8_t *)"hidden", 6, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    file = libmpq__file_open(path, "r+b");
    TEST_CHECK(file != NULL && libmpq__file_seek(file, 52, SEEK_SET) == 0);
    TEST_CHECK(fwrite(absent, 1, sizeof(absent), file) == sizeof(absent) && fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "hidden", &number) == 0);
    row = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    for (slot = 0; slot < 16; ++slot)
        if (archive->mpq_hash[slot].block_table_index == row)
            break;
    TEST_CHECK(slot < 16);
    for (unsigned i = 0;; ++i) {
        (void)snprintf(candidate, sizeof(candidate), "candidate-%u", i);
        libmpq__file_hash(candidate, &hashes[0], &hashes[1], &hashes[2]);
        if ((hashes[0] & 15) != slot)
            break;
    }
    archive->mpq_hash[slot].hash_a = hashes[1];
    archive->mpq_hash[slot].hash_b = hashes[2];
    for (uint32_t i = 0; i < 16; ++i) {
        const mpq_hash_s *hash = &archive->mpq_hash[i];
        libmpq__store_le32(wire + i * 16, hash->hash_a);
        libmpq__store_le32(wire + i * 16 + 4, hash->hash_b);
        libmpq__store_le16(wire + i * 16 + 8, hash->locale);
        libmpq__store_le16(wire + i * 16 + 10, hash->platform);
        libmpq__store_le32(wire + i * 16 + 12, hash->block_table_index);
    }
    position = archive->mpq_header.hash_table_offset;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            wire, sizeof(wire), libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    file = libmpq__file_open(path, "r+b");
    TEST_CHECK(file != NULL && libmpq__file_seek(file, position, SEEK_SET) == 0);
    TEST_CHECK(fwrite(wire, 1, sizeof(wire), file) == sizeof(wire) && fclose(file) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, candidate, &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_add_data(update, candidate, (const uint8_t *)"new", 3, NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Fixed HashString vectors independently generated for a wrapping 16-slot chain. */
static const uint32_t alias_hashes[4][3] = {
    { 0x5c7e8976u, 0xd46af3efu, 0xba4a7e14u }, /* known: target at slot 6. */
    { 0x77f5926eu, 0x7fa7b98cu, 0xb5274c2eu }, /* chain-32: retained ciphertext. */
    { 0xbe6676ceu, 0xcbc3a0f3u, 0x2f5cc301u }, /* chain-43: inserted member. */
    { 0xd844b7beu, 0xed7285e7u, 0x9894e0b7u }  /* Independent retained alias. */
};

/* Change synthetic classic identities, refreshing stored-byte/header MD5 for v4. */
static int
test_alias_table_write_count(
    const char *path, const mpq_hash_s *hashes, uint32_t count, int unsupported
)
{
    mpq_archive_s *archive = NULL;
    uint8_t *bytes = NULL;
    size_t size;
    uint32_t position;
    uint32_t block_position;
    uint32_t block_size;
    uint32_t version;
    uint32_t hash_size;
    mpq_md5_s md5;
    int32_t status;
    UPDATE_CHECK(read_bytes(path, &bytes, &size) == 0);
    UPDATE_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    UPDATE_CHECK(count <= UINT32_MAX / 16);
    UPDATE_CHECK(archive->mpq_header.hash_table_count == count);
    hash_size = count * 16;
    position = archive->mpq_header.hash_table_offset;
    block_position = archive->mpq_header.block_table_offset;
    block_size = archive->mpq_header.block_table_count * 16;
    version = archive->mpq_header.version;
    status = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(status == 0);
    UPDATE_CHECK(position <= size && hash_size <= size - position);
    for (uint32_t i = 0; i < count; ++i) {
        uint8_t *wire = bytes + position + i * 16;
        libmpq__store_le32(wire, hashes[i].hash_a);
        libmpq__store_le32(wire + 4, hashes[i].hash_b);
        libmpq__store_le16(wire + 8, hashes[i].locale);
        libmpq__store_le16(wire + 10, hashes[i].platform);
        libmpq__store_le32(wire + 12, hashes[i].block_table_index);
    }
    UPDATE_CHECK(
        libmpq__crypto_encrypt_block(
            bytes + position, hash_size, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    if (unsupported) {
        uint8_t *wire = bytes + block_position;
        uint32_t key = libmpq__crypto_hash_string("(block table)", 0x300);
        UPDATE_CHECK(
            block_position <= size && block_size <= size - block_position && block_size >= 32
        );
        UPDATE_CHECK(libmpq__crypto_decrypt_block(wire, block_size, key) == 0);
        libmpq__store_le32(wire + 28, libmpq__load_le32(wire + 28) | 1u);
        UPDATE_CHECK(libmpq__crypto_encrypt_block(wire, block_size, key) == 0);
    }
    if (version == LIBMPQ_ARCHIVE_VERSION_4) {
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, bytes + position, hash_size);
        libmpq__md5_final(&md5, bytes + 128);
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, bytes + block_position, block_size);
        libmpq__md5_final(&md5, bytes + 112);
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, bytes, 192);
        libmpq__md5_final(&md5, bytes + 192);
    }
    UPDATE_CHECK(write_bytes(path, bytes, size) == 0);
    free(bytes);
    return 0;
fail:
    free(bytes);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    return 1;
}

/* Keep the compact alias builders on their established sixteen-slot layout. */
static int
test_alias_table_write(const char *path, const mpq_hash_s hashes[16], int unsupported)
{
    return test_alias_table_write_count(path, hashes, 16, unsupported);
}

/* Inspect serialized aliases, not just the default filename lookup result. */
static int
test_alias_table_check(const char *path, const mpq_hash_s expected[16])
{
    mpq_archive_s *archive = NULL;
    uint8_t wire[256];
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.hash_table_count == 16);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, archive->mpq_header.hash_table_offset, wire, sizeof(wire)
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_decrypt_block(
            wire, sizeof(wire), libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    for (uint32_t i = 0; i < 16; ++i) {
        TEST_CHECK(libmpq__load_le32(wire + i * 16) == expected[i].hash_a);
        TEST_CHECK(libmpq__load_le32(wire + i * 16 + 4) == expected[i].hash_b);
        TEST_CHECK(libmpq__load_le16(wire + i * 16 + 8) == expected[i].locale);
        TEST_CHECK(libmpq__load_le16(wire + i * 16 + 10) == expected[i].platform);
        TEST_CHECK(libmpq__load_le32(wire + i * 16 + 12) == expected[i].block_table_index);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Read the selected variant rather than the ordinary first-hit name. */
static int
check_exact_contents(
    mpq_archive_s *archive, const char *name, uint16_t locale, uint16_t platform,
    const uint8_t *expected, size_t length
)
{
    mpq_stream_s *stream = NULL;
    uint8_t actual[2048];
    libmpq__off_t received;
    TEST_CHECK(length <= sizeof(actual));
    TEST_CHECK(libmpq__stream_open_name_identity(archive, name, locale, platform, &stream) == 0);
    TEST_CHECK(libmpq__stream_read(stream, actual, sizeof(actual), &received) == 0);
    TEST_CHECK(
        received == (libmpq__off_t)length && (length == 0 || memcmp(actual, expected, length) == 0)
    );
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    return 0;
}

/* Compare every ordinary hash row and packed member across a qualifier-only rebuild. */
static int
test_change_identity_stage(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform, uint16_t new_locale,
    uint16_t new_platform
)
{
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    mpq_hash_s hashes[256];
    mpq_entry_s entries[16] = { 0 };
    mpq_file_attributes_s attributes[16] = { 0 };
    int32_t attribute_status[16] = { 0 };
    uint8_t special[16] = { 0 };
    uint8_t packed[16][2048] = { { 0 } };
    uint8_t logical[2048];
    uint8_t wire[4096];
    uint32_t rows[256];
    uint32_t count;
    uint32_t files;
    uint32_t expected_files;
    uint32_t number;
    uint32_t slot = UINT32_MAX;
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    uint32_t version;
    uint32_t raw_size;
    libmpq__off_t length;
    libmpq__off_t received;
    static const char *const metadata[] = { "(listfile)", "(attributes)", "(signature)" };
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    count = archive->mpq_header.hash_table_count;
    files = expected_files = archive->files;
    version = archive->mpq_header.version;
    TEST_CHECK(count != 0 && count <= 256 && files <= 16);
    TEST_CHECK(libmpq__archive_raw_chunk_size_get(archive, &raw_size) == 0);
    memcpy(hashes, archive->mpq_hash, count * sizeof(*hashes));
    for (uint32_t i = 0; i < 3; ++i)
        if (libmpq__file_number(archive, metadata[i], &number) == 0) {
            special[number] = 1;
            if (i == 2)
                --expected_files;
        }
    if (expected_files == files && libmpq__file_number(archive, "(listfile)", &number) == 0)
        special[number] = 0;
    for (uint32_t i = 0; i < files; ++i) {
        entries[i] = archive->mpq_entry[archive->mpq_map[i].entry_index];
        if (special[i])
            continue;
        TEST_CHECK(entries[i].packed_size <= sizeof(packed[i]));
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, (uint64_t)archive->archive_offset + entries[i].offset, packed[i],
                (size_t)entries[i].packed_size
            ) == 0
        );
        attribute_status[i] = libmpq__file_attributes(archive, i, &attributes[i]);
        TEST_CHECK(attribute_status[i] == 0 || attribute_status[i] == LIBMPQ_ERROR_EXIST);
    }
    libmpq__file_hash(name, &hash1, &hash2, &hash3);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t index;
        rows[i] = UINT32_MAX;
        if (hashes[i].block_table_index >= LIBMPQ_HASH_DELETED)
            continue;
        TEST_CHECK(
            libmpq__entry_index_from_classic(archive, hashes[i].block_table_index, &index) == 0
        );
        number = archive->mpq_entry[index].file_number;
        TEST_CHECK(number < files);
        if (!special[number])
            rows[i] = number;
        if (hashes[i].hash_a == hash2 && hashes[i].hash_b == hash3 && hashes[i].locale == locale &&
            hashes[i].platform == platform) {
            TEST_CHECK(slot == UINT32_MAX);
            slot = i;
        }
    }
    TEST_CHECK(slot != UINT32_MAX);
    TEST_CHECK(libmpq__stream_open_name_identity(archive, name, locale, platform, &stream) == 0);
    TEST_CHECK(libmpq__stream_size(stream, &length) == 0);
    TEST_CHECK(length >= 0 && (uint64_t)length <= sizeof(logical));
    TEST_CHECK(libmpq__stream_read(stream, logical, sizeof(logical), &received) == 0);
    TEST_CHECK(received == length);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        libmpq__update_change_identity(update, name, locale, platform, new_locale, new_platform) ==
        0
    );
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(archive->files == expected_files && archive->mpq_header.version == version);
    TEST_CHECK(archive->mpq_header.hash_table_count == count);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source,
            (uint64_t)archive->archive_offset + archive->mpq_header.hash_table_offset, wire,
            count * 16
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_decrypt_block(
            wire, count * 16, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t index;
        mpq_file_attributes_s actual;
        uint8_t bytes[2048];
        const mpq_entry_s *entry;
        const uint8_t *row = wire + i * 16;
        uint32_t old = rows[i];
        uint32_t mismatches;
        if (old == UINT32_MAX)
            continue;
        TEST_CHECK(old < files && !special[old]);
        TEST_CHECK(libmpq__load_le32(row) == hashes[i].hash_a);
        TEST_CHECK(libmpq__load_le32(row + 4) == hashes[i].hash_b);
        TEST_CHECK(libmpq__load_le16(row + 8) == (i == slot ? new_locale : hashes[i].locale));
        TEST_CHECK(libmpq__load_le16(row + 10) == (i == slot ? new_platform : hashes[i].platform));
        TEST_CHECK(
            libmpq__entry_index_from_classic(archive, libmpq__load_le32(row + 12), &index) == 0
        );
        entry = &archive->mpq_entry[index];
        TEST_CHECK(entry->offset == entries[old].offset);
        TEST_CHECK(entry->packed_size == entries[old].packed_size);
        TEST_CHECK(entry->unpacked_size == entries[old].unpacked_size);
        TEST_CHECK(entry->flags == entries[old].flags);
        TEST_CHECK(entry->source_mask == entries[old].source_mask);
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, (uint64_t)archive->archive_offset + entry->offset, bytes,
                (size_t)entry->packed_size
            ) == 0
        );
        TEST_CHECK(memcmp(bytes, packed[old], (size_t)entry->packed_size) == 0);
        TEST_CHECK(
            libmpq__file_attributes(archive, entry->file_number, &actual) == attribute_status[old]
        );
        if (attribute_status[old] == 0) {
            TEST_CHECK(actual.flags == attributes[old].flags);
            TEST_CHECK(actual.filetime == attributes[old].filetime);
            TEST_CHECK(actual.crc32 == attributes[old].crc32);
            TEST_CHECK(actual.patch_bit == attributes[old].patch_bit);
            TEST_CHECK(memcmp(actual.md5, attributes[old].md5, 16) == 0);
        }
        TEST_CHECK(
            libmpq__file_verify(archive, entry->file_number, LIBMPQ_VERIFY_RAW_MD5, &mismatches) ==
                0 &&
            mismatches == 0
        );
    }
    TEST_CHECK(
        libmpq__file_number_from_identity(archive, name, locale, platform, &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        check_exact_contents(archive, name, new_locale, new_platform, logical, (size_t)length) == 0
    );
    TEST_CHECK(libmpq__archive_raw_chunk_size_get(archive, &number) == 0 && number == raw_size);
    if (version == LIBMPQ_ARCHIVE_VERSION_4 && archive->het_data != NULL) {
        int32_t expected = raw_size != 0 ? 0 : LIBMPQ_ERROR_EXIST;
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) == expected);
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) == expected);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Persist tuple changes across every generation, compression layout and MPQE publication. */
static int
test_change_identity_updates(uint32_t version, uint32_t raw_size, uint8_t single, int wrapped)
{
    mpq_archive_create_options_s create = { version, 8, single ? 4096 : 512,
                                            single ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_COMPRESS |
                                       LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_update_ops_s failing = { fflush, fclose, fail_publish, malloc };
    mpq_archive_s *archive = NULL;
    mpq_writer_s *member = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char snapshot[512];
    char stage[512];
    uint8_t payload[1507];
    uint32_t number;
    uint32_t mismatch;
    mpq_file_attributes_s attributes;
    options.flags |= single ? LIBMPQ_FILE_FLAG_SINGLE : LIBMPQ_FILE_FLAG_SECTOR_CRC;
    test_payload(payload, sizeof(payload), 19);
    TEST_CHECK(test_temp_path(path, sizeof(path), "change-identity") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "change-identity-original") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "change-identity-stage") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, raw_size) == 0);
    TEST_CHECK(libmpq__writer_begin(archive, "voice.bin", sizeof(payload), &options, &member) == 0);
    TEST_CHECK(libmpq__writer_timestamp(member, 91) == 0);
    TEST_CHECK(libmpq__writer_write(member, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__writer_finish(member) == 0);
    if (single) {
        static const uint8_t list[] = "voice.bin\n(attributes)\n";
        TEST_CHECK(
            libmpq__writer_begin(archive, "(listfile)", sizeof(list) - 1, &options, &member) == 0
        );
        TEST_CHECK(libmpq__writer_timestamp(member, 92) == 0);
        TEST_CHECK(libmpq__writer_write(member, list, sizeof(list) - 1) == 0);
        TEST_CHECK(libmpq__writer_finish(member) == 0);
    }

    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "voice.bin", 0, 0, 0, 0) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_change_identity(update, "(listfile)", 0, 0, 0, 0) == 0);
    TEST_CHECK(
        libmpq__update_change_identity(update, "(listfile)", 0, 0, 1, 0) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_change_identity(update, NULL, 0, 0, 0, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));

    TEST_CHECK(
        libmpq__update_change_identity(update, "voice.bin", 1, 0, 1, 0) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__update_change_identity(update, "missing", 0, 0, 0, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(test_change_identity_stage(update, "voice.bin", 0, 0, 0x409, 0) == 0);
    TEST_CHECK(test_change_identity_stage(update, "voice.bin", 0x409, 0, 0x409, 2) == 0);
    TEST_CHECK(
        test_change_identity_stage(update, "voice.bin", 0x409, 2, UINT16_MAX, UINT16_MAX) == 0
    );
    TEST_CHECK(test_change_identity_stage(update, "voice.bin", UINT16_MAX, UINT16_MAX, 0, 0) == 0);
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(test_change_identity_stage(update, "voice.bin", 0, 0, 0x409, 2) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, 0)) == 0
    );
    TEST_CHECK(check_exact_contents(archive, "voice.bin", 0x409, 2, payload, sizeof(payload)) == 0);
    TEST_CHECK(
        libmpq__file_number_from_identity(archive, "voice.bin", 0, 0, &number) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__file_number_from_identity(archive, "voice.bin", 0x409, 2, &number) == 0);
    TEST_CHECK(
        libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 91
    );
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "voice.bin") == 0);
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mismatch) == 0 && mismatch == 0
    );
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(test_change_identity_stage(update, "voice.bin", 0x409, 2, 0, 0) == 0);
    libmpq__update_set_ops(update, &failing);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0 && remove(stage) == 0);
    return 0;
}

/* Signature placeholders test invalidation policy, not cryptographic trust. */
static int
test_change_identity_signature(uint32_t version)
{
    mpq_archive_create_options_s create = { version, 8, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t placeholder[72] = { 0 };
    uint8_t list[256] = { 0 };
    char path[512];
    char snapshot[512];
    uint32_t number;
    libmpq__off_t size;
    libmpq__off_t received;
    TEST_CHECK(test_temp_path(path, sizeof(path), "change-identity-signature") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "change-identity-signature-source") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "voice", (const uint8_t *)"payload", 7, NULL) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, "(signature)", placeholder, sizeof(placeholder), NULL) ==
        0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "voice", 0, 0, 0, 0) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(test_change_identity_stage(update, "voice", 0, 0, 0x409, 1) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "(signature)", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == 0);
    TEST_CHECK(size >= 0 && (uint64_t)size < sizeof(list));
    TEST_CHECK(libmpq__file_read(archive, number, list, size, &received) == 0 && received == size);
    TEST_CHECK(strstr((const char *)list, "(signature)") == NULL);
    TEST_CHECK(
        check_exact_contents(archive, "voice", 0x409, 1, (const uint8_t *)"payload", 7) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Independent HashString vectors: all three filenames start at slot 255 of 256. */
static const char *const exact_alias_names[5] = { "alias-70\\voice.bin", "alias-70\\voice.bin",
                                                  "alias-465\\voice.bin", "alias-618\\voice.bin",
                                                  "alias-70\\voice.bin" };
static const uint16_t exact_alias_locales[5] = { 0, 0x409, 0, 0x411, 0x412 };
static const uint16_t exact_alias_platforms[5] = { 0, 1, 0, 2, 3 };
static const uint32_t exact_alias_hashes[3][3] = { { 0x7af660ffu, 0x1bb4969du, 0x5db143f0u },
                                                   { 0x41bee0ffu, 0x30a1241fu, 0x3a325ffcu },
                                                   { 0xdc119bffu, 0xb557ef8cu, 0xe5b48603u } };

static int test_compact_embed(
    const char *path, unsigned form, int wrapped, uint8_t prefix[4096], uint64_t *origin
);
static int test_compact_prefix(
    mpq_archive_s *archive, unsigned form, const uint8_t *expected, uint64_t origin
);

typedef struct
{
    mpq_hash_s hashes[256];
    uint32_t slots[5];
    mpq_entry_s entry;
    mpq_entry_s other;
    mpq_file_attributes_s attributes;
    mpq_file_attributes_s other_attributes;
    uint32_t other_slot;
    uint8_t packed[773];
    uint8_t plaintext[773];
    uint32_t version;
    uint32_t raw_size;
    uint64_t origin;
    unsigned form;
    uint8_t prefix[4096];
} exact_alias_snapshot_s;

/* Check final KEY ciphertext directly, separately from named stream decoding. */
static int
test_exact_ciphertext(
    const char *path, const char *name, uint16_t locale, uint16_t platform, const uint8_t *expected,
    size_t size, uint32_t basename_key, uint64_t original_offset
)
{
    mpq_archive_s *archive = NULL;
    const mpq_entry_s *entry;
    mpq_file_attributes_s attributes;
    uint8_t bytes[773];
    uint32_t number;
    uint32_t key;
    uint32_t mismatches;
    TEST_CHECK(size <= sizeof(bytes));
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number_from_identity(archive, name, locale, platform, &number) == 0);
    entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(entry->offset != original_offset && entry->packed_size == size);
    TEST_CHECK(entry->unpacked_size == size);
    TEST_CHECK(
        entry->flags == (LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE |
                         LIBMPQ_FILE_FLAG_KEY)
    );
    key = (basename_key + (uint32_t)entry->offset) ^ (uint32_t)size;
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, (uint64_t)archive->archive_offset + entry->offset, bytes, size
        ) == 0
    );
    TEST_CHECK(memcmp(bytes, expected, size) != 0);
    TEST_CHECK(libmpq__crypto_decrypt_block(bytes, (uint32_t)size, key) == 0);
    TEST_CHECK(memcmp(bytes, expected, size) == 0);
    TEST_CHECK(check_exact_contents(archive, name, locale, platform, expected, size) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(attributes.filetime == 77);
    TEST_CHECK(
        attributes.flags ==
        (LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME)
    );
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, name) == 0);
    TEST_CHECK(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mismatches) == 0);
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Inspect retained hash slots, remapped rows, attributes and pinned bytes after each stage. */
static int
test_exact_cross_check(
    const char *path, const exact_alias_snapshot_s *original, uint32_t retained, int mixed
)
{
    mpq_archive_s *archive = NULL;
    uint8_t wire[4096];
    uint8_t packed[773];
    uint32_t shared_number = UINT32_MAX;
    uint64_t payload_end = 0;
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(
        test_compact_prefix(archive, original->form, original->prefix, original->origin) == 0
    );
    TEST_CHECK(archive->mpq_header.hash_table_count == 256);
    TEST_CHECK(archive->mpq_header.version == original->version);
    TEST_CHECK((archive->het_data != NULL) == mixed);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source,
            (uint64_t)archive->archive_offset + archive->mpq_header.hash_table_offset, wire,
            sizeof(wire)
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_decrypt_block(
            wire, sizeof(wire), libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    TEST_CHECK(libmpq__load_le32(wire + 255 * 16 + 12) == LIBMPQ_HASH_DELETED);
    for (uint32_t i = 0; i < 5; ++i) {
        uint32_t number;
        uint32_t mismatch;
        const mpq_entry_s *entry;
        const mpq_hash_s *hash = &original->hashes[original->slots[i]];
        const uint8_t *stored = wire + original->slots[i] * 16;
        mpq_file_attributes_s attributes;
        if ((retained & (1u << i)) == 0)
            continue;
        TEST_CHECK(
            libmpq__file_number_from_identity(
                archive, exact_alias_names[i], exact_alias_locales[i], exact_alias_platforms[i],
                &number
            ) == 0
        );
        if (shared_number == UINT32_MAX)
            shared_number = number;
        TEST_CHECK(number == shared_number);
        entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(entry->classic_source_index != original->entry.classic_source_index);
        TEST_CHECK(libmpq__load_le32(stored) == hash->hash_a);
        TEST_CHECK(libmpq__load_le32(stored + 4) == hash->hash_b);
        TEST_CHECK(libmpq__load_le16(stored + 8) == hash->locale);
        TEST_CHECK(libmpq__load_le16(stored + 10) == hash->platform);
        TEST_CHECK(libmpq__load_le32(stored + 12) == entry->classic_source_index);
        TEST_CHECK(entry->source_mask == original->entry.source_mask);
        TEST_CHECK(entry->offset == original->entry.offset);
        TEST_CHECK(entry->packed_size == original->entry.packed_size);
        TEST_CHECK(entry->unpacked_size == original->entry.unpacked_size);
        TEST_CHECK(entry->flags == original->entry.flags);
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, (uint64_t)archive->archive_offset + entry->offset, packed,
                sizeof(packed)
            ) == 0
        );
        TEST_CHECK(memcmp(packed, original->packed, sizeof(packed)) == 0);
        TEST_CHECK(
            check_exact_contents(
                archive, exact_alias_names[i], exact_alias_locales[i], exact_alias_platforms[i],
                original->plaintext, sizeof(original->plaintext)
            ) == 0
        );
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.flags == original->attributes.flags);
        TEST_CHECK(attributes.filetime == original->attributes.filetime);
        TEST_CHECK(attributes.crc32 == original->attributes.crc32);
        TEST_CHECK(attributes.patch_bit == original->attributes.patch_bit);
        TEST_CHECK(memcmp(attributes.md5, original->attributes.md5, 16) == 0);
        TEST_CHECK(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &mismatch) == 0);
        TEST_CHECK(mismatch == 0);
    }
    TEST_CHECK(check_exact_contents(archive, "other", 0, 0, (const uint8_t *)"other", 5) == 0);
    {
        uint32_t number;
        mpq_file_attributes_s attributes;
        const mpq_entry_s *entry;
        const mpq_hash_s *hash = &original->hashes[original->other_slot];
        const uint8_t *stored = wire + original->other_slot * 16;
        TEST_CHECK(libmpq__file_number_from_identity(archive, "other", 0, 0, &number) == 0);
        entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(entry->offset == original->other.offset);
        TEST_CHECK(entry->packed_size == original->other.packed_size);
        TEST_CHECK(entry->unpacked_size == original->other.unpacked_size);
        TEST_CHECK(entry->flags == original->other.flags);
        TEST_CHECK(libmpq__load_le32(stored) == hash->hash_a);
        TEST_CHECK(libmpq__load_le32(stored + 4) == hash->hash_b);
        TEST_CHECK(libmpq__load_le16(stored + 8) == hash->locale);
        TEST_CHECK(libmpq__load_le16(stored + 10) == hash->platform);
        TEST_CHECK(libmpq__load_le32(stored + 12) == entry->classic_source_index);
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.flags == original->other_attributes.flags);
        TEST_CHECK(attributes.filetime == original->other_attributes.filetime);
        TEST_CHECK(attributes.crc32 == original->other_attributes.crc32);
        TEST_CHECK(attributes.patch_bit == original->other_attributes.patch_bit);
        TEST_CHECK(memcmp(attributes.md5, original->other_attributes.md5, 16) == 0);
    }
    {
        uint8_t list[512] = { 0 };
        uint32_t number;
        libmpq__off_t size;
        libmpq__off_t received;
        TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == 0);
        TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == 0);
        TEST_CHECK(size >= 0 && (uint64_t)size < sizeof(list));
        TEST_CHECK(libmpq__file_read(archive, number, list, size, &received) == 0);
        TEST_CHECK(received == size);
        TEST_CHECK(strstr((const char *)list, exact_alias_names[3]) == NULL);
        TEST_CHECK(
            (strstr((const char *)list, exact_alias_names[2]) != NULL) ==
            ((retained & (1u << 2)) != 0)
        );
        TEST_CHECK(
            (strstr((const char *)list, exact_alias_names[0]) != NULL) ==
            ((retained & ((1u << 0) | (1u << 1) | (1u << 4))) != 0)
        );
    }

    if (original->version < LIBMPQ_ARCHIVE_VERSION_3) {
        for (uint32_t i = 0; i < archive->files; ++i) {
            const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
            uint64_t end = entry->offset + entry->packed_size;
            if (end > payload_end)
                payload_end = end;
        }
        TEST_CHECK(archive->mpq_header.hash_table_offset >= payload_end);
        TEST_CHECK(
            archive->mpq_header.block_table_offset >=
            (uint64_t)archive->mpq_header.hash_table_offset + sizeof(wire)
        );
        if (original->version == LIBMPQ_ARCHIVE_VERSION_2)
            TEST_CHECK(
                archive->mpq_header_ex.extended_offset >=
                (uint64_t)archive->mpq_header.block_table_offset +
                    (uint64_t)archive->mpq_header.block_table_count * 16
            );
    }
    if (original->version == LIBMPQ_ARCHIVE_VERSION_4) {
        uint32_t raw_size;
        int32_t available = mixed && original->raw_size != 0 ? 0 : LIBMPQ_ERROR_EXIST;
        TEST_CHECK(libmpq__archive_raw_chunk_size_get(archive, &raw_size) == 0);
        TEST_CHECK(raw_size == original->raw_size);
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) == available);
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) == available);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Cross-filename aliases stay pinned through repeated exact operations and failed publication. */
static int
test_exact_cross_names(uint32_t version, uint32_t raw_size, int mixed, unsigned form)
{
    mpq_archive_create_options_s create = { version, 128, 1024, 0,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s options = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0, 0
    };
    mpq_update_ops_s failing = { fflush, fclose, fail_publish, malloc };
    exact_alias_snapshot_s original = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_writer_s *member = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char snapshot[512];
    char staged[512];
    static const uint8_t list[] = "drop\nalias-70\\voice.bin\nalias-465\\voice.bin\nother\n";
    static const uint8_t replacement[] = "replacement";
    uint32_t number;
    uint32_t source_block;
    uint32_t slot;
    uint32_t retained = 31;
    TEST_CHECK(test_temp_path(path, sizeof(path), "exact-cross-name") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "exact-cross-original") == 0);
    TEST_CHECK(test_temp_path(staged, sizeof(staged), "exact-cross-stage") == 0);
    test_payload(original.plaintext, sizeof(original.plaintext), 39);
    original.version = version;
    original.raw_size = raw_size;
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, raw_size) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "drop", (const uint8_t *)"drop", 4, NULL) == 0);
    TEST_CHECK(
        libmpq__writer_begin(
            archive, exact_alias_names[0], sizeof(original.plaintext), &options, &member
        ) == 0
    );
    TEST_CHECK(libmpq__writer_timestamp(member, 77) == 0);
    TEST_CHECK(libmpq__writer_write(member, original.plaintext, sizeof(original.plaintext)) == 0);
    TEST_CHECK(libmpq__writer_finish(member) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"other", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "(listfile)", list, sizeof(list) - 1, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (!mixed && version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(test_v4_source_layout(path, 1) == 0);
    else if (!mixed && version == LIBMPQ_ARCHIVE_VERSION_3) {
        uint8_t empty[16] = { 0 };
        FILE *file = libmpq__file_open(path, "r+b");
        TEST_CHECK(file != NULL);
        TEST_CHECK(libmpq__file_seek(file, 52, SEEK_SET) == 0);
        TEST_CHECK(fwrite(empty, 1, sizeof(empty), file) == sizeof(empty));
        TEST_CHECK(fclose(file) == 0);
    }
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(archive->mpq_header.hash_table_count == 256);
    TEST_CHECK(libmpq__file_number(archive, exact_alias_names[0], &number) == 0);
    original.entry = archive->mpq_entry[archive->mpq_map[number].entry_index];
    source_block = original.entry.classic_source_index;
    TEST_CHECK(source_block == 1 && original.entry.packed_size == sizeof(original.packed));
    TEST_CHECK(libmpq__file_attributes(archive, number, &original.attributes) == 0);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, original.entry.offset, original.packed, sizeof(original.packed)
        ) == 0
    );
    memcpy(original.hashes, archive->mpq_hash, sizeof(original.hashes));
    TEST_CHECK(libmpq__file_number(archive, "other", &number) == 0);
    original.other = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(libmpq__file_attributes(archive, number, &original.other_attributes) == 0);
    original.other_slot = UINT32_MAX;
    for (uint32_t i = 0; i < 256; ++i)
        if (original.hashes[i].block_table_index == original.other.classic_source_index)
            original.other_slot = i;
    TEST_CHECK(original.other_slot < 256);

    TEST_CHECK(original.hashes[255].block_table_index == source_block);
    original.hashes[255] = (mpq_hash_s){ 0, 0, 0, 0, LIBMPQ_HASH_DELETED };
    slot = 0;
    for (uint32_t i = 0; i < 5; ++i) {
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t vector = i == 2 ? 1 : i == 3 ? 2 : 0;
        libmpq__file_hash(exact_alias_names[i], &a, &b, &c);
        TEST_CHECK(a == exact_alias_hashes[vector][0]);
        TEST_CHECK(b == exact_alias_hashes[vector][1] && c == exact_alias_hashes[vector][2]);
        while (original.hashes[slot].block_table_index != LIBMPQ_HASH_FREE)
            slot = (slot + 1) % 256;
        original.slots[i] = slot;
        original.hashes[slot] =
            (mpq_hash_s){ b, c, exact_alias_locales[i], exact_alias_platforms[i], source_block };
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_alias_table_write_count(path, original.hashes, 256, 0) == 0);
    original.form = form;
    TEST_CHECK(test_compact_embed(path, form, 0, original.prefix, &original.origin) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "drop", 0, 0) == 0);
    TEST_CHECK(
        test_exact_cross_check(libmpq__update_path(update), &original, retained, mixed) == 0
    );
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(copy_file(libmpq__update_path(update), staged) == 0);
    if (!mixed) {
        TEST_CHECK(
            libmpq__update_change_identity(update, exact_alias_names[1], 0x409, 1, 0, 0) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
        TEST_CHECK(
            test_change_identity_stage(update, exact_alias_names[1], 0x409, 1, 0x409, 9) == 0
        );
        TEST_CHECK(
            test_change_identity_stage(update, exact_alias_names[1], 0x409, 9, UINT16_MAX, 9) == 0
        );
        TEST_CHECK(
            test_change_identity_stage(update, exact_alias_names[1], UINT16_MAX, 9, 0x409, 1) == 0
        );
        TEST_CHECK(
            test_exact_cross_check(libmpq__update_path(update), &original, retained, 0) == 0
        );
    } else {
        TEST_CHECK(
            libmpq__update_change_identity(update, exact_alias_names[1], 0x409, 1, 0x409, 1) == 0
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
        TEST_CHECK(
            libmpq__update_change_identity(update, exact_alias_names[1], 0x409, 1, 0x407, 1) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
        TEST_CHECK(
            libmpq__update_change_identity(update, exact_alias_names[2], 0, 0, 1, 0) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
    }
    const mpq_update_replace_range_s range = { 2, replacement, 3 };
    TEST_CHECK(copy_file(libmpq__update_path(update), staged) == 0);
    TEST_CHECK(
        libmpq__update_replace_ranges(update, exact_alias_names[0], &range, 1) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(same_file(libmpq__update_path(update), staged));
    if (mixed) {
        TEST_CHECK(
            libmpq__update_replace_ranges_identity(
                update, exact_alias_names[1], 0x409, 1, &range, 1
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
    } else {
        uint8_t edited[sizeof(original.plaintext)];
        memcpy(edited, original.plaintext, sizeof(edited));
        memcpy(edited + range.offset, range.data, range.size);
        TEST_CHECK(
            libmpq__update_replace_ranges_identity(
                update, exact_alias_names[1], 0x409, 1, &range, 1
            ) == 0
        );
        TEST_CHECK(
            test_exact_cross_check(
                libmpq__update_path(update), &original, retained & ~(1u << 1), 0
            ) == 0
        );
        TEST_CHECK(
            test_exact_ciphertext(
                libmpq__update_path(update), exact_alias_names[1], 0x409, 1, edited, sizeof(edited),
                0x0be448fdu, original.entry.offset
            ) == 0
        );
    }
    if (mixed) {
        TEST_CHECK(
            libmpq__update_replace_data_identity(
                update, exact_alias_names[0], 0x409, 1, replacement, sizeof(replacement) - 1, NULL
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
        TEST_CHECK(
            libmpq__update_remove_identity(update, exact_alias_names[0], 0, 0) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
        TEST_CHECK(
            libmpq__update_rename_identity(update, exact_alias_names[2], "renamed/new.bin", 0, 0) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
    } else {
        options.locale = 0x409;
        options.platform = 1;
        TEST_CHECK(
            libmpq__update_replace_data_identity(
                update, exact_alias_names[1], 0x409, 1, replacement, sizeof(replacement) - 1,
                &options
            ) == 0
        );
        TEST_CHECK(
            test_change_identity_stage(update, exact_alias_names[1], 0x409, 1, 0x409, 7) == 0
        );
        TEST_CHECK(
            test_change_identity_stage(update, exact_alias_names[1], 0x409, 7, 0x409, 1) == 0
        );
        retained &= ~(1u << 1);
        TEST_CHECK(
            test_exact_cross_check(libmpq__update_path(update), &original, retained, 0) == 0
        );
        TEST_CHECK(
            test_exact_ciphertext(
                libmpq__update_path(update), exact_alias_names[1], 0x409, 1, replacement,
                sizeof(replacement) - 1, 0x0be448fdu, original.entry.offset
            ) == 0
        );
        TEST_CHECK(
            libmpq__update_rename_identity(update, exact_alias_names[2], "renamed/new.bin", 0, 0) ==
            0
        );
        TEST_CHECK(test_change_identity_stage(update, "renamed/new.bin", 0, 0, 7, 2) == 0);
        TEST_CHECK(test_change_identity_stage(update, "renamed/new.bin", 7, 2, 0, 0) == 0);
        retained &= ~(1u << 2);
        TEST_CHECK(
            test_exact_cross_check(libmpq__update_path(update), &original, retained, 0) == 0
        );
        TEST_CHECK(
            test_exact_ciphertext(
                libmpq__update_path(update), "renamed/new.bin", 0, 0, original.plaintext,
                sizeof(original.plaintext), 0xf7f647b2u, original.entry.offset
            ) == 0
        );
        TEST_CHECK(libmpq__update_remove_identity(update, exact_alias_names[0], 0, 0) == 0);
        TEST_CHECK(test_change_identity_stage(update, exact_alias_names[4], 0x412, 3, 0, 0) == 0);
        TEST_CHECK(test_change_identity_stage(update, exact_alias_names[4], 0, 0, 0x412, 3) == 0);
        retained &= ~1u;
        TEST_CHECK(
            test_exact_cross_check(libmpq__update_path(update), &original, retained, 0) == 0
        );
        TEST_CHECK(copy_file(libmpq__update_path(update), staged) == 0);
        TEST_CHECK(
            libmpq__update_rename_identity(update, "renamed/new.bin", "other", 0, 0) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
        TEST_CHECK(libmpq__update_remove_identity(update, exact_alias_names[1], 0x409, 1) == 0);
        TEST_CHECK(
            libmpq__update_rename_identity(update, "renamed/new.bin", "again/new.bin", 0, 0) == 0
        );
        TEST_CHECK(
            test_exact_cross_check(libmpq__update_path(update), &original, retained, 0) == 0
        );
    }
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(test_exact_cross_check(path, &original, retained, mixed) == 0);
    if (!mixed)
        TEST_CHECK(
            test_exact_ciphertext(
                path, "again/new.bin", 0, 0, original.plaintext, sizeof(original.plaintext),
                0xf7f647b2u, original.entry.offset
            ) == 0
        );
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    if (mixed)
        TEST_CHECK(
            libmpq__update_replace_data_identity(
                update, "other", 0, 0, replacement, sizeof(replacement) - 1, NULL
            ) == 0
        );
    else {
        TEST_CHECK(libmpq__update_remove_identity(update, exact_alias_names[4], 0x412, 3) == 0);
        TEST_CHECK(test_exact_cross_check(libmpq__update_path(update), &original, 1u << 3, 0) == 0);
    }
    libmpq__update_set_ops(update, &failing);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(test_exact_cross_check(path, &original, retained, mixed) == 0);
    if (!mixed) {
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        TEST_CHECK(libmpq__update_remove_identity(update, exact_alias_names[4], 0x412, 3) == 0);
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(test_exact_cross_check(path, &original, 1u << 3, 0) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, exact_alias_names[0], 0x412, 3, &number) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0 && remove(staged) == 0);
    return 0;
}

/* Reject duplicate sources and destination hashes hidden beyond a never-used slot. */
static int
test_change_identity_ambiguous(uint8_t unreachable)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_1, 8, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s hashes[16];
    char path[512];
    char snapshot[512];
    uint32_t number;
    uint32_t block;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    TEST_CHECK(test_temp_path(path, sizeof(path), "change-identity-ambiguous") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "change-identity-ambiguous-source") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"one", 3, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"two", 3, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    memcpy(hashes, archive->mpq_hash, sizeof(hashes));
    TEST_CHECK(libmpq__file_number(archive, "other", &number) == 0);
    block = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    for (uint32_t i = 0; i < 16; ++i)
        if (hashes[i].block_table_index == block)
            hashes[i] = (mpq_hash_s){ 0, 0, 0, 0, LIBMPQ_HASH_DELETED };
    libmpq__file_hash("voice", &h1, &h2, &h3);
    if (unreachable) {
        uint32_t gap = (h1 + 1) % 16;
        uint32_t hidden = (h1 + 4) % 16;
        hashes[gap] =
            (mpq_hash_s){ UINT32_MAX, UINT32_MAX, UINT16_MAX, UINT16_MAX, LIBMPQ_HASH_FREE };
        hashes[hidden] = (mpq_hash_s){ h2, h3, 1, 0, block };
    } else {
        for (uint32_t i = 1; i < 16; ++i) {
            uint32_t slot = (h1 + i) % 16;
            if (hashes[slot].block_table_index == LIBMPQ_HASH_FREE) {
                hashes[slot] = (mpq_hash_s){ h2, h3, 0, 0, block };
                break;
            }
        }
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_change_identity(update, "voice", 0, 0, 0, 0) ==
        (unreachable ? 0 : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(libmpq__update_change_identity(update, "voice", 0, 0, 1, 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Distinct payloads and a large original probe table survive repeated exact staging. */
static int
test_exact_distinct(uint32_t version)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_archive_create_options_s create = { version, 128, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s options = { 0 };
    mpq_file_identity_s identity;
    uint32_t number;
    TEST_CHECK(test_temp_path(path, sizeof(path), "exact-distinct") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "voice", (const uint8_t *)"neutral", 7, NULL) == 0
    );
    options.locale = 0x409;
    options.platform = 1;
    TEST_CHECK(
        libmpq__archive_add_data(archive, "voice", (const uint8_t *)"localized", 9, &options) == 0
    );
    options.platform = 2;
    TEST_CHECK(
        libmpq__archive_add_data(archive, "voice", (const uint8_t *)"platform", 8, &options) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "voice", 0x409, 1, (const uint8_t *)"x", (libmpq__off_t)UINT32_MAX + 1, NULL
        ) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "voice", 0x409, 1, (const uint8_t *)"new", 3, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__update_remove_identity(update, "voice", 0x409, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_rename_identity(update, "voice", "renamed", 0x409, 1) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "voice", 0x409, 1) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__update_replace_data_identity(update, "renamed", 0x409, 1, NULL, 0, NULL) == 0
    );
    TEST_CHECK(libmpq__update_remove_identity(update, "voice", 0x409, 2) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(check_exact_contents(archive, "voice", 0, 0, (const uint8_t *)"neutral", 7) == 0);
    TEST_CHECK(check_exact_contents(archive, "renamed", 0x409, 1, NULL, 0) == 0);
    TEST_CHECK(libmpq__file_identity(archive, "voice", 1, &identity) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__file_number_from_identity(archive, "voice", 0x409, 2, &number) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(archive->mpq_header.hash_table_count == 256);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Exact stages detach one classic alias while preserving packed payloads and attributes. */
static int
test_exact_updates(uint32_t version, uint32_t chunk, unsigned layout, uint8_t single, unsigned form)
{
    mpq_archive_create_options_s create = {
        version, 8, single ? 4096 : 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
        layout == 2 ? 0 : LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME
    };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_update_ops_s failing = { fflush, fclose, fail_publish, malloc };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_writer_s *member = NULL;
    mpq_hash_s hashes[16];
    mpq_file_attributes_s attributes;
    char path[512];
    char snapshot[512];
    char staged[512];
    char input[512];
    uint8_t original[1507];
    uint8_t packed[2048];
    uint8_t retained[2048];
    static const uint8_t replacement[] = "replacement bytes";
    uint64_t original_offset;
    size_t packed_size;
    uint16_t locale = layout == 0 || layout == 3 ? 0x409 : 0;
    uint16_t platform = locale != 0 ? 1 : 0;
    uint32_t number;
    uint32_t mismatch;
    uint32_t old_number;
    uint8_t encrypted = layout == 4;
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;

    TEST_CHECK(test_temp_path(path, sizeof(path), "exact-update") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "exact-update-original") == 0);
    TEST_CHECK(test_temp_path(staged, sizeof(staged), "exact-update-stage") == 0);
    TEST_CHECK(test_temp_path(input, sizeof(input), "exact-update-input") == 0);
    test_payload(original, sizeof(original), 71);
    options.flags |= single ? LIBMPQ_FILE_FLAG_SINGLE : LIBMPQ_FILE_FLAG_SECTOR_CRC;
    TEST_CHECK(
        (encrypted ? libmpq__archive_create_mpqe(
                         &archive, path, auth_code, sizeof(auth_code) - 1, &create
                     )
                   : libmpq__archive_create(&archive, path, &create)) == 0
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, chunk) == 0);
    TEST_CHECK(libmpq__writer_begin(archive, "chain-32", sizeof(original), &options, &member) == 0);
    if (create.attributes != 0)
        TEST_CHECK(libmpq__writer_timestamp(member, 77) == 0);
    TEST_CHECK(libmpq__writer_write(member, original, sizeof(original)) == 0);
    TEST_CHECK(libmpq__writer_finish(member) == 0);
    options.locale = 0x409;
    options.platform = 1;
    TEST_CHECK(
        libmpq__archive_add_data(archive, "other", (const uint8_t *)"other", 5, &options) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version >= LIBMPQ_ARCHIVE_VERSION_3 && (layout == 0 || layout == 2)) {
        if (version == LIBMPQ_ARCHIVE_VERSION_4)
            TEST_CHECK(test_v4_source_layout(path, layout == 0 ? 1 : 2) == 0);
        else {
            uint8_t *bytes;
            size_t size;
            TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
            if (layout == 0)
                memset(bytes + 52, 0, 16);
            else {
                size = libmpq__load_le32(bytes + 16);
                memset(bytes + 16, 0, 28);
                libmpq__store_le32(bytes + 8, (uint32_t)size);
                libmpq__store_le64(bytes + 44, size);
            }
            int written = write_bytes(path, bytes, size);
            free(bytes);
            TEST_CHECK(written == 0);
        }
    }
    if (layout == 0 || layout == 3) {
        TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
        TEST_CHECK(archive->mpq_header.hash_table_count == 16);
        memcpy(hashes, archive->mpq_hash, sizeof(hashes));
        TEST_CHECK(libmpq__file_number(archive, "chain-32", &old_number) == 0);
        uint32_t block =
            archive->mpq_entry[archive->mpq_map[old_number].entry_index].classic_source_index;
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        libmpq__file_hash("chain-32", &h1, &h2, &h3);
        TEST_CHECK(
            h1 == alias_hashes[1][0] && h2 == alias_hashes[1][1] && h3 == alias_hashes[1][2]
        );
        for (uint32_t i = 0; i < 16; ++i)
            if (hashes[i].hash_a == h2 && hashes[i].hash_b == h3)
                hashes[i] = (mpq_hash_s){ 0, 0, 0, 0, LIBMPQ_HASH_DELETED };
        for (uint32_t i = 0; i < 3; ++i) {
            uint32_t slot = (h1 + 1) % 16;
            while (hashes[slot].block_table_index != LIBMPQ_HASH_FREE)
                slot = (slot + 1) % 16;
            hashes[slot] = (mpq_hash_s){ h2, h3,
                                         i == 0   ? 0
                                         : i == 1 ? 0x409
                                                  : 0x411,
                                         i == 0   ? 0
                                         : i == 1 ? 1
                                                  : 2,
                                         block };
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    }
    TEST_CHECK(test_compact_embed(path, form, encrypted, prefix, &origin) == 0);
    TEST_CHECK(
        (encrypted ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                   : libmpq__archive_open(&archive, path, -1)) == 0
    );
    if (layout != 2) {
        mpq_stream_s *selected = (mpq_stream_s *)archive;
        uint32_t default_number;
        uint32_t exact_number;
        TEST_CHECK(libmpq__file_number(archive, "other", &default_number) == 0);
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, "other", 0x409, 1, &exact_number) == 0
        );
        TEST_CHECK(default_number == exact_number);
        exact_number = UINT32_MAX;
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, "other", 0, 0, &exact_number) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(exact_number == 0);
        TEST_CHECK(
            libmpq__stream_open_name_identity(archive, "other", 0, 0, &selected) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(selected == NULL);
        TEST_CHECK(libmpq__stream_open_name(archive, "other", &selected) == 0);
        TEST_CHECK(libmpq__stream_close(selected) == 0);
    }
    TEST_CHECK(libmpq__file_number(archive, "chain-32", &number) == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    original_offset = entry->offset;
    packed_size = (size_t)entry->packed_size;
    TEST_CHECK(packed_size <= sizeof(packed));
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + original_offset, packed, packed_size) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(write_bytes(input, replacement, sizeof(replacement) - 1) == 0);
    TEST_CHECK(
        (encrypted ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                   : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_data_identity(update, "chain-32", 0x407, 0, NULL, 0, NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__update_rename_identity(update, "chain-32", "CHAIN-32", locale, platform) == 0
    );
    if (layout == 0) {
        TEST_CHECK(test_change_identity_stage(update, "chain-32", 0x409, 1, 0x409, 9) == 0);
        TEST_CHECK(test_change_identity_stage(update, "chain-32", 0x409, 9, 0x409, 1) == 0);
    }
    if (layout == 2) {
        TEST_CHECK(libmpq__update_change_identity(update, "chain-32", 0, 0, 0, 0) == 0);
        TEST_CHECK(copy_file(libmpq__update_path(update), staged) == 0);
        TEST_CHECK(
            libmpq__update_change_identity(update, "chain-32", 0, 0, 1, 0) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(
            libmpq__update_change_identity(update, "chain-32", 1, 0, 0, 0) == LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(same_file(libmpq__update_path(update), staged));
    }
    if (layout == 3) {
        TEST_CHECK(
            libmpq__update_replace_data_identity(
                update, "chain-32", locale, platform, NULL, 0, NULL
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(
            libmpq__update_remove_identity(update, "chain-32", locale, platform) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(
            libmpq__update_rename_identity(update, "chain-32", "renamed", locale, platform) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
        goto cleanup;
    }
    options.locale = (uint16_t)(locale + 1);
    options.platform = platform;
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "chain-32", locale, platform, NULL, 0, &options
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "chain-32", locale, platform, replacement, sizeof(replacement) - 1, NULL
        ) == 0
    );
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(copy_file(libmpq__update_path(update), staged) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "chain-32", 0x407, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), staged));
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(
        (encrypted ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                   : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "chain-32", locale, platform, replacement, sizeof(replacement) - 1, NULL
        ) == 0
    );
    if (layout == 0) {
        TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
        TEST_CHECK(
            check_exact_contents(archive, "chain-32", 0, 0, original, sizeof(original)) == 0
        );
        TEST_CHECK(libmpq__file_number_from_identity(archive, "chain-32", 0, 0, &number) == 0);
        entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(entry->offset == original_offset && entry->packed_size == packed_size);
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, origin + entry->offset, retained, packed_size
            ) == 0 &&
            memcmp(packed, retained, packed_size) == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(libmpq__update_rename_identity(update, "chain-32", "renamed", 0x411, 2) == 0);
        TEST_CHECK(libmpq__update_remove_identity(update, "chain-32", 0, 0) == 0);
    }
    options.locale = locale;
    options.platform = platform;
    TEST_CHECK(
        libmpq__update_replace_path_identity(
            update, "chain-32", locale, platform, input, &options
        ) == 0
    );
    TEST_CHECK(
        libmpq__update_rename_identity(update, "chain-32", "other", locale, platform) ==
        LIBMPQ_ERROR_EXIST
    );
    if (layout != 0)
        TEST_CHECK(
            libmpq__update_rename_identity(update, "chain-32", "renamed", locale, platform) == 0
        );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (encrypted ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                   : libmpq__archive_open(&archive, path, -1)) == 0
    );
    const char *name = layout == 0 ? "chain-32" : "renamed";
    TEST_CHECK(
        check_exact_contents(
            archive, name, locale, platform, replacement, sizeof(replacement) - 1
        ) == 0
    );
    TEST_CHECK(libmpq__file_number_from_identity(archive, name, locale, platform, &number) == 0);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, name) == 0);
    TEST_CHECK(
        libmpq__file_verify(
            archive, number, layout == 2 ? LIBMPQ_VERIFY_RAW_MD5 : LIBMPQ_VERIFY_ALL, &mismatch
        ) == 0 &&
        mismatch == 0
    );
    libmpq__reader_offsets_release(archive, number);
    if (layout == 0) {
        TEST_CHECK(
            check_exact_contents(archive, "renamed", 0x411, 2, original, sizeof(original)) == 0
        );
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, "chain-32", 0, 0, &number) ==
            LIBMPQ_ERROR_EXIST
        );
    }
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(archive->mpq_header.version == version);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(archive->mpq_header_v4.raw_chunk_size == chunk);
    if (layout != 2) {
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, name, locale, platform, &number) == 0
        );
        TEST_CHECK(
            libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 77
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (encrypted ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                   : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, name, locale, platform) == 0);
    libmpq__update_set_ops(update, &failing);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, snapshot));
cleanup:
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove(snapshot) == 0);
    if (layout != 3)
        TEST_CHECK(remove(staged) == 0);
    TEST_CHECK(remove(input) == 0);
    return 0;
}

/* Serialize independent locale aliases into a wrapping probe chain, then select exactly. */
static int
test_identity_access(uint32_t version, uint32_t chunk, unsigned layout, uint8_t single)
{
    mpq_archive_create_options_s create = { version, 8, single ? 4096 : 512, 0, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    mpq_hash_s hashes[16];
    mpq_file_identity_s identity;
    mpq_file_identity_s zero = { 0 };
    uint8_t first[257];
    uint8_t second[1507];
    uint8_t output[1507];
    uint32_t number;
    uint32_t original;
    libmpq__off_t got;
    char path[512];

    TEST_CHECK(test_temp_path(path, sizeof(path), "exact-identity") == 0);
    for (size_t i = 0; i < sizeof(first); i++)
        first[i] = (uint8_t)(i * 7);
    for (size_t i = 0; i < sizeof(second); i++)
        second[i] = (uint8_t)(i * 13 + i / 17);
    options.flags |= single ? LIBMPQ_FILE_FLAG_SINGLE : LIBMPQ_FILE_FLAG_SECTOR_CRC;
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, chunk) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "chain-32", first, sizeof(first), &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "nested/chain-32", second, sizeof(second), &options) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version >= LIBMPQ_ARCHIVE_VERSION_3 && layout != 1) {
        if (version == LIBMPQ_ARCHIVE_VERSION_4)
            TEST_CHECK(test_v4_source_layout(path, layout == 0 ? 1 : 2) == 0);
        else if (layout == 2) {
            uint8_t *image;
            size_t image_size;
            uint32_t end;
            TEST_CHECK(read_bytes(path, &image, &image_size) == 0);
            end = libmpq__load_le32(image + 16);
            TEST_CHECK(end <= image_size && end >= LIBMPQ_HEADER_V3_WIRE_SIZE);
            memset(image + 16, 0, 28);
            libmpq__store_le32(image + 8, end);
            libmpq__store_le64(image + 44, end);
            TEST_CHECK(write_bytes(path, image, end) == 0);
            free(image);
        } else {
            FILE *file = libmpq__file_open(path, "r+b");
            uint8_t absent[28] = { 0 };
            TEST_CHECK(file != NULL);
            TEST_CHECK(libmpq__file_seek(file, layout == 0 ? 52 : 16, SEEK_SET) == 0);
            TEST_CHECK(fwrite(absent, 1, layout == 0 ? 16 : 28, file) == (layout == 0 ? 16u : 28u));
            TEST_CHECK(fclose(file) == 0);
        }
    }
    if (layout != 2) {
        memset(hashes, 0xff, sizeof(hashes));
        hashes[14] = (mpq_hash_s){ 0, 0, 0, 0, LIBMPQ_HASH_DELETED };
        hashes[15] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0x411, 2, 0 };
        hashes[0] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0, 0, 0 };
        hashes[1] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0x409, 1, 1 };
        hashes[2] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0x409, 2, 0 };
        hashes[13] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 99, 99, 0 };
        TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    }
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "chain-32", &original) == 0);
    TEST_CHECK(libmpq__file_identity(archive, "chain-32", 0, &identity) == 0);
    TEST_CHECK(identity.reserved == 0 && identity.locale == 0 && identity.platform == 0);
    TEST_CHECK(
        identity.flags == (layout == 0   ? LIBMPQ_IDENTITY_CLASSIC
                           : layout == 1 ? LIBMPQ_IDENTITY_CLASSIC | LIBMPQ_IDENTITY_BET
                                         : LIBMPQ_IDENTITY_BET)
    );
    TEST_CHECK(libmpq__file_number_from_identity(archive, "chain-32", 0, 0, &number) == 0);
    TEST_CHECK(number == original && number == identity.file_number);
    if (layout != 2) {
        TEST_CHECK(libmpq__file_identity(archive, "chain-32", 1, &identity) == 0);
        TEST_CHECK(
            identity.locale == 0x409 && identity.platform == 1 && identity.file_number != original
        );
        TEST_CHECK(libmpq__file_number_from_identity(archive, "chain-32", 0x409, 1, &number) == 0);
        TEST_CHECK(number == identity.file_number);
        TEST_CHECK(libmpq__file_identity(archive, "chain-32", 2, &identity) == 0);
        TEST_CHECK(
            identity.locale == 0x409 && identity.platform == 2 && identity.file_number == original
        );
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, "chain-32", 0x409, 2, &number) == 0 &&
            number == original
        );
        TEST_CHECK(libmpq__file_identity(archive, "chain-32", 3, &identity) == 0);
        TEST_CHECK(
            identity.locale == 0x411 && identity.platform == 2 && identity.file_number == original
        );
        TEST_CHECK(libmpq__stream_open_name_identity(archive, "chain-32", 0x409, 1, &stream) == 0);
    } else {
        TEST_CHECK(libmpq__stream_open_name_identity(archive, "chain-32", 0, 0, &stream) == 0);
        archive->mpq_het.header.name_hash_bit_size = 63;
        memset(&identity, 0xff, sizeof(identity));
        TEST_CHECK(libmpq__file_identity(archive, "chain-32", 0, &identity) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(memcmp(&identity, &zero, sizeof(zero)) == 0);
        archive->mpq_het.header.name_hash_bit_size = 64;
        {
            mpq_het_hash_s parts;
            uint64_t hash;
            uint64_t saved_bits;
            uint32_t slot;
            uint32_t duplicate;
            uint8_t saved_name;
            uint8_t *names = (uint8_t *)archive->mpq_het.name_hash1;
            uint8_t *bits = (uint8_t *)archive->mpq_het.index_bits;
            uint32_t stride = archive->mpq_het.header.index_size_total;
            uint32_t width = archive->mpq_het.header.index_size;
            uint32_t row =
                archive->mpq_entry[archive->mpq_map[original].entry_index].bet_source_index;
            TEST_CHECK(libmpq__het_hash_filename("chain-32", &hash) == 0);
            TEST_CHECK(
                libmpq__het_hash_partition(hash, 64, archive->mpq_het.header.total_count, &parts) ==
                0
            );
            slot = parts.initial_slot;
            for (uint32_t probe = 0; probe < archive->mpq_het.header.total_count; probe++) {
                uint64_t index;
                TEST_CHECK(libmpq__het_slot_index(&archive->mpq_het, slot, &index) == 0);
                if (index == row)
                    break;
                slot = (slot + 1) % archive->mpq_het.header.total_count;
            }
            duplicate = (slot + 1) % archive->mpq_het.header.total_count;
            saved_name = names[duplicate];
            TEST_CHECK(
                libmpq__bit_get(
                    bits, archive->mpq_het.index_bits_size, (uint64_t)duplicate * stride, width,
                    &saved_bits
                ) == 0
            );
            names[duplicate] = names[slot];
            TEST_CHECK(
                libmpq__bit_set(
                    bits, archive->mpq_het.index_bits_size, (uint64_t)duplicate * stride, width, row
                ) == 0
            );
            TEST_CHECK(
                libmpq__file_identity(archive, "chain-32", 0, &identity) == LIBMPQ_ERROR_FORMAT
            );
            TEST_CHECK(memcmp(&identity, &zero, sizeof(zero)) == 0);
            names[duplicate] = saved_name;
            TEST_CHECK(
                libmpq__bit_set(
                    bits, archive->mpq_het.index_bits_size, (uint64_t)duplicate * stride, width,
                    saved_bits
                ) == 0
            );
        }
    }
    memset(&identity, 0xff, sizeof(identity));
    TEST_CHECK(
        libmpq__file_identity(archive, "chain-32", layout == 2 ? 1 : 4, &identity) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(memcmp(&identity, &zero, sizeof(zero)) == 0);
    number = UINT32_MAX;
    TEST_CHECK(
        libmpq__file_number_from_identity(archive, "chain-32", 0x409, 0, &number) ==
            LIBMPQ_ERROR_EXIST &&
        number == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "chain-32", &number) == 0 && number == original);
    {
        uint32_t index = archive->mpq_map[original].entry_index;
        uint32_t saved = archive->mpq_entry[index].file_number;
        archive->mpq_entry[index].file_number = archive->entry_count;
        TEST_CHECK(libmpq__file_identity(archive, "chain-32", 0, &identity) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(memcmp(&identity, &zero, sizeof(zero)) == 0);
        archive->mpq_entry[index].file_number = saved;
        if (layout == 1) {
            archive->mpq_hash[0].locale = 0x415;
            number = UINT32_MAX;
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "chain-32", 0, 0, &number) ==
                    LIBMPQ_ERROR_EXIST &&
                number == 0
            );
            TEST_CHECK(
                libmpq__file_number(archive, "chain-32", &number) == 0 && number == original
            );
            archive->mpq_hash[0].locale = 0;
            TEST_CHECK(libmpq__file_identity(archive, "nested/chain-32", 0, &identity) == 0);
            TEST_CHECK(
                identity.flags == LIBMPQ_IDENTITY_BET && identity.locale == 0 &&
                identity.platform == 0
            );
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "nested/chain-32", 0, 0, &number) == 0
            );
            TEST_CHECK(number == identity.file_number);
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "nested/chain-32", 0x409, 1, &number) ==
                    LIBMPQ_ERROR_EXIST &&
                number == 0
            );
        }
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__stream_read(stream, output, sizeof(output), &got) == 0);
    TEST_CHECK(got == (libmpq__off_t)(layout == 2 ? sizeof(first) : sizeof(second)));
    TEST_CHECK(memcmp(output, layout == 2 ? first : second, (size_t)got) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    if (layout == 2) {
        mpq_update_s *timestamp_update = NULL;
        TEST_CHECK(libmpq__update_begin(&timestamp_update, path) == 0);
        TEST_CHECK(
            libmpq__update_timestamp(timestamp_update, "chain-32", 0) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(
            libmpq__update_timestamp_identity(timestamp_update, "chain-32", 0, 0, 0) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(
            libmpq__update_timestamp_identity(timestamp_update, "chain-32", 1, 0, 0) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(libmpq__update_abort(timestamp_update) == 0);
    }
    if (layout != 2) {
        for (unsigned conflict = 0; conflict < 2; conflict++) {
            mpq_hash_s saved = hashes[15];
            hashes[15] = hashes[0];
            hashes[15].block_table_index = conflict;
            TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
            TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
            memset(&identity, 0xff, sizeof(identity));
            TEST_CHECK(
                libmpq__file_identity(archive, "chain-32", 0, &identity) == LIBMPQ_ERROR_FORMAT
            );
            TEST_CHECK(memcmp(&identity, &zero, sizeof(zero)) == 0);
            number = UINT32_MAX;
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "chain-32", 0, 0, &number) ==
                    LIBMPQ_ERROR_FORMAT &&
                number == 0
            );
            stream = (mpq_stream_s *)&identity;
            TEST_CHECK(
                libmpq__stream_open_name_identity(archive, "chain-32", 0, 0, &stream) ==
                    LIBMPQ_ERROR_FORMAT &&
                stream == NULL
            );
            TEST_CHECK(libmpq__archive_close(archive) == 0);
            hashes[15] = saved;
            TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
        }
        if (layout == 0) {
            for (uint32_t i = 2; i < 13; i++)
                hashes[i].block_table_index = LIBMPQ_HASH_DELETED;
            TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
            TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
            TEST_CHECK(libmpq__file_identity(archive, "chain-32", 2, &identity) == 0);
            TEST_CHECK(identity.locale == 99 && identity.platform == 99);
            TEST_CHECK(
                libmpq__file_identity(archive, "chain-32", 3, &identity) == 0 &&
                identity.locale == 0x411
            );
            TEST_CHECK(libmpq__archive_close(archive) == 0);
        }
    }
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Unknown aliases and locale rows survive a replacement followed by tombstone reuse. */
static int
test_alias_probe_update(uint32_t version, uint32_t chunk, int mixed)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s encrypted = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                         LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_KEY,
                                     LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_file_options_s named = { 0, 0, 0, 0x415, 4 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s hashes[16];
    mpq_hash_s saved[16];
    mpq_entry_s original;
    mpq_entry_s original_variant = { 0 };
    mpq_file_attributes_s attributes;
    uint8_t payload[1507];
    uint8_t stored[2048];
    uint8_t after[2048];
    uint8_t *pristine;
    size_t pristine_size;
    char path[512];
    char snapshot[512];
    uint32_t number;
    uint32_t index;
    uint32_t attrs_row;
    uint32_t mismatch;
    {
        const char *vectors[] = { "known", "chain-32", "chain-43", "chain-57" };
        for (unsigned i = 0; i < 4; ++i) {
            uint32_t computed[3];
            libmpq__file_hash(vectors[i], &computed[0], &computed[1], &computed[2]);
            TEST_CHECK(memcmp(computed, alias_hashes[i], sizeof(computed)) == 0);
        }
    }
    TEST_CHECK(test_temp_path(path, sizeof(path), "alias-probe") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "alias-before") == 0);
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i * 17 + i / 37);
    TEST_CHECK(
        (version == LIBMPQ_ARCHIVE_VERSION_4
             ? libmpq__writer_archive_create_v4(&archive, path, NULL, &create, chunk)
             : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "known", (const uint8_t *)"old", 3, &named) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "chain-32", payload, sizeof(payload), &encrypted) == 0
    );
    archive->write_attributes[1].filetime = 77;
    if (!mixed)
        TEST_CHECK(
            libmpq__archive_add_data(
                archive, "variant", (const uint8_t *)"locale variant", 14, NULL
            ) == 0
        );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (!mixed) {
        if (version == LIBMPQ_ARCHIVE_VERSION_4)
            TEST_CHECK(test_v4_source_layout(path, 1) == 0);
        else {
            FILE *file = libmpq__file_open(path, "r+b");
            uint8_t absent[16] = { 0 };
            TEST_CHECK(file != NULL && libmpq__file_seek(file, 52, SEEK_SET) == 0);
            TEST_CHECK(
                fwrite(absent, 1, sizeof(absent), file) == sizeof(absent) && fclose(file) == 0
            );
        }
    }
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &number) == 0);
    attrs_row = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    TEST_CHECK(libmpq__file_number(archive, "chain-32", &number) == 0);
    original = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(original.classic_source_index == 1 && original.packed_size <= sizeof(stored));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, original.offset, stored, (size_t)original.packed_size
        ) == 0
    );
    if (!mixed) {
        TEST_CHECK(libmpq__entry_index_from_classic(archive, 2, &index) == 0);
        original_variant = archive->mpq_entry[index];
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    memset(hashes, 0xff, sizeof(hashes));
    hashes[6] = (mpq_hash_s){ alias_hashes[0][1], alias_hashes[0][2], 0x415, 4, 0 };
    hashes[15] =
        (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0x409, 1, LIBMPQ_HASH_DELETED };
    hashes[0] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0x409, 1, 1 };
    hashes[1] = (mpq_hash_s){ alias_hashes[3][1], alias_hashes[3][2], 0x407, 2, 1 };
    hashes[2] = (mpq_hash_s){ alias_hashes[1][1], alias_hashes[1][2], 0x411, 3, mixed ? 1u : 2u };
    hashes[14] = (mpq_hash_s){ 0xd38437cbu, 0x07dfeaecu, 0, 0, attrs_row };
    TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    TEST_CHECK(test_alias_table_check(path, hashes) == 0);
    for (unsigned step = 0; step < 2; ++step) {
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, alias_hashes[1][0], alias_hashes[1][1], alias_hashes[1][2], &number
            ) == 0
        );
        TEST_CHECK(
            archive->mpq_entry[archive->mpq_map[number].entry_index].offset == original.offset
        );
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, alias_hashes[3][0], alias_hashes[3][1], alias_hashes[3][2], &index
            ) == 0 &&
            index == number
        );
        archive->mpq_hash[15].block_table_index = LIBMPQ_HASH_FREE;
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, alias_hashes[1][0], alias_hashes[1][1], alias_hashes[1][2], &index
            ) == LIBMPQ_ERROR_EXIST
        );
        archive->mpq_hash[15].block_table_index = LIBMPQ_HASH_DELETED;
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        if (step == 0)
            TEST_CHECK(
                libmpq__update_replace_data(
                    update, "known", (const uint8_t *)"replacement", 11, NULL
                ) == 0
            );
        else {
            named.locale = 0x416;
            named.platform = 5;
            TEST_CHECK(
                libmpq__update_add_data(update, "chain-43", (const uint8_t *)"added", 5, &named) ==
                0
            );
        }
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(
            archive->mpq_header.version == version && archive->mpq_header_v4.raw_chunk_size == chunk
        );
        TEST_CHECK((archive->het_data != NULL) == mixed);
        TEST_CHECK(libmpq__file_number(archive, "chain-32", &number) == 0);
        index = archive->mpq_map[number].entry_index;
        TEST_CHECK(archive->mpq_entry[index].classic_source_index == 0);
        TEST_CHECK(
            archive->mpq_entry[index].offset == original.offset &&
            archive->mpq_entry[index].flags == original.flags
        );
        TEST_CHECK(
            archive->mpq_entry[index].packed_size == original.packed_size &&
            archive->mpq_entry[index].unpacked_size == original.unpacked_size
        );
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, original.offset, after, (size_t)original.packed_size
            ) == 0
        );
        TEST_CHECK(memcmp(stored, after, (size_t)original.packed_size) == 0);
        TEST_CHECK(check_named(archive, "chain-32", payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "chain-32") == 0);
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mismatch) == 0 && mismatch == 0
        );
        TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
        TEST_CHECK(
            libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 77
        );
        if (mixed) {
            mpq_bet_entry_s record;
            uint64_t row;
            TEST_CHECK(
                libmpq__het_lookup(
                    &archive->mpq_het, "chain-32", archive->mpq_bet.header.entry_count,
                    libmpq__bet_match, &archive->mpq_bet, &row
                ) == 0
            );
            TEST_CHECK(row == archive->mpq_entry[index].bet_source_index);
            TEST_CHECK(
                libmpq__entry_index_from_bet(
                    archive, archive->mpq_entry[index].bet_source_index, &attrs_row
                ) == 0 &&
                attrs_row == index
            );
            TEST_CHECK(
                libmpq__bet_record_decode(
                    &archive->mpq_bet, archive->mpq_entry[index].bet_source_index, &record
                ) == 0
            );
            TEST_CHECK(record.offset == original.offset && record.flags == original.flags);
        } else {
            uint8_t variant[14];
            libmpq__off_t got;
            TEST_CHECK(
                libmpq__entry_index_from_classic(
                    archive, archive->mpq_hash[2].block_table_index, &index
                ) == 0
            );
            TEST_CHECK(archive->mpq_entry[index].file_number != number);
            TEST_CHECK(
                archive->mpq_entry[index].offset == original_variant.offset &&
                archive->mpq_entry[index].flags == original_variant.flags &&
                archive->mpq_entry[index].packed_size == original_variant.packed_size &&
                archive->mpq_entry[index].unpacked_size == original_variant.unpacked_size
            );
            TEST_CHECK(
                libmpq__file_read(
                    archive, archive->mpq_entry[index].file_number, variant, sizeof(variant), &got
                ) == 0 &&
                got == sizeof(variant)
            );
            TEST_CHECK(memcmp(variant, "locale variant", sizeof(variant)) == 0);
        }
        TEST_CHECK(check_named(archive, "known", (const uint8_t *)"replacement", 11) == 0);
        if (step != 0)
            TEST_CHECK(check_named(archive, "chain-43", (const uint8_t *)"added", 5) == 0);
        TEST_CHECK(libmpq__file_number(archive, "known", &number) == 0);
        TEST_CHECK(
            archive->mpq_hash[6].block_table_index ==
            archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index
        );
        TEST_CHECK(libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &number) == 0);
        TEST_CHECK(
            archive->mpq_hash[step == 0 ? 14 : 15].block_table_index ==
            archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index
        );
        if (step != 0) {
            TEST_CHECK(libmpq__file_number(archive, "chain-43", &number) == 0);
            TEST_CHECK(
                archive->mpq_hash[14].block_table_index ==
                archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index
            );
        }
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, alias_hashes[1][0], alias_hashes[1][1], alias_hashes[1][2], &number
            ) == 0
        );
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, alias_hashes[3][0], alias_hashes[3][1], alias_hashes[3][2], &index
            ) == 0 &&
            index == number
        );
        if (mixed && version == LIBMPQ_ARCHIVE_VERSION_4) {
            int32_t available = chunk == 0 ? LIBMPQ_ERROR_EXIST : 0;
            TEST_CHECK(
                libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) == available
            );
            TEST_CHECK(
                libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) == available
            );
        }
        for (uint32_t slot = 0; slot < 16; ++slot) {
            if (slot == 14 && step != 0) {
                TEST_CHECK(
                    archive->mpq_hash[slot].hash_a == alias_hashes[2][1] &&
                    archive->mpq_hash[slot].hash_b == alias_hashes[2][2]
                );
                TEST_CHECK(
                    archive->mpq_hash[slot].locale == 0x416 && archive->mpq_hash[slot].platform == 5
                );
            } else if (slot == 15 && step != 0) {
                TEST_CHECK(
                    archive->mpq_hash[slot].hash_a == hashes[14].hash_a &&
                    archive->mpq_hash[slot].hash_b == hashes[14].hash_b
                );
                TEST_CHECK(
                    archive->mpq_hash[slot].locale == 0 && archive->mpq_hash[slot].platform == 0
                );
            } else {
                TEST_CHECK(
                    archive->mpq_hash[slot].hash_a == hashes[slot].hash_a &&
                    archive->mpq_hash[slot].hash_b == hashes[slot].hash_b
                );
                TEST_CHECK(
                    archive->mpq_hash[slot].locale == hashes[slot].locale &&
                    archive->mpq_hash[slot].platform == hashes[slot].platform
                );
            }
            if (slot == 0 || slot == 1 || (slot == 2 && mixed))
                TEST_CHECK(archive->mpq_hash[slot].block_table_index == 0);
            if (slot == 15 && step == 0)
                TEST_CHECK(archive->mpq_hash[slot].block_table_index == LIBMPQ_HASH_DELETED);
            hashes[slot].block_table_index = archive->mpq_hash[slot].block_table_index;
        }
        if (step != 0) {
            hashes[14] = archive->mpq_hash[14];
            hashes[15] = archive->mpq_hash[15];
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(test_alias_table_check(path, hashes) == 0);
    }
    TEST_CHECK(read_bytes(path, &pristine, &pristine_size) == 0);
    for (unsigned failure = 0; failure < 7; ++failure) {
        if (failure == 3 && !mixed)
            continue;
        memcpy(saved, hashes, sizeof(saved));
        if (failure == 2)
            saved[1].block_table_index = 0xfffffff0u;
        if (failure == 3 && mixed)
            saved[6].block_table_index = saved[0].block_table_index;
        TEST_CHECK(test_alias_table_write(path, saved, failure == 4) == 0);
        TEST_CHECK(copy_file(path, snapshot) == 0);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        if (failure == 0) {
            named.locale = 0x999;
            TEST_CHECK(
                libmpq__update_replace_data(update, "known", NULL, 0, &named) == LIBMPQ_ERROR_FORMAT
            );
        } else if (failure == 6) {
            uint32_t available = 0;
            for (uint32_t slot = 0; slot < 16; ++slot)
                available += hashes[slot].block_table_index >= LIBMPQ_HASH_DELETED;
            for (uint32_t i = 0; i < available; ++i) {
                char name[32];
                (void)snprintf(name, sizeof(name), "slot-fill-%u", i);
                TEST_CHECK(libmpq__update_add_data(update, name, NULL, 0, NULL) == 0);
            }
            TEST_CHECK(
                libmpq__update_add_data(update, "overflow", NULL, 0, NULL) == LIBMPQ_ERROR_SIZE
            );
        } else if (failure == 1)
            TEST_CHECK(
                libmpq__update_replace_data(update, "chain-32", NULL, 0, NULL) ==
                LIBMPQ_ERROR_FORMAT
            );
        else if (failure == 5)
            TEST_CHECK(
                libmpq__update_add_data(update, "chain-57", NULL, 0, NULL) == LIBMPQ_ERROR_EXIST
            );
        else if (failure != 3 || mixed)
            TEST_CHECK(
                libmpq__update_add_data(update, "unrelated", NULL, 0, NULL) == LIBMPQ_ERROR_FORMAT
            );
        TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(check_named(archive, "chain-32", payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(write_bytes(path, pristine, pristine_size) == 0);
        TEST_CHECK(test_alias_table_check(path, hashes) == 0);
    }
    free(pristine);
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Compare the retained physical member and all attributes except the requested FILETIME. */
static int
test_timestamp_check(
    const char *path, const char *name, uint16_t locale, uint16_t platform, uint64_t filetime,
    const mpq_entry_s *old, const uint8_t *packed, const mpq_file_attributes_s *before
)
{
    mpq_archive_s *archive = NULL;
    mpq_file_attributes_s after;
    uint8_t bytes[4096];
    uint32_t number;
    uint32_t mismatch;
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number_from_identity(archive, name, locale, platform, &number) == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        entry->offset == old->offset && entry->packed_size == old->packed_size &&
        entry->unpacked_size == old->unpacked_size && entry->flags == old->flags
    );
    TEST_CHECK(entry->packed_size <= sizeof(bytes));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, (uint64_t)archive->archive_offset + entry->offset, bytes,
            (size_t)entry->packed_size
        ) == 0
    );
    TEST_CHECK(memcmp(bytes, packed, (size_t)entry->packed_size) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &after) == 0);
    TEST_CHECK(
        after.flags == before->flags && after.filetime == filetime &&
        after.crc32 == before->crc32 && after.patch_bit == before->patch_bit &&
        memcmp(after.md5, before->md5, 16) == 0
    );
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &mismatch) == 0 && mismatch == 0
    );
    if (archive->het_data != NULL && archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_4) {
        int32_t expected = archive->mpq_header_v4.raw_chunk_size ? 0 : LIBMPQ_ERROR_EXIST;
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) == expected);
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) == expected);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Exercise metadata-only staging without decoding compressed or encrypted retained bytes. */
static int
test_timestamp_updates(
    uint32_t version, uint32_t raw, int wrapped, unsigned storage, int classic, unsigned form
)
{
    mpq_archive_create_options_s create = { version, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                            LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 |
                                                LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY |
                                       LIBMPQ_FILE_FLAG_COMPRESS,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_writer_s *member = NULL;
    mpq_stream_s *stream = NULL;
    mpq_entry_s original;
    mpq_file_attributes_s attributes;
    uint8_t payload[1508];
    uint8_t packed[4096];
    uint8_t decoded[1508];
    uint8_t out[1508];
    static const uint64_t values[] = { 0, 1, UINT64_C(0xfedcba9876543210), UINT64_MAX, 17 };
    char path[512];
    char snapshot[512];
    char staged[512];
    uint32_t number;
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    libmpq__off_t got;
    test_payload(payload, sizeof(payload), 41);
    create.sector_size = storage == 1 ? 4096 : 512;
    if (storage == 2) {
        memset(payload, 0, 44);
        memcpy(payload, "RIFF", 4);
        libmpq__store_le32(payload + 4, sizeof(payload) - 8);
        memcpy(payload + 8, "WAVEfmt ", 8);
        libmpq__store_le32(payload + 16, 16);
        libmpq__store_le16(payload + 20, 1);
        libmpq__store_le16(payload + 22, 1);
        libmpq__store_le32(payload + 24, 22050);
        libmpq__store_le32(payload + 28, 44100);
        libmpq__store_le16(payload + 32, 2);
        libmpq__store_le16(payload + 34, 16);
        memcpy(payload + 36, "data", 4);
        libmpq__store_le32(payload + 40, sizeof(payload) - 44);
    }

    if (storage == 1)
        options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
    else
        options.flags |= LIBMPQ_FILE_FLAG_SECTOR_CRC;
    if (storage == 2)
        options.compression_next = LIBMPQ_COMPRESSION_WAVE_MONO;
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "timestamp-original") == 0);
    TEST_CHECK(test_temp_path(staged, sizeof(staged), "timestamp-stage") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, raw) == 0);
    TEST_CHECK(
        libmpq__writer_begin(archive, "nested/voice.bin", sizeof(payload), &options, &member) == 0
    );
    TEST_CHECK(libmpq__writer_timestamp(member, 91) == 0);
    TEST_CHECK(libmpq__writer_write(member, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__writer_finish(member) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"other", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "empty", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (classic && version >= LIBMPQ_ARCHIVE_VERSION_3) {
        if (version == LIBMPQ_ARCHIVE_VERSION_4)
            TEST_CHECK(test_v4_source_layout(path, 1) == 0);
        else {
            FILE *file = libmpq__file_open(path, "r+b");
            uint8_t absent[16] = { 0 };
            TEST_CHECK(file != NULL && libmpq__file_seek(file, 52, SEEK_SET) == 0);
            TEST_CHECK(fwrite(absent, 1, sizeof(absent), file) == sizeof(absent));
            TEST_CHECK(fclose(file) == 0);
        }
    }
    TEST_CHECK(test_compact_embed(path, form, wrapped, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "nested/voice.bin", &number) == 0);
    original = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(original.packed_size <= sizeof(packed));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + original.offset, packed, (size_t)original.packed_size
        ) == 0
    );
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, "nested/voice.bin", &stream) == 0);
    TEST_CHECK(
        libmpq__stream_read(stream, decoded, sizeof(decoded), &got) == 0 && got == sizeof(decoded)
    );
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), staged) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "nested/voice.bin", 91) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), staged));
    TEST_CHECK(
        libmpq__update_timestamp_identity(update, "nested/voice.bin", 1, 0, 1) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(same_file(libmpq__update_path(update), staged));
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        TEST_CHECK(
            libmpq__update_timestamp_identity(update, "nested/voice.bin", 0, 0, values[i]) == 0
        );
        TEST_CHECK(
            test_timestamp_check(
                libmpq__update_path(update), "nested/voice.bin", 0, 0, values[i], &original, packed,
                &attributes
            ) == 0
        );
        TEST_CHECK(same_file(path, snapshot));
    }
    TEST_CHECK(libmpq__update_timestamp(update, "empty", UINT64_MAX) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "empty", 0) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__stream_open_name(archive, "nested/voice.bin", &stream) == 0);
    TEST_CHECK(libmpq__stream_read(stream, out, sizeof(out), &got) == 0 && got == sizeof(out));
    TEST_CHECK(memcmp(decoded, out, sizeof(out)) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        test_timestamp_check(
            libmpq__update_path(update), "nested/voice.bin", 0, 0, 17, &original, packed,
            &attributes
        ) == 0
    );
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "nested/voice.bin", 18) == 0);
    libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc });
    TEST_CHECK(libmpq__update_commit(update) != 0);
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_timestamp(update, "nested/voice.bin", 19) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0 && remove(staged) == 0);
    return 0;
}

/* An opaque alias is a live reference even when it has no listfile name. */
static int
test_timestamp_aliases(uint32_t version, uint32_t raw)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s rows[16];
    mpq_file_options_s encrypted = { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0,
                                     0 };
    uint32_t hashes[3];
    uint32_t slot;
    uint32_t number;
    char path[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-alias") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "timestamp-alias-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, raw) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "chain-32", (const uint8_t *)"data", 4, &encrypted) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"other", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.hash_table_count == 16);
    memcpy(rows, archive->mpq_hash, sizeof(rows));
    TEST_CHECK(libmpq__file_number(archive, "chain-32", &number) == 0);
    uint32_t block = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    for (unsigned alias = 0; alias < 2; ++alias) {
        libmpq__file_hash(alias ? "opaque" : "chain-32", &hashes[0], &hashes[1], &hashes[2]);
        for (slot = hashes[0] & 15; rows[slot].block_table_index < LIBMPQ_HASH_DELETED;
             slot = (slot + 1) & 15) {
        }
        rows[slot] = (mpq_hash_s){ hashes[1], hashes[2], alias ? 0 : 0x409, 0, block };
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_alias_table_write(path, rows, 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "chain-32", 0) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "chain-32", 0x409, 0, 0) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "opaque", 0) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_timestamp(update, "chain-32", 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__update_timestamp_identity(update, "chain-32", 0x409, 0, 1) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__update_timestamp(update, "opaque", 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_timestamp(update, "other", 5) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, stage));
    for (slot = 0; slot < 16; ++slot)
        if (rows[slot].block_table_index == block && rows[slot].locale == 0x409)
            rows[slot].locale = 0;
    TEST_CHECK(test_alias_table_write(path, rows, 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "chain-32", 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(remove(path) == 0 && remove(stage) == 0);
    return 0;
}

/* Missing arrays, malformed payloads and omitted live rows never become valid zeroes. */
static int
test_timestamp_metadata(unsigned mode)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_1, 2, 512, 0,
                                            mode == 1 ? LIBMPQ_ATTRIBUTE_CRC32 : 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t raw[16] = { 0 };
    char path[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-metadata") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "timestamp-metadata-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (mode >= 2) {
        libmpq__store_le32(raw, mode == 2 ? 99 : 100);
        libmpq__store_le32(raw + 4, LIBMPQ_ATTRIBUTE_FILETIME | (mode == 4 ? 0x80u : 0));
        TEST_CHECK(libmpq__archive_add_data(archive, "(attributes)", raw, sizeof(raw), NULL) == 0);
    }
    TEST_CHECK(libmpq__archive_add_data(archive, "payload", (const uint8_t *)"x", 1, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "absent", 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_timestamp(update, "payload", 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__update_timestamp_identity(update, "payload", 0, 0, 1) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, stage));
    TEST_CHECK(remove(path) == 0 && remove(stage) == 0);
    return 0;
}

/* Read the current staged row, never assume a public number survives reconstruction. */
static int
test_timestamp_value(
    mpq_update_s *update, const char *name, uint16_t locale, uint16_t platform, uint64_t expected
)
{
    mpq_archive_s *archive = NULL;
    mpq_file_attributes_s attributes;
    uint32_t number;
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(libmpq__file_number_from_identity(archive, name, locale, platform, &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_FILETIME) && attributes.filetime == expected);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Timestamp staging respects the existing ordinary/exact replacement distinction. */
static int
test_timestamp_sequences(uint32_t version)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-sequence") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"old", 3, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 5) == 0);
    TEST_CHECK(libmpq__update_replace_data(update, "voice", (const uint8_t *)"new", 3, NULL) == 0);
    TEST_CHECK(test_timestamp_value(update, "voice", 0, 0, 0) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 7) == 0);
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "voice", 0, 0, (const uint8_t *)"exact", 5, NULL
        ) == 0
    );
    TEST_CHECK(test_timestamp_value(update, "voice", 0, 0, 7) == 0);
    TEST_CHECK(libmpq__update_rename_identity(update, "voice", "renamed", 0, 0) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 9) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_timestamp(update, "renamed", 9) == 0);
    TEST_CHECK(
        libmpq__update_change_identity(update, "renamed", 0, 0, UINT16_MAX, UINT16_MAX) == 0
    );
    TEST_CHECK(
        libmpq__update_timestamp_identity(update, "renamed", 0, 0, 10) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__update_timestamp_identity(update, "renamed", UINT16_MAX, UINT16_MAX, 10) == 0
    );
    TEST_CHECK(test_timestamp_value(update, "renamed", UINT16_MAX, UINT16_MAX, 10) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "renamed", 11) == 0);
    TEST_CHECK(test_timestamp_value(update, "renamed", UINT16_MAX, UINT16_MAX, 11) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "renamed", UINT16_MAX, UINT16_MAX) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "renamed", 11) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Separate classic rows remain independently addressable through the same filename. */
static int
test_timestamp_variants(uint32_t version)
{
    const uint64_t timestamp = UINT64_C(0xfedcba9876543210);
    mpq_archive_create_options_s create = { version, 8, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s options = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-variants") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "voice", (const uint8_t *)"neutral", 7, NULL) == 0
    );
    options.locale = 0x409;
    options.platform = 2;
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, version >= LIBMPQ_ARCHIVE_VERSION_3 ? "localized" : "voice",
            (const uint8_t *)"localized", 9, &options
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version >= LIBMPQ_ARCHIVE_VERSION_3) {
        if (version == LIBMPQ_ARCHIVE_VERSION_4)
            TEST_CHECK(test_v4_source_layout(path, 1) == 0);
        else {
            FILE *file = libmpq__file_open(path, "r+b");
            uint8_t absent[16] = { 0 };
            TEST_CHECK(file != NULL && libmpq__file_seek(file, 52, SEEK_SET) == 0);
            TEST_CHECK(fwrite(absent, 1, sizeof(absent), file) == sizeof(absent));
            TEST_CHECK(fclose(file) == 0);
        }
        mpq_hash_s rows[16];
        uint32_t hashes[3];
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(archive->mpq_header.hash_table_count == 16);
        memcpy(rows, archive->mpq_hash, sizeof(rows));
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        for (unsigned slot = 0; slot < 16; ++slot)
            if (rows[slot].block_table_index == 1)
                rows[slot].block_table_index = LIBMPQ_HASH_DELETED;
        libmpq__file_hash("voice", &hashes[0], &hashes[1], &hashes[2]);
        uint32_t slot = hashes[0] & 15;
        while (rows[slot].block_table_index < LIBMPQ_HASH_DELETED)
            slot = (slot + 1) & 15;
        rows[slot] = (mpq_hash_s){ hashes[1], hashes[2], 0x409, 2, 1 };
        TEST_CHECK(test_alias_table_write(path, rows, 0) == 0);
    }
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "voice", 0x409, 2, timestamp) == 0);
    TEST_CHECK(test_timestamp_value(update, "voice", 0, 0, 0) == 0);
    TEST_CHECK(test_timestamp_value(update, "voice", 0x409, 2, timestamp) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 17) == 0);
    TEST_CHECK(test_timestamp_value(update, "voice", 0, 0, 17) == 0);
    TEST_CHECK(test_timestamp_value(update, "voice", 0x409, 2, timestamp) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(check_exact_contents(archive, "voice", 0, 0, (const uint8_t *)"neutral", 7) == 0);
    TEST_CHECK(
        check_exact_contents(archive, "voice", 0x409, 2, (const uint8_t *)"localized", 9) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Signed physical bytes remain identical on no-op; actual metadata edits remove stale trust. */
static int
test_timestamp_signatures(void)
{
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_file_attributes_s attributes;
    uint32_t number;
    uint32_t signatures;
    uint32_t checked;
    char path[512];
    char snapshot[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-signed") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "timestamp-signed-before") == 0);
    TEST_CHECK(copy_file(FIXTURE_DIR "/mpq-v1-features.mpq", path) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "wave-mono.wav", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0 && signatures != 0);
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
            sizeof(test_signature_public_key), &checked
        ) == 0 &&
        checked == 0
    );
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &checked
        ) == 0 &&
        checked == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "wave-mono.wav", attributes.filetime) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), snapshot));
    TEST_CHECK(libmpq__update_commit(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "wave-mono.wav", attributes.filetime ^ 1) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0 && signatures == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Adoption failures keep the source intact and preserve the established abort-only boundary. */
static int
test_timestamp_failure(uint32_t version, int wrapped, int closing)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char original[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-failure") == 0);
    TEST_CHECK(test_temp_path(original, sizeof(original), "timestamp-failure-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "timestamp-failure-stage") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, original) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 1) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    libmpq__update_set_ops(
        update, &(mpq_update_ops_s){ closing ? fflush : fail_flush, closing ? fail_close : fclose,
                                     fail_publish, malloc }
    );
    TEST_CHECK(
        libmpq__update_timestamp(update, "voice", 2) ==
        (closing ? LIBMPQ_ERROR_CLOSE : LIBMPQ_ERROR_WRITE)
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    if (closing)
        TEST_CHECK(libmpq__update_timestamp(update, "voice", 3) == LIBMPQ_ERROR_EXIST);
    else
        TEST_CHECK(test_timestamp_value(update, "voice", 0, 0, 1) == 0);
    libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc });
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(same_file(path, original));
    TEST_CHECK(remove(path) == 0 && remove(original) == 0 && remove(stage) == 0);
    return 0;
}

/* Physical raw corruption must not be hidden by regenerating a changed candidate. */
static int
test_timestamp_raw_corruption(void)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_4, 8, 512, 0,
                                            LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint32_t number;
    uint64_t digest;
    char path[512];
    char snapshot[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-raw-corrupt") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "timestamp-raw-before") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, 17) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    digest = entry->offset + entry->packed_size;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    FILE *file = libmpq__file_open(path, "r+b");
    TEST_CHECK(file != NULL && libmpq__file_seek(file, (libmpq__off_t)digest, SEEK_SET) == 0);
    int byte = fgetc(file);
    TEST_CHECK(byte != EOF && libmpq__file_seek(file, (libmpq__off_t)digest, SEEK_SET) == 0);
    TEST_CHECK(fputc(byte ^ 1, file) != EOF && fclose(file) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 1) == LIBMPQ_ERROR_READ);
    TEST_CHECK(same_file(libmpq__update_path(update), snapshot));
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* A BET-only filename may share a classic-backed row: no-op is safe, mutation is not. */
static int
test_timestamp_bet_alias(uint32_t version)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s rows[16];
    uint32_t hashes[3];
    char path[512];
    char snapshot[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "timestamp-bet-alias") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "timestamp-bet-before") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "second.bin", (const uint8_t *)"data", 4, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.hash_table_count == 16);
    memcpy(rows, archive->mpq_hash, sizeof(rows));
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    for (unsigned slot = 0; slot < 16; ++slot)
        if (rows[slot].block_table_index == 0)
            rows[slot].block_table_index = LIBMPQ_HASH_DELETED;
    libmpq__file_hash("first.bin", &hashes[0], &hashes[1], &hashes[2]);
    uint32_t slot = hashes[0] & 15;
    while (rows[slot].block_table_index < LIBMPQ_HASH_DELETED)
        slot = (slot + 1) & 15;
    rows[slot] = (mpq_hash_s){ hashes[1], hashes[2], 0, 0, 0 };
    TEST_CHECK(test_alias_table_write(path, rows, 0) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "first.bin", 0) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "second.bin", 0) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "second.bin", 0, 0, 0) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), snapshot));
    TEST_CHECK(libmpq__update_timestamp(update, "first.bin", 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_timestamp(update, "second.bin", 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(same_file(libmpq__update_path(update), snapshot));
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0);
    return 0;
}

/* Inspect actual serialized payload order independently of the compaction planner. */
static int
test_compact_dense(mpq_archive_s *archive)
{
    uint64_t cursor = archive->mpq_header.header_size;
    for (uint32_t i = 0; i < archive->files; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[i].entry_index];
        TEST_CHECK(entry->offset == cursor);
        cursor += entry->packed_size;
        if (archive->mpq_header_v4.raw_chunk_size != 0 && entry->packed_size != 0)
            cursor += ((entry->packed_size - 1) / archive->mpq_header_v4.raw_chunk_size + 1) * 16;
    }
    uint64_t table = archive->het_data != NULL
                         ? archive->mpq_header_v3.het_table_offset
                         : archive->mpq_header.hash_table_offset |
                               ((uint64_t)archive->mpq_header_ex.hash_table_offset_high << 32);
    TEST_CHECK(cursor == table);
    return 0;
}

/* Wrap synthetic output as bytes, without changing any MPQ-relative field. */
static int
test_compact_embed(
    const char *path, unsigned form, int wrapped, uint8_t prefix[4096], uint64_t *origin
)
{
    static const uint64_t origins[] = { 0, 512, 1024, 4096, 96, 608, 2048 };
    mpq_archive_s *archive = NULL;
    TEST_CHECK(form < sizeof(origins) / sizeof(origins[0]));
    *origin = origins[form];
    if (form == 0)
        return 0;
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    size_t size = (size_t)archive->file_size;
    uint8_t *bytes = malloc(size + (size_t)*origin);
    TEST_CHECK(bytes != NULL);
    for (size_t i = 0; i < (size_t)*origin; ++i)
        prefix[i] = (uint8_t)(i * 13 + 7);
    libmpq__store_le32(prefix + 17, LIBMPQ_HEADER);
    if (form == 4 || form == 5) {
        size_t user = form == 4 ? 0 : 512;
        libmpq__store_le32(prefix + user, LIBMPQ_USER_DATA_HEADER);
        libmpq__store_le32(prefix + user + 4, form == 4 ? 32 : 64);
        libmpq__store_le32(prefix + user + 8, 96);
        libmpq__store_le32(prefix + user + 12, form == 4 ? 16 : 24);
        libmpq__store_le32(prefix + user + 25, LIBMPQ_USER_DATA_HEADER);
    }
    if (form == 6)
        libmpq__store_le32(prefix, 0x57334d48u);
    memcpy(bytes, prefix, (size_t)*origin);
    TEST_CHECK(libmpq__source_read_at(archive->source, 0, bytes + *origin, size) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (wrapped) {
        uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
        FILE *input = tmpfile();
        FILE *output = libmpq__file_open(path, "wb");
        int written = input != NULL && output != NULL &&
                      fwrite(bytes, 1, size + (size_t)*origin, input) == size + (size_t)*origin;
        int32_t transformed =
            written ? libmpq__mpqe_key(key, auth_code, sizeof(auth_code) - 1) : LIBMPQ_ERROR_OPEN;
        if (transformed == 0)
            transformed = libmpq__writer_mpqe_transform_file(input, output, key);
        libmpq__mpqe_clear(key, sizeof(key));
        int closed_input = input != NULL ? fclose(input) : -1;
        int closed_output = output != NULL ? fclose(output) : -1;
        if (!written || transformed != 0 || closed_input != 0 || closed_output != 0) {
            free(bytes);
            TEST_CHECK(0);
        }
    } else
        TEST_CHECK(write_bytes(path, bytes, size + (size_t)*origin) == 0);
    free(bytes);
    return 0;
}

/* Inspect origin, exact prefix bytes and user-data fields through normal discovery. */
static int
test_compact_prefix(mpq_archive_s *archive, unsigned form, const uint8_t *expected, uint64_t origin)
{
    mpq_prefix_info_s info;
    uint8_t actual[4096];
    TEST_CHECK(archive->archive_offset == (libmpq__off_t)origin);
    TEST_CHECK(libmpq__reader_archive_prefix_info(archive, &info) == 0 && info.origin == origin);
    TEST_CHECK(libmpq__source_read_at(archive->source, 0, actual, (size_t)origin) == 0);
    TEST_CHECK(memcmp(actual, expected, (size_t)origin) == 0);
    TEST_CHECK(info.has_user_data == (form == 4 || form == 5));
    if (info.has_user_data) {
        TEST_CHECK(info.user_data_position == (form == 4 ? 0u : 512u));
        TEST_CHECK(info.header_offset == 96 && info.user_data_size == (form == 4 ? 32u : 64u));
        TEST_CHECK(info.user_data_header_size == (form == 4 ? 16u : 24u));
    }
    return 0;
}

/* Every staged operation must remain normally discoverable with an identical prefix. */
static int
test_embedded_stage(mpq_update_s *update, unsigned form, const uint8_t *prefix, uint64_t origin)
{
    mpq_archive_s *archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Ordinary and exact operations retain separate semantics across successive wrapped stages. */
static int
test_embedded_mutations(mpq_update_s *update, unsigned form, const uint8_t *prefix, uint64_t origin)
{
    char input[512];
    char stage[512];
    TEST_CHECK(test_temp_path(input, sizeof(input), "embedded-input") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "embedded-final-stage") == 0);
    TEST_CHECK(write_bytes(input, (const uint8_t *)"new", 3) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "folder\\voice", 17) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "folder\\voice", 0, 0, 1, 2) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "folder\\voice", 1, 2, 18) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "folder\\voice", 1, 2, 0, 0) == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "folder\\voice", (const uint8_t *)"new", 3, NULL) == 0
    );
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(test_timestamp_value(update, "folder\\voice", 0, 0, 0) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "folder\\voice", 19) == 0);
    TEST_CHECK(
        libmpq__update_replace_path_identity(update, "folder\\voice", 0, 0, input, NULL) == 0
    );
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(test_timestamp_value(update, "folder\\voice", 0, 0, 19) == 0);
    TEST_CHECK(libmpq__update_add_data(update, "temporary", NULL, 0, NULL) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_rename(update, "temporary", "temporary-renamed") == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_replace_path(update, "temporary-renamed", input, NULL) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "temporary-renamed", 0, 0) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_add_path(update, "temporary-renamed", input, NULL) == 0);
    TEST_CHECK(
        libmpq__update_replace_data_identity(update, "temporary-renamed", 0, 0, NULL, 0, NULL) == 0
    );
    TEST_CHECK(libmpq__update_rename_identity(update, "temporary-renamed", "temporary", 0, 0) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_remove(update, "temporary") == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(remove(input) == 0 && remove(stage) == 0);
    return 0;
}

/* Empty legacy archives take named reconstruction too; subsequent stages retain discovery. */
static int
test_embedded_empty(uint32_t version, unsigned form, uint8_t from_path)
{
    mpq_archive_create_options_s create = { version, 4, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    char path[512];
    char input[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "embedded-empty") == 0);
    TEST_CHECK(test_temp_path(input, sizeof(input), "embedded-empty-input") == 0);
    TEST_CHECK(write_bytes(input, (const uint8_t *)"path", 4) == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        (from_path ? libmpq__update_add_path(update, "new", input, NULL)
                   : libmpq__update_add_data(update, "new", (const uint8_t *)"path", 4, NULL)) == 0
    );
    TEST_CHECK(test_embedded_stage(update, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(check_named(archive, "new", (const uint8_t *)"path", 4) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(input) == 0);
    return 0;
}

/* No-op dispatch precedes strict rebuild eligibility; legacy suffix copying stays separate. */
static int
test_embedded_trailer(uint32_t version)
{
    mpq_archive_create_options_s create = { version, 4, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t prefix[4096];
    uint64_t origin;
    char path[512];
    char before[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "embedded-trailer") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "embedded-trailer-before") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "embedded-trailer-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    FILE *file = libmpq__file_open(path, "ab");
    TEST_CHECK(file != NULL && fwrite("suffix", 1, 6, file) == 6 && fclose(file) == 0);
    TEST_CHECK(test_compact_embed(path, 5, 0, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 0) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "voice", 0, 0, 0) == 0);
    TEST_CHECK(libmpq__update_rename_identity(update, "voice", "VOICE", 0, 0) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "voice", 0, 0, 0, 0) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_timestamp(update, "voice", 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_remove_identity(update, "voice", 0, 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    if (version < LIBMPQ_ARCHIVE_VERSION_3) {
        TEST_CHECK(
            libmpq__update_replace_data(update, "voice", (const uint8_t *)"new", 3, NULL) == 0
        );
        TEST_CHECK(test_embedded_stage(update, 5, prefix, origin) == 0);
        TEST_CHECK(libmpq__update_commit(update) == 0);
        uint8_t *bytes = NULL;
        size_t size;
        TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
        TEST_CHECK(size >= 6 && memcmp(bytes + size - 6, "suffix", 6) == 0);
        free(bytes);
    } else {
        TEST_CHECK(
            libmpq__update_replace_data(update, "voice", NULL, 0, NULL) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, before));
    }
    TEST_CHECK(remove(path) == 0 && remove(before) == 0 && remove(stage) == 0);
    return 0;
}

/* All generations reclaim a deliberate hole without changing packed contents or attributes. */
static int
test_compaction(uint32_t version, uint32_t raw, unsigned encryption, int wrapped, unsigned form)
{
    mpq_archive_create_options_s create = {
        version, 8, 512,
        LIBMPQ_ARCHIVE_CREATE_LISTFILE | LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
        LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5
    };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_writer_s *member = NULL;
    uint8_t payload[1508];
    uint8_t packed[4096];
    uint8_t after[4096];
    mpq_file_attributes_s attributes;
    mpq_entry_s original;
    mpq_hash_s hashes[16];
    char path[512];
    char snapshot[512];
    char stage[512];
    uint32_t number;
    uint64_t origin;
    uint8_t prefix[4096] = { 0 };
    test_payload(payload, sizeof(payload), 41);
    if (encryption == 2 && wrapped) {
        create.sector_size = 4096;
        options.flags &= ~LIBMPQ_FILE_FLAG_SECTOR_CRC;
        options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
    }
    if (encryption != 0)
        options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
    if (encryption == 2)
        options.flags |= LIBMPQ_FILE_FLAG_KEY;
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact") == 0);
    TEST_CHECK(test_temp_path(snapshot, sizeof(snapshot), "compact-original") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-stage") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, raw) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(
        libmpq__writer_begin(archive, "folder\\voice", sizeof(payload), &options, &member) == 0
    );
    TEST_CHECK(libmpq__writer_timestamp(member, UINT64_MAX) == 0);
    TEST_CHECK(libmpq__writer_write(member, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__writer_finish(member) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "empty", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, wrapped, prefix, &origin) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    uint64_t old_size = archive->file_size;
    TEST_CHECK(libmpq__file_number(archive, "folder\\voice", &number) == 0);
    original = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(original.packed_size <= sizeof(packed));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + original.offset, packed, original.packed_size
        ) == 0
    );
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(archive->mpq_header.hash_table_count == 16);
    memcpy(hashes, archive->mpq_hash, sizeof(hashes));
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(same_file(path, snapshot));
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(test_compact_dense(archive) == 0 && archive->file_size < old_size);
    TEST_CHECK(
        archive->mpq_header.version == version && archive->mpq_header_v4.raw_chunk_size == raw
    );
    TEST_CHECK(libmpq__file_number(archive, "folder\\voice", &number) == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        entry->offset < original.offset && entry->flags == original.flags &&
        entry->packed_size == original.packed_size && entry->unpacked_size == original.unpacked_size
    );
    TEST_CHECK(check_named(archive, "folder\\voice", payload, sizeof(payload)) == 0);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + entry->offset, after, entry->packed_size
        ) == 0
    );
    if (encryption != 2)
        TEST_CHECK(memcmp(packed, after, entry->packed_size) == 0);
    else
        TEST_CHECK(memcmp(packed, after, entry->packed_size) != 0);
    mpq_file_attributes_s actual;
    TEST_CHECK(libmpq__file_attributes(archive, number, &actual) == 0);
    TEST_CHECK(
        actual.filetime == UINT64_MAX && actual.crc32 == attributes.crc32 &&
        memcmp(actual.md5, attributes.md5, 16) == 0
    );
    TEST_CHECK(memcmp(hashes, archive->mpq_hash, sizeof(hashes)) == 0);
    uint32_t mismatches;
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "folder\\voice") == 0);
    TEST_CHECK(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mismatches) == 0 && mismatches == 0
    );
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_compact(update) == 0 && same_file(libmpq__update_path(update), stage)
    );
    if (form != 0) {
        TEST_CHECK(test_embedded_mutations(update, form, prefix, origin) == 0);
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            (wrapped
                 ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
        );
        TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
        TEST_CHECK(check_named(archive, "folder\\voice", (const uint8_t *)"new", 3) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(copy_file(snapshot, path) == 0);
        for (unsigned failure = 0; failure < 2; ++failure) {
            TEST_CHECK(
                (wrapped
                     ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                     : libmpq__update_begin(&update, path)) == 0
            );
            TEST_CHECK(libmpq__update_compact(update) == 0);
            if (failure) {
                libmpq__update_set_ops(
                    update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc }
                );
                TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
            } else
                TEST_CHECK(libmpq__update_abort(update) == 0);
            TEST_CHECK(same_file(path, snapshot));
        }
        TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0 && remove(stage) == 0);
        return 0;
    }
    TEST_CHECK(libmpq__update_timestamp(update, "folder\\voice", 17) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_remove(update, "empty") == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(copy_file(path, snapshot) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_timestamp(update, "folder\\voice", 19) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc });
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, snapshot));
    TEST_CHECK(remove(path) == 0 && remove(snapshot) == 0 && remove(stage) == 0);
    return 0;
}

/* Unknown names need no key for offset-independent ciphertext; shared rows stay shared. */
static int
test_compaction_opaque(uint32_t version, unsigned layout, unsigned encryption, unsigned form)
{
    mpq_archive_create_options_s create = { version, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                   LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s hashes[16];
    mpq_entry_s before;
    uint8_t payload[1508];
    uint8_t stored[2048];
    uint8_t output[2048];
    char path[512];
    char stage[512];
    uint32_t number;
    uint64_t origin;
    uint8_t prefix[4096] = { 0 };
    uint32_t hash[3];
    test_payload(payload, sizeof(payload), 57);
    if (encryption == 4)
        create.flags |= LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    if (encryption)
        options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
    if (encryption == 2 || encryption == 6)
        options.flags |= LIBMPQ_FILE_FLAG_KEY;
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-opaque") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-opaque-before") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, 17) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "opaque", payload, sizeof(payload), &options) == 0
    );
    if (encryption >= 5) {
        static const uint8_t list[] = "folder/opaque\nopaque\n";
        archive->write_internal = 1;
        TEST_CHECK(
            libmpq__writer_file_add(archive, LIBMPQ_LISTFILE_NAME, list, sizeof(list) - 1, NULL) ==
            0
        );
        archive->write_internal = 0;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version >= LIBMPQ_ARCHIVE_VERSION_3 && layout != 1) {
        if (version == LIBMPQ_ARCHIVE_VERSION_4)
            TEST_CHECK(test_v4_source_layout(path, layout == 0 ? 1 : 2) == 0);
        else {
            uint8_t *bytes;
            size_t size;
            TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
            if (layout == 0)
                memset(bytes + 52, 0, 16);
            else {
                size = libmpq__load_le32(bytes + 16);
                memset(bytes + 16, 0, 28);
                libmpq__store_le32(bytes + 8, (uint32_t)size);
                libmpq__store_le64(bytes + 44, size);
            }
            TEST_CHECK(write_bytes(path, bytes, size) == 0);
            free(bytes);
        }
    }
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
    before = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(before.packed_size <= sizeof(stored));
    TEST_CHECK(
        libmpq__source_read_at(archive->source, before.offset, stored, before.packed_size) == 0
    );
    if (layout != 2) {
        TEST_CHECK(archive->mpq_header.hash_table_count == 16);
        memcpy(hashes, archive->mpq_hash, sizeof(hashes));
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (layout != 2 && (encryption == 0 || encryption == 3 || encryption >= 4)) {
        libmpq__file_hash(
            encryption == 4   ? "opaque"
            : encryption >= 5 ? "folder/opaque"
                              : "other-alias",
            &hash[0], &hash[1], &hash[2]
        );
        uint32_t slot = hash[0] & 15;
        while (hashes[slot].block_table_index < LIBMPQ_HASH_DELETED)
            slot = (slot + 1) & 15;
        hashes[slot] = (mpq_hash_s){ hash[1], hash[2], 0x409, 2, before.classic_source_index };
        TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    }
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    if (encryption == 2 || encryption == 3) {
        TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_DECRYPT);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        const char *hints[] = { "opaque", "other-alias" };
        if (encryption == 2) {
            TEST_CHECK(libmpq__update_compact_ex(update, hints, 1) == 0);
            TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
            TEST_CHECK(check_named(archive, "opaque", payload, sizeof(payload)) == 0);
            TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
            TEST_CHECK(
                archive->mpq_entry[archive->mpq_map[number].entry_index].offset < before.offset
            );
            TEST_CHECK(libmpq__archive_close(archive) == 0);
            TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
            TEST_CHECK(
                libmpq__update_compact(update) == 0 && same_file(libmpq__update_path(update), stage)
            );
        } else {
            TEST_CHECK(libmpq__update_compact_ex(update, hints, 2) == LIBMPQ_ERROR_FORMAT);
            TEST_CHECK(same_file(libmpq__update_path(update), stage));
        }
        TEST_CHECK(libmpq__update_abort(update) == 0);
    } else {
        TEST_CHECK(libmpq__update_compact(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
        TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
        TEST_CHECK(
            archive->files == (encryption >= 4 ? 2u : 1u) && test_compact_dense(archive) == 0
        );
        TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(entry->offset < before.offset && entry->packed_size == before.packed_size);
        TEST_CHECK(
            libmpq__source_read_at(
                archive->source, origin + entry->offset, output, entry->packed_size
            ) == 0
        );
        TEST_CHECK((memcmp(stored, output, entry->packed_size) == 0) == (encryption != 6));
        TEST_CHECK(check_named(archive, "opaque", payload, sizeof(payload)) == 0);
        if (layout != 2 && (encryption == 0 || encryption >= 4)) {
            uint32_t alias;
            TEST_CHECK(
                libmpq__file_number_from_identity(
                    archive,
                    encryption == 4   ? "opaque"
                    : encryption >= 5 ? "folder/opaque"
                                      : "other-alias",
                    0x409, 2, &alias
                ) == 0 &&
                alias == number
            );
            for (uint32_t slot = 0; slot < 16; ++slot) {
                if (hashes[slot].block_table_index == before.classic_source_index)
                    hashes[slot].block_table_index = 0;
                TEST_CHECK(
                    memcmp(&hashes[slot], &archive->mpq_hash[slot], sizeof(hashes[slot])) == 0
                );
            }
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        TEST_CHECK(
            libmpq__update_compact(update) == 0 && same_file(libmpq__update_path(update), stage)
        );
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
        TEST_CHECK(check_named(archive, "opaque", payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    if (form == 0 && layout != 2 && encryption == 0) {
        uint32_t occupied = 0;
        uint32_t free_slot = 0;
        while (hashes[occupied].block_table_index >= LIBMPQ_HASH_DELETED)
            ++occupied;
        while (hashes[free_slot].block_table_index < LIBMPQ_HASH_DELETED)
            ++free_slot;
        hashes[free_slot] = hashes[occupied];
        TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        TEST_CHECK(libmpq__update_abort(update) == 0);
        hashes[free_slot].hash_a ^= 1;
        hashes[free_slot].block_table_index = 1;
        TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        TEST_CHECK(libmpq__update_abort(update) == 0);
    }
    TEST_CHECK(remove(path) == 0 && remove(stage) == 0);
    return 0;
}

/* Inspect regenerated metadata independently of the compactor's candidate checks. */
static int
test_compaction_listfile(uint32_t version, unsigned storage, int signature, int listed)
{
    mpq_archive_create_options_s create = { version, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                            LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 |
                                                LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_file_attributes_s attributes;
    mpq_entry_s before;
    uint8_t list[4096];
    uint8_t expected[4096];
    uint8_t packed[8192];
    uint8_t actual[8192];
    uint8_t *snapshot;
    size_t snapshot_size;
    size_t size = 0;
    size_t expected_size = 0;
    char path[512];
    uint32_t number;
    if (storage != 0) {
        options.flags = LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE;
        options.compression_first = options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
    }
    if (storage == 2 || storage == 3) {
        options.flags =
            LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SECTOR_CRC;
        if (storage == 3)
            options.flags |= LIBMPQ_FILE_FLAG_KEY;
    }
    if (storage == 7) {
        options.flags = LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC;
        options.compression_first = 0;
    }
    if (storage == 4)
        options.flags = LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_SINGLE;
    if (storage != 5) {
        static const char lines[] = "voice\r\n\nvoice\rvoice\n\r\n";
        for (unsigned i = 0; i < (storage == 2 || storage == 3 || storage == 7 ? 80u : 10u); ++i) {
            memcpy(list + size, lines, sizeof(lines) - 1);
            size += sizeof(lines) - 1;
        }
    }
    memcpy(expected, list, size);
    expected_size = size;
    if (listed) {
        memcpy(list + size, "(SiGnAtUrE)\r\n", 13);
        size += 13;
    }
    if (storage != 5) {
        memcpy(list + size, "voice", sizeof("voice"));
        size += 5;
        memcpy(expected + expected_size, "voice", sizeof("voice"));
        expected_size += 5;
    }
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-listfile") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, signature == 1 ? 0 : 17) == 0);
    if (signature == 1)
        TEST_CHECK(
            libmpq__archive_sign(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    if (signature == 2) {
        uint8_t stale[72] = { 0 };
        archive->write_internal = 1;
        TEST_CHECK(
            libmpq__writer_file_add(archive, LIBMPQ_SIGNATURE_NAME, stale, sizeof(stale), NULL) == 0
        );
        archive->write_internal = 0;
    }
    uint32_t row = archive->write_next_block;
    archive->write_internal = 1;
    TEST_CHECK(libmpq__writer_file_add(archive, LIBMPQ_LISTFILE_NAME, list, size, &options) == 0);
    archive->write_internal = 0;
    archive->write_attributes[row].filetime = UINT64_MAX;
    if (storage == 6)
        memset(archive->write_attributes[row].md5, 0, 16);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0);
    before = archive->mpq_entry[archive->mpq_map[number].entry_index];
    if (storage == 6) {
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(!(attributes.flags & LIBMPQ_ATTRIBUTE_MD5));
    }
    TEST_CHECK(before.packed_size <= sizeof(packed));
    TEST_CHECK(
        libmpq__source_read_at(archive->source, before.offset, packed, before.packed_size) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(read_bytes(path, &snapshot, &snapshot_size) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    if (storage == 5) {
        TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(same_file(libmpq__update_path(update), path));
        TEST_CHECK(libmpq__update_abort(update) == 0);
    } else {
        TEST_CHECK(libmpq__update_compact(update) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
        TEST_CHECK(libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0);
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(entry->flags == before.flags && entry->offset < before.offset);
        if (signature && listed) {
            uint32_t attribute_number;
            TEST_CHECK(
                libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &attribute_number) == 0
            );
            const mpq_entry_s *attribute_entry =
                &archive->mpq_entry[archive->mpq_map[attribute_number].entry_index];
            uint32_t chunk = archive->mpq_header_v4.raw_chunk_size;
            uint64_t physical = entry->packed_size;
            if (chunk && physical)
                physical += ((entry->packed_size - 1) / chunk + 1) * UINT64_C(16);
            TEST_CHECK(attribute_entry->offset == entry->offset + physical);
        }
        if (!(signature && listed)) {
            TEST_CHECK(entry->packed_size == before.packed_size);
            if (storage != 3) {
                TEST_CHECK(
                    libmpq__source_read_at(
                        archive->source, entry->offset, actual, entry->packed_size
                    ) == 0
                );
                TEST_CHECK(memcmp(actual, packed, entry->packed_size) == 0);
            }
        }
        mpq_stream_s *stream = NULL;
        libmpq__off_t transferred;
        size_t wanted = signature && listed ? expected_size : size;
        const uint8_t *content = signature && listed ? expected : list;
        TEST_CHECK(libmpq__stream_open_name(archive, LIBMPQ_LISTFILE_NAME, &stream) == 0);
        TEST_CHECK(libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0);
        TEST_CHECK(transferred == (libmpq__off_t)wanted && memcmp(actual, content, wanted) == 0);
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        if (storage != 0) {
            TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, LIBMPQ_LISTFILE_NAME) == 0);
            for (uint32_t sector = 0; sector < libmpq__reader_count_file_blocks(archive, number);
                 ++sector) {
                uint32_t method;
                TEST_CHECK(libmpq__block_compression(archive, number, sector, &method) == 0);
                if (storage == 7 && sector == 0)
                    TEST_CHECK(method == 0);
                TEST_CHECK(
                    method == 0 ||
                    method == (storage == 4 ? LIBMPQ_COMPRESSION_PKZIP : LIBMPQ_COMPRESSION_ZLIB)
                );
            }
            TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
        }
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.filetime == UINT64_MAX);
        TEST_CHECK(attributes.crc32 == (uint32_t)crc32(0, content, (uInt)wanted));
        mpq_md5_s md5;
        uint8_t digest[16];
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, content, wanted);
        libmpq__md5_final(&md5, digest);
        TEST_CHECK(memcmp(attributes.md5, digest, 16) == 0);
        uint32_t mismatches;
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &mismatches) == 0 &&
            mismatches == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        uint8_t *stage;
        size_t stage_size;
        TEST_CHECK(read_bytes(libmpq__update_path(update), &stage, &stage_size) == 0);
        TEST_CHECK(libmpq__update_compact(update) == 0);
        uint8_t *again;
        size_t again_size;
        TEST_CHECK(read_bytes(libmpq__update_path(update), &again, &again_size) == 0);
        TEST_CHECK(stage_size == again_size && memcmp(stage, again, stage_size) == 0);
        free(stage);
        free(again);
        TEST_CHECK(libmpq__update_commit(update) == 0);
    }
    if (storage == 5) {
        uint8_t *after;
        size_t after_size;
        TEST_CHECK(read_bytes(path, &after, &after_size) == 0);
        TEST_CHECK(after_size == snapshot_size && memcmp(after, snapshot, after_size) == 0);
        free(after);
    }
    free(snapshot);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Reuse the signer to cover a synthetic HM3W prefix, without enabling embedded signing. */
static int
test_compact_hm3w_sign(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_s signer = { 0 };
    uint32_t number;
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_SIGNATURE_NAME, &number) == 0);
    signer.write_signature_offset = (uint64_t)archive->archive_offset +
                                    archive->mpq_entry[archive->mpq_map[number].entry_index].offset;
    uint64_t end = (uint64_t)archive->archive_offset +
                   libmpq__header_archive_size(&archive->mpq_header, &archive->mpq_header_v3);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    signer.fp = libmpq__file_open(path, "r+b");
    TEST_CHECK(signer.fp != NULL);
    signer.write_signature = signer.write_strong_signature = 1;
    memcpy(
        signer.write_signature_key, test_signature_private_key, sizeof(test_signature_private_key)
    );
    test_strong_signature_private_key(signer.write_strong_signature_key);
    TEST_CHECK(libmpq__signature_finish(&signer, end) == 0);
    TEST_CHECK(fclose(signer.fp) == 0);
    return 0;
}

/* No-op compaction retains valid signatures; physical changes invalidate old trust. */
static int
test_compaction_signatures(int fragmented, unsigned form)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_1, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char stage[512];
    uint32_t signatures;
    uint64_t origin;
    uint8_t prefix[4096] = { 0 };
    uint8_t strong_key[512];
    test_strong_signature_private_key(strong_key);
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-signed") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-signed-before") == 0);
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
    if (fragmented)
        TEST_CHECK(
            libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0
        );
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    if (form == 6)
        TEST_CHECK(test_compact_hm3w_sign(path) == 0);
    TEST_CHECK(copy_file(path, stage) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_rename_identity(update, "voice", "VOICE", 0, 0) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "voice", 0, 0, 0, 0) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    const char *bad_names[] = { "voice", "missing" };
    TEST_CHECK(libmpq__update_compact_ex(update, bad_names, 2) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    if (!fragmented) {
        const char *ignored_names[] = { NULL };
        const char *valid_names[] = { "voice", LIBMPQ_SIGNATURE_NAME };
        TEST_CHECK(libmpq__update_compact_ex(update, NULL, 0) == 0);
        TEST_CHECK(libmpq__update_compact_ex(update, ignored_names, 0) == 0);
        TEST_CHECK(libmpq__update_compact_ex(update, valid_names, 2) == 0);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
    }
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage) == !fragmented);
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    TEST_CHECK(
        fragmented ? signatures == 0
                   : signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG)
    );
    if (!fragmented) {
        uint32_t mismatch;
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                sizeof(test_signature_public_key), &mismatch
            ) == 0 &&
            mismatch == 0
        );
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mismatch
            ) == 0 &&
            mismatch == 0
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(same_file(path, stage) == !fragmented);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "voice", (const uint8_t *)"changed", 7, NULL) == 0
    );
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0 && signatures == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(stage) == 0);
    return 0;
}

/* Existing flush/close hooks exercise semantic rejection and the abort-only adoption boundary. */
static int
test_compaction_failure(uint32_t version, int closing, unsigned form)
{
    mpq_archive_create_options_s create = { version, 4, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char before[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-fault") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "compact-fault-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-fault-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    uint64_t origin;
    uint8_t prefix[4096];
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    libmpq__update_set_ops(
        update, &(mpq_update_ops_s){ closing ? fflush : fail_flush, closing ? fail_close : fclose,
                                     fail_publish, malloc }
    );
    TEST_CHECK(
        libmpq__update_compact(update) == (closing ? LIBMPQ_ERROR_CLOSE : LIBMPQ_ERROR_WRITE)
    );
    TEST_CHECK(same_file(path, before) && same_file(libmpq__update_path(update), stage));
    if (closing)
        TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, before));
    TEST_CHECK(remove(path) == 0 && remove(before) == 0 && remove(stage) == 0);
    return 0;
}

/* Stored ADPCM streams survive relocation without another lossy encoding pass. */
static int
test_compaction_adpcm(uint32_t version, unsigned form, int extended)
{
    mpq_archive_create_options_s create = { version, 4, 512,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                   LIBMPQ_COMPRESSION_WAVE_MONO, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t input[1508];
    uint8_t decoded[1508];
    uint8_t actual[1508];
    uint8_t stored[2048];
    uint8_t output[2048];
    char path[512];
    uint32_t number;
    uint64_t origin;
    uint8_t prefix[4096] = { 0 };
    uint32_t method;
    libmpq__off_t got;
    memset(input, 0, sizeof(input));
    memcpy(input, "RIFF", 4);
    libmpq__store_le32(input + 4, sizeof(input) - 8);
    memcpy(input + 8, "WAVEfmt ", 8);
    libmpq__store_le32(input + 16, 16);
    libmpq__store_le16(input + 20, 1);
    libmpq__store_le16(input + 22, 1);
    libmpq__store_le32(input + 24, 22050);
    libmpq__store_le32(input + 28, 44100);
    libmpq__store_le16(input + 32, 2);
    libmpq__store_le16(input + 34, 16);
    memcpy(input + 36, "data", 4);
    libmpq__store_le32(input + 40, sizeof(input) - 44);
    for (size_t i = 44; i < sizeof(input); i += 2)
        libmpq__store_le16(input + i, (uint16_t)(((int)(i % 101) - 50) * 317));
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-adpcm") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "audio", input, sizeof(input), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "audio", &number) == 0);
    const mpq_entry_s before = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(before.packed_size <= sizeof(stored));
    TEST_CHECK(
        libmpq__block_compression(archive, number, 1, &method) == 0 &&
        method == LIBMPQ_COMPRESSION_WAVE_MONO
    );
    TEST_CHECK(
        libmpq__file_read(archive, number, decoded, sizeof(decoded), &got) == 0 &&
        got == sizeof(decoded)
    );
    TEST_CHECK(memcmp(decoded, input, sizeof(input)) != 0);
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + before.offset, stored, before.packed_size
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    if (form == 0 && extended) {
        const mpq_update_replace_range_s range = { 600, (const uint8_t *)"x", 1 };
        TEST_CHECK(
            libmpq__update_replace_ranges_identity(update, "audio", 0, 0, &range, 1) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(path, libmpq__update_path(update)));
    }
    const char *hint[] = { "audio" };
    TEST_CHECK(
        (extended ? libmpq__update_compact_ex(update, hint, 1) : libmpq__update_compact(update)) ==
        0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "audio", &number) == 0);
    const mpq_entry_s after = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(after.offset < before.offset && after.packed_size == before.packed_size);
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + after.offset, output, after.packed_size) ==
        0
    );
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(memcmp(stored, output, after.packed_size) == 0);
    TEST_CHECK(
        libmpq__file_read(archive, number, actual, sizeof(actual), &got) == 0 &&
        got == sizeof(actual)
    );
    TEST_CHECK(memcmp(decoded, actual, sizeof(decoded)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    return 0;
}

/* Unknown KEY bytes stay intact on no-ops and metadata-only relocation. */
static int
test_compact_embedded_noop(uint32_t version, int wrapped, int gap)
{
    mpq_archive_create_options_s create = { version, 4, 512, 0, 0 };
    mpq_file_options_s options = {
        LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY | LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0
    };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char before[512];
    char stage[512];
    uint8_t prefix[4096];
    uint64_t origin;
    TEST_CHECK(test_temp_path(path, sizeof(path), "embedded-noop") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "embedded-noop-before") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, "opaque", (const uint8_t *)"data", 4, &options) == 0
    );
    if (gap)
        TEST_CHECK(
            libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0
        );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, 5, wrapped, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    uint32_t number;
    uint8_t stored[4];
    TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
    uint64_t relative = archive->mpq_entry[archive->mpq_map[number].entry_index].offset;
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + relative, stored, sizeof(stored)) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        snprintf(stage, sizeof(stage), "%s", libmpq__update_path(update)) < (int)sizeof(stage)
    );
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK((strcmp(stage, libmpq__update_path(update)) == 0) == !gap);
    TEST_CHECK(
        snprintf(stage, sizeof(stage), "%s", libmpq__update_path(update)) < (int)sizeof(stage)
    );
    TEST_CHECK(
        libmpq__update_compact(update) == 0 && strcmp(stage, libmpq__update_path(update)) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0 && same_file(path, before) == !gap);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    TEST_CHECK(test_compact_prefix(archive, 5, prefix, origin) == 0);
    TEST_CHECK(check_named(archive, "opaque", (const uint8_t *)"data", 4) == 0);
    TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
    TEST_CHECK(archive->mpq_entry[archive->mpq_map[number].entry_index].offset == relative);
    uint8_t actual[4];
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + relative, actual, sizeof(actual)) == 0
    );
    TEST_CHECK(memcmp(stored, actual, sizeof(stored)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(before) == 0);
    return 0;
}

/* Public begin rejects undiscoverable or contradictory wrappers without touching the source. */
static int
test_compact_bad_prefix(unsigned kind)
{
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_archive_create_options_s create = { 0, 4, 512, 0, 0 };
    char path[512] = { 0 };
    uint8_t *mpq = NULL;
    uint8_t *bytes = NULL;
    uint8_t *after = NULL;
    int result = 1;
    size_t size;
    UPDATE_CHECK(test_temp_path(path, sizeof(path), "embedded-bad-prefix") == 0);
    UPDATE_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    UPDATE_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    int32_t status = libmpq__archive_close(archive);
    archive = NULL;
    UPDATE_CHECK(status == 0);
    UPDATE_CHECK(read_bytes(path, &mpq, &size) == 0);
    size_t origin = kind == 0 ? 17 : 96;
    bytes = calloc(1, origin + size);
    UPDATE_CHECK(bytes != NULL);
    memcpy(bytes + origin, mpq, size);
    free(mpq);
    mpq = NULL;
    if (kind != 0) {
        libmpq__store_le32(bytes, LIBMPQ_USER_DATA_HEADER);
        libmpq__store_le32(bytes + 4, kind == 1 ? 97 : 32);
        libmpq__store_le32(bytes + 8, kind == 2 ? UINT32_MAX : kind == 3 ? 8 : kind == 4 ? 95 : 96);
        libmpq__store_le32(bytes + 12, kind == 5 ? 33 : 16);
        if (kind == 6)
            libmpq__store_le32(bytes + origin, LIBMPQ_USER_DATA_HEADER);
    }
    UPDATE_CHECK(write_bytes(path, bytes, origin + size) == 0);
    UPDATE_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_ERROR_FORMAT && update == NULL);
    size_t after_size;
    UPDATE_CHECK(read_bytes(path, &after, &after_size) == 0);
    UPDATE_CHECK(after_size == origin + size && memcmp(bytes, after, after_size) == 0);
    UPDATE_CHECK(remove(path) == 0);
    result = 0;
fail:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (update != NULL)
        (void)libmpq__update_abort(update);
    free(mpq);
    free(bytes);
    free(after);
    if (result != 0 && path[0] != 0)
        (void)remove(path);
    return result;
}

/* Unsupported wrappers, physical patches and corrupt raw storage never replace the stage. */
static int
test_compaction_rejection(unsigned kind)
{
    mpq_archive_create_options_s create = { kind == 3 ? LIBMPQ_ARCHIVE_VERSION_4
                                                      : LIBMPQ_ARCHIVE_VERSION_1,
                                            4, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    char before[512];
    char stage[512];
    uint8_t image[16384];
    size_t size;
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-reject") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "compact-reject-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-reject-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (kind == 3)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, 17) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    if (kind == 2) {
        archive->write_patch_mode = 1;
        TEST_CHECK(libmpq__writer_patch_delete_marker(archive, "deleted", 0, 0) == 0);
    }
    if (kind == 5) {
        uint8_t malformed[8] = { 99, 0, 0, 0, 0, 0, 0, 0 };
        archive->write_internal = 1;
        TEST_CHECK(
            libmpq__writer_file_add(
                archive, LIBMPQ_ATTRIBUTES_NAME, malformed, sizeof(malformed), NULL
            ) == 0
        );
        archive->write_internal = 0;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    FILE *input = libmpq__file_open(path, "rb");
    TEST_CHECK(input != NULL);
    size = fread(image, 1, sizeof(image), input);
    int closed = fclose(input);
    TEST_CHECK(closed == 0 && size < sizeof(image));
    if (kind == 0) {
        uint8_t embedded[sizeof(image) + 518] = { 0 };
        memcpy(embedded + 512, image, size);
        memcpy(embedded + 512 + size, "suffix", 6);
        TEST_CHECK(write_bytes(path, embedded, size + 518) == 0);
    } else if (kind == 1) {
        FILE *file = libmpq__file_open(path, "ab");
        TEST_CHECK(file != NULL && fwrite("trailer", 1, 7, file) == 7 && fclose(file) == 0);
    } else if (kind == 3) {
        TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
        uint32_t number;
        TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(entry->offset + entry->packed_size < size);
        image[entry->offset + entry->packed_size] ^= 1;
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(write_bytes(path, image, size) == 0);
    }
    if (kind == 4) {
        uint32_t offset = libmpq__load_le32(image + 20);
        uint32_t bytes = libmpq__load_le32(image + 28) * 16;
        uint32_t key = libmpq__crypto_hash_string("(block table)", 0x300);
        TEST_CHECK(offset <= size && bytes <= size - offset);
        TEST_CHECK(libmpq__crypto_decrypt_block(image + offset, bytes, key) == 0);
        libmpq__store_le32(image + offset, libmpq__load_le32(image + 16));
        TEST_CHECK(libmpq__crypto_encrypt_block(image + offset, bytes, key) == 0);
        TEST_CHECK(write_bytes(path, image, size) == 0);
    }
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    uint8_t signing_key[512];
    test_strong_signature_private_key(signing_key);
    TEST_CHECK(
        libmpq__update_sign(update, LIBMPQ_SIGNATURE_STRONG, signing_key, sizeof(signing_key)) ==
        (kind == 3 ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    libmpq__rsa_clear(signing_key, sizeof(signing_key));
    TEST_CHECK(
        libmpq__update_sign(
            update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == (kind == 3 ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(
        libmpq__update_compact(update) == (kind == 3 ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    const char *external[] = { "voice" };
    const char *ignored_names[] = { NULL };
    TEST_CHECK(
        libmpq__update_compact_ex(update, NULL, 0) ==
        (kind == 3 ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(
        libmpq__update_compact_ex(update, ignored_names, 0) ==
        (kind == 3 ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(
        libmpq__update_compact_ex(update, external, 1) ==
        (kind == 3 ? LIBMPQ_ERROR_READ : LIBMPQ_ERROR_FORMAT)
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, before));
    TEST_CHECK(remove(path) == 0 && remove(before) == 0 && remove(stage) == 0);
    return 0;
}

/* A single known spelling supplies keys for distinct qualified physical payloads. */
static int
test_compaction_qualified(uint32_t version, unsigned form, int extended)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0,
                                            LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 |
                                                LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint64_t origin;
    uint8_t prefix[4096] = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s hashes[16];
    uint32_t name_hash[3];
    uint8_t payload[1508];
    uint8_t actual[1508];
    char path[512];
    memset(payload, 'N', sizeof(payload));
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-qualified") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "left/voice", payload, sizeof(payload), &options) == 0
    );
    memset(payload, 'L', sizeof(payload));
    TEST_CHECK(
        libmpq__archive_add_data(archive, "right/voice", payload, sizeof(payload), &options) == 0
    );
    archive->write_attributes[0].filetime = 11;
    archive->write_attributes[1].filetime = 22;
    archive->write_internal = 1;
    TEST_CHECK(
        libmpq__writer_file_add(
            archive, LIBMPQ_LISTFILE_NAME, (const uint8_t *)"left/voice\n", 11, NULL
        ) == 0
    );
    archive->write_internal = 0;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(test_v4_source_layout(path, 1) == 0);
    else if (version == LIBMPQ_ARCHIVE_VERSION_3) {
        FILE *file = libmpq__file_open(path, "r+b");
        uint8_t zero[16] = { 0 };
        TEST_CHECK(file != NULL && libmpq__file_seek(file, 52, SEEK_SET) == 0);
        TEST_CHECK(fwrite(zero, 1, sizeof(zero), file) == sizeof(zero) && fclose(file) == 0);
    }
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    memcpy(hashes, archive->mpq_hash, sizeof(hashes));
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    libmpq__file_hash("left/voice", &name_hash[0], &name_hash[1], &name_hash[2]);
    for (uint32_t slot = 0; slot < 16; ++slot)
        if (hashes[slot].block_table_index == 1)
            hashes[slot] = (mpq_hash_s){ name_hash[1], name_hash[2], 0x409, 2, 1 };

    /* The first lookup already reaches this row before encountering a never-used slot. */
    uint32_t target = name_hash[0] & 15;
    uint32_t localized = target;
    while (hashes[localized].block_table_index != 1 &&
           hashes[localized].block_table_index < LIBMPQ_HASH_DELETED)
        localized = (localized + 1) & 15;
    if (hashes[localized].block_table_index != 1) {
        uint32_t old = 0;
        while (hashes[old].block_table_index != 1)
            ++old;
        hashes[old].block_table_index = LIBMPQ_HASH_DELETED;
        hashes[localized] = (mpq_hash_s){ name_hash[1], name_hash[2], 0x409, 2, 1 };
    }
    TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    const char *hint[] = { "left/voice" };
    TEST_CHECK(
        (extended ? libmpq__update_compact_ex(update, hint, 1) : libmpq__update_compact(update)) ==
        0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    for (unsigned identity = 0; identity < 2; ++identity) {
        mpq_stream_s *stream = NULL;
        mpq_file_attributes_s attributes;
        uint32_t number;
        libmpq__off_t got;
        TEST_CHECK(
            libmpq__file_number_from_identity(
                archive, "left/voice", identity ? 0x409 : 0, identity ? 2 : 0, &number
            ) == 0
        );
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.filetime == (identity ? 22u : 11u));
        TEST_CHECK(
            libmpq__stream_open_name_identity(
                archive, "left/voice", identity ? 0x409 : 0, identity ? 2 : 0, &stream
            ) == 0
        );
        TEST_CHECK(
            libmpq__stream_read(stream, actual, sizeof(actual), &got) == 0 && got == sizeof(actual)
        );
        memset(payload, identity ? 'L' : 'N', sizeof(payload));
        TEST_CHECK(memcmp(actual, payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__stream_close(stream) == 0);
    }
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(memcmp(hashes, archive->mpq_hash, sizeof(hashes)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    return 0;
}

/* Reader caches use public numbers even when deleted classic rows leave canonical holes. */
static int
test_compaction_cache_mapping(uint32_t version, int single)
{
    mpq_archive_create_options_s create = { version, 8, single ? 4096u : 512u,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 |
                                                LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[1508];
    char path[512];
    uint32_t number;
    test_payload(payload, sizeof(payload), 39);
    if (single)
        options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-cache-mapping") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "discard", payload, 16, NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", payload, sizeof(payload), &options) == 0);
    archive->write_attributes[1].filetime = 42;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        libmpq__update_begin(&update, path) == 0 && libmpq__update_remove(update, "discard") == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0 && number == 0);
    TEST_CHECK(archive->mpq_map[number].entry_index == 1);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0 && libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(test_compact_dense(archive) == 0);
    TEST_CHECK(check_named(archive, "voice", payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    mpq_file_attributes_s attributes;
    TEST_CHECK(
        libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 42
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    return 0;
}

/* Signature presence is separate from verification with the deterministic matching public keys. */
static int
test_update_signed(
    const char *path, uint32_t expected, unsigned form, const uint8_t *prefix, uint64_t origin
)
{
    mpq_archive_s *archive = NULL;
    uint32_t types;
    uint32_t mismatches;
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &types) == 0 && types == expected);
    if (types & LIBMPQ_SIGNATURE_WEAK) {
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                sizeof(test_signature_public_key), &mismatches
            ) == 0 &&
            mismatches == 0
        );
        uint8_t wrong[128];
        memcpy(wrong, test_signature_public_key, sizeof(wrong));
        memset(wrong + 64, 0, 64);
        wrong[127] = 3;
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_WEAK, wrong, sizeof(wrong), &mismatches
            ) == 0 &&
            mismatches == LIBMPQ_SIGNATURE_WEAK
        );
        uint32_t number;
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, LIBMPQ_SIGNATURE_NAME, 0, 0, &number) == 0
        );
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(
            entry->packed_size == 72 && entry->unpacked_size == 72 &&
            (entry->flags & ~(LIBMPQ_FLAG_EXISTS | LIBMPQ_FILE_FLAG_SINGLE)) == 0
        );
        if (archive->attributes != NULL || libmpq__attributes_load(archive) == 0) {
            mpq_file_attributes_s attributes;
            const uint8_t zero[16] = { 0 };
            TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
            TEST_CHECK(
                attributes.crc32 == 0 && attributes.filetime == 0 &&
                memcmp(attributes.md5, zero, sizeof(zero)) == 0
            );
        }
    }
    if (types & LIBMPQ_SIGNATURE_STRONG)
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mismatches
            ) == 0 &&
            mismatches == 0
        );
    for (uint32_t i = 0; i < archive->files; ++i)
        TEST_CHECK(
            libmpq__file_verify(archive, i, LIBMPQ_VERIFY_RAW_MD5, &mismatches) == 0 &&
            mismatches == 0
        );
    if (archive->het_data != NULL && archive->mpq_header_v4.raw_chunk_size != 0) {
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_HET_SIGNATURE) == 0);
        TEST_CHECK(libmpq__reader_verify_ext_raw_md5(archive, LIBMPQ_BET_SIGNATURE) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Sign finalized embedded candidates directly before any transaction adopts them. */
static int
test_update_sign_ranges(unsigned form)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_1, 4, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    uint8_t strong[512];
    char path[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "sign-ranges") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    FILE *file = libmpq__file_open(path, "r+b");
    TEST_CHECK(file != NULL);
    TEST_CHECK(
        libmpq__signature_sign_file(
            archive, file, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(fclose(file) == 0 && libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_update_signed(path, LIBMPQ_SIGNATURE_WEAK, form, prefix, origin) == 0);
    test_strong_signature_private_key(strong);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    file = libmpq__file_open(path, "r+b");
    TEST_CHECK(file != NULL);
    TEST_CHECK(
        libmpq__signature_sign_file(
            archive, file, LIBMPQ_SIGNATURE_STRONG, strong, sizeof(strong)
        ) == 0
    );
    TEST_CHECK(fclose(file) == 0 && libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        test_update_signed(
            path, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG, form, prefix, origin
        ) == 0
    );
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Pinned unknown KEY bytes, listfile policy and FILETIME survive signature ordering. */
static int
test_update_signing(uint32_t version, uint32_t raw, unsigned form, int wrapped, unsigned storage)
{
    mpq_archive_create_options_s create = { version, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                            LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 |
                                                LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                       LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_KEY,
                                   LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_file_options_s list_options = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_writer_s *member = NULL;
    uint8_t payload[1025];
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    uint8_t list[1024];
    size_t list_size = 0;
    static const uint8_t line[] = "folder\\voice.bin\r\n\r\nother\n";
    uint8_t packed[2048];
    uint8_t actual[2048];
    mpq_entry_s original;
    uint8_t strong[512];
    char path[512];
    char before[512];
    char stage[512];
    uint32_t number;
    uint32_t mismatch;
    int32_t result;
    test_payload(payload, sizeof(payload), 57);
    test_strong_signature_private_key(strong);
    for (unsigned i = 0; i < 12; ++i) {
        memcpy(list + list_size, line, sizeof(line) - 1);
        list_size += sizeof(line) - 1;
    }
    if (storage != 0) {
        list_options.flags = LIBMPQ_FILE_FLAG_COMPRESS;
        list_options.compression_first = list_options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
        if (storage > 1)
            list_options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
        if (storage > 2)
            list_options.flags |= LIBMPQ_FILE_FLAG_KEY | LIBMPQ_FILE_FLAG_SINGLE;
    }
    TEST_CHECK(test_temp_path(path, sizeof(path), "update-sign") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "update-sign-before") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "update-sign-stage") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, raw) == 0);
    TEST_CHECK(
        libmpq__writer_begin(archive, "folder/voice.bin", sizeof(payload), &options, &member) == 0
    );
    TEST_CHECK(libmpq__writer_timestamp(member, 91) == 0);
    TEST_CHECK(
        libmpq__writer_write(member, payload, sizeof(payload)) == 0 &&
        libmpq__writer_finish(member) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"other", 5, NULL) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, LIBMPQ_LISTFILE_NAME, list, list_size, &list_options) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, wrapped, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "folder/voice.bin", &number) == 0);
    original = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(original.packed_size <= sizeof(packed));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + original.offset, packed, (size_t)original.packed_size
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_sign(
            update, 0, test_signature_private_key, sizeof(test_signature_private_key)
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__update_sign(update, LIBMPQ_SIGNATURE_WEAK, NULL, 128) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__update_sign(update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key, 127) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    if (raw != 0 || wrapped) {
        result = libmpq__update_sign(
            update, raw ? LIBMPQ_SIGNATURE_WEAK : LIBMPQ_SIGNATURE_STRONG,
            raw ? test_signature_private_key : strong,
            raw ? sizeof(test_signature_private_key) : sizeof(strong)
        );
        TEST_CHECK(result == LIBMPQ_ERROR_FORMAT && same_file(libmpq__update_path(update), stage));
    }
    if (raw == 0) {
        TEST_CHECK(
            libmpq__update_sign(
                update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
        TEST_CHECK(
            test_update_signed(
                libmpq__update_path(update), LIBMPQ_SIGNATURE_WEAK, form, prefix, origin
            ) == 0
        );
        TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        TEST_CHECK(libmpq__update_timestamp(update, "folder/voice.bin", 91) == 0);
        TEST_CHECK(
            libmpq__update_rename_identity(update, "folder/voice.bin", "FOLDER\\VOICE.BIN", 0, 0) ==
            0
        );
        TEST_CHECK(libmpq__update_change_identity(update, "folder/voice.bin", 0, 0, 0, 0) == 0);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        uint8_t bad[128];
        memcpy(bad, test_signature_private_key, sizeof(bad));
        memset(bad + 64, 0, 64);
        bad[127] = 3;
        TEST_CHECK(libmpq__update_sign(update, LIBMPQ_SIGNATURE_WEAK, bad, sizeof(bad)) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                sizeof(test_signature_public_key), &mismatch
            ) == 0 &&
            mismatch == LIBMPQ_SIGNATURE_WEAK
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(
            libmpq__update_sign(
                update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
        libmpq__rsa_clear(bad, sizeof(bad));
    }
    if (!wrapped) {
        TEST_CHECK(
            libmpq__update_sign(update, LIBMPQ_SIGNATURE_STRONG, strong, sizeof(strong)) == 0
        );
        TEST_CHECK(
            test_update_signed(
                libmpq__update_path(update),
                LIBMPQ_SIGNATURE_STRONG | (raw == 0 ? LIBMPQ_SIGNATURE_WEAK : 0), form, prefix,
                origin
            ) == 0
        );
        TEST_CHECK(
            libmpq__update_sign(update, LIBMPQ_SIGNATURE_STRONG, strong, sizeof(strong)) == 0
        );
        if (raw == 0) {
            TEST_CHECK(
                libmpq__update_sign(
                    update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                    sizeof(test_signature_private_key)
                ) == 0
            );
            TEST_CHECK(
                test_update_signed(
                    libmpq__update_path(update), LIBMPQ_SIGNATURE_WEAK, form, prefix, origin
                ) == 0
            );
        }
    }
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(libmpq__file_number_from_identity(archive, "folder/voice.bin", 0, 0, &number) == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        entry->offset == original.offset && entry->packed_size == original.packed_size &&
        entry->flags == original.flags
    );
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + entry->offset, actual, (size_t)entry->packed_size
        ) == 0
    );
    TEST_CHECK(memcmp(actual, packed, (size_t)entry->packed_size) == 0);
    TEST_CHECK(check_named(archive, "folder/voice.bin", payload, sizeof(payload)) == 0);
    mpq_file_attributes_s attributes;
    TEST_CHECK(
        libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 91
    );
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0);
    entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(entry->flags == (list_options.flags | LIBMPQ_FLAG_EXISTS));
    uint8_t decoded[2048];
    libmpq__off_t decoded_size;
    libmpq__off_t received;
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &decoded_size) == 0);
    TEST_CHECK(
        decoded_size == (libmpq__off_t)(list_size + (raw == 0 ? sizeof(LIBMPQ_SIGNATURE_NAME) : 0))
    );
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, LIBMPQ_LISTFILE_NAME) == 0);
    TEST_CHECK(
        libmpq__file_read(archive, number, decoded, sizeof(decoded), &received) == 0 &&
        received == decoded_size
    );
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(memcmp(decoded, list, list_size) == 0);
    if (raw == 0)
        TEST_CHECK(
            memcmp(
                decoded + list_size, LIBMPQ_SIGNATURE_NAME "\n", sizeof(LIBMPQ_SIGNATURE_NAME)
            ) == 0
        );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(same_file(path, before));
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        test_update_signed(
            libmpq__update_path(update), raw == 0 ? LIBMPQ_SIGNATURE_WEAK : LIBMPQ_SIGNATURE_STRONG,
            form, prefix, origin
        ) == 0
    );
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(libmpq__update_timestamp(update, "folder/voice.bin", 92) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    uint32_t types;
    TEST_CHECK(libmpq__archive_signatures(archive, &types) == 0 && types == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, before));
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_sign(
            update, raw == 0 ? LIBMPQ_SIGNATURE_WEAK : LIBMPQ_SIGNATURE_STRONG,
            raw == 0 ? test_signature_private_key : strong,
            raw == 0 ? sizeof(test_signature_private_key) : sizeof(strong)
        ) == 0
    );
    libmpq__update_set_ops(update, &(mpq_update_ops_s){ fflush, fclose, fail_publish, malloc });
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, before));
    TEST_CHECK(remove(path) == 0 && remove(before) == 0 && remove(stage) == 0);
    libmpq__rsa_clear(strong, sizeof(strong));
    return 0;
}

/* Classic aliases stay shared; HET-only signing retains its stored provenance. */
static int
test_update_sign_layout(uint32_t version, unsigned layout, int failure)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t key[128];
    uint8_t prefix[4096] = { 0 };
    uint8_t strong[512];
    mpq_hash_s rows[16];
    uint32_t number;
    char path[512];
    char before[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "sign-layout") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "sign-layout-before") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "sign-layout-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, 0) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "chain-32", (const uint8_t *)"payload", 7, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(test_v4_source_layout(path, layout) == 0);
    if (version < LIBMPQ_ARCHIVE_VERSION_3 || layout == 1) {
        uint32_t hashes[3];
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(archive->mpq_header.hash_table_count == 16);
        memcpy(rows, archive->mpq_hash, sizeof(rows));
        TEST_CHECK(libmpq__file_number(archive, "chain-32", &number) == 0);
        uint32_t block =
            archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
        for (unsigned alias = 0; alias < 2; ++alias) {
            libmpq__file_hash(
                alias ? "unknown-alias" : "chain-32", &hashes[0], &hashes[1], &hashes[2]
            );
            uint32_t slot = hashes[0] & 15;
            while (rows[slot].block_table_index < LIBMPQ_HASH_DELETED)
                slot = (slot + 1) & 15;
            rows[slot] = (mpq_hash_s){ hashes[1], hashes[2], alias ? 0 : 1033, 2, block };
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(test_alias_table_write(path, rows, 0) == 0);
    }
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    memcpy(key, test_signature_private_key, sizeof(key));
    for (unsigned invalid = 0; invalid < 4; ++invalid) {
        memcpy(key, test_signature_private_key, sizeof(key));
        if (invalid == 0)
            key[0] = 0;
        if (invalid == 1)
            key[63] &= 0xfe;
        if (invalid == 2)
            memset(key + 64, 0, 64);
        if (invalid == 3)
            memcpy(key + 64, key, 64);
        TEST_CHECK(
            libmpq__update_sign(update, LIBMPQ_SIGNATURE_WEAK, key, sizeof(key)) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
    }
    libmpq__rsa_clear(key, sizeof(key));
    if (failure) {
        libmpq__update_set_ops(
            update, &(mpq_update_ops_s){ failure == 1 ? fail_flush : fflush,
                                         failure == 2 ? fail_close : fclose, fail_publish, malloc }
        );
        TEST_CHECK(
            libmpq__update_sign(
                update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == (failure == 1 ? LIBMPQ_ERROR_WRITE : LIBMPQ_ERROR_CLOSE)
        );
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        if (failure == 2)
            TEST_CHECK(
                libmpq__update_sign(
                    update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                    sizeof(test_signature_private_key)
                ) == LIBMPQ_ERROR_EXIST
            );
    } else {
        TEST_CHECK(
            libmpq__update_sign(
                update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
        test_strong_signature_private_key(strong);
        TEST_CHECK(
            libmpq__update_sign(update, LIBMPQ_SIGNATURE_STRONG, strong, sizeof(strong)) == 0
        );
        libmpq__rsa_clear(strong, sizeof(strong));
        TEST_CHECK(
            test_update_signed(
                libmpq__update_path(update), LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG, 0,
                prefix, 0
            ) == 0
        );
        TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), 0) == 0);
        TEST_CHECK(check_named(archive, "chain-32", (const uint8_t *)"payload", 7) == 0);
        if (version < LIBMPQ_ARCHIVE_VERSION_3 || layout == 1) {
            uint32_t alias;
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "chain-32", 1033, 2, &number) == 0
            );
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "unknown-alias", 0, 2, &alias) == 0 &&
                alias == number
            );
            for (uint32_t slot = 0; slot < 16; ++slot) {
                if (rows[slot].block_table_index < LIBMPQ_HASH_DELETED) {
                    TEST_CHECK(
                        archive->mpq_hash[slot].hash_a == rows[slot].hash_a &&
                        archive->mpq_hash[slot].hash_b == rows[slot].hash_b &&
                        archive->mpq_hash[slot].locale == rows[slot].locale &&
                        archive->mpq_hash[slot].platform == rows[slot].platform
                    );
                }
            }
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            test_update_signed(
                path, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG, 0, prefix, 0
            ) == 0
        );
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    }
    TEST_CHECK(libmpq__update_abort(update) == 0);
    if (failure)
        TEST_CHECK(same_file(path, before));
    TEST_CHECK(remove(path) == 0 && remove(before) == 0 && remove(stage) == 0);
    return 0;
}

/* Signing preserves learned key spellings for a later mutation or compaction. */
static int
test_update_sign_names(void)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 8, 512, 0, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    char path[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "sign-names") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "base", (const uint8_t *)"base", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_add_data(update, "secret", (const uint8_t *)"secret", 6, &options) == 0
    );
    TEST_CHECK(
        libmpq__update_sign(
            update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(check_named(archive, "secret", (const uint8_t *)"secret", 6) == 0);
    uint32_t signatures;
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0 && signatures == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    return 0;
}

/* Rewritten attributes retain their storage policy and physical-row associations. */
static int
test_update_sign_attributes(unsigned storage)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 8, 512,
                                            LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    const uint32_t flags =
        LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME;
    mpq_file_attributes_s attributes[2] = { { 0 } };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t *data = NULL;
    size_t size;
    uint8_t prefix[4096] = { 0 };
    char path[512];
    uint32_t number;
    TEST_CHECK(test_temp_path(path, sizeof(path), "sign-attributes") == 0);
    attributes[0].filetime = 91;
    attributes[0].crc32 = (uint32_t)crc32(0, (const uint8_t *)"payload", 7);
    mpq_md5_s md5;
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, (const uint8_t *)"payload", 7);
    libmpq__md5_final(&md5, attributes[0].md5);
    if (storage != 0) {
        options.flags = LIBMPQ_FILE_FLAG_COMPRESS;
        options.compression_first = options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
    }
    if (storage > 1)
        options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY;
    if (storage == 2)
        options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
    if (storage == 3)
        options.flags |= LIBMPQ_FILE_FLAG_SECTOR_CRC;
    TEST_CHECK(libmpq__attributes_serialize(attributes, 2, 1, flags, &data, &size) == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "voice", (const uint8_t *)"payload", 7, NULL) == 0
    );
    archive->write_internal = 1;
    TEST_CHECK(libmpq__writer_file_add(archive, LIBMPQ_ATTRIBUTES_NAME, data, size, &options) == 0);
    archive->write_internal = 0;
    free(data);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_sign(
            update, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(
        test_update_signed(libmpq__update_path(update), LIBMPQ_SIGNATURE_WEAK, 0, prefix, 0) == 0
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &number) == 0);
    TEST_CHECK(
        archive->mpq_entry[archive->mpq_map[number].entry_index].flags ==
        (options.flags | LIBMPQ_FLAG_EXISTS)
    );
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    mpq_file_attributes_s actual;
    TEST_CHECK(
        libmpq__file_attributes(archive, number, &actual) == 0 && actual.flags == flags &&
        actual.filetime == 91 && actual.crc32 == attributes[0].crc32 &&
        memcmp(actual.md5, attributes[0].md5, 16) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    return 0;
}

/* Provenance is owned by the transaction, re-resolved after every exact stage. */
static unsigned provenance_allocation;
static void *
fail_provenance_allocation(size_t size)
{
    if (provenance_allocation-- == 0)
        return NULL;
    return malloc(size);
}

static int
test_key_provenance(uint32_t version, unsigned form, int adjusted)
{
    mpq_archive_create_options_s create = { version, 16, 512, 0, LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0,
                                   0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[403];
    uint8_t encoded[403];
    uint8_t actual[403];
    uint8_t opaque[403];
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    uint32_t number;
    char path[512];
    char before[512];
    char stage[512];
    TEST_CHECK(LIBMPQ_FILE_FLAG_KEY == 0x00020000u);
    test_payload(payload, sizeof(payload), 43);
    TEST_CHECK(test_temp_path(path, sizeof(path), "key-provenance") == 0);
    TEST_CHECK(test_temp_path(before, sizeof(before), "key-provenance-before") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "key-provenance-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(libmpq__archive_raw_chunk_size_set(archive, 17) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "opaque", payload, sizeof(payload), &options) == 0
    );
    if (adjusted)
        options.flags |= LIBMPQ_FILE_FLAG_KEY;
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", payload, sizeof(payload), &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "other", payload, 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, 0, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, before) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
    mpq_entry_s entry = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + entry.offset, opaque, sizeof(opaque)) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(
        libmpq__update_replace_data(update, "voice", payload, sizeof(payload), &options) == 0
    );
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "other", 0, 0, 0, 0) == 0);
    TEST_CHECK(libmpq__update_rename_identity(update, "voice", "voice", 0, 0) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "voice", 0, 0, 0) == 0);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    if (version == LIBMPQ_ARCHIVE_VERSION_3 && form == 0 && adjusted) {
        const mpq_update_ops_s *original_ops = libmpq__update_ops(update);
        mpq_update_ops_s ops = *original_ops;
        ops.allocate_names = fail_provenance_allocation;
        for (unsigned failure = 0; failure < 3; ++failure) {
            provenance_allocation = failure;
            libmpq__update_set_ops(update, &ops);
            TEST_CHECK(
                libmpq__update_change_identity(update, "other", 0, 0, 1033, 2) ==
                LIBMPQ_ERROR_MALLOC
            );
            TEST_CHECK(same_file(libmpq__update_path(update), stage) && same_file(path, before));
            libmpq__update_set_ops(update, original_ops);
            TEST_CHECK(libmpq__update_compact(update) == 0);
            TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        }
        libmpq__update_set_ops(update, original_ops);
    }
    TEST_CHECK(libmpq__update_change_identity(update, "other", 0, 0, 1033, 2) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__update_rename_identity(update, "voice", "voice2", 0, 0) == 0);
    TEST_CHECK(libmpq__update_timestamp_identity(update, "other", 1033, 2, 99) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__update_change_identity(update, "other", 1033, 2, 1041, 3) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "other", 1033, 2) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_add_data(update, "voice", payload, 4, NULL) == 0);
    TEST_CHECK(libmpq__update_remove_identity(update, "voice", 0, 0) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_compact(update) == 0 && same_file(libmpq__update_path(update), stage)
    );
    TEST_CHECK(same_file(path, before));
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(check_named(archive, "voice2", payload, sizeof(payload)) == 0);
    TEST_CHECK(check_named(archive, "opaque", payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number_from_identity(archive, "other", 1041, 3, &number) == 0);
    mpq_file_attributes_s attributes;
    TEST_CHECK(
        libmpq__file_attributes(archive, number, &attributes) == 0 && attributes.filetime == 99
    );
    TEST_CHECK(libmpq__file_number(archive, "opaque", &number) == 0);
    entry = archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + entry.offset, actual, sizeof(actual)) == 0
    );
    TEST_CHECK(memcmp(actual, opaque, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice2", &number) == 0);
    entry = archive->mpq_entry[archive->mpq_map[number].entry_index];
    uint32_t key = libmpq__crypto_file_key("voice2");
    if (adjusted)
        key = (key + (uint32_t)entry.offset) ^ (uint32_t)sizeof(payload);
    memcpy(encoded, payload, sizeof(encoded));
    TEST_CHECK(libmpq__crypto_encrypt_block(encoded, sizeof(encoded), key) == 0);
    TEST_CHECK(
        libmpq__source_read_at(archive->source, origin + entry.offset, actual, sizeof(actual)) == 0
    );
    TEST_CHECK(memcmp(actual, encoded, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(before) == 0 && remove(stage) == 0);
    return 0;
}

/* Fresh synthetic stages keep filename-input tests independent of listfile coverage. */
static int
test_compact_ex_create(
    const char *path, uint32_t version, unsigned form, int wrapped, unsigned storage,
    const uint8_t *payload, size_t size, uint8_t prefix[4096], uint64_t *origin
)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0,
                                            LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_CRC32 |
                                                LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;
    options.flags |= storage == 1 ? LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC
                                  : LIBMPQ_FILE_FLAG_SINGLE;
    if (storage != 2)
        options.flags |= LIBMPQ_FILE_FLAG_KEY;
    if (storage == 1)
        options.compression_first = options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
    if (storage == 3) {
        options.locale = 1033;
        options.platform = 2;
    }
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(
            libmpq__archive_raw_chunk_size_set(
                archive, storage == 3   ? 0
                         : storage == 4 ? 0x4000
                                        : 17
            ) == 0
        );
    TEST_CHECK(libmpq__archive_add_data(archive, "other", (const uint8_t *)"keep", 4, NULL) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", payload, size, &options) == 0);
    archive->write_attributes[1].filetime = 42;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, wrapped, prefix, origin) == 0);
    return 0;
}

/* Borrowed arrays are atomic, and zero-count calls use precisely the original route. */
static int
test_compact_ex(uint32_t version, unsigned form, int wrapped, unsigned storage)
{
    uint8_t payload[1508];
    uint8_t stored[2048];
    uint8_t actual[2048];
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    size_t size = storage == 1 ? sizeof(payload) : 403;
    char path[512];
    char source[512];
    char stage[512];
    char zero[512];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint32_t number;
    test_payload(payload, sizeof(payload), 43);
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-ex") == 0);
    TEST_CHECK(test_temp_path(source, sizeof(source), "compact-ex-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-ex-stage") == 0);
    TEST_CHECK(test_temp_path(zero, sizeof(zero), "compact-ex-zero") == 0);
    TEST_CHECK(
        test_compact_ex_create(
            path, version, form, wrapped, storage, payload, size, prefix, &origin
        ) == 0
    );
    TEST_CHECK(copy_file(path, source) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    mpq_entry_s before = archive->mpq_entry[archive->mpq_map[number].entry_index];
    mpq_file_attributes_s attributes;
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(before.packed_size <= sizeof(stored));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + before.offset, stored, before.packed_size
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    const char *ignored[] = { NULL };
    for (unsigned mode = 0; mode < 3; ++mode) {
        TEST_CHECK(
            (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                     : libmpq__update_begin(&update, path)) == 0
        );
        char *previous = libmpq__string_duplicate(libmpq__update_path(update));
        TEST_CHECK(previous != NULL);
        int32_t status = mode == 0
                             ? libmpq__update_compact(update)
                             : libmpq__update_compact_ex(update, mode == 1 ? NULL : ignored, 0);
        TEST_CHECK(status == (storage == 2 ? 0 : LIBMPQ_ERROR_DECRYPT));
        TEST_CHECK((strcmp(previous, libmpq__update_path(update)) == 0) == (storage != 2));
        free(previous);
        if (mode == 0)
            TEST_CHECK(copy_file(libmpq__update_path(update), zero) == 0);
        else
            TEST_CHECK(same_file(libmpq__update_path(update), zero));
        TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, source));
    }
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_compact_ex(NULL, NULL, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_compact_ex(update, NULL, 1) == LIBMPQ_ERROR_EXIST);
    const char *invalid[][2] = { { "voice", NULL }, { "voice", "" }, { "voice", "missing" } };
    for (unsigned i = 0; i < 3; ++i) {
        TEST_CHECK(libmpq__update_compact_ex(update, invalid[i], 2) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        if (storage != 2)
            TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_DECRYPT);
    }
    const char *one[] = { "voice" };
    TEST_CHECK(libmpq__update_compact_ex(update, one, SIZE_MAX) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__update_compact_ex(update, one, UINT32_MAX) == LIBMPQ_ERROR_SIZE);
#if SIZE_MAX > UINT32_MAX
    TEST_CHECK(libmpq__update_compact_ex(update, one, (size_t)UINT32_MAX + 1) == LIBMPQ_ERROR_SIZE);
#endif
    char *name = libmpq__string_duplicate("voice");
    TEST_CHECK(name != NULL);
    const char *names[] = { name, "VOICE", name, LIBMPQ_ATTRIBUTES_NAME };
    TEST_CHECK(libmpq__update_compact_ex(update, names, 4) == 0);
    memset(name, 'x', 5);
    free(name);
    TEST_CHECK(!same_file(libmpq__update_path(update), stage) && same_file(path, source));
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(test_compact_dense(archive) == 0);
    TEST_CHECK(check_named(archive, "voice", payload, size) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    uint32_t selected;
    TEST_CHECK(
        libmpq__file_number_from_identity(
            archive, "voice", storage == 3 ? 1033 : 0, storage == 3 ? 2 : 0, &selected
        ) == 0 &&
        selected == number
    );
    if (storage == 3)
        TEST_CHECK(
            libmpq__file_number_from_identity(archive, "voice", 0, 0, &selected) ==
            LIBMPQ_ERROR_EXIST
        );
    const mpq_entry_s *after = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK(
        after->offset < before.offset && after->packed_size == before.packed_size &&
        after->unpacked_size == before.unpacked_size && after->flags == before.flags
    );
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, origin + after->offset, actual, after->packed_size
        ) == 0
    );
    TEST_CHECK((memcmp(stored, actual, after->packed_size) == 0) == (storage == 2));
    if (storage == 0 || storage >= 3) {
        uint8_t expected[403];
        memcpy(expected, payload, sizeof(expected));
        uint32_t key =
            (libmpq__crypto_file_key("voice") + (uint32_t)after->offset) ^ (uint32_t)size;
        TEST_CHECK(libmpq__crypto_encrypt_block(expected, sizeof(expected), key) == 0);
        TEST_CHECK(memcmp(expected, actual, sizeof(expected)) == 0);
    }
    mpq_file_attributes_s retained;
    TEST_CHECK(libmpq__file_attributes(archive, number, &retained) == 0);
    TEST_CHECK(
        retained.filetime == 42 && retained.crc32 == attributes.crc32 &&
        memcmp(retained.md5, attributes.md5, 16) == 0
    );
    uint32_t checked;
    uint32_t unavailable;
    uint32_t mismatches;
    TEST_CHECK(
        libmpq__file_verify_ex(
            archive, number, "voice", LIBMPQ_VERIFY_ALL, &checked, &unavailable, &mismatches
        ) == 0 &&
        mismatches == 0 && (checked | unavailable) == LIBMPQ_VERIFY_ALL
    );
    TEST_CHECK(
        libmpq__archive_verify_ex(
            archive, LIBMPQ_VERIFY_METADATA_ALL, &checked, &unavailable, &mismatches
        ) == 0 &&
        mismatches == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_compact(update) == 0 && same_file(libmpq__update_path(update), stage)
    );
    TEST_CHECK(libmpq__update_compact_ex(update, invalid[2], 2) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));

    /* Moving a later replacement of row zero requires the retained voice spelling again. */
    TEST_CHECK(libmpq__update_replace_data(update, "other", payload, 32, NULL) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_compact_ex(update, one, 1) == 0 &&
        same_file(libmpq__update_path(update), stage)
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_3 && form == 0 && wrapped == 0 && storage == 0) {
        mpq_update_ops_s ops = *libmpq__update_ops(update);
        ops.publish = fail_publish;
        libmpq__update_set_ops(update, &ops);
        TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, source));
    } else {
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            (wrapped
                 ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
        );
        TEST_CHECK(check_named(archive, "voice", payload, size) == 0);
        TEST_CHECK(check_named(archive, "other", payload, 32) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(remove(path) == 0 && remove(source) == 0 && remove(stage) == 0 && remove(zero) == 0);
    return 0;
}

/* No-op hints do not learn names; dirty MPQE stages still publish their prior changes. */
static int
test_compact_ex_noop(uint32_t version, int wrapped)
{
    uint8_t payload[403];
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    char path[512];
    char source[512];
    char stage[512];
    mpq_update_s *update = NULL;
    mpq_archive_s *archive = NULL;
    const char *names[] = { "voice" };
    test_payload(payload, sizeof(payload), 43);
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-ex-noop") == 0);
    TEST_CHECK(test_temp_path(source, sizeof(source), "compact-ex-noop-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-ex-noop-stage") == 0);
    TEST_CHECK(
        test_compact_ex_create(
            path, version, 0, wrapped, 0, payload, sizeof(payload), prefix, &origin
        ) == 0
    );
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_compact_ex(update, names, 1) == 0 && libmpq__update_commit(update) == 0
    );
    TEST_CHECK(copy_file(path, source) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    char *previous = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(previous != NULL);
    const char *bad[] = { "voice", "missing" };
    TEST_CHECK(libmpq__update_compact_ex(update, bad, 2) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_compact_ex(update, names, 1) == 0);
    TEST_CHECK(
        strcmp(previous, libmpq__update_path(update)) == 0 &&
        same_file(libmpq__update_path(update), stage)
    );
    free(previous);
    mpq_update_ops_s ops = *libmpq__update_ops(update);
    ops.publish = fail_publish;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_commit(update) == (wrapped ? 0 : LIBMPQ_ERROR_WRITE));
    TEST_CHECK(same_file(path, source));
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(libmpq__update_compact_ex(update, names, 1) == 0);
    TEST_CHECK(libmpq__update_replace_data(update, "other", payload, 32, NULL) == 0);
    TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_DECRYPT);
    TEST_CHECK(libmpq__update_compact_ex(update, names, 1) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_compact_ex(update, names, 1) == 0 &&
        same_file(libmpq__update_path(update), stage)
    );
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    TEST_CHECK(check_named(archive, "other", payload, 32) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0 && remove(source) == 0 && remove(stage) == 0);
    return 0;
}

/* Collection/provenance failures are retryable; consumed adoption streams remain abort-only. */
static int
test_compact_ex_failure(unsigned failure)
{
    uint8_t payload[403];
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    char path[512];
    char source[512];
    char stage[512];
    mpq_update_s *update = NULL;
    const char *names[] = { "voice", "VOICE" };
    test_payload(payload, sizeof(payload), 43);
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-ex-fault") == 0);
    TEST_CHECK(test_temp_path(source, sizeof(source), "compact-ex-fault-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-ex-fault-stage") == 0);
    TEST_CHECK(
        test_compact_ex_create(
            path, LIBMPQ_ARCHIVE_VERSION_3, 0, 0, 0, payload, sizeof(payload), prefix, &origin
        ) == 0
    );
    TEST_CHECK(copy_file(path, source) == 0 && libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_replace_data(update, "other", payload, 8, NULL) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    const mpq_update_ops_s *original = libmpq__update_ops(update);
    mpq_update_ops_s ops = *original;
    if (failure < 6) {
        ops.allocate_names = fail_provenance_allocation;
        provenance_allocation = failure;
    } else if (failure == 6)
        ops.flush = fail_flush;
    else
        ops.close = fail_close;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(
        libmpq__update_compact_ex(update, names, 2) == (failure < 6    ? LIBMPQ_ERROR_MALLOC
                                                        : failure == 6 ? LIBMPQ_ERROR_WRITE
                                                                       : LIBMPQ_ERROR_CLOSE)
    );
    TEST_CHECK(same_file(path, source) && same_file(libmpq__update_path(update), stage));
    if (failure == 7) {
        TEST_CHECK(libmpq__update_compact_ex(update, names, 2) == LIBMPQ_ERROR_EXIST);
    } else {
        libmpq__update_set_ops(update, original);
        TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_DECRYPT);
        TEST_CHECK(libmpq__update_compact_ex(update, names, 2) == 0);
    }
    libmpq__update_set_ops(update, original);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, source));
    TEST_CHECK(remove(path) == 0 && remove(source) == 0 && remove(stage) == 0);
    return 0;
}

/* Retain every compatible alias, including distinct classic slash spellings. */
static int
test_compact_ex_aliases(uint32_t version, int incompatible)
{
    mpq_archive_create_options_s create = { version, 8, 512, 0, 0 };
    mpq_file_options_s options = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0, 0
    };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_hash_s hashes[16];
    uint8_t payload[403];
    uint8_t *image;
    size_t size;
    uint32_t number;
    char path[512];
    char stage[512];
    test_payload(payload, sizeof(payload), 43);
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-ex-aliases") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-ex-alias-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__file_seek(archive->fp, 8191, SEEK_SET) == 0 && fputc(0, archive->fp) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "left/voice", payload, sizeof(payload), &options) == 0
    );
    if (incompatible == 3) {
        static const uint8_t list[] = "left/voice\nright/voice\n";
        archive->write_internal = 1;
        TEST_CHECK(
            libmpq__writer_file_add(archive, LIBMPQ_LISTFILE_NAME, list, sizeof(list) - 1, NULL) ==
            0
        );
        archive->write_internal = 0;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK(test_v4_source_layout(path, 1) == 0);
    else if (version == LIBMPQ_ARCHIVE_VERSION_3) {
        TEST_CHECK(read_bytes(path, &image, &size) == 0);
        memset(image + 52, 0, 16);
        int written = write_bytes(path, image, size);
        free(image);
        TEST_CHECK(written == 0);
    }
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    memcpy(hashes, archive->mpq_hash, sizeof(hashes));
    TEST_CHECK(libmpq__file_number(archive, "left/voice", &number) == 0);
    uint32_t block = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    char first[] = "left/voice";
    char second[] = "right/voice";
    char third[] = "left\\voice";
    const char *names[] = { first, second, incompatible ? "wrong" : third };
    for (unsigned alias = 1; alias < 3; ++alias) {
        uint32_t h[3];
        libmpq__file_hash(names[alias], &h[0], &h[1], &h[2]);
        uint32_t slot = h[0] & 15;
        while (hashes[slot].block_table_index < LIBMPQ_HASH_DELETED)
            slot = (slot + 1) & 15;
        hashes[slot] = (mpq_hash_s){ h[1], h[2], alias == 1 ? 1033 : 0, (uint16_t)alias, block };
    }
    TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    if (incompatible == 2)
        TEST_CHECK(libmpq__update_change_identity(update, "left/voice", 0, 0, 17, 0) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(
        libmpq__update_compact(update) ==
        (incompatible >= 2 ? LIBMPQ_ERROR_FORMAT : LIBMPQ_ERROR_DECRYPT)
    );
    TEST_CHECK(libmpq__update_compact_ex(update, names, 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    if (incompatible) {
        TEST_CHECK(libmpq__update_compact_ex(update, names, 3) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
    } else {
        TEST_CHECK(libmpq__update_compact_ex(update, names, 3) == 0);
        memset(first, 'x', sizeof(first) - 1);
        memset(second, 'y', sizeof(second) - 1);
        memset(third, 'z', sizeof(third) - 1);
        TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        TEST_CHECK(
            libmpq__update_compact(update) == 0 && same_file(libmpq__update_path(update), stage)
        );
        TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
        TEST_CHECK(archive->files == 1);
        const char *original[] = { "left/voice", "right/voice", "left\\voice" };
        for (unsigned i = 0; i < 3; ++i) {
            TEST_CHECK(
                libmpq__file_number_from_identity(
                    archive, original[i], i == 1 ? 1033 : 0, (uint16_t)i, &number
                ) == 0 &&
                number == 0
            );
            TEST_CHECK(check_named(archive, original[i], payload, sizeof(payload)) == 0);
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(libmpq__update_abort(update) == 0);
    if (!incompatible) {
        uint32_t h[3];
        libmpq__file_hash("left/voice", &h[0], &h[1], &h[2]);
        uint32_t slot = h[0] & 15;
        while (hashes[slot].block_table_index < LIBMPQ_HASH_DELETED)
            slot = (slot + 1) & 15;
        hashes[slot] = (mpq_hash_s){ h[1], h[2], 0, 0, block };
        TEST_CHECK(test_alias_table_write(path, hashes, 0) == 0);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0);
        TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
        const char *duplicate[] = { "left/voice" };
        TEST_CHECK(libmpq__update_compact_ex(update, duplicate, 1) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(same_file(libmpq__update_path(update), stage));
        TEST_CHECK(libmpq__update_abort(update) == 0);
    }
    TEST_CHECK(remove(path) == 0 && remove(stage) == 0);
    return 0;
}

/* Reader-compatible reduced hashes must not fall back to otherwise complete classic names. */
static int
test_compact_ex_reduced(void)
{
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_3, 4, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t *het;
    uint8_t *bet;
    uint8_t *image;
    uint8_t *stored_het = NULL;
    uint8_t *stored_bet = NULL;
    size_t size;
    size_t het_size;
    size_t bet_size;
    char path[512];
    char stage[512];
    TEST_CHECK(test_temp_path(path, sizeof(path), "compact-ex-reduced") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "compact-ex-reduced-stage") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"data", 4, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    het_size = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + archive->mpq_het.header.envelope.data_size;
    bet_size = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + archive->mpq_bet.header.envelope.data_size;
    het = malloc(het_size);
    bet = malloc(bet_size);
    if (het == NULL || bet == NULL) {
        free(het);
        free(bet);
        TEST_CHECK(0);
    }
    memcpy(het, archive->het_data, het_size);
    memcpy(bet, archive->bet_data, bet_size);
    int closed = libmpq__archive_close(archive);
    libmpq__store_le32(het + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + 12, 63);
    libmpq__store_le32(bet + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + 64, 55);
    int encoded_het = libmpq__ext_table_encode(het, het_size, false, &stored_het, &het_size);
    int encoded_bet = libmpq__ext_table_encode(bet, bet_size, false, &stored_bet, &bet_size);
    free(het);
    free(bet);
    if (closed != 0 || encoded_het != 0 || encoded_bet != 0) {
        free(stored_het);
        free(stored_bet);
        TEST_CHECK(0);
    }
    if (read_bytes(path, &image, &size) != 0) {
        free(stored_het);
        free(stored_bet);
        TEST_CHECK(0);
    }
    uint64_t prefix = libmpq__load_le64(image + 60);
    uint32_t hash_position = libmpq__load_le32(image + 16);
    uint32_t block_position = libmpq__load_le32(image + 20);
    size_t hash_size = (size_t)libmpq__load_le32(image + 24) * 16;
    size_t block_size = (size_t)libmpq__load_le32(image + 28) * 16;
    if (!(prefix <= size && hash_position <= size && hash_size <= size - hash_position &&
          block_position <= size && block_size <= size - block_position)) {
        free(stored_het);
        free(stored_bet);
        free(image);
        TEST_CHECK(0);
    }
    uint64_t end = prefix + het_size + bet_size + hash_size + block_size;
    libmpq__store_le32(image + 8, (uint32_t)end);
    libmpq__store_le64(image + 44, end);
    libmpq__store_le64(image + 52, prefix + het_size);
    libmpq__store_le32(image + 16, (uint32_t)(prefix + het_size + bet_size));
    libmpq__store_le32(image + 20, (uint32_t)(prefix + het_size + bet_size + hash_size));
    int written = write_bytes(path, image, (size_t)prefix);
    FILE *file = written == 0 ? libmpq__file_open(path, "ab") : NULL;
    int appended = file != NULL && fwrite(stored_het, 1, het_size, file) == het_size &&
                   fwrite(stored_bet, 1, bet_size, file) == bet_size &&
                   fwrite(image + hash_position, 1, hash_size, file) == hash_size &&
                   fwrite(image + block_position, 1, block_size, file) == block_size;
    int finished = file != NULL ? fclose(file) : -1;
    free(stored_het);
    free(stored_bet);
    free(image);
    TEST_CHECK(written == 0 && appended && finished == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(archive->mpq_het.header.name_hash_bit_size == 63);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    const char *names[] = { "voice" };
    TEST_CHECK(libmpq__update_compact_ex(update, names, 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_compact_ex(update, NULL, 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__update_compact(update) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(same_file(libmpq__update_path(update), stage));
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(remove(path) == 0 && remove(stage) == 0);
    return 0;
}

/* Existing update routes share the oversized SINGLE writer without changing origin or ownership. */
static int
test_single_updates(uint32_t version, unsigned form, int wrapped)
{
    mpq_archive_create_options_s create = { version, 16, 4096, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_file_options_s options = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 1033, 2
    };
    mpq_file_options_s added = options;
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint8_t payload[9001];
    uint8_t prefix[4096] = { 0 };
    uint64_t origin;
    char path[512];
    char source[512];
    char stage[512];
    char input[512];
    test_payload(payload, sizeof(payload), 43);
    added.locale = 0;
    added.platform = 0;
    TEST_CHECK(test_temp_path(path, sizeof(path), "single-update") == 0);
    TEST_CHECK(test_temp_path(source, sizeof(source), "single-update-source") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "single-update-stage") == 0);
    TEST_CHECK(test_temp_path(input, sizeof(input), "single-update-input") == 0);
    TEST_CHECK(write_bytes(input, payload, sizeof(payload)) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", payload, 17, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, wrapped, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, source) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_data(update, "voice", payload, sizeof(payload), &options) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "voice", 1033, 2, payload, sizeof(payload), &options
        ) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_path_identity(update, "voice", 1033, 2, input, &options) == 0
    );
    TEST_CHECK(libmpq__update_add_data(update, "added", payload, sizeof(payload), &added) == 0);
    TEST_CHECK(libmpq__update_add_path(update, "from-path", input, &added) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_replace_path(update, "added", NULL, &added) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(same_file(libmpq__update_path(update), stage) && same_file(path, source));

    mpq_file_options_s unsupported = added;
    unsupported.flags |= LIBMPQ_FILE_FLAG_PATCH_FILE;
    TEST_CHECK(
        libmpq__update_replace_data(update, "added", payload, sizeof(payload), &unsupported) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage) && same_file(path, source));

    TEST_CHECK(libmpq__update_replace_data(update, "added", NULL, 0, NULL) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    uint32_t empty_number;
    libmpq__off_t empty_size;
    TEST_CHECK(libmpq__file_number(archive, "added", &empty_number) == 0);
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, empty_number, &empty_size) == 0 && empty_size == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_replace_path(update, "added", input, &added) == 0);
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    mpq_file_options_s bad = options;
    bad.flags |= LIBMPQ_FILE_FLAG_COMPRESS;
    bad.compression_first = bad.compression_next = LIBMPQ_COMPRESSION_WAVE_MONO;
    TEST_CHECK(
        libmpq__update_replace_data_identity(
            update, "voice", 1033, 2, payload, sizeof(payload), &bad
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage) && same_file(path, source));
    TEST_CHECK(libmpq__update_timestamp_identity(update, "voice", 1033, 2, 123) == 0);
    TEST_CHECK(libmpq__update_compact(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    const char *names[] = { "voice", "added", "from-path" };
    for (unsigned i = 0; i < 3; i++) {
        uint32_t number;
        uint32_t blocks;
        uint32_t checked;
        uint32_t unavailable;
        uint32_t mismatches;
        TEST_CHECK(check_named(archive, names[i], payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
        TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 1);
        const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        TEST_CHECK(
            (entry->flags & LIBMPQ_FILE_FLAG_SINGLE) && entry->packed_size == sizeof(payload)
        );
        TEST_CHECK(
            libmpq__file_verify_ex(
                archive, number, names[i], LIBMPQ_VERIFY_ALL, &checked, &unavailable, &mismatches
            ) == 0 &&
            mismatches == 0
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    if (version == 2 && form == 0 && !wrapped) {
        mpq_update_ops_s ops = *libmpq__update_ops(update);
        ops.publish = fail_publish;
        libmpq__update_set_ops(update, &ops);
        TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE && same_file(path, source));
    } else {
        TEST_CHECK(libmpq__update_commit(update) == 0);
        TEST_CHECK(
            (wrapped
                 ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
        );
        TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
        TEST_CHECK(check_named(archive, "voice", payload, sizeof(payload)) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(copy_file(path, source) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_data(update, "voice", payload, sizeof(payload), &options) == 0
    );
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, source));
    TEST_CHECK(
        remove(path) == 0 && remove(source) == 0 && remove(stage) == 0 && remove(input) == 0
    );
    return 0;
}

static int
test_replace_ranges(uint32_t version, const mpq_file_options_s *options, int wrapped, int form)
{
    const mpq_archive_create_options_s create = { version, 16, 4096, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                                  LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                      LIBMPQ_ATTRIBUTE_FILETIME };
    const uint8_t edits[] = { 9, 8, 7, 6, 5 };
    uint8_t payload[9001];
    uint8_t expected[9001];
    uint8_t actual[9001];
    uint8_t prefix[4096] = { 0 };
    char path[512];
    char source[512];
    char stage[512];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_writer_s *writer;
    mpq_stream_s *stream;
    uint64_t origin;
    uint32_t number;
    uint32_t checked;
    uint32_t unavailable;
    uint32_t mismatches;
    libmpq__off_t size;
    mpq_file_attributes_s attributes;
    const mpq_update_replace_range_s empty = { sizeof(payload), NULL, 0 };
    mpq_update_replace_range_s ranges[] = { { 4094, edits, sizeof(edits) },
                                            { 89, edits, 2 },
                                            { 4096, edits, 3 },
                                            { 9000, edits + 4, 1 },
                                            { 17, NULL, 0 } };
    mpq_update_replace_range_s invalid[] = { { 4, edits, 1 }, { -1, edits, 1 } };
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i % 37);
    memcpy(expected, payload, sizeof(expected));
    for (size_t i = 0; i < sizeof(ranges) / sizeof(ranges[0]); ++i)
        if (ranges[i].size != 0)
            memcpy(expected + ranges[i].offset, ranges[i].data, ranges[i].size);
    TEST_CHECK(test_temp_path(path, sizeof(path), "replace-ranges") == 0);
    TEST_CHECK(test_temp_path(source, sizeof(source), "replace-ranges-original") == 0);
    TEST_CHECK(test_temp_path(stage, sizeof(stage), "replace-ranges-stage") == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_create_mpqe(
                       &archive, path, auth_code, sizeof(auth_code) - 1, &create
                   )
                 : libmpq__archive_create(&archive, path, &create)) == 0
    );
    TEST_CHECK(libmpq__writer_begin(archive, "voice", sizeof(payload), options, &writer) == 0);
    TEST_CHECK(libmpq__writer_timestamp(writer, 123456789) == 0);
    TEST_CHECK(libmpq__writer_write(writer, payload, sizeof(payload)) == 0);
    TEST_CHECK(libmpq__writer_finish(writer) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "empty", NULL, 0, NULL) == 0);
    if (options->locale != 0)
        TEST_CHECK(libmpq__archive_add_data(archive, "voice", edits, sizeof(edits), NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_compact_embed(path, form, wrapped, prefix, &origin) == 0);
    TEST_CHECK(copy_file(path, source) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(copy_file(libmpq__update_path(update), stage) == 0);
    TEST_CHECK(libmpq__update_replace_ranges(update, "empty", NULL, 0) == 0);
    TEST_CHECK(
        libmpq__update_replace_ranges_identity(
            update, "voice", options->locale, options->platform, &empty, 1
        ) == 0
    );
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", NULL, 1) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__update_replace_ranges_identity(
            update, "voice", options->locale, options->platform, invalid, 2
        ) == LIBMPQ_ERROR_SEEK
    );
    invalid[1].offset = sizeof(payload);
    TEST_CHECK(
        libmpq__update_replace_ranges_identity(
            update, "voice", options->locale, options->platform, invalid, 2
        ) == LIBMPQ_ERROR_SIZE
    );
    invalid[1].offset = INT64_MAX;
    invalid[1].size = SIZE_MAX;
    TEST_CHECK(
        libmpq__update_replace_ranges_identity(
            update, "voice", options->locale, options->platform, invalid, 2
        ) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(same_file(libmpq__update_path(update), stage) && same_file(path, source));
    TEST_CHECK(
        libmpq__update_replace_ranges_identity(
            update, "voice", options->locale, options->platform, ranges,
            sizeof(ranges) / sizeof(ranges[0])
        ) == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), -1) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &size) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    const mpq_update_replace_range_s ordinary = { 0, edits + 1, 1 };
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", &ordinary, 1) == 0);
    if (size == sizeof(payload))
        expected[0] = edits[1];
    TEST_CHECK(same_file(path, source));
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1)
                 : libmpq__archive_open(&archive, path, -1)) == 0
    );
    TEST_CHECK(test_compact_prefix(archive, form, prefix, origin) == 0);
    TEST_CHECK(
        libmpq__stream_open_name_identity(
            archive, "voice", options->locale, options->platform, &stream
        ) == 0
    );
    TEST_CHECK(
        libmpq__stream_read(stream, actual, sizeof(actual), &size) == 0 && size == sizeof(actual)
    );
    TEST_CHECK(memcmp(expected, actual, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(
        libmpq__file_number_from_identity(
            archive, "voice", options->locale, options->platform, &number
        ) == 0
    );
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    TEST_CHECK((entry->flags & ~LIBMPQ_FLAG_EXISTS) == options->flags);
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(attributes.filetime == 123456789);
    TEST_CHECK(
        libmpq__file_verify_ex(
            archive, number, "voice", LIBMPQ_VERIFY_ALL, &checked, &unavailable, &mismatches
        ) == 0 &&
        mismatches == 0
    );
    TEST_CHECK(
        (checked & (LIBMPQ_VERIFY_FILE_MD5 | LIBMPQ_VERIFY_FILE_CRC32)) ==
        (LIBMPQ_VERIFY_FILE_MD5 | LIBMPQ_VERIFY_FILE_CRC32)
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_4) {
        TEST_CHECK((checked & LIBMPQ_VERIFY_RAW_MD5) != 0);
        TEST_CHECK(
            libmpq__archive_verify_ex(
                archive, LIBMPQ_VERIFY_METADATA_ALL, &checked, &unavailable, &mismatches
            ) == 0 &&
            mismatches == 0
        );
        TEST_CHECK((checked | unavailable) == LIBMPQ_VERIFY_METADATA_ALL);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (wrapped ? libmpq__update_begin_mpqe(&update, path, auth_code, sizeof(auth_code) - 1)
                 : libmpq__update_begin(&update, path)) == 0
    );
    TEST_CHECK(
        libmpq__update_replace_ranges_identity(
            update, "voice", options->locale, options->platform, &ordinary, 1
        ) == 0
    );
    TEST_CHECK(copy_file(path, stage) == 0);
    TEST_CHECK(libmpq__update_abort(update) == 0 && same_file(path, stage));
    remove(path);
    remove(source);
    remove(stage);
    return 0;
}

/* A malformed advertised checksum table and a checksum mismatch both block adoption. */
static int
test_ranges_bad_checksum(int malformed)
{
    const mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_1, 8, 4096, 0, 0 };
    const mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC,
                                         LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    const mpq_update_replace_range_s range = { 2, (const uint8_t *)"x", 1 };
    char path[512];
    uint8_t input[9001];
    uint32_t number;
    uint32_t blocks;
    libmpq__off_t position;
    uint8_t checksum[4];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;

    memset(input, 'a', sizeof(input));
    TEST_CHECK(test_temp_path(path, sizeof(path), "ranges-checksum") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", input, sizeof(input), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "voice", &number) == 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 3);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, "voice") == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    const uint32_t begin = archive->mpq_file[number]->packed_offset[blocks];
    const uint32_t end = archive->mpq_file[number]->packed_offset[blocks + 1];
    TEST_CHECK(end - begin == blocks * sizeof(uint32_t));
    position = (libmpq__off_t)entry->offset + (malformed ? (blocks + 1) * 4 : begin);
    libmpq__store_le32(checksum, malformed ? end + 1 : 1);
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    FILE *file = fopen(path, "r+b");
    TEST_CHECK(file != NULL && libmpq__file_seek(file, position, SEEK_SET) == 0);
    TEST_CHECK(fwrite(checksum, 1, sizeof(checksum), file) == sizeof(checksum));
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    const int32_t result = libmpq__update_replace_ranges(update, "voice", &range, 1);
    TEST_CHECK(
        malformed ? result == LIBMPQ_ERROR_FORMAT || result == LIBMPQ_ERROR_READ
                  : result == LIBMPQ_ERROR_READ
    );
    TEST_CHECK(same_file(path, libmpq__update_path(update)));
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

static int
test_ranges_signed(void)
{
    const mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_1, 8, 512, 0, 0 };
    const mpq_update_replace_range_s range = { 2, (const uint8_t *)"x", 1 };
    uint8_t strong_key[sizeof(test_strong_signature_public_key)];
    const char *path = "update-signed-ranges.mpq";
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint32_t signatures;
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
    TEST_CHECK(libmpq__archive_add_data(archive, "voice", (const uint8_t *)"voice", 5, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", NULL, 0) == 0);
    TEST_CHECK(same_file(path, libmpq__update_path(update)));
    mpq_update_ops_s original_ops = *libmpq__update_ops(update);
    mpq_update_ops_s ops = original_ops;
    provenance_allocation = 0;
    ops.allocate_names = fail_provenance_allocation;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", &range, 1) == LIBMPQ_ERROR_MALLOC);
    TEST_CHECK(same_file(path, libmpq__update_path(update)));
    ops = original_ops;
    ops.flush = fail_flush;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", &range, 1) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(same_file(path, libmpq__update_path(update)));
    libmpq__update_set_ops(update, &original_ops);
    TEST_CHECK(libmpq__update_replace_ranges_identity(update, "voice", 0, 0, &range, 1) == 0);
    TEST_CHECK(same_file(path, libmpq__update_path(update)) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, libmpq__update_path(update), 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0 && signatures == 0);
    TEST_CHECK(check_named(archive, "voice", (const uint8_t *)"voxce", 5) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    ops = original_ops;
    ops.publish = fail_publish;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(
        libmpq__archive_signatures(archive, &signatures) == 0 &&
        signatures == (LIBMPQ_SIGNATURE_STRONG | LIBMPQ_SIGNATURE_WEAK)
    );
    TEST_CHECK(check_named(archive, "voice", (const uint8_t *)"voice", 5) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    ops = original_ops;
    ops.close = fail_close;
    libmpq__update_set_ops(update, &ops);
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", &range, 1) == LIBMPQ_ERROR_CLOSE);
    TEST_CHECK(libmpq__update_replace_ranges(update, "voice", &range, 1) == LIBMPQ_ERROR_EXIST);
    libmpq__update_set_ops(update, &original_ops);
    TEST_CHECK(libmpq__update_abort(update) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Capture serialized bytes, then independently decrypt the sector using its ordinal. */
static int
range_sector_image(
    mpq_archive_s *archive, const char *name, uint32_t block, uint8_t *stored, uint8_t *packed,
    uint32_t *size, uint32_t *seed, uint64_t *position
)
{
    uint32_t number;
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, name) == 0);
    const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
    uint32_t start = archive->mpq_file[number]->packed_offset[block];
    uint32_t end = archive->mpq_file[number]->packed_offset[block + 1];
    TEST_CHECK(end > start && end - start <= 4096);
    *size = end - start;
    *position = (uint64_t)archive->archive_offset + entry->offset + start;
    TEST_CHECK(libmpq__source_read_at(archive->source, *position, stored, *size) == 0);
    memcpy(packed, stored, *size);
    *seed = libmpq__crypto_file_key(name);
    if ((entry->flags & LIBMPQ_FILE_FLAG_KEY) != 0)
        *seed = (*seed + (uint32_t)entry->offset) ^ (uint32_t)entry->unpacked_size;
    *seed += block;
    if ((entry->flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0)
        TEST_CHECK(libmpq__crypto_decrypt_block(packed, *size, *seed) == 0);
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    return 0;
}

/* Retained sectors preserve framing and have ciphertext for the destination key. */
static int
test_range_packed_sectors(uint32_t version, uint32_t flags, int attributes, int damaged)
{
    const mpq_archive_create_options_s create = {
        version, 8, 4096, LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
        attributes ? (LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_FILETIME) : 0
    };
    const uint32_t codec = (flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0 ? LIBMPQ_COMPRESSION_BZIP2 : 0;
    const mpq_file_options_s options = { flags, codec, codec, 0, 0 };
    const char *name = "voice";
    char path[512];
    uint8_t bytes[8197];
    uint8_t edit[537];
    uint8_t old_stored[4096];
    uint8_t old_packed[4096];
    uint8_t new_stored[4096];
    uint8_t new_packed[4096];
    uint32_t old_size;
    uint32_t new_size;
    uint32_t old_seed;
    uint32_t new_seed;
    uint64_t position;
    uint64_t unused;
    uint32_t number;
    uint32_t checked;
    uint32_t unavailable;
    uint32_t mismatches;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *candidate = NULL;
    mpq_update_s *update = NULL;
    const mpq_update_replace_range_s range = { 203, edit, sizeof(edit) };
    memset(bytes, 0x37, sizeof(bytes));
    for (size_t i = 0; i < sizeof(edit); ++i)
        edit[i] = (uint8_t)(i ^ (i >> 3));
    TEST_CHECK(test_temp_path(path, sizeof(path), "range-packed") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    TEST_CHECK(libmpq__writer_output_seek(archive, 8192, SEEK_SET) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, name, bytes, sizeof(bytes), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    if (damaged) {

        /* With no advertised checksum or RAW digest, the candidate decoder must reject this. */
        TEST_CHECK(
            range_sector_image(
                archive, name, 1, old_stored, old_packed, &old_size, &old_seed, &position
            ) == 0
        );
        TEST_CHECK(old_packed[0] == LIBMPQ_COMPRESSION_BZIP2);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        FILE *file = libmpq__file_open(path, "r+b");
        TEST_CHECK(file != NULL && libmpq__file_seek(file, (libmpq__off_t)position, SEEK_SET) == 0);
        TEST_CHECK(fputc(0x04, file) == 0x04 && fclose(file) == 0);
    }
    TEST_CHECK(libmpq__update_begin(&update, path) == 0);
    int32_t result = libmpq__update_replace_ranges_identity(update, name, 0, 0, &range, 1);
    if (damaged) {
        TEST_CHECK(result == LIBMPQ_ERROR_UNPACK);
        TEST_CHECK(same_file(path, libmpq__update_path(update)));
        TEST_CHECK(libmpq__update_abort(update) == 0 && remove(path) == 0);
        return 0;
    }
    TEST_CHECK(result == 0);
    TEST_CHECK(libmpq__archive_open(&candidate, libmpq__update_path(update), 0) == 0);
    for (uint32_t block = 0; block < 3; ++block) {
        TEST_CHECK(
            range_sector_image(
                archive, name, block, old_stored, old_packed, &old_size, &old_seed, &position
            ) == 0
        );
        TEST_CHECK(
            range_sector_image(
                candidate, name, block, new_stored, new_packed, &new_size, &new_seed, &unused
            ) == 0
        );
        if (block == 0) {
            if (codec != 0)
                TEST_CHECK(old_size != new_size);
            continue;
        }
        TEST_CHECK(old_size == new_size && memcmp(old_packed, new_packed, old_size) == 0);
        if (codec != 0 && block == 1)
            TEST_CHECK(new_packed[0] == LIBMPQ_COMPRESSION_BZIP2);
        if ((flags & LIBMPQ_FILE_FLAG_KEY) != 0) {
            TEST_CHECK(old_seed != new_seed);
            TEST_CHECK(memcmp(old_stored, new_stored, old_size & ~3u) != 0);
        } else {
            TEST_CHECK(memcmp(old_stored, new_stored, old_size) == 0);
        }
        TEST_CHECK(
            memcmp(old_stored + (old_size & ~3u), new_stored + (old_size & ~3u), old_size & 3u) == 0
        );
    }
    memcpy(bytes + range.offset, edit, sizeof(edit));
    TEST_CHECK(check_named(candidate, name, bytes, sizeof(bytes)) == 0);
    TEST_CHECK(libmpq__file_number(candidate, name, &number) == 0);
    TEST_CHECK(
        libmpq__file_verify_ex(
            candidate, number, name, LIBMPQ_VERIFY_ALL, &checked, &unavailable, &mismatches
        ) == 0
    );
    TEST_CHECK(mismatches == 0);
    if (attributes)
        TEST_CHECK(
            (checked & (LIBMPQ_VERIFY_FILE_MD5 | LIBMPQ_VERIFY_FILE_CRC32)) ==
            (LIBMPQ_VERIFY_FILE_MD5 | LIBMPQ_VERIFY_FILE_CRC32)
        );
    if ((flags & LIBMPQ_FILE_FLAG_SECTOR_CRC) != 0)
        TEST_CHECK((checked & LIBMPQ_VERIFY_SECTOR_CRC) != 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        TEST_CHECK((checked & LIBMPQ_VERIFY_RAW_MD5) != 0);
    TEST_CHECK(libmpq__archive_close(candidate) == 0 && libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_commit(update) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(check_named(archive, name, bytes, sizeof(bytes)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0 && remove(path) == 0);
    return 0;
}

int
main(void)
{
    TEST_CHECK(
        test_range_packed_sectors(
            LIBMPQ_ARCHIVE_VERSION_2, LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0
        ) == 0
    );
    TEST_CHECK(
        test_range_packed_sectors(
            LIBMPQ_ARCHIVE_VERSION_4,
            LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC | LIBMPQ_FILE_FLAG_ENCRYPTED |
                LIBMPQ_FILE_FLAG_KEY,
            1, 0
        ) == 0
    );
    TEST_CHECK(
        test_range_packed_sectors(
            LIBMPQ_ARCHIVE_VERSION_2, LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0
        ) == 0
    );
    TEST_CHECK(
        test_range_packed_sectors(LIBMPQ_ARCHIVE_VERSION_2, LIBMPQ_FILE_FLAG_COMPRESS, 0, 1) == 0
    );
    TEST_CHECK(test_ranges_bad_checksum(0) == 0);
    TEST_CHECK(test_ranges_bad_checksum(1) == 0);
    TEST_CHECK(test_ranges_signed() == 0);
    const mpq_file_options_s range_storage[] = {
        { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 1033, 2 },
        { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SECTOR_CRC,
          LIBMPQ_COMPRESSION_BZIP2, LIBMPQ_COMPRESSION_ZLIB, 0, 0 },
        { LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 0,
          0 },
        { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED |
              LIBMPQ_FILE_FLAG_KEY,
          LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 }
    };
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (size_t i = 0; i < sizeof(range_storage) / sizeof(range_storage[0]); ++i) {
            mpq_file_options_s storage = range_storage[i];
            if (version >= LIBMPQ_ARCHIVE_VERSION_3)
                storage.locale = storage.platform = 0;
            TEST_CHECK(test_replace_ranges(version, &storage, 0, 0) == 0);
            TEST_CHECK(test_replace_ranges(version, &storage, 1, 0) == 0);
            TEST_CHECK(test_replace_ranges(version, &storage, 0, 2) == 0);
        }

    for (uint32_t version = 0; version < 4; version++)
        for (unsigned form = 0; form <= 4; form += 2)
            for (int mpqe = 0; mpqe < 2; mpqe++)
                TEST_CHECK(test_single_updates(version, form, mpqe) == 0);
    TEST_CHECK(test_compact_ex_reduced() == 0);
    for (uint32_t version = 0; version < 4; ++version) {
        for (int wrapped = 0; wrapped < 2; ++wrapped) {
            TEST_CHECK(test_compact_ex_noop(version, wrapped) == 0);
            for (unsigned form = 0; form <= 4; form += 2)
                for (unsigned storage = 0; storage < 5; ++storage)
                    TEST_CHECK(test_compact_ex(version, form, wrapped, storage) == 0);
        }
        TEST_CHECK(test_compaction_adpcm(version, 0, 1) == 0);
        TEST_CHECK(test_compaction_qualified(version, 0, 1) == 0);
        TEST_CHECK(test_compact_ex_aliases(version, 0) == 0);
        TEST_CHECK(test_compact_ex_aliases(version, 1) == 0);
        TEST_CHECK(test_compact_ex_aliases(version, 2) == 0);
        TEST_CHECK(test_compact_ex_aliases(version, 3) == 0);
    }
    for (unsigned failure = 0; failure < 8; ++failure)
        TEST_CHECK(test_compact_ex_failure(failure) == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (unsigned form = 0; form <= 4; form += 2)
            for (int adjusted = 0; adjusted < 2; ++adjusted)
                TEST_CHECK(test_key_provenance(version, form, adjusted) == 0);
    for (uint32_t version = 0; version < 2; ++version)
        for (int single = 0; single < 2; ++single)
            TEST_CHECK(test_compaction_cache_mapping(version, single) == 0);

    for (unsigned kind = 0; kind < 6; ++kind)
        TEST_CHECK(test_compaction_rejection(kind) == 0);

    for (uint32_t version = 0; version < 4; ++version) {
        TEST_CHECK(test_compaction_qualified(version, 0, 0) == 0);
        TEST_CHECK(test_compaction_failure(version, 0, 0) == 0);
        TEST_CHECK(test_compaction_failure(version, 1, 0) == 0);
        TEST_CHECK(test_compaction_adpcm(version, 0, 0) == 0);
    }

    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (unsigned storage = 0; storage < 8; ++storage) {
            TEST_CHECK(test_compaction_listfile(version, storage, 1, 1) == 0);
            if (storage < 5) {
                TEST_CHECK(test_compaction_listfile(version, storage, 1, 0) == 0);
                TEST_CHECK(test_compaction_listfile(version, storage, 0, 0) == 0);
                if (version == LIBMPQ_ARCHIVE_VERSION_4)
                    TEST_CHECK(test_compaction_listfile(version, storage, 2, 1) == 0);
            }
        }
    TEST_CHECK(test_compaction_signatures(0, 0) == 0);
    TEST_CHECK(test_compaction_signatures(1, 0) == 0);
    for (uint32_t version = 0; version < 4; ++version)
        for (unsigned layout = 0; layout < (version >= 2 ? 3u : 1u); ++layout)
            for (unsigned encryption = 0; encryption < 7; ++encryption)
                if (layout != 2 || (encryption != 3 && encryption < 5))
                    TEST_CHECK(test_compaction_opaque(version, layout, encryption, 0) == 0);

    TEST_CHECK(libmpq__update_compact(NULL) == LIBMPQ_ERROR_EXIST);
    for (uint32_t version = 0; version < 4; ++version)
        for (uint32_t raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u); ++raw)
            for (unsigned encryption = 0; encryption < 3; ++encryption)
                for (int wrapped = 0; wrapped < 2; ++wrapped)
                    TEST_CHECK(
                        test_compaction(
                            version,
                            raw == 1   ? 17
                            : raw == 2 ? 0x4000
                                       : 0,
                            encryption, wrapped, 0
                        ) == 0
                    );

    for (uint32_t version = 0; version < 4; ++version)
        for (unsigned form = 1; form <= 5; ++form)
            for (unsigned encryption = 0; encryption < 3; ++encryption)
                for (uint32_t raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u);
                     ++raw) {
                    TEST_CHECK(
                        test_compaction(
                            version,
                            raw == 1   ? 17
                            : raw == 2 ? 0x4000
                                       : 0,
                            encryption, 0, form
                        ) == 0
                    );
                    if (form == 4)
                        TEST_CHECK(
                            test_compaction(
                                version,
                                raw == 1   ? 17
                                : raw == 2 ? 0x4000
                                           : 0,
                                encryption, 1, form
                            ) == 0
                        );
                }

    for (uint32_t version = 0; version < 4; ++version) {
        TEST_CHECK(test_compaction_adpcm(version, 5, 0) == 0);
        TEST_CHECK(test_compaction_qualified(version, 5, 0) == 0);
        for (unsigned layout = 0; layout < (version >= 2 ? 3u : 1u); ++layout)
            for (unsigned encryption = 0; encryption < 3; ++encryption)
                TEST_CHECK(test_compaction_opaque(version, layout, encryption, 5) == 0);
    }
    for (unsigned form = 1; form <= 6; form += 5) {
        TEST_CHECK(test_compaction_signatures(0, form) == 0);
        TEST_CHECK(test_compaction_signatures(1, form) == 0);
    }

    for (uint32_t version = 0; version < 4; ++version) {
        TEST_CHECK(test_compact_embedded_noop(version, 0, 0) == 0);
        TEST_CHECK(test_compact_embedded_noop(version, 1, 0) == 0);
        if (version >= LIBMPQ_ARCHIVE_VERSION_3) {
            TEST_CHECK(test_compact_embedded_noop(version, 0, 1) == 0);
            TEST_CHECK(test_compact_embedded_noop(version, 1, 1) == 0);
        }
        TEST_CHECK(test_compaction_failure(version, 0, 5) == 0);
        TEST_CHECK(test_compaction_failure(version, 1, 5) == 0);
    }
    for (unsigned kind = 0; kind < 7; ++kind)
        TEST_CHECK(test_compact_bad_prefix(kind) == 0);

    for (uint32_t version = 0; version < 4; ++version) {
        TEST_CHECK(test_exact_cross_names(version, 17, 0, 5) == 0);
        if (version >= LIBMPQ_ARCHIVE_VERSION_3)
            TEST_CHECK(test_exact_cross_names(version, 17, 1, 4) == 0);
        TEST_CHECK(test_embedded_trailer(version) == 0);
        for (unsigned form = 1; form <= 5; ++form)
            for (uint8_t from_path = 0; from_path < 2; ++from_path)
                TEST_CHECK(test_embedded_empty(version, form, from_path) == 0);
        for (unsigned layout = 0; layout < (version >= 2 ? 5u : 1u); ++layout) {
            TEST_CHECK(test_exact_updates(version, 17, layout, 0, 5) == 0);
            TEST_CHECK(test_exact_updates(version, 0, layout, 1, 4) == 0);
        }
        for (unsigned storage = 0; storage < 3; ++storage) {
            TEST_CHECK(test_timestamp_updates(version, 17, 0, storage, 0, 5) == 0);
            TEST_CHECK(test_timestamp_updates(version, 0, 1, storage, 0, 4) == 0);
        }
        TEST_CHECK(test_timestamp_updates(version, 0x4000, 0, 0, 1, 3) == 0);
    }

    TEST_CHECK(
        libmpq__update_sign(
            NULL, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == LIBMPQ_ERROR_EXIST
    );
    for (unsigned storage = 0; storage < 4; ++storage)
        TEST_CHECK(test_update_sign_attributes(storage) == 0);
    TEST_CHECK(test_update_sign_names() == 0);
    TEST_CHECK(test_update_sign_layout(0, 0, 0) == 0);
    TEST_CHECK(test_update_sign_layout(1, 0, 0) == 0);
    TEST_CHECK(test_update_sign_layout(3, 1, 0) == 0);
    TEST_CHECK(test_update_sign_layout(3, 2, 0) == 0);
    TEST_CHECK(test_update_sign_layout(0, 0, 1) == 0);
    TEST_CHECK(test_update_sign_layout(0, 0, 2) == 0);
    TEST_CHECK(test_update_sign_ranges(5) == 0);
    TEST_CHECK(test_update_sign_ranges(6) == 0);
    for (uint32_t version = 0; version < 4; ++version) {
        for (unsigned form = 0; form <= 6; ++form)
            TEST_CHECK(test_update_signing(version, 0, form, 0, form % 4) == 0);
        TEST_CHECK(test_update_signing(version, 0, 5, 1, 3) == 0);
    }
    TEST_CHECK(test_update_signing(LIBMPQ_ARCHIVE_VERSION_4, 17, 4, 0, 2) == 0);
    TEST_CHECK(test_update_signing(LIBMPQ_ARCHIVE_VERSION_4, 0x4000, 6, 0, 0) == 0);

    TEST_CHECK(libmpq__update_timestamp(NULL, "x", 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__update_timestamp_identity(NULL, "x", 0, 0, UINT64_MAX) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(test_timestamp_signatures() == 0);
    TEST_CHECK(test_timestamp_bet_alias(LIBMPQ_ARCHIVE_VERSION_3) == 0);
    TEST_CHECK(test_timestamp_bet_alias(LIBMPQ_ARCHIVE_VERSION_4) == 0);
    TEST_CHECK(test_timestamp_raw_corruption() == 0);
    TEST_CHECK(test_timestamp_variants(LIBMPQ_ARCHIVE_VERSION_1) == 0);
    TEST_CHECK(test_timestamp_variants(LIBMPQ_ARCHIVE_VERSION_2) == 0);
    for (unsigned mode = 0; mode < 5; ++mode)
        TEST_CHECK(test_timestamp_metadata(mode) == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version) {
        TEST_CHECK(test_timestamp_sequences(version) == 0);
        if (version >= LIBMPQ_ARCHIVE_VERSION_3)
            TEST_CHECK(test_timestamp_variants(version) == 0);
        for (int wrapped = 0; wrapped < 2; ++wrapped)
            for (int closing = 0; closing < 2; ++closing)
                TEST_CHECK(test_timestamp_failure(version, wrapped, closing) == 0);
        static const uint32_t raw_sizes[] = { 0, 17, 0x4000 };
        for (unsigned raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u); ++raw) {
            TEST_CHECK(test_timestamp_aliases(version, raw_sizes[raw]) == 0);
            for (unsigned storage = 0; storage < 3; ++storage)
                for (int wrapped = 0; wrapped < 2; ++wrapped)
                    TEST_CHECK(
                        test_timestamp_updates(version, raw_sizes[raw], wrapped, storage, 0, 0) == 0
                    );
            if (version >= LIBMPQ_ARCHIVE_VERSION_3)
                TEST_CHECK(test_timestamp_updates(version, raw_sizes[raw], 0, 0, 1, 0) == 0);
        }
    }
    TEST_CHECK(test_change_identity_ambiguous(0) == 0);
    TEST_CHECK(test_change_identity_ambiguous(1) == 0);
    TEST_CHECK(libmpq__update_change_identity(NULL, "absent", 0, 0, 1, 0) == LIBMPQ_ERROR_EXIST);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        TEST_CHECK(test_change_identity_signature(version) == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (unsigned raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u); ++raw)
            for (uint8_t single = 0; single < 2; ++single) {
                const uint32_t chunks[] = { 0, 17, 0x4000 };
                TEST_CHECK(test_change_identity_updates(version, chunks[raw], single, 0) == 0);
                TEST_CHECK(test_change_identity_updates(version, chunks[raw], single, 1) == 0);
            }
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (unsigned raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u); ++raw) {
            const uint32_t chunks[] = { 0, 17, 0x4000 };
            TEST_CHECK(test_exact_cross_names(version, chunks[raw], 0, 0) == 0);
            if (version >= LIBMPQ_ARCHIVE_VERSION_3)
                TEST_CHECK(test_exact_cross_names(version, chunks[raw], 1, 0) == 0);
        }
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (unsigned layout = 0; layout < (version >= LIBMPQ_ARCHIVE_VERSION_3 ? 4u : 1u);
             ++layout)
            for (unsigned raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u); ++raw) {
                const uint32_t chunks[] = { 0, 17, 0x4000 };
                TEST_CHECK(
                    test_exact_updates(version, chunks[raw], layout, (uint8_t)(raw % 2), 0) == 0
                );
            }
    TEST_CHECK(test_exact_distinct(LIBMPQ_ARCHIVE_VERSION_1) == 0);
    TEST_CHECK(test_exact_distinct(LIBMPQ_ARCHIVE_VERSION_2) == 0);
    TEST_CHECK(test_exact_updates(LIBMPQ_ARCHIVE_VERSION_4, 17, 4, 0, 0) == 0);

    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         version++) {
        for (unsigned layout = 0; layout < (version >= LIBMPQ_ARCHIVE_VERSION_3 ? 3u : 1u);
             layout++)
            for (uint8_t single = 0; single < 2; single++)
                for (unsigned raw = 0; raw < (version == LIBMPQ_ARCHIVE_VERSION_4 ? 3u : 1u);
                     raw++) {
                    const uint32_t sizes[] = { 0, 17, 0x4000 };
                    TEST_CHECK(test_identity_access(version, sizes[raw], layout, single) == 0);
                }
    }

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
    for (unsigned layout = 0; layout < 4; ++layout)
        for (int mpqe = 0; mpqe < 2; ++mpqe) {
            TEST_CHECK(test_v4_updates(0, layout, mpqe) == 0);
            TEST_CHECK(test_v4_updates(0x4000, layout, mpqe) == 0);
            TEST_CHECK(test_v4_updates(17, layout, mpqe) == 0);
        }
    for (unsigned kind = 0; kind < 3; ++kind)
        for (unsigned encryption = 0; encryption < 3; ++encryption) {
            uint32_t flags = encryption ? LIBMPQ_FILE_FLAG_ENCRYPTED : 0;
            if (encryption == 2)
                flags |= LIBMPQ_FILE_FLAG_KEY;
            TEST_CHECK(test_v4_preserved_packed(0, flags, kind) == 0);
            TEST_CHECK(test_v4_preserved_packed(0x4000, flags, kind) == 0);
            TEST_CHECK(test_v4_preserved_packed(17, flags, kind) == 0);
        }
    for (unsigned layout = 0; layout < 3; ++layout)
        for (int mpqe = 0; mpqe < 2; ++mpqe) {
            TEST_CHECK(test_unknown_members(LIBMPQ_ARCHIVE_VERSION_3, layout, 0, mpqe) == 0);
            TEST_CHECK(test_unknown_members(LIBMPQ_ARCHIVE_VERSION_4, layout, 0, mpqe) == 0);
            TEST_CHECK(test_unknown_members(LIBMPQ_ARCHIVE_VERSION_4, layout, 17, mpqe) == 0);
            TEST_CHECK(test_unknown_members(LIBMPQ_ARCHIVE_VERSION_4, layout, 0x4000, mpqe) == 0);
        }
    for (int mixed = 0; mixed < 2; ++mixed) {
        TEST_CHECK(test_alias_probe_update(LIBMPQ_ARCHIVE_VERSION_3, 0, mixed) == 0);
        TEST_CHECK(test_alias_probe_update(LIBMPQ_ARCHIVE_VERSION_4, 0, mixed) == 0);
        TEST_CHECK(test_alias_probe_update(LIBMPQ_ARCHIVE_VERSION_4, 17, mixed) == 0);
        TEST_CHECK(test_alias_probe_update(LIBMPQ_ARCHIVE_VERSION_4, 0x4000, mixed) == 0);
    }
    TEST_CHECK(test_unknown_identity_limits() == 0);
    TEST_CHECK(test_unknown_collision() == 0);
    TEST_CHECK(test_v4_rejected_source(0) == 0);
    TEST_CHECK(test_v4_rejected_source(1) == 0);
    TEST_CHECK(test_mpqe_noop() == 0);
    TEST_CHECK(test_public_mpqe_updates() == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version) {
        TEST_CHECK(test_generic_add(version, 0, 1) == 0);
        TEST_CHECK(test_generic_add(version, 1, 1) == 0);
    }
    TEST_CHECK(test_generic_add(LIBMPQ_ARCHIVE_VERSION_4, 0, 0) == 0);
    TEST_CHECK(test_generic_add(LIBMPQ_ARCHIVE_VERSION_4, 1, 0) == 0);
    TEST_CHECK(test_generic_add(LIBMPQ_ARCHIVE_VERSION_3, 0, 0) == 0);
    TEST_CHECK(test_generic_add(LIBMPQ_ARCHIVE_VERSION_3, 1, 0) == 0);
    TEST_CHECK(test_named_reconstruction(0, LIBMPQ_ARCHIVE_VERSION_3) == 0);
    TEST_CHECK(test_named_reconstruction(1, LIBMPQ_ARCHIVE_VERSION_3) == 0);
    TEST_CHECK(test_named_reconstruction(0, LIBMPQ_ARCHIVE_VERSION_4) == 0);
    TEST_CHECK(test_named_reconstruction(1, LIBMPQ_ARCHIVE_VERSION_4) == 0);
    TEST_CHECK(test_v3_metadata_rollback() == 0);
    TEST_CHECK(test_v3_normalized_update(0) == 0);
    TEST_CHECK(test_v3_normalized_update(1) == 0);
    TEST_CHECK(test_compact_key_update(LIBMPQ_ARCHIVE_VERSION_1) == 0);
    TEST_CHECK(test_compact_key_update(LIBMPQ_ARCHIVE_VERSION_2) == 0);
    TEST_CHECK(test_key_patch_prefix(0) == 0);
    TEST_CHECK(test_key_patch_prefix(1) == 0);
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version) {
        for (int mpqe = 0; mpqe < 2; ++mpqe) {
            for (int embedded = 0; embedded < 2; ++embedded) {
                for (unsigned flags = 0; flags < 4; ++flags) {
                    uint32_t storage = LIBMPQ_FILE_FLAG_ENCRYPTED;
                    storage |= (flags & 1) != 0 ? LIBMPQ_FILE_FLAG_KEY : 0;
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
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_1; version <= LIBMPQ_ARCHIVE_VERSION_4;
         ++version)
        for (int mpqe = 0; mpqe < 2; ++mpqe)
            for (int commit = 0; commit < 2; ++commit) {
                TEST_CHECK(test_adoption_failure(UPDATE_FAULT_FLUSH, commit, mpqe, version) == 0);
                TEST_CHECK(test_adoption_failure(UPDATE_FAULT_CLOSE, commit, mpqe, version) == 0);
            }
    TEST_CHECK(test_add_dense(LIBMPQ_ARCHIVE_VERSION_1) == 0);
    TEST_CHECK(test_add_dense(LIBMPQ_ARCHIVE_VERSION_2) == 0);
    TEST_CHECK(test_add_dense(LIBMPQ_ARCHIVE_VERSION_3) == 0);
    TEST_CHECK(test_add_dense(LIBMPQ_ARCHIVE_VERSION_4) == 0);
    return 0;
}
