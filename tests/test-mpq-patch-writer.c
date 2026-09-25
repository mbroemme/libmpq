/*
 *  test-mpq-patch-writer.c -- private patch writer round-trip regressions.
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

#include "mpq-attributes.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-patch-writer.h"
#include "mpq-patch.h"
#include "mpq-source.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t old_data[] = "old payload";
static const uint8_t new_data[] = "new complete replacement";
static const uint8_t removed_data[] = "remove this member";
static const uint8_t retained_data[] = "keep this member";
static const uint64_t original_filetime = 132537600000000000ULL;

/* Create a deterministic ordinary base with three independently named files. */
static int
create_base(const char *path, uint32_t version)
{
    mpq_archive_create_options_s options = { version, 16, 4096, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_FILETIME |
                                                 LIBMPQ_ATTRIBUTE_MD5 |
                                                 LIBMPQ_ATTRIBUTE_PATCH_BIT };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_file_options_s marker = { LIBMPQ_FILE_FLAG_DELETE_MARKER, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;

    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "not-a-patch.txt", NULL, 0, &marker) ==
        LIBMPQ_ERROR_FORMAT
    );
    storage.locale = 0x409;
    storage.platform = 1;
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, "replace.txt", old_data, sizeof(old_data) - 1, &storage
        ) == LIBMPQ_SUCCESS
    );
    archive->write_attributes[0].filetime = original_filetime;
    storage.locale = 0;
    storage.platform = 0;
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, "remove.txt", removed_data, sizeof(removed_data) - 1, &storage
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        libmpq__archive_add_data(
            archive, "keep.txt", retained_data, sizeof(retained_data) - 1, &storage
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

/* Read a named file and compare its complete logical contents. */
static int
check_file(mpq_archive_s *archive, const char *name, const uint8_t *expected, size_t size)
{
    uint32_t number;
    uint8_t *actual = NULL;
    size_t actual_size = 0;

    TEST_CHECK(libmpq__file_number(archive, name, &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(test_archive_read(archive, number, &actual, &actual_size) == 0);
    TEST_CHECK(actual_size == size && memcmp(actual, expected, size) == 0);
    free(actual);
    return 0;
}

/* Confirm that the generated archive advertises patch semantics, not just bytes. */
static int
check_patch_archive(const char *path, uint8_t replace, uint8_t remove_member)
{
    mpq_archive_s *archive = NULL;
    mpq_file_attributes_s attributes;
    mpq_patch_info_s info;
    mpq_md5_s md5;
    uint8_t *stored = NULL;
    uint8_t digest[LIBMPQ_MD5_SIZE];
    size_t stored_size = 0;
    uint64_t offset;
    uint32_t number;
    uint32_t block;
    uint32_t flags;
    uint32_t attribute_flags;

    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_attributes(archive, &attribute_flags) == LIBMPQ_SUCCESS);
    TEST_CHECK((attribute_flags & LIBMPQ_ATTRIBUTE_FILETIME) == 0);
    TEST_CHECK(libmpq__file_number(archive, "(patch_metadata)", &number) == LIBMPQ_ERROR_EXIST);
    if (replace) {
        TEST_CHECK(libmpq__file_number(archive, "replace.txt", &number) == LIBMPQ_SUCCESS);
        block = archive->mpq_map[number].block_table_indices;
        TEST_CHECK(libmpq__file_flags(archive, number, &flags) == LIBMPQ_SUCCESS);
        TEST_CHECK((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) != 0);
        TEST_CHECK((flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) == 0);
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == LIBMPQ_SUCCESS);
        TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
        TEST_CHECK(attributes.patch_bit == 1);
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, new_data, sizeof(new_data) - 1);
        libmpq__md5_final(&md5, digest);
        TEST_CHECK(memcmp(attributes.md5, digest, sizeof(digest)) == 0);
        stored_size = archive->mpq_block[block].packed_size;
        TEST_CHECK(stored_size >= LIBMPQ_PATCH_INFO_SIZE + 68);
        stored = malloc(stored_size);
        TEST_CHECK(stored != NULL);
        offset = (uint64_t)archive->archive_offset + archive->mpq_block[block].offset +
                 ((uint64_t)archive->mpq_block_ex[block].offset_high << 32);
        TEST_CHECK(
            libmpq__source_read_at(archive->source, offset, stored, stored_size) == LIBMPQ_SUCCESS
        );
        TEST_CHECK(libmpq__patch_info_parse(stored, stored_size, &info) == LIBMPQ_SUCCESS);
        TEST_CHECK(info.length == LIBMPQ_PATCH_INFO_SIZE);
        TEST_CHECK(stored_size == info.length + info.data_size);
        TEST_CHECK(memcmp(stored + info.length, "PTCH", 4) == 0);
        TEST_CHECK(memcmp(stored + info.length + 40, digest, sizeof(digest)) == 0);
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, old_data, sizeof(old_data) - 1);
        libmpq__md5_final(&md5, digest);
        TEST_CHECK(memcmp(stored + info.length + 24, digest, sizeof(digest)) == 0);
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, stored + info.length, info.data_size);
        libmpq__md5_final(&md5, digest);
        TEST_CHECK(memcmp(info.md5, digest, sizeof(digest)) == 0);
        TEST_CHECK(memcmp(info.md5, attributes.md5, sizeof(digest)) != 0);
        free(stored);
        stored = NULL;
    }
    if (remove_member) {
        TEST_CHECK(libmpq__file_number(archive, "remove.txt", &number) == LIBMPQ_SUCCESS);
        block = archive->mpq_map[number].block_table_indices;
        TEST_CHECK(libmpq__file_flags(archive, number, &flags) == LIBMPQ_SUCCESS);
        TEST_CHECK((flags & LIBMPQ_FILE_FLAG_DELETE_MARKER) != 0);
        TEST_CHECK((flags & LIBMPQ_FILE_FLAG_PATCH_FILE) == 0);
        TEST_CHECK(archive->mpq_block[block].packed_size == 0);
        TEST_CHECK(archive->mpq_block[block].unpacked_size == 0);
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == LIBMPQ_SUCCESS);
        TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
        TEST_CHECK(attributes.patch_bit == 0);
        TEST_CHECK(archive->attributes != NULL);
        TEST_CHECK(block < archive->attributes->patch_bits);
        TEST_CHECK(
            (archive->attributes->data[archive->attributes->offsets[3] + block / 8] &
             (0x80u >> (block % 8))) == 0
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

/* The on-disk block describes the result, while TPatchInfo describes PTCH data. */
static int
test_patch_block_size(const char *path)
{
    mpq_archive_s *archive = NULL;
    mpq_patch_info_s info;
    uint8_t prefix[LIBMPQ_PATCH_INFO_SIZE];
    uint64_t offset;
    uint32_t number;
    uint32_t block;

    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(archive, "replace.txt", &number) == LIBMPQ_SUCCESS);
    block = archive->mpq_map[number].block_table_indices;
    TEST_CHECK(archive->mpq_block[block].unpacked_size == sizeof(new_data) - 1);
    offset = (uint64_t)archive->archive_offset + archive->mpq_block[block].offset +
             ((uint64_t)archive->mpq_block_ex[block].offset_high << 32);
    TEST_CHECK(
        libmpq__source_read_at(archive->source, offset, prefix, sizeof(prefix)) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == LIBMPQ_SUCCESS);
    TEST_CHECK(info.data_size == 68 + sizeof(new_data) - 1);
    TEST_CHECK(info.data_size != archive->mpq_block[block].unpacked_size);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

/* Exercise replacement, deletion, and both operations in one archive. */
static int
round_trip(uint32_t version, uint8_t replace, uint8_t remove_member)
{
    char base_path[1024];
    char patch_path[1024];
    const char *layers[] = { patch_path };
    mpq_patch_writer_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_archive_s *base = NULL;
    mpq_archive_s *result;
    mpq_stream_s *stream = NULL;
    mpq_file_attributes_s attributes;
    uint8_t streamed[sizeof(new_data)] = { 0 };
    libmpq__off_t transferred = 0;
    uint32_t number;

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "patch-writer-base") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-writer-output") == 0);
    TEST_CHECK(create_base(base_path, version) == 0);
    TEST_CHECK(libmpq__patch_writer_begin(&writer, base_path, patch_path) == LIBMPQ_SUCCESS);
    TEST_CHECK(writer != NULL);
    if (replace)
        TEST_CHECK(
            libmpq__patch_writer_replace(writer, "replace.txt", new_data, sizeof(new_data) - 1) ==
            LIBMPQ_SUCCESS
        );
    if (remove_member)
        TEST_CHECK(libmpq__patch_writer_remove(writer, "remove.txt") == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__patch_writer_finish(writer) == LIBMPQ_SUCCESS);
    TEST_CHECK(check_patch_archive(patch_path, replace, remove_member) == 0);
    if (replace)
        TEST_CHECK(test_patch_block_size(patch_path) == 0);

    TEST_CHECK(libmpq__archive_open(&base, base_path, 0) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_number(base, "replace.txt", &number) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__file_attributes(base, number, &attributes) == LIBMPQ_SUCCESS);
    TEST_CHECK(attributes.patch_bit == 0);
    TEST_CHECK(attributes.filetime == original_filetime);
    TEST_CHECK(check_file(base, "replace.txt", old_data, sizeof(old_data) - 1) == 0);
    TEST_CHECK(check_file(base, "remove.txt", removed_data, sizeof(removed_data) - 1) == 0);
    TEST_CHECK(libmpq__archive_close(base) == LIBMPQ_SUCCESS);

    TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 1) == LIBMPQ_SUCCESS);
    result = libmpq__patch_view_archive(view);
    TEST_CHECK(
        check_file(
            result, "replace.txt", replace ? new_data : old_data,
            replace ? sizeof(new_data) - 1 : sizeof(old_data) - 1
        ) == 0
    );
    TEST_CHECK(check_file(result, "keep.txt", retained_data, sizeof(retained_data) - 1) == 0);
    if (remove_member)
        TEST_CHECK(libmpq__file_number(result, "remove.txt", &number) == LIBMPQ_ERROR_EXIST);
    else
        TEST_CHECK(check_file(result, "remove.txt", removed_data, sizeof(removed_data) - 1) == 0);
    if (replace) {
        TEST_CHECK(libmpq__file_number(result, "replace.txt", &number) == LIBMPQ_SUCCESS);
        TEST_CHECK(libmpq__file_attributes(result, number, &attributes) == LIBMPQ_SUCCESS);
        TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
        TEST_CHECK(attributes.patch_bit == 1);
        TEST_CHECK(attributes.filetime == original_filetime);
        TEST_CHECK(libmpq__stream_open_name(result, "replace.txt", &stream) == LIBMPQ_SUCCESS);
        TEST_CHECK(
            libmpq__stream_read(stream, streamed, sizeof(new_data) - 1, &transferred) ==
            LIBMPQ_SUCCESS
        );
        TEST_CHECK(transferred == sizeof(new_data) - 1);
        TEST_CHECK(memcmp(streamed, new_data, sizeof(new_data) - 1) == 0);
        TEST_CHECK(libmpq__stream_close(stream) == LIBMPQ_SUCCESS);
    }
    TEST_CHECK(libmpq__patch_view_close(view) == LIBMPQ_SUCCESS);
    TEST_CHECK(remove(patch_path) == 0);
    TEST_CHECK(remove(base_path) == 0);
    return 0;
}

/* A plaintext name unlocks an encrypted base member during patch creation. */
static int
test_encrypted_base(void)
{
    char patch_path[1024];
    const char *layers[] = { patch_path };
    mpq_patch_writer_s *writer = NULL;
    mpq_patch_view_s *view = NULL;

    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-writer-encrypted") == 0);
    TEST_CHECK(
        libmpq__patch_writer_begin(&writer, FIXTURE_DIR "/mpq-v1-features.mpq", patch_path) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        libmpq__patch_writer_replace(
            writer, "encrypted-compress.txt", new_data, sizeof(new_data) - 1
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__patch_writer_finish(writer) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", layers, 1) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        check_file(
            libmpq__patch_view_archive(view), "encrypted-compress.txt", new_data,
            sizeof(new_data) - 1
        ) == 0
    );
    TEST_CHECK(libmpq__patch_view_close(view) == LIBMPQ_SUCCESS);
    TEST_CHECK(remove(patch_path) == 0);
    return 0;
}

/* Materializing a generated patch must not drop an unlisted base member. */
static int
test_unlisted_base_member(void)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    char base_path[1024];
    char patch_path[1024];
    const char *layers[] = { patch_path };
    mpq_archive_s *base = NULL;
    mpq_patch_writer_s *writer = NULL;
    mpq_patch_view_s *view = NULL;

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "patch-writer-unlisted-base") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-writer-unlisted") == 0);
    TEST_CHECK(libmpq__archive_create(&base, base_path, &options) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__archive_add_data(base, "replace.txt", old_data, sizeof(old_data) - 1, &storage) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        libmpq__archive_add_data(
            base, "unlisted.txt", retained_data, sizeof(retained_data) - 1, &storage
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__archive_close(base) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__patch_writer_begin(&writer, base_path, patch_path) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__patch_writer_replace(writer, "replace.txt", new_data, sizeof(new_data) - 1) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__patch_writer_finish(writer) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 1) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        check_file(
            libmpq__patch_view_archive(view), "unlisted.txt", retained_data,
            sizeof(retained_data) - 1
        ) == 0
    );
    TEST_CHECK(libmpq__patch_view_close(view) == LIBMPQ_SUCCESS);
    TEST_CHECK(remove(patch_path) == 0);
    TEST_CHECK(remove(base_path) == 0);
    return 0;
}

/* An aborted writer does not publish its partial patch archive. */
static int
test_abort(void)
{
    char base_path[1024];
    char patch_path[1024];
    mpq_patch_writer_s *writer = NULL;
    FILE *published;
    uint8_t unexpectedly_published;

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "patch-writer-abort-base") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-writer-abort") == 0);
    TEST_CHECK(create_base(base_path, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(libmpq__patch_writer_begin(&writer, base_path, patch_path) == LIBMPQ_SUCCESS);
    TEST_CHECK(
        libmpq__patch_writer_replace(writer, "missing.txt", new_data, sizeof(new_data) - 1) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__patch_writer_replace(writer, "replace.txt", new_data, sizeof(new_data) - 1) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__patch_writer_abort(writer) == LIBMPQ_SUCCESS);
    published = fopen(patch_path, "rb");
    unexpectedly_published = published != NULL;
    if (published != NULL)
        (void)fclose(published);
    TEST_CHECK(unexpectedly_published == 0);
    TEST_CHECK(remove(base_path) == 0);
    return 0;
}

/* MPQE and embedded bases are not converted to ordinary patch outputs. */
static int
test_unsupported_base(void)
{
    char patch_path[1024];
    mpq_patch_writer_s *writer = NULL;

    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-writer-unsupported") == 0);
    TEST_CHECK(
        libmpq__patch_writer_begin(&writer, FIXTURE_DIR "/mpq-v1-features.mpqe", patch_path) !=
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(writer == NULL);
    TEST_CHECK(
        libmpq__patch_writer_begin(&writer, FIXTURE_DIR "/mpq-v1-features.w3x", patch_path) !=
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(writer == NULL);
    return 0;
}

int
main(void)
{
    TEST_CHECK(round_trip(LIBMPQ_ARCHIVE_VERSION_ONE, 1, 0) == 0);
    TEST_CHECK(round_trip(LIBMPQ_ARCHIVE_VERSION_ONE, 0, 1) == 0);
    TEST_CHECK(round_trip(LIBMPQ_ARCHIVE_VERSION_ONE, 1, 1) == 0);
    TEST_CHECK(round_trip(LIBMPQ_ARCHIVE_VERSION_TWO, 1, 1) == 0);
    TEST_CHECK(test_encrypted_base() == 0);
    TEST_CHECK(test_unlisted_base_member() == 0);
    TEST_CHECK(test_abort() == 0);
    TEST_CHECK(test_unsupported_base() == 0);
    return 0;
}
