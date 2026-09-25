/*
 *  test-mpq-patch.c -- deterministic private MPQ patch-view regressions.
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
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-patch.h"
#include "mpq-source.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static const uint8_t first_text[] = "Patch layer one\n";
static const uint8_t second_text[] = "Patch layer two\n";
static const uint8_t v2_text[] = "Version two patch\n";
static const uint8_t new_text[] = "Patch-only member\n";

/* Calculate a fixture digest using the library's private MD5 implementation. */
static void
fixture_md5(const uint8_t *data, size_t size, uint8_t digest[16])
{
    mpq_md5_s state;

    libmpq__md5_init(&state);
    libmpq__md5_update(&state, data, size);
    libmpq__md5_final(&state, digest);
}

/* Serialize a minimal valid COPY patch with its MPQ patch-info prefix. */
static uint8_t *
fixture_copy_patch(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    size_t *stored_size
)
{
    size_t payload_size = 68 + after_size;
    uint8_t *stored = calloc(1, 28 + payload_size);
    uint8_t *patch;

    if (stored == NULL || before_size > UINT32_MAX || after_size > UINT32_MAX - 68) {
        free(stored);
        return NULL;
    }
    patch = stored + 28;
    libmpq__store_le32(stored, 28);
    libmpq__store_le32(stored + 4, 0x80000000u);
    libmpq__store_le32(stored + 8, (uint32_t)payload_size);
    memcpy(patch, "PTCH", 4);
    libmpq__store_le32(patch + 4, (uint32_t)payload_size);
    libmpq__store_le32(patch + 8, (uint32_t)before_size);
    libmpq__store_le32(patch + 12, (uint32_t)after_size);
    memcpy(patch + 16, "MD5_", 4);
    libmpq__store_le32(patch + 20, 40);
    fixture_md5(before, before_size, patch + 24);
    fixture_md5(after, after_size, patch + 40);
    memcpy(patch + 56, "XFRM", 4);
    libmpq__store_le32(patch + 60, (uint32_t)after_size + 12);
    memcpy(patch + 64, "COPY", 4);
    memcpy(patch + 68, after, after_size);
    fixture_md5(patch, payload_size, stored + 12);
    *stored_size = 28 + payload_size;
    return stored;
}

/* Build one small patch MPQ using only deterministic, local test bytes. */
static int
fixture_patch_archive(
    const char *path, uint32_t version, const uint8_t *before, size_t before_size,
    const uint8_t *after, size_t after_size, const char *deleted
)
{
    mpq_archive_create_options_s options = { version, 16, 4096, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             version == LIBMPQ_ARCHIVE_VERSION_TWO
                                                 ? LIBMPQ_ATTRIBUTE_PATCH_BIT
                                                 : 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    uint8_t *stored;
    size_t stored_size = 0;

    stored = fixture_copy_patch(before, before_size, after, after_size, &stored_size);
    TEST_CHECK(stored != NULL);
    TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", stored, (libmpq__off_t)stored_size, &storage
        ) == 0
    );
    writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_PATCH_FILE;
    if (deleted != NULL) {
        TEST_CHECK(libmpq__archive_add_data(writer, deleted, NULL, 0, &storage) == 0);
        writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
    }
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "patch-only.txt", new_text, sizeof(new_text) - 1, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    free(stored);
    return 0;
}

/* Wrap an ordinary patch MPQ with a deterministic 512-byte map-style prefix. */
static int
fixture_container(const char *source, const char *destination)
{
    uint8_t *archive = NULL;
    size_t size = 0;
    uint8_t prefix[512] = { 0 };
    FILE *output;

    TEST_CHECK(test_read_path(source, &archive, &size) == 0);
    output = fopen(destination, "wb");
    TEST_CHECK(output != NULL);
    TEST_CHECK(fwrite(prefix, 1, sizeof(prefix), output) == sizeof(prefix));
    TEST_CHECK(fwrite(archive, 1, size, output) == size);
    TEST_CHECK(fclose(output) == 0);
    free(archive);
    return 0;
}

/* Regenerate the three repository patch fixtures from the canonical bases. */
static int
refresh_fixtures(void)
{
    mpq_archive_s *base = NULL;
    uint8_t *original = NULL;
    size_t original_size = 0;
    uint32_t number;
    char intermediate[1024];

    TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v1-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(base, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(base, number, &original, &original_size) == 0);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    TEST_CHECK(
        fixture_patch_archive(
            FIXTURE_DIR "/mpq-v1-features-patch.mpq", LIBMPQ_ARCHIVE_VERSION_ONE, original,
            original_size, first_text, sizeof(first_text) - 1, "pkware.txt"
        ) == 0
    );
    free(original);
    TEST_CHECK(
        snprintf(intermediate, sizeof(intermediate), "%s/mpq-v1-patch-second.mpq", FIXTURE_DIR) > 0
    );
    TEST_CHECK(
        fixture_patch_archive(
            intermediate, LIBMPQ_ARCHIVE_VERSION_ONE, first_text, sizeof(first_text) - 1,
            second_text, sizeof(second_text) - 1, "bzip2.txt"
        ) == 0
    );
    TEST_CHECK(fixture_container(intermediate, FIXTURE_DIR "/mpq-v1-features-patch.w3x") == 0);
    TEST_CHECK(remove(intermediate) == 0);

    TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v2-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(base, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(base, number, &original, &original_size) == 0);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    TEST_CHECK(
        fixture_patch_archive(
            FIXTURE_DIR "/mpq-v2-features-patch.mpq", LIBMPQ_ARCHIVE_VERSION_TWO, original,
            original_size, v2_text, sizeof(v2_text) - 1, "pkware.txt"
        ) == 0
    );
    free(original);
    return 0;
}

/* Assert that ordinary reads and logical streams agree on patched contents. */
static int
check_view(mpq_patch_view_s *view, const uint8_t *expected, size_t expected_size)
{
    mpq_archive_s *archive = libmpq__patch_view_archive(view);
    mpq_stream_s *stream = NULL;
    uint8_t *data = NULL;
    size_t size = 0;
    libmpq__off_t transferred = 0;
    uint32_t number;

    TEST_CHECK(archive != NULL);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(size == expected_size && memcmp(data, expected, size) == 0);
    free(data);
    data = malloc(expected_size);
    TEST_CHECK(data != NULL);
    TEST_CHECK(libmpq__stream_open_name(archive, "overview.txt", &stream) == 0);
    TEST_CHECK(libmpq__stream_read(stream, data, (libmpq__off_t)expected_size, &transferred) == 0);
    TEST_CHECK(transferred == (libmpq__off_t)expected_size);
    TEST_CHECK(memcmp(data, expected, expected_size) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    free(data);
    TEST_CHECK(libmpq__file_number(archive, "patch-only.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(size == sizeof(new_text) - 1 && memcmp(data, new_text, size) == 0);
    free(data);
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(size != 0);
    {
        char *text = malloc(size + 1);

        TEST_CHECK(text != NULL);
        memcpy(text, data, size);
        text[size] = '\0';
        TEST_CHECK(strstr(text, "patch-only.txt") != NULL);
        free(text);
    }
    free(data);
    TEST_CHECK(libmpq__file_number(archive, "(patch_metadata)", &number) == LIBMPQ_ERROR_EXIST);
    return 0;
}

/* Exercise replacement, deletion, ordered chains, and the embedded container. */
static int
test_views(void)
{
    mpq_patch_view_s *view = NULL;
    uint32_t number;
    const char *v1[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq" };
    const char *chain[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq",
                            FIXTURE_DIR "/mpq-v1-features-patch.w3x" };
    const char *v2[] = { FIXTURE_DIR "/mpq-v2-features-patch.mpq" };
    uint32_t signatures = UINT32_MAX;

    TEST_CHECK(libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", v1, 1) == 0);
    TEST_CHECK(check_view(view, first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "pkware.txt", &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "(signature)", &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__archive_signatures(libmpq__patch_view_archive(view), &signatures) == 0);
    TEST_CHECK(signatures == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", chain, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "bzip2.txt", &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.w3x", chain, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v2-features.mpq", v2, 1) == 0);
    TEST_CHECK(check_view(view, v2_text, sizeof(v2_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    return 0;
}

/* Embedded views retain the map-style prefix and arbitrary trailing bytes. */
static int
test_container_bytes(void)
{
    static const uint8_t suffix[] = "unrelated-container-tail";
    const char *layers[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq",
                             FIXTURE_DIR "/mpq-v1-features-patch.w3x" };
    uint8_t *original = NULL;
    uint8_t *prefix = NULL;
    uint8_t actual[sizeof(suffix) - 1];
    size_t original_size = 0;
    mpq_patch_view_s *view = NULL;
    mpq_archive_s *archive;
    mpq_archive_s *base = NULL;
    libmpq__off_t expected_offset;
    FILE *file;
    char path[1024];

    TEST_CHECK(test_read_path(FIXTURE_DIR "/mpq-v1-features.w3x", &original, &original_size) == 0);
    TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v1-features.w3x", -1) == 0);
    expected_offset = base->archive_offset;
    TEST_CHECK(expected_offset > 0 && (uint64_t)expected_offset < original_size);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "patch-container") == 0);
    file = fopen(path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(original, 1, original_size, file) == original_size);
    TEST_CHECK(fwrite(suffix, 1, sizeof(suffix) - 1, file) == sizeof(suffix) - 1);
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, path, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    archive = libmpq__patch_view_archive(view);
    TEST_CHECK(archive->archive_offset == expected_offset);
    prefix = malloc((size_t)archive->archive_offset);
    TEST_CHECK(prefix != NULL);
    TEST_CHECK(
        libmpq__source_read_at(archive->source, 0, prefix, (size_t)archive->archive_offset) == 0
    );
    TEST_CHECK(memcmp(prefix, original, (size_t)archive->archive_offset) == 0);
    TEST_CHECK(archive->file_size >= sizeof(actual));
    TEST_CHECK(
        libmpq__source_read_at(
            archive->source, archive->file_size - sizeof(actual), actual, sizeof(actual)
        ) == 0
    );
    TEST_CHECK(memcmp(actual, suffix, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(path) == 0);
    free(prefix);
    free(original);
    return 0;
}

/* A metadata-only layer must not invalidate an otherwise untouched signature. */
static int
test_noop_signature(void)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 4, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    uint32_t signatures = 0;
    char path[1024];
    const char *layers[] = { path };

    TEST_CHECK(test_temp_path(path, sizeof(path), "patch-noop-signature") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", layers, 1) == 0);
    TEST_CHECK(libmpq__archive_signatures(libmpq__patch_view_archive(view), &signatures) == 0);
    TEST_CHECK(signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG));
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* PATCH_BIT alone is not a patch indicator, and MPQE chains stay unsupported. */
static int
test_unsupported_layers(void)
{
    mpq_patch_view_s *view = NULL;
    const char *ordinary[] = { FIXTURE_DIR "/mpq-v2-features.mpq" };
    const char *patches[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq" };
    const char *encrypted_patch[] = { FIXTURE_DIR "/mpq-v1-features.mpqe" };

    TEST_CHECK(
        libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", ordinary, 1) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(view == NULL);
    TEST_CHECK(
        libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", encrypted_patch, 1) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(view == NULL);
    TEST_CHECK(
        libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpqe", patches, 1) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(view == NULL);
    return 0;
}

/* An unknown new hash cannot be inserted without its name's probe position. */
static int
test_unlisted_patch_member(void)
{
    mpq_archive_s *writer = NULL;
    mpq_archive_s *patch = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 4, 4096,
                                             LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    char path[1024];
    const char *patches[] = { path };

    for (uint32_t mode = 0; mode < 2; mode++) {
        uint32_t number;

        options.flags = mode == 0 ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE;
        TEST_CHECK(test_temp_path(path, sizeof(path), "patch-unlisted") == 0);
        TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_add_data(writer, "hidden.txt", (const uint8_t *)"new", 3, &storage) == 0
        );
        if (mode != 0) {
            char *hidden = malloc(1);

            TEST_CHECK(hidden != NULL);
            hidden[0] = '\0';
            free(writer->write_names[writer->write_next_block - 1]);
            writer->write_names[writer->write_next_block - 1] = hidden;
        }
        TEST_CHECK(libmpq__archive_close(writer) == 0);
        writer = NULL;
        TEST_CHECK(libmpq__archive_open(&patch, path, 0) == 0);
        TEST_CHECK(
            libmpq__file_number(patch, "(listfile)", &number) ==
            (mode == 0 ? LIBMPQ_ERROR_EXIST : LIBMPQ_SUCCESS)
        );
        TEST_CHECK(libmpq__archive_close(patch) == 0);
        patch = NULL;
        TEST_CHECK(
            libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", patches, 1) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(view == NULL);
        TEST_CHECK(remove(path) == 0);
    }
    return 0;
}

/* Existing hashes identify patch entries even without a complete listfile. */
static int
test_missing_listfile(void)
{
    mpq_archive_s *base = NULL;
    mpq_archive_s *patch = NULL;
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    uint8_t *before = NULL;
    uint8_t *stored = NULL;
    size_t before_size = 0;
    size_t stored_size = 0;
    uint32_t number;
    char path[1024];
    const char *patches[] = { path };

    TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v1-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(base, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(base, number, &before, &before_size) == 0);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    stored =
        fixture_copy_patch(before, before_size, first_text, sizeof(first_text) - 1, &stored_size);
    TEST_CHECK(stored != NULL);
    for (uint32_t mode = 0; mode < 2; mode++) {
        options.flags = mode == 0 ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE;
        TEST_CHECK(test_temp_path(path, sizeof(path), "patch-no-listfile") == 0);
        TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, "overview.txt", stored, (libmpq__off_t)stored_size, &storage
            ) == 0
        );
        writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_PATCH_FILE;
        if (mode != 0) {
            char *hidden = malloc(1);

            TEST_CHECK(hidden != NULL);
            hidden[0] = '\0';
            free(writer->write_names[writer->write_next_block - 1]);
            writer->write_names[writer->write_next_block - 1] = hidden;
        }
        TEST_CHECK(libmpq__archive_add_data(writer, "pkware.txt", NULL, 0, &storage) == 0);
        writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
        TEST_CHECK(libmpq__archive_close(writer) == 0);
        writer = NULL;
        TEST_CHECK(libmpq__archive_open(&patch, path, 0) == 0);
        TEST_CHECK(
            libmpq__file_number(patch, "(listfile)", &number) ==
            (mode == 0 ? LIBMPQ_ERROR_EXIST : LIBMPQ_SUCCESS)
        );
        TEST_CHECK(libmpq__archive_close(patch) == 0);
        patch = NULL;
        TEST_CHECK(
            libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v1-features.mpq", patches, 1) == 0
        );
        TEST_CHECK(
            libmpq__file_number(libmpq__patch_view_archive(view), "(listfile)", &number) == 0
        );
        TEST_CHECK(
            libmpq__file_number(libmpq__patch_view_archive(view), "pkware.txt", &number) ==
            LIBMPQ_ERROR_EXIST
        );
        TEST_CHECK(
            libmpq__file_number(libmpq__patch_view_archive(view), "overview.txt", &number) == 0
        );
        {
            uint8_t *actual = NULL;
            size_t actual_size = 0;

            TEST_CHECK(
                test_archive_read(
                    libmpq__patch_view_archive(view), number, &actual, &actual_size
                ) == 0
            );
            TEST_CHECK(actual_size == sizeof(first_text) - 1);
            TEST_CHECK(memcmp(actual, first_text, actual_size) == 0);
            free(actual);
        }
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
        TEST_CHECK(remove(path) == 0);
    }
    free(stored);
    free(before);
    return 0;
}

/* Patch overlay splits a shared alias instead of inheriting update rejection. */
static int
test_shared_base_block(void)
{
    mpq_archive_s *fixture = NULL;
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    uint8_t *before = NULL;
    uint8_t *actual = NULL;
    size_t before_size = 0;
    size_t actual_size = 0;
    uint32_t first = UINT32_MAX;
    uint32_t second = UINT32_MAX;
    uint32_t number;
    char path[1024];
    const char *patches[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq" };

    TEST_CHECK(libmpq__archive_open(&fixture, FIXTURE_DIR "/mpq-v1-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(fixture, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(fixture, number, &before, &before_size) == 0);
    TEST_CHECK(libmpq__archive_close(fixture) == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "patch-shared-base") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", before, (libmpq__off_t)before_size, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, "alias-b", before, (libmpq__off_t)before_size, &storage) ==
        0
    );
    for (uint32_t i = 0; i < writer->mpq_header.hash_table_count; i++) {
        if (writer->mpq_hash[i].hash_a == libmpq__crypto_hash_string("overview.txt", 0x100) &&
            writer->mpq_hash[i].hash_b == libmpq__crypto_hash_string("overview.txt", 0x200))
            first = i;
        if (writer->mpq_hash[i].hash_a == libmpq__crypto_hash_string("alias-b", 0x100) &&
            writer->mpq_hash[i].hash_b == libmpq__crypto_hash_string("alias-b", 0x200))
            second = i;
    }
    TEST_CHECK(first != UINT32_MAX && second != UINT32_MAX);
    writer->mpq_hash[second].block_table_index = writer->mpq_hash[first].block_table_index;
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, path, patches, 1) == 0);
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "overview.txt", &number) == 0);
    TEST_CHECK(
        test_archive_read(libmpq__patch_view_archive(view), number, &actual, &actual_size) == 0
    );
    TEST_CHECK(actual_size == sizeof(first_text) - 1);
    TEST_CHECK(memcmp(actual, first_text, actual_size) == 0);
    free(actual);
    actual = NULL;
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "alias-b", &number) == 0);
    TEST_CHECK(
        test_archive_read(libmpq__patch_view_archive(view), number, &actual, &actual_size) == 0
    );
    TEST_CHECK(actual_size == before_size);
    TEST_CHECK(memcmp(actual, before, before_size) == 0);
    free(actual);
    free(before);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Relocating a file must carry its attributes, not its old physical row. */
static int
test_attribute_identity_remap(
    const char *base_path, uint32_t original_block, const mpq_file_attributes_s *original
)
{
    static const uint8_t changed_b[] = "Changed patch-only member\n";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_TWO, 16, 4096,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    mpq_archive_s *base = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_file_attributes_s attributes;
    mpq_file_attributes_s original_b;
    uint8_t expected_a_md5[16];
    uint8_t expected_b_md5[16];
    uint32_t expected_a_crc;
    uint32_t expected_b_crc;
    uint8_t *actual = NULL;
    size_t actual_size = 0;
    uint32_t number;
    uint32_t original_b_block;
    char patch_b[1024];
    char patch_a[1024];
    const char *layers[] = { patch_b, patch_a };

    TEST_CHECK(libmpq__archive_open(&base, base_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(base, "patch-only.txt", &number) == 0);
    original_b_block = base->mpq_map[number].block_table_indices;
    TEST_CHECK(libmpq__file_attributes(base, number, &original_b) == 0);
    TEST_CHECK(
        (original->flags & (LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_FILETIME |
                            LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_PATCH_BIT)) ==
        (LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_FILETIME | LIBMPQ_ATTRIBUTE_MD5 |
         LIBMPQ_ATTRIBUTE_PATCH_BIT)
    );
    TEST_CHECK(original_b.patch_bit == 0);
    fixture_md5(second_text, sizeof(second_text) - 1, expected_a_md5);
    fixture_md5(changed_b, sizeof(changed_b) - 1, expected_b_md5);
    expected_a_crc = (uint32_t)crc32(0, second_text, sizeof(second_text) - 1);
    expected_b_crc = (uint32_t)crc32(0, changed_b, sizeof(changed_b) - 1);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    TEST_CHECK(test_temp_path(patch_b, sizeof(patch_b), "patch-identity-b") == 0);
    TEST_CHECK(test_temp_path(patch_a, sizeof(patch_a), "patch-identity-a") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, patch_b, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "patch-only.txt", changed_b, sizeof(changed_b) - 1, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__archive_create(&writer, patch_a, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", second_text, sizeof(second_text) - 1, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    for (size_t count = 1; count <= 2; count++) {
        mpq_archive_s *result;

        TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, count) == 0);
        result = libmpq__patch_view_archive(view);
        TEST_CHECK(libmpq__file_number(result, "overview.txt", &number) == 0);
        TEST_CHECK(libmpq__file_attributes(result, number, &attributes) == 0);
        TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
        TEST_CHECK(attributes.patch_bit == 1);
        TEST_CHECK(attributes.filetime == original->filetime);
        if (count == 1) {
            TEST_CHECK(result->mpq_map[number].block_table_indices == original_block);
            TEST_CHECK(attributes.crc32 == original->crc32);
            TEST_CHECK(memcmp(attributes.md5, original->md5, sizeof(attributes.md5)) == 0);
        }
        if (count == 2) {
            TEST_CHECK(result->mpq_map[number].block_table_indices != original_block);
            TEST_CHECK(attributes.crc32 == expected_a_crc);
            TEST_CHECK(memcmp(attributes.md5, expected_a_md5, sizeof(expected_a_md5)) == 0);
            TEST_CHECK(test_archive_read(result, number, &actual, &actual_size) == 0);
            TEST_CHECK(actual_size == sizeof(second_text) - 1);
            TEST_CHECK(memcmp(actual, second_text, actual_size) == 0);
            free(actual);
            actual = NULL;
        }
        TEST_CHECK(libmpq__file_number(result, "patch-only.txt", &number) == 0);
        TEST_CHECK(result->mpq_map[number].block_table_indices != original_b_block);
        TEST_CHECK(libmpq__file_attributes(result, number, &attributes) == 0);
        TEST_CHECK(attributes.patch_bit == original_b.patch_bit);
        TEST_CHECK(attributes.filetime == original_b.filetime);
        TEST_CHECK(attributes.crc32 == expected_b_crc);
        TEST_CHECK(memcmp(attributes.md5, expected_b_md5, sizeof(expected_b_md5)) == 0);
        TEST_CHECK(test_archive_read(result, number, &actual, &actual_size) == 0);
        TEST_CHECK(actual_size == sizeof(changed_b) - 1);
        TEST_CHECK(memcmp(actual, changed_b, actual_size) == 0);
        free(actual);
        actual = NULL;
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
    }
    TEST_CHECK(remove(patch_b) == 0);
    TEST_CHECK(remove(patch_a) == 0);
    return 0;
}

/* PATCH_BIT is still read as attributes metadata, never written as true. */
static int
test_patch_bit(void)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_file_attributes_s attributes;
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_TWO, 16, 4096,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    uint8_t *bytes = NULL;
    uint8_t *original = NULL;
    size_t size = 0;
    size_t original_size = 0;
    uint64_t bit_offset;
    uint32_t data_block;
    uint32_t attributes_number;
    uint32_t attributes_block;
    uint32_t number;
    FILE *file;
    char path[1024];
    char plain_path[1024];
    const char *ordinary[] = { FIXTURE_DIR "/mpq-v2-features-patch.mpq" };

    TEST_CHECK(libmpq__archive_open(&archive, FIXTURE_DIR "/mpq-v2-features-patch.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
    TEST_CHECK(attributes.patch_bit == 0);
    TEST_CHECK(
        libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v2-features.mpq", ordinary, 1) == 0
    );
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(libmpq__patch_view_archive(view), number, &attributes) == 0);
    TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
    TEST_CHECK(attributes.patch_bit == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = libmpq__patch_view_archive(view);
    TEST_CHECK(libmpq__attributes_load(archive) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    data_block = archive->mpq_map[number].block_table_indices;
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &attributes_number) == 0);
    attributes_block = archive->mpq_map[attributes_number].block_table_indices;
    TEST_CHECK((archive->mpq_block[attributes_block].flags & LIBMPQ_FLAG_SINGLE) != 0);
    TEST_CHECK(
        archive->mpq_block[attributes_block].packed_size ==
        archive->mpq_block[attributes_block].unpacked_size
    );
    bit_offset = (uint64_t)archive->archive_offset + archive->mpq_block[attributes_block].offset +
                 archive->attributes->offsets[3] + data_block / 8;
    TEST_CHECK(test_read_path(archive->filename, &bytes, &size) == 0);
    TEST_CHECK(bit_offset < size);
    bytes[bit_offset] |= (uint8_t)(0x80u >> (data_block % 8));
    TEST_CHECK(test_temp_path(path, sizeof(path), "patch-bit-true") == 0);
    file = fopen(path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(bytes, 1, size, file) == size);
    TEST_CHECK(fclose(file) == 0);
    free(bytes);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
    TEST_CHECK(attributes.patch_bit == 1);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_attribute_identity_remap(path, data_block, &attributes) == 0);
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, FIXTURE_DIR "/mpq-v2-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &original, &original_size) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_temp_path(plain_path, sizeof(plain_path), "patch-no-base-attributes") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, plain_path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", original, (libmpq__off_t)original_size, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    free(original);
    TEST_CHECK(libmpq__patch_view_open(&view, plain_path, ordinary, 1) == 0);
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(libmpq__patch_view_archive(view), number, &attributes) == 0);
    TEST_CHECK((attributes.flags & LIBMPQ_ATTRIBUTE_PATCH_BIT) != 0);
    TEST_CHECK(attributes.patch_bit == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(plain_path) == 0);
    return 0;
}

/* Verify the bounded BSD0 delta path and reject damaged patch metadata. */
static int
test_patch_payload_validation(void)
{
    static const uint8_t before[] = { 'a', 'b', 'c' };
    static const uint8_t after[] = { 'a', 'b', 'd' };
    uint8_t patch[68 + 32 + 12 + 3] = { 0 };
    uint8_t moving[68 + 32 + 24 + 2] = { 0 };
    uint8_t rle[68 + 4 + 2 * (sizeof(patch) - 68)] = { 0 };
    uint8_t prefix[28] = { 0 };
    uint8_t *result = NULL;
    size_t result_size = 0;
    mpq_patch_info_s info;

    memcpy(patch, "PTCH", 4);
    libmpq__store_le32(patch + 4, sizeof(patch));
    libmpq__store_le32(patch + 8, sizeof(before));
    libmpq__store_le32(patch + 12, sizeof(after));
    memcpy(patch + 16, "MD5_", 4);
    libmpq__store_le32(patch + 20, 40);
    fixture_md5(before, sizeof(before), patch + 24);
    fixture_md5(after, sizeof(after), patch + 40);
    memcpy(patch + 56, "XFRM", 4);
    libmpq__store_le32(patch + 60, sizeof(patch) - 56);
    memcpy(patch + 64, "BSD0", 4);
    memcpy(patch + 68, "BSDIFF40", 8);
    libmpq__store_le64(patch + 76, 12);
    libmpq__store_le64(patch + 84, 3);
    libmpq__store_le64(patch + 92, 3);
    libmpq__store_le32(patch + 100, 3);
    patch[114] = 1;
    TEST_CHECK(
        libmpq__patch_apply(before, sizeof(before), patch, sizeof(patch), &result, &result_size) ==
        0
    );
    TEST_CHECK(result_size == sizeof(after) && memcmp(result, after, sizeof(after)) == 0);
    free(result);
    result = NULL;
    patch[114] = 2;
    TEST_CHECK(
        libmpq__patch_apply(before, sizeof(before), patch, sizeof(patch), &result, &result_size) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(result == NULL && result_size == 0);
    patch[114] = 1;
    memcpy(rle, patch, 68);
    {
        size_t input = 68;
        size_t output = 72;

        while (input < sizeof(patch)) {
            uint8_t zero = patch[input] == 0;
            size_t start = input;

            while (input < sizeof(patch) && (patch[input] == 0) == zero && input - start < 128)
                input++;
            rle[output++] = (uint8_t)((zero ? 0 : 0x80u) | (input - start - 1));
            if (!zero) {
                memcpy(rle + output, patch + start, input - start);
                output += input - start;
            }
        }
        TEST_CHECK(output - 68 < sizeof(patch) - 68);
        libmpq__store_le32(rle + 60, (uint32_t)(output - 56));
        TEST_CHECK(
            libmpq__patch_apply(before, sizeof(before), rle, output, &result, &result_size) == 0
        );
    }
    TEST_CHECK(result_size == sizeof(after) && memcmp(result, after, sizeof(after)) == 0);
    free(result);
    result = NULL;
    memcpy(moving, "PTCH", 4);
    libmpq__store_le32(moving + 4, sizeof(moving));
    libmpq__store_le32(moving + 8, sizeof(before));
    libmpq__store_le32(moving + 12, 2);
    memcpy(moving + 16, "MD5_", 4);
    libmpq__store_le32(moving + 20, 40);
    fixture_md5(before, sizeof(before), moving + 24);
    fixture_md5((const uint8_t *)"ba", 2, moving + 40);
    memcpy(moving + 56, "XFRM", 4);
    libmpq__store_le32(moving + 60, sizeof(moving) - 56);
    memcpy(moving + 64, "BSD0", 4);
    memcpy(moving + 68, "BSDIFF40", 8);
    libmpq__store_le64(moving + 76, 24);
    libmpq__store_le64(moving + 84, 2);
    libmpq__store_le64(moving + 92, 2);
    libmpq__store_le32(moving + 100, 1);
    libmpq__store_le32(moving + 108, 0x80000001u);
    libmpq__store_le32(moving + 112, 1);
    moving[124] = 1;
    TEST_CHECK(
        libmpq__patch_apply(
            before, sizeof(before), moving, sizeof(moving), &result, &result_size
        ) == 0
    );
    TEST_CHECK(result_size == 2 && memcmp(result, "ba", 2) == 0);
    free(result);
    result = NULL;
    libmpq__store_le32(prefix, sizeof(prefix));
    libmpq__store_le32(prefix + 4, 0x80000000u);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == 0);
    libmpq__store_le32(prefix, sizeof(prefix) + 1);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

/* An unrelated patch must retain base members absent from its listfile. */
static int
test_unknown_base_name(void)
{
    mpq_archive_s *fixture = NULL;
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    uint8_t *overview = NULL;
    uint8_t *unknown = NULL;
    size_t overview_size = 0;
    size_t unknown_size = 0;
    uint32_t number;
    char path[1024];
    const char *patches[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq" };

    TEST_CHECK(libmpq__archive_open(&fixture, FIXTURE_DIR "/mpq-v1-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(fixture, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(fixture, number, &overview, &overview_size) == 0);
    TEST_CHECK(libmpq__archive_close(fixture) == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "patch-unknown") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", overview, (libmpq__off_t)overview_size, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, "pkware.txt", (const uint8_t *)"old", 3, &storage) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, "unknown.txt", (const uint8_t *)"kept", 4, &storage) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    free(overview);
    TEST_CHECK(libmpq__patch_view_open(&view, path, patches, 1) == 0);
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "unknown.txt", &number) == 0);
    TEST_CHECK(
        test_archive_read(libmpq__patch_view_archive(view), number, &unknown, &unknown_size) == 0
    );
    TEST_CHECK(unknown_size == 4 && memcmp(unknown, "kept", 4) == 0);
    free(unknown);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* A patch-only member may require growing a full base block table. */
static int
test_patch_only_growth(void)
{
    mpq_archive_s *fixture = NULL;
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 2, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    uint8_t *overview = NULL;
    size_t overview_size = 0;
    uint32_t number;
    uint8_t count[4];
    FILE *file;
    char path[1024];
    char patch_path[1024];
    const char *patches[] = { patch_path };

    TEST_CHECK(libmpq__archive_open(&fixture, FIXTURE_DIR "/mpq-v1-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(fixture, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(fixture, number, &overview, &overview_size) == 0);
    TEST_CHECK(libmpq__archive_close(fixture) == 0);
    TEST_CHECK(test_temp_path(path, sizeof(path), "patch-grow") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-grow-layer") == 0);
    TEST_CHECK(
        fixture_patch_archive(
            patch_path, LIBMPQ_ARCHIVE_VERSION_ONE, overview, overview_size, first_text,
            sizeof(first_text) - 1, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", overview, (libmpq__off_t)overview_size, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, "pkware.txt", (const uint8_t *)"old", 3, &storage) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    free(overview);
    file = fopen(path, "r+b");
    TEST_CHECK(file != NULL);
    libmpq__store_le32(count, 2);
    TEST_CHECK(fseek(file, 28, SEEK_SET) == 0);
    TEST_CHECK(fwrite(count, 1, sizeof(count), file) == sizeof(count));
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__archive_open(&fixture, path, 0) == 0);
    TEST_CHECK(fixture->mpq_header.block_table_count == 2);
    TEST_CHECK(libmpq__archive_close(fixture) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, path, patches, 1) == 0);
    TEST_CHECK(libmpq__patch_view_archive(view)->mpq_header.block_table_count > 2);
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "patch-only.txt", &number) == 0
    );
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(path) == 0);
    TEST_CHECK(remove(patch_path) == 0);
    return 0;
}

/* Keep fixture refresh opt-in so normal test runs never rewrite sources. */
int
main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--refresh") == 0)
        return refresh_fixtures();
    TEST_CHECK(argc == 1);
    TEST_CHECK(test_views() == 0);
    TEST_CHECK(test_container_bytes() == 0);
    TEST_CHECK(test_noop_signature() == 0);
    TEST_CHECK(test_patch_bit() == 0);
    TEST_CHECK(test_unsupported_layers() == 0);
    TEST_CHECK(test_unlisted_patch_member() == 0);
    TEST_CHECK(test_missing_listfile() == 0);
    TEST_CHECK(test_shared_base_block() == 0);
    TEST_CHECK(test_patch_payload_validation() == 0);
    TEST_CHECK(test_unknown_base_name() == 0);
    TEST_CHECK(test_patch_only_growth() == 0);
    return 0;
}
