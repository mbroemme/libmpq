/*
 *  test-mpq-patch-reader.c -- deterministic private MPQ patch-view regressions.
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

#include "mpq-archive.h"
#include "mpq-attributes.h"
#include "mpq-block.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-md5.h"
#include "mpq-mpqe.h"
#include "mpq-patch-reader.h"
#include "mpq-patch-writer.h"
#include "mpq-reader.h"
#include "mpq-source.h"
#include "mpq-writer.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifdef LIBMPQ_TEST_PATCH_IO_WRAP

/* Linker wrappers affect only this regression executable, not the installed library. */
typedef enum
{
    PATCH_FAULT_NONE,
    PATCH_FAULT_VALIDATE,
    PATCH_FAULT_CLOSE_LOWER,
    PATCH_FAULT_REMOVE_OLD,
    PATCH_FAULT_EXPOSE,
    PATCH_FAULT_FINALIZE
} patch_fault_e;

static struct
{
    patch_fault_e fault;
    uint8_t enabled;
    uint8_t invalid;
    uint32_t lower_closes;
    uint32_t candidate_opens;
    uint32_t candidate_closes;
    uint32_t removal_failures;
    uint32_t removed;
    uint32_t fail_open;
    uint32_t writer_closes;
    mpq_archive_s *lower;
    mpq_archive_s *candidate;
    mpq_archive_s *candidates[8];
    char base_path[1024];
    char candidate_path[1024];
    char old_path[1024];
} patch_fault;

int32_t
__real_libmpq__archive_open(mpq_archive_s **archive, const char *path, libmpq__off_t offset);
int32_t __real_libmpq__archive_close(mpq_archive_s *archive);
int32_t __real_libmpq__directory_remove(mpq_directory_s *directory, const char *name);

int32_t
__wrap_libmpq__archive_open(mpq_archive_s **archive, const char *path, libmpq__off_t offset)
{
    int32_t status = __real_libmpq__archive_open(archive, path, offset);

    if (!patch_fault.enabled || status != 0)
        return status;
    if (strcmp(path, patch_fault.base_path) == 0) {
        patch_fault.lower = *archive;
    } else if (strstr(path, ".libmpq-patch-view-") != NULL) {
        if (strlen(path) >= sizeof(patch_fault.candidate_path)) {
            patch_fault.invalid = 1;
            return status;
        }
        memcpy(patch_fault.candidate_path, path, strlen(path) + 1);
        patch_fault.candidate = *archive;
        for (size_t i = 0; i < 8; i++) {
            if (patch_fault.candidates[i] == NULL) {
                patch_fault.candidates[i] = *archive;
                break;
            }
        }
        patch_fault.candidate_opens++;
        if ((patch_fault.fault == PATCH_FAULT_VALIDATE &&
             (patch_fault.fail_open == 0 ||
              patch_fault.candidate_opens == patch_fault.fail_open)) ||
            (patch_fault.fault == PATCH_FAULT_EXPOSE &&
             patch_fault.candidate_opens ==
                 (patch_fault.fail_open == 0 ? 2u : patch_fault.fail_open))) {

            /* A failed open owns no handle, even when late validation consumed one. */
            status = __real_libmpq__archive_close(*archive);
            for (size_t i = 0; i < 8; i++)
                if (patch_fault.candidates[i] == *archive)
                    patch_fault.candidates[i] = NULL;
            *archive = NULL;
            patch_fault.candidate = NULL;
            patch_fault.candidate_closes++;
            if (status == 0)
                status = patch_fault.fault == PATCH_FAULT_VALIDATE ? LIBMPQ_ERROR_FORMAT
                                                                   : LIBMPQ_ERROR_OPEN;
        }
    }
    return status;
}

int32_t
__wrap_libmpq__archive_close(mpq_archive_s *archive)
{
    uint8_t lower = patch_fault.enabled && archive == patch_fault.lower;
    uint8_t writing = patch_fault.enabled && archive->write_mode;
    int32_t status;

    if (lower && ++patch_fault.lower_closes != 1) {
        patch_fault.invalid = 1;
        return LIBMPQ_ERROR_CLOSE;
    }
    if (patch_fault.enabled)
        for (size_t i = 0; i < 8; i++)
            if (archive == patch_fault.candidates[i]) {
                patch_fault.candidate_closes++;
                patch_fault.candidates[i] = NULL;
            }
    status = __real_libmpq__archive_close(archive);
    if (lower)
        patch_fault.lower = NULL;
    if (writing && ++patch_fault.writer_closes == patch_fault.fail_open &&
        patch_fault.fault == PATCH_FAULT_FINALIZE && status == 0)
        return LIBMPQ_ERROR_CLOSE;

    /* Close consumes the real archive before reporting an injected failure. */
    return lower && patch_fault.fault == PATCH_FAULT_CLOSE_LOWER && status == 0 ? LIBMPQ_ERROR_CLOSE
                                                                                : status;
}

int32_t
__wrap_libmpq__directory_remove(mpq_directory_s *directory, const char *name)
{
    int32_t status;

    if (patch_fault.enabled && patch_fault.candidate_path[0] != '\0') {
        size_t length = strlen(patch_fault.candidate_path);
        size_t name_length = strlen(name);
        if (length < name_length ||
            strcmp(patch_fault.candidate_path + length - name_length, name) != 0) {
            const char *separator = (strrchr)(patch_fault.candidate_path, '/');
            size_t prefix =
                separator == NULL ? 0 : (size_t)(separator - patch_fault.candidate_path) + 1;
            if (prefix + name_length + 1 > sizeof(patch_fault.old_path)) {
                patch_fault.invalid = 1;
                return LIBMPQ_ERROR_SIZE;
            }
            memcpy(patch_fault.old_path, patch_fault.candidate_path, prefix);
            memcpy(patch_fault.old_path + prefix, name, name_length + 1);
            if (patch_fault.fault == PATCH_FAULT_REMOVE_OLD && patch_fault.removal_failures == 0 &&
                (patch_fault.fail_open == 0 ||
                 patch_fault.candidate_opens == patch_fault.fail_open)) {
                if (patch_fault.lower_closes != 1 ||
                    patch_fault.candidate_closes != patch_fault.candidate_opens)
                    patch_fault.invalid = 1;
                patch_fault.removal_failures++;
                return LIBMPQ_ERROR_WRITE;
            }
        }
    }
    status = __real_libmpq__directory_remove(directory, name);
    if (patch_fault.enabled && status == 0)
        patch_fault.removed++;
    return status;
}
#endif

static const uint8_t first_text[] = "Patch layer one\n";
static const uint8_t second_text[] = "Patch layer two\n";
static const uint8_t v2_text[] = "Version two patch\n";
static const uint8_t new_text[] = "Patch-only member\n";
static const uint8_t v3_fixture_copy[] = "Version three patch\n";
static const uint8_t v3_fixture_line[] = "Encrypted synthetic v3 patch member.\n";
static const uint8_t mpqe_auth_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
static const uint8_t first_patch_auth_code[] = "LIBMPQ-MPQE-PATCH-AUTH-CODE-00002";
static const uint8_t second_patch_auth_code[] = "LIBMPQ-MPQE-PATCH-AUTH-CODE-00003";

/* Calculate a fixture digest using the library's private MD5 implementation. */
static void
fixture_md5(const uint8_t *data, size_t size, uint8_t digest[16])
{
    mpq_md5_s state;

    libmpq__md5_init(&state);
    libmpq__md5_update(&state, data, size);
    libmpq__md5_final(&state, digest);
}

/* Every rejected payload must leave the caller's output in the empty state. */
static int
expect_bad_patch(const uint8_t *base, size_t base_size, const uint8_t *patch, size_t patch_size)
{
    uint8_t *output = (uint8_t *)patch;
    size_t output_size = 123;
    int32_t status = libmpq__patch_apply(base, base_size, patch, patch_size, &output, &output_size);

    TEST_CHECK(status != 0);
    TEST_CHECK(output == NULL && output_size == 0);
    return 0;
}

/* Serialize a minimal valid COPY patch with its MPQ patch-info prefix. */
static uint8_t *
fixture_copy_patch(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    size_t *stored_size
)
{
    static const uint8_t md5_tag[4] = { 'M', 'D', '5', '_' };
    static const uint8_t transform_tag[4] = { 'X', 'F', 'R', 'M' };
    static const uint8_t copy_tag[4] = { 'C', 'O', 'P', 'Y' };
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
    memcpy(patch + 16, md5_tag, sizeof(md5_tag));
    libmpq__store_le32(patch + 20, 40);
    fixture_md5(before, before_size, patch + 24);
    fixture_md5(after, after_size, patch + 40);
    memcpy(patch + 56, transform_tag, sizeof(transform_tag));
    libmpq__store_le32(patch + 60, (uint32_t)after_size + 12);
    memcpy(patch + 64, copy_tag, sizeof(copy_tag));
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

/* Public payload reads keep the target size distinct from PTCH bytes. */
static int
test_public_patch_payload(void)
{
    char path[512];
    mpq_archive_s *archive = NULL;
    uint8_t *stored = NULL;
    uint8_t *decoded = NULL;
    size_t stored_size = 0;
    uint32_t number;
    libmpq__off_t payload_size = -1;
    libmpq__off_t transferred = -1;

    TEST_CHECK(libmpq__patch_payload_size(NULL, 0, &payload_size) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(payload_size == 0);
    TEST_CHECK(
        libmpq__patch_payload_read(NULL, 0, NULL, NULL, 0, &transferred) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(transferred == 0);

    TEST_CHECK(test_temp_path(path, sizeof(path), "public-patch-payload") == 0);
    stored = fixture_copy_patch(
        first_text, sizeof(first_text) - 1, second_text, sizeof(second_text) - 1, &stored_size
    );
    TEST_CHECK(stored != NULL);
    TEST_CHECK(
        fixture_patch_archive(
            path, LIBMPQ_ARCHIVE_VERSION_ONE, first_text, sizeof(first_text) - 1, second_text,
            sizeof(second_text) - 1, NULL
        ) == 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);

    /* The cloned payload reader must resolve its own canonical entry order. */
    {
        uint32_t index = archive->mpq_map[number].entry_index;
        uint32_t other = index == 0 ? 1 : 0;
        mpq_entry_s saved = archive->mpq_entry[index];
        archive->mpq_entry[index] = archive->mpq_entry[other];
        archive->mpq_entry[other] = saved;
        for (uint32_t i = 0; i < archive->entry_count; ++i) {
            mpq_entry_s *entry = &archive->mpq_entry[i];
            archive->classic_entry_indices[entry->classic_source_index] = i;
            if (entry->file_number != UINT32_MAX)
                archive->mpq_map[entry->file_number].entry_index = i;
        }
    }
    TEST_CHECK(libmpq__patch_payload_size(archive, number, &payload_size) == 0);
    free(archive->mpq_block);
    free(archive->mpq_block_ex);
    archive->mpq_block = NULL;
    archive->mpq_block_ex = NULL;
    TEST_CHECK(payload_size == (libmpq__off_t)(stored_size - LIBMPQ_PATCH_INFO_SIZE));
    decoded = malloc((size_t)payload_size);
    TEST_CHECK(decoded != NULL);
    TEST_CHECK(
        libmpq__patch_payload_read(
            archive, number, "overview.txt", decoded, payload_size - 1, &transferred
        ) == LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(transferred == 0);
    TEST_CHECK(
        libmpq__patch_payload_read(
            archive, number, "overview.txt", decoded, payload_size, &transferred
        ) == 0
    );
    TEST_CHECK(transferred == payload_size);
    TEST_CHECK(memcmp(decoded, stored + LIBMPQ_PATCH_INFO_SIZE, (size_t)payload_size) == 0);
    TEST_CHECK(libmpq__file_number(archive, "patch-only.txt", &number) == 0);
    TEST_CHECK(libmpq__patch_payload_size(archive, number, &payload_size) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(payload_size == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(stored);
    free(decoded);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Create one synthetic namespaced layer without changing the public writer. */
static int
fixture_namespaced_patch(
    uint32_t version, const char *path, const char *marker, const char *replacement,
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    const char *deleted, const char *added, uint8_t listfile
)
{
    mpq_archive_create_options_s options = { version, 32, 4096,
                                             listfile ? LIBMPQ_ARCHIVE_CREATE_LISTFILE : 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    uint8_t *payload = NULL;
    size_t payload_size = 0;

    TEST_CHECK(libmpq__archive_create(&writer, path, &options) == 0);
    if (marker != NULL)
        TEST_CHECK(
            libmpq__archive_add_data(writer, marker, (const uint8_t *)"test", 4, &storage) == 0
        );
    if (replacement != NULL) {
        if (before != NULL) {
            payload = fixture_copy_patch(before, before_size, after, after_size, &payload_size);
            TEST_CHECK(payload != NULL);
        }
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, replacement, before == NULL ? after : payload,
                (libmpq__off_t)(before == NULL ? after_size : payload_size), &storage
            ) == 0
        );
        if (before != NULL)
            writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_PATCH_FILE;
    }
    if (deleted != NULL) {
        TEST_CHECK(libmpq__archive_add_data(writer, deleted, NULL, 0, &storage) == 0);
        writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
    }
    if (added != NULL)
        TEST_CHECK(
            libmpq__archive_add_data(writer, added, new_text, sizeof(new_text) - 1, &storage) == 0
        );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    free(payload);
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

/* Wrap synthetic MPQ patch bytes in an MPQE source with test-only credentials. */
static int
fixture_mpqe_patch(
    const char *source, const char *destination, const uint8_t *auth_code, size_t auth_size
)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE];
    uint8_t *data = NULL;
    size_t size = 0;
    FILE *output;

    TEST_CHECK(test_read_path(source, &data, &size) == 0);
    TEST_CHECK(libmpq__mpqe_key(key, auth_code, auth_size) == 0);
    for (size_t offset = 0; offset < size; offset += sizeof(chunk)) {
        size_t count = size - offset < sizeof(chunk) ? size - offset : sizeof(chunk);

        memset(chunk, 0, sizeof(chunk));
        memcpy(chunk, data + offset, count);
        libmpq__mpqe_transform_chunk(chunk, key, offset);
        memcpy(data + offset, chunk, count);
    }
    libmpq__mpqe_clear(chunk, sizeof(chunk));
    libmpq__mpqe_clear(key, sizeof(key));
    output = fopen(destination, "wb");
    TEST_CHECK(output != NULL);
    TEST_CHECK(fwrite(data, 1, size, output) == size);
    TEST_CHECK(fclose(output) == 0);
    free(data);
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

/* Reuse the legacy fixture recipe and existing BSD0 encoder for one complete v3 layer. */
static int
generate_v3_patch_fixture(const char *path)
{
    static const char *const names[] = { "overview.txt", "zlib.txt", "encrypted-compress.txt" };
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_THREE, 16, 4096,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME |
                                                LIBMPQ_ATTRIBUTE_PATCH_BIT };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *base = NULL;
    mpq_archive_s *writer = NULL;
    uint8_t secure[32 * (sizeof(v3_fixture_line) - 1)];
    uint8_t added[32];
    uint32_t number;

    for (size_t i = 0; i < 32; i++)
        memcpy(
            secure + i * (sizeof(v3_fixture_line) - 1), v3_fixture_line, sizeof(v3_fixture_line) - 1
        );
    memset(added, 'B', sizeof(added));
    TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v3-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__archive_create(&writer, path, &create) == 0);
    writer->write_patch_mode = 1;
    for (size_t i = 0; i < 3; i++) {
        uint8_t *before = NULL;
        uint8_t *after = NULL;
        uint8_t *payload;
        size_t before_size;
        size_t after_size;
        size_t payload_size;
        TEST_CHECK(libmpq__file_number(base, names[i], &number) == 0);
        TEST_CHECK(libmpq__reader_offsets_acquire(base, number, names[i]) == 0);
        TEST_CHECK(test_archive_read(base, number, &before, &before_size) == 0);
        TEST_CHECK(libmpq__reader_offsets_release(base, number) == 0);
        after_size = i == 0 ? sizeof(v3_fixture_copy) - 1 : i == 1 ? before_size : sizeof(secure);
        after = malloc(after_size);
        TEST_CHECK(after != NULL);
        memcpy(after, i == 0 ? v3_fixture_copy : i == 1 ? before : secure, after_size);
        if (i == 1) {
            TEST_CHECK(after_size > 17);
            after[17] ^= 0x5au;
        }
        payload = fixture_copy_patch(before, before_size, after, after_size, &payload_size);
        TEST_CHECK(payload != NULL);
        if (i == 1) {
            uint8_t *encoded = NULL;
            size_t encoded_size;
            size_t expanded_size;
            TEST_CHECK(
                libmpq__patch_bsd0_encode(
                    before, before_size, after, after_size, 0, &encoded, &encoded_size,
                    &expanded_size
                ) == 0
            );
            TEST_CHECK(
                encoded != NULL && encoded_size < after_size && expanded_size <= UINT32_MAX - 68
            );
            memcpy(payload + 28 + 68, encoded, encoded_size);
            memcpy(payload + 28 + 64, "BSD0", 4);
            libmpq__store_le32(payload + 28 + 4, (uint32_t)expanded_size + 68);
            libmpq__store_le32(payload + 28 + 60, (uint32_t)encoded_size + 12);
            payload_size = 28 + 68 + encoded_size;
            libmpq__store_le32(payload + 8, (uint32_t)payload_size - 28);
            fixture_md5(payload + 28, payload_size - 28, payload + 12);
            free(encoded);
        }
        storage.flags = i == 0 ? LIBMPQ_FILE_FLAG_SINGLE : LIBMPQ_FILE_FLAG_COMPRESS;
        if (i == 2)
            storage.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u;
        storage.compression_first = storage.compression_next = i == 0 ? 0 : LIBMPQ_COMPRESSION_ZLIB;
        TEST_CHECK(
            libmpq__writer_patch_file_add(
                writer, names[i], payload, 28, payload + 28, (libmpq__off_t)payload_size - 28,
                (libmpq__off_t)after_size, &storage
            ) == 0
        );
        writer->write_attributes[writer->write_next_block - 1].crc32 =
            crc32(0, after, (uInt)after_size);
        fixture_md5(after, after_size, writer->write_attributes[writer->write_next_block - 1].md5);
        writer->write_attributes[writer->write_next_block - 1].filetime =
            UINT64_C(132537600000000000) + i * 10000000;
        free(payload);
        free(after);
        free(before);
    }

    /* Naming the unlisted BET-only tail allows complete base reconstruction. */
    TEST_CHECK(libmpq__file_number(base, "zero.bin", &number) == 0);
    TEST_CHECK(
        base->mpq_entry[base->mpq_map[number].entry_index].source_mask == LIBMPQ_ENTRY_SOURCE_BET
    );
    TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "zero.bin", 0, 0) == 0);
    storage =
        (mpq_file_options_s){ LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0,
                              0, 0, 0 };
    TEST_CHECK(
        libmpq__archive_add_data(writer, "folder/reference.bin", added, sizeof(added), &storage) ==
        0
    );
    writer->write_attributes[writer->write_next_block - 1].filetime = UINT64_C(132537600040000000);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    return 0;
}

/* Assert that ordinary reads and logical streams agree on patched contents. */
static int
check_view(mpq_patch_view_s *view, const uint8_t *expected, size_t expected_size)
{
    mpq_archive_s *archive = libmpq__patch_view_archive(view);
    mpq_stream_s *stream = NULL;
    uint8_t stream_data[128];
    uint8_t *data = NULL;
    size_t size = 0;
    libmpq__off_t transferred = 0;
    uint32_t number;

    TEST_CHECK(archive != NULL);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(size == expected_size && memcmp(data, expected, size) == 0);
    free(data);
    TEST_CHECK(expected_size <= sizeof(stream_data));
    TEST_CHECK(libmpq__stream_open_name(archive, "overview.txt", &stream) == 0);
    TEST_CHECK(
        libmpq__stream_read(stream, stream_data, (libmpq__off_t)expected_size, &transferred) == 0
    );
    TEST_CHECK(transferred == (libmpq__off_t)expected_size);
    TEST_CHECK(memcmp(stream_data, expected, expected_size) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(libmpq__file_number(archive, "patch-only.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(size == sizeof(new_text) - 1 && memcmp(data, new_text, size) == 0);
    free(data);
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_LISTFILE_NAME, &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(size != 0);
    {
        static const uint8_t needle[] = "patch-only.txt";
        uint8_t found = 0;

        if (size >= sizeof(needle) - 1)
            for (size_t i = 0; i <= size - (sizeof(needle) - 1); i++)
                if (memcmp(data + i, needle, sizeof(needle) - 1) == 0) {
                    found = 1;
                    break;
                }
        free(data);
        data = NULL;
        TEST_CHECK(found);
    }
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

/* Compose ordinary replacement and delete layers over an authenticated MPQE base. */
static int
test_mpqe_base_views(void)
{
    const char *base_path = FIXTURE_DIR "/mpq-v1-features.mpqe";
    const char *replacement[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq" };
    const char *chain[] = { FIXTURE_DIR "/mpq-v1-features-patch.mpq",
                            FIXTURE_DIR "/mpq-v1-features-patch.w3x" };
    const char *mpqe_patch[] = { FIXTURE_DIR "/mpq-v1-features.mpqe" };
    const char *delete_layer[1];
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_patch_view_s *view = NULL;
    mpq_archive_s *base = NULL;
    mpq_archive_s *writer = NULL;
    uint8_t wrong_code[sizeof(mpqe_auth_code) - 1];
    uint8_t malformed[64] = { 0 };
    char malformed_path[1024];
    char delete_path[1024];
    uint32_t number;
    FILE *file;

    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(
            &view, base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, replacement, 1
        ) == 0
    );
    TEST_CHECK(check_view(view, first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "pkware.txt", &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    TEST_CHECK(test_temp_path(delete_path, sizeof(delete_path), "patch-mpqe-delete") == 0);
    delete_layer[0] = delete_path;
    TEST_CHECK(libmpq__archive_create(&writer, delete_path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(writer, "pkware.txt", NULL, 0, &storage) == 0);
    writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(
            &view, base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, delete_layer, 1
        ) == 0
    );
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "pkware.txt", &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(delete_path) == 0);

    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(
            &view, base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, chain, 2
        ) == 0
    );
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "bzip2.txt", &number) ==
        LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(&view, base_path, NULL, 0, replacement, 1) ==
        LIBMPQ_ERROR_DECRYPT
    );
    TEST_CHECK(view == NULL);
    memcpy(wrong_code, mpqe_auth_code, sizeof(wrong_code));
    wrong_code[0] ^= 1u;
    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(
            &view, base_path, wrong_code, sizeof(wrong_code), replacement, 1
        ) != 0
    );
    TEST_CHECK(view == NULL);
    TEST_CHECK(test_temp_path(malformed_path, sizeof(malformed_path), "patch-mpqe-malformed") == 0);
    file = fopen(malformed_path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(malformed, 1, sizeof(malformed), file) == sizeof(malformed));
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(
            &view, malformed_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, replacement, 1
        ) != 0
    );
    TEST_CHECK(view == NULL);
    TEST_CHECK(remove(malformed_path) == 0);

    TEST_CHECK(
        libmpq__patch_view_open_mpqe_base(
            &view, base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, mpqe_patch, 1
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(view == NULL);
    TEST_CHECK(
        libmpq__archive_open_mpqe(
            &base, base_path, -1, mpqe_auth_code, sizeof(mpqe_auth_code) - 1
        ) == 0
    );
    TEST_CHECK(libmpq__file_number(base, "overview.txt", &number) == 0);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    return 0;
}

/* Authenticate each mixed patch layer independently, including failed attempts. */
static int
test_mpqe_patch_layers(void)
{
    const char *plain_base_path = FIXTURE_DIR "/mpq-v1-features.mpq";
    const char *mpqe_base_path = FIXTURE_DIR "/mpq-v1-features.mpqe";
    const char *plain_first_path = FIXTURE_DIR "/mpq-v1-features-patch.mpq";
    const char *plain_second_path = FIXTURE_DIR "/mpq-v1-features-patch.w3x";
    char first_path[1024];
    char second_path[1024];
    uint8_t wrong_patch_auth[sizeof(first_patch_auth_code) - 1];
    uint8_t wrong_base_auth[sizeof(mpqe_auth_code) - 1];
    uint8_t *base_before = NULL;
    uint8_t *base_after = NULL;
    size_t before_size = 0;
    size_t after_size = 0;
    mpq_patch_source_s plain_base = { plain_base_path, NULL, 0, NULL };
    mpq_patch_source_s mpqe_base = { mpqe_base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1,
                                     NULL };
    mpq_patch_source_s plain_first = { plain_first_path, NULL, 0, NULL };
    mpq_patch_source_s plain_second = { plain_second_path, NULL, 0, NULL };
    mpq_patch_source_s first_secure;
    mpq_patch_source_s second_secure;
    mpq_patch_source_s layers[2];
    mpq_patch_view_s *view = NULL;

    TEST_CHECK(test_temp_path(first_path, sizeof(first_path), "patch-mpqe-first") == 0);
    TEST_CHECK(test_temp_path(second_path, sizeof(second_path), "patch-mpqe-second") == 0);
    TEST_CHECK(
        fixture_mpqe_patch(
            plain_first_path, first_path, first_patch_auth_code, sizeof(first_patch_auth_code) - 1
        ) == 0
    );
    TEST_CHECK(
        fixture_mpqe_patch(
            plain_second_path, second_path, second_patch_auth_code,
            sizeof(second_patch_auth_code) - 1
        ) == 0
    );
    first_secure = (mpq_patch_source_s){ first_path, first_patch_auth_code,
                                         sizeof(first_patch_auth_code) - 1, NULL };
    second_secure = (mpq_patch_source_s){ second_path, second_patch_auth_code,
                                          sizeof(second_patch_auth_code) - 1, NULL };
    TEST_CHECK(test_read_path(mpqe_base_path, &base_before, &before_size) == 0);

    layers[0] = first_secure;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &plain_base, layers, 1) == 0);
    TEST_CHECK(check_view(view, first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 1) == 0);
    TEST_CHECK(check_view(view, first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    layers[0] = plain_first;
    layers[1] = second_secure;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &plain_base, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    layers[0] = first_secure;
    layers[1] = plain_second;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &plain_base, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    layers[1] = second_secure;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    memcpy(wrong_patch_auth, first_patch_auth_code, sizeof(wrong_patch_auth));
    wrong_patch_auth[0] ^= 1u;
    layers[0] = first_secure;
    layers[0].auth_code = wrong_patch_auth;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &plain_base, layers, 1) != 0);
    TEST_CHECK(view == NULL);
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 1) != 0);
    TEST_CHECK(view == NULL);
    layers[0] = first_secure;
    layers[0].auth_code = NULL;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &plain_base, layers, 1) != 0);
    TEST_CHECK(view == NULL);
    layers[0] = plain_first;
    layers[1] = second_secure;
    layers[1].auth_code = wrong_patch_auth;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &plain_base, layers, 2) != 0);
    TEST_CHECK(view == NULL);
    layers[1] = second_secure;
    memcpy(wrong_base_auth, mpqe_auth_code, sizeof(wrong_base_auth));
    wrong_base_auth[0] ^= 1u;
    mpqe_base.auth_code = wrong_base_auth;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 2) != 0);
    TEST_CHECK(view == NULL);
    mpqe_base.auth_code = mpqe_auth_code;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &mpqe_base, layers, 2) == 0);
    TEST_CHECK(check_view(view, second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    TEST_CHECK(test_read_path(mpqe_base_path, &base_after, &after_size) == 0);
    TEST_CHECK(after_size == before_size && memcmp(base_before, base_after, before_size) == 0);
    free(base_before);
    free(base_after);
    TEST_CHECK(remove(first_path) == 0);
    TEST_CHECK(remove(second_path) == 0);
    return 0;
}

/* Compose replacement, deletion, restoration, and patch-only member chains. */
static int
test_chain_edges(void)
{
    static const uint8_t first[] = "first";
    static const uint8_t second[] = "second";
    static const uint8_t keep[] = "untouched";
    mpq_archive_create_options_s create = { LIBMPQ_ARCHIVE_VERSION_TWO, 16, 4096,
                                            LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                            LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 |
                                                LIBMPQ_ATTRIBUTE_FILETIME |
                                                LIBMPQ_ATTRIBUTE_PATCH_BIT };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    mpq_archive_s *base = NULL;
    mpq_patch_view_s *view = NULL;
    mpq_file_attributes_s attributes;
    mpq_file_attributes_s original_keep;
    uint8_t digest[16];
    uint8_t *actual = NULL;
    size_t actual_size = 0;
    uint32_t number;
    uint32_t original_chain_block;
    char base_path[1024];
    char layer_a[1024];
    char layer_b[1024];
    const char *layers[] = { layer_a, layer_b };

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "patch-chain-base") == 0);
    TEST_CHECK(test_temp_path(layer_a, sizeof(layer_a), "patch-chain-a") == 0);
    TEST_CHECK(test_temp_path(layer_b, sizeof(layer_b), "patch-chain-b") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, base_path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(writer, "chain.txt", first, sizeof(first) - 1, &storage) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(writer, "keep.txt", keep, sizeof(keep) - 1, &storage) == 0);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__archive_open(&base, base_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(base, "chain.txt", &number) == 0);
    TEST_CHECK(
        base->mpq_entry[base->mpq_map[number].entry_index].source_mask ==
        LIBMPQ_ENTRY_SOURCE_CLASSIC
    );
    original_chain_block = base->mpq_entry[base->mpq_map[number].entry_index].classic_source_index;
    TEST_CHECK(libmpq__file_number(base, "keep.txt", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(base, number, &original_keep) == 0);
    TEST_CHECK(libmpq__archive_close(base) == 0);
    for (uint32_t scenario = 0; scenario < 5; scenario++) {
        const char *name = scenario >= 3 ? "patch-only.txt" : "chain.txt";
        uint8_t delete_first = scenario == 2;
        uint8_t delete_second = scenario == 1 || scenario == 4;
        const uint8_t *expected = scenario == 0 || scenario == 2 || scenario == 3 ? second : NULL;

        TEST_CHECK(libmpq__archive_create(&writer, layer_a, &create) == 0);
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, name, delete_first ? NULL : first,
                delete_first ? 0 : (libmpq__off_t)sizeof(first) - 1, &storage
            ) == 0
        );
        if (delete_first)
            writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
        TEST_CHECK(libmpq__archive_close(writer) == 0);
        TEST_CHECK(libmpq__archive_create(&writer, layer_b, &create) == 0);
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, "(patch_metadata)", (const uint8_t *)"test", 4, &storage
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, name, delete_second ? NULL : second,
                delete_second ? 0 : (libmpq__off_t)sizeof(second) - 1, &storage
            ) == 0
        );
        if (delete_second)
            writer->mpq_block[writer->write_next_block - 1].flags |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
        TEST_CHECK(libmpq__archive_close(writer) == 0);
        TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 2) == 0);
        TEST_CHECK(
            libmpq__file_number(libmpq__patch_view_archive(view), name, &number) ==
            (expected == NULL ? LIBMPQ_ERROR_EXIST : 0)
        );
        if (expected != NULL) {
            if (scenario < 3) {
                TEST_CHECK(
                    libmpq__patch_view_archive(view)
                        ->mpq_entry[libmpq__patch_view_archive(view)->mpq_map[number].entry_index]
                        .source_mask == LIBMPQ_ENTRY_SOURCE_CLASSIC
                );
                TEST_CHECK(
                    libmpq__patch_view_archive(view)
                        ->mpq_entry[libmpq__patch_view_archive(view)->mpq_map[number].entry_index]
                        .classic_source_index != original_chain_block
                );
            }
            TEST_CHECK(
                test_archive_read(
                    libmpq__patch_view_archive(view), number, &actual, &actual_size
                ) == 0
            );
            TEST_CHECK(
                actual_size == sizeof(second) - 1 && memcmp(actual, expected, actual_size) == 0
            );
            free(actual);
            actual = NULL;
            TEST_CHECK(
                libmpq__file_attributes(libmpq__patch_view_archive(view), number, &attributes) == 0
            );
            fixture_md5(expected, sizeof(second) - 1, digest);
            TEST_CHECK(attributes.crc32 == crc32(0, expected, sizeof(second) - 1));
            TEST_CHECK(memcmp(attributes.md5, digest, sizeof(digest)) == 0);
            TEST_CHECK(attributes.patch_bit == 0);
        }
        TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "keep.txt", &number) == 0);
        TEST_CHECK(
            test_archive_read(libmpq__patch_view_archive(view), number, &actual, &actual_size) == 0
        );
        TEST_CHECK(actual_size == sizeof(keep) - 1 && memcmp(actual, keep, actual_size) == 0);
        free(actual);
        actual = NULL;
        TEST_CHECK(
            libmpq__file_attributes(libmpq__patch_view_archive(view), number, &attributes) == 0
        );
        fixture_md5(keep, sizeof(keep) - 1, digest);
        TEST_CHECK(attributes.crc32 == crc32(0, keep, sizeof(keep) - 1));
        TEST_CHECK(memcmp(attributes.md5, digest, sizeof(digest)) == 0);
        TEST_CHECK(attributes.filetime == original_keep.filetime);
        if (scenario == 1) {
            mpq_file_attributes_s removed_row;
            mpq_archive_s *result = libmpq__patch_view_archive(view);
            static const uint8_t zero_md5[16] = { 0 };

            TEST_CHECK(libmpq__attributes_load(result) == 0);
            libmpq__attributes_get(result->attributes, original_chain_block, &removed_row);
            TEST_CHECK(
                removed_row.crc32 == 0 && removed_row.filetime == 0 && removed_row.patch_bit == 0
            );
            TEST_CHECK(memcmp(removed_row.md5, zero_md5, sizeof(zero_md5)) == 0);
        }
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
        TEST_CHECK(remove(layer_a) == 0);
        TEST_CHECK(remove(layer_b) == 0);
    }
    TEST_CHECK(remove(base_path) == 0);
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

/* PATCH_BIT alone is not a patch indicator; MPQE patch layers stay unsupported. */
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
            (mode == 0 ? LIBMPQ_ERROR_EXIST : 0)
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
            (mode == 0 ? LIBMPQ_ERROR_EXIST : 0)
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

/* Rewriting a final listfile line without a newline must reserve its terminator. */
static int
test_listfile_without_final_newline(void)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    static const uint8_t before[] = "Original member";
    static const uint8_t listing[] = "overview.txt";
    static const uint8_t expected[] = "overview.txt\n";
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    uint8_t *stored = NULL;
    uint8_t *actual = NULL;
    size_t stored_size = 0;
    size_t actual_size = 0;
    uint32_t number;
    char base_path[1024];
    char patch_path[1024];
    const char *patches[] = { patch_path };

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "patch-listfile-base") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "patch-listfile-layer") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, base_path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(writer, "overview.txt", before, sizeof(before) - 1, &storage) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, "(listfile)", listing, sizeof(listing) - 1, &storage) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    stored = fixture_copy_patch(
        before, sizeof(before) - 1, first_text, sizeof(first_text) - 1, &stored_size
    );
    TEST_CHECK(stored != NULL);
    TEST_CHECK(libmpq__archive_create(&writer, patch_path, &options) == 0);
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
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    free(stored);
    TEST_CHECK(libmpq__patch_view_open(&view, base_path, patches, 1) == 0);
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "(listfile)", &number) == 0);
    TEST_CHECK(
        test_archive_read(libmpq__patch_view_archive(view), number, &actual, &actual_size) == 0
    );
    TEST_CHECK(actual_size == sizeof(expected) - 1);
    TEST_CHECK(memcmp(actual, expected, actual_size) == 0);
    free(actual);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    TEST_CHECK(remove(patch_path) == 0);
    TEST_CHECK(remove(base_path) == 0);
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
    TEST_CHECK(
        base->mpq_entry[base->mpq_map[number].entry_index].source_mask ==
        LIBMPQ_ENTRY_SOURCE_CLASSIC
    );
    original_b_block = base->mpq_entry[base->mpq_map[number].entry_index].classic_source_index;
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
            TEST_CHECK(
                result->mpq_entry[result->mpq_map[number].entry_index].source_mask ==
                LIBMPQ_ENTRY_SOURCE_CLASSIC
            );
            TEST_CHECK(
                result->mpq_entry[result->mpq_map[number].entry_index].classic_source_index ==
                original_block
            );
            TEST_CHECK(attributes.crc32 == original->crc32);
            TEST_CHECK(memcmp(attributes.md5, original->md5, sizeof(attributes.md5)) == 0);
        }
        if (count == 2) {
            TEST_CHECK(
                result->mpq_entry[result->mpq_map[number].entry_index].source_mask ==
                LIBMPQ_ENTRY_SOURCE_CLASSIC
            );
            TEST_CHECK(
                result->mpq_entry[result->mpq_map[number].entry_index].classic_source_index !=
                original_block
            );
            TEST_CHECK(attributes.crc32 == expected_a_crc);
            TEST_CHECK(memcmp(attributes.md5, expected_a_md5, sizeof(expected_a_md5)) == 0);
            TEST_CHECK(test_archive_read(result, number, &actual, &actual_size) == 0);
            TEST_CHECK(actual_size == sizeof(second_text) - 1);
            TEST_CHECK(memcmp(actual, second_text, actual_size) == 0);
            free(actual);
            actual = NULL;
        }
        TEST_CHECK(libmpq__file_number(result, "patch-only.txt", &number) == 0);
        TEST_CHECK(
            result->mpq_entry[result->mpq_map[number].entry_index].source_mask ==
            LIBMPQ_ENTRY_SOURCE_CLASSIC
        );
        TEST_CHECK(
            result->mpq_entry[result->mpq_map[number].entry_index].classic_source_index !=
            original_b_block
        );
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
    uint32_t attributes_entry;
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
    TEST_CHECK(
        archive->mpq_entry[archive->mpq_map[number].entry_index].source_mask ==
        LIBMPQ_ENTRY_SOURCE_CLASSIC
    );
    data_block = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    TEST_CHECK(libmpq__file_number(archive, LIBMPQ_ATTRIBUTES_NAME, &attributes_number) == 0);
    attributes_entry = archive->mpq_map[attributes_number].entry_index;
    TEST_CHECK((archive->mpq_entry[attributes_entry].flags & LIBMPQ_FLAG_SINGLE) != 0);
    TEST_CHECK(
        archive->mpq_entry[attributes_entry].packed_size ==
        archive->mpq_entry[attributes_entry].unpacked_size
    );
    bit_offset = (uint64_t)archive->archive_offset + archive->mpq_entry[attributes_entry].offset +
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
    size_t rle_size = 0;
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
    {
        uint8_t trailing[sizeof(patch) + 12] = { 0 };

        memcpy(trailing, patch, 68 + 31);
        libmpq__store_le32(trailing + 4, 68 + 31);
        libmpq__store_le32(trailing + 60, 68 + 31 - 56);
        TEST_CHECK(expect_bad_patch(before, sizeof(before), trailing, 68 + 31) == 0);
        memcpy(trailing, patch, sizeof(patch));
        libmpq__store_le32(trailing + 4, sizeof(patch) + 1);
        libmpq__store_le32(trailing + 60, sizeof(patch) + 1 - 56);
        TEST_CHECK(expect_bad_patch(before, sizeof(before), trailing, sizeof(patch) + 1) == 0);
        libmpq__store_le64(trailing + 84, 4);
        TEST_CHECK(expect_bad_patch(before, sizeof(before), trailing, sizeof(patch) + 1) == 0);
        memcpy(trailing, patch, 112);
        memcpy(trailing + 124, patch + 112, sizeof(patch) - 112);
        libmpq__store_le32(trailing + 4, sizeof(trailing));
        libmpq__store_le32(trailing + 60, sizeof(trailing) - 56);
        libmpq__store_le64(trailing + 76, 24);
        TEST_CHECK(expect_bad_patch(before, sizeof(before), trailing, sizeof(trailing)) == 0);
    }
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
        rle_size = output;
        libmpq__store_le32(rle + 60, (uint32_t)(output - 56));
        TEST_CHECK(
            libmpq__patch_apply(before, sizeof(before), rle, output, &result, &result_size) == 0
        );
    }
    TEST_CHECK(result_size == sizeof(after) && memcmp(result, after, sizeof(after)) == 0);
    free(result);
    result = NULL;
    libmpq__store_le32(rle + 60, (uint32_t)(rle_size - 1 - 56));
    TEST_CHECK(expect_bad_patch(before, sizeof(before), rle, rle_size - 1) == 0);
    libmpq__store_le32(rle + 60, (uint32_t)(rle_size - 56));
    rle[72] = 0xff;
    TEST_CHECK(expect_bad_patch(before, sizeof(before), rle, rle_size) == 0);
    rle[72] = 0x8f;
    libmpq__store_le32(rle + 60, 73 - 56);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), rle, 73) == 0);
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
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch) - 1) == 0);
    patch[68] = 'X';
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    patch[68] = 'B';
    libmpq__store_le64(patch + 76, UINT64_MAX);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    libmpq__store_le64(patch + 76, 12);
    libmpq__store_le64(patch + 84, UINT64_MAX);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    libmpq__store_le64(patch + 84, 3);
    libmpq__store_le32(patch + 100, 0);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    libmpq__store_le32(patch + 100, 4);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    libmpq__store_le32(patch + 100, 3);
    libmpq__store_le64(patch + 76, 0);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    libmpq__store_le64(patch + 76, 12);
    patch[112] = 1;
    TEST_CHECK(expect_bad_patch(before, sizeof(before), patch, sizeof(patch)) == 0);
    patch[112] = 0;
    moving[108] = 0xff;
    moving[109] = 0xff;
    moving[110] = 0xff;
    moving[111] = 0xff;
    TEST_CHECK(expect_bad_patch(before, sizeof(before), moving, sizeof(moving)) == 0);
    libmpq__store_le32(moving + 108, 0x7fffffffu);
    TEST_CHECK(expect_bad_patch(before, sizeof(before), moving, sizeof(moving)) == 0);
    libmpq__store_le32(prefix, sizeof(prefix));
    libmpq__store_le32(prefix + 4, 0x80000000u);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == 0);
    libmpq__store_le32(prefix, sizeof(prefix) + 1);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

/* Exercise prefix limits without letting untrusted sizes reach a reader allocation. */
static int
test_patch_prefix_boundaries(void)
{
    uint8_t prefix[LIBMPQ_PATCH_INFO_SIZE + 8] = { 0 };
    mpq_patch_info_s info;

    libmpq__store_le32(prefix, LIBMPQ_PATCH_INFO_SIZE);
    libmpq__store_le32(prefix + 4, 0x80000000u);
    TEST_CHECK(libmpq__patch_info_parse(NULL, 0, &info) == LIBMPQ_ERROR_FORMAT);
    for (size_t size = 0; size < LIBMPQ_PATCH_INFO_SIZE; size++)
        TEST_CHECK(libmpq__patch_info_parse(prefix, size, &info) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__patch_info_parse(prefix, LIBMPQ_PATCH_INFO_SIZE, &info) == 0);
    TEST_CHECK(info.length == LIBMPQ_PATCH_INFO_SIZE && info.data_size == 0);
    libmpq__store_le32(prefix, LIBMPQ_PATCH_INFO_SIZE - 1);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == LIBMPQ_ERROR_FORMAT);
    libmpq__store_le32(prefix, sizeof(prefix) + 1);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == LIBMPQ_ERROR_FORMAT);
    libmpq__store_le32(prefix, sizeof(prefix));
    libmpq__store_le32(prefix + 4, 0);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == LIBMPQ_ERROR_FORMAT);
    libmpq__store_le32(prefix + 4, 0x80000000u);
    libmpq__store_le32(prefix + 8, UINT32_MAX);
    TEST_CHECK(libmpq__patch_info_parse(prefix, sizeof(prefix), &info) == 0);
    TEST_CHECK(info.length == sizeof(prefix) && info.data_size == UINT32_MAX);
    return 0;
}

/* Corrupt one field at a time, including sizes, transforms, and both digests. */
static int
test_copy_payload_boundaries(void)
{
    static const uint8_t before[] = "old";
    static const uint8_t after[] = "new contents";
    static const uint8_t empty_bytes[] = { 0 };
    uint8_t *stored;
    uint8_t *patch;
    uint8_t *output = NULL;
    size_t stored_size = 0;
    size_t patch_size;
    size_t output_size = 0;
    uint8_t *empty;
    size_t empty_size = 0;

    empty = fixture_copy_patch(empty_bytes, 0, empty_bytes, 0, &empty_size);
    TEST_CHECK(empty != NULL);
    TEST_CHECK(
        libmpq__patch_apply(
            NULL, 0, empty + LIBMPQ_PATCH_INFO_SIZE, empty_size - LIBMPQ_PATCH_INFO_SIZE, &output,
            &output_size
        ) == 0
    );
    TEST_CHECK(output != NULL && output_size == 0);
    free(output);
    output = NULL;
    free(empty);

    stored = fixture_copy_patch(before, sizeof(before) - 1, after, sizeof(after) - 1, &stored_size);
    TEST_CHECK(stored != NULL);
    patch = stored + LIBMPQ_PATCH_INFO_SIZE;
    patch_size = stored_size - LIBMPQ_PATCH_INFO_SIZE;
    TEST_CHECK(libmpq__patch_apply(before, 3, patch, patch_size, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(after) - 1);
    free(output);
    TEST_CHECK(expect_bad_patch(before, 3, NULL, patch_size) == 0);
    TEST_CHECK(expect_bad_patch(NULL, 3, patch, patch_size) == 0);
    for (size_t size = 0; size < 68; size++)
        TEST_CHECK(expect_bad_patch(before, 3, patch, size) == 0);
    patch[0] = 'X';
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    patch[0] = 'P';
    libmpq__store_le32(patch + 4, (uint32_t)patch_size - 1);
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    libmpq__store_le32(patch + 4, (uint32_t)patch_size);
    libmpq__store_le32(patch + 8, 4);
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    libmpq__store_le32(patch + 8, 3);
    patch[16] = 'X';
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    patch[16] = 'M';
    libmpq__store_le32(patch + 20, 39);
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    libmpq__store_le32(patch + 20, 40);
    patch[24] ^= 1;
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    patch[24] ^= 1;
    patch[40] ^= 1;
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    patch[40] ^= 1;
    patch[56] = 'Y';
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    patch[56] = 'X';
    libmpq__store_le32(patch + 60, 11);
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    libmpq__store_le32(patch + 60, (uint32_t)patch_size - 55);
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    libmpq__store_le32(patch + 60, (uint32_t)patch_size - 56);
    patch[64] = 'X';
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    patch[64] = 'C';
    libmpq__store_le32(patch + 12, (uint32_t)sizeof(after));
    TEST_CHECK(expect_bad_patch(before, 3, patch, patch_size) == 0);
    free(stored);
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

/* Check the logical name, not the patch layer's physical namespace. */
static int
check_named_member(mpq_patch_view_s *view, const char *name, const uint8_t *expected, size_t size)
{
    mpq_archive_s *archive = libmpq__patch_view_archive(view);
    uint8_t *actual = NULL;
    size_t actual_size = 0;
    uint32_t number;

    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &actual, &actual_size) == 0);
    TEST_CHECK(actual_size == size && memcmp(actual, expected, size) == 0);
    free(actual);
    return 0;
}

/* Search a length-delimited listfile without assuming a trailing NUL. */
static uint8_t
contains_text(const uint8_t *data, size_t size, const char *text)
{
    size_t length = strlen(text);

    if (length > size)
        return 0;
    for (size_t i = 0; i <= size - length; i++)
        if (memcmp(data + i, text, length) == 0)
            return 1;
    return 0;
}

/* A layer's physical prefix is stripped before matching or materialization. */
static int
test_patch_namespaces(uint32_t version)
{
    mpq_archive_create_options_s options = { version, 32, 4096, LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    static const uint8_t original[] = "old";
    static const uint8_t kept[] = "kept";
    char base_path[1024];
    char first_path[1024];
    char second_path[1024];
    char delete_path[1024];
    char root_path[1024];
    char boundary_path[1024];
    char unknown_path[1024];
    char conflict_path[1024];
    char secure_path[1024];
    char secure_second_path[1024];
    char secure_base_path[1024];
    char restore_path[1024];
    char patch_only_path[1024];
    char mixed_path[1024];
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    uint32_t number;
    mpq_patch_source_s base;
    mpq_patch_source_s layers[2];
    uint8_t *list = NULL;
    size_t list_size = 0;

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "prefix-base") == 0);
    TEST_CHECK(test_temp_path(first_path, sizeof(first_path), "prefix-first") == 0);
    TEST_CHECK(test_temp_path(second_path, sizeof(second_path), "prefix-second") == 0);
    TEST_CHECK(test_temp_path(delete_path, sizeof(delete_path), "prefix-delete") == 0);
    TEST_CHECK(test_temp_path(root_path, sizeof(root_path), "prefix-root") == 0);
    TEST_CHECK(test_temp_path(boundary_path, sizeof(boundary_path), "prefix-boundary") == 0);
    TEST_CHECK(test_temp_path(unknown_path, sizeof(unknown_path), "prefix-unknown") == 0);
    TEST_CHECK(test_temp_path(conflict_path, sizeof(conflict_path), "prefix-conflict") == 0);
    TEST_CHECK(test_temp_path(secure_path, sizeof(secure_path), "prefix-secure") == 0);
    TEST_CHECK(
        test_temp_path(secure_second_path, sizeof(secure_second_path), "prefix-secure-two") == 0
    );
    TEST_CHECK(test_temp_path(secure_base_path, sizeof(secure_base_path), "prefix-mpqe-base") == 0);
    TEST_CHECK(test_temp_path(restore_path, sizeof(restore_path), "prefix-restore") == 0);
    TEST_CHECK(test_temp_path(patch_only_path, sizeof(patch_only_path), "prefix-only") == 0);
    TEST_CHECK(test_temp_path(mixed_path, sizeof(mixed_path), "prefix-mixed") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, base_path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "overview.txt", original, sizeof(original) - 1, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_add_data(writer, "keep.txt", kept, sizeof(kept) - 1, &storage) == 0);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(
        fixture_namespaced_patch(
            version, first_path, "Base\\(patch_metadata)", "Base\\overview.txt", original,
            sizeof(original) - 1, first_text, sizeof(first_text) - 1, "Base\\keep.txt",
            "Base\\patch-only.txt", 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, second_path, "enGB\\(patch_metadata)", "enGB\\overview.txt", first_text,
            sizeof(first_text) - 1, second_text, sizeof(second_text) - 1, NULL, NULL, 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, delete_path, "enGB\\(patch_metadata)", NULL, NULL, 0, NULL, 0,
            "enGB\\overview.txt", NULL, 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, root_path, "(patch_metadata)", "overview.txt", original, sizeof(original) - 1,
            first_text, sizeof(first_text) - 1, NULL, NULL, 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, boundary_path, "Base\\(patch_metadata)", "Baseball\\overview.txt", original,
            sizeof(original) - 1, first_text, sizeof(first_text) - 1, NULL, NULL, 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, unknown_path, NULL, "Base\\overview.txt", original, sizeof(original) - 1,
            first_text, sizeof(first_text) - 1, NULL, NULL, 0
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, restore_path, "enGB\\(patch_metadata)", "enGB\\overview.txt", NULL, 0,
            second_text, sizeof(second_text) - 1, NULL, NULL, 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, patch_only_path, "enGB\\(patch_metadata)", "enGB\\patch-only.txt", NULL, 0,
            second_text, sizeof(second_text) - 1, NULL, NULL, 1
        ) == 0
    );
    TEST_CHECK(
        fixture_namespaced_patch(
            version, mixed_path, "(patch_metadata)", "overview.txt", first_text,
            sizeof(first_text) - 1, second_text, sizeof(second_text) - 1, NULL, NULL, 1
        ) == 0
    );
    TEST_CHECK(libmpq__archive_create(&writer, conflict_path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "Base\\(patch_metadata)", (const uint8_t *)"a", 1, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "Other\\(patch_metadata)", (const uint8_t *)"b", 1, &storage
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);

    base = (mpq_patch_source_s){ base_path, NULL, 0, NULL };
    layers[0] = (mpq_patch_source_s){ first_path, NULL, 0, "Base" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(check_named_member(view, "patch-only.txt", new_text, sizeof(new_text) - 1) == 0);
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "keep.txt", &number) != 0);
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), "Base\\overview.txt", &number) != 0
    );
    TEST_CHECK(
        libmpq__file_number(libmpq__patch_view_archive(view), LIBMPQ_LISTFILE_NAME, &number) == 0
    );
    TEST_CHECK(test_archive_read(libmpq__patch_view_archive(view), number, &list, &list_size) == 0);
    TEST_CHECK(contains_text(list, list_size, "patch-only.txt"));
    TEST_CHECK(!contains_text(list, list_size, "Base\\patch-only.txt"));
    free(list);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    layers[0].prefix = NULL;
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[0].prefix = "Base\\";
    layers[1] = (mpq_patch_source_s){ second_path, NULL, 0, "enGB" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(check_named_member(view, "patch-only.txt", new_text, sizeof(new_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[1] = (mpq_patch_source_s){ mixed_path, NULL, 0, NULL };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[1] = (mpq_patch_source_s){ patch_only_path, NULL, 0, NULL };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == 0);
    TEST_CHECK(
        check_named_member(view, "patch-only.txt", second_text, sizeof(second_text) - 1) == 0
    );
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[1] = (mpq_patch_source_s){ delete_path, NULL, 0, NULL };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == 0);
    TEST_CHECK(libmpq__file_number(libmpq__patch_view_archive(view), "overview.txt", &number) != 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[0] = (mpq_patch_source_s){ delete_path, NULL, 0, NULL };
    layers[1] = (mpq_patch_source_s){ restore_path, NULL, 0, NULL };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[0] = (mpq_patch_source_s){ root_path, NULL, 0, NULL };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    layers[0] = (mpq_patch_source_s){ boundary_path, NULL, 0, "Base" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", original, sizeof(original) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    layers[0] = (mpq_patch_source_s){ unknown_path, NULL, 0, "Base" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(view == NULL);
    layers[0] = (mpq_patch_source_s){ first_path, NULL, 0, "Other" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(view == NULL);
    layers[0] = (mpq_patch_source_s){ conflict_path, NULL, 0, NULL };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(view == NULL);

    TEST_CHECK(
        fixture_mpqe_patch(
            first_path, secure_path, first_patch_auth_code, sizeof(first_patch_auth_code) - 1
        ) == 0
    );
    layers[0] = (mpq_patch_source_s){ secure_path, first_patch_auth_code,
                                      sizeof(first_patch_auth_code) - 1, "Base" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 1) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", first_text, sizeof(first_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    TEST_CHECK(
        fixture_mpqe_patch(
            base_path, secure_base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1
        ) == 0
    );
    base =
        (mpq_patch_source_s){ secure_base_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, NULL };
    layers[0] = (mpq_patch_source_s){ first_path, NULL, 0, "Base" };
    TEST_CHECK(
        fixture_mpqe_patch(
            second_path, secure_second_path, second_patch_auth_code,
            sizeof(second_patch_auth_code) - 1
        ) == 0
    );
    layers[1] = (mpq_patch_source_s){ secure_second_path, second_patch_auth_code,
                                      sizeof(second_patch_auth_code) - 1, "enGB" };
    TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == 0);
    TEST_CHECK(check_named_member(view, "overview.txt", second_text, sizeof(second_text) - 1) == 0);
    TEST_CHECK(libmpq__patch_view_close(view) == 0);

    TEST_CHECK(remove(base_path) == 0);
    TEST_CHECK(remove(first_path) == 0);
    TEST_CHECK(remove(second_path) == 0);
    TEST_CHECK(remove(delete_path) == 0);
    TEST_CHECK(remove(root_path) == 0);
    TEST_CHECK(remove(boundary_path) == 0);
    TEST_CHECK(remove(unknown_path) == 0);
    TEST_CHECK(remove(conflict_path) == 0);
    TEST_CHECK(remove(secure_path) == 0);
    TEST_CHECK(remove(secure_second_path) == 0);
    TEST_CHECK(remove(secure_base_path) == 0);
    TEST_CHECK(remove(restore_path) == 0);
    TEST_CHECK(remove(patch_only_path) == 0);
    TEST_CHECK(remove(mixed_path) == 0);
    return 0;
}

/* Convert runtime-generated mixed tables to a complete named BET-only source. */
static int
strip_v3_classic_tables(const char *path)
{
    mpq_archive_s *archive = NULL;
    uint8_t *image = NULL;
    size_t size;
    size_t end;
    FILE *output;

    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    end = archive->mpq_header.hash_table_offset;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(test_read_path(path, &image, &size) == 0);
    TEST_CHECK(end >= LIBMPQ_HEADER_V3_WIRE_SIZE && end <= size);
    memset(image + 16, 0, 28);
    libmpq__store_le32(image + 8, (uint32_t)end);
    libmpq__store_le64(image + 44, end);
    output = fopen(path, "wb");
    TEST_CHECK(output != NULL && fwrite(image, 1, end, output) == end);
    TEST_CHECK(fclose(output) == 0);
    free(image);
    return 0;
}

/* Named reads, random seeks and both tables must describe one materialized row. */
static int
check_v3_materialized_member(
    mpq_archive_s *archive, const char *name, const uint8_t *expected, size_t size,
    uint32_t storage_flags
)
{
    mpq_stream_s *stream = NULL;
    mpq_bet_entry_s bet;
    uint8_t actual[9000];
    uint32_t number;
    uint32_t classic;
    uint32_t hashes[3];
    uint32_t flags;
    uint32_t index;
    uint64_t bet_index;
    libmpq__off_t transferred;
    libmpq__off_t unpacked;
    libmpq__off_t packed;
    libmpq__off_t position;
    const mpq_entry_s *entry;

    TEST_CHECK(size <= sizeof(actual));
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    libmpq__file_hash(name, &hashes[0], &hashes[1], &hashes[2]);
    TEST_CHECK(
        libmpq__file_number_from_hash(archive, hashes[0], hashes[1], hashes[2], &classic) == 0
    );
    TEST_CHECK(classic == number);
    index = archive->mpq_map[number].entry_index;
    entry = &archive->mpq_entry[index];
    TEST_CHECK(entry->source_mask == (LIBMPQ_ENTRY_SOURCE_CLASSIC | LIBMPQ_ENTRY_SOURCE_BET));
    TEST_CHECK(
        libmpq__het_lookup(
            &archive->mpq_het, name, archive->mpq_bet.header.entry_count, libmpq__bet_match,
            &archive->mpq_bet, &bet_index
        ) == 0
    );
    TEST_CHECK(libmpq__entry_index_from_bet(archive, bet_index, &classic) == 0 && classic == index);
    TEST_CHECK(libmpq__bet_record_decode(&archive->mpq_bet, bet_index, &bet) == 0);
    TEST_CHECK(bet.offset == entry->offset && bet.packed_size == entry->packed_size);
    TEST_CHECK(bet.unpacked_size == size && bet.flags == entry->flags);
    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
    TEST_CHECK((flags & (LIBMPQ_FILE_FLAG_PATCH_FILE | LIBMPQ_FILE_FLAG_DELETE_MARKER)) == 0);
    TEST_CHECK((flags & storage_flags) == storage_flags);
    TEST_CHECK(
        libmpq__file_size_unpacked(archive, number, &unpacked) == 0 &&
        unpacked == (libmpq__off_t)size
    );
    TEST_CHECK(
        libmpq__file_size_packed(archive, number, &packed) == 0 &&
        packed == (libmpq__off_t)bet.packed_size
    );
    TEST_CHECK(libmpq__stream_open_name(archive, name, &stream) == 0);
    TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, name) == 0);
    TEST_CHECK(libmpq__file_read(archive, number, actual, (libmpq__off_t)size, &transferred) == 0);
    TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
    TEST_CHECK(transferred == (libmpq__off_t)size && memcmp(actual, expected, size) == 0);
    TEST_CHECK(libmpq__stream_read(stream, actual, (libmpq__off_t)size, &transferred) == 0);
    TEST_CHECK(transferred == (libmpq__off_t)size && memcmp(actual, expected, size) == 0);
    TEST_CHECK(libmpq__stream_tell(stream, &position) == 0 && position == (libmpq__off_t)size);
    TEST_CHECK(libmpq__stream_seek(stream, (libmpq__off_t)(size / 2), LIBMPQ_SEEK_SET) == 0);
    TEST_CHECK(
        libmpq__stream_read(stream, actual, (libmpq__off_t)(size - size / 2), &transferred) == 0
    );
    TEST_CHECK(transferred == (libmpq__off_t)(size - size / 2));
    TEST_CHECK(memcmp(actual, expected + size / 2, size - size / 2) == 0);
    TEST_CHECK(libmpq__stream_read(stream, actual, 1, &transferred) == 0 && transferred == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    return 0;
}

/* Independent MPQ cipher recipe, with a generated table rather than native crypto. */
static void
reference_patch_cipher(uint8_t *data, size_t size, uint32_t key, uint8_t decrypt)
{
    uint32_t table[256];
    uint32_t generator = 0x00100001u;
    uint32_t seed = 0xeeeeeeeeu;

    for (uint32_t i = 0; i < 256; i++) {
        for (uint32_t bank = 0; bank < 5; bank++) {
            uint32_t value;
            generator = (generator * 125u + 3u) % 0x2aaaabu;
            value = (generator & 0xffffu) << 16;
            generator = (generator * 125u + 3u) % 0x2aaaabu;
            if (bank == 4)
                table[i] = value | (generator & 0xffffu);
        }
    }
    for (size_t i = 0; size - i >= 4; i += 4) {
        uint32_t input = libmpq__load_le32(data + i);
        uint32_t output;
        uint32_t plain;
        seed += table[key & 0xffu];
        output = input ^ (key + seed);
        plain = decrypt ? output : input;
        key = ((~key << 21) + 0x11111111u) | (key >> 11);
        seed += plain + (seed << 5) + 3u;
        libmpq__store_le32(data + i, output);
    }
}

/* Check the reference recipe against independently fixed ciphertext before using it. */
static int
test_patch_cipher_vector(void)
{
    static const uint8_t expected[32] = { 0x2d, 0xba, 0xad, 0xd4, 0xd8, 0xf2, 0xcb, 0x4a,
                                          0xe5, 0xb6, 0xed, 0xb5, 0xa3, 0x4d, 0x5c, 0xfe,
                                          0x95, 0x38, 0xa9, 0x01, 0xb9, 0xf3, 0x8a, 0xc7,
                                          0x37, 0xba, 0xb8, 0xe8, 0x95, 0x24, 0x7d, 0x06 };
    uint8_t data[32];
    memset(data, 'B', sizeof(data));
    reference_patch_cipher(data, sizeof(data), 0xa25af234u, 0);
    TEST_CHECK(memcmp(data, expected, sizeof(data)) == 0);
    reference_patch_cipher(data, sizeof(data), 0xa25af234u, 1);
    for (size_t i = 0; i < sizeof(data); i++)
        TEST_CHECK(data[i] == 'B');
    return 0;
}

/* Inspect wire block metadata and ciphertext without native key/cipher helpers. */
static int
check_relocated_patch_cipher(
    mpq_archive_s *archive, const uint8_t *plain, size_t size, uint64_t original_offset
)
{
    uint8_t header[LIBMPQ_HEADER_V3_WIRE_SIZE];
    uint8_t table[4096];
    uint8_t expected[9000];
    uint8_t stored[9000];
    uint8_t high[2];
    uint32_t number;
    uint32_t count;
    uint32_t row;
    uint32_t flags;
    uint32_t key;
    uint32_t sector_size;
    uint64_t table_offset;
    uint64_t offset;
    uint64_t high_offset;
    const uint8_t *record;

    TEST_CHECK(archive->archive_offset == 0 && size <= sizeof(stored));
    TEST_CHECK(libmpq__file_number(archive, "folder/reference.bin", &number) == 0);
    row = archive->mpq_entry[archive->mpq_map[number].entry_index].classic_source_index;
    TEST_CHECK(libmpq__source_read_at(archive->source, 0, header, sizeof(header)) == 0);
    count = libmpq__load_le32(header + 28);
    TEST_CHECK(row < count && count <= sizeof(table) / 16);
    table_offset =
        libmpq__load_le32(header + 20) | ((uint64_t)libmpq__load_le16(header + 42) << 32);
    TEST_CHECK(
        libmpq__source_read_at(archive->source, table_offset, table, (size_t)count * 16) == 0
    );
    reference_patch_cipher(table, (size_t)count * 16, 0xec83b3a3u, 1);
    record = table + (size_t)row * 16;
    offset = libmpq__load_le32(record);
    high_offset = libmpq__load_le64(header + 32);
    if (high_offset != 0) {
        TEST_CHECK(
            libmpq__source_read_at(archive->source, high_offset + (uint64_t)row * 2, high, 2) == 0
        );
        offset |= (uint64_t)libmpq__load_le16(high) << 32;
    }
    flags = libmpq__load_le32(record + 12);
    TEST_CHECK(offset != original_offset);
    TEST_CHECK(offset == archive->mpq_entry[archive->mpq_map[number].entry_index].offset);
    TEST_CHECK(libmpq__load_le32(record + 4) == size && libmpq__load_le32(record + 8) == size);
    TEST_CHECK(
        (flags & (LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u)) ==
        (LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u)
    );
    TEST_CHECK((flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE)) == 0);
    TEST_CHECK(libmpq__load_le16(header + 14) <= 15);
    sector_size = 512u << libmpq__load_le16(header + 14);

    /* Independently fixed basename hash for reference.bin, excluding its directory. */
    key = (0xa25af234u + (uint32_t)offset) ^ (uint32_t)size;
    memcpy(expected, plain, size);
    for (size_t position = 0, sector = 0; position < size; sector++) {
        size_t length = (flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ? size : sector_size;
        if (length > size - position)
            length = size - position;
        reference_patch_cipher(expected + position, length, key + (uint32_t)sector, 0);
        position += length;
    }
    TEST_CHECK(libmpq__source_read_at(archive->source, offset, stored, size) == 0);
    TEST_CHECK(memcmp(stored, expected, size) == 0);
    return 0;
}

/* The committed layer and its regenerated recipe agree, and materialize exact logical contents. */
static int
test_v3_committed_patch(void)
{
    const char *path = FIXTURE_DIR "/mpq-v3-features-patch.mpq";
    const char *layers[] = { path };
    char generated_path[1024];
    uint8_t *committed = NULL;
    uint8_t *generated = NULL;
    size_t committed_size;
    size_t generated_size;
    mpq_archive_s *base = NULL;
    mpq_archive_s *patch = NULL;
    mpq_patch_view_s *view = NULL;
    uint8_t *zlib_data = NULL;
    size_t zlib_size;
    uint8_t secure[32 * (sizeof(v3_fixture_line) - 1)];
    uint8_t added[32];
    uint32_t number;
    uint64_t added_offset;

    TEST_CHECK(test_temp_path(generated_path, sizeof(generated_path), "v3-patch-recipe") == 0);
    TEST_CHECK(generate_v3_patch_fixture(generated_path) == 0);
    TEST_CHECK(test_read_path(path, &committed, &committed_size) == 0);
    TEST_CHECK(test_read_path(generated_path, &generated, &generated_size) == 0);
    TEST_CHECK(
        committed_size == generated_size && memcmp(committed, generated, committed_size) == 0
    );
    free(committed);
    free(generated);
    TEST_CHECK(remove(generated_path) == 0);
    TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v3-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__file_number(base, "zlib.txt", &number) == 0);
    TEST_CHECK(test_archive_read(base, number, &zlib_data, &zlib_size) == 0);
    TEST_CHECK(zlib_size > 17);
    zlib_data[17] ^= 0x5au;
    TEST_CHECK(libmpq__archive_close(base) == 0);
    for (size_t i = 0; i < 32; i++)
        memcpy(
            secure + i * (sizeof(v3_fixture_line) - 1), v3_fixture_line, sizeof(v3_fixture_line) - 1
        );
    memset(added, 'B', sizeof(added));
    TEST_CHECK(libmpq__archive_open(&patch, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(patch, "folder/reference.bin", &number) == 0);
    added_offset = patch->mpq_entry[patch->mpq_map[number].entry_index].offset;

    /* Independently checked basename key and wire ciphertext for the directory addition. */
    TEST_CHECK(check_relocated_patch_cipher(patch, added, sizeof(added), UINT64_MAX) == 0);
    TEST_CHECK(libmpq__archive_close(patch) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, FIXTURE_DIR "/mpq-v3-features.mpq", layers, 1) == 0);
    patch = libmpq__patch_view_archive(view);
    TEST_CHECK(
        patch->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE &&
        patch->mpq_header.header_size == 0x44
    );
    TEST_CHECK(
        patch->files == 17 && patch->mpq_het.header.entry_count == patch->mpq_bet.header.entry_count
    );
    TEST_CHECK(
        check_v3_materialized_member(
            patch, "overview.txt", v3_fixture_copy, sizeof(v3_fixture_copy) - 1, 0
        ) == 0
    );
    TEST_CHECK(
        check_v3_materialized_member(
            patch, "zlib.txt", zlib_data, zlib_size, LIBMPQ_FILE_FLAG_COMPRESS
        ) == 0
    );
    TEST_CHECK(
        check_v3_materialized_member(
            patch, "encrypted-compress.txt", secure, sizeof(secure),
            LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_COMPRESS
        ) == 0
    );
    TEST_CHECK(
        check_v3_materialized_member(
            patch, "folder/reference.bin", added, sizeof(added),
            LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE | 0x00020000u
        ) == 0
    );
    TEST_CHECK(check_relocated_patch_cipher(patch, added, sizeof(added), added_offset) == 0);
    TEST_CHECK(libmpq__file_number(patch, "zero.bin", &number) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_number(patch, "(signature)", &number) == LIBMPQ_ERROR_EXIST);
    {
        static const char *const retained[] = {
            "implode.txt",     "huffman.txt",      "pkware.txt",      "bzip2.txt",
            "chain.txt",       "wave-mono.wav",    "wave-stereo.wav", "sparse.txt",
            "sparse-zlib.txt", "sparse-bzip2.txt", "lzma.txt"
        };
        TEST_CHECK(libmpq__archive_open(&base, FIXTURE_DIR "/mpq-v3-features.mpq", 0) == 0);
        for (size_t i = 0; i < sizeof(retained) / sizeof(retained[0]); i++) {
            uint8_t *before = NULL;
            uint8_t *after = NULL;
            size_t before_size;
            size_t after_size;
            uint32_t original_flags;
            uint32_t final_flags;
            libmpq__off_t original_packed;
            libmpq__off_t final_packed;
            TEST_CHECK(libmpq__file_number(base, retained[i], &number) == 0);
            TEST_CHECK(libmpq__file_flags(base, number, &original_flags) == 0);
            TEST_CHECK(libmpq__file_size_packed(base, number, &original_packed) == 0);
            TEST_CHECK(test_archive_read(base, number, &before, &before_size) == 0);
            TEST_CHECK(libmpq__file_number(patch, retained[i], &number) == 0);
            TEST_CHECK(
                libmpq__file_flags(patch, number, &final_flags) == 0 &&
                final_flags == original_flags
            );
            TEST_CHECK(
                libmpq__file_size_packed(patch, number, &final_packed) == 0 &&
                final_packed == original_packed
            );
            TEST_CHECK(test_archive_read(patch, number, &after, &after_size) == 0);
            TEST_CHECK(after_size == before_size && memcmp(before, after, before_size) == 0);
            free(after);
            free(before);
        }
        TEST_CHECK(libmpq__archive_close(base) == 0);
    }
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    free(zlib_data);
    return 0;
}

/* Later transforms consume the preceding contents, including relocated encrypted members. */
static int
test_v3_chain(uint32_t flags, uint8_t bet_only)
{
    static const char name[] = "folder/reference.bin";
    char base_path[1024];
    char paths[4][1024];
    const char *layers[4];
    uint8_t contents[4][9000];
    size_t size = (flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ? 1024 : 9000;
    size_t sizes[4];
    mpq_archive_create_options_s create = {
        LIBMPQ_ARCHIVE_VERSION_THREE, 16, 4096, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
        bet_only ? 0 : LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME
    };
    mpq_file_options_s storage = { flags, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_file_options_s plain = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    uint64_t original_offset;
    uint32_t number;
    uint8_t *base_image = NULL;
    uint8_t *unchanged = NULL;
    size_t base_size;
    size_t unchanged_size;
    uint8_t signed_inputs = !bet_only && (flags & 0x00020000u) != 0;

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "chain-v3-base") == 0);
    for (size_t i = 0; i < 4; i++) {
        char tag[32];
        TEST_CHECK(snprintf(tag, sizeof(tag), "chain-v3-layer-%u", (unsigned)i) > 0);
        TEST_CHECK(test_temp_path(paths[i], sizeof(paths[i]), tag) == 0);
        layers[i] = paths[i];
        sizes[i] = size - i * 7;
        memset(contents[i], (int)('A' + i), size);
    }
    TEST_CHECK(libmpq__archive_create(&writer, base_path, &create) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(writer, name, contents[0], (libmpq__off_t)size, &storage) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, "keep.bin", contents[0], (libmpq__off_t)size, &storage) ==
        0
    );
    if (!bet_only)
        writer->write_attributes[writer->write_next_block - 1].filetime = 123456;
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "removed.txt", first_text, sizeof(first_text) - 1, &plain
        ) == 0
    );
    if (signed_inputs)
        TEST_CHECK(
            libmpq__archive_sign(
                writer, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    if (bet_only)
        TEST_CHECK(strip_v3_classic_tables(base_path) == 0);
    TEST_CHECK(libmpq__archive_open(&writer, base_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(writer, name, &number) == 0);
    original_offset = writer->mpq_entry[writer->mpq_map[number].entry_index].offset;
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(test_read_path(base_path, &base_image, &base_size) == 0);
    for (size_t i = 0; i < 4; i++) {
        uint8_t *payload;
        size_t payload_size;
        TEST_CHECK(libmpq__archive_create(&writer, paths[i], &create) == 0);
        writer->write_patch_mode = 1;
        if (i < 3) {
            payload = fixture_copy_patch(
                contents[i], sizes[i], contents[i + 1], sizes[i + 1], &payload_size
            );
            TEST_CHECK(payload != NULL);
            TEST_CHECK(
                libmpq__writer_patch_file_add(
                    writer, name, payload, LIBMPQ_PATCH_INFO_SIZE, payload + LIBMPQ_PATCH_INFO_SIZE,
                    (libmpq__off_t)(payload_size - LIBMPQ_PATCH_INFO_SIZE),
                    (libmpq__off_t)sizes[i + 1], &storage
                ) == 0
            );
            free(payload);
            if (i < 2)
                TEST_CHECK(
                    libmpq__archive_add_data(
                        writer, "transient.txt", contents[i + 1], 32, &plain
                    ) == 0
                );
            else
                TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "transient.txt", 0, 0) == 0);
            if (i == 1)
                TEST_CHECK(
                    libmpq__archive_add_data(
                        writer, "removed.txt", second_text, sizeof(second_text) - 1, &plain
                    ) == 0
                );
            else
                TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "removed.txt", 0, 0) == 0);
        }
        if (i == 3)
            TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "removed.txt", 0, 0) == 0);
        TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "absent.txt", 0, 0) == 0);
        if (signed_inputs)
            TEST_CHECK(
                libmpq__archive_sign(
                    writer, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                    sizeof(test_signature_private_key)
                ) == 0
            );
        TEST_CHECK(libmpq__archive_close(writer) == 0);
        if (bet_only)
            TEST_CHECK(strip_v3_classic_tables(paths[i]) == 0);
    }
    for (size_t count = 1; count <= 4; count++) {
        mpq_archive_s *archive;
        TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, count) == 0);
        archive = libmpq__patch_view_archive(view);
        TEST_CHECK(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE);
        TEST_CHECK(archive->mpq_header.header_size == LIBMPQ_HEADER_V3_WIRE_SIZE);
        TEST_CHECK(
            archive->mpq_header_v3.het_table_offset < archive->mpq_header_v3.bet_table_offset
        );
        TEST_CHECK(archive->mpq_header_v3.bet_table_offset < archive->mpq_header.hash_table_offset);
        TEST_CHECK(
            check_v3_materialized_member(
                archive, name, contents[count < 4 ? count : 3], sizes[count < 4 ? count : 3], flags
            ) == 0
        );
        TEST_CHECK(
            check_v3_materialized_member(archive, "keep.bin", contents[0], size, flags) == 0
        );
        if (!bet_only) {
            mpq_file_attributes_s attributes;
            uint8_t digest[16];
            fixture_md5(contents[0], size, digest);
            TEST_CHECK(libmpq__file_number(archive, "keep.bin", &number) == 0);
            TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
            TEST_CHECK(attributes.filetime == 123456);
            TEST_CHECK(attributes.crc32 == crc32(0, contents[0], (uInt)size));
            TEST_CHECK(memcmp(attributes.md5, digest, sizeof(digest)) == 0);
        }
        TEST_CHECK(libmpq__file_number(archive, "absent.txt", &number) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(
            libmpq__file_number(archive, "removed.txt", &number) ==
            (count == 2 ? 0 : LIBMPQ_ERROR_EXIST)
        );
        if (count < 3)
            TEST_CHECK(
                check_v3_materialized_member(
                    archive, "transient.txt", contents[count], 32, LIBMPQ_FILE_FLAG_SINGLE
                ) == 0
            );
        else
            TEST_CHECK(
                libmpq__file_number(archive, "transient.txt", &number) == LIBMPQ_ERROR_EXIST
            );
        TEST_CHECK(
            archive->files == (count == 1   ? 4u
                               : count == 2 ? 5u
                                            : 3u) +
                                  (bet_only ? 0u : 1u)
        );
        if ((flags & (0x00020000u | LIBMPQ_FILE_FLAG_COMPRESS)) == 0x00020000u)
            TEST_CHECK(
                check_relocated_patch_cipher(
                    archive, contents[count < 4 ? count : 3], sizes[count < 4 ? count : 3],
                    original_offset
                ) == 0
            );
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
    }
    {
        const char *interleaved[] = { paths[0], paths[3], paths[1], paths[2] };

        /* An absent deletion between transforms must not reset the current contents. */
        TEST_CHECK(libmpq__patch_view_open(&view, base_path, interleaved, 4) == 0);
        TEST_CHECK(
            check_v3_materialized_member(
                libmpq__patch_view_archive(view), name, contents[3], sizes[3], flags
            ) == 0
        );
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
    }
    {
        char wrapped[3][1024];
        uint8_t codes[3][sizeof(mpqe_auth_code) - 1];
        uint8_t wrong[sizeof(mpqe_auth_code) - 1];
        mpq_patch_source_s base_source;
        mpq_patch_source_s sources[3];
        const char *inputs[] = { base_path, paths[0], paths[1] };
        for (size_t i = 0; i < 3; i++) {
            char tag[32];
            memcpy(codes[i], mpqe_auth_code, sizeof(codes[i]));
            codes[i][0] ^= (uint8_t)i;
            TEST_CHECK(snprintf(tag, sizeof(tag), "chain-wrapped-%u", (unsigned)i) > 0);
            TEST_CHECK(test_temp_path(wrapped[i], sizeof(wrapped[i]), tag) == 0);
            TEST_CHECK(fixture_mpqe_patch(inputs[i], wrapped[i], codes[i], sizeof(codes[i])) == 0);
            if (signed_inputs) {
                uint32_t mismatches;
                TEST_CHECK(
                    libmpq__archive_open_mpqe(
                        &writer, wrapped[i], -1, codes[i], sizeof(codes[i])
                    ) == 0
                );
                TEST_CHECK(
                    libmpq__archive_verify(
                        writer, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                        sizeof(test_signature_public_key), &mismatches
                    ) == 0 &&
                    mismatches == 0
                );
                TEST_CHECK(libmpq__archive_close(writer) == 0);
            }
        }

        /* Each source independently selects its container and authentication code. */
        for (uint32_t mask = 0; mask < 8; mask++) {
            base_source =
                (mpq_patch_source_s){ mask & 1 ? wrapped[0] : base_path, mask & 1 ? codes[0] : NULL,
                                      mask & 1 ? sizeof(mpqe_auth_code) - 1 : 0, NULL };
            for (size_t i = 0; i < 2; i++) {
                uint8_t encrypted = (uint8_t)(mask & (2u << i));
                sources[i] =
                    (mpq_patch_source_s){ encrypted ? wrapped[i + 1] : paths[i],
                                          encrypted ? codes[i + 1] : NULL,
                                          encrypted ? sizeof(mpqe_auth_code) - 1 : 0, NULL };
            }
            sources[2] = (mpq_patch_source_s){ paths[2], NULL, 0, NULL };
            TEST_CHECK(libmpq__patch_view_open_sources(&view, &base_source, sources, 3) == 0);
            TEST_CHECK(!libmpq__source_is_mpqe(libmpq__patch_view_archive(view)->source));
            {
                uint32_t signatures;
                TEST_CHECK(
                    libmpq__archive_signatures(libmpq__patch_view_archive(view), &signatures) ==
                        0 &&
                    signatures == 0
                );
            }
            TEST_CHECK(
                check_v3_materialized_member(
                    libmpq__patch_view_archive(view), name, contents[3], sizes[3], flags
                ) == 0
            );
            TEST_CHECK(
                check_v3_materialized_member(
                    libmpq__patch_view_archive(view), "keep.bin", contents[0], size, flags
                ) == 0
            );
            TEST_CHECK(libmpq__patch_view_close(view) == 0);
            view = NULL;
        }
        for (size_t i = 0; i < 3; i++) {
            uint8_t *snapshot = NULL;
            uint8_t *current = NULL;
            size_t snapshot_size;
            size_t current_size;
            base_source =
                (mpq_patch_source_s){ wrapped[0], codes[0], sizeof(mpqe_auth_code) - 1, NULL };
            sources[0] =
                (mpq_patch_source_s){ wrapped[1], codes[1], sizeof(mpqe_auth_code) - 1, NULL };
            sources[1] =
                (mpq_patch_source_s){ wrapped[2], codes[2], sizeof(mpqe_auth_code) - 1, NULL };
            memcpy(wrong, codes[i], sizeof(wrong));
            wrong[0] ^= 0x80u;
            if (i == 0)
                base_source.auth_code = wrong;
            else
                sources[i - 1].auth_code = wrong;
            TEST_CHECK(test_read_path(wrapped[i], &snapshot, &snapshot_size) == 0);
            TEST_CHECK(libmpq__patch_view_open_sources(&view, &base_source, sources, 3) != 0);
            TEST_CHECK(view == NULL);
            TEST_CHECK(test_read_path(wrapped[i], &current, &current_size) == 0);
            TEST_CHECK(
                current_size == snapshot_size && memcmp(current, snapshot, current_size) == 0
            );
            free(current);
            free(snapshot);
        }

        /* Path-only callers cannot supply per-layer MPQE credentials. */
        layers[0] = wrapped[1];
        TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 3) != 0 && view == NULL);
        layers[0] = paths[0];
        TEST_CHECK(fixture_container(base_path, wrapped[0]) == 0);
        if (signed_inputs) {
            uint32_t mismatches;
            TEST_CHECK(libmpq__archive_open(&writer, wrapped[0], -1) == 0);
            TEST_CHECK(writer->archive_offset == 512);
            TEST_CHECK(
                libmpq__archive_verify(
                    writer, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                    sizeof(test_signature_public_key), &mismatches
                ) == 0 &&
                mismatches == 0
            );
            TEST_CHECK(libmpq__archive_close(writer) == 0);
        }
        base_source = (mpq_patch_source_s){ wrapped[0], NULL, 0, NULL };
        for (size_t i = 0; i < 3; i++)
            sources[i] = (mpq_patch_source_s){ paths[i], NULL, 0, NULL };
        TEST_CHECK(libmpq__patch_view_open_sources(&view, &base_source, sources, 3) == 0);
        TEST_CHECK(libmpq__patch_view_archive(view)->archive_offset == 0);
        TEST_CHECK(
            check_v3_materialized_member(
                libmpq__patch_view_archive(view), name, contents[3], sizes[3], flags
            ) == 0
        );
        if ((flags & (0x00020000u | LIBMPQ_FILE_FLAG_COMPRESS)) == 0x00020000u)
            TEST_CHECK(
                check_relocated_patch_cipher(
                    libmpq__patch_view_archive(view), contents[3], sizes[3], original_offset
                ) == 0
            );
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
        TEST_CHECK(
            fixture_mpqe_patch(wrapped[0], wrapped[2], codes[0], sizeof(mpqe_auth_code) - 1) == 0
        );
        base_source =
            (mpq_patch_source_s){ wrapped[2], codes[0], sizeof(mpqe_auth_code) - 1, NULL };
        sources[0] = (mpq_patch_source_s){ wrapped[1], codes[1], sizeof(mpqe_auth_code) - 1, NULL };
        TEST_CHECK(libmpq__patch_view_open_sources(&view, &base_source, sources, 3) == 0);
        TEST_CHECK(
            check_v3_materialized_member(
                libmpq__patch_view_archive(view), name, contents[3], sizes[3], flags
            ) == 0
        );
        if ((flags & (0x00020000u | LIBMPQ_FILE_FLAG_COMPRESS)) == 0x00020000u)
            TEST_CHECK(
                check_relocated_patch_cipher(
                    libmpq__patch_view_archive(view), contents[3], sizes[3], original_offset
                ) == 0
            );
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
        view = NULL;
        for (size_t i = 0; i < 3; i++)
            TEST_CHECK(remove(wrapped[i]) == 0);
    }
#ifdef LIBMPQ_TEST_PATCH_IO_WRAP
    for (uint32_t scenario = 0; scenario < 8; scenario++) {
        uint32_t layer = scenario % 2 + 2;
        uint32_t fault = scenario / 2;
        memset(&patch_fault, 0, sizeof(patch_fault));
        patch_fault.fault = fault == 0   ? PATCH_FAULT_VALIDATE
                            : fault == 1 ? PATCH_FAULT_EXPOSE
                            : fault == 2 ? PATCH_FAULT_REMOVE_OLD
                                         : PATCH_FAULT_FINALIZE;
        patch_fault.fail_open = fault == 3 ? layer : layer * 2 - (fault == 1 ? 2u : 1u);
        memcpy(patch_fault.base_path, base_path, strlen(base_path) + 1);
        patch_fault.enabled = 1;
        TEST_CHECK(
            libmpq__patch_view_open(&view, base_path, layers, 3) ==
            (fault == 0   ? LIBMPQ_ERROR_FORMAT
             : fault == 1 ? LIBMPQ_ERROR_OPEN
             : fault == 2 ? LIBMPQ_ERROR_WRITE
                          : LIBMPQ_ERROR_CLOSE)
        );
        patch_fault.enabled = 0;
        TEST_CHECK(view == NULL && !patch_fault.invalid);
        TEST_CHECK(patch_fault.removed == layer + (fault == 1 ? 0u : 1u));
        TEST_CHECK(patch_fault.candidate_closes == patch_fault.candidate_opens);
    }
    memset(&patch_fault, 0, sizeof(patch_fault));
#endif

    /* A later incomplete namespace fails after earlier candidates have been adopted. */
    create.flags = 0;
    TEST_CHECK(libmpq__archive_create(&writer, paths[3], &create) == 0);
    writer->write_patch_mode = 1;
    TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "unknown.txt", 0, 0) == 0);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 4) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(view == NULL);
    {
        uint8_t *payload;
        size_t payload_size;
        create.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
        TEST_CHECK(libmpq__archive_create(&writer, paths[2], &create) == 0);
        writer->write_patch_mode = 1;
        payload = fixture_copy_patch(contents[2], sizes[2], contents[3], sizes[3], &payload_size);
        TEST_CHECK(payload != NULL);
        payload[12] ^= 1;
        TEST_CHECK(
            libmpq__writer_patch_file_add(
                writer, name, payload, LIBMPQ_PATCH_INFO_SIZE, payload + LIBMPQ_PATCH_INFO_SIZE,
                (libmpq__off_t)(payload_size - LIBMPQ_PATCH_INFO_SIZE), (libmpq__off_t)sizes[3],
                &storage
            ) == 0
        );
        free(payload);
        TEST_CHECK(libmpq__archive_close(writer) == 0);
        TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 3) != 0);
        TEST_CHECK(view == NULL);
        if ((flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0) {
            FILE *file;
            uint64_t offset;
            int byte;
            TEST_CHECK(libmpq__archive_open(&writer, paths[2], 0) == 0);
            TEST_CHECK(libmpq__file_number(writer, name, &number) == 0);
            offset = writer->mpq_entry[writer->mpq_map[number].entry_index].offset;
            TEST_CHECK(libmpq__archive_close(writer) == 0);
            file = libmpq__file_open(paths[2], "r+b");
            TEST_CHECK(file != NULL && libmpq__file_seek(file, offset + 12, SEEK_SET) == 0);
            byte = fgetc(file);
            TEST_CHECK(byte != EOF && libmpq__file_seek(file, offset + 12, SEEK_SET) == 0);

            /* Restore valid integrity metadata, then corrupt the encrypted body itself. */
            TEST_CHECK(fputc(byte ^ 1, file) != EOF);
            TEST_CHECK(libmpq__file_seek(file, offset + LIBMPQ_PATCH_INFO_SIZE, SEEK_SET) == 0);
            byte = fgetc(file);
            TEST_CHECK(
                byte != EOF &&
                libmpq__file_seek(file, offset + LIBMPQ_PATCH_INFO_SIZE, SEEK_SET) == 0
            );
            TEST_CHECK(fputc(byte ^ 1, file) != EOF && fclose(file) == 0);
            TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 3) != 0 && view == NULL);
        }
    }
    TEST_CHECK(test_read_path(base_path, &unchanged, &unchanged_size) == 0);
    TEST_CHECK(unchanged_size == base_size && memcmp(unchanged, base_image, base_size) == 0);
    free(unchanged);
    free(base_image);
    TEST_CHECK(libmpq__archive_open(&writer, base_path, 0) == 0);
    TEST_CHECK(libmpq__file_number(writer, name, &number) == 0);
    TEST_CHECK(writer->mpq_entry[writer->mpq_map[number].entry_index].offset == original_offset);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    for (size_t i = 0; i < 4; i++)
        TEST_CHECK(remove(paths[i]) == 0);
    TEST_CHECK(remove(base_path) == 0);
    return 0;
}

/* Exercise full named rebuilds without committing or modifying any source fixture. */
static int
test_v3_materialization(
    uint8_t bet_only, uint8_t prefix, uint32_t flags, uint8_t bad_names, uint8_t corrupt,
    uint8_t embedded
)
{
    static const char name[] = "folder/reference.bin";
    char physical[128];
    char base_path[1024];
    char patch_path[1024];
    char embedded_path[1024];
    uint8_t before[9000];
    uint8_t after[9000];
    size_t member_size = (flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ? 1024 : sizeof(before);
    size_t after_size = (flags & 0x00020000u) != 0 && (flags & LIBMPQ_FILE_FLAG_COMPRESS) == 0
                            ? member_size - 17
                            : member_size;
    uint8_t *payload = NULL;
    size_t payload_size;
    uint8_t *base_image = NULL;
    uint8_t *patch_image = NULL;
    uint8_t *unchanged = NULL;
    size_t base_size;
    size_t patch_size;
    size_t unchanged_size;
    mpq_archive_s *writer = NULL;
    mpq_archive_s *archive;
    mpq_patch_view_s *view = NULL;
    mpq_patch_source_s base = { base_path, NULL, 0, NULL };
    mpq_patch_source_s layer = { patch_path, NULL, 0, prefix ? "Base" : NULL };
    mpq_archive_create_options_s options = {
        LIBMPQ_ARCHIVE_VERSION_THREE, 16, 4096, bad_names == 1 ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE,
        bet_only ? 0 : LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME
    };
    mpq_file_options_s storage = { flags, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_file_options_s plain = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_file_attributes_s attributes;
    uint32_t number;
    uint32_t count;
    uint64_t het_size;
    uint64_t bet_size;
    uint64_t original_offset;
    uint64_t kept_offset;
    int32_t expected_failure = 0;

    if ((flags & LIBMPQ_FILE_FLAG_COMPRESS) == 0)
        storage.compression_first = storage.compression_next = 0;
    for (size_t i = 0; i < sizeof(before); i++) {
        before[i] = (uint8_t)(i % 31);
        after[i] = (uint8_t)(i % 29);
    }
    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "v3-materialize-base") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "v3-materialize-layer") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, base_path, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(writer, name, before, member_size, &storage) == 0);
    TEST_CHECK(libmpq__archive_add_data(writer, "keep.bin", before, member_size, &storage) == 0);
    if (!bet_only)
        writer->write_attributes[writer->write_next_block - 1].filetime = 123456;
    TEST_CHECK(libmpq__archive_add_data(writer, "regular.txt", before, member_size, &storage) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "remove.txt", first_text, sizeof(first_text) - 1, &plain
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    if (bet_only)
        TEST_CHECK(strip_v3_classic_tables(base_path) == 0);
    if (embedded) {
        TEST_CHECK(
            test_temp_path(embedded_path, sizeof(embedded_path), "v3-materialize-container") == 0
        );
        TEST_CHECK(fixture_container(base_path, embedded_path) == 0);
        base.path = embedded_path;
    }
    TEST_CHECK(libmpq__archive_open(&archive, base.path, -1) == 0);
    TEST_CHECK(archive->archive_offset == (embedded ? 512 : 0));
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    original_offset = archive->mpq_entry[archive->mpq_map[number].entry_index].offset;
    TEST_CHECK(libmpq__file_number(archive, "keep.bin", &number) == 0);
    kept_offset = archive->mpq_entry[archive->mpq_map[number].entry_index].offset;
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    options.flags = bad_names == 2 ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    TEST_CHECK(libmpq__archive_create(&writer, patch_path, &options) == 0);
    writer->write_patch_mode = 1;
    payload = fixture_copy_patch(before, member_size, after, after_size, &payload_size);
    TEST_CHECK(payload != NULL);
    if (corrupt)
        payload[12] ^= 1;
    TEST_CHECK(snprintf(physical, sizeof(physical), "%s%s", prefix ? "Base\\" : "", name) > 0);
    TEST_CHECK(
        libmpq__writer_patch_file_add(
            writer, physical, payload, LIBMPQ_PATCH_INFO_SIZE, payload + LIBMPQ_PATCH_INFO_SIZE,
            (libmpq__off_t)(payload_size - LIBMPQ_PATCH_INFO_SIZE), (libmpq__off_t)after_size,
            &storage
        ) == 0
    );
    free(payload);
    TEST_CHECK(snprintf(physical, sizeof(physical), "%sremove.txt", prefix ? "Base\\" : "") > 0);
    TEST_CHECK(libmpq__writer_patch_delete_marker(writer, physical, 0, 0) == 0);
    TEST_CHECK(snprintf(physical, sizeof(physical), "%sregular.txt", prefix ? "Base\\" : "") > 0);
    TEST_CHECK(
        libmpq__archive_add_data(writer, physical, new_text, sizeof(new_text) - 1, &plain) == 0
    );
    TEST_CHECK(snprintf(physical, sizeof(physical), "%sadded.txt", prefix ? "Base\\" : "") > 0);
    TEST_CHECK(
        libmpq__archive_add_data(writer, physical, new_text, sizeof(new_text) - 1, &plain) == 0
    );
    TEST_CHECK(snprintf(physical, sizeof(physical), "%szero.bin", prefix ? "Base\\" : "") > 0);
    TEST_CHECK(libmpq__archive_add_data(writer, physical, NULL, 0, &plain) == 0);
    TEST_CHECK(
        snprintf(physical, sizeof(physical), "%s(patch_metadata)", prefix ? "Base\\" : "") > 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(writer, physical, first_text, sizeof(first_text) - 1, &plain) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    if (bet_only)
        TEST_CHECK(strip_v3_classic_tables(patch_path) == 0);
    TEST_CHECK(test_read_path(base.path, &base_image, &base_size) == 0);
    TEST_CHECK(test_read_path(patch_path, &patch_image, &patch_size) == 0);
#ifdef LIBMPQ_TEST_PATCH_IO_WRAP
    if (patch_fault.fault != PATCH_FAULT_NONE) {
        TEST_CHECK(strlen(base.path) < sizeof(patch_fault.base_path));
        memcpy(patch_fault.base_path, base.path, strlen(base.path) + 1);
        patch_fault.enabled = 1;
        expected_failure = patch_fault.fault == PATCH_FAULT_CLOSE_LOWER  ? LIBMPQ_ERROR_CLOSE
                           : patch_fault.fault == PATCH_FAULT_REMOVE_OLD ? LIBMPQ_ERROR_WRITE
                           : patch_fault.fault == PATCH_FAULT_EXPOSE     ? LIBMPQ_ERROR_OPEN
                                                                         : LIBMPQ_ERROR_FORMAT;
    }
#endif
    if (bad_names || corrupt || expected_failure != 0) {
        TEST_CHECK(
            libmpq__patch_view_open_sources(&view, &base, &layer, 1) ==
            (expected_failure != 0 ? expected_failure : LIBMPQ_ERROR_FORMAT)
        );
        TEST_CHECK(view == NULL);
    } else {
        mpq_patch_source_s layers[2] = { layer, layer };
        TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, layers, 2) == LIBMPQ_ERROR_FORMAT);
        TEST_CHECK(view == NULL);
        TEST_CHECK(libmpq__patch_view_open_sources(&view, &base, &layer, 1) == 0);
        archive = libmpq__patch_view_archive(view);
        TEST_CHECK(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_THREE);
        TEST_CHECK(archive->mpq_header.header_size == LIBMPQ_HEADER_V3_WIRE_SIZE);
        TEST_CHECK(archive->het_data != NULL && archive->bet_data != NULL);
        TEST_CHECK(archive->mpq_header_v3.archive_size == archive->file_size);
        TEST_CHECK(libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size) == 0);
        TEST_CHECK(
            archive->mpq_header_v3.het_table_offset + het_size ==
            archive->mpq_header_v3.bet_table_offset
        );
        TEST_CHECK(
            archive->mpq_header_v3.bet_table_offset + bet_size ==
            archive->mpq_header.hash_table_offset
        );
        TEST_CHECK(libmpq__archive_files(archive, &count) == 0 && count == (bet_only ? 6u : 7u));
        TEST_CHECK(check_v3_materialized_member(archive, name, after, after_size, flags) == 0);
        TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
        TEST_CHECK(
            archive->mpq_entry[archive->mpq_map[number].entry_index].offset != original_offset
        );
        if ((flags & 0x00020000u) != 0 && (flags & LIBMPQ_FILE_FLAG_COMPRESS) == 0)
            TEST_CHECK(
                check_relocated_patch_cipher(archive, after, after_size, original_offset) == 0
            );
        TEST_CHECK(
            check_v3_materialized_member(archive, "keep.bin", before, member_size, flags) == 0
        );
        TEST_CHECK(libmpq__file_number(archive, "keep.bin", &number) == 0);
        TEST_CHECK(archive->mpq_entry[archive->mpq_map[number].entry_index].offset == kept_offset);
        TEST_CHECK(
            check_v3_materialized_member(
                archive, "regular.txt", new_text, sizeof(new_text) - 1, flags
            ) == 0
        );
        TEST_CHECK(
            check_v3_materialized_member(
                archive, "added.txt", new_text, sizeof(new_text) - 1, LIBMPQ_FILE_FLAG_SINGLE
            ) == 0
        );
        TEST_CHECK(
            check_v3_materialized_member(
                archive, "zero.bin", (const uint8_t *)"", 0, LIBMPQ_FILE_FLAG_SINGLE
            ) == 0
        );
        TEST_CHECK(libmpq__file_number(archive, "remove.txt", &number) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(libmpq__file_number(archive, "(signature)", &number) == LIBMPQ_ERROR_EXIST);
        if (!bet_only) {
            TEST_CHECK(libmpq__file_number(archive, "keep.bin", &number) == 0);
            TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
            TEST_CHECK(attributes.filetime == 123456);
            TEST_CHECK(attributes.crc32 == crc32(0, before, (uInt)member_size));
            TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
            TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
            TEST_CHECK(attributes.crc32 == crc32(0, after, (uInt)after_size));
        }
        TEST_CHECK(libmpq__patch_view_close(view) == 0);
    }
#ifdef LIBMPQ_TEST_PATCH_IO_WRAP
    patch_fault.enabled = 0;
    if (expected_failure != 0) {
        FILE *leftover;
        TEST_CHECK(!patch_fault.invalid && patch_fault.lower_closes == 1);
        TEST_CHECK(
            patch_fault.candidate_opens == (patch_fault.fault == PATCH_FAULT_EXPOSE ? 2u : 1u)
        );
        TEST_CHECK(patch_fault.candidate_closes == patch_fault.candidate_opens);
        TEST_CHECK(patch_fault.removed == 2);
        TEST_CHECK(
            patch_fault.removal_failures == (patch_fault.fault == PATCH_FAULT_REMOVE_OLD ? 1u : 0u)
        );
        leftover = libmpq__file_open(patch_fault.candidate_path, "rb");
        TEST_CHECK(leftover == NULL);
        leftover = libmpq__file_open(patch_fault.old_path, "rb");
        TEST_CHECK(leftover == NULL);
    }
#endif
    TEST_CHECK(test_read_path(base.path, &unchanged, &unchanged_size) == 0);
    TEST_CHECK(unchanged_size == base_size && memcmp(unchanged, base_image, base_size) == 0);
    free(unchanged);
    TEST_CHECK(test_read_path(patch_path, &unchanged, &unchanged_size) == 0);
    TEST_CHECK(unchanged_size == patch_size && memcmp(unchanged, patch_image, patch_size) == 0);
    free(unchanged);
    free(base_image);
    free(patch_image);
    TEST_CHECK(remove(base_path) == 0);
    if (embedded)
        TEST_CHECK(remove(embedded_path) == 0);
    TEST_CHECK(remove(patch_path) == 0);
    return 0;
}

/* An absent delete marker leaves even an unlisted base byte-for-byte unchanged. */
static int
test_v3_noop_view(void)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_THREE, 4, 4096, 0, 0 };
    mpq_file_options_s storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
    mpq_archive_s *writer = NULL;
    mpq_patch_view_s *view = NULL;
    char base_path[1024];
    char patch_path[1024];
    const char *layers[] = { patch_path, patch_path };
    uint8_t *original = NULL;
    uint8_t actual[4096];
    size_t size;
    uint32_t signatures;
    uint32_t mismatches;

    TEST_CHECK(test_temp_path(base_path, sizeof(base_path), "v3-noop-base") == 0);
    TEST_CHECK(test_temp_path(patch_path, sizeof(patch_path), "v3-noop-layer") == 0);
    TEST_CHECK(libmpq__archive_create(&writer, base_path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(
            writer, "unlisted.txt", first_text, sizeof(first_text) - 1, &storage
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_sign(
            writer, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    TEST_CHECK(libmpq__archive_create(&writer, patch_path, &options) == 0);
    writer->write_patch_mode = 1;
    TEST_CHECK(libmpq__writer_patch_delete_marker(writer, "missing.txt", 0, 0) == 0);
    TEST_CHECK(libmpq__archive_close(writer) == 0);
    TEST_CHECK(test_read_path(base_path, &original, &size) == 0);
    TEST_CHECK(size <= sizeof(actual));
    TEST_CHECK(libmpq__patch_view_open(&view, base_path, layers, 2) == 0);
    TEST_CHECK(libmpq__patch_view_archive(view)->file_size == size);
    TEST_CHECK(
        libmpq__source_read_at(libmpq__patch_view_archive(view)->source, 0, actual, size) == 0
    );
    TEST_CHECK(memcmp(actual, original, size) == 0);
    TEST_CHECK(
        libmpq__archive_signatures(libmpq__patch_view_archive(view), &signatures) == 0 &&
        signatures == LIBMPQ_SIGNATURE_WEAK
    );
    TEST_CHECK(
        libmpq__archive_verify(
            libmpq__patch_view_archive(view), LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
            sizeof(test_signature_public_key), &mismatches
        ) == 0 &&
        mismatches == 0
    );
    TEST_CHECK(libmpq__patch_view_close(view) == 0);
    free(original);
    TEST_CHECK(remove(base_path) == 0);
    TEST_CHECK(remove(patch_path) == 0);
    return 0;
}

/* Keep fixture refresh opt-in so normal test runs never rewrite sources. */
int
main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--v3-output") == 0)
        return generate_v3_patch_fixture(argv[2]);
    if (argc == 2 && strcmp(argv[1], "--refresh") == 0)
        return refresh_fixtures();
    TEST_CHECK(argc == 1);
    TEST_CHECK(test_public_patch_payload() == 0);
    TEST_CHECK(test_views() == 0);
    TEST_CHECK(test_mpqe_base_views() == 0);
    TEST_CHECK(test_mpqe_patch_layers() == 0);
    TEST_CHECK(test_chain_edges() == 0);
    TEST_CHECK(test_container_bytes() == 0);
    TEST_CHECK(test_noop_signature() == 0);
    TEST_CHECK(test_patch_bit() == 0);
    TEST_CHECK(test_unsupported_layers() == 0);
    TEST_CHECK(test_unlisted_patch_member() == 0);
    TEST_CHECK(test_missing_listfile() == 0);
    TEST_CHECK(test_listfile_without_final_newline() == 0);
    TEST_CHECK(test_shared_base_block() == 0);
    TEST_CHECK(test_patch_payload_validation() == 0);
    TEST_CHECK(test_patch_prefix_boundaries() == 0);
    TEST_CHECK(test_copy_payload_boundaries() == 0);
    TEST_CHECK(test_unknown_base_name() == 0);
    TEST_CHECK(test_patch_only_growth() == 0);
    TEST_CHECK(test_patch_namespaces(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_patch_namespaces(LIBMPQ_ARCHIVE_VERSION_THREE) == 0);
    TEST_CHECK(test_patch_cipher_vector() == 0);
    TEST_CHECK(test_v3_committed_patch() == 0);
    TEST_CHECK(test_v3_materialization(0, 0, LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0) == 0);
    TEST_CHECK(
        test_v3_materialization(
            0, 1, LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0
        ) == 0
    );
    TEST_CHECK(
        test_v3_materialization(
            1, 1, LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0
        ) == 0
    );
    TEST_CHECK(
        test_v3_materialization(
            1, 0, LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0
        ) == 0
    );
    TEST_CHECK(test_v3_materialization(0, 0, LIBMPQ_FILE_FLAG_SINGLE, 1, 0, 0) == 0);
    TEST_CHECK(test_v3_materialization(1, 0, LIBMPQ_FILE_FLAG_SINGLE, 2, 0, 0) == 0);
    TEST_CHECK(test_v3_materialization(1, 0, LIBMPQ_FILE_FLAG_SINGLE, 0, 1, 0) == 0);
    TEST_CHECK(
        test_v3_materialization(
            0, 1, LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 1
        ) == 0
    );
    TEST_CHECK(
        test_v3_materialization(0, 1, LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 1) == 0
    );
#ifdef LIBMPQ_TEST_PATCH_IO_WRAP
    for (uint32_t fault = PATCH_FAULT_VALIDATE; fault <= PATCH_FAULT_EXPOSE; fault++) {
        memset(&patch_fault, 0, sizeof(patch_fault));
        patch_fault.fault = (patch_fault_e)fault;
        TEST_CHECK(
            test_v3_materialization(
                0, 0, LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0
            ) == 0
        );
    }
    memset(&patch_fault, 0, sizeof(patch_fault));
#endif
    TEST_CHECK(test_v3_noop_view() == 0);
    TEST_CHECK(test_v3_chain(LIBMPQ_FILE_FLAG_SINGLE, 0) == 0);
    TEST_CHECK(test_v3_chain(LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 1) == 0);
    TEST_CHECK(
        test_v3_chain(LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0) == 0
    );
    TEST_CHECK(test_v3_chain(LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 1) == 0);
    TEST_CHECK(
        test_v3_chain(LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0) == 0
    );
    return 0;
}
