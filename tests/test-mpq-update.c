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

#include "mpq-file.h"
#include "mpq-internal.h"
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

    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
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

    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_ops(update)->publish == libmpq__directory_replace);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
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
test_working_copy_isolation(const char *path, const char *reference)
{
    mpq_update_s *update = NULL;
    FILE *working;

    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);

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
    TEST_CHECK(libmpq__update_begin(&update, "source.bin") == LIBMPQ_SUCCESS);
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
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
    working = fopen(libmpq__update_path(update), "wb");
    TEST_CHECK(working != NULL);
    TEST_CHECK(fwrite(changed, 1, sizeof(changed) - 1U, working) == sizeof(changed) - 1U);
    TEST_CHECK(fclose(working) == 0);
    TEST_CHECK(read_bytes(path, &bytes, &size) == 0);
    TEST_CHECK(size == sizeof(original) - 1U && memcmp(bytes, original, size) == 0);
    free(bytes);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
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
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
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
    TEST_CHECK(libmpq__update_commit(update) != LIBMPQ_SUCCESS);
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
    uint8_t *archive_bytes;
    uint8_t *container;
    size_t archive_size;
    size_t container_size;

    TEST_CHECK(read_bytes(archive_path, &archive_bytes, &archive_size) == 0);
    container_size = sizeof(prefix) - 1U + archive_size + sizeof(suffix) - 1U;
    container = malloc(container_size);
    TEST_CHECK(container != NULL);
    memcpy(container, prefix, sizeof(prefix) - 1U);
    memcpy(container + sizeof(prefix) - 1U, archive_bytes, archive_size);
    memcpy(container + sizeof(prefix) - 1U + archive_size, suffix, sizeof(suffix) - 1U);
    TEST_CHECK(write_bytes(path, container, container_size) == 0);
    TEST_CHECK(write_bytes("update-embedded-reference.bin", container, container_size) == 0);
    free(container);
    free(archive_bytes);
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(path, "update-embedded-reference.bin"));
    return 0;
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
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
    temporary = libmpq__string_duplicate(libmpq__update_path(update));
    TEST_CHECK(temporary != NULL);
    TEST_CHECK(write_bytes("update-replacement.bin", replacement, sizeof(replacement) - 1U) == 0);
    TEST_CHECK(rename("update-replacement.bin", path) == 0);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_ERROR_EXIST);
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
    TEST_CHECK(libmpq__update_begin(&update, "update-link.bin") != LIBMPQ_SUCCESS);
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
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
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
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__update_commit(update) == LIBMPQ_SUCCESS);
    TEST_CHECK(same_file(path, reference));
    TEST_CHECK(
        libmpq__archive_open_mpqe(&archive, path, 0, auth_code, sizeof(auth_code) - 1U) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    return 0;
}

int
main(void)
{
    const char *archive_path = "update.mpq";
    mpq_update_s *update = NULL;

    TEST_CHECK(libmpq__update_begin(NULL, archive_path) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_begin(&update, NULL) == LIBMPQ_ERROR_EXIST && update == NULL);
    TEST_CHECK(libmpq__update_commit(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__update_abort(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(create_archive(archive_path) == 0);
    TEST_CHECK(copy_file(archive_path, "update-reference.mpq") == 0);
    TEST_CHECK(test_abort(archive_path) == 0);
    TEST_CHECK(test_working_copy_isolation(archive_path, "update-reference.mpq") == 0);
    TEST_CHECK(test_noop_commit(archive_path, "update-reference.mpq") == 0);
    TEST_CHECK(test_publication("update-container.bin") == 0);
    TEST_CHECK(test_failure_cleanup("update-flush.bin", UPDATE_FAULT_FLUSH) == 0);
    TEST_CHECK(test_failure_cleanup("update-close.bin", UPDATE_FAULT_CLOSE) == 0);
    TEST_CHECK(test_failure_cleanup("update-publish.bin", UPDATE_FAULT_PUBLISH) == 0);
    TEST_CHECK(test_embedded_preservation(archive_path, "update-embedded.bin") == 0);
#ifndef _WIN32
    TEST_CHECK(test_stable_working_path() == 0);
    TEST_CHECK(test_identity_mismatch("update-identity.bin") == 0);
    TEST_CHECK(test_symlink_destination() == 0);
    TEST_CHECK(test_permissions("update-permissions.bin") == 0);
#endif
    TEST_CHECK(test_mpqe_noop() == 0);
    return 0;
}
