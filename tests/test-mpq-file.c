/*
 *  test-mpq-file.c -- native file and directory regression tests.
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
#include "mpq-source.h"
#include "test-mpq-helper.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#endif

typedef struct
{
    mpq_io_backend_s backend;
    unsigned closes;
} close_failure_s;

static int32_t
close_failure_read(void *context, uint64_t offset, uint8_t *buffer, size_t size)
{
    close_failure_s *failure = context;

    return failure->backend.read_at(failure->backend.context, offset, buffer, size);
}

static int32_t
close_failure_identity(void *context, uint64_t *device, uint64_t *inode)
{
    close_failure_s *failure = context;

    return failure->backend.identity(failure->backend.context, device, inode);
}

static int32_t
close_failure_close(void *context)
{
    close_failure_s *failure = context;
    int32_t result;

    ++failure->closes;
    result = failure->backend.close == NULL ? LIBMPQ_SUCCESS
                                            : failure->backend.close(failure->backend.context);
    return result == LIBMPQ_SUCCESS ? LIBMPQ_ERROR_CLOSE : result;
}

static void
close_failure_discard(void *context)
{
    close_failure_s *failure = context;

    if (failure->backend.discard != NULL)
        failure->backend.discard(failure->backend.context);
    else if (failure->backend.close != NULL)
        (void)failure->backend.close(failure->backend.context);
}

static void
close_failure_install(mpq_source_s *source, close_failure_s *failure)
{
    failure->backend = source->backend;
    source->backend.context = failure;
    source->backend.read_at = close_failure_read;
    source->backend.identity = close_failure_identity;
    source->backend.close = close_failure_close;
    source->backend.discard = close_failure_discard;
}

static int
test_source_ownership(mpq_archive_s *archive)
{
    mpq_source_s borrowed = { 0 };
    close_failure_s failure = { 0 };
    FILE *file;
    uint64_t device;
    uint64_t inode;
    mpq_io_identity_fn identity;

    TEST_CHECK(libmpq__source_file_identity(archive->source, &device, &inode) == 0);
    identity = archive->source->backend.identity;
    archive->source->backend.identity = NULL;
    TEST_CHECK(
        libmpq__source_file_identity(archive->source, &device, &inode) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(device == 0 && inode == 0);
    archive->source->backend.identity = identity;

    close_failure_install(archive->source, &failure);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_CLOSE);
    TEST_CHECK(failure.closes == 1);

    file = tmpfile();
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite("x", 1, 1, file) == 1 && fflush(file) == 0);
    TEST_CHECK(libmpq__source_borrow_file(&borrowed, file, 1) == 0);
    TEST_CHECK(libmpq__source_close(&borrowed) == 0);
    TEST_CHECK(fwrite("y", 1, 1, file) == 1);
    TEST_CHECK(fclose(file) == 0);
    return 0;
}

/* Invalid helper arguments must have identical contracts on both platforms. */
static int
invalid_arguments(void)
{
    mpq_directory_s *directory = NULL;
    char *name = NULL;
    FILE *file = NULL;
    uint64_t device = 1;
    uint64_t inode = 1;
    const char *valid = ".libmpq-raw-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

    TEST_CHECK(libmpq__directory_open(".", NULL, &name) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_open(".", &directory, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_open(NULL, &directory, &name) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(directory == NULL && name == NULL);
    TEST_CHECK(libmpq__directory_temporary(NULL, valid, 1, &name, &file) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_remove(NULL, "name") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_replace(NULL, "name", "other") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_open(NULL, "rb") == NULL);
    TEST_CHECK(libmpq__file_open("name", NULL) == NULL);
    TEST_CHECK(libmpq__file_seek(NULL, 0, SEEK_SET) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_tell(NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__file_identity(NULL, &device, &inode) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(device == 0 && inode == 0);
    TEST_CHECK(libmpq__directory_open("unused.mpq", &directory, &name) == 0);
    free(name);
    name = NULL;
    TEST_CHECK(libmpq__directory_temporary(directory, valid, 1, NULL, &file) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_temporary(directory, valid, 1, &name, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_temporary(directory, NULL, 1, &name, &file) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__directory_temporary(directory, "short", 1, &name, &file) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(
        libmpq__directory_temporary(
            directory, ".libmpq-raw-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXY", 1, &name, &file
        ) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(name == NULL && file == NULL);
    TEST_CHECK(libmpq__directory_remove(directory, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_replace(directory, NULL, "other") == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__directory_replace(directory, "name", NULL) == LIBMPQ_ERROR_EXIST);
    libmpq__directory_close(directory);
    return 0;
}

/* Exercise offsets beyond 2 GiB, UTF-8 names, replacement, and handle identity. */
int
main(void)
{
    mpq_directory_s *directory = NULL;
    char *destination = NULL;
    char *temporary = NULL;
    FILE *file = NULL;
    FILE *original = NULL;
    uint64_t device;
    uint64_t inode;
    uint64_t replacement_device;
    uint64_t replacement_inode;
    const uint64_t offset = UINT64_C(3) * 1024 * 1024 * 1024;
    const char *path = "native-\xc3\xa4-\xe6\xb5\x8b.mpq";
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_archive_create_options_s options = { 0, 4, 4096, 0, 0 };

    TEST_CHECK(invalid_arguments() == 0);
    TEST_CHECK(libmpq__directory_open(path, &directory, &destination) == 0);
    TEST_CHECK(
        libmpq__directory_temporary(
            directory, ".libmpq-raw-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &temporary, &file
        ) == 0
    );
#ifndef _WIN32
    {
        struct stat status;

        TEST_CHECK(fstat(fileno(file), &status) == 0);
        TEST_CHECK((status.st_mode & 0777) == 0600);
        TEST_CHECK((fcntl(fileno(file), F_GETFD) & FD_CLOEXEC) != 0);
    }
#endif
    TEST_CHECK(libmpq__file_seek(file, offset, SEEK_SET) == 0);
    TEST_CHECK(fwrite("x", 1, 1, file) == 1);
    TEST_CHECK(libmpq__file_tell(file) == (libmpq__off_t)offset + 1);
    TEST_CHECK(libmpq__file_seek(file, UINT64_MAX, SEEK_SET) == LIBMPQ_ERROR_SEEK);
    TEST_CHECK(libmpq__file_seek(file, offset, SEEK_SET) == 0);
    TEST_CHECK(fgetc(file) == 'x');
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(libmpq__directory_remove(directory, temporary) == 0);
    free(temporary);
    temporary = NULL;

    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "test.txt", (const uint8_t *)"test", 4, NULL) == 0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    clone = NULL;
    TEST_CHECK(test_source_ownership(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    original = libmpq__file_open(path, "rb");
    TEST_CHECK(original != NULL);
    TEST_CHECK(libmpq__file_identity(original, &device, &inode) == 0);
    TEST_CHECK(
        libmpq__directory_temporary(
            directory, ".libmpq-mpqe-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 0, &temporary, &file
        ) == 0
    );
    TEST_CHECK(libmpq__file_identity(file, &replacement_device, &replacement_inode) == 0);
    TEST_CHECK(device != replacement_device || inode != replacement_inode);
    TEST_CHECK(fclose(file) == 0);

    /* Simulate external path replacement without requiring overwrite of an open target. */
    TEST_CHECK(libmpq__directory_replace(directory, destination, "displaced.mpq") == 0);
    TEST_CHECK(libmpq__directory_replace(directory, temporary, destination) == 0);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(clone == NULL);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(fclose(original) == 0);
    TEST_CHECK(libmpq__directory_remove(directory, "displaced.mpq") == 0);
    TEST_CHECK(libmpq__directory_remove(directory, destination) == 0);
    archive = NULL;
    {
        static const uint8_t auth_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
        uint8_t output[4];
        libmpq__off_t transferred = 0;
#ifdef _WIN32
        const char *encrypted_path = ".\\native-\xc3\xa4-\xe6\xb5\x8b.mpq";
#else
        const char *encrypted_path = path;
#endif

        TEST_CHECK(
            libmpq__archive_create_mpqe(
                &archive, encrypted_path, auth_code, sizeof(auth_code) - 1, &options
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_add_data(archive, "test.txt", (const uint8_t *)"test", 4, NULL) == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        TEST_CHECK(
            libmpq__archive_open_mpqe(&archive, path, -1, auth_code, sizeof(auth_code) - 1) == 0
        );
        TEST_CHECK(libmpq__file_read(archive, 0, output, sizeof(output), &transferred) == 0);
        TEST_CHECK(transferred == 4 && memcmp(output, "test", 4) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(libmpq__directory_remove(directory, destination) == 0);
    }
    free(temporary);
    free(destination);
    libmpq__directory_close(directory);
    return 0;
}
