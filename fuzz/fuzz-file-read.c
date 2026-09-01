/*
 *  fuzz-file-read.c -- Fuzz target for filename lookup and file extraction.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#define _POSIX_C_SOURCE 200809L

#include <libmpq/mpq.h>

#include "fuzz-common.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LIBMPQ_FUZZ_FILE_MAX_NAME 255U
#define LIBMPQ_FUZZ_FILE_MAX_OUTPUT 65536U

static int archive_fd = -1;
static char archive_path[] = "/tmp/libmpq-fuzz-file-read.XXXXXX";

/* Build a small valid archive so every input reaches lookup and reader paths. */
static int
create_seed_archive(void)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s archive_options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096,
                                                      LIBMPQ_ARCHIVE_CREATE_LISTFILE };
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint8_t payload[8192];

    memset(payload, 'R', sizeof(payload));
    memcpy(payload, "libmpq file-read fuzz seed\n", 27);
    if (libmpq__archive_create(&archive, archive_path, &archive_options) != 0 ||
        libmpq__file_add(archive, "fuzz-read.bin", payload, sizeof(payload), &compressed) != 0 ||
        libmpq__file_add(archive, "dir/entry.txt", payload, 64, &raw) != 0 ||
        libmpq__archive_close(archive) != 0) {
        return -1;
    }

    return 0;
}

/* Remove the valid seed archive when the fuzzer process exits. */
static void
archive_cleanup(void)
{
    if (archive_fd >= 0) {
        close(archive_fd);
    }
    unlink(archive_path);
}

/* Set up the on-disk seed archive used by every lookup and extraction run. */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    archive_fd = mkstemp(archive_path);
    if (archive_fd < 0 || close(archive_fd) != 0) {
        perror("mkstemp");
        exit(EXIT_FAILURE);
    }
    archive_fd = -1;
    if (create_seed_archive() != 0 || atexit(archive_cleanup) != 0) {
        perror("create seed archive");
        archive_cleanup();
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* Build a NUL-terminated lookup name from fuzzer input without path allocation. */
static void
make_name(const uint8_t *data, size_t size, char name[LIBMPQ_FUZZ_FILE_MAX_NAME + 1U])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./\\_-()";
    size_t length = size < LIBMPQ_FUZZ_FILE_MAX_NAME ? size : LIBMPQ_FUZZ_FILE_MAX_NAME;
    size_t i;

    for (i = 0; i < length; ++i) {
        name[i] = alphabet[data[i] % (sizeof(alphabet) - 1U)];
    }
    name[length] = '\0';
}

/* Exercise valid and mutated names plus arbitrary file indexes against a valid archive. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *const known_names[] = { "fuzz-read.bin", "dir/entry.txt", "(listfile)" };
    mpq_archive_s *archive = NULL;
    const char *name;
    char mutated_name[LIBMPQ_FUZZ_FILE_MAX_NAME + 1U];
    libmpq__off_t unpacked_size;
    uint8_t *output;
    uint32_t number;
    libmpq__off_t transferred;

    if (libmpq__archive_open(&archive, archive_path, 0) != 0) {
        return 0;
    }

    if (size > 0 && (data[0] & 1U) == 0U) {
        name = known_names[data[0] % (sizeof(known_names) / sizeof(known_names[0]))];
    } else {
        make_name(size > 1 ? data + 1 : data, size > 1 ? size - 1 : size, mutated_name);
        name = mutated_name;
    }

    if (libmpq__file_number(archive, name, &number) == 0 &&
        libmpq__file_size_unpacked(archive, number, &unpacked_size) == 0 && unpacked_size >= 0 &&
        (uint64_t)unpacked_size <= LIBMPQ_FUZZ_FILE_MAX_OUTPUT) {
        output = malloc((size_t)unpacked_size == 0 ? 1U : (size_t)unpacked_size);
        if (output != NULL) {
            (void)libmpq__file_read(archive, number, output, unpacked_size, &transferred);
            free(output);
        }
    }

    if (size >= 5) {
        number = libmpq_fuzz_le32(data + 1);
        if (libmpq__file_size_unpacked(archive, number, &unpacked_size) == 0 && unpacked_size >= 0 &&
            (uint64_t)unpacked_size <= LIBMPQ_FUZZ_FILE_MAX_OUTPUT) {
            output = malloc((size_t)unpacked_size == 0 ? 1U : (size_t)unpacked_size);
            if (output != NULL) {
                (void)libmpq__file_read(archive, number, output, unpacked_size, &transferred);
                free(output);
            }
        }
    }

    libmpq__archive_close(archive);
    return 0;
}
