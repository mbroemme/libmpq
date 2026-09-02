/*
 *  fuzz-encrypted-archive.c -- Fuzz target for encrypted MPQ archive state.
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
#include <sys/stat.h>
#include <unistd.h>

#define LIBMPQ_FUZZ_ENCRYPTED_MAX_SIZE (1024U * 1024U)

static uint8_t *seed_data;
static size_t seed_size;
static int archive_fd = -1;
static char archive_path[] = "/tmp/libmpq-fuzz-encrypted.XXXXXX";
static char seed_path[] = "/tmp/libmpq-fuzz-encrypted-seed.XXXXXX";

/* Create a valid archive containing encrypted raw and compressed file paths. */
static int
create_seed_archive(void)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s archive_options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096,
                                                     LIBMPQ_ARCHIVE_CREATE_LISTFILE };
    mpq_file_options_s raw = { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_COMPRESS,
                                      LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint8_t payload[12000];

    memset(payload, 'E', sizeof(payload));
    memcpy(payload, "RIFF", 4);
    if (libmpq__archive_create(&archive, seed_path, &archive_options) != 0 ||
        libmpq__file_add(archive, "encrypted.raw", payload, sizeof(payload), &raw) != 0 ||
        libmpq__file_add(
            archive, "encrypted-compressed.bin", payload, sizeof(payload), &compressed
        ) != 0 ||
        libmpq__archive_close(archive) != 0) {
        return -1;
    }

    return 0;
}

/* Load the valid encrypted archive once, leaving each input free to mutate its bytes. */
static int
load_seed_archive(void)
{
    struct stat st;
    int fd;
    size_t read_total = 0;

    fd = open(seed_path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > LIBMPQ_FUZZ_ENCRYPTED_MAX_SIZE) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    seed_size = (size_t)st.st_size;
    seed_data = malloc(seed_size);
    if (seed_data == NULL) {
        close(fd);
        return -1;
    }
    while (read_total < seed_size) {
        ssize_t result = read(fd, seed_data + read_total, seed_size - read_total);

        if (result <= 0) {
            free(seed_data);
            seed_data = NULL;
            close(fd);
            return -1;
        }
        read_total += (size_t)result;
    }

    close(fd);
    return 0;
}

/* Dispose of generated archives and their in-memory seed after fuzzing stops. */
static void
archive_cleanup(void)
{
    if (archive_fd >= 0) {
        close(archive_fd);
    }
    free(seed_data);
    unlink(archive_path);
    unlink(seed_path);
}

/* Generate the encrypted seed that drives header, table, and known-key parsing. */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int seed_fd;

    (void)argc;
    (void)argv;

    archive_fd = mkstemp(archive_path);
    seed_fd = mkstemp(seed_path);
    if (archive_fd < 0 || seed_fd < 0 || close(seed_fd) != 0 || create_seed_archive() != 0 ||
        load_seed_archive() != 0 || atexit(archive_cleanup) != 0) {
        perror("create encrypted seed archive");
        archive_cleanup();
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* Mutate selected encrypted archive bytes, then exercise known-name and index reads. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *const names[] = { "encrypted.raw", "encrypted-compressed.bin",
                                         "(listfile)" };
    mpq_archive_s *archive = NULL;
    uint8_t *candidate;
    uint32_t number;
    libmpq__off_t unpacked_size;
    uint8_t *output;
    libmpq__off_t transferred;
    size_t offset;
    size_t i;

    if (seed_data == NULL || seed_size == 0 || size > LIBMPQ_FUZZ_ENCRYPTED_MAX_SIZE) {
        return 0;
    }

    candidate = malloc(seed_size);
    if (candidate == NULL) {
        return 0;
    }
    memcpy(candidate, seed_data, seed_size);
    for (i = 1; i + 4 < size && i < 161; i += 5) {
        offset = (size_t)(libmpq_fuzz_le32(data + i) % seed_size);
        candidate[offset] ^= data[i + 4];
    }

    if (libmpq_fuzz_write_fd(archive_fd, candidate, seed_size) == 0 &&
        libmpq__archive_open(&archive, archive_path, 0) == 0) {
        for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            if (libmpq__file_number(archive, names[i], &number) == 0 &&
                libmpq__file_size_unpacked(archive, number, &unpacked_size) == 0 &&
                unpacked_size >= 0 && (uint64_t)unpacked_size <= LIBMPQ_FUZZ_ENCRYPTED_MAX_SIZE) {
                output = malloc((size_t)unpacked_size == 0 ? 1U : (size_t)unpacked_size);
                if (output != NULL) {
                    (void)libmpq__file_read(archive, number, output, unpacked_size, &transferred);
                    free(output);
                }
            }
        }
        if (size >= 4) {
            number = libmpq_fuzz_le32(data);
            (void)libmpq__block_open_offset(archive, number);
            (void)libmpq__block_close_offset(archive, number);
        }
        libmpq__archive_close(archive);
    }

    free(candidate);
    return 0;
}
