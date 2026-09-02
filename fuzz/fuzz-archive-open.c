/*
 *  fuzz-archive-open.c -- Fuzz target for MPQ archive opening.
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LIBMPQ_FUZZ_MAX_INPUT (1024U * 1024U)

static int archive_fd = -1;
static char archive_path[] = "/tmp/libmpq-fuzz-archive.XXXXXX";

/* Remove the per-process temporary archive after the fuzzer exits. */
static void
archive_cleanup(void)
{
    if (archive_fd >= 0) {
        close(archive_fd);
    }
    unlink(archive_path);
}

/* Write one fuzzer input to the reusable temporary archive file. */
static int
archive_write_input(const uint8_t *data, size_t size)
{
    size_t written = 0;

    if (ftruncate(archive_fd, 0) != 0 || lseek(archive_fd, 0, SEEK_SET) < 0) {
        return -1;
    }

    while (written < size) {
        ssize_t result = write(archive_fd, data + written, size - written);

        if (result <= 0) {
            return -1;
        }
        written += (size_t)result;
    }

    return 0;
}

/* Set up one isolated on-disk archive because libmpq opens paths, not streams. */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    archive_fd = mkstemp(archive_path);
    if (archive_fd < 0) {
        perror("mkstemp");
        exit(EXIT_FAILURE);
    }
    if (atexit(archive_cleanup) != 0) {
        perror("atexit");
        archive_cleanup();
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* Exercise direct and embedded-header archive parsing for one byte sequence. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mpq_archive_s *archive = NULL;

    if (size > LIBMPQ_FUZZ_MAX_INPUT || archive_write_input(data, size) != 0) {
        return 0;
    }

    if (libmpq__archive_open(&archive, archive_path, 0) == 0) {
        libmpq__archive_close(archive);
    }

    archive = NULL;
    if (libmpq__archive_open(&archive, archive_path, -1) == 0) {
        libmpq__archive_close(archive);
    }

    return 0;
}
