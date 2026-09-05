/*
 *  fuzz-mpqe-open.c -- Fuzz target for caller-authenticated MPQE opening.
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LIBMPQ_FUZZ_MAX_INPUT (1024U * 1024U)

static const uint8_t auth_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
static int archive_fd = -1;
static char archive_path[] = "/tmp/libmpq-fuzz-mpqe.XXXXXX";

/* Remove the per-process temporary MPQE stream after the fuzzer exits. */
static void
archive_cleanup(void)
{
    if (archive_fd >= 0)
        close(archive_fd);
    unlink(archive_path);
}

/* Set up an isolated file because the public MPQE API accepts a path. */
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

/* Exercise MPQE chunk decryption and the contained MPQ header parser. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const libmpq__off_t archive_offsets[] = { 0, -1 };
    size_t i;

    if (size > LIBMPQ_FUZZ_MAX_INPUT || libmpq_fuzz_write_fd(archive_fd, data, size) != 0)
        return 0;
    for (i = 0; i < sizeof(archive_offsets) / sizeof(archive_offsets[0]); ++i) {
        mpq_archive_s *archive = NULL;

        if (libmpq__archive_open_mpqe(
                &archive, archive_path, archive_offsets[i], auth_code, sizeof(auth_code) - 1
            ) == 0) {
            libmpq__archive_close(archive);
        }
    }
    return 0;
}
