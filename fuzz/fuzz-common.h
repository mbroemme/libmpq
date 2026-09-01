/*
 *  fuzz-common.h -- Small shared helpers for libmpq fuzz harnesses.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#ifndef LIBMPQ_FUZZ_COMMON_H
#define LIBMPQ_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/* Replace the complete contents of an already-open temporary file. */
static int
libmpq_fuzz_write_fd(int fd, const uint8_t *data, size_t size)
{
    size_t written = 0;

    if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
    }

    while (written < size) {
        ssize_t result = write(fd, data + written, size - written);

        if (result <= 0) {
            return -1;
        }
        written += (size_t)result;
    }

    return 0;
}

/* Decode a little-endian 32-bit value from a fuzzer-controlled frame. */
static uint32_t
libmpq_fuzz_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

#endif /* LIBMPQ_FUZZ_COMMON_H */
