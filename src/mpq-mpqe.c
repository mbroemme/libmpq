/*
 *  mpq-mpqe.c -- private MPQE cryptographic helper implementations.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-mpqe.h"

#include <string.h>

/* Clear key material without allowing the compiler to elide the writes. */
void
libmpq__mpqe_clear(void *buffer, size_t size)
{
    volatile uint8_t *bytes = buffer;

    while (size-- != 0)
        *bytes++ = 0;
}

/* Rotate a 32-bit word left; MPQE uses this as part of its per-chunk shuffle. */
static uint32_t
rol32(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32U - count));
}

/* Derive the MPQE working key from the installer authentication-code bytes. */
int32_t
libmpq__mpqe_key(
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t *auth_code, size_t auth_code_size
)
{
    static const char template_key[] =
        "expand 32-byte k000000000000000000000000000000000000000000000000";
    static const uint8_t source_words[8] = { 3, 7, 2, 6, 1, 5, 0, 4 };
    static const uint8_t target_words[8] = { 0, 2, 3, 5, 6, 8, 9, 11 };
    uint8_t derived_key[LIBMPQ_MPQE_CHUNK_SIZE];
    size_t i;

    if (key == NULL || auth_code == NULL || auth_code_size < LIBMPQ_MPQE_AUTH_CODE_MINIMUM)
        return LIBMPQ_ERROR_DECRYPT;
    memcpy(derived_key, template_key, sizeof(derived_key));
    for (i = 0; i < sizeof(source_words); ++i) {
        uint32_t value = libmpq__load_le32(auth_code + source_words[i] * sizeof(uint32_t));

        libmpq__store_le32(derived_key + (4U + target_words[i]) * sizeof(uint32_t), value);
    }
    memcpy(key, derived_key, sizeof(derived_key));
    libmpq__mpqe_clear(derived_key, sizeof(derived_key));
    return LIBMPQ_SUCCESS;
}

/* Decrypt one zero-padded MPQE chunk in place using its absolute stream position. */
void
libmpq__mpqe_transform_chunk(
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE],
    uint64_t offset
)
{
    uint32_t shuffled[16];
    uint32_t key_mirror[16];
    uint32_t mirror[16];
    uint64_t chunk_number = offset / LIBMPQ_MPQE_CHUNK_SIZE;
    unsigned round;
    unsigned i;

    for (i = 0; i < 16; ++i)
        key_mirror[i] = libmpq__load_le32(key + i * sizeof(uint32_t));
    key_mirror[5] = (uint32_t)(chunk_number >> 32);
    key_mirror[8] = (uint32_t)chunk_number;
    shuffled[14] = key_mirror[0];
    shuffled[12] = key_mirror[1];
    shuffled[5] = key_mirror[2];
    shuffled[15] = key_mirror[3];
    shuffled[10] = key_mirror[4];
    shuffled[7] = key_mirror[5];
    shuffled[11] = key_mirror[6];
    shuffled[9] = key_mirror[7];
    shuffled[3] = key_mirror[8];
    shuffled[6] = key_mirror[9];
    shuffled[8] = key_mirror[10];
    shuffled[13] = key_mirror[11];
    shuffled[2] = key_mirror[12];
    shuffled[4] = key_mirror[13];
    shuffled[1] = key_mirror[14];
    shuffled[0] = key_mirror[15];
    for (round = 0; round < 20; round += 2) {
        shuffled[10] ^= rol32(shuffled[14] + shuffled[2], 7);
        shuffled[3] ^= rol32(shuffled[10] + shuffled[14], 9);
        shuffled[2] ^= rol32(shuffled[3] + shuffled[10], 13);
        shuffled[14] ^= rol32(shuffled[2] + shuffled[3], 18);
        shuffled[7] ^= rol32(shuffled[12] + shuffled[4], 7);
        shuffled[6] ^= rol32(shuffled[7] + shuffled[12], 9);
        shuffled[4] ^= rol32(shuffled[6] + shuffled[7], 13);
        shuffled[12] ^= rol32(shuffled[4] + shuffled[6], 18);
        shuffled[11] ^= rol32(shuffled[5] + shuffled[1], 7);
        shuffled[8] ^= rol32(shuffled[11] + shuffled[5], 9);
        shuffled[1] ^= rol32(shuffled[8] + shuffled[11], 13);
        shuffled[5] ^= rol32(shuffled[1] + shuffled[8], 18);
        shuffled[9] ^= rol32(shuffled[15] + shuffled[0], 7);
        shuffled[13] ^= rol32(shuffled[9] + shuffled[15], 9);
        shuffled[0] ^= rol32(shuffled[13] + shuffled[9], 13);
        shuffled[15] ^= rol32(shuffled[0] + shuffled[13], 18);
        shuffled[4] ^= rol32(shuffled[14] + shuffled[9], 7);
        shuffled[8] ^= rol32(shuffled[4] + shuffled[14], 9);
        shuffled[9] ^= rol32(shuffled[8] + shuffled[4], 13);
        shuffled[14] ^= rol32(shuffled[9] + shuffled[8], 18);
        shuffled[1] ^= rol32(shuffled[12] + shuffled[10], 7);
        shuffled[13] ^= rol32(shuffled[1] + shuffled[12], 9);
        shuffled[10] ^= rol32(shuffled[13] + shuffled[1], 13);
        shuffled[12] ^= rol32(shuffled[10] + shuffled[13], 18);
        shuffled[0] ^= rol32(shuffled[5] + shuffled[7], 7);
        shuffled[3] ^= rol32(shuffled[0] + shuffled[5], 9);
        shuffled[7] ^= rol32(shuffled[3] + shuffled[0], 13);
        shuffled[5] ^= rol32(shuffled[7] + shuffled[3], 18);
        shuffled[2] ^= rol32(shuffled[15] + shuffled[11], 7);
        shuffled[6] ^= rol32(shuffled[2] + shuffled[15], 9);
        shuffled[11] ^= rol32(shuffled[6] + shuffled[2], 13);
        shuffled[15] ^= rol32(shuffled[11] + shuffled[6], 18);
    }
    for (i = 0; i < 16; ++i)
        mirror[i] = libmpq__load_le32(chunk + i * sizeof(uint32_t));
    mirror[0] ^= shuffled[14] + key_mirror[0];
    mirror[1] ^= shuffled[4] + key_mirror[13];
    mirror[2] ^= shuffled[8] + key_mirror[10];
    mirror[3] ^= shuffled[9] + key_mirror[7];
    mirror[4] ^= shuffled[10] + key_mirror[4];
    mirror[5] ^= shuffled[12] + key_mirror[1];
    mirror[6] ^= shuffled[1] + key_mirror[14];
    mirror[7] ^= shuffled[13] + key_mirror[11];
    mirror[8] ^= shuffled[3] + key_mirror[8];
    mirror[9] ^= shuffled[7] + key_mirror[5];
    mirror[10] ^= shuffled[5] + key_mirror[2];
    mirror[11] ^= shuffled[0] + key_mirror[15];
    mirror[12] ^= shuffled[2] + key_mirror[12];
    mirror[13] ^= shuffled[6] + key_mirror[9];
    mirror[14] ^= shuffled[11] + key_mirror[6];
    mirror[15] ^= shuffled[15] + key_mirror[3];
    for (i = 0; i < 16; ++i)
        libmpq__store_le32(chunk + i * sizeof(uint32_t), mirror[i]);
    libmpq__mpqe_clear(shuffled, sizeof(shuffled));
    libmpq__mpqe_clear(key_mirror, sizeof(key_mirror));
    libmpq__mpqe_clear(mirror, sizeof(mirror));
}
