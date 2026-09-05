/*
 *  mpq-stream.c -- private random-access archive stream implementations.
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
#include "mpq-platform.h"
#include "mpq-stream.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define LIBMPQ_MPQE_READ_BUFFER_SIZE (LIBMPQ_MPQE_CHUNK_SIZE * 64U)

typedef enum
{
    LIBMPQ_STREAM_FILE,
    LIBMPQ_STREAM_MPQE
} libmpq_stream_provider_e;

struct mpq_stream
{
    FILE *file;
    uint64_t size;
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    libmpq_stream_provider_e provider;
};

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
libmpq__stream_rol32(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32U - count));
}

/* Reverse a 32-bit word while retaining byte-oriented stream storage. */
static uint32_t
libmpq__stream_bswap32(uint32_t value)
{
    return ((value & 0x000000ffU) << 24) | ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) | ((value & 0xff000000U) >> 24);
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
    uint8_t native_key[LIBMPQ_MPQE_CHUNK_SIZE];
    size_t i;

    if (key == NULL || auth_code == NULL || auth_code_size < LIBMPQ_MPQE_AUTH_CODE_MINIMUM)
        return LIBMPQ_ERROR_DECRYPT;
    memcpy(native_key, template_key, sizeof(native_key));
    for (i = 0; i < sizeof(source_words); ++i) {
        uint32_t value = libmpq__load_le32(auth_code + source_words[i] * sizeof(uint32_t));

        libmpq__store_le32(native_key + (4U + target_words[i]) * sizeof(uint32_t), value);
    }
    for (i = 0; i < LIBMPQ_MPQE_CHUNK_SIZE / sizeof(uint32_t); ++i) {
        uint32_t value = libmpq__load_le32(native_key + i * sizeof(uint32_t));

        key[i * sizeof(uint32_t) + 0] = (uint8_t)(value >> 24);
        key[i * sizeof(uint32_t) + 1] = (uint8_t)(value >> 16);
        key[i * sizeof(uint32_t) + 2] = (uint8_t)(value >> 8);
        key[i * sizeof(uint32_t) + 3] = (uint8_t)value;
    }
    libmpq__mpqe_clear(native_key, sizeof(native_key));
    return LIBMPQ_SUCCESS;
}

/* Decrypt one zero-padded MPQE chunk in place using its absolute stream position. */
void
libmpq__mpqe_transform_chunk(
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t key[64], uint64_t offset
)
{
    uint32_t shuffled[16];
    uint32_t key_mirror[16];
    uint32_t mirror[16];
    uint64_t chunk_number = offset / LIBMPQ_MPQE_CHUNK_SIZE;
    unsigned round;
    unsigned i;

    for (i = 0; i < 16; ++i)
        key_mirror[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
                        ((uint32_t)key[i * 4 + 2] << 8) | key[i * 4 + 3];
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
        shuffled[10] ^= libmpq__stream_rol32(shuffled[14] + shuffled[2], 7);
        shuffled[3] ^= libmpq__stream_rol32(shuffled[10] + shuffled[14], 9);
        shuffled[2] ^= libmpq__stream_rol32(shuffled[3] + shuffled[10], 13);
        shuffled[14] ^= libmpq__stream_rol32(shuffled[2] + shuffled[3], 18);
        shuffled[7] ^= libmpq__stream_rol32(shuffled[12] + shuffled[4], 7);
        shuffled[6] ^= libmpq__stream_rol32(shuffled[7] + shuffled[12], 9);
        shuffled[4] ^= libmpq__stream_rol32(shuffled[6] + shuffled[7], 13);
        shuffled[12] ^= libmpq__stream_rol32(shuffled[4] + shuffled[6], 18);
        shuffled[11] ^= libmpq__stream_rol32(shuffled[5] + shuffled[1], 7);
        shuffled[8] ^= libmpq__stream_rol32(shuffled[11] + shuffled[5], 9);
        shuffled[1] ^= libmpq__stream_rol32(shuffled[8] + shuffled[11], 13);
        shuffled[5] ^= libmpq__stream_rol32(shuffled[1] + shuffled[8], 18);
        shuffled[9] ^= libmpq__stream_rol32(shuffled[15] + shuffled[0], 7);
        shuffled[13] ^= libmpq__stream_rol32(shuffled[9] + shuffled[15], 9);
        shuffled[0] ^= libmpq__stream_rol32(shuffled[13] + shuffled[9], 13);
        shuffled[15] ^= libmpq__stream_rol32(shuffled[0] + shuffled[13], 18);
        shuffled[4] ^= libmpq__stream_rol32(shuffled[14] + shuffled[9], 7);
        shuffled[8] ^= libmpq__stream_rol32(shuffled[4] + shuffled[14], 9);
        shuffled[9] ^= libmpq__stream_rol32(shuffled[8] + shuffled[4], 13);
        shuffled[14] ^= libmpq__stream_rol32(shuffled[9] + shuffled[8], 18);
        shuffled[1] ^= libmpq__stream_rol32(shuffled[12] + shuffled[10], 7);
        shuffled[13] ^= libmpq__stream_rol32(shuffled[1] + shuffled[12], 9);
        shuffled[10] ^= libmpq__stream_rol32(shuffled[13] + shuffled[1], 13);
        shuffled[12] ^= libmpq__stream_rol32(shuffled[10] + shuffled[13], 18);
        shuffled[0] ^= libmpq__stream_rol32(shuffled[5] + shuffled[7], 7);
        shuffled[3] ^= libmpq__stream_rol32(shuffled[0] + shuffled[5], 9);
        shuffled[7] ^= libmpq__stream_rol32(shuffled[3] + shuffled[0], 13);
        shuffled[5] ^= libmpq__stream_rol32(shuffled[7] + shuffled[3], 18);
        shuffled[2] ^= libmpq__stream_rol32(shuffled[15] + shuffled[11], 7);
        shuffled[6] ^= libmpq__stream_rol32(shuffled[2] + shuffled[15], 9);
        shuffled[11] ^= libmpq__stream_rol32(shuffled[6] + shuffled[2], 13);
        shuffled[15] ^= libmpq__stream_rol32(shuffled[11] + shuffled[6], 18);
    }
    for (i = 0; i < 16; ++i)
        mirror[i] = ((uint32_t)chunk[i * 4] << 24) | ((uint32_t)chunk[i * 4 + 1] << 16) |
                    ((uint32_t)chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
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
        libmpq__store_le32(chunk + i * sizeof(uint32_t), libmpq__stream_bswap32(mirror[i]));
    libmpq__mpqe_clear(shuffled, sizeof(shuffled));
    libmpq__mpqe_clear(key_mirror, sizeof(key_mirror));
    libmpq__mpqe_clear(mirror, sizeof(mirror));
}

#ifdef LIBMPQ_TESTING

/* Build deterministic test ciphertext with the same symmetric MPQE transform. */
void
libmpq__stream_mpqe_test_transform_chunk(
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE], const uint8_t *auth_code, uint64_t offset
)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];

    if (libmpq__mpqe_key(key, auth_code, LIBMPQ_MPQE_AUTH_CODE_MINIMUM) == LIBMPQ_SUCCESS)
        libmpq__mpqe_transform_chunk(chunk, key, offset);
    libmpq__mpqe_clear(key, sizeof(key));
}
#endif

/* Seek through the project offset type without narrowing large file positions. */
static int32_t
libmpq__stream_file_seek(mpq_stream_s *stream, uint64_t offset)
{
    libmpq__off_t position;

    if (offset > (uint64_t)INT64_MAX)
        return LIBMPQ_ERROR_SEEK;
    position = (libmpq__off_t)offset;
#if !defined(_MSC_VER)
    if ((uint64_t)(off_t)position != offset)
        return LIBMPQ_ERROR_SEEK;
#endif
    return fseeko(stream->file, position, SEEK_SET) < 0 ? LIBMPQ_ERROR_SEEK : LIBMPQ_SUCCESS;
}

/* Read an exact physical byte range from the underlying ordinary file. */
static int32_t
libmpq__stream_file_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (offset > stream->size || size > stream->size - offset)
        return LIBMPQ_ERROR_READ;
    if (size == 0)
        return LIBMPQ_SUCCESS;
    if (libmpq__stream_file_seek(stream, offset) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_SEEK;
    if (fread(buffer, 1, size, stream->file) != size)
        return LIBMPQ_ERROR_READ;
    return LIBMPQ_SUCCESS;
}

/* Open a backing file and capture its immutable size for range validation. */
static int32_t
libmpq__stream_open_common(mpq_stream_s **stream, const char *path)
{
    libmpq__off_t end;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (path == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = calloc(1, sizeof(**stream));
    if (*stream == NULL)
        return LIBMPQ_ERROR_MALLOC;
    (*stream)->file = fopen(path, "rb");
    if ((*stream)->file == NULL) {
        free(*stream);
        *stream = NULL;
        return errno == ENOENT ? LIBMPQ_ERROR_EXIST : LIBMPQ_ERROR_OPEN;
    }
    if (fseeko((*stream)->file, (libmpq__off_t)0, SEEK_END) < 0 ||
        (end = (libmpq__off_t)ftello((*stream)->file)) < 0) {
        fclose((*stream)->file);
        free(*stream);
        *stream = NULL;
        return LIBMPQ_ERROR_SEEK;
    }
    (*stream)->size = (uint64_t)end;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__stream_open_file(mpq_stream_s **stream, const char *path)
{
    int32_t result = libmpq__stream_open_common(stream, path);

    if (result == LIBMPQ_SUCCESS)
        (*stream)->provider = LIBMPQ_STREAM_FILE;
    return result;
}

int32_t
libmpq__stream_open_mpqe(
    mpq_stream_s **stream, const char *path, const uint8_t *auth_code, size_t auth_code_size
)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    result = libmpq__mpqe_key(key, auth_code, auth_code_size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = libmpq__stream_open_common(stream, path);
    if (result != LIBMPQ_SUCCESS) {
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    (*stream)->provider = LIBMPQ_STREAM_MPQE;
    memcpy((*stream)->key, key, sizeof(key));
    libmpq__mpqe_clear(key, sizeof(key));
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__stream_clone(mpq_stream_s **stream, const mpq_stream_s *source, const char *path)
{
    int32_t result;

    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    *stream = NULL;
    if (source == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__stream_open_common(stream, path);

    if (result != LIBMPQ_SUCCESS)
        return result;
    (*stream)->provider = source->provider;
    if (source->provider == LIBMPQ_STREAM_MPQE)
        memcpy((*stream)->key, source->key, sizeof((*stream)->key));
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__stream_read_at(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    size_t copied = 0;

    if (stream == NULL || (buffer == NULL && size != 0))
        return LIBMPQ_ERROR_EXIST;
    if (offset > stream->size || size > stream->size - offset)
        return LIBMPQ_ERROR_READ;
    if (stream->provider == LIBMPQ_STREAM_FILE)
        return libmpq__stream_file_read_at(stream, offset, buffer, size);
    while (copied < size) {
        uint64_t request_offset = offset + copied;
        uint64_t chunk_offset = request_offset & ~(uint64_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);
        uint8_t chunks[LIBMPQ_MPQE_READ_BUFFER_SIZE] = { 0 };
        uint64_t remaining = stream->size - chunk_offset;
        uint64_t request_end = offset + size;
        uint64_t required = request_end - chunk_offset;
        uint64_t rounded_required;
        uint64_t physical_u64;
        size_t physical;
        size_t decrypt_size;
        size_t batch_start = (size_t)(request_offset - chunk_offset);
        size_t available;
        size_t chunk;
        int32_t result;

        if (required > UINT64_MAX - (LIBMPQ_MPQE_CHUNK_SIZE - 1U)) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_SIZE;
        }
        rounded_required =
            (required + (LIBMPQ_MPQE_CHUNK_SIZE - 1U)) & ~(uint64_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);
        if (rounded_required > sizeof(chunks))
            rounded_required = sizeof(chunks);
        physical_u64 = remaining < rounded_required ? remaining : rounded_required;
        if (physical_u64 > sizeof(chunks)) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_SIZE;
        }
        physical = (size_t)physical_u64;
        decrypt_size =
            (physical + (LIBMPQ_MPQE_CHUNK_SIZE - 1U)) & ~(size_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);

        if (chunk_offset >= stream->size || physical <= batch_start) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return LIBMPQ_ERROR_READ;
        }
        result = libmpq__stream_file_read_at(stream, chunk_offset, chunks, physical);
        if (result != LIBMPQ_SUCCESS) {
            libmpq__mpqe_clear(chunks, sizeof(chunks));
            return result;
        }
        for (chunk = 0; chunk < decrypt_size; chunk += LIBMPQ_MPQE_CHUNK_SIZE) {
            libmpq__mpqe_transform_chunk(
                chunks + chunk, stream->key, chunk_offset + (uint64_t)chunk
            );
        }
        available = physical - batch_start;
        if (available > size - copied)
            available = size - copied;
        memcpy(buffer + copied, chunks + batch_start, available);
        copied += available;
        libmpq__mpqe_clear(chunks, sizeof(chunks));
    }
    return LIBMPQ_SUCCESS;
}

uint64_t
libmpq__stream_size(const mpq_stream_s *stream)
{
    return stream == NULL ? 0 : stream->size;
}

int32_t
libmpq__stream_close(mpq_stream_s *stream)
{
    if (stream == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (stream->file != NULL && fclose(stream->file) != 0)
        return LIBMPQ_ERROR_CLOSE;
    libmpq__mpqe_clear(stream->key, sizeof(stream->key));
    free(stream);
    return LIBMPQ_SUCCESS;
}

void
libmpq__stream_discard(mpq_stream_s *stream)
{
    if (stream == NULL)
        return;
    if (stream->file != NULL)
        (void)fclose(stream->file);
    libmpq__mpqe_clear(stream->key, sizeof(stream->key));
    free(stream);
}
