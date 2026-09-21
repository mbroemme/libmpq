/*
 *  mpq-signature.c -- weak MPQ signature hashing and lifecycle.
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

#include "mpq-signature.h"
#include "mpq-crypto.h"
#include "mpq-file.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "mpq-rsa.h"
#include "mpq-sha1.h"
#include "mpq-stream.h"
#include "mpq-writer.h"
#include <string.h>

/* The signature range has already been bounded by locate before this call. */
static int
overlaps(uint64_t start, uint64_t size, uint64_t signature)
{
    return start < signature + LIBMPQ_SIGNATURE_SIZE &&
           (start > signature || size > signature - start);
}

/* Inspect the physical hash/block entry, including entries excluded from the
 * public reader map. An invalid internal file must not look like absence. */
static int32_t
locate(mpq_archive_s *a, uint64_t *offset, uint64_t *extent, uint8_t payload[LIBMPQ_SIGNATURE_SIZE])
{
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t i;
    uint32_t index = UINT32_MAX;
    uint64_t size;
    uint64_t pos;
    uint64_t table;
    uint64_t table_size;
    int32_t result;
    libmpq__file_hash(LIBMPQ_SIGNATURE_NAME, &h1, &h2, &h3);
    for (i = 0; i < a->mpq_header.hash_table_count; ++i) {
        const mpq_hash_s *entry = &a->mpq_hash[i];
        if (entry->block_table_index >= 0xfffffffeu || entry->hash_a != h2 || entry->hash_b != h3)
            continue;
        if (index != UINT32_MAX || entry->locale != 0 || entry->platform != 0 ||
            entry->block_table_index >= a->mpq_header.block_table_count)
            return LIBMPQ_ERROR_FORMAT;
        index = entry->block_table_index;
    }
    if (index == UINT32_MAX)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_signature_extent(a, &size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (a->mpq_block[index].unpacked_size != LIBMPQ_SIGNATURE_SIZE ||
        a->mpq_block[index].packed_size != LIBMPQ_SIGNATURE_SIZE ||
        (a->mpq_block[index].flags & ~LIBMPQ_FLAG_SINGLE) != LIBMPQ_FLAG_EXISTS)
        return LIBMPQ_ERROR_FORMAT;
    pos = a->mpq_block[index].offset | ((uint64_t)a->mpq_block_ex[index].offset_high << 32);
    if (a->archive_offset < 0 || size < a->mpq_header.header_size ||
        pos < a->mpq_header.header_size || pos > size || size - pos < LIBMPQ_SIGNATURE_SIZE ||
        (uint64_t)a->archive_offset > a->file_size ||
        size > a->file_size - (uint64_t)a->archive_offset)
        return LIBMPQ_ERROR_FORMAT;
    table =
        a->mpq_header.hash_table_offset | ((uint64_t)a->mpq_header_ex.hash_table_offset_high << 32);
    table_size = (uint64_t)a->mpq_header.hash_table_count * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    if (table > size || table_size > size - table || overlaps(table, table_size, pos))
        return LIBMPQ_ERROR_FORMAT;
    table = a->mpq_header.block_table_offset |
            ((uint64_t)a->mpq_header_ex.block_table_offset_high << 32);
    table_size = (uint64_t)a->mpq_header.block_table_count * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    if (table > size || table_size > size - table || overlaps(table, table_size, pos))
        return LIBMPQ_ERROR_FORMAT;
    table = a->mpq_header_ex.extended_offset;
    table_size = (uint64_t)a->mpq_header.block_table_count * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE;
    if (table != 0 &&
        (table > size || table_size > size - table || overlaps(table, table_size, pos)))
        return LIBMPQ_ERROR_FORMAT;
    for (i = 0; i < a->mpq_header.block_table_count; ++i) {
        uint64_t other = a->mpq_block[i].offset | ((uint64_t)a->mpq_block_ex[i].offset_high << 32);
        if ((a->mpq_block[i].flags & LIBMPQ_FLAG_EXISTS) && a->mpq_block[i].packed_size != 0) {
            if (other > size || a->mpq_block[i].packed_size > size - other ||
                (i != index && overlaps(other, a->mpq_block[i].packed_size, pos)))
                return LIBMPQ_ERROR_FORMAT;
        }
    }
    result = libmpq__stream_read_at(
        a->stream, (uint64_t)a->archive_offset + pos, payload, LIBMPQ_SIGNATURE_SIZE
    );
    if (result != LIBMPQ_SUCCESS)
        return result;
    for (i = 0; i < LIBMPQ_SIGNATURE_PREFIX_SIZE; ++i)
        if (payload[i] != 0)
            return LIBMPQ_ERROR_FORMAT;
    *offset = pos;
    *extent = size;
    return LIBMPQ_SUCCESS;
}

/* Hash only the logical archive, zeroing every intersection with the internal
 * signature payload. The same read-at implementation handles finalized writers. */
static int32_t
digest_archive(
    mpq_stream_s *stream, uint64_t start, uint64_t size, uint64_t excluded,
    uint8_t digest[LIBMPQ_MD5_SIZE]
)
{
    mpq_md5_s context;
    uint8_t buffer[16384];
    uint64_t pos = 0;
    if (start > UINT64_MAX - size || excluded > size || size - excluded < LIBMPQ_SIGNATURE_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    libmpq__md5_init(&context);
    while (pos < size) {
        size_t count = size - pos < sizeof(buffer) ? (size_t)(size - pos) : sizeof(buffer);
        uint64_t begin = pos > excluded ? pos : excluded;
        uint64_t end = pos + count < excluded + LIBMPQ_SIGNATURE_SIZE
                           ? pos + count
                           : excluded + LIBMPQ_SIGNATURE_SIZE;
        int32_t result = libmpq__stream_read_at(stream, start + pos, buffer, count);
        if (result != LIBMPQ_SUCCESS)
            return result;
        if (begin < end)
            memset(buffer + (size_t)(begin - pos), 0, (size_t)(end - begin));
        libmpq__md5_update(&context, buffer, count);
        pos += count;
    }
    libmpq__md5_final(&context, digest);
    return LIBMPQ_SUCCESS;
}

/* Locate a structurally complete external NGIS trailer. Trailing data is
 * accepted for compatibility with Blizzard-format archives. */
static int32_t
strong_locate(mpq_archive_s *a, uint64_t *extent, uint8_t signature[LIBMPQ_STRONG_SIGNATURE_SIZE])
{
    static const uint8_t marker[LIBMPQ_STRONG_SIGNATURE_MARKER_SIZE] = { 'N', 'G', 'I', 'S' };
    uint8_t trailer[LIBMPQ_STRONG_TRAILER_SIZE];
    uint64_t offset;
    int32_t result;

    /* MPQE encrypts its complete transport stream and has no defined external
     * strong-trailer representation. Do not interpret ciphertext as NGIS. */
    if (a->stream->provider == LIBMPQ_STREAM_MPQE)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__archive_signature_extent(a, extent);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (a->archive_offset < 0 || (uint64_t)a->archive_offset > UINT64_MAX - *extent)
        return LIBMPQ_ERROR_FORMAT;
    offset = (uint64_t)a->archive_offset + *extent;
    if (offset > a->file_size || LIBMPQ_STRONG_TRAILER_SIZE > a->file_size - offset)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__stream_read_at(a->stream, offset, trailer, sizeof(trailer));
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (memcmp(trailer, marker, sizeof(marker)) != 0)
        return LIBMPQ_ERROR_EXIST;
    memcpy(signature, trailer + sizeof(marker), LIBMPQ_STRONG_SIGNATURE_SIZE);
    return LIBMPQ_SUCCESS;
}

/* HM3W is a container-specific signed-range rule. */
static int32_t
signature_hash_range(mpq_archive_s *a, uint64_t extent, uint64_t *start, uint64_t *size)
{
    static const uint8_t hm3w[4] = { 'H', 'M', '3', 'W' };
    uint8_t prefix[sizeof(hm3w)];
    uint64_t end;
    int32_t result;
    if (a->archive_offset < 0 || (uint64_t)a->archive_offset > UINT64_MAX - extent)
        return LIBMPQ_ERROR_FORMAT;
    end = (uint64_t)a->archive_offset + extent;
    *start = (uint64_t)a->archive_offset;
    if (a->archive_offset > 0 && a->file_size >= sizeof(prefix)) {
        result = libmpq__stream_read_at(a->stream, 0, prefix, sizeof(prefix));
        if (result != LIBMPQ_SUCCESS)
            return result;
        if (memcmp(prefix, hm3w, sizeof(prefix)) == 0)
            *start = 0;
    }
    if (*start > end)
        return LIBMPQ_ERROR_FORMAT;
    *size = end - *start;
    return LIBMPQ_SUCCESS;
}

static int32_t
strong_digest_base(mpq_archive_s *a, uint64_t start, uint64_t size, mpq_sha1_s *context)
{
    uint8_t buffer[16384];
    uint64_t pos = 0;
    int32_t result;
    libmpq__sha1_init(context);
    while (pos < size) {
        size_t count = size - pos < sizeof(buffer) ? (size_t)(size - pos) : sizeof(buffer);
        result = libmpq__stream_read_at(a->stream, start + pos, buffer, count);
        if (result != LIBMPQ_SUCCESS)
            return result;
        libmpq__sha1_update(context, buffer, count);
        pos += count;
    }
    return LIBMPQ_SUCCESS;
}

static int32_t
strong_digest_variant(
    mpq_archive_s *a, const mpq_sha1_s *base, unsigned int variant, uint8_t digest[LIBMPQ_SHA1_SIZE]
)
{
    static const uint8_t archive_suffix[] = "ARCHIVE";
    mpq_sha1_s context = *base;
    if (variant == 1u) {
        const char *name = a->filename;
        const char *base = name;
        size_t i;
        if (name == NULL)
            return LIBMPQ_ERROR_FORMAT;
        for (i = 0; name[i] != '\0'; ++i)
            if (name[i] == '/' || name[i] == '\\')
                base = name + i + 1;
        for (i = 0; base[i] != '\0'; ++i) {
            uint8_t character = (uint8_t)base[i];
            if (character >= 'a' && character <= 'z')
                character = (uint8_t)(character - ('a' - 'A'));
            libmpq__sha1_update(&context, &character, 1);
        }
    } else if (variant == 2u) {
        libmpq__sha1_update(&context, archive_suffix, sizeof(archive_suffix) - 1);
    }
    libmpq__sha1_final(&context, digest);
    return LIBMPQ_SUCCESS;
}

static void
strong_encoded(
    const uint8_t digest[LIBMPQ_SHA1_SIZE], uint8_t encoded[LIBMPQ_STRONG_SIGNATURE_SIZE]
)
{
    size_t i;
    encoded[0] = 0x0b;
    memset(encoded + 1, 0xbb, LIBMPQ_STRONG_SIGNATURE_SIZE - LIBMPQ_SHA1_SIZE - 1);
    for (i = 0; i < LIBMPQ_SHA1_SIZE; ++i)
        encoded[LIBMPQ_STRONG_SIGNATURE_SIZE - LIBMPQ_SHA1_SIZE + i] =
            digest[LIBMPQ_SHA1_SIZE - 1 - i];
}

static int32_t
strong_verify(mpq_archive_s *a, const uint8_t *key, size_t key_size, uint32_t *mismatches)
{
    uint8_t signature[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t input[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t actual[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t expected[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t digest[LIBMPQ_SHA1_SIZE];
    mpq_sha1_s base;
    uint64_t extent;
    uint64_t start;
    uint64_t size;
    size_t i;
    unsigned int variant;
    int32_t result;
    if (libmpq__rsa_public_key_validate(key, key_size, LIBMPQ_RSA_STRONG_SIZE) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_FORMAT;
    result = strong_locate(a, &extent, signature);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = signature_hash_range(a, extent, &start, &size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    for (i = 0; i < sizeof(input); ++i)
        input[i] = signature[sizeof(input) - 1 - i];

    /* A trailer value outside the RSA representative domain is a failed
     * signature, not malformed MPQ storage or an invalid caller key. */
    if (memcmp(input, key, LIBMPQ_RSA_STRONG_SIZE) >= 0) {
        *mismatches |= LIBMPQ_SIGNATURE_STRONG;
        return LIBMPQ_SUCCESS;
    }
    result = libmpq__rsa_public_operation(
        key, LIBMPQ_RSA_STRONG_SIZE, key + LIBMPQ_RSA_STRONG_SIZE, LIBMPQ_RSA_STRONG_SIZE, input,
        actual
    );
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = strong_digest_base(a, start, size, &base);
    if (result != LIBMPQ_SUCCESS)
        return result;
    for (variant = 0; variant < 3; ++variant) {
        result = strong_digest_variant(a, &base, variant, digest);
        if (result != LIBMPQ_SUCCESS)
            return result;
        strong_encoded(digest, expected);
        if (memcmp(actual, expected, sizeof(actual)) == 0)
            return LIBMPQ_SUCCESS;
    }
    *mismatches |= LIBMPQ_SIGNATURE_STRONG;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__signature_detect(mpq_archive_s *a, uint32_t *signatures)
{
    uint8_t payload[LIBMPQ_SIGNATURE_SIZE];
    uint8_t strong[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint64_t offset;
    uint64_t extent;
    int32_t result;
    if (signatures != NULL)
        *signatures = 0;
    if (a == NULL || signatures == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (a->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    result = locate(a, &offset, &extent, payload);
    if (result != LIBMPQ_ERROR_EXIST && result != LIBMPQ_SUCCESS)
        return result;
    if (result == LIBMPQ_SUCCESS)
        *signatures = LIBMPQ_SIGNATURE_WEAK;
    result = strong_locate(a, &extent, strong);
    if (result == LIBMPQ_ERROR_EXIST)
        return LIBMPQ_SUCCESS;
    if (result == LIBMPQ_SUCCESS)
        *signatures |= LIBMPQ_SIGNATURE_STRONG;
    return result;
}

int32_t
libmpq__signature_verify(
    mpq_archive_s *a, uint32_t flags, const uint8_t *key, size_t key_size, uint32_t *mismatches
)
{
    uint8_t payload[LIBMPQ_SIGNATURE_SIZE];
    uint8_t digest[LIBMPQ_MD5_SIZE];
    uint8_t expected[LIBMPQ_RSA_SIZE];
    uint8_t input[LIBMPQ_RSA_SIZE];
    uint8_t actual[LIBMPQ_RSA_SIZE];
    uint64_t offset;
    uint64_t extent;
    uint64_t start;
    uint64_t size;
    uint64_t excluded;
    size_t i;
    int32_t result;
    if (mismatches != NULL)
        *mismatches = 0;
    if (a == NULL || mismatches == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (a->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (flags == LIBMPQ_SIGNATURE_STRONG)
        return strong_verify(a, key, key_size, mismatches);
    if (flags != LIBMPQ_SIGNATURE_WEAK || libmpq__rsa_key_validate(key, key_size) != 0)
        return LIBMPQ_ERROR_FORMAT;
    result = locate(a, &offset, &extent, payload);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = signature_hash_range(a, extent, &start, &size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if ((uint64_t)a->archive_offset > UINT64_MAX - offset ||
        (uint64_t)a->archive_offset + offset < start)
        return LIBMPQ_ERROR_FORMAT;
    excluded = (uint64_t)a->archive_offset + offset - start;
    result = digest_archive(a->stream, start, size, excluded, digest);
    if (result != LIBMPQ_SUCCESS)
        return result;
    libmpq__rsa_md5_encode(digest, expected);
    for (i = 0; i < LIBMPQ_RSA_SIZE; ++i)
        input[i] = payload[(LIBMPQ_SIGNATURE_SIZE - 1) - i];
    if (libmpq__rsa_operation(key, input, actual) != LIBMPQ_SUCCESS ||
        memcmp(expected, actual, LIBMPQ_RSA_SIZE) != 0)
        *mismatches = LIBMPQ_SIGNATURE_WEAK;
    return LIBMPQ_SUCCESS;
}

/* Reserve the zero payload immediately. Duplicate names are rejected by the
 * writer, and existing listfile/attributes reservations remain in force. */
int32_t
libmpq__signature_configure(mpq_archive_s *a, uint32_t type, const uint8_t *key, size_t key_size)
{
    uint8_t zero[LIBMPQ_SIGNATURE_SIZE] = { 0 };
    mpq_file_options_s options = { 0, 0, 0, 0, 0 };
    uint32_t index;
    uint32_t i;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    int32_t result;
    if (a == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (!a->write_mode || a->write_finalized || a->write_current)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (type != LIBMPQ_SIGNATURE_WEAK || a->write_signature ||
        libmpq__rsa_key_validate(key, key_size) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_FORMAT;
    index = a->write_next_block;
    libmpq__file_hash(LIBMPQ_SIGNATURE_NAME, &h1, &h2, &h3);
    for (i = 0; i < a->write_hash_capacity; ++i) {
        if (a->mpq_hash[i].block_table_index < a->write_capacity && a->mpq_hash[i].hash_a == h2 &&
            a->mpq_hash[i].hash_b == h3)
            return LIBMPQ_ERROR_FORMAT;
    }
    result = libmpq__writer_file_add(a, LIBMPQ_SIGNATURE_NAME, zero, sizeof(zero), &options);
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (a->write_attributes != NULL)
        memset(&a->write_attributes[index], 0, sizeof(*a->write_attributes));
    a->write_signature_offset = a->mpq_block[index].offset;
    memcpy(a->write_signature_key, key, LIBMPQ_RSA_KEY_SIZE);
    a->write_signature = 1;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__signature_finish(mpq_archive_s *a, uint64_t size)
{
    mpq_stream_s stream = { 0 };
    uint8_t digest[LIBMPQ_MD5_SIZE];
    uint8_t encoded[LIBMPQ_RSA_SIZE];
    uint8_t signature[LIBMPQ_RSA_SIZE];
    uint8_t reversed[LIBMPQ_RSA_SIZE];
    size_t i;
    int32_t result;
    if (!a->write_signature)
        return LIBMPQ_SUCCESS;
    libmpq__stream_borrow_file(&stream, a->fp, size);
    result = digest_archive(&stream, 0, size, a->write_signature_offset, digest);
    if (result == LIBMPQ_SUCCESS) {
        libmpq__rsa_md5_encode(digest, encoded);
        result = libmpq__rsa_operation(a->write_signature_key, encoded, signature);
    }
    if (result == LIBMPQ_SUCCESS) {
        for (i = 0; i < LIBMPQ_RSA_SIZE; ++i)
            reversed[i] = signature[(LIBMPQ_RSA_SIZE - 1) - i];
        if (libmpq__file_seek(
                a->fp, (libmpq__off_t)a->write_signature_offset + LIBMPQ_SIGNATURE_PREFIX_SIZE,
                SEEK_SET
            ) < 0)
            result = LIBMPQ_ERROR_SEEK;
        else if (fwrite(reversed, 1, LIBMPQ_RSA_SIZE, a->fp) != LIBMPQ_RSA_SIZE ||
                 fflush(a->fp) != 0)
            result = LIBMPQ_ERROR_WRITE;
    }
    libmpq__rsa_clear(a->write_signature_key, sizeof(a->write_signature_key));
    libmpq__rsa_clear(signature, sizeof(signature));
    libmpq__rsa_clear(reversed, sizeof(reversed));
    return result;
}
