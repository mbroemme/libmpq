/*
 *  test-mpq-signature.c -- archive signature regression tests.
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

#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "mpq-rsa.h"
#include "mpq-sha1.h"
#include "mpq-signature.h"
#include "mpq-stream.h"
#include "test-mpq-helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Independently calculated MD5 DigestInfo and RSA result for the libmpq
 * weak-signature known answer.
 */
static const uint8_t test_digest[16] = {
    0xaa, 0xaf, 0x4f, 0x2e, 0x9f, 0x11, 0xa5, 0xf0, 0x62, 0xad, 0x92, 0x01, 0x8b, 0xe1, 0x24, 0x95,
};
static const uint8_t test_encoded[64] = {
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x30, 0x20,
    0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10,
    0xaa, 0xaf, 0x4f, 0x2e, 0x9f, 0x11, 0xa5, 0xf0, 0x62, 0xad, 0x92, 0x01, 0x8b, 0xe1, 0x24, 0x95,
};
static const uint8_t test_signature[64] = {
    0x18, 0xb1, 0x47, 0x35, 0xc9, 0x3b, 0x03, 0x32, 0xf5, 0x4f, 0x84, 0xa4, 0x85, 0x93, 0xee, 0xf3,
    0x75, 0x48, 0x4e, 0x81, 0x29, 0x9b, 0x45, 0x9b, 0xc0, 0x2c, 0x3d, 0x55, 0xf4, 0x89, 0xfa, 0x1b,
    0xfb, 0x0b, 0x99, 0x90, 0x63, 0xc7, 0x97, 0xf5, 0x0e, 0x9f, 0x6c, 0xcf, 0x6e, 0xd4, 0xcf, 0xc0,
    0x60, 0xbd, 0x89, 0xdf, 0x8e, 0x9a, 0x3a, 0x72, 0x24, 0x9b, 0x09, 0xc4, 0x78, 0xba, 0xc1, 0x4c,
};

/* Test-only private exponent matching test_strong_signature_public_key. */
static const uint8_t test_strong_signature_private_exponent[LIBMPQ_RSA_STRONG_SIZE] = {
    0x14, 0xc9, 0x75, 0x9f, 0x7c, 0x1b, 0xa1, 0xf2, 0x4a, 0xb0, 0xde, 0x0b, 0xd2, 0x53, 0xba, 0xc7,
    0xb4, 0x70, 0xe7, 0xfb, 0xf9, 0x11, 0x08, 0x88, 0x44, 0x78, 0x3b, 0xea, 0x5a, 0x62, 0xda, 0x15,
    0x0c, 0x24, 0x35, 0x6f, 0xd6, 0x70, 0x71, 0x2b, 0x98, 0xa9, 0xae, 0xa0, 0x3e, 0xcb, 0x52, 0xb7,
    0xb1, 0x85, 0x97, 0x63, 0x7b, 0x2c, 0xf7, 0xf1, 0x6a, 0xfc, 0xb6, 0xd5, 0xcf, 0x67, 0xa7, 0x27,
    0xb9, 0x43, 0x7a, 0xbf, 0x07, 0x8a, 0x75, 0xb9, 0x07, 0x45, 0x0f, 0xb4, 0xfc, 0x56, 0x39, 0x6d,
    0xd8, 0xd6, 0x50, 0xa7, 0x14, 0x84, 0xd4, 0x16, 0x36, 0x41, 0xec, 0xa5, 0x54, 0x99, 0x7c, 0x29,
    0xaf, 0xbf, 0x20, 0x1c, 0x4d, 0xf4, 0x44, 0x35, 0x4c, 0x29, 0x88, 0x2e, 0xf7, 0x97, 0xb8, 0x55,
    0x80, 0xf2, 0x59, 0x26, 0x0f, 0x77, 0xef, 0xc6, 0x86, 0xee, 0xac, 0xd3, 0x1d, 0xa3, 0xd9, 0xc3,
    0x37, 0x89, 0x74, 0x33, 0xf8, 0xef, 0x83, 0x38, 0x90, 0xa0, 0x4d, 0x55, 0xcb, 0xfc, 0x53, 0xf2,
    0xdd, 0x8f, 0x96, 0xbd, 0x9b, 0x93, 0xe2, 0x8f, 0xc6, 0xf0, 0x22, 0x78, 0x6b, 0x36, 0xe5, 0x1d,
    0xe3, 0x8e, 0xc0, 0xd5, 0xd4, 0x1a, 0xba, 0x3e, 0xed, 0x96, 0x47, 0x83, 0x1f, 0xb1, 0x6f, 0xcb,
    0xc3, 0xb1, 0x6e, 0xac, 0xa9, 0x1e, 0x60, 0x89, 0x4a, 0xa7, 0x72, 0xb0, 0x2b, 0x22, 0xa3, 0xff,
    0xb7, 0x04, 0x2e, 0x52, 0x53, 0x11, 0x63, 0xd0, 0x89, 0x20, 0x9d, 0xf6, 0x41, 0x20, 0x98, 0x61,
    0x3e, 0xf5, 0x96, 0x64, 0xed, 0x70, 0x88, 0x4e, 0x33, 0xf3, 0xe3, 0x05, 0x6c, 0xcf, 0xb9, 0x11,
    0xbc, 0xc0, 0x4d, 0x2c, 0x73, 0x14, 0x29, 0x96, 0x94, 0x6d, 0x88, 0xbe, 0x0d, 0xaa, 0x29, 0xaa,
    0xfa, 0x1b, 0xab, 0x3d, 0x10, 0xff, 0x4d, 0x52, 0x29, 0x58, 0x80, 0xc8, 0xfa, 0xd6, 0xd6, 0x41,
};

static void
test_strong_signature_private_key(uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE])
{
    memcpy(key, test_strong_signature_public_key, LIBMPQ_RSA_STRONG_SIZE);
    memcpy(
        key + LIBMPQ_RSA_STRONG_SIZE, test_strong_signature_private_exponent,
        sizeof(test_strong_signature_private_exponent)
    );
}

static int test_rsa2048_public_vector(void);
static int test_rsa2048_private_vector(void);
static int write_bytes(const char *path, const uint8_t *data, size_t size, size_t prefix);

/* Count signed-range reads without depending on verifier chunk sizes. */
typedef struct
{
    mpq_io_read_at_fn read_at;
    void *context;
    uint64_t start;
    uint64_t end;
    uint64_t bytes;
} strong_read_count_s;

typedef struct
{
    const uint8_t *data;
    size_t size;
} strong_memory_source_s;

static int32_t
strong_memory_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    const strong_memory_source_s *source = context;

    if (source == NULL || offset < 0 || (uint64_t)offset > source->size ||
        size > source->size - (size_t)offset)
        return LIBMPQ_ERROR_READ;
    memcpy(buffer, source->data + (size_t)offset, size);
    return LIBMPQ_SUCCESS;
}

static int32_t
count_strong_read(void *context, uint64_t offset, uint8_t *buffer, size_t size)
{
    strong_read_count_s *count = context;

    if (offset >= count->start && offset <= count->end && size <= count->end - offset &&
        !(offset == count->start && size == 4))
        count->bytes += size;
    return count->read_at(count->context, offset, buffer, size);
}

static int
verify_strong_fixture(
    const char *path, libmpq__off_t offset, uint32_t expected_signatures, int verify_weak
)
{
    mpq_archive_s *archive = NULL;
    uint32_t signatures = 0;
    uint32_t mismatches = UINT32_MAX;

    TEST_CHECK(libmpq__archive_open(&archive, path, offset) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    TEST_CHECK(signatures == expected_signatures);
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == 0
    );
    TEST_CHECK(mismatches == 0);
    if (verify_weak) {
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                sizeof(test_signature_public_key), &mismatches
            ) == 0
        );
        TEST_CHECK(mismatches == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

static int
test_custom_io_strong_source_names(void)
{
    char source_name[] = "/custom/path/mpq-v1-features.w3x";
    strong_memory_source_s source = { 0 };
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    uint8_t *data = NULL;
    size_t size = 0;
    uint32_t mismatches = UINT32_MAX;

    TEST_CHECK(test_read_path(FIXTURE_DIR "/mpq-v1-features.w3x", &data, &size) == 0);
    source.data = data;
    source.size = size;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, strong_memory_read_at, (libmpq__off_t)source.size, -1, source_name
        ) == LIBMPQ_SUCCESS
    );
    {
        char *base = strrchr(source_name, '/');

        TEST_CHECK(base != NULL);
        base[1] = 'X';
    }
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    TEST_CHECK(
        libmpq__archive_verify(
            clone, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__archive_close(clone) == LIBMPQ_SUCCESS);
    clone = NULL;

    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, strong_memory_read_at, (libmpq__off_t)source.size, -1, NULL
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(mismatches == LIBMPQ_SIGNATURE_STRONG);
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == LIBMPQ_SUCCESS);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    TEST_CHECK(
        libmpq__archive_verify(
            clone, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(mismatches == LIBMPQ_SIGNATURE_STRONG);
    TEST_CHECK(libmpq__archive_close(clone) == LIBMPQ_SUCCESS);
    clone = NULL;
    free(data);
    data = NULL;

    TEST_CHECK(test_read_path(FIXTURE_DIR "/mpq-v1-features.mpq", &data, &size) == 0);
    source.data = data;
    source.size = size;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, strong_memory_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    archive = NULL;
    free(data);
    data = NULL;

    TEST_CHECK(test_read_path(FIXTURE_DIR "/mpq-v2-features.mpq", &data, &size) == 0);
    source.data = data;
    source.size = size;
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &source, strong_memory_read_at, (libmpq__off_t)source.size, 0, NULL
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_SUCCESS);
    free(data);
    return 0;
}

/* Check canonical fixtures, negative mutations, and the MPQE limitation. */
static int
test_strong_signatures(void)
{
    static const uint8_t auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    static const uint8_t list_marker[] = "overview.txt\n";
    mpq_archive_s *archive = NULL;
    uint8_t *data = NULL;
    uint8_t *changed = NULL;
    uint8_t *wrapped = NULL;
    uint8_t invalid[sizeof(test_strong_signature_public_key)];
    uint64_t extent;
    size_t size;
    size_t wrapped_size;
    size_t i;
    size_t marker = 0;
    uint32_t signatures;
    uint32_t mismatches;
    char temporary[512];

    TEST_CHECK(
        verify_strong_fixture(
            FIXTURE_DIR "/mpq-v1-features.mpq", 0, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG,
            1
        ) == 0
    );
    TEST_CHECK(
        verify_strong_fixture(
            FIXTURE_DIR "/mpq-v2-features.mpq", 0, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG,
            1
        ) == 0
    );
    TEST_CHECK(
        verify_strong_fixture(
            FIXTURE_DIR "/mpq-v1-features.w3x", -1, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG,
            1
        ) == 0
    );

    /* The basename variant recognizes both separator styles and ASCII case. */
    TEST_CHECK(libmpq__archive_open(&archive, FIXTURE_DIR "/mpq-v1-features.w3x", -1) == 0);
    {
        char *saved = archive->filename;
        archive->filename = "ignored\\directory\\mpq-v1-features.w3x";
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mismatches
            ) == 0
        );
        TEST_CHECK(mismatches == 0);
        archive->filename = saved;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    /*
     * Tamper an HM3W wrapper byte after the marker so range selection remains
     * unchanged. Both weak and strong signatures must detect the change.
     */
    TEST_CHECK(test_read_path(FIXTURE_DIR "/mpq-v1-features.w3x", &wrapped, &wrapped_size) == 0);
    TEST_CHECK(wrapped_size > 4 && memcmp(wrapped, "HM3W", 4) == 0);
    wrapped[4] ^= 1;
    TEST_CHECK(test_temp_path(temporary, sizeof(temporary), "hm3w-tamper") == 0);
    TEST_CHECK(write_bytes(temporary, wrapped, wrapped_size, 0) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, temporary, -1) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    TEST_CHECK(signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG));
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
            sizeof(test_signature_public_key), &mismatches
        ) == 0
    );
    TEST_CHECK(mismatches == LIBMPQ_SIGNATURE_WEAK);
    {
        char *saved = archive->filename;
        archive->filename = "mpq-v1-features.w3x";
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mismatches
            ) == 0
        );
        TEST_CHECK(mismatches == LIBMPQ_SIGNATURE_STRONG);
        archive->filename = saved;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(temporary) == 0);
    free(wrapped);
    wrapped = NULL;

    /* A normal embedded MPQ excludes its non-HM3W prefix from the digest. */
    TEST_CHECK(test_read_path(FIXTURE_DIR "/mpq-v1-features.mpq", &data, &size) == 0);
    TEST_CHECK(test_temp_path(temporary, sizeof(temporary), "strong-embedded") == 0);
    TEST_CHECK(write_bytes(temporary, data, size, 19) == 0);
    TEST_CHECK(
        verify_strong_fixture(temporary, 19, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG, 1) ==
        0
    );
    TEST_CHECK(remove(temporary) == 0);

    TEST_CHECK(libmpq__archive_open(&archive, FIXTURE_DIR "/mpq-v1-features.mpq", 0) == 0);
    TEST_CHECK(libmpq__archive_signature_extent(archive, &extent) == 0);
    TEST_CHECK(extent < size && size - (size_t)extent == LIBMPQ_STRONG_TRAILER_SIZE);
    {
        strong_read_count_s count = { archive->stream->backend.read_at,
                                      archive->stream->backend.context, archive->archive_offset,
                                      archive->archive_offset + extent, 0 };
        archive->stream->backend.read_at = count_strong_read;
        archive->stream->backend.context = &count;
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mismatches
            ) == 0
        );
        TEST_CHECK(mismatches == 0 && count.bytes == extent);
        archive->stream->backend.read_at = count.read_at;
        archive->stream->backend.context = count.context;
    }
    memcpy(invalid, test_strong_signature_public_key, sizeof(invalid));
    invalid[sizeof(invalid) - 1] = 3;
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, invalid, sizeof(invalid), &mismatches
        ) == 0
    );
    TEST_CHECK(mismatches == LIBMPQ_SIGNATURE_STRONG);
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key) - 1, &mismatches
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(mismatches == 0);
    for (i = 0; i < 3; ++i) {
        memcpy(invalid, test_strong_signature_public_key, sizeof(invalid));
        if (i == 0)
            invalid[LIBMPQ_RSA_STRONG_SIZE - 1u] &= 0xfe;
        else if (i == 1)
            invalid[0] = 0;
        else
            memset(invalid + LIBMPQ_RSA_STRONG_SIZE, 0, LIBMPQ_RSA_STRONG_SIZE);
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, invalid, sizeof(invalid), &mismatches
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(mismatches == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    for (i = 0; i + sizeof(list_marker) <= (size_t)extent; ++i) {
        if (memcmp(data + i, list_marker, sizeof(list_marker) - 1) == 0) {
            marker = i;
            break;
        }
    }
    TEST_CHECK(marker != 0);
    changed = malloc(size + 1);
    TEST_CHECK(changed != NULL);
    for (i = 0; i < 8; ++i) {
        size_t length = size;
        memcpy(changed, data, size);
        if (i == 0)
            changed[marker] ^= 1;
        else if (i == 1)
            changed[extent + LIBMPQ_STRONG_SIGNATURE_MARKER_SIZE] ^= 1;
        else if (i == 2) {
            size_t j;
            for (j = 0; j < LIBMPQ_STRONG_SIGNATURE_SIZE; ++j)
                changed[extent + LIBMPQ_STRONG_SIGNATURE_MARKER_SIZE + j] =
                    test_strong_signature_public_key[LIBMPQ_STRONG_SIGNATURE_SIZE - 1u - j];
        } else if (i == 3)
            length = (size_t)extent;
        else if (i == 4)
            changed[extent] ^= 1;
        else if (i == 5)
            --length;
        else if (i == 6)
            changed[length++] = 0x5a;
        else
            memset(
                changed + extent + LIBMPQ_STRONG_SIGNATURE_MARKER_SIZE, 0,
                LIBMPQ_STRONG_SIGNATURE_SIZE
            );
        TEST_CHECK(write_bytes(temporary, changed, length, 0) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, temporary, 0) == 0);
        TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
        if (i >= 3 && i <= 5) {
            TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
            TEST_CHECK(
                libmpq__archive_verify(
                    archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                    sizeof(test_strong_signature_public_key), &mismatches
                ) == LIBMPQ_ERROR_EXIST
            );
            TEST_CHECK(mismatches == 0);
        } else {
            TEST_CHECK(signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG));
            TEST_CHECK(
                libmpq__archive_verify(
                    archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                    sizeof(test_strong_signature_public_key), &mismatches
                ) == 0
            );
            TEST_CHECK(mismatches == (i == 6 ? 0 : LIBMPQ_SIGNATURE_STRONG));
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(remove(temporary) == 0);
    free(changed);
    free(data);

    TEST_CHECK(
        libmpq__archive_open_mpqe(
            &archive, FIXTURE_DIR "/mpq-v1-features.mpqe", 0, auth, sizeof(auth) - 1
        ) == 0
    );
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);

    return 0;
}

static int
test_sha1_vectors(void)
{
    static const uint8_t empty[20] = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                                       0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 };
    static const uint8_t abc[20] = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                     0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
    static const uint8_t long_digest[20] = { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2,
                                             0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                                             0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };
    static const uint8_t long_input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    mpq_sha1_s context;
    uint8_t digest[20];
    libmpq__sha1_init(&context);
    libmpq__sha1_final(&context, digest);
    TEST_CHECK(memcmp(digest, empty, sizeof(digest)) == 0);
    libmpq__sha1_init(&context);
    libmpq__sha1_update(&context, (const uint8_t *)"abc", 3);
    libmpq__sha1_final(&context, digest);
    TEST_CHECK(memcmp(digest, abc, sizeof(digest)) == 0);
    libmpq__sha1_init(&context);
    libmpq__sha1_update(&context, long_input, sizeof(long_input) - 1);
    libmpq__sha1_final(&context, digest);
    TEST_CHECK(memcmp(digest, long_digest, sizeof(digest)) == 0);
    return 0;
}

static int
write_bytes(const char *path, const uint8_t *data, size_t size, size_t prefix)
{
    FILE *file = libmpq__file_open(path, "wb");
    size_t i;
    TEST_CHECK(file != NULL);
    for (i = 0; i < prefix; ++i)
        TEST_CHECK(fputc(0, file) != EOF);
    TEST_CHECK(fwrite(data, 1, size, file) == size);
    TEST_CHECK(fclose(file) == 0);
    return 0;
}

static int
check_archive(const char *path, libmpq__off_t offset, uint32_t expected)
{
    mpq_archive_s *a = NULL;
    uint32_t signatures = 99;
    uint32_t mismatches = 99;
    TEST_CHECK(libmpq__archive_open(&a, path, offset) == 0);
    TEST_CHECK(libmpq__archive_signatures(a, &signatures) == 0);
    TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(
        libmpq__archive_verify(a, signatures, test_signature_public_key, 128, &mismatches) == 0
    );
    TEST_CHECK(mismatches == expected);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    return 0;
}

/*
 * Re-sign a deliberately padded v1 archive. This follows the on-disk weak
 * signature representation so the reader is exercised against a genuine
 * archive rather than an in-memory metadata shortcut.
 */
static int
sign_padded_v1_archive(uint8_t *data, size_t size, uint64_t signature_offset)
{
    mpq_md5_s context;
    uint8_t digest[LIBMPQ_MD5_SIZE];
    uint8_t encoded[LIBMPQ_RSA_SIZE];
    uint8_t signature[LIBMPQ_RSA_SIZE];
    size_t i;
    if (data == NULL || size > UINT32_MAX || signature_offset > size ||
        size - signature_offset < LIBMPQ_SIGNATURE_SIZE)
        return -1;
    libmpq__store_le32(data + 8, (uint32_t)size);
    memset(data + signature_offset, 0, LIBMPQ_SIGNATURE_SIZE);
    libmpq__md5_init(&context);
    libmpq__md5_update(&context, data, size);
    libmpq__md5_final(&context, digest);
    libmpq__rsa_md5_encode(digest, encoded);
    if (libmpq__rsa_weak_operation(test_signature_private_key, encoded, signature) !=
        LIBMPQ_SUCCESS)
        return -1;
    for (i = 0; i < LIBMPQ_RSA_SIZE; ++i)
        data[signature_offset + LIBMPQ_SIGNATURE_PREFIX_SIZE + i] =
            signature[LIBMPQ_RSA_SIZE - 1 - i];
    return 0;
}

static int32_t
failed_read(void *context, uint64_t offset, uint8_t *buffer, size_t size)
{
    (void)context;
    (void)offset;
    (void)buffer;
    (void)size;
    return LIBMPQ_ERROR_READ;
}

/*
 * A virtual high-offset signature avoids allocating or hashing gigabytes.
 * Record the first digest read and fail it deliberately after successful
 * signature location. This tests the verifier's extent handoff as well.
 */
static int32_t
high_read(void *context, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (offset == (UINT64_C(1) << 32) + 64 && size == 72) {
        memset(buffer, 0, size);
        return 0;
    }
    if (offset == (UINT64_C(1) << 32) + 136 && size == LIBMPQ_STRONG_TRAILER_SIZE) {
        memset(buffer, 0, size);
        return 0;
    }
    *(size_t *)context = size;
    return LIBMPQ_ERROR_READ;
}

static int
test_logical_extent(void)
{
    mpq_archive_s archive = { 0 };
    mpq_block_s block = { 0 };
    mpq_block_ex_s high = { 0 };
    mpq_hash_s hash = { 0 };
    mpq_stream_s stream = { 0 };
    uint64_t extent = 99;
    uint32_t unused;
    uint32_t signatures;
    uint32_t mismatches;
    size_t digest_read = 0;
    archive.mpq_header.version = LIBMPQ_ARCHIVE_VERSION_TWO;
    archive.mpq_header.header_size = 44;
    archive.mpq_header.archive_size = 136;
    archive.mpq_header.hash_table_offset = 44;
    archive.mpq_header.hash_table_count = 1;
    archive.mpq_header.block_table_offset = 136;
    archive.mpq_header.block_table_count = 1;
    archive.mpq_header_ex.extended_offset = 152;
    archive.mpq_hash = &hash;
    archive.mpq_block = &block;
    archive.mpq_block_ex = &high;
    archive.file_size = UINT64_MAX;
    archive.stream = &stream;
    stream.size = UINT64_MAX;
    stream.backend.size = UINT64_MAX;
    stream.backend.read_at = high_read;
    stream.backend.context = &digest_read;
    libmpq__file_hash("(signature)", &unused, &hash.hash_a, &hash.hash_b);
    block.offset = 64;
    block.packed_size = block.unpacked_size = 72;
    block.flags = LIBMPQ_FLAG_EXISTS;
    high.offset_high = 1;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(1) << 32) + 136);
    TEST_CHECK(libmpq__archive_signatures(&archive, &signatures) == 0);
    TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(
        libmpq__archive_verify(
            &archive, signatures, test_signature_public_key, sizeof(test_signature_public_key),
            &mismatches
        ) == LIBMPQ_ERROR_READ
    );
    TEST_CHECK(digest_read == 16384 && mismatches == 0);

    archive.mpq_header_ex.hash_table_offset_high = 2;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(2) << 32) + 60);
    archive.mpq_header_ex.block_table_offset_high = 3;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(3) << 32) + 152);
    archive.mpq_header_ex.extended_offset = (UINT64_C(4) << 32);
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(4) << 32) + 2);
    archive.mpq_header_ex.extended_offset = UINT64_MAX - 1;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(extent == 0);
    TEST_CHECK(libmpq__archive_signatures(&archive, &signatures) == LIBMPQ_ERROR_FORMAT);
    archive.mpq_header_ex.extended_offset = UINT64_MAX - 2;
    archive.archive_offset = 1;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == LIBMPQ_ERROR_FORMAT);
    archive.archive_offset = 0;
    archive.file_size = 136;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == LIBMPQ_ERROR_FORMAT);
    archive.archive_offset = 0;
    archive.file_size = UINT64_MAX;
    archive.mpq_header_ex.hash_table_offset_high = 0;
    archive.mpq_header_ex.block_table_offset_high = 0;
    archive.mpq_header_ex.extended_offset = 0;
    block.offset = UINT32_MAX;
    block.packed_size = 0;
    block.unpacked_size = 0;
    high.offset_high = UINT16_MAX;
    TEST_CHECK(libmpq__archive_required_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == 152);
    return 0;
}

/*
 * Decode a writer-produced NGIS trailer directly. This distinguishes the
 * plain SHA-1 archive-range encoding from every verification-only variant.
 */
static int
test_strong_writer_plain_block(mpq_archive_s *archive)
{
    static const uint8_t marker[LIBMPQ_STRONG_SIGNATURE_MARKER_SIZE] = { 'N', 'G', 'I', 'S' };
    uint8_t trailer[LIBMPQ_STRONG_TRAILER_SIZE];
    uint8_t input[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t actual[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t expected[LIBMPQ_STRONG_SIGNATURE_SIZE];
    uint8_t digest[LIBMPQ_SHA1_SIZE];
    uint8_t buffer[16384];
    mpq_sha1_s context;
    uint64_t extent;
    uint64_t trailer_offset;
    uint64_t position = 0;
    size_t count;
    size_t i;

    TEST_CHECK(archive != NULL && archive->archive_offset >= 0);
    TEST_CHECK(libmpq__archive_signature_extent(archive, &extent) == LIBMPQ_SUCCESS);
    TEST_CHECK((uint64_t)archive->archive_offset <= UINT64_MAX - extent);
    trailer_offset = (uint64_t)archive->archive_offset + extent;
    TEST_CHECK(trailer_offset <= archive->file_size);
    TEST_CHECK(sizeof(trailer) <= archive->file_size - trailer_offset);
    TEST_CHECK(
        libmpq__stream_read_at(archive->stream, trailer_offset, trailer, sizeof(trailer)) ==
        LIBMPQ_SUCCESS
    );
    TEST_CHECK(memcmp(trailer, marker, sizeof(marker)) == 0);
    for (i = 0; i < sizeof(input); ++i)
        input[i] = trailer[sizeof(marker) + sizeof(input) - 1 - i];
    TEST_CHECK(
        libmpq__rsa_strong_public_operation(test_strong_signature_public_key, input, actual) ==
        LIBMPQ_SUCCESS
    );

    libmpq__sha1_init(&context);
    while (position < extent) {
        count = extent - position < sizeof(buffer) ? (size_t)(extent - position) : sizeof(buffer);
        TEST_CHECK(
            libmpq__stream_read_at(
                archive->stream, (uint64_t)archive->archive_offset + position, buffer, count
            ) == LIBMPQ_SUCCESS
        );
        libmpq__sha1_update(&context, buffer, count);
        position += count;
    }
    libmpq__sha1_final(&context, digest);
    expected[0] = 0x0b;
    memset(expected + 1, 0xbb, LIBMPQ_STRONG_SIGNATURE_SIZE - LIBMPQ_SHA1_SIZE - 1u);
    for (i = 0; i < sizeof(digest); ++i)
        expected[LIBMPQ_STRONG_SIGNATURE_SIZE - LIBMPQ_SHA1_SIZE + i] =
            digest[sizeof(digest) - 1 - i];
    TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
    return 0;
}

static int
test_strong_writer_signatures(void)
{
    static const uint8_t payload[] = "strong writer signature";
    static const uint8_t auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096, 0, 0 };
    mpq_file_options_s raw_options = { 0, 0, 0, 0, 0 };
    uint8_t strong_private[LIBMPQ_RSA_STRONG_KEY_SIZE];
    uint8_t invalid[LIBMPQ_RSA_STRONG_KEY_SIZE];
    uint32_t signatures;
    uint32_t mismatches;
    uint32_t version;
    char path[512];
    char renamed[512];
    mpq_writer_s *writer = NULL;

    test_strong_signature_private_key(strong_private);
    TEST_CHECK(test_temp_path(path, sizeof(path), "strong-writer") == 0);
    for (version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_TWO; ++version) {
        options.version = version;
        TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
        TEST_CHECK(
            libmpq__archive_sign(
                archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private)
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_sign(
                archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private)
            ) == LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(
            libmpq__archive_add_data(
                archive, "payload", payload, sizeof(payload) - 1, &raw_options
            ) == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        if (version == LIBMPQ_ARCHIVE_VERSION_ONE) {
            TEST_CHECK(test_temp_path(renamed, sizeof(renamed), "strong-writer-renamed") == 0);
            TEST_CHECK(rename(path, renamed) == 0);
        }
        TEST_CHECK(
            libmpq__archive_open(
                &archive, version == LIBMPQ_ARCHIVE_VERSION_ONE ? renamed : path, 0
            ) == 0
        );
        TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
        TEST_CHECK(signatures == LIBMPQ_SIGNATURE_STRONG);
        TEST_CHECK(test_strong_writer_plain_block(archive) == 0);
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mismatches
            ) == 0
        );
        TEST_CHECK(mismatches == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        if (version == LIBMPQ_ARCHIVE_VERSION_ONE)
            TEST_CHECK(remove(renamed) == 0);
    }

    options.version = LIBMPQ_ARCHIVE_VERSION_ONE;
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private)
        ) == 0
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, "payload", payload, sizeof(payload) - 1, &raw_options) ==
        0
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
    TEST_CHECK(signatures == (LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG));
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
            sizeof(test_signature_public_key), &mismatches
        ) == 0
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(
        libmpq__archive_verify(
            archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
            sizeof(test_strong_signature_public_key), &mismatches
        ) == 0
    );
    TEST_CHECK(mismatches == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(libmpq__writer_begin(archive, "active", 0, &raw_options, &writer) == 0);
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private)
        ) == LIBMPQ_ERROR_NOT_INITIALIZED
    );
    TEST_CHECK(libmpq__writer_finish(writer) == 0);
    writer = NULL;
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private) - 1
        ) == LIBMPQ_ERROR_FORMAT
    );
    memcpy(invalid, strong_private, sizeof(invalid));
    invalid[LIBMPQ_RSA_STRONG_SIZE - 1u] &= 0xfe;
    TEST_CHECK(
        libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, invalid, sizeof(invalid)) ==
        LIBMPQ_ERROR_FORMAT
    );
    memcpy(invalid, strong_private, sizeof(invalid));
    memset(invalid + LIBMPQ_RSA_STRONG_SIZE, 0, LIBMPQ_RSA_STRONG_SIZE);
    TEST_CHECK(
        libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, invalid, sizeof(invalid)) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK | LIBMPQ_SIGNATURE_STRONG, strong_private,
            sizeof(strong_private)
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;

    TEST_CHECK(libmpq__archive_create_mpqe(&archive, path, auth, sizeof(auth) - 1, &options) == 0);
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_STRONG, strong_private, sizeof(strong_private)
        ) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(remove(path) == 0);
    libmpq__rsa_clear(strong_private, sizeof(strong_private));
    return 0;
}

int
main(void)
{
    mpq_archive_s *a = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096,
                                             LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s raw_options = { 0, 0, 0, 0, 0 };
    mpq_file_attributes_s attributes;
    uint8_t output[64];
    uint8_t encoded[64];
    uint8_t invalid_key[128];
    uint8_t payload[17000];
    uint8_t *archive_data;
    uint8_t *padded_data;
    size_t archive_size;
    size_t padded_size;
    size_t payload_size;
    uint32_t number;
    uint32_t index;
    uint32_t mismatch = 99;
    uint32_t types = 99;
    uint32_t flags;
    uint32_t saved_offset;
    uint32_t i;
    uint64_t signature_offset;
    uint64_t required_extent;
    uint64_t signature_extent;
    char path[512];
    char changed[512];

    TEST_CHECK(test_logical_extent() == 0);
    TEST_CHECK(test_sha1_vectors() == 0);
    TEST_CHECK(test_rsa2048_public_vector() == 0);
    TEST_CHECK(test_rsa2048_private_vector() == 0);
    libmpq__rsa_md5_encode(test_digest, encoded);
    TEST_CHECK(memcmp(encoded, test_encoded, 64) == 0);
    TEST_CHECK(libmpq__rsa_weak_key_validate(test_signature_private_key, 128) == 0);
    TEST_CHECK(libmpq__rsa_weak_key_validate(test_signature_public_key, 128) == 0);
    TEST_CHECK(libmpq__rsa_weak_operation(test_signature_private_key, encoded, output) == 0);
    TEST_CHECK(memcmp(output, test_signature, 64) == 0);
    TEST_CHECK(libmpq__rsa_weak_operation(test_signature_public_key, output, encoded) == 0);
    TEST_CHECK(memcmp(encoded, test_encoded, 64) == 0);
    TEST_CHECK(test_strong_writer_signatures() == 0);
    TEST_CHECK(test_strong_signatures() == 0);
    TEST_CHECK(test_custom_io_strong_source_names() == 0);
    TEST_CHECK(libmpq__rsa_weak_key_validate(NULL, 128) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__rsa_weak_key_validate(test_signature_public_key, 127) == LIBMPQ_ERROR_FORMAT
    );
    memcpy(invalid_key, test_signature_public_key, 128);
    invalid_key[63] &= 0xfe;
    TEST_CHECK(libmpq__rsa_weak_key_validate(invalid_key, 128) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_signatures(NULL, &types) == LIBMPQ_ERROR_EXIST && types == 0);
    TEST_CHECK(
        libmpq__archive_verify(NULL, 1, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_EXIST &&
        mismatch == 0
    );

    TEST_CHECK(test_temp_path(path, sizeof(path), "signature") == 0);
    TEST_CHECK(test_temp_path(changed, sizeof(changed), "signature-changed") == 0);
    memset(payload, 0x5a, sizeof(payload));
    TEST_CHECK(libmpq__archive_create(&a, path, &options) == 0);
    payload_size = 16384 - 24 - (size_t)libmpq__file_tell(a->fp);
    TEST_CHECK(libmpq__archive_sign(a, 2, test_signature_private_key, 128) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_add_data(a, "payload", payload, payload_size, &raw_options) == 0);
    TEST_CHECK(libmpq__archive_sign(a, 1, test_signature_private_key, 128) == 0);
    TEST_CHECK(libmpq__archive_sign(a, 1, test_signature_private_key, 128) == LIBMPQ_ERROR_FORMAT);
    signature_offset = a->write_signature_offset;
    TEST_CHECK(signature_offset / 16384 != (signature_offset + 71) / 16384);
    TEST_CHECK(libmpq__archive_add_data(a, "after", payload, 20, &raw_options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(a, "(SIGNATURE)", payload, 72, &raw_options) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(check_archive(path, 0, 0) == 0);

    TEST_CHECK(libmpq__archive_open(&a, path, 0) == 0);
    memcpy(invalid_key, test_signature_public_key, sizeof(invalid_key));
    invalid_key[127] = 3;
    TEST_CHECK(libmpq__archive_verify(a, 1, invalid_key, sizeof(invalid_key), &mismatch) == 0);
    TEST_CHECK(mismatch == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(libmpq__file_number(a, "(signature)", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(a, number, &attributes) == 0);
    TEST_CHECK(attributes.crc32 == 0);
    for (i = 0; i < 16; ++i)
        TEST_CHECK(attributes.md5[i] == 0);
    TEST_CHECK(libmpq__file_number(a, "(listfile)", &index) == 0);
    TEST_CHECK(
        libmpq__archive_verify(a, 0, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_FORMAT &&
        mismatch == 0
    );
    TEST_CHECK(
        libmpq__archive_verify(a, 1, NULL, 128, &mismatch) == LIBMPQ_ERROR_FORMAT && mismatch == 0
    );
    index = a->mpq_map[number].block_table_indices;
    for (i = 71; i <= 73; i += 2) {
        a->mpq_block[index].unpacked_size = i;
        TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    }
    a->mpq_block[index].unpacked_size = 72;
    flags = a->mpq_block[index].flags;
    TEST_CHECK(flags == LIBMPQ_FLAG_EXISTS);
    a->mpq_block[index].flags |= LIBMPQ_FLAG_SINGLE;
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) == 0 &&
        mismatch == 0
    );
    for (i = 0; i < 3; ++i) {
        static const uint32_t invalid_flags[] = { LIBMPQ_FLAG_COMPRESS_MULTI, LIBMPQ_FLAG_ENCRYPTED,
                                                  LIBMPQ_FLAG_CRC };
        a->mpq_block[index].flags = flags | invalid_flags[i];
        TEST_CHECK(
            libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) ==
                LIBMPQ_ERROR_FORMAT &&
            mismatch == 0
        );
    }
    a->mpq_block[index].flags = flags;
    a->mpq_block[index].packed_size = 71;
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT);
    a->mpq_block[index].packed_size = 72;
    saved_offset = a->mpq_header.hash_table_offset;
    a->mpq_header.hash_table_offset = a->mpq_header.archive_size;
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    a->mpq_header.hash_table_offset = saved_offset;
    saved_offset = a->mpq_block[0].offset;
    a->mpq_block[0].offset = a->mpq_header.archive_size;
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    a->mpq_block[0].offset = saved_offset;
    a->stream->backend.read_at = failed_read;
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_READ &&
        mismatch == 0
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);

    TEST_CHECK(test_read_path(path, &archive_data, &archive_size) == 0);
    padded_size = archive_size + 16;
    padded_data = malloc(padded_size);
    TEST_CHECK(padded_data != NULL);
    memcpy(padded_data, archive_data, archive_size);
    memset(padded_data + archive_size, 0xa5, padded_size - archive_size);
    TEST_CHECK(sign_padded_v1_archive(padded_data, padded_size, signature_offset) == 0);
    TEST_CHECK(write_bytes(changed, padded_data, padded_size, 0) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    TEST_CHECK(libmpq__archive_required_extent(a, &required_extent) == 0);
    TEST_CHECK(required_extent < padded_size);
    TEST_CHECK(libmpq__archive_signature_extent(a, &signature_extent) == 0);
    TEST_CHECK(signature_extent == padded_size);
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) == 0 &&
        mismatch == 0
    );
    a->mpq_header.archive_size = (uint32_t)(required_extent - 1);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    a->mpq_header.archive_size = (uint32_t)(padded_size + 1);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    free(padded_data);
    TEST_CHECK(write_bytes(changed, archive_data, archive_size, 512) == 0);
    {
        FILE *file = libmpq__file_open(changed, "ab");
        TEST_CHECK(file != NULL);
        TEST_CHECK(fputs("unrelated trailing data", file) >= 0);
        TEST_CHECK(fclose(file) == 0);
    }
    TEST_CHECK(check_archive(changed, 512, 0) == 0);
    archive_data[signature_offset - 1] ^= 1;
    TEST_CHECK(write_bytes(changed, archive_data, archive_size, 0) == 0);
    TEST_CHECK(check_archive(changed, 0, 1) == 0);
    archive_data[signature_offset - 1] ^= 1;
    archive_data[signature_offset + 8] ^= 1;
    TEST_CHECK(write_bytes(changed, archive_data, archive_size, 0) == 0);
    TEST_CHECK(check_archive(changed, 0, 1) == 0);
    free(archive_data);

    options.version = LIBMPQ_ARCHIVE_VERSION_TWO;
    options.attributes = 0;
    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_sign(a, 1, test_signature_private_key, 128) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(check_archive(changed, 0, 0) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    a->mpq_header.archive_size = 1;
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) == 0 &&
        mismatch == 0
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);
    {
        static const uint8_t auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
        TEST_CHECK(libmpq__archive_create_mpqe(&a, changed, auth, sizeof(auth) - 1, &options) == 0);
        TEST_CHECK(
            libmpq__archive_sign(
                a, 1, test_signature_private_key, sizeof(test_signature_private_key)
            ) == 0
        );
        TEST_CHECK(libmpq__archive_add_data(a, "payload", payload, 72, &raw_options) == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
        TEST_CHECK(libmpq__archive_open_mpqe(&a, changed, 0, auth, sizeof(auth) - 1) == 0);
        TEST_CHECK(libmpq__archive_signatures(a, &types) == 0 && types == LIBMPQ_SIGNATURE_WEAK);
        TEST_CHECK(
            libmpq__archive_verify(
                a, types, test_signature_public_key, sizeof(test_signature_public_key), &mismatch
            ) == 0
        );
        TEST_CHECK(mismatch == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
    }
    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(a, "(signature)", payload, 72, &raw_options) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_close(a) == 0);

    memset(payload, 0, 72);
    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(a, "(signature)", payload, 72, &raw_options) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(check_archive(changed, 0, 1) == 0);

    /*
     * Persist malformed payload lengths through the ordinary writer, rather
     * than relying only on the defensive in-memory metadata checks above.
     */
    for (i = 71; i <= 73; i += 2) {
        TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
        TEST_CHECK(libmpq__archive_add_data(a, "(signature)", payload, i, &raw_options) == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
        TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
        TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
    }

    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == 0 && types == 0);
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_EXIST &&
        mismatch == 0
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);
    remove(path);
    remove(changed);
    return 0;
}

/*
 * Test-only RSA-2048 public-operation KAT. Expected output was generated
 * independently with Python: pow(input, 65537, modulus), serialized big-endian.
 */
static const uint8_t test_rsa2048_modulus[LIBMPQ_RSA_STRONG_SIZE] = {
    0xc8, 0xb9, 0x7d, 0x0b, 0x16, 0xb3, 0x2a, 0x9b, 0x13, 0x0d, 0x73, 0x55, 0xb1, 0x99, 0x4a, 0x28,
    0x6d, 0x6d, 0xde, 0x05, 0xb6, 0x68, 0xcf, 0x9c, 0xe3, 0xc4, 0x84, 0x4f, 0xbd, 0x5b, 0x4b, 0x21,
    0x49, 0xb2, 0x81, 0x63, 0xf7, 0xe0, 0xd7, 0x53, 0xd6, 0x2b, 0x8e, 0xeb, 0x04, 0xc6, 0x87, 0xd0,
    0xeb, 0xd6, 0x6b, 0xc1, 0xcb, 0xc8, 0x74, 0xf8, 0xa3, 0x23, 0x06, 0x9a, 0x8e, 0x35, 0xba, 0xf4,
    0x37, 0xce, 0x8f, 0xb6, 0xc3, 0x6b, 0xd5, 0x82, 0x7a, 0xff, 0x73, 0x3b, 0x04, 0x1f, 0x91, 0x2a,
    0x0f, 0x1c, 0x40, 0x83, 0x8f, 0x84, 0x77, 0xb2, 0x19, 0xff, 0x4a, 0xde, 0x44, 0x9a, 0x00, 0x71,
    0xd6, 0x29, 0xd0, 0x92, 0x97, 0x6a, 0xb4, 0xd0, 0x29, 0xfe, 0x74, 0xc1, 0xff, 0xb8, 0x36, 0x76,
    0x48, 0x2a, 0x1f, 0xaf, 0x11, 0xa2, 0x64, 0x7f, 0x0d, 0x20, 0x8b, 0x26, 0x7c, 0xe0, 0xbf, 0x79,
    0x70, 0x6b, 0xc2, 0x77, 0xc5, 0x6a, 0x02, 0x32, 0xf1, 0x67, 0xe0, 0xb1, 0xa4, 0x47, 0xf9, 0x21,
    0x4b, 0xf7, 0xdf, 0x3f, 0xbe, 0x14, 0x8b, 0x42, 0x0d, 0xc0, 0x01, 0xf4, 0x30, 0x35, 0xc3, 0x94,
    0x6f, 0x3c, 0x28, 0x3b, 0x9c, 0x51, 0x3a, 0xdc, 0x8c, 0xaa, 0x9f, 0x2f, 0xb9, 0x63, 0x3f, 0x25,
    0xa5, 0xa9, 0x17, 0x88, 0x4b, 0x04, 0xf8, 0x27, 0xf1, 0xfd, 0x5f, 0xaa, 0x2f, 0x1a, 0x63, 0xfc,
    0x2b, 0xd8, 0xc6, 0xc0, 0x91, 0x03, 0x7d, 0x0f, 0x04, 0xc5, 0xfd, 0xc8, 0x4a, 0xe1, 0x88, 0x03,
    0x98, 0x10, 0x3d, 0x28, 0xf9, 0x9e, 0x53, 0x0e, 0xa7, 0xc7, 0xf1, 0xfb, 0x59, 0x1a, 0xf8, 0x63,
    0x68, 0x3b, 0xd9, 0xf6, 0xe2, 0x2e, 0xca, 0xcc, 0x0d, 0x14, 0x18, 0xa3, 0x19, 0x44, 0x0f, 0x3d,
    0x0f, 0x5b, 0xb7, 0x83, 0x3d, 0x14, 0x07, 0x51, 0xf9, 0x66, 0x96, 0x29, 0x8f, 0xb3, 0x2a, 0x5b,
};
static const uint8_t test_rsa2048_exponent[LIBMPQ_RSA_STRONG_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
};
static const uint8_t test_rsa2048_input[LIBMPQ_RSA_STRONG_SIZE] = {
    0x7a, 0x1a, 0x60, 0x32, 0x8a, 0x39, 0xe8, 0xe2, 0x99, 0x6b, 0x9a, 0xc7, 0xab, 0xef, 0xd3, 0x81,
    0xd6, 0x93, 0xf7, 0xfc, 0xd4, 0xb8, 0x66, 0x9c, 0x80, 0xab, 0xc2, 0x4c, 0x49, 0x61, 0x95, 0xc2,
    0xb4, 0x41, 0xb8, 0x87, 0xbd, 0xf6, 0xaa, 0x2a, 0x35, 0x14, 0xa9, 0xad, 0xf1, 0x8d, 0xa4, 0x17,
    0x71, 0xf0, 0x14, 0xef, 0x46, 0x8a, 0xb8, 0xdf, 0x0c, 0x65, 0x9b, 0x28, 0xc3, 0x03, 0x2c, 0x43,
    0x7e, 0xa4, 0x34, 0xdc, 0x4b, 0xa0, 0x3a, 0xa2, 0x67, 0xae, 0x5b, 0xd9, 0xc3, 0x81, 0x31, 0x51,
    0x8e, 0xb7, 0x6d, 0xcd, 0x1a, 0xe1, 0x03, 0x57, 0xfe, 0x54, 0x96, 0x3c, 0x67, 0xd6, 0x52, 0xc1,
    0x33, 0xd1, 0xd5, 0x63, 0x47, 0xe4, 0xae, 0x0f, 0xb1, 0x1a, 0x37, 0x77, 0xbf, 0x98, 0x55, 0x0a,
    0x5b, 0xb4, 0xf9, 0xa5, 0x4d, 0x10, 0xa5, 0x4b, 0x7e, 0x66, 0xac, 0x5c, 0x42, 0x8c, 0xa9, 0x42,
    0x69, 0xd4, 0xc4, 0xde, 0x14, 0x3a, 0x13, 0x49, 0xa5, 0x47, 0x97, 0xef, 0x6c, 0xc3, 0x07, 0x0f,
    0x42, 0xc7, 0x30, 0xcc, 0xac, 0xd4, 0x17, 0x15, 0x07, 0x29, 0x87, 0xb8, 0x4a, 0xf6, 0xac, 0x72,
    0xfa, 0x19, 0x87, 0xb7, 0x7b, 0x8b, 0x65, 0xd3, 0x59, 0xf0, 0x9e, 0x6f, 0x4c, 0xdd, 0x2a, 0x11,
    0x50, 0x2c, 0x9c, 0x32, 0x89, 0xed, 0x11, 0xaf, 0xe5, 0x09, 0xbe, 0x2b, 0x81, 0x37, 0x6f, 0x43,
    0xa7, 0xd7, 0xdf, 0x64, 0x1c, 0x03, 0xb9, 0x06, 0x52, 0xca, 0x9d, 0x6e, 0xd5, 0xa7, 0x12, 0x58,
    0xc0, 0x9a, 0xc0, 0x55, 0xba, 0x60, 0x86, 0x6d, 0x22, 0x83, 0x27, 0x32, 0x3f, 0xfa, 0xa6, 0x1a,
    0xd4, 0x6c, 0x50, 0x5e, 0xa2, 0xa4, 0xc1, 0x93, 0x33, 0x0f, 0x8a, 0x34, 0x4e, 0xe8, 0xb7, 0x13,
    0xca, 0x29, 0x6b, 0xee, 0xaa, 0xb6, 0xd5, 0x2f, 0x0e, 0xdd, 0xe0, 0xbc, 0xd7, 0xc8, 0xf6, 0x9c,
};
static const uint8_t test_rsa2048_expected[LIBMPQ_RSA_STRONG_SIZE] = {
    0x3e, 0x8e, 0x76, 0x67, 0x70, 0xde, 0x75, 0x9c, 0xe6, 0x79, 0xfa, 0x68, 0x1d, 0x79, 0x78, 0xc9,
    0xd4, 0x9b, 0x56, 0x09, 0x27, 0x2f, 0x40, 0xbc, 0x75, 0xc3, 0x53, 0xba, 0x8b, 0xc6, 0x15, 0x7c,
    0xc2, 0xc5, 0x1c, 0x2d, 0xf0, 0xdc, 0xc0, 0xc5, 0xc6, 0xa1, 0xb6, 0x89, 0x14, 0x06, 0x33, 0x9b,
    0xde, 0xa3, 0x24, 0xa1, 0xb1, 0x02, 0x5a, 0x0d, 0x29, 0x17, 0x72, 0x74, 0x82, 0x6a, 0xcf, 0x0b,
    0xf2, 0xc0, 0x84, 0x0f, 0x53, 0x7c, 0x46, 0x9c, 0xce, 0x2b, 0x7e, 0xfb, 0xc7, 0x47, 0x36, 0x5e,
    0x26, 0x98, 0xc2, 0x16, 0x89, 0x43, 0xf2, 0x81, 0x32, 0x33, 0x5f, 0x1f, 0xd5, 0x73, 0xdd, 0x59,
    0xaf, 0x83, 0xdd, 0x72, 0x1a, 0xaa, 0xf3, 0x3f, 0x22, 0x52, 0x6f, 0x48, 0xad, 0x2e, 0xad, 0x40,
    0xb7, 0x9f, 0x94, 0x30, 0xdd, 0xdb, 0x58, 0x30, 0xc2, 0xd9, 0x46, 0xfc, 0x31, 0xfd, 0x79, 0x75,
    0xfd, 0xf7, 0xf2, 0x20, 0x7a, 0xe3, 0x1e, 0xad, 0xed, 0x6f, 0x3a, 0x0e, 0x3b, 0xef, 0x1a, 0x10,
    0x8a, 0x8f, 0x5e, 0x2d, 0x5f, 0xfa, 0x01, 0x70, 0xd3, 0xae, 0x7c, 0x8a, 0x95, 0x62, 0x38, 0xb1,
    0x25, 0x77, 0x38, 0x67, 0x76, 0x82, 0xd9, 0xf7, 0xc9, 0x6d, 0x21, 0xa8, 0x5a, 0x0f, 0x9b, 0xfa,
    0xa3, 0xee, 0xa0, 0x10, 0x93, 0x14, 0xde, 0x5f, 0xe4, 0x24, 0x47, 0xf7, 0xd1, 0x0a, 0x2a, 0xcf,
    0x4a, 0x8b, 0x16, 0x6d, 0xda, 0x36, 0xce, 0x60, 0x65, 0x95, 0xcb, 0x3a, 0x9a, 0x81, 0xeb, 0xfc,
    0x74, 0x29, 0xeb, 0xac, 0x80, 0x2e, 0xb7, 0x81, 0x97, 0x01, 0x5a, 0x43, 0x4a, 0x06, 0x30, 0xd7,
    0x56, 0xce, 0x54, 0xdc, 0x51, 0x1c, 0xd0, 0x99, 0x88, 0x64, 0xfe, 0xb8, 0xff, 0x70, 0xff, 0xdb,
    0xcb, 0x06, 0x91, 0xaa, 0x50, 0xa4, 0x83, 0xb2, 0xec, 0x44, 0x94, 0xda, 0x82, 0xad, 0x97, 0xb1,
};

/*
 * Independently calculated with Python pow(input, d, modulus), using the
 * test-only strong key and the nontrivial public-operation KAT input.
 */
static const uint8_t test_rsa2048_private_expected[LIBMPQ_RSA_STRONG_SIZE] = {
    0x78, 0xc5, 0xbf, 0x14, 0x93, 0x66, 0xef, 0xd9, 0x93, 0x76, 0x8a, 0xf2, 0x95, 0xb6, 0x39, 0x2b,
    0x31, 0xa3, 0x5b, 0x69, 0xed, 0x26, 0xa3, 0x7c, 0xf7, 0x94, 0x1a, 0xfd, 0x0d, 0xba, 0xfe, 0x3b,
    0x98, 0x4e, 0x8a, 0xba, 0xd9, 0xf1, 0x22, 0x56, 0xf7, 0xbf, 0x7c, 0x31, 0x8c, 0xf4, 0x65, 0x6d,
    0x2c, 0x6c, 0x02, 0xdb, 0x10, 0xcb, 0x05, 0x6b, 0xb6, 0xe0, 0xc4, 0x01, 0xc2, 0xdb, 0x96, 0xf6,
    0xda, 0x54, 0xdd, 0xda, 0x3f, 0xd7, 0xfc, 0x4d, 0xf0, 0x6b, 0x3b, 0xfb, 0x88, 0x86, 0x59, 0x7f,
    0xc4, 0x45, 0xfa, 0xb9, 0x28, 0xe0, 0xb9, 0x15, 0x81, 0xf4, 0x03, 0x87, 0x7e, 0x1b, 0xc2, 0x40,
    0xd8, 0x50, 0xce, 0x6a, 0x07, 0xe6, 0xbf, 0x56, 0x56, 0xdf, 0x14, 0x7c, 0xb9, 0x52, 0x8e, 0xf8,
    0x84, 0x08, 0xc0, 0xf6, 0x02, 0x12, 0xab, 0x0f, 0x6f, 0x70, 0x80, 0xf9, 0xa9, 0x19, 0xae, 0x59,
    0x11, 0x44, 0x9c, 0xab, 0x32, 0xaf, 0xc6, 0x7b, 0xaa, 0xc8, 0xc2, 0x64, 0x0a, 0xcf, 0x2f, 0xa3,
    0x90, 0x98, 0xd1, 0x49, 0x12, 0x17, 0x06, 0xb9, 0xb9, 0x6e, 0x1b, 0xb6, 0xf6, 0xa2, 0x71, 0x78,
    0xf1, 0xbf, 0x3e, 0xd0, 0xb2, 0x05, 0x2e, 0x88, 0xf3, 0xc3, 0xfb, 0x0d, 0x20, 0xfd, 0xf0, 0x7e,
    0x36, 0xf9, 0x1c, 0x58, 0xb1, 0xcc, 0xc3, 0x77, 0x1e, 0x67, 0x93, 0x51, 0xa6, 0x5a, 0xa5, 0xb8,
    0x38, 0x86, 0xb6, 0x49, 0x94, 0x6d, 0x87, 0x23, 0x32, 0x4e, 0x50, 0xbe, 0x7c, 0x93, 0xe1, 0x4b,
    0xd6, 0xcf, 0x6e, 0xb1, 0xd6, 0x68, 0x34, 0x4b, 0x63, 0x23, 0x5f, 0xdb, 0x58, 0xbc, 0xb0, 0xcb,
    0x22, 0x23, 0xb6, 0xc1, 0x1e, 0x01, 0x72, 0x96, 0x1b, 0x0b, 0x73, 0xc1, 0xfa, 0x30, 0x5b, 0xf9,
    0x08, 0x1d, 0xe0, 0x35, 0x39, 0xcc, 0x2c, 0x6d, 0x39, 0x49, 0x2d, 0x37, 0x0f, 0x68, 0x83, 0x2f,
};

static int
test_rsa2048_public_vector(void)
{
    uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE];
    uint8_t output[LIBMPQ_RSA_STRONG_SIZE];
    uint8_t greater[LIBMPQ_RSA_STRONG_SIZE];
    memcpy(greater, test_rsa2048_modulus, sizeof(greater));
    greater[LIBMPQ_RSA_STRONG_SIZE - 1u] = (uint8_t)(greater[LIBMPQ_RSA_STRONG_SIZE - 1u] + 2u);
    memcpy(key, test_rsa2048_modulus, sizeof(test_rsa2048_modulus));
    memcpy(
        key + sizeof(test_rsa2048_modulus), test_rsa2048_exponent, sizeof(test_rsa2048_exponent)
    );
    TEST_CHECK(
        libmpq__rsa_strong_public_operation(key, test_rsa2048_input, output) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(memcmp(output, test_rsa2048_expected, sizeof(output)) == 0);
    TEST_CHECK(
        libmpq__rsa_strong_public_operation(key, test_rsa2048_modulus, output) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__rsa_strong_public_operation(key, greater, output) == LIBMPQ_ERROR_FORMAT);
    return 0;
}

static int
test_rsa2048_private_vector(void)
{
    uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE];
    uint8_t output[LIBMPQ_RSA_STRONG_SIZE];
    test_strong_signature_private_key(key);
    TEST_CHECK(
        libmpq__rsa_strong_private_operation(key, test_rsa2048_input, output) == LIBMPQ_SUCCESS
    );
    TEST_CHECK(memcmp(output, test_rsa2048_private_expected, sizeof(output)) == 0);
    return 0;
}
