/*
 *  test-mpq-compression.c -- libmpq regression tests.
 *
 *  Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
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

/* Exercise raw, zlib, bzip2, and invalid compression paths. */
#include "mpq-compression.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Enumerate policies independently of the production encoder's validation. */
static int
test_policies(void)
{
    uint32_t version;
    uint32_t mask;
    libmpq_compression_policy_t policy;

    TEST_CHECK(sizeof(libmpq_compression_policy_t) == sizeof(int32_t));
    TEST_CHECK(libmpq__archive_compression_allowed(1, 0, INT32_MIN) == 0);
    TEST_CHECK(libmpq__archive_compression_allowed(1, 0, INT32_MAX) == 0);

    for (version = 0; version <= LIBMPQ_ARCHIVE_VERSION_THREE; ++version) {
        for (policy = 0; policy <= 1; ++policy) {
            for (mask = 0; mask < 512; ++mask) {
                int expected = (mask & ~0xfbU) == 0 && (mask & 0xc0U) != 0xc0U &&
                               !((mask & 0x20U) && (mask & 0xc0U));
                if (version >= LIBMPQ_ARCHIVE_VERSION_TWO) {
                    expected = expected && (mask & 0x12U) != 0x12U;
                    if (policy == LIBMPQ_COMPRESSION_POLICY_STANDARD)
                        expected = mask == 0 || mask == 0x02 || mask == 0x08 || mask == 0x10 ||
                                   mask == 0x20 || mask == 0x22 || mask == 0x30 || mask == 0x41 ||
                                   mask == 0x81;
                    if (mask == LIBMPQ_COMPRESSION_LZMA)
                        expected = 1;
                }
                TEST_CHECK(libmpq__archive_compression_allowed(version, mask, policy) == expected);
            }
        }
    }
    TEST_CHECK(libmpq__archive_compression_allowed(3, 0, 0) == 0);
    TEST_CHECK(libmpq__archive_compression_allowed(UINT32_MAX, 0, 0) == 0);
    TEST_CHECK(libmpq__archive_compression_allowed(1, UINT32_MAX, 0) == 0);
    TEST_CHECK(libmpq__archive_compression_allowed(1, 0, -1) == 0);
    TEST_CHECK(libmpq__archive_compression_allowed(1, 0, 2) == 0);
    return 0;
}

/* Writer flags select policy; normal readers reopen both policies identically. */
static int
test_policy_writer(uint32_t version, libmpq_compression_policy_t policy, uint32_t storage_flags)
{
    static const uint32_t masks[] = { 0x01, 0x02,  0x08, 0x10, 0x03, 0x0a, 0x12,
                                      0x13, 0x100, 0x20, 0x22, 0x30, 0x21, 0x28,
                                      0x32, 0x60,  0xa0, 0x61, 0xa1, 0x04, 0x120 };
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s create = { version, 32, 4096, 0, 0 };
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, 0, 0, 0, 0 };
    uint8_t input[8192];
    uint8_t *output = NULL;
    size_t size;
    size_t i;
    uint32_t number;
    libmpq__off_t packed_size;
    char path[128];
    char name[32];
    int32_t result;

    if (policy == LIBMPQ_COMPRESSION_POLICY_EXTENDED)
        create.flags = LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED;
    if (storage_flags & LIBMPQ_FILE_FLAG_SINGLE)
        create.sector_size = 16384;
    options.flags |= storage_flags;
    test_sparse_payload(input, sizeof(input));
    TEST_CHECK(test_temp_path(path, sizeof(path), "compression-policy") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &create) == 0);
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); ++i) {
        TEST_CHECK(snprintf(name, sizeof(name), "method-%u", masks[i]) > 0);
        options.compression_first = masks[i];
        options.compression_next = LIBMPQ_COMPRESSION_ZLIB;
        if (!libmpq__archive_compression_allowed(version, masks[i], policy) ||
            ((storage_flags & LIBMPQ_FILE_FLAG_SINGLE) && (masks[i] & 0xc0u))) {
            TEST_CHECK(
                libmpq__archive_add_data(archive, name, input, sizeof(input), &options) ==
                LIBMPQ_ERROR_FORMAT
            );
            options.compression_first = LIBMPQ_COMPRESSION_ZLIB;
            options.compression_next = masks[i];
            TEST_CHECK(
                libmpq__archive_add_data(archive, name, input, sizeof(input), &options) ==
                LIBMPQ_ERROR_FORMAT
            );
        } else {
            options.compression_next = masks[i];
            TEST_CHECK(
                libmpq__archive_add_data(archive, name, input, sizeof(input), &options) == 0
            );
        }
    }
    result = libmpq__archive_close(archive);
    archive = NULL;
    TEST_CHECK(result == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); ++i) {
        mpq_stream_s *stream = NULL;
        libmpq__off_t transferred;
        if (!libmpq__archive_compression_allowed(version, masks[i], policy) ||
            ((storage_flags & LIBMPQ_FILE_FLAG_SINGLE) && (masks[i] & 0xc0u)))
            continue;
        TEST_CHECK(snprintf(name, sizeof(name), "method-%u", masks[i]) > 0);
        TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
        TEST_CHECK(libmpq__file_size_packed(archive, number, &packed_size) == 0);
        TEST_CHECK(packed_size < (libmpq__off_t)sizeof(input));
        TEST_CHECK(libmpq__stream_open_name(archive, name, &stream) == 0);
        output = malloc(sizeof(input));
        TEST_CHECK(output != NULL);
        result = libmpq__stream_read(stream, output, sizeof(input), &transferred);
        if (result != 0)
            fprintf(
                stderr, "codec read: version=%u policy=%d flags=%x mask=%x error=%d\n", version,
                policy, storage_flags, masks[i], result
            );
        TEST_CHECK(result == 0);
        size = (size_t)transferred;
        TEST_CHECK(size == sizeof(input) && memcmp(output, input, size) == 0);
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        free(output);
        output = NULL;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}

/* Compare v2/v3 codec output and fallback at sector-size boundaries. */
static int
test_v2_v3_sector_semantics(void)
{
    static const uint32_t masks[] = { 0,    0x01, 0x02, 0x08, 0x10,  0x20, 0x22,
                                      0x30, 0x03, 0x0a, 0x12, 0x100, 0x41, 0x81 };
    static const size_t lengths[] = { 0, 1, 31, 511, 512, 513, 4096 };
    uint8_t input[4096];
    uint8_t decoded[4096];
    unsigned int pattern;
    size_t m;
    size_t n;
    libmpq_compression_policy_t policy;
    for (pattern = 0; pattern < 2; ++pattern) {
        uint32_t state = 1;
        for (n = 0; n < sizeof(input); ++n) {
            state = state * 1664525u + 1013904223u;
            input[n] = pattern == 0 ? 0 : (uint8_t)(state >> 24);
        }
        for (policy = LIBMPQ_COMPRESSION_POLICY_STANDARD;
             policy <= LIBMPQ_COMPRESSION_POLICY_EXTENDED; ++policy) {
            for (m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
                int allowed =
                    libmpq__compression_allowed(LIBMPQ_ARCHIVE_VERSION_TWO, masks[m], policy);
                TEST_CHECK(
                    allowed ==
                    libmpq__compression_allowed(LIBMPQ_ARCHIVE_VERSION_THREE, masks[m], policy)
                );
                for (n = 0; n < sizeof(lengths) / sizeof(lengths[0]); ++n) {
                    uint8_t *packed[2] = { NULL, NULL };
                    uint8_t emitted[2] = { 0, 0 };
                    size_t sizes[2] = { 0, 0 };
                    unsigned int v;
                    for (v = 0; v < 2; ++v) {
                        uint32_t version = LIBMPQ_ARCHIVE_VERSION_TWO + v;
                        int32_t result = libmpq__compression_encode_sector(
                            input, lengths[n], masks[m], version, policy, &packed[v], &sizes[v],
                            &emitted[v]
                        );
                        TEST_CHECK(result == (allowed ? 0 : LIBMPQ_ERROR_FORMAT));
                        if (!allowed)
                            continue;
                        if (masks[m] == LIBMPQ_COMPRESSION_LZMA && emitted[v] != 0)
                            TEST_CHECK(emitted[v] == 0x12);
                        else
                            TEST_CHECK(libmpq__compression_allowed(version, emitted[v], policy));
                        if (emitted[v] == 0) {
                            TEST_CHECK(sizes[v] == lengths[n]);
                            TEST_CHECK(memcmp(packed[v], input, lengths[n]) == 0);
                        } else {
                            TEST_CHECK(sizes[v] < lengths[n] && packed[v][0] == emitted[v]);
                            TEST_CHECK(
                                libmpq__compression_decompress_multi(
                                    packed[v], (uint32_t)sizes[v], decoded, (uint32_t)lengths[n],
                                    version
                                ) == (int32_t)lengths[n]
                            );
                            if ((masks[m] & 0xc0u) == 0)
                                TEST_CHECK(memcmp(decoded, input, lengths[n]) == 0);
                        }
                    }
                    if (allowed) {
                        TEST_CHECK(emitted[0] == emitted[1] && sizes[0] == sizes[1]);
                        TEST_CHECK(memcmp(packed[0], packed[1], sizes[0]) == 0);
                    }
                    free(packed[0]);
                    free(packed[1]);
                }
            }
        }
    }
    return 0;
}

/* Create one compressed entry and verify its complete round trip. */
static int
test_round_trip(
    const char *path, const char *name, const uint8_t *payload, size_t size, uint32_t compression
)
{
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, compression, compression, 0, 0 };
    uint8_t *output = NULL;
    size_t output_size;
    uint32_t number;

    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, name, payload, size, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == size && memcmp(output, payload, size) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

/* Exercise allowed compression selections and rejected codec masks. */
int
main(void)
{
    char path[128];
    uint8_t data[20000];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s invalid = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE, 0, 0, 0,
                                   0 };

    TEST_CHECK(test_temp_path(path, sizeof(path), "compression") == 0);
    TEST_CHECK(test_policies() == 0);
    TEST_CHECK(test_v2_v3_sector_semantics() == 0);
    TEST_CHECK(
        test_policy_writer(LIBMPQ_ARCHIVE_VERSION_ONE, LIBMPQ_COMPRESSION_POLICY_STANDARD, 0) == 0
    );
    TEST_CHECK(
        test_policy_writer(LIBMPQ_ARCHIVE_VERSION_ONE, LIBMPQ_COMPRESSION_POLICY_EXTENDED, 0) == 0
    );
    TEST_CHECK(
        test_policy_writer(LIBMPQ_ARCHIVE_VERSION_TWO, LIBMPQ_COMPRESSION_POLICY_STANDARD, 0) == 0
    );
    TEST_CHECK(
        test_policy_writer(LIBMPQ_ARCHIVE_VERSION_TWO, LIBMPQ_COMPRESSION_POLICY_EXTENDED, 0) == 0
    );
    TEST_CHECK(
        test_policy_writer(LIBMPQ_ARCHIVE_VERSION_THREE, LIBMPQ_COMPRESSION_POLICY_STANDARD, 0) == 0
    );
    TEST_CHECK(
        test_policy_writer(LIBMPQ_ARCHIVE_VERSION_THREE, LIBMPQ_COMPRESSION_POLICY_EXTENDED, 0) == 0
    );
    for (uint32_t version = LIBMPQ_ARCHIVE_VERSION_ONE; version <= LIBMPQ_ARCHIVE_VERSION_THREE;
         ++version) {
        for (libmpq_compression_policy_t policy = LIBMPQ_COMPRESSION_POLICY_STANDARD;
             policy <= LIBMPQ_COMPRESSION_POLICY_EXTENDED; ++policy) {
            TEST_CHECK(test_policy_writer(version, policy, LIBMPQ_FILE_FLAG_ENCRYPTED) == 0);
            TEST_CHECK(test_policy_writer(version, policy, LIBMPQ_FILE_FLAG_SINGLE) == 0);
            TEST_CHECK(
                test_policy_writer(
                    version, policy, LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED
                ) == 0
            );
        }
    }
    memset(data, 'C', sizeof(data));
    TEST_CHECK(test_round_trip(path, "zlib", data, sizeof(data), LIBMPQ_COMPRESSION_ZLIB) == 0);
    remove(path);
    TEST_CHECK(test_round_trip(path, "bzip2", data, sizeof(data), LIBMPQ_COMPRESSION_BZIP2) == 0);
    remove(path);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "invalid", data, sizeof(data), &invalid) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}
