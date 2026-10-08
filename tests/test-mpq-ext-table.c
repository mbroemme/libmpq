/*
 *  test-mpq-ext-table.c -- MPQ extended-table envelope regression tests.
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

#include "../src/mpq-compression.h"
#include "../src/mpq-crypto.h"
#include "../src/mpq-endian.h"
#include "../src/mpq-ext-table-builder.h"
#include "../src/mpq-ext-table.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Independent fixed vectors calculated from the deterministic table recipe/cipher. */
static const uint8_t encrypted_het[] = { 0x48, 0x45, 0x54, 0x1a, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00,
                                         0x00, 0x00, 0xe8, 0xcf, 0x3c, 0x86, 0xfc, 0x26, 0xcd, 0x67,
                                         0x0a, 0x91, 0x90, 0x60, 0x97, 0x14, 0xb2, 0x16, 0xf2, 0xac,
                                         0x0f, 0x7c, 0xa8, 0xef, 0xde, 0x37, 0xab, 0x7e, 0xe8, 0xbd,
                                         0xc2, 0x18, 0xd2, 0xa4, 0xa4, 0x4e, 0xb8, 0x36 };
static const uint8_t encrypted_bet[] = {
    0x42, 0x45, 0x54, 0x1a, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0xc7, 0x67, 0x48,
    0x3d, 0xcd, 0xd3, 0x08, 0xca, 0x7f, 0xc0, 0x35, 0xf8, 0xf4, 0x2c, 0x34, 0x68, 0x8d, 0xb3,
    0xba, 0x32, 0x29, 0x42, 0xb4, 0x70, 0x38, 0x4e, 0x45, 0x6c, 0xb6, 0xae, 0x9a, 0x7e, 0x4e,
    0x2a, 0x4a, 0x8c, 0x10, 0x2e, 0x3b, 0x8f, 0x83, 0xd7, 0xa9, 0x4b, 0xdf, 0xe4, 0x07, 0xb8,
    0xae, 0x47, 0x0d, 0x9e, 0xec, 0xd6, 0x61, 0xe9, 0x7c, 0x59, 0xf6, 0x4f, 0xfe, 0x3b, 0x6d,
    0xc8, 0x09, 0xa3, 0x1d, 0xab, 0x85, 0x26, 0xf5, 0x05, 0x14, 0xbe, 0xa2, 0xa9
};

/* Mirror the loader's decrypt/decompress path without adding production archive I/O. */
static int
encoding_roundtrip(const uint8_t *wire, size_t size, bool compress, int smaller)
{
    uint8_t *stored = NULL;
    uint8_t *again = NULL;
    uint8_t *decoded;
    size_t stored_size;
    size_t again_size;
    size_t payload_size = size - 12;
    size_t stored_payload;
    uint32_t signature = libmpq__load_le32(wire);
    uint32_t key = signature == LIBMPQ_HET_SIGNATURE ? 0xc3af3770u : 0xec83b3a3u;
    mpq_het_header_s het;
    mpq_bet_header_s bet;

    TEST_CHECK(size >= 12 && size <= LIBMPQ_EXT_TABLE_MAX_SIZE);
    TEST_CHECK(libmpq__ext_table_encode(wire, size, compress, &stored, &stored_size) == 0);
    TEST_CHECK(smaller ? stored_size < size : stored_size == size);
    TEST_CHECK(memcmp(stored, wire, 12) == 0);
    TEST_CHECK(memcmp(stored + 12, wire + 12, stored_size - 12) != 0);
    TEST_CHECK(libmpq__ext_table_encode(wire, size, compress, &again, &again_size) == 0);
    TEST_CHECK(again_size == stored_size && memcmp(stored, again, stored_size) == 0);
    free(again);
    stored_payload = stored_size - 12;
    if (!compress && size % 4 != 0)
        TEST_CHECK(memcmp(stored + size - size % 4, wire + size - size % 4, size % 4) == 0);

    decoded = malloc(size * 2);
    if (decoded == NULL) {
        free(stored);
        return 1;
    }
    memcpy(decoded, wire, 12);
    /* Wrong key must fail structural parsing (or compressed-stream decoding). */
    memcpy(decoded + 12, stored + 12, stored_payload);
    libmpq__crypto_decrypt_block(decoded + 12, (uint32_t)stored_payload, key ^ 1u);
    if (stored_size == size) {
        TEST_CHECK(
            signature == LIBMPQ_HET_SIGNATURE ? libmpq__het_header_decode(decoded, size, &het) != 0
                                              : libmpq__bet_header_decode(decoded, size, &bet) != 0
        );
    } else {
        int32_t result;
        memcpy(decoded + size, wire, 12);
        result = libmpq__compression_decompress_table(
            decoded + 12, (uint32_t)stored_payload, decoded + size + 12, (uint32_t)payload_size,
            LIBMPQ_ARCHIVE_VERSION_THREE
        );
        TEST_CHECK(
            result != (int32_t)payload_size ||
            (signature == LIBMPQ_HET_SIGNATURE
                 ? libmpq__het_header_decode(decoded + size, size, &het) != 0
                 : libmpq__bet_header_decode(decoded + size, size, &bet) != 0)
        );
    }
    libmpq__crypto_decrypt_block(stored + 12, (uint32_t)stored_payload, key);
    if (stored_size < size) {
        TEST_CHECK(stored[12] == LIBMPQ_COMPRESSION_ZLIB);
        TEST_CHECK(
            libmpq__compression_decompress_table(
                stored + 12, (uint32_t)stored_payload, decoded + 12, (uint32_t)payload_size,
                LIBMPQ_ARCHIVE_VERSION_THREE
            ) == (int32_t)payload_size
        );
    } else {
        memcpy(decoded + 12, stored + 12, payload_size);
    }
    TEST_CHECK(memcmp(decoded, wire, size) == 0);
    TEST_CHECK(
        signature == LIBMPQ_HET_SIGNATURE ? libmpq__het_header_decode(decoded, size, &het) == 0
                                          : libmpq__bet_header_decode(decoded, size, &bet) == 0
    );
    free(decoded);
    free(stored);
    return 0;
}

static int
encoder_failure(const uint8_t *wire, size_t size)
{
    uint8_t sentinel = 0;
    uint8_t *stored = &sentinel;
    size_t stored_size = SIZE_MAX;
    TEST_CHECK(libmpq__ext_table_encode(wire, size, true, &stored, &stored_size) < 0);
    TEST_CHECK(stored == NULL && stored_size == 0);
    return 0;
}

static int
test_encoding(void)
{
    mpq_het_builder_s het = { 0 };
    mpq_bet_builder_s bet = { 0 };
    mpq_ext_table_file_s files[64];
    char names[64][24];
    uint8_t *wire = NULL;
    uint8_t *stored = NULL;
    size_t size;
    size_t stored_size;
    size_t i;
    unsigned residues = 0;
    TEST_CHECK(libmpq__ext_tables_build(NULL, 0, &het, &bet) == 0);
    for (i = 0; i < 2; ++i) {
        const uint8_t *expected = i == 0 ? encrypted_het : encrypted_bet;
        size_t expected_size = i == 0 ? sizeof(encrypted_het) : sizeof(encrypted_bet);
        TEST_CHECK(
            i == 0 ? libmpq__het_serialize(&het, &wire, &size) == 0
                   : libmpq__bet_serialize(&bet, &wire, &size) == 0
        );
        TEST_CHECK(libmpq__ext_table_encode(wire, size, false, &stored, &stored_size) == 0);
        TEST_CHECK(stored_size == expected_size && memcmp(stored, expected, stored_size) == 0);
        free(stored);
        TEST_CHECK(encoding_roundtrip(wire, size, false, 0) == 0);
        TEST_CHECK(encoding_roundtrip(wire, size, true, 1) == 0);
        TEST_CHECK(encoder_failure(wire, size - 1) == 0);
        TEST_CHECK(encoder_failure(wire, LIBMPQ_EXT_TABLE_MAX_SIZE + 1u) == 0);
        wire[0] ^= 1;
        TEST_CHECK(encoder_failure(wire, size) == 0);
        wire[0] ^= 1;
        wire[4] = 2;
        TEST_CHECK(encoder_failure(wire, size) == 0);
        wire[4] = 1;
        wire[12] ^= 1;
        TEST_CHECK(encoder_failure(wire, size) == 0);
        wire[12] ^= 1;
        TEST_CHECK(
            libmpq__ext_table_encode(wire, size, false, NULL, &stored_size) == LIBMPQ_ERROR_SIZE &&
            stored_size == 0
        );
        TEST_CHECK(
            libmpq__ext_table_encode(wire, size, false, &stored, NULL) == LIBMPQ_ERROR_SIZE &&
            stored == NULL
        );
        free(wire);
    }
    TEST_CHECK(encoder_failure(NULL, 12) == 0);
    TEST_CHECK(encoder_failure(encrypted_het, 11) == 0);
    for (i = 0; i < 64; ++i) {
        snprintf(names[i], sizeof(names[i]), "synthetic-%zu", i);
        files[i] = (mpq_ext_table_file_s){ names[i], i * 1024, i + 1, i + 2, 0x80000000u };
    }
    for (i = 1; i <= 64; ++i) {
        TEST_CHECK(libmpq__ext_tables_build(files, i, &het, &bet) == 0);
        TEST_CHECK(libmpq__bet_serialize(&bet, &wire, &size) == 0);
        residues |= 1u << (size % 4);
        TEST_CHECK(encoding_roundtrip(wire, size, false, 0) == 0);
        if (i == 64)
            TEST_CHECK(encoding_roundtrip(wire, size, true, 1) == 0);
        free(wire);
    }
    TEST_CHECK(residues == 15);
    TEST_CHECK(libmpq__het_serialize(&het, &wire, &size) == 0);
    TEST_CHECK(encoding_roundtrip(wire, size, true, 1) == 0);
    free(wire);
    libmpq__het_builder_free(&het);
    libmpq__bet_builder_free(&bet);
    return 0;
}

/* Valid geometry with deterministic high-entropy slot/index bytes. */
static int
test_compression_fallback(void)
{
    uint32_t counts[2] = { 24, 64 };
    size_t c;
    for (c = 0; c < 2; ++c) {
        uint8_t wire[364] = { 0 };
        uint8_t compressed[512];
        uint32_t n = counts[c];
        uint32_t fields[11] = {
            LIBMPQ_HET_SIGNATURE, 1, 32 + 5 * n, 32 + 5 * n, n, n, 64, 32, 0, 32, 4 * n
        };
        uint32_t seed = 0x12345678u;
        size_t i;
        size_t size = 44 + 5 * n;
        unsigned long length = sizeof(compressed);
        for (i = 0; i < 11; ++i)
            libmpq__store_le32(wire + 4 * i, fields[i]);
        for (i = 44; i < size; ++i) {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            wire[i] = (uint8_t)seed;
        }
        TEST_CHECK(
            compress2(compressed, &length, wire + 12, size - 12, Z_DEFAULT_COMPRESSION) == Z_OK
        );
        TEST_CHECK(c == 0 ? length + 1 == size - 12 : length + 1 > size - 12);
        TEST_CHECK(encoding_roundtrip(wire, size, true, 0) == 0);
    }
    return 0;
}

/* The explicit envelope vector fixes signature bytes and data-size semantics. */
int
main(void)
{
    static const uint8_t wire[] = { 'H', 'E', 'T', 0x1a, 1, 0, 0, 0, 3, 0, 0, 0, 0xab, 0xcd, 0xef };
    static const uint8_t bad_version[] = { 'H', 'E', 'T', 0x1a, 2, 0, 0, 0, 0, 0, 0, 0 };
    static const uint8_t oversized[] = { 'B', 'E', 'T', 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t empty[] = { 'B', 'E', 'T', 0x1a, 1, 0, 0, 0, 0, 0, 0, 0 };
    mpq_ext_table_header_s header = { 0 };
    size_t i;
    TEST_CHECK(test_encoding() == 0);
    TEST_CHECK(test_compression_fallback() == 0);

    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_HET_SIGNATURE, &header) == 0);
    TEST_CHECK(header.signature == 0x1a544548 && header.version == 1 && header.data_size == 3);
    TEST_CHECK(libmpq__ext_table_decode(empty, sizeof(empty), LIBMPQ_BET_SIGNATURE, &header) == 0);
    TEST_CHECK(header.data_size == 0);
    for (i = 0; i < sizeof(wire); i++)
        TEST_CHECK(libmpq__ext_table_decode(wire, i, LIBMPQ_HET_SIGNATURE, &header) != 0);
    TEST_CHECK(
        libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_BET_SIGNATURE, &header) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__ext_table_decode(wire, sizeof(wire), 0, &header) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__ext_table_decode(bad_version, sizeof(bad_version), LIBMPQ_HET_SIGNATURE, &header) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(
        libmpq__ext_table_decode(oversized, sizeof(oversized), LIBMPQ_BET_SIGNATURE, &header) ==
        LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__ext_table_decode(NULL, sizeof(wire), LIBMPQ_HET_SIGNATURE, &header) ==
        LIBMPQ_ERROR_SIZE
    );
    TEST_CHECK(
        libmpq__ext_table_decode(wire, sizeof(wire), LIBMPQ_HET_SIGNATURE, NULL) ==
        LIBMPQ_ERROR_SIZE
    );
    return 0;
}
