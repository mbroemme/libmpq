/*
 *  test-mpq-bit.c -- Checked little-endian bit-access regression tests.
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

#include "../src/mpq-bit.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Independent bytes fix the little-endian convention, including cross-byte bits. */
static int
test_vectors(void)
{
    static const uint8_t wire[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    static const uint32_t widths[] = { 1, 8, 16, 32, 64 };
    static const uint64_t values[] = { 1, 1, 0x2301, 0x67452301, UINT64_C(0xefcdab8967452301) };
    uint8_t actual[sizeof(wire)] = { 0 };
    uint64_t value;
    size_t i;

    for (i = 0; i < sizeof(widths) / sizeof(widths[0]); i++) {
        TEST_CHECK(libmpq__bit_get(wire, sizeof(wire), 0, widths[i], &value) == 0);
        TEST_CHECK(value == values[i]);
    }
    TEST_CHECK(libmpq__bit_get(wire, sizeof(wire), 4, 16, &value) == 0);
    TEST_CHECK(value == 0x5230);
    TEST_CHECK(libmpq__bit_get(wire, sizeof(wire), 63, 1, &value) == 0 && value == 1);
    TEST_CHECK(libmpq__bit_set(actual, sizeof(actual), 0, 64, values[4]) == 0);
    TEST_CHECK(memcmp(actual, wire, sizeof(wire)) == 0);
    return 0;
}

/* Every supported boundary width round-trips without touching neighboring bits. */
static int
test_round_trips(void)
{
    static const uint32_t widths[] = { 1, 3, 7, 8, 9, 15, 16, 31, 32, 33, 63, 64 };
    uint8_t actual[10];
    uint64_t value;
    size_t i;
    uint32_t bit;

    for (i = 0; i < sizeof(widths) / sizeof(widths[0]); i++) {
        uint64_t source = UINT64_C(0x93abcdef12345679);

        if (widths[i] < 64)
            source &= (UINT64_C(1) << widths[i]) - 1;
        memset(actual, 0xa5, sizeof(actual));
        TEST_CHECK(libmpq__bit_set(actual, sizeof(actual), 3, widths[i], source) == 0);
        TEST_CHECK(libmpq__bit_get(actual, sizeof(actual), 3, widths[i], &value) == 0);
        TEST_CHECK(value == source);
        for (bit = 0; bit < sizeof(actual) * 8; bit++) {
            if (bit < 3 || bit >= 3 + widths[i])
                TEST_CHECK(((actual[bit / 8] >> (bit % 8)) & 1u) == ((0xa5u >> (bit % 8)) & 1u));
        }
    }
    memset(actual, 0xa5, sizeof(actual));
    TEST_CHECK(libmpq__bit_set(actual, sizeof(actual), 3, 9, 0x12f) == 0);
    TEST_CHECK(actual[0] == 0x7d && actual[1] == 0xa9 && actual[2] == 0xa5);
    return 0;
}

/* Empty fields, overflow, invalid widths, and failed writes are bounded safely. */
static int
test_bounds(void)
{
    uint8_t wire = 0xa5;
    uint64_t value = 99;
    size_t bytes = 99;

    TEST_CHECK(libmpq__bit_get(NULL, 0, 0, 0, &value) == 0 && value == 0);
    TEST_CHECK(libmpq__bit_set(NULL, 0, 0, 0, 0) == 0);
    TEST_CHECK(libmpq__bit_get(&wire, 1, 8, 0, &value) == 0);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 8, 0, 0) == 0);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 7, 1, 0) == 0 && wire == 0x25);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 7, 1, 1) == 0 && wire == 0xa5);
    TEST_CHECK(libmpq__bit_get(&wire, 1, 7, 2, &value) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(value == 0);
    TEST_CHECK(libmpq__bit_get(&wire, 1, UINT64_MAX, 1, &value) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_get(&wire, 1, UINT64_MAX - 3, 8, &value) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_get(&wire, 1, 9, 0, &value) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_get(&wire, 1, 0, 65, &value) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_get(NULL, 1, 0, 1, &value) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_get(&wire, 1, 0, 1, NULL) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 7, 2, 0) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_set(&wire, 1, UINT64_MAX, 1, 0) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 0, 65, 0) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 0, 1, 2) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_set(&wire, 1, 0, 0, 1) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__bit_set(NULL, 1, 0, 1, 0) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(wire == 0xa5);
    TEST_CHECK(libmpq__bit_bytes(3, 3, &bytes) == 0 && bytes == 2);
    TEST_CHECK(libmpq__bit_bytes(UINT64_MAX, 0, &bytes) == 0 && bytes == 0);
    TEST_CHECK(libmpq__bit_bytes(UINT64_MAX, 2, &bytes) == LIBMPQ_ERROR_SIZE && bytes == 0);
    TEST_CHECK(
        libmpq__bit_bytes(UINT64_MAX, 1, &bytes) ==
        (SIZE_MAX < UINT64_MAX / 8 + 1 ? LIBMPQ_ERROR_SIZE : 0)
    );
    TEST_CHECK(libmpq__bit_bytes(1, 1, NULL) == LIBMPQ_ERROR_SIZE);
    return 0;
}

/* Run the deterministic bit access regressions. */
int
main(void)
{
    TEST_CHECK(test_vectors() == 0);
    TEST_CHECK(test_round_trips() == 0);
    TEST_CHECK(test_bounds() == 0);
    return 0;
}
