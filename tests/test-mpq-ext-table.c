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

#include "../src/mpq-ext-table.h"
#include "test-mpq-helper.h"
#include <libmpq/mpq.h>

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
