/*
 *  mpq-ext-table.c -- MPQ extended-table envelope decoding.
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

#include "mpq-ext-table.h"
#include "mpq-bet.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-het.h"
#include <libmpq/mpq.h>
#include <stdlib.h>
#include <string.h>

int32_t
libmpq__ext_table_encode(
    const uint8_t *wire, size_t wire_size, bool compress, uint8_t **stored, size_t *stored_size
)
{
    uint32_t signature;
    uint32_t key;
    size_t payload_size;
    uint8_t *payload = NULL;
    uint8_t *output;
    int32_t result;

    if (stored != NULL)
        *stored = NULL;
    if (stored_size != NULL)
        *stored_size = 0;
    if (wire == NULL || stored == NULL || stored_size == NULL ||
        wire_size < LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE || wire_size > LIBMPQ_EXT_TABLE_MAX_SIZE)
        return LIBMPQ_ERROR_SIZE;
    signature = libmpq__load_le32(wire);
    if (libmpq__load_le32(wire + 8) != wire_size - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_FORMAT;
    if (signature == LIBMPQ_HET_SIGNATURE) {
        mpq_het_header_s header;
        result = libmpq__het_header_decode(wire, wire_size, &header);
        key = libmpq__crypto_hash_string("(hash table)", 0x300);
    } else if (signature == LIBMPQ_BET_SIGNATURE) {
        mpq_bet_header_s header;
        result = libmpq__bet_header_decode(wire, wire_size, &header);
        key = libmpq__crypto_hash_string("(block table)", 0x300);
    } else {
        return LIBMPQ_ERROR_FORMAT;
    }
    if (result != 0)
        return result;
    payload_size = wire_size - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
    if (compress) {
        uint8_t mask;

        /* Zlib framing is shared with v2; normal creation still rejects v3. */
        result = libmpq__compression_encode_sector(
            wire + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE, payload_size, LIBMPQ_COMPRESSION_ZLIB,
            LIBMPQ_ARCHIVE_VERSION_TWO, LIBMPQ_COMPRESSION_POLICY_STANDARD, &payload, &payload_size,
            &mask
        );
        if (result != 0)
            return result;
    }

    /* Equal-sized compressed data is ambiguous to the loader: store the original instead. */
    if (payload_size >= wire_size - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE) {
        free(payload);
        payload = NULL;
        payload_size = wire_size - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE;
    }
    if (payload_size > LIBMPQ_EXT_TABLE_MAX_SIZE - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE) {
        free(payload);
        return LIBMPQ_ERROR_SIZE;
    }
    output = malloc(LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + payload_size);
    if (output == NULL) {
        free(payload);
        return LIBMPQ_ERROR_MALLOC;
    }
    memcpy(output, wire, LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE);
    memcpy(
        output + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE,
        payload != NULL ? payload : wire + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE, payload_size
    );
    free(payload);

    /* The bounded payload fits uint32_t; trailing incomplete words remain unchanged. */
    libmpq__crypto_encrypt_block(
        output + LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE, (uint32_t)payload_size, key
    );
    *stored = output;
    *stored_size = LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE + payload_size;
    return 0;
}

/* Validate an already-decoded envelope; crypto/compression belong to its loader. */
int32_t
libmpq__ext_table_decode(
    const uint8_t *input, size_t size, uint32_t signature, mpq_ext_table_header_s *header
)
{
    mpq_ext_table_header_s decoded;

    if (input == NULL || header == NULL || size < LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    decoded.signature = libmpq__load_le32(input);
    decoded.version = libmpq__load_le32(input + 4);
    decoded.data_size = libmpq__load_le32(input + 8);
    if ((signature != LIBMPQ_HET_SIGNATURE && signature != LIBMPQ_BET_SIGNATURE) ||
        decoded.signature != signature || decoded.version != LIBMPQ_EXT_TABLE_VERSION)
        return LIBMPQ_ERROR_FORMAT;
    if (decoded.data_size > size - LIBMPQ_EXT_TABLE_HEADER_WIRE_SIZE)
        return LIBMPQ_ERROR_SIZE;
    *header = decoded;
    return 0;
}
