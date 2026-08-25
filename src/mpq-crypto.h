/*
 *  mpq-crypto.h -- internal hash, encryption and key-recovery helpers.
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

#ifndef LIBMPQ_CRYPTO_H
#define LIBMPQ_CRYPTO_H

#include <stdint.h>

/*
 * Hash a normalized MPQ name with one Storm hash-table phase. key is read
 * until its NUL terminator and remains caller-owned; offset selects the
 * phase-specific 256-entry table used by lookup or key derivation.
 */
uint32_t libmpq__crypto_hash_string(const char *key, uint32_t offset);

/*
 * Encrypt complete little-endian words in place with the MPQ stream cipher.
 * The buffer is caller-owned and may contain a trailing partial word, which
 * is intentionally left unchanged. The function returns success after the
 * word-oriented transformation has completed.
 */
int32_t libmpq__crypto_encrypt_block(uint8_t *in_buf, uint32_t in_size, uint32_t seed);

/* Decrypt an MPQ cipher block in place; trailing bytes shorter than one word remain unchanged. */
int32_t libmpq__crypto_decrypt_block(uint8_t *in_buf, uint32_t in_size, uint32_t seed);

/*
 * Recover a file encryption seed by testing known signatures in an encrypted
 * payload. key is written only when a supported signature and its companion
 * words identify a seed; insufficient or unrecognized data returns the
 * documented decryption error.
 */
int32_t libmpq__crypto_detect_file_key(
    const uint8_t *in_buf, uint32_t in_size, uint32_t file_size, uint32_t *key
);

/*
 * Recover the seed for an encrypted sector-offset table. The input table is
 * decrypted in place after a candidate is found, and key receives that seed;
 * malformed sizes, unknown seeds, and inconsistent offsets are reported to
 * the caller without transferring ownership of in_buf.
 */
int32_t libmpq__crypto_derive_block_table_seed(
    uint8_t *in_buf, uint32_t in_size, uint32_t block_size, uint32_t *key
);

#endif /* LIBMPQ_CRYPTO_H */
