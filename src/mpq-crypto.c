/*
 *  mpq-crypto.c -- internal hash, encryption and key-recovery helpers.
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

#include "mpq-crypto.h"
#include "mpq-crypt-buf.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include <libmpq/mpq.h>

#include <ctype.h>
#include <stdlib.h>

/* Hash an MPQ table name or file name with one of the Storm hash table offsets.
 * The caller supplies the table offset that selects the required hash phase,
 * and the returned value is used for MPQ lookup and encryption-key derivation. */
uint32_t
libmpq__crypto_hash_string(const char *key, uint32_t offset)
{

    /* Storm hashing starts with fixed seed values for every input string. */
    uint32_t seed1 = 0x7FED7FED;
    uint32_t seed2 = 0xEEEEEEEE;

    uint32_t ch;

    while (*key != 0) {
        ch = toupper(*key++);
        seed1 = crypt_buf[offset + ch] ^ (seed1 + seed2);
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
    }

    return seed1;
}

/* Encrypt a block in place using the MPQ block cipher and the supplied seed.
 * The routine serializes complete little-endian words and leaves any trailing
 * incomplete bytes untouched because MPQ encryption is word-oriented. */
int32_t
libmpq__crypto_encrypt_block(uint8_t *in_buf, uint32_t in_size, uint32_t seed)
{

    /* The cipher updates both seeds for every 32-bit word. */
    uint32_t seed2 = 0xEEEEEEEE;
    uint32_t ch;
    uint32_t value;

    /* The MPQ block cipher operates on complete 32-bit words. */
    for (; in_size >= 4; in_size -= 4) {
        seed2 += crypt_buf[0x400 + (seed & 0xFF)];
        value = libmpq__load_le32(in_buf);
        ch = value ^ (seed + seed2);
        seed = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
        seed2 = value + seed2 + (seed2 << 5) + 3;
        libmpq__store_le32(in_buf, ch);
        in_buf += sizeof(uint32_t);
    }

    /* Block encryption has no recoverable per-word error state. */
    return LIBMPQ_SUCCESS;
}

/* Decrypt a block in place using the MPQ block cipher and the supplied seed.
 * It reverses the word transformation performed by the matching encryptor,
 * so callers can reuse the same buffer without allocating a second copy. */
int32_t
libmpq__crypto_decrypt_block(uint8_t *in_buf, uint32_t in_size, uint32_t seed)
{

    /* The cipher updates both seeds for every 32-bit word. */
    uint32_t seed2 = 0xEEEEEEEE;
    uint32_t ch;

    /* The MPQ block cipher operates on complete 32-bit words. */
    for (; in_size >= 4; in_size -= 4) {
        seed2 += crypt_buf[0x400 + (seed & 0xFF)];
        ch = libmpq__load_le32(in_buf) ^ (seed + seed2);
        seed = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
        seed2 = ch + seed2 + (seed2 << 5) + 3;
        libmpq__store_le32(in_buf, ch);
        in_buf += sizeof(uint32_t);
    }

    /* Block decryption has no recoverable per-word error state. */
    return LIBMPQ_SUCCESS;
}

/* Recover a file seed by matching StormLib's small set of known file signatures.
 * The function tests the encrypted prefix against RIFF, executable, XML, and
 * MPQ signatures and writes the unique matching seed to the caller's output. */
int32_t
libmpq__crypto_detect_file_key(
    const uint8_t *in_buf, uint32_t in_size, uint32_t file_size, uint32_t *key
)
{
    static const uint32_t wave_magic = 0x46464952; /* "RIFF" */
    static const uint32_t exe_magic = 0x00905A4D;  /* "MZ" and DOS stub signature */
    static const uint32_t xml_magic = 0x6D783F3C;  /* "<?xm" */
    static const uint32_t mpq_magic = 0x1A51504D;  /* "MPQ\x1A" */
    uint32_t encrypted_first;
    uint32_t encrypted_second;
    uint32_t first;
    static const uint32_t known_first[] = { wave_magic, exe_magic, xml_magic, mpq_magic };
    const uint32_t known_second[] = { file_size - 8, 3, 0x6576206C, 32 }; /* "l ve" */
    uint32_t i;

    if (in_buf == NULL || key == NULL || in_size < 8) {
        return LIBMPQ_ERROR_DECRYPT;
    }

    encrypted_first = libmpq__load_le32(in_buf);
    encrypted_second = libmpq__load_le32(in_buf + sizeof(encrypted_first));

    for (i = 0; i < 0x100; i++) {
        uint32_t j;

        /* Invert the first cipher word for each known signature. */
        for (j = 0; j < sizeof(known_first) / sizeof(known_first[0]); j++) {
            uint32_t seed = (encrypted_first ^ known_first[j]) - 0xEEEEEEEE - crypt_buf[0x400 + i];
            uint32_t seed2;
            uint32_t next_seed;
            uint32_t second;

            if ((seed & 0xFF) != i) {
                continue;
            }

            first = known_first[j];
            seed2 = 0xEEEEEEEE + crypt_buf[0x400 + i];
            next_seed = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
            seed2 = first + seed2 + (seed2 << 5) + 3;
            seed2 += crypt_buf[0x400 + (next_seed & 0xFF)];
            second = encrypted_second ^ (next_seed + seed2);

            if (second == known_second[j]) {
                *key = seed;
                return LIBMPQ_SUCCESS;
            }
        }
    }

    return LIBMPQ_ERROR_DECRYPT;
}

/* Recover the per-file block-table seed from the first encrypted block offsets.
 * It checks all possible low-byte cipher candidates and accepts only a seed
 * whose first two decoded offsets describe a plausible sector-table layout. */
int32_t
libmpq__crypto_derive_block_table_seed(
    uint8_t *in_buf, uint32_t in_size, uint32_t block_size, uint32_t *key
)
{

    /* Candidate seed saved after matching the first known block offset. */
    uint32_t saveseed1;

    /* Intermediate value matching seed1 + seed2 for the first encrypted word. */
    uint32_t temp;
    uint32_t i = 0;

    /* Derive the first seed candidate from the known block-table size. */
    if (in_buf == NULL || key == NULL || in_size < 8) {
        return LIBMPQ_ERROR_DECRYPT;
    }

    temp = (libmpq__load_le32(in_buf) ^ in_size) - 0xEEEEEEEE;

    /* Try every possible low byte used to index the encryption table. */
    for (i = 0; i < 0x100; i++) {

        /* Candidate seeds and decrypted block offsets for this low byte. */
        uint32_t seed1;
        uint32_t seed2 = 0xEEEEEEEE;
        uint32_t ch;
        uint32_t ch2;

        /* The first encrypted value must decrypt to the block table size. */
        seed1 = temp - crypt_buf[0x400 + i];
        seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
        ch = libmpq__load_le32(in_buf) ^ (seed1 + seed2);

        if (ch != in_size) {
            continue;
        }

        /* Sector offset tables are encrypted with one less than the file seed. */
        saveseed1 = seed1 + 1;
        ch2 = ch;

        /*
         *  The second decrypted offset is unknown, but each compressed sector is at most
         *  0xFFFF bytes, so the distance from the first offset must fit in block_size.
         */
        seed1 = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
        seed2 = ch + seed2 + (seed2 << 5) + 3;
        seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
        ch = libmpq__load_le32(in_buf + sizeof(uint32_t)) ^ (seed1 + seed2);

        if ((ch - ch2) <= block_size) {
            *key = saveseed1;
            return LIBMPQ_SUCCESS;
        }
    }

    /* No candidate produced a plausible block offset sequence. */
    return LIBMPQ_ERROR_DECRYPT;
}
