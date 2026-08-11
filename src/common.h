/*
 *  common.h -- internal hash, crypt and decompression helpers.
 *
 *  Copyright (c) 2003-2011 Maik Broemme <mbroemme@libmpq.org>
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

#ifndef _COMMON_H
#define _COMMON_H

/* Hash an MPQ table name or file name with one of the Storm hash table offsets. */
uint32_t libmpq__hash_string(const char *key, uint32_t offset);

/* Encrypt a block in place using the MPQ block cipher. */
int32_t libmpq__encrypt_block(uint32_t *in_buf, uint32_t in_size, uint32_t seed);

/* Decrypt a block in place using the MPQ block cipher. */
int32_t libmpq__decrypt_block(uint32_t *in_buf, uint32_t in_size, uint32_t seed);

/* Recover a file block-table decryption seed from encrypted block offsets. */
int32_t libmpq__decrypt_key(uint8_t *in_buf, uint32_t in_size, uint32_t block_size, uint32_t *key);

/* Decompress one archive block according to its MPQ compression flags. */
int32_t libmpq__decompress_block(
    uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size,
    uint32_t compression_type
);

#endif /* _COMMON_H */
