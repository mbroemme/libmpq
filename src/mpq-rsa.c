/*
 *  mpq-rsa.c -- private fixed-width legacy RSA arithmetic.
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

#include "mpq-rsa.h"
#include <libmpq/mpq.h>
#include <string.h>

/* Little-endian base-256 limbs avoid native word size and alignment assumptions.
 * The weak private operation uses fixed iterations and mask selection. The public
 * operation deliberately skips leading zero public-exponent bits for efficiency.
 * This legacy implementation is not a modern cryptographic API. */
static void
add_mod(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *n, size_t size)
{
    uint8_t sum[LIBMPQ_RSA_MAX_SIZE];
    uint8_t reduced[LIBMPQ_RSA_MAX_SIZE];
    uint32_t carry = 0;
    uint32_t borrow = 0;
    uint32_t mask;
    size_t i;
    for (i = 0; i < size; ++i) {
        uint32_t value = (uint32_t)a[i] + b[i] + carry;
        sum[i] = (uint8_t)value;
        carry = value >> 8;
    }
    for (i = 0; i < size; ++i) {
        uint32_t value = (uint32_t)sum[i] - n[i] - borrow;
        reduced[i] = (uint8_t)value;
        borrow = value >> 31;
    }
    mask = 0u - (carry | (borrow ^ 1u));
    for (i = 0; i < size; ++i)
        out[i] = (uint8_t)((reduced[i] & mask) | (sum[i] & ~mask));
    libmpq__rsa_clear(sum, sizeof(sum));
    libmpq__rsa_clear(reduced, sizeof(reduced));
}

static void
multiply(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *n, size_t size)
{
    uint8_t result[LIBMPQ_RSA_MAX_SIZE] = { 0 };
    uint8_t sum[LIBMPQ_RSA_MAX_SIZE];
    size_t bit;
    size_t i;
    for (bit = (size * 8); bit-- > 0;) {
        uint32_t mask = 0u - ((b[bit / 8] >> (bit % 8)) & 1u);
        add_mod(result, result, result, n, size);
        add_mod(sum, result, a, n, size);
        for (i = 0; i < size; ++i)
            result[i] = (uint8_t)((sum[i] & mask) | (result[i] & ~mask));
    }
    memcpy(out, result, size);
    libmpq__rsa_clear(result, sizeof(result));
    libmpq__rsa_clear(sum, sizeof(sum));
}

/* A raw key is equal-width big-endian n || exponent components. A full-width
 * odd modulus and an odd exponent in [3,n) are required. */
int32_t
libmpq__rsa_public_key_validate(const uint8_t *key, size_t key_size, size_t modulus_size)
{
    uint8_t small = 0;
    size_t i;
    if (key == NULL || modulus_size == 0 || modulus_size > LIBMPQ_RSA_MAX_SIZE ||
        key_size != 2u * modulus_size || !(key[0] & 0x80) || !(key[modulus_size - 1] & 1) ||
        !(key[key_size - 1] & 1))
        return LIBMPQ_ERROR_FORMAT;
    for (i = modulus_size; i < key_size - 1; ++i)
        small |= key[i];
    if ((small == 0 && key[key_size - 1] < 3) || memcmp(key + modulus_size, key, modulus_size) >= 0)
        return LIBMPQ_ERROR_FORMAT;
    return 0;
}

int32_t
libmpq__rsa_key_validate(const uint8_t *key, size_t size)
{
    return libmpq__rsa_public_key_validate(key, size, LIBMPQ_RSA_SIZE);
}

int32_t
libmpq__rsa_operation(
    const uint8_t key[LIBMPQ_RSA_KEY_SIZE], const uint8_t input[LIBMPQ_RSA_SIZE],
    uint8_t output[LIBMPQ_RSA_SIZE]
)
{
    uint8_t n[LIBMPQ_RSA_SIZE];
    uint8_t base[LIBMPQ_RSA_SIZE];
    uint8_t result[LIBMPQ_RSA_SIZE] = { 1 };
    uint8_t product[LIBMPQ_RSA_SIZE];
    size_t i;
    size_t bit;
    if (memcmp(input, key, LIBMPQ_RSA_SIZE) >= 0)
        return LIBMPQ_ERROR_FORMAT;
    for (i = 0; i < LIBMPQ_RSA_SIZE; ++i) {
        n[i] = key[(LIBMPQ_RSA_SIZE - 1) - i];
        base[i] = input[(LIBMPQ_RSA_SIZE - 1) - i];
    }
    for (bit = 0; bit < (LIBMPQ_RSA_SIZE * 8); ++bit) {
        uint32_t mask = 0u - ((key[LIBMPQ_RSA_SIZE + bit / 8] >> (7 - bit % 8)) & 1u);
        multiply(result, result, result, n, LIBMPQ_RSA_SIZE);
        multiply(product, result, base, n, LIBMPQ_RSA_SIZE);
        for (i = 0; i < LIBMPQ_RSA_SIZE; ++i)
            result[i] = (uint8_t)((product[i] & mask) | (result[i] & ~mask));
    }
    for (i = 0; i < LIBMPQ_RSA_SIZE; ++i)
        output[i] = result[(LIBMPQ_RSA_SIZE - 1) - i];
    libmpq__rsa_clear(n, sizeof(n));
    libmpq__rsa_clear(base, sizeof(base));
    libmpq__rsa_clear(result, sizeof(result));
    libmpq__rsa_clear(product, sizeof(product));
    return 0;
}

/* Public exponents are normally short (for example 65537), so begin at the
 * first set bit instead of needlessly processing every padded exponent bit. */
int32_t
libmpq__rsa_public_operation(
    const uint8_t *modulus, size_t modulus_size, const uint8_t *exponent, size_t exponent_size,
    const uint8_t *input, uint8_t *output
)
{
    uint8_t n[LIBMPQ_RSA_MAX_SIZE];
    uint8_t base[LIBMPQ_RSA_MAX_SIZE];
    uint8_t result[LIBMPQ_RSA_MAX_SIZE] = { 0 };
    uint8_t product[LIBMPQ_RSA_MAX_SIZE];
    size_t i;
    size_t bit;
    int started = 0;
    if (modulus == NULL || exponent == NULL || input == NULL || output == NULL ||
        modulus_size == 0 || modulus_size > LIBMPQ_RSA_MAX_SIZE || exponent_size == 0 ||
        exponent_size > modulus_size || memcmp(input, modulus, modulus_size) >= 0)
        return LIBMPQ_ERROR_FORMAT;
    for (i = 0; i < modulus_size; ++i) {
        n[i] = modulus[modulus_size - 1 - i];
        base[i] = input[modulus_size - 1 - i];
    }
    result[0] = 1;
    for (bit = 0; bit < exponent_size * 8u; ++bit) {
        uint8_t set = (uint8_t)((exponent[bit / 8u] >> (7u - bit % 8u)) & 1u);
        if (!started) {
            if (!set)
                continue;
            started = 1;
            multiply(result, result, base, n, modulus_size);
            continue;
        }
        multiply(result, result, result, n, modulus_size);
        if (set) {
            multiply(product, result, base, n, modulus_size);
            memcpy(result, product, modulus_size);
        }
    }
    if (!started) {
        libmpq__rsa_clear(n, sizeof(n));
        libmpq__rsa_clear(base, sizeof(base));
        libmpq__rsa_clear(result, sizeof(result));
        libmpq__rsa_clear(product, sizeof(product));
        return LIBMPQ_ERROR_FORMAT;
    }
    for (i = 0; i < modulus_size; ++i)
        output[i] = result[modulus_size - 1 - i];
    libmpq__rsa_clear(n, sizeof(n));
    libmpq__rsa_clear(base, sizeof(base));
    libmpq__rsa_clear(result, sizeof(result));
    libmpq__rsa_clear(product, sizeof(product));
    return 0;
}

/* RFC 8017 EMSA-PKCS1-v1_5: 00 01 FF...FF 00 DigestInfo(MD5). */
void
libmpq__rsa_md5_encode(const uint8_t digest[LIBMPQ_MD5_SIZE], uint8_t encoded[LIBMPQ_RSA_SIZE])
{
    static const uint8_t prefix[18] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                        0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
    memset(encoded, 0xff, LIBMPQ_RSA_SIZE);
    encoded[0] = 0;
    encoded[1] = 1;
    encoded[29] = 0;
    memcpy(encoded + 30, prefix, sizeof(prefix));
    memcpy(encoded + 48, digest, LIBMPQ_MD5_SIZE);
}

void
libmpq__rsa_clear(void *data, size_t size)
{
    volatile uint8_t *bytes = data;
    while (size-- != 0)
        *bytes++ = 0;
}
