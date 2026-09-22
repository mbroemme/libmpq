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
#include "mpq-endian.h"
#include <libmpq/mpq.h>
#include <string.h>

/*
 * Little-endian base-256 limbs avoid native word size and alignment assumptions.
 * Weak RSA-512 and strong RSA-2048 private operations use fixed iterations and
 * mask selection. Strong RSA-2048 public operation skips leading zero exponent
 * bits for efficiency. This legacy implementation is not a modern cryptographic API.
 */
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

#define LIBMPQ_RSA_MAX_WORDS (LIBMPQ_RSA_MAX_SIZE / 4u)

/*
 * Montgomery multiplication with base 2^32. The inputs and output have the
 * same fixed width; the caller supplies values in Montgomery representation.
 */
static void
montgomery_multiply(
    uint32_t *output, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
    uint32_t inverse, size_t words
)
{
    uint32_t temporary[LIBMPQ_RSA_MAX_WORDS + 2u] = { 0 };
    uint32_t reduced[LIBMPQ_RSA_MAX_WORDS];
    uint64_t carry;
    uint64_t value;
    uint32_t borrow = 0;
    uint32_t select;
    size_t i;
    size_t j;

    for (i = 0; i < words; ++i) {
        carry = 0;
        for (j = 0; j < words; ++j) {
            value = (uint64_t)temporary[j] + (uint64_t)left[j] * right[i] + carry;
            temporary[j] = (uint32_t)value;
            carry = value >> 32;
        }
        value = (uint64_t)temporary[words] + carry;
        temporary[words] = (uint32_t)value;
        temporary[words + 1u] = (uint32_t)(value >> 32);

        carry = 0;
        value = (uint32_t)((uint64_t)temporary[0] * inverse);
        for (j = 0; j < words; ++j) {
            uint64_t sum = (uint64_t)temporary[j] + value * modulus[j] + carry;
            if (j != 0)
                temporary[j - 1u] = (uint32_t)sum;
            carry = sum >> 32;
        }
        value = (uint64_t)temporary[words] + carry;
        temporary[words - 1u] = (uint32_t)value;
        carry = (uint64_t)temporary[words + 1u] + (value >> 32);
        temporary[words] = (uint32_t)carry;
        temporary[words + 1u] = (uint32_t)(carry >> 32);
    }
    for (i = 0; i < words; ++i) {
        uint64_t difference = (uint64_t)temporary[i] - modulus[i] - borrow;
        reduced[i] = (uint32_t)difference;
        borrow = (uint32_t)(difference >> 63);
    }
    select = 0u - ((temporary[words] != 0u) | (borrow ^ 1u));
    for (i = 0; i < words; ++i)
        output[i] = (reduced[i] & select) | (temporary[i] & ~select);
    libmpq__rsa_clear(temporary, sizeof(temporary));
    libmpq__rsa_clear(reduced, sizeof(reduced));
}

static void
montgomery_r_squared(uint32_t *output, const uint32_t *modulus, size_t words)
{
    uint8_t value[LIBMPQ_RSA_MAX_SIZE] = { 1 };
    uint8_t doubled[LIBMPQ_RSA_MAX_SIZE];
    uint8_t bytes[LIBMPQ_RSA_MAX_SIZE];
    size_t i;
    size_t bit;

    for (i = 0; i < words; ++i) {
        libmpq__store_le32(bytes + 4u * i, modulus[i]);
    }
    for (bit = 0; bit < words * 64u; ++bit) {
        add_mod(doubled, value, value, bytes, words * 4u);
        memcpy(value, doubled, words * 4u);
    }
    for (i = 0; i < words; ++i) {
        output[i] = libmpq__load_le32(value + 4u * i);
    }
    libmpq__rsa_clear(value, sizeof(value));
    libmpq__rsa_clear(doubled, sizeof(doubled));
    libmpq__rsa_clear(bytes, sizeof(bytes));
}

/*
 * A raw key is equal-width big-endian n || exponent components. A full-width
 * odd modulus and an odd exponent in [3,n) are required.
 */
static int32_t
rsa_key_validate(const uint8_t *key, size_t key_size, size_t modulus_size)
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
libmpq__rsa_weak_key_validate(const uint8_t *key, size_t key_size)
{
    return rsa_key_validate(key, key_size, LIBMPQ_RSA_SIZE);
}

int32_t
libmpq__rsa_strong_key_validate(const uint8_t *key, size_t key_size)
{
    return rsa_key_validate(key, key_size, LIBMPQ_RSA_STRONG_SIZE);
}

int32_t
libmpq__rsa_strong_private_operation(
    const uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE], const uint8_t input[LIBMPQ_RSA_STRONG_SIZE],
    uint8_t output[LIBMPQ_RSA_STRONG_SIZE]
)
{
    uint32_t modulus[LIBMPQ_RSA_MAX_WORDS];
    uint32_t base[LIBMPQ_RSA_MAX_WORDS];
    uint32_t result[LIBMPQ_RSA_MAX_WORDS];
    uint32_t product[LIBMPQ_RSA_MAX_WORDS];
    uint32_t squared[LIBMPQ_RSA_MAX_WORDS];
    uint32_t r_squared[LIBMPQ_RSA_MAX_WORDS];
    uint32_t one[LIBMPQ_RSA_MAX_WORDS] = { 0 };
    uint32_t inverse = 1;
    size_t i;
    size_t bit;
    if (libmpq__rsa_strong_key_validate(key, LIBMPQ_RSA_STRONG_KEY_SIZE) != 0 || input == NULL ||
        output == NULL || memcmp(input, key, LIBMPQ_RSA_STRONG_SIZE) >= 0)
        return LIBMPQ_ERROR_FORMAT;
    for (i = 0; i < LIBMPQ_RSA_MAX_WORDS; ++i) {
        modulus[i] = libmpq__load_be32(key + LIBMPQ_RSA_STRONG_SIZE - 4u * (i + 1u));
        base[i] = libmpq__load_be32(input + LIBMPQ_RSA_STRONG_SIZE - 4u * (i + 1u));
    }
    for (i = 0; i < 5; ++i)
        inverse *= 2u - modulus[0] * inverse;
    inverse = 0u - inverse;
    one[0] = 1;
    montgomery_r_squared(r_squared, modulus, LIBMPQ_RSA_MAX_WORDS);
    montgomery_multiply(base, base, r_squared, modulus, inverse, LIBMPQ_RSA_MAX_WORDS);
    montgomery_multiply(result, one, r_squared, modulus, inverse, LIBMPQ_RSA_MAX_WORDS);
    for (bit = 0; bit < (LIBMPQ_RSA_STRONG_SIZE * 8); ++bit) {
        uint32_t mask = 0u - ((key[LIBMPQ_RSA_STRONG_SIZE + bit / 8] >> (7 - bit % 8)) & 1u);
        montgomery_multiply(squared, result, result, modulus, inverse, LIBMPQ_RSA_MAX_WORDS);
        montgomery_multiply(product, squared, base, modulus, inverse, LIBMPQ_RSA_MAX_WORDS);
        for (i = 0; i < LIBMPQ_RSA_MAX_WORDS; ++i)
            result[i] = (product[i] & mask) | (squared[i] & ~mask);
    }
    montgomery_multiply(result, result, one, modulus, inverse, LIBMPQ_RSA_MAX_WORDS);
    for (i = 0; i < LIBMPQ_RSA_MAX_WORDS; ++i)
        libmpq__store_be32(output + 4u * (LIBMPQ_RSA_MAX_WORDS - i - 1u), result[i]);
    libmpq__rsa_clear(modulus, sizeof(modulus));
    libmpq__rsa_clear(base, sizeof(base));
    libmpq__rsa_clear(result, sizeof(result));
    libmpq__rsa_clear(product, sizeof(product));
    libmpq__rsa_clear(squared, sizeof(squared));
    libmpq__rsa_clear(r_squared, sizeof(r_squared));
    libmpq__rsa_clear(one, sizeof(one));
    return 0;
}

int32_t
libmpq__rsa_weak_operation(
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

/*
 * Public exponents are normally short (for example 65537), so begin at the
 * first set bit instead of needlessly processing every padded exponent bit.
 */
int32_t
libmpq__rsa_strong_public_operation(
    const uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE], const uint8_t input[LIBMPQ_RSA_STRONG_SIZE],
    uint8_t output[LIBMPQ_RSA_STRONG_SIZE]
)
{
    uint8_t n[LIBMPQ_RSA_MAX_SIZE];
    uint8_t base[LIBMPQ_RSA_MAX_SIZE];
    uint8_t result[LIBMPQ_RSA_MAX_SIZE] = { 0 };
    uint8_t product[LIBMPQ_RSA_MAX_SIZE];
    size_t i;
    size_t bit;
    int started = 0;
    if (libmpq__rsa_strong_key_validate(key, LIBMPQ_RSA_STRONG_KEY_SIZE) != 0 || input == NULL ||
        output == NULL || memcmp(input, key, LIBMPQ_RSA_STRONG_SIZE) >= 0)
        return LIBMPQ_ERROR_FORMAT;
    for (i = 0; i < LIBMPQ_RSA_STRONG_SIZE; ++i) {
        n[i] = key[LIBMPQ_RSA_STRONG_SIZE - 1 - i];
        base[i] = input[LIBMPQ_RSA_STRONG_SIZE - 1 - i];
    }
    result[0] = 1;
    for (bit = 0; bit < LIBMPQ_RSA_STRONG_SIZE * 8u; ++bit) {
        uint8_t set = (uint8_t)((key[LIBMPQ_RSA_STRONG_SIZE + bit / 8u] >> (7u - bit % 8u)) & 1u);
        if (!started) {
            if (!set)
                continue;
            started = 1;
            multiply(result, result, base, n, LIBMPQ_RSA_STRONG_SIZE);
            continue;
        }
        multiply(result, result, result, n, LIBMPQ_RSA_STRONG_SIZE);
        if (set) {
            multiply(product, result, base, n, LIBMPQ_RSA_STRONG_SIZE);
            memcpy(result, product, LIBMPQ_RSA_STRONG_SIZE);
        }
    }
    if (!started) {
        libmpq__rsa_clear(n, sizeof(n));
        libmpq__rsa_clear(base, sizeof(base));
        libmpq__rsa_clear(result, sizeof(result));
        libmpq__rsa_clear(product, sizeof(product));
        return LIBMPQ_ERROR_FORMAT;
    }
    for (i = 0; i < LIBMPQ_RSA_STRONG_SIZE; ++i)
        output[i] = result[LIBMPQ_RSA_STRONG_SIZE - 1 - i];
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
