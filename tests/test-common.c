/* Shared deterministic helpers for the libmpq C regression programs. */
#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct
{
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} test_sha256_context;

static uint32_t
test_rotr(uint32_t value, unsigned count)
{
    return (value >> count) | (value << (32u - count));
}

static void
test_sha256_block(test_sha256_context *context, const uint8_t *block)
{
    static const uint32_t constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
        0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
        0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
        0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
        0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
        0xc67178f2u
    };
    uint32_t words[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    unsigned i;
    for (i = 0; i < 16; ++i)
        words[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (i = 16; i < 64; ++i) {
        uint32_t s0 =
            test_rotr(words[i - 15], 7) ^ test_rotr(words[i - 15], 18) ^ (words[i - 15] >> 3);
        uint32_t s1 =
            test_rotr(words[i - 2], 17) ^ test_rotr(words[i - 2], 19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];
    for (i = 0; i < 64; ++i) {
        uint32_t s1 = test_rotr(e, 6) ^ test_rotr(e, 11) ^ test_rotr(e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + choice + constants[i] + words[i];
        uint32_t s0 = test_rotr(a, 2) ^ test_rotr(a, 13) ^ test_rotr(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

void
test_failure(const char *file, unsigned line, const char *condition)
{
    fprintf(stderr, "%s:%u: check failed: %s\n", file, line, condition);
}

int
test_temp_path(char *path, size_t path_size, const char *tag)
{
    int result = snprintf(path, path_size, "libmpq-test-%ld-%s.mpq", (long)getpid(), tag);
    return result > 0 && (size_t)result < path_size ? 0 : -1;
}

int
test_read_path(const char *path, uint8_t **data, size_t *size)
{
    FILE *stream = fopen(path, "rb");
    long length;
    uint8_t *buffer = NULL;
    if (stream == NULL)
        return -1;
    if (fseek(stream, 0, SEEK_END) != 0 || (length = ftell(stream)) < 0 ||
        fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        return -1;
    }
    buffer = malloc((size_t)length + 1);
    if (buffer == NULL) {
        fclose(stream);
        return -1;
    }
    if (fread(buffer, 1, (size_t)length, stream) != (size_t)length) {
        free(buffer);
        fclose(stream);
        return -1;
    }
    if (fclose(stream) != 0) {
        free(buffer);
        return -1;
    }
    *data = buffer;
    *size = (size_t)length;
    return 0;
}

void
test_payload(uint8_t *data, size_t size, uint32_t seed)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        seed = seed * 1664525u + 1013904223u;
        data[i] = (uint8_t)(seed >> 24);
    }
}

int
test_sha256(const uint8_t *data, size_t size, char output[65])
{
    test_sha256_context context = { { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u },
                                    0,
                                    { 0 },
                                    0 };
    size_t i;
    for (i = 0; i < size; ++i) {
        context.block[context.used++] = data[i];
        context.bits += 8;
        if (context.used == sizeof(context.block)) {
            test_sha256_block(&context, context.block);
            context.used = 0;
        }
    }
    context.block[context.used++] = 0x80;
    if (context.used > 56) {
        while (context.used < 64)
            context.block[context.used++] = 0;
        test_sha256_block(&context, context.block);
        context.used = 0;
    }
    while (context.used < 56)
        context.block[context.used++] = 0;
    for (i = 0; i < 8; ++i)
        context.block[63 - i] = (uint8_t)(context.bits >> (i * 8));
    test_sha256_block(&context, context.block);
    for (i = 0; i < 8; ++i)
        snprintf(output + i * 8, 9, "%08x", context.state[i]);
    output[64] = '\0';
    return 0;
}

int
test_archive_read(mpq_archive_s *archive, uint32_t number, uint8_t **data, size_t *size)
{
    libmpq__off_t unpacked;
    libmpq__off_t transferred = 0;
    uint8_t *buffer = NULL;
    if (libmpq__file_size_unpacked(archive, number, &unpacked) < 0 || unpacked < 0 ||
        (buffer = malloc((size_t)unpacked + 1)) == NULL ||
        libmpq__file_read(archive, number, buffer, unpacked, &transferred) < 0 ||
        transferred != unpacked) {
        free(buffer);
        return -1;
    }
    *data = buffer;
    *size = (size_t)unpacked;
    return 0;
}

int
test_add_archive(mpq_archive_s **archive, const char *path, uint32_t version, uint32_t flags)
{
    mpq_archive_create_options_s options = { version, 32, 4096, flags };
    return libmpq__archive_create(archive, path, &options);
}
