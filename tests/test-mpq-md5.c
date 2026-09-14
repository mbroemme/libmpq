/* Fixed RFC 1321 vectors and incremental padding-boundary coverage. */
#include "mpq-md5.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <string.h>

static int
vector(const char *input, const char *expected)
{
    size_t split;
    size_t size = strlen(input);
    for (split = 0; split <= size; ++split) {
        mpq_md5_s context;
        uint8_t digest[16];
        char hex[33];
        size_t i;
        libmpq__md5_init(&context);
        libmpq__md5_update(&context, (const uint8_t *)input, split);
        libmpq__md5_update(&context, (const uint8_t *)input + split, size - split);
        libmpq__md5_final(&context, digest);
        for (i = 0; i < sizeof(digest); ++i)
            snprintf(hex + i * 2, 3, "%02x", digest[i]);
        TEST_CHECK(strcmp(hex, expected) == 0);
    }
    return 0;
}

int
main(void)
{
    mpq_md5_s context;
    uint8_t digest[16];
    uint8_t data[1001];
    const uint8_t million_a[16] = { 0x77, 0x07, 0xd6, 0xae, 0x4e, 0x02, 0x7c, 0x70,
                                    0xee, 0xa2, 0xa9, 0x35, 0xc2, 0x29, 0x6f, 0x21 };
    size_t i;
    TEST_CHECK(vector("", "d41d8cd98f00b204e9800998ecf8427e") == 0);
    TEST_CHECK(vector("a", "0cc175b9c0f1b6a831c399e269772661") == 0);
    TEST_CHECK(vector("abc", "900150983cd24fb0d6963f7d28e17f72") == 0);
    TEST_CHECK(vector("message digest", "f96b697d7cb7938d525a2f31aaf161d0") == 0);
    TEST_CHECK(vector("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b") == 0);
    TEST_CHECK(
        vector(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f"
        ) == 0
    );
    TEST_CHECK(
        vector(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a"
        ) == 0
    );
    memset(data, 'a', sizeof(data));
    libmpq__md5_init(&context);
    for (i = 0; i < 1000; ++i)
        libmpq__md5_update(&context, data + 1, 1000);
    libmpq__md5_final(&context, digest);
    TEST_CHECK(memcmp(digest, million_a, 16) == 0);
    return 0;
}
