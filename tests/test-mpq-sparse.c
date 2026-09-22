/* Exercise bounded SPARSE tokens, policy-independent decoding, and writer paths. */
#include "mpq-compression.h"
#include "mpq-sparse.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* These vectors are specified directly from the token grammar, not our encoder. */
static int
test_vectors(void)
{
    static const uint8_t zeros[] = { 0, 0, 0, 64, 61 };
    static const uint8_t mixed[] = { 0, 0, 0, 8, 0, 0x82, 'A', 'B', 'C', 0x81, 0, 0 };
    static const uint8_t expected[] = { 0, 0, 0, 'A', 'B', 'C', 0, 0 };
    static const uint8_t tail_zero[] = { 0, 0, 0, 1, 0x7f };
    static const uint8_t tail_literal[] = { 0, 0, 0, 2, 0xff, 'A', 'B' };
    static const uint8_t malformed[][8] = {
        { 0, 0, 0, 4, 0 }, { 0, 0, 0, 4, 0x83, 'A' }, { 0, 0, 0, 1, 0, 0 },
        { 0, 0, 0, 0, 0 }, { 0x80, 0, 0, 0, 0 },      { 0, 0, 1, 0, 0 },
    };
    static const uint32_t sizes[] = { 5, 6, 6, 5, 5, 5 };
    uint8_t output[66];
    uint8_t encoded[80];
    uint8_t plain[64] = { 0 };
    size_t i;

    memset(output, 0xa5, sizeof(output));
    TEST_CHECK(libmpq__sparse_decompress(zeros, sizeof(zeros), output + 1, 64) == 64);
    TEST_CHECK(output[0] == 0xa5 && output[65] == 0xa5);
    TEST_CHECK(memcmp(output + 1, plain, sizeof(plain)) == 0);
    TEST_CHECK(libmpq__sparse_compress(plain, sizeof(plain), encoded, sizeof(encoded)) == 5);
    TEST_CHECK(memcmp(encoded, zeros, sizeof(zeros)) == 0);
    TEST_CHECK(libmpq__sparse_decompress(mixed, sizeof(mixed), output, sizeof(output)) == 8);
    TEST_CHECK(memcmp(output, expected, sizeof(expected)) == 0);
    TEST_CHECK(libmpq__sparse_decompress(tail_zero, sizeof(tail_zero), output, 1) == 1);
    TEST_CHECK(output[0] == 0);
    TEST_CHECK(libmpq__sparse_decompress(tail_literal, sizeof(tail_literal), output, 2) == 2);
    TEST_CHECK(memcmp(output, "AB", 2) == 0);
    TEST_CHECK(libmpq__sparse_decompress(zeros, sizeof(zeros), output, 63) == LIBMPQ_ERROR_UNPACK);
    TEST_CHECK(libmpq__sparse_decompress(zeros, sizeof(zeros), output, UINT32_MAX) == 64);
    for (i = 0; i < 5; ++i)
        TEST_CHECK(
            libmpq__sparse_decompress(zeros, (uint32_t)i, output, sizeof(output)) ==
            LIBMPQ_ERROR_UNPACK
        );
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
        TEST_CHECK(
            libmpq__sparse_decompress(malformed[i], sizes[i], output, sizeof(output)) ==
            LIBMPQ_ERROR_UNPACK
        );
    TEST_CHECK(libmpq__sparse_decompress(NULL, 5, output, 64) == LIBMPQ_ERROR_UNPACK);
    TEST_CHECK(libmpq__sparse_decompress(zeros, 5, NULL, 64) == LIBMPQ_ERROR_UNPACK);
    TEST_CHECK(libmpq__sparse_compress(NULL, 64, encoded, sizeof(encoded)) == LIBMPQ_ERROR_UNPACK);
    TEST_CHECK(libmpq__sparse_compress(plain, 0, encoded, sizeof(encoded)) == LIBMPQ_ERROR_UNPACK);
    TEST_CHECK(
        libmpq__sparse_compress(plain, UINT32_MAX, encoded, sizeof(encoded)) == LIBMPQ_ERROR_UNPACK
    );
    return 0;
}

/* Sweep literal and zero-run boundaries, including short tails and exact capacities. */
static int
test_boundaries(void)
{
    uint8_t plain[400];
    uint8_t packed[420];
    uint8_t output[400];
    uint32_t length;
    uint32_t kind;
    uint32_t i;

    for (kind = 0; kind < 4; ++kind) {
        for (length = 1; length <= sizeof(plain); ++length) {
            int32_t size;
            for (i = 0; i < length; ++i)
                plain[i] = kind == 0   ? 0
                           : kind == 1 ? (uint8_t)(i % 255U + 1U)
                           : kind == 2 ? (uint8_t)(i % 132U < 129U ? 0 : 'A')
                                       : (uint8_t)(i + 2U < length ? 0 : 'B');
            size = libmpq__sparse_compress(plain, length, packed, sizeof(packed));
            TEST_CHECK(size > 0);
            TEST_CHECK(
                libmpq__sparse_decompress(packed, (uint32_t)size, output, length) == (int32_t)length
            );
            TEST_CHECK(memcmp(output, plain, length) == 0);
            TEST_CHECK(libmpq__sparse_compress(plain, length, packed, (uint32_t)size) == size);
            TEST_CHECK(
                libmpq__sparse_compress(plain, length, packed, (uint32_t)size - 1U) ==
                LIBMPQ_ERROR_UNPACK
            );
        }
    }
    return 0;
}

/* Check actual emitted masks, raw fallback, and a lossless EXTENDED chain. */
static int
test_sectors(void)
{
    static const uint32_t methods[] = { 0x20, 0x22, 0x30, 0x21, 0x28 };
    uint8_t plain[TEST_SPARSE_FIXTURE_SIZE];
    uint8_t decoded[TEST_SPARSE_FIXTURE_SIZE];
    uint8_t *packed = NULL;
    size_t packed_size;
    uint8_t emitted;
    uint32_t version;
    size_t i;
    size_t length;

    for (version = 0; version < 2; ++version) {
        for (i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i) {
            int32_t result;

            test_sparse_payload(plain, sizeof(plain));
            if (i >= 3) {

                /*
                 * Zero runs shrink first; repeated SPARSE tokens let the second
                 * Huffman or PKWARE stage win too, without relying on fallback.
                 */
                for (length = 0; length < sizeof(plain); ++length)
                    plain[length] = length % 4U == 0 ? 'A' : 0;
            }
            result = libmpq__compression_encode_sector(
                plain, sizeof(plain), methods[i], version, LIBMPQ_COMPRESSION_POLICY_EXTENDED,
                &packed, &packed_size, &emitted
            );
            TEST_CHECK(result == 0);
            result =
                emitted == methods[i] && packed[0] == methods[i] && packed_size < sizeof(plain);
            if (result)
                result = libmpq__compression_decompress_multi(
                             packed, (uint32_t)packed_size, decoded, sizeof(decoded), version
                         ) == sizeof(decoded) &&
                         memcmp(decoded, plain, sizeof(plain)) == 0;
            free(packed);
            packed = NULL;
            TEST_CHECK(result);
        }
    }
    for (length = 0; length <= 128; ++length) {
        int32_t result;
        memset(plain, 'X', sizeof(plain));
        result = libmpq__compression_encode_sector(
            plain, length, 0x20, 1, LIBMPQ_COMPRESSION_POLICY_STANDARD, &packed, &packed_size,
            &emitted
        );
        TEST_CHECK(result == 0);
        result = emitted == 0 && packed_size == length && memcmp(packed, plain, length) == 0;
        free(packed);
        packed = NULL;
        TEST_CHECK(result);
    }
    return 0;
}

/* Exercise both archive wrappers, policies, versions, and sector/encryption paths. */
static int
test_archives(void)
{
    static const uint8_t code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    static const uint32_t lengths[] = { 0, 1, 6, 7, 511, 512, 513, 4095, 4096, 4097, 8193 };
    static const uint32_t methods[] = { 0x20, 0x22, 0x30 };
    uint8_t plain[8193];
    uint32_t configuration;
    char path[128];

    test_sparse_payload(plain, sizeof(plain));
    TEST_CHECK(test_temp_path(path, sizeof(path), "sparse") == 0);
    for (configuration = 0; configuration < 16; ++configuration) {
        mpq_archive_s *archive = NULL;
        mpq_archive_create_options_s create = {
            configuration & 1U, 256, configuration & 8U ? 512U : 4096U,
            configuration & 8U ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0
        };
        uint32_t flags;
        size_t i;
        size_t j;
        char name[64];
        int32_t result;

        if (configuration & 2U)
            create.flags |= LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED;
        if (configuration & 4U)
            result = libmpq__archive_create_mpqe(&archive, path, code, sizeof(code) - 1U, &create);
        else
            result = libmpq__archive_create(&archive, path, &create);
        TEST_CHECK(result == 0);

        /*
         * Match existing writer coverage: encrypted sectorized or plain single-unit.
         * Compressed encrypted single units have no reader seed-recovery path.
         */
        for (flags = 0; flags < 3; ++flags) {
            for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
                if (lengths[i] == 0 || ((flags & 1U) && lengths[i] < 8U) ||
                    ((flags & 2U) && lengths[i] > create.sector_size))
                    continue;
                for (j = 0; j < sizeof(methods) / sizeof(methods[0]); ++j) {
                    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, methods[j],
                                                   methods[(j + 1U) % 3U], 0, 0 };
                    if (flags & 1U)
                        options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
                    if (flags & 2U)
                        options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
                    snprintf(name, sizeof(name), "file-%u-%zu-%zu", flags, i, j);
                    result = libmpq__archive_add_data(archive, name, plain, lengths[i], &options);
                    if (result != 0) {
                        fprintf(
                            stderr, "sparse configuration %u, %s: %d\n", configuration, name, result
                        );
                        libmpq__archive_close(archive);
                        archive = NULL;
                        remove(path);
                        TEST_CHECK(result == 0);
                    }
                }
            }
        }
        result = libmpq__archive_close(archive);
        archive = NULL;
        TEST_CHECK(result == 0);
        if (configuration & 4U)
            result = libmpq__archive_open_mpqe(&archive, path, -1, code, sizeof(code) - 1U);
        else
            result = libmpq__archive_open(&archive, path, -1);
        TEST_CHECK(result == 0);
        for (flags = 0; flags < 3; ++flags) {
            for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
                if (lengths[i] == 0 || ((flags & 1U) && lengths[i] < 8U) ||
                    ((flags & 2U) && lengths[i] > create.sector_size))
                    continue;
                for (j = 0; j < sizeof(methods) / sizeof(methods[0]); ++j) {
                    uint8_t *data = NULL;
                    size_t size = 0;
                    uint32_t number;
                    snprintf(name, sizeof(name), "file-%u-%zu-%zu", flags, i, j);
                    TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
                    result = test_archive_read(archive, number, &data, &size);
                    if (result == 0)
                        result = size == lengths[i] && memcmp(data, plain, size) == 0 ? 0 : -1;
                    free(data);
                    if (result != 0)
                        fprintf(
                            stderr, "sparse read configuration %u, %s: %d, size %zu\n",
                            configuration, name, result, size
                        );
                    TEST_CHECK(result == 0);
                }
            }
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        TEST_CHECK(remove(path) == 0);
    }
    return 0;
}

/* Run the same byte-order-independent checks on all native CI architectures. */
int
main(void)
{
    TEST_CHECK(test_vectors() == 0);
    TEST_CHECK(test_boundaries() == 0);
    TEST_CHECK(test_sectors() == 0);
    TEST_CHECK(test_archives() == 0);
    return 0;
}
