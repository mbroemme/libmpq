/* Verify read-only MPQE stream-provider opening with public fixtures. */
#include "test-mpq-helper.h"

#include "mpq-stream.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t authentication_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";

/* The raw and MPQE fixtures are paired archive streams with matching bytes. */
typedef struct
{
    const char *raw_name;
    const char *mpqe_name;
    const char *overview_hash;
    uint32_t version;
} mpqe_fixture_s;

static const mpqe_fixture_s fixtures[] = {
    {
        "mpq-v1-features.mpq",
        "mpq-v1-features.mpqe",
        "c974912482320e001e3550b36f7eda21a8df2c57c9ef7c9fa84154579c21b8d9",
        1,
    },
    {
        "mpq-v2-features.mpq",
        "mpq-v2-features.mpqe",
        "5b82917a5cb24bee72be9b0526c6f28b5a3e977d31156398b129502fd191ad0b",
        2,
    },
};

/* Compare random-access MPQE reads with the corresponding raw MPQ fixture. */
static int
test_stream_reads(const char *raw_path, const char *mpqe_path)
{
    mpq_stream_s *stream = NULL;
    uint8_t *raw_data = NULL;
    uint8_t cross_chunk[96];
    uint8_t trailing[64];
    size_t raw_size;
    size_t trailing_size;

    TEST_CHECK(test_read_path(raw_path, &raw_data, &raw_size) == 0);
    TEST_CHECK(raw_size > sizeof(cross_chunk) && raw_size % 64U != 0U);
    TEST_CHECK(
        libmpq__stream_open_mpqe(
            &stream, mpqe_path, authentication_code, sizeof(authentication_code) - 1U
        ) == 0
    );
    TEST_CHECK(libmpq__stream_size(stream) == raw_size);
    TEST_CHECK(libmpq__stream_read_at(stream, 32, cross_chunk, sizeof(cross_chunk)) == 0);
    TEST_CHECK(memcmp(cross_chunk, raw_data + 32, sizeof(cross_chunk)) == 0);
    trailing_size = raw_size % 64U;
    TEST_CHECK(
        libmpq__stream_read_at(stream, raw_size - trailing_size, trailing, trailing_size) == 0
    );
    TEST_CHECK(memcmp(trailing, raw_data + raw_size - trailing_size, trailing_size) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    free(raw_data);
    return 0;
}

/* Build a temporary MPQE stream to cover an unaligned read through two batches. */
static int
test_stream_cross_batch(void)
{
    enum
    {
        plain_size = 12288 + 31,
        read_offset = 4096 - 19,
        read_size = 4200
    };
    char path[512];
    FILE *file;
    mpq_stream_s *stream = NULL;
    uint8_t plain[plain_size];
    uint8_t encrypted[plain_size];
    uint8_t read_data[read_size];
    size_t chunk;

    test_payload(plain, sizeof(plain), 0x4d505145U);
    memcpy(encrypted, plain, sizeof(encrypted));
    for (chunk = 0; chunk < sizeof(encrypted); chunk += 64U) {
        uint8_t block[64] = { 0 };
        size_t bytes = sizeof(encrypted) - chunk;

        if (bytes > sizeof(block))
            bytes = sizeof(block);
        memcpy(block, encrypted + chunk, bytes);
        libmpq__stream_mpqe_test_transform_chunk(block, authentication_code, chunk);
        memcpy(encrypted + chunk, block, bytes);
    }
    TEST_CHECK(test_temp_path(path, sizeof(path), "mpqe-batch") == 0);
    file = fopen(path, "wb");
    TEST_CHECK(file != NULL);
    TEST_CHECK(fwrite(encrypted, 1, sizeof(encrypted), file) == sizeof(encrypted));
    TEST_CHECK(fclose(file) == 0);
    TEST_CHECK(
        libmpq__stream_open_mpqe(
            &stream, path, authentication_code, sizeof(authentication_code) - 1U
        ) == 0
    );
    TEST_CHECK(libmpq__stream_read_at(stream, read_offset, read_data, sizeof(read_data)) == 0);
    TEST_CHECK(memcmp(read_data, plain + read_offset, sizeof(read_data)) == 0);
    TEST_CHECK(libmpq__stream_close(stream) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Validate parsing, extraction, and cloning for a paired public fixture. */
static int
test_fixture(const mpqe_fixture_s *fixture, size_t index)
{
    char raw_path[512];
    char mpqe_path[512];
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    uint8_t wrong_code[sizeof(authentication_code) - 1U];
    uint8_t *data = NULL;
    size_t size;
    char hash[65];
    uint32_t version;
    uint32_t files;
    uint32_t number;
    int32_t result;

    TEST_CHECK(snprintf(raw_path, sizeof(raw_path), "%s/%s", FIXTURE_DIR, fixture->raw_name) > 0);
    TEST_CHECK(
        snprintf(mpqe_path, sizeof(mpqe_path), "%s/%s", FIXTURE_DIR, fixture->mpqe_name) > 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, mpqe_path, 0) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(archive == NULL);
    if (index == 0) {
        TEST_CHECK(
            libmpq__archive_open_mpqe(&archive, mpqe_path, 0, NULL, 0) == LIBMPQ_ERROR_DECRYPT
        );
        TEST_CHECK(archive == NULL);
        TEST_CHECK(
            libmpq__archive_open_mpqe(
                &archive, mpqe_path, 0, authentication_code, sizeof(authentication_code) - 2U
            ) == LIBMPQ_ERROR_DECRYPT
        );
        TEST_CHECK(archive == NULL);
        memcpy(wrong_code, authentication_code, sizeof(wrong_code));
        wrong_code[0] ^= 1U;
        result = libmpq__archive_open_mpqe(&archive, mpqe_path, 0, wrong_code, sizeof(wrong_code));
        TEST_CHECK(result < 0);
        TEST_CHECK(archive == NULL);
    }
    TEST_CHECK(
        libmpq__archive_open_mpqe(
            &archive, mpqe_path, index == 0 ? 0 : -1, authentication_code,
            sizeof(authentication_code) - 1U
        ) == 0
    );
    TEST_CHECK(libmpq__archive_version(archive, &version) == 0 && version == fixture->version);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 10);
    TEST_CHECK(libmpq__file_number(archive, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(strcmp(hash, fixture->overview_hash) == 0);
    free(data);
    data = NULL;
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__file_number(clone, "overview.txt", &number) == 0);
    TEST_CHECK(test_archive_read(clone, number, &data, &size) == 0);
    TEST_CHECK(test_sha256(data, size, hash) == 0);
    TEST_CHECK(strcmp(hash, fixture->overview_hash) == 0);
    free(data);
    TEST_CHECK(libmpq__archive_close(clone) == 0);
    return test_stream_reads(raw_path, mpqe_path);
}

/* Open failures must clear caller output pointers before stream allocation. */
static int
test_open_failure_output(void)
{
    char missing_path[512];
    mpq_archive_s *archive = (mpq_archive_s *)(uintptr_t)1;

    TEST_CHECK(
        snprintf(missing_path, sizeof(missing_path), "%s/%s", FIXTURE_DIR, "missing.mpq") > 0
    );
    TEST_CHECK(libmpq__archive_open(&archive, missing_path, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(archive == NULL);

    archive = (mpq_archive_s *)(uintptr_t)1;
    TEST_CHECK(
        libmpq__archive_open_mpqe(
            &archive, missing_path, 0, authentication_code, sizeof(authentication_code) - 2U
        ) == LIBMPQ_ERROR_DECRYPT
    );
    TEST_CHECK(archive == NULL);

    archive = (mpq_archive_s *)(uintptr_t)1;
    TEST_CHECK(
        libmpq__archive_open_mpqe(
            &archive, missing_path, 0, authentication_code, sizeof(authentication_code) - 1U
        ) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(archive == NULL);
    TEST_CHECK(libmpq__archive_open(NULL, missing_path, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(
        libmpq__archive_open_mpqe(
            NULL, missing_path, 0, authentication_code, sizeof(authentication_code) - 1U
        ) == LIBMPQ_ERROR_EXIST
    );
    return 0;
}

/* Exercise full v1 and v2 fixtures through the public MPQE open path. */
int
main(void)
{
    size_t i;

    for (i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i)
        TEST_CHECK(test_fixture(&fixtures[i], i) == 0);
    TEST_CHECK(test_open_failure_output() == 0);
    TEST_CHECK(test_stream_cross_batch() == 0);
    return 0;
}
