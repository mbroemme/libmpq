/* Exercise deterministic writer output and generated writer/readback properties. */
#include "mpq-stream.h"
#include "mpq-writer.h"
#include "test-mpq-helper.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct
{
    const char *name;
    mpq_file_options_s options;
} writer_mode_s;

/* Cover lossless raw, PKWARE, multi-codec, encryption, and compatible single units. */
static const writer_mode_s writer_modes[] = {
    { "raw", { 0, 0, 0, 0, 0 } },
    { "raw-encrypted", { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "raw-single", { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 } },
    { "raw-single-encrypted",
      { LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "implode", { LIBMPQ_FILE_FLAG_IMPLODE, 0, 0, 0, 0 } },
    { "implode-encrypted", { LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "huffman",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_HUFFMAN, LIBMPQ_COMPRESSION_HUFFMAN, 0, 0 } },
    { "zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "pkware",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_PKZIP, LIBMPQ_COMPRESSION_PKZIP, 0, 0 } },
    { "bzip2",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_BZIP2, LIBMPQ_COMPRESSION_BZIP2, 0, 0 } },
    { "multi",
      { LIBMPQ_FILE_FLAG_COMPRESS,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        0, 0 } },
    { "mixed-sectors",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_BZIP2, 0, 0 } },
    { "zlib-encrypted",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "multi-encrypted",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        0, 0 } },
    { "zlib-single",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } }
};

static const uint8_t mpqe_authentication_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";

/* Write a sentinel destination used to prove failed publication never replaces it. */
static int
write_test_path(const char *path, const uint8_t *data, size_t size)
{
    FILE *file = fopen(path, "wb");

    if (file == NULL)
        return 1;
    if (fwrite(data, 1, size, file) != size) {
        (void)fclose(file);
        return 1;
    }
    return fclose(file) == 0 ? 0 : 1;
}

/* Create v1/v2 MPQE archives and verify ordinary file lookup/readback through the public reader. */
static void
mpqe_payload(uint8_t *data, size_t size, uint8_t salt)
{
    size_t i;

    for (i = 0; i < size; ++i)
        data[i] = (uint8_t)(salt + (i * 17U) % 251U);
}

/* Add representative raw, compressed, encrypted, and combined files to one archive. */
static int
add_mpqe_feature_files(mpq_archive_s *archive)
{
    uint8_t raw[512];
    uint8_t packed[1024];
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_file_options_s encrypted = { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    mpq_file_options_s packed_encrypted = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                            LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0,
                                            0 };
    int32_t result;

    mpqe_payload(raw, sizeof(raw), 7);
    mpqe_payload(packed, sizeof(packed), 23);
    result = libmpq__file_add(archive, "raw.bin", raw, sizeof(raw), NULL);
    if (result == 0)
        result = libmpq__file_add(archive, "compressed.bin", packed, sizeof(packed), &compressed);
    if (result == 0)
        result = libmpq__file_add(archive, "encrypted.bin", raw, sizeof(raw), &encrypted);
    if (result == 0) {
        result = libmpq__file_add(
            archive, "compressed-encrypted.bin", packed, sizeof(packed), &packed_encrypted
        );
    }
    if (result != 0)
        return 1;
    return 0;
}

/* Read a named member and compare it with deterministic expected bytes. */
static int
verify_mpqe_file(mpq_archive_s *archive, const char *name, const uint8_t *expected, size_t size)
{
    uint8_t *actual;
    libmpq__off_t transferred = 0;
    uint32_t number;
    int status = 1;

    actual = malloc(size);
    if (actual == NULL)
        return 1;
    if (libmpq__file_number(archive, name, &number) != 0 ||
        libmpq__file_read(archive, number, actual, (libmpq__off_t)size, &transferred) != 0 ||
        transferred != (libmpq__off_t)size || memcmp(actual, expected, size) != 0)
        goto cleanup;
    status = 0;

cleanup:
    free(actual);
    return status;
}

/* Create v1/v2 MPQE archives and verify the complete supported file feature set. */
static int
test_mpqe_writer_roundtrip(uint32_t version, int replace_existing)
{
    char path[160] = { 0 };
    FILE *existing = NULL;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *reader = NULL;
    mpq_archive_create_options_s options = { version, 8, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE };
    uint8_t raw[512];
    uint8_t packed[1024];
    uint8_t encrypted_output[512];
    libmpq__off_t transferred = 0;
    uint32_t encrypted = 0;
    uint32_t number;
    int32_t result;
    int status = 1;

    if (test_temp_path(path, sizeof(path), "writer-mpqe") != 0)
        goto cleanup;
    if (replace_existing) {
        existing = fopen(path, "wb");
        if (existing == NULL)
            goto cleanup;
        if (fwrite("previous destination", 1, 20, existing) != 20) {
            fclose(existing);
            existing = NULL;
            goto cleanup;
        }
        if (fclose(existing) != 0) {
            existing = NULL;
            goto cleanup;
        }
        existing = NULL;
    }
    mpqe_payload(raw, sizeof(raw), 7);
    mpqe_payload(packed, sizeof(packed), 23);
    result = libmpq__archive_create_mpqe(
        &archive, path, mpqe_authentication_code, sizeof(mpqe_authentication_code) - 1U, &options
    );
    if (result == 0)
        result = add_mpqe_feature_files(archive) == 0 ? 0 : LIBMPQ_ERROR_WRITE;
    if (result == 0) {
        result = libmpq__archive_close(archive);
        archive = NULL;
    }
    if (result != 0)
        goto cleanup;
    result = libmpq__archive_open_mpqe(
        &reader, path, 0, mpqe_authentication_code, sizeof(mpqe_authentication_code) - 1U
    );
    if (result != 0 || verify_mpqe_file(reader, "raw.bin", raw, sizeof(raw)) != 0)
        goto cleanup;
    if (verify_mpqe_file(reader, "compressed.bin", packed, sizeof(packed)) != 0)
        goto cleanup;
    if (libmpq__file_number(reader, "encrypted.bin", &number) != 0 ||
        libmpq__file_encrypted(reader, number, &encrypted) != 0 || encrypted == 0 ||
        libmpq__file_read(
            reader, number, encrypted_output, sizeof(encrypted_output), &transferred
        ) != LIBMPQ_ERROR_DECRYPT)
        goto cleanup;
    if (verify_mpqe_file(reader, "compressed-encrypted.bin", packed, sizeof(packed)) != 0)
        goto cleanup;
    if (libmpq__file_number(reader, "(listfile)", &number) != 0)
        goto cleanup;
    status = 0;

cleanup:
    if (existing != NULL)
        fclose(existing);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (reader != NULL)
        (void)libmpq__archive_close(reader);
    remove(path);
    return status;
}

/* Reject short borrowed credentials before creating a temporary output. */
static int
test_mpqe_writer_credential_validation(void)
{
    char path[160] = { 0 };
    mpq_archive_s *archive = (mpq_archive_s *)(uintptr_t)1;

    TEST_CHECK(test_temp_path(path, sizeof(path), "writer-mpqe-invalid") == 0);
    remove(path);
    TEST_CHECK(
        libmpq__archive_create_mpqe(
            &archive, path, mpqe_authentication_code, sizeof(mpqe_authentication_code) - 2U, NULL
        ) == LIBMPQ_ERROR_DECRYPT
    );
    TEST_CHECK(archive == NULL);
    TEST_CHECK(access(path, F_OK) != 0);
    return 0;
}

/* Decrypt one generated MPQE file with the private test transform for byte equality checks. */
static int
decrypt_mpqe_path(const char *path, uint8_t **data, size_t *size)
{
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE];
    size_t offset;

    if (test_read_path(path, data, size) != 0)
        return 1;
    for (offset = 0; offset < *size; offset += sizeof(chunk)) {
        size_t physical = *size - offset;

        if (physical > sizeof(chunk))
            physical = sizeof(chunk);
        memset(chunk, 0, sizeof(chunk));
        memcpy(chunk, *data + offset, physical);
        libmpq__stream_mpqe_test_transform_chunk(chunk, mpqe_authentication_code, offset);
        memcpy(*data + offset, chunk, physical);
    }
    return 0;
}

/* Compare normal writer bytes with the complete decrypted MPQE stream, including its final chunk.
 */
static int
test_mpqe_writer_byte_equality(uint32_t version)
{
    char raw_path[160] = { 0 };
    char mpqe_path[160] = { 0 };
    mpq_archive_create_options_s options = { version, 8, 512, 0 };
    const uint8_t payload[193] = { 0 };
    mpq_archive_s *raw_archive = NULL;
    mpq_archive_s *mpqe_archive = NULL;
    struct stat raw_status;
    struct stat mpqe_status;
    uint8_t *raw = NULL;
    uint8_t *decrypted = NULL;
    size_t raw_size;
    size_t decrypted_size;
    int32_t result;
    int status = 1;

    if (test_temp_path(raw_path, sizeof(raw_path), "writer-mpqe-raw") != 0 ||
        test_temp_path(mpqe_path, sizeof(mpqe_path), "writer-mpqe-encrypted") != 0)
        goto cleanup;
    if (libmpq__archive_create(&raw_archive, raw_path, &options) != 0 ||
        libmpq__file_add(raw_archive, "partial.bin", payload, sizeof(payload), NULL) != 0)
        goto cleanup;
    result = libmpq__archive_close(raw_archive);
    raw_archive = NULL;
    if (result != 0)
        goto cleanup;
    if (libmpq__archive_create_mpqe(
            &mpqe_archive, mpqe_path, mpqe_authentication_code,
            sizeof(mpqe_authentication_code) - 1U, &options
        ) != 0 ||
        libmpq__file_add(mpqe_archive, "partial.bin", payload, sizeof(payload), NULL) != 0)
        goto cleanup;
    result = libmpq__archive_close(mpqe_archive);
    mpqe_archive = NULL;
    if (result != 0)
        goto cleanup;
    if (stat(raw_path, &raw_status) != 0 || stat(mpqe_path, &mpqe_status) != 0 ||
        raw_status.st_size != mpqe_status.st_size || raw_status.st_size % 64 == 0 ||
        (raw_status.st_mode & 0777) != (mpqe_status.st_mode & 0777) ||
        test_read_path(raw_path, &raw, &raw_size) != 0 ||
        decrypt_mpqe_path(mpqe_path, &decrypted, &decrypted_size) != 0 ||
        raw_size != decrypted_size || memcmp(raw, decrypted, raw_size) != 0 || raw_size < 93 ||
        memcmp(raw + 31, decrypted + 31, 61) != 0)
        goto cleanup;
    status = 0;

cleanup:
    if (raw_archive != NULL)
        (void)libmpq__archive_close(raw_archive);
    if (mpqe_archive != NULL)
        (void)libmpq__archive_close(mpqe_archive);
    free(raw);
    free(decrypted);
    remove(raw_path);
    remove(mpqe_path);
    return status;
}

/* Count this test's private writer temporaries without relying on their randomized names. */
static int
count_mpqe_temps(const char *directory)
{
    DIR *entries;
    struct dirent *entry;
    int count = 0;

    entries = opendir(directory);
    if (entries == NULL)
        return -1;
    while ((entry = readdir(entries)) != NULL) {
        if (strncmp(entry->d_name, ".libmpq-raw-", 12) == 0 ||
            strncmp(entry->d_name, ".libmpq-mpqe-", 13) == 0)
            count++;
    }
    closedir(entries);
    return count;
}

/* A handled finalization failure must consume the writer and preserve an existing destination. */
static int
test_mpqe_writer_fault(libmpq_writer_test_fault_e fault)
{
    char directory[160] = { 0 };
    char path[176] = { 0 };
    static const uint8_t original[] = "existing MPQE destination";
    uint8_t *actual = NULL;
    size_t actual_size;
    mpq_archive_s *archive = NULL;
    int32_t result;
    int status = 1;

    if (test_temp_path(directory, sizeof(directory), "writer-mpqe-fault") != 0 ||
        mkdir(directory, 0700) != 0 ||
        snprintf(path, sizeof(path), "%s/archive.mpqe", directory) < 0)
        goto cleanup;
    if (write_test_path(path, original, sizeof(original) - 1U) != 0)
        goto cleanup;
    if (libmpq__archive_create_mpqe(
            &archive, path, mpqe_authentication_code, sizeof(mpqe_authentication_code) - 1U, NULL
        ) != 0 ||
        libmpq__file_add(archive, "payload.bin", original, sizeof(original) - 1U, NULL) != 0)
        goto cleanup;
    libmpq__writer_test_fault_set(fault);
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result == 0)
        goto cleanup;
    libmpq__writer_test_fault_set(LIBMPQ_WRITER_TEST_FAULT_NONE);
    if (test_read_path(path, &actual, &actual_size) != 0 || actual_size != sizeof(original) - 1U ||
        memcmp(actual, original, actual_size) != 0 || count_mpqe_temps(directory) != 0)
        goto cleanup;
    status = 0;

cleanup:
    libmpq__writer_test_fault_set(LIBMPQ_WRITER_TEST_FAULT_NONE);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    free(actual);
    remove(path);
    rmdir(directory);
    return status;
}

/* Keep MPQE temporary cleanup and publication anchored if callers later change cwd. */
static int
test_mpqe_writer_chdir(void)
{
    char directory[160] = { 0 };
    char source_directory[176] = { 0 };
    char other_directory[176] = { 0 };
    char archive_path[192] = { 0 };
    static const uint8_t payload[] = "MPQE directory descriptor regression\n";
    mpq_archive_s *archive = NULL;
    mpq_archive_s *reader = NULL;
    char *initial_directory = NULL;
    int changed_directory = 0;
    int32_t result;
    uint32_t number;
    int status = 1;

    if (test_temp_path(directory, sizeof(directory), "writer-mpqe-chdir") != 0 ||
        snprintf(source_directory, sizeof(source_directory), "%s/source", directory) < 0 ||
        snprintf(other_directory, sizeof(other_directory), "%s/other", directory) < 0 ||
        snprintf(archive_path, sizeof(archive_path), "%s/archive.mpqe", source_directory) < 0 ||
        mkdir(directory, 0700) != 0 || mkdir(source_directory, 0700) != 0 ||
        mkdir(other_directory, 0700) != 0)
        goto cleanup;
    initial_directory = getcwd(NULL, 0);
    if (initial_directory == NULL || chdir(source_directory) != 0)
        goto cleanup;
    changed_directory = 1;
    if (libmpq__archive_create_mpqe(
            &archive, "archive.mpqe", mpqe_authentication_code,
            sizeof(mpqe_authentication_code) - 1U, NULL
        ) != 0 ||
        libmpq__file_add(archive, "cwd.txt", payload, sizeof(payload) - 1U, NULL) != 0 ||
        chdir("../other") != 0)
        goto cleanup;
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != 0 || chdir(initial_directory) != 0)
        goto cleanup;
    changed_directory = 0;
    if (libmpq__archive_open_mpqe(
            &reader, archive_path, 0, mpqe_authentication_code,
            sizeof(mpqe_authentication_code) - 1U
        ) != 0 ||
        libmpq__file_number(reader, "cwd.txt", &number) != 0 ||
        verify_mpqe_file(reader, "cwd.txt", payload, sizeof(payload) - 1U) != 0 ||
        count_mpqe_temps(source_directory) != 0)
        goto cleanup;
    status = 0;

cleanup:
    if (changed_directory && initial_directory != NULL)
        (void)chdir(initial_directory);
    free(initial_directory);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (reader != NULL)
        (void)libmpq__archive_close(reader);
    remove(archive_path);
    rmdir(other_directory);
    rmdir(source_directory);
    rmdir(directory);
    return status;
}

/* Make payloads deterministic and compressible while retaining changing bytes. */
static void
fill_property_payload(uint8_t *data, size_t size)
{
    size_t i;

    for (i = 0; i < size; ++i) {
        data[i] = (uint8_t)((i / 97U + i % 5U) & 0xffU);
    }
    if (size >= 8U) {
        data[0] = 'R';
        data[1] = 'I';
        data[2] = 'F';
        data[3] = 'F';
        data[4] = (uint8_t)((size - 8U) & 0xffU);
        data[5] = (uint8_t)(((size - 8U) >> 8) & 0xffU);
        data[6] = (uint8_t)(((size - 8U) >> 16) & 0xffU);
        data[7] = (uint8_t)(((size - 8U) >> 24) & 0xffU);
    }
}

/* Select combinations the MPQ writer can represent for this payload shape. */
static int
property_mode_supported(const writer_mode_s *mode, uint32_t sector_size, size_t payload_size)
{
    if (payload_size == 0 &&
        (mode->options.flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE |
                                LIBMPQ_FILE_FLAG_ENCRYPTED)) != 0) {
        return 0;
    }
    if (payload_size < 8U && (mode->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0)
        return 0;
    if (payload_size > sector_size && (mode->options.flags & LIBMPQ_FILE_FLAG_SINGLE) != 0)
        return 0;
    return 1;
}

/* Verify one generated archive can reopen and reproduce every selected mode. */
static int
test_property_case(uint32_t version, uint32_t sector_size, size_t payload_size)
{
    char path[160] = { 0 };
    uint8_t *payload = NULL;
    uint8_t *output = NULL;
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s archive_options = { version, 32, sector_size, 0 };
    libmpq__off_t transferred;
    int32_t result;
    uint32_t number;
    size_t i;
    int status = 1;

    payload = malloc(payload_size == 0 ? 1U : payload_size);
    if (payload == NULL) {
        test_failure(__FILE__, __LINE__, "payload != NULL");
        goto cleanup;
    }
    output = malloc(payload_size == 0 ? 1U : payload_size);
    if (output == NULL) {
        test_failure(__FILE__, __LINE__, "output != NULL");
        goto cleanup;
    }
    fill_property_payload(payload, payload_size);
    if (test_temp_path(path, sizeof(path), "writer-property") != 0) {
        test_failure(
            __FILE__, __LINE__, "test_temp_path(path, sizeof(path), \"writer-property\") == 0"
        );
        goto cleanup;
    }
    if (libmpq__archive_create(&archive, path, &archive_options) != 0) {
        test_failure(
            __FILE__, __LINE__, "libmpq__archive_create(&archive, path, &archive_options) == 0"
        );
        goto cleanup;
    }
    for (i = 0; i < sizeof(writer_modes) / sizeof(writer_modes[0]); ++i) {
        int32_t add_result;

        if (!property_mode_supported(&writer_modes[i], sector_size, payload_size)) {
            continue;
        }
        add_result = libmpq__file_add(
            archive, writer_modes[i].name, payload, (libmpq__off_t)payload_size,
            &writer_modes[i].options
        );
        if (add_result != 0) {
            fprintf(
                stderr, "writer property add failed: v%u sector %u size %zu mode %s: %d\n", version,
                sector_size, payload_size, writer_modes[i].name, add_result
            );
        }
        if (add_result != 0) {
            test_failure(__FILE__, __LINE__, "add_result == 0");
            goto cleanup;
        }
    }
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != 0) {
        test_failure(__FILE__, __LINE__, "libmpq__archive_close(archive) == 0");
        goto cleanup;
    }
    if (libmpq__archive_open(&archive, path, 0) != 0) {
        test_failure(__FILE__, __LINE__, "libmpq__archive_open(&archive, path, 0) == 0");
        goto cleanup;
    }
    for (i = 0; i < sizeof(writer_modes) / sizeof(writer_modes[0]); ++i) {
        if (!property_mode_supported(&writer_modes[i], sector_size, payload_size)) {
            continue;
        }
        if (libmpq__file_number(archive, writer_modes[i].name, &number) != 0) {
            test_failure(
                __FILE__, __LINE__,
                "libmpq__file_number(archive, writer_modes[i].name, &number) == 0"
            );
            goto cleanup;
        }
        result =
            libmpq__file_read(archive, number, output, (libmpq__off_t)payload_size, &transferred);
        if (result != 0) {
            fprintf(
                stderr, "writer property failed: v%u sector %u size %zu mode %s: %d\n", version,
                sector_size, payload_size, writer_modes[i].name, result
            );
        }
        if (result != 0) {
            test_failure(__FILE__, __LINE__, "result == 0");
            goto cleanup;
        }
        if (transferred != (libmpq__off_t)payload_size) {
            test_failure(__FILE__, __LINE__, "transferred == (libmpq__off_t)payload_size");
            goto cleanup;
        }
        if (memcmp(output, payload, payload_size) != 0) {
            size_t mismatch = 0;

            while (mismatch < payload_size && output[mismatch] == payload[mismatch])
                mismatch++;
            fprintf(
                stderr,
                "writer property mismatch: v%u sector %u size %zu mode %s at %zu (%u != %u)\n",
                version, sector_size, payload_size, writer_modes[i].name, mismatch,
                output[mismatch], payload[mismatch]
            );
        }
        if (memcmp(output, payload, payload_size) != 0) {
            test_failure(__FILE__, __LINE__, "memcmp(output, payload, payload_size) == 0");
            goto cleanup;
        }
    }
    if (libmpq__archive_close(archive) != 0) {
        test_failure(__FILE__, __LINE__, "libmpq__archive_close(archive) == 0");
        goto cleanup;
    }
    archive = NULL;
    status = 0;

cleanup:
    if (archive != NULL)
        libmpq__archive_close(archive);
    free(output);
    free(payload);
    if (path[0] != '\0')
        remove(path);
    return status;
}

/* Cover archive versions, valid sector sizes, and every sector-boundary shape. */
static int
test_writer_properties(void)
{
    static const uint32_t versions[] = { LIBMPQ_ARCHIVE_VERSION_ONE, LIBMPQ_ARCHIVE_VERSION_TWO };
    static const uint32_t sector_sizes[] = { 512, 4096, 16384 };
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i) {
        for (j = 0; j < sizeof(sector_sizes) / sizeof(sector_sizes[0]); ++j) {
            size_t sector_size = sector_sizes[j];
            size_t lengths[] = { 0,
                                 1,
                                 sector_size - 1U,
                                 sector_size,
                                 sector_size + 1U,
                                 sector_size * 2U - 1U,
                                 sector_size * 2U,
                                 sector_size * 2U + 1U };
            size_t k;

            for (k = 0; k < sizeof(lengths) / sizeof(lengths[0]); ++k) {
                TEST_CHECK(test_property_case(versions[i], sector_sizes[j], lengths[k]) == 0);
            }
        }
    }

    return 0;
}

/* Retain convenience-path and streamed-writer coverage in deterministic archives. */
static int
test_create_one(const char *path, uint32_t version)
{
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };
    mpq_file_options_s compressed = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                      LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    uint8_t repetitive[12000];
    uint8_t stream_data[5000];
    char source_path[160];
    FILE *source;

    TEST_CHECK(test_add_archive(&archive, path, version, LIBMPQ_ARCHIVE_CREATE_LISTFILE) == 0);
    memset(repetitive, 'R', sizeof(repetitive));
    test_payload(stream_data, sizeof(stream_data), 42);
    TEST_CHECK(snprintf(source_path, sizeof(source_path), "%s.input", path) > 0);
    source = fopen(source_path, "wb");
    TEST_CHECK(source != NULL && fwrite("path-data", 1, 9, source) == 9);
    TEST_CHECK(fclose(source) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "repeat.bin", repetitive, sizeof(repetitive), &compressed) == 0
    );
    TEST_CHECK(libmpq__file_add_path(archive, "path.bin", source_path, &raw) == 0);
    TEST_CHECK(libmpq__file_begin(archive, "stream.bin", sizeof(stream_data), &raw, &writer) == 0);
    TEST_CHECK(libmpq__file_write(writer, stream_data, 1234) == 0);
    TEST_CHECK(libmpq__file_write(writer, stream_data + 1234, sizeof(stream_data) - 1234) == 0);
    TEST_CHECK(libmpq__file_finish(writer) == 0);
    {
        int32_t result = libmpq__archive_close(archive);

        archive = NULL;
        TEST_CHECK(result == 0);
    }
    remove(source_path);
    return 0;
}

/* Retain the byte-for-byte determinism check for repeated v1 output. */
static int
test_writer_determinism(void)
{
    char first_path[160];
    char second_path[160];
    uint8_t *first;
    uint8_t *second;
    size_t first_size;
    size_t second_size;
    TEST_CHECK(test_temp_path(first_path, sizeof(first_path), "writer-a") == 0);
    TEST_CHECK(test_temp_path(second_path, sizeof(second_path), "writer-b") == 0);
    TEST_CHECK(test_create_one(first_path, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_create_one(second_path, LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_read_path(first_path, &first, &first_size) == 0);
    TEST_CHECK(test_read_path(second_path, &second, &second_size) == 0);
    TEST_CHECK(first_size == second_size && memcmp(first, second, first_size) == 0);
    free(first);
    free(second);
    remove(first_path);
    remove(second_path);
    TEST_CHECK(test_temp_path(first_path, sizeof(first_path), "writer-v2") == 0);
    TEST_CHECK(test_create_one(first_path, LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    remove(first_path);
    return 0;
}

/* Verify deterministic output, generated properties, and MPQE creation/failure hardening. */
int
main(void)
{
    TEST_CHECK(test_writer_determinism() == 0);
    TEST_CHECK(test_writer_properties() == 0);
    TEST_CHECK(test_mpqe_writer_credential_validation() == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_ONE, 1) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_TWO, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_TWO, 1) == 0);
    TEST_CHECK(test_mpqe_writer_byte_equality(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_mpqe_writer_byte_equality(LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    TEST_CHECK(test_mpqe_writer_chdir() == 0);
    TEST_CHECK(test_mpqe_writer_fault(LIBMPQ_WRITER_TEST_FAULT_FINALIZE) == 0);
    TEST_CHECK(test_mpqe_writer_fault(LIBMPQ_WRITER_TEST_FAULT_TRANSFORM) == 0);
    TEST_CHECK(test_mpqe_writer_fault(LIBMPQ_WRITER_TEST_FAULT_OUTPUT_CLOSE) == 0);
    TEST_CHECK(test_mpqe_writer_fault(LIBMPQ_WRITER_TEST_FAULT_PUBLISH) == 0);
    return 0;
}
