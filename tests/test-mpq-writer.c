/*
 *  test-mpq-writer.c -- libmpq regression tests.
 *
 *  Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
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

/* GNU stream cookies provide local write-error injection, never production hooks. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

/* Exercise deterministic writer output and generated writer/readback properties. */
#include "mpq-archive.h"
#include "mpq-bet.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-mpqe.h"
#include "mpq-reader.h"
#include "mpq-source.h"
#include "mpq-writer.h"
#include "test-mpq-helper.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef __GLIBC__
#include <sys/types.h>
#endif

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
    { "lzma",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_LZMA, LIBMPQ_COMPRESSION_LZMA, 0, 0 } },
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
    { "lzma-encrypted",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_LZMA,
        LIBMPQ_COMPRESSION_LZMA, 0, 0 } },
    { "multi-encrypted",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_PKZIP |
            LIBMPQ_COMPRESSION_BZIP2,
        0, 0 } },
    { "zlib-single",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "lzma-single",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE, LIBMPQ_COMPRESSION_LZMA,
        LIBMPQ_COMPRESSION_LZMA, 0, 0 } }
};

static const uint8_t mpqe_auth_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";

typedef enum
{
    MPQE_WRITER_FAULT_FINALIZE,
    MPQE_WRITER_FAULT_TRANSFORM,
    MPQE_WRITER_FAULT_OUTPUT_CLOSE,
    MPQE_WRITER_FAULT_PUBLISH
} mpqe_writer_fault_e;

/* Per-archive operations fail deterministically without affecting other writers. */
static int32_t
fail_finalize(mpq_archive_s *archive)
{
    (void)archive;
    return LIBMPQ_ERROR_WRITE;
}

static int32_t
fail_transform(mpq_archive_s *archive)
{
    (void)archive;
    return LIBMPQ_ERROR_WRITE;
}

static int
fail_close_output(FILE *output)
{
    (void)fclose(output);
    return EOF;
}

static int32_t
fail_publish(mpq_directory_s *directory, const char *temporary, const char *destination)
{
    (void)directory;
    (void)temporary;
    (void)destination;
    return LIBMPQ_ERROR_WRITE;
}

static void
apply_finalize_fault(mpq_writer_mpqe_ops_s *ops)
{
    ops->finalize = fail_finalize;
}

static void
apply_transform_fault(mpq_writer_mpqe_ops_s *ops)
{
    ops->transform = fail_transform;
}

static void
apply_output_close_fault(mpq_writer_mpqe_ops_s *ops)
{
    ops->close_output = fail_close_output;
}

static void
apply_publish_fault(mpq_writer_mpqe_ops_s *ops)
{
    ops->publish = fail_publish;
}

static void (*const fault_appliers[])(mpq_writer_mpqe_ops_s *) = {
    apply_finalize_fault,
    apply_transform_fault,
    apply_output_close_fault,
    apply_publish_fault,
};

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
    result = libmpq__archive_add_data(archive, "raw.bin", raw, sizeof(raw), NULL);
    if (result == 0)
        result = libmpq__archive_add_data(
            archive, "compressed.bin", packed, sizeof(packed), &compressed
        );
    if (result == 0)
        result = libmpq__archive_add_data(archive, "encrypted.bin", raw, sizeof(raw), &encrypted);
    if (result == 0) {
        result = libmpq__archive_add_data(
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
    mpq_archive_create_options_s options = { version, 8, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
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
        &archive, path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1U, &options
    );
    if (result == 0)
        result = add_mpqe_feature_files(archive) == 0 ? 0 : LIBMPQ_ERROR_WRITE;
    if (result == 0) {
        result = libmpq__archive_close(archive);
        archive = NULL;
    }
    if (result != 0)
        goto cleanup;
    result =
        libmpq__archive_open_mpqe(&reader, path, 0, mpqe_auth_code, sizeof(mpqe_auth_code) - 1U);
    if (result != 0 || verify_mpqe_file(reader, "raw.bin", raw, sizeof(raw)) != 0)
        goto cleanup;
    if (verify_mpqe_file(reader, "compressed.bin", packed, sizeof(packed)) != 0)
        goto cleanup;
    if (libmpq__file_number(reader, "encrypted.bin", &number) != 0 ||
        libmpq__file_flags(reader, number, &encrypted) != 0 ||
        (encrypted & LIBMPQ_FILE_FLAG_ENCRYPTED) == 0 ||
        libmpq__file_read(
            reader, number, encrypted_output, sizeof(encrypted_output), &transferred
        ) != LIBMPQ_ERROR_DECRYPT)
        goto cleanup;
    if (verify_mpqe_file(reader, "compressed-encrypted.bin", packed, sizeof(packed)) != 0)
        goto cleanup;
    if (libmpq__file_number(reader, "(listfile)", &number) != 0)
        goto cleanup;
    if (version >= LIBMPQ_ARCHIVE_VERSION_THREE) {
        mpq_stream_s *stream = NULL;
        uint32_t generation;
        if (libmpq__archive_version(reader, &generation) != 0 || generation != version + 1 ||
            reader->mpq_bet.header.entry_count == 0 ||
            libmpq__stream_open_name(reader, "raw.bin", &stream) != 0)
            goto cleanup;
        result = libmpq__stream_seek(stream, 31, SEEK_SET);
        if (result == 0)
            result = libmpq__stream_read(stream, encrypted_output, 41, &transferred);
        if (libmpq__stream_close(stream) != 0 || result != 0 || transferred != 41 ||
            memcmp(encrypted_output, raw + 31, 41) != 0)
            goto cleanup;
    }
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
            &archive, path, mpqe_auth_code, sizeof(mpqe_auth_code) - 2U, NULL
        ) == LIBMPQ_ERROR_DECRYPT
    );
    TEST_CHECK(archive == NULL);
    {
        struct stat status;

        TEST_CHECK(stat(path, &status) != 0);
    }
    return 0;
}

/* Apply the private symmetric transform with a test-owned derived MPQE key. */
static int32_t
transform_mpqe_chunk(uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE], uint64_t offset)
{
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    int32_t result;

    result = libmpq__mpqe_key(key, mpqe_auth_code, sizeof(mpqe_auth_code) - 1U);
    if (result == 0)
        libmpq__mpqe_transform_chunk(chunk, key, offset);
    libmpq__mpqe_clear(key, sizeof(key));
    return result;
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
        if (transform_mpqe_chunk(chunk, offset) != 0) {
            libmpq__mpqe_clear(chunk, sizeof(chunk));
            free(*data);
            *data = NULL;
            *size = 0;
            return 1;
        }
        memcpy(*data + offset, chunk, physical);
    }
    return 0;
}

/*
 * Compare normal writer bytes with the complete decrypted MPQE stream, including its final chunk.
 */
static int
test_mpqe_writer_byte_equality(uint32_t version)
{
    char raw_path[160] = { 0 };
    char mpqe_path[160] = { 0 };
    mpq_archive_create_options_s options = { version, 8, 512, 0, 0 };
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
        libmpq__archive_add_data(raw_archive, "partial.bin", payload, sizeof(payload), NULL) != 0)
        goto cleanup;
    result = libmpq__archive_close(raw_archive);
    raw_archive = NULL;
    if (result != 0)
        goto cleanup;
    if (libmpq__archive_create_mpqe(
            &mpqe_archive, mpqe_path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1U, &options
        ) != 0 ||
        libmpq__archive_add_data(mpqe_archive, "partial.bin", payload, sizeof(payload), NULL) != 0)
        goto cleanup;
    result = libmpq__archive_close(mpqe_archive);
    mpqe_archive = NULL;
    if (result != 0)
        goto cleanup;
    if (stat(raw_path, &raw_status) != 0 || stat(mpqe_path, &mpqe_status) != 0 ||
        raw_status.st_size != mpqe_status.st_size || raw_status.st_size % 64 == 0 ||
#ifndef _WIN32
        (raw_status.st_mode & 0777) != (mpqe_status.st_mode & 0777) ||
#endif
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
#ifdef _WIN32
    WIN32_FIND_DATAA entry;
    HANDLE search;
    char pattern[1024];
    int count = 0;

    if (snprintf(pattern, sizeof(pattern), "%s/*", directory) >= (int)sizeof(pattern))
        return -1;
    search = FindFirstFileA(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE)
        return -1;
    do {
        if (strncmp(entry.cFileName, ".libmpq-raw-", 12) == 0 ||
            strncmp(entry.cFileName, ".libmpq-mpqe-", 13) == 0)
            count++;
    } while (FindNextFileA(search, &entry));
    FindClose(search);
    return count;
#else
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
#endif
}

/* A handled finalization failure must consume the writer and preserve an existing destination. */
static int
test_mpqe_writer_fault(mpqe_writer_fault_e fault, uint32_t attributes, uint32_t version)
{
    char directory[160] = { 0 };
    char path[176] = { 0 };
    static const uint8_t original[] = "existing MPQE destination";
    uint8_t *actual = NULL;
    size_t actual_size;
    mpq_archive_s *archive = NULL;
    mpq_writer_mpqe_ops_s ops;
    mpq_archive_create_options_s options = { version, 8, 4096,
                                             attributes ? LIBMPQ_ARCHIVE_CREATE_LISTFILE : 0,
                                             attributes };
    int32_t result;
    int status = 1;

    if (test_temp_path(directory, sizeof(directory), "writer-mpqe-fault") != 0 ||
        test_mkdir(directory) != 0 ||
        snprintf(path, sizeof(path), "%s/archive.mpqe", directory) < 0)
        goto cleanup;
    if (write_test_path(path, original, sizeof(original) - 1U) != 0)
        goto cleanup;
    if (libmpq__archive_create_mpqe(
            &archive, path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1U, &options
        ) != 0 ||
        libmpq__archive_add_data(archive, "payload.bin", original, sizeof(original) - 1U, NULL) !=
            0)
        goto cleanup;
    if (archive->write_mpqe_ops == NULL)
        goto cleanup;
    ops = *archive->write_mpqe_ops;
    if ((size_t)fault >= sizeof(fault_appliers) / sizeof(fault_appliers[0]))
        goto cleanup;
    fault_appliers[fault](&ops);
    archive->write_mpqe_ops = &ops;
    if (version == LIBMPQ_ARCHIVE_VERSION_FOUR) {
        result = libmpq__writer_finalize(archive);
        if (result == 0)
            result = libmpq__writer_finalize_mpqe(archive);
        if (result == 0 || archive->write_error != result ||
            libmpq__writer_finalize(archive) != result ||
            libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, NULL, 0) != result ||
            libmpq__archive_add_data(archive, "late", original, 1, NULL) != result)
            goto cleanup;
    }
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result == 0)
        goto cleanup;
    if (test_read_path(path, &actual, &actual_size) != 0 || actual_size != sizeof(original) - 1U ||
        memcmp(actual, original, actual_size) != 0 || count_mpqe_temps(directory) != 0)
        goto cleanup;
    status = 0;

cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    free(actual);
    remove(path);
    test_rmdir(directory);
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
        test_mkdir(directory) != 0 || test_mkdir(source_directory) != 0 ||
        test_mkdir(other_directory) != 0)
        goto cleanup;
    initial_directory = test_getcwd();
    if (initial_directory == NULL || test_chdir(source_directory) != 0)
        goto cleanup;
    changed_directory = 1;
    if (libmpq__archive_create_mpqe(
            &archive, "archive.mpqe", mpqe_auth_code, sizeof(mpqe_auth_code) - 1U, NULL
        ) != 0 ||
        libmpq__archive_add_data(archive, "cwd.txt", payload, sizeof(payload) - 1U, NULL) != 0 ||
        test_chdir("../other") != 0)
        goto cleanup;
    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != 0 || test_chdir(initial_directory) != 0)
        goto cleanup;
    changed_directory = 0;
    if (libmpq__archive_open_mpqe(
            &reader, archive_path, 0, mpqe_auth_code, sizeof(mpqe_auth_code) - 1U
        ) != 0 ||
        libmpq__file_number(reader, "cwd.txt", &number) != 0 ||
        verify_mpqe_file(reader, "cwd.txt", payload, sizeof(payload) - 1U) != 0 ||
        count_mpqe_temps(source_directory) != 0)
        goto cleanup;
    status = 0;

cleanup:
    if (changed_directory && initial_directory != NULL)
        (void)test_chdir(initial_directory);
    free(initial_directory);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (reader != NULL)
        (void)libmpq__archive_close(reader);
    remove(archive_path);
    test_rmdir(other_directory);
    test_rmdir(source_directory);
    test_rmdir(directory);
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
property_mode_supported(
    const writer_mode_s *mode, uint32_t version, uint32_t sector_size, size_t payload_size
)
{
    if (!libmpq__archive_compression_allowed(
            version, mode->options.compression_first, LIBMPQ_COMPRESSION_POLICY_EXTENDED
        ) ||
        !libmpq__archive_compression_allowed(
            version, mode->options.compression_next, LIBMPQ_COMPRESSION_POLICY_EXTENDED
        )) {
        return 0;
    }
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
    mpq_archive_create_options_s archive_options = { version, 32, sector_size,
                                                     LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                                     0 };
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

        if (!property_mode_supported(&writer_modes[i], version, sector_size, payload_size)) {
            continue;
        }
        add_result = libmpq__archive_add_data(
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
        if (!property_mode_supported(&writer_modes[i], version, sector_size, payload_size)) {
            continue;
        }
        if (libmpq__file_number(archive, writer_modes[i].name, &number) != 0) {
            test_failure(
                __FILE__, __LINE__,
                "libmpq__file_number(archive, writer_modes[i].name, &number) == 0"
            );
            goto cleanup;
        }
        {
            uint32_t flags = 0;

            if (libmpq__file_flags(archive, number, &flags) != 0 ||
                flags != archive->mpq_entry[archive->mpq_map[number].entry_index].flags) {
                test_failure(__FILE__, __LINE__, "stored file flags match canonical metadata");
                goto cleanup;
            }
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
    static const uint32_t versions[] = { LIBMPQ_ARCHIVE_VERSION_ONE, LIBMPQ_ARCHIVE_VERSION_TWO,
                                         LIBMPQ_ARCHIVE_VERSION_THREE };
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
        libmpq__archive_add_data(
            archive, "repeat.bin", repetitive, sizeof(repetitive), &compressed
        ) == 0
    );
    TEST_CHECK(libmpq__archive_add_path(archive, "path.bin", source_path, &raw) == 0);
    TEST_CHECK(
        libmpq__writer_begin(archive, "stream.bin", sizeof(stream_data), &raw, &writer) == 0
    );
    TEST_CHECK(libmpq__writer_write(writer, stream_data, 1234) == 0);
    TEST_CHECK(libmpq__writer_write(writer, stream_data + 1234, sizeof(stream_data) - 1234) == 0);
    TEST_CHECK(libmpq__writer_finish(writer) == 0);
    {
        int32_t result = libmpq__archive_close(archive);

        archive = NULL;
        TEST_CHECK(result == 0);
    }
    remove(source_path);
    return 0;
}

/* Closing after a write error consumes the archive and releases its writer. */
static int
test_writer_abort_on_close(void)
{
    char path[160];
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };

    TEST_CHECK(test_temp_path(path, sizeof(path), "writer-abort") == 0);
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(libmpq__writer_begin(archive, "unfinished.bin", 1, &raw, &writer) == 0);
    TEST_CHECK(writer != NULL);
    TEST_CHECK(libmpq__writer_write(writer, (const uint8_t *)"xx", 2) == LIBMPQ_ERROR_SIZE);
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_SIZE);
    remove(path);
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

/* Probe the writer hash table without changing duplicate identity rules. */
static int
test_writer_duplicate_identity(void)
{
    char path[160];
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { 0, 0, 0, 0, 0 };
    const uint8_t data[] = { 0x42 };

    TEST_CHECK(test_temp_path(path, sizeof(path), "writer-duplicate") == 0);
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "first.bin", data, sizeof(data), &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "second.bin", data, sizeof(data), &options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "FIRST.BIN", data, sizeof(data), &options) ==
        LIBMPQ_ERROR_EXIST
    );
    options.locale = 1;
    TEST_CHECK(libmpq__archive_add_data(archive, "first.bin", data, sizeof(data), &options) == 0);
    options.locale = 0;
    options.platform = 1;
    TEST_CHECK(libmpq__archive_add_data(archive, "first.bin", data, sizeof(data), &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}

/* A duplicate must be found after an earlier name displaced its hash slot. */
static int
test_writer_displaced_duplicate(void)
{
    char path[160];
    char first[64] = { 0 };
    char second[64] = { 0 };
    mpq_archive_s *archive = NULL;
    const uint8_t data[] = { 0x42 };
    uint32_t capacity;
    uint32_t first_hash[3] = { 0, 0, 0 };
    uint32_t second_hash[3] = { 0, 0, 0 };
    uint32_t bucket;
    uint32_t displaced;
    int found = 0;

    TEST_CHECK(test_temp_path(path, sizeof(path), "writer-displaced") == 0);
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    capacity = archive->write_hash_capacity;
    TEST_CHECK(capacity != 0 && (capacity & (capacity - 1)) == 0);
    for (uint32_t a = 0; a < capacity && !found; a++) {
        (void)snprintf(first, sizeof(first), "collision-%04u.bin", a);
        libmpq__file_hash(first, &first_hash[0], &first_hash[1], &first_hash[2]);
        for (uint32_t b = a + 1; b <= capacity; b++) {
            (void)snprintf(second, sizeof(second), "collision-%04u.bin", b);
            libmpq__file_hash(second, &second_hash[0], &second_hash[1], &second_hash[2]);
            if ((first_hash[0] & (capacity - 1)) == (second_hash[0] & (capacity - 1)) &&
                (first_hash[0] != second_hash[0] || first_hash[1] != second_hash[1] ||
                 first_hash[2] != second_hash[2])) {
                found = 1;
                break;
            }
        }
    }
    TEST_CHECK(found && strcmp(first, second) != 0);
    bucket = first_hash[0] & (capacity - 1);
    displaced = (bucket + 1) & (capacity - 1);
    TEST_CHECK((second_hash[0] & (capacity - 1)) == bucket);
    TEST_CHECK(libmpq__archive_add_data(archive, first, data, sizeof(data), NULL) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, second, data, sizeof(data), NULL) == 0);
    TEST_CHECK(archive->mpq_hash[bucket].hash_a == first_hash[1]);
    TEST_CHECK(archive->mpq_hash[bucket].hash_b == first_hash[2]);
    TEST_CHECK(archive->mpq_hash[displaced].hash_a == second_hash[1]);
    TEST_CHECK(archive->mpq_hash[displaced].hash_b == second_hash[2]);
    TEST_CHECK(archive->mpq_hash[displaced].block_table_index != LIBMPQ_HASH_FREE);
    TEST_CHECK(
        archive->mpq_hash[displaced].block_table_index !=
        archive->mpq_hash[bucket].block_table_index
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, second, data, sizeof(data), NULL) == LIBMPQ_ERROR_EXIST
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}

#ifdef __GLIBC__
typedef struct
{
    uint64_t position;
    uint64_t size;
    size_t read_size;
    int closed;
} writer_signature_io_s;

/* Virtual storage checks wide signing positions without hashing a 4 GiB hole. */
static ssize_t
writer_signature_read(void *context, char *output, size_t size)
{
    writer_signature_io_s *io = context;
    (void)output;
    io->read_size = size;
    return 0;
}

static ssize_t
writer_signature_write(void *context, const char *input, size_t size)
{
    writer_signature_io_s *io = context;
    (void)input;
    if (size > (uint64_t)INT64_MAX - io->position)
        return 0;
    io->position += size;
    if (io->position > io->size)
        io->size = io->position;
    return (ssize_t)size;
}

static int
writer_signature_seek(void *context, off64_t *offset, int origin)
{
    writer_signature_io_s *io = context;
    off64_t base = origin == SEEK_SET ? 0 : (off64_t)(origin == SEEK_END ? io->size : io->position);
    if (*offset < -base || *offset > INT64_MAX - base)
        return -1;
    *offset += base;
    io->position = (uint64_t)*offset;
    return 0;
}

static int
writer_signature_close(void *context)
{
    ((writer_signature_io_s *)context)->closed = 1;
    return 0;
}

static int
test_v3_high_signature_io(void)
{
    cookie_io_functions_t ops = { writer_signature_read, writer_signature_write,
                                  writer_signature_seek, writer_signature_close };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_THREE, 4, 512, 0, 0 };
    uint8_t strong_key[sizeof(test_strong_signature_public_key)];
    test_strong_signature_private_key(strong_key);
    for (unsigned int strong = 0; strong < 2; ++strong) {
        writer_signature_io_s io = { 0 };
        mpq_archive_s *archive = NULL;
        FILE *fp = fopencookie(&io, "w+b", ops);
        TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
        TEST_CHECK(
            libmpq__writer_archive_create_file(&archive, "wide-signature", fp, &options) == 0
        );
        TEST_CHECK(libmpq__file_seek(fp, UINT64_C(0x100000040), SEEK_SET) == 0);
        TEST_CHECK(
            libmpq__archive_sign(
                archive, strong ? LIBMPQ_SIGNATURE_STRONG : LIBMPQ_SIGNATURE_WEAK,
                strong ? strong_key : test_signature_private_key,
                strong ? sizeof(strong_key) : sizeof(test_signature_private_key)
            ) == 0
        );
        if (!strong)
            TEST_CHECK(archive->write_signature_offset == UINT64_C(0x100000040));
        TEST_CHECK(
            libmpq__archive_add_data(archive, "payload", (const uint8_t *)"data", 4, NULL) == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_READ);
        TEST_CHECK(io.closed && io.size > UINT32_MAX && io.read_size != 0 && io.read_size <= 16384);
    }
    return 0;
}

typedef struct
{
    uint8_t bytes[16384];
    size_t size;
    uint64_t position;
    size_t fail_at;
    int closed;
    uint64_t end_override;
} writer_v3_fault_s;

static ssize_t
writer_v3_fault_write(void *context, const char *input, size_t size)
{
    writer_v3_fault_s *fault = context;
    if (fault->position > sizeof(fault->bytes) || fault->position >= fault->fail_at ||
        size > fault->fail_at - fault->position || size > sizeof(fault->bytes) - fault->position)
        return 0;
    memcpy(fault->bytes + fault->position, input, size);
    fault->position += size;
    if (fault->position > fault->size)
        fault->size = fault->position;
    return (ssize_t)size;
}

static int
writer_v3_fault_seek(void *context, off64_t *offset, int origin)
{
    writer_v3_fault_s *fault = context;

    /* Report virtual near-limit ends without allocating or writing at those positions. */
    if (*offset == 0 && ((origin == SEEK_END && fault->end_override != 0) ||
                         (origin == SEEK_CUR && fault->position > sizeof(fault->bytes)))) {
        if (origin == SEEK_END)
            fault->position = fault->end_override;
        *offset = (off64_t)fault->position;
        return 0;
    }
    off64_t base =
        origin == SEEK_SET ? 0 : (off64_t)(origin == SEEK_END ? fault->size : fault->position);
    if (*offset < -base || *offset > (off64_t)sizeof(fault->bytes) - base)
        return -1;
    *offset += base;
    fault->position = (size_t)*offset;
    return 0;
}

static int
writer_v3_fault_close(void *context)
{
    writer_v3_fault_s *fault = context;
    fault->closed = 1;
    return 0;
}

static int
test_v3_failures(void)
{
    cookie_io_functions_t ops = { NULL, writer_v3_fault_write, writer_v3_fault_seek,
                                  writer_v3_fault_close };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_THREE, 4, 512, 0, 0 };
    uint64_t positions[6];
    writer_v3_fault_s reference = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
    mpq_archive_s *archive = NULL;
    uint8_t data[600] = { 1 };
    FILE *fp = fopencookie(&reference, "w+b", ops);
    size_t i;
    TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
    TEST_CHECK(libmpq__writer_archive_create_file(&archive, "cookie-v3", fp, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL) == 0);
    TEST_CHECK(libmpq__writer_finalize(archive) == 0 && archive->write_finalized);
    positions[0] = 68;
    positions[1] = archive->mpq_header_v3.het_table_offset;
    positions[2] = archive->mpq_header_v3.bet_table_offset;
    positions[3] = archive->mpq_header.hash_table_offset;
    positions[4] = archive->mpq_header.block_table_offset;
    positions[5] = 0;
    TEST_CHECK(libmpq__archive_close(archive) == 0 && reference.closed);
    for (i = 0; i < 6; ++i) {
        writer_v3_fault_s fault = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
        int32_t result;
        fp = fopencookie(&fault, "w+b", ops);
        TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
        TEST_CHECK(libmpq__writer_archive_create_file(&archive, "cookie-v3", fp, &options) == 0);
        if (i == 0)
            fault.fail_at = (size_t)positions[i];
        result = libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL);
        if (i == 0) {
            TEST_CHECK(result == LIBMPQ_ERROR_WRITE);
            TEST_CHECK(libmpq__archive_close(archive) != 0 && fault.closed);
        } else {
            TEST_CHECK(result == 0);
            fault.fail_at = (size_t)positions[i];
            TEST_CHECK(libmpq__writer_finalize(archive) == LIBMPQ_ERROR_WRITE);
            TEST_CHECK(!archive->write_finalized);
            TEST_CHECK(libmpq__archive_close(archive) != 0 && fault.closed);
        }
        TEST_CHECK(fault.bytes[0] == 0); /* No successful header escaped a failed write. */
    }

    /* At the last representable classic table position, layout succeeds before I/O fails. */
    {
        writer_v3_fault_s fault = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
        fp = fopencookie(&fault, "w+b", ops);
        TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
        TEST_CHECK(libmpq__writer_archive_create_file(&archive, "cookie-v3", fp, &options) == 0);
        TEST_CHECK(libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL) == 0);
        fault.end_override = UINT64_C(0xffffffffffff) - (positions[4] - positions[1]);
        TEST_CHECK(libmpq__writer_finalize(archive) == LIBMPQ_ERROR_WRITE);
        TEST_CHECK(archive->mpq_header.block_table_offset == UINT32_MAX);
        TEST_CHECK(archive->mpq_header_ex.block_table_offset_high == UINT16_MAX);
        TEST_CHECK(archive->mpq_header_v3.bet_table_offset > UINT32_MAX);
        TEST_CHECK(libmpq__archive_close(archive) != 0 && fault.closed);
    }

    /* Reject each overflowing prefix, then both kinds of unrepresentable classic offset. */
    for (i = 0; i < 7; ++i) {
        writer_v3_fault_s fault = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
        fp = fopencookie(&fault, "w+b", ops);
        TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
        TEST_CHECK(libmpq__writer_archive_create_file(&archive, "cookie-v3", fp, &options) == 0);
        TEST_CHECK(libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL) == 0);
        if (i < 4) {
            uint64_t prefix = i == 0 ? 0 : positions[i + 1] - positions[1];
            fault.end_override = (uint64_t)INT64_MAX - prefix;
        } else if (i < 6) {
            uint64_t prefix = i == 4 ? 0 : positions[4] - positions[1];
            fault.end_override = UINT64_C(0x1000000000000) - prefix;
        } else {
            archive->write_hash_capacity = UINT32_MAX;
        }
        TEST_CHECK(libmpq__writer_finalize(archive) == LIBMPQ_ERROR_SIZE);
        TEST_CHECK(!archive->write_finalized && fault.bytes[0] == 0);
        TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_SIZE && fault.closed);
    }
    return 0;
}
#endif

static int
test_v3_writer(uint32_t count, bool compress_tables, uint64_t position)
{
    bool high = position > UINT32_MAX;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_THREE, 16, 4096, 0, 0 };
    mpq_archive_s *archive = NULL;
    char path[512];
    char name[32];
    uint8_t payload[10317];
    uint8_t actual[10317];
    uint32_t files;
    uint32_t i;
    uint64_t het_size;
    uint64_t bet_size;
    uint64_t hash_position;
    uint64_t block_position;
    libmpq__off_t transferred;
    libmpq__off_t value;
    uint8_t header[68];
    FILE *fp;

    TEST_CHECK(test_temp_path(path, sizeof(path), "public-v3") == 0);
    options.version = LIBMPQ_ARCHIVE_VERSION_FOUR + 1;
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(archive == NULL);
    options.version = LIBMPQ_ARCHIVE_VERSION_THREE;
    if (count == 8) {
        options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
        options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5;
    }
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(archive->write_ext_compress);

    /* Raw table storage is an internal test variant, not a new public option. */
    archive->write_ext_compress = compress_tables;
    if (count == 8)
        TEST_CHECK(
            libmpq__archive_sign(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
    if (position != 0)
        TEST_CHECK(libmpq__file_seek(archive->fp, (libmpq__off_t)position, SEEK_SET) == 0);
    {
        mpq_writer_s *writer = NULL;
        TEST_CHECK(
            libmpq__writer_begin(
                archive, "too-large", (libmpq__off_t)UINT32_MAX + 1, NULL, &writer
            ) == LIBMPQ_ERROR_SIZE
        );
        TEST_CHECK(writer == NULL);
    }
    for (i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i % 113);
    memcpy(payload, "<?xml version=\"1.0\"?>", 21);
    for (i = 0; i < count; ++i) {
        mpq_file_options_s storage = { 0, 0, 0, 0, 0 };
        snprintf(name, sizeof(name), "synthetic-%u.bin", i);
        if (i >= 2 && i != 6)
            storage.flags |= LIBMPQ_FILE_FLAG_COMPRESS;
        if ((i >= 3 && i != 7) || high)
            storage.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
        if ((i >= 4 && i != 7) || high)
            storage.flags |= 0x00020000u;
        if (i >= 6)
            storage.flags |= LIBMPQ_FILE_FLAG_SINGLE;
        if (i >= 2)
            storage.compression_first = storage.compression_next = LIBMPQ_COMPRESSION_ZLIB;
        {
            int32_t result = libmpq__archive_add_data(
                archive, name, payload, i == 1 ? 0 : (i >= 6 ? 233 : sizeof(payload)), &storage
            );
            if (result != 0)
                fprintf(stderr, "v3 add %u failed: %d\n", i, result);
            TEST_CHECK(result == 0);
        }
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    fp = libmpq__file_open(path, "rb");
    {
        mpq_update_s *update = NULL;
        mpq_patch_s *patch = NULL;
        char patch_path[1024];
        snprintf(patch_path, sizeof(patch_path), "%s.patch", path);
        TEST_CHECK(libmpq__update_begin(&update, path) == 0 && update != NULL);
        TEST_CHECK(libmpq__update_abort(update) == 0);
        TEST_CHECK(libmpq__patch_begin(&patch, path, patch_path) == 0 && patch != NULL);
        TEST_CHECK(libmpq__patch_abort(patch) == 0);
    }
    TEST_CHECK(fp != NULL && fread(header, 1, sizeof(header), fp) == sizeof(header));
    TEST_CHECK(fclose(fp) == 0);
    TEST_CHECK(header[4] == 68 && header[12] == 2 && header[13] == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.header_size == 68 && archive->mpq_header.version == 2);
    TEST_CHECK(archive->mpq_header_v3.archive_size == archive->file_size);
    TEST_CHECK(archive->mpq_header.archive_size == (archive->file_size & UINT32_MAX));
    TEST_CHECK(
        libmpq__archive_files(archive, &files) == 0 && files == count + (count == 8 ? 3u : 0u)
    );
    TEST_CHECK(archive->mpq_bet.header.entry_count == files);
    TEST_CHECK(archive->mpq_header.block_table_count == files && archive->entry_count == files);
    TEST_CHECK(libmpq__reader_ext_table_sizes(archive, &het_size, &bet_size) == 0);
    if (compress_tables) {
        TEST_CHECK(het_size < 12u + archive->mpq_het.header.table_size);
        TEST_CHECK(bet_size < 12u + archive->mpq_bet.header.table_size);
    } else {
        TEST_CHECK(het_size == 12u + archive->mpq_het.header.table_size);
        TEST_CHECK(bet_size == 12u + archive->mpq_bet.header.table_size);
    }
    hash_position = archive->mpq_header.hash_table_offset |
                    ((uint64_t)archive->mpq_header_ex.hash_table_offset_high << 32);
    block_position = archive->mpq_header.block_table_offset |
                     ((uint64_t)archive->mpq_header_ex.block_table_offset_high << 32);
    TEST_CHECK(
        archive->mpq_header_v3.het_table_offset + het_size ==
        archive->mpq_header_v3.bet_table_offset
    );
    TEST_CHECK(archive->mpq_header_v3.bet_table_offset + bet_size == hash_position);
    TEST_CHECK(
        hash_position + (uint64_t)archive->mpq_header.hash_table_count * 16 == block_position
    );
    if (position != 0) {
        TEST_CHECK(
            archive->mpq_header_ex.hash_table_offset_high == 1 &&
            archive->mpq_header_ex.block_table_offset_high == 1
        );
        TEST_CHECK(
            hash_position > UINT32_MAX && block_position > UINT32_MAX &&
            archive->mpq_header_v3.het_table_offset > UINT32_MAX &&
            archive->mpq_header_v3.bet_table_offset > UINT32_MAX
        );
    }
    if (high) {
        TEST_CHECK(archive->mpq_header_ex.extended_offset == block_position + (uint64_t)files * 16);
        TEST_CHECK(
            archive->mpq_header_v3.archive_size ==
            archive->mpq_header_ex.extended_offset + (uint64_t)files * 2
        );
    } else {
        TEST_CHECK(archive->mpq_header_ex.extended_offset == 0);
        TEST_CHECK(archive->mpq_header_v3.archive_size == block_position + (uint64_t)files * 16);
    }
    for (i = 0; i < count; ++i) {
        uint32_t number;
        uint32_t classic_number;
        uint32_t hashes[3];
        uint32_t flags;
        mpq_bet_entry_s record;
        mpq_entry_s *entry;
        mpq_stream_s *stream = NULL;
        size_t length = i == 1 ? 0 : (i >= 6 ? 233 : sizeof(payload));
        snprintf(name, sizeof(name), "synthetic-%u.bin", i);
        TEST_CHECK(libmpq__file_number(archive, name, &number) == 0);
        libmpq__file_hash(name, &hashes[0], &hashes[1], &hashes[2]);
        TEST_CHECK(
            libmpq__file_number_from_hash(
                archive, hashes[0], hashes[1], hashes[2], &classic_number
            ) == 0
        );
        TEST_CHECK(number == classic_number);
        entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
        uint32_t row = entry->classic_source_index;
        if (position != 0 && i == 0)
            TEST_CHECK(entry->offset == position);
        TEST_CHECK(archive->classic_entry_indices[row] == archive->bet_entry_indices[row]);
        TEST_CHECK(entry->source_mask == (LIBMPQ_ENTRY_SOURCE_CLASSIC | LIBMPQ_ENTRY_SOURCE_BET));
        TEST_CHECK(entry->bet_source_index == row);
        TEST_CHECK(libmpq__bet_record_decode(&archive->mpq_bet, row, &record) == 0);
        TEST_CHECK(
            record.offset == entry->offset && record.packed_size == entry->packed_size &&
            record.unpacked_size == entry->unpacked_size && record.flags == entry->flags
        );
        TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0 && flags == record.flags);
        TEST_CHECK(
            libmpq__file_offset(archive, number, &value) == 0 && (uint64_t)value == record.offset
        );
        TEST_CHECK(
            libmpq__file_size_packed(archive, number, &value) == 0 &&
            (uint64_t)value == record.packed_size
        );
        TEST_CHECK(
            libmpq__file_size_unpacked(archive, number, &value) == 0 &&
            value == (libmpq__off_t)length
        );
        {
            int32_t result = libmpq__file_read(archive, number, actual, length, &transferred);
            if (result != 0)
                fprintf(stderr, "v3 read %u failed: %d\n", i, result);
            TEST_CHECK(result == 0);
        }
        TEST_CHECK(transferred == (libmpq__off_t)length && memcmp(actual, payload, length) == 0);
        TEST_CHECK(libmpq__stream_open(archive, number, &stream) == 0);
        TEST_CHECK(libmpq__stream_size(stream, &value) == 0 && value == (libmpq__off_t)length);
        if (length != 0) {
            libmpq__off_t start = length > 4091 ? 4091 : 7;
            TEST_CHECK(libmpq__stream_seek(stream, start, SEEK_SET) == 0);
            TEST_CHECK(
                libmpq__stream_read(stream, actual, 31, &transferred) == 0 && transferred == 31
            );
            TEST_CHECK(memcmp(actual, payload + start, 31) == 0);
            TEST_CHECK(libmpq__stream_tell(stream, &value) == 0 && value == start + 31);
        }
        TEST_CHECK(libmpq__stream_close(stream) == 0);
        if ((flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0) {
            TEST_CHECK(libmpq__stream_open_name(archive, name, &stream) == 0);
            TEST_CHECK(
                libmpq__stream_read(stream, actual, 31, &transferred) == 0 && transferred == 31
            );
            TEST_CHECK(memcmp(actual, payload, 31) == 0);
            TEST_CHECK(libmpq__stream_close(stream) == 0);
        }
    }
    if (count == 8) {
        uint32_t mismatch;
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                sizeof(test_signature_public_key), &mismatch
            ) == 0 &&
            mismatch == 0
        );
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

static int
test_legacy_writer_capacity(uint32_t version)
{
    mpq_archive_create_options_s options = { version, 7, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    char path[512];
    uint8_t payload[3] = { 1, 2, 3 };
    uint8_t actual[3];
    libmpq__off_t transferred;
    uint32_t files;
    uint32_t number;
    TEST_CHECK(test_temp_path(path, sizeof(path), "legacy-capacity") == 0);
    TEST_CHECK(libmpq__archive_create(&archive, path, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "payload", payload, sizeof(payload), NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(
        archive->mpq_header.hash_table_count == 16 && archive->mpq_header.block_table_count == 7
    );
    TEST_CHECK(
        archive->mpq_header.block_table_offset ==
        archive->mpq_header.hash_table_offset + 16u * LIBMPQ_HASH_ENTRY_WIRE_SIZE
    );
    if (version == LIBMPQ_ARCHIVE_VERSION_TWO)
        TEST_CHECK(
            archive->mpq_header_ex.extended_offset ==
            archive->mpq_header.block_table_offset + 7u * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE
        );
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 1);
    TEST_CHECK(libmpq__file_number(archive, "payload", &number) == 0);
    TEST_CHECK(
        libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0 &&
        transferred == 3
    );
    TEST_CHECK(memcmp(actual, payload, sizeof(actual)) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Validate the capacity ceiling without allocating multi-gigabyte tables. */
static int
test_v3_capacity_options(void)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_THREE, 0x04000000u, 4096, 0,
                                             0 };
    TEST_CHECK(libmpq__writer_validate_options(&options) == 0);
    TEST_CHECK(
        (uint64_t)options.max_files * 2 * LIBMPQ_HASH_ENTRY_WIRE_SIZE == UINT64_C(0x80000000)
    );
    ++options.max_files;
    TEST_CHECK(libmpq__writer_validate_options(&options) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(
        libmpq__archive_create(&archive, "invalid-capacity.mpq", &options) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(archive == NULL);
    return 0;
}

#ifdef __GLIBC__

/* Reuse the existing bounded stream cookie for stored-byte read failures. */
static ssize_t
writer_v4_fault_read(void *context, char *output, size_t size)
{
    writer_v3_fault_s *fault = context;
    if (fault->position >= fault->fail_at || size > fault->fail_at - fault->position)
        return -1;
    if (fault->position > fault->size)
        return 0;
    if (size > fault->size - fault->position)
        size = fault->size - fault->position;
    memcpy(output, fault->bytes + fault->position, size);
    fault->position += size;
    return (ssize_t)size;
}

/* Reserve the existing virtual-end sentinel for a deterministic seek failure. */
static int
writer_v4_fault_seek(void *context, off64_t *offset, int origin)
{
    if (((writer_v3_fault_s *)context)->end_override == UINT64_MAX)
        return -1;
    return writer_v3_fault_seek(context, offset, origin);
}

/* Return a genuine short write after storing the permitted prefix bytes. */
static ssize_t
writer_v4_partial_write(void *context, const char *input, size_t size)
{
    writer_v3_fault_s *fault = context;
    if (fault->position < fault->fail_at && size > fault->fail_at - fault->position)
        size = (size_t)(fault->fail_at - fault->position);
    return writer_v3_fault_write(context, input, size);
}

/* Partial begin/flush failures are terminal; untouched validation remains recoverable. */
static int
test_v4_error_state(unsigned int which)
{
    cookie_io_functions_t ops = { writer_v4_fault_read, writer_v4_partial_write,
                                  writer_v4_fault_seek, writer_v3_fault_close };
    writer_v3_fault_s fault = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_FOUR, 4, 512, 0,
                                             LIBMPQ_ATTRIBUTE_FILETIME };
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_entry_s entry = { 0 };
    uint8_t data[512] = { 1 };
    FILE *fp = fopencookie(&fault, "w+b", ops);
    TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
    TEST_CHECK(
        libmpq__writer_archive_create_v4(
            &archive, "cookie-v4-state", fp, &options, which == 3 ? 1 : 0
        ) == 0
    );
    if (which == 0) {
        uint8_t prefix[28] = { 0 };
        libmpq__store_le32(prefix, sizeof(prefix));
        libmpq__store_le32(prefix + 4, 0x80000000u);
        libmpq__store_le32(prefix + 8, sizeof(data));

        /* Fault the shared prefix path only; no v4 patch archive is finalized. */
        archive->write_patch_mode = 1;
        fault.fail_at = 212;
        TEST_CHECK(
            libmpq__writer_patch_file_add(
                archive, "payload", prefix, sizeof(prefix), data, sizeof(data), sizeof(data), NULL
            ) == LIBMPQ_ERROR_WRITE
        );
        TEST_CHECK(fault.size == 212 && libmpq__load_le32(fault.bytes + 208) == sizeof(prefix));
    } else if (which == 1) {
        TEST_CHECK(libmpq__writer_file_begin(archive, "payload", sizeof(data), NULL, &writer) == 0);
        fault.fail_at = 212;
        TEST_CHECK(libmpq__writer_file_write(writer, data, sizeof(data)) == LIBMPQ_ERROR_WRITE);
        TEST_CHECK(fault.size == 212 && archive->write_error == LIBMPQ_ERROR_WRITE);
        TEST_CHECK(libmpq__writer_file_timestamp(writer, 123) == LIBMPQ_ERROR_WRITE);
        TEST_CHECK(libmpq__writer_file_finish(writer) == LIBMPQ_ERROR_WRITE);
    } else {
        entry.offset = UINT64_C(0x1000000000000);
        TEST_CHECK(
            libmpq__writer_import_member(archive, "invalid", &entry, 0, 0, NULL) ==
            (which == 3 ? LIBMPQ_ERROR_FORMAT : LIBMPQ_ERROR_SIZE)
        );
        TEST_CHECK(archive->write_error == 0 && fault.size == 208);
        TEST_CHECK(libmpq__writer_file_begin(archive, "payload", sizeof(data), NULL, &writer) == 0);
        TEST_CHECK(libmpq__writer_file_write(writer, NULL, 1) == LIBMPQ_ERROR_SIZE);
        TEST_CHECK(libmpq__writer_finalize(archive) == LIBMPQ_ERROR_SIZE);
        TEST_CHECK(archive->write_error == 0 && fault.size == 208);
        TEST_CHECK(libmpq__writer_file_timestamp(writer, 123) == 0);
        TEST_CHECK(libmpq__writer_file_write(writer, data, sizeof(data)) == 0);
        TEST_CHECK(libmpq__writer_file_finish(writer) == 0);
        TEST_CHECK(libmpq__writer_finalize(archive) == 0 && archive->write_finalized);
        TEST_CHECK(libmpq__archive_close(archive) == 0 && fault.closed);
        return 0;
    }
    fault.fail_at = SIZE_MAX;
    clearerr(fp);
    TEST_CHECK(libmpq__writer_finalize(archive) == LIBMPQ_ERROR_WRITE);
    TEST_CHECK(!archive->write_finalized && fault.bytes[0] == 0);
    TEST_CHECK(
        libmpq__writer_import_member(archive, "later", &entry, 0, 0, NULL) == LIBMPQ_ERROR_WRITE
    );
    TEST_CHECK(
        libmpq__archive_add_data(archive, "later", data, sizeof(data), NULL) == LIBMPQ_ERROR_WRITE
    );
    TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_WRITE && fault.closed);
    return 0;
}

/* Fail each v4 publication boundary without replacing the stream abstraction. */
static int
test_v4_failures(void)
{
    cookie_io_functions_t ops = { writer_v4_fault_read, writer_v3_fault_write, writer_v4_fault_seek,
                                  writer_v3_fault_close };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_FOUR, 4, 512, 0, 0 };
    writer_v3_fault_s reference = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
    mpq_archive_s *archive = NULL;
    uint64_t positions[7];
    uint8_t data[512] = { 1 };
    FILE *fp = fopencookie(&reference, "w+b", ops);
    TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
    TEST_CHECK(libmpq__writer_archive_create_v4(&archive, "cookie-v4", fp, &options, 64) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL) == 0);
    TEST_CHECK(libmpq__writer_finalize(archive) == 0 && archive->write_finalized);
    positions[0] = 208;
    positions[1] = 208 + sizeof(data);
    positions[2] = archive->mpq_header_v3.het_table_offset;
    positions[3] = archive->mpq_header_v3.bet_table_offset;
    positions[4] = archive->mpq_header.hash_table_offset;
    positions[5] = archive->mpq_header.block_table_offset;
    positions[6] = 0;
    TEST_CHECK(libmpq__archive_close(archive) == 0 && reference.closed);
    for (size_t i = 0; i < 7; ++i) {
        writer_v3_fault_s fault = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
        fp = fopencookie(&fault, "w+b", ops);
        TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
        TEST_CHECK(libmpq__writer_archive_create_v4(&archive, "cookie-v4", fp, &options, 64) == 0);
        if (i < 2)
            fault.fail_at = (size_t)positions[i];
        if (i < 2) {
            TEST_CHECK(
                libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL) ==
                LIBMPQ_ERROR_WRITE
            );
        } else {
            TEST_CHECK(libmpq__archive_add_data(archive, "payload", data, sizeof(data), NULL) == 0);
            fault.fail_at = (size_t)positions[i];
            TEST_CHECK(libmpq__writer_finalize(archive) == LIBMPQ_ERROR_WRITE);
        }
        TEST_CHECK(!archive->write_finalized && fault.bytes[0] == 0);
        fault.fail_at = SIZE_MAX;
        clearerr(fp);
        TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_WRITE && fault.closed);
    }
    for (unsigned int which = 0; which < 4; ++which) {
        writer_v3_fault_s fault = { { 0 }, 0, 0, SIZE_MAX, 0, 0 };
        int32_t expected = which == 0   ? LIBMPQ_ERROR_READ
                           : which == 3 ? LIBMPQ_ERROR_SEEK
                                        : LIBMPQ_ERROR_SIZE;
        fp = fopencookie(&fault, "w+b", ops);
        TEST_CHECK(fp != NULL && setvbuf(fp, NULL, _IONBF, 0) == 0);
        TEST_CHECK(
            libmpq__writer_archive_create_v4(
                &archive, "cookie-v4", fp, &options, which == 2 ? 1 : 64
            ) == 0
        );
        if (which == 0 || which == 3) {
            mpq_writer_s *writer = NULL;
            TEST_CHECK(
                libmpq__writer_file_begin(archive, "payload", sizeof(data), NULL, &writer) == 0
            );
            TEST_CHECK(libmpq__writer_file_write(writer, data, sizeof(data)) == 0);
            if (which == 0)
                fault.fail_at = 208;
            else
                fault.end_override = UINT64_MAX;
            TEST_CHECK(libmpq__writer_file_finish(writer) == expected);
        } else if (which == 1) {
            fault.end_override = INT64_MAX;
            TEST_CHECK(libmpq__writer_finalize(archive) == expected);
        } else {

            /* A canonical member cannot exceed the uint32_t classic size representation. */
            mpq_writer_s *writer = NULL;
            TEST_CHECK(
                libmpq__writer_file_begin(
                    archive, "oversized", (libmpq__off_t)UINT32_MAX + 1, NULL, &writer
                ) == expected
            );
            archive->write_hash_capacity = UINT32_MAX;
            TEST_CHECK(libmpq__writer_finalize(archive) == expected);
        }
        TEST_CHECK(!archive->write_finalized && fault.bytes[0] == 0);
        TEST_CHECK(libmpq__archive_close(archive) == expected && fault.closed);
    }
    return 0;
}
#endif

/* Independently select MD5 input ranges from literal wire offsets, not writer state. */
static int
check_v4_stored_md5(mpq_archive_s *archive, uint64_t position, size_t size, const uint8_t *expected)
{
    mpq_md5_s md5;
    uint8_t buffer[4096];
    uint8_t actual[16];
    libmpq__md5_init(&md5);
    while (size != 0) {
        size_t take = size < sizeof(buffer) ? size : sizeof(buffer);
        TEST_CHECK(libmpq__source_read_at(archive->source, position, buffer, take) == 0);
        libmpq__md5_update(&md5, buffer, take);
        position += take;
        size -= take;
    }
    libmpq__md5_final(&md5, actual);
    TEST_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
    return 0;
}

/* Inspect all v4 table extents and stored digests without using the header decoder. */
static int
check_v4_wire(mpq_archive_s *archive, uint32_t chunk_size)
{
    uint8_t wire[208];
    static const uint8_t zero[16] = { 0 };
    uint64_t positions[5];
    const unsigned int size_offsets[] = { 68, 76, 84, 92, 100 };
    const unsigned int md5_offsets[] = { 128, 112, 144, 176, 160 };
    uint64_t end;
    TEST_CHECK(libmpq__source_read_at(archive->source, 0, wire, sizeof(wire)) == 0);
    TEST_CHECK(libmpq__load_le32(wire) == 0x1a51504du && libmpq__load_le32(wire + 4) == 208);
    TEST_CHECK(libmpq__load_le16(wire + 12) == 3 && libmpq__load_le32(wire + 108) == chunk_size);
    end = libmpq__load_le64(wire + 44);
    TEST_CHECK(end == archive->file_size && libmpq__load_le32(wire + 8) == (uint32_t)end);
    TEST_CHECK(check_v4_stored_md5(archive, 0, 192, wire + 192) == 0);
    positions[0] = libmpq__load_le32(wire + 16) | ((uint64_t)libmpq__load_le16(wire + 40) << 32);
    positions[1] = libmpq__load_le32(wire + 20) | ((uint64_t)libmpq__load_le16(wire + 42) << 32);
    positions[2] = libmpq__load_le64(wire + 32);
    positions[3] = libmpq__load_le64(wire + 60);
    positions[4] = libmpq__load_le64(wire + 52);
    TEST_CHECK(libmpq__load_le64(wire + 68) == (uint64_t)libmpq__load_le32(wire + 24) * 16);
    TEST_CHECK(libmpq__load_le64(wire + 76) == (uint64_t)libmpq__load_le32(wire + 28) * 16);
    for (size_t i = 0; i < 5; ++i) {
        uint64_t size = libmpq__load_le64(wire + size_offsets[i]);
        if (positions[i] == 0) {
            TEST_CHECK(size == 0 && memcmp(wire + md5_offsets[i], zero, sizeof(zero)) == 0);
            continue;
        }
        TEST_CHECK(positions[i] >= 208 && positions[i] <= end && size <= end - positions[i]);
        TEST_CHECK(size > 0 && size <= SIZE_MAX);
        TEST_CHECK(
            check_v4_stored_md5(archive, positions[i], (size_t)size, wire + md5_offsets[i]) == 0
        );
    }
    TEST_CHECK(positions[3] + libmpq__load_le64(wire + 92) == positions[4]);
    TEST_CHECK(positions[4] + libmpq__load_le64(wire + 100) == positions[0]);
    TEST_CHECK(positions[0] + libmpq__load_le64(wire + 68) == (positions[1] ? positions[1] : end));
    if (positions[2]) {
        TEST_CHECK(libmpq__load_le64(wire + 84) == (uint64_t)archive->files * 2);
        TEST_CHECK(positions[1] + libmpq__load_le64(wire + 76) == positions[2]);
        TEST_CHECK(positions[2] + libmpq__load_le64(wire + 84) == end);
    } else if (positions[1]) {
        TEST_CHECK(positions[1] + libmpq__load_le64(wire + 76) == end);
    }
    for (uint32_t i = 0; i < archive->entry_count; ++i) {
        const mpq_entry_s *entry = &archive->mpq_entry[i];
        uint64_t physical_end = entry->offset + entry->packed_size;
        if (chunk_size && entry->packed_size)
            physical_end += ((entry->packed_size - 1) / chunk_size + 1) * 16;
        TEST_CHECK(entry->offset >= 208 && physical_end <= positions[3]);
        TEST_CHECK(entry->source_mask == (LIBMPQ_ENTRY_SOURCE_CLASSIC | LIBMPQ_ENTRY_SOURCE_BET));
        TEST_CHECK(entry->classic_source_index == i && entry->bet_source_index == i);
        if (i + 1 < archive->entry_count)
            TEST_CHECK(physical_end <= archive->mpq_entry[i + 1].offset);
        if (chunk_size && entry->packed_size) {
            uint64_t position = entry->offset;
            uint64_t remaining = entry->packed_size;
            uint64_t digest_position = position + remaining;
            while (remaining) {
                uint64_t take = remaining < chunk_size ? remaining : chunk_size;
                uint8_t digest[16];
                TEST_CHECK(
                    libmpq__source_read_at(
                        archive->source, digest_position, digest, sizeof(digest)
                    ) == 0
                );
                TEST_CHECK(check_v4_stored_md5(archive, position, (size_t)take, digest) == 0);
                remaining -= take;
                position += take;
                digest_position += 16;
            }
        }
    }
    return 0;
}

/* Public MPQ and MPQE constructors share the default layout and final stored-byte digests. */
static int
test_v4_public(int mpqe, int empty)
{
    mpq_archive_create_options_s options = {
        LIBMPQ_ARCHIVE_VERSION_FOUR, 8, 512, empty ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE,
        empty ? 0 : LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME
    };
    mpq_file_options_s storage[] = {
        { LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0, 0 },
        { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE | 0x00020000u, 0, 0, 0, 0 },
        { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SECTOR_CRC,
          LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 }
    };
    const char *names[] = { "folder/reference.bin", "folder/single.bin", "folder/compressed.bin" };
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    mpq_patch_s *patch = NULL;
    char path[512];
    uint8_t payload[32769];
    uint8_t actual[32769];
    uint8_t expected[16];
    uint32_t number;
    uint32_t mask;
    uint32_t files;
    libmpq__off_t transferred;
    TEST_CHECK(test_temp_path(path, sizeof(path), "public-v4") == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_create_mpqe(
                    &archive, path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, &options
                )
              : libmpq__archive_create(&archive, path, &options)) == 0
    );
    TEST_CHECK(archive->mpq_header_v4.raw_chunk_size == 0x4000);
    TEST_CHECK(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == LIBMPQ_ERROR_FORMAT
    );
    if (mpqe) {
        uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE];
        test_strong_signature_private_key(key);
        TEST_CHECK(
            libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, key, sizeof(key)) ==
            LIBMPQ_ERROR_FORMAT
        );
    }
    {
        mpq_entry_s entry = { 0 };
        TEST_CHECK(
            libmpq__writer_import_member(archive, "import", &entry, 0, 0, NULL) ==
            LIBMPQ_ERROR_FORMAT
        );
        TEST_CHECK(archive->write_error == 0);
    }
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i % 251);
    if (!empty) {
        for (size_t i = 0; i < sizeof(storage) / sizeof(storage[0]); ++i)
            TEST_CHECK(
                libmpq__archive_add_data(
                    archive, names[i], payload, i == 1 ? 256 : sizeof(payload), &storage[i]
                ) == 0
            );
        TEST_CHECK(libmpq__archive_add_data(archive, "abc", (const uint8_t *)"abc", 3, NULL) == 0);
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__archive_open_mpqe(
                    &archive, path, 0, mpqe_auth_code, sizeof(mpqe_auth_code) - 1
                )
              : libmpq__archive_open(&archive, path, 0)) == 0
    );
    TEST_CHECK(check_v4_wire(archive, 0x4000) == 0);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == (empty ? 0u : 6u));
    if (!empty) {
        for (size_t i = 0; i < sizeof(storage) / sizeof(storage[0]); ++i) {
            mpq_stream_s *stream = NULL;
            const mpq_entry_s *entry;
            size_t size = i == 1 ? 256 : sizeof(payload);
            size_t start = i == 1 ? 7 : 16380;
            TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
            entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
            TEST_CHECK(
                entry->unpacked_size == size &&
                (entry->flags & storage[i].flags) == storage[i].flags
            );
            TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, names[i]) == 0);
            TEST_CHECK(
                libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0 &&
                transferred == (libmpq__off_t)size && memcmp(actual, payload, size) == 0
            );
            TEST_CHECK(
                libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mask) == 0 && mask == 0
            );
            TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
            TEST_CHECK(libmpq__stream_open_name(archive, names[i], &stream) == 0);
            TEST_CHECK(libmpq__stream_seek(stream, (libmpq__off_t)start, LIBMPQ_SEEK_SET) == 0);
            TEST_CHECK(
                libmpq__stream_read(stream, actual, 16, &transferred) == 0 && transferred == 16 &&
                memcmp(actual, payload + start, 16) == 0
            );
            TEST_CHECK(libmpq__stream_close(stream) == 0);
            if (i == 0) {
                uint32_t key = (0xa25af234u + (uint32_t)entry->offset) ^ (uint32_t)sizeof(payload);
                memcpy(expected, payload, sizeof(expected));
                TEST_CHECK(libmpq__crypto_encrypt_block(expected, sizeof(expected), key) == 0);
                TEST_CHECK(
                    libmpq__source_read_at(
                        archive->source, entry->offset, actual, sizeof(expected)
                    ) == 0
                );
                TEST_CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
            }
        }
        TEST_CHECK(libmpq__file_number(archive, "abc", &number) == 0);
        {
            static const uint8_t md5[16] = { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                                             0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 };
            const mpq_entry_s *entry = &archive->mpq_entry[archive->mpq_map[number].entry_index];
            TEST_CHECK(libmpq__source_read_at(archive->source, entry->offset + 3, actual, 16) == 0);
            TEST_CHECK(memcmp(actual, md5, sizeof(md5)) == 0);
        }
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(
        (mpqe ? libmpq__update_begin_mpqe(&update, path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1)
              : libmpq__update_begin(&update, path)) == LIBMPQ_ERROR_FORMAT &&
        update == NULL
    );
    if (!mpqe)
        TEST_CHECK(
            libmpq__patch_begin(&patch, path, "unused-v4-patch.mpq") == LIBMPQ_ERROR_FORMAT &&
            patch == NULL
        );
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Exercise private chunk-size selection and retain invalid-version and update restrictions. */
static int
test_v4_writer(uint32_t chunk_size, int empty, uint64_t position)
{
    static const uint8_t abc[] = { 'a', 'b', 'c' };
    static const uint8_t abc_md5[16] = { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                                         0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 };
    static const uint8_t ab_c_md5[32] = { 0x18, 0x7e, 0xf4, 0x43, 0x61, 0x22, 0xd1, 0xcc,
                                          0x2f, 0x40, 0xdc, 0x2b, 0x92, 0xf0, 0xeb, 0xa0,
                                          0x4a, 0x8a, 0x08, 0xf0, 0x9d, 0x37, 0xb7, 0x37,
                                          0x95, 0x64, 0x90, 0x38, 0x40, 0x8b, 0x5f, 0x33 };
    static const char *names[] = { "abc",    "empty",  "sector", "single", "folder/reference.bin",
                                   "normal", "zipped", "lzma" };
    mpq_file_options_s storage[] = { { 0, 0, 0, 0, 0 },
                                     { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 },
                                     { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SECTOR_CRC,
                                       LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 },
                                     { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE,
                                       LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 },
                                     { LIBMPQ_FILE_FLAG_ENCRYPTED | 0x00020000u, 0, 0, 0, 0 },
                                     { LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE, 0, 0,
                                       0, 0 },
                                     { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED |
                                           LIBMPQ_FILE_FLAG_SECTOR_CRC | 0x00020000u,
                                       LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 },
                                     { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE,
                                       LIBMPQ_COMPRESSION_LZMA, LIBMPQ_COMPRESSION_LZMA, 0, 0 } };
    mpq_archive_create_options_s options = {
        LIBMPQ_ARCHIVE_VERSION_FOUR, 16, 512, empty ? 0 : LIBMPQ_ARCHIVE_CREATE_LISTFILE,
        empty ? 0 : LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 | LIBMPQ_ATTRIBUTE_FILETIME
    };
    char path[512];
    uint8_t payload[1025];
    uint8_t actual[1025];
    uint8_t expected[16];
    mpq_archive_s *archive = NULL;
    mpq_update_s *update = NULL;
    uint32_t files;
    uint32_t number;
    uint32_t mask;
    libmpq__off_t transferred;
    TEST_CHECK(test_temp_path(path, sizeof(path), "private-v4") == 0);
    options.version = LIBMPQ_ARCHIVE_VERSION_FOUR + 1;
    TEST_CHECK(
        libmpq__archive_create(&archive, path, &options) == LIBMPQ_ERROR_FORMAT && archive == NULL
    );
    TEST_CHECK(
        libmpq__writer_archive_create_file(&archive, path, NULL, &options) == LIBMPQ_ERROR_FORMAT &&
        archive == NULL
    );
    TEST_CHECK(
        libmpq__archive_create_mpqe(
            &archive, path, mpqe_auth_code, sizeof(mpqe_auth_code) - 1, &options
        ) == LIBMPQ_ERROR_FORMAT &&
        archive == NULL
    );
    options.version = LIBMPQ_ARCHIVE_VERSION_FOUR;
    TEST_CHECK(libmpq__writer_archive_create_v4(&archive, path, NULL, &options, chunk_size) == 0);
    archive->write_ext_compress = chunk_size != 0;
    if (position)
        TEST_CHECK(libmpq__file_seek(archive->fp, position, SEEK_SET) == 0);
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i % 17);
    if (!empty) {
        for (size_t i = 0; i < 8; ++i) {
            size_t size = i == 0                                              ? sizeof(abc)
                          : i == 1                                            ? 0
                          : (storage[i].flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ? 256
                                                                              : sizeof(payload);
            TEST_CHECK(
                libmpq__archive_add_data(
                    archive, names[i], i == 0 ? abc : payload, (libmpq__off_t)size, &storage[i]
                ) == 0
            );
        }
    }
    TEST_CHECK(libmpq__writer_finalize(archive) == 0 && archive->write_finalized);
    TEST_CHECK(
        libmpq__archive_add_data(archive, "late", payload, 1, NULL) == LIBMPQ_ERROR_NOT_INITIALIZED
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_FOUR);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == (empty ? 0u : 10u));
    TEST_CHECK(check_v4_wire(archive, chunk_size) == 0);
    if (!empty) {
        for (size_t i = 0; i < 8; ++i) {
            mpq_stream_s *stream = NULL;
            uint8_t *saved;
            uint32_t classic_number;
            size_t size = i == 0                                              ? sizeof(abc)
                          : i == 1                                            ? 0
                          : (storage[i].flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ? 256
                                                                              : sizeof(payload);
            TEST_CHECK(libmpq__file_number(archive, names[i], &number) == 0);
            saved = archive->het_data;
            archive->het_data = NULL;
            TEST_CHECK(
                libmpq__file_number(archive, names[i], &classic_number) == 0 &&
                number == classic_number
            );
            archive->het_data = saved;
            TEST_CHECK(libmpq__stream_open_name(archive, names[i], &stream) == 0);
            TEST_CHECK(
                libmpq__stream_read(stream, actual, sizeof(actual), &transferred) == 0 &&
                transferred == (libmpq__off_t)size
            );
            TEST_CHECK(memcmp(actual, i == 0 ? abc : payload, size) == 0);

            /* Numeric verification needs a named seed on this handle, not its stream clone. */
            TEST_CHECK(libmpq__reader_offsets_acquire(archive, number, names[i]) == 0);
            {
                int32_t result = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mask);
                if (result != 0 || mask != 0)
                    fprintf(stderr, "v4 verify %s failed: %d, mask %u\n", names[i], result, mask);
                TEST_CHECK(result == 0 && mask == 0);
            }
            TEST_CHECK(libmpq__reader_offsets_release(archive, number) == 0);
            if (size > 16) {
                size_t start = size > 527 ? 511 : 7;
                TEST_CHECK(libmpq__stream_seek(stream, (libmpq__off_t)start, LIBMPQ_SEEK_SET) == 0);
                TEST_CHECK(
                    libmpq__stream_read(stream, actual, 16, &transferred) == 0 &&
                    transferred == 16 && memcmp(actual, payload + start, 16) == 0
                );
            }
            TEST_CHECK(libmpq__stream_close(stream) == 0);
            if (i == 0 && (chunk_size == 2 || chunk_size == 3)) {
                uint64_t offset = archive->mpq_entry[archive->mpq_map[number].entry_index].offset;
                size_t size = chunk_size == 2 ? sizeof(ab_c_md5) : sizeof(abc_md5);
                TEST_CHECK(libmpq__source_read_at(archive->source, offset + 3, actual, size) == 0);
                TEST_CHECK(memcmp(actual, chunk_size == 2 ? ab_c_md5 : abc_md5, size) == 0);
            }
            if (i == 4) {
                const mpq_entry_s *entry =
                    &archive->mpq_entry[archive->mpq_map[number].entry_index];
                uint32_t key = (0xa25af234u + (uint32_t)entry->offset) ^ (uint32_t)sizeof(payload);
                memcpy(expected, payload, sizeof(expected));
                TEST_CHECK(libmpq__crypto_encrypt_block(expected, sizeof(expected), key) == 0);
                TEST_CHECK(
                    libmpq__source_read_at(
                        archive->source, entry->offset, actual, sizeof(expected)
                    ) == 0
                );
                TEST_CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
            }
        }
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__update_begin(&update, path) == LIBMPQ_ERROR_FORMAT && update == NULL);
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* Flip only the selected stored byte, allowing each integrity failure to be isolated. */
static int
writer_flip_byte(const char *path, uint64_t position)
{
    FILE *fp = libmpq__file_open(path, "r+b");
    int byte;
    TEST_CHECK(fp != NULL && libmpq__file_seek(fp, position, SEEK_SET) == 0);
    byte = fgetc(fp);
    TEST_CHECK(byte != EOF && libmpq__file_seek(fp, position, SEEK_SET) == 0);
    TEST_CHECK(fputc(byte ^ 1, fp) != EOF && fclose(fp) == 0);
    return 0;
}

/* Generated checksums must protect stored metadata and raw data independently. */
static int
test_v4_corruption(void)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_FOUR, 4, 512, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_archive_s *archive = NULL;
    uint8_t wire[208];
    char path[512];
    uint64_t positions[5];
    uint32_t number;
    uint32_t mask;
    TEST_CHECK(test_temp_path(path, sizeof(path), "private-v4-corrupt") == 0);
    TEST_CHECK(libmpq__writer_archive_create_v4(&archive, path, NULL, &options, 3) == 0);
    TEST_CHECK(libmpq__archive_add_data(archive, "abc", (const uint8_t *)"abc", 3, NULL) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__source_read_at(archive->source, 0, wire, sizeof(wire)) == 0);
    positions[0] = 108;
    positions[1] = libmpq__load_le64(wire + 60);
    positions[2] = libmpq__load_le64(wire + 52);
    positions[3] = libmpq__load_le32(wire + 16);
    positions[4] = libmpq__load_le32(wire + 20);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    for (size_t i = 0; i < 5; ++i) {
        TEST_CHECK(writer_flip_byte(path, positions[i]) == 0);
        TEST_CHECK(
            libmpq__archive_open(&archive, path, 0) == LIBMPQ_ERROR_FORMAT && archive == NULL
        );
        TEST_CHECK(writer_flip_byte(path, positions[i]) == 0);
    }
    for (unsigned int digest = 0; digest < 2; ++digest) {
        TEST_CHECK(writer_flip_byte(path, digest ? 211 : 208) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
        TEST_CHECK(libmpq__file_number(archive, "abc", &number) == 0);
        TEST_CHECK(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &mask) == 0);
        TEST_CHECK(
            mask ==
            (digest ? LIBMPQ_VERIFY_RAW_MD5
                    : LIBMPQ_VERIFY_RAW_MD5 | LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(writer_flip_byte(path, digest ? 211 : 208) == 0);
    }
    TEST_CHECK(remove(path) == 0);
    return 0;
}

/* The private path remains deterministic and cannot silently finalize stale signature digests. */
static int
test_v4_determinism_and_signing(void)
{

    /* Fixed wire digests independently checked with Python hashlib. */
    static const uint8_t digests[5][16] = {
        { 0x5b, 0x7b, 0xe9, 0x4b, 0xc5, 0x6d, 0x76, 0xf9, 0xcb, 0xeb, 0xb3, 0x0f, 0xb0, 0x60, 0x7c,
          0x3d },
        { 0xa1, 0x92, 0xec, 0xf5, 0x6a, 0x9c, 0x85, 0x39, 0xad, 0x4d, 0x47, 0x1e, 0x3b, 0xdd, 0x03,
          0x79 },
        { 0x21, 0xab, 0xd0, 0x85, 0x81, 0x0f, 0xe8, 0x1f, 0x91, 0x59, 0x94, 0x0f, 0x61, 0x6a, 0x6a,
          0x47 },
        { 0xfc, 0x12, 0x19, 0x4b, 0x75, 0xab, 0xda, 0x6a, 0xd8, 0x70, 0x0e, 0x65, 0x35, 0x79, 0xb8,
          0x27 },
        { 0xf2, 0x74, 0xc7, 0x21, 0xaa, 0x09, 0x52, 0x9a, 0x75, 0x92, 0x3e, 0x1c, 0x3d, 0x02, 0x61,
          0xd4 },
    };
    static const unsigned int digest_offsets[] = { 192, 128, 112, 176, 160 };
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_FOUR, 4, 512, 0, 0 };
    mpq_archive_s *archive = NULL;
    char paths[2][512];
    uint8_t *first;
    uint8_t *second;
    size_t first_size;
    size_t second_size;
    TEST_CHECK(test_temp_path(paths[0], sizeof(paths[0]), "private-v4-first") == 0);
    TEST_CHECK(test_temp_path(paths[1], sizeof(paths[1]), "private-v4-second") == 0);
    options.max_files = 0x04000001u;
    TEST_CHECK(
        libmpq__writer_archive_create_v4(&archive, paths[0], NULL, &options, 1) ==
            LIBMPQ_ERROR_FORMAT &&
        archive == NULL
    );
    options.max_files = 4;
    for (size_t i = 0; i < 2; ++i) {
        TEST_CHECK(libmpq__writer_archive_create_v4(&archive, paths[i], NULL, &options, 3) == 0);
        archive->write_ext_compress = 0;
        TEST_CHECK(libmpq__archive_add_data(archive, "abc", (const uint8_t *)"abc", 3, NULL) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(test_read_path(paths[0], &first, &first_size) == 0);
    TEST_CHECK(test_read_path(paths[1], &second, &second_size) == 0);
    TEST_CHECK(first_size == second_size && memcmp(first, second, first_size) == 0);
    TEST_CHECK(first_size == 520);
    for (size_t i = 0; i < 5; ++i)
        TEST_CHECK(memcmp(first + digest_offsets[i], digests[i], 16) == 0);
    free(first);
    free(second);
    {
        uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
        uint8_t actual[3];
        uint32_t number;
        uint32_t mask;
        libmpq__off_t transferred;
        FILE *input = libmpq__file_open(paths[0], "r+b");
        FILE *output = libmpq__file_open(paths[1], "wb");
        TEST_CHECK(input != NULL && output != NULL);
        TEST_CHECK(libmpq__mpqe_key(key, mpqe_auth_code, sizeof(mpqe_auth_code) - 1) == 0);
        TEST_CHECK(libmpq__writer_mpqe_transform_file(input, output, key) == 0);
        libmpq__mpqe_clear(key, sizeof(key));
        TEST_CHECK(fclose(input) == 0 && fclose(output) == 0);
        TEST_CHECK(
            libmpq__archive_open_mpqe(
                &archive, paths[1], 0, mpqe_auth_code, sizeof(mpqe_auth_code) - 1
            ) == 0
        );
        TEST_CHECK(libmpq__file_number(archive, "abc", &number) == 0);
        TEST_CHECK(
            libmpq__file_read(archive, number, actual, sizeof(actual), &transferred) == 0 &&
            transferred == 3 && memcmp(actual, "abc", 3) == 0
        );
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &mask) == 0 && mask == 0
        );
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }

    for (unsigned int raw = 0; raw < 2; ++raw) {
        uint32_t mask;
        TEST_CHECK(
            libmpq__writer_archive_create_v4(&archive, paths[0], NULL, &options, raw ? 3 : 0) == 0
        );
        TEST_CHECK(
            libmpq__archive_sign(
                archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == (raw ? LIBMPQ_ERROR_FORMAT : 0)
        );
        TEST_CHECK(libmpq__archive_add_data(archive, "abc", (const uint8_t *)"abc", 3, NULL) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        if (!raw) {
            TEST_CHECK(libmpq__archive_open(&archive, paths[0], 0) == 0);
            TEST_CHECK(
                libmpq__archive_verify(
                    archive, LIBMPQ_SIGNATURE_WEAK, test_signature_public_key,
                    sizeof(test_signature_public_key), &mask
                ) == 0 &&
                mask == 0
            );
            TEST_CHECK(libmpq__archive_close(archive) == 0);
        }
    }
    {
        uint8_t key[LIBMPQ_RSA_STRONG_KEY_SIZE];
        uint32_t mask;
        uint32_t number;
        test_strong_signature_private_key(key);
        TEST_CHECK(libmpq__archive_create(&archive, paths[0], &options) == 0);
        TEST_CHECK(libmpq__archive_sign(archive, LIBMPQ_SIGNATURE_STRONG, key, sizeof(key)) == 0);
        TEST_CHECK(libmpq__archive_add_data(archive, "abc", (const uint8_t *)"abc", 3, NULL) == 0);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        TEST_CHECK(libmpq__archive_open(&archive, paths[0], 0) == 0);
        TEST_CHECK(
            libmpq__archive_verify(
                archive, LIBMPQ_SIGNATURE_STRONG, test_strong_signature_public_key,
                sizeof(test_strong_signature_public_key), &mask
            ) == 0 &&
            mask == 0
        );
        TEST_CHECK(libmpq__file_number(archive, "abc", &number) == 0);
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_RAW_MD5, &mask) == 0 && mask == 0
        );
        TEST_CHECK(archive->file_size == archive->mpq_header_v3.archive_size + 260);
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    TEST_CHECK(remove(paths[0]) == 0 && remove(paths[1]) == 0);
    return 0;
}

int
main(void)
{
#ifdef __GLIBC__
    for (unsigned int which = 0; which < 4; ++which)
        TEST_CHECK(test_v4_error_state(which) == 0);
    TEST_CHECK(test_v4_failures() == 0);
#endif
    TEST_CHECK(test_v4_corruption() == 0);
    TEST_CHECK(test_v4_determinism_and_signing() == 0);
    TEST_CHECK(test_v4_writer(0, 1, 0) == 0);
    TEST_CHECK(test_v4_writer(3, 1, 0) == 0);
    TEST_CHECK(test_v4_writer(0, 0, 0) == 0);
    TEST_CHECK(test_v4_writer(1, 0, 0) == 0);
    TEST_CHECK(test_v4_writer(2, 0, 0) == 0);
    TEST_CHECK(test_v4_writer(3, 0, 0) == 0);
    TEST_CHECK(test_v4_writer(512, 0, 0) == 0);
    TEST_CHECK(test_v4_writer(UINT32_MAX, 0, UINT64_C(0x100000000)) == 0);
    TEST_CHECK(test_legacy_writer_capacity(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_legacy_writer_capacity(LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
#ifdef __GLIBC__
    TEST_CHECK(test_v3_failures() == 0);
    TEST_CHECK(test_v3_high_signature_io() == 0);
#endif
    TEST_CHECK(test_v3_capacity_options() == 0);
    TEST_CHECK(test_v3_writer(0, false, false) == 0);
    TEST_CHECK(test_v3_writer(1, true, false) == 0);
    TEST_CHECK(test_v3_writer(8, false, false) == 0);
    TEST_CHECK(test_v3_writer(8, true, false) == 0);
    TEST_CHECK(test_v3_writer(1, true, UINT32_MAX) == 0);
    TEST_CHECK(test_v3_writer(1, true, UINT64_C(0x100000000)) == 0);
    TEST_CHECK(test_v3_writer(1, true, UINT64_C(0x100000040)) == 0);
    TEST_CHECK(test_writer_abort_on_close() == 0);
    TEST_CHECK(test_writer_determinism() == 0);
    TEST_CHECK(test_writer_duplicate_identity() == 0);
    TEST_CHECK(test_writer_displaced_duplicate() == 0);
    TEST_CHECK(test_writer_properties() == 0);
    TEST_CHECK(test_mpqe_writer_credential_validation() == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_ONE, 1) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_TWO, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_TWO, 1) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_THREE, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_THREE, 1) == 0);
    TEST_CHECK(test_mpqe_writer_byte_equality(LIBMPQ_ARCHIVE_VERSION_ONE) == 0);
    TEST_CHECK(test_mpqe_writer_byte_equality(LIBMPQ_ARCHIVE_VERSION_TWO) == 0);
    TEST_CHECK(test_mpqe_writer_byte_equality(LIBMPQ_ARCHIVE_VERSION_THREE) == 0);
    TEST_CHECK(test_v4_public(0, 1) == 0);
    TEST_CHECK(test_v4_public(0, 0) == 0);
    TEST_CHECK(test_v4_public(1, 1) == 0);
    TEST_CHECK(test_v4_public(1, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_FOUR, 0) == 0);
    TEST_CHECK(test_mpqe_writer_roundtrip(LIBMPQ_ARCHIVE_VERSION_FOUR, 1) == 0);
    TEST_CHECK(test_mpqe_writer_byte_equality(LIBMPQ_ARCHIVE_VERSION_FOUR) == 0);
    for (unsigned int fault = 0; fault < sizeof(fault_appliers) / sizeof(fault_appliers[0]);
         ++fault)
        TEST_CHECK(
            test_mpqe_writer_fault((mpqe_writer_fault_e)fault, 0x0f, LIBMPQ_ARCHIVE_VERSION_FOUR) ==
            0
        );
    TEST_CHECK(test_mpqe_writer_chdir() == 0);
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_FINALIZE, 0, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_TRANSFORM, 0, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_OUTPUT_CLOSE, 0, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_PUBLISH, 0, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_FINALIZE, 0x0f, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_TRANSFORM, 0x0f, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_OUTPUT_CLOSE, 0x0f, LIBMPQ_ARCHIVE_VERSION_ONE) ==
        0
    );
    TEST_CHECK(
        test_mpqe_writer_fault(MPQE_WRITER_FAULT_PUBLISH, 0x0f, LIBMPQ_ARCHIVE_VERSION_ONE) == 0
    );
    return 0;
}
