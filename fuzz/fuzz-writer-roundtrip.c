/*
 *  fuzz-writer-roundtrip.c -- Fuzz target for archive creation and reopening.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 */

#define _POSIX_C_SOURCE 200809L

#include <libmpq/mpq.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LIBMPQ_FUZZ_WRITER_MAX_INPUT 65536U

static char archive_path[] = "/tmp/libmpq-fuzz-writer.XXXXXX";
static const uint8_t mpqe_authentication_code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";

/* Release the output path created for this fuzzer process. */
static void
archive_cleanup(void)
{
    unlink(archive_path);
}

/* Choose a writer-supported storage, encryption, and single-unit combination. */
static mpq_file_options_s
file_options(uint8_t selector)
{
    static const uint32_t codecs[] = { 0,
                                       LIBMPQ_COMPRESSION_ZLIB,
                                       LIBMPQ_COMPRESSION_BZIP2,
                                       LIBMPQ_COMPRESSION_PKZIP,
                                       LIBMPQ_COMPRESSION_HUFFMAN,
                                       LIBMPQ_COMPRESSION_HUFFMAN | LIBMPQ_COMPRESSION_ZLIB |
                                           LIBMPQ_COMPRESSION_PKZIP | LIBMPQ_COMPRESSION_BZIP2 };
    uint32_t codec = codecs[selector % (sizeof(codecs) / sizeof(codecs[0]))];
    mpq_file_options_s options = { 0, 0, 0, 0, 0 };

    if (codec != 0) {
        options.flags = LIBMPQ_FILE_FLAG_COMPRESS;
        options.compression_first = codec;
        options.compression_next = codec;
    }
    if ((selector & 0x08U) != 0U) {
        options.flags |= LIBMPQ_FILE_FLAG_ENCRYPTED;
    }
    if ((selector & 0x10U) != 0U && (selector & 0x08U) == 0U) {
        options.flags |= LIBMPQ_FILE_FLAG_SINGLE;
    }

    return options;
}

/* Initialize one reusable output name; each input creates and removes its archive. */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int fd;

    (void)argc;
    (void)argv;

    fd = mkstemp(archive_path);
    if (fd < 0 || close(fd) != 0 || atexit(archive_cleanup) != 0) {
        perror("mkstemp");
        archive_cleanup();
        exit(EXIT_FAILURE);
    }
    unlink(archive_path);
    return 0;
}

/* Create a bounded archive, stream a fuzzed payload, then reopen and verify it. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mpq_archive_s *archive = NULL;
    mpq_writer_s *writer = NULL;
    mpq_archive_create_options_s archive_options;
    mpq_file_options_s options;
    const uint8_t *payload;
    uint8_t *encrypted_payload = NULL;
    uint8_t *output = NULL;
    uint32_t number;
    libmpq__off_t transferred;
    size_t payload_size;
    size_t first_chunk;
    int mpqe;
    int32_t result;

    static const uint32_t sector_sizes[] = { 512, 1024, 4096, 16384 };

    if (size < 3 || size > LIBMPQ_FUZZ_WRITER_MAX_INPUT) {
        return 0;
    }

    payload_size = size - 3U;
    archive_options.version =
        (data[0] & 1U) == 0U ? LIBMPQ_ARCHIVE_VERSION_ONE : LIBMPQ_ARCHIVE_VERSION_TWO;
    archive_options.max_files = 16;
    archive_options.sector_size =
        sector_sizes[data[2] % (sizeof(sector_sizes) / sizeof(sector_sizes[0]))];
    archive_options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    mpqe = (data[0] & 0x04U) != 0U;
    options = file_options(data[1]);
    payload = data + 3;
    if ((options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0) {
        if (payload_size < 8U) {
            options.flags &= ~LIBMPQ_FILE_FLAG_ENCRYPTED;
        } else {
            encrypted_payload = malloc(payload_size);
            if (encrypted_payload == NULL) {
                return 0;
            }
            memcpy(encrypted_payload, payload, payload_size);
            memcpy(encrypted_payload, "RIFF", 4);
            encrypted_payload[4] = (uint8_t)((payload_size - 8U) & 0xffU);
            encrypted_payload[5] = (uint8_t)(((payload_size - 8U) >> 8) & 0xffU);
            encrypted_payload[6] = (uint8_t)(((payload_size - 8U) >> 16) & 0xffU);
            encrypted_payload[7] = (uint8_t)(((payload_size - 8U) >> 24) & 0xffU);
            payload = encrypted_payload;
        }
    }
    unlink(archive_path);

    if ((mpqe ? libmpq__archive_create_mpqe(
                    &archive, archive_path, mpqe_authentication_code,
                    sizeof(mpqe_authentication_code) - 1U, &archive_options
                )
              : libmpq__archive_create(&archive, archive_path, &archive_options)) != 0)
        goto cleanup;
    if (libmpq__file_begin(
            archive, "roundtrip.bin", (libmpq__off_t)payload_size, &options, &writer
        ) != 0)
        goto cleanup;

    first_chunk = payload_size / 2U;
    if (libmpq__file_write(writer, payload, (libmpq__off_t)first_chunk) != 0 ||
        libmpq__file_write(
            writer, payload + first_chunk, (libmpq__off_t)(payload_size - first_chunk)
        ) != 0 ||
        libmpq__file_finish(writer) != 0)
        goto cleanup;

    result = libmpq__archive_close(archive);
    archive = NULL;
    if (result != 0)
        goto cleanup;
    if ((mpqe ? libmpq__archive_open_mpqe(
                    &archive, archive_path, 0, mpqe_authentication_code,
                    sizeof(mpqe_authentication_code) - 1U
                )
              : libmpq__archive_open(&archive, archive_path, 0)) == 0) {
        if (libmpq__file_number(archive, "roundtrip.bin", &number) != 0)
            goto cleanup;
        output = malloc(payload_size == 0 ? 1U : payload_size);
        if (output != NULL &&
            libmpq__file_read(archive, number, output, (libmpq__off_t)payload_size, &transferred) ==
                0 &&
            transferred == payload_size && memcmp(output, payload, payload_size) != 0) {
            abort();
        }
        free(output);
        output = NULL;
    }

cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    unlink(archive_path);
    free(output);
    free(encrypted_payload);
    return 0;
}
