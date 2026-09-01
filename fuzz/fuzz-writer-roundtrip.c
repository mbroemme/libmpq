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

/* Release the output path created for this fuzzer process. */
static void
archive_cleanup(void)
{
    unlink(archive_path);
}

/* Choose a writer-supported raw or compressed storage option from one byte. */
static mpq_file_options_s
file_options(uint8_t selector)
{
    static const uint32_t codecs[] = { 0, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_BZIP2,
                                       LIBMPQ_COMPRESSION_PKZIP, LIBMPQ_COMPRESSION_HUFFMAN };
    uint32_t codec = codecs[selector % (sizeof(codecs) / sizeof(codecs[0]))];
    mpq_file_options_s options = { 0, 0, 0, 0, 0 };

    if (codec != 0) {
        options.flags = LIBMPQ_FILE_FLAG_COMPRESS;
        options.compression_first = codec;
        options.compression_next = codec;
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
    uint8_t *output = NULL;
    uint32_t number;
    uint32_t transferred;
    size_t payload_size;
    size_t first_chunk;

    if (size < 2 || size > LIBMPQ_FUZZ_WRITER_MAX_INPUT) {
        return 0;
    }

    payload_size = size - 2U;
    archive_options.version = (data[0] & 1U) == 0U ? LIBMPQ_ARCHIVE_VERSION_ONE :
                                                    LIBMPQ_ARCHIVE_VERSION_TWO;
    archive_options.max_files = 16;
    archive_options.sector_size = 4096;
    archive_options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE;
    options = file_options(data[1]);
    unlink(archive_path);

    if (libmpq__archive_create(&archive, archive_path, &archive_options) != 0 ||
        libmpq__file_begin(archive, "roundtrip.bin", (libmpq__off_t)payload_size, &options,
                           &writer) != 0) {
        if (archive != NULL) {
            libmpq__archive_close(archive);
        }
        unlink(archive_path);
        return 0;
    }

    first_chunk = payload_size / 2U;
    if (libmpq__file_write(writer, data + 2, (libmpq__off_t)first_chunk) != 0 ||
        libmpq__file_write(writer, data + 2 + first_chunk,
                           (libmpq__off_t)(payload_size - first_chunk)) != 0 ||
        libmpq__file_finish(writer) != 0 || libmpq__archive_close(archive) != 0) {
        unlink(archive_path);
        return 0;
    }

    archive = NULL;
    if (libmpq__archive_open(&archive, archive_path, 0) == 0 &&
        libmpq__file_number(archive, "roundtrip.bin", &number) == 0) {
        output = malloc(payload_size == 0 ? 1U : payload_size);
        if (output != NULL &&
            libmpq__file_read(archive, number, output, (libmpq__off_t)payload_size, &transferred) ==
                0 &&
            transferred == payload_size && memcmp(output, data + 2, payload_size) != 0) {
            abort();
        }
        free(output);
        libmpq__archive_close(archive);
    }

    unlink(archive_path);
    return 0;
}
