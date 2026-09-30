/*
 *  bench-mpq-patch-reader.c -- deterministic private patch-view benchmark.
 *
 *  Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
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

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "mpq-internal.h"
#include "mpq-patch-reader.h"
#include "mpq-patch-writer.h"
#include "mpq-source.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* Return wall-clock seconds without depending on an external timing package. */
static double
elapsed_now(void)
{
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)frequency.QuadPart;
#else
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
#endif
}

/* Fill reproducible, poorly compressible bytes without a random dependency. */
static void
fill_bytes(uint8_t *data, size_t size, uint32_t seed)
{
    for (size_t i = 0; i < size; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        data[i] = (uint8_t)seed;
    }
}

/* Make an ordinary one-member archive for either the initial or next layer. */
static int
make_archive(const char *path, const uint8_t *data, size_t size)
{
    mpq_archive_create_options_s creation = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096,
                                              LIBMPQ_ARCHIVE_CREATE_LISTFILE, 0 };
    mpq_file_options_s storage = { 0, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;

    int32_t status = libmpq__archive_create(&archive, path, &creation);

    if (status != LIBMPQ_SUCCESS) {
        fprintf(stderr, "archive create failed: %d\n", status);
        return 1;
    }
    status = libmpq__archive_add_data(archive, "payload.bin", data, (libmpq__off_t)size, &storage);
    if (status != LIBMPQ_SUCCESS) {
        fprintf(stderr, "archive add failed: %d\n", status);
        (void)libmpq__archive_close(archive);
        return 1;
    }
    return libmpq__archive_close(archive) != LIBMPQ_SUCCESS;
}

/* Generate a patch with production selection and normal finalization. */
static int
make_patch(const char *base, const char *path, const uint8_t *data, size_t size)
{
    mpq_patch_writer_s *writer = NULL;
    mpq_file_options_s storage = { 0, 0, 0, 0, 0 };

    int32_t status = libmpq__patch_writer_begin(&writer, base, path);

    if (status != LIBMPQ_SUCCESS) {
        fprintf(stderr, "patch begin failed: %d\n", status);
        return 1;
    }
    status =
        libmpq__patch_writer_replace(writer, "payload.bin", data, (libmpq__off_t)size, &storage);
    if (status != LIBMPQ_SUCCESS) {
        fprintf(stderr, "patch replace failed: %d\n", status);
        (void)libmpq__patch_writer_abort(writer);
        return 1;
    }
    return libmpq__patch_writer_finish(writer) != LIBMPQ_SUCCESS;
}

/* Inspect the stored plaintext patch prefix and PTCH transform before timing. */
static int
check_transform(const char *path, const char expected[4])
{
    mpq_archive_s *archive = NULL;
    mpq_patch_info_s info;
    uint8_t prefix[LIBMPQ_PATCH_INFO_SIZE];
    uint8_t header[68];
    uint64_t offset;
    uint32_t number;
    uint32_t block;
    int failed = 1;

    if (libmpq__archive_open(&archive, path, 0) != LIBMPQ_SUCCESS)
        goto done;
    if (libmpq__file_number(archive, "payload.bin", &number) != LIBMPQ_SUCCESS)
        goto done;
    block = archive->mpq_map[number].block_table_indices;
    if ((archive->mpq_block[block].flags & LIBMPQ_FILE_FLAG_PATCH_FILE) == 0 ||
        archive->mpq_block[block].packed_size < sizeof(prefix) + sizeof(header))
        goto done;
    offset = (uint64_t)archive->archive_offset + archive->mpq_block[block].offset +
             ((uint64_t)archive->mpq_block_ex[block].offset_high << 32);
    if (libmpq__source_read_at(archive->source, offset, prefix, sizeof(prefix)) != LIBMPQ_SUCCESS ||
        libmpq__patch_info_parse(prefix, sizeof(prefix), &info) != LIBMPQ_SUCCESS ||
        info.length != sizeof(prefix) ||
        libmpq__source_read_at(archive->source, offset + info.length, header, sizeof(header)) !=
            LIBMPQ_SUCCESS ||
        memcmp(header, "PTCH", 4) != 0)
        goto done;
    if (memcmp(header + 64, expected, 4) != 0) {
        fprintf(stderr, "%s: expected %.4s transform, found %.4s\n", path, expected, header + 64);
        goto done;
    }
    failed = 0;

done:
    if (failed)
        fprintf(stderr, "%s: patch transform inspection failed\n", path);
    if (archive != NULL && libmpq__archive_close(archive) != LIBMPQ_SUCCESS)
        failed = 1;
    return failed;
}

/* Benchmark materialization only; setup and verification are outside the timer. */
static int
run_case(size_t size, int layers, int mode, unsigned repeats)
{
    char base_path[96];
    char next_path[96];
    char patch_one[96];
    char patch_two[96];
    const char *patches[2];
    uint8_t *before = NULL;
    uint8_t *middle = NULL;
    uint8_t *after = NULL;
    int failed = 1;
    double best = 1e30;

    (void)snprintf(
        base_path, sizeof(base_path), "bench-base-%lu-%d.mpq", (unsigned long)size, mode
    );
    (void)snprintf(
        next_path, sizeof(next_path), "bench-next-%lu-%d.mpq", (unsigned long)size, mode
    );
    (void)snprintf(patch_one, sizeof(patch_one), "bench-one-%lu-%d.mpq", (unsigned long)size, mode);
    (void)snprintf(patch_two, sizeof(patch_two), "bench-two-%lu-%d.mpq", (unsigned long)size, mode);
    before = malloc(size);
    middle = malloc(size);
    after = malloc(size);
    if (before == NULL || middle == NULL || after == NULL)
        goto done;
    fill_bytes(before, size, 0x12345678u);
    memcpy(middle, before, size);
    memcpy(after, before, size);
    if (mode == 1) {
        for (size_t i = size / 2; i < size / 2 + 32; i++) {
            middle[i] ^= 0x5au;
            after[i] ^= 0xa5u;
        }
    } else {
        fill_bytes(middle, size, 0x87654321u);
        fill_bytes(after, size, 0x13579bdfu);
        if (mode == 2) {
            memcpy(after, middle, size);
            for (size_t i = size / 2; i < size / 2 + 32; i++)
                after[i] ^= 0xa5u;
        }
    }
    if (make_archive(base_path, before, size) || make_patch(base_path, patch_one, middle, size) ||
        check_transform(patch_one, mode == 1 ? "BSD0" : "COPY"))
        goto done;
    patches[0] = patch_one;
    if (layers == 2) {
        if (make_archive(next_path, middle, size) ||
            make_patch(next_path, patch_two, after, size) ||
            check_transform(patch_two, mode == 0 ? "COPY" : "BSD0"))
            goto done;
        patches[1] = patch_two;
    }
    for (unsigned i = 0; i < repeats; i++) {
        mpq_patch_view_s *view = NULL;
        mpq_archive_s *archive;
        uint32_t number;
        uint8_t *actual = NULL;
        libmpq__off_t transferred = 0;
        double start = elapsed_now();
        double duration;

        int32_t status = libmpq__patch_view_open(&view, base_path, patches, (size_t)layers);

        if (status != LIBMPQ_SUCCESS) {
            fprintf(stderr, "patch view failed: %d\n", status);
            goto done;
        }
        duration = elapsed_now() - start;
        if (duration < best)
            best = duration;
        archive = libmpq__patch_view_archive(view);
        if (libmpq__file_number(archive, "payload.bin", &number) != LIBMPQ_SUCCESS ||
            (actual = malloc(size)) == NULL ||
            libmpq__file_read(archive, number, actual, (libmpq__off_t)size, &transferred) !=
                LIBMPQ_SUCCESS ||
            transferred != (libmpq__off_t)size ||
            memcmp(actual, layers == 2 ? after : middle, size) != 0) {
            free(actual);
            (void)libmpq__patch_view_close(view);
            goto done;
        }
        free(actual);
        if (libmpq__patch_view_close(view) != LIBMPQ_SUCCESS)
            goto done;
    }
    printf(
        "%s %s %lu KiB: %.3f ms (best/%u); %lu reconstructed member bytes, "
        "%d full-view passes\n",
        layers == 2 ? "chain" : "single", mode == 2 ? "COPY+BSD0" : (mode == 1 ? "BSD0" : "COPY"),
        (unsigned long)(size / 1024), best * 1000.0, repeats,
        (unsigned long)(size * (size_t)layers), layers
    );
    failed = 0;

done:
    (void)remove(base_path);
    (void)remove(next_path);
    (void)remove(patch_one);
    (void)remove(patch_two);
    free(before);
    free(middle);
    free(after);
    return failed;
}

/* Run identical deterministic cases at useful small, medium, and large sizes. */
int
main(int argc, char **argv)
{
    unsigned repeats = 3;
    const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };

    if (argc > 1) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (end == argv[1] || *end != '\0' || parsed == 0 || parsed > 100)
            return 2;
        repeats = (unsigned)parsed;
    }
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        for (int layers = 1; layers <= 2; layers++)
            for (int mode = 0; mode <= (layers == 2 ? 2 : 1); mode++)
                if (run_case(sizes[i], layers, mode, repeats) != 0)
                    return 1;
    return 0;
}
