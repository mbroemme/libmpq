/*
 *  bench-mpq-source.c -- file and custom-I/O source benchmark.
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

#include "mpq-reader.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define BENCH_SMALL_FILES 512u
#define BENCH_SEEKS 256u
#define BENCH_SEEK_SIZE 4096u

typedef struct
{
    const uint8_t *data;
    size_t size;
    int count;
    uint64_t reads;
    uint64_t bytes;
    size_t minimum;
    size_t maximum;
} memory_source_s;

typedef struct
{
    const char *label;
    mpq_file_options_s options;
} bench_mode_s;

static const uint8_t bench_auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
static const bench_mode_s bench_modes[] = {
    { "stored", { 0, 0, 0, 0, 0 } },
    { "zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 } },
    { "encrypted stored", { LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 } },
    { "encrypted+zlib",
      { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, LIBMPQ_COMPRESSION_ZLIB,
        LIBMPQ_COMPRESSION_ZLIB, 0, 0 } }
};

/* Return monotonic elapsed seconds on the current platform. */
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

/* Fill deterministic source bytes with sector-local compressible variation. */
static void
fill_bytes(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = (uint8_t)(((i / 64u) + (i % 11u)) & 0x7fu);
}

/* Copy exact caller-requested bytes; count requests only in diagnostic runs. */
static int32_t
memory_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    memory_source_s *source = context;

    if (source == NULL || (buffer == NULL && size != 0) || offset < 0 ||
        (uint64_t)offset > source->size || size > source->size - (size_t)offset)
        return LIBMPQ_ERROR_READ;
    if (source->count) {
        ++source->reads;
        source->bytes += size;
        if (size < source->minimum)
            source->minimum = size;
        if (size > source->maximum)
            source->maximum = size;
    }
    if (size != 0)
        memcpy(buffer, source->data + (size_t)offset, size);
    return 0;
}

/* Reset diagnostic counters without changing the caller-owned byte buffer. */
static void
start_counting(memory_source_s *source)
{
    source->reads = 0;
    source->bytes = 0;
    source->minimum = SIZE_MAX;
    source->maximum = 0;
    source->count = 1;
}

/* Print callback granularity after an untimed diagnostic operation. */
static void
print_counts(const char *label, memory_source_s *source)
{
    source->count = 0;
    printf(
        "%s callbacks: %llu reads, %llu bytes, min %zu, max %zu\n", label,
        (unsigned long long)source->reads, (unsigned long long)source->bytes,
        source->reads ? source->minimum : 0, source->maximum
    );
}

/* Open equivalent archive bytes through either public source interface. */
static int32_t
open_archive(
    mpq_archive_s **archive, const char *path, memory_source_s *memory, int custom, int mpqe
)
{
    if (mpqe) {
        if (custom)
            return libmpq__archive_open_mpqe_io(
                archive, memory, memory_read_at, (libmpq__off_t)memory->size, 0, bench_auth,
                sizeof(bench_auth) - 1u, NULL
            );
        return libmpq__archive_open_mpqe(archive, path, 0, bench_auth, sizeof(bench_auth) - 1u);
    }
    if (custom)
        return libmpq__archive_open_io(
            archive, memory, memory_read_at, (libmpq__off_t)memory->size, 0, NULL
        );
    return libmpq__archive_open(archive, path, 0);
}

/* Create one normal or MPQE archive before any open/extraction timing. */
static int
make_archive(const char *path, const uint8_t *data, size_t size, const bench_mode_s *mode, int mpqe)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 16, 4096, 0, 0 };
    mpq_archive_s *archive = NULL;
    int32_t result;

    if (mpqe)
        result = libmpq__archive_create_mpqe(
            &archive, path, bench_auth, sizeof(bench_auth) - 1u, &options
        );
    else
        result = libmpq__archive_create(&archive, path, &options);
    if (result != 0)
        return 1;
    result =
        libmpq__archive_add_data(archive, "payload.bin", data, (libmpq__off_t)size, &mode->options);
    if (result == 0)
        result = libmpq__archive_close(archive);
    else
        (void)libmpq__archive_close(archive);
    return result != 0;
}

/* Build a metadata-heavy archive to exercise table reads at open time. */
static int
make_many_archive(const char *path)
{
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 1024, 4096, 0, 0 };
    mpq_file_options_s file_options = { 0, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;
    uint8_t data[128];
    char name[40];
    int32_t result = libmpq__archive_create(&archive, path, &options);

    if (result != 0)
        return 1;
    for (unsigned i = 0; i < BENCH_SMALL_FILES; i++) {
        (void)snprintf(name, sizeof(name), "small-%04u.bin", i);
        fill_bytes(data, sizeof(data));
        data[0] = (uint8_t)i;
        result = libmpq__archive_add_data(archive, name, data, sizeof(data), &file_options);
        if (result != 0)
            break;
    }
    if (result == 0)
        result = libmpq__archive_close(archive);
    else
        (void)libmpq__archive_close(archive);
    return result != 0;
}

/* Time only archive opening, then diagnose custom callback granularity separately. */
static int
run_open(const char *path, memory_source_s *memory, const char *label, int mpqe, unsigned runs)
{
    double best[2] = { 1e30, 1e30 };
    mpq_archive_s *archive = NULL;

    for (int custom = 0; custom < 2; custom++) {
        for (unsigned run = 0; run < runs; run++) {
            double start = elapsed_now();
            int32_t result = open_archive(&archive, path, memory, custom, mpqe);
            double duration = elapsed_now() - start;

            if (result != 0)
                return 1;
            if (duration < best[custom])
                best[custom] = duration;
            result = libmpq__archive_close(archive);
            archive = NULL;
            if (result != 0)
                return 1;
        }
    }
    start_counting(memory);
    if (open_archive(&archive, path, memory, 1, mpqe) != 0) {
        memory->count = 0;
        return 1;
    }
    print_counts(label, memory);
    if (libmpq__archive_close(archive) != 0)
        return 1;
    printf("%s file open: %.3f ms elapsed (best/%u)\n", label, best[0] * 1000.0, runs);
    printf("%s custom open: %.3f ms elapsed (best/%u)\n", label, best[1] * 1000.0, runs);
    return 0;
}

/* Read a named member through the normal reader and release its offset state. */
static int32_t
extract_payload(mpq_archive_s *archive, uint32_t number, uint8_t *output, size_t size)
{
    libmpq__off_t transferred = 0;
    int32_t result = libmpq__reader_offsets_acquire(archive, number, "payload.bin");

    if (result != 0)
        return result;
    result = libmpq__file_read(archive, number, output, (libmpq__off_t)size, &transferred);
    if (libmpq__reader_offsets_release(archive, number) != 0)
        return LIBMPQ_ERROR_READ;
    return result == 0 && transferred != (libmpq__off_t)size ? LIBMPQ_ERROR_READ : result;
}

/* Confirm the first and last sectors match the claimed storage mode. */
static int
verify_mode(mpq_archive_s *archive, uint32_t number, const bench_mode_s *mode)
{
    uint32_t blocks = 0;
    int failed = 1;

    if (libmpq__file_blocks(archive, number, &blocks) != 0 || blocks == 0 ||
        libmpq__reader_offsets_acquire(archive, number, "payload.bin") != 0)
        return 1;
    for (unsigned i = 0; i < 2; i++) {
        uint32_t method = UINT32_MAX;
        uint32_t block = i == 0 ? 0 : blocks - 1u;
        uint32_t expected =
            mode->options.flags & LIBMPQ_FILE_FLAG_COMPRESS ? LIBMPQ_COMPRESSION_ZLIB : 0;

        if (libmpq__block_compression(archive, number, block, &method) != 0 || method != expected)
            goto done;
    }
    failed = 0;
done:
    if (libmpq__reader_offsets_release(archive, number) != 0)
        failed = 1;
    return failed;
}

/* Compare exact extraction through already-open path and custom sources. */
static int
run_extract(
    const char *path, memory_source_s *memory, const uint8_t *expected, size_t size,
    const char *label, const bench_mode_s *mode, int mpqe, unsigned runs
)
{
    mpq_archive_s *archives[2] = { NULL, NULL };
    uint32_t numbers[2] = { 0, 0 };
    uint8_t *actual = malloc(size);
    char diagnostic_label[128];
    double best[2] = { 1e30, 1e30 };
    int failed = 1;

    if (actual == NULL)
        return 1;
    for (int custom = 0; custom < 2; custom++) {
        uint32_t flags = 0;
        libmpq__off_t logical_size = 0;

        if (open_archive(&archives[custom], path, memory, custom, mpqe) != 0 ||
            libmpq__file_number(archives[custom], "payload.bin", &numbers[custom]) != 0 ||
            libmpq__file_flags(archives[custom], numbers[custom], &flags) != 0 ||
            libmpq__file_size_unpacked(archives[custom], numbers[custom], &logical_size) != 0 ||
            logical_size != (libmpq__off_t)size ||
            (flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED)) !=
                mode->options.flags ||
            verify_mode(archives[custom], numbers[custom], mode))
            goto done;
        for (unsigned run = 0; run < runs; run++) {
            double start;
            double duration;
            int32_t result;

            memset(actual, 0xa5, size);
            start = elapsed_now();
            result = extract_payload(archives[custom], numbers[custom], actual, size);
            duration = elapsed_now() - start;
            if (result != 0 || memcmp(actual, expected, size) != 0)
                goto done;
            if (duration < best[custom])
                best[custom] = duration;
        }
    }
    start_counting(memory);
    memset(actual, 0xa5, size);
    if (extract_payload(archives[1], numbers[1], actual, size) != 0 ||
        memcmp(actual, expected, size) != 0) {
        memory->count = 0;
        goto done;
    }
    (void)snprintf(diagnostic_label, sizeof(diagnostic_label), "%s %s extract", label, mode->label);
    print_counts(diagnostic_label, memory);
    printf(
        "%s %s file extract: %.3f ms elapsed (best/%u)\n", label, mode->label, best[0] * 1000.0,
        runs
    );
    printf(
        "%s %s custom extract: %.3f ms elapsed (best/%u)\n", label, mode->label, best[1] * 1000.0,
        runs
    );
    failed = 0;
done:
    for (int custom = 0; custom < 2; custom++)
        if (archives[custom] != NULL && libmpq__archive_close(archives[custom]) != 0)
            failed = 1;
    free(actual);
    if (failed)
        fprintf(stderr, "source extraction benchmark failed: %s %s\n", label, mode->label);
    return failed;
}

/* Run sequential or fixed seek/read work against an already-open stream. */
static int
stream_work(
    mpq_stream_s *stream, size_t size, uint8_t *actual, size_t chunk, int random,
    const size_t offsets[BENCH_SEEKS]
)
{
    if (!random) {
        for (size_t offset = 0; offset < size; offset += chunk) {
            libmpq__off_t transferred = 0;
            size_t take = size - offset < chunk ? size - offset : chunk;

            if (libmpq__stream_read(stream, actual + offset, (libmpq__off_t)take, &transferred) !=
                    0 ||
                transferred != (libmpq__off_t)take)
                return 1;
        }
        return 0;
    }
    for (unsigned i = 0; i < BENCH_SEEKS; i++) {
        libmpq__off_t transferred = 0;

        if (libmpq__stream_seek(stream, (libmpq__off_t)offsets[i], LIBMPQ_SEEK_SET) != 0 ||
            libmpq__stream_read(
                stream, actual + (size_t)i * BENCH_SEEK_SIZE, BENCH_SEEK_SIZE, &transferred
            ) != 0 ||
            transferred != BENCH_SEEK_SIZE)
            return 1;
    }
    return 0;
}

/* Check completed stream bytes after the elapsed-time interval. */
static int
verify_stream_output(
    const uint8_t *expected, size_t size, const uint8_t *actual, int random,
    const size_t offsets[BENCH_SEEKS]
)
{
    if (!random)
        return memcmp(actual, expected, size) != 0;
    for (unsigned i = 0; i < BENCH_SEEKS; i++)
        if (memcmp(actual + (size_t)i * BENCH_SEEK_SIZE, expected + offsets[i], BENCH_SEEK_SIZE) !=
            0)
            return 1;
    return 0;
}

/* Compare focused stream workloads without including stream creation time. */
static int
run_stream(
    const char *path, memory_source_s *memory, const uint8_t *expected, size_t size, size_t chunk,
    int random, const char *label, unsigned runs
)
{
    mpq_archive_s *archives[2] = { NULL, NULL };
    mpq_stream_s *streams[2] = { NULL, NULL };
    uint8_t *actual = malloc(random ? BENCH_SEEKS * BENCH_SEEK_SIZE : size);
    size_t offsets[BENCH_SEEKS];
    double best[2] = { 1e30, 1e30 };
    int failed = 1;

    if (actual == NULL)
        return 1;
    for (unsigned i = 0; i < BENCH_SEEKS; i++)
        offsets[i] = ((size_t)i * 104729u) % (size - BENCH_SEEK_SIZE + 1u);
    for (int custom = 0; custom < 2; custom++) {
        if (open_archive(&archives[custom], path, memory, custom, 0) != 0 ||
            libmpq__stream_open_name(archives[custom], "payload.bin", &streams[custom]) != 0)
            goto done;
        for (unsigned run = 0; run < runs; run++) {
            double start;
            double duration;

            if (libmpq__stream_seek(streams[custom], 0, LIBMPQ_SEEK_SET) != 0)
                goto done;
            memset(actual, 0xa5, random ? BENCH_SEEKS * BENCH_SEEK_SIZE : size);
            start = elapsed_now();
            int invalid = stream_work(streams[custom], size, actual, chunk, random, offsets);
            duration = elapsed_now() - start;
            if (invalid || verify_stream_output(expected, size, actual, random, offsets))
                goto done;
            if (duration < best[custom])
                best[custom] = duration;
        }
    }
    if (libmpq__stream_seek(streams[1], 0, LIBMPQ_SEEK_SET) != 0)
        goto done;
    memset(actual, 0xa5, random ? BENCH_SEEKS * BENCH_SEEK_SIZE : size);
    start_counting(memory);
    if (stream_work(streams[1], size, actual, chunk, random, offsets) ||
        verify_stream_output(expected, size, actual, random, offsets)) {
        memory->count = 0;
        goto done;
    }
    print_counts(label, memory);
    printf("%s file stream: %.3f ms elapsed (best/%u)\n", label, best[0] * 1000.0, runs);
    printf("%s custom stream: %.3f ms elapsed (best/%u)\n", label, best[1] * 1000.0, runs);
    failed = 0;
done:
    for (int custom = 0; custom < 2; custom++) {
        if (streams[custom] != NULL && libmpq__stream_close(streams[custom]) != 0)
            failed = 1;
        if (archives[custom] != NULL && libmpq__archive_close(archives[custom]) != 0)
            failed = 1;
    }
    free(actual);
    return failed;
}

/* Stage a fixture and its exact byte-for-byte memory backing before timing. */
static int
run_fixture(size_t size, const char *size_label, const bench_mode_s *mode, int mpqe, unsigned runs)
{
    const char *path = mpqe ? "bench-source.mpqe" : "bench-source.mpq";
    uint8_t *expected = malloc(size);
    uint8_t *backing = NULL;
    size_t backing_size = 0;
    memory_source_s memory = { 0 };
    int failed = 1;

    if (expected == NULL)
        return 1;
    fill_bytes(expected, size);
    if (make_archive(path, expected, size, mode, mpqe) ||
        test_read_path(path, &backing, &backing_size) || backing_size > INT64_MAX)
        goto done;
    memory.data = backing;
    memory.size = backing_size;
    if ((size == 64u * 1024u && mode == &bench_modes[0] && !mpqe &&
         run_open(path, &memory, "minimal MPQ", 0, runs)) ||
        (size == 1024u * 1024u && mode == &bench_modes[0] && mpqe &&
         run_open(path, &memory, "1 MiB MPQE", 1, runs)) ||
        run_extract(path, &memory, expected, size, size_label, mode, mpqe, runs))
        goto done;
    if (size == 16u * 1024u * 1024u && mode == &bench_modes[0] && !mpqe) {
        if (run_stream(
                path, &memory, expected, size, 4096u, 0, "16 MiB stored stream 4 KiB", runs
            ) ||
            run_stream(
                path, &memory, expected, size, 65536u, 0, "16 MiB stored stream 64 KiB", runs
            ) ||
            run_stream(
                path, &memory, expected, size, BENCH_SEEK_SIZE, 1, "16 MiB stored stream seek/read",
                runs
            ))
            goto done;
    }
    failed = 0;
done:
    free(expected);
    free(backing);
    (void)remove(path);
    return failed;
}

/* Measure opening a deterministic 512-member archive through both sources. */
static int
run_many_open(unsigned runs)
{
    const char *path = "bench-source-many.mpq";
    memory_source_s memory = { 0 };
    uint8_t *backing = NULL;
    size_t backing_size = 0;
    int failed = 1;

    if (make_many_archive(path) || test_read_path(path, &backing, &backing_size))
        goto done;
    memory.data = backing;
    memory.size = backing_size;
    if (run_open(path, &memory, "512-file MPQ", 0, runs))
        goto done;
    failed = 0;
done:
    free(backing);
    (void)remove(path);
    return failed;
}

/* Run deterministic file/custom source comparisons with the common CLI. */
int
main(int argc, char **argv)
{
    const size_t sizes[] = { 64u * 1024u, 1024u * 1024u, 16u * 1024u * 1024u };
    const char *labels[] = { "64 KiB", "1 MiB", "16 MiB" };
    unsigned runs = 3;

    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (argv[1][0] < '0' || argv[1][0] > '9' || *end != 0 || parsed == 0 || parsed > 100)
            return 2;
        runs = (unsigned)parsed;
    }
    for (size_t i = 0; i < 3; i++) {
        for (size_t mode = 0; mode < 4; mode++) {
            if (run_fixture(sizes[i], labels[i], &bench_modes[mode], 0, runs))
                return 1;
        }
    }
    if (run_many_open(runs) || run_fixture(1024u * 1024u, "1 MiB MPQE", &bench_modes[0], 1, runs) ||
        run_fixture(16u * 1024u * 1024u, "16 MiB MPQE", &bench_modes[0], 1, runs))
        return 1;
    return 0;
}
