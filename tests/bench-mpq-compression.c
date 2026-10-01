/*
 *  bench-mpq-compression.c -- production MPQ compression dispatch benchmark.
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

#include "mpq-compression.h"
#include "mpq-internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

typedef enum
{
    INPUT_REPEAT,
    INPUT_STRUCTURED,
    INPUT_RANDOM,
    INPUT_SPARSE,
    INPUT_PCM
} input_kind_t;

typedef struct
{
    const char *codec;
    const char *kind_label;
    uint32_t mask;
    uint32_t version;
    size_t size;
    input_kind_t kind;
    int lossy;
} benchmark_case_s;

/* Large cases focus on mainstream codecs; legacy codecs stay at 64 KiB. */
static const benchmark_case_s cases[] = {
    { "raw dispatch", "random", 0, 0, 1024u * 1024u, INPUT_RANDOM, 0 },
    { "raw dispatch", "structured", 0, 0, 16u * 1024u * 1024u, INPUT_STRUCTURED, 0 },
    { "zlib", "repeat", LIBMPQ_COMPRESSION_ZLIB, 0, 64u * 1024u, INPUT_REPEAT, 0 },
    { "zlib", "structured", LIBMPQ_COMPRESSION_ZLIB, 0, 1024u * 1024u, INPUT_STRUCTURED, 0 },
    { "zlib", "random", LIBMPQ_COMPRESSION_ZLIB, 0, 1024u * 1024u, INPUT_RANDOM, 0 },
    { "zlib", "structured", LIBMPQ_COMPRESSION_ZLIB, 0, 16u * 1024u * 1024u, INPUT_STRUCTURED, 0 },
    { "bzip2", "structured", LIBMPQ_COMPRESSION_BZIP2, 0, 64u * 1024u, INPUT_STRUCTURED, 0 },
    { "bzip2", "structured", LIBMPQ_COMPRESSION_BZIP2, 0, 1024u * 1024u, INPUT_STRUCTURED, 0 },
    { "LZMA", "structured", LIBMPQ_COMPRESSION_LZMA, 1, 64u * 1024u, INPUT_STRUCTURED, 0 },
    { "LZMA", "structured", LIBMPQ_COMPRESSION_LZMA, 1, 1024u * 1024u, INPUT_STRUCTURED, 0 },
    { "PKWARE", "repeat", LIBMPQ_COMPRESSION_PKZIP, 0, 64u * 1024u, INPUT_REPEAT, 0 },
    { "Huffman", "repeat", LIBMPQ_COMPRESSION_HUFFMAN, 0, 64u * 1024u, INPUT_REPEAT, 0 },
    { "SPARSE", "sparse", LIBMPQ_COMPRESSION_SPARSE, 0, 64u * 1024u, INPUT_SPARSE, 0 },
    { "SPARSE+zlib", "sparse", LIBMPQ_COMPRESSION_SPARSE | LIBMPQ_COMPRESSION_ZLIB, 0, 64u * 1024u,
      INPUT_SPARSE, 0 },
    { "ADPCM mono", "PCM", LIBMPQ_COMPRESSION_WAVE_MONO, 0, 64u * 1024u, INPUT_PCM, 1 },
    { "ADPCM+Huffman", "PCM", LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_HUFFMAN, 0,
      64u * 1024u, INPUT_PCM, 1 }
};

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

static void
fill_input(uint8_t *data, size_t size, input_kind_t kind)
{
    uint32_t state = 0x13579bdfu;
    size_t i;

    for (i = 0; i < size; i++) {
        switch (kind) {
        case INPUT_REPEAT:
            data[i] = (uint8_t)(i % 8u);
            break;
        case INPUT_STRUCTURED:
            data[i] = (uint8_t)(((i / 128u) + (i % 37u)) & 0xffu);
            break;
        case INPUT_RANDOM:
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            data[i] = (uint8_t)state;
            break;
        case INPUT_SPARSE:
            data[i] = (i % 256u < 240u) ? 0 : (uint8_t)i;
            break;
        case INPUT_PCM:

            /* Little-endian signed 16-bit triangular PCM, not arbitrary bytes. */
            if ((i & 1u) == 0) {
                int16_t sample = (int16_t)(((i / 2u) % 256u) * 192u - 24576);
                data[i] = (uint8_t)sample;
                if (i + 1 < size)
                    data[i + 1] = (uint8_t)((uint16_t)sample >> 8);
            }
            break;
        }
    }
}

static int
encode(
    const benchmark_case_s *case_info, const uint8_t *input, uint8_t **packed, size_t *packed_size,
    uint8_t *emitted
)
{
    return libmpq__compression_encode_sector(
               input, case_info->size, case_info->mask, case_info->version,
               LIBMPQ_COMPRESSION_POLICY_EXTENDED, packed, packed_size, emitted
           ) == LIBMPQ_SUCCESS;
}

static int
decode(
    const benchmark_case_s *case_info, const uint8_t *packed, size_t packed_size, uint8_t emitted,
    uint8_t *decoded
)
{
    uint8_t *mutable_packed = malloc(packed_size ? packed_size : 1);
    int32_t result;

    if (mutable_packed == NULL)
        return 0;
    memcpy(mutable_packed, packed, packed_size);
    if (emitted == 0)
        result = libmpq__compression_decompress_block(
            mutable_packed, (uint32_t)packed_size, decoded, (uint32_t)case_info->size,
            LIBMPQ_FLAG_COMPRESS_NONE, case_info->version
        );
    else
        result = libmpq__compression_decompress_block(
            mutable_packed, (uint32_t)packed_size, decoded, (uint32_t)case_info->size,
            LIBMPQ_FLAG_COMPRESS_MULTI, case_info->version
        );
    free(mutable_packed);
    return result == (int32_t)case_info->size;
}

static int
run_case(const benchmark_case_s *case_info, unsigned runs)
{
    uint8_t expected_mask = case_info->mask == LIBMPQ_COMPRESSION_LZMA
                                ? LIBMPQ_COMPRESSION_LZMA_METHOD
                                : (uint8_t)case_info->mask;
    const char *size_label = case_info->size == 64u * 1024u     ? "64 KiB"
                             : case_info->size == 1024u * 1024u ? "1 MiB"
                                                                : "16 MiB";
    uint8_t *input = malloc(case_info->size);
    uint8_t *decoded = malloc(case_info->size);
    uint8_t *reference = NULL;
    uint8_t *packed = NULL;
    size_t packed_size = 0;
    uint8_t emitted = 0;
    double encode_best = 1e30;
    double decode_best = 1e30;
    unsigned run;
    int failed = 1;

    if (input == NULL || decoded == NULL)
        goto done;
    fill_input(input, case_info->size, case_info->kind);
    if (!encode(case_info, input, &packed, &packed_size, &emitted))
        goto done;
    if (case_info->mask != 0 && case_info->kind != INPUT_RANDOM && emitted != expected_mask)
        goto done;
    if (case_info->mask != 0 && case_info->kind == INPUT_RANDOM && emitted != 0)
        goto done;

    /* Lossy ADPCM is checked against an untimed decode, not source PCM. */
    if (case_info->lossy && emitted != 0) {
        reference = malloc(case_info->size);
        if (reference == NULL || !decode(case_info, packed, packed_size, emitted, reference))
            goto done;
    }
    if (!decode(case_info, packed, packed_size, emitted, decoded) ||
        memcmp(decoded, reference != NULL ? reference : input, case_info->size) != 0)
        goto done;

    for (run = 0; run < runs; run++) {
        uint8_t *candidate = NULL;
        size_t candidate_size = 0;
        uint8_t candidate_mask = 0;
        double start = elapsed_now();
        double duration;

        if (!encode(case_info, input, &candidate, &candidate_size, &candidate_mask))
            goto done;
        duration = elapsed_now() - start;
        if (duration < encode_best)
            encode_best = duration;
        if (candidate_size != packed_size || candidate_mask != emitted ||
            memcmp(candidate, packed, packed_size) != 0) {
            free(candidate);
            goto done;
        }
        free(candidate);
    }
    for (run = 0; run < runs; run++) {
        uint8_t *mutable_packed = malloc(packed_size ? packed_size : 1);
        int32_t result;
        double start;
        double duration;

        if (mutable_packed == NULL)
            goto done;
        memcpy(mutable_packed, packed, packed_size);
        memset(decoded, 0xa5, case_info->size);
        start = elapsed_now();
        result = libmpq__compression_decompress_block(
            mutable_packed, (uint32_t)packed_size, decoded, (uint32_t)case_info->size,
            emitted == 0 ? LIBMPQ_FLAG_COMPRESS_NONE : LIBMPQ_FLAG_COMPRESS_MULTI,
            case_info->version
        );
        duration = elapsed_now() - start;
        free(mutable_packed);
        if (result != (int32_t)case_info->size ||
            memcmp(decoded, reference != NULL ? reference : input, case_info->size) != 0)
            goto done;
        if (duration < decode_best)
            decode_best = duration;
    }

    printf(
        "%s / %s / %s: %zu bytes %s (mask 0x%02x), compress %.3f ms, "
        "decompress %.3f ms elapsed "
        "(best/%u)\n",
        case_info->codec, case_info->kind_label, size_label, packed_size,
        emitted == 0 ? "stored fallback" : "packed", (unsigned)emitted, encode_best * 1000.0,
        decode_best * 1000.0, runs
    );
    failed = 0;

done:
    if (failed)
        fprintf(
            stderr, "bench-compression: %s / %s / %s failed\n", case_info->codec,
            case_info->kind_label, size_label
        );
    free(packed);
    free(reference);
    free(decoded);
    free(input);
    return failed;
}

int
main(int argc, char **argv)
{
    unsigned runs = 3;
    size_t i;

    if (argc > 2)
        return 2;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);

        if (argv[1][0] < '0' || argv[1][0] > '9' || *end != 0 || parsed == 0 || parsed > 100)
            return 2;
        runs = (unsigned)parsed;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (run_case(&cases[i], runs))
            return 1;
    }
    return 0;
}
