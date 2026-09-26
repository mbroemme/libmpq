/*
 *  mpq-patch-bsd0.c -- private BSD0 patch generation.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
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

#include "mpq-patch-bsd0.h"
#include "mpq-endian.h"
#include "mpq-internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LIBMPQ_BSD0_HEADER_SIZE 32u
#define LIBMPQ_BSD0_CONTROL_SIZE 12u

/* Encode zero runs and literal runs using the reader's bounded RLE format. */
static size_t
patch_bsd0_rle(const uint8_t *raw, size_t size, uint8_t *output)
{
    size_t input = 0;
    size_t used = 4;

    memset(output, 0, 4);
    while (input < size) {
        size_t count = 0;
        uint8_t zero = raw[input] == 0;

        while (count < size - input && count < 128 && (raw[input + count] == 0) == zero)
            count++;
        output[used++] = (uint8_t)(count - 1) | (zero ? 0 : 0x80u);
        if (!zero) {
            memcpy(output + used, raw + input, count);
            used += count;
        }
        input += count;
    }
    return used;
}

/* Successful BSD0 output always uses the reader's RLE wrapper. */
static int32_t
patch_bsd0_pack(uint8_t *raw, size_t raw_size, uint8_t **encoded, size_t *encoded_size)
{
    size_t rle_capacity;
    size_t rle_size;
    uint8_t *rle;

    if (raw_size > (SIZE_MAX - 4) / 2) {
        free(raw);
        return LIBMPQ_ERROR_SIZE;
    }
    rle_capacity = raw_size * 2 + 4;
    rle = malloc(rle_capacity);
    if (rle == NULL) {
        free(raw);
        return LIBMPQ_ERROR_MALLOC;
    }
    rle_size = patch_bsd0_rle(raw, raw_size, rle);
    free(raw);
    *encoded = rle;
    *encoded_size = rle_size;
    return LIBMPQ_SUCCESS;
}

/* Build the aligned candidate, where unchanged bytes become zero differences. */
static uint8_t *
patch_bsd0_aligned(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    size_t *raw_size
)
{
    size_t overlap = before_size < after_size ? before_size : after_size;
    uint8_t *raw;

    *raw_size = LIBMPQ_BSD0_HEADER_SIZE + LIBMPQ_BSD0_CONTROL_SIZE + after_size;
    raw = calloc(1, *raw_size);
    if (raw == NULL)
        return NULL;
    memcpy(raw, "BSDIFF40", 8);
    libmpq__store_le64(raw + 8, LIBMPQ_BSD0_CONTROL_SIZE);
    libmpq__store_le64(raw + 16, overlap);
    libmpq__store_le64(raw + 24, after_size);
    libmpq__store_le32(raw + 32, (uint32_t)overlap);
    libmpq__store_le32(raw + 36, (uint32_t)(after_size - overlap));
    for (size_t i = 0; i < overlap; i++)
        raw[LIBMPQ_BSD0_HEADER_SIZE + LIBMPQ_BSD0_CONTROL_SIZE + i] =
            (uint8_t)(after[i] - before[i]);
    if (after_size != overlap)
        memcpy(
            raw + LIBMPQ_BSD0_HEADER_SIZE + LIBMPQ_BSD0_CONTROL_SIZE + overlap, after + overlap,
            after_size - overlap
        );
    return raw;
}

/*
 * A BSD0 tuple's add count combines base bytes with diff bytes. Its copy count
 * consumes literal extra-block bytes, not bytes from the base. The first
 * tuple copies the unchanged prefix literally and seeks to the old middle.
 * The second diffs overlapping middle bytes, copies inserted bytes from the
 * extra block, then skips any removed old-middle bytes. The final tuple
 * copies the unchanged suffix literally. Empty ranges omit their tuple.
 * This matches libmpq's BSD0 decoder, not a generic bsdiff copy operation.
 */
static uint8_t *
patch_bsd0_splice(
    const uint8_t *before, const uint8_t *after, size_t after_size, size_t prefix, size_t suffix,
    size_t old_middle, size_t *raw_size
)
{
    size_t new_middle = after_size - prefix - suffix;
    size_t overlap = old_middle < new_middle ? old_middle : new_middle;
    size_t inserted = new_middle - overlap;
    size_t control_count = (prefix != 0) + (overlap + inserted != 0) + (suffix != 0);
    size_t control_size = control_count * LIBMPQ_BSD0_CONTROL_SIZE;
    size_t delta_offset = LIBMPQ_BSD0_HEADER_SIZE + control_size;
    size_t extra_offset = delta_offset + overlap;
    size_t control_offset = LIBMPQ_BSD0_HEADER_SIZE;
    uint8_t *raw;

    *raw_size = LIBMPQ_BSD0_HEADER_SIZE + control_size + after_size;
    raw = calloc(1, *raw_size);
    if (raw == NULL)
        return NULL;
    memcpy(raw, "BSDIFF40", 8);
    libmpq__store_le64(raw + 8, control_size);
    libmpq__store_le64(raw + 16, overlap);
    libmpq__store_le64(raw + 24, after_size);
    if (prefix != 0) {
        libmpq__store_le32(raw + control_offset + 4, (uint32_t)prefix);
        libmpq__store_le32(raw + control_offset + 8, (uint32_t)prefix);
        control_offset += LIBMPQ_BSD0_CONTROL_SIZE;
        memcpy(raw + extra_offset, after, prefix);
    }
    if (overlap + inserted != 0) {
        libmpq__store_le32(raw + control_offset, (uint32_t)overlap);
        libmpq__store_le32(raw + control_offset + 4, (uint32_t)inserted);
        libmpq__store_le32(raw + control_offset + 8, (uint32_t)(old_middle - overlap));
        control_offset += LIBMPQ_BSD0_CONTROL_SIZE;
    }
    for (size_t i = 0; i < overlap; i++)
        raw[delta_offset + i] = (uint8_t)(after[prefix + i] - before[prefix + i]);
    if (inserted != 0)
        memcpy(raw + extra_offset + prefix, after + prefix + overlap, inserted);
    if (suffix != 0) {
        libmpq__store_le32(raw + control_offset + 4, (uint32_t)suffix);
        memcpy(raw + extra_offset + prefix + inserted, after + prefix + new_middle, suffix);
    }
    return raw;
}

/*
 * PTCH BSD0 uses libmpq's existing RLE-wrapped BSDIFF40-compatible layout.
 * The splice tuples above retain that decoder contract; the output is not a
 * generic bsdiff patch file.
 */
int32_t
libmpq__patch_bsd0_encode(
    const uint8_t *before, size_t before_size, const uint8_t *after, size_t after_size,
    uint8_t splice, uint8_t **encoded, size_t *encoded_size, size_t *patch_stream_size
)
{
    size_t prefix = 0;
    size_t suffix = 0;
    size_t raw_size;
    uint8_t *raw;

    if (encoded == NULL || encoded_size == NULL || patch_stream_size == NULL)
        return LIBMPQ_ERROR_EXIST;
    *encoded = NULL;
    *encoded_size = 0;
    *patch_stream_size = 0;
    if ((before == NULL && before_size != 0) || (after == NULL && after_size != 0))
        return LIBMPQ_ERROR_EXIST;
    if (before_size > UINT32_MAX || after_size > UINT32_MAX ||
        after_size > SIZE_MAX - LIBMPQ_BSD0_HEADER_SIZE - 3 * LIBMPQ_BSD0_CONTROL_SIZE ||
        after_size == 0)
        return LIBMPQ_ERROR_SIZE;
    if (splice == 0) {
        raw = patch_bsd0_aligned(before, before_size, after, after_size, &raw_size);
    } else {
        while (prefix < before_size && prefix < after_size && before[prefix] == after[prefix])
            prefix++;
        while (suffix < before_size - prefix && suffix < after_size - prefix &&
               before[before_size - suffix - 1] == after[after_size - suffix - 1])
            suffix++;
        if (suffix < 16 || (prefix == 0 && prefix + suffix == after_size) ||
            before_size - prefix - suffix > INT32_MAX)
            return LIBMPQ_SUCCESS;
        raw = patch_bsd0_splice(
            before, after, after_size, prefix, suffix, before_size - prefix - suffix, &raw_size
        );
    }
    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    *patch_stream_size = raw_size;
    return patch_bsd0_pack(raw, raw_size, encoded, encoded_size);
}
