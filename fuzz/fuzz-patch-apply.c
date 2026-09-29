/*
 *  fuzz-patch-apply.c -- bounded private patch parser and decoder fuzzing.
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

#include "mpq-endian.h"
#include "mpq-patch-reader.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mpq_patch_info_s info;
    uint8_t *output = NULL;
    size_t output_size = 0;
    size_t base_size;
    const uint8_t *patch;
    size_t patch_size;

    if (size < 2 || size > 8192)
        return 0;
    libmpq__patch_info_parse(data, size, &info);
    base_size = libmpq__load_le16(data) % (size - 1);
    patch = data + 2 + base_size;
    patch_size = size - 2 - base_size;
    libmpq__patch_info_parse(patch, patch_size, &info);
    if (patch_size >= 16 && libmpq__load_le32(patch + 12) > 65536)
        return 0;
    if (patch_size >= 8 && libmpq__load_le32(patch + 4) > 65536)
        return 0;
    libmpq__patch_apply(data + 2, base_size, patch, patch_size, &output, &output_size);
    free(output);
    return 0;
}
