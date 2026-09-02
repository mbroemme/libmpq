/*
 *  mpq-wave.h -- MPQ WAVE decompression declarations and lookup tables.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This source was adapted from the C++ version of mpq-wave.h included
 *  in stormlib. The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik.zezula.net>
 *  Tom Amigo <tomamigo@apexmail.com>
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

#ifndef LIBMPQ_WAVE_H
#define LIBMPQ_WAVE_H

#include <stdint.h>

/* Locations and size of the PCM data chunk in a validated RIFF/WAVE file. */
typedef struct
{
    uint16_t channels;
    uint32_t data_offset;
    uint32_t data_size;
} libmpq_wave_info_s;

/* Validate a RIFF/WAVE PCM16 payload and return its channel/data boundaries. */
int32_t libmpq__wave_probe_pcm16(const uint8_t *data, uint32_t size, libmpq_wave_info_s *info);

/* Validate a RIFF/WAVE PCM16 prefix against the complete declared file size. */
int32_t libmpq__wave_probe_pcm16_prefix(
    const uint8_t *data, uint32_t prefix_size, uint64_t file_size, libmpq_wave_info_s *info
);

/* Encode complete PCM16 mono or stereo samples as MPQ ADPCM payload bytes. */
int32_t libmpq__wave_compress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t **out_buf, uint32_t *out_size,
    uint32_t channels
);

/* Decode mono or stereo MPQ ADPCM predictor data into signed PCM16 bytes. */
int32_t libmpq__wave_decompress(
    uint8_t *out_buf, int32_t out_length, uint8_t *in_buf, int32_t in_length, int32_t channels
);

#endif /* LIBMPQ_WAVE_H */
