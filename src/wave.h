/*
 *  wave.h -- MPQ WAVE decompression declarations and lookup tables.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This source was adapted from the C++ version of wave.h included
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

#ifndef _WAVE_H
#define _WAVE_H

/* Cursor that can address WAVE output as bytes or 16-bit PCM samples. */
typedef union
{
    uint16_t *pw;
    uint8_t *pb;
} byte_and_int16_t;

/* Decompress mono or stereo MPQ WAVE predictor data into PCM bytes. */
int32_t libmpq__do_decompress_wave(
    uint8_t *out_buf, int32_t out_length, uint8_t *in_buf, int32_t in_length, int32_t channels
);

#endif /* _WAVE_H */
