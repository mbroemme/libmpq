/*
 *  wave.c -- WAVE decompression helpers for MPQ audio payloads.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This source was adapted from the C++ version of wave.cpp included
 *  in stormlib. The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
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

#include "wave.h"
#include "endian.h"

/* Predictor-index adjustments used by the MPQ ADPCM WAVE decoder. */
static const uint32_t wave_step_adjustments[] = {
    0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000004, 0xFFFFFFFF, 0x00000002, 0xFFFFFFFF, 0x00000006,
    0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0x00000005, 0xFFFFFFFF, 0x00000003, 0xFFFFFFFF, 0x00000007,
    0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0x00000005, 0xFFFFFFFF, 0x00000003, 0xFFFFFFFF, 0x00000007,
    0xFFFFFFFF, 0x00000002, 0xFFFFFFFF, 0x00000004, 0xFFFFFFFF, 0x00000006, 0xFFFFFFFF, 0x00000008
};

/* Step-size table used by the MPQ ADPCM WAVE decoder. */
static const uint32_t wave_step_sizes[] = {
    0x00000007, 0x00000008, 0x00000009, 0x0000000A, 0x0000000B, 0x0000000C, 0x0000000D, 0x0000000E,
    0x00000010, 0x00000011, 0x00000013, 0x00000015, 0x00000017, 0x00000019, 0x0000001C, 0x0000001F,
    0x00000022, 0x00000025, 0x00000029, 0x0000002D, 0x00000032, 0x00000037, 0x0000003C, 0x00000042,
    0x00000049, 0x00000050, 0x00000058, 0x00000061, 0x0000006B, 0x00000076, 0x00000082, 0x0000008F,
    0x0000009D, 0x000000AD, 0x000000BE, 0x000000D1, 0x000000E6, 0x000000FD, 0x00000117, 0x00000133,
    0x00000151, 0x00000173, 0x00000198, 0x000001C1, 0x000001EE, 0x00000220, 0x00000256, 0x00000292,
    0x000002D4, 0x0000031C, 0x0000036C, 0x000003C3, 0x00000424, 0x0000048E, 0x00000502, 0x00000583,
    0x00000610, 0x000006AB, 0x00000756, 0x00000812, 0x000008E0, 0x000009C3, 0x00000ABD, 0x00000BD0,
    0x00000CFF, 0x00000E4C, 0x00000FBA, 0x0000114C, 0x00001307, 0x000014EE, 0x00001706, 0x00001954,
    0x00001BDC, 0x00001EA5, 0x000021B6, 0x00002515, 0x000028CA, 0x00002CDF, 0x0000315B, 0x0000364B,
    0x00003BB9, 0x000041B2, 0x00004844, 0x00004F7E, 0x00005771, 0x0000602F, 0x000069CE, 0x00007462,
    0x00007FFF
};

/* Decompress mono or stereo MPQ WAVE predictor data into PCM bytes. */
int32_t
libmpq__do_decompress_wave(
    uint8_t *out_buf, int32_t out_length, uint8_t *in_buf, int32_t in_length, int32_t channels
)
{

    /* Decoder state for channel deltas and transferred bytes. */
    uint8_t *out_ptr;
    uint32_t index;
    int32_t step_indices[2];
    int32_t predictor_samples[2];
    int32_t count = 0;

    if (channels < 1 || channels > 2 || in_length < 2 + channels * 2) {
        return 0;
    }

    /* Stop decoding when the compressed stream cursor reaches this address. */
    uint8_t *in_end = in_buf + in_length;

    out_ptr = out_buf;
    step_indices[0] = 0x2C;
    step_indices[1] = 0x2C;

    /* The first word is the MPQ WAVE predictor header, followed by seed samples. */
    in_buf += sizeof(uint16_t);

    /* Emit the initial seed sample for each channel. */
    for (count = 0; count < channels; count++) {

        /* Current sample code and output channel for this input byte. */
        int32_t temp;

        temp = (int16_t)libmpq__load_le16(in_buf);
        in_buf += sizeof(uint16_t);
        predictor_samples[count] = temp;

        if (out_length < 2) {
            return (int32_t)(out_ptr - out_buf);
        }

        libmpq__store_le16(out_ptr, (uint16_t)temp);
        out_ptr += sizeof(uint16_t);
        out_length -= 2;
    }

    /* Start with the last channel so stereo data alternates on each emitted sample. */
    index = channels - 1;

    while (in_buf < in_end) {
        uint8_t one_byte = *in_buf++;

        if (channels == 2) {
            index = (index == 0) ? 1 : 0;
        }

        /* High-bit control bytes adjust predictor state instead of carrying deltas. */
        if (one_byte & 0x80) {
            switch (one_byte & 0x7F) {
            case 0:

                if (step_indices[index] != 0) {
                    step_indices[index]--;
                }

                if (out_length < 2) {
                    break;
                }

                libmpq__store_le16(out_ptr, (uint16_t)predictor_samples[index]);
                out_ptr += sizeof(uint16_t);
                out_length -= 2;
                continue;
            case 1:

                step_indices[index] += 8;

                if (step_indices[index] > 0x58) {
                    step_indices[index] = 0x58;
                }

                if (channels == 2) {
                    index = (index == 0) ? 1 : 0;
                }
                continue;
            case 2:
                continue;
            default:
                step_indices[index] -= 8;

                if (step_indices[index] < 0) {
                    step_indices[index] = 0;
                }

                if (channels != 2) {
                    continue;
                }
                index = (index == 0) ? 1 : 0;
                continue;
            }
        } else {

            /* Decode a signed delta from the current step-size table entry. */
            uint32_t temp1 = wave_step_sizes[step_indices[index]];
            uint32_t temp2 = temp1 >> in_buf[1];
            int32_t temp3 = predictor_samples[index];

            if (one_byte & 0x01) {
                temp2 += (temp1 >> 0);
            }
            if (one_byte & 0x02) {
                temp2 += (temp1 >> 1);
            }
            if (one_byte & 0x04) {
                temp2 += (temp1 >> 2);
            }
            if (one_byte & 0x08) {
                temp2 += (temp1 >> 3);
            }
            if (one_byte & 0x10) {
                temp2 += (temp1 >> 4);
            }
            if (one_byte & 0x20) {
                temp2 += (temp1 >> 5);
            }
            if (one_byte & 0x40) {
                temp3 -= temp2;
                if (temp3 <= (int32_t)0xFFFF8000) {
                    temp3 = (int32_t)0xFFFF8000;
                }
            } else {
                temp3 += temp2;
                if (temp3 >= 0x7FFF) {
                    temp3 = 0x7FFF;
                }
            }

            /* Store the clamped predictor sample for the active channel. */
            predictor_samples[index] = temp3;

            if (out_length < 2) {
                break;
            }

            temp2 = step_indices[index];
            one_byte &= 0x1F;
            libmpq__store_le16(out_ptr, (uint16_t)temp3);
            out_ptr += sizeof(uint16_t);
            out_length -= 2;
            temp2 += wave_step_adjustments[one_byte];
            step_indices[index] = temp2;

            if (step_indices[index] < 0) {
                step_indices[index] = 0;
            } else {
                if (step_indices[index] > 0x58) {
                    step_indices[index] = 0x58;
                }
            }
        }
    }

    return (int32_t)(out_ptr - out_buf);
}
