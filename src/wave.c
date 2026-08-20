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
#include <libmpq/mpq.h>
#include <stdlib.h>
#include <string.h>

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

/* Quantize one PCM predictor difference into the MPQ ADPCM control byte.
 * The predictor and step index are updated in place so the next sample uses
 * the same adaptive state as the matching decoder. */
static uint8_t
wave_encode_delta(int32_t difference, int32_t *predictor, int32_t *step_index, uint32_t shift)
{
    uint32_t step = wave_step_sizes[*step_index];
    uint32_t magnitude = (difference < 0) ? (uint32_t)-difference : (uint32_t)difference;
    uint32_t code = difference < 0 ? 0x40u : 0;
    uint32_t bit;
    int32_t delta = (int32_t)(step >> shift);
    for (bit = 0; bit < 6; bit++) {
        uint32_t contribution = step >> bit;
        if (magnitude >= (uint32_t)(delta + (int32_t)contribution)) {
            code |= 1u << bit;
            delta += (int32_t)contribution;
        }
    }
    if (difference < 0)
        *predictor -= delta;
    else
        *predictor += delta;
    if (*predictor > 32767)
        *predictor = 32767;
    if (*predictor < -32768)
        *predictor = -32768;
    *step_index += (int32_t)wave_step_adjustments[code & 0x1f];
    if (*step_index < 0)
        *step_index = 0;
    if (*step_index > 0x58)
        *step_index = 0x58;
    return (uint8_t)code;
}

/* Inspect a RIFF/WAVE prefix and validate its PCM16 channel configuration.
 * Chunk boundaries, padding, channel count, sample width, and complete PCM
 * frames are checked before offsets and sizes are returned to the caller. */
int32_t
libmpq__wave_probe_pcm16(const uint8_t *data, uint32_t size, libmpq_wave_info_s *info)
{
    uint32_t pos = 12;
    uint32_t end;
    uint16_t channels = 0;
    uint16_t format = 0;
    uint16_t bits = 0;
    uint32_t data_offset = 0;
    uint32_t data_size = 0;
    if (data == NULL || info == NULL || size < 12 || memcmp(data, "RIFF", 4) != 0 ||
        memcmp(data + 8, "WAVE", 4) != 0)
        return LIBMPQ_ERROR_FORMAT;
    end = size;

    /* Walk RIFF chunks while honoring the required even-byte chunk padding. */
    while (pos + 8 <= end) {
        uint32_t chunk_size = libmpq__load_le32(data + pos + 4);
        uint32_t next = pos + 8 + chunk_size + (chunk_size & 1u);
        if (next < pos || next > end)
            return LIBMPQ_ERROR_FORMAT;
        if (memcmp(data + pos, "fmt ", 4) == 0 && chunk_size >= 16) {
            format = libmpq__load_le16(data + pos + 8);
            channels = libmpq__load_le16(data + pos + 10);
            bits = libmpq__load_le16(data + pos + 22);
        } else if (memcmp(data + pos, "data", 4) == 0) {
            data_offset = pos + 8;
            data_size = chunk_size;
        }
        pos = next;
    }
    if (format != 1 || (channels != 1 && channels != 2) || bits != 16 || data_offset == 0 ||
        data_offset > size || (data_size % (channels * 2)) != 0)
        return LIBMPQ_ERROR_FORMAT;
    info->channels = channels;
    info->data_offset = data_offset;
    info->data_size = data_size;
    return 0;
}

/* Validate a RIFF/WAVE prefix when later PCM bytes are not buffered yet.
 * The available prefix must contain the format and data chunk headers, while
 * the declared data range must fit within the complete writer file size. */
int32_t
libmpq__wave_probe_pcm16_prefix(
    const uint8_t *data, uint32_t prefix_size, uint64_t file_size, libmpq_wave_info_s *info
)
{
    uint32_t pos = 12;
    uint16_t channels = 0;
    uint16_t format = 0;
    uint16_t bits = 0;
    uint32_t data_offset = 0;
    uint32_t data_size = 0;

    if (data == NULL || info == NULL || prefix_size < 12 || file_size < prefix_size ||
        memcmp(data, "RIFF", 4) != 0 || memcmp(data + 8, "WAVE", 4) != 0)
        return LIBMPQ_ERROR_FORMAT;
    while (pos + 8 <= prefix_size) {
        uint32_t chunk_size = libmpq__load_le32(data + pos + 4);
        uint64_t next = (uint64_t)pos + 8 + chunk_size + (chunk_size & 1u);
        if (next < pos || next > file_size)
            return LIBMPQ_ERROR_FORMAT;
        if (memcmp(data + pos, "fmt ", 4) == 0 && chunk_size >= 16) {
            if ((uint64_t)pos + 24 > prefix_size)
                return LIBMPQ_ERROR_FORMAT;
            format = libmpq__load_le16(data + pos + 8);
            channels = libmpq__load_le16(data + pos + 10);
            bits = libmpq__load_le16(data + pos + 22);
        } else if (memcmp(data + pos, "data", 4) == 0) {
            data_offset = pos + 8;
            data_size = chunk_size;
            if ((uint64_t)data_offset + data_size > file_size)
                return LIBMPQ_ERROR_FORMAT;
            break;
        }
        if (next > prefix_size)
            break;
        pos = (uint32_t)next;
    }
    if (format != 1 || (channels != 1 && channels != 2) || bits != 16 || data_offset == 0 ||
        data_offset > prefix_size || (data_size % (channels * 2)) != 0)
        return LIBMPQ_ERROR_FORMAT;
    info->channels = channels;
    info->data_offset = data_offset;
    info->data_size = data_size;
    return 0;
}

/* Encode one complete PCM sector using the MPQ mono/stereo ADPCM format.
 * The first sample of each channel seeds the predictor header, and subsequent
 * interleaved samples are reduced to adaptive six-bit delta codes. */
int32_t
libmpq__wave_compress(
    const uint8_t *in_buf, uint32_t in_size, uint8_t **out_buf, uint32_t *out_size,
    uint32_t channels
)
{
    uint32_t samples;
    uint32_t i;
    uint32_t shift = 4;
    uint32_t pos;

    int32_t predictor[2] = { 0, 0 };
    int32_t index[2] = { 0x2c, 0x2c };

    uint8_t *out;
    if (out_buf == NULL || out_size == NULL || in_buf == NULL || (channels != 1 && channels != 2) ||
        in_size < channels * 2 || (in_size % (channels * 2)) != 0)
        return LIBMPQ_ERROR_FORMAT;
    samples = in_size / (channels * 2);
    out = malloc(2 + channels * 2 + samples * channels);
    if (out == NULL)
        return LIBMPQ_ERROR_MALLOC;
    libmpq__store_le16(out, 0);
    out[1] = (uint8_t)shift;
    pos = 2;

    /* Store one initial predictor sample per channel in the compressed header. */
    for (i = 0; i < channels; i++) {
        predictor[i] = (int16_t)libmpq__load_le16(in_buf + i * 2);
        libmpq__store_le16(out + pos, (uint16_t)predictor[i]);
        pos += 2;
    }

    /* Encode the remaining interleaved frames using shared channel state. */
    for (i = 1; i < samples; i++) {
        uint32_t channel;
        for (channel = 0; channel < channels; channel++) {
            int32_t sample = (int16_t)libmpq__load_le16(in_buf + (i * channels + channel) * 2);
            out[pos++] = wave_encode_delta(
                sample - predictor[channel], &predictor[channel], &index[channel], shift
            );
        }
    }
    *out_buf = out;
    *out_size = pos;
    return 0;
}

/* Decompress mono or stereo MPQ WAVE predictor data into PCM bytes.
 * It restores channel seed samples first, then applies control and delta
 * bytes until the input or caller-provided output capacity is exhausted. */
int32_t
libmpq__wave_decompress(
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

    /* Emit the initial seed sample for each channel before delta decoding. */
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

    /* Decode interleaved control bytes until input or output capacity is exhausted. */
    while (in_buf < in_end) {
        uint8_t one_byte = *in_buf++;

        if (channels == 2) {
            index = (index == 0) ? 1 : 0;
        }

        /* High-bit control bytes adjust predictor index and do not emit samples. */
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

            /* Low-bit values update the active channel predictor and emit PCM. */

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
