/* Exercise RIFF/WAVE-shaped payload handling and boundary payloads. */
#include "../src/mpq-wave.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Store a little-endian 16-bit value in a generated RIFF/WAVE header. */
static void
put_le16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
}

/* Store a little-endian 32-bit value in a generated RIFF/WAVE header. */
static void
put_le32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

/* Generate a bounded triangular PCM waveform suitable for quality checks. */
static void
make_pcm(uint8_t *pcm, size_t samples, uint16_t channels)
{
    size_t i;
    uint16_t channel;
    for (i = 0; i < samples; ++i) {
        uint32_t phase = (uint32_t)((i * 17u) % 4096u);
        int32_t base = phase < 2048 ? (int32_t)phase - 1024 : 3072 - (int32_t)phase;
        for (channel = 0; channel < channels; ++channel) {
            int32_t sample = base * 24 + (channel ? 1800 : 0);
            put_le16(pcm + (i * channels + channel) * 2, (uint16_t)sample);
        }
    }
}

/* Construct a valid PCM16 RIFF/WAVE payload around deterministic samples. */
static uint8_t *
make_wave(size_t samples, uint16_t channels, size_t *size)
{
    static const uint8_t riff_wave_fmt[] = { 'W', 'A', 'V', 'E', 'f', 'm', 't', ' ' };
    static const uint8_t data_tag[] = { 'd', 'a', 't', 'a' };
    uint8_t *wave;
    size_t pcm_size = samples * channels * 2;
    *size = 44 + pcm_size;
    wave = calloc(1, *size);
    if (wave == NULL)
        return NULL;
    memcpy(wave, "RIFF", 4);
    put_le32(wave + 4, (uint32_t)(*size - 8));
    memcpy(wave + 8, riff_wave_fmt, sizeof(riff_wave_fmt));
    put_le32(wave + 16, 16);
    put_le16(wave + 20, 1);
    put_le16(wave + 22, channels);
    put_le32(wave + 24, 22050);
    put_le32(wave + 28, 22050 * channels * 2);
    put_le16(wave + 32, (uint16_t)(channels * 2));
    put_le16(wave + 34, 16);
    memcpy(wave + 36, data_tag, sizeof(data_tag));
    put_le32(wave + 40, (uint32_t)pcm_size);
    make_pcm(wave + 44, samples, channels);
    return wave;
}

/* Exercise direct mono/stereo ADPCM encoding, decoding, determinism, and quality. */
static int
test_adpcm_codec(uint16_t channels)
{
    const size_t samples = 257;
    size_t pcm_size = samples * channels * 2;
    uint8_t *pcm = malloc(pcm_size);
    uint8_t *encoded = NULL;
    uint8_t *encoded_again = NULL;
    uint8_t *decoded = calloc(1, pcm_size);
    uint32_t encoded_size = 0;
    uint32_t encoded_again_size = 0;
    int32_t decoded_size;
    uint64_t absolute_error = 0;
    int32_t maximum_error = 0;
    size_t i;

    if (pcm == NULL || decoded == NULL) {
        test_failure(__FILE__, __LINE__, "pcm != NULL && decoded != NULL");
        free(decoded);
        free(pcm);
        return 1;
    }
    make_pcm(pcm, samples, channels);
    if (libmpq__wave_compress(pcm, (uint32_t)pcm_size, &encoded, &encoded_size, channels) != 0)
        goto failure;
    if (libmpq__wave_compress(
            pcm, (uint32_t)pcm_size, &encoded_again, &encoded_again_size, channels
        ) != 0)
        goto failure;
    if (encoded_size != encoded_again_size || memcmp(encoded, encoded_again, encoded_size) != 0)
        goto failure;
    if (encoded_size >= pcm_size)
        goto failure;
    decoded_size = libmpq__wave_decompress(
        decoded, (int32_t)pcm_size, encoded, (int32_t)encoded_size, channels
    );
    if (decoded_size != (int32_t)pcm_size)
        goto failure;
    for (i = 0; i < pcm_size / 2; ++i) {
        int32_t original = (int16_t)(pcm[i * 2] | ((uint16_t)pcm[i * 2 + 1] << 8));
        int32_t result = (int16_t)(decoded[i * 2] | ((uint16_t)decoded[i * 2 + 1] << 8));
        int32_t error = original - result;
        if (error < 0)
            error = -error;
        absolute_error += (uint32_t)error;
        if (error > maximum_error)
            maximum_error = error;
    }
    if (absolute_error / (pcm_size / 2) >= 6000 || maximum_error >= 16000)
        goto failure;
    free(decoded);
    free(encoded_again);
    free(encoded);
    free(pcm);
    return 0;

failure:
    test_failure(__FILE__, __LINE__, "ADPCM round trip");
    free(decoded);
    free(encoded_again);
    free(encoded);
    free(pcm);
    return 1;
}

/* Prove that archive sectors after the lossless WAVE header use ADPCM. */
static int
test_adpcm_archive(void)
{
    char path[128];
    uint8_t *wave;
    uint8_t *output = NULL;
    size_t wave_size;
    size_t output_size;
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, 0,
                                   LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_HUFFMAN, 0,
                                   0 };
    uint32_t number;
    uint32_t blocks;
    uint32_t compressed;
    libmpq__off_t packed;
    libmpq__off_t unpacked;
    size_t i;
    uint64_t absolute_error = 0;
    size_t compared = 0;

    TEST_CHECK(test_temp_path(path, sizeof(path), "wave-adpcm") == 0);
    wave = make_wave(7000, 1, &wave_size);
    TEST_CHECK(wave != NULL);
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "tone.wav", wave, wave_size, &options) == 0);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    archive = NULL;
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "tone.wav", &number) == 0);
    TEST_CHECK(libmpq__file_compressed(archive, number, &compressed) == 0 && compressed != 0);
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 4);
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0);
    TEST_CHECK(packed < unpacked);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == wave_size);
    TEST_CHECK(memcmp(output, wave, 4096) == 0);
    for (i = 4096; i < wave_size; i += 2) {
        int32_t original = (int16_t)(wave[i] | ((uint16_t)wave[i + 1] << 8));
        int32_t result = (int16_t)(output[i] | ((uint16_t)output[i + 1] << 8));
        int32_t error = original - result;
        if (error < 0)
            error = -error;
        absolute_error += (uint32_t)error;
        compared++;
    }
    TEST_CHECK(compared != 0 && absolute_error / compared < 6000);
    free(output);
    free(wave);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    return 0;
}

/* Reject a lossy request when the declared WAVE data exceeds the file. */
static int
test_adpcm_rejects_invalid_wave(void)
{
    char path[128];
    uint8_t *wave;
    size_t wave_size;
    mpq_archive_s *archive = NULL;
    mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, 0, LIBMPQ_COMPRESSION_WAVE_MONO, 0,
                                   0 };

    TEST_CHECK(test_temp_path(path, sizeof(path), "wave-invalid") == 0);
    wave = make_wave(7000, 1, &wave_size);
    TEST_CHECK(wave != NULL);
    put_le32(wave + 40, 20000);
    TEST_CHECK(test_add_archive(&archive, path, LIBMPQ_ARCHIVE_VERSION_ONE, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(archive, "invalid.wav", wave, wave_size, &options) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(wave);
    remove(path);
    return 0;
}

/* Store and extract empty, sector-boundary, XML, WAVE, and nested payloads. */
int
main(void)
{
    static const uint8_t riff_tag[] = { 'R', 'I', 'F', 'F' };
    static const uint8_t riff_wave_fmt[] = { 'W', 'A', 'V', 'E', 'f', 'm', 't', ' ' };
    static const uint8_t data_tag[] = { 'd', 'a', 't', 'a' };
    char path[128];
    char inner_path[128];
    char extracted_path[128];
    uint8_t exact[4096];
    uint8_t partial[4097];
    uint8_t wave[44 + 16];
    uint8_t *inner;
    uint8_t *output;
    size_t inner_size;
    size_t output_size;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *inner_archive = NULL;
    mpq_file_options_s raw = { 0, 0, 0, 0, 0 };
    uint32_t number;

    TEST_CHECK(test_temp_path(path, sizeof(path), "wave") == 0);
    TEST_CHECK(test_adpcm_codec(1) == 0);
    TEST_CHECK(test_adpcm_codec(2) == 0);
    TEST_CHECK(test_adpcm_archive() == 0);
    TEST_CHECK(test_adpcm_rejects_invalid_wave() == 0);
    TEST_CHECK(test_temp_path(inner_path, sizeof(inner_path), "wave-inner") == 0);
    TEST_CHECK(test_temp_path(extracted_path, sizeof(extracted_path), "wave-extracted") == 0);
    test_payload(exact, sizeof(exact), 7);
    test_payload(partial, sizeof(partial), 8);
    memset(wave, 0, sizeof(wave));
    memcpy(wave, riff_tag, sizeof(riff_tag));
    memcpy(wave + 8, riff_wave_fmt, sizeof(riff_wave_fmt));
    wave[16] = 16;
    wave[20] = 1;
    wave[22] = 1;
    wave[24] = 0x44;
    wave[25] = 0xac;
    wave[32] = 2;
    wave[34] = 16;
    memcpy(wave + 36, data_tag, sizeof(data_tag));
    wave[40] = 16;
    TEST_CHECK(test_add_archive(&inner_archive, inner_path, 0, 0) == 0);
    TEST_CHECK(
        libmpq__file_add(inner_archive, "inner.txt", (const uint8_t *)"nested", 6, &raw) == 0
    );
    TEST_CHECK(libmpq__archive_close(inner_archive) == 0);
    TEST_CHECK(test_read_path(inner_path, &inner, &inner_size) == 0);
    TEST_CHECK(test_add_archive(&archive, path, 0, 0) == 0);
    TEST_CHECK(libmpq__file_add(archive, "empty", NULL, 0, &raw) == 0);
    TEST_CHECK(libmpq__file_add(archive, "exact", exact, sizeof(exact), &raw) == 0);
    TEST_CHECK(libmpq__file_add(archive, "partial", partial, sizeof(partial), &raw) == 0);
    TEST_CHECK(
        libmpq__file_add(
            archive, "xml", (const uint8_t *)"<?xml version=\"1.0\"?><x/>",
            strlen("<?xml version=\"1.0\"?><x/>"), &raw
        ) == 0
    );
    TEST_CHECK(libmpq__file_add(archive, "wave", wave, sizeof(wave), &raw) == 0);
    TEST_CHECK(libmpq__file_add(archive, "nested.mpq", inner, inner_size, &raw) == 0);
    free(inner);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__file_number(archive, "wave", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &output, &output_size) == 0);
    TEST_CHECK(output_size == sizeof(wave) && memcmp(output, "RIFF", 4) == 0);
    free(output);
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    remove(path);
    remove(inner_path);
    remove(extracted_path);
    return 0;
}
