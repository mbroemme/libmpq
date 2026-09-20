/*
 *  test-mpq-signature.c -- weak signature regression tests.
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
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "mpq-rsa.h"
#include "mpq-signature.h"
#include "mpq-stream.h"
#include "test-mpq-helper.h"
#include <stdlib.h>
#include <string.h>

/* Independently calculated MD5 DigestInfo and RSA result for the libmpq
 * weak-signature known answer. */
static const uint8_t test_digest[16] = {
    0xaa, 0xaf, 0x4f, 0x2e, 0x9f, 0x11, 0xa5, 0xf0, 0x62, 0xad, 0x92, 0x01, 0x8b, 0xe1, 0x24, 0x95,
};
static const uint8_t test_encoded[64] = {
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x30, 0x20,
    0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10,
    0xaa, 0xaf, 0x4f, 0x2e, 0x9f, 0x11, 0xa5, 0xf0, 0x62, 0xad, 0x92, 0x01, 0x8b, 0xe1, 0x24, 0x95,
};
static const uint8_t test_signature[64] = {
    0x18, 0xb1, 0x47, 0x35, 0xc9, 0x3b, 0x03, 0x32, 0xf5, 0x4f, 0x84, 0xa4, 0x85, 0x93, 0xee, 0xf3,
    0x75, 0x48, 0x4e, 0x81, 0x29, 0x9b, 0x45, 0x9b, 0xc0, 0x2c, 0x3d, 0x55, 0xf4, 0x89, 0xfa, 0x1b,
    0xfb, 0x0b, 0x99, 0x90, 0x63, 0xc7, 0x97, 0xf5, 0x0e, 0x9f, 0x6c, 0xcf, 0x6e, 0xd4, 0xcf, 0xc0,
    0x60, 0xbd, 0x89, 0xdf, 0x8e, 0x9a, 0x3a, 0x72, 0x24, 0x9b, 0x09, 0xc4, 0x78, 0xba, 0xc1, 0x4c,
};

static int
write_bytes(const char *path, const uint8_t *data, size_t size, size_t prefix)
{
    FILE *file = libmpq__file_open(path, "wb");
    size_t i;
    TEST_CHECK(file != NULL);
    for (i = 0; i < prefix; ++i)
        TEST_CHECK(fputc(0, file) != EOF);
    TEST_CHECK(fwrite(data, 1, size, file) == size);
    TEST_CHECK(fclose(file) == 0);
    return 0;
}

static int
check_archive(const char *path, libmpq__off_t offset, uint32_t expected)
{
    mpq_archive_s *a = NULL;
    uint32_t signatures = 99;
    uint32_t mismatches = 99;
    TEST_CHECK(libmpq__archive_open(&a, path, offset) == 0);
    TEST_CHECK(libmpq__archive_signatures(a, &signatures) == 0);
    TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(
        libmpq__archive_verify(a, signatures, test_signature_public_key, 128, &mismatches) == 0
    );
    TEST_CHECK(mismatches == expected);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    return 0;
}

/* Re-sign a deliberately padded v1 archive. This follows the on-disk weak
 * signature representation so the reader is exercised against a genuine
 * archive rather than an in-memory metadata shortcut. */
static int
sign_padded_v1_archive(uint8_t *data, size_t size, uint64_t signature_offset)
{
    mpq_md5_s context;
    uint8_t digest[LIBMPQ_MD5_SIZE];
    uint8_t encoded[LIBMPQ_RSA_SIZE];
    uint8_t signature[LIBMPQ_RSA_SIZE];
    size_t i;
    if (data == NULL || size > UINT32_MAX || signature_offset > size ||
        size - signature_offset < LIBMPQ_SIGNATURE_SIZE)
        return -1;
    libmpq__store_le32(data + 8, (uint32_t)size);
    memset(data + signature_offset, 0, LIBMPQ_SIGNATURE_SIZE);
    libmpq__md5_init(&context);
    libmpq__md5_update(&context, data, size);
    libmpq__md5_final(&context, digest);
    libmpq__rsa_md5_encode(digest, encoded);
    if (libmpq__rsa_operation(test_signature_private_key, encoded, signature) != LIBMPQ_SUCCESS)
        return -1;
    for (i = 0; i < LIBMPQ_RSA_SIZE; ++i)
        data[signature_offset + LIBMPQ_SIGNATURE_PREFIX_SIZE + i] =
            signature[LIBMPQ_RSA_SIZE - 1 - i];
    return 0;
}

static int32_t
failed_read(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    (void)stream;
    (void)offset;
    (void)buffer;
    (void)size;
    return LIBMPQ_ERROR_READ;
}

/* A virtual high-offset signature avoids allocating or hashing gigabytes.
 * Record the first digest read and fail it deliberately after successful
 * signature location. This tests the verifier's extent handoff as well. */
static int32_t
high_read(mpq_stream_s *stream, uint64_t offset, uint8_t *buffer, size_t size)
{
    if (offset == (UINT64_C(1) << 32) + 64 && size == 72) {
        memset(buffer, 0, size);
        return 0;
    }
    *(size_t *)stream->read_context = size;
    return LIBMPQ_ERROR_READ;
}

static int
test_logical_extent(void)
{
    mpq_archive_s archive = { 0 };
    mpq_block_s block = { 0 };
    mpq_block_ex_s high = { 0 };
    mpq_hash_s hash = { 0 };
    mpq_stream_s stream = { 0 };
    uint64_t extent = 99;
    uint32_t unused;
    uint32_t signatures;
    uint32_t mismatches;
    size_t digest_read = 0;
    archive.mpq_header.version = LIBMPQ_ARCHIVE_VERSION_TWO;
    archive.mpq_header.header_size = 44;
    archive.mpq_header.archive_size = 136;
    archive.mpq_header.hash_table_offset = 44;
    archive.mpq_header.hash_table_count = 1;
    archive.mpq_header.block_table_offset = 136;
    archive.mpq_header.block_table_count = 1;
    archive.mpq_header_ex.extended_offset = 152;
    archive.mpq_hash = &hash;
    archive.mpq_block = &block;
    archive.mpq_block_ex = &high;
    archive.file_size = UINT64_MAX;
    archive.stream = &stream;
    stream.size = UINT64_MAX;
    stream.read_at = high_read;
    stream.read_context = &digest_read;
    libmpq__file_hash("(signature)", &unused, &hash.hash_a, &hash.hash_b);
    block.offset = 64;
    block.packed_size = block.unpacked_size = 72;
    block.flags = LIBMPQ_FLAG_EXISTS;
    high.offset_high = 1;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(1) << 32) + 136);
    TEST_CHECK(libmpq__archive_signatures(&archive, &signatures) == 0);
    TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(
        libmpq__archive_verify(
            &archive, signatures, test_signature_public_key, sizeof(test_signature_public_key),
            &mismatches
        ) == LIBMPQ_ERROR_READ
    );
    TEST_CHECK(digest_read == 16384 && mismatches == 0);

    archive.mpq_header_ex.hash_table_offset_high = 2;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(2) << 32) + 60);
    archive.mpq_header_ex.block_table_offset_high = 3;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(3) << 32) + 152);
    archive.mpq_header_ex.extended_offset = (UINT64_C(4) << 32);
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == (UINT64_C(4) << 32) + 2);
    archive.mpq_header_ex.extended_offset = UINT64_MAX - 1;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(extent == 0);
    TEST_CHECK(libmpq__archive_signatures(&archive, &signatures) == LIBMPQ_ERROR_FORMAT);
    archive.mpq_header_ex.extended_offset = UINT64_MAX - 2;
    archive.archive_offset = 1;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == LIBMPQ_ERROR_FORMAT);
    archive.archive_offset = 0;
    archive.file_size = 136;
    TEST_CHECK(libmpq__archive_signature_extent(&archive, &extent) == LIBMPQ_ERROR_FORMAT);
    archive.archive_offset = 0;
    archive.file_size = UINT64_MAX;
    archive.mpq_header_ex.hash_table_offset_high = 0;
    archive.mpq_header_ex.block_table_offset_high = 0;
    archive.mpq_header_ex.extended_offset = 0;
    block.offset = UINT32_MAX;
    block.packed_size = 0;
    block.unpacked_size = 0;
    high.offset_high = UINT16_MAX;
    TEST_CHECK(libmpq__archive_required_extent(&archive, &extent) == 0);
    TEST_CHECK(extent == 152);
    return 0;
}

int
main(void)
{
    mpq_archive_s *a = NULL;
    mpq_archive_create_options_s options = { LIBMPQ_ARCHIVE_VERSION_ONE, 8, 4096,
                                             LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s raw_options = { 0, 0, 0, 0, 0 };
    mpq_file_attributes_s attributes;
    uint8_t output[64];
    uint8_t encoded[64];
    uint8_t invalid_key[128];
    uint8_t payload[17000];
    uint8_t *archive_data;
    uint8_t *padded_data;
    size_t archive_size;
    size_t padded_size;
    size_t payload_size;
    uint32_t number;
    uint32_t index;
    uint32_t mismatch = 99;
    uint32_t types = 99;
    uint32_t flags;
    uint32_t saved_offset;
    uint32_t i;
    uint64_t signature_offset;
    uint64_t required_extent;
    uint64_t signature_extent;
    char path[512];
    char changed[512];

    TEST_CHECK(test_logical_extent() == 0);
    libmpq__rsa_md5_encode(test_digest, encoded);
    TEST_CHECK(memcmp(encoded, test_encoded, 64) == 0);
    TEST_CHECK(libmpq__rsa_key_validate(test_signature_private_key, 128) == 0);
    TEST_CHECK(libmpq__rsa_key_validate(test_signature_public_key, 128) == 0);
    TEST_CHECK(libmpq__rsa_operation(test_signature_private_key, encoded, output) == 0);
    TEST_CHECK(memcmp(output, test_signature, 64) == 0);
    TEST_CHECK(libmpq__rsa_operation(test_signature_public_key, output, encoded) == 0);
    TEST_CHECK(memcmp(encoded, test_encoded, 64) == 0);
    TEST_CHECK(libmpq__rsa_key_validate(NULL, 128) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__rsa_key_validate(test_signature_public_key, 127) == LIBMPQ_ERROR_FORMAT);
    memcpy(invalid_key, test_signature_public_key, 128);
    invalid_key[63] &= 0xfe;
    TEST_CHECK(libmpq__rsa_key_validate(invalid_key, 128) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_signatures(NULL, &types) == LIBMPQ_ERROR_EXIST && types == 0);
    TEST_CHECK(
        libmpq__archive_verify(NULL, 1, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_EXIST &&
        mismatch == 0
    );

    TEST_CHECK(test_temp_path(path, sizeof(path), "signature") == 0);
    TEST_CHECK(test_temp_path(changed, sizeof(changed), "signature-changed") == 0);
    memset(payload, 0x5a, sizeof(payload));
    TEST_CHECK(libmpq__archive_create(&a, path, &options) == 0);
    payload_size = 16384 - 24 - (size_t)libmpq__file_tell(a->fp);
    TEST_CHECK(libmpq__archive_sign(a, 2, test_signature_private_key, 128) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_add_data(a, "payload", payload, payload_size, &raw_options) == 0);
    TEST_CHECK(libmpq__archive_sign(a, 1, test_signature_private_key, 128) == 0);
    TEST_CHECK(libmpq__archive_sign(a, 1, test_signature_private_key, 128) == LIBMPQ_ERROR_FORMAT);
    signature_offset = a->write_signature_offset;
    TEST_CHECK(signature_offset / 16384 != (signature_offset + 71) / 16384);
    TEST_CHECK(libmpq__archive_add_data(a, "after", payload, 20, &raw_options) == 0);
    TEST_CHECK(
        libmpq__archive_add_data(a, "(SIGNATURE)", payload, 72, &raw_options) == LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(check_archive(path, 0, 0) == 0);

    TEST_CHECK(libmpq__archive_open(&a, path, 0) == 0);
    memcpy(invalid_key, test_signature_public_key, sizeof(invalid_key));
    invalid_key[127] = 3;
    TEST_CHECK(libmpq__archive_verify(a, 1, invalid_key, sizeof(invalid_key), &mismatch) == 0);
    TEST_CHECK(mismatch == LIBMPQ_SIGNATURE_WEAK);
    TEST_CHECK(libmpq__file_number(a, "(signature)", &number) == 0);
    TEST_CHECK(libmpq__file_attributes(a, number, &attributes) == 0);
    TEST_CHECK(attributes.crc32 == 0);
    for (i = 0; i < 16; ++i)
        TEST_CHECK(attributes.md5[i] == 0);
    TEST_CHECK(libmpq__file_number(a, "(listfile)", &index) == 0);
    TEST_CHECK(
        libmpq__archive_verify(a, 0, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_FORMAT &&
        mismatch == 0
    );
    TEST_CHECK(
        libmpq__archive_verify(a, 1, NULL, 128, &mismatch) == LIBMPQ_ERROR_FORMAT && mismatch == 0
    );
    index = a->mpq_map[number].block_table_indices;
    for (i = 71; i <= 73; i += 2) {
        a->mpq_block[index].unpacked_size = i;
        TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    }
    a->mpq_block[index].unpacked_size = 72;
    flags = a->mpq_block[index].flags;
    TEST_CHECK(flags == LIBMPQ_FLAG_EXISTS);
    a->mpq_block[index].flags |= LIBMPQ_FLAG_SINGLE;
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) == 0 &&
        mismatch == 0
    );
    for (i = 0; i < 3; ++i) {
        static const uint32_t invalid_flags[] = { LIBMPQ_FLAG_COMPRESS_MULTI, LIBMPQ_FLAG_ENCRYPTED,
                                                  LIBMPQ_FLAG_CRC };
        a->mpq_block[index].flags = flags | invalid_flags[i];
        TEST_CHECK(
            libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) ==
                LIBMPQ_ERROR_FORMAT &&
            mismatch == 0
        );
    }
    a->mpq_block[index].flags = flags;
    a->mpq_block[index].packed_size = 71;
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT);
    a->mpq_block[index].packed_size = 72;
    saved_offset = a->mpq_header.hash_table_offset;
    a->mpq_header.hash_table_offset = a->mpq_header.archive_size;
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    a->mpq_header.hash_table_offset = saved_offset;
    saved_offset = a->mpq_block[0].offset;
    a->mpq_block[0].offset = a->mpq_header.archive_size;
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    a->mpq_block[0].offset = saved_offset;
    a->stream->read_at = failed_read;
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_READ &&
        mismatch == 0
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);

    TEST_CHECK(test_read_path(path, &archive_data, &archive_size) == 0);
    padded_size = archive_size + 16;
    padded_data = malloc(padded_size);
    TEST_CHECK(padded_data != NULL);
    memcpy(padded_data, archive_data, archive_size);
    memset(padded_data + archive_size, 0xa5, padded_size - archive_size);
    TEST_CHECK(sign_padded_v1_archive(padded_data, padded_size, signature_offset) == 0);
    TEST_CHECK(write_bytes(changed, padded_data, padded_size, 0) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    TEST_CHECK(libmpq__archive_required_extent(a, &required_extent) == 0);
    TEST_CHECK(required_extent < padded_size);
    TEST_CHECK(libmpq__archive_signature_extent(a, &signature_extent) == 0);
    TEST_CHECK(signature_extent == padded_size);
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) == 0 &&
        mismatch == 0
    );
    a->mpq_header.archive_size = (uint32_t)(required_extent - 1);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    a->mpq_header.archive_size = (uint32_t)(padded_size + 1);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    free(padded_data);
    TEST_CHECK(write_bytes(changed, archive_data, archive_size, 512) == 0);
    {
        FILE *file = libmpq__file_open(changed, "ab");
        TEST_CHECK(file != NULL);
        TEST_CHECK(fputs("unrelated trailing data", file) >= 0);
        TEST_CHECK(fclose(file) == 0);
    }
    TEST_CHECK(check_archive(changed, 512, 0) == 0);
    archive_data[signature_offset - 1] ^= 1;
    TEST_CHECK(write_bytes(changed, archive_data, archive_size, 0) == 0);
    TEST_CHECK(check_archive(changed, 0, 1) == 0);
    archive_data[signature_offset - 1] ^= 1;
    archive_data[signature_offset + 8] ^= 1;
    TEST_CHECK(write_bytes(changed, archive_data, archive_size, 0) == 0);
    TEST_CHECK(check_archive(changed, 0, 1) == 0);
    free(archive_data);

    options.version = LIBMPQ_ARCHIVE_VERSION_TWO;
    options.attributes = 0;
    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_sign(a, 1, test_signature_private_key, 128) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(check_archive(changed, 0, 0) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    a->mpq_header.archive_size = 1;
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) == 0 &&
        mismatch == 0
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);
    {
        static const uint8_t auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
        TEST_CHECK(libmpq__archive_create_mpqe(&a, changed, auth, sizeof(auth) - 1, &options) == 0);
        TEST_CHECK(
            libmpq__archive_sign(
                a, 1, test_signature_private_key, sizeof(test_signature_private_key)
            ) == 0
        );
        TEST_CHECK(libmpq__archive_add_data(a, "payload", payload, 72, &raw_options) == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
        TEST_CHECK(libmpq__archive_open_mpqe(&a, changed, 0, auth, sizeof(auth) - 1) == 0);
        TEST_CHECK(libmpq__archive_signatures(a, &types) == 0 && types == LIBMPQ_SIGNATURE_WEAK);
        TEST_CHECK(
            libmpq__archive_verify(
                a, types, test_signature_public_key, sizeof(test_signature_public_key), &mismatch
            ) == 0
        );
        TEST_CHECK(mismatch == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
    }
    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(a, "(signature)", payload, 72, &raw_options) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT);
    TEST_CHECK(libmpq__archive_close(a) == 0);

    memset(payload, 0, 72);
    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_add_data(a, "(signature)", payload, 72, &raw_options) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(check_archive(changed, 0, 1) == 0);

    /* Persist malformed payload lengths through the ordinary writer, rather
     * than relying only on the defensive in-memory metadata checks above. */
    for (i = 71; i <= 73; i += 2) {
        TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
        TEST_CHECK(libmpq__archive_add_data(a, "(signature)", payload, i, &raw_options) == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
        TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
        TEST_CHECK(libmpq__archive_signatures(a, &types) == LIBMPQ_ERROR_FORMAT && types == 0);
        TEST_CHECK(libmpq__archive_close(a) == 0);
    }

    TEST_CHECK(libmpq__archive_create(&a, changed, &options) == 0);
    TEST_CHECK(libmpq__archive_close(a) == 0);
    TEST_CHECK(libmpq__archive_open(&a, changed, 0) == 0);
    TEST_CHECK(libmpq__archive_signatures(a, &types) == 0 && types == 0);
    TEST_CHECK(
        libmpq__archive_verify(a, 1, test_signature_public_key, 128, &mismatch) ==
            LIBMPQ_ERROR_EXIST &&
        mismatch == 0
    );
    TEST_CHECK(libmpq__archive_close(a) == 0);
    remove(path);
    remove(changed);
    return 0;
}
