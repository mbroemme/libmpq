/*
 *  test-mpq-verify.c -- explicit sector and file checksum regressions.
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

#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "mpq-stream.h"
#include "test-mpq-helper.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            test_failure(__FILE__, __LINE__, #condition);                                          \
            result = 1;                                                                            \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

/* Each test archive borrows its own mock context; no process-global test mode. */
typedef struct
{
    mpq_stream_read_at_fn read_at;
    uint64_t offset;
    unsigned reads;
} read_failure_s;

static int32_t
fail_read(mpq_stream_s *stream, uint64_t offset, uint8_t *data, size_t size)
{
    read_failure_s *failure = stream->read_context;
    if (offset == failure->offset) {
        ++failure->reads;
        return LIBMPQ_ERROR_READ;
    }
    return failure->read_at(stream, offset, data, size);
}

/* Corrupt a byte in a selected raw-fallback sector, leaving table metadata intact. */
static int32_t
corrupt_read(mpq_stream_s *stream, uint64_t offset, uint8_t *data, size_t size)
{
    read_failure_s *failure = stream->read_context;
    int32_t status = failure->read_at(stream, offset, data, size);
    if (status == 0 && offset == failure->offset && size != 0) {
        data[size - 1] ^= 1;
        ++failure->reads;
    }
    return status;
}

/* Construct only the checksum-bearing file payload here. The normal writer
 * supplies archive tables and attributes. Checksums cover pre-encryption bytes,
 * including a deliberately raw final sector. The checksum table is never encrypted. */
static int
test_sectors(
    uint32_t version, int encrypted, int compressed_table, uint32_t corrupt, int attributes,
    int absent
)
{
    enum
    {
        sectors = 17,
        sector_size = 512,
        tail = 37
    };
    mpq_archive_create_options_s options = {
        version, 3, sector_size, 0, attributes ? LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 : 0
    };
    mpq_archive_s *archive = NULL;
    mpq_md5_s md5;
    uint8_t plain[(sectors - 1) * sector_size + tail];
    uint8_t output[sizeof(plain)];
    uint8_t packed[sizeof(plain) + 256];
    uint8_t checksums[sectors * 4];
    uint8_t encoded[sectors * 4 + 64];
    uint32_t offsets[sectors + 2];
    uint32_t key = libmpq__crypto_hash_string("payload", 0x300);
    uint32_t number;
    uint32_t index;
    uint32_t request;
    uint32_t bits;
    uint32_t expected;
    uint32_t position = sizeof(offsets);
    uint32_t i;
    libmpq__off_t transferred;
    int32_t status;
    int result = 0;
    char path[256] = { 0 };

    memset(plain, 'a', sizeof(plain));
    test_payload(plain + (sectors - 1) * sector_size, tail, 17);
    for (i = 0; i < sectors; ++i) {
        size_t size = i == sectors - 1 ? tail : sector_size;
        unsigned long size_packed = sizeof(packed) - position - 1;
        uint32_t checksum;
        offsets[i] = position;
        if (i == sectors - 1) {
            memcpy(packed + position, plain + i * sector_size, size);
            size_packed = size;
        } else {
            packed[position] = LIBMPQ_COMPRESSION_ZLIB;
            REQUIRE(
                compress2(packed + position + 1, &size_packed, plain + i * sector_size, size, 6) ==
                Z_OK
            );
            ++size_packed;
            REQUIRE(size_packed < size);
        }
        checksum = (uint32_t)adler32(0, packed + position, (uInt)size_packed);
        if (i == 0 && (corrupt & LIBMPQ_VERIFY_SECTOR_CRC))
            checksum ^= 1;
        if (absent == 2)
            checksum = i % 2 ? UINT32_MAX : 0;
        libmpq__store_le32(checksums + i * 4, checksum);
        if (encrypted)
            REQUIRE(
                libmpq__crypto_encrypt_block(packed + position, (uint32_t)size_packed, key + i) == 0
            );
        position += (uint32_t)size_packed;
    }
    offsets[sectors] = position;
    if (compressed_table) {
        unsigned long size = sizeof(encoded) - 1;
        encoded[0] = LIBMPQ_COMPRESSION_ZLIB;
        REQUIRE(compress2(encoded + 1, &size, checksums, sizeof(checksums), 6) == Z_OK);
        REQUIRE(size + 1 < sizeof(checksums));
        memcpy(packed + position, encoded, size + 1);
        position += (uint32_t)size + 1;
    } else {
        memcpy(packed + position, checksums, sizeof(checksums));
        position += sizeof(checksums);
    }
    offsets[sectors + 1] = absent == 1 ? 0 : position;
    for (i = 0; i < sectors + 2; ++i)
        libmpq__store_le32(packed + i * 4, offsets[i]);
    if (encrypted)
        REQUIRE(libmpq__crypto_encrypt_block(packed, sizeof(offsets), key - 1) == 0);

    REQUIRE(test_temp_path(path, sizeof(path), "sector-verify") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    REQUIRE(libmpq__archive_add_data(archive, "payload", packed, position, NULL) == 0);
    archive->mpq_block[0].unpacked_size = sizeof(plain);
    archive->mpq_block[0].flags = LIBMPQ_FLAG_EXISTS | LIBMPQ_FLAG_COMPRESS_MULTI |
                                  LIBMPQ_FLAG_CRC | (encrypted ? LIBMPQ_FLAG_ENCRYPTED : 0);
    if (attributes) {
        archive->write_attributes[0].crc32 = (uint32_t)crc32(0, plain, sizeof(plain));
        libmpq__md5_init(&md5);
        libmpq__md5_update(&md5, plain, sizeof(plain));
        libmpq__md5_final(&md5, archive->write_attributes[0].md5);
        if (corrupt & LIBMPQ_VERIFY_FILE_CRC32)
            archive->write_attributes[0].crc32 ^= 1;
        if (corrupt & LIBMPQ_VERIFY_FILE_MD5)
            archive->write_attributes[0].md5[0] ^= 1;
    }
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_open(&archive, path, 0) == 0);
    REQUIRE(libmpq__file_number(archive, "payload", &number) == 0);
    index = archive->mpq_map[number].block_table_indices;
    for (request = 0; request <= LIBMPQ_VERIFY_ALL; ++request) {
        bits = UINT32_MAX;
        status = libmpq__file_verify(archive, number, request, &bits);
        if (!attributes && (request & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5))) {
            REQUIRE(status == LIBMPQ_ERROR_EXIST && bits == 0);
            continue;
        }
        expected = request & corrupt;
        if (absent)
            expected &= ~LIBMPQ_VERIFY_SECTOR_CRC;
        REQUIRE(status == 0 && bits == expected);
        REQUIRE((bits & ~request) == 0);
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    REQUIRE(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == sizeof(plain) && memcmp(plain, output, sizeof(plain)) == 0);

    if (!absent && (corrupt & LIBMPQ_VERIFY_SECTOR_CRC)) {
        uint32_t *table = NULL;
        uint32_t observed = 0;
        read_failure_s failure;

        /* Prove the first sector mismatches, then fail the next physical read.
         * The public verifier uses the per-stream mock without linker wrapping. */
        REQUIRE(libmpq__reader_sector_checksums(archive, number, &table) == 0);
        status = libmpq__reader_block_read(
            archive, number, 0, output, sector_size, &transferred, table, &observed
        );
        free(table);
        REQUIRE(status == 0 && observed == LIBMPQ_VERIFY_SECTOR_CRC);
        failure.read_at = archive->stream->read_at;
        failure.offset =
            (uint64_t)archive->archive_offset + archive->mpq_block[index].offset + offsets[1];
        failure.reads = 0;
        archive->stream->read_context = &failure;
        archive->stream->read_at = fail_read;
        bits = UINT32_MAX;
        status = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits);
        archive->stream->read_at = failure.read_at;
        archive->stream->read_context = NULL;
        REQUIRE(status == LIBMPQ_ERROR_READ && bits == 0 && failure.reads == 1);
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    if (!absent) {
        uint32_t saved;
        saved = archive->mpq_block[index].packed_size;
        archive->mpq_block[index].packed_size = position - 1;
        bits = UINT32_MAX;
        REQUIRE(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits) ==
                LIBMPQ_ERROR_FORMAT &&
            bits == 0
        );
        REQUIRE(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
        archive->mpq_block[index].packed_size = saved;
        REQUIRE(archive->mpq_file[number] == NULL);
    }
cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        unlink(path);
    return result;
}

/* Exercise the public writer, not a manually fabricated sector payload. */
static int
test_writer_checksums(uint32_t version, uint32_t storage, size_t size, int mpqe)
{
    mpq_archive_create_options_s options = { version, 3,
                                             (storage & LIBMPQ_FILE_FLAG_SINGLE) ? 16384 : 512, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s file = { storage | LIBMPQ_FILE_FLAG_SECTOR_CRC, LIBMPQ_COMPRESSION_ZLIB,
                                LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    static const uint8_t code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    mpq_archive_s *archive = NULL;
    uint8_t plain[8229];
    uint8_t output[sizeof(plain)];
    uint8_t packed[16384];
    uint32_t *checksums = NULL;
    uint32_t *offsets = NULL;
    uint32_t number;
    uint32_t index;
    uint32_t blocks;
    uint32_t bits = UINT32_MAX;
    uint32_t i;
    uint32_t key = libmpq__crypto_hash_string("payload", 0x300);
    libmpq__off_t transferred;
    int eligible = size != 0 && !(storage & LIBMPQ_FILE_FLAG_SINGLE) &&
                   (storage & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE));
    int32_t status;
    int result = 0;
    char path[256] = { 0 };

    memset(plain, 'a', sizeof(plain));
    if (size >= 8) {
        memcpy(plain, "RIFF", 4);
        libmpq__store_le32(plain + 4, (uint32_t)size - 8);
    }
    if (size > 512)
        test_payload(plain + size - 37, 37, 17);
    REQUIRE(test_temp_path(path, sizeof(path), "writer-checksums") == 0);
    status = mpqe ? libmpq__archive_create_mpqe(&archive, path, code, sizeof(code) - 1, &options)
                  : libmpq__archive_create(&archive, path, &options);
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_add_data(archive, "payload", plain, size, &file) == 0);
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    status = mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, code, sizeof(code) - 1)
                  : libmpq__archive_open(&archive, path, 0);
    REQUIRE(status == 0);
    REQUIRE(libmpq__file_number(archive, "payload", &number) == 0);
    index = archive->mpq_map[number].block_table_indices;
    REQUIRE(((archive->mpq_block[index].flags & LIBMPQ_FLAG_CRC) != 0) == !!eligible);
    REQUIRE(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits) == 0 && bits == 0
    );
    if (size == 0 && !(storage & LIBMPQ_FILE_FLAG_SINGLE) &&
        (storage & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE))) {

        /* Empty sectorized codec files retain their existing reader behavior;
         * this case checks only that requesting CRC produces no checksum table. */
        goto cleanup;
    }
    REQUIRE(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits) == 0 && bits == 0);
    REQUIRE(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == (libmpq__off_t)size && memcmp(plain, output, size) == 0);
    if (eligible) {
        uint64_t base = archive->archive_offset + (uint64_t)archive->mpq_block[index].offset;
        REQUIRE(libmpq__file_blocks(archive, number, &blocks) == 0);
        REQUIRE(test_archive_offsets(archive, number, &offsets) == 0);
        REQUIRE(offsets[0] == (blocks + 2) * 4);
        REQUIRE(offsets[blocks + 1] == archive->mpq_block[index].packed_size);
        REQUIRE(libmpq__reader_sector_checksums(archive, number, &checksums) == 0);
        REQUIRE(checksums != NULL);
        if (blocks > 8)
            REQUIRE(offsets[blocks + 1] - offsets[blocks] < blocks * 4);
        else if (blocks <= 2)
            REQUIRE(offsets[blocks + 1] - offsets[blocks] == blocks * 4);
        for (i = 0; i < blocks; ++i) {
            uint32_t length = offsets[i + 1] - offsets[i];
            REQUIRE(length <= sizeof(packed));
            REQUIRE(
                libmpq__stream_read_at(archive->stream, base + offsets[i], packed, length) == 0
            );
            if (storage & LIBMPQ_FILE_FLAG_ENCRYPTED)
                REQUIRE(libmpq__crypto_decrypt_block(packed, length, key + i) == 0);
            REQUIRE(checksums[i] == (uint32_t)adler32(0, packed, length));
        }

        /* Even implode requests must perform the requested check, not skip it. */
        {
            read_failure_s failure;
            failure.read_at = archive->stream->read_at;
            failure.offset = base + offsets[1];
            failure.reads = 0;
            archive->stream->read_context = &failure;
            archive->stream->read_at = fail_read;
            status = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits);
            archive->stream->read_at = failure.read_at;
            archive->stream->read_context = NULL;

            /* One-sector files hit this offset while loading the checksum table. */
            REQUIRE(status == LIBMPQ_ERROR_READ && bits == 0 && failure.reads == 1);
        }
        if (size == sizeof(plain)) {
            read_failure_s failure;
            REQUIRE(offsets[blocks] - offsets[blocks - 1] == 37);
            failure.read_at = archive->stream->read_at;
            failure.offset = base + offsets[blocks - 1];
            failure.reads = 0;
            archive->stream->read_context = &failure;
            archive->stream->read_at = corrupt_read;
            status = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits);
            archive->stream->read_at = failure.read_at;
            archive->stream->read_context = NULL;
            REQUIRE(status == 0 && failure.reads == 1);
            REQUIRE(
                bits ==
                (LIBMPQ_VERIFY_SECTOR_CRC | LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)
            );
        }
        REQUIRE(archive->mpq_file[number] == NULL);
    }
cleanup:
    free(checksums);
    free(offsets);
    if (result != 0)
        fprintf(
            stderr, "writer checksum case: version=%u storage=%u size=%zu mpqe=%d\n", version,
            storage, size, mpqe
        );
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        unlink(path);
    return result;
}

int
main(void)
{
    uint32_t version;
    uint32_t corrupt;
    int encrypted;
    int compressed;
    int absent;
    size_t i;
    size_t j;
    static const size_t sizes[] = { 0, 1, 37, 512, 513, 8229 };
    static const uint32_t storage[] = { 0,
                                        LIBMPQ_FILE_FLAG_SINGLE,
                                        LIBMPQ_FILE_FLAG_COMPRESS,
                                        LIBMPQ_FILE_FLAG_IMPLODE,
                                        LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE,
                                        LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_SINGLE,
                                        LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                        LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED };

    for (version = 0; version <= 1; ++version)
        for (encrypted = 0; encrypted <= 1; ++encrypted)
            for (compressed = 0; compressed <= 1; ++compressed)
                for (corrupt = 0; corrupt <= LIBMPQ_VERIFY_ALL; ++corrupt)
                    TEST_CHECK(test_sectors(version, encrypted, compressed, corrupt, 1, 0) == 0);
    for (absent = 0; absent <= 2; ++absent)
        TEST_CHECK(test_sectors(1, 1, 1, LIBMPQ_VERIFY_SECTOR_CRC, 0, absent) == 0);
    for (version = 0; version <= 1; ++version)
        for (i = 0; i < sizeof(storage) / sizeof(storage[0]); ++i)
            for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); ++j)
                TEST_CHECK(test_writer_checksums(version, storage[i], sizes[j], 0) == 0);
    TEST_CHECK(
        test_writer_checksums(1, LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED, 8229, 1) ==
        0
    );
    return 0;
}
