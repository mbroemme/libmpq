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

#include "mpq-archive.h"
#include "mpq-block.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-md5.h"
#include "mpq-reader.h"
#include "mpq-source.h"
#include "mpq-verify.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define REQUIRE(condition)                                \
    do {                                                  \
        if (!(condition)) {                               \
            test_failure(__FILE__, __LINE__, #condition); \
            result = 1;                                   \
            goto cleanup;                                 \
        }                                                 \
    } while (0)

/* Each test archive borrows its own mock context; no process-global test mode. */
typedef struct
{
    mpq_io_backend_s backend;
    uint64_t offset;
    unsigned reads;
} read_failure_s;

static int32_t
failure_close(void *context)
{
    read_failure_s *failure = context;

    return failure->backend.close == NULL ? 0 : failure->backend.close(failure->backend.context);
}

static void
failure_discard(void *context)
{
    read_failure_s *failure = context;

    if (failure->backend.discard != NULL)
        failure->backend.discard(failure->backend.context);
}

static void
failure_install(mpq_source_s *source, read_failure_s *failure, mpq_io_read_at_fn read_at)
{
    failure->backend = source->backend;
    source->backend.context = failure;
    source->backend.read_at = read_at;
    source->backend.close = failure_close;
    source->backend.discard = failure_discard;
}

static void
failure_restore(mpq_source_s *source, const read_failure_s *failure)
{
    source->backend = failure->backend;
}

static int32_t
fail_read(void *context, uint64_t offset, uint8_t *data, size_t size)
{
    read_failure_s *failure = context;
    if (offset == failure->offset) {
        ++failure->reads;
        return LIBMPQ_ERROR_READ;
    }
    return failure->backend.read_at(failure->backend.context, offset, data, size);
}

/* Corrupt a byte in a selected raw-fallback sector, leaving table metadata intact. */
static int32_t
corrupt_read(void *context, uint64_t offset, uint8_t *data, size_t size)
{
    read_failure_s *failure = context;
    int32_t status = failure->backend.read_at(failure->backend.context, offset, data, size);
    if (status == 0 && offset <= failure->offset && failure->offset - offset < size) {
        data[(size_t)(failure->offset - offset)] ^= 1;
        ++failure->reads;
    }
    return status;
}

/* An invalid compression mask fails decoding after the Adler-32 comparison. */
static int32_t
corrupt_method(void *context, uint64_t offset, uint8_t *data, size_t size)
{
    read_failure_s *failure = context;
    int32_t status = failure->backend.read_at(failure->backend.context, offset, data, size);
    if (status == 0 && offset == failure->offset && size != 0) {
        data[0] = 0x04;
        ++failure->reads;
    }
    return status;
}

/* Both outputs must be cleared, including on invalid indices and absent data. */
static int
check_block_error(mpq_archive_s *archive, uint32_t number, uint32_t block, int32_t error)
{
    uint32_t checksum = UINT32_MAX;
    uint32_t mismatches = UINT32_MAX;
    TEST_CHECK(libmpq__block_verify(archive, number, block, &checksum, &mismatches) == error);
    TEST_CHECK(checksum == 0 && mismatches == 0);
    return 0;
}

/*
 * Construct only the checksum-bearing file payload here. The normal writer
 * supplies archive tables and attributes. Checksums cover pre-encryption bytes,
 * including a deliberately raw final sector. The checksum table is never encrypted.
 */
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
        if (absent == 2 || (absent == 3 && i != 0))
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
    index = archive->mpq_map[number].entry_index;
    for (i = 0; i < sectors; ++i) {
        uint32_t stored = UINT32_MAX;
        bits = UINT32_MAX;
        status = libmpq__block_verify(archive, number, i, &stored, &bits);
        if (absent && (absent != 3 || i != 0)) {
            REQUIRE(status == LIBMPQ_ERROR_EXIST && stored == 0 && bits == 0);
        } else {
            REQUIRE(status == 0 && stored == libmpq__load_le32(checksums + i * 4));
            REQUIRE(bits == (i == 0 ? corrupt & LIBMPQ_VERIFY_SECTOR_CRC : 0));
        }
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    REQUIRE(check_block_error(archive, number, sectors, LIBMPQ_ERROR_EXIST) == 0);
    REQUIRE(check_block_error(archive, UINT32_MAX, 0, LIBMPQ_ERROR_EXIST) == 0);
    for (request = 0; request <= LIBMPQ_VERIFY_ALL; ++request) {
        uint32_t checked = UINT32_MAX;
        uint32_t unavailable = UINT32_MAX;
        uint32_t expected_checked = request & ~LIBMPQ_VERIFY_RAW_MD5;
        uint32_t expected_bits = request & corrupt;

        if (!attributes)
            expected_checked &= ~(LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5);
        if (absent && absent != 3)
            expected_checked &= ~LIBMPQ_VERIFY_SECTOR_CRC;
        expected_bits &= expected_checked;
        REQUIRE(
            libmpq__file_verify_ex(archive, number, NULL, request, &checked, &unavailable, &bits) ==
            0
        );
        REQUIRE(checked == expected_checked);
        REQUIRE(
            unavailable ==
            ((request & ~checked) | (absent == 3 ? request & LIBMPQ_VERIFY_SECTOR_CRC : 0))
        );
        REQUIRE(bits == expected_bits);
        REQUIRE((bits & ~checked) == 0 && (checked | unavailable) == request);
    }
    for (request = 0; request <= LIBMPQ_VERIFY_ALL; ++request) {
        bits = UINT32_MAX;
        status = libmpq__file_verify(archive, number, request, &bits);
        if (!attributes && (request & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5))) {
            REQUIRE(status == LIBMPQ_ERROR_EXIST && bits == 0);
            continue;
        }
        expected = request & corrupt;
        if (absent && absent != 3)
            expected &= ~LIBMPQ_VERIFY_SECTOR_CRC;
        REQUIRE(status == 0 && bits == expected);
        REQUIRE((bits & ~request) == 0);
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    REQUIRE(
        libmpq__file_read(archive, number, output, sizeof(output), &transferred) ==
        (((!absent || absent == 3) && (corrupt & LIBMPQ_VERIFY_SECTOR_CRC) != 0) ||
                 (attributes &&
                  (corrupt & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)) != 0)
             ? LIBMPQ_ERROR_READ
             : 0)
    );
    REQUIRE(memcmp(plain, output, sizeof(plain)) == 0);

    /*
     * Block reads are intentionally partial and do not load a checksum table.
     * A changed packed final sector is rejected by the complete file read.
     */
    if (corrupt == 0 && !absent && !encrypted && !compressed_table) {
        read_failure_s failure;
        libmpq__off_t tail_size;
        mpq_stream_s *stream = NULL;
        FILE *file;
        uint8_t checksum[sizeof(uint32_t)];

        /* A valid stream verifies sector checksums before exposing its data. */
        REQUIRE(libmpq__stream_open(archive, number, &stream) == 0);
        REQUIRE(libmpq__stream_read(stream, output, sector_size, &transferred) == 0);
        REQUIRE(transferred == sector_size && memcmp(output, plain, sector_size) == 0);
        REQUIRE(libmpq__stream_close(stream) == 0);

        REQUIRE(libmpq__block_size_unpacked(archive, number, sectors - 1, &tail_size) == 0);
        failure.offset = (uint64_t)archive->archive_offset + archive->mpq_entry[index].offset +
                         offsets[sectors - 1];
        failure.reads = 0;
        failure_install(archive->source, &failure, corrupt_read);
        status = libmpq__block_read(archive, number, sectors - 1, output, tail_size, &transferred);
        REQUIRE(status == 0 && transferred == tail_size && failure.reads == 1);
        failure.reads = 0;
        status = libmpq__file_read(archive, number, output, sizeof(output), &transferred);
        failure_restore(archive->source, &failure);
        REQUIRE(status == LIBMPQ_ERROR_READ && failure.reads == 1);

        /*
         * Corrupt sector one's stored Adler-32 after the source archive opened.
         * The packed payload remains valid, so the stream failure is unambiguously
         * caused by automatic sector checksum verification.
         */
        file = fopen(path, "r+b");
        REQUIRE(file != NULL);
        REQUIRE(
            fseek(
                file,
                (long)((uint64_t)archive->archive_offset + archive->mpq_entry[index].offset +
                       offsets[sectors] + sizeof(checksum)),
                SEEK_SET
            ) == 0
        );
        REQUIRE(fread(checksum, 1, sizeof(checksum), file) == sizeof(checksum));
        checksum[0] ^= 1;
        REQUIRE(fseek(file, -(long)sizeof(checksum), SEEK_CUR) == 0);
        REQUIRE(fwrite(checksum, 1, sizeof(checksum), file) == sizeof(checksum));
        REQUIRE(fclose(file) == 0);
        REQUIRE(libmpq__stream_open(archive, number, &stream) == 0);
        status = libmpq__stream_read(stream, output, sizeof(output), &transferred);
        REQUIRE(status == LIBMPQ_ERROR_READ && transferred == sector_size);
        REQUIRE(memcmp(output, plain, sector_size) == 0);
        REQUIRE(libmpq__stream_tell(stream, &tail_size) == 0 && tail_size == sector_size);
        REQUIRE(libmpq__stream_close(stream) == 0);
    }

    if (!absent && (corrupt & LIBMPQ_VERIFY_SECTOR_CRC)) {
        uint32_t *table = NULL;
        uint32_t observed = 0;
        read_failure_s failure;

        /*
         * Prove the first sector mismatches, then fail the next physical read.
         * The public verifier uses the per-stream mock without linker wrapping.
         */
        REQUIRE(libmpq__reader_sector_checksums(archive, number, &table) == 0);
        status = libmpq__reader_block_read(
            archive, number, 0, output, sector_size, &transferred, table, &observed, NULL
        );
        free(table);
        REQUIRE(status == 0 && observed == LIBMPQ_VERIFY_SECTOR_CRC);
        failure.offset =
            (uint64_t)archive->archive_offset + archive->mpq_entry[index].offset + offsets[1];
        failure.reads = 0;
        failure_install(archive->source, &failure, fail_read);
        bits = UINT32_MAX;
        status = libmpq__block_compression(archive, number, 1, &bits);
        REQUIRE(status == LIBMPQ_ERROR_READ && bits == 0 && failure.reads == 1);
        REQUIRE(archive->mpq_file[number] == NULL);
        failure.reads = 0;
        status = check_block_error(archive, number, 1, LIBMPQ_ERROR_READ);
        REQUIRE(status == 0 && failure.reads == 1);
        failure.reads = 0;
        bits = UINT32_MAX;
        status = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits);
        REQUIRE(status == LIBMPQ_ERROR_READ && bits == 0 && failure.reads == 1);
        {
            uint32_t checked = UINT32_MAX;
            uint32_t unavailable = UINT32_MAX;
            failure.reads = 0;
            REQUIRE(
                libmpq__file_verify_ex(
                    archive, number, NULL, LIBMPQ_VERIFY_ALL, &checked, &unavailable, &bits
                ) == LIBMPQ_ERROR_READ
            );
            REQUIRE(checked == 0 && unavailable == 0 && bits == 0 && failure.reads == 1);
        }
        failure_restore(archive->source, &failure);
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    if (!absent) {
        uint64_t saved;
        saved = archive->mpq_entry[index].packed_size;
        archive->mpq_entry[index].packed_size = position - 1;
        REQUIRE(check_block_error(archive, number, 0, LIBMPQ_ERROR_FORMAT) == 0);
        bits = UINT32_MAX;
        REQUIRE(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits) ==
                LIBMPQ_ERROR_FORMAT &&
            bits == 0
        );
        REQUIRE(
            libmpq__file_read(archive, number, output, sizeof(output), &transferred) ==
            (attributes && (corrupt & (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)) != 0
                 ? LIBMPQ_ERROR_READ
                 : 0)
        );
        archive->mpq_entry[index].packed_size = saved;
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    if (!absent && !encrypted) {
        read_failure_s failure;
        failure.offset =
            (uint64_t)archive->archive_offset + archive->mpq_entry[index].offset + offsets[0];
        failure.reads = 0;
        failure_install(archive->source, &failure, corrupt_method);
        bits = UINT32_MAX;
        status = libmpq__block_compression(archive, number, 0, &bits);
        REQUIRE(status == 0 && bits == 0x04 && failure.reads == 1);
        REQUIRE(archive->mpq_file[number] == NULL);
        failure.reads = 0;
        status = check_block_error(archive, number, 0, LIBMPQ_ERROR_UNPACK);
        failure_restore(archive->source, &failure);
        REQUIRE(status == 0 && failure.reads == 1);
        REQUIRE(archive->mpq_file[number] == NULL);
    }
cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        remove(path);
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
    {
        libmpq__off_t packed_size = -1;
        uint32_t method = UINT32_MAX;
        REQUIRE(libmpq__block_compression(archive, 0, 0, &method) == LIBMPQ_ERROR_NOT_INITIALIZED);
        REQUIRE(method == 0);
        REQUIRE(
            libmpq__block_size_packed(archive, 0, 0, &packed_size) == LIBMPQ_ERROR_NOT_INITIALIZED
        );
        REQUIRE(packed_size == 0);
    }
    REQUIRE(check_block_error(archive, 0, 0, LIBMPQ_ERROR_NOT_INITIALIZED) == 0);
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    status = mpqe ? libmpq__archive_open_mpqe(&archive, path, 0, code, sizeof(code) - 1)
                  : libmpq__archive_open(&archive, path, 0);
    REQUIRE(status == 0);
    REQUIRE(libmpq__file_number(archive, "payload", &number) == 0);
    index = archive->mpq_map[number].entry_index;
    REQUIRE(((archive->mpq_entry[index].flags & LIBMPQ_FLAG_CRC) != 0) == !!eligible);
    REQUIRE(libmpq__file_blocks(archive, number, &blocks) == 0);
    for (i = 0; i < blocks; ++i) {
        libmpq__off_t packed_size = -1;
        libmpq__off_t unpacked_size;
        uint32_t method = UINT32_MAX;
        REQUIRE(libmpq__block_size_packed(archive, number, i, &packed_size) == 0);
        REQUIRE(libmpq__block_size_unpacked(archive, number, i, &unpacked_size) == 0);
        REQUIRE(libmpq__block_compression(archive, number, i, &method) == 0);
        REQUIRE(
            method == (packed_size >= unpacked_size           ? 0U
                       : (storage & LIBMPQ_FILE_FLAG_IMPLODE) ? LIBMPQ_COMPRESSION_PKZIP
                                                              : LIBMPQ_COMPRESSION_ZLIB)
        );
        if (storage & LIBMPQ_FILE_FLAG_SINGLE) {
            REQUIRE((uint64_t)packed_size == archive->mpq_entry[index].packed_size);
        } else if (!eligible) {
            size_t remaining = size - (size_t)i * 512;
            REQUIRE(packed_size == (libmpq__off_t)(remaining < 512 ? remaining : 512));
        }
        REQUIRE(archive->mpq_file[number] == NULL);
    }
    {
        libmpq__off_t packed_size = -1;
        uint32_t method = UINT32_MAX;
        REQUIRE(libmpq__block_compression(archive, number, blocks, &method) == LIBMPQ_ERROR_EXIST);
        REQUIRE(method == 0);
        method = UINT32_MAX;
        REQUIRE(libmpq__block_compression(archive, UINT32_MAX, 0, &method) == LIBMPQ_ERROR_EXIST);
        REQUIRE(method == 0);
        REQUIRE(libmpq__block_compression(archive, number, 0, NULL) == LIBMPQ_ERROR_EXIST);
        REQUIRE(
            libmpq__block_size_packed(archive, number, blocks, &packed_size) == LIBMPQ_ERROR_EXIST
        );
        REQUIRE(packed_size == 0);
        packed_size = -1;
        REQUIRE(
            libmpq__block_size_packed(archive, UINT32_MAX, 0, &packed_size) == LIBMPQ_ERROR_EXIST
        );
        REQUIRE(packed_size == 0);
        REQUIRE(libmpq__block_size_packed(archive, number, 0, NULL) == LIBMPQ_ERROR_EXIST);
    }
    if (!eligible)
        REQUIRE(check_block_error(archive, number, 0, LIBMPQ_ERROR_EXIST) == 0);
    REQUIRE(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits) == 0 && bits == 0
    );
    if (size == 0 && !(storage & LIBMPQ_FILE_FLAG_SINGLE) &&
        (storage & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE))) {

        /*
         * Empty sectorized codec files retain their existing reader behavior;
         * this case checks only that requesting CRC produces no checksum table.
         */
        goto cleanup;
    }
    REQUIRE(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits) == 0 && bits == 0);
    {
        uint32_t checked;
        uint32_t unavailable;
        REQUIRE(
            libmpq__file_verify_ex(
                archive, number, NULL, LIBMPQ_VERIFY_ALL, &checked, &unavailable, &bits
            ) == 0
        );
        REQUIRE(
            checked == ((LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5) |
                        (eligible && size != 0 ? LIBMPQ_VERIFY_SECTOR_CRC : 0))
        );
        REQUIRE(unavailable == (LIBMPQ_VERIFY_ALL & ~checked) && bits == 0);
    }
    REQUIRE(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == (libmpq__off_t)size && memcmp(plain, output, size) == 0);
    if (eligible) {
        uint64_t base = archive->archive_offset + (uint64_t)archive->mpq_entry[index].offset;
        REQUIRE(libmpq__file_blocks(archive, number, &blocks) == 0);
        REQUIRE(test_archive_offsets(archive, number, &offsets) == 0);
        if (!mpqe && blocks > 1)
            REQUIRE(test_archive_verify_offsets(archive, number, LIBMPQ_VERIFY_ALL) == 0);
        REQUIRE(offsets[0] == (blocks + 2) * 4);
        REQUIRE(offsets[blocks + 1] == archive->mpq_entry[index].packed_size);
        REQUIRE(libmpq__reader_sector_checksums(archive, number, &checksums) == 0);
        REQUIRE(checksums != NULL);
        if (blocks > 8)
            REQUIRE(offsets[blocks + 1] - offsets[blocks] < blocks * 4);
        else if (blocks <= 2)
            REQUIRE(offsets[blocks + 1] - offsets[blocks] == blocks * 4);
        for (i = 0; i < blocks; ++i) {
            uint32_t stored = 0;
            uint32_t length = offsets[i + 1] - offsets[i];
            libmpq__off_t packed_size = -1;
            REQUIRE(libmpq__block_size_packed(archive, number, i, &packed_size) == 0);
            REQUIRE(packed_size == length);
            REQUIRE(libmpq__block_verify(archive, number, i, &stored, &bits) == 0);
            REQUIRE(stored == checksums[i] && bits == 0);
            REQUIRE(length <= sizeof(packed));
            REQUIRE(
                libmpq__source_read_at(archive->source, base + offsets[i], packed, length) == 0
            );
            if (storage & LIBMPQ_FILE_FLAG_ENCRYPTED)
                REQUIRE(libmpq__crypto_decrypt_block(packed, length, key + i) == 0);
            REQUIRE(checksums[i] == (uint32_t)adler32(0, packed, length));
        }

        /* Even implode requests must perform the requested check, not skip it. */
        {
            read_failure_s failure;
            failure.offset = base + offsets[1];
            if (mpqe)
                failure.offset &= ~(uint64_t)(LIBMPQ_MPQE_CHUNK_SIZE - 1U);
            failure.reads = 0;
            failure_install(archive->source, &failure, fail_read);
            status = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits);
            failure_restore(archive->source, &failure);

            /* One-sector files hit this offset while loading the checksum table. */
            REQUIRE(status == LIBMPQ_ERROR_READ && bits == 0 && failure.reads == 1);
        }
        if (size == sizeof(plain)) {
            read_failure_s failure;
            REQUIRE(offsets[blocks] - offsets[blocks - 1] == 37);
            REQUIRE(offsets[1] - offsets[0] != 37);
            failure.offset = base + offsets[blocks] - 1U;
            failure.reads = 0;
            failure_install(archive->source, &failure, corrupt_read);
            {
                uint32_t stored = 0;
                status = libmpq__block_verify(archive, number, blocks - 1, &stored, &bits);
                REQUIRE(status == 0 && stored == checksums[blocks - 1]);
                REQUIRE(bits == LIBMPQ_VERIFY_SECTOR_CRC);
                if (mpqe)
                    REQUIRE(failure.reads >= 1);
                else
                    REQUIRE(failure.reads == 1);
                failure.reads = 0;
            }
            status = libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &bits);
            failure_restore(archive->source, &failure);
            REQUIRE(status == 0);
            if (mpqe)
                REQUIRE(failure.reads >= 1);
            else
                REQUIRE(failure.reads == 1);
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
        remove(path);
    return result;
}

/*
 * Single-unit encryption has no offset table from which to recover a key.
 * Preserve the reader's DECRYPT error, and reuse a named internal cache when
 * its key is available. The inspection must leave that outer reference alive.
 */
static int
test_single_compression(int key)
{
    mpq_archive_create_options_s options = { 1, 2, 512, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s file = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE |
                                    LIBMPQ_FILE_FLAG_ENCRYPTED,
                                LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    uint8_t plain[512];
    uint8_t output[sizeof(plain)];
    uint32_t method = UINT32_MAX;
    libmpq__off_t transferred;
    int32_t status;
    int result = 0;
    char path[256] = { 0 };

    if (key)
        file.flags |= LIBMPQ_FILE_FLAG_KEY;
    memset(plain, 'a', sizeof(plain));
    REQUIRE(test_temp_path(path, sizeof(path), "single-compression") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    REQUIRE(libmpq__archive_add_data(archive, "payload", plain, sizeof(plain), &file) == 0);
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_open(&archive, path, 0) == 0);
    status = libmpq__stream_open(archive, 0, &stream);
    REQUIRE(status == LIBMPQ_ERROR_DECRYPT);
    REQUIRE(stream == NULL);
    REQUIRE(libmpq__stream_open_name(archive, "payload", &stream) == 0);
    REQUIRE(libmpq__stream_read(stream, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == sizeof(plain) && memcmp(output, plain, sizeof(plain)) == 0);
    REQUIRE(libmpq__stream_close(stream) == 0);
    stream = NULL;
    REQUIRE(libmpq__block_compression(archive, 0, 0, &method) == LIBMPQ_ERROR_DECRYPT);
    REQUIRE(method == 0 && archive->mpq_file[0] == NULL);
    {
        uint32_t checked = UINT32_MAX;
        uint32_t unavailable = UINT32_MAX;
        uint32_t mismatches = UINT32_MAX;
        REQUIRE(
            libmpq__file_verify_ex(
                archive, 0, NULL, LIBMPQ_VERIFY_FILE_CRC32, &checked, &unavailable, &mismatches
            ) == LIBMPQ_ERROR_DECRYPT
        );
        REQUIRE(checked == 0 && unavailable == 0 && mismatches == 0);
        REQUIRE(
            libmpq__file_verify_ex(
                archive, 0, "payload", LIBMPQ_VERIFY_ALL, &checked, &unavailable, &mismatches
            ) == 0
        );
        REQUIRE(checked == (LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5));
        REQUIRE(unavailable == (LIBMPQ_VERIFY_SECTOR_CRC | LIBMPQ_VERIFY_RAW_MD5));
        REQUIRE(mismatches == 0 && archive->mpq_file[0] == NULL);
        REQUIRE(
            libmpq__file_verify_ex(
                archive, 0, "wrong", LIBMPQ_VERIFY_ALL, &checked, &unavailable, &mismatches
            ) == LIBMPQ_ERROR_EXIST
        );
        REQUIRE(checked == 0 && unavailable == 0 && mismatches == 0);
        REQUIRE(
            libmpq__file_verify(archive, 0, LIBMPQ_VERIFY_FILE_CRC32, &mismatches) ==
            LIBMPQ_ERROR_DECRYPT
        );
    }
    REQUIRE(libmpq__reader_offsets_acquire(archive, 0, "payload") == 0);
    REQUIRE(libmpq__block_compression(archive, 0, 0, &method) == 0);
    REQUIRE(method == LIBMPQ_COMPRESSION_ZLIB);
    REQUIRE(archive->mpq_file[0]->open_count == 1);
    REQUIRE(libmpq__block_read(archive, 0, 0, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == sizeof(plain) && memcmp(output, plain, sizeof(plain)) == 0);
    REQUIRE(libmpq__reader_offsets_release(archive, 0) == 0);
    REQUIRE(archive->mpq_file[0] == NULL);
cleanup:
    if (stream != NULL)
        (void)libmpq__stream_close(stream);
    if (archive != NULL)
        libmpq__archive_close(archive);
    if (path[0] != 0)
        remove(path);
    return result;
}

/* A trailing encrypted partial word remains readable without a file seed. */
static int
test_short_encrypted_stream(void)
{
    mpq_archive_create_options_s options = { 1, 1, 512, 0, 0 };
    mpq_file_options_s file = { LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED, 0, 0, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_stream_s *stream = NULL;
    static const uint8_t plain[] = { 0x31, 0x32, 0x33 };
    uint8_t output[sizeof(plain)];
    libmpq__off_t packed_size;
    libmpq__off_t transferred;
    int result = 0;
    char path[256] = { 0 };

    REQUIRE(test_temp_path(path, sizeof(path), "short-encrypted-stream") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    REQUIRE(libmpq__archive_add_data(archive, "payload", plain, sizeof(plain), &file) == 0);
    REQUIRE(libmpq__archive_close(archive) == 0);
    archive = NULL;
    REQUIRE(libmpq__archive_open(&archive, path, 0) == 0);
    REQUIRE(libmpq__block_size_packed(archive, 0, 0, &packed_size) == 0);
    REQUIRE(packed_size == sizeof(plain));
    REQUIRE(libmpq__stream_open(archive, 0, &stream) == 0);
    REQUIRE(libmpq__stream_read(stream, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == sizeof(plain) && memcmp(output, plain, sizeof(plain)) == 0);
    REQUIRE(libmpq__stream_close(stream) == 0);
    stream = NULL;
cleanup:
    if (stream != NULL)
        (void)libmpq__stream_close(stream);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        remove(path);
    return result;
}

/* Exercise output atomicity, empty checksums and circular metadata independently. */
static int
test_verification_coverage(uint32_t version)
{
    mpq_archive_create_options_s options = { version, 5, 512, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s secure = {
        LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_KEY, 0, 0, 1033, 2
    };
    mpq_archive_s *archive = NULL;
    char path[256] = { 0 };
    static const uint8_t crc_zero[] = { 0x9d, 0x0a, 0xd9, 0x6d };
    uint8_t data[64];
    uint32_t number;
    uint32_t checked;
    uint32_t unavailable;
    uint32_t bits;
    int32_t status;
    int result = 0;

    test_payload(data, sizeof(data), 71);
    REQUIRE(test_temp_path(path, sizeof(path), "verify-coverage") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    if (version == LIBMPQ_ARCHIVE_VERSION_4)
        REQUIRE(libmpq__archive_raw_chunk_size_set(archive, 0) == 0);
    REQUIRE(
        libmpq__archive_sign(
            archive, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
            sizeof(test_signature_private_key)
        ) == 0
    );
    REQUIRE(crc32(0, crc_zero, sizeof(crc_zero)) == 0);
    REQUIRE(
        libmpq__archive_add_data(archive, "crc-zero.bin", crc_zero, sizeof(crc_zero), NULL) == 0
    );
    REQUIRE(libmpq__archive_add_data(archive, "empty", NULL, 0, NULL) == 0);
    REQUIRE(libmpq__archive_add_data(archive, "secure.bin", data, sizeof(data), &secure) == 0);
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_open(&archive, path, 0) == 0);
    REQUIRE(libmpq__file_number(archive, "crc-zero.bin", &number) == 0);
    REQUIRE(libmpq__file_verify_ex(archive, number, NULL, 6, &checked, &unavailable, &bits) == 0);
    REQUIRE(checked == 6 && unavailable == 0 && bits == 0);
    REQUIRE(libmpq__file_number(archive, "empty", &number) == 0);
    REQUIRE(
        libmpq__file_verify_ex(
            archive, number, NULL, LIBMPQ_VERIFY_ALL, &checked, &unavailable, &bits
        ) == 0
    );
    REQUIRE(checked == 6 && unavailable == 9 && bits == 0);
    REQUIRE(libmpq__file_number(archive, "(attributes)", &number) == 0);
    REQUIRE(libmpq__file_verify_ex(archive, number, NULL, 6, &checked, &unavailable, &bits) == 0);
    REQUIRE(checked == 0 && unavailable == 6 && bits == 0);
    REQUIRE(libmpq__file_verify(archive, number, 2, &bits) == 0 && bits == 2);
    REQUIRE(libmpq__file_number(archive, "(signature)", &number) == 0);
    REQUIRE(libmpq__file_verify_ex(archive, number, NULL, 6, &checked, &unavailable, &bits) == 0);
    REQUIRE(checked == 0 && unavailable == 6 && bits == 0);
    REQUIRE(libmpq__file_verify(archive, number, 2, &bits) == 0 && bits == 2);
    REQUIRE(libmpq__file_number_from_identity(archive, "secure.bin", 1033, 2, &number) == 0);
    REQUIRE(
        libmpq__file_verify_ex(archive, number, "secure.bin", 6, &checked, &unavailable, &bits) == 0
    );
    REQUIRE(checked == 6 && unavailable == 0 && bits == 0);
    REQUIRE(archive->mpq_file[number] == NULL);
    REQUIRE(
        libmpq__file_verify_ex(archive, number, NULL, 6, &checked, &unavailable, &bits) ==
        LIBMPQ_ERROR_DECRYPT
    );
    REQUIRE(checked == 0 && unavailable == 0 && bits == 0);
    REQUIRE(
        libmpq__file_verify_ex(archive, number, "empty", 6, &checked, &unavailable, &bits) ==
        LIBMPQ_ERROR_EXIST
    );
    REQUIRE(checked == 0 && unavailable == 0 && bits == 0);
    REQUIRE(libmpq__file_verify_ex(archive, number, NULL, 0, &checked, &unavailable, &bits) == 0);
    REQUIRE(checked == 0 && unavailable == 0 && bits == 0);
    checked = unavailable = bits = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify_ex(archive, number, NULL, 16, &checked, &unavailable, &bits) ==
        LIBMPQ_ERROR_FORMAT
    );
    REQUIRE(checked == 0 && unavailable == 0 && bits == 0);
    checked = unavailable = bits = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify_ex(archive, UINT32_MAX, NULL, 0, &checked, &unavailable, &bits) ==
        LIBMPQ_ERROR_EXIST
    );
    REQUIRE(checked == 0 && unavailable == 0 && bits == 0);
    checked = unavailable = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify_ex(archive, number, NULL, 0, &checked, &unavailable, NULL) ==
        LIBMPQ_ERROR_EXIST
    );
    REQUIRE(checked == 0 && unavailable == 0);
cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        remove(path);
    return result;
}

/* Small wire images independently place tables, payloads and expected digest storage. */
enum
{
    RAW_VALID,
    RAW_CORRUPT,
    RAW_START,
    RAW_INTERIOR,
    RAW_ORDER_START,
    RAW_ORDER_INTERIOR,
    RAW_END,
    RAW_PARTIAL,
    RAW_ZEROS,
    RAW_PADDING,
    RAW_SHARED,
    RAW_EMPTY,
    RAW_DELETE,
    RAW_UNUSED,
    RAW_ZERO_NEIGHBOR,
    RAW_NESTED
};

typedef struct
{
    uint8_t bytes[1024];
    size_t size;
    uint64_t reads;
    int fail;
} raw_image_s;

/* Exact callback reads also expose unwanted I/O during layout preprocessing. */
static int32_t
raw_image_read(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    raw_image_s *image = context;

    if (image->fail || offset < 0 || (uint64_t)offset > image->size ||
        size > image->size - (size_t)offset)
        return LIBMPQ_ERROR_READ;
    image->reads++;
    memcpy(buffer, image->bytes + (size_t)offset, size);
    return 0;
}

/* Deliberate conflicts retain correct structural digests and ordinary discovery. */
static int
raw_image_build(raw_image_s *image, unsigned mode, uint32_t chunk, size_t base)
{
    static const uint8_t digest_x[16] = { 0x9d, 0xd4, 0xe4, 0x61, 0x26, 0x8c, 0x80, 0x34,
                                          0xf5, 0xc8, 0x56, 0x4e, 0x15, 0x5c, 0x67, 0xa6 };
    uint8_t *header;
    uint8_t *hashes;
    uint8_t *blocks;
    uint32_t offsets[3] = { 384, 401, 418 };
    uint32_t lengths[3] = { 1, 1, 1 };
    uint32_t flags[3] = { 0x81000000u, 0x81000000u, 0x81000000u };
    size_t extent = 435;
    mpq_md5_s md5;

    memset(image, 0, sizeof(*image));
    header = image->bytes + base;
    hashes = header + 208;
    blocks = header + 336;
    memset(hashes, 0xff, 128);
    for (uint32_t i = 0; i < 3; i++) {
        header[offsets[i]] = 'x';
        memcpy(header + offsets[i] + 1, digest_x, 16);
    }
    if (mode == RAW_CORRUPT || mode == RAW_START)
        header[385] ^= 1;
    if (mode == RAW_START || mode == RAW_ORDER_START || mode == RAW_ORDER_INTERIOR)
        offsets[1] = 385;
    if (mode == RAW_INTERIOR)
        offsets[1] = 386;
    if (mode == RAW_ORDER_START || mode == RAW_ORDER_INTERIOR) {
        offsets[2] = 386;
        if (mode == RAW_ORDER_INTERIOR) {
            offsets[1] = 386;
            offsets[2] = 385;
        }
    }
    if (mode == RAW_END || mode == RAW_PARTIAL) {
        extent = mode == RAW_END ? 385 : 393;
        flags[1] = flags[2] = 0;
    }
    if (mode == RAW_ZEROS || mode == RAW_PADDING)
        memset(header + 385, mode == RAW_ZEROS ? 0 : 'P', 16);
    if (mode == RAW_SHARED)
        offsets[1] = 384;
    if (mode == RAW_EMPTY)
        lengths[0] = 0;
    if (mode == RAW_DELETE)
        flags[0] |= LIBMPQ_FILE_FLAG_DELETE_MARKER;
    if (mode == RAW_UNUSED) {
        flags[1] = 0;
        offsets[1] = 385;
    }
    if (mode == RAW_ZERO_NEIGHBOR) {
        offsets[1] = 385;
        lengths[1] = 0;
    }
    if (mode == RAW_NESTED) {
        offsets[1] = 380;
        lengths[1] = 20;
        offsets[2] = 384;
    }
    for (uint32_t i = 0; i < 3; i++) {
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        uint32_t slot;
        uint32_t row = mode == RAW_ORDER_INTERIOR && i != 0 ? 3 - i : i;
        char name[3] = { 'f', (char)('0' + i), 0 };

        libmpq__file_hash(name, &h1, &h2, &h3);
        slot = h1 % 8;
        while (libmpq__load_le32(hashes + slot * 16 + 12) != UINT32_MAX)
            slot = (slot + 1) % 8;
        libmpq__store_le32(hashes + slot * 16, h2);
        libmpq__store_le32(hashes + slot * 16 + 4, h3);
        libmpq__store_le32(hashes + slot * 16 + 8, 0);
        libmpq__store_le32(hashes + slot * 16 + 12, mode == RAW_SHARED && i == 1 ? 0 : row);
        libmpq__store_le32(blocks + i * 16, offsets[i]);
        libmpq__store_le32(blocks + i * 16 + 4, lengths[i]);
        libmpq__store_le32(blocks + i * 16 + 8, lengths[i]);
        libmpq__store_le32(blocks + i * 16 + 12, flags[i]);
    }
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            hashes, 128, libmpq__crypto_hash_string("(hash table)", 0x300)
        ) == 0
    );
    TEST_CHECK(
        libmpq__crypto_encrypt_block(
            blocks, 48, libmpq__crypto_hash_string("(block table)", 0x300)
        ) == 0
    );
    libmpq__store_le32(header, 0x1a51504d);
    libmpq__store_le32(header + 4, 208);
    libmpq__store_le32(header + 8, (uint32_t)extent);
    libmpq__store_le16(header + 12, 3);
    libmpq__store_le16(header + 14, 3);
    libmpq__store_le32(header + 16, 208);
    libmpq__store_le32(header + 20, 336);
    libmpq__store_le32(header + 24, 8);
    libmpq__store_le32(header + 28, 3);
    libmpq__store_le64(header + 44, extent);
    libmpq__store_le64(header + 68, 128);
    libmpq__store_le64(header + 76, 48);
    libmpq__store_le32(header + 108, chunk);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, blocks, 48);
    libmpq__md5_final(&md5, header + 112);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, hashes, 128);
    libmpq__md5_final(&md5, header + 128);
    libmpq__md5_init(&md5);
    libmpq__md5_update(&md5, header, 192);
    libmpq__md5_final(&md5, header + 192);
    image->size = base + extent;
    return 0;
}

/* Legacy results are controls; extended failures must clear every coverage output. */
static int
test_raw_layout(unsigned mode, uint32_t chunk, size_t base)
{
    raw_image_s image;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    struct mpq_raw_index *index;
    uint32_t checked = UINT32_MAX;
    uint32_t unavailable = UINT32_MAX;
    uint32_t bits = UINT32_MAX;
    uint32_t alias;
    int malformed = mode == RAW_START || mode == RAW_INTERIOR || mode == RAW_ORDER_START ||
                    mode == RAW_ORDER_INTERIOR || mode == RAW_END || mode == RAW_PARTIAL ||
                    mode == RAW_NESTED;
    uint32_t mismatch = mode == RAW_CORRUPT || mode == RAW_ZEROS || mode == RAW_PADDING ? 8 : 0;
    uint32_t applicable = chunk != 0 && mode != RAW_EMPTY && mode != RAW_DELETE ? 8 : 0;
    int32_t status;

    TEST_CHECK(raw_image_build(&image, mode, chunk, base) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &image, raw_image_read, (libmpq__off_t)image.size, -1, NULL
        ) == 0
    );
    TEST_CHECK(archive->archive_offset == (libmpq__off_t)base);
    TEST_CHECK(archive->raw_index == NULL);
    status = libmpq__file_verify_ex(archive, 0, NULL, 8, &checked, &unavailable, &bits);
    TEST_CHECK(status == (malformed && applicable ? LIBMPQ_ERROR_FORMAT : 0));
    TEST_CHECK(checked == (malformed ? 0 : applicable));
    TEST_CHECK(unavailable == (malformed ? 0 : 8u & ~applicable));
    TEST_CHECK(bits == (malformed || !applicable ? 0 : mismatch));
    status = libmpq__file_verify(archive, 0, 8, &bits);
    TEST_CHECK(status == (mode == RAW_END || mode == RAW_PARTIAL ? LIBMPQ_ERROR_FORMAT : 0));
    TEST_CHECK(bits == (mode == RAW_START || mismatch ? 8u : 0));
    if (!malformed && applicable) {
        index = archive->raw_index;
        TEST_CHECK(index != NULL && index->references == 1);
        TEST_CHECK(libmpq__archive_clone(&clone, archive) == 0);
        TEST_CHECK(clone->raw_index == index && index->references == 2);
        TEST_CHECK(libmpq__file_verify_ex(archive, 0, "f0", 8, &checked, &unavailable, &bits) == 0);
        TEST_CHECK(archive->raw_index == index && index->references == 2);
        TEST_CHECK(checked == 8 && unavailable == 0 && bits == mismatch);
        if (mode == RAW_SHARED) {
            TEST_CHECK(
                libmpq__file_number_from_identity(archive, "f1", 0, 0, &alias) == 0 && alias == 0
            );
            TEST_CHECK(
                libmpq__file_verify_ex(archive, alias, "f1", 8, &checked, &unavailable, &bits) == 0
            );
            TEST_CHECK(checked == 8 && unavailable == 0 && bits == 0);
        }
        TEST_CHECK(libmpq__archive_close(archive) == 0);
        archive = NULL;
        TEST_CHECK(index->references == 1);
        TEST_CHECK(libmpq__file_verify_ex(clone, 0, NULL, 8, &checked, &unavailable, &bits) == 0);
        TEST_CHECK(checked == 8 && unavailable == 0 && bits == mismatch);
        TEST_CHECK(libmpq__archive_close(clone) == 0);
    } else {
        TEST_CHECK(libmpq__archive_close(archive) == 0);
    }
    return 0;
}

static size_t raw_allocation_size;

/* Fail only the injected index allocation, without replacing process-global malloc. */
static void *
raw_allocation_fail(size_t size)
{
    raw_allocation_size = size;
    return NULL;
}

/* Close the underlying adapter but still report its finalization error. */
static int32_t
raw_close_failure(void *context)
{
    read_failure_s *failure = context;

    failure->reads++;
    if (failure->backend.close != NULL)
        (void)failure->backend.close(failure->backend.context);
    return LIBMPQ_ERROR_CLOSE;
}

/* Cover failed construction, retries, shared lifetime and clone failure cleanup. */
static int
test_raw_index_failures(void)
{
    raw_image_s image;
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    struct mpq_raw_index *index;
    uint32_t checked = UINT32_MAX;
    uint32_t unavailable = UINT32_MAX;
    uint32_t bits = UINT32_MAX;
    uint64_t reads;
    uint64_t old_offset;
    uint32_t old_count;

    TEST_CHECK(raw_image_build(&image, RAW_VALID, 17, 0) == 0);
    TEST_CHECK(
        libmpq__archive_open_io(
            &archive, &image, raw_image_read, (libmpq__off_t)image.size, 0, NULL
        ) == 0
    );
    reads = image.reads;
    TEST_CHECK(
        libmpq__verify_file_ex(
            archive, 0, NULL, 8, &checked, &unavailable, &bits, raw_allocation_fail
        ) == LIBMPQ_ERROR_MALLOC
    );
    TEST_CHECK(checked == 0 && unavailable == 0 && bits == 0 && archive->raw_index == NULL);
    TEST_CHECK(
        raw_allocation_size == sizeof(struct mpq_raw_index) + 9 * sizeof(mpq_raw_interval_s)
    );
    TEST_CHECK(image.reads == reads);
    old_offset = archive->mpq_entry[1].offset;
    archive->mpq_entry[1].offset = UINT64_MAX;
    TEST_CHECK(
        libmpq__verify_file_ex(archive, 0, NULL, 8, &checked, &unavailable, &bits, malloc) ==
        LIBMPQ_ERROR_FORMAT
    );
    TEST_CHECK(checked == 0 && unavailable == 0 && bits == 0 && archive->raw_index == NULL);
    archive->mpq_entry[1].offset = old_offset;
    old_count = archive->entry_count;
    archive->entry_count = UINT32_MAX;
    TEST_CHECK(
        libmpq__verify_file_ex(
            archive, 0, NULL, 8, &checked, &unavailable, &bits, raw_allocation_fail
        ) == (((uint64_t)UINT32_MAX + 6 >
               (SIZE_MAX - sizeof(struct mpq_raw_index)) / sizeof(mpq_raw_interval_s))
                  ? LIBMPQ_ERROR_SIZE
                  : LIBMPQ_ERROR_MALLOC)
    );
    TEST_CHECK(checked == 0 && unavailable == 0 && bits == 0 && archive->raw_index == NULL);
    archive->entry_count = old_count;
    TEST_CHECK(libmpq__file_verify_ex(archive, 0, NULL, 8, &checked, &unavailable, &bits) == 0);
    TEST_CHECK(checked == 8 && unavailable == 0 && bits == 0);
    index = archive->raw_index;
    index->references = SIZE_MAX;
    TEST_CHECK(libmpq__archive_clone(&clone, archive) == LIBMPQ_ERROR_SIZE && clone == NULL);
    index->references = 1;
    image.fail = 1;
    TEST_CHECK(
        libmpq__file_verify_ex(archive, 0, "f0", 8, &checked, &unavailable, &bits) ==
        LIBMPQ_ERROR_READ
    );
    TEST_CHECK(checked == 0 && unavailable == 0 && bits == 0);
    TEST_CHECK(archive->raw_index == index && index->references == 1);
    image.fail = 0;
    TEST_CHECK(
        libmpq__verify_file_ex(
            archive, 0, NULL, 8, &checked, &unavailable, &bits, raw_allocation_fail
        ) == 0
    );
    TEST_CHECK(checked == 8 && unavailable == 0 && bits == 0 && archive->raw_index == index);
    {
        read_failure_s failure;

        failure.reads = 0;
        failure_install(archive->source, &failure, fail_read);
        archive->source->backend.close = raw_close_failure;
        TEST_CHECK(libmpq__archive_close(archive) == LIBMPQ_ERROR_CLOSE);
        TEST_CHECK(failure.reads == 1);
    }
    return 0;
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
    uint32_t value = UINT32_MAX;
    static const size_t sizes[] = { 0, 1, 37, 512, 513, 8229 };
    static const uint32_t storage[] = { 0,
                                        LIBMPQ_FILE_FLAG_SINGLE,
                                        LIBMPQ_FILE_FLAG_COMPRESS,
                                        LIBMPQ_FILE_FLAG_IMPLODE,
                                        LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE,
                                        LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_SINGLE,
                                        LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                        LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED };

    for (unsigned mode = RAW_VALID; mode <= RAW_NESTED; ++mode)
        for (size_t base = 0; base <= 512; base += 512)
            TEST_CHECK(test_raw_layout(mode, 17, base) == 0);
    for (size_t i = 0; i < 4; i++) {
        static const uint32_t chunks[] = { 1, 17, 0x4000, UINT32_MAX };
        TEST_CHECK(test_raw_layout(RAW_VALID, chunks[i], 0) == 0);
    }
    TEST_CHECK(test_raw_layout(RAW_VALID, 0, 0) == 0);
    TEST_CHECK(test_raw_index_failures() == 0);
    TEST_CHECK(check_block_error(NULL, 0, 0, LIBMPQ_ERROR_EXIST) == 0);
    for (version = 0; version <= 3; ++version)
        TEST_CHECK(test_verification_coverage(version) == 0);
    TEST_CHECK(test_single_compression(0) == 0);
    TEST_CHECK(test_single_compression(1) == 0);
    TEST_CHECK(test_short_encrypted_stream() == 0);
    TEST_CHECK(libmpq__block_compression(NULL, 0, 0, &value) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(value == 0);
    {
        libmpq__off_t packed_size = -1;
        TEST_CHECK(libmpq__block_size_packed(NULL, 0, 0, &packed_size) == LIBMPQ_ERROR_EXIST);
        TEST_CHECK(packed_size == 0);
    }
    TEST_CHECK(libmpq__block_verify(NULL, 0, 0, NULL, &value) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(value == 0);
    value = UINT32_MAX;
    TEST_CHECK(libmpq__block_verify(NULL, 0, 0, &value, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(value == 0);
    for (version = 0; version <= 1; ++version)
        for (encrypted = 0; encrypted <= 1; ++encrypted)
            for (compressed = 0; compressed <= 1; ++compressed)
                for (corrupt = 0; corrupt <= (LIBMPQ_VERIFY_ALL & ~LIBMPQ_VERIFY_RAW_MD5);
                     ++corrupt)
                    TEST_CHECK(test_sectors(version, encrypted, compressed, corrupt, 1, 0) == 0);
    for (absent = 0; absent <= 3; ++absent)
        TEST_CHECK(test_sectors(1, 1, 1, LIBMPQ_VERIFY_SECTOR_CRC, 0, absent) == 0);
    TEST_CHECK(test_sectors(1, 0, 1, 0, 0, 0) == 0);
    for (version = 0; version <= 1; ++version)
        for (i = 0; i < sizeof(storage) / sizeof(storage[0]); ++i)
            for (j = 0; j < sizeof(sizes) / sizeof(sizes[0]); ++j)
                TEST_CHECK(test_writer_checksums(version, storage[i], sizes[j], 0) == 0);
    TEST_CHECK(
        test_writer_checksums(1, LIBMPQ_FILE_FLAG_IMPLODE | LIBMPQ_FILE_FLAG_ENCRYPTED, 8229, 1) ==
        0
    );
    TEST_CHECK(test_writer_checksums(1, LIBMPQ_FILE_FLAG_ENCRYPTED, 8229, 0) == 0);
    return 0;
}
