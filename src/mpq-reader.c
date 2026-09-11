/*
 *  mpq-reader.c -- internal archive reader implementation.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "mpq-platform.h"
#include "mpq-reader.h"
#include "mpq-stream.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>

/* Release a cached block offset table when the last user closes it.
 * Reference counting permits nested block operations while ensuring the cache
 * is freed only after the final matching close. */
int32_t
libmpq__reader_offsets_release(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    mpq_archive->mpq_file[file_number]->open_count--;

    if (mpq_archive->mpq_file[file_number]->open_count != 0) {

        /* Keep the cache alive until every matching open operation closes. */
        return LIBMPQ_SUCCESS;
    }

    free(mpq_archive->mpq_file[file_number]->packed_offset);
    free(mpq_archive->mpq_file[file_number]);

    mpq_archive->mpq_file[file_number] = NULL;

    return LIBMPQ_SUCCESS;
}

/* Read a complete file by opening its block offset table and copying each block.
 * The output buffer must hold the complete unpacked file, and cached offset
 * state is closed on both successful and failed block reads. */
int32_t
libmpq__reader_file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
)
{

    /* Block loop state and total bytes transferred to the caller. */
    uint32_t i;
    uint32_t blocks = 0;
    int32_t result = 0;
    libmpq__off_t file_offset = 0;
    libmpq__off_t unpacked_size = 0;
    libmpq__off_t transferred_block = 0;
    libmpq__off_t transferred_total = 0;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    libmpq__file_size_unpacked(mpq_archive, file_number, &unpacked_size);

    if (unpacked_size > out_size) {
        return LIBMPQ_ERROR_SIZE;
    }

    libmpq__file_offset(mpq_archive, file_number, &file_offset);
    libmpq__file_blocks(mpq_archive, file_number, &blocks);

    if ((result = libmpq__reader_offsets_acquire(mpq_archive, file_number, NULL)) < 0) {
        return result;
    }

    /* Read each block into its exact destination slice and maintain one total. */
    for (i = 0; i < blocks; i++) {
        unpacked_size = 0;

        libmpq__block_size_unpacked(mpq_archive, file_number, i, &unpacked_size);

        if ((result = libmpq__block_read(
                 mpq_archive, file_number, i, out_buf + transferred_total, unpacked_size,
                 &transferred_block
             )) < 0) {
            libmpq__reader_offsets_release(mpq_archive, file_number);
            return result;
        }

        transferred_total += transferred_block;
    }

    libmpq__reader_offsets_release(mpq_archive, file_number);

    if (transferred != NULL) {
        *transferred = transferred_total;
    }

    return LIBMPQ_SUCCESS;
}

/* Metadata-only sizes need no decryption key. For sectorized codec files,
 * reuse the reader's parsed offsets and exclude the checksum-table extent. */
int32_t
libmpq__reader_block_size_packed(
    mpq_archive_s *archive, uint32_t number, uint32_t block, libmpq__off_t *size
)
{
    uint32_t index;
    uint32_t flags;
    uint64_t start = 0;
    uint64_t length;
    int32_t status;

    if (size != NULL)
        *size = 0;
    if (archive == NULL || size == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (archive->write_mode)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (libmpq__reader_validate_file_number(archive, number) < 0 ||
        libmpq__reader_validate_block_number(archive, number, block) < 0)
        return LIBMPQ_ERROR_EXIST;
    index = archive->mpq_map[number].block_table_indices;
    flags = archive->mpq_block[index].flags;
    if ((flags & LIBMPQ_FLAG_SINGLE) != 0) {
        length = archive->mpq_block[index].packed_size;
    } else if ((flags & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0) {
        libmpq__off_t unpacked;
        status = libmpq__block_size_unpacked(archive, number, block, &unpacked);
        if (status < 0)
            return status;
        start = (uint64_t)block * archive->block_size;
        length = (uint64_t)unpacked;
    } else {
        uint32_t end;
        status = libmpq__reader_offsets_acquire(archive, number, NULL);
        if (status < 0)
            return status;
        start = archive->mpq_file[number]->packed_offset[block];
        end = archive->mpq_file[number]->packed_offset[block + 1U];
        status = libmpq__reader_offsets_release(archive, number);
        if (status < 0)
            return status;
        if (end < start)
            return LIBMPQ_ERROR_FORMAT;
        length = end - start;
    }
    if (start > archive->mpq_block[index].packed_size ||
        length > archive->mpq_block[index].packed_size - start)
        return LIBMPQ_ERROR_FORMAT;
    status = libmpq__reader_validate_payload_range(archive, index, start, length);
    if (status < 0)
        return status;
    *size = (libmpq__off_t)length;
    return LIBMPQ_SUCCESS;
}

/* Sector checksums follow packed sectors and are not encrypted, even when
 * file data is encrypted. Reuse the offset table loaded by open_named(). */
static int32_t sector_checksums(mpq_archive_s *archive, uint32_t number, uint32_t **checksums);

int32_t
libmpq__reader_sector_checksums(mpq_archive_s *archive, uint32_t number, uint32_t **checksums)
{
    int32_t result = libmpq__reader_offsets_acquire(archive, number, NULL);
    *checksums = NULL;
    if (result < 0)
        return result;
    result = sector_checksums(archive, number, checksums);
    (void)libmpq__reader_offsets_release(archive, number);
    return result;
}

static int32_t
sector_checksums(mpq_archive_s *archive, uint32_t number, uint32_t **checksums)
{
    uint32_t index = archive->mpq_map[number].block_table_indices;
    uint32_t flags = archive->mpq_block[index].flags;
    uint32_t blocks = libmpq__reader_count_file_blocks(archive, number);
    uint32_t start;
    uint32_t end;
    uint32_t packed_size;
    size_t size;
    uint64_t offset;
    uint8_t *packed = NULL;
    uint32_t *table = NULL;
    int32_t status;

    *checksums = NULL;
    if (blocks == 0 || (flags & LIBMPQ_FLAG_CRC) == 0 || (flags & LIBMPQ_FLAG_SINGLE) != 0 ||
        (flags & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) == 0)
        return LIBMPQ_SUCCESS;
    if (archive->mpq_file[number] == NULL ||
        archive->mpq_file[number]->packed_offset_count != blocks + 1)
        return LIBMPQ_ERROR_OPEN;

    /* The existing parser allocates and decodes one extra offset for CRC files. */
    start = archive->mpq_file[number]->packed_offset[blocks];
    end = archive->mpq_file[number]->packed_offset[blocks + 1];
    if (end == 0 || end == start)
        return LIBMPQ_SUCCESS;
    if (end < start || end > archive->mpq_block[index].packed_size)
        return LIBMPQ_ERROR_FORMAT;
    if ((uint64_t)blocks * sizeof(uint32_t) > INT32_MAX ||
        (uint64_t)blocks * sizeof(uint32_t) > SIZE_MAX)
        return LIBMPQ_ERROR_SIZE;
    size = (size_t)blocks * sizeof(uint32_t);
    packed_size = end - start;
    if (packed_size > size)
        return LIBMPQ_ERROR_FORMAT;
    status = libmpq__reader_validate_payload_range(archive, index, start, packed_size);
    if (status < 0)
        return status;
    offset = (uint64_t)archive->archive_offset + archive->mpq_block[index].offset +
             ((uint64_t)archive->mpq_block_ex[index].offset_high << 32) + start;
    packed = malloc(packed_size);
    table = malloc(size);
    if (packed == NULL || table == NULL) {
        status = LIBMPQ_ERROR_MALLOC;
        goto cleanup;
    }
    status = libmpq__stream_read_at(archive->stream, offset, packed, packed_size);
    if (status < 0)
        goto cleanup;
    status = libmpq__compression_decompress_block(
        packed, packed_size, (uint8_t *)table, size, LIBMPQ_FLAG_COMPRESS_MULTI,
        archive->mpq_header.version
    );
    if (status < 0 || (uint64_t)status != size) {
        status = LIBMPQ_ERROR_FORMAT;
        goto cleanup;
    }
    libmpq__reader_decode_uint32_table(table, (const uint8_t *)table, blocks);
    *checksums = table;
    table = NULL;
    status = LIBMPQ_SUCCESS;
cleanup:
    free(table);
    free(packed);
    return status;
}

/* Read, decrypt and decompress one block from an opened file entry.
 * The routine computes packed bounds, applies per-block encryption, selects
 * raw or codec output, and reports the exact unpacked byte count. */
static int32_t read_block(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint8_t *buffer, libmpq__off_t size,
    libmpq__off_t *transferred, const uint32_t *checksum, uint32_t *mismatches
);

int32_t
libmpq__reader_block_read(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint8_t *buffer, libmpq__off_t size,
    libmpq__off_t *transferred, const uint32_t *checksum, uint32_t *mismatches
)
{
    int32_t result;
    if (libmpq__reader_validate_block_number(archive, number, block) < 0)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__reader_offsets_acquire(archive, number, NULL);
    if (result < 0)
        return result;
    result = read_block(archive, number, block, buffer, size, transferred, checksum, mismatches);
    (void)libmpq__reader_offsets_release(archive, number);
    return result;
}

static int32_t
read_block(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred, const uint32_t *checksum,
    uint32_t *mismatches
)
{

    /* Packed input buffer, size bookkeeping and block decryption state. */
    uint8_t *in_buf;
    uint32_t seed = 0;
    uint32_t encrypted = 0;
    uint32_t compressed = 0;
    uint32_t imploded = 0;
    int32_t tb = 0;
    uint8_t use_out_buf = FALSE;
    libmpq__off_t block_offset = 0;
    libmpq__off_t in_size = 0;
    libmpq__off_t unpacked_size = 0;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (libmpq__reader_validate_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    libmpq__block_size_unpacked(mpq_archive, file_number, block_number, &unpacked_size);

    if (unpacked_size > out_size) {
        return LIBMPQ_ERROR_SIZE;
    }

    /* Compute the absolute payload position from archive, file, and block offsets.
     * The stored block offset is relative to the file payload start, not the
     * beginning of the archive file. */
    if (mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] <
            mpq_archive->mpq_file[file_number]->packed_offset[block_number] ||
        mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] >
            mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                .packed_size) {
        return LIBMPQ_ERROR_FORMAT;
    }
    in_size = mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] -
              mpq_archive->mpq_file[file_number]->packed_offset[block_number];
    if (libmpq__reader_validate_payload_range(
            mpq_archive, mpq_archive->mpq_map[file_number].block_table_indices,
            mpq_archive->mpq_file[file_number]->packed_offset[block_number], (uint64_t)in_size
        ) < 0) {
        return LIBMPQ_ERROR_READ;
    }
    block_offset =
        mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].offset +
        (((long long)mpq_archive
              ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
              .offset_high)
         << 32) +
        mpq_archive->mpq_file[file_number]->packed_offset[block_number];

    libmpq__file_encrypted(mpq_archive, file_number, &encrypted);
    libmpq__file_compressed(mpq_archive, file_number, &compressed);
    libmpq__file_imploded(mpq_archive, file_number, &imploded);

    /* Raw unencrypted blocks can be read directly into the caller's buffer. */
    use_out_buf = !encrypted && !compressed && !imploded && in_size <= out_size;

    if (use_out_buf) {

        /* Raw data can bypass a temporary allocation when no transform is needed. */
        in_buf = out_buf;
    } else {
        if ((in_buf = calloc(1, in_size)) == NULL) {
            return LIBMPQ_ERROR_MALLOC;
        }
    }

    if ((tb = libmpq__stream_read_at(
             mpq_archive->stream, (uint64_t)block_offset + (uint64_t)mpq_archive->archive_offset,
             in_buf, (size_t)in_size
         )) < 0) {
        if (!use_out_buf) {
            free(in_buf);
        }
        return tb;
    }

    if (encrypted) {

        /* Encrypted blocks use a seed derived from the file and block number. */
        if (libmpq__reader_get_block_seed(mpq_archive, file_number, block_number, &seed) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_DECRYPT;
        }

        if (libmpq__crypto_decrypt_block(in_buf, (uint32_t)in_size, seed) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_DECRYPT;
        }
    }

    /* MPQ sector CRCs are Adler-32 over decrypted packed bytes, not CRC32.
     * Zero and all-ones entries are unavailable legacy checksum values. */
    if (checksum != NULL && *checksum != 0 && *checksum != UINT32_MAX &&
        (uint32_t)adler32(0, in_buf, (uInt)in_size) != *checksum)
        *mismatches |= LIBMPQ_VERIFY_SECTOR_CRC;

    /* Blizzard multi-compression blocks declare their exact backend chain in the payload. */
    if (compressed) {

        /* The payload's leading mask selects and orders its decompression stages. */
        if ((tb = libmpq__compression_decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI,
                 mpq_archive->mpq_header.version
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    /* PKWARE-imploded blocks use the legacy explode decoder. */
    if (imploded) {

        /* Standalone PKWARE payloads use the legacy decoder without a mask byte. */
        if ((tb = libmpq__compression_decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKZIP,
                 mpq_archive->mpq_header.version
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    if (compressed && imploded) {
        if (!use_out_buf) {
            free(in_buf);
        }
        return LIBMPQ_ERROR_UNPACK;
    }

    if (!compressed && !imploded) {

        /* A raw block is copied only after encrypted and compressed paths are excluded. */
        if ((tb = libmpq__compression_decompress_block(
                 in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE,
                 mpq_archive->mpq_header.version
             )) < 0) {
            if (!use_out_buf) {
                free(in_buf);
            }
            return LIBMPQ_ERROR_UNPACK;
        }
    }

    if (!use_out_buf) {
        free(in_buf);
    }

    if (transferred != NULL) {
        *transferred = tb;
    }

    return LIBMPQ_SUCCESS;
}

/* Verify that a file payload subrange is both internally consistent and
 * contained in the physical backing file captured when the archive opened.
 * Sector offsets and block-table sizes are archive-controlled, so this check
 * must happen before using either value for allocation or stream reads. */
int32_t
libmpq__reader_validate_payload_range(
    const mpq_archive_s *mpq_archive, uint32_t block_table_index, uint64_t relative_offset,
    uint64_t size
)
{
    uint64_t payload_offset;
    uint64_t absolute_offset;

    if (mpq_archive->archive_offset < 0) {
        return LIBMPQ_ERROR_FORMAT;
    }

    payload_offset = ((uint64_t)mpq_archive->mpq_block_ex[block_table_index].offset_high << 32) |
                     mpq_archive->mpq_block[block_table_index].offset;
    absolute_offset = (uint64_t)mpq_archive->archive_offset;
    if (payload_offset > UINT64_MAX - absolute_offset) {
        return LIBMPQ_ERROR_FORMAT;
    }
    absolute_offset += payload_offset;
    if (relative_offset > UINT64_MAX - absolute_offset) {
        return LIBMPQ_ERROR_FORMAT;
    }
    absolute_offset += relative_offset;
    if (absolute_offset > mpq_archive->file_size ||
        size > mpq_archive->file_size - absolute_offset) {
        return LIBMPQ_ERROR_READ;
    }

    return LIBMPQ_SUCCESS;
}

/* Open a file entry and cache its packed block offset table for block operations.
 * Compressed entries load and decrypt their serialized offsets, while raw or
 * single-unit entries receive synthesized offsets from block metadata. */
int32_t
libmpq__reader_offsets_acquire(mpq_archive_s *mpq_archive, uint32_t file_number, const char *name)
{

    /* Packed block table state, file seed and read status. */
    uint32_t blocks;
    uint32_t i;
    uint32_t block_table_index;
    uint32_t packed_offset_count;
    uint32_t packed_size;
    int32_t result = 0;
    uint8_t *packed_data = NULL;

    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number]) {

        /* A named internal read can supply a key to an anonymous cached open. */
        if (name != NULL && !mpq_archive->mpq_file[file_number]->seed_known) {
            uint32_t index = mpq_archive->mpq_map[file_number].block_table_indices;
            uint32_t seed = libmpq__crypto_hash_string(name, 0x300);
            if (mpq_archive->mpq_block[index].flags & 0x00020000u)
                seed = (seed + mpq_archive->mpq_block[index].offset) ^
                       mpq_archive->mpq_block[index].unpacked_size;
            mpq_archive->mpq_file[file_number]->seed = seed;
            mpq_archive->mpq_file[file_number]->seed_known = TRUE;
        }

        /* Nested callers share the cached offsets through a reference count. */
        mpq_archive->mpq_file[file_number]->open_count++;
        return LIBMPQ_SUCCESS;
    }

    block_table_index = mpq_archive->mpq_map[file_number].block_table_indices;
    blocks = libmpq__reader_count_file_blocks(mpq_archive, file_number);
    if (blocks > UINT32_MAX / sizeof(uint32_t) - 2U) {
        return LIBMPQ_ERROR_FORMAT;
    }
    packed_offset_count = blocks + 1;
    packed_size = sizeof(uint32_t) * packed_offset_count;

    if ((mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_CRC) != 0) {
        packed_size += sizeof(uint32_t);
    }

    if ((mpq_archive->mpq_file[file_number] = calloc(1, sizeof(mpq_file_s))) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    if ((mpq_archive->mpq_file[file_number]->packed_offset = calloc(1, packed_size)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    mpq_archive->mpq_file[file_number]->packed_offset_count = packed_offset_count;
    mpq_archive->mpq_file[file_number]->open_count = 1;

    if (name != NULL) {
        uint32_t seed = libmpq__crypto_hash_string(name, 0x300);
        if (mpq_archive->mpq_block[block_table_index].flags & 0x00020000u)
            seed = (seed + mpq_archive->mpq_block[block_table_index].offset) ^
                   mpq_archive->mpq_block[block_table_index].unpacked_size;
        mpq_archive->mpq_file[file_number]->seed = seed;
        mpq_archive->mpq_file[file_number]->seed_known = TRUE;
    }

    /* Compressed multi-sector files carry serialized offsets before their first
     * payload, so load that table before any block can be read. */
    if ((mpq_archive->mpq_block[block_table_index].flags &
         (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP)) != 0 &&
        (mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_SINGLE) == 0) {
        if (mpq_archive->mpq_block[block_table_index].packed_size < packed_size ||
            libmpq__reader_validate_payload_range(mpq_archive, block_table_index, 0, packed_size) <
                0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((packed_data = malloc(packed_size)) == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }
        if ((result = libmpq__stream_read_at(
                 mpq_archive->stream,
                 mpq_archive->mpq_block[block_table_index].offset +
                     ((uint64_t)mpq_archive->mpq_block_ex[block_table_index].offset_high << 32) +
                     (uint64_t)mpq_archive->archive_offset,
                 packed_data, packed_size
             )) < 0) {
            goto error;
        }

        /* Some protected archives omit the encrypted flag; a wrong first offset exposes that. */
        if (libmpq__load_le32(packed_data) != packed_size &&
            libmpq__load_le32(packed_data) != packed_size + 4) {
            mpq_archive->mpq_block[block_table_index].flags |= LIBMPQ_FLAG_ENCRYPTED;
        }

        /* The packed offset table uses seed - 1, so recover the file seed first. */
        if (mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_ENCRYPTED) {
            uint32_t seed = mpq_archive->mpq_file[file_number]->seed;

            if (!mpq_archive->mpq_file[file_number]->seed_known &&
                libmpq__crypto_derive_block_table_seed(
                    packed_data, packed_size, mpq_archive->block_size, &seed
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
            mpq_archive->mpq_file[file_number]->seed = seed;
            mpq_archive->mpq_file[file_number]->seed_known = TRUE;

            if (libmpq__crypto_decrypt_block(
                    packed_data, packed_size, mpq_archive->mpq_file[file_number]->seed - 1
                ) < 0) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }

            /* A valid decrypted table starts with its own byte size. */
            if (libmpq__load_le32(packed_data) != packed_size) {
                result = LIBMPQ_ERROR_DECRYPT;
                goto error;
            }
        }

        libmpq__reader_decode_uint32_table(
            mpq_archive->mpq_file[file_number]->packed_offset, packed_data,
            packed_size / sizeof(uint32_t)
        );
        if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        for (i = 1; i < packed_offset_count; i++) {
            if (mpq_archive->mpq_file[file_number]->packed_offset[i] <
                    mpq_archive->mpq_file[file_number]->packed_offset[i - 1] ||
                mpq_archive->mpq_file[file_number]->packed_offset[i] >
                    mpq_archive->mpq_block[block_table_index].packed_size) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }
        }
        free(packed_data);
        packed_data = NULL;
    } else {

        /* Raw sectorized files derive offsets directly from their fixed sector size. */
        if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
             LIBMPQ_FLAG_SINGLE) == 0) {

            /* Synthesize offsets for uncompressed multi-sector files. */
            for (i = 0; i < packed_offset_count; i++) {
                if (i == blocks) {
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        mpq_archive
                            ->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                            .unpacked_size;
                } else {
                    mpq_archive->mpq_file[file_number]->packed_offset[i] =
                        i * mpq_archive->block_size;
                }
            }
        } else {
            mpq_archive->mpq_file[file_number]->packed_offset[0] = 0;
            mpq_archive->mpq_file[file_number]->packed_offset[1] =
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .packed_size;
        }
    }

    /* Raw encrypted files have no encrypted offset table from which to derive a seed. */
    if ((mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices].flags &
         (LIBMPQ_FLAG_ENCRYPTED | LIBMPQ_FLAG_COMPRESSED)) == LIBMPQ_FLAG_ENCRYPTED &&
        !mpq_archive->mpq_file[file_number]->seed_known) {
        uint8_t first_block[8];
        uint32_t first_offset;
        uint32_t second_offset;
        uint32_t first_size;
        uint32_t seed;

        if (packed_offset_count < 2) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        first_offset = mpq_archive->mpq_file[file_number]->packed_offset[0];
        second_offset = mpq_archive->mpq_file[file_number]->packed_offset[1];
        if (second_offset < first_offset) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }

        first_size = second_offset - first_offset;
        if (first_size < sizeof(first_block)) {
            result = LIBMPQ_ERROR_DECRYPT;
            goto error;
        }

        if ((result = libmpq__stream_read_at(
                 mpq_archive->stream,
                 mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                         .offset +
                     ((uint64_t)mpq_archive
                          ->mpq_block_ex[mpq_archive->mpq_map[file_number].block_table_indices]
                          .offset_high
                      << 32) +
                     (uint64_t)mpq_archive->archive_offset,
                 first_block, sizeof(first_block)
             )) < 0) {
            goto error;
        }

        /* Raw encrypted payloads require signature-based key recovery instead. */
        if (libmpq__crypto_detect_file_key(
                first_block, sizeof(first_block),
                mpq_archive->mpq_block[mpq_archive->mpq_map[file_number].block_table_indices]
                    .unpacked_size,
                &seed
            ) < 0) {
            result = LIBMPQ_ERROR_DECRYPT;
            goto error;
        }

        mpq_archive->mpq_file[file_number]->seed = seed;
        mpq_archive->mpq_file[file_number]->seed_known = TRUE;
    }

    return LIBMPQ_SUCCESS;

error:

    free(packed_data);

    if (mpq_archive->mpq_file[file_number] != NULL) {
        free(mpq_archive->mpq_file[file_number]->packed_offset);
        free(mpq_archive->mpq_file[file_number]);
        mpq_archive->mpq_file[file_number] = NULL;
    }

    return result;
}

/* Calculate a serialized table size while rejecting arithmetic overflow.
 * MPQ table lengths are stored in 32-bit fields, so both native allocation
 * size and on-disk representation must fit before the caller proceeds. */
static int32_t
table_size(uint32_t count, size_t item_size, size_t *size)
{
    if (item_size == 0 || count > SIZE_MAX / item_size || (size_t)count * item_size > UINT32_MAX) {
        return LIBMPQ_ERROR_FORMAT;
    }

    *size = (size_t)count * item_size;
    return LIBMPQ_SUCCESS;
}

/* Decode the fixed MPQ v1 header from its little-endian byte representation.
 * The helper performs no validation; callers validate version, offsets, and
 * counts after all header fields have been loaded. */
static void
decode_mpq_header(mpq_header_s *header, const uint8_t *raw)
{
    header->mpq_magic = libmpq__load_le32(raw + 0);
    header->header_size = libmpq__load_le32(raw + 4);
    header->archive_size = libmpq__load_le32(raw + 8);
    header->version = libmpq__load_le16(raw + 12);
    header->block_size = libmpq__load_le16(raw + 14);
    header->hash_table_offset = libmpq__load_le32(raw + 16);
    header->block_table_offset = libmpq__load_le32(raw + 20);
    header->hash_table_count = libmpq__load_le32(raw + 24);
    header->block_table_count = libmpq__load_le32(raw + 28);
}

/* Decode the optional MPQ v2 high-offset header extension.
 * Its fields extend table and archive offsets without changing the v1 header
 * layout, so they are loaded separately when the archive version requires it. */
static void
decode_mpq_header_ex(mpq_header_ex_s *header, const uint8_t *raw)
{
    header->extended_offset = libmpq__load_le64(raw + 0);
    header->hash_table_offset_high = libmpq__load_le16(raw + 8);
    header->block_table_offset_high = libmpq__load_le16(raw + 10);
}

/* Decode the encrypted hash-table entries into native archive structures.
 * Each entry is read field-by-field to avoid alignment and host-endian
 * assumptions when the library runs on a different architecture. */
static void
decode_mpq_hash_table(mpq_hash_s *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    if (table == 0 || raw == 0)
        return;
    for (i = 0; i < count; i++) {
        const uint8_t *entry = raw + i * sizeof(mpq_hash_s);

        table[i].hash_a = libmpq__load_le32(entry + 0);
        table[i].hash_b = libmpq__load_le32(entry + 4);
        table[i].locale = libmpq__load_le16(entry + 8);
        table[i].platform = libmpq__load_le16(entry + 10);
        table[i].block_table_index = libmpq__load_le32(entry + 12);
    }
}

/* Decode the fixed-width block table used by MPQ v1 and v2 archives.
 * The high offset words are handled separately by the extended-table helper. */
static void
decode_mpq_block_table(mpq_block_s *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    if (table == 0 || raw == 0)
        return;
    for (i = 0; i < count; i++) {
        const uint8_t *entry = raw + i * sizeof(mpq_block_s);

        table[i].offset = libmpq__load_le32(entry + 0);
        table[i].packed_size = libmpq__load_le32(entry + 4);
        table[i].unpacked_size = libmpq__load_le32(entry + 8);
        table[i].flags = libmpq__load_le32(entry + 12);
    }
}

/* Decode the optional high 16-bit offset table for MPQ v2 block entries.
 * The caller has already positioned the input at the extension table and
 * supplies storage sized for the block-table entry count. */
static void
decode_mpq_block_ex_table(mpq_block_ex_s *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    if (table == 0 || raw == 0)
        return;
    for (i = 0; i < count; i++) {
        table[i].offset_high = libmpq__load_le16(raw + i * sizeof(mpq_block_ex_s));
    }
}

/* Decode a packed array of little-endian 32-bit values in place.
 * This is used for sector offset tables whose serialized representation is
 * independent of the host CPU's byte order. */
void
libmpq__reader_decode_uint32_table(uint32_t *table, const uint8_t *raw, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        table[i] = libmpq__load_le32(raw + i * sizeof(uint32_t));
    }
}

/* Open an MPQ archive path and prepare decoded metadata for later operations.
 * The routine locates the header, loads and decrypts all metadata tables, and
 * builds the compact file map used by the public archive and block APIs. */
static int32_t
libmpq__reader_archive_open_stream(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    mpq_stream_s *stream
)
{

    /* Archive table counters and status used while building the file map. */
    uint32_t i = 0;
    uint32_t count = 0;
    int32_t result = 0;
    uint32_t header_search = FALSE;
    uint8_t header_data[sizeof(mpq_header_s)];
    uint8_t header_ex_data[sizeof(mpq_header_ex_s)];
    uint8_t *table_data = NULL;
    size_t table_bytes = 0;

    if (mpq_archive == NULL) {
        libmpq__stream_discard(stream);
        return LIBMPQ_ERROR_EXIST;
    }
    *mpq_archive = NULL;

    /* A sentinel offset requests the embedded-archive scan used by readers. */
    if (archive_offset == -1) {
        archive_offset = 0;
        header_search = TRUE;
    } else if (archive_offset < 0) {
        libmpq__stream_discard(stream);
        return LIBMPQ_ERROR_SEEK;
    }

    if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {
        libmpq__stream_discard(stream);
        return LIBMPQ_ERROR_MALLOC;
    }

    /* Transfer stream ownership before any later archive initialization can fail. */
    (*mpq_archive)->stream = stream;

    (*mpq_archive)->filename = malloc(strlen(mpq_filename) + 1);
    if ((*mpq_archive)->filename == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }
    memcpy((*mpq_archive)->filename, mpq_filename, strlen(mpq_filename) + 1);

#if !defined(_WIN32) && !defined(_WIN64)
    {
        struct stat file_status;

        if (stat(mpq_filename, &file_status) == 0) {
            (*mpq_archive)->file_device = (uint64_t)file_status.st_dev;
            (*mpq_archive)->file_inode = (uint64_t)file_status.st_ino;
            (*mpq_archive)->file_identity_valid = TRUE;
        }
    }
#endif

    (*mpq_archive)->file_size = libmpq__stream_size(stream);

    (*mpq_archive)->mpq_header.mpq_magic = 0;
    (*mpq_archive)->files = 0;

    /* Probe the requested location, or advance in 512-byte steps for embedded archives. */
    while (TRUE) {
        (*mpq_archive)->mpq_header.mpq_magic = 0;

        if ((uint64_t)archive_offset > (*mpq_archive)->file_size ||
            sizeof(header_data) > (*mpq_archive)->file_size - (uint64_t)archive_offset) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((result = libmpq__stream_read_at(
                 (*mpq_archive)->stream, (uint64_t)archive_offset, header_data, sizeof(header_data)
             )) < 0)
            goto error;

        decode_mpq_header(&(*mpq_archive)->mpq_header, header_data);

        if ((*mpq_archive)->mpq_header.mpq_magic == LIBMPQ_HEADER) {
            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {

                /* Protected archives may store a bogus header size; normalize it locally. */
                if ((*mpq_archive)->mpq_header.header_size != sizeof(mpq_header_s)) {
                    (*mpq_archive)->mpq_header.header_size = sizeof(mpq_header_s);
                }
            }

            if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
                if ((*mpq_archive)->mpq_header.header_size !=
                    sizeof(mpq_header_s) + sizeof(mpq_header_ex_s)) {
                    (*mpq_archive)->mpq_header.header_size =
                        sizeof(mpq_header_s) + sizeof(mpq_header_ex_s);
                }
            }

            if ((*mpq_archive)->mpq_header.version > LIBMPQ_ARCHIVE_VERSION_TWO) {
                result = LIBMPQ_ERROR_FORMAT;
                goto error;
            }

            break;
        }

        if (!header_search) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        archive_offset += 512;
    }

    if ((*mpq_archive)->mpq_header.block_size > 22) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }

    (*mpq_archive)->block_size = 512U << (*mpq_archive)->mpq_header.block_size;
    (*mpq_archive)->archive_offset = archive_offset;

    if (table_size((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s), &table_bytes) <
            0 ||
        (uint64_t)table_bytes > (*mpq_archive)->file_size ||
        table_size(
            (*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s), &table_bytes
        ) < 0 ||
        (uint64_t)table_bytes > (*mpq_archive)->file_size) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }

    /* MPQ v2 stores high table offsets in a separate extension immediately after v1. */
    if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        if ((uint64_t)archive_offset > UINT64_MAX - sizeof(mpq_header_s) ||
            (uint64_t)archive_offset + sizeof(mpq_header_s) > (*mpq_archive)->file_size ||
            sizeof(header_ex_data) >
                (*mpq_archive)->file_size - ((uint64_t)archive_offset + sizeof(mpq_header_s))) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if ((result = libmpq__stream_read_at(
                 (*mpq_archive)->stream, (uint64_t)archive_offset + sizeof(mpq_header_s),
                 header_ex_data, sizeof(header_ex_data)
             )) < 0)
            goto error;

        decode_mpq_header_ex(&(*mpq_archive)->mpq_header_ex, header_ex_data);
    }

    /* Metadata tables are decoded once and kept with the archive handle for later lookups. */
    if (((*mpq_archive)->mpq_header.block_table_count != 0 &&
         (((*mpq_archive)->mpq_block =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s))) == NULL ||
          ((*mpq_archive)->mpq_block_ex =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s))) ==
              NULL ||
          ((*mpq_archive)->mpq_file =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_file_s *))) ==
              NULL ||
          ((*mpq_archive)->mpq_map =
               calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_map_s))) == NULL)) ||
        ((*mpq_archive)->mpq_header.hash_table_count != 0 &&
         ((*mpq_archive)->mpq_hash =
              calloc((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s))) == NULL)) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    if (table_size((*mpq_archive)->mpq_header.hash_table_count, sizeof(mpq_hash_s), &table_bytes) <
        0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }
    if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* Locate, read, decrypt, and decode the hash table before file lookup begins. */
    if ((result = libmpq__stream_read_at(
             (*mpq_archive)->stream,
             (*mpq_archive)->mpq_header.hash_table_offset +
                 ((uint64_t)(*mpq_archive)->mpq_header_ex.hash_table_offset_high << 32) +
                 (uint64_t)(*mpq_archive)->archive_offset,
             table_data, table_bytes
         )) < 0) {
        goto error;
    }

    /* MPQ stores the hash table encrypted with the fixed "(hash table)" key. */
    libmpq__crypto_decrypt_block(
        table_data, (uint32_t)table_bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    decode_mpq_hash_table(
        (*mpq_archive)->mpq_hash, table_data, (*mpq_archive)->mpq_header.hash_table_count
    );
    free(table_data);
    table_data = NULL;

    if (table_size(
            (*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s), &table_bytes
        ) < 0) {
        result = LIBMPQ_ERROR_FORMAT;
        goto error;
    }
    if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto error;
    }

    /* The block table uses the same fixed key pattern as the hash table. */
    if ((result = libmpq__stream_read_at(
             (*mpq_archive)->stream,
             (*mpq_archive)->mpq_header.block_table_offset +
                 ((uint64_t)(*mpq_archive)->mpq_header_ex.block_table_offset_high << 32) +
                 (uint64_t)(*mpq_archive)->archive_offset,
             table_data, table_bytes
         )) < 0) {
        goto error;
    }

    /* MPQ stores the block table encrypted with the fixed "(block table)" key. */
    libmpq__crypto_decrypt_block(
        table_data, (uint32_t)table_bytes, libmpq__crypto_hash_string("(block table)", 0x300)
    );
    decode_mpq_block_table(
        (*mpq_archive)->mpq_block, table_data, (*mpq_archive)->mpq_header.block_table_count
    );
    free(table_data);
    table_data = NULL;

    /* v2 block high words are optional and are loaded only when present. */
    if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {
        if (table_size(
                (*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s), &table_bytes
            ) < 0) {
            result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        if (table_bytes != 0 && (table_data = malloc(table_bytes)) == NULL) {
            result = LIBMPQ_ERROR_MALLOC;
            goto error;
        }

        if ((result = libmpq__stream_read_at(
                 (*mpq_archive)->stream,
                 (*mpq_archive)->mpq_header_ex.extended_offset + (uint64_t)archive_offset,
                 table_data, table_bytes
             )) < 0) {
            if (result == LIBMPQ_ERROR_READ)
                result = LIBMPQ_ERROR_FORMAT;
            goto error;
        }
        decode_mpq_block_ex_table(
            (*mpq_archive)->mpq_block_ex, table_data, (*mpq_archive)->mpq_header.block_table_count
        );
        free(table_data);
        table_data = NULL;
    }

    /* Build the compact public file-number map from existing block-table entries. */
    for (i = 0; i < (*mpq_archive)->mpq_header.block_table_count; i++) {
        (*mpq_archive)->mpq_map[i].block_table_diff = i - count;

        if (((*mpq_archive)->mpq_block[i].flags & LIBMPQ_FLAG_EXISTS) == 0) {
            continue;
        }

        (*mpq_archive)->mpq_map[count].block_table_indices = i;
        count++;
    }

    (*mpq_archive)->files = count;

    free(table_data);
    return LIBMPQ_SUCCESS;

error:

    /* All partially allocated reader state is released through one failure path. */
    free(table_data);
    if ((*mpq_archive)->stream)
        libmpq__stream_discard((*mpq_archive)->stream);

    free((*mpq_archive)->mpq_map);
    free((*mpq_archive)->mpq_file);
    free((*mpq_archive)->mpq_hash);
    free((*mpq_archive)->mpq_block);
    free((*mpq_archive)->mpq_block_ex);
    free((*mpq_archive)->filename);
    free(*mpq_archive);

    *mpq_archive = NULL;

    return result;
}

int32_t
libmpq__reader_archive_open_path(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
)
{
    mpq_stream_s *stream = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    result = libmpq__stream_open_file(&stream, mpq_filename);

    return result == LIBMPQ_SUCCESS ? libmpq__reader_archive_open_stream(
                                          mpq_archive, mpq_filename, archive_offset, stream
                                      )
                                    : result;
}

int32_t
libmpq__reader_archive_open_mpqe(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    const uint8_t *auth_code, size_t auth_code_size
)
{
    mpq_stream_s *stream = NULL;
    int32_t result;

    if (mpq_archive == NULL)
        return LIBMPQ_ERROR_EXIST;
    *mpq_archive = NULL;
    result = libmpq__stream_open_mpqe(&stream, mpq_filename, auth_code, auth_code_size);

    return result == LIBMPQ_SUCCESS ? libmpq__reader_archive_open_stream(
                                          mpq_archive, mpq_filename, archive_offset, stream
                                      )
                                    : result;
}

int32_t
libmpq__reader_archive_clone(mpq_archive_s **clone, const mpq_archive_s *source)
{
    mpq_stream_s *stream = NULL;
    int32_t result;

    if (clone == NULL)
        return LIBMPQ_ERROR_EXIST;
    *clone = NULL;
    if (source == NULL || source->stream == NULL || source->filename == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = libmpq__stream_clone(&stream, source->stream, source->filename);

    return result == LIBMPQ_SUCCESS ? libmpq__reader_archive_open_stream(
                                          clone, source->filename, source->archive_offset, stream
                                      )
                                    : result;
}

/* Validate that a public file number maps to an extractable archive entry.
 * Public numbering excludes unused block-table slots, so this check protects
 * all later map and block-table accesses from an invalid compact index. */
int32_t
libmpq__reader_validate_file_number(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    if (file_number >= mpq_archive->files) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the number of sectors needed to represent a file entry.
 * Single-unit files always have one payload block; sectorized files use the
 * archive block size and round the unpacked length up to a complete sector. */
uint32_t
libmpq__reader_count_file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number)
{
    uint32_t block_table_index = mpq_archive->mpq_map[file_number].block_table_indices;
    uint32_t unpacked_size = mpq_archive->mpq_block[block_table_index].unpacked_size;

    if ((mpq_archive->mpq_block[block_table_index].flags & LIBMPQ_FLAG_SINGLE) != 0) {
        return 1;
    }

    return (unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
}

/* Validate that a block number exists for the selected file entry.
 * The file's storage mode determines the valid range, including the special
 * one-block case for single-unit entries. */
int32_t
libmpq__reader_validate_block_number(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number
)
{
    if (block_number >= libmpq__reader_count_file_blocks(mpq_archive, file_number)) {
        return LIBMPQ_ERROR_EXIST;
    }

    return LIBMPQ_SUCCESS;
}

/* Return the per-block decryption seed derived from the file seed and block number.
 * The helper validates file and block ownership, ensures offset metadata is
 * available, and refuses to guess a key when anonymous decryption failed. */
int32_t
libmpq__reader_get_block_seed(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed
)
{
    if (libmpq__reader_validate_file_number(mpq_archive, file_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (libmpq__reader_validate_block_number(mpq_archive, file_number, block_number) < 0) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (mpq_archive->mpq_file[file_number] == NULL ||
        mpq_archive->mpq_file[file_number]->packed_offset == NULL) {
        return LIBMPQ_ERROR_OPEN;
    }

    if (mpq_archive->mpq_file[file_number]->packed_offset_count <= block_number + 1) {
        return LIBMPQ_ERROR_EXIST;
    }

    if (!mpq_archive->mpq_file[file_number]->seed_known) {
        return LIBMPQ_ERROR_DECRYPT;
    }

    *seed = mpq_archive->mpq_file[file_number]->seed + block_number;

    return LIBMPQ_SUCCESS;
}
