/*
 *  mpq-writer.c -- seekable MPQ archive creation.
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

#include "mpq-attributes.h"
#include "mpq-compression.h"
#include "mpq-crypto.h"
#include "mpq-endian.h"
#include "mpq-file.h"
#include "mpq-internal.h"
#include "mpq-mpqe.h"
#include "mpq-pkware.h"
#include "mpq-signature.h"
#include "mpq-wave.h"
#include "mpq-writer.h"
#include <libmpq/mpq.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Resolve the private writer policy from the existing archive-creation flags. */
static libmpq_compression_policy_t
compression_policy(const mpq_archive_s *archive)
{
    return (archive->write_flags & LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED) != 0
               ? LIBMPQ_COMPRESSION_POLICY_EXTENDED
               : LIBMPQ_COMPRESSION_POLICY_STANDARD;
}

/* Return the smallest supported power-of-two table capacity at or above value.
 * MPQ hash tables use power-of-two probing, so this helper provides the next
 * legal capacity without exceeding the format's 32-bit range. */
static uint32_t
next_power_two(uint32_t value)
{
    uint32_t result = 4;
    while (result < value && result < 0x80000000u)
        result <<= 1;
    return result;
}

/* Write one byte range at an absolute archive offset.
 * Seeking and writing are treated as one archive operation so short writes
 * and positioning failures are converted to the library's write error. */
static int32_t
write_at(FILE *fp, uint64_t offset, const void *data, size_t size)
{
    if (libmpq__file_seek(fp, offset, SEEK_SET) < 0 || (size && fwrite(data, 1, size, fp) != size))
        return LIBMPQ_ERROR_WRITE;
    return LIBMPQ_SUCCESS;
}

/* Calculate the MPQ file encryption key from a normalized file name.
 * Slash normalization matches MPQ's Windows-oriented name hashing while the
 * temporary normalized string remains private to this calculation. */
static uint32_t
file_key(const char *name)
{
    char *normalized = NULL;
    size_t i;
    size_t length = strlen(name);
    uint32_t key;

    normalized = malloc(length + 1);
    if (normalized == NULL)
        return 0;
    for (i = 0; i < length; i++)
        normalized[i] = name[i] == '/' ? '\\' : name[i];
    normalized[length] = 0;
    key = libmpq__crypto_hash_string(normalized, 0x300);
    free(normalized);
    return key;
}

/* Compress, encrypt, and append the writer's currently buffered sector.
 * Sector zero and later sectors may use different masks; the resulting offset
 * is recorded relative to the payload for the table written during finish. */
static int32_t
stream_flush_sector(mpq_writer_s *writer)
{
    mpq_archive_s *archive = writer->archive;
    uint8_t *packed = NULL;
    size_t packed_size = writer->data_size;
    uint8_t emitted = 0;
    uint32_t requested = writer->sector_index == 0 ? writer->options.compression_first
                                                   : writer->options.compression_next;
    int32_t result;

    /* Reject an extra flush before touching the archive stream. */
    if (writer->sector_index >= writer->block_count)
        return LIBMPQ_ERROR_SIZE;
    if ((writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0)
        result = libmpq__compression_encode_sector(
            writer->data, writer->data_size, requested, archive->mpq_header.version,
            compression_policy(archive), &packed, &packed_size, &emitted
        );
    else if ((writer->options.flags & LIBMPQ_FILE_FLAG_IMPLODE) != 0) {
        uint32_t packed32 = 0;
        result = libmpq__pkzip_compress(writer->data, writer->data_size, &packed, &packed32);
        packed_size = packed32;
        if (result == LIBMPQ_SUCCESS && packed_size >= writer->data_size) {
            free(packed);
            packed = malloc(writer->data_size ? writer->data_size : 1);
            if (packed == NULL)
                result = LIBMPQ_ERROR_MALLOC;
            else {
                memcpy(packed, writer->data, writer->data_size);
                packed_size = writer->data_size;
            }
        }
    } else {
        packed = malloc(packed_size ? packed_size : 1);
        result = packed == NULL ? LIBMPQ_ERROR_MALLOC : LIBMPQ_SUCCESS;
        if (result == 0)
            memcpy(packed, writer->data, packed_size);
    }
    if (result < 0) {
        free(packed);
        return result;
    }

    /* Sector checksums cover packed bytes before payload encryption. */
    if (writer->checksums != NULL)
        writer->checksums[writer->sector_index] = (uint32_t)adler32(0, packed, (uInt)packed_size);

    /* Payload encryption uses the file seed advanced by the sector number. */
    if (writer->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED)
        libmpq__crypto_encrypt_block(
            packed, (uint32_t)packed_size, file_key(writer->name) + writer->sector_index
        );
    if (writer->offsets) {
        libmpq__off_t position = libmpq__file_tell(archive->fp);

        if (position < 0) {
            free(packed);
            return LIBMPQ_ERROR_SEEK;
        }
        writer->offsets[writer->sector_index] =
            (uint32_t)((uint64_t)position - writer->payload_offset);
    }
    if (fwrite(packed, 1, packed_size, archive->fp) != packed_size) {
        free(packed);
        return LIBMPQ_ERROR_WRITE;
    }
    writer->packed_total += packed_size;
    if (writer->sector_index == 0 &&
        (writer->options.compression_next &
         (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO))) {
        libmpq_wave_info_s wave;

        /* Validate the complete WAVE geometry before preserving lossy output. */
        if (libmpq__wave_probe_pcm16_prefix(
                writer->data, writer->data_size, (uint64_t)writer->expected, &wave
            ) == 0) {
            writer->options.compression_next &=
                ~(LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO);
            writer->options.compression_next |=
                wave.channels == 1 ? LIBMPQ_COMPRESSION_WAVE_MONO : LIBMPQ_COMPRESSION_WAVE_STEREO;
        } else {
            free(packed);
            return LIBMPQ_ERROR_FORMAT;
        }
    }
    writer->sector_index++;
    writer->data_size = 0;
    free(packed);
    return LIBMPQ_SUCCESS;
}

/* Append the optional checksum table without file encryption. Like sector data,
 * zlib framing is retained only when it reduces the serialized table size. */
static int32_t
stream_write_checksums(mpq_writer_s *writer)
{
    size_t size = (size_t)writer->block_count * sizeof(uint32_t);
    uint8_t *raw = malloc(size);
    uint8_t *packed = NULL;
    size_t packed_size = 0;
    uint8_t emitted = 0;
    uint32_t i;
    int32_t result;

    if (raw == NULL)
        return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < writer->block_count; ++i)
        libmpq__store_le32(raw + i * 4, writer->checksums[i]);
    result = libmpq__compression_encode_sector(
        raw, size, LIBMPQ_COMPRESSION_ZLIB, writer->archive->mpq_header.version,
        LIBMPQ_COMPRESSION_POLICY_STANDARD, &packed, &packed_size, &emitted
    );
    free(raw);
    if (result == LIBMPQ_SUCCESS) {
        if (packed_size > UINT32_MAX - writer->offsets[writer->block_count])
            result = LIBMPQ_ERROR_SIZE;
        else if (fwrite(packed, 1, packed_size, writer->archive->fp) != packed_size)
            result = LIBMPQ_ERROR_WRITE;
        else {
            writer->packed_total += packed_size;
            writer->offsets[writer->block_count + 1] =
                writer->offsets[writer->block_count] + (uint32_t)packed_size;
        }
    }
    free(packed);
    return result;
}

/* Finish the streamed file by writing its offset table and archive metadata.
 * The serialized table is placed before packed sectors, encrypted separately,
 * and then the completed file is inserted into the block and hash tables. */
static int32_t
stream_finish(mpq_writer_s *writer)
{
    mpq_archive_s *archive = writer->archive;
    uint32_t index;
    uint32_t slot;
    uint32_t hash1;
    uint32_t hash2;
    uint32_t hash3;
    uint32_t i;
    uint64_t total;
    size_t table_size;
    uint8_t *table;
    int32_t result;

    /* A file is publishable only after its declared byte and sector counts match. */
    if (writer->written != writer->expected || writer->sector_index != writer->block_count)
        return LIBMPQ_ERROR_SIZE;
    if (writer->offsets) {
        uint32_t entries = writer->block_count + 1 + (writer->checksums != NULL);
        table_size = (size_t)entries * 4;
        if (writer->packed_total > UINT32_MAX - table_size)
            return LIBMPQ_ERROR_SIZE;
        writer->offsets[writer->block_count] =
            (uint32_t)writer->packed_total + (uint32_t)table_size;
        if (writer->checksums != NULL) {
            result = stream_write_checksums(writer);
            if (result < 0)
                return result;
        }
        table = malloc(table_size);
        if (table == NULL)
            return LIBMPQ_ERROR_MALLOC;
        for (i = 0; i < entries; i++)
            libmpq__store_le32(table + i * 4, writer->offsets[i]);
        if (writer->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED)
            libmpq__crypto_encrypt_block(table, (uint32_t)table_size, file_key(writer->name) - 1);
        result = write_at(archive->fp, writer->payload_offset, table, table_size);
        free(table);
        if (result < 0)
            return result;
        total = writer->packed_total + table_size;
    } else {
        total = writer->packed_total;
    }

    /* Restore the append position after rewriting the table at the file start. */
    if (libmpq__file_seek(archive->fp, (writer->payload_offset + total), SEEK_SET) < 0)
        return LIBMPQ_ERROR_SEEK;
    if (writer->payload_offset > UINT32_MAX || total > UINT32_MAX || writer->expected > UINT32_MAX)
        return archive->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE
                   ? LIBMPQ_ERROR_SIZE
                   : (writer->payload_offset >> 32 > UINT16_MAX ? LIBMPQ_ERROR_SIZE : 0);

    /* Reserve the next block slot only after payload and offset sizes validate. */
    index = archive->write_next_block;
    libmpq__file_hash(writer->name, &hash1, &hash2, &hash3);
    archive->mpq_block[index].offset = (uint32_t)writer->payload_offset;
    archive->mpq_block[index].packed_size = (uint32_t)total;
    archive->mpq_block[index].unpacked_size = (uint32_t)writer->expected;
    archive->mpq_block[index].flags = LIBMPQ_FLAG_EXISTS | writer->options.flags;
    if (writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS)
        archive->mpq_block[index].flags |= LIBMPQ_FLAG_COMPRESS_MULTI;
    archive->mpq_block_ex[index].offset_high = (uint16_t)(writer->payload_offset >> 32);
    archive->write_names[index] = writer->name;
    archive->write_locales[index] = writer->options.locale;
    archive->write_platforms[index] = writer->options.platform;
    writer->name = NULL;
    archive->write_next_block++;
    archive->files = archive->write_next_block;
    for (slot = 0; slot < archive->write_hash_capacity; slot++) {
        uint32_t pos = (hash1 + slot) & (archive->write_hash_capacity - 1);
        if (archive->mpq_hash[pos].block_table_index == LIBMPQ_HASH_FREE) {
            archive->mpq_hash[pos].hash_a = hash2;
            archive->mpq_hash[pos].hash_b = hash3;
            archive->mpq_hash[pos].locale = writer->options.locale;
            archive->mpq_hash[pos].platform = writer->options.platform;
            archive->mpq_hash[pos].block_table_index = index;
            if (archive->write_attributes != NULL) {
                if (writer->attributes.flags & LIBMPQ_ATTRIBUTE_MD5)
                    libmpq__md5_final(&writer->md5, writer->attributes.md5);
                archive->write_attributes[index] = writer->attributes;
            }
            return LIBMPQ_SUCCESS;
        }
    }
    return LIBMPQ_ERROR_SIZE;
}

/* Serialize the completed hash, block, extended tables, and archive header.
 * Finalization optionally creates the listfile, encrypts metadata with the
 * fixed MPQ table keys, writes v2 high offsets, and commits the header last. */
static int32_t
finalize_archive(mpq_archive_s *a)
{
    uint8_t *raw;
    uint32_t i;
    size_t bytes;
    uint64_t end;
    uint8_t header[LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE];

    /* An unfinished streamed file would leave archive tables inconsistent. */
    if (a->write_current)
        return LIBMPQ_ERROR_SIZE;
    a->write_internal = TRUE;
    if (libmpq__attributes_write_flags(a) != 0 && a->write_attributes == NULL) {
        a->write_attributes = calloc(a->write_capacity, sizeof(*a->write_attributes));
        if (a->write_attributes == NULL)
            return LIBMPQ_ERROR_MALLOC;
    }
    if ((a->write_flags & LIBMPQ_ARCHIVE_CREATE_LISTFILE) != 0) {
        size_t total = 1 + (libmpq__attributes_write_flags(a) ? sizeof(LIBMPQ_ATTRIBUTES_NAME) : 0);
        uint8_t *list;
        for (i = 0; i < a->write_next_block; i++)
            total += strlen(a->write_names[i]) + 1;
        list = malloc(total);
        if (!list)
            return LIBMPQ_ERROR_MALLOC;
        total = 0;
        for (i = 0; i < a->write_next_block; i++) {
            size_t n = strlen(a->write_names[i]);
            memcpy(list + total, a->write_names[i], n);
            total += n;
            list[total++] = '\n';
        }
        if (libmpq__attributes_write_flags(a)) {
            memcpy(list + total, LIBMPQ_ATTRIBUTES_NAME "\n", sizeof(LIBMPQ_ATTRIBUTES_NAME));
            total += sizeof(LIBMPQ_ATTRIBUTES_NAME);
        }
        {
            mpq_file_options_s o = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
            int32_t r =
                libmpq__writer_file_add(a, LIBMPQ_LISTFILE_NAME, list, (libmpq__off_t)total, &o);
            free(list);
            if (r < 0)
                return r;
        }
    }

    if (libmpq__attributes_write_flags(a) != 0) {
        mpq_file_options_s options = { LIBMPQ_FILE_FLAG_COMPRESS, LIBMPQ_COMPRESSION_ZLIB,
                                       LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
        int32_t result = libmpq__attributes_serialize(
            a->write_attributes, a->write_capacity, a->write_next_block,
            libmpq__attributes_write_flags(a), &raw, &bytes
        );
        if (result != LIBMPQ_SUCCESS)
            return result;
        result =
            libmpq__writer_file_add(a, LIBMPQ_ATTRIBUTES_NAME, raw, (libmpq__off_t)bytes, &options);
        free(raw);
        if (result != LIBMPQ_SUCCESS)
            return result;
    }

    /* Serialize and encrypt the hash table before writing the block metadata. */
    bytes = (size_t)a->write_hash_capacity * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    raw = malloc(bytes);
    if (!raw)
        return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < a->write_hash_capacity; i++) {
        libmpq__store_le32(raw + (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE, a->mpq_hash[i].hash_a);
        libmpq__store_le32(
            raw + (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE + 4, a->mpq_hash[i].hash_b
        );
        libmpq__store_le16(
            raw + (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE + 8, a->mpq_hash[i].locale
        );
        libmpq__store_le16(
            raw + (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE + 10, a->mpq_hash[i].platform
        );
        libmpq__store_le32(
            raw + (size_t)i * LIBMPQ_HASH_ENTRY_WIRE_SIZE + 12, a->mpq_hash[i].block_table_index
        );
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(hash table)", 0x300)
    );
    if (write_at(a->fp, a->mpq_header.hash_table_offset, raw, bytes) < 0) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);

    /* Serialize the fixed-capacity block table using explicit little-endian fields. */
    bytes = (size_t)a->write_capacity * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    raw = malloc(bytes);
    if (!raw)
        return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < a->write_capacity; i++) {
        libmpq__store_le32(raw + (size_t)i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE, a->mpq_block[i].offset);
        libmpq__store_le32(
            raw + (size_t)i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE + 4, a->mpq_block[i].packed_size
        );
        libmpq__store_le32(
            raw + (size_t)i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE + 8, a->mpq_block[i].unpacked_size
        );
        libmpq__store_le32(
            raw + (size_t)i * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE + 12, a->mpq_block[i].flags
        );
    }
    libmpq__crypto_encrypt_block(
        raw, (uint32_t)bytes, libmpq__crypto_hash_string("(block table)", 0x300)
    );
    if (write_at(a->fp, a->mpq_header.block_table_offset, raw, bytes) < 0) {
        free(raw);
        return LIBMPQ_ERROR_WRITE;
    }
    free(raw);
    if (a->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        bytes = (size_t)a->write_capacity * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE;
        raw = malloc(bytes);
        if (!raw)
            return LIBMPQ_ERROR_MALLOC;
        for (i = 0; i < a->write_capacity; i++)
            libmpq__store_le16(
                raw + (size_t)i * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE, a->mpq_block_ex[i].offset_high
            );
        if (write_at(a->fp, a->mpq_header_ex.extended_offset, raw, bytes) < 0) {
            free(raw);
            return LIBMPQ_ERROR_WRITE;
        }
        free(raw);
    }
    if (libmpq__file_seek(a->fp, 0, SEEK_END) < 0)
        return LIBMPQ_ERROR_SEEK;
    end = (uint64_t)libmpq__file_tell(a->fp);
    if (end > INT64_MAX)
        return LIBMPQ_ERROR_SEEK;
    if (end > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    memset(header, 0, sizeof(header));
    libmpq__store_le32(header, LIBMPQ_HEADER);
    libmpq__store_le32(header + 4, a->mpq_header.header_size);
    libmpq__store_le32(header + 8, (uint32_t)end);
    libmpq__store_le16(header + 12, a->mpq_header.version);
    libmpq__store_le16(header + 14, a->mpq_header.block_size);
    libmpq__store_le32(header + 16, a->mpq_header.hash_table_offset);
    libmpq__store_le32(header + 20, a->mpq_header.block_table_offset);
    libmpq__store_le32(header + 24, a->mpq_header.hash_table_count);
    libmpq__store_le32(header + 28, a->mpq_header.block_table_count);
    if (a->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        libmpq__store_le64(header + LIBMPQ_HEADER_WIRE_SIZE, a->mpq_header_ex.extended_offset);
        libmpq__store_le16(
            header + LIBMPQ_HEADER_WIRE_SIZE + 8,
            (uint16_t)(((uint64_t)a->mpq_header.hash_table_offset) >> 32)
        );
        libmpq__store_le16(
            header + LIBMPQ_HEADER_WIRE_SIZE + 10,
            (uint16_t)(((uint64_t)a->mpq_header.block_table_offset) >> 32)
        );
    }
    if (write_at(a->fp, 0, header, a->mpq_header.header_size) < 0 || fflush(a->fp) != 0)
        return LIBMPQ_ERROR_WRITE;
    {
        int32_t result = libmpq__signature_finish(a, end);
        if (result != LIBMPQ_SUCCESS)
            return result;
    }
    if (!a->write_mpqe)
        a->write_finalized = TRUE;
    return LIBMPQ_SUCCESS;
}

/* Transform the finalized raw archive with bounded sequential MPQE I/O. */
static int32_t
transform_mpqe(mpq_archive_s *a)
{
    uint8_t chunk[LIBMPQ_MPQE_CHUNK_SIZE];
    uint64_t offset = 0;
    size_t read;

    if (fflush(a->fp) != 0)
        return LIBMPQ_ERROR_WRITE;
    if (libmpq__file_seek(a->fp, 0, SEEK_SET) < 0)
        return LIBMPQ_ERROR_SEEK;
    while ((read = fread(chunk, 1, sizeof(chunk), a->fp)) != 0) {
        if (read < sizeof(chunk))
            memset(chunk + read, 0, sizeof(chunk) - read);
        libmpq__mpqe_transform_chunk(chunk, a->write_mpqe_key, offset);
        if (fwrite(chunk, 1, read, a->write_mpqe_output) != read) {
            libmpq__mpqe_clear(chunk, sizeof(chunk));
            return LIBMPQ_ERROR_WRITE;
        }
        offset += read;
    }
    libmpq__mpqe_clear(chunk, sizeof(chunk));
    if (ferror(a->fp) || fflush(a->write_mpqe_output) != 0)
        return LIBMPQ_ERROR_WRITE;
    return LIBMPQ_SUCCESS;
}

/* Production MPQE finalization operations used by every newly created MPQE archive. */
static const mpq_writer_mpqe_ops_s default_mpqe_ops = {
    finalize_archive,
    transform_mpqe,
    fclose,
    libmpq__directory_replace,
};

/* Finish MPQE output only after the ordinary MPQ writer has finalized its raw stream. */
int32_t
libmpq__writer_finalize_mpqe(mpq_archive_s *a)
{
    const mpq_writer_mpqe_ops_s *ops;
    int32_t result;

    if (a == NULL || !a->write_mpqe)
        return LIBMPQ_ERROR_EXIST;
    ops = a->write_mpqe_ops;
    if (ops == NULL)
        return LIBMPQ_ERROR_EXIST;
    result = ops->transform(a);
    if (a->fp != NULL && fclose(a->fp) != 0 && result == LIBMPQ_SUCCESS)
        result = LIBMPQ_ERROR_CLOSE;
    a->fp = NULL;
    if (result != LIBMPQ_SUCCESS)
        return result;
    if (libmpq__directory_remove(a->write_mpqe_directory, a->filename) != 0)
        return LIBMPQ_ERROR_WRITE;
    if (ops->close_output(a->write_mpqe_output) != 0) {
        a->write_mpqe_output = NULL;
        return LIBMPQ_ERROR_CLOSE;
    }
    a->write_mpqe_output = NULL;
    result =
        ops->publish(a->write_mpqe_directory, a->write_mpqe_output_path, a->write_mpqe_destination);
    if (result == LIBMPQ_SUCCESS)
        a->write_finalized = TRUE;
    return result;
}

/* Close/unlink private MPQE artifacts on every handled completion or failure. */
void
libmpq__writer_mpqe_cleanup(mpq_archive_s *a)
{
    if (a == NULL)
        return;
    if (a->write_mpqe_output != NULL)
        (void)fclose(a->write_mpqe_output);
    a->write_mpqe_output = NULL;
    if (a->write_mpqe && a->write_mpqe_directory != NULL && a->filename != NULL)
        (void)libmpq__directory_remove(a->write_mpqe_directory, a->filename);
    if (a->write_mpqe_directory != NULL && a->write_mpqe_output_path != NULL)
        (void)libmpq__directory_remove(a->write_mpqe_directory, a->write_mpqe_output_path);
    if (a->write_mpqe_directory != NULL)
        (void)libmpq__directory_close(a->write_mpqe_directory);
    a->write_mpqe_directory = NULL;
    libmpq__mpqe_clear(a->write_mpqe_key, sizeof(a->write_mpqe_key));
}

/* Create a new seekable MPQ v1 or v2 archive with reserved metadata tables.
 * The function validates creation options, reserves table space, initializes
 * empty hash entries, and leaves the file positioned at the first payload. */
static int32_t
writer_validate_options(const mpq_archive_create_options_s *options)
{
    if (options == NULL)
        return LIBMPQ_SUCCESS;
    if (options->version > LIBMPQ_ARCHIVE_VERSION_TWO || options->max_files == UINT32_MAX ||
        (options->max_files && options->max_files > 0x40000000u))
        return LIBMPQ_ERROR_FORMAT;
    if (options->sector_size &&
        (options->sector_size < 512 || (options->sector_size & (options->sector_size - 1)) != 0))
        return LIBMPQ_ERROR_FORMAT;
    if ((options->attributes & ~LIBMPQ_ATTRIBUTES_ALL) != 0)
        return LIBMPQ_ERROR_FORMAT;
    if (options->attributes != 0 && options->max_files != 0 &&
        options->max_files < 1u + ((options->flags & LIBMPQ_ARCHIVE_CREATE_LISTFILE) != 0))
        return LIBMPQ_ERROR_SIZE;
    return LIBMPQ_SUCCESS;
}

/* Allocate the writer before opening ordinary output, or adopt a private stream. */
static int32_t
writer_archive_create_handle(
    mpq_archive_s **out, const char *path, FILE *file, const mpq_archive_create_options_s *options
)
{
    mpq_archive_create_options_s defaults = { LIBMPQ_ARCHIVE_VERSION_ONE, 1024, 4096, 0, 0 };
    mpq_archive_s *a;
    uint32_t i;
    uint32_t header_size;
    uint64_t offset;
    uint8_t *zero;

    if (out == NULL || path == NULL)
        return LIBMPQ_ERROR_EXIST;
    *out = NULL;
    if (options == NULL)
        options = &defaults;

    /* Reject versions, capacities, and sector sizes that cannot be represented safely. */
    if (writer_validate_options(options) != LIBMPQ_SUCCESS) {
        if (file != NULL)
            (void)fclose(file);
        return LIBMPQ_ERROR_FORMAT;
    }
    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        if (file != NULL)
            (void)fclose(file);
        return LIBMPQ_ERROR_MALLOC;
    }
    a->write_mpqe_directory = NULL;
    a->fp = file;
    if (a->fp == NULL)
        a->fp = libmpq__file_open(path, "w+b");
    a->filename = libmpq__string_duplicate(path);
    if (a->fp == NULL || a->filename == NULL) {
        if (a->fp != NULL)
            (void)fclose(a->fp);
        free(a->filename);
        free(a);
        return LIBMPQ_ERROR_OPEN;
    }
    a->write_mode = TRUE;
    a->write_capacity = options->max_files ? options->max_files : 1024;
    a->write_sector_size = options->sector_size ? options->sector_size : 4096;
    a->write_flags = options->flags;
    a->write_attributes_flags = options->attributes;

    /* Keep hash load below one half so linear probing remains bounded. */
    a->write_hash_capacity = next_power_two(a->write_capacity * 2);
    header_size = options->version == LIBMPQ_ARCHIVE_VERSION_TWO
                      ? LIBMPQ_HEADER_WIRE_SIZE + LIBMPQ_HEADER_EX_WIRE_SIZE
                      : LIBMPQ_HEADER_WIRE_SIZE;
    a->mpq_header.version = (uint16_t)options->version;
    a->mpq_header.header_size = header_size;
    a->mpq_header.block_size = 0;
    while ((512u << a->mpq_header.block_size) < a->write_sector_size)
        a->mpq_header.block_size++;
    a->mpq_header.hash_table_count = a->write_hash_capacity;
    a->mpq_header.block_table_count = a->write_capacity;
    a->mpq_header.hash_table_offset = header_size;

    /* StormLib skips v1 attributes when a table starts exactly at header end.
     * Reserve a small gap only for opt-in attributes, leaving ordinary output unchanged. */
    if (options->version == LIBMPQ_ARCHIVE_VERSION_ONE && libmpq__attributes_write_flags(a))
        a->mpq_header.hash_table_offset += 16;
    a->mpq_header.block_table_offset =
        a->mpq_header.hash_table_offset + a->write_hash_capacity * LIBMPQ_HASH_ENTRY_WIRE_SIZE;
    a->mpq_header_ex.extended_offset = 0;
    offset = (uint64_t)a->mpq_header.block_table_offset +
             (uint64_t)a->write_capacity * LIBMPQ_BLOCK_ENTRY_WIRE_SIZE;
    if (options->version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        a->mpq_header_ex.extended_offset = offset;
        offset += (uint64_t)a->write_capacity * LIBMPQ_BLOCK_EX_ENTRY_WIRE_SIZE;
    }
    offset = (offset + 511) & ~UINT64_C(511);
    if (options->version == LIBMPQ_ARCHIVE_VERSION_ONE && offset > UINT32_MAX) {
        fclose(a->fp);
        free(a->filename);
        free(a);
        return LIBMPQ_ERROR_SIZE;
    }
    a->mpq_hash = calloc(a->write_hash_capacity, sizeof(*a->mpq_hash));
    a->mpq_block = calloc(a->write_capacity, sizeof(*a->mpq_block));
    a->mpq_block_ex = calloc(a->write_capacity, sizeof(*a->mpq_block_ex));
    a->write_names = calloc(a->write_capacity, sizeof(*a->write_names));
    a->write_locales = calloc(a->write_capacity, sizeof(*a->write_locales));
    a->write_platforms = calloc(a->write_capacity, sizeof(*a->write_platforms));
    if (!a->mpq_hash || !a->mpq_block || !a->mpq_block_ex || !a->write_names || !a->write_locales ||
        !a->write_platforms) {
        fclose(a->fp);
        free(a->filename);
        free(a->mpq_hash);
        free(a->mpq_block);
        free(a->mpq_block_ex);
        free(a->write_names);
        free(a->write_locales);
        free(a->write_platforms);
        free(a);
        return LIBMPQ_ERROR_MALLOC;
    }
    for (i = 0; i < a->write_hash_capacity; i++)
        a->mpq_hash[i].block_table_index = LIBMPQ_HASH_FREE;
    zero = calloc(1, (size_t)(offset > 4096 ? 4096 : offset));
    if (zero == NULL || fwrite(zero, 1, (size_t)(offset > 4096 ? 4096 : offset), a->fp) !=
                            (size_t)(offset > 4096 ? 4096 : offset)) {
        free(zero);
        fclose(a->fp);
        free(a->filename);
        free(a->mpq_hash);
        free(a->mpq_block);
        free(a->mpq_block_ex);
        free(a->write_names);
        free(a->write_locales);
        free(a->write_platforms);
        free(a);
        return LIBMPQ_ERROR_WRITE;
    }
    free(zero);
    if (libmpq__file_seek(a->fp, offset, SEEK_SET) < 0) {
        fclose(a->fp);
        free(a->filename);
        free(a->mpq_hash);
        free(a->mpq_block);
        free(a->mpq_block_ex);
        free(a->write_names);
        free(a->write_locales);
        free(a->write_platforms);
        free(a);
        return LIBMPQ_ERROR_SEEK;
    }
    *out = a;
    return LIBMPQ_SUCCESS;
}

/* Create an ordinary seekable MPQ directly at its requested destination. */
int32_t
libmpq__writer_archive_create(
    mpq_archive_s **out, const char *path, const mpq_archive_create_options_s *options
)
{
    if (out == NULL || path == NULL)
        return LIBMPQ_ERROR_EXIST;
    *out = NULL;
    if (writer_validate_options(options) != LIBMPQ_SUCCESS)
        return LIBMPQ_ERROR_FORMAT;
    return writer_archive_create_handle(out, path, NULL, options);
}

/* Create raw and encrypted private files, then initialize the unchanged MPQ writer on raw output.
 */
int32_t
libmpq__writer_archive_create_mpqe(
    mpq_archive_s **out, const char *path, const uint8_t *auth_code, size_t auth_code_size,
    const mpq_archive_create_options_s *options
)
{
    FILE *raw = NULL;
    FILE *encrypted = NULL;
    char *raw_path = NULL;
    char *encrypted_path = NULL;
    char *destination = NULL;
    uint8_t key[LIBMPQ_MPQE_CHUNK_SIZE];
    mpq_directory_s *directory = NULL;
    int32_t result;

    if (out == NULL)
        return LIBMPQ_ERROR_EXIST;
    *out = NULL;
    result = libmpq__mpqe_key(key, auth_code, auth_code_size);
    if (result != LIBMPQ_SUCCESS)
        return result;
    result = writer_validate_options(options);
    if (result != LIBMPQ_SUCCESS) {
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    result = libmpq__directory_open(path, &directory, &destination);
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__directory_temporary(
            directory, ".libmpq-raw-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 1, &raw_path, &raw
        );
    if (result == LIBMPQ_SUCCESS)
        result = libmpq__directory_temporary(
            directory, ".libmpq-mpqe-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 0, &encrypted_path,
            &encrypted
        );
    if (result == LIBMPQ_SUCCESS) {
        result = writer_archive_create_handle(out, raw_path, raw, options);
        raw = NULL;
    }
    if (result != LIBMPQ_SUCCESS) {
        if (raw != NULL)
            (void)fclose(raw);
        if (encrypted != NULL)
            (void)fclose(encrypted);
        if (directory != NULL && raw_path != NULL)
            (void)libmpq__directory_remove(directory, raw_path);
        if (directory != NULL && encrypted_path != NULL)
            (void)libmpq__directory_remove(directory, encrypted_path);
        if (directory != NULL)
            (void)libmpq__directory_close(directory);
        free(raw_path);
        free(encrypted_path);
        free(destination);
        libmpq__mpqe_clear(key, sizeof(key));
        return result;
    }
    (*out)->write_mpqe = TRUE;
    memcpy((*out)->write_mpqe_key, key, sizeof(key));
    (*out)->write_mpqe_output = encrypted;
    (*out)->write_mpqe_directory = directory;
    (*out)->write_mpqe_destination = destination;
    (*out)->write_mpqe_output_path = encrypted_path;
    (*out)->write_mpqe_ops = &default_mpqe_ops;
    encrypted = NULL;
    encrypted_path = NULL;
    destination = NULL;
    directory = NULL;
    free(raw_path);
    libmpq__mpqe_clear(key, sizeof(key));
    return LIBMPQ_SUCCESS;
}

/* Begin streaming one file into the archive using the requested options.
 * It validates flags and duplicate names, allocates one sector of input space,
 * and reserves an offset table when compressed multi-sector storage requires it. */
int32_t
libmpq__writer_file_begin(
    mpq_archive_s *a, const char *name, libmpq__off_t size, const mpq_file_options_s *options,
    mpq_writer_s **out
)
{
    mpq_file_options_s defaults = { 0, 0, 0, 0, 0 };
    mpq_writer_s *w;
    if (!a || !a->write_mode || !name || !out || size < 0 || a->write_current)
        return LIBMPQ_ERROR_FORMAT;
    if (a->write_signature) {
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        uint32_t s1;
        uint32_t s2;
        uint32_t s3;
        libmpq__file_hash(name, &h1, &h2, &h3);
        libmpq__file_hash(LIBMPQ_SIGNATURE_NAME, &s1, &s2, &s3);
        if (h2 == s2 && h3 == s3)
            return LIBMPQ_ERROR_FORMAT;
    }
    if (options == NULL)
        options = &defaults;
    if (libmpq__attributes_write_flags(a) != 0) {
        uint32_t reserved = 1u + ((a->write_flags & LIBMPQ_ARCHIVE_CREATE_LISTFILE) != 0);
        uint32_t hash1;
        uint32_t hash2;
        uint32_t hash3;
        uint32_t internal1;
        uint32_t internal2;
        uint32_t internal3;
        if (!a->write_internal &&
            (reserved > a->write_capacity || a->write_next_block >= a->write_capacity - reserved))
            return LIBMPQ_ERROR_SIZE;
        libmpq__file_hash(name, &hash1, &hash2, &hash3);
        libmpq__file_hash(LIBMPQ_ATTRIBUTES_NAME, &internal1, &internal2, &internal3);
        if (!a->write_internal && hash1 == internal1 && hash2 == internal2 && hash3 == internal3)
            return LIBMPQ_ERROR_FORMAT;
        if (a->write_attributes == NULL) {
            if ((uint64_t)a->write_capacity * sizeof(*a->write_attributes) > SIZE_MAX)
                return LIBMPQ_ERROR_SIZE;
            a->write_attributes = calloc(a->write_capacity, sizeof(*a->write_attributes));
            if (a->write_attributes == NULL)
                return LIBMPQ_ERROR_MALLOC;
        }
    }
    w = calloc(1, sizeof(*w));
    if (w == NULL)
        return LIBMPQ_ERROR_MALLOC;
    if ((uint64_t)size > SIZE_MAX || a->write_next_block >= a->write_capacity) {
        free(w);
        return LIBMPQ_ERROR_SIZE;
    }
    if ((options->flags & LIBMPQ_FILE_FLAG_IMPLODE) &&
        (options->flags & LIBMPQ_FILE_FLAG_COMPRESS)) {
        free(w);
        return LIBMPQ_ERROR_FORMAT;
    }
    if ((options->flags & LIBMPQ_FILE_FLAG_COMPRESS) &&
        (!libmpq__compression_allowed(
             a->mpq_header.version, options->compression_first, compression_policy(a)
         ) ||
         !libmpq__compression_allowed(
             a->mpq_header.version, options->compression_next, compression_policy(a)
         ))) {
        free(w);
        return LIBMPQ_ERROR_FORMAT;
    }
    if ((options->flags & LIBMPQ_FILE_FLAG_SINGLE) &&
        ((options->compression_first | options->compression_next) &
         (LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO))) {
        free(w);
        return LIBMPQ_ERROR_FORMAT;
    }

    /* Probe existing entries for duplicate name/locale/platform combinations. */
    {
        uint32_t h1;
        uint32_t h2;
        uint32_t h3;
        uint32_t i;
        libmpq__file_hash(name, &h1, &h2, &h3);
        for (i = 0; i < a->write_next_block; i++) {
            uint32_t a1;
            uint32_t a2;
            uint32_t a3;
            if (a->write_names[i] == NULL || a->write_locales[i] != options->locale ||
                a->write_platforms[i] != options->platform)
                continue;
            libmpq__file_hash(a->write_names[i], &a1, &a2, &a3);
            if (h1 == a1 && h2 == a2 && h3 == a3) {
                free(w);
                return LIBMPQ_ERROR_EXIST;
            }
        }
    }
    w->data = malloc(a->write_sector_size ? a->write_sector_size : 1);
    w->name = libmpq__string_duplicate(name);
    if (w->data == NULL || w->name == NULL) {
        free(w->data);
        free(w->name);
        free(w);
        return LIBMPQ_ERROR_MALLOC;
    }
    w->archive = a;
    w->expected = size;
    w->options = *options;
    if (size == 0 || (w->options.flags & LIBMPQ_FILE_FLAG_SINGLE) != 0 ||
        (w->options.flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE)) == 0)
        w->options.flags &= ~LIBMPQ_FILE_FLAG_SECTOR_CRC;
    w->options.compression_first &=
        ~(LIBMPQ_COMPRESSION_WAVE_MONO | LIBMPQ_COMPRESSION_WAVE_STEREO);

    /* STANDARD v2 keeps the first WAVE sector lossless without standalone Huffman. */
    if (!libmpq__compression_allowed(
            a->mpq_header.version, w->options.compression_first, compression_policy(a)
        ))
        w->options.compression_first = LIBMPQ_COMPRESSION_ZLIB;
    if (w->options.compression_next == 0)
        w->options.compression_next = w->options.compression_first;
    if (a->write_sector_size == 0) {
        free(w->name);
        free(w->data);
        free(w);
        return LIBMPQ_ERROR_FORMAT;
    }
    w->block_count = (w->options.flags & LIBMPQ_FILE_FLAG_SINGLE)
                         ? 1
                         : (uint32_t)((size + a->write_sector_size - 1) / a->write_sector_size);
    if (w->block_count == 0)
        w->block_count = 1;
    w->payload_offset = (uint64_t)libmpq__file_tell(a->fp);
    if (w->payload_offset > INT64_MAX) {
        free(w->data);
        free(w->name);
        free(w);
        return LIBMPQ_ERROR_SEEK;
    }

    /* Reserve offset-table space before the first packed sector is written. */
    if (!(w->options.flags & LIBMPQ_FILE_FLAG_SINGLE) &&
        (w->options.flags & (LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_IMPLODE))) {
        uint32_t crc = (w->options.flags & LIBMPQ_FILE_FLAG_SECTOR_CRC) != 0;
        uint64_t entries = (uint64_t)w->block_count + 1 + crc;
        uint64_t allocated = entries + (crc ? w->block_count : 0);
        size_t table_size;
        if (entries > UINT32_MAX / 4 || allocated > SIZE_MAX / sizeof(*w->offsets)) {
            free(w->data);
            free(w->name);
            free(w);
            return LIBMPQ_ERROR_SIZE;
        }
        table_size = (size_t)entries * 4;
        w->offsets = calloc((size_t)allocated, sizeof(*w->offsets));
        if (w->offsets == NULL) {
            free(w->offsets);
            free(w->data);
            free(w->name);
            free(w);
            return LIBMPQ_ERROR_MALLOC;
        }
        w->offsets[0] = (uint32_t)table_size;
        if (crc)
            w->checksums = w->offsets + (size_t)entries;
        if (libmpq__file_seek(a->fp, (w->payload_offset + table_size), SEEK_SET) < 0) {
            free(w->offsets);
            free(w->data);
            free(w->name);
            free(w);
            return LIBMPQ_ERROR_SEEK;
        }
    }
    a->write_current = w;
    w->attributes.flags = libmpq__attributes_write_flags(a);
    if (w->attributes.flags & LIBMPQ_ATTRIBUTE_MD5)
        libmpq__md5_init(&w->md5);
    *out = w;
    return LIBMPQ_SUCCESS;
}

/* Append caller-provided bytes and flush complete sectors immediately.
 * The input is copied into a single sector buffer, so memory use is bounded
 * independently of the total file size. */
int32_t
libmpq__writer_file_write(mpq_writer_s *w, const uint8_t *buffer, libmpq__off_t size)
{
    if (!w || (!buffer && size != 0) || size < 0 || size > w->expected - w->written)
        return LIBMPQ_ERROR_SIZE;

    /* Fill the current sector, flushing exactly when it reaches capacity. */
    while (size != 0) {
        uint32_t room = w->archive->write_sector_size - w->data_size;
        uint32_t take = (uint32_t)((size < room) ? size : room);
        if (w->attributes.flags & LIBMPQ_ATTRIBUTE_CRC32)
            w->attributes.crc32 = (uint32_t)crc32(w->attributes.crc32, buffer, take);
        if (w->attributes.flags & LIBMPQ_ATTRIBUTE_MD5)
            libmpq__md5_update(&w->md5, buffer, take);
        memcpy(w->data + w->data_size, buffer, take);
        w->data_size += take;
        w->written += take;
        buffer += take;
        size -= take;
        if (w->data_size == w->archive->write_sector_size) {
            int32_t result = stream_flush_sector(w);
            if (result < 0)
                return result;
        }
    }
    return LIBMPQ_SUCCESS;
}

/* Assign FILETIME without importing filesystem state or altering file bytes.
 * Only the currently active writer can accept this metadata. */
int32_t
libmpq__writer_file_timestamp(mpq_writer_s *writer, uint64_t filetime)
{
    if (writer == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (writer->archive->write_current != writer)
        return LIBMPQ_ERROR_NOT_INITIALIZED;
    if (!(writer->attributes.flags & LIBMPQ_ATTRIBUTE_FILETIME))
        return LIBMPQ_ERROR_FORMAT;
    writer->attributes.filetime = filetime;
    return LIBMPQ_SUCCESS;
}

/* Flush the final sector and commit the file's block and hash-table entries.
 * Cleanup occurs on both success and failure so the archive never retains an
 * active writer after this function returns. */
int32_t
libmpq__writer_file_finish(mpq_writer_s *w)
{
    int32_t result;
    if (!w)
        return LIBMPQ_ERROR_EXIST;
    if (w->data_size != 0 || w->expected == 0) {
        result = stream_flush_sector(w);
    } else {
        result = 0;
    }
    if (result == 0)
        result = stream_finish(w);
    w->archive->write_current = NULL;
    free(w->name);
    free(w->data);
    free(w->offsets);
    free(w);
    return result;
}

/* Discard an unfinished file after a write failure or archive close.
 * Any partially written payload remains unreachable because no block or hash
 * table entry is committed until writer_file_finish succeeds. */
void
libmpq__writer_file_abort(mpq_writer_s *writer)
{
    if (writer == NULL)
        return;
    if (writer->archive->write_current == writer)
        writer->archive->write_current = NULL;
    free(writer->name);
    free(writer->data);
    free(writer->offsets);
    free(writer);
}

/* Add an in-memory file through the streaming writer interface.
 * This convenience wrapper uses the same sector pipeline as explicit begin,
 * write, and finish calls and cleans up an aborted stream. */
int32_t
libmpq__writer_file_add(
    mpq_archive_s *a, const char *name, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
)
{
    mpq_writer_s *w;
    int32_t result = libmpq__writer_file_begin(a, name, size, options, &w);
    if (result < 0)
        return result;
    result = libmpq__writer_file_write(w, data, size);
    if (result < 0) {
        libmpq__writer_file_abort(w);
        return result;
    }
    return libmpq__writer_file_finish(w);
}

/* Add a filesystem file while keeping only one input sector in memory.
 * The source length is determined first so the streaming writer can enforce
 * its declared size while reading bounded chunks from disk. */
int32_t
libmpq__writer_file_add_path(
    mpq_archive_s *a, const char *name, const char *source, const mpq_file_options_s *options
)
{
    FILE *fp;
    libmpq__off_t size;
    uint8_t buffer[4096];
    size_t got;
    int32_t result;
    mpq_writer_s *writer;
    fp = libmpq__file_open(source, "rb");
    if (!fp)
        return LIBMPQ_ERROR_OPEN;
    if (libmpq__file_seek(fp, 0, SEEK_END) < 0 || (size = libmpq__file_tell(fp)) < 0 ||
        libmpq__file_seek(fp, 0, SEEK_SET) < 0) {
        fclose(fp);
        return LIBMPQ_ERROR_SEEK;
    }
    result = libmpq__writer_file_begin(a, name, size, options, &writer);
    if (result < 0) {
        fclose(fp);
        return result;
    }
    while (!feof(fp) && !ferror(fp)) {
        got = fread(buffer, 1, sizeof(buffer), fp);
        if (got == 0)
            break;
        result = libmpq__writer_file_write(writer, buffer, (libmpq__off_t)got);
        if (result < 0)
            break;
    }
    if (ferror(fp))
        result = LIBMPQ_ERROR_READ;
    fclose(fp);
    if (result == 0)
        result = libmpq__writer_file_finish(writer);
    else
        libmpq__writer_file_abort(writer);
    return result;
}

/* Finalize a writer archive and make it readable by libmpq.
 * The public close path uses this internal wrapper to keep serialization in
 * the writer module while preserving the archive handle lifecycle. */
int32_t
libmpq__writer_finalize(mpq_archive_s *a)
{
    if (a == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (a->write_mpqe && a->write_mpqe_ops != NULL)
        return a->write_mpqe_ops->finalize(a);
    return finalize_archive(a);
}
