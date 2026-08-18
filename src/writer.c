/* Seekable MPQ archive creation. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "common.h"
#include "endian.h"
#include "extract.h"
#include "mpq-internal.h"
#include <libmpq/mpq.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <bzlib.h>
#include <zlib.h>

static uint32_t
next_power_two(uint32_t value)
{
    uint32_t result = 4;
    while (result < value && result < 0x80000000u)
        result <<= 1;
    return result;
}

static int32_t
write_at(FILE *fp, uint64_t offset, const void *data, size_t size)
{
    if (fseeko(fp, (off_t)offset, SEEK_SET) < 0 || (size && fwrite(data, 1, size, fp) != size))
        return LIBMPQ_ERROR_WRITE;
    return LIBMPQ_SUCCESS;
}

static uint32_t
file_key(const char *name)
{
    char *normalized = NULL;
    size_t i, length = strlen(name);
    uint32_t key;

    normalized = malloc(length + 1);
    if (normalized == NULL)
        return 0;
    for (i = 0; i < length; i++)
        normalized[i] = name[i] == '/' ? '\\' : name[i];
    normalized[length] = 0;
    key = libmpq__hash_string(normalized, 0x300);
    free(normalized);
    return key;
}

static int
supported_mask(uint32_t mask)
{
    return (mask & ~(LIBMPQ_COMPRESSION_ZLIB | LIBMPQ_COMPRESSION_BZIP2)) == 0;
}

static int32_t
compress_stage(uint8_t **data, size_t *size, uint32_t mask)
{
    uint8_t *out;
    size_t out_size = *size + (*size / 100) + 1024;
    z_stream z;
    bz_stream b;
    int result;

    out = malloc(out_size);
    if (out == NULL)
        return LIBMPQ_ERROR_MALLOC;
    if (mask == LIBMPQ_COMPRESSION_ZLIB) {
        memset(&z, 0, sizeof(z));
        z.next_in = *data;
        z.avail_in = (uInt)*size;
        z.next_out = out;
        z.avail_out = (uInt)out_size;
        result = deflateInit(&z, Z_DEFAULT_COMPRESSION);
        if (result == Z_OK)
            result = deflate(&z, Z_FINISH);
        if (result == Z_STREAM_END)
            result = deflateEnd(&z);
        else
            deflateEnd(&z);
        if (result != Z_OK) {
            free(out);
            return LIBMPQ_ERROR_UNPACK;
        }
        out_size = z.total_out;
    } else {
        memset(&b, 0, sizeof(b));
        b.next_in = (char *)*data;
        b.avail_in = (unsigned int)*size;
        b.next_out = (char *)out;
        b.avail_out = (unsigned int)out_size;
        result = BZ2_bzCompressInit(&b, 9, 0, 30);
        if (result == BZ_OK) {
            do {
                result = BZ2_bzCompress(&b, BZ_FINISH);
            } while (result == BZ_FINISH_OK);
        }
        if (result == BZ_STREAM_END)
            result = BZ2_bzCompressEnd(&b);
        else
            BZ2_bzCompressEnd(&b);
        if (result != BZ_OK) {
            free(out);
            return LIBMPQ_ERROR_UNPACK;
        }
        out_size = b.total_out_lo32;
    }
    free(*data);
    *data = out;
    *size = out_size;
    return LIBMPQ_SUCCESS;
}

static int32_t
encode_sector(const uint8_t *input, size_t input_size, uint32_t requested, uint8_t **output,
              size_t *output_size, uint8_t *emitted_mask)
{
    uint8_t *data;
    size_t size;
    uint32_t masks[] = { LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_BZIP2 };
    size_t i;

    if (!supported_mask(requested))
        return LIBMPQ_ERROR_FORMAT;
    data = malloc(input_size ? input_size : 1);
    if (data == NULL)
        return LIBMPQ_ERROR_MALLOC;
    memcpy(data, input, input_size);
    size = input_size;
    *emitted_mask = 0;
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        if (requested & masks[i]) {
            int32_t result = compress_stage(&data, &size, masks[i]);
            if (result < 0) {
                free(data);
                return result;
            }
            *emitted_mask |= (uint8_t)masks[i];
        }
    }
    if (*emitted_mask == 0 || size + 1 >= input_size) {
        *emitted_mask = 0;
        *output = data;
        *output_size = size;
    } else {
        uint8_t *packed = realloc(data, size + 1);
        if (packed == NULL) {
            free(data);
            return LIBMPQ_ERROR_MALLOC;
        }
        memmove(packed + 1, packed, size);
        packed[0] = *emitted_mask;
        *output = packed;
        *output_size = size + 1;
    }
    return LIBMPQ_SUCCESS;
}

static int32_t
add_finished(mpq_file_writer_s *writer)
{
    mpq_archive_s *archive = writer->archive;
    uint32_t index, slot, hash1, hash2, hash3, mask;
    uint32_t blocks, i;
    uint64_t payload_offset, packed_total = 0;
    uint8_t *packed = NULL;
    uint32_t *offsets = NULL;
    uint32_t offset_count;
    int32_t result = LIBMPQ_SUCCESS;

    if (writer->written != writer->expected || archive->write_next_block >= archive->write_capacity)
        return LIBMPQ_ERROR_SIZE;
    if (archive->write_current != writer)
        return LIBMPQ_ERROR_EXIST;
    if ((writer->options.flags & LIBMPQ_FILE_FLAG_IMPLODE) != 0)
        return LIBMPQ_ERROR_FORMAT;
    mask = writer->options.compression_first;
    if (writer->options.compression_next == 0)
        writer->options.compression_next = mask;
    if ((writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0 && !supported_mask(mask))
        return LIBMPQ_ERROR_FORMAT;
    if ((writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0 &&
        !supported_mask(writer->options.compression_next))
        return LIBMPQ_ERROR_FORMAT;

    libmpq__file_hash(writer->name, &hash1, &hash2, &hash3);
    for (index = 0; index < archive->write_next_block; index++)
        if (archive->write_names[index] && archive->write_locales[index] == writer->options.locale &&
            archive->write_platforms[index] == writer->options.platform) {
            uint32_t a, b, c;
            libmpq__file_hash(archive->write_names[index], &a, &b, &c);
            if (a == hash1 && b == hash2 && c == hash3)
                return LIBMPQ_ERROR_EXIST;
        }

    blocks = (writer->options.flags & LIBMPQ_FILE_FLAG_SINGLE) ? 1 :
        (uint32_t)((writer->expected + archive->write_sector_size - 1) / archive->write_sector_size);
    if (blocks == 0)
        blocks = 1;
    if (blocks > UINT32_MAX - 1)
        return LIBMPQ_ERROR_SIZE;
    offset_count = blocks + 1;
    payload_offset = (uint64_t)ftello(archive->fp);
    if ((writer->options.flags & LIBMPQ_FILE_FLAG_SINGLE) == 0 &&
        (writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0) {
        offsets = calloc(offset_count, sizeof(*offsets));
        if (offsets == NULL)
            return LIBMPQ_ERROR_MALLOC;
        /* The offset table is part of the packed file and precedes its sectors. */
        if (fseeko(archive->fp, (off_t)(payload_offset + (uint64_t)offset_count * 4), SEEK_SET) < 0) {
            free(offsets);
            return LIBMPQ_ERROR_SEEK;
        }
        offsets[0] = offset_count * 4;
    }

    index = archive->write_next_block;
    if (payload_offset > UINT64_MAX)
        result = LIBMPQ_ERROR_SIZE;
    for (i = 0; result == LIBMPQ_SUCCESS && i < blocks; i++) {
        size_t input_size = (size_t)(writer->expected - (libmpq__off_t)i * archive->write_sector_size);
        if (input_size > archive->write_sector_size)
            input_size = archive->write_sector_size;
        uint32_t requested = (i == 0) ? writer->options.compression_first : writer->options.compression_next;
        uint8_t emitted = 0;
        size_t packed_size = input_size;
        uint32_t key = file_key(writer->name);
        if ((writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0)
            result = encode_sector(writer->data + (size_t)i * archive->write_sector_size,
                                   input_size, requested, &packed, &packed_size, &emitted);
        else {
            packed = malloc(input_size ? input_size : 1);
            if (packed == NULL)
                result = LIBMPQ_ERROR_MALLOC;
            else
                memcpy(packed, writer->data + (size_t)i * archive->write_sector_size, input_size);
        }
        if (result < 0)
            break;
        if ((writer->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED) != 0)
            libmpq__encrypt_block(packed, (uint32_t)packed_size, key + i);
        if (offsets)
            offsets[i] = (uint32_t)(ftello(archive->fp) - (off_t)payload_offset);
        if (fwrite(packed, 1, packed_size, archive->fp) != packed_size)
            result = LIBMPQ_ERROR_WRITE;
        packed_total += packed_size;
        free(packed);
        packed = NULL;
        if ((writer->options.flags & LIBMPQ_FILE_FLAG_SINGLE) != 0)
            break;
    }
    if (result < 0)
        goto done;
    if (offsets) {
        size_t table_size = (size_t)offset_count * sizeof(uint32_t);
        offsets[offset_count - 1] = (uint32_t)packed_total + (uint32_t)table_size;
        packed = malloc(table_size);
        if (packed == NULL) { result = LIBMPQ_ERROR_MALLOC; goto done; }
        for (i = 0; i < offset_count; i++)
            libmpq__store_le32(packed + i * 4, offsets[i]);
        if (writer->options.flags & LIBMPQ_FILE_FLAG_ENCRYPTED)
            libmpq__encrypt_block(packed, (uint32_t)table_size, file_key(writer->name) - 1);
        if (fseeko(archive->fp, (off_t)payload_offset, SEEK_SET) < 0 ||
            fwrite(packed, 1, table_size, archive->fp) != table_size) {
            result = LIBMPQ_ERROR_WRITE;
            goto done;
        }
        if (fseeko(archive->fp, 0, SEEK_END) < 0) { result = LIBMPQ_ERROR_SEEK; goto done; }
        packed_total += table_size;
    }
    if (payload_offset > UINT32_MAX || packed_total > UINT32_MAX || writer->expected > UINT32_MAX) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }
    archive->mpq_block[index].offset = (uint32_t)payload_offset;
    archive->mpq_block[index].packed_size = (uint32_t)packed_total;
    archive->mpq_block[index].unpacked_size = (uint32_t)writer->expected;
    archive->mpq_block[index].flags = LIBMPQ_FLAG_EXISTS | writer->options.flags;
    if ((writer->options.flags & LIBMPQ_FILE_FLAG_COMPRESS) != 0)
        archive->mpq_block[index].flags |= LIBMPQ_FLAG_COMPRESSED;
    archive->mpq_block_ex[index].offset_high = (uint16_t)(payload_offset >> 32);
    archive->write_names[index] = writer->name;
    archive->write_locales[index] = writer->options.locale;
    archive->write_platforms[index] = writer->options.platform;
    writer->name = NULL;
    archive->write_next_block++;
    archive->files = archive->write_next_block;
    mask = hash1 & (archive->write_hash_capacity - 1);
    for (slot = 0; slot < archive->write_hash_capacity; slot++) {
        uint32_t pos = (mask + slot) & (archive->write_hash_capacity - 1);
        if (archive->mpq_hash[pos].block_table_index == LIBMPQ_HASH_FREE) {
            archive->mpq_hash[pos].hash_a = hash2;
            archive->mpq_hash[pos].hash_b = hash3;
            archive->mpq_hash[pos].locale = writer->options.locale;
            archive->mpq_hash[pos].platform = writer->options.platform;
            archive->mpq_hash[pos].block_table_index = index;
            break;
        }
    }
done:
    free(offsets);
    free(packed);
    return result;
}

int32_t
libmpq__archive_create(mpq_archive_s **out, const char *path, const mpq_archive_create_options_s *options)
{
    mpq_archive_create_options_s defaults = { LIBMPQ_ARCHIVE_VERSION_ONE, 1024, 4096, 0 };
    mpq_archive_s *a;
    uint32_t i, header_size;
    uint64_t offset;
    uint8_t *zero;

    if (out == NULL || path == NULL) return LIBMPQ_ERROR_EXIST;
    *out = NULL;
    if (options == NULL) options = &defaults;
    if (options->version > LIBMPQ_ARCHIVE_VERSION_TWO || options->max_files == UINT32_MAX ||
        (options->max_files && options->max_files > 0x40000000u))
        return LIBMPQ_ERROR_FORMAT;
    if (options->sector_size && (options->sector_size < 512 ||
        (options->sector_size & (options->sector_size - 1)) != 0)) return LIBMPQ_ERROR_FORMAT;
    a = calloc(1, sizeof(*a));
    if (a == NULL) return LIBMPQ_ERROR_MALLOC;
    a->fp = fopen(path, "w+b");
    a->filename = strdup(path);
    if (a->fp == NULL || a->filename == NULL) { if (a->fp) fclose(a->fp); free(a->filename); free(a); return LIBMPQ_ERROR_OPEN; }
    a->write_mode = TRUE;
    a->write_capacity = options->max_files ? options->max_files : 1024;
    a->write_sector_size = options->sector_size ? options->sector_size : 4096;
    a->write_flags = options->flags;
    a->write_hash_capacity = next_power_two(a->write_capacity * 2);
    header_size = options->version == LIBMPQ_ARCHIVE_VERSION_TWO ? 44 : 32;
    a->mpq_header.version = (uint16_t)options->version;
    a->mpq_header.header_size = header_size;
    a->mpq_header.block_size = 0;
    while ((512u << a->mpq_header.block_size) < a->write_sector_size) a->mpq_header.block_size++;
    a->mpq_header.hash_table_count = a->write_hash_capacity;
    a->mpq_header.block_table_count = a->write_capacity;
    a->mpq_header.hash_table_offset = header_size;
    a->mpq_header.block_table_offset = header_size + a->write_hash_capacity * 16;
    a->mpq_header_ex.extended_offset = 0;
    offset = (uint64_t)a->mpq_header.block_table_offset + (uint64_t)a->write_capacity * 16;
    if (options->version == LIBMPQ_ARCHIVE_VERSION_TWO) {
        a->mpq_header_ex.extended_offset = offset;
        offset += (uint64_t)a->write_capacity * 2;
    }
    offset = (offset + 511) & ~UINT64_C(511);
    if (options->version == LIBMPQ_ARCHIVE_VERSION_ONE && offset > UINT32_MAX) { fclose(a->fp); free(a->filename); free(a); return LIBMPQ_ERROR_SIZE; }
    a->mpq_hash = calloc(a->write_hash_capacity, sizeof(*a->mpq_hash));
    a->mpq_block = calloc(a->write_capacity, sizeof(*a->mpq_block));
    a->mpq_block_ex = calloc(a->write_capacity, sizeof(*a->mpq_block_ex));
    a->write_names = calloc(a->write_capacity, sizeof(*a->write_names));
    a->write_locales = calloc(a->write_capacity, sizeof(*a->write_locales));
    a->write_platforms = calloc(a->write_capacity, sizeof(*a->write_platforms));
    if (!a->mpq_hash || !a->mpq_block || !a->mpq_block_ex || !a->write_names || !a->write_locales || !a->write_platforms) { fclose(a->fp); free(a->filename); free(a->mpq_hash); free(a->mpq_block); free(a->mpq_block_ex); free(a->write_names); free(a->write_locales); free(a->write_platforms); free(a); return LIBMPQ_ERROR_MALLOC; }
    for (i = 0; i < a->write_hash_capacity; i++) a->mpq_hash[i].block_table_index = LIBMPQ_HASH_FREE;
    zero = calloc(1, (size_t)(offset > 4096 ? 4096 : offset));
    if (zero == NULL || fwrite(zero, 1, (size_t)(offset > 4096 ? 4096 : offset), a->fp) != (size_t)(offset > 4096 ? 4096 : offset)) { free(zero); fclose(a->fp); free(a->filename); free(a->mpq_hash); free(a->mpq_block); free(a->mpq_block_ex); free(a->write_names); free(a->write_locales); free(a->write_platforms); free(a); return LIBMPQ_ERROR_WRITE; }
    free(zero);
    if (fseeko(a->fp, (off_t)offset, SEEK_SET) < 0) { fclose(a->fp); free(a->filename); return LIBMPQ_ERROR_SEEK; }
    *out = a;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__file_begin(mpq_archive_s *a, const char *name, libmpq__off_t size, const mpq_file_create_options_s *options, mpq_file_writer_s **out)
{
    mpq_file_create_options_s defaults = { 0, 0, 0, 0, 0 };
    mpq_file_writer_s *w;
    if (!a || !a->write_mode || !name || !out || size < 0 || a->write_current) return LIBMPQ_ERROR_FORMAT;
    if (options == NULL) options = &defaults;
    w = calloc(1, sizeof(*w));
    if (w == NULL) return LIBMPQ_ERROR_MALLOC;
    w->data = malloc(size ? (size_t)size : 1);
    w->name = strdup(name);
    if (w->data == NULL || w->name == NULL || (uint64_t)size > SIZE_MAX) { free(w->data); free(w->name); free(w); return LIBMPQ_ERROR_MALLOC; }
    w->archive = a; w->expected = size; w->options = *options; a->write_current = w; *out = w;
    return LIBMPQ_SUCCESS;
}

int32_t
libmpq__file_write(mpq_file_writer_s *w, const uint8_t *buffer, libmpq__off_t size)
{
    if (!w || !buffer || size < 0 || size > w->expected - w->written) return LIBMPQ_ERROR_SIZE;
    memcpy(w->data + w->written, buffer, (size_t)size); w->written += size; return LIBMPQ_SUCCESS;
}

int32_t
libmpq__file_finish(mpq_file_writer_s *w)
{
    int32_t result;
    if (!w) return LIBMPQ_ERROR_EXIST;
    result = add_finished(w);
    w->archive->write_current = NULL;
    free(w->name); free(w->data); free(w);
    return result;
}

int32_t
libmpq__file_add(mpq_archive_s *a, const char *name, const uint8_t *data, libmpq__off_t size, const mpq_file_create_options_s *options)
{
    mpq_file_writer_s *w; int32_t result = libmpq__file_begin(a, name, size, options, &w);
    if (result < 0) return result;
    result = libmpq__file_write(w, data, size); if (result < 0) { free(w->name); free(w->data); free(w); a->write_current = NULL; return result; }
    return libmpq__file_finish(w);
}

int32_t
libmpq__file_add_path(mpq_archive_s *a, const char *name, const char *source, const mpq_file_create_options_s *options)
{
    FILE *fp; off_t size; uint8_t *data; size_t got; int32_t result;
    fp = fopen(source, "rb"); if (!fp) return LIBMPQ_ERROR_OPEN;
    if (fseeko(fp, 0, SEEK_END) < 0 || (size = ftello(fp)) < 0 || fseeko(fp, 0, SEEK_SET) < 0) { fclose(fp); return LIBMPQ_ERROR_SEEK; }
    data = malloc(size ? (size_t)size : 1); if (!data) { fclose(fp); return LIBMPQ_ERROR_MALLOC; }
    got = fread(data, 1, (size_t)size, fp); fclose(fp); if (got != (size_t)size) { free(data); return LIBMPQ_ERROR_READ; }
    result = libmpq__file_add(a, name, data, size, options); free(data); return result;
}

static int32_t
finalize_archive(mpq_archive_s *a)
{
    uint8_t *raw; uint32_t i; size_t bytes; uint64_t end;
    uint8_t header[44];
    if (a->write_current) return LIBMPQ_ERROR_SIZE;
    if ((a->write_flags & LIBMPQ_ARCHIVE_CREATE_LISTFILE) != 0) {
        size_t total = 1; uint8_t *list; for (i = 0; i < a->write_next_block; i++) total += strlen(a->write_names[i]) + 1;
        list = malloc(total); if (!list) return LIBMPQ_ERROR_MALLOC; total = 0;
        for (i = 0; i < a->write_next_block; i++) { size_t n = strlen(a->write_names[i]); memcpy(list + total, a->write_names[i], n); total += n; list[total++] = '\n'; }
        { mpq_file_create_options_s o = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 }; int32_t r = libmpq__file_add(a, LIBMPQ_LISTFILE_NAME, list, (libmpq__off_t)total, &o); free(list); if (r < 0) return r; }
    }
    bytes = (size_t)a->write_hash_capacity * 16; raw = malloc(bytes); if (!raw) return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < a->write_hash_capacity; i++) { libmpq__store_le32(raw+i*16,a->mpq_hash[i].hash_a); libmpq__store_le32(raw+i*16+4,a->mpq_hash[i].hash_b); libmpq__store_le16(raw+i*16+8,a->mpq_hash[i].locale); libmpq__store_le16(raw+i*16+10,a->mpq_hash[i].platform); libmpq__store_le32(raw+i*16+12,a->mpq_hash[i].block_table_index); }
    libmpq__encrypt_block(raw, (uint32_t)bytes, libmpq__hash_string("(hash table)", 0x300));
    if (write_at(a->fp, a->mpq_header.hash_table_offset, raw, bytes) < 0) { free(raw); return LIBMPQ_ERROR_WRITE; } free(raw);
    bytes = (size_t)a->write_capacity * 16; raw = malloc(bytes); if (!raw) return LIBMPQ_ERROR_MALLOC;
    for (i = 0; i < a->write_capacity; i++) { libmpq__store_le32(raw+i*16,a->mpq_block[i].offset); libmpq__store_le32(raw+i*16+4,a->mpq_block[i].packed_size); libmpq__store_le32(raw+i*16+8,a->mpq_block[i].unpacked_size); libmpq__store_le32(raw+i*16+12,a->mpq_block[i].flags); }
    libmpq__encrypt_block(raw, (uint32_t)bytes, libmpq__hash_string("(block table)", 0x300));
    if (write_at(a->fp, a->mpq_header.block_table_offset, raw, bytes) < 0) { free(raw); return LIBMPQ_ERROR_WRITE; } free(raw);
    if (a->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) { bytes = (size_t)a->write_capacity * 2; raw = malloc(bytes); if (!raw) return LIBMPQ_ERROR_MALLOC; for (i=0;i<a->write_capacity;i++) libmpq__store_le16(raw+i*2,a->mpq_block_ex[i].offset_high); if (write_at(a->fp,a->mpq_header_ex.extended_offset,raw,bytes)<0){free(raw);return LIBMPQ_ERROR_WRITE;} free(raw); }
    if (fseeko(a->fp, 0, SEEK_END) < 0)
        return LIBMPQ_ERROR_SEEK;
    end = (uint64_t)ftello(a->fp);
    if (end > UINT32_MAX)
        return LIBMPQ_ERROR_SIZE;
    memset(header, 0, sizeof(header)); libmpq__store_le32(header, LIBMPQ_HEADER); libmpq__store_le32(header+4,a->mpq_header.header_size); libmpq__store_le32(header+8,(uint32_t)end); libmpq__store_le16(header+12,a->mpq_header.version); libmpq__store_le16(header+14,a->mpq_header.block_size); libmpq__store_le32(header+16,a->mpq_header.hash_table_offset); libmpq__store_le32(header+20,a->mpq_header.block_table_offset); libmpq__store_le32(header+24,a->mpq_header.hash_table_count); libmpq__store_le32(header+28,a->mpq_header.block_table_count);
    if (a->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) { libmpq__store_le64(header+32,a->mpq_header_ex.extended_offset); libmpq__store_le16(header+40,(uint16_t)(((uint64_t)a->mpq_header.hash_table_offset)>>32)); libmpq__store_le16(header+42,(uint16_t)(((uint64_t)a->mpq_header.block_table_offset)>>32)); }
    if (write_at(a->fp, 0, header, a->mpq_header.header_size) < 0 || fflush(a->fp) != 0) return LIBMPQ_ERROR_WRITE;
    a->write_finalized = TRUE; return LIBMPQ_SUCCESS;
}

int32_t
libmpq__writer_finalize(mpq_archive_s *a)
{
    return finalize_archive(a);
}
