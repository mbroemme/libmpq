/*
 *  mpq-reader.h -- internal archive reader declarations.
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

#ifndef LIBMPQ_READER_H
#define LIBMPQ_READER_H

#include <libmpq/mpq.h>
#include <stddef.h>
#include <stdint.h>

/* Translate a classic block row to validated canonical metadata, not a public number. */
int32_t libmpq__entry_index_from_classic(
    const mpq_archive_s *archive, uint32_t block_index, uint32_t *entry_index
);
int32_t libmpq__entry_index_from_bet(
    const mpq_archive_s *archive, uint64_t bet_index, uint32_t *entry_index
);

/* Infer v3 stored sizes from ordering, or use independently bounded v4 extents. */
int32_t libmpq__reader_ext_table_sizes(
    const mpq_archive_s *archive, uint64_t *het_size, uint64_t *bet_size
);

/* Explicit v4 stored-envelope raw verification; EXIST means unavailable, not verified. */
int32_t libmpq__reader_verify_ext_raw_md5(mpq_archive_s *archive, uint32_t signature);

int32_t libmpq__reader_block_size_packed(
    mpq_archive_s *archive, uint32_t number, uint32_t block, libmpq__off_t *packed_size
);

int32_t libmpq__reader_block_compression(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint32_t *compression
);

int32_t libmpq__reader_file_read(
    mpq_archive_s *archive, uint32_t number, uint8_t *buffer, libmpq__off_t size,
    libmpq__off_t *transferred
);

/*
 * Internal scoped cache references shared by file reads, attributes and verify.
 * A name supplies the known internal file key. Every success needs a release.
 */
int32_t libmpq__reader_offsets_acquire(mpq_archive_s *archive, uint32_t number, const char *name);

/* Optional caller-owned seed is already adjusted for the original member metadata. */
int32_t libmpq__reader_offsets_acquire_key(
    mpq_archive_s *archive, uint32_t number, const char *name, const uint32_t *seed
);
int32_t libmpq__reader_offsets_release(mpq_archive_s *archive, uint32_t number);

/* Share block I/O; callers can supply one checksum and mismatch result. */
int32_t libmpq__reader_block_read(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred, const uint32_t *checksum,
    uint32_t *mismatches, int *lossy
);
int32_t libmpq__reader_block_read_acquired(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred, const uint32_t *checksum,
    uint32_t *mismatches, int *lossy
);

/* Strict name provenance, with classic enumeration in original slot order. */
typedef struct
{
    mpq_file_identity_s identity;
    uint32_t slot; /* UINT32_MAX for a name represented only by BET. */
} mpq_named_identity_s;

int32_t libmpq__reader_name_identities(
    mpq_archive_s *archive, const char *name, mpq_named_identity_s **identities, uint32_t *count
);
int32_t libmpq__reader_bet_match(void *context, uint64_t index, uint64_t hash, int *matches);

/* Private packed-sector operations on a member with acquired offsets. */
int32_t libmpq__reader_block_stored_acquired(
    mpq_archive_s *archive, uint32_t number, uint32_t block, uint8_t *buffer, uint32_t capacity,
    uint32_t *size
);
void libmpq__reader_packed_block_check(
    uint32_t flags, const uint8_t *packed, uint32_t size, uint32_t plain_size,
    const uint32_t *checksum, uint32_t *mismatches, int *lossy
);
int32_t libmpq__reader_packed_block_decode(
    uint32_t flags, uint32_t version, uint8_t *packed, uint32_t size, uint8_t *out,
    uint32_t plain_size
);

/*
 * Load optional checksums with an internally scoped sector-offset reference.
 * A successful NULL result means this file has no checksum table.
 */
int32_t
libmpq__reader_sector_checksums(mpq_archive_s *archive, uint32_t file_number, uint32_t **checksums);
int32_t libmpq__reader_validate_payload_range(
    const mpq_archive_s *archive, uint32_t index, uint64_t offset, uint64_t size
);

/* Discovery provenance is revalidated from source bytes, not inherited from clones. */
typedef struct
{
    uint64_t origin;
    uint64_t user_data_position;
    uint32_t user_data_size;
    uint32_t user_data_header_size;
    uint32_t header_offset;
    uint8_t has_user_data;
} mpq_prefix_info_s;

int32_t libmpq__reader_archive_prefix_info(const mpq_archive_s *archive, mpq_prefix_info_s *prefix);

/*
 * Open and parse an archive at archive_offset. A negative offset enables the
 * embedded-archive scan; otherwise the offset is interpreted as an absolute
 * file position. On success the returned archive owns its input source and metadata.
 */
int32_t libmpq__reader_archive_open_path(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
);
int32_t libmpq__reader_archive_open_mpqe(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    const uint8_t *auth_code, size_t auth_code_size
);
int32_t libmpq__reader_archive_open_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const char *source_name
);
int32_t libmpq__reader_archive_open_mpqe_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const uint8_t *auth_code,
    size_t auth_code_size, const char *source_name
);
int32_t libmpq__reader_archive_clone(mpq_archive_s **clone, const mpq_archive_s *source);

/* Decode count serialized little-endian uint32 values into native storage. */
void libmpq__reader_decode_uint32_table(uint32_t *table, const uint8_t *raw, uint32_t count);

/* Validate that file_number addresses a populated file entry in the archive. */
int32_t libmpq__reader_validate_file_number(mpq_archive_s *mpq_archive, uint32_t file_number);

/* Return the number of sectors required by a file, or zero for an invalid file. */
uint32_t libmpq__reader_count_file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number);

/* Validate both a file number and one of its sector indexes. */
int32_t libmpq__reader_validate_block_number(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number
);

/* Resolve and, when necessary, recover the encryption seed for one file sector. */
int32_t libmpq__reader_get_block_seed(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed
);

/*
 * Return the checked minimum archive-relative extent required by parsed classic
 * serialized ranges. This does not include valid v1 trailing padding.
 */
int32_t libmpq__archive_required_extent(const mpq_archive_s *archive, uint64_t *size);

/*
 * Return the archive-relative extent weak signatures must cover. v1 uses its
 * declared archive size after validating it contains the required extent;
 * v2 uses the full 64-bit required extent. v3 uses its effective declared size.
 */
int32_t libmpq__archive_signature_extent(const mpq_archive_s *archive, uint64_t *size);

/* Stored classic extents, including compressed table representations. */
int32_t libmpq__reader_classic_table_sizes(const mpq_archive_s *archive, uint64_t sizes[2]);

#endif /* LIBMPQ_READER_H */
