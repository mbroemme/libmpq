/*
 *  mpq.h -- public libmpq API declarations and constants.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  Some parts (the encryption and decryption stuff) were adapted from
 *  the C++ version of StormLib.h and StormPort.h included in stormlib.
 *  The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
 *  Marko Friedemann <marko.friedemann@bmx-chemnitz.de>
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

#ifndef LIBMPQ_MPQ_H
#define LIBMPQ_MPQ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Export public symbols when the compiler supports symbol visibility. */
#ifndef LIBMPQ_API
#if !defined(_WIN32) && defined(__GNUC__) && (__GNUC__ >= 4)
#define LIBMPQ_API __attribute__((visibility("default")))
#else
#define LIBMPQ_API
#endif
#endif

/* Public error codes. */

/*
 * API return codes shared by archive, file, and block operations.
 * Successful calls return zero; failures return one of these negative values
 * so callers can distinguish I/O, format, allocation, size, and unpacking
 * failures without relying on a process-global error variable. Functions
 * that return a pointer or have a void result document their separate result
 * behavior at the declaration site.
 */
#define LIBMPQ_ERROR_OPEN (-1)            /* File open failed. */
#define LIBMPQ_ERROR_CLOSE (-2)           /* File close failed. */
#define LIBMPQ_ERROR_SEEK (-3)            /* File seek failed. */
#define LIBMPQ_ERROR_READ (-4)            /* File read failed. */
#define LIBMPQ_ERROR_WRITE (-5)           /* File write failed. */
#define LIBMPQ_ERROR_MALLOC (-6)          /* Memory allocation failed. */
#define LIBMPQ_ERROR_FORMAT (-7)          /* Archive format is invalid. */
#define LIBMPQ_ERROR_NOT_INITIALIZED (-8) /* Library initialization is missing. */
#define LIBMPQ_ERROR_SIZE (-9)            /* Caller-provided buffer is too small. */
#define LIBMPQ_ERROR_EXIST (-10)          /* Archive, file, or block does not exist. */
#define LIBMPQ_ERROR_DECRYPT (-11)        /* Decryption seed is unknown. */
#define LIBMPQ_ERROR_UNPACK (-12)         /* File unpacking failed. */

/* Public types and opaque handles. */

/*
 * Signed public type used for archive offsets, logical positions, and sizes.
 * The signed representation also permits negative relative offsets for
 * libmpq__stream_seek().
 */
typedef int64_t libmpq__off_t;

/* Fixed-width archive-writer compression policy; reading needs no policy. */
typedef int32_t libmpq_compression_policy_t;

/*
 * Opaque archive handle owned by libmpq. Callers obtain it from an open or
 * create operation and must release it with libmpq__archive_close. The
 * structure layout is private so applications must not allocate or inspect it.
 */
typedef struct mpq_archive mpq_archive_s;

/* Opaque incremental stream for one logical archive member. */
typedef struct mpq_stream mpq_stream_s;

/*
 * Opaque state for one file currently being written to an archive. A writer
 * is created by libmpq__writer_begin and owns the streaming state until finish
 * or failure. Applications operate on this handle through libmpq__writer_*
 * instead of accessing its private allocation directly. The handle is consumed
 * by libmpq__writer_finish(), regardless of its result.
 */
typedef struct mpq_writer mpq_writer_s;

/* Opaque staged archive-update transaction; commit or abort consumes it. */
typedef struct mpq_update mpq_update_s;

/* Opaque staged patch-artifact writer; finish or abort consumes it. */
typedef struct mpq_patch mpq_patch_s;

/*
 * Read exactly size bytes at an absolute offset in a caller-owned source.
 * Success requires a zero result and a fully populated buffer. Negative
 * LIBMPQ_ERROR_* results report failure; callbacks must not retain buffer.
 */
typedef int32_t (*libmpq_read_at_fn)(
    void *context, libmpq__off_t offset, uint8_t *buffer, size_t size
);

/* Archive format and creation constants. */

/*
 * On-disk archive format versions (not combinable flags). Creation accepts
 * only ONE and TWO; THREE is supported for reading classic-table archives.
 * libmpq__archive_version() reports the corresponding one-based generation.
 */
#define LIBMPQ_ARCHIVE_VERSION_ONE 0
#define LIBMPQ_ARCHIVE_VERSION_TWO 1
#define LIBMPQ_ARCHIVE_VERSION_THREE 2

/*
 * Archive-creation flags accepted by mpq_archive_create_options_s.flags.
 * LIBMPQ_ARCHIVE_CREATE_LISTFILE asks the writer to generate an internal
 * `(listfile)` entry containing the names added to the archive in insertion
 * order. This improves name discovery in external MPQ tools and has no
 * effect on the payload compression or encryption of user files.
 */
#define LIBMPQ_ARCHIVE_CREATE_LISTFILE 0x00000001u

/* Opt into EXTENDED writer compression; absence selects STANDARD. */
#define LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED 0x00000002u

/* File storage and compression constants. */

/*
 * File-storage flags accepted by mpq_file_options_s.flags.
 * IMPLODE selects standalone PKWARE storage, while COMPRESS selects the MPQ
 * multi-compression container whose stages come from the compression masks.
 * ENCRYPTED applies per-file sector encryption after packing; SINGLE stores
 * the file as one unit and is incompatible with sector-level ADPCM options.
 * LIBMPQ_FILE_FLAG_LOCALE is a zero-valued compatibility marker; locale and
 * platform identity are supplied by the corresponding structure members.
 */
#define LIBMPQ_FILE_FLAG_IMPLODE 0x00000100u
#define LIBMPQ_FILE_FLAG_COMPRESS 0x00000200u
#define LIBMPQ_FILE_FLAG_ENCRYPTED 0x00010000u
#define LIBMPQ_FILE_FLAG_SINGLE 0x01000000u

/* Reader-visible patch and deletion entries; these are not writer options. */
#define LIBMPQ_FILE_FLAG_PATCH_FILE 0x00100000u
#define LIBMPQ_FILE_FLAG_DELETE_MARKER 0x02000000u

/*
 * Generate sector Adler-32 checksums for sectorized compressed/imploded files.
 * Ignored for empty, raw, or single-unit files.
 */
#define LIBMPQ_FILE_FLAG_SECTOR_CRC 0x04000000u
#define LIBMPQ_FILE_FLAG_LOCALE 0x00000000u

/* Writer interoperability policy values. */
enum
{
    LIBMPQ_COMPRESSION_POLICY_STANDARD = 0,
    LIBMPQ_COMPRESSION_POLICY_EXTENDED = 1
};

/*
 * Compression-stage bits accepted by mpq_file_options_s.compression_first and
 * compression_next. Each selected stage is attempted in registry order and
 * only successful size-reducing stages are emitted in the sector mask.
 * The first-sector mask may differ from the mask used for later sectors, and
 * the reader reverses the successful stages when unpacking a sector. The
 * mono and stereo WAVE ADPCM bits are mutually exclusive. For MPQ v2+, the
 * writer rejects chains containing both zlib and bzip2 because the resulting
 * successful-stage mask could be 0x12, which is reserved for LZMA.
 *
 * STANDARD further limits v2 to zlib, PKWARE, bzip2, LZMA, SPARSE alone or
 * paired with zlib/bzip2, and Huffman paired with exactly one WAVE ADPCM bit.
 *
 * EXTENDED permits other implemented chains and standalone Huffman, which
 * may be less interoperable with other readers.
 *
 * SPARSE cannot precede lossy WAVE ADPCM under either policy.
 */
#ifndef LIBMPQ_COMPRESSION_HUFFMAN
#define LIBMPQ_COMPRESSION_HUFFMAN 0x01u
#endif

#ifndef LIBMPQ_COMPRESSION_ZLIB
#define LIBMPQ_COMPRESSION_ZLIB 0x02u
#endif

#ifndef LIBMPQ_COMPRESSION_PKZIP
#define LIBMPQ_COMPRESSION_PKZIP 0x08u
#endif

#ifndef LIBMPQ_COMPRESSION_BZIP2
#define LIBMPQ_COMPRESSION_BZIP2 0x10u
#endif

#ifndef LIBMPQ_COMPRESSION_WAVE_MONO
#define LIBMPQ_COMPRESSION_WAVE_MONO 0x40u
#endif

#ifndef LIBMPQ_COMPRESSION_WAVE_STEREO
#define LIBMPQ_COMPRESSION_WAVE_STEREO 0x80u
#endif

/*
 * Exclusive MPQ v2+ LZMA writer selector. This API-only value is outside the
 * serialized one-byte MPQ compression mask: the writer maps it to on-disk
 * method 0x12. It must not be combined with compression-stage bits.
 */
#ifndef LIBMPQ_COMPRESSION_LZMA
#define LIBMPQ_COMPRESSION_LZMA 0x00000100u
#endif

/* Lossless zero-run stage; cannot be combined with lossy WAVE ADPCM. */
#ifndef LIBMPQ_COMPRESSION_SPARSE
#define LIBMPQ_COMPRESSION_SPARSE 0x20u
#endif

/* Integrity and signature constants. */

/*
 * Array-presence flags in the independent version-100 attributes payload.
 * Also accepted by mpq_archive_create_options_s.attributes in every supported
 * MPQ version. Any nonzero combination creates one `(attributes)` file and
 * consumes one reserved file slot, regardless of the number of selected arrays.
 */
#define LIBMPQ_ATTRIBUTE_CRC32 0x01u
#define LIBMPQ_ATTRIBUTE_FILETIME 0x02u
#define LIBMPQ_ATTRIBUTE_MD5 0x04u
#define LIBMPQ_ATTRIBUTE_PATCH_BIT 0x08u

/* Shared bits for requested checks and reported mismatches, not attributes. */
#define LIBMPQ_VERIFY_SECTOR_CRC 0x00000001u
#define LIBMPQ_VERIFY_FILE_CRC32 0x00000002u
#define LIBMPQ_VERIFY_FILE_MD5 0x00000004u
#define LIBMPQ_VERIFY_ALL                                                                          \
    (LIBMPQ_VERIFY_SECTOR_CRC | LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5)

/*
 * Signature type bits returned by libmpq__archive_signatures() and accepted
 * by signing and verification APIs.
 */
#define LIBMPQ_SIGNATURE_WEAK 0x00000001u
#define LIBMPQ_SIGNATURE_STRONG 0x00000002u

/* Stream seek constants. */

/*
 * Seek origins accepted by libmpq__stream_seek(): SET begins at zero,
 * CUR uses the current position, and END uses the logical member end.
 */
#define LIBMPQ_SEEK_SET 0
#define LIBMPQ_SEEK_CUR 1
#define LIBMPQ_SEEK_END 2

/* Public option and metadata structures. */

/*
 * Options controlling creation of a new MPQ archive. Zero values select the
 * writer defaults, while explicit values make archive layout and capacity
 * reproducible. The structure is read when libmpq__archive_create is called
 * and is not retained by the library after that call returns. Its native ABI
 * is 20 bytes, with five consecutive 32-bit fields and no padding.
 */
typedef struct
{
    uint32_t version;     /* Archive format selector; LIBMPQ_ARCHIVE_VERSION_* is required. */
    uint32_t max_files;   /* Reserved file-entry capacity; zero selects the default capacity. */
    uint32_t sector_size; /* Power-of-two unpacked sector size; zero selects 4096 bytes. */
    uint32_t flags;       /* LIBMPQ_ARCHIVE_CREATE_* policy and finalization options. */
    uint32_t attributes;  /* LIBMPQ_ATTRIBUTE_* arrays; zero disables attributes generation. */
} mpq_archive_create_options_s;

/*
 * Options controlling how one archive member is stored by writer, add,
 * replacement, and patch-creation operations. Compression masks select the
 * first-sector and later-sector pipelines, while flags select raw,
 * compressed, encrypted, imploded, or single-unit storage.
 * LIBMPQ_COMPRESSION_LZMA is an exclusive MPQ v2+ selector rather than a
 * chainable pipeline mask. Locale and platform participate in duplicate
 * detection and hash lookup; replacement requires them to match the existing
 * member. The structure is copied when a file writer is started.
 */
typedef struct mpq_file_options
{
    uint32_t flags;             /* LIBMPQ_FILE_FLAG_* storage, compression, and encryption bits. */
    uint32_t compression_first; /* Multi-compression mask applied to the first sector. */
    uint32_t compression_next;  /* Multi-compression mask applied to later sectors. */
    uint16_t locale;            /* MPQ locale identifier used for lookup and duplicate checks. */
    uint16_t platform;          /* MPQ platform identifier used for lookup and duplicates. */
} mpq_file_options_s;

/*
 * Stored per-file metadata. Complete lossless reads verify available CRC32/MD5
 * values; flags identifies available fields; unavailable fields are zero. FILETIME
 * is an unsigned Windows timestamp, MD5 is sixteen bytes, and patch_bit is
 * zero or one. The native ABI is 40 bytes with FILETIME at offset 8 and
 * four explicit reserved bytes at offset 36, always returned as zero.
 * Natural alignment is retained; this is not the serialized attributes layout.
 */
typedef struct
{
    uint32_t flags;      /* LIBMPQ_ATTRIBUTE_* bits identifying available values. */
    uint32_t crc32;      /* Source-byte CRC32 when the corresponding flag is set. */
    uint64_t filetime;   /* Windows FILETIME when the corresponding flag is set. */
    uint8_t md5[16];     /* Source-byte MD5 when the corresponding flag is set. */
    int32_t patch_bit;   /* Patch marker value, zero or one, when available. */
    uint8_t reserved[4]; /* Explicit ABI padding; not serialized attribute data. */
} mpq_file_attributes_s;

/* Utility functions. */

/*
 * Return the library package version as a static, NUL-terminated string.
 * The returned pointer is owned by libmpq and remains valid for the process
 * lifetime; callers must not modify or free it. This function cannot fail.
 */
extern LIBMPQ_API const char *libmpq__version(void);

/*
 * Translate a libmpq return code into a static diagnostic string.
 * The returned pointer is owned by the library and is safe to retain, but its
 * contents must not be modified or freed. Unknown or unsupported codes
 * return NULL without allocation or other side effects.
 */
extern LIBMPQ_API const char *libmpq__strerror(int32_t return_code);

/*
 * Return 1 if the compression selection is allowed for the archive version
 * and policy, otherwise 0. archive_version uses
 * LIBMPQ_ARCHIVE_VERSION_* selectors (0=v1, 1=v2), not the one-based value
 * returned by libmpq__archive_version. Zero means raw storage. LZMA requires
 * the exclusive LIBMPQ_COMPRESSION_LZMA selector, not on-disk method 0x12.
 * WAVE input and file-storage constraints still apply when adding a file.
 * SPARSE is allowed alone or with lossless stages according to the policy.
 * This query does not restrict reads.
 */
extern LIBMPQ_API int32_t libmpq__archive_compression_allowed(
    uint32_t archive_version, uint32_t compression_mask, libmpq_compression_policy_t policy
);

/* Archive lifecycle. */

/*
 * Open an MPQ archive from a path and return a newly allocated read handle.
 * A negative archive_offset requests embedded-header scanning; a nonnegative
 * value restricts parsing to that absolute byte offset in the backing source. On
 * success the caller owns the handle and must close it. On failure the output
 * handle is set to NULL and the function returns a negative LIBMPQ_ERROR_* code.
 */
extern LIBMPQ_API int32_t libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
);

/*
 * Open an MPQ from a caller-owned exact random-access byte source. The source
 * is borrowed: context, including NULL for stateless callbacks, and callback
 * state must remain valid through archive close and any derived clones.
 * Negative archive_offset enables header scan. source_name is optional and is
 * copied into archive-owned storage as the logical archive name. Its basename
 * is used for legacy strong-signature verification; omit it when unavailable.
 */
extern LIBMPQ_API int32_t libmpq__archive_open_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const char *source_name
);

/*
 * Open a read-only MPQE-encrypted stream containing an MPQ archive. MPQE is
 * an installer transport layer and is decrypted before the normal MPQ header,
 * table, and file processing begins. auth_code is an opaque
 * caller-owned buffer: at least its first 32 bytes must be available for the
 * legacy MPQE key derivation. The buffer is neither retained nor modified.
 *
 * The function supports only MPQ versions otherwise supported by libmpq. It
 * does not discover, store, or retrieve installer keys. A NULL or too-short
 * authentication-code buffer returns LIBMPQ_ERROR_DECRYPT. A structurally
 * valid but wrong code cannot be identified by MPQE itself. The resulting
 * bytes are parsed normally and can produce LIBMPQ_ERROR_FORMAT or another
 * ordinary parser error. On failure, mpq_archive is set to NULL when it is
 * non-NULL.
 */
extern LIBMPQ_API int32_t libmpq__archive_open_mpqe(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset,
    const uint8_t *auth_code, size_t auth_code_size
);

/*
 * Open an MPQE-wrapped MPQ through a caller-owned exact random-access source.
 * The source ownership and lifetime rules, including optional copied source_name,
 * match libmpq__archive_open_io().
 */
extern LIBMPQ_API int32_t libmpq__archive_open_mpqe_io(
    mpq_archive_s **mpq_archive, void *context, libmpq_read_at_fn read_at,
    libmpq__off_t source_size, libmpq__off_t archive_offset, const uint8_t *auth_code,
    size_t auth_code_size, const char *source_name
);

/*
 * Create a seekable MPQ v1 or v2 archive at mpq_filename.
 * The options determine the format, reserved table capacity, sector size, and
 * optional internal files; zero options select documented writer defaults.
 * The returned handle remains in write mode until close finalizes its tables,
 * and the caller must close it even when no files are added.
 */
extern LIBMPQ_API int32_t libmpq__archive_create(
    mpq_archive_s **mpq_archive, const char *mpq_filename,
    const mpq_archive_create_options_s *options
);

/*
 * Create a new MPQE-encrypted stream containing an MPQ v1 or v2 archive.
 * The archive is first finalized in a private temporary file, then encrypted
 * and atomically published at mpqe_filename when libmpq__archive_close()
 * succeeds. auth_code is borrowed only during this call; at least
 * 32 bytes are required and invalid input returns LIBMPQ_ERROR_DECRYPT.
 *
 * Creation requires temporary plaintext storage in the destination directory;
 * that file is owner-only, while the completed MPQE output uses the caller's
 * normal umask permissions. Cleanup is best effort, so a process crash can leave an
 * owner-only temporary plaintext file behind.
 */
extern LIBMPQ_API int32_t libmpq__archive_create_mpqe(
    mpq_archive_s **mpq_archive, const char *mpqe_filename, const uint8_t *auth_code,
    size_t auth_code_size, const mpq_archive_create_options_s *options
);

/*
 * Clone an opened archive into an independent read handle.
 * The clone reopens a filesystem source or clones the custom source backend
 * and reparses its tables, so decoded metadata and caches are independent.
 * Custom-I/O callback context remains caller-owned. Both handles are
 * independently closable; the backing source must remain valid.
 */
extern LIBMPQ_API int32_t libmpq__archive_clone(mpq_archive_s **clone, mpq_archive_s *source);

/*
 * Close an archive handle and release all decoded tables, caches, and streams.
 * For writer handles this also finalizes the archive header and encrypted
 * metadata tables. The archive handle is invalid after this call regardless
 * of the returned status.
 */
extern LIBMPQ_API int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);

/* Archive information and signatures. */

/*
 * Add the stored sizes of all extractable entries to *packed_size.
 * The sizes include packed payload bytes but exclude headers and tables.
 * Pass a valid opened archive and output pointer, initialized to zero when
 * the total alone is required.
 */
extern LIBMPQ_API int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size);

/*
 * Add the logical sizes of all extractable entries to *unpacked_size.
 * Pass a valid opened archive and output pointer, initialized to zero when
 * the total alone is required.
 */
extern LIBMPQ_API int32_t
libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, libmpq__off_t *unpacked_size);

/*
 * Return the archive's absolute start offset in its backing file.
 * Normal standalone archives return zero, while an archive embedded in another
 * file reports the discovered or requested location. The output is written
 * to offset and the handle remains unchanged.
 */
extern LIBMPQ_API int32_t libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset);

/*
 * Return the public MPQ format version of an opened archive.
 * The result identifies the supported v1, v2 or v3 layout rather than the raw
 * on-disk version field. Pass a valid opened archive and output pointer.
 */
extern LIBMPQ_API int32_t libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version);

/*
 * Return the number of valid extractable file entries in an archive.
 * The value is the public file-number range used by the file query and read
 * functions, not the reserved block-table capacity or raw hash-table count.
 */
extern LIBMPQ_API int32_t libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files);

/*
 * Query the optional internal file on a reader. Returns EXIST if absent,
 * FORMAT for invalid metadata, and stores its header flags in *flags on
 * success. Ordinary archive opening and extraction do not depend on
 * attributes validity.
 */
extern LIBMPQ_API int32_t libmpq__archive_attributes(mpq_archive_s *mpq_archive, uint32_t *flags);

/* Detect structurally present weak and strong signatures; this does not verify them. */
extern LIBMPQ_API int32_t libmpq__archive_signatures(mpq_archive_s *archive, uint32_t *signatures);

/*
 * Verify exactly one requested signature using a caller-owned public key.
 * Store a cryptographic mismatch in *mismatches; the archive is not consumed.
 */
extern LIBMPQ_API int32_t libmpq__archive_verify(
    mpq_archive_s *archive, uint32_t verify_flags, const uint8_t *public_key,
    size_t public_key_size, uint32_t *mismatches
);

/*
 * Configure weak or strong signing on a writable archive using a copied key.
 * Signing occurs during archive close; this call does not consume the handle.
 * MPQE-wrapped archives support weak, but not external strong, signatures.
 */
extern LIBMPQ_API int32_t libmpq__archive_sign(
    mpq_archive_s *archive, uint32_t signature_type, const uint8_t *private_key,
    size_t private_key_size
);

/* File access and verification. */

/*
 * Resolve a plaintext MPQ filename to its public file number.
 * The name is hashed using the library's Storm-compatible rules and matched
 * against locale and platform variants in the archive. The returned number
 * is suitable for the size, property, block, and read APIs.
 */
extern LIBMPQ_API int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number);

/*
 * Calculate the three Storm-compatible hashes used to identify an MPQ name.
 * The outputs are deterministic for a given byte string and are written to
 * hash1, hash2, and hash3; this helper performs no archive lookup and cannot
 * report an allocation or I/O error.
 */
extern LIBMPQ_API void
libmpq__file_hash(const char *filename, uint32_t *hash1, uint32_t *hash2, uint32_t *hash3);

/*
 * Resolve precomputed Storm filename hashes to a public file number.
 * This avoids recalculating the hashes when a caller already has them, but it
 * otherwise follows the same collision probing and table validation as name
 * lookup. The caller must supply all three hashes from the same filename.
 */
extern LIBMPQ_API int32_t libmpq__file_number_from_hash(
    mpq_archive_s *mpq_archive, uint32_t hash1, uint32_t hash2, uint32_t hash3, uint32_t *number
);

/*
 * Return the stored size of one public file entry.
 * The value includes sector offset-table bytes when the file uses a packed
 * multi-sector representation, and excludes unrelated archive metadata.
 */
extern LIBMPQ_API int32_t libmpq__file_size_packed(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *packed_size
);

/*
 * Return the logical size of one public file entry after decompression.
 * This is the size callers should expect from libmpq__file_read, independent
 * of how many sectors or compression stages are stored on disk. For a patch
 * member it is the patched target size, not the decoded PTCH payload size.
 */
extern LIBMPQ_API int32_t libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
);

/*
 * Return the file payload offset relative to the beginning of the MPQ archive.
 * The value points to the stored file representation, which may begin with a
 * sector offset table for compressed multi-sector files.
 */
extern LIBMPQ_API int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset);

/*
 * Return the number of logical sectors used by one file entry.
 * For compressed files this is also the number of data sectors described by
 * the packed offset table; single-unit files report one block.
 */
extern LIBMPQ_API int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks);

/*
 * Return the actual stored MPQ block-table flags for one archive member.
 * Inspect LIBMPQ_FILE_FLAG_* bits for storage properties; compressed files
 * may contain raw fallback sectors. The output is zeroed before validation.
 */
extern LIBMPQ_API int32_t
libmpq__file_flags(mpq_archive_s *archive, uint32_t file_number, uint32_t *flags);

/*
 * Return available stored attributes for a public file number on a reader.
 * Legacy missing entries return zero flags, not invented checksum values.
 * PATCH_BIT is metadata only and does not enable patch application.
 */
extern LIBMPQ_API int32_t libmpq__file_attributes(
    mpq_archive_s *mpq_archive, uint32_t file_number, mpq_file_attributes_s *attributes
);

/*
 * Verify requested available sector Adler-32 and file CRC32/MD5 checksums.
 * Sector checks use decrypted packed bytes; file checks use extracted bytes.
 * Returns success with mismatch bits in *mismatches, or a negative operation error.
 * The output is a subset of verify_flags: set bits denote available mismatches;
 * clear bits denote matching or unavailable/skipped checksums.
 * File checks require attributes (EXIST if absent); sector checks do not.
 * Missing individual values or sector tables are skipped.
 * A zero request is a no-op on a valid reader/file. Unknown bits return FORMAT.
 * *mismatches is zero on errors. Zero bits do not imply values were present.
 * Lossy ADPCM output can differ from the writer's source-byte checksums.
 */
extern LIBMPQ_API int32_t libmpq__file_verify(
    mpq_archive_s *archive, uint32_t file_number, uint32_t verify_flags, uint32_t *mismatches
);

/*
 * Read a complete logical file into a caller-provided output buffer.
 * The library decrypts and decompresses sectors as necessary and reports the
 * number of bytes copied through transferred. When available, stored CRC32
 * and MD5 values are checked after decoding a complete lossless logical file;
 * usable sector Adler-32 values are checked over decrypted packed data before
 * decoding. A mismatch returns LIBMPQ_ERROR_READ. Malformed optional metadata
 * is skipped during extraction, and lossy ADPCM skips only file CRC32/MD5.
 * out_size must be large enough for the unpacked file or the operation returns
 * LIBMPQ_ERROR_SIZE.
 */
extern LIBMPQ_API int32_t libmpq__file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
);

/* Logical member streams. */

/*
 * Open an independent stream for a logical archive member. The stream owns a
 * private archive clone and remains usable after archive closes.
 * Open by name when the plaintext filename is needed for encrypted members.
 */
extern LIBMPQ_API int32_t
libmpq__stream_open(mpq_archive_s *archive, uint32_t file_number, mpq_stream_s **stream);

/* Open an independent incremental stream after resolving a plaintext filename. */
extern LIBMPQ_API int32_t
libmpq__stream_open_name(mpq_archive_s *archive, const char *filename, mpq_stream_s **stream);

/*
 * Read up to size logical bytes and advance the stream position. Reads at EOF
 * succeed with zero transferred bytes. Available sector Adler-32 values are
 * checked as sectors load; file-level CRC32/MD5 attributes are not implicit.
 */
extern LIBMPQ_API int32_t libmpq__stream_read(
    mpq_stream_s *stream, uint8_t *buffer, libmpq__off_t size, libmpq__off_t *transferred
);

/*
 * Set the logical position relative to LIBMPQ_SEEK_SET, LIBMPQ_SEEK_CUR, or
 * LIBMPQ_SEEK_END. Only positions from zero through the logical size are valid.
 */
extern LIBMPQ_API int32_t
libmpq__stream_seek(mpq_stream_s *stream, libmpq__off_t offset, int32_t origin);

/* Return the current logical read position without performing archive I/O. */
extern LIBMPQ_API int32_t libmpq__stream_tell(mpq_stream_s *stream, libmpq__off_t *position);

/* Return the immutable logical unpacked member size without performing archive I/O. */
extern LIBMPQ_API int32_t libmpq__stream_size(mpq_stream_s *stream, libmpq__off_t *size);

/* Close and consume a logical stream, releasing its cache and private clone. */
extern LIBMPQ_API int32_t libmpq__stream_close(mpq_stream_s *stream);

/* Block access and verification. */

/*
 * Return one block's stored byte size, excluding offset/checksum tables.
 * Compressed sector offsets are loaded internally; raw and single-unit sizes
 * come from archive metadata. Encryption does not change the size. A non-NULL
 * packed_size output is initialized to zero and remains zero on any failure.
 */
extern LIBMPQ_API int32_t libmpq__block_size_packed(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, libmpq__off_t *packed_size
);

/*
 * Return the logical unpacked size of one sector in an archive member.
 * No explicit offset-table management is required;
 * block_number must be within the count returned by libmpq__file_blocks.
 */
extern LIBMPQ_API int32_t libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
);

/*
 * Return the stored method byte, zero for raw storage (including fallback),
 * or LIBMPQ_COMPRESSION_PKZIP for a legacy imploded block. Method 0x12 is the
 * legacy bzip2/zlib chain in v1 and LZMA in v2; this is not the writer's LZMA
 * selector. No decompression or checksum verification is performed. A non-NULL
 * compression output is initialized to zero and remains zero on failure.
 */
extern LIBMPQ_API int32_t libmpq__block_compression(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint32_t *compression
);

/*
 * Verify one sector's stored Adler-32 over packed bytes after decryption.
 * Success returns the stored checksum and either zero or VERIFY_SECTOR_CRC
 * in mismatches. Unavailable checksums (including zero/all-ones entries) return
 * ERROR_EXIST. Both non-NULL outputs are zeroed before validation and remain
 * zero on any error. libmpq__block_read() does not implicitly verify the
 * stored sector checksum.
 */
extern LIBMPQ_API int32_t libmpq__block_verify(
    mpq_archive_s *archive, uint32_t file_number, uint32_t block_number, uint32_t *checksum,
    uint32_t *mismatches
);

/*
 * Read one logical sector from an archive member, managing its offset cache
 * internally for the duration of the read.
 * The operation locates the packed bytes, decrypts them when required, and
 * reverses the MPQ compression pipeline before copying to out_buf. The
 * caller must provide sufficient space for the selected block and receives the
 * actual byte count through transferred.
 */
extern LIBMPQ_API int32_t libmpq__block_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
);

/* Archive writing. */

/*
 * Begin writing a file in a writer archive and reserve its declared size.
 * The returned writer accepts only the number of bytes specified by
 * unpacked_size and applies the copied file options sector by sector.
 * Only one writer may be active per archive; finish it or abandon it before
 * beginning another file.
 */
extern LIBMPQ_API int32_t libmpq__writer_begin(
    mpq_archive_s *mpq_archive, const char *filename, libmpq__off_t unpacked_size,
    const mpq_file_options_s *options, mpq_writer_s **writer
);

/*
 * Set Windows FILETIME, not Unix time, on an active file writer. Generation of
 * FILETIME must be enabled or FORMAT is returned. The default is zero;
 * neither this API nor path-based addition imports filesystem metadata.
 */
extern LIBMPQ_API int32_t libmpq__writer_timestamp(mpq_writer_s *writer, uint64_t filetime);

/*
 * Append source bytes to an active file writer.
 * The writer buffers at most one sector and flushes complete sectors through
 * the selected compression and encryption pipeline. The call fails if the
 * input would exceed the size declared by libmpq__writer_begin.
 */
extern LIBMPQ_API int32_t
libmpq__writer_write(mpq_writer_s *writer, const uint8_t *buffer, libmpq__off_t size);

/*
 * Finish an active file writer and publish its block and hash-table entries.
 * Any final partial sector is flushed before metadata is committed, and the
 * writer handle becomes invalid after this call regardless of its result.
 */
extern LIBMPQ_API int32_t libmpq__writer_finish(mpq_writer_s *writer);

/*
 * Add a complete in-memory file to a writer archive.
 * This convenience operation performs begin, write, and finish using the same
 * validation and per-sector pipeline as the streaming API. The input buffer
 * remains owned by the caller and may be released after the call returns.
 */
extern LIBMPQ_API int32_t libmpq__archive_add_data(
    mpq_archive_s *mpq_archive, const char *filename, const uint8_t *buffer, libmpq__off_t size,
    const mpq_file_options_s *options
);

/*
 * Add a filesystem file to a writer archive without requiring the whole source
 * file in memory. The source is read in bounded chunks, while the archive
 * entry uses the supplied name and storage options. The source file is read
 * only; it is never modified by this operation.
 */
extern LIBMPQ_API int32_t libmpq__archive_add_path(
    mpq_archive_s *mpq_archive, const char *filename, const char *source_path,
    const mpq_file_options_s *options
);

/* Transactional archive updates. */

/*
 * Stage changes to an existing filesystem MPQ in a private working copy.
 * Changes reach the original only when commit atomically publishes that copy.
 * Embedded MPQs retain their container prefix and unrelated trailing bytes.
 * Stale weak and strong signatures are removed on modification. MPQE archives
 * require the explicit authenticated update_begin_mpqe() entry point.
 */
extern LIBMPQ_API int32_t libmpq__update_begin(mpq_update_s **update, const char *path);

/*
 * Begin an authenticated MPQE update using a private plaintext working copy.
 * The caller's authentication code is borrowed only during this call; at
 * least 32 bytes are required. Commit re-encrypts and atomically publishes
 * the updated archive. A crash can leave a private plaintext temporary file.
 */
extern LIBMPQ_API int32_t libmpq__update_begin_mpqe(
    mpq_update_s **update, const char *archive_path, const uint8_t *auth_code, size_t auth_code_size
);

/*
 * Stage replacement of an existing named member from caller-owned bytes.
 * NULL options select native defaults and preserve locale/platform identity.
 */
extern LIBMPQ_API int32_t libmpq__update_replace_data(
    mpq_update_s *update, const char *filename, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
);

/*
 * Stage replacement from a filesystem path; the source remains caller-owned.
 * NULL options select native defaults and preserve locale/platform identity.
 */
extern LIBMPQ_API int32_t libmpq__update_replace_path(
    mpq_update_s *update, const char *filename, const char *source_path,
    const mpq_file_options_s *options
);

/* Stage removal of one named member without consuming the update handle. */
extern LIBMPQ_API int32_t libmpq__update_remove(mpq_update_s *update, const char *filename);

/* Stage a named-member rename without consuming the update handle. */
extern LIBMPQ_API int32_t
libmpq__update_rename(mpq_update_s *update, const char *old_filename, const char *new_filename);

/*
 * Validate and atomically publish staged changes. This consumes the update
 * handle even if publication fails; callers must not use it afterward.
 */
extern LIBMPQ_API int32_t libmpq__update_commit(mpq_update_s *update);

/*
 * Discard staged changes and leave the original archive untouched.
 * This consumes the update handle even when cleanup reports an error.
 */
extern LIBMPQ_API int32_t libmpq__update_abort(mpq_update_s *update);

/* Patch payload access. */

/*
 * Return the decoded PTCH payload size for a patch-file member. The ordinary
 * file size describes the patched target, not this stored payload.
 */
extern LIBMPQ_API int32_t
libmpq__patch_payload_size(mpq_archive_s *archive, uint32_t file_number, libmpq__off_t *size);

/*
 * Decode and validate a patch-file member's PTCH payload into caller memory.
 * filename is the physical archive name used for encrypted members; it may be
 * NULL when no name-derived key is needed. This does not apply the patch.
 */
extern LIBMPQ_API int32_t libmpq__patch_payload_read(
    mpq_archive_s *archive, uint32_t file_number, const char *filename, uint8_t *buffer,
    libmpq__off_t capacity, libmpq__off_t *transferred
);

/* Patch archive creation. */

/*
 * Stage a new patch archive without changing the base archive. The output
 * path is published only when finish succeeds; abort discards it. MPQE and
 * embedded base archives are not supported by this patch writer.
 */
extern LIBMPQ_API int32_t
libmpq__patch_begin(mpq_patch_s **patch, const char *base_archive, const char *output_patch);

/*
 * Stage an MPQE-wrapped patch artifact using a caller-supplied authentication
 * code. The code is borrowed only during begin; finish publishes the encrypted
 * patch and abort discards it. The base remains an ordinary filesystem MPQ.
 */
extern LIBMPQ_API int32_t libmpq__patch_begin_mpqe(
    mpq_patch_s **patch, const char *base_archive, const char *output_patch,
    const uint8_t *auth_code, size_t auth_code_size
);

/*
 * Configure signing on an active patch writer using the archive signing API.
 * The call is non-consuming; actual signing occurs during finish.
 */
extern LIBMPQ_API int32_t libmpq__patch_sign(
    mpq_patch_s *patch, uint32_t signature_type, const uint8_t *private_key, size_t private_key_size
);

/*
 * Stage replacement of an existing base member from caller-owned bytes.
 * NULL options select patch defaults; explicit options store the patch member
 * and must match the base member's locale and platform.
 */
extern LIBMPQ_API int32_t libmpq__patch_replace_data(
    mpq_patch_s *patch, const char *filename, const uint8_t *data, libmpq__off_t size,
    const mpq_file_options_s *options
);

/*
 * Stage replacement from a filesystem path without changing the base archive.
 * NULL options select patch defaults; explicit options must match the base
 * member's locale and platform.
 */
extern LIBMPQ_API int32_t libmpq__patch_replace_path(
    mpq_patch_s *patch, const char *filename, const char *source_path,
    const mpq_file_options_s *options
);

/* Stage a delete marker for an existing named base member. */
extern LIBMPQ_API int32_t libmpq__patch_remove(mpq_patch_s *patch, const char *filename);

/*
 * Finalize and publish the patch artifact without changing the base archive.
 * This consumes the patch handle even if finalization fails.
 */
extern LIBMPQ_API int32_t libmpq__patch_finish(mpq_patch_s *patch);

/*
 * Discard the staged patch artifact without changing the base archive.
 * This consumes the patch handle even when cleanup reports an error.
 */
extern LIBMPQ_API int32_t libmpq__patch_abort(mpq_patch_s *patch);

#ifdef __cplusplus
}
#endif

#endif /* LIBMPQ_MPQ_H */
