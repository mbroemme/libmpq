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
#if defined(__GNUC__) && (__GNUC__ >= 4)
#define LIBMPQ_API __attribute__((visibility("default")))
#else
#define LIBMPQ_API
#endif

/*
 * API return codes shared by archive, file, and block operations.
 * Successful calls return zero; failures return one of these negative values
 * so callers can distinguish I/O, format, allocation, size, and unpacking
 * failures without relying on a process-global error variable.  Functions
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

/*
 * Opaque archive handle owned by libmpq. Callers obtain it from an open or
 * create operation and must release it with libmpq__archive_close. The
 * structure layout is private so applications must not allocate or inspect it.
 */
typedef struct mpq_archive mpq_archive_s;

/*
 * Opaque state for one file currently being written to an archive. A writer
 * is created by libmpq__file_begin and owns the streaming state until finish
 * or failure. Applications must use the writer API instead of accessing its
 * private allocation directly.
 */
typedef struct mpq_writer mpq_writer_s;

/*
 * Archive format selectors accepted by mpq_archive_create_options_s.version.
 * Version one writes the classic 32-bit-offset MPQ header, while version two
 * adds the high-offset table required by the extended v2 layout.  The values
 * are selectors rather than the raw on-disk version numbers and must not be
 * combined with one another.
 */
#define LIBMPQ_ARCHIVE_VERSION_ONE 0
#define LIBMPQ_ARCHIVE_VERSION_TWO 1

/*
 * Archive-creation flags accepted by mpq_archive_create_options_s.flags.
 * LIBMPQ_ARCHIVE_CREATE_LISTFILE asks the writer to generate an internal
 * `(listfile)` entry containing the names added to the archive in insertion
 * order.  This improves name discovery in external MPQ tools and has no
 * effect on the payload compression or encryption of user files.
 */
#define LIBMPQ_ARCHIVE_CREATE_LISTFILE 0x00000001u

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
#define LIBMPQ_FILE_FLAG_LOCALE 0x00000000u

/*
 * Compression-stage bits accepted by mpq_file_options_s.compression_first and
 * compression_next.  Each selected stage is attempted in registry order and
 * only successful size-reducing stages are emitted in the sector mask.
 * The first-sector mask may differ from the mask used for later sectors, and
 * the reader reverses the successful stages when unpacking a sector.  The
 * mono and stereo WAVE ADPCM bits are mutually exclusive.
 */
#ifndef LIBMPQ_COMPRESSION_HUFFMAN
#define LIBMPQ_COMPRESSION_HUFFMAN 0x01u
#define LIBMPQ_COMPRESSION_ZLIB 0x02u
#define LIBMPQ_COMPRESSION_PKZIP 0x08u
#define LIBMPQ_COMPRESSION_BZIP2 0x10u
#define LIBMPQ_COMPRESSION_WAVE_MONO 0x40u
#define LIBMPQ_COMPRESSION_WAVE_STEREO 0x80u
#endif

/*
 * Options controlling creation of a new MPQ archive. Zero values select the
 * writer defaults, while explicit values make archive layout and capacity
 * reproducible. The structure is read when libmpq__archive_create is called
 * and is not retained by the library after that call returns.
 */
typedef struct
{
    uint32_t version;     /* Archive format selector; LIBMPQ_ARCHIVE_VERSION_* is required. */
    uint32_t max_files;   /* Reserved file-entry capacity; zero selects the default capacity. */
    uint32_t sector_size; /* Power-of-two unpacked sector size; zero selects 4096 bytes. */
    uint32_t flags;       /* LIBMPQ_ARCHIVE_CREATE_* options applied during finalization. */
} mpq_archive_create_options_s;

/*
 * Options controlling how one file is stored in a newly created archive.
 * Compression masks select the first-sector and later-sector pipelines, while
 * flags select raw, compressed, encrypted, imploded, or single-unit storage.
 * The locale and platform fields participate in duplicate detection and hash
 * lookup; the structure is copied when a file writer is started.
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
 * Signed public offset type used for archive positions and file sizes. A
 * negative value is reserved for error reporting and is never a valid size or
 * offset. The type keeps the public ABI consistent across supported systems.
 */
typedef int64_t libmpq__off_t;

/*
 * Return the library package version as a static, NUL-terminated string.
 * The returned pointer is owned by libmpq and remains valid for the process
 * lifetime; callers must not modify or free it. This function cannot fail.
 */
extern LIBMPQ_API const char *libmpq__version(void);

/*
 * Translate a libmpq return code into a static diagnostic string.
 * The returned pointer is owned by the library and is safe to retain, but its
 * contents must not be modified or freed. Unknown codes produce a generic
 * diagnostic rather than causing an allocation or other side effect.
 */
extern LIBMPQ_API const char *libmpq__strerror(int32_t return_code);

/*
 * Open an MPQ archive from a path and return a newly allocated read handle.
 * A negative archive_offset requests embedded-header scanning; a nonnegative
 * value restricts parsing to that absolute archive-relative location. On
 * success the caller owns the handle and must close it. On failure the output
 * handle is set to NULL and the function returns a negative LIBMPQ_ERROR_* code.
 */
extern LIBMPQ_API int32_t libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
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
 * Existing MPQE streams cannot be modified. Creation requires temporary
 * plaintext storage in the destination directory; that temporary file is
 * owner-only, while the completed MPQE output uses the caller's normal umask
 * permissions. Cleanup is best effort, so a process crash can leave an
 * owner-only temporary plaintext file behind.
 */
extern LIBMPQ_API int32_t libmpq__archive_create_mpqe(
    mpq_archive_s **mpq_archive, const char *mpqe_filename, const uint8_t *auth_code,
    size_t auth_code_size, const mpq_archive_create_options_s *options
);

/*
 * Begin a file stream in a writer archive and reserve its declared size.
 * The returned writer accepts only the number of bytes specified by
 * unpacked_size and applies the copied file options sector by sector.
 * Only one writer may be active per archive; finish it or abandon it before
 * beginning another file.
 */
extern LIBMPQ_API int32_t libmpq__file_begin(
    mpq_archive_s *mpq_archive, const char *filename, libmpq__off_t unpacked_size,
    const mpq_file_options_s *options, mpq_writer_s **writer
);

/*
 * Append source bytes to an active file writer.
 * The writer buffers at most one sector and flushes complete sectors through
 * the selected compression and encryption pipeline. The call fails if the
 * input would exceed the size declared by libmpq__file_begin.
 */
extern LIBMPQ_API int32_t
libmpq__file_write(mpq_writer_s *writer, const uint8_t *buffer, libmpq__off_t size);

/*
 * Finish an active file writer and publish its block and hash-table entries.
 * Any final partial sector is flushed before metadata is committed, and the
 * writer handle becomes invalid after this call regardless of its result.
 */
extern LIBMPQ_API int32_t libmpq__file_finish(mpq_writer_s *writer);

/*
 * Add a complete in-memory file to a writer archive.
 * This convenience operation performs begin, write, and finish using the same
 * validation and per-sector pipeline as the streaming API. The input buffer
 * remains owned by the caller and may be released after the call returns.
 */
extern LIBMPQ_API int32_t libmpq__file_add(
    mpq_archive_s *mpq_archive, const char *filename, const uint8_t *buffer, libmpq__off_t size,
    const mpq_file_options_s *options
);

/*
 * Add a filesystem file to a writer archive without requiring the whole source
 * file in memory. The source is read in bounded chunks, while the archive
 * entry uses the supplied name and storage options. The source file is read
 * only; it is never modified by this operation.
 */
extern LIBMPQ_API int32_t libmpq__file_add_path(
    mpq_archive_s *mpq_archive, const char *filename, const char *source_path,
    const mpq_file_options_s *options
);

/*
 * Clone an opened archive into an independent read handle.
 * The clone reopens and reparses the source so file positions, decoded tables,
 * and cached state are not shared with the original handle. Both handles are
 * independently closable, but the source must remain valid while cloning.
 */
extern LIBMPQ_API int32_t libmpq__archive_clone(mpq_archive_s **clone, mpq_archive_s *source);

/*
 * Close an archive handle and release all decoded tables, caches, and streams.
 * For writer handles this also finalizes the archive header and encrypted
 * metadata tables. A reader close failure leaves the handle intact so the
 * caller may retry; otherwise the handle must not be used again after this call.
 */
extern LIBMPQ_API int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);

/*
 * Calculate the total stored size of all extractable file entries.
 * The result includes packed payload bytes as represented by the block table,
 * but excludes archive headers and table storage. The output pointer must be
 * valid and the handle must refer to an opened archive.
 */
extern LIBMPQ_API int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size);

/*
 * Calculate the total logical size of all extractable file entries.
 * Sizes are summed after decompression and before any caller buffer limits are
 * applied. The function writes the result to unpacked_size and returns a
 * negative error for an invalid handle or output pointer.
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
 * The result identifies the supported v1 or v2 layout rather than the raw
 * on-disk version field. The output pointer must be valid and is unchanged on
 * failure.
 */
extern LIBMPQ_API int32_t libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version);

/*
 * Return the number of valid extractable file entries in an archive.
 * The value is the public file-number range used by the file query and read
 * functions, not the reserved block-table capacity or raw hash-table count.
 */
extern LIBMPQ_API int32_t libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files);

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
 * of how many sectors or compression stages are stored on disk.
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
 * Report whether one file entry has MPQ sector encryption enabled.
 * The output is set to a nonzero value when the block flags contain the
 * encrypted bit and to zero otherwise; no payload is read or modified.
 */
extern LIBMPQ_API int32_t
libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted);

/*
 * Report whether one file entry uses Blizzard multi-compression.
 * This identifies the MPQ COMPRESS container flag and does not claim that each
 * requested stage reduced every sector; individual sectors may use raw data.
 */
extern LIBMPQ_API int32_t
libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed);

/*
 * Report whether one file entry uses the standalone PKWARE implode format.
 * Standalone implode is distinct from PKWARE being selected as one bit in a
 * Blizzard multi-compression mask.
 */
extern LIBMPQ_API int32_t
libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded);

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
 * Read a complete logical file into a caller-provided output buffer.
 * The library decrypts and decompresses sectors as necessary and reports the
 * number of bytes copied through transferred. out_size must be large enough
 * for the unpacked file or the operation returns LIBMPQ_ERROR_SIZE.
 */
extern LIBMPQ_API int32_t libmpq__file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
);

/*
 * Open and cache the packed sector-offset table for one file entry.
 * This is required before block-level queries or reads of compressed files and
 * increments an internal cache reference count. Repeated opens are allowed
 * and must be balanced with libmpq__block_close_offset calls.
 */
extern LIBMPQ_API int32_t
libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number);

/*
 * Release one reference to a cached sector-offset table.
 * When the final reference is closed, the associated allocation is discarded;
 * callers must not use block offsets obtained from that cache afterward.
 */
extern LIBMPQ_API int32_t
libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number);

/*
 * Return the logical unpacked size of one sector in an opened file entry.
 * The file's offset table must be open for compressed multi-sector data, and
 * block_number must be within the count returned by libmpq__file_blocks.
 */
extern LIBMPQ_API int32_t libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
);

/*
 * Read one logical sector from an opened file entry.
 * The operation locates the packed bytes, decrypts them when required, and
 * reverses the MPQ compression pipeline before copying to out_buf. The
 * caller must provide sufficient space for the selected block and receives the
 * actual byte count through transferred.
 */
extern LIBMPQ_API int32_t libmpq__block_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
);

#ifdef __cplusplus
}
#endif

#endif /* LIBMPQ_MPQ_H */
