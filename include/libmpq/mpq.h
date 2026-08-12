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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define LIBMPQ_API __attribute__((visibility("default")))
#else
#define LIBMPQ_API
#endif

/* API return values. Negative values are errors, zero means success. */
#define LIBMPQ_ERROR_OPEN (-1)            /* File open failed. */
#define LIBMPQ_ERROR_CLOSE (-2)           /* File close failed. */
#define LIBMPQ_ERROR_SEEK (-3)            /* File seek failed. */
#define LIBMPQ_ERROR_READ (-4)            /* File read failed. */
#define LIBMPQ_ERROR_WRITE (-5)           /* File write failed. */
#define LIBMPQ_ERROR_MALLOC (-6)          /* Memory allocation failed. */
#define LIBMPQ_ERROR_FORMAT (-7)          /* Archive format is invalid. */
#define LIBMPQ_ERROR_NOT_INITIALIZED (-8) /* Library initialization is missing. */
#define LIBMPQ_ERROR_SIZE (-9)            /* Caller-provided buffer is too small. */
#define LIBMPQ_ERROR_EXIST (-10)          /* File or block does not exist in archive. */
#define LIBMPQ_ERROR_DECRYPT (-11)        /* Decryption seed is unknown. */
#define LIBMPQ_ERROR_UNPACK (-12)         /* File unpacking failed. */

/* Opaque archive handle owned by libmpq. */
typedef struct mpq_archive mpq_archive_s;

/* Public file offset type used by all archive and file size APIs. */
typedef int64_t libmpq__off_t;

/* Return the configured libmpq package version string. */
extern LIBMPQ_API const char *libmpq__version(void);

/* Translate a libmpq return code into a static diagnostic string. */
extern LIBMPQ_API const char *libmpq__strerror(int32_t return_code);

/* Open an MPQ archive from a file path and optional embedded archive offset. */
extern LIBMPQ_API int32_t libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
);

/* Close an opened archive and release its decoded metadata tables. */
extern LIBMPQ_API int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);

/* Return the sum of packed sizes for all extractable files. */
extern LIBMPQ_API int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size);

/* Return the sum of unpacked sizes for all extractable files. */
extern LIBMPQ_API int32_t
libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, libmpq__off_t *unpacked_size);

/* Return the byte offset where the MPQ archive starts in the backing file. */
extern LIBMPQ_API int32_t libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset);

/* Return the MPQ archive format version. */
extern LIBMPQ_API int32_t libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version);

/* Return the number of valid file entries discovered while opening the archive. */
extern LIBMPQ_API int32_t libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files);

/* Return the packed size for one file entry. */
extern LIBMPQ_API int32_t libmpq__file_size_packed(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *packed_size
);

/* Return the unpacked size for one file entry. */
extern LIBMPQ_API int32_t libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
);

/* Return the file payload offset relative to the archive start. */
extern LIBMPQ_API int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset);

/* Return the number of blocks used by one file entry. */
extern LIBMPQ_API int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks);

/* Report whether one file entry has the MPQ encrypted flag set. */
extern LIBMPQ_API int32_t
libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted);

/* Report whether one file entry uses Blizzard multi-compression. */
extern LIBMPQ_API int32_t
libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed);

/* Report whether one file entry uses PKWARE implosion. */
extern LIBMPQ_API int32_t
libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded);

/* Resolve an MPQ file name to a public file number. */
extern LIBMPQ_API int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number);

/* Read a complete file into the caller-provided output buffer. */
extern LIBMPQ_API int32_t libmpq__file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
);

/* Open and cache the packed block offset table for one file entry. */
extern LIBMPQ_API int32_t
libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number);

/* Release a cached block offset table for one file entry. */
extern LIBMPQ_API int32_t
libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number);

/* Return the unpacked size for one block of an opened file entry. */
extern LIBMPQ_API int32_t libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
);

/* Read, decrypt and decompress one block from an opened file entry. */
extern LIBMPQ_API int32_t libmpq__block_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
);

#ifdef __cplusplus
}
#endif

#endif /* LIBMPQ_MPQ_H */
