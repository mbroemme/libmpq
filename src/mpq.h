/*
 *  mpq.h -- public libmpq API declarations and constants.
 *
 *  Copyright (c) 2003-2011 Maik Broemme <mbroemme@libmpq.org>
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

#ifndef _MPQ_H
#define _MPQ_H

#ifdef __cplusplus
extern "C" {
#endif

/* system includes. */
#include <stdint.h>
#include <sys/types.h>

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define LIBMPQ_API __attribute__((visibility("default")))
#else
#define LIBMPQ_API
#endif

/* API return values. Negative values are errors, zero means success. */
#define LIBMPQ_ERROR_OPEN -1            /* open error on file. */
#define LIBMPQ_ERROR_CLOSE -2           /* close error on file. */
#define LIBMPQ_ERROR_SEEK -3            /* lseek error on file. */
#define LIBMPQ_ERROR_READ -4            /* read error on file. */
#define LIBMPQ_ERROR_WRITE -5           /* write error on file. */
#define LIBMPQ_ERROR_MALLOC -6          /* memory allocation error. */
#define LIBMPQ_ERROR_FORMAT -7          /* format error. */
#define LIBMPQ_ERROR_NOT_INITIALIZED -8 /* libmpq__init() wasn't called. */
#define LIBMPQ_ERROR_SIZE -9            /* buffer size is too small. */
#define LIBMPQ_ERROR_EXIST -10          /* file or block does not exist in archive. */
#define LIBMPQ_ERROR_DECRYPT -11        /* we don't know the decryption seed. */
#define LIBMPQ_ERROR_UNPACK -12         /* error on unpacking file. */

/* Opaque archive handle owned by libmpq. */
typedef struct mpq_archive mpq_archive_s;

/* Public file offset type used by all archive and file size APIs. */
typedef int64_t libmpq__off_t;

/* Library metadata. */
extern LIBMPQ_API const char *libmpq__version(void);

/* Error reporting. */
extern LIBMPQ_API const char *libmpq__strerror(int32_t return_code);

/* Archive lifecycle and metadata APIs. */
extern LIBMPQ_API int32_t libmpq__archive_open(
    mpq_archive_s **mpq_archive, const char *mpq_filename, libmpq__off_t archive_offset
);
extern LIBMPQ_API int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);
extern LIBMPQ_API int32_t
libmpq__archive_size_packed(mpq_archive_s *mpq_archive, libmpq__off_t *packed_size);
extern LIBMPQ_API int32_t
libmpq__archive_size_unpacked(mpq_archive_s *mpq_archive, libmpq__off_t *unpacked_size);
extern LIBMPQ_API int32_t libmpq__archive_offset(mpq_archive_s *mpq_archive, libmpq__off_t *offset);
extern LIBMPQ_API int32_t libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version);
extern LIBMPQ_API int32_t libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files);

/* File metadata and full-file read APIs. */
extern LIBMPQ_API int32_t libmpq__file_size_packed(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *packed_size
);
extern LIBMPQ_API int32_t libmpq__file_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *unpacked_size
);
extern LIBMPQ_API int32_t
libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, libmpq__off_t *offset);
extern LIBMPQ_API int32_t
libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks);
extern LIBMPQ_API int32_t
libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted);
extern LIBMPQ_API int32_t
libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed);
extern LIBMPQ_API int32_t
libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded);
extern LIBMPQ_API int32_t
libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number);
extern LIBMPQ_API int32_t libmpq__file_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, libmpq__off_t out_size,
    libmpq__off_t *transferred
);

/* Block offset cache and per-block read APIs. */
extern LIBMPQ_API int32_t
libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t
libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__block_size_unpacked(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number,
    libmpq__off_t *unpacked_size
);
extern LIBMPQ_API int32_t libmpq__block_read(
    mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf,
    libmpq__off_t out_size, libmpq__off_t *transferred
);

#ifdef __cplusplus
}
#endif

#endif /* _MPQ_H */
