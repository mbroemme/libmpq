/*
 *  mpq-internal.h -- internal MPQ archive structures and constants.
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

#ifndef LIBMPQ_MPQ_INTERNAL_H
#define LIBMPQ_MPQ_INTERNAL_H

#include <libmpq/mpq.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* Common success return code used by libmpq functions. */
#define LIBMPQ_SUCCESS 0

/* MPQ archive signature stored as the little-endian bytes "MPQ\x1A". */
#define LIBMPQ_HEADER 0x1A51504D

/* MPQ archive version used before World of Warcraft: The Burning Crusade. */
#define LIBMPQ_ARCHIVE_VERSION_ONE 0

/* MPQ archive version used by World of Warcraft: The Burning Crusade and newer. */
#define LIBMPQ_ARCHIVE_VERSION_TWO 1

/* File entry exists in the block table and has not been deleted. */
#define LIBMPQ_FLAG_EXISTS 0x80000000

/* File payload is encrypted and must be decrypted before decompression. */
#define LIBMPQ_FLAG_ENCRYPTED 0x00010000

/* Mask covering all MPQ compression mode bits. */
#define LIBMPQ_FLAG_COMPRESSED 0x0000FF00

/* File payload uses the PKWARE Data Compression Library algorithm. */
#define LIBMPQ_FLAG_COMPRESS_PKZIP 0x00000100

/* File payload uses Blizzard's chained multi-compression format. */
#define LIBMPQ_FLAG_COMPRESS_MULTI 0x00000200

/* Internal libmpq marker for an uncompressed block. */
#define LIBMPQ_FLAG_COMPRESS_NONE 0x00000300

/* File is stored as a single sector without a packed block offset table. */
#define LIBMPQ_FLAG_SINGLE 0x01000000

/* Packed block offset table has an additional CRC checksum entry. */
#define LIBMPQ_FLAG_CRC 0x04000000

/* Hash-table slot has never held a file entry. */
#define LIBMPQ_HASH_FREE 0xFFFFFFFF

/* Well-known pseudo-files stored inside some MPQ archives. */
#define LIBMPQ_LISTFILE_NAME "(listfile)"
#define LIBMPQ_SIGNATURE_NAME "(signature)"
#define LIBMPQ_ATTRIBUTES_NAME "(attributes)"

/* Keep boolean-like constants available for old C environments. */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#include "pack_begin.h"

/* On-disk MPQ archive header. */
typedef struct
{
    uint32_t mpq_magic;          /* MPQ signature. */
    uint32_t header_size;        /* Size of this header in bytes. */
    uint32_t archive_size;       /* Size of the archive in bytes. */
    uint16_t version;            /* Archive format version. */
    uint16_t block_size;         /* File sector size exponent: 512 * 2 ^ block_size. */
    uint32_t hash_table_offset;  /* Offset of the hash table from the archive start. */
    uint32_t block_table_offset; /* Offset of the block table from the archive start. */
    uint32_t hash_table_count;   /* Number of entries in the hash table. */
    uint32_t block_table_count;  /* Number of entries in the block table. */
} PACK_STRUCT mpq_header_s;

/* Extended archive offsets used by version 2 archives. */
typedef struct
{
    uint64_t extended_offset; /* Offset of the extended block table from the archive start. */
    uint16_t
        hash_table_offset_high; /* Upper 16 bits of the hash table offset for large archives. */
    uint16_t
        block_table_offset_high; /* Upper 16 bits of the block table offset for large archives. */
} PACK_STRUCT mpq_header_ex_s;

/* Hash-table entry used to locate a file by Storm filename hashes. */
typedef struct
{
    uint32_t hash_a;            /* First filename hash. */
    uint32_t hash_b;            /* Second filename hash. */
    uint16_t locale;            /* File locale identifier. */
    uint16_t platform;          /* File platform identifier; zero means default. */
    uint32_t block_table_index; /* Index into the block table. */
} PACK_STRUCT mpq_hash_s;

/* Block-table entry describing the stored payload for one file. */
typedef struct
{
    uint32_t offset;        /* Payload offset from the archive start. */
    uint32_t packed_size;   /* Stored payload size. */
    uint32_t unpacked_size; /* Size after decryption and decompression. */
    uint32_t flags;         /* MPQ file flags. */
} PACK_STRUCT mpq_block_s;

/* High offset bits for large archives whose file payloads cross 4 GiB. */
typedef struct
{
    uint16_t offset_high; /* Upper 16 bits of the file payload offset. */
} PACK_STRUCT mpq_block_ex_s;

/* Cached state for an opened MPQ file entry. */
typedef struct
{
    uint32_t seed;                /* Per-file decryption seed. */
    uint8_t seed_known;           /* Whether seed was recovered successfully. */
    uint32_t *packed_offset;      /* Packed sector offsets for multi-sector files. */
    uint32_t packed_offset_count; /* Number of packed_offset entries. */
    uint32_t open_count;          /* Reference count for the cached sector table. */
} PACK_STRUCT mpq_file_s;

/* Mapping from public file numbers to valid block-table indices. */
typedef struct
{
    uint32_t block_table_indices; /* Block-table index for this public file number. */
    uint32_t block_table_diff;    /* Number of skipped invalid block entries before this file. */
} PACK_STRUCT mpq_map_s;
#include "pack_end.h"

/* Runtime archive handle containing file I/O state and decoded metadata tables. */
struct mpq_archive
{
    FILE *fp;                    /* Backing file handle. */
    char *filename;              /* Original path used to reopen this archive. */
    uint64_t file_device;        /* Device identity captured when supported. */
    uint64_t file_inode;         /* Inode identity captured when supported. */
    uint8_t file_identity_valid; /* Whether the path identity is reliable. */
    uint32_t block_size;         /* Unpacked sector size in bytes. */
    off_t archive_offset;        /* Absolute archive start in the backing file. */

    mpq_header_s mpq_header;       /* Decoded base archive header. */
    mpq_header_ex_s mpq_header_ex; /* Decoded extended archive header. */
    mpq_hash_s *mpq_hash;          /* Decrypted hash table. */
    mpq_block_s *mpq_block;        /* Decrypted block table. */
    mpq_block_ex_s *mpq_block_ex;  /* Optional extended block table. */
    mpq_file_s **mpq_file;         /* Per-file cached sector tables. */

    mpq_map_s *mpq_map; /* Public file-number to block-table mapping. */
    uint32_t files;     /* Number of valid extractable file entries. */

    /* Writer-only state.  Reader handles leave these fields zeroed. */
    uint8_t write_mode;
    uint8_t write_finalized;
    uint32_t write_capacity;
    uint32_t write_hash_capacity;
    uint32_t write_sector_size;
    uint32_t write_flags;
    uint32_t write_next_block;
    char **write_names;
    uint16_t *write_locales;
    uint16_t *write_platforms;
    mpq_file_writer_s *write_current;
};

struct mpq_file_writer
{
    mpq_archive_s *archive;
    char *name;
    uint8_t *data;
    uint32_t data_size;
    uint32_t sector_index;
    uint32_t block_count;
    uint64_t payload_offset;
    uint64_t packed_total;
    uint32_t *offsets;
    libmpq__off_t expected;
    libmpq__off_t written;
    mpq_file_create_options_s options;
};

int32_t libmpq__writer_finalize(mpq_archive_s *archive);

#endif /* LIBMPQ_MPQ_INTERNAL_H */
