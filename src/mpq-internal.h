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

#include "mpq-pack-begin.h"

/*
 * The fixed portion of an MPQ archive header stored at the archive start.
 * It identifies the format, describes the sector-size exponent, and locates
 * the encrypted hash and block tables relative to the archive. Version 1
 * archives use the 32-bit offsets in this structure; version 2 archives pair
 * them with mpq_header_ex_s when the table locations need high bits.
 */
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
    uint64_t extended_offset;         /* Extended block-table offset from the archive start. */
    uint16_t hash_table_offset_high;  /* High 16 bits of the hash-table offset. */
    uint16_t block_table_offset_high; /* High 16 bits of the block-table offset. */
} PACK_STRUCT mpq_header_ex_s;

/*
 * One encrypted-table entry used to resolve a filename without storing its
 * plaintext in the hash table. The two Storm filename hashes are matched
 * together with locale and platform before the block-table index is used.
 * A free index marks an unused slot, while a valid index must refer to an
 * existing entry in the archive's block table.
 */
typedef struct
{
    uint32_t hash_a;            /* First filename hash. */
    uint32_t hash_b;            /* Second filename hash. */
    uint16_t locale;            /* File locale identifier. */
    uint16_t platform;          /* File platform identifier; zero means default. */
    uint32_t block_table_index; /* Index into the block table. */
} PACK_STRUCT mpq_hash_s;

/*
 * The serialized metadata for one stored file payload. The offset and
 * packed size identify the bytes on disk, while the unpacked size describes
 * the result after decryption and decompression. Flags select the storage,
 * encryption, and compression rules needed to interpret that payload.
 */
typedef struct
{
    uint32_t offset;        /* Payload offset from the archive start. */
    uint32_t packed_size;   /* Stored payload size. */
    uint32_t unpacked_size; /* Size after decryption and decompression. */
    uint32_t flags;         /* MPQ file flags. */
} PACK_STRUCT mpq_block_s;

/*
 * The version 2 extension for a block-table entry whose payload offset does
 * not fit in the legacy 32-bit block-table field. The low offset remains in
 * mpq_block_s, and this field supplies its upper 16 bits. It is unused for
 * version 1 archives and must remain synchronized with the low offset.
 */
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

/*
 * Translation from libmpq's compact public file numbering to the serialized
 * block table. MPQ block tables can contain unused or invalid entries, so a
 * public file number is not necessarily the same as its block-table index.
 * block_table_diff preserves how many invalid entries were skipped while
 * constructing the mapping for callers that need the original layout.
 */
typedef struct
{
    uint32_t block_table_indices; /* Block-table index for this public file number. */
    uint32_t block_table_diff;    /* Number of skipped invalid block entries before this file. */
} PACK_STRUCT mpq_map_s;
#include "mpq-pack-end.h"

/*
 * Runtime handle for an opened or newly created MPQ archive. It owns the
 * backing stream, decoded header and tables, file mappings, and per-file
 * caches used during extraction. In write mode it additionally owns the
 * reserved table capacity and file-name metadata needed to finalize the
 * archive; reader handles leave those writer-only fields empty.
 */
struct mpq_archive
{
    FILE *fp;                    /* Backing file handle. */
    char *filename;              /* Original path used to reopen this archive. */
    uint64_t file_device;        /* Device identity captured when supported. */
    uint64_t file_inode;         /* Inode identity captured when supported. */
    uint8_t file_identity_valid; /* Whether the path identity is reliable. */
    uint64_t file_size;          /* Physical backing-file size captured at open time. */
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

    /* Writer-only state. Reader handles leave these fields zeroed. */
    uint8_t write_mode;           /* Whether this handle was opened for creation. */
    uint8_t write_finalized;      /* Whether the final header and tables were written. */
    uint32_t write_capacity;      /* Reserved number of block-table entries. */
    uint32_t write_hash_capacity; /* Reserved number of hash-table entries. */
    uint32_t write_sector_size;   /* Sector size used while buffering and packing files. */
    uint32_t write_flags;         /* Archive-creation flags, including listfile generation. */
    uint32_t write_next_block;    /* Next block-table slot assigned to a completed file. */
    char **write_names;           /* Names corresponding to assigned block-table entries. */
    uint16_t *write_locales;      /* Locales corresponding to assigned file entries. */
    uint16_t *write_platforms;    /* Platforms corresponding to assigned file entries. */
    mpq_writer_s *write_current;  /* Active file writer; only one file may be streamed at once. */
};

/*
 * A live writer owns the state for one file being streamed into an archive.
 * It buffers at most one archive sector, applies the selected compression and
 * encryption options when that sector is flushed, and records packed offsets
 * for compressed files. The archive owns the active writer through
 * mpq_archive.write_current; the writer is released after file finish or an
 * aborted write, and must not outlive its parent archive.
 */
struct mpq_writer
{
    mpq_archive_s *archive;     /* Parent archive that owns the output stream. */
    char *name;                 /* File name used for hashing and encryption keys. */
    uint8_t *data;              /* Buffer for the current uncompressed input sector. */
    uint32_t data_size;         /* Number of valid bytes currently buffered in data. */
    uint32_t sector_index;      /* Index of the next sector to flush. */
    uint32_t block_count;       /* Number of sectors expected for this file. */
    uint64_t payload_offset;    /* Archive offset where this file's payload begins. */
    uint64_t packed_total;      /* Bytes written for packed sectors, excluding the table. */
    uint32_t *offsets;          /* Relative sector offsets for compressed files. */
    libmpq__off_t expected;     /* File size declared when the writer was opened. */
    libmpq__off_t written;      /* Number of source bytes accepted by the writer. */
    mpq_file_options_s options; /* Storage, compression, encryption, and identity options. */
};

#endif /* LIBMPQ_MPQ_INTERNAL_H */
