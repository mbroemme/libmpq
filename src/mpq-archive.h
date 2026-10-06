/*
 *  mpq-archive.h -- private runtime MPQ archive state.
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

#ifndef LIBMPQ_MPQ_ARCHIVE_H
#define LIBMPQ_MPQ_ARCHIVE_H

#include "mpq-attributes.h"
#include "mpq-block.h"
#include "mpq-entry.h"
#include "mpq-file.h"
#include "mpq-hash.h"
#include "mpq-header.h"
#include "mpq-mpqe.h"
#include "mpq-rsa.h"

#include <libmpq/mpq.h>
#include <stdint.h>
#include <stdio.h>

/* Well-known pseudo-files stored inside some MPQ archives. */
#define LIBMPQ_LISTFILE_NAME "(listfile)"
#define LIBMPQ_SIGNATURE_NAME "(signature)"
#define LIBMPQ_ATTRIBUTES_NAME "(attributes)"

struct mpq_writer_mpqe_ops;

/*
 * Runtime handle for an opened or newly created MPQ archive. It owns the
 * backing source, decoded header and tables, file mappings, and per-file
 * caches used during extraction. In write mode it additionally owns the
 * reserved table capacity and file-name metadata needed to finalize the
 * archive; reader handles leave those writer-only fields empty.
 */
struct mpq_archive
{
    FILE *fp;                     /* Backing file handle used only by writers. */
    struct mpq_source *source;    /* Read-only random-access source provider for readers. */
    char *filename;               /* Path or optional logical name retained by the archive. */
    uint64_t file_device;         /* Device or Windows volume identity. */
    uint64_t file_inode;          /* Inode or Windows file identity. */
    uint8_t file_identity_valid;  /* Whether the path identity is reliable. */
    uint64_t file_size;           /* Physical backing-file size captured at open time. */
    uint32_t block_size;          /* Unpacked sector size in bytes. */
    libmpq__off_t archive_offset; /* Absolute archive start in the backing file. */

    mpq_header_s mpq_header;         /* Decoded base archive header. */
    mpq_header_ex_s mpq_header_ex;   /* Decoded extended archive header. */
    mpq_header_v3_s mpq_header_v3;   /* Decoded v3 extension; zero for short headers. */
    mpq_hash_s *mpq_hash;            /* Decrypted hash table. */
    mpq_block_s *mpq_block;          /* Decrypted block table. */
    mpq_block_ex_s *mpq_block_ex;    /* Optional extended block table. */
    mpq_file_s **mpq_file;           /* Per-file cached sector tables. */
    mpq_entry_s *mpq_entry;          /* Archive-owned canonical entries for consumption. */
    uint32_t entry_count;            /* Entry/cache capacity, including unused classic rows. */
    uint32_t *classic_entry_indices; /* Classic block row to canonical entry index. */

    mpq_map_s *mpq_map;                      /* Public file-number to canonical-entry mapping. */
    uint32_t files;                          /* Number of valid extractable file entries. */
    mpq_attributes_s *attributes;            /* Lazy validated reader attributes. */
    int32_t attributes_error;                /* Cached absence or structural failure. */
    mpq_file_attributes_s *write_attributes; /* Records indexed by physical block slot. */
    uint32_t write_attributes_flags;         /* Selected LIBMPQ_ATTRIBUTE_* arrays. */
    uint8_t write_internal;                  /* Finalization is adding generated internal files. */
    uint8_t write_patch_mode; /* Private patch writer may serialize true patch bits. */

    /* Writer-only state. Reader handles leave these fields zeroed. */
    uint8_t write_mode;             /* Whether this handle was opened for creation. */
    uint8_t write_finalized;        /* Whether the final header and tables were written. */
    uint8_t write_signature;        /* Caller requested weak signing. */
    uint8_t write_strong_signature; /* Caller requested plain strong signing. */
    uint64_t write_signature_offset;
    uint8_t write_signature_key[LIBMPQ_RSA_KEY_SIZE];               /* Cleared on every close. */
    uint8_t write_strong_signature_key[LIBMPQ_RSA_STRONG_KEY_SIZE]; /* Cleared on close. */
    uint32_t write_capacity;      /* Reserved number of block-table entries. */
    uint32_t write_hash_capacity; /* Reserved number of hash-table entries. */
    uint32_t write_sector_size;   /* Sector size used while buffering and packing files. */
    uint32_t write_flags;         /* Archive-creation flags, including listfile generation. */
    uint32_t write_next_block;    /* Next block-table slot assigned to a completed file. */
    char **write_names;           /* Names corresponding to assigned block-table entries. */
    uint16_t *write_locales;      /* Locales corresponding to assigned file entries. */
    uint16_t *write_platforms;    /* Platforms corresponding to assigned file entries. */
    mpq_writer_s *write_current;  /* Active file writer; only one file may be streamed at once. */
    uint8_t write_mpqe;           /* Whether finalization publishes an MPQE stream. */
    uint8_t
        write_mpqe_key[LIBMPQ_MPQE_CHUNK_SIZE]; /* Derived MPQE key retained only while writing. */
    FILE *write_mpqe_output;                    /* Secure temporary encrypted output handle. */
    mpq_directory_s
        *write_mpqe_directory;    /* Destination directory context for anchored operations. */
    char *write_mpqe_destination; /* Final MPQE destination basename in that directory. */
    char *write_mpqe_output_path; /* Secure encrypted temporary basename in that directory. */
    const struct mpq_writer_mpqe_ops *write_mpqe_ops; /* Private MPQE finalization operations. */
};

#endif /* LIBMPQ_MPQ_ARCHIVE_H */
