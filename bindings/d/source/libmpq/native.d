/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/**
 * Exact D declarations for the public libmpq C ABI.
 *
 * This module intentionally contains no ownership policy or exception
 * translation. Higher-level wrappers in archive.d and mpq.d perform those
 * tasks while retaining these declarations for applications that need direct
 * ABI access.
 */
module libmpq.native;

alias off_t = long;

enum ERROR_OPEN = -1;
enum ERROR_CLOSE = -2;
enum ERROR_SEEK = -3;
enum ERROR_READ = -4;
enum ERROR_WRITE = -5;
enum ERROR_MALLOC = -6;
enum ERROR_FORMAT = -7;
enum ERROR_NOT_INITIALIZED = -8;
enum ERROR_SIZE = -9;
enum ERROR_EXIST = -10;
enum ERROR_DECRYPT = -11;
enum ERROR_UNPACK = -12;

/** C-style constant spellings matching the public native header. */
alias LIBMPQ_ERROR_OPEN = ERROR_OPEN;
alias LIBMPQ_ERROR_CLOSE = ERROR_CLOSE;
alias LIBMPQ_ERROR_SEEK = ERROR_SEEK;
alias LIBMPQ_ERROR_READ = ERROR_READ;
alias LIBMPQ_ERROR_WRITE = ERROR_WRITE;
alias LIBMPQ_ERROR_MALLOC = ERROR_MALLOC;
alias LIBMPQ_ERROR_FORMAT = ERROR_FORMAT;
alias LIBMPQ_ERROR_NOT_INITIALIZED = ERROR_NOT_INITIALIZED;
alias LIBMPQ_ERROR_SIZE = ERROR_SIZE;
alias LIBMPQ_ERROR_EXIST = ERROR_EXIST;
alias LIBMPQ_ERROR_DECRYPT = ERROR_DECRYPT;
alias LIBMPQ_ERROR_UNPACK = ERROR_UNPACK;

enum ARCHIVE_VERSION_ONE = 0u;
enum ARCHIVE_VERSION_TWO = 1u;
enum ARCHIVE_CREATE_LISTFILE = 0x00000001u;
enum ARCHIVE_CREATE_COMPRESSION_EXTENDED = 0x00000002u;
enum COMPRESSION_POLICY_STANDARD = 0;
enum COMPRESSION_POLICY_EXTENDED = 1;
/** The native policy is int32_t; D int is a signed 32-bit integer. */
alias libmpq_compression_policy_t = int;
alias LIBMPQ_COMPRESSION_POLICY_STANDARD = COMPRESSION_POLICY_STANDARD;
alias LIBMPQ_COMPRESSION_POLICY_EXTENDED = COMPRESSION_POLICY_EXTENDED;
alias LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED = ARCHIVE_CREATE_COMPRESSION_EXTENDED;
alias LIBMPQ_ARCHIVE_VERSION_ONE = ARCHIVE_VERSION_ONE;
alias LIBMPQ_ARCHIVE_VERSION_TWO = ARCHIVE_VERSION_TWO;
alias LIBMPQ_ARCHIVE_CREATE_LISTFILE = ARCHIVE_CREATE_LISTFILE;

enum FILE_FLAG_IMPLODE = 0x00000100u;
enum FILE_FLAG_COMPRESS = 0x00000200u;
enum FILE_FLAG_ENCRYPTED = 0x00010000u;
enum FILE_FLAG_SINGLE = 0x01000000u;
enum FILE_FLAG_SECTOR_CRC = 0x04000000u;
enum FILE_FLAG_LOCALE = 0u;
alias LIBMPQ_FILE_FLAG_IMPLODE = FILE_FLAG_IMPLODE;
alias LIBMPQ_FILE_FLAG_COMPRESS = FILE_FLAG_COMPRESS;
alias LIBMPQ_FILE_FLAG_ENCRYPTED = FILE_FLAG_ENCRYPTED;
alias LIBMPQ_FILE_FLAG_SINGLE = FILE_FLAG_SINGLE;
alias LIBMPQ_FILE_FLAG_SECTOR_CRC = FILE_FLAG_SECTOR_CRC;
alias LIBMPQ_FILE_FLAG_LOCALE = FILE_FLAG_LOCALE;

enum COMPRESSION_HUFFMAN = 0x01u;
enum COMPRESSION_ZLIB = 0x02u;
enum COMPRESSION_PKZIP = 0x08u;
enum COMPRESSION_BZIP2 = 0x10u;
enum COMPRESSION_SPARSE = 0x20u;
enum COMPRESSION_WAVE_MONO = 0x40u;
enum COMPRESSION_WAVE_STEREO = 0x80u;

/** Exclusive MPQ v2+ LZMA selector; it is not a chainable mask bit. */
enum COMPRESSION_LZMA = 0x00000100u;
alias LIBMPQ_COMPRESSION_HUFFMAN = COMPRESSION_HUFFMAN;
alias LIBMPQ_COMPRESSION_ZLIB = COMPRESSION_ZLIB;
alias LIBMPQ_COMPRESSION_PKZIP = COMPRESSION_PKZIP;
alias LIBMPQ_COMPRESSION_BZIP2 = COMPRESSION_BZIP2;
alias LIBMPQ_COMPRESSION_SPARSE = COMPRESSION_SPARSE;
alias LIBMPQ_COMPRESSION_WAVE_MONO = COMPRESSION_WAVE_MONO;
alias LIBMPQ_COMPRESSION_WAVE_STEREO = COMPRESSION_WAVE_STEREO;
alias LIBMPQ_COMPRESSION_LZMA = COMPRESSION_LZMA;

/** Opaque native archive state owned by libmpq. */
extern(C) struct mpq_archive_s;

/** Opaque native streaming-writer state owned by libmpq. */
extern(C) struct mpq_writer_s;

/** Opaque native logical-member stream state owned by libmpq. */
extern(C) struct mpq_stream_s;

enum LIBMPQ_SEEK_SET = 0;
enum LIBMPQ_SEEK_CUR = 1;
enum LIBMPQ_SEEK_END = 2;

/** Native layout passed to libmpq__archive_create. */
extern(C) struct mpq_archive_create_options_s {
    uint version_;
    uint max_files;
    uint sector_size;
    uint flags;
    uint attributes;
}

/** Native layout passed to file-add and file-begin operations. */
extern(C) struct mpq_file_options_s {
    uint flags;
    uint compression_first;
    uint compression_next;
    ushort locale;
    ushort platform;
}

/** Per-block array flags, also accepted by the creation attributes option. */
enum ATTRIBUTE_CRC32 = 0x1u;
alias LIBMPQ_ATTRIBUTE_CRC32 = ATTRIBUTE_CRC32;
enum ATTRIBUTE_FILETIME = 0x2u;
alias LIBMPQ_ATTRIBUTE_FILETIME = ATTRIBUTE_FILETIME;
enum ATTRIBUTE_MD5 = 0x4u;
alias LIBMPQ_ATTRIBUTE_MD5 = ATTRIBUTE_MD5;
enum ATTRIBUTE_PATCH_BIT = 0x8u;
alias LIBMPQ_ATTRIBUTE_PATCH_BIT = ATTRIBUTE_PATCH_BIT;

/** Shared request/mismatch bits; clear bits mean matched or unavailable. */
enum VERIFY_SECTOR_CRC = 0x1u;
enum VERIFY_FILE_CRC32 = 0x2u;
enum VERIFY_FILE_MD5 = 0x4u;
enum VERIFY_ALL = VERIFY_SECTOR_CRC | VERIFY_FILE_CRC32 | VERIFY_FILE_MD5;
enum SIGNATURE_WEAK = 0x00000001u;
enum SIGNATURE_STRONG = 0x00000002u;
alias LIBMPQ_SIGNATURE_WEAK = SIGNATURE_WEAK;
alias LIBMPQ_SIGNATURE_STRONG = SIGNATURE_STRONG;
alias LIBMPQ_VERIFY_SECTOR_CRC = VERIFY_SECTOR_CRC;
alias LIBMPQ_VERIFY_FILE_CRC32 = VERIFY_FILE_CRC32;
alias LIBMPQ_VERIFY_FILE_MD5 = VERIFY_FILE_MD5;
alias LIBMPQ_VERIFY_ALL = VERIFY_ALL;

/** 40-byte naturally aligned native result; unavailable/reserved fields are zero. */
extern(C) struct mpq_file_attributes_s {
    uint flags;
    uint crc32;
    ulong filetime;
    ubyte[16] md5;
    int patch_bit;
    ubyte[4] reserved;
}

/** Compile-time native ABI sizes and offsets, independent of pointer width. */
static assert(mpq_archive_create_options_s.sizeof == 20);
static assert(mpq_archive_create_options_s.version_.offsetof == 0 &&
              mpq_archive_create_options_s.version_.sizeof == 4);
static assert(mpq_archive_create_options_s.max_files.offsetof == 4 &&
              mpq_archive_create_options_s.max_files.sizeof == 4);
static assert(mpq_archive_create_options_s.sector_size.offsetof == 8 &&
              mpq_archive_create_options_s.sector_size.sizeof == 4);
static assert(mpq_archive_create_options_s.flags.offsetof == 12 &&
              mpq_archive_create_options_s.flags.sizeof == 4);
static assert(mpq_archive_create_options_s.attributes.offsetof == 16 &&
              mpq_archive_create_options_s.attributes.sizeof == 4);

static assert(mpq_file_options_s.sizeof == 16);
static assert(mpq_file_options_s.flags.offsetof == 0 &&
              mpq_file_options_s.flags.sizeof == 4);
static assert(mpq_file_options_s.compression_first.offsetof == 4 &&
              mpq_file_options_s.compression_first.sizeof == 4);
static assert(mpq_file_options_s.compression_next.offsetof == 8 &&
              mpq_file_options_s.compression_next.sizeof == 4);
static assert(mpq_file_options_s.locale.offsetof == 12 &&
              mpq_file_options_s.locale.sizeof == 2);
static assert(mpq_file_options_s.platform.offsetof == 14 &&
              mpq_file_options_s.platform.sizeof == 2);

static assert(mpq_file_attributes_s.sizeof == 40);
static assert(mpq_file_attributes_s.flags.offsetof == 0 &&
              mpq_file_attributes_s.flags.sizeof == 4);
static assert(mpq_file_attributes_s.crc32.offsetof == 4 &&
              mpq_file_attributes_s.crc32.sizeof == 4);
static assert(mpq_file_attributes_s.filetime.offsetof == 8 &&
              mpq_file_attributes_s.filetime.sizeof == 8);
static assert(mpq_file_attributes_s.md5.offsetof == 16 &&
              mpq_file_attributes_s.md5.sizeof == 16);
static assert(mpq_file_attributes_s.patch_bit.offsetof == 32 &&
              mpq_file_attributes_s.patch_bit.sizeof == 4);
static assert(mpq_file_attributes_s.reserved.offsetof == 36 &&
              mpq_file_attributes_s.reserved.sizeof == 4);

extern(C) {

    /** Optional metadata queries and explicit writer FILETIME. */
    int libmpq__archive_attributes(mpq_archive_s* archive, uint* flags);
    int libmpq__archive_signatures(mpq_archive_s* archive, uint* signatures);
    int libmpq__archive_verify(mpq_archive_s* archive, uint flags,
                               const(ubyte)* key, size_t keySize, uint* mismatches);
    int libmpq__archive_sign(mpq_archive_s* archive, uint type,
                             const(ubyte)* key, size_t keySize);
    int libmpq__file_attributes(mpq_archive_s* archive, uint number, mpq_file_attributes_s* attributes);
    int libmpq__file_verify(mpq_archive_s* archive, uint number, uint flags, uint* mismatches);
    int libmpq__block_verify(mpq_archive_s* archive, uint number, uint block,
                            uint* checksum, uint* mismatches);
    int libmpq__writer_timestamp(mpq_writer_s* writer, ulong filetime);

    /** Return the static package version string. */
    const(char)* libmpq__version();

    /** Translate a libmpq status code into a static diagnostic string. */
    const(char)* libmpq__strerror(int return_code);

    /** Query whether writer compression is allowed; archive versions are zero-based selectors. */
    int libmpq__archive_compression_allowed(uint archive_version, uint compression_mask,
                                          libmpq_compression_policy_t policy);

    /** Open an archive and return its owned native handle through output. */
    int libmpq__archive_open(mpq_archive_s** archive, const(char)* path,
                             off_t offset);

    /** Open a read-only MPQE stream and parse its contained MPQ archive. */
    int libmpq__archive_open_mpqe(mpq_archive_s** archive, const(char)* path,
                                  off_t offset,
                                  const(ubyte)* auth_code,
                                  size_t auth_code_size);

    /** Create an archive using the supplied native option structure. */
    int libmpq__archive_create(mpq_archive_s** archive, const(char)* path,
                               const(mpq_archive_create_options_s)* options);
    int libmpq__archive_create_mpqe(mpq_archive_s** archive, const(char)* path,
                                    const(ubyte)* auth_code,
                                    size_t auth_code_size,
                                    const(mpq_archive_create_options_s)* options);

    /** Begin one streamed archive entry. */
    int libmpq__writer_begin(mpq_archive_s* archive, const(char)* filename,
                           off_t size, const(mpq_file_options_s)* options,
                           mpq_writer_s** writer);

    /** Append bytes to an active native writer. */
    int libmpq__writer_write(mpq_writer_s* writer, const(ubyte)* buffer,
                           off_t size);

    /** Finish and publish an active native writer. */
    int libmpq__writer_finish(mpq_writer_s* writer);

    /** Add one complete in-memory file to an archive. */
    int libmpq__archive_add_data(mpq_archive_s* archive, const(char)* filename,
                         const(ubyte)* buffer, off_t size,
                         const(mpq_file_options_s)* options);

    /** Add a filesystem file to an archive. */
    int libmpq__archive_add_path(mpq_archive_s* archive, const(char)* filename,
                              const(char)* source_path,
                              const(mpq_file_options_s)* options);

    /** Clone an archive into an independent native handle. */
    int libmpq__archive_clone(mpq_archive_s** clone, mpq_archive_s* source);

    /** Close an archive and release all native state. */
    int libmpq__archive_close(mpq_archive_s* archive);

    /** Query aggregate packed archive size. */
    int libmpq__archive_size_packed(mpq_archive_s* archive, off_t* value);

    /** Query aggregate unpacked archive size. */
    int libmpq__archive_size_unpacked(mpq_archive_s* archive, off_t* value);

    /** Query the archive header offset. */
    int libmpq__archive_offset(mpq_archive_s* archive, off_t* value);

    /** Query the archive format version. */
    int libmpq__archive_version(mpq_archive_s* archive, uint* value);

    /** Query the number of valid archive files. */
    int libmpq__archive_files(mpq_archive_s* archive, uint* value);

    /** Query one file's packed size. */
    int libmpq__file_size_packed(mpq_archive_s* archive, uint number,
                                 off_t* value);

    /** Query one file's unpacked size. */
    int libmpq__file_size_unpacked(mpq_archive_s* archive, uint number,
                                   off_t* value);

    /** Query one file's archive-relative payload offset. */
    int libmpq__file_offset(mpq_archive_s* archive, uint number, off_t* value);

    /** Query one file's block count. */
    int libmpq__file_blocks(mpq_archive_s* archive, uint number, uint* value);

    /** Query one file's stored block-table flags. */
    int libmpq__file_flags(mpq_archive_s* archive, uint number, uint* flags);

    /** Resolve a filename using Storm's archive hash tables. */
    int libmpq__file_number(mpq_archive_s* archive, const(char)* filename,
                            uint* number);

    /** Calculate the three Storm hashes for a filename. */
    void libmpq__file_hash(const(char)* filename, uint* hash1, uint* hash2,
                           uint* hash3);

    /** Resolve precomputed Storm hashes to a file number. */
    int libmpq__file_number_from_hash(mpq_archive_s* archive, uint hash1,
                                      uint hash2, uint hash3, uint* number);

    /** Read one complete unpacked file into the caller's buffer. */
    int libmpq__file_read(mpq_archive_s* archive, uint number, ubyte* buffer,
                          off_t size, off_t* transferred);

    int libmpq__stream_open(mpq_archive_s* archive, uint number, mpq_stream_s** stream);
    int libmpq__stream_open_name(mpq_archive_s* archive, const(char)* filename,
                                 mpq_stream_s** stream);
    int libmpq__stream_read(mpq_stream_s* stream, ubyte* buffer, off_t size,
                            off_t* transferred);
    int libmpq__stream_seek(mpq_stream_s* stream, off_t offset, int origin);
    int libmpq__stream_tell(mpq_stream_s* stream, off_t* position);
    int libmpq__stream_size(mpq_stream_s* stream, off_t* size);
    int libmpq__stream_close(mpq_stream_s* stream);

    /** Query one block's stored size, excluding offset/checksum tables. */
    int libmpq__block_size_packed(mpq_archive_s* archive, uint number,
                                uint block, off_t* value);

    /** Query the stored method byte, or zero for raw fallback. */
    int libmpq__block_compression(mpq_archive_s* archive, uint number,
                                 uint block, uint* compression);

    /** Query one block's unpacked size. */
    int libmpq__block_size_unpacked(mpq_archive_s* archive, uint number,
                                    uint block, off_t* value);

    /** Read one decrypted and decompressed block. */
    int libmpq__block_read(mpq_archive_s* archive, uint number, uint block,
                           ubyte* buffer, off_t size, off_t* transferred);
}
