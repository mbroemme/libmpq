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

/* Keep the names used by the original D binding as public aliases. */
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
alias LIBMPQ_ARCHIVE_VERSION_ONE = ARCHIVE_VERSION_ONE;
alias LIBMPQ_ARCHIVE_VERSION_TWO = ARCHIVE_VERSION_TWO;
alias LIBMPQ_ARCHIVE_CREATE_LISTFILE = ARCHIVE_CREATE_LISTFILE;

enum FILE_FLAG_IMPLODE = 0x00000100u;
enum FILE_FLAG_COMPRESS = 0x00000200u;
enum FILE_FLAG_ENCRYPTED = 0x00010000u;
enum FILE_FLAG_SINGLE = 0x01000000u;
enum FILE_FLAG_LOCALE = 0u;
alias LIBMPQ_FILE_FLAG_IMPLODE = FILE_FLAG_IMPLODE;
alias LIBMPQ_FILE_FLAG_COMPRESS = FILE_FLAG_COMPRESS;
alias LIBMPQ_FILE_FLAG_ENCRYPTED = FILE_FLAG_ENCRYPTED;
alias LIBMPQ_FILE_FLAG_SINGLE = FILE_FLAG_SINGLE;
alias LIBMPQ_FILE_FLAG_LOCALE = FILE_FLAG_LOCALE;

enum COMPRESSION_HUFFMAN = 0x01u;
enum COMPRESSION_ZLIB = 0x02u;
enum COMPRESSION_PKZIP = 0x08u;
enum COMPRESSION_BZIP2 = 0x10u;
enum COMPRESSION_WAVE_MONO = 0x40u;
enum COMPRESSION_WAVE_STEREO = 0x80u;
alias LIBMPQ_COMPRESSION_HUFFMAN = COMPRESSION_HUFFMAN;
alias LIBMPQ_COMPRESSION_ZLIB = COMPRESSION_ZLIB;
alias LIBMPQ_COMPRESSION_PKZIP = COMPRESSION_PKZIP;
alias LIBMPQ_COMPRESSION_BZIP2 = COMPRESSION_BZIP2;
alias LIBMPQ_COMPRESSION_WAVE_MONO = COMPRESSION_WAVE_MONO;
alias LIBMPQ_COMPRESSION_WAVE_STEREO = COMPRESSION_WAVE_STEREO;

/** Opaque native archive state owned by libmpq. */
extern(C) struct mpq_archive_s;

/** Opaque native streaming-writer state owned by libmpq. */
extern(C) struct mpq_writer_s;

/** Native layout passed to libmpq__archive_create. */
extern(C) struct mpq_archive_create_options_s {
    uint version_;
    uint max_files;
    uint sector_size;
    uint flags;
}

/** Native layout passed to file-add and file-begin operations. */
extern(C) struct mpq_file_options_s {
    uint flags;
    uint compression_first;
    uint compression_next;
    ushort locale;
    ushort platform;
}

extern(C) {
    /** Return the static package version string. */
    const(char)* libmpq__version();

    /** Translate a libmpq status code into a static diagnostic string. */
    const(char)* libmpq__strerror(int return_code);

    /** Open an archive and return its owned native handle through output. */
    int libmpq__archive_open(mpq_archive_s** archive, const(char)* path,
                             off_t offset);

    /** Open a read-only MPQE stream and parse its contained MPQ archive. */
    int libmpq__archive_open_mpqe(mpq_archive_s** archive, const(char)* path,
                                  off_t offset,
                                  const(ubyte)* authentication_code,
                                  size_t authentication_code_size);

    /** Create an archive using the supplied native option structure. */
    int libmpq__archive_create(mpq_archive_s** archive, const(char)* path,
                               const(mpq_archive_create_options_s)* options);

    /** Begin one streamed archive entry. */
    int libmpq__file_begin(mpq_archive_s* archive, const(char)* filename,
                           off_t size, const(mpq_file_options_s)* options,
                           mpq_writer_s** writer);

    /** Append bytes to an active native writer. */
    int libmpq__file_write(mpq_writer_s* writer, const(ubyte)* buffer,
                           off_t size);

    /** Finish and publish an active native writer. */
    int libmpq__file_finish(mpq_writer_s* writer);

    /** Add one complete in-memory file to an archive. */
    int libmpq__file_add(mpq_archive_s* archive, const(char)* filename,
                         const(ubyte)* buffer, off_t size,
                         const(mpq_file_options_s)* options);

    /** Add a filesystem file to an archive. */
    int libmpq__file_add_path(mpq_archive_s* archive, const(char)* filename,
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

    /** Query one file's encryption flag. */
    int libmpq__file_encrypted(mpq_archive_s* archive, uint number,
                               uint* value);

    /** Query one file's compression flag. */
    int libmpq__file_compressed(mpq_archive_s* archive, uint number,
                                uint* value);

    /** Query one file's PKWARE implode flag. */
    int libmpq__file_imploded(mpq_archive_s* archive, uint number,
                              uint* value);

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

    /** Open and cache one file's packed block-offset table. */
    int libmpq__block_open_offset(mpq_archive_s* archive, uint number);

    /** Close one file's cached block-offset table. */
    int libmpq__block_close_offset(mpq_archive_s* archive, uint number);

    /** Query one block's unpacked size. */
    int libmpq__block_size_unpacked(mpq_archive_s* archive, uint number,
                                    uint block, off_t* value);

    /** Read one decrypted and decompressed block. */
    int libmpq__block_read(mpq_archive_s* archive, uint number, uint block,
                           ubyte* buffer, off_t size, off_t* transferred);
}
