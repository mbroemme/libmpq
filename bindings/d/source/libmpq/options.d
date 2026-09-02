/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** Typed D options corresponding to libmpq's public creation structures. */
module libmpq.options;

import libmpq.native;

/** Options controlling v1/v2 archive creation. */
struct ArchiveCreateOptions {
    /** Native archive version selector. */
    uint version_ = ARCHIVE_VERSION_ONE;
    /** Reserved archive file-entry capacity; zero selects the native default. */
    uint maxFiles;
    /** Unpacked sector size; zero selects the native default. */
    uint sectorSize;
    /** Archive creation flags such as `ARCHIVE_CREATE_LISTFILE`. */
    uint flags;

    /** Return defaults for a v1 archive. */
    static ArchiveCreateOptions v1() {
        auto result = ArchiveCreateOptions();
        result.version_ = ARCHIVE_VERSION_ONE;
        return result;
    }

    /** Return defaults for a v2 archive. */
    static ArchiveCreateOptions v2() {
        auto result = ArchiveCreateOptions();
        result.version_ = ARCHIVE_VERSION_TWO;
        return result;
    }

    /** Request deterministic listfile generation. */
    ref ArchiveCreateOptions withListfile() return {
        flags |= ARCHIVE_CREATE_LISTFILE;
        return this;
    }

    /** Convert the safe D representation to the exact native layout. */
    mpq_archive_create_options_s nativeOptions() const {
        return mpq_archive_create_options_s(version_, maxFiles, sectorSize, flags);
    }
}

/** Options controlling one file's storage pipeline. */
struct FileOptions {
    /** Native storage flags. */
    uint flags;
    /** Compression mask for the first sector. */
    uint compressionFirst;
    /** Compression mask for later sectors. */
    uint compressionNext;
    /** MPQ locale identifier. */
    ushort locale;
    /** MPQ platform identifier. */
    ushort platform;

    /** Store a raw, sectorized file. */
    static FileOptions raw() {
        return FileOptions();
    }

    /** Store a file through MPQ multi-compression masks. */
    static FileOptions compressed(uint first) {
        return compressed(first, first);
    }

    /** Store a file with distinct first-sector and later-sector masks. */
    static FileOptions compressed(uint first, uint next) {
        auto result = FileOptions();
        result.flags = FILE_FLAG_COMPRESS;
        result.compressionFirst = first;
        result.compressionNext = next;
        return result;
    }

    /** Add per-sector encryption to these options. */
    ref FileOptions encrypted() return {
        flags |= FILE_FLAG_ENCRYPTED;
        return this;
    }

    /** Store the payload as one unit when supported by the native writer. */
    ref FileOptions singleUnit() return {
        flags |= FILE_FLAG_SINGLE;
        return this;
    }

    /** Select standalone PKWARE implode storage. */
    ref FileOptions imploded() return {
        flags |= FILE_FLAG_IMPLODE;
        return this;
    }

    /** Set the locale and platform lookup identity. */
    ref FileOptions identity(ushort locale_, ushort platform_) return {
        locale = locale_;
        platform = platform_;
        return this;
    }

    /** Convert the safe D representation to the exact native layout. */
    mpq_file_options_s nativeOptions() const {
        return mpq_file_options_s(flags, compressionFirst, compressionNext,
                                  locale, platform);
    }
}
