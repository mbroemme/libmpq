/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** Public facade for the D libmpq binding. */
module libmpq.mpq;

import core.stdc.string : strlen;
import std.string : toStringz;
import std.traits : ParameterTypeTuple;

public import libmpq.archive;
public import libmpq.errors;
public import libmpq.native;
public import libmpq.options;

/** Convenience entry point for constants and stateless MPQ operations. */
final class Mpq {
    /** Return the libmpq package version. */
    static string version_() {
        auto message = libmpq__version();
        return message[0 .. strlen(message)].idup;
    }

    /** Translate a native status code to its diagnostic text. */
    static string strerror(int code) {
        auto message = libmpq__strerror(code);
        return message is null ? "unknown error" : message[0 .. strlen(message)].idup;
    }

    /** Calculate the three Storm hashes for an archive entry name. */
    static StormHash fileHash(string name) {
        StormHash result;
        libmpq__file_hash(toStringz(name), &result.hash1, &result.hash2, &result.hash3);
        return result;
    }
}

/** Historical direct version-function spelling. */
alias libmpq__version libversion;

/* Retain the original low-level names for source compatibility. */
alias libmpq__archive_open archive_open;
alias libmpq__archive_open_mpqe archive_open_mpqe;
alias libmpq__archive_create archive_create;
alias libmpq__archive_create_mpqe archive_create_mpqe;
alias libmpq__archive_clone archive_clone;
alias libmpq__archive_close archive_close;
alias libmpq__archive_size_packed archive_size_packed;
alias libmpq__archive_size_unpacked archive_size_unpacked;
alias libmpq__archive_offset archive_offset;
alias libmpq__archive_version archive_version;
alias libmpq__archive_files archive_files;
alias libmpq__file_begin file_begin;
alias libmpq__file_write file_write;
alias libmpq__file_finish file_finish;
alias libmpq__file_add file_add;
alias libmpq__file_add_path file_add_path;
alias libmpq__file_size_packed file_size_packed;
alias libmpq__file_size_unpacked file_unpacked_size;
alias libmpq__file_size_unpacked file_size_unpacked;
alias libmpq__file_offset file_offset;
alias libmpq__file_blocks file_blocks;
alias libmpq__file_encrypted file_encrypted;
alias libmpq__file_compressed file_compressed;
alias libmpq__file_imploded file_imploded;
alias libmpq__file_number file_number;
alias libmpq__file_hash file_hash;
alias libmpq__file_number_from_hash file_number_from_hash;
alias libmpq__file_read file_read;
alias libmpq__block_open_offset block_open_offset;
alias libmpq__block_close_offset block_close_offset;
alias libmpq__block_size_unpacked block_size_unpacked;
alias libmpq__block_read block_read;

/** Generate a compatibility alias for a checked native function. */
template MPQ_FUNC(string name) {
    enum MPQ_FUNC = "alias MPQ_CHECKERR!(libmpq__" ~ name ~ ") " ~ name ~ ";";
}

/** Compatibility helper for code using the original throwing template. */
int MPQ_CHECKERR(alias Function)(ParameterTypeTuple!(Function) args) {
    auto result = Function(args);
    if (result < 0)
        throw new MPQException(Function.stringof, result);
    return result;
}
