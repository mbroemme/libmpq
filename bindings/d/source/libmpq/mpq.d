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

public import libmpq.archive;
public import libmpq.errors;
public import libmpq.native;
public import libmpq.options;

/** Convenience entry point for constants and stateless MPQ operations. */
final class Mpq {
    /** Query whether writer compression is allowed using zero-based version and policy selectors. */
    static bool archiveCompressionAllowed(uint version_, uint mask,
                                         libmpq_compression_policy_t policy =
                                             COMPRESSION_POLICY_STANDARD) {
        return libmpq__archive_compression_allowed(version_, mask, policy) != 0;
    }

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
