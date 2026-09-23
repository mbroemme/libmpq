/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import org.libmpq.ffi.LibmpqNative;

/**
 * Entry points, constants, and value types shared by the high-level Java
 * binding.  This class is the Java-facing counterpart of the stable public
 * functions and constants in {@code include/libmpq/mpq.h}; it does not expose
 * private codec or archive-layout implementation details.
 */
public final class Mpq {
    /** Seek from the logical member start. */
    public static final int SEEK_SET = 0;
    /** Seek from the current logical member position. */
    public static final int SEEK_CUR = 1;
    /** Seek from the logical member end. */
    public static final int SEEK_END = 2;
    /** Attributes CRC32 array presence. */
    public static final int ATTRIBUTE_CRC32 = 0x1;
    /** Attributes FILETIME array presence. */
    public static final int ATTRIBUTE_FILETIME = 0x2;
    /** Attributes MD5 array presence. */
    public static final int ATTRIBUTE_MD5 = 0x4;
    /** Attributes PATCH_BIT array presence. */
    public static final int ATTRIBUTE_PATCH_BIT = 0x8;

    /** Request packed-sector Adler-32 comparison, or report its mismatch. */
    public static final int VERIFY_SECTOR_CRC = 0x1;
    /** Request comparison of the stored CRC32, or report its mismatch. */
    public static final int VERIFY_FILE_CRC32 = 0x2;
    /** Request comparison of the stored MD5, or report its mismatch. */
    public static final int VERIFY_FILE_MD5 = 0x4;
    /** Request all implemented file checksum comparisons. */
    public static final int VERIFY_ALL = VERIFY_SECTOR_CRC | VERIFY_FILE_CRC32 | VERIFY_FILE_MD5;
    public static final int SIGNATURE_WEAK = 0x00000001;
    public static final int SIGNATURE_STRONG = 0x00000002;
    /** Native failure while opening or creating a file. */
    public static final int ERROR_OPEN = -1;
    /** Native failure while closing a file or archive. */
    public static final int ERROR_CLOSE = -2;
    /** Native seek failure. */
    public static final int ERROR_SEEK = -3;
    /** Native read failure. */
    public static final int ERROR_READ = -4;
    /** Native write failure. */
    public static final int ERROR_WRITE = -5;
    /** Native allocation failure. */
    public static final int ERROR_MALLOC = -6;
    /** Input is not a valid or supported MPQ format. */
    public static final int ERROR_FORMAT = -7;
    /** A required native handle or context is not initialized. */
    public static final int ERROR_NOT_INITIALIZED = -8;
    /** A caller-supplied size or buffer is invalid. */
    public static final int ERROR_SIZE = -9;
    /** An entry already exists or a requested entry is absent. */
    public static final int ERROR_EXIST = -10;
    /** Decryption failed because a key or encrypted structure is invalid. */
    public static final int ERROR_DECRYPT = -11;
    /** Decompression or codec processing failed. */
    public static final int ERROR_UNPACK = -12;

    /** Creation selector for the MPQ v1 archive layout. */
    public static final int ARCHIVE_VERSION_ONE = 0;
    /** Creation selector for the MPQ v2 archive layout. */
    public static final int ARCHIVE_VERSION_TWO = 1;
    /** Creation flag requesting a generated {@code (listfile)} entry. */
    public static final int ARCHIVE_CREATE_LISTFILE = 0x00000001;
    /** Select EXTENDED compression in archive creation flags; zero defaults to STANDARD. */
    public static final int ARCHIVE_CREATE_COMPRESSION_EXTENDED = 0x00000002;
    /** Interoperability-oriented writer compression policy. */
    public static final int COMPRESSION_POLICY_STANDARD = 0;
    /** Permit implemented compression forms that may be less interoperable. */
    public static final int COMPRESSION_POLICY_EXTENDED = 1;
    /** MPQ flag for standalone PKWARE implode storage. */
    public static final int FILE_FLAG_IMPLODE = 0x00000100;
    /** MPQ flag for multi-compression storage. */
    public static final int FILE_FLAG_COMPRESS = 0x00000200;
    /** MPQ flag for encrypted storage. */
    public static final int FILE_FLAG_ENCRYPTED = 0x00010000;
    /** MPQ flag for single-unit, non-sectorized storage. */
    public static final int FILE_FLAG_SINGLE = 0x01000000;
    /** Generate checksums for sectorized compressed/imploded files. */
    public static final int FILE_FLAG_SECTOR_CRC = 0x04000000;
    /** MPQ Huffman compression mask bit. */
    public static final int COMPRESSION_HUFFMAN = 0x01;
    /** MPQ zlib compression mask bit. */
    public static final int COMPRESSION_ZLIB = 0x02;
    /** MPQ PKWARE compression mask bit. */
    public static final int COMPRESSION_PKZIP = 0x08;
    /** MPQ bzip2 compression mask bit. */
    public static final int COMPRESSION_BZIP2 = 0x10;
    /** Lossless SPARSE zero-run stage; cannot be combined with WAVE ADPCM. */
    public static final int COMPRESSION_SPARSE = 0x20;
    /** MPQ mono WAVE ADPCM compression mask bit. */
    public static final int COMPRESSION_WAVE_MONO = 0x40;
    /** MPQ stereo WAVE ADPCM compression mask bit. */
    public static final int COMPRESSION_WAVE_STEREO = 0x80;
    /** Exclusive MPQ v2+ LZMA selector; it is not a chainable mask bit. */
    public static final int COMPRESSION_LZMA = 0x00000100;

    private Mpq() { }

    /**
     * Returns the version string compiled into the loaded native libmpq
     * library.  This operation does not require an archive handle.
     */
    public static String version() {
        return Support.cString(LibmpqNative.version());
    }

    /**
     * Converts a native return code into stable human-readable diagnostic
     * text.  Unknown values are handled by the native library's fallback
     * diagnostic.
     *
     * @param code a native success or error return code
     * @return diagnostic text supplied by libmpq
     */
    public static String strerror(int code) {
        return Support.cString(LibmpqNative.strerror(code));
    }

    /** Query whether writer compression is allowed using zero-based version and policy selectors. */
    public static boolean archiveCompressionAllowed(int version, int mask, int policy) {
        return LibmpqNative.archiveCompressionAllowed(version, mask, policy) != 0;
    }

    /**
     * Calculates the three Storm hash values used to locate a UTF-8 MPQ
     * filename.  The returned values are stored in Java {@code int}s but must
     * be treated as unsigned 32-bit values when serialized or compared.
     *
     * @param filename MPQ filename using the archive's Storm hashing rules
     * @return the hash-name, hash-extension, and hash-table values
     */
    public static StormHash fileHash(String filename) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = Support.text(arena, filename);
            MemorySegment hash1 = arena.allocate(java.lang.foreign.ValueLayout.JAVA_INT);
            MemorySegment hash2 = arena.allocate(java.lang.foreign.ValueLayout.JAVA_INT);
            MemorySegment hash3 = arena.allocate(java.lang.foreign.ValueLayout.JAVA_INT);
            LibmpqNative.fileHash(name, hash1, hash2, hash3);
            return new StormHash(LibmpqNative.getInt(hash1), LibmpqNative.getInt(hash2),
                                 LibmpqNative.getInt(hash3));
        }
    }

    /** Three unsigned 32-bit Storm hashes for one MPQ filename. */
    public record StormHash(int hash1, int hash2, int hash3) { }
}
