/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq.ffi;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Complete low-level Foreign Function and Memory API mapping for the stable
 * libmpq ABI.  Methods in this class deliberately preserve native handles,
 * pointers, output parameters, and negative status returns.  Most callers
 * should use the safer {@code org.libmpq} facade, which owns arenas, converts
 * strings and buffers, and translates failures into {@code LibmpqException}.
 */
public final class LibmpqNative {
    private static final Linker LINKER = Linker.nativeLinker();
    private static final ValueLayout.OfInt C_INT = ValueLayout.JAVA_INT.withOrder(ByteOrder.nativeOrder());
    private static final ValueLayout.OfShort C_SHORT =
        ValueLayout.JAVA_SHORT.withOrder(ByteOrder.nativeOrder());
    private static final ValueLayout.OfLong C_LONG = ValueLayout.JAVA_LONG.withOrder(ByteOrder.nativeOrder());
    private static final ValueLayout C_SIZE_T = canonicalValueLayout("size_t");

    /**
     * Native layout of {@code struct mpq_archive_create_options_s}: five
     * native-endian uint32 fields for version, capacity, sector size, flags,
     * and attributes. Nonzero attributes reserve one internal file slot.
     */
    public static final MemoryLayout ARCHIVE_OPTIONS = MemoryLayout.structLayout(
        C_INT.withName("version"), C_INT.withName("max_files"),
        C_INT.withName("sector_size"), C_INT.withName("flags"),
        C_INT.withName("attributes"));
    /**
     * Native layout of {@code struct mpq_file_options_s}: three int32 fields
     * followed by two native-endian uint16-compatible locale fields.
     */
    public static final MemoryLayout FILE_OPTIONS = MemoryLayout.structLayout(
        C_INT.withName("flags"), C_INT.withName("compression_first"),
        C_INT.withName("compression_next"), C_SHORT.withName("locale"),
        C_SHORT.withName("platform"));

    private static final MethodHandle VERSION;
    private static final MethodHandle ARCHIVE_ATTRIBUTES;
    private static final MethodHandle FILE_ATTRIBUTES;
    private static final MethodHandle WRITER_TIMESTAMP;

    /** 40-byte native result with explicit reserved bytes, not the disk layout. */
    public static final MemoryLayout FILE_ATTRIBUTES_LAYOUT = attributesLayout();

    private static MemoryLayout attributesLayout() {
        long alignment = canonicalValueLayout("long long").byteAlignment();
        return MemoryLayout.structLayout(
            C_INT.withName("flags"), C_INT.withName("crc32"),
            C_LONG.withByteAlignment(alignment).withName("filetime"),
            MemoryLayout.sequenceLayout(16, ValueLayout.JAVA_BYTE).withName("md5"),
            C_INT.withName("patch_bit"),
            MemoryLayout.sequenceLayout(4, ValueLayout.JAVA_BYTE).withName("reserved")
        );
    }
    private static final MethodHandle STRERROR;
    private static final MethodHandle ARCHIVE_COMPRESSION_ALLOWED;
    private static final MethodHandle ARCHIVE_OPEN;
    private static final MethodHandle ARCHIVE_OPEN_MPQE;
    private static final MethodHandle ARCHIVE_CREATE;
    private static final MethodHandle ARCHIVE_CREATE_MPQE;
    private static final MethodHandle WRITER_BEGIN;
    private static final MethodHandle WRITER_WRITE;
    private static final MethodHandle WRITER_FINISH;
    private static final MethodHandle ARCHIVE_ADD_DATA;
    private static final MethodHandle ARCHIVE_ADD_PATH;
    private static final MethodHandle ARCHIVE_CLONE;
    private static final MethodHandle ARCHIVE_CLOSE;
    private static final MethodHandle ARCHIVE_SIZE_PACKED;
    private static final MethodHandle ARCHIVE_SIZE_UNPACKED;
    private static final MethodHandle ARCHIVE_OFFSET;
    private static final MethodHandle ARCHIVE_VERSION;
    private static final MethodHandle ARCHIVE_FILES;
    private static final MethodHandle FILE_SIZE_PACKED;
    private static final MethodHandle FILE_SIZE_UNPACKED;
    private static final MethodHandle FILE_OFFSET;
    private static final MethodHandle FILE_BLOCKS;
    private static final MethodHandle FILE_FLAGS;
    private static final MethodHandle FILE_NUMBER;
    private static final MethodHandle FILE_HASH;
    private static final MethodHandle FILE_NUMBER_FROM_HASH;
    private static final MethodHandle FILE_READ;
    private static final MethodHandle FILE_VERIFY;
    private static final MethodHandle BLOCK_VERIFY;
    private static final MethodHandle BLOCK_SIZE_UNPACKED;
    private static final MethodHandle BLOCK_SIZE_PACKED;
    private static final MethodHandle BLOCK_COMPRESSION;
    private static final MethodHandle BLOCK_READ;

    static {
        SymbolLookup lookup = loadLibrary();
        Linker linker = LINKER;
        ARCHIVE_ATTRIBUTES = uintMetadata(linker, lookup, "libmpq__archive_attributes");
        FILE_ATTRIBUTES = function(linker, lookup, "libmpq__file_attributes",
            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT, ValueLayout.ADDRESS));
        FILE_VERIFY = function(linker, lookup, "libmpq__file_verify",
            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT, C_INT, ValueLayout.ADDRESS));
        BLOCK_VERIFY = function(linker, lookup, "libmpq__block_verify",
            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT, C_INT,
                                  ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        WRITER_TIMESTAMP = function(linker, lookup, "libmpq__writer_timestamp",
            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_LONG));
        VERSION = function(linker, lookup, "libmpq__version",
                           FunctionDescriptor.of(ValueLayout.ADDRESS));
        STRERROR = function(linker, lookup, "libmpq__strerror",
                            FunctionDescriptor.of(ValueLayout.ADDRESS, C_INT));
        ARCHIVE_COMPRESSION_ALLOWED = function(linker, lookup, "libmpq__archive_compression_allowed",
                                         FunctionDescriptor.of(C_INT, C_INT, C_INT, C_INT));
        ARCHIVE_OPEN = function(linker, lookup, "libmpq__archive_open",
                                FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                      ValueLayout.ADDRESS, C_LONG));
        ARCHIVE_OPEN_MPQE = function(linker, lookup, "libmpq__archive_open_mpqe",
                                     FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                           ValueLayout.ADDRESS, C_LONG,
                                                           ValueLayout.ADDRESS, C_SIZE_T));
        ARCHIVE_CREATE = function(linker, lookup, "libmpq__archive_create",
                                  FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        WRITER_BEGIN = function(linker, lookup, "libmpq__writer_begin",
                              FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                    ValueLayout.ADDRESS, C_LONG,
                                                    ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        WRITER_WRITE = function(linker, lookup, "libmpq__writer_write",
                              FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                    ValueLayout.ADDRESS, C_LONG));
        WRITER_FINISH = function(linker, lookup, "libmpq__writer_finish",
                               FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS));
        ARCHIVE_ADD_DATA = function(linker, lookup, "libmpq__archive_add_data",
                            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                  ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                                  C_LONG, ValueLayout.ADDRESS));
        ARCHIVE_ADD_PATH = function(linker, lookup, "libmpq__archive_add_path",
                                 FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                       ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                                        ValueLayout.ADDRESS));
        ARCHIVE_CREATE_MPQE = function(linker, lookup, "libmpq__archive_create_mpqe",
                                       FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                             ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                                             C_SIZE_T, ValueLayout.ADDRESS));
        ARCHIVE_CLONE = function(linker, lookup, "libmpq__archive_clone",
                                 FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                       ValueLayout.ADDRESS));
        ARCHIVE_CLOSE = function(linker, lookup, "libmpq__archive_close",
                                 FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS));
        ARCHIVE_SIZE_PACKED = metadata(linker, lookup, "libmpq__archive_size_packed");
        ARCHIVE_SIZE_UNPACKED = metadata(linker, lookup, "libmpq__archive_size_unpacked");
        ARCHIVE_OFFSET = metadata(linker, lookup, "libmpq__archive_offset");
        ARCHIVE_VERSION = uintMetadata(linker, lookup, "libmpq__archive_version");
        ARCHIVE_FILES = uintMetadata(linker, lookup, "libmpq__archive_files");
        FILE_SIZE_PACKED = fileMetadata(linker, lookup, "libmpq__file_size_packed");
        FILE_SIZE_UNPACKED = fileMetadata(linker, lookup, "libmpq__file_size_unpacked");
        FILE_OFFSET = fileMetadata(linker, lookup, "libmpq__file_offset");
        FILE_BLOCKS = fileUintMetadata(linker, lookup, "libmpq__file_blocks");
        FILE_FLAGS = fileUintMetadata(linker, lookup, "libmpq__file_flags");
        FILE_NUMBER = function(linker, lookup, "libmpq__file_number",
                               FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                     ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FILE_HASH = function(linker, lookup, "libmpq__file_hash",
                             FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                                       ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FILE_NUMBER_FROM_HASH = function(linker, lookup, "libmpq__file_number_from_hash",
                                         FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS,
                                                               C_INT, C_INT, C_INT,
                                                               ValueLayout.ADDRESS));
        FILE_READ = function(linker, lookup, "libmpq__file_read",
                             FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT,
                                                   ValueLayout.ADDRESS, C_LONG,
                                                   ValueLayout.ADDRESS));
        BLOCK_SIZE_PACKED = function(linker, lookup, "libmpq__block_size_packed",
            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT, C_INT, ValueLayout.ADDRESS));
        BLOCK_COMPRESSION = function(linker, lookup, "libmpq__block_compression",
            FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT, C_INT, ValueLayout.ADDRESS));
        BLOCK_SIZE_UNPACKED = function(linker, lookup, "libmpq__block_size_unpacked",
                                       FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT,
                                                             C_INT, ValueLayout.ADDRESS));
        BLOCK_READ = function(linker, lookup, "libmpq__block_read",
                              FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT, C_INT,
                                                    ValueLayout.ADDRESS, C_LONG, ValueLayout.ADDRESS));
    }

    /** Prevents construction of this static native mapping. */
    private LibmpqNative() { }

    /** Loads an explicitly configured library or the JVM loader's libmpq. */
    private static SymbolLookup loadLibrary() {
        String explicit = System.getProperty("org.libmpq.library");
        if (explicit != null && !explicit.isBlank()) {
            return SymbolLookup.libraryLookup(Path.of(explicit), Arena.global());
        }
        System.loadLibrary("mpq");
        return SymbolLookup.loaderLookup();
    }

    /** Resolves one exported symbol and creates its downcall handle. */
    private static MethodHandle function(Linker linker, SymbolLookup lookup, String name,
                                         FunctionDescriptor descriptor) {
        MemorySegment address = lookup.find(name)
            .orElseThrow(() -> new UnsatisfiedLinkError("Missing libmpq symbol: " + name));
        return linker.downcallHandle(address, descriptor);
    }

    /** Returns the platform linker layout for one named native scalar type. */
    private static ValueLayout canonicalValueLayout(String name) {
        MemoryLayout layout = LINKER.canonicalLayouts().get(name);
        if (!(layout instanceof ValueLayout valueLayout)) {
            throw new IllegalStateException("Missing native value layout: " + name);
        }
        return valueLayout;
    }

    /** Converts a non-negative Java length without truncating native size_t. */
    private static Object nativeSizeT(long value) {
        Class<?> carrier = C_SIZE_T.carrier();

        if (value < 0) {
            throw new IllegalArgumentException("size_t value must not be negative: " + value);
        }
        if (carrier == long.class) {
            return value;
        }
        if (carrier == int.class) {
            if (value > Integer.toUnsignedLong(-1)) {
                throw new IllegalArgumentException("size_t value is too large: " + value);
            }
            return (int) value;
        }
        throw new IllegalStateException("Unsupported native size_t carrier: " + carrier);
    }

    /** Builds a handle for archive int64 output queries returning a status. */
    private static MethodHandle metadata(Linker linker, SymbolLookup lookup, String name) {
        return function(linker, lookup, name,
                        FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /** Builds a handle for archive uint32 output queries returning a status. */
    private static MethodHandle uintMetadata(Linker linker, SymbolLookup lookup, String name) {
        return function(linker, lookup, name,
                        FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /** Builds a handle for indexed file int64 output queries. */
    private static MethodHandle fileMetadata(Linker linker, SymbolLookup lookup, String name) {
        return function(linker, lookup, name,
                        FunctionDescriptor.of(C_INT, ValueLayout.ADDRESS, C_INT,
                                              ValueLayout.ADDRESS));
    }

    /** Reuses the indexed output layout for file uint32 metadata queries. */
    private static MethodHandle fileUintMetadata(Linker linker, SymbolLookup lookup, String name) {
        return fileMetadata(linker, lookup, name);
    }

    /** Invokes a status-returning native handle and preserves Java failures. */
    private static int callInt(MethodHandle handle, Object... arguments) {
        try {
            return (int) handle.invokeWithArguments(arguments);
        } catch (Throwable error) {
            throw new IllegalStateException("Unable to call libmpq", error);
        }
    }

    /** Invokes a native function returning a pointer segment. */
    private static MemorySegment callAddress(MethodHandle handle, Object... arguments) {
        try {
            return (MemorySegment) handle.invokeWithArguments(arguments);
        } catch (Throwable error) {
            throw new IllegalStateException("Unable to call libmpq", error);
        }
    }

    /** Invokes a native function with no return value, such as file hashing. */
    private static void callVoid(MethodHandle handle, Object... arguments) {
        try {
            handle.invokeWithArguments(arguments);
        } catch (Throwable error) {
            throw new IllegalStateException("Unable to call libmpq", error);
        }
    }

    /**
     * Returns the native pointer to libmpq's static version string.  The
     * pointer is borrowed and must be copied before any library unload.
     */
    public static MemorySegment version() { return callAddress(VERSION); }
    /**
     * Returns the native pointer to the diagnostic string for a status code.
     * The pointer is borrowed and has static-library lifetime.
     */
    public static MemorySegment strerror(int code) { return callAddress(STRERROR, code); }
    /**
     * Returns 1 if compression is allowed for the version and policy, otherwise 0.
     * Both policy and the return value are native int32_t values.
     */
    public static int archiveCompressionAllowed(int version, int mask, int policy) {
        return callInt(ARCHIVE_COMPRESSION_ALLOWED, version, mask, policy);
    }
    /** Calls {@code libmpq__archive_open} and writes the resulting handle to out. */
    public static int archiveOpen(MemorySegment out, MemorySegment path, long offset) {
        return callInt(ARCHIVE_OPEN, out, path, offset);
    }
    /** Calls {@code libmpq__archive_open_mpqe} with borrowed authentication bytes. */
    public static int archiveOpenMpqe(MemorySegment out, MemorySegment path, long offset,
                                      MemorySegment authCode, long authCodeSize) {
        return callInt(ARCHIVE_OPEN_MPQE, out, path, offset, authCode, nativeSizeT(authCodeSize));
    }
    /** Calls {@code libmpq__archive_create} with a native options struct. */
    public static int archiveCreate(MemorySegment out, MemorySegment path, MemorySegment options) {
        return callInt(ARCHIVE_CREATE, out, path, options);
    }
    /** Calls {@code libmpq__archive_create_mpqe} with borrowed authentication bytes. */
    public static int archiveCreateMpqe(MemorySegment out, MemorySegment path,
                                        MemorySegment authCode, long authCodeSize,
                                        MemorySegment options) {
        return callInt(ARCHIVE_CREATE_MPQE, out, path, authCode, nativeSizeT(authCodeSize), options);
    }
    /** Starts a native streaming entry and writes its writer handle to out. */
    public static int writerBegin(MemorySegment archive, MemorySegment name, long size,
                                MemorySegment options, MemorySegment out) {
        return callInt(WRITER_BEGIN, archive, name, size, options, out);
    }
    /** Appends one native buffer to an active streaming writer. */
    public static int writerWrite(MemorySegment writer, MemorySegment buffer, long size) {
        return callInt(WRITER_WRITE, writer, buffer, size);
    }
    /** Finalizes a native streaming writer and publishes its entry. */
    public static int writerFinish(MemorySegment writer) { return callInt(WRITER_FINISH, writer); }

    /** Query attributes presence flags without treating missing metadata as zero flags. */
    public static int archiveAttributes(MemorySegment archive, MemorySegment flags) {
        return callInt(ARCHIVE_ATTRIBUTES, archive, flags);
    }

    /** Read a native aligned attributes result for one public file number. */
    public static int fileAttributes(MemorySegment archive, int number, MemorySegment output) {
        return callInt(FILE_ATTRIBUTES, archive, number, output);
    }

    /** Verify available checksums; mismatches receives a subset of flags, or zero on error. */
    public static int fileVerify(MemorySegment archive, int number, int flags, MemorySegment mismatches) {
        return callInt(FILE_VERIFY, archive, number, flags, mismatches);
    }

    /** Return the stored sector Adler-32 and mismatch bit; both outputs are zero on error. */
    public static int blockVerify(MemorySegment archive, int number, int block,
                                  MemorySegment checksum, MemorySegment mismatches) {
        return callInt(BLOCK_VERIFY, archive, number, block, checksum, mismatches);
    }

    /** Supply unsigned Windows FILETIME bits, not Unix time, to an active writer. */
    public static int writerTimestamp(MemorySegment writer, long filetime) {
        return callInt(WRITER_TIMESTAMP, writer, filetime);
    }
    /** Adds a complete native buffer as one archive entry. */
    public static int archiveAddData(MemorySegment archive, MemorySegment name, MemorySegment buffer,
                              long size, MemorySegment options) {
        return callInt(ARCHIVE_ADD_DATA, archive, name, buffer, size, options);
    }
    /** Adds a filesystem path as one archive entry. */
    public static int archiveAddPath(MemorySegment archive, MemorySegment name, MemorySegment path,
                                  MemorySegment options) {
        return callInt(ARCHIVE_ADD_PATH, archive, name, path, options);
    }
    /** Reopens an archive into an independent native handle. */
    public static int archiveClone(MemorySegment out, MemorySegment archive) {
        return callInt(ARCHIVE_CLONE, out, archive);
    }
    /** Closes one native archive handle. */
    public static int archiveClose(MemorySegment archive) { return callInt(ARCHIVE_CLOSE, archive); }
    /** Queries either packed or unpacked archive size through an int64 output. */
    public static int archiveLong(MemorySegment archive, MemorySegment output, boolean unpacked) {
        return callInt(unpacked ? ARCHIVE_SIZE_UNPACKED : ARCHIVE_SIZE_PACKED, archive, output);
    }
    /** Queries the archive header offset through an int64 output. */
    public static int archiveOffset(MemorySegment archive, MemorySegment output) {
        return callInt(ARCHIVE_OFFSET, archive, output);
    }
    /** Queries either the public version or file count through uint32 output. */
    public static int archiveUint(MemorySegment archive, MemorySegment output, boolean files) {
        return callInt(files ? ARCHIVE_FILES : ARCHIVE_VERSION, archive, output);
    }
    /** Queries a selected indexed file size or offset through int64 output. */
    public static int fileLong(MemorySegment archive, int number, MemorySegment output,
                               boolean unpacked, boolean offset) {
        MethodHandle handle = offset ? FILE_OFFSET : (unpacked ? FILE_SIZE_UNPACKED : FILE_SIZE_PACKED);
        return callInt(handle, archive, number, output);
    }
    /** Queries a selected indexed file flag or block count through uint32 output. */
    public static int fileUint(MemorySegment archive, int number, MemorySegment output, int kind) {
        MethodHandle handle = switch (kind) {
            case 0 -> FILE_BLOCKS;
            case 1 -> FILE_FLAGS;
            default -> throw new IllegalArgumentException("Unknown file query: " + kind);
        };
        return callInt(handle, archive, number, output);
    }
    /** Resolves a native archive filename to its public file number. */
    public static int fileNumber(MemorySegment archive, MemorySegment name, MemorySegment output) {
        return callInt(FILE_NUMBER, archive, name, output);
    }
    /** Computes the three Storm hash values into caller-provided outputs. */
    public static void fileHash(MemorySegment name, MemorySegment hash1, MemorySegment hash2,
                                MemorySegment hash3) {
        callVoid(FILE_HASH, name, hash1, hash2, hash3);
    }
    /** Resolves precomputed Storm hashes to a public file number. */
    public static int fileNumberFromHash(MemorySegment archive, int hash1, int hash2, int hash3,
                                         MemorySegment output) {
        return callInt(FILE_NUMBER_FROM_HASH, archive, hash1, hash2, hash3, output);
    }
    /** Reads and decodes an entire native file into a caller buffer. */
    public static int fileRead(MemorySegment archive, int number, MemorySegment output, long size,
                               MemorySegment transferred) {
        return callInt(FILE_READ, archive, number, output, size, transferred);
    }
    /** Queries one sector's stored size, excluding offset/checksum tables. */
    public static int blockSizePacked(MemorySegment archive, int number, int block, MemorySegment output) {
        return callInt(BLOCK_SIZE_PACKED, archive, number, block, output);
    }

    public static int blockCompression(MemorySegment archive, int number, int block, MemorySegment output) {
        return callInt(BLOCK_COMPRESSION, archive, number, block, output);
    }

    /** Return one block's unpacked size. */
    public static int blockSize(MemorySegment archive, int number, int block, MemorySegment output) {
        return callInt(BLOCK_SIZE_UNPACKED, archive, number, block, output);
    }
    /** Reads and decodes one sector into a caller-provided native buffer. */
    public static int blockRead(MemorySegment archive, int number, int block, MemorySegment output,
                                long size, MemorySegment transferred) {
        return callInt(BLOCK_READ, archive, number, block, output, size, transferred);
    }

    /**
     * Serializes Java archive creation values into the exact native struct
     * layout expected by {@code libmpq__archive_create}.
     */
    public static void setArchiveOptions(MemorySegment memory, int version, int maxFiles,
                                          int sectorSize, int flags, int attributes) {
        memory.set(C_INT, 0, version);
        memory.set(C_INT, 4, maxFiles);
        memory.set(C_INT, 8, sectorSize);
        memory.set(C_INT, 12, flags);
        memory.set(C_INT, 16, attributes);
    }

    /**
     * Serializes Java file storage values into the exact native struct layout
     * expected by file-add and streaming-entry functions.
     */
    public static void setFileOptions(MemorySegment memory, int flags, int first, int next,
                                      short locale, short platform) {
        memory.set(C_INT, 0, flags);
        memory.set(C_INT, 4, first);
        memory.set(C_INT, 8, next);
        memory.set(C_SHORT, 12, locale);
        memory.set(C_SHORT, 14, platform);
    }

    /** Reads a native-endian int32 output parameter. */
    public static int getInt(MemorySegment memory) { return memory.get(C_INT, 0); }
    /** Reads a native-endian int64 output parameter. */
    public static long getLong(MemorySegment memory) { return memory.get(C_LONG, 0); }
    /** Reads a native pointer output parameter. */
    public static MemorySegment getAddress(MemorySegment memory) {
        return memory.get(ValueLayout.ADDRESS, 0);
    }

    /** Validates a non-null segment before crossing the native boundary. */
    public static MemorySegment requireSegment(MemorySegment segment) {
        return Objects.requireNonNull(segment, "segment");
    }
}
