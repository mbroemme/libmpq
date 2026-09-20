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
import java.lang.foreign.ValueLayout;
import java.nio.file.Path;
import java.util.Objects;
import org.libmpq.ffi.LibmpqNative;

/**
 * A closeable handle for an opened or newly created MPQ archive.  Each
 * instance owns one native archive handle; callers must keep it open while
 * querying or modifying the archive and should use try-with-resources.
 */
public final class Archive implements AutoCloseable {

    /** Return weak signature presence bits; malformed storage throws. */
    public int signatures() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.archiveSignatures(handle, result));
            return result.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /** Verify with a 128-byte key: 64-byte big-endian n then e; return mismatch bits. */
    public int verify(byte[] publicKey) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(publicKey);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, publicKey);
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.archiveVerify(handle, Mpq.SIGNATURE_WEAK,
                                                    key, publicKey.length, result));
            return result.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /** Configure signing with a 128-byte key: 64-byte big-endian n then d. */
    public void sign(byte[] privateKey) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(privateKey);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, privateKey);
            try {
                Support.check(LibmpqNative.archiveSign(handle, Mpq.SIGNATURE_WEAK, key, privateKey.length));
            } finally {
                key.fill((byte) 0);
            }
        }
    }

    /** Stored unsigned Adler-32 and zero or Mpq.VERIFY_SECTOR_CRC mismatch bits. */
    public record BlockVerification(long checksum, int mismatches) {}

    /** Verify one sector; unavailable checksums throw ERROR_EXIST. */
    public BlockVerification verifyBlock(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment checksum = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment mismatches = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.blockVerify(handle, number, block, checksum, mismatches));
            return new BlockVerification(Integer.toUnsignedLong(checksum.get(ValueLayout.JAVA_INT, 0)),
                                         mismatches.get(ValueLayout.JAVA_INT, 0));
        }
    }

    /** Verify all available file checksums and return mismatch bits. */
    public int verify(int number) throws LibmpqException {
        return verify(number, Mpq.VERIFY_ALL);
    }

    /** Return mismatches as a subset of flags; clear bits mean matched or unavailable.
     * File checks require attributes; sector-only checks do not. Errors throw. */
    public int verify(int number, int flags) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment mismatches = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileVerify(handle, number, flags, mismatches));
            return mismatches.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /** Return flags, or empty when absent; malformed attributes are still errors. */
    public java.util.OptionalInt attributes() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment flags = arena.allocate(ValueLayout.JAVA_INT);
            int status = LibmpqNative.archiveAttributes(handle, flags);
            if (status == Mpq.ERROR_EXIST) return java.util.OptionalInt.empty();
            Support.check(status);
            return java.util.OptionalInt.of(flags.get(ValueLayout.JAVA_INT, 0));
        }
    }

    /** Return owned stored attributes; availability is represented by result flags. */
    public FileAttributes attributes(int number) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment value = arena.allocate(LibmpqNative.FILE_ATTRIBUTES_LAYOUT);
            Support.check(LibmpqNative.fileAttributes(handle, number, value));
            return new FileAttributes(value.get(ValueLayout.JAVA_INT, 0),
                Integer.toUnsignedLong(value.get(ValueLayout.JAVA_INT, 4)),
                value.get(ValueLayout.JAVA_LONG_UNALIGNED, 8),
                value.asSlice(16, 16).toArray(ValueLayout.JAVA_BYTE),
                value.get(ValueLayout.JAVA_INT, 32) != 0);
        }
    }
    private MemorySegment handle;

    /** Wraps a newly returned native archive handle. */
    private Archive(MemorySegment handle) {
        this.handle = handle;
    }

    /**
     * Opens an archive from a filesystem path.  An offset of zero opens a
     * standalone archive at the beginning of the file; a negative offset
     * asks libmpq to scan for an embedded MPQ header.
     *
     * @param path archive file to open
     * @param offset standalone or embedded archive offset, with negative
     * values selecting header scanning
     * @return an owned archive handle
     * @throws LibmpqException if the file cannot be opened or is malformed
     */
    public static Archive open(Path path, long offset) throws LibmpqException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.archiveOpen(output, Support.text(arena, path.toString()), offset));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /**
     * Opens a standalone archive whose MPQ header begins at file offset zero.
     *
     * @param path archive file to open
     * @return an owned archive handle
     * @throws LibmpqException if the file cannot be opened or is malformed
     */
    public static Archive open(Path path) throws LibmpqException {
        return open(path, 0);
    }

    /**
     * Opens an MPQE transport stream containing an archive at its initial offset.
     * The authentication code is copied for the duration of the native call and
     * is not retained by this Java binding.
     *
     * @param path MPQE stream to open
     * @param authCode caller-supplied MPQE authentication code
     * @return an owned archive handle
     * @throws LibmpqException if credentials are invalid or the decrypted data cannot be parsed
     */
    public static Archive openMpqe(Path path, byte[] authCode) throws LibmpqException {
        return openMpqe(path, authCode, 0);
    }

    /**
     * Opens an MPQE transport stream. A negative offset asks libmpq to scan
     * the decrypted stream for an embedded MPQ header.
     *
     * @param path MPQE stream to open
     * @param authCode caller-supplied MPQE authentication code
     * @param offset standalone or embedded archive offset
     * @return an owned archive handle
     * @throws LibmpqException if credentials are invalid or the decrypted data cannot be parsed
     */
    public static Archive openMpqe(Path path, byte[] authCode, long offset)
        throws LibmpqException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(authCode, "authCode");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment authCodeSegment = Support.bytes(arena, authCode);
            Support.check(LibmpqNative.archiveOpenMpqe(
                output, Support.text(arena, path.toString()), offset, authCodeSegment, authCode.length
            ));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /**
     * Creates a new archive and returns its writable native handle.  The
     * archive remains open for additions until this object is closed; closing
     * finalizes headers, tables, and all completed entries.
     *
     * @param path destination archive path
     * @param options creation parameters, or {@code null} for native defaults
     * @return a newly created archive handle
     * @throws LibmpqException if creation or option validation fails
     */
    public static Archive create(Path path, ArchiveCreateOptions options) throws LibmpqException {
        if (options == null) {
            options = ArchiveCreateOptions.defaults();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment nativeOptions = arena.allocate(LibmpqNative.ARCHIVE_OPTIONS);
            LibmpqNative.setArchiveOptions(nativeOptions, options.version(),
                                            Support.uint32(options.maxFiles(), "maxFiles"),
                                            Support.uint32(options.sectorSize(), "sectorSize"),
                                            options.flags(), options.attributes());
            Support.check(LibmpqNative.archiveCreate(output, Support.text(arena, path.toString()),
                                                      nativeOptions));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /** Creates a new MPQE-wrapped archive using caller-supplied authentication bytes. */
    public static Archive createMpqe(Path path, byte[] authCode,
                                     ArchiveCreateOptions options) throws LibmpqException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(authCode, "authCode");
        if (options == null) {
            options = ArchiveCreateOptions.defaults();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment nativeOptions = arena.allocate(LibmpqNative.ARCHIVE_OPTIONS);
            LibmpqNative.setArchiveOptions(nativeOptions, options.version(),
                                            Support.uint32(options.maxFiles(), "maxFiles"),
                                            Support.uint32(options.sectorSize(), "sectorSize"),
                                            options.flags(), options.attributes());
            Support.check(LibmpqNative.archiveCreateMpqe(
                output, Support.text(arena, path.toString()), Support.bytes(arena, authCode),
                authCode.length, nativeOptions
            ));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /**
     * Reopens this archive through an independent native handle.  The clone
     * has its own file stream and can outlive this object or be closed before
     * it without affecting the original handle.
     *
     * @return an independent archive handle
     * @throws LibmpqException if the archive cannot be reopened
     */
    public Archive cloneArchive() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.archiveClone(output, handle));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /** Returns the sum of stored payload sizes reported by the native archive. */
    public long packedSize() throws LibmpqException {
        return archiveLong(false);
    }

    /** Returns the sum of logical, unpacked file sizes reported by the archive. */
    public long unpackedSize() throws LibmpqException {
        return archiveLong(true);
    }

    /** Returns the archive header offset in its backing file. */
    public long offset() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.archiveOffset(handle, result));
            return LibmpqNative.getLong(result);
        }
    }

    /**
     * Returns the public archive format version, normally one for v1 and two
     * for v2.  This differs from the zero/one creation selectors in
     * {@link ArchiveCreateOptions}.
     */
    public long version() throws LibmpqException {
        return archiveUint(false);
    }

    /** Returns the number of public file entries, excluding internal tables. */
    public long fileCount() throws LibmpqException {
        return archiveUint(true);
    }

    /**
     * Reads all archive-level metadata and returns it as one immutable
     * snapshot.  Individual native queries can fail independently, so no
     * partially populated object is returned.
     */
    public ArchiveMetadata metadata() throws LibmpqException {
        return new ArchiveMetadata(packedSize(), unpackedSize(), offset(), version(), fileCount());
    }

    /**
     * Resolves an MPQ filename through the native hash tables.
     *
     * @param filename exact archive filename, including any path components
     * @return zero-based public file number
     * @throws LibmpqException if the name is absent or the archive is closed
     */
    public int fileNumber(String filename) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileNumber(handle, Support.text(arena, filename), result));
            return LibmpqNative.getInt(result);
        }
    }

    /**
     * Resolves precomputed Storm hashes without hashing the filename again.
     *
     * @param hash three values previously returned by {@link Mpq#fileHash}
     * @return zero-based public file number
     * @throws LibmpqException if the hash is absent or the archive is closed
     */
    public int fileNumber(Mpq.StormHash hash) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileNumberFromHash(handle, hash.hash1(), hash.hash2(),
                                                           hash.hash3(), result));
            return LibmpqNative.getInt(result);
        }
    }

    /** Returns one entry's stored payload size. */
    public long filePackedSize(int number) throws LibmpqException {
        return fileLong(number, false, false);
    }

    /** Returns one entry's logical size after decompression. */
    public long fileUnpackedSize(int number) throws LibmpqException {
        return fileLong(number, true, false);
    }

    /** Returns one entry's payload offset relative to the archive file. */
    public long fileOffset(int number) throws LibmpqException {
        return fileLong(number, false, true);
    }

    /** Returns one entry's number of logical MPQ sectors. */
    public long fileBlocks(int number) throws LibmpqException {
        return fileUint(number, 0);
    }

    /** Returns the unsigned stored MPQ block-table flags. */
    public long fileFlags(int number) throws LibmpqException {
        return fileUint(number, 1);
    }

    /** Reports whether one entry's stored sectors are encrypted. */
    public boolean fileEncrypted(int number) throws LibmpqException {
        return (fileFlags(number) & Mpq.FILE_FLAG_ENCRYPTED) != 0;
    }

    /** Reports whether one entry uses MPQ multi-compression. */
    public boolean fileCompressed(int number) throws LibmpqException {
        return (fileFlags(number) & Mpq.FILE_FLAG_COMPRESS) != 0;
    }

    /** Reports whether one entry uses standalone PKWARE implode. */
    public boolean fileImploded(int number) throws LibmpqException {
        return (fileFlags(number) & Mpq.FILE_FLAG_IMPLODE) != 0;
    }

    /**
     * Reads all metadata for one entry and returns a single immutable
     * snapshot, including storage flags and sector count.
     */
    public FileMetadata fileMetadata(int number) throws LibmpqException {
        return new FileMetadata(filePackedSize(number), fileUnpackedSize(number), fileOffset(number),
                                fileBlocks(number), fileEncrypted(number), fileCompressed(number),
                                fileImploded(number));
    }

    /**
     * Reads and decodes a complete logical file into a new Java byte array.
     * The native reader handles sector offsets, decryption, and supported
     * compression stages before copying the result into Java memory.
     *
     * @param number zero-based public file number
     * @return exact unpacked file bytes
     * @throws LibmpqException if decoding or reading fails
     * @throws IllegalArgumentException if the file cannot fit in a Java array
     */
    public byte[] readFile(int number) throws LibmpqException {
        long size = fileUnpackedSize(number);
        byte[] result = new byte[Support.checkedArraySize(size)];
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(result.length == 0 ? 1 : result.length, 1);
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.fileRead(handle, number,
                                                result.length == 0 ? MemorySegment.NULL : output,
                                                size, transferred));
            Support.copyTo(output, result);
            return result;
        }
    }

    /** Returns stored sector bytes, excluding offset/checksum tables. */
    public long blockSizePacked(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.blockSizePacked(handle, number, block, result));
            return result.get(ValueLayout.JAVA_LONG, 0);
        }
    }

    /** Returns the stored method byte, not a writer selector; zero means raw. */
    public int blockCompression(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.blockCompression(handle, number, block, result));
            return result.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /** Return one block's unpacked size. */
    public long blockSize(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.blockSize(handle, number, block, result));
            return LibmpqNative.getLong(result);
        }
    }

    /** Reads one decoded sector; native code manages the offset cache. */
    public byte[] readBlock(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            long size = blockSize(number, block);
            byte[] result = new byte[Support.checkedArraySize(size)];
            MemorySegment output = arena.allocate(result.length == 0 ? 1 : result.length, 1);
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.blockRead(handle, number, block,
                                                 result.length == 0 ? MemorySegment.NULL : output,
                                                 size, transferred));
            Support.copyTo(output, result);
            return result;
        }
    }

    /**
     * Adds a complete in-memory file to an archive being created.  The byte
     * array is copied or consumed by the native call before the method
     * returns, so its Java lifetime need not extend beyond this call.
     *
     * @param name archive filename
     * @param data exact logical file bytes
     * @param options storage options, or {@code null} for raw storage
     */
    public void add(String name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        if (options == null) {
            options = FileOptions.raw();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeOptions = fileOptions(arena, options);
            Support.check(LibmpqNative.archiveAddData(handle, Support.text(arena, name),
                                                Support.bytes(arena, data), data.length, nativeOptions));
        }
    }

    /**
     * Reads a filesystem file through libmpq and adds it under a caller-
     * supplied archive filename.
     *
     * @param name archive filename
     * @param source filesystem source path
     * @param options storage options, or {@code null} for raw storage
     */
    public void addPath(String name, Path source, FileOptions options) throws LibmpqException {
        checkOpen();
        if (options == null) {
            options = FileOptions.raw();
        }
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.archiveAddPath(handle, Support.text(arena, name),
                                                   Support.text(arena, source.toString()),
                                                   fileOptions(arena, options)));
        }
    }

    /**
     * Starts a streaming writer for one archive entry.  The declared size is
     * mandatory because MPQ headers and sector tables are finalized from it;
     * callers must write exactly that many bytes before finishing.
     *
     * @param name archive filename
     * @param size exact logical size to be written
     * @param options storage options, or {@code null} for raw storage
     * @return a closeable writer for the new entry
     */
    public MpqFileWriter begin(String name, long size, FileOptions options) throws LibmpqException {
        checkOpen();
        if (size < 0) {
            throw new IllegalArgumentException("size must not be negative");
        }
        if (options == null) {
            options = FileOptions.raw();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.writerBegin(handle, Support.text(arena, name), size,
                                                  fileOptions(arena, options), output));
            return new MpqFileWriter(LibmpqNative.getAddress(output), size);
        }
    }

    /**
     * Closes the native archive handle.  Closing is idempotent from Java's
     * perspective; a failed native close is still reported to the caller.
     */
    @Override
    public void close() throws LibmpqException {
        MemorySegment current = handle;
        if (current == null || current.equals(MemorySegment.NULL)) {
            return;
        }
        handle = MemorySegment.NULL;
        Support.check(LibmpqNative.archiveClose(current));
    }

    /** Returns the live native handle for package-private writer operations. */
    MemorySegment nativeHandle() {
        checkOpenUnchecked();
        return handle;
    }

    /** Converts immutable Java options into the native struct layout. */
    private MemorySegment fileOptions(Arena arena, FileOptions options) {
        MemorySegment result = arena.allocate(LibmpqNative.FILE_OPTIONS);
        LibmpqNative.setFileOptions(result, options.flags(), options.compressionFirst(),
                                    options.compressionNext(), (short) options.locale(),
                                    (short) options.platform());
        return result;
    }

    /** Performs one of the archive's signed 64-bit metadata queries. */
    private long archiveLong(boolean unpacked) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.archiveLong(handle, result, unpacked));
            return LibmpqNative.getLong(result);
        }
    }

    /** Performs one of the archive's unsigned 32-bit metadata queries. */
    private long archiveUint(boolean files) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.archiveUint(handle, result, files));
            return Integer.toUnsignedLong(LibmpqNative.getInt(result));
        }
    }

    /** Performs one selected signed 64-bit file metadata query. */
    private long fileLong(int number, boolean unpacked, boolean offset) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.fileLong(handle, number, result, unpacked, offset));
            return LibmpqNative.getLong(result);
        }
    }

    /** Performs one selected unsigned 32-bit file metadata query. */
    private long fileUint(int number, int kind) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileUint(handle, number, result, kind));
            return Integer.toUnsignedLong(LibmpqNative.getInt(result));
        }
    }

    /** Rejects operations after the archive's native handle was closed. */
    private void checkOpen() throws LibmpqException {
        if (handle == null || handle.equals(MemorySegment.NULL)) {
            throw new LibmpqException(Mpq.ERROR_NOT_INITIALIZED, "Archive is closed");
        }
    }

    /** Rejects package-private handle access after close without checked errors. */
    private void checkOpenUnchecked() {
        if (handle == null || handle.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("Archive is closed");
        }
    }
}
