/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Reference;
import java.nio.file.Path;
import java.nio.channels.SeekableByteChannel;
import java.util.List;
import java.util.Objects;
import org.libmpq.ffi.LibmpqNative;

/**
 * A closeable handle for an opened or newly created MPQ archive.  Each
 * instance owns one native archive handle; callers must keep it open while
 * querying or modifying the archive and should use try-with-resources.
 * String name arguments use strict UTF-8. See {@link MpqName} and
 * {@link NativePath} for byte-exact name and filesystem arguments.
 */
public final class Archive implements AutoCloseable {

    /** Checksum coverage; member and archive methods use separate flag domains. */
    public record VerificationResult(int checked, int unavailable, int mismatches) {}

    /** Verify all archive structural and RAW metadata checks. Use verify() for digital signatures. */
    public VerificationResult verifyEx() throws LibmpqException {
        return verifyEx(Mpq.VERIFY_METADATA_ALL);
    }

    /** Verify the requested archive structural and RAW metadata checks. */
    public VerificationResult verifyEx(int flags) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment checked = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment unavailable = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment mismatches = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.archiveVerifyEx(handle, flags, checked, unavailable, mismatches));
            return new VerificationResult(checked.get(ValueLayout.JAVA_INT, 0),
                unavailable.get(ValueLayout.JAVA_INT, 0), mismatches.get(ValueLayout.JAVA_INT, 0));
        }
    }

    public VerificationResult verifyFileResult(int number, int flags) throws LibmpqException {
        return verifyFileResult(number, flags, null);
    }

    /** Optional filename provides key context for the selected number, not selection. */
    public VerificationResult verifyFileResult(int number, int flags, String filename)
            throws LibmpqException {
        return verifyFileResultBytes(number, flags, Support.optionalName(filename));
    }

    /** Byte-exact form of {@link #verifyFileResult(int, int, String)}. */
    public VerificationResult verifyFileResultBytes(int number, int flags, MpqName filename)
            throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = Support.nullableName(arena, filename);
            MemorySegment checked = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment unavailable = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment mismatches = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileVerifyEx(handle, number, name, flags, checked,
                                                    unavailable, mismatches));
            return new VerificationResult(checked.get(ValueLayout.JAVA_INT, 0),
                                          unavailable.get(ValueLayout.JAVA_INT, 0),
                                          mismatches.get(ValueLayout.JAVA_INT, 0));
        }
    }

    /** Return weak and strong signature presence bits; malformed storage throws. */
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
        return verify(Mpq.SIGNATURE_WEAK, publicKey);
    }

    /** Verify the selected weak or strong signature type using a caller public key. */
    public int verify(int signatureType, byte[] publicKey) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(publicKey);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, publicKey);
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.archiveVerify(handle, signatureType,
                                                    key, publicKey.length, result));
            return result.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /** Configure weak signing with a 128-byte key: 64-byte big-endian n then d. */
    public void sign(byte[] privateKey) throws LibmpqException {
        sign(Mpq.SIGNATURE_WEAK, privateKey);
    }

    /** Configure weak or plain strong signing using the selected raw private key. */
    public void sign(int signatureType, byte[] privateKey) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(privateKey);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, privateKey);
            try {
                Support.check(LibmpqNative.archiveSign(handle, signatureType, key, privateKey.length));
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

    /** Return archive-wide stored attribute flags, or empty if absent. Malformed metadata still throws. */
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

    /**
     * Return owned stored member attributes without verifying them. Result
     * flags identify the available fields.
     * @throws LibmpqException if the query fails, including
     * {@link Mpq#ERROR_FORMAT} when the member lacks a valid classic block-table
     * row, even if a BET-only member is readable. A valid classic row without
     * an applicable attributes file yields {@link Mpq#ERROR_EXIST}.
     */
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
    private SourceState sourceState;
    private SinkState sinkState;

    /** Wraps a newly returned native archive handle. */
    private Archive(MemorySegment handle) {
        this.handle = handle;
    }

    private Archive(MemorySegment handle, SourceState sourceState) {
        this.handle = handle;
        this.sourceState = sourceState == null ? null : sourceState.retain();
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
        return openBytes(NativePath.of(path), offset);
    }

    /** Byte-exact form of {@link #open(Path, long)}. */
    public static Archive openBytes(NativePath path, long offset) throws LibmpqException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.archiveOpen(output, path.marshal(arena), offset));
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
        return openMpqeBytes(NativePath.of(path), authCode, offset);
    }

    /** Byte-exact form of {@link #openMpqe(Path, byte[], long)}. */
    public static Archive openMpqeBytes(NativePath path, byte[] authCode, long offset)
        throws LibmpqException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(authCode, "authCode");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment authCodeSegment = Support.bytes(arena, authCode);
            Support.check(LibmpqNative.archiveOpenMpqe(
                output, path.marshal(arena), offset, authCodeSegment, authCode.length
            ));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /** Open a borrowed seekable channel using libmpq's exact random-access input API. */
    public static Archive openSource(SeekableByteChannel source, String sourceName)
        throws LibmpqException {
        return openSource(source, sourceName, -1);
    }

    /**
     * Open a borrowed seekable channel at a standalone or embedded MPQ offset.
     * Each native request is filled exactly using bounded views of its destination.
     * The channel must not retain those views. It remains caller-owned and must
     * stay valid until this archive and its dependent clones and streams close.
     */
    public static Archive openSource(SeekableByteChannel source, String sourceName, long offset)
        throws LibmpqException {
        return openSourceBytes(source, Support.optionalName(sourceName), offset);
    }

    /** Byte-exact form of {@link #openSource(SeekableByteChannel, String, long)}. */
    public static Archive openSourceBytes(SeekableByteChannel source, MpqName sourceName, long offset)
        throws LibmpqException {
        SourceState state = new SourceState(source);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment name = Support.nullableName(arena, sourceName);
            Support.check(LibmpqNative.archiveOpenIo(output, MemorySegment.NULL, state.callback(),
                                                     state.size(), offset, name));
            return new Archive(LibmpqNative.getAddress(output), state);
        } catch (RuntimeException | LibmpqException error) {
            state.discard();
            throw error;
        }
    }

    /** Open a borrowed MPQE seekable channel using the supplied authentication code. */
    public static Archive openMpqeSource(SeekableByteChannel source, byte[] authCode,
                                         String sourceName, long offset) throws LibmpqException {
        return openMpqeSourceBytes(source, authCode, Support.optionalName(sourceName), offset);
    }

    /** Byte-exact form of {@link #openMpqeSource(SeekableByteChannel, byte[], String, long)}. */
    public static Archive openMpqeSourceBytes(SeekableByteChannel source, byte[] authCode,
                                              MpqName sourceName, long offset) throws LibmpqException {
        Objects.requireNonNull(authCode, "authCode");
        SourceState state = new SourceState(source);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment name = Support.nullableName(arena, sourceName);
            Support.check(LibmpqNative.archiveOpenMpqeIo(
                output, MemorySegment.NULL, state.callback(), state.size(), offset,
                Support.bytes(arena, authCode), authCode.length, name
            ));
            return new Archive(LibmpqNative.getAddress(output), state);
        } catch (RuntimeException | LibmpqException error) {
            state.discard();
            throw error;
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
        return createBytes(NativePath.of(path), options);
    }

    /** Byte-exact form of {@link #create(Path, ArchiveCreateOptions)}. */
    public static Archive createBytes(NativePath path, ArchiveCreateOptions options) throws LibmpqException {
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
            Support.check(LibmpqNative.archiveCreate(output, path.marshal(arena),
                                                      nativeOptions));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /**
     * Creates an archive in a borrowed, initially empty seekable channel.
     * The channel must supply zero-filled gaps. V4 and signing require readBack.
     * The caller manages flushing and closing the channel.
     */
    public static Archive createSink(SeekableByteChannel sink, boolean readBack, ArchiveCreateOptions options)
        throws LibmpqException {
        return createSink(sink, readBack, options, null);
    }

    /**
     * Performs the caller's final sink operation during native archive close.
     * The callback runs synchronously after successful output and must not re-enter
     * the writer. An ordinary exception makes close report {@link Mpq#ERROR_CLOSE}.
     * Throw {@link LibmpqCallbackException} to report a specific native error.
     */
    @FunctionalInterface
    public interface FlushCallback {
        /** Flushes or finalizes application-managed sink state. */
        void flush() throws IOException;
    }

    /**
     * Creates an archive in a borrowed, initially empty seekable channel.
     * The channel must supply zero-filled gaps. V4 and signing require readBack.
     * Native close invokes a nonnull flush callback once after the final writes
     * succeed. The caller retains ownership of the channel.
     */
    public static Archive createSink(SeekableByteChannel sink, boolean readBack,
                                     ArchiveCreateOptions options, FlushCallback flush)
        throws LibmpqException {
        return createSinkInternal(sink, readBack, options, null, flush);
    }

    /** Creates an MPQE transport at close. The borrowed channel needs only write access. */
    public static Archive
    createMpqeSink(SeekableByteChannel sink, byte[] authCode, ArchiveCreateOptions options)
        throws LibmpqException
    {
        return createMpqeSink(sink, authCode, options, null);
    }

    /**
     * Creates an MPQE transport at close over a borrowed write-only channel.
     * Native close invokes a nonnull flush callback once after successful transport output.
     * The caller retains ownership of the channel.
     */
    public static Archive createMpqeSink(SeekableByteChannel sink, byte[] authCode,
                                         ArchiveCreateOptions options, FlushCallback flush)
        throws LibmpqException {
        return createSinkInternal(sink, false, options, Objects.requireNonNull(authCode, "authCode"),
                                  flush);
    }

    private static Archive createSinkInternal(
        SeekableByteChannel sink, boolean readBack, ArchiveCreateOptions options, byte[] authCode,
        FlushCallback flush
    ) throws LibmpqException
    {
        if (options == null) {
            options = ArchiveCreateOptions.defaults();
        }
        Archive archive = new Archive(MemorySegment.NULL);
        SinkState state = new SinkState(sink, readBack, flush);
        boolean success = false;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment nativeOptions = arena.allocate(LibmpqNative.ARCHIVE_OPTIONS);
            LibmpqNative.setArchiveOptions(nativeOptions, options.version(),
                                            Support.uint32(options.maxFiles(), "maxFiles"),
                                            Support.uint32(options.sectorSize(), "sectorSize"),
                                            options.flags(), options.attributes());
            if (authCode == null) {
                Support.check(LibmpqNative.archiveCreateIo(
                    output, MemorySegment.NULL, state.read, state.write, state.flush,
                    nativeOptions
                ));
            } else {
                Support.check(LibmpqNative.archiveCreateMpqeIo(
                    output, MemorySegment.NULL, MemorySegment.NULL, state.write, state.flush,
                    Support.bytes(arena, authCode), authCode.length, nativeOptions
                ));
            }
            archive.handle = LibmpqNative.getAddress(output);
            archive.sinkState = state;
            success = true;
            return archive;
        } finally {
            if (!success) {
                state.release();
            }
        }
    }

    /** Creates a new MPQE-wrapped archive using caller-supplied authentication bytes. */
    public static Archive createMpqe(Path path, byte[] authCode,
                                     ArchiveCreateOptions options) throws LibmpqException {
        return createMpqeBytes(NativePath.of(path), authCode, options);
    }

    /** Byte-exact form of {@link #createMpqe(Path, byte[], ArchiveCreateOptions)}. */
    public static Archive createMpqeBytes(NativePath path, byte[] authCode,
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
                output, path.marshal(arena), Support.bytes(arena, authCode),
                authCode.length, nativeOptions
            ));
            return new Archive(LibmpqNative.getAddress(output));
        }
    }

    /**
     * Materialize borrowed ordered layers as an independently owned read-only archive.
     * Pass one prefix per layer when supplying prefixes. A null list or entry
     * requests inference and an empty string selects root. Keep the inputs alive
     * during the call. The returned archive retains none of their source state.
     */
    public static Archive openPatch(Archive base, List<Archive> patches, List<String> prefixes)
            throws LibmpqException {
        return openPatchBytes(base, patches, Support.names(prefixes));
    }

    /** Byte-exact form of {@link #openPatch(Archive, List<Archive>, List<String>)}. */
    public static Archive openPatchBytes(Archive base, List<Archive> patches, List<MpqName> prefixes)
            throws LibmpqException {
        Objects.requireNonNull(base, "base");
        PatchInputs inputs = base.patchInputs(patches, prefixes);
        try (Arena arena = Arena.ofConfined()) {
            PatchPointers pointers = inputs.marshal(arena);
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.archiveOpenPatch(output, base.handle, pointers.handles(),
                                                       pointers.prefixes(), inputs.layers().length));
            MemorySegment result = LibmpqNative.getAddress(output);
            try {
                return new Archive(result);
            } catch (RuntimeException | Error failure) {
                LibmpqNative.archiveClose(result);
                throw failure;
            }
        } finally {
            Reference.reachabilityFence(base);
            Reference.reachabilityFence(inputs);
        }
    }

    private PatchInputs patchInputs(List<Archive> patches, List<MpqName> prefixes)
            throws LibmpqException {
        Archive[] layers = Objects.requireNonNull(patches, "patches").toArray(Archive[]::new);
        MpqName[] names = prefixes == null ? null : prefixes.toArray(MpqName[]::new);
        if (names != null && names.length != layers.length) {
            throw new IllegalArgumentException("prefix count must match patch count");
        }
        checkOpen();
        for (Archive layer : layers) {
            Objects.requireNonNull(layer, "patch layer").checkOpen();
        }
        return new PatchInputs(layers, names);
    }

    private record PatchPointers(MemorySegment handles, MemorySegment prefixes) {}

    private record PatchInputs(Archive[] layers, MpqName[] names) {
        PatchPointers marshal(Arena arena) {
            MemorySegment handles = layers.length == 0 ? MemorySegment.NULL
                : arena.allocate(ValueLayout.ADDRESS, layers.length);
            MemorySegment nativeNames = names == null || names.length == 0 ? MemorySegment.NULL
                : arena.allocate(ValueLayout.ADDRESS, names.length);
            for (int i = 0; i < layers.length; i++) {
                handles.setAtIndex(ValueLayout.ADDRESS, i, layers[i].handle);
                if (names != null) {
                    nativeNames.setAtIndex(ValueLayout.ADDRESS, i,
                        Support.nullableName(arena, names[i]));
                }
            }
            return new PatchPointers(handles, nativeNames);
        }
    }

    /**
     * Open a stream using ordinary lookup in the final patched view.
     * Prefixes follow {@link #openPatch(Archive, List, List)}. Opening
     * synchronously reconstructs and verifies the member in private scratch
     * storage. After success the inputs can close. Stream close releases
     * the private storage.
     */
    public MpqStream openPatchStream(String filename, List<Archive> patches, List<String> prefixes)
            throws LibmpqException {
        return openPatchStreamBytes(MpqName.ofUtf8(filename), patches, Support.names(prefixes));
    }

    /** Byte-exact form of {@link #openPatchStream(String, List<Archive>, List<String>)}. */
    public MpqStream openPatchStreamBytes(MpqName filename, List<Archive> patches, List<MpqName> prefixes)
            throws LibmpqException {
        return openPatchStream(filename, patches, prefixes, false, (short) 0, (short) 0);
    }

    /**
     * Open the exact patched filename and tuple, including neutral (0, 0).
     * No fallback is applied. The detached stream owns its scratch storage.
     * Prefixes follow {@link #openPatch(Archive, List, List)}.
     */
    public MpqStream openPatchStream(String filename, int locale, int platform,
                                     List<Archive> patches, List<String> prefixes)
            throws LibmpqException {
        return openPatchStreamBytes(MpqName.ofUtf8(filename), locale, platform, patches,
                                    Support.names(prefixes));
    }

    /** Byte-exact form of {@link #openPatchStream(String, int, int, List<Archive>, List<String>)}. */
    public MpqStream openPatchStreamBytes(MpqName filename, int locale, int platform,
                                          List<Archive> patches, List<MpqName> prefixes)
            throws LibmpqException {
        return openPatchStream(filename, patches, prefixes, true, identitySelector(locale),
                               identitySelector(platform));
    }

    private MpqStream openPatchStream(MpqName filename, List<Archive> patches,
                                      List<MpqName> prefixes, boolean exact, short locale, short platform)
            throws LibmpqException {
        Objects.requireNonNull(filename, "filename");
        if (filename.isEmpty()) {
            throw new IllegalArgumentException("filename must be nonempty");
        }
        PatchInputs inputs = patchInputs(patches, prefixes);
        try (Arena arena = Arena.ofConfined()) {
            PatchPointers pointers = inputs.marshal(arena);
            MemorySegment out = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment name = filename.marshal(arena);
            long count = inputs.layers().length;
            Support.check(exact
                ? LibmpqNative.streamOpenPatchIdentity(handle, pointers.handles(), pointers.prefixes(),
                                                      count, name, locale, platform, out)
                : LibmpqNative.streamOpenPatch(handle, pointers.handles(), pointers.prefixes(),
                                              count, name, out));
            MemorySegment stream = LibmpqNative.getAddress(out);
            try {
                return new MpqStream(stream);
            } catch (RuntimeException | Error failure) {
                LibmpqNative.streamClose(stream);
                throw failure;
            }
        } finally {
            Reference.reachabilityFence(this);
            Reference.reachabilityFence(inputs);
        }
    }

    /** Materialize layers using inferred prefixes. */
    public static Archive openPatch(Archive base, List<Archive> patches) throws LibmpqException {
        return openPatch(base, patches, null);
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
            return new Archive(LibmpqNative.getAddress(output), sourceState);
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

    /** Returns the archive origin in its backing source, which can be nonzero for embedded MPQs. */
    public long offset() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.archiveOffset(handle, result));
            return LibmpqNative.getLong(result);
        }
    }

    /** Set the v4 raw policy before member begin, signing or finalization. */
    public void setRawChunkSize(long size) throws LibmpqException {
        checkOpen();
        Support.check(LibmpqNative.archiveSetRawChunkSize(handle, Support.uint32(size, "rawChunkSize")));
    }

    /** Return configured/loaded raw size, or zero for older generations. */
    public long getRawChunkSize() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.archiveGetRawChunkSize(handle, output));
            return Integer.toUnsignedLong(output.get(ValueLayout.JAVA_INT, 0));
        }
    }

    /**
     * Returns the MPQ generation (1 through 4). Creation uses selectors
     * 0 through 3 in {@link ArchiveCreateOptions}.
     */
    public long version() throws LibmpqException {
        return archiveUint(false);
    }

    /** Returns the count of live canonical entries, including stored internal members where present. */
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

    /** Enumerate stored identities in native slot order; provenance is not a storage flag. */
    public List<FileIdentity> variants(String name) throws LibmpqException {
        return variantsBytes(MpqName.ofUtf8(name));
    }

    /** Byte-exact form of {@link #variants(String)}. */
    public List<FileIdentity> variantsBytes(MpqName name) throws LibmpqException {
        checkOpen();
        var result = new java.util.ArrayList<FileIdentity>();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment encoded = name.marshal(arena);
            MemorySegment output = arena.allocate(LibmpqNative.FILE_IDENTITY);
            for (long ordinal = 0; ordinal <= 0xffffffffL; ordinal++) {
                int status = LibmpqNative.fileIdentity(handle, encoded, (int) ordinal, output);
                if (status == Mpq.ERROR_EXIST) return List.copyOf(result);
                Support.check(status);
                result.add(new FileIdentity(output.get(ValueLayout.JAVA_INT, 0),
                    output.get(ValueLayout.JAVA_INT, 4), Short.toUnsignedInt(output.get(ValueLayout.JAVA_SHORT, 8)),
                    Short.toUnsignedInt(output.get(ValueLayout.JAVA_SHORT, 10))));
            }
        }
        throw new IllegalStateException("too many identities");
    }

    /**
     * Select the exact locale/platform tuple using classic and supported
     * HET/BET identities. A HET/BET-only identity accepts only {@code (0, 0)}.
     * No selector fallback is applied.
     */
    public int fileNumber(String name, int locale, int platform) throws LibmpqException {
        return fileNumberBytes(MpqName.ofUtf8(name), locale, platform);
    }

    /** Byte-exact form of {@link #fileNumber(String, int, int)}. */
    public int fileNumberBytes(MpqName name, int locale, int platform) throws LibmpqException {
        checkOpen();
        short l = identitySelector(locale), p = identitySelector(platform);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileNumberFromIdentity(handle, name.marshal(arena), l, p, output));
            return output.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /** Open the exact tuple on an owned clone sharing any caller-owned source. */
    public MpqStream openStream(String name, int locale, int platform) throws LibmpqException {
        return openStreamBytes(MpqName.ofUtf8(name), locale, platform);
    }

    /** Byte-exact form of {@link #openStream(String, int, int)}. */
    public MpqStream openStreamBytes(MpqName name, int locale, int platform) throws LibmpqException {
        checkOpen();
        short l = identitySelector(locale), p = identitySelector(platform);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.streamOpenNameIdentity(handle, name.marshal(arena), l, p, output));
            return new MpqStream(LibmpqNative.getAddress(output), sourceState);
        }
    }

    private static short identitySelector(int value) {
        if (value < 0 || value > 65535) throw new IllegalArgumentException("identity selector must fit uint16");
        return (short) value;
    }

    /**
     * Resolves an MPQ filename through HET/BET when present, falling back to
     * classic lookup on a miss.
     *
     * @param filename archive filename, including any path components
     * @return zero-based public file number
     * @throws LibmpqException if lookup fails, including an absent name,
     * malformed metadata, or a closed archive
     */
    public int fileNumber(String filename) throws LibmpqException {
        return fileNumberBytes(MpqName.ofUtf8(filename));
    }

    /** Byte-exact form of {@link #fileNumber(String)}. */
    public int fileNumberBytes(MpqName filename) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.fileNumber(handle, filename.marshal(arena), result));
            return LibmpqNative.getInt(result);
        }
    }

    /**
     * Resolves precomputed Storm hashes using only the classic hash table.
     * HET/BET requires the filename to compute a separate hash. Use
     * {@link #fileNumber(String)} for filename-aware lookup.
     *
     * @param hash three values previously returned by {@link Mpq#fileHash}
     * @return zero-based public file number
     * @throws LibmpqException if lookup fails, including a missing classic
     * table, an unmatched hash, or a closed archive
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

    /** Returns one entry's stored payload offset relative to the start of the MPQ. */
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

    /**
     * Reads and verifies a whole member into caller-owned writable native memory.
     * The destination must hold the expected logical size. Keep it accessible
     * and unchanged by other threads until this synchronous call returns.
     * A native error can leave bytes in the destination.
     *
     * @return the actual number of decoded bytes
     */
    public long readFile(int number, MemorySegment destination) throws LibmpqException {
        checkOpen();
        Support.checkNativeBuffer(destination, true);
        long capacity = destination.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            // A zero-length SINGLE block can still use the caller's output address.
            MemorySegment output = capacity == 0 ? arena.allocate(1) : destination;
            Support.check(LibmpqNative.fileRead(handle, number, output, capacity, transferred));
            return Support.transferred(transferred, capacity);
        }
    }

    /** Return decoded PTCH size, distinct from the final patched target size. */
    public long patchPayloadSize(int number) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment size = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.patchPayloadSize(handle, number, size));
            return size.get(ValueLayout.JAVA_LONG, 0);
        }
    }

    /** Read validated PTCH bytes without applying the patch or including its prefix.
     * filename may be null when encryption does not need a name-derived key.
     * The returned array is caller-owned; native errors throw LibmpqException.
     */
    public byte[] readPatchPayload(int number, String filename) throws LibmpqException {
        return readPatchPayloadBytes(number, Support.optionalName(filename));
    }

    /** Byte-exact form of {@link #readPatchPayload(int, String)}. */
    public byte[] readPatchPayloadBytes(int number, MpqName filename) throws LibmpqException {
        long size = patchPayloadSize(number);
        int capacity = Support.checkedArraySize(size);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(capacity == 0 ? 1 : capacity, 1);
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.patchPayloadRead(handle, number,
                    Support.nullableName(arena, filename),
                    capacity == 0 ? MemorySegment.NULL : output, size, transferred));
            long count = transferred.get(ValueLayout.JAVA_LONG, 0);
            if (count < 0 || count > size) {
                throw new IllegalArgumentException("Invalid native PTCH byte count");
            }
            byte[] result = new byte[Support.checkedArraySize(count)];
            Support.copyTo(output, result);
            return result;
        }
    }

    /**
     * Reads validated decoded PTCH bytes into writable native memory and
     * returns the transferred length. The optional filename supplies key
     * context. Use {@link #patchPayloadSize(int)} for the destination size.
     */
    public long readPatchPayload(int number, String filename, MemorySegment destination)
            throws LibmpqException {
        return readPatchPayloadBytes(number, Support.optionalName(filename), destination);
    }

    /**
     * Byte-exact form of {@link #readPatchPayload(int, String, MemorySegment)}.
     * The destination is borrowed for the synchronous call.
     */
    public long readPatchPayloadBytes(int number, MpqName filename, MemorySegment destination)
            throws LibmpqException {
        checkOpen();
        Support.checkNativeBuffer(destination, true);
        long capacity = destination.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.patchPayloadRead(handle, number,
                    Support.nullableName(arena, filename), destination, capacity, transferred));
            return Support.transferred(transferred, capacity);
        }
    }

    /** Read a payload that does not require an explicit encryption filename. */
    public byte[] readPatchPayload(int number) throws LibmpqException {
        return readPatchPayload(number, null);
    }

    /** Open by file number on an owned clone sharing any caller-owned source. */
    public MpqStream openStream(int number) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.streamOpen(handle, number, output));
            return new MpqStream(LibmpqNative.getAddress(output), sourceState);
        }
    }

    /** Open by ordinary filename lookup with the source lifetime of {@link #openStream(int)}. */
    public MpqStream openStream(String name) throws LibmpqException {
        return openStreamBytes(MpqName.ofUtf8(name));
    }

    /** Byte-exact form of {@link #openStream(String)}. */
    public MpqStream openStreamBytes(MpqName name) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.streamOpenName(handle, name.marshal(arena), output));
            return new MpqStream(LibmpqNative.getAddress(output), sourceState);
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

    /** Compatibility alias for {@link #blockSizeUnpacked(int, int)}. */
    public long blockSize(int number, int block) throws LibmpqException {
        return blockSizeUnpacked(number, block);
    }

    /** Returns the expected logical size of one block from metadata. */
    public long blockSizeUnpacked(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.blockSize(handle, number, block, result));
            return LibmpqNative.getLong(result);
        }
    }

    /**
     * Returns the bytes actually decoded for one block. The array can be
     * shorter than the expected logical size from {@link #blockSizeUnpacked(int, int)}.
     * Use {@link #blockSizePacked(int, int)} for the stored size.
     */
    public byte[] readBlock(int number, int block) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            long size = blockSizeUnpacked(number, block);
            byte[] result = new byte[Support.checkedArraySize(size)];
            MemorySegment output = arena.allocate(result.length == 0 ? 1 : result.length, 1);
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.blockRead(handle, number, block,
                                                 result.length == 0 ? MemorySegment.NULL : output,
                                                 size, transferred));
            long count = LibmpqNative.getLong(transferred);
            if (count < 0 || count > result.length) {
                throw new IllegalArgumentException("Invalid native block byte count");
            }
            if (count != result.length) {
                result = new byte[(int) count];
            }
            Support.copyTo(output, result);
            return result;
        }
    }

    /**
     * Decodes one block into caller-owned writable native memory. Capacity must
     * cover the expected unpacked size, and native block and decoder limits apply.
     * The segment must stay alive and free from concurrent access until return.
     * This operation uses block decoding without implicit checksum verification.
     *
     * @param number public file number
     * @param block block index within the member
     * @param destination destination segment, including a zero-length segment for an empty block
     * @return actual decoded byte count, which can be smaller than the expected size
     * @throws LibmpqException if native block reading fails
     */
    public long readBlock(int number, int block, MemorySegment destination) throws LibmpqException {
        checkOpen();
        Support.checkNativeBuffer(destination, true);
        long capacity = destination.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            // The empty SINGLE decoder can still use a non-null output address.
            MemorySegment output = destination.address() == 0 ? arena.allocate(1) : destination;
            Support.check(LibmpqNative.blockRead(handle, number, block, output, capacity, transferred));
            return Support.transferred(transferred, capacity);
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
        addBytes(MpqName.ofUtf8(name), data, options);
    }

    /** Byte-exact form of {@link #add(String, byte[], FileOptions)}. */
    public void addBytes(MpqName name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        if (options == null) {
            options = FileOptions.raw();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeOptions = fileOptions(arena, options);
            Support.check(LibmpqNative.archiveAddData(handle, name.marshal(arena),
                                                Support.bytes(arena, data), data.length, nativeOptions));
        }
    }

    /**
     * Adds a complete member from a Java array, with the same behavior as
     * {@link #add(String, byte[], FileOptions)}.
     *
     * @param name archive filename
     * @param data logical file bytes
     * @param options storage options, or {@code null} for raw storage
     * @throws LibmpqException if native writing fails
     */
    public void addData(String name, byte[] data, FileOptions options) throws LibmpqException {
        add(name, data, options);
    }

    /**
     * Adds a complete member from an array with a byte-exact filename.
     *
     * @param name byte-exact archive filename
     * @param data logical file bytes
     * @param options storage options, or {@code null} for raw storage
     * @throws LibmpqException if native writing fails
     */
    public void addDataBytes(MpqName name, byte[] data, FileOptions options) throws LibmpqException {
        addBytes(name, data, options);
    }

    /**
     * Adds a complete member in one native call from caller-owned native memory.
     * Empty and read-only input segments are supported. Keep the segment alive
     * and unchanged until return. Native member and archive size limits apply.
     *
     * @param name archive filename
     * @param data native segment containing the logical file bytes
     * @param options storage options, or {@code null} for raw storage
     * @throws LibmpqException if native writing fails
     */
    public void addDataSegment(String name, MemorySegment data, FileOptions options) throws LibmpqException {
        addDataSegmentBytes(MpqName.ofUtf8(name), data, options);
    }

    /**
     * Byte-exact form of {@link #addDataSegment(String, MemorySegment, FileOptions)}.
     *
     * @param name byte-exact archive filename
     * @param data native segment containing the logical file bytes
     * @param options storage options, or {@code null} for raw storage
     * @throws LibmpqException if native writing fails
     */
    public void addDataSegmentBytes(MpqName name, MemorySegment data, FileOptions options)
            throws LibmpqException {
        checkOpen();
        Support.checkNativeBuffer(data, false);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeOptions = fileOptions(arena, options == null ? FileOptions.raw() : options);
            Support.check(LibmpqNative.archiveAddData(handle, name.marshal(arena),
                    data, data.byteSize(), nativeOptions));
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
        addPathBytes(MpqName.ofUtf8(name), NativePath.of(source), options);
    }

    /** Byte-exact form of {@link #addPath(String, Path, FileOptions)}. */
    public void addPathBytes(MpqName name, NativePath source, FileOptions options) throws LibmpqException {
        checkOpen();
        if (options == null) {
            options = FileOptions.raw();
        }
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.archiveAddPath(handle, name.marshal(arena),
                                                   source.marshal(arena),
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
        return beginBytes(MpqName.ofUtf8(name), size, options);
    }

    /** Byte-exact form of {@link #begin(String, long, FileOptions)}. */
    public MpqFileWriter beginBytes(MpqName name, long size, FileOptions options) throws LibmpqException {
        checkOpen();
        if (size < 0) {
            throw new IllegalArgumentException("size must not be negative");
        }
        if (options == null) {
            options = FileOptions.raw();
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.writerBegin(handle, name.marshal(arena), size,
                                                  fileOptions(arena, options), output));
            return new MpqFileWriter(this, LibmpqNative.getAddress(output), size);
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
        try {
            Support.check(LibmpqNative.archiveClose(current));
        } finally {
            if (sinkState != null) {
                sinkState.release();
                sinkState = null;
            }
            if (sourceState != null) {
                sourceState.release();
                sourceState = null;
            }
        }
    }

    boolean isOpenForWriter() {
        return handle != null && !handle.equals(MemorySegment.NULL);
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
