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

/** A staged patch artifact; closing without finish aborts it. */
public final class MpqPatch implements AutoCloseable {
    private MemorySegment handle;

    private MpqPatch(MemorySegment handle) {
        this.handle = handle;
    }

    /** Begin a patch without modifying its base archive. */
    public static MpqPatch begin(Path baseArchive, Path outputPatch) throws LibmpqException {
        Objects.requireNonNull(baseArchive, "baseArchive");
        Objects.requireNonNull(outputPatch, "outputPatch");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.patchBegin(output,
                    Support.text(arena, baseArchive.toString()),
                    Support.text(arena, outputPatch.toString())));
            return new MpqPatch(LibmpqNative.getAddress(output));
        }
    }

    /** Begin an MPQE-wrapped patch using caller-supplied authentication bytes. */
    public static MpqPatch beginMpqe(Path baseArchive, Path outputPatch, byte[] authCode)
            throws LibmpqException {
        Objects.requireNonNull(baseArchive, "baseArchive");
        Objects.requireNonNull(outputPatch, "outputPatch");
        Objects.requireNonNull(authCode, "authCode");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.patchBeginMpqe(output,
                    Support.text(arena, baseArchive.toString()),
                    Support.text(arena, outputPatch.toString()),
                    Support.bytes(arena, authCode), authCode.length));
            return new MpqPatch(LibmpqNative.getAddress(output));
        }
    }

    /** Stage bytes using ordinary writer defaults. */
    public void addData(String name, byte[] data) throws LibmpqException {
        addData(name, data, null);
    }

    /** Stage bytes with explicit ordinary-member storage options. */
    public void addData(String name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        if (name.indexOf('\0') >= 0) throw new IllegalArgumentException("NUL in name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.patchAddData(handle, Support.text(arena, name),
                    Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /** Stage a filesystem source using ordinary writer defaults. */
    public void addPath(String name, Path source) throws LibmpqException {
        addPath(name, source, null);
    }

    /** Stage a filesystem source with explicit ordinary-member storage options. */
    public void addPath(String name, Path source, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        if (name.indexOf('\0') >= 0) throw new IllegalArgumentException("NUL in name");
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.patchAddPath(handle, Support.text(arena, name),
                    Support.text(arena, source.toString()), options(arena, options)));
        }
    }

    /** Stage bytes using native patch storage defaults. */
    public void replaceData(String name, byte[] data) throws LibmpqException {
        replaceData(name, data, null);
    }

    /** Stage bytes with explicit patch-member storage options. */
    public void replaceData(String name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.patchReplaceData(handle, Support.text(arena, name),
                    Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /** Stage a filesystem source using native patch storage defaults. */
    public void replacePath(String name, Path source) throws LibmpqException {
        replacePath(name, source, null);
    }

    /** Stage a filesystem source with explicit patch-member storage options. */
    public void replacePath(String name, Path source, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.patchReplacePath(handle, Support.text(arena, name),
                    Support.text(arena, source.toString()), options(arena, options)));
        }
    }

    /** Stage a delete marker for an existing named member. */
    public void remove(String name) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.patchRemove(handle, Support.text(arena, name)));
        }
    }

    /** Read the configured raw size, including after member writing begins. */
    public long getRawChunkSize() throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.JAVA_INT);
            Support.check(LibmpqNative.patchGetRawChunkSize(handle, output));
            return Integer.toUnsignedLong(output.get(ValueLayout.JAVA_INT, 0));
        }
    }

    /** Set the v4 raw policy before member begin or successful signing. */
    public void setRawChunkSize(long size) throws LibmpqException {
        checkOpen();
        Support.check(LibmpqNative.patchSetRawChunkSize(handle, Support.uint32(size, "rawChunkSize")));
    }

    /** Configure weak signing with the existing raw private-key convention. */
    public void sign(byte[] privateKey) throws LibmpqException {
        sign(Mpq.SIGNATURE_WEAK, privateKey);
    }

    /** Configure weak or strong signing without consuming the patch. */
    public void sign(int signatureType, byte[] privateKey) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(privateKey, "privateKey");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, privateKey);
            try {
                Support.check(LibmpqNative.patchSign(handle, signatureType, key, privateKey.length));
            } finally {
                key.fill((byte) 0);
            }
        }
    }

    /** Publish the patch; the handle is consumed even on native error. */
    public void finish() throws LibmpqException {
        MemorySegment current = take();
        Support.check(LibmpqNative.patchFinish(current));
    }

    /** Discard the patch; the handle is consumed even on native error. */
    public void abort() throws LibmpqException {
        MemorySegment current = take();
        Support.check(LibmpqNative.patchAbort(current));
    }

    /** Abort if still active; repeated closes are harmless. */
    @Override
    public void close() throws LibmpqException {
        if (handle != null && !handle.equals(MemorySegment.NULL)) {
            abort();
        }
    }

    private MemorySegment options(Arena arena, FileOptions value) {
        if (value == null) return MemorySegment.NULL;
        MemorySegment result = arena.allocate(LibmpqNative.FILE_OPTIONS);
        LibmpqNative.setFileOptions(result, value.flags(), value.compressionFirst(),
                value.compressionNext(), (short) value.locale(), (short) value.platform());
        return result;
    }

    private MemorySegment take() {
        checkOpen();
        MemorySegment current = handle;
        handle = MemorySegment.NULL;
        return current;
    }

    private void checkOpen() {
        if (handle == null || handle.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("Patch is closed");
        }
    }
}
