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
import java.util.Objects;
import org.libmpq.ffi.LibmpqNative;

/** Incremental, seekable decoded MPQ member stream. */
public final class MpqStream implements AutoCloseable {
    private MemorySegment handle;

    MpqStream(MemorySegment handle) {
        this.handle = Objects.requireNonNull(handle);
    }

    /** Read up to {@code length} bytes, returning -1 at EOF. */
    public int read(byte[] buffer, int offset, int length) throws LibmpqException {
        requireOpen();
        Objects.checkFromIndexSize(offset, length, buffer.length);
        if (length == 0) {
            return 0;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeBuffer = arena.allocate(length, 1);
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.streamRead(handle, nativeBuffer, length, transferred));
            int count = Math.toIntExact(LibmpqNative.getLong(transferred));
            if (count == 0) {
                return -1;
            }
            nativeBuffer.asByteBuffer().get(buffer, offset, count);
            return count;
        }
    }

    /** Read up to {@code buffer.length} bytes, returning -1 at EOF. */
    public int read(byte[] buffer) throws LibmpqException {
        return read(buffer, 0, buffer.length);
    }

    /** Move to a valid logical position using Mpq.SEEK_SET, SEEK_CUR, or SEEK_END. */
    public void seek(long offset, int origin) throws LibmpqException {
        requireOpen();
        Support.check(LibmpqNative.streamSeek(handle, offset, origin));
    }

    /** Return the current logical position. */
    public long position() throws LibmpqException {
        requireOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.streamTell(handle, result));
            return LibmpqNative.getLong(result);
        }
    }

    /** Return the immutable logical member size. */
    public long size() throws LibmpqException {
        requireOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ValueLayout.JAVA_LONG);
            Support.check(LibmpqNative.streamSize(handle, result));
            return LibmpqNative.getLong(result);
        }
    }

    /** Consume the native stream; repeated Java closes are harmless. */
    @Override
    public void close() throws LibmpqException {
        if (!handle.equals(MemorySegment.NULL)) {
            MemorySegment current = handle;
            handle = MemorySegment.NULL;
            Support.check(LibmpqNative.streamClose(current));
        }
    }

    private void requireOpen() {
        if (handle.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("stream is closed");
        }
    }
}
