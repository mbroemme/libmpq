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
    private SourceState sourceState;

    MpqStream(MemorySegment handle) {
        this.handle = Objects.requireNonNull(handle);
    }

    MpqStream(MemorySegment handle, SourceState sourceState) {
        this.handle = Objects.requireNonNull(handle);
        this.sourceState = sourceState == null ? null : sourceState.retain();
    }

    /**
     * Reads up to {@code length} bytes, returning -1 at EOF or 0 for a zero-length request.
     * If native reading fails, the valid prefix has already been copied into
     * {@code buffer} starting at {@code offset}. The exception's
     * {@link LibmpqException#transferred()} reports the prefix length, and
     * {@link #position()} includes it.
     */
    public int read(byte[] buffer, int offset, int length) throws LibmpqException {
        requireOpen();
        Objects.checkFromIndexSize(offset, length, buffer.length);
        if (length == 0) {
            return 0;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeBuffer = arena.allocate(length, 1);
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            int status = LibmpqNative.streamRead(handle, nativeBuffer, length, transferred);
            int count = Math.toIntExact(LibmpqNative.getLong(transferred));
            if (count != 0) {
                nativeBuffer.asSlice(0, count).asByteBuffer().get(buffer, offset, count);
            }
            if (status < 0) {
                throw new LibmpqException(status, Mpq.strerror(status), count);
            }
            return count == 0 ? -1 : count;
        }
    }

    /** Read into the whole array, with the same EOF and partial error behavior as the slice overload. */
    public int read(byte[] buffer) throws LibmpqException {
        return read(buffer, 0, buffer.length);
    }

    /**
     * Reads into caller-owned writable native memory in one native call.
     * Keep the segment alive and free from concurrent access until return.
     * If reading fails, the valid prefix is already in the destination.
     * {@link LibmpqException#transferredLong()} gives its full length, and
     * {@link #position()} includes those bytes.
     *
     * @param destination writable native segment whose size is the requested capacity
     * @return bytes transferred, or zero for EOF or an empty destination
     * @throws LibmpqException if native reading fails
     */
    public long readSegment(MemorySegment destination) throws LibmpqException {
        requireOpen();
        Support.checkNativeBuffer(destination, true);
        long capacity = destination.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment transferred = arena.allocate(ValueLayout.JAVA_LONG);
            int status = LibmpqNative.streamRead(handle, destination, capacity, transferred);
            long count = Support.transferred(transferred, capacity);
            if (status < 0) {
                throw new LibmpqException(status, Mpq.strerror(status), count);
            }
            return count;
        }
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
            try {
                Support.check(LibmpqNative.streamClose(current));
            } finally {
                if (sourceState != null) {
                    sourceState.release();
                    sourceState = null;
                }
            }
        }
    }

    private void requireOpen() {
        if (handle.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("stream is closed");
        }
    }
}
