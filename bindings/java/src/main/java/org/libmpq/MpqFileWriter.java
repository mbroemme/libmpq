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
 * Closeable streaming writer for one MPQ file entry.  The writer owns a
 * native stream returned by {@link Archive#begin}; bytes are accepted until
 * the declared logical size is reached, after which {@link #finish} publishes
 * the entry and invalidates this object.
 */
public final class MpqFileWriter implements AutoCloseable {

    /** Set Windows FILETIME bits, not Unix time, without importing filesystem metadata. */
    public void timestamp(long filetime) throws LibmpqException {
        if (!archive.isOpenForWriter() || handle == null || handle.equals(MemorySegment.NULL))
            throw new IllegalStateException("Writer is finished");
        Support.check(LibmpqNative.writerTimestamp(handle, filetime));
    }
    private final Archive archive;
    private MemorySegment handle;
    private final long expected;
    private long written;

    /** Wraps the native writer handle and records its declared size. */
    MpqFileWriter(Archive archive, MemorySegment handle, long expected) {
        this.archive = archive;
        this.handle = handle;
        this.expected = expected;
    }

    /**
     * Appends one byte array to the native stream.  The call fails before
     * crossing the native boundary if it would exceed the declared file size.
     *
     * @param data bytes to append; an empty array is permitted
     * @throws LibmpqException if native writing fails
     * @throws IllegalArgumentException if the write exceeds the declaration
     * @throws IllegalStateException if the writer has already been finished
     */
    public void write(byte[] data) throws LibmpqException {
        requireActive();
        checkWriteSize(data.length);
        try (Arena arena = Arena.ofConfined()) {
            writeNative(Support.bytes(arena, data), data.length);
        }
    }

    /**
     * Appends bytes from caller-owned native memory in one native call.
     * Keep the segment alive and unchanged until return. Empty and read-only
     * inputs are supported. Native output errors can occur after some bytes have
     * been accepted and can latch on the parent archive.
     *
     * @param data native segment containing the bytes to append
     * @throws LibmpqException if native writing fails
     * @throws IllegalArgumentException if the segment is invalid or exceeds the declared size
     * @throws IllegalStateException if the writer or its parent has closed
     */
    public void writeSegment(MemorySegment data) throws LibmpqException {
        requireActive();
        Support.checkNativeBuffer(data, false);
        long length = data.byteSize();
        checkWriteSize(length);
        writeNative(data, length);
    }

    private void requireActive() {
        if (!archive.isOpenForWriter() || handle == null || handle.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("Writer is finished");
        }
    }

    private void checkWriteSize(long length) {
        if (length > expected - written) {
            throw new IllegalArgumentException("write exceeds declared file size");
        }
    }

    private void writeNative(MemorySegment data, long length) throws LibmpqException {
        Support.check(LibmpqNative.writerWrite(handle, data, length));
        written += length;
    }

    /**
     * Finishes the native stream and publishes the archive entry.  libmpq
     * invalidates the writer even when finalization reports an error, so this
     * Java object cannot be reused after the call.
     *
     * @throws LibmpqException if the stream is incomplete or finalization
     * fails
     */
    public void finish() throws LibmpqException {
        MemorySegment current = handle;
        if (!archive.isOpenForWriter() || current == null || current.equals(MemorySegment.NULL)) {
            return;
        }
        handle = MemorySegment.NULL;
        Support.check(LibmpqNative.writerFinish(current));
    }

    /**
     * Finishes the native writer as required by {@link AutoCloseable}.  An
     * incomplete stream therefore reports an explicit native error instead of
     * silently discarding data.
     */
    @Override
    public void close() throws LibmpqException {
        finish();
    }

    /** Returns the exact logical size supplied to {@link Archive#begin}. */
    public long expectedSize() {
        return expected;
    }

    /** Returns the number of bytes successfully accepted so far. */
    public long writtenSize() {
        return written;
    }
}
