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
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Objects;
import org.libmpq.ffi.LibmpqNative;

/** Shared borrowed channel state and FFM callback lifetime for custom sources. */
final class SourceState {
    private final SeekableByteChannel source;
    private final long size;
    private final Arena arena;
    private final MemorySegment callback;
    private int references;

    SourceState(SeekableByteChannel source) {
        Arena created = Arena.ofShared();
        arena = created;
        try {
            this.source = Objects.requireNonNull(source, "source");
            size = source.size();
            if (size < 0) {
                throw new IllegalArgumentException("source size is negative");
            }
            MethodHandle target = MethodHandles.lookup().findVirtual(
                SourceState.class, "readAt",
                MethodType.methodType(int.class, MemorySegment.class, long.class,
                                      MemorySegment.class, long.class)
            ).bindTo(this);
            callback = LibmpqNative.readAtUpcall(target, created);
        } catch (ReflectiveOperationException error) {
            created.close();
            throw new IllegalStateException("Unable to create libmpq read callback", error);
        } catch (java.io.IOException error) {
            created.close();
            throw new IllegalArgumentException("Unable to determine source size", error);
        } catch (RuntimeException | Error error) {
            created.close();
            throw error;
        }
    }

    synchronized SourceState retain() {
        references++;
        return this;
    }

    synchronized void release() {
        if (--references == 0) {
            arena.close();
        }
    }

    /** Discard a state whose native archive open never retained it. */
    void discard() { arena.close(); }

    long size() { return size; }
    MemorySegment callback() { return callback; }

    /** Exact native callback. Java I/O failures are reduced to ERROR_READ. */
    private synchronized int readAt(MemorySegment context, long offset,
                                    MemorySegment output, long count) {
        if (offset < 0 || count < 0 || offset > size || count > size - offset) {
            return Mpq.ERROR_READ;
        }
        try {
            long position = source.position();
            try {
                source.position(offset);
                ByteBuffer target = output.reinterpret(count).asByteBuffer();
                while (target.hasRemaining()) {
                    if (source.read(target) <= 0) {
                        return Mpq.ERROR_READ;
                    }
                }
                return 0;
            } finally {
                source.position(position);
            }
        } catch (Throwable error) {
            return Mpq.ERROR_READ;
        }
    }
}
