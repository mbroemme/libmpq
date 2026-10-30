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
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Objects;
import org.libmpq.ffi.LibmpqNative;

/** Borrowed channel and upcall lifetime for one writable archive. */
final class SinkState {
    private final SeekableByteChannel sink;
    private final Arena arena = Arena.ofShared();
    final MemorySegment read;
    final MemorySegment write;

    SinkState(SeekableByteChannel sink, boolean readBack) {
        try {
            this.sink = Objects.requireNonNull(sink, "sink");
            write = upcall("writeAt");
            read = readBack ? upcall("readAt") : MemorySegment.NULL;
        } catch (ReflectiveOperationException error) {
            arena.close();
            throw new IllegalStateException("Unable to create libmpq sink callbacks", error);
        } catch (RuntimeException | Error error) {
            arena.close();
            throw error;
        }
    }

    private MemorySegment upcall(String name) throws ReflectiveOperationException {
        MethodHandle target = MethodHandles.lookup().findVirtual(
            SinkState.class, name, MethodType.methodType(int.class, MemorySegment.class, long.class,
                                                         MemorySegment.class, long.class)
        ).bindTo(this);
        return LibmpqNative.sinkTransferUpcall(target, arena);
    }

    void release() {
        arena.close();
    }

    private int readAt(MemorySegment context, long offset, MemorySegment buffer, long size) {
        return transfer(offset, buffer, size, true);
    }

    private int writeAt(MemorySegment context, long offset, MemorySegment buffer, long size) {
        return transfer(offset, buffer, size, false);
    }

    /** Keep the channel cursor private to each synchronous operation. */
    private int transfer(long offset, MemorySegment buffer, long size, boolean reading) {
        int failure = reading ? Mpq.ERROR_READ : Mpq.ERROR_WRITE;
        if (offset < 0 || size < 0 || size > Long.MAX_VALUE - offset) {
            return failure;
        }
        try (Arena call = Arena.ofConfined()) {
            synchronized (sink) {
                long original = sink.position();
                try {
                    sink.position(offset);
                    MemorySegment bytes = buffer.reinterpret(size, call, null);
                    for (long position = 0; position < size;) {
                        long chunk = Math.min(Integer.MAX_VALUE, size - position);
                        ByteBuffer part = bytes.asSlice(position, chunk).asByteBuffer();
                        if (!reading)
                            part = part.asReadOnlyBuffer();
                        while (part.hasRemaining()) {
                            if ((reading ? sink.read(part) : sink.write(part)) <= 0)
                                return failure;
                        }
                        position += chunk;
                    }
                } finally {
                    sink.position(original);
                }
            }
            return 0;
        } catch (Throwable error) {
            return failure;
        }
    }
}
