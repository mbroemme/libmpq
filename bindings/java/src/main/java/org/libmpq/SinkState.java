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
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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
    private final Archive.FlushCallback onFlush;
    private final Arena arena = Arena.ofShared();
    final MemorySegment read;
    final MemorySegment write;
    final MemorySegment flush;

    SinkState(SeekableByteChannel sink, boolean readBack, Archive.FlushCallback onFlush) {
        try {
            this.sink = Objects.requireNonNull(sink, "sink");
            this.onFlush = onFlush;
            write = upcall("writeAt");
            read = readBack ? upcall("readAt") : MemorySegment.NULL;
            flush = onFlush == null ? MemorySegment.NULL : flushUpcall();
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

    private MemorySegment flushUpcall() throws ReflectiveOperationException {
        MethodHandle target = MethodHandles.lookup().findVirtual(
            SinkState.class, "flushSink", MethodType.methodType(int.class, MemorySegment.class)
        ).bindTo(this);
        return Linker.nativeLinker().upcallStub(target,
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS), arena);
    }

    private int flushSink(MemorySegment context) {
        try {
            onFlush.flush();
            return 0;
        } catch (LibmpqCallbackException error) {
            return error.code();
        } catch (Throwable error) {
            return Mpq.ERROR_CLOSE;
        }
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
        int status = 0;
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
                } catch (LibmpqCallbackException error) {
                    status = error.code();
                    return status;
                } finally {
                    sink.position(original);
                }
            }
            return 0;
        } catch (LibmpqCallbackException error) {
            return status != 0 ? status : error.code();
        } catch (Throwable error) {
            return status != 0 ? status : failure;
        }
    }
}
