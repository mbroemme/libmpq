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
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Objects;
import org.libmpq.ffi.LibmpqNative;

/** Shared borrowed channel state and FFM callback lifetime for custom sources. */
final class SourceState {
    private static final int MAX_VIEW_BYTES = 1 << 20;

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
        } catch (IOException error) {
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

    /**
     * Fill one borrowed native destination, keeping the first failure if
     * restoring the caller's cursor also fails.
     */
    private synchronized int readAt(MemorySegment context, long offset,
                                    MemorySegment output, long count) {
        if (offset < 0 || count < 0 || offset > size || count > size - offset) {
            return Mpq.ERROR_READ;
        }
        int status = 0;
        try {
            if (count != 0 && !validDestination(output, count)) {
                return Mpq.ERROR_READ;
            }
            long position = source.position();
            try {
                source.position(offset);
                if (count != 0) {
                    status = readExactly(output.reinterpret(count));
                }
            } catch (LibmpqCallbackException error) {
                status = error.code();
            } catch (Throwable error) {
                status = Mpq.ERROR_READ;
            } finally {
                source.position(position);
            }
        } catch (LibmpqCallbackException error) {
            return status != 0 ? status : error.code();
        } catch (Throwable error) {
            return status != 0 ? status : Mpq.ERROR_READ;
        }
        return status;
    }

    private static boolean validDestination(MemorySegment output, long count) {
        long address = output.address();
        // For a nonzero request, bound the last byte without adding to the address.
        // On 64-bit targets the extent must also stay within one signed long half.
        long limit = ValueLayout.ADDRESS.byteSize() == 4 ? 0xffff_ffffL
                : (address < 0 ? -1L : Long.MAX_VALUE);
        return address != 0 && Long.compareUnsigned(address, limit) <= 0
                && count - 1 <= limit - address
                && output.isNative() && !output.isReadOnly() && output.scope().isAlive()
                && output.isAccessibleBy(Thread.currentThread());
    }

    private int readExactly(MemorySegment destination) throws IOException {
        long count = destination.byteSize();
        long transferred = 0;
        while (transferred < count) {
            long viewSize = Math.min(count - transferred, MAX_VIEW_BYTES);
            ByteBuffer target = destination.asSlice(transferred, viewSize).asByteBuffer();
            while (target.hasRemaining()) {
                int before = target.position();
                int read = source.read(target);
                if (read <= 0 || read != target.position() - before) {
                    return Mpq.ERROR_READ;
                }
                transferred += read;
            }
        }
        return 0;
    }
}
