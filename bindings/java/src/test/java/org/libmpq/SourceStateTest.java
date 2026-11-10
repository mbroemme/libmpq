/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Direct calls to the positioned source upcall, independent of archive parsing. */
class SourceStateTest {
    private static final int VIEW = 1 << 20;
    private static final long CURSOR = 77;
    private static final long LARGE_OFFSET = (1L << 32) + 19;

    @BeforeAll
    static void requireNativeLibrary() {
        LibmpqTest.requireNativeLibrary();
        Assumptions.assumeTrue(ValueLayout.ADDRESS.byteSize() == Long.BYTES);
    }

    @Test
    void exactReadsPreserveCursorAndFillMultipleViews() throws Throwable {
        Channel channel = new Channel();
        assertEquals(0, invoke(channel, LARGE_OFFSET, MemorySegment.NULL, 0));
        assertEquals(0, channel.reads);
        assertEquals(CURSOR, channel.position);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(2 * VIEW + 17).fill((byte) 0x55);
            assertEquals(0, invoke(channel, LARGE_OFFSET, output, 1));
            assertEquals(1, channel.transferred);
            assertEquals((byte) LARGE_OFFSET, output.get(ValueLayout.JAVA_BYTE, 0));
            assertEquals((byte) 0x55, output.get(ValueLayout.JAVA_BYTE, 1));
            assertEquals(CURSOR, channel.position);

            channel = new Channel();
            assertEquals(0, invoke(channel, LARGE_OFFSET, output, output.byteSize()));
            assertEquals(output.byteSize(), channel.transferred);
            assertEquals(3, channel.views);
            assertTrue(channel.reads > channel.views);
            for (long offset : new long[] {0, VIEW - 1L, VIEW, 2L * VIEW, output.byteSize() - 1}) {
                assertEquals((byte) (LARGE_OFFSET + offset), output.get(ValueLayout.JAVA_BYTE, offset));
            }
            assertEquals(CURSOR, channel.position);
        }
    }

    @Test
    void transferAndCursorFailuresKeepFirstStatus() throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(8);
            for (End end : End.values()) {
                for (int progress : new int[] {0, 3}) {
                    output.fill((byte) 0x55);
                    Channel channel = new Channel(progress, end);
                    int expected = end == End.MALLOC ? Mpq.ERROR_MALLOC : Mpq.ERROR_READ;
                    assertEquals(expected, invoke(channel, LARGE_OFFSET, output, output.byteSize()));
                    assertEquals(progress, channel.transferred);
                    assertEquals(CURSOR, channel.position);
                    assertEquals((byte) 0x55, output.get(ValueLayout.JAVA_BYTE, progress));
                }
            }

            for (End end : End.values()) {
                Channel bothFail = new Channel(3, end);
                bothFail.failRestore = true;
                assertEquals(end == End.MALLOC ? Mpq.ERROR_MALLOC : Mpq.ERROR_READ,
                        invoke(bothFail, LARGE_OFFSET, output, output.byteSize()));
                assertEquals(3, bothFail.transferred);
                assertEquals(1, bothFail.restoreAttempts);
                assertEquals(LARGE_OFFSET + 3, bothFail.position);
            }

            Channel restoreOnly = new Channel();
            restoreOnly.failRestore = true;
            assertEquals(Mpq.ERROR_WRITE, invoke(restoreOnly, LARGE_OFFSET, output, output.byteSize()));
            assertEquals(output.byteSize(), restoreOnly.transferred);
            assertEquals(1, restoreOnly.restoreAttempts);
        }
    }

    @Test
    void rejectsUnrepresentableSourceAndBufferRanges() throws Throwable {
        Channel channel = new Channel();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(8);
            assertEquals(Mpq.ERROR_READ, invoke(channel, -1, output, 1));
            assertEquals(Mpq.ERROR_READ, invoke(channel, 0, output, -1));
            assertEquals(Mpq.ERROR_READ, invoke(channel, Long.MAX_VALUE - 1, output, 2));
            assertEquals(Mpq.ERROR_READ, invoke(channel, 0, MemorySegment.NULL, 1));
            assertEquals(Mpq.ERROR_READ, invoke(channel, 0, MemorySegment.ofAddress(Long.MAX_VALUE), 2));
            assertEquals(Mpq.ERROR_READ, invoke(channel, 0, MemorySegment.ofAddress(-1L), 2));
            assertEquals(0, channel.reads);
            assertEquals(0, channel.seeks);
            assertEquals(0, invoke(channel, Long.MAX_VALUE - 1, output, 1));
            assertEquals(1, channel.transferred);
            assertEquals(CURSOR, channel.position);
        }
    }

    @Test
    void largeRequestsReachChannelWithoutPopulatingFullMapping(@TempDir Path directory) throws Throwable {
        Assumptions.assumeTrue(System.getProperty("os.name").equals("Linux"));
        long capacity = (long) Integer.MAX_VALUE + 1;
        try (Arena arena = Arena.ofConfined();
             FileChannel file = FileChannel.open(directory.resolve("sparse"), StandardOpenOption.CREATE_NEW,
                     StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.SPARSE)) {
            MemorySegment output = file.map(FileChannel.MapMode.READ_WRITE, 0, capacity, arena);
            Channel atLimit = new Channel(0, End.MALLOC);
            assertEquals(Mpq.ERROR_MALLOC, invoke(atLimit, LARGE_OFFSET, output, Integer.MAX_VALUE));
            assertEquals(1, atLimit.reads);
            assertEquals(0, atLimit.transferred);
            assertEquals(CURSOR, atLimit.position);

            Channel pastLimit = new Channel(VIEW + 3, End.MALLOC);
            assertEquals(Mpq.ERROR_MALLOC, invoke(pastLimit, LARGE_OFFSET, output, capacity));
            assertEquals(2, pastLimit.views);
            assertTrue(pastLimit.reads > pastLimit.views);
            assertEquals(VIEW + 3, pastLimit.transferred);
            assertEquals((byte) (LARGE_OFFSET + VIEW - 1), output.get(ValueLayout.JAVA_BYTE, VIEW - 1));
            assertEquals((byte) (LARGE_OFFSET + VIEW + 2), output.get(ValueLayout.JAVA_BYTE, VIEW + 2));
            assertEquals((byte) 0, output.get(ValueLayout.JAVA_BYTE, VIEW + 3));
            assertEquals(CURSOR, pastLimit.position);
        }
    }

    private static int invoke(Channel channel, long offset, MemorySegment output, long count)
            throws Throwable {
        SourceState state = new SourceState(channel);
        try {
            Linker linker = Linker.nativeLinker();
            var descriptor = FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, linker.canonicalLayouts().get("size_t"));
            var call = linker.downcallHandle(state.callback(), descriptor);
            return (int) call.invokeExact(MemorySegment.NULL, offset, output, count);
        } finally {
            state.discard();
        }
    }

    private enum End { ZERO, EOF, IO, MALLOC }

    private static final class Channel implements SeekableByteChannel {
        private final long budget;
        private final End end;
        long position = CURSOR;
        long transferred;
        int reads;
        int views;
        int seeks;
        int restoreAttempts;
        boolean failRestore;

        Channel() { this(Long.MAX_VALUE, End.EOF); }

        Channel(long budget, End end) {
            this.budget = budget;
            this.end = end;
        }

        @Override public int read(ByteBuffer target) throws IOException {
            reads++;
            if (target.position() == 0) views++;
            if (transferred == budget) {
                return switch (end) {
                    case ZERO -> 0;
                    case EOF -> -1;
                    case IO -> throw new IOException("read failed");
                    case MALLOC -> throw new LibmpqCallbackException(Mpq.ERROR_MALLOC);
                };
            }
            int length = (int) Math.min(Math.min(target.remaining(), 1 << 16), budget - transferred);
            for (int i = 0; i < length; i++) {
                target.put((byte) position++);
            }
            transferred += length;
            return length;
        }

        @Override public long position() { return position; }
        @Override public SeekableByteChannel position(long value) throws IOException {
            seeks++;
            if (value == CURSOR) {
                restoreAttempts++;
                if (failRestore) throw new LibmpqCallbackException(Mpq.ERROR_WRITE);
            }
            position = value;
            return this;
        }
        @Override public long size() { return Long.MAX_VALUE; }
        @Override public int write(ByteBuffer source) { throw new UnsupportedOperationException(); }
        @Override public SeekableByteChannel truncate(long size) { throw new UnsupportedOperationException(); }
        @Override public boolean isOpen() { return true; }
        @Override public void close() { }
    }
}
