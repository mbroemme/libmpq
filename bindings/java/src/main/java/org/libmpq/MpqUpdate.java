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

/** An isolated filesystem MPQ transaction; closing without commit aborts. */
public final class MpqUpdate implements AutoCloseable {
    private MemorySegment handle;

    private MpqUpdate(MemorySegment handle) {
        this.handle = handle;
    }

    /** Begin an update over an existing filesystem MPQ. */
    public static MpqUpdate begin(Path path) throws LibmpqException {
        Objects.requireNonNull(path, "path");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.updateBegin(output, Support.text(arena, path.toString())));
            return new MpqUpdate(LibmpqNative.getAddress(output));
        }
    }

    /** Stage replacement from bytes; null options use native defaults. */
    public void replaceData(String name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceData(handle, Support.text(arena, name),
                    Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /** Stage path replacement; null options use native defaults. */
    public void replacePath(String name, Path source, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplacePath(handle, Support.text(arena, name),
                    Support.text(arena, source.toString()), options(arena, options)));
        }
    }

    /** Stage removal of an existing named member. */
    public void remove(String name) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRemove(handle, Support.text(arena, name)));
        }
    }

    /** Stage a member rename. */
    public void rename(String oldName, String newName) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRename(handle, Support.text(arena, oldName),
                                                    Support.text(arena, newName)));
        }
    }

    /** Atomically publish staged changes; consumes the handle even on error. */
    public void commit() throws LibmpqException {
        MemorySegment current = take();
        Support.check(LibmpqNative.updateCommit(current));
    }

    /** Discard staged changes; consumes the handle even on error. */
    public void abort() throws LibmpqException {
        MemorySegment current = take();
        Support.check(LibmpqNative.updateAbort(current));
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
            throw new IllegalStateException("Update is closed");
        }
    }
}
