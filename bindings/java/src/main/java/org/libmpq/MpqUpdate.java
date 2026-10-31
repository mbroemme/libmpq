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
import java.util.List;
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

    /** Begin an authenticated MPQE update with temporary native authentication bytes. */
    public static MpqUpdate beginMpqe(Path path, byte[] authCode) throws LibmpqException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(authCode, "authCode");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.updateBeginMpqe(output,
                    Support.text(arena, path.toString()), Support.bytes(arena, authCode),
                    authCode.length));
            return new MpqUpdate(LibmpqNative.getAddress(output));
        }
    }

    /** Stage a new member from bytes; duplicate names fail. */
    public void addData(String name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateAddData(handle, Support.text(arena, name),
                    Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /** Stage a new member from a caller-owned source path. */
    public void addPath(String name, Path source, FileOptions options) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateAddPath(handle, Support.text(arena, name),
                    Support.text(arena, source.toString()), options(arena, options)));
        }
    }

    /** Immutable replacement bytes at a logical offset. */
    public record ReplaceRange(long offset, byte[] data) {
        public ReplaceRange {
            data = data.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }
    }

    /** Stage fixed-size replacements using ordinary filename lookup. */
    public void replaceRanges(String name, List<ReplaceRange> ranges) throws LibmpqException {
        replaceRanges(name, (short) 0, (short) 0, ranges, false);
    }

    /** Stage fixed-size replacements for one exact locale/platform identity. */
    public void replaceRanges(String name, int locale, int platform, List<ReplaceRange> ranges)
            throws LibmpqException {
        replaceRanges(name, selector(locale), selector(platform), ranges, true);
    }

    private void replaceRanges(String name, short locale, short platform,
                               List<ReplaceRange> ranges, boolean exact) throws LibmpqException {
        checkOpen();
        List<ReplaceRange> entries = List.copyOf(ranges);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeName = Support.text(arena, name);
            MemorySegment nativeRanges = LibmpqNative.allocateReplaceRanges(arena, entries.size());
            for (int i = 0; i < entries.size(); i++) {
                ReplaceRange range = entries.get(i);
                LibmpqNative.setReplaceRange(nativeRanges, i, range.offset(),
                        Support.bytes(arena, range.data), range.data.length);
            }
            Support.check(exact
                    ? LibmpqNative.updateReplaceRangesIdentity(handle, nativeName, locale, platform,
                            nativeRanges, entries.size())
                    : LibmpqNative.updateReplaceRanges(handle, nativeName, nativeRanges, entries.size()));
        }
    }

    /** Stage replacement from bytes; null options use native defaults. */
    public void replaceData(String name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceData(handle, Support.text(arena, name), Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /** Stage path replacement; null options use native defaults. */
    public void replacePath(String name, Path source, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplacePath(handle, Support.text(arena, name), Support.text(arena, source.toString()), options(arena, options)));
        }
    }

    /** Immediately sign the private stage with a caller-owned raw weak key. */
    public void sign(byte[] privateKey) throws LibmpqException {
        sign(Mpq.SIGNATURE_WEAK, privateKey);
    }

    /** Generate the requested signature now; commit alone publishes it. */
    public void sign(int signatureType, byte[] privateKey) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(privateKey);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, privateKey);
            try {
                Support.check(LibmpqNative.updateSign(handle, signatureType, key, privateKey.length));
            } finally {
                key.fill((byte) 0);
            }
        }
    }

    /** Immediately stage physical compaction; commit alone publishes it. */
    public void compact() throws LibmpqException {
        checkOpen();
        Support.check(LibmpqNative.updateCompact(handle));
    }

    /** Compact with borrowed filename context; only actual adoption retains names. */
    public void compact(List<String> filenames) throws LibmpqException {
        checkOpen();
        String[] names = Objects.requireNonNull(filenames, "filenames").toArray(String[]::new);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeNames = names.length == 0 ? MemorySegment.NULL
                : arena.allocate(ValueLayout.ADDRESS, names.length);
            for (int i = 0; i < names.length; i++) {
                String name = Objects.requireNonNull(names[i], "filename");
                if (name.isEmpty() || name.indexOf('\0') >= 0) {
                    throw new IllegalArgumentException("filenames must be nonempty and contain no NUL");
                }
                nativeNames.setAtIndex(ValueLayout.ADDRESS, i, Support.text(arena, name));
            }
            Support.check(LibmpqNative.updateCompactEx(handle, nativeNames, names.length));
        }
    }

    /** Set existing Windows FILETIME bits, with no filesystem time conversion. */
    public void timestamp(String name, long filetime) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateTimestamp(handle, Support.text(arena, name), filetime));
        }
    }

    public void timestamp(String name, long filetime, int locale, int platform)
            throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateTimestampIdentity(handle, Support.text(arena, name),
                    filetime, selectedLocale, selectedPlatform));
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
            Support.check(LibmpqNative.updateRename(handle, Support.text(arena, oldName), Support.text(arena, newName)));
        }
    }

    /** Replace only the exact locale/platform identity; null options retain its selectors. */
    public void replaceData(String name, int locale, int platform, byte[] data,
                            FileOptions options) throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceDataIdentity(handle, Support.text(arena, name), selectedLocale, selectedPlatform, Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /** Replace one exact identity from a source path. */
    public void replacePath(String name, int locale, int platform, Path source,
                            FileOptions options) throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplacePathIdentity(handle, Support.text(arena, name), selectedLocale, selectedPlatform, Support.text(arena, source.toString()), options(arena, options)));
        }
    }

    /** Remove only the selected identity, preserving shared payload aliases. */
    public void remove(String name, int locale, int platform) throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRemoveIdentity(handle, Support.text(arena, name), selectedLocale, selectedPlatform));
        }
    }

    /** Rename one exact identity without changing its locale/platform. */
    public void rename(String name, String newName, int locale, int platform)
            throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRenameIdentity(handle, Support.text(arena, name), Support.text(arena, newName), selectedLocale, selectedPlatform));
        }
    }

    /** Change an exact stored tuple while preserving the payload and unrelated aliases. */
    public void changeIdentity(String name, int locale, int platform, int newLocale, int newPlatform)
            throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        short destinationLocale = selector(newLocale);
        short destinationPlatform = selector(newPlatform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateChangeIdentity(handle, Support.text(arena, name),
                    selectedLocale, selectedPlatform, destinationLocale, destinationPlatform));
        }
    }

    private static short selector(int value) {
        if (value < 0 || value > 65535) {
            throw new IllegalArgumentException("Identity selector must be in 0..65535");
        }
        return (short) value;
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
