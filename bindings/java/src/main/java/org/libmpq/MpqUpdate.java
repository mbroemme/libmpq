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
import java.lang.ref.Reference;
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
        return beginBytes(NativePath.of(path));
    }

    /** Byte-exact form of {@link #begin(Path)}. */
    public static MpqUpdate beginBytes(NativePath path) throws LibmpqException {
        Objects.requireNonNull(path, "path");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.updateBegin(output, path.marshal(arena)));
            return new MpqUpdate(LibmpqNative.getAddress(output));
        }
    }

    /** Begin an authenticated MPQE update with temporary native authentication bytes. */
    public static MpqUpdate beginMpqe(Path path, byte[] authCode) throws LibmpqException {
        return beginMpqeBytes(NativePath.of(path), authCode);
    }

    /** Byte-exact form of {@link #beginMpqe(Path, byte[])}. */
    public static MpqUpdate beginMpqeBytes(NativePath path, byte[] authCode) throws LibmpqException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(authCode, "authCode");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment output = arena.allocate(ValueLayout.ADDRESS);
            Support.check(LibmpqNative.updateBeginMpqe(output,
                    path.marshal(arena), Support.bytes(arena, authCode),
                    authCode.length));
            return new MpqUpdate(LibmpqNative.getAddress(output));
        }
    }

    /** Stage a new member from bytes; duplicate names fail. */
    public void addData(String name, byte[] data, FileOptions options) throws LibmpqException {
        addDataBytes(MpqName.ofUtf8(name), data, options);
    }

    /** Byte-exact form of {@link #addData(String, byte[], FileOptions)}. */
    public void addDataBytes(MpqName name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateAddData(handle, name.marshal(arena),
                    Support.bytes(arena, data), data.length, options(arena, options)));
        }
    }

    /**
     * Stage a new member from caller-owned native memory. Keep the segment alive
     * and its bytes stable until the synchronous call returns.
     */
    public void addDataSegment(String name, MemorySegment data,
                                   FileOptions options) throws LibmpqException {
        addDataSegmentBytes(MpqName.ofUtf8(name), data, options);
    }

    /** Byte-exact form of {@link #addDataSegment(String, MemorySegment, FileOptions)}. */
    public void addDataSegmentBytes(MpqName name, MemorySegment data,
                                        FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Support.checkNativeBuffer(data, false);
        long size = data.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateAddData(handle, name.marshal(arena),
                    size == 0 ? MemorySegment.NULL : data, size, options(arena, options)));
        }
    }

    /** Stage a new member from a caller-owned source path. */
    public void addPath(String name, Path source, FileOptions options) throws LibmpqException {
        addPathBytes(MpqName.ofUtf8(name), NativePath.of(source), options);
    }

    /** Byte-exact form of {@link #addPath(String, Path, FileOptions)}. */
    public void addPathBytes(MpqName name, NativePath source, FileOptions options) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateAddPath(handle, name.marshal(arena),
                    source.marshal(arena), options(arena, options)));
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
        replaceRangesBytes(MpqName.ofUtf8(name), ranges);
    }

    /** Byte-exact form of {@link #replaceRanges(String, List<ReplaceRange>)}. */
    public void replaceRangesBytes(MpqName name, List<ReplaceRange> ranges) throws LibmpqException {
        replaceRanges(name, (short) 0, (short) 0, ranges, false);
    }

    /** Stage fixed-size replacements for one exact locale/platform identity. */
    public void replaceRanges(String name, int locale, int platform, List<ReplaceRange> ranges)
            throws LibmpqException {
        replaceRangesBytes(MpqName.ofUtf8(name), locale, platform, ranges);
    }

    /** Byte-exact form of {@link #replaceRanges(String, int, int, List<ReplaceRange>)}. */
    public void replaceRangesBytes(MpqName name, int locale, int platform, List<ReplaceRange> ranges)
            throws LibmpqException {
        replaceRanges(name, selector(locale), selector(platform), ranges, true);
    }

    private void replaceRanges(MpqName name, short locale, short platform,
                               List<ReplaceRange> ranges, boolean exact) throws LibmpqException {
        checkOpen();
        List<ReplaceRange> entries = List.copyOf(ranges);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeName = name.marshal(arena);
            MemorySegment nativeRanges = LibmpqNative.allocateReplaceRanges(arena, entries.size());
            for (int i = 0; i < entries.size(); i++) {
                ReplaceRange range = entries.get(i);
                LibmpqNative.setReplaceRange(nativeRanges, i, range.offset(),
                        Support.bytes(arena, range.data), range.data.length);
            }
            applyRanges(nativeName, locale, platform, nativeRanges, entries.size(), exact);
        }
    }

    /**
     * A fixed-size replacement at a nonnegative logical offset. The descriptor
     * keeps a reference to caller-owned native memory without copying its bytes.
     * Keep the segment alive and unchanged throughout each staging call.
     *
     * @param offset logical byte offset in the selected member
     * @param data native replacement bytes, including empty or read-only input
     */
    public record SegmentReplaceRange(long offset, MemorySegment data) {
        /**
         * Creates a descriptor and validates the offset and segment.
         *
         * @throws IllegalArgumentException if the offset is negative or the segment is invalid
         * @throws NullPointerException if the segment is null
         */
        public SegmentReplaceRange {
            if (offset < 0) {
                throw new IllegalArgumentException("replacement offset must not be negative");
            }
            Support.checkNativeBuffer(data, false);
        }
    }

    /**
     * Stages fixed-size replacements from native memory using ordinary lookup.
     * Later ranges win on overlap. The segments are borrowed until return.
     * Empty vectors and zero-length ranges retain native validation semantics.
     *
     * @param name archive filename
     * @param ranges replacement descriptors in application order
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesSegment(String name, List<SegmentReplaceRange> ranges)
            throws LibmpqException {
        replaceRangesSegmentBytes(MpqName.ofUtf8(name), ranges);
    }

    /**
     * Byte-exact form of {@link #replaceRangesSegment(String, List)}.
     *
     * @param name byte-exact archive filename
     * @param ranges replacement descriptors in application order
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesSegmentBytes(MpqName name, List<SegmentReplaceRange> ranges)
            throws LibmpqException {
        replaceRangesSegmentImpl(name, (short) 0, (short) 0, ranges, false);
    }

    /**
     * Stages native-memory ranges for exactly the selected locale/platform.
     * Later ranges win on overlap. The segments are borrowed until return.
     *
     * @param name archive filename
     * @param locale unsigned 16-bit locale selector
     * @param platform unsigned 16-bit platform selector
     * @param ranges replacement descriptors in application order
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesSegment(String name, int locale, int platform,
                                     List<SegmentReplaceRange> ranges) throws LibmpqException {
        replaceRangesSegmentBytes(MpqName.ofUtf8(name), locale, platform, ranges);
    }

    /**
     * Byte-exact form of {@link #replaceRangesSegment(String, int, int, List)}.
     *
     * @param name byte-exact archive filename
     * @param locale unsigned 16-bit locale selector
     * @param platform unsigned 16-bit platform selector
     * @param ranges replacement descriptors in application order
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesSegmentBytes(MpqName name, int locale, int platform,
                                          List<SegmentReplaceRange> ranges) throws LibmpqException {
        replaceRangesSegmentImpl(name, selector(locale), selector(platform), ranges, true);
    }

    private void replaceRangesSegmentImpl(MpqName name, short locale, short platform,
                                          List<SegmentReplaceRange> ranges, boolean exact)
            throws LibmpqException {
        checkOpen();
        List<SegmentReplaceRange> entries = List.copyOf(ranges);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeName = name.marshal(arena);
            MemorySegment nativeRanges = LibmpqNative.allocateReplaceRanges(arena, entries.size());
            for (int i = 0; i < entries.size(); i++) {
                SegmentReplaceRange range = entries.get(i);
                MemorySegment data = range.data();
                Support.checkNativeBuffer(data, false);
                LibmpqNative.setReplaceRange(nativeRanges, i, range.offset(), data, data.byteSize());
            }
            applyRanges(nativeName, locale, platform, nativeRanges, entries.size(), exact);
        } finally {
            // Descriptor pointers alone do not keep segments in automatic arenas alive.
            Reference.reachabilityFence(entries);
        }
    }

    /**
     * Stages a caller-owned native descriptor vector using ordinary lookup.
     * Use {@link LibmpqNative#replaceRangeLayout()} to lay out the vector.
     * Later descriptors win on overlap. Keep the vector and every referenced
     * payload alive, accessible and unchanged until this call returns.
     * The vector may be read-only. The caller is responsible for the validity
     * of embedded payload pointers. Native range validation applies.
     * Commit publishes the stage.
     *
     * @param name archive filename
     * @param ranges native descriptor vector, or {@link MemorySegment#NULL} for zero count
     * @param rangeCount number of descriptors in application order
     * @throws IllegalArgumentException if the vector or count is invalid
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesNative(String name, MemorySegment ranges, long rangeCount)
            throws LibmpqException {
        replaceRangesNativeBytes(MpqName.ofUtf8(name), ranges, rangeCount);
    }

    /**
     * Byte-exact form of {@link #replaceRangesNative(String, MemorySegment, long)}.
     *
     * @param name byte-exact archive filename
     * @param ranges borrowed native descriptor vector
     * @param rangeCount number of descriptors in application order
     * @throws IllegalArgumentException if the vector or count is invalid
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesNativeBytes(MpqName name, MemorySegment ranges, long rangeCount)
            throws LibmpqException {
        replaceRangesNativeImpl(name, (short) 0, (short) 0, ranges, rangeCount, false);
    }

    /**
     * Stages a native vector for one exact locale/platform identity.
     * Buffer, ownership, and ordering rules match
     * {@link #replaceRangesNative(String, MemorySegment, long)}.
     *
     * @param name archive filename
     * @param locale unsigned 16-bit locale selector
     * @param platform unsigned 16-bit platform selector
     * @param ranges borrowed native descriptor vector
     * @param rangeCount number of descriptors in application order
     * @throws IllegalArgumentException if the selector, vector or count is invalid
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesNative(String name, int locale, int platform,
                                    MemorySegment ranges, long rangeCount) throws LibmpqException {
        replaceRangesNativeBytes(MpqName.ofUtf8(name), locale, platform, ranges, rangeCount);
    }

    /**
     * Byte-exact form of {@link #replaceRangesNative(String, int, int, MemorySegment, long)}.
     *
     * @param name byte-exact archive filename
     * @param locale unsigned 16-bit locale selector
     * @param platform unsigned 16-bit platform selector
     * @param ranges borrowed native descriptor vector
     * @param rangeCount number of descriptors in application order
     * @throws IllegalArgumentException if the selector, vector or count is invalid
     * @throws LibmpqException if the native transaction rejects the edit
     */
    public void replaceRangesNativeBytes(MpqName name, int locale, int platform,
                                         MemorySegment ranges, long rangeCount) throws LibmpqException {
        replaceRangesNativeImpl(name, selector(locale), selector(platform), ranges, rangeCount, true);
    }

    private void replaceRangesNativeImpl(MpqName name, short locale, short platform,
                                         MemorySegment ranges, long rangeCount, boolean exact)
            throws LibmpqException {
        checkOpen();
        Support.checkNativeBuffer(ranges, false);
        var layout = LibmpqNative.replaceRangeLayout();
        if (rangeCount < 0 || rangeCount > ranges.byteSize() / layout.byteSize()) {
            throw new IllegalArgumentException("descriptor count must fit the native vector extent");
        }
        if (rangeCount != 0 && ranges.address() % layout.byteAlignment() != 0) {
            throw new IllegalArgumentException("range descriptor vector is misaligned");
        }
        try (Arena arena = Arena.ofConfined()) {
            applyRanges(name.marshal(arena), locale, platform, ranges, rangeCount, exact);
        }
    }

    private void applyRanges(MemorySegment name, short locale, short platform, MemorySegment ranges,
                             long count, boolean exact) throws LibmpqException {
        Support.check(exact
                ? LibmpqNative.updateReplaceRangesIdentity(handle, name, locale, platform, ranges, count)
                : LibmpqNative.updateReplaceRanges(handle, name, ranges, count));
    }

    /** Stage replacement from bytes; null options use native defaults. */
    public void replaceData(String name, byte[] data, FileOptions options) throws LibmpqException {
        replaceDataBytes(MpqName.ofUtf8(name), data, options);
    }

    /** Byte-exact form of {@link #replaceData(String, byte[], FileOptions)}. */
    public void replaceDataBytes(MpqName name, byte[] data, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceData(
                handle, name.marshal(arena), Support.bytes(arena, data), data.length,
                options(arena, options)
            ));
        }
    }

    /**
     * Stage a replacement from caller-owned native memory. Keep the segment alive
     * and its bytes stable until the synchronous call returns.
     */
    public void replaceDataSegment(String name, MemorySegment data,
                                   FileOptions options) throws LibmpqException {
        replaceDataSegmentBytes(MpqName.ofUtf8(name), data, options);
    }

    /** Byte-exact form of {@link #replaceDataSegment(String, MemorySegment, FileOptions)}. */
    public void replaceDataSegmentBytes(MpqName name, MemorySegment data,
                                        FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Support.checkNativeBuffer(data, false);
        long size = data.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceData(handle, name.marshal(arena),
                    size == 0 ? MemorySegment.NULL : data, size, options(arena, options)));
        }
    }

    /** Stage path replacement; null options use native defaults. */
    public void replacePath(String name, Path source, FileOptions options) throws LibmpqException {
        replacePathBytes(MpqName.ofUtf8(name), NativePath.of(source), options);
    }

    /** Byte-exact form of {@link #replacePath(String, Path, FileOptions)}. */
    public void replacePathBytes(MpqName name, NativePath source, FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplacePath(
                handle, name.marshal(arena), source.marshal(arena), options(arena, options)
            ));
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
        compactBytes(Support.names(filenames));
    }

    /** Byte-exact form of {@link #compact(List<String>)}. */
    public void compactBytes(List<MpqName> filenames) throws LibmpqException {
        checkOpen();
        MpqName[] names = Objects.requireNonNull(filenames, "filenames").toArray(MpqName[]::new);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeNames = names.length == 0 ? MemorySegment.NULL
                : arena.allocate(ValueLayout.ADDRESS, names.length);
            for (int i = 0; i < names.length; i++) {
                MpqName name = Objects.requireNonNull(names[i], "filename");
                if (name.isEmpty()) {
                    throw new IllegalArgumentException("filenames must be nonempty");
                }
                nativeNames.setAtIndex(ValueLayout.ADDRESS, i, name.marshal(arena));
            }
            Support.check(LibmpqNative.updateCompactEx(handle, nativeNames, names.length));
        }
    }

    /** Set existing Windows FILETIME bits, with no filesystem time conversion. */
    public void timestamp(String name, long filetime) throws LibmpqException {
        timestampBytes(MpqName.ofUtf8(name), filetime);
    }

    /** Byte-exact form of {@link #timestamp(String, long)}. */
    public void timestampBytes(MpqName name, long filetime) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateTimestamp(handle, name.marshal(arena), filetime));
        }
    }

    /** Set Windows FILETIME on the exact filename, locale and platform. */
    public void timestamp(String name, int locale, int platform, long filetime)
            throws LibmpqException {
        timestampBytes(MpqName.ofUtf8(name), locale, platform, filetime);
    }

    /** Byte-exact form of {@link #timestamp(String, int, int, long)}. */
    public void timestampBytes(MpqName name, int locale, int platform, long filetime)
            throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateTimestampIdentity(handle, name.marshal(arena),
                    selectedLocale, selectedPlatform, filetime));
        }
    }

    /** Stage removal of an existing named member. */
    public void remove(String name) throws LibmpqException {
        removeBytes(MpqName.ofUtf8(name));
    }

    /** Byte-exact form of {@link #remove(String)}. */
    public void removeBytes(MpqName name) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRemove(handle, name.marshal(arena)));
        }
    }

    /** Stage a filename change for the ordinarily selected member, keeping its tuple. */
    public void rename(String oldName, String newName) throws LibmpqException {
        renameBytes(MpqName.ofUtf8(oldName), MpqName.ofUtf8(newName));
    }

    /** Byte-exact form of {@link #rename(String, String)}. */
    public void renameBytes(MpqName oldName, MpqName newName) throws LibmpqException {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRename(handle, oldName.marshal(arena), newName.marshal(arena)));
        }
    }

    /** Replace only the exact locale/platform identity; null options retain its selectors. */
    public void replaceData(String name, int locale, int platform, byte[] data,
                            FileOptions options) throws LibmpqException {
        replaceDataBytes(MpqName.ofUtf8(name), locale, platform, data, options);
    }

    /** Byte-exact form of {@link #replaceData(String, int, int, byte[], FileOptions)}. */
    public void replaceDataBytes(MpqName name, int locale, int platform, byte[] data,
                                 FileOptions options) throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        Objects.requireNonNull(data, "data");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceDataIdentity(
                handle, name.marshal(arena), selectedLocale, selectedPlatform,
                Support.bytes(arena, data), data.length, options(arena, options)
            ));
        }
    }

    /**
     * Stage an exact-identity replacement from caller-owned native memory. Keep the segment alive
     * and its bytes stable until the synchronous call returns.
     */
    public void replaceDataSegment(String name, int locale, int platform, MemorySegment data,
                                   FileOptions options) throws LibmpqException {
        replaceDataSegmentBytes(MpqName.ofUtf8(name), locale, platform, data, options);
    }

    /** Byte-exact form of {@link #replaceDataSegment(String, int, int, MemorySegment, FileOptions)}. */
    public void replaceDataSegmentBytes(MpqName name, int locale, int platform, MemorySegment data,
                                        FileOptions options) throws LibmpqException {
        checkOpen();
        Objects.requireNonNull(name, "name");
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        Support.checkNativeBuffer(data, false);
        long size = data.byteSize();
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplaceDataIdentity(handle, name.marshal(arena), selectedLocale, selectedPlatform,
                    size == 0 ? MemorySegment.NULL : data, size, options(arena, options)));
        }
    }

    /** Replace one exact identity from a source path. */
    public void replacePath(String name, int locale, int platform, Path source,
                            FileOptions options) throws LibmpqException {
        replacePathBytes(MpqName.ofUtf8(name), locale, platform, NativePath.of(source), options);
    }

    /** Byte-exact form of {@link #replacePath(String, int, int, Path, FileOptions)}. */
    public void replacePathBytes(MpqName name, int locale, int platform, NativePath source,
                                 FileOptions options) throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        Objects.requireNonNull(source, "source");
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateReplacePathIdentity(
                handle, name.marshal(arena), selectedLocale, selectedPlatform, source.marshal(arena),
                options(arena, options)
            ));
        }
    }

    /** Remove only the selected identity, preserving shared payload aliases. */
    public void remove(String name, int locale, int platform) throws LibmpqException {
        removeBytes(MpqName.ofUtf8(name), locale, platform);
    }

    /** Byte-exact form of {@link #remove(String, int, int)}. */
    public void removeBytes(MpqName name, int locale, int platform) throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRemoveIdentity(
                handle, name.marshal(arena), selectedLocale, selectedPlatform
            ));
        }
    }

    /** Rename one exact identity without changing its locale/platform. */
    public void rename(String oldName, int locale, int platform, String newName)
            throws LibmpqException {
        renameBytes(MpqName.ofUtf8(oldName), locale, platform, MpqName.ofUtf8(newName));
    }

    /** Byte-exact form of {@link #rename(String, int, int, String)}. */
    public void renameBytes(MpqName oldName, int locale, int platform, MpqName newName)
            throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateRenameIdentity(
                handle, oldName.marshal(arena), newName.marshal(arena), selectedLocale, selectedPlatform
            ));
        }
    }

    /**
     * Change the exact tuple (locale, platform) to (newLocale, newPlatform).
     * The filename, payload and unrelated aliases are preserved.
     * @throws LibmpqException if staging fails, including
     * {@link Mpq#ERROR_EXIST} for an occupied destination tuple
     */
    public void changeIdentity(String name, int locale, int platform, int newLocale, int newPlatform)
            throws LibmpqException {
        changeIdentityBytes(MpqName.ofUtf8(name), locale, platform, newLocale, newPlatform);
    }

    /** Byte-exact form of {@link #changeIdentity(String, int, int, int, int)}. */
    public void changeIdentityBytes(MpqName name, int locale, int platform, int newLocale, int newPlatform)
            throws LibmpqException {
        checkOpen();
        short selectedLocale = selector(locale);
        short selectedPlatform = selector(platform);
        short destinationLocale = selector(newLocale);
        short destinationPlatform = selector(newPlatform);
        try (Arena arena = Arena.ofConfined()) {
            Support.check(LibmpqNative.updateChangeIdentity(handle, name.marshal(arena),
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
