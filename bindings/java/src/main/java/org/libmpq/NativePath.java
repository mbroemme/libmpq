/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

import java.io.File;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * An immutable host path for libmpq's C filesystem APIs. POSIX paths can contain
 * arbitrary non-NUL bytes. On Windows, libmpq requires UTF-8 for conversion to
 * Win32 wide paths, which limits this API to Unicode paths encodable as UTF-8.
 */
public final class NativePath {
    private final byte[] bytes;

    private NativePath(byte[] bytes) {
        this.bytes = Support.copyCString(bytes);
    }

    /**
     * Copy the host path bytes passed to libmpq. Supply UTF-8 on Windows.
     * @throws IllegalArgumentException if the bytes contain NUL
     */
    public static NativePath ofBytes(byte[] bytes) {
        return new NativePath(bytes);
    }

    /**
     * Convert a default-filesystem path while preserving its native spelling.
     * On POSIX, use {@link #ofBytes(byte[])} if the path cannot round-trip as UTF-8.
     * @throws IllegalArgumentException if the path is on another filesystem,
     *         contains malformed text, or cannot be represented without loss
     */
    public static NativePath of(Path path) {
        if (path.getFileSystem() != FileSystems.getDefault()) {
            throw new IllegalArgumentException("path must use the default filesystem");
        }
        Path absolute = path.toAbsolutePath();
        byte[] encoded = Support.utf8(absolute.toString());
        if (File.separatorChar == '/') {
            StringBuilder uri = new StringBuilder("file://");
            HexFormat hex = HexFormat.of();
            // Check UTF-8 bytes through the POSIX provider's byte-preserving URI
            // decoder. A text round trip alone depends on the JVM's path encoding.
            for (byte b : encoded) {
                if (b == '/') {
                    uri.append('/');
                } else {
                    hex.toHexDigits(uri.append('%'), b);
                }
            }
            if (!Path.of(URI.create(uri.toString())).equals(absolute)) {
                throw new IllegalArgumentException("path cannot be represented as native UTF-8; "
                                                   + "use NativePath.ofBytes");
            }
        }
        return new NativePath(encoded);
    }

    MemorySegment marshal(Arena arena) {
        return Support.cString(arena, bytes);
    }
}
