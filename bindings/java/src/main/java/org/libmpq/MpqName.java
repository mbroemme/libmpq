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

/**
 * An immutable native byte string for an MPQ name, patch prefix or source label.
 * Bytes are preserved exactly. Native lookup and hashing still apply their usual
 * case and separator rules.
 */
public final class MpqName {
    private final byte[] bytes;

    private MpqName(byte[] bytes) {
        this.bytes = Support.copyCString(bytes);
    }

    /**
     * Copy native name bytes without decoding them.
     * @throws IllegalArgumentException if the bytes contain NUL
     */
    public static MpqName ofBytes(byte[] bytes) {
        return new MpqName(bytes);
    }

    /**
     * Encode text as UTF-8 without normalization or replacement.
     * @throws IllegalArgumentException if the text contains NUL or an unpaired surrogate
     */
    public static MpqName ofUtf8(String value) {
        return new MpqName(Support.utf8(value));
    }

    boolean isEmpty() {
        return bytes.length == 0;
    }

    MemorySegment marshal(Arena arena) {
        return Support.cString(arena, bytes);
    }
}
