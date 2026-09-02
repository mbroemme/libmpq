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
import java.nio.charset.StandardCharsets;
import org.libmpq.ffi.LibmpqNative;

/** Internal memory, encoding, range, and native-error helpers for the binding. */
final class Support {
    /** Prevents construction of this static helper class. */
    private Support() { }

    /**
     * Converts a negative native status into {@link LibmpqException}; zero and
     * positive native statuses are accepted as successful results.
     */
    static void check(int code) throws LibmpqException {
        if (code < 0) {
            String message = cString(LibmpqNative.strerror(code));
            throw new LibmpqException(code, message);
        }
    }

    /**
     * Copies a NUL-terminated UTF-8 string returned by native libmpq into a
     * Java string.  Native diagnostic and version strings are static and are
     * therefore copied before the binding's temporary arena is closed.
     */
    static String cString(MemorySegment value) {
        MemorySegment text = value.reinterpret(4096);
        int length = 0;
        while (text.get(ValueLayout.JAVA_BYTE, length) != 0) {
            length++;
        }
        byte[] bytes = new byte[length];
        for (int index = 0; index < length; index++) {
            bytes[index] = text.get(ValueLayout.JAVA_BYTE, index);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Allocates a temporary NUL-terminated UTF-8 string for a C API argument.
     * The caller must keep the supplied arena alive until the native call
     * returns.
     */
    static MemorySegment text(Arena arena, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        MemorySegment result = arena.allocate(bytes.length + 1, 1);
        result.asSlice(0, bytes.length).copyFrom(MemorySegment.ofArray(bytes));
        result.set(ValueLayout.JAVA_BYTE, bytes.length, (byte) 0);
        return result;
    }

    /**
     * Allocates temporary native storage and copies a Java byte array into it.
     * Empty arrays are represented by the C null pointer because libmpq uses
     * a separate size argument for empty payloads.
     */
    static MemorySegment bytes(Arena arena, byte[] value) {
        if (value.length == 0) {
            return MemorySegment.NULL;
        }
        MemorySegment result = arena.allocate(value.length, 1);
        result.copyFrom(MemorySegment.ofArray(value));
        return result;
    }

    /** Copies native output bytes into a Java destination array. */
    static void copyTo(MemorySegment source, byte[] destination) {
        if (destination.length != 0) {
            MemorySegment.ofArray(destination).copyFrom(source.asSlice(0, destination.length));
        }
    }

    /** Validates and narrows a Java value to an unsigned C uint32_t bit pattern. */
    static int uint32(long value, String name) {
        if (value < 0 || value > 0xffff_ffffL) {
            throw new IllegalArgumentException(name + " is outside uint32_t range");
        }
        return (int) value;
    }

    /** Ensures a native file size can be represented by a Java byte array. */
    static int checkedArraySize(long value) {
        if (value < 0 || value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("MPQ file is too large for a Java byte array");
        }
        return (int) value;
    }
}
