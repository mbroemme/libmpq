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

/**
 * Signals a documented native libmpq error from a positioned source or sink
 * callback, including an optional final flush. The adapter returns the code
 * to C, and the native operation determines the final reported status.
 */
public final class LibmpqCallbackException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int code;

    /**
     * Creates an intentional callback failure.
     *
     * @param code a documented negative {@code Mpq.ERROR_*} code
     * @throws IllegalArgumentException if the code is outside that domain
     */
    public LibmpqCallbackException(int code) {
        super("libmpq callback failed with status " + code);
        if (code < Mpq.ERROR_UNPACK || code > Mpq.ERROR_OPEN) {
            throw new IllegalArgumentException("callback status must be a documented negative libmpq error");
        }
        this.code = code;
    }

    /** Returns the native status selected by the callback. */
    public int code() {
        return code;
    }
}
