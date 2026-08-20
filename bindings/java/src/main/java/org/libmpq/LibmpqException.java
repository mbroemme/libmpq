/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

/**
 * Reports a negative return code from the native libmpq API.  The exception
 * message combines the native diagnostic string with the numeric code so
 * applications can log both human-readable and machine-readable details.
 */
public final class LibmpqException extends Exception {
    private static final long serialVersionUID = 1L;
    private final int code;

    /**
     * Creates an exception preserving the native error code and diagnostic
     * message returned by libmpq.
     *
     * @param code documented negative {@code LIBMPQ_ERROR_*} value
     * @param message native diagnostic text without the numeric suffix
     */
    public LibmpqException(int code, String message) {
        super(message + " (" + code + ")");
        this.code = code;
    }

    /**
     * Returns the original negative libmpq error code for programmatic error
     * handling.
     */
    public int code() {
        return code;
    }
}
