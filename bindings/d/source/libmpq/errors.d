/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** D exception and status-code helpers for libmpq. */
module libmpq.errors;

import core.stdc.string : strlen;
import std.string : format;
import libmpq.native : libmpq__strerror;

/**
 * Exception raised when a native libmpq operation returns a negative status.
 *
 * `code` preserves the original documented `LIBMPQ_ERROR_*` value and
 * `functionName` identifies the operation that failed. The exception message
 * includes both values and the native diagnostic text where available.
 */
class MPQException : Exception {
    /** Original negative libmpq status code. */
    public immutable int code;

    /** Native operation or high-level wrapper that failed. */
    public immutable string functionName;

    /** Build an exception for one native status code. */
    this(string functionName, int code) {
        this(functionName, code, nativeMessage(code));
    }

    private this(string functionName, int code, string diagnostic) {
        super(format("Error in %s(): %s (%d)", functionName, diagnostic, code));
        this.functionName = functionName.idup;
        this.code = code;
    }

    private static string nativeMessage(int code) {
        auto message = libmpq__strerror(code);
        return message is null ? "unknown error" : message[0 .. strlen(message)].idup;
    }
}

/** Throw `MPQException` when a native call returns a negative status. */
void checkStatus(int status, string functionName) {
    if (status < 0)
        throw new MPQException(functionName, status);
}
