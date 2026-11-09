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
import std.string : format, toStringz;
import libmpq.native : ERROR_FORMAT, ERROR_OPEN, ERROR_UNPACK, libmpq__strerror;

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

/** Signal a documented negative ERROR_* status from a positioned I/O callback. */
final class MPQCallbackException : MPQException {
    /** Throws Exception if code is outside the documented native error domain. */
    this(int code) {
        super("positioned I/O callback", checkedCode(code));
    }

    private static int checkedCode(int code) {
        if (code < ERROR_UNPACK || code > ERROR_OPEN)
            throw new Exception("callback status must be a documented negative libmpq error");
        return code;
    }
}

/** A native stream-read failure with the valid byte count in the caller's buffer. */
final class StreamReadException : MPQException {
    /** Length of the valid prefix, also reflected in the stream position. */
    immutable size_t transferred;

    this(int code, size_t transferred) {
        super("libmpq__stream_read", code);
        this.transferred = transferred;
    }
}

/** Throw `MPQException` when a native call returns a negative status. */
void checkStatus(int status, string functionName) {
    if (status < 0)
        throw new MPQException(functionName, status);
}

/** Marshal native string bytes without permitting C-string truncation. */
package(libmpq) const(char)* checkedStringz(string value) {
    foreach (char codeUnit; value)
        if (codeUnit == 0)
            throw new MPQException("native string", ERROR_FORMAT, "embedded NUL");
    return toStringz(value);
}
