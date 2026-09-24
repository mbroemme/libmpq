/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** Transactional filesystem archive updates. */
module libmpq.update;

import std.string : toStringz;
import libmpq.errors : MPQException, checkStatus;
import libmpq.native;
import libmpq.options : FileOptions;

/** A transaction whose uncommitted changes are aborted on destruction. */
final class Update {
    private mpq_update_s* handle;

    private this(mpq_update_s* handle) { this.handle = handle; }

    /** Begin an isolated transaction over an existing filesystem MPQ. */
    static Update begin(string path) {
        mpq_update_s* result;
        checkStatus(libmpq__update_begin(&result, toStringz(path)), "libmpq__update_begin");
        return new Update(result);
    }

    /** Stage replacement using native defaults and preserving member identity. */
    void replaceData(string name, const(ubyte)[] data) {
        replaceDataImpl(name, data, null);
    }

    /** Stage replacement with explicit storage options and matching identity. */
    void replaceData(string name, const(ubyte)[] data, FileOptions options) {
        auto nativeOptions = options.nativeOptions();
        replaceDataImpl(name, data, &nativeOptions);
    }

    private void replaceDataImpl(string name, const(ubyte)[] data,
                                 const(mpq_file_options_s)* options) {
        ensureOpen();
        if (data.length > cast(size_t)long.max)
            throw new MPQException("Update.replaceData", ERROR_SIZE);
        checkStatus(libmpq__update_replace_data(handle, toStringz(name),
                    data.length == 0 ? null : data.ptr, cast(off_t)data.length,
                    options), "libmpq__update_replace_data");
    }

    /** Stage path replacement using native defaults and preserving identity. */
    void replacePath(string name, string sourcePath) {
        replacePathImpl(name, sourcePath, null);
    }

    /** Stage path replacement with explicit storage options. */
    void replacePath(string name, string sourcePath, FileOptions options) {
        auto nativeOptions = options.nativeOptions();
        replacePathImpl(name, sourcePath, &nativeOptions);
    }

    private void replacePathImpl(string name, string sourcePath,
                                 const(mpq_file_options_s)* options) {
        ensureOpen();
        checkStatus(libmpq__update_replace_path(handle, toStringz(name),
                    toStringz(sourcePath), options),
                    "libmpq__update_replace_path");
    }

    /** Stage removal of one named member. */
    void remove(string name) {
        ensureOpen();
        checkStatus(libmpq__update_remove(handle, toStringz(name)),
                    "libmpq__update_remove");
    }

    /** Stage a filename change. */
    void rename(string oldName, string newName) {
        ensureOpen();
        checkStatus(libmpq__update_rename(handle, toStringz(oldName),
                    toStringz(newName)), "libmpq__update_rename");
    }

    /** Publish staged changes; this object is consumed even on native error. */
    void commit() {
        auto current = take();
        checkStatus(libmpq__update_commit(current), "libmpq__update_commit");
    }

    /** Discard staged changes; this object is consumed even on native error. */
    void abort() {
        auto current = take();
        checkStatus(libmpq__update_abort(current), "libmpq__update_abort");
    }

    /** Abort an active transaction; repeated wrapper closes are harmless. */
    void close() {
        if (handle !is null) abort();
    }

    /** Best-effort abort of an update that was not committed. */
    ~this() {
        if (handle !is null) {
            auto current = handle;
            handle = null;
            libmpq__update_abort(current);
        }
    }

    private mpq_update_s* take() {
        ensureOpen();
        auto current = handle;
        handle = null;
        return current;
    }

    private void ensureOpen() {
        if (handle is null)
            throw new MPQException("Update", ERROR_NOT_INITIALIZED);
    }
}
