/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** Staged patch archive creation. */
module libmpq.patch;

import std.string : toStringz;
import libmpq.errors : MPQException, checkStatus;
import libmpq.native;
import libmpq.options : FileOptions;

/** A patch artifact whose unpublished changes are aborted on destruction. */
final class Patch {
    private mpq_patch_s* handle;

    private this(mpq_patch_s* handle) { this.handle = handle; }

    /** Begin a patch without changing its base archive. */
    static Patch begin(string baseArchive, string outputPatch) {
        mpq_patch_s* result;
        checkStatus(libmpq__patch_begin(&result, toStringz(baseArchive),
                    toStringz(outputPatch)), "libmpq__patch_begin");
        return new Patch(result);
    }

    /** Stage replacement using native patch storage defaults. */
    void replaceData(string name, const(ubyte)[] data) {
        replaceDataImpl(name, data, null);
    }

    /** Stage replacement with explicit patch-member storage options. */
    void replaceData(string name, const(ubyte)[] data, FileOptions options) {
        auto nativeOptions = options.nativeOptions();
        replaceDataImpl(name, data, &nativeOptions);
    }

    private void replaceDataImpl(string name, const(ubyte)[] data,
                                 const(mpq_file_options_s)* options) {
        ensureOpen();
        if (data.length > cast(size_t)long.max)
            throw new MPQException("Patch.replaceData", ERROR_SIZE);
        checkStatus(libmpq__patch_replace_data(handle, toStringz(name),
                    data.length == 0 ? null : data.ptr, cast(off_t)data.length,
                    options), "libmpq__patch_replace_data");
    }

    /** Stage path replacement using native patch storage defaults. */
    void replacePath(string name, string sourcePath) {
        replacePathImpl(name, sourcePath, null);
    }

    /** Stage path replacement with explicit patch-member storage options. */
    void replacePath(string name, string sourcePath, FileOptions options) {
        auto nativeOptions = options.nativeOptions();
        replacePathImpl(name, sourcePath, &nativeOptions);
    }

    private void replacePathImpl(string name, string sourcePath,
                                 const(mpq_file_options_s)* options) {
        ensureOpen();
        checkStatus(libmpq__patch_replace_path(handle, toStringz(name),
                    toStringz(sourcePath), options),
                    "libmpq__patch_replace_path");
    }

    /** Stage a delete marker for an existing named member. */
    void remove(string name) {
        ensureOpen();
        checkStatus(libmpq__patch_remove(handle, toStringz(name)),
                    "libmpq__patch_remove");
    }

    /** Publish this patch; the handle is consumed even on native error. */
    void finish() {
        auto current = take();
        checkStatus(libmpq__patch_finish(current), "libmpq__patch_finish");
    }

    /** Discard this patch; the handle is consumed even on native error. */
    void abort() {
        auto current = take();
        checkStatus(libmpq__patch_abort(current), "libmpq__patch_abort");
    }

    /** Abort an active patch; repeated wrapper closes are harmless. */
    void close() {
        if (handle !is null) abort();
    }

    /** Best-effort abort of an unfinished patch. */
    ~this() {
        if (handle !is null) {
            auto current = handle;
            handle = null;
            libmpq__patch_abort(current);
        }
    }

    private mpq_patch_s* take() {
        ensureOpen();
        auto current = handle;
        handle = null;
        return current;
    }

    private void ensureOpen() {
        if (handle is null)
            throw new MPQException("Patch", ERROR_NOT_INITIALIZED);
    }
}
