/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** High-level ownership-safe wrappers around the libmpq C API. */
module libmpq.archive;

import std.string : splitLines, toStringz;
import libmpq.errors : MPQException, checkStatus;
import libmpq.native;
import libmpq.options : ArchiveCreateOptions, FileOptions;

/** The three Storm hash values used by MPQ name lookup. */
struct StormHash { uint hash1; uint hash2; uint hash3; }

/** Aggregate metadata describing an opened archive. */
struct ArchiveMetadata {
    /** Total packed bytes in extractable entries. */ off_t packedSize;
    /** Total unpacked bytes in extractable entries. */ off_t unpackedSize;
    /** Archive start offset in the backing file. */ off_t offset;
    /** Archive format selector. */ uint version_;
    /** Number of valid file entries. */ uint fileCount;
}

/** Metadata describing one archive entry. */
struct FileMetadata {
    /** Packed entry size. */ off_t packedSize;
    /** Unpacked entry size. */ off_t unpackedSize;
    /** Entry payload offset relative to archive start. */ off_t offset;
    /** Number of sectors or blocks in the entry. */ uint blockCount;
    /** Non-zero when the entry is encrypted. */ uint encrypted;
    /** Non-zero when the entry uses MPQ multi-compression. */ uint compressed;
    /** Non-zero when the entry uses PKWARE implode. */ uint imploded;
}

/**
 * An opened or newly created MPQ archive.
 *
 * The object owns the native handle. Call `close` explicitly, preferably with
 * `scope(exit) archive.close()`, because D destructors cannot report close
 * errors. A closed archive must not be used again.
 */
class Archive {
    private mpq_archive_s* handle;
    private bool closed;

    /** Open an archive, optionally at a specific embedded offset. */
    this(string path, off_t offset = -1) {
        checkStatus(libmpq__archive_open(&handle, toStringz(path), offset),
                    "libmpq__archive_open");
    }

    private this(mpq_archive_s* handle) { this.handle = handle; }

    /** Open an archive using a named factory method. */
    static Archive open(string path, off_t offset = -1) {
        return new Archive(path, offset);
    }

    /** Open a caller-authenticated MPQE stream containing an MPQ archive. */
    static Archive openMpqe(string path, const(ubyte)[] authenticationCode,
                            off_t offset = -1) {
        mpq_archive_s* result;
        auto authenticationPointer = authenticationCode.length == 0 ? null :
            authenticationCode.ptr;
        checkStatus(libmpq__archive_open_mpqe(&result, toStringz(path), offset,
                                               authenticationPointer,
                                               authenticationCode.length),
                    "libmpq__archive_open_mpqe");
        return new Archive(result);
    }

    /** Create an archive using explicit v1/v2 and storage options. */
    static Archive create(string path,
                          ArchiveCreateOptions options = ArchiveCreateOptions.v1()) {
        auto nativeOptions = options.nativeOptions();
        mpq_archive_s* result;
        checkStatus(libmpq__archive_create(&result, toStringz(path),
                                            &nativeOptions),
                    "libmpq__archive_create");
        return new Archive(result);
    }

    /** Create a new MPQE-wrapped archive with borrowed authentication bytes. */
    static Archive createMpqe(string path, const(ubyte)[] authenticationCode,
                              ArchiveCreateOptions options = ArchiveCreateOptions.v1()) {
        auto nativeOptions = options.nativeOptions();
        mpq_archive_s* result;
        auto authenticationPointer = authenticationCode.length == 0 ? null :
            authenticationCode.ptr;
        checkStatus(libmpq__archive_create_mpqe(&result, toStringz(path), authenticationPointer,
                                                 authenticationCode.length, &nativeOptions),
                    "libmpq__archive_create_mpqe");
        return new Archive(result);
    }

    /** Return an independently parsed clone of this archive. */
    Archive clone() {
        ensureOpen();
        mpq_archive_s* result;
        checkStatus(libmpq__archive_clone(&result, handle),
                    "libmpq__archive_clone");
        return new Archive(result);
    }

    /** Compatibility spelling for callers preferring an explicit noun. */
    Archive cloneArchive() { return clone(); }

    /** Close the native handle; repeated calls are harmless. */
    void close() {
        if (closed) return;
        auto status = libmpq__archive_close(handle);
        closed = true;
        handle = null;
        checkStatus(status, "libmpq__archive_close");
    }

    /** Best-effort destructor cleanup; errors cannot be thrown here. */
    ~this() {
        if (!closed && handle !is null) libmpq__archive_close(handle);
    }

    /** Return whether this wrapper has released its native archive. */
    bool isClosed() const { return closed; }

    /** Return aggregate archive metadata in one value. */
    ArchiveMetadata metadata() {
        ensureOpen();
        ArchiveMetadata result;
        checkStatus(libmpq__archive_size_packed(handle, &result.packedSize),
                    "libmpq__archive_size_packed");
        checkStatus(libmpq__archive_size_unpacked(handle, &result.unpackedSize),
                    "libmpq__archive_size_unpacked");
        checkStatus(libmpq__archive_offset(handle, &result.offset),
                    "libmpq__archive_offset");
        checkStatus(libmpq__archive_version(handle, &result.version_),
                    "libmpq__archive_version");
        checkStatus(libmpq__archive_files(handle, &result.fileCount),
                    "libmpq__archive_files");
        return result;
    }

    /** Return total packed payload bytes. */ off_t packedSize() { return metadata().packedSize; }
    /** Return total unpacked payload bytes. */ off_t unpackedSize() { return metadata().unpackedSize; }
    /** Return archive start offset. */ off_t offset() { return metadata().offset; }
    /** Return archive format selector. */ uint version_() { return metadata().version_; }
    /** Return number of valid file entries. */ uint fileCount() { return metadata().fileCount; }
    /** Historical property spelling for the entry count. */ uint files() { return fileCount(); }
    /** Historical snake_case spelling for packed aggregate size. */ off_t packed_size() { return packedSize(); }
    /** Historical snake_case spelling for unpacked aggregate size. */ off_t unpacked_size() { return unpackedSize(); }

    /** Resolve a file name through the Storm hash tables. */
    uint fileNumber(string name) {
        ensureOpen(); uint result;
        checkStatus(libmpq__file_number(handle, toStringz(name), &result),
                    "libmpq__file_number");
        return result;
    }

    /** Resolve a precomputed Storm hash through the archive tables. */
    uint fileNumber(StormHash hash) {
        ensureOpen(); uint result;
        checkStatus(libmpq__file_number_from_hash(handle, hash.hash1, hash.hash2,
                                                  hash.hash3, &result),
                    "libmpq__file_number_from_hash");
        return result;
    }

    /** Return a file wrapper resolved by name. */ File file(string name) { return new File(this, name); }
    /** Return a file wrapper resolved by numeric entry. */ File file(uint number) { return new File(this, number); }
    /** Index an archive by name, preserving the historical API. */ File opIndex(string name) { return file(name); }
    /** Index an archive by mutable name for old D callers. */ File opIndex(char[] name) { return file(name.idup); }
    /** Index an archive by entry number, preserving the historical API. */ File opIndex(uint number) { return file(number); }
    /** Index an archive by signed integer for old source compatibility. */
    File opIndex(int number) {
        if (number < 0) throw new MPQException("Archive.opIndex", ERROR_EXIST);
        return file(cast(uint) number);
    }

    /** Add a complete in-memory file to a writer archive. */
    void add(string name, const(ubyte)[] data, FileOptions options = FileOptions.raw()) {
        ensureOpen(); auto nativeOptions = options.nativeOptions();
        checkStatus(libmpq__file_add(handle, toStringz(name), data.ptr,
                                     cast(off_t) data.length, &nativeOptions),
                    "libmpq__file_add");
    }

    /** Add a filesystem file under a chosen archive name. */
    void addPath(string name, string sourcePath, FileOptions options = FileOptions.raw()) {
        ensureOpen(); auto nativeOptions = options.nativeOptions();
        checkStatus(libmpq__file_add_path(handle, toStringz(name), toStringz(sourcePath),
                                          &nativeOptions), "libmpq__file_add_path");
    }

    /** Begin a streaming file writer with a declared unpacked size. */
    MpqFileWriter begin(string name, off_t size, FileOptions options = FileOptions.raw()) {
        ensureOpen(); auto nativeOptions = options.nativeOptions(); mpq_writer_s* writer;
        checkStatus(libmpq__file_begin(handle, toStringz(name), size, &nativeOptions, &writer),
                    "libmpq__file_begin");
        return new MpqFileWriter(writer, size);
    }

    /** Return the raw native handle for advanced ABI integrations. */
    mpq_archive_s* nativeHandle() { ensureOpen(); return handle; }
    /** Historical raw-handle spelling. */ mpq_archive_s* archive() { return nativeHandle(); }

    /** Return `(listfile)` names split into lines, or an empty array. */
    string[] fileList() {
        try {
            return splitLines(cast(string) file("(listfile)").read());
        } catch (MPQException error) {
            if (error.code == ERROR_EXIST)
                return [];
            throw error;
        }
    }
    /** Historical lowercase spelling. */ string[] filelist() { return fileList(); }

    private void ensureOpen() {
        if (closed || handle is null)
            throw new MPQException("Archive", ERROR_NOT_INITIALIZED);
    }
}

/**
 * A file entry borrowed from an archive.
 *
 * The wrapper owns no native memory and is invalid after its archive closes.
 * `read` and `readBlock` return newly allocated D arrays owned by the caller.
 */
class File {
    private Archive archiveRef;
    private uint number;
    private string entryName;

    /** Resolve an entry by numeric index. */
    this(Archive archive, uint number) {
        this.archiveRef = archive; this.number = number;
        if (number >= archive.fileCount()) throw new MPQException("File", ERROR_EXIST);
    }

    /** Resolve an entry by MPQ name. */
    this(Archive archive, string name) {
        this.archiveRef = archive; this.entryName = name;
        this.number = archive.fileNumber(name);
    }

    /** Resolve a mutable D string for old source compatibility. */
    this(Archive archive, char[] name) { this(archive, name.idup); }

    /** Return the public numeric entry index. */ uint no() const { return number; }
    /** Return the requested name, when created by name. */ string name() const { return entryName; }

    /** Query all native metadata for this entry. */
    FileMetadata metadata() {
        auto archive = archiveRef.nativeHandle(); FileMetadata result;
        checkStatus(libmpq__file_size_packed(archive, number, &result.packedSize), "libmpq__file_size_packed");
        checkStatus(libmpq__file_size_unpacked(archive, number, &result.unpackedSize), "libmpq__file_size_unpacked");
        checkStatus(libmpq__file_offset(archive, number, &result.offset), "libmpq__file_offset");
        checkStatus(libmpq__file_blocks(archive, number, &result.blockCount), "libmpq__file_blocks");
        checkStatus(libmpq__file_encrypted(archive, number, &result.encrypted), "libmpq__file_encrypted");
        checkStatus(libmpq__file_compressed(archive, number, &result.compressed), "libmpq__file_compressed");
        checkStatus(libmpq__file_imploded(archive, number, &result.imploded), "libmpq__file_imploded");
        return result;
    }

    /** Return packed size. */ off_t packedSize() { return metadata().packedSize; }
    /** Return unpacked size. */ off_t unpackedSize() { return metadata().unpackedSize; }
    /** Return payload offset. */ off_t offset() { return metadata().offset; }
    /** Return block count. */ uint blockCount() { return metadata().blockCount; }
    /** Return encryption flag. */ uint encrypted() { return metadata().encrypted; }
    /** Return multi-compression flag. */ uint compressed() { return metadata().compressed; }
    /** Return PKWARE implode flag. */ uint imploded() { return metadata().imploded; }

    /** Read the complete unpacked file into a newly allocated D array. */
    ubyte[] read() {
        auto archive = archiveRef.nativeHandle(); auto expected = unpackedSize();
        if (expected < 0 || cast(ulong) expected > size_t.max) throw new MPQException("File.read", ERROR_SIZE);
        ubyte[] result; result.length = cast(size_t) expected; off_t transferred;
        auto pointer = result.length == 0 ? null : result.ptr;
        checkStatus(libmpq__file_read(archive, number, pointer, expected, &transferred), "libmpq__file_read");
        if (transferred < 0 || cast(ulong) transferred > result.length) throw new MPQException("File.read", ERROR_SIZE);
        result.length = cast(size_t) transferred; return result;
    }

    /** Read one unpacked block after opening its offset table. */
    ubyte[] readBlock(uint blockNumber) {
        auto archive = archiveRef.nativeHandle();
        checkStatus(libmpq__block_open_offset(archive, number), "libmpq__block_open_offset");
        /* Do not let cleanup hide the primary read/decompression exception. */
        scope(failure) libmpq__block_close_offset(archive, number);
        off_t expected;
        checkStatus(libmpq__block_size_unpacked(archive, number, blockNumber, &expected), "libmpq__block_size_unpacked");
        if (expected < 0 || cast(ulong) expected > size_t.max) throw new MPQException("File.readBlock", ERROR_SIZE);
        ubyte[] result; result.length = cast(size_t) expected; off_t transferred;
        auto pointer = result.length == 0 ? null : result.ptr;
        checkStatus(libmpq__block_read(archive, number, blockNumber, pointer, expected, &transferred), "libmpq__block_read");
        if (transferred < 0 || cast(ulong) transferred > result.length) throw new MPQException("File.readBlock", ERROR_SIZE);
        checkStatus(libmpq__block_close_offset(archive, number), "libmpq__block_close_offset");
        result.length = cast(size_t) transferred; return result;
    }

    /** Historical snake_case aliases. */ off_t packed_size() { return packedSize(); }
    /** Historical snake_case alias. */ off_t unpacked_size() { return unpackedSize(); }
    /** Historical snake_case alias. */ uint blocks() { return blockCount(); }
    /** Historical property spelling for the entry number. */ uint fileno() { return no(); }
}

/** A streaming writer returned by `Archive.begin`. */
class MpqFileWriter {
    private mpq_writer_s* handle; private off_t declaredSize; private off_t writtenSize; private bool finishedState;
    private this(mpq_writer_s* handle, off_t declaredSize) { this.handle = handle; this.declaredSize = declaredSize; }

    /** Append bytes; the input array is borrowed only for this call. */
    void write(const(ubyte)[] data) {
        ensureActive();
        if (writtenSize > declaredSize || data.length > cast(size_t) (declaredSize - writtenSize))
            throw new MPQException("MpqFileWriter.write", ERROR_SIZE);
        checkStatus(libmpq__file_write(handle, data.ptr, cast(off_t) data.length), "libmpq__file_write");
        writtenSize += cast(off_t) data.length;
    }
    /** Finish and publish the entry, invalidating state before native cleanup. */
    void finish() {
        ensureActive();
        auto current = handle;
        handle = null;
        finishedState = true;
        checkStatus(libmpq__file_finish(current), "libmpq__file_finish");
    }
    /** Return whether the writer was finalized. */ bool finished() const { return finishedState; }
    /** Return bytes submitted so far. */ off_t written() const { return writtenSize; }
    /** Return the declared unpacked size. */ off_t declared() const { return declaredSize; }
    /** Finish an active stream, matching D's explicit resource-close pattern. */
    void close() {
        if (finishedState) return;
        auto current = handle;
        handle = null;
        finishedState = true;
        checkStatus(libmpq__file_finish(current), "libmpq__file_finish");
    }
    /** Best-effort destructor cleanup; destructors cannot report errors. */
    ~this() { if (!finishedState && handle !is null) libmpq__file_finish(handle); }
    private void ensureActive() { if (finishedState || handle is null) throw new MPQException("MpqFileWriter", ERROR_NOT_INITIALIZED); }
}

/** Compatibility alias for the shorter historical writer name. */
alias MpqFileWriter FileWriter;
