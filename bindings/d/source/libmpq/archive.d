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

import core.memory : GC;
import std.string : splitLines, toStringz;
import libmpq.errors : MPQException, checkStatus;
import libmpq.native;
import libmpq.options : ArchiveCreateOptions, FileOptions;
import std.typecons : Nullable, nullable;

/** Stored filename identity; flags describe provenance, not storage flags. */
struct FileIdentity {
    uint fileNumber;
    uint flags;
    ushort locale;
    ushort platform;
}

/** Owned stored metadata; complete lossless reads verify available CRC32/MD5 hashes. */
struct FileAttributes {
    uint flags;
    uint crc32;
    ulong filetime;
    ubyte[16] md5;
    bool patchBit;
}

/** Stored sector Adler-32 and zero or VERIFY_SECTOR_CRC mismatch bits. */
struct BlockVerification { uint checksum; uint mismatches; }

/** Member coverage masks, independent of signature trust or whole-archive integrity. */
struct VerificationResult { uint checked; uint unavailable; uint mismatches; }

/** The three Storm hash values used by classic MPQ name lookup. */
struct StormHash { uint hash1; uint hash2; uint hash3; }

/** Aggregate metadata describing an opened archive. */
struct ArchiveMetadata {
    /** Sum of stored sizes of live canonical entries. */ off_t packedSize;
    /** Sum of logical sizes of live canonical entries. */ off_t unpackedSize;
    /** Archive origin in the backing source. */ off_t offset;
    /** MPQ generation (1 through 4). */ uint version_;
    /** Count of live canonical entries, including stored internal members where present. */ uint fileCount;
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

/** Caller-owned exact random-access source for Archive.openSource. */
interface MpqSource {
    ulong size();
    void readAt(ulong offset, ubyte[] buffer);
}

/* Shared GC-owned state retained by archives and streams using one source. */
private class SourceState {
    MpqSource source;
    ulong size;

    this(MpqSource source, ulong size) {
        this.source = source;
        this.size = size;
    }
}

private extern(C) int
sourceReadAt(void* context, off_t offset, ubyte* buffer, size_t size)
{
    try {
        auto state = cast(SourceState) context;
        if (state is null || offset < 0 || cast(ulong)offset > state.size ||
            size > state.size - cast(ulong)offset)
            return ERROR_READ;
        state.source.readAt(cast(ulong)offset, buffer[0 .. size]);
        return 0;
    } catch (Throwable) {
        return ERROR_READ;
    }
}

/** Exact positioned write into a borrowed sink. Throw on incomplete transfer. */
alias MpqWriteAt = void delegate(off_t offset, scope const(ubyte)[] buffer);
/** Exact positioned read. Fill the full borrowed slice or throw. */
alias MpqReadAt = void delegate(off_t offset, scope ubyte[] buffer);
/** Optional final sink operation. Throw on failure. */
alias MpqFlushSink = void delegate();

private class SinkState {
    MpqWriteAt writeAt;
    MpqReadAt readAt;
    MpqFlushSink flush;
    bool closed;

    this(MpqWriteAt writeAt, MpqReadAt readAt, MpqFlushSink flush) {
        this.writeAt = writeAt;
        this.readAt = readAt;
        this.flush = flush;
    }
}

private extern(C) int sinkWriteAt(void* context, off_t offset, const(ubyte)* buffer, size_t size) {
    try {
        auto state = cast(SinkState) context;
        if (state.closed)
            return ERROR_WRITE;
        state.writeAt(offset, buffer[0 .. size]);
        return 0;
    } catch (Throwable) {
        return ERROR_WRITE;
    }
}

private extern(C) int sinkReadAt(void* context, off_t offset, ubyte* buffer, size_t size) {
    try {
        auto state = cast(SinkState) context;
        if (state.closed)
            return ERROR_READ;
        state.readAt(offset, buffer[0 .. size]);
        return 0;
    } catch (Throwable) {
        return ERROR_READ;
    }
}

private extern(C) int sinkFlush(void* context) {
    try {
        auto state = cast(SinkState) context;
        if (state.closed)
            return ERROR_CLOSE;
        state.flush();
        return 0;
    } catch (Throwable) {
        return ERROR_CLOSE;
    }
}

/**
 * An opened or newly created MPQ archive.
 *
 * The object owns the native handle. Call `close` explicitly, preferably with
 * `scope(exit) archive.close()`, because D destructors cannot report close
 * errors. A closed archive must not be used again.
 */
class Archive {
    /** Detect structurally valid weak and strong signatures; absence returns zero. */
    uint signatures() {
        uint result;
        checkStatus(libmpq__archive_signatures(nativeHandle(), &result), "libmpq__archive_signatures");
        return result;
    }

    /** Verify archive structural and RAW metadata. Use verify() for digital signatures. */
    VerificationResult verifyEx(uint flags = VERIFY_METADATA_ALL) {
        VerificationResult result;
        checkStatus(libmpq__archive_verify_ex(nativeHandle(), flags,
            &result.checked, &result.unavailable, &result.mismatches), "libmpq__archive_verify_ex");
        return result;
    }

    /** Verify a weak signature and return mismatch bits. */
    uint verify(const(ubyte)[] publicKey) {
        return verify(publicKey, SIGNATURE_WEAK);
    }

    /** Verify the selected signature type and return mismatch bits. */
    uint verify(const(ubyte)[] publicKey, uint signatureType) {
        uint result;
        checkStatus(libmpq__archive_verify(nativeHandle(), signatureType,
                    publicKey.ptr, publicKey.length, &result), "libmpq__archive_verify");
        return result;
    }

    /** Configure weak signing using a 128-byte key: 64-byte big-endian n then d. */
    void sign(const(ubyte)[] privateKey) {
        sign(privateKey, SIGNATURE_WEAK);
    }

    /** Configure weak or plain strong signing using the selected raw private key. */
    void sign(const(ubyte)[] privateKey, uint signatureType) {
        checkStatus(libmpq__archive_sign(nativeHandle(), signatureType,
                    privateKey.ptr, privateKey.length), "libmpq__archive_sign");
    }
    /** Return archive-wide stored attribute flags, or null if absent. Malformed metadata still throws. */
    Nullable!uint attributes() {
        uint flags;
        auto status = libmpq__archive_attributes(nativeHandle(), &flags);
        if (status == ERROR_EXIST) return Nullable!uint.init;
        checkStatus(status, "libmpq__archive_attributes");
        return nullable(flags);
    }
    private mpq_archive_s* handle;
    private bool closed;
    private SourceState sourceState;
    private SinkState sinkState;

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
    static Archive openMpqe(string path, const(ubyte)[] authCode,
                            off_t offset = -1) {
        mpq_archive_s* result;
        auto authPointer = authCode.length == 0 ? null : authCode.ptr;
        checkStatus(libmpq__archive_open_mpqe(&result, toStringz(path), offset, authPointer,
                                               authCode.length),
                    "libmpq__archive_open_mpqe");
        return new Archive(result);
    }

    /** Open a borrowed typed random-access source; the source remains caller-owned. */
    static Archive openSource(MpqSource source, string sourceName = null,
                              off_t offset = -1) {
        auto sourceSize = source is null ? ulong.max : source.size();
        if (source is null || sourceSize > cast(ulong)long.max)
            throw new MPQException("Archive.openSource", ERROR_SIZE);
        auto state = new SourceState(source, sourceSize);
        mpq_archive_s* result;
        auto name = sourceName is null ? null : toStringz(sourceName);
        checkStatus(libmpq__archive_open_io(&result, cast(void*)state, &sourceReadAt,
                                             cast(off_t)state.size, offset, name),
                    "libmpq__archive_open_io");
        auto archive = new Archive(result);
        archive.sourceState = state;
        return archive;
    }

    /** Open a borrowed typed MPQE source; the source remains caller-owned. */
    static Archive openMpqeSource(MpqSource source, const(ubyte)[] authCode,
                                  string sourceName = null, off_t offset = -1) {
        auto sourceSize = source is null ? ulong.max : source.size();
        if (source is null || sourceSize > cast(ulong)long.max)
            throw new MPQException("Archive.openMpqeSource", ERROR_SIZE);
        auto state = new SourceState(source, sourceSize);
        mpq_archive_s* result;
        auto name = sourceName is null ? null : toStringz(sourceName);
        auto authPointer = authCode.length == 0 ? null : authCode.ptr;
        checkStatus(libmpq__archive_open_mpqe_io(&result, cast(void*)state, &sourceReadAt,
                                                  cast(off_t)state.size, offset, authPointer,
                                                  authCode.length, name),
                    "libmpq__archive_open_mpqe_io");
        auto archive = new Archive(result);
        archive.sourceState = state;
        return archive;
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

    /**
     * Create a fresh archive over exact positioned output delegates.
     * The owner supplies an empty sink with zero-filled gaps. Read-back is
     * required for v4 and signing. Explicit close finalizes without owning
     * or closing the sink. Delegates must not retain the borrowed slices.
     */
    static Archive createSink(MpqWriteAt writeAt,
                               ArchiveCreateOptions options = ArchiveCreateOptions.v1(),
                               MpqReadAt readAt = null, MpqFlushSink flush = null) {
        return createSinkInternal(writeAt, options, readAt, flush, null, false);
    }

    /** Create MPQE transport output at close over a borrowed write-only sink. */
    static Archive createMpqeSink(MpqWriteAt writeAt, const(ubyte)[] authCode,
                                   ArchiveCreateOptions options = ArchiveCreateOptions.v1(),
                                   MpqFlushSink flush = null) {
        return createSinkInternal(writeAt, options, null, flush, authCode, true);
    }

    private static Archive createSinkInternal(MpqWriteAt writeAt, ArchiveCreateOptions options,
                                              MpqReadAt readAt, MpqFlushSink flush,
                                              const(ubyte)[] authCode, bool wrapped) {
        if (writeAt is null)
            throw new MPQException("Archive.createSink", ERROR_EXIST);
        auto state = new SinkState(writeAt, readAt, flush);
        GC.addRoot(cast(void*) state);
        scope(failure) GC.removeRoot(cast(void*) state);
        auto nativeOptions = options.nativeOptions();
        auto archive = new Archive(cast(mpq_archive_s*) null);
        if (wrapped) {
            checkStatus(libmpq__archive_create_mpqe_io(&archive.handle, cast(void*) state,
                        null, &sinkWriteAt, flush is null ? null : &sinkFlush,
                        authCode.ptr, authCode.length, &nativeOptions),
                        "libmpq__archive_create_mpqe_io");
        } else {
            checkStatus(libmpq__archive_create_io(&archive.handle, cast(void*) state,
                        readAt is null ? null : &sinkReadAt, &sinkWriteAt,
                        flush is null ? null : &sinkFlush, &nativeOptions),
                        "libmpq__archive_create_io");
        }
        archive.sinkState = state;
        return archive;
    }

    /** Create a new MPQE-wrapped archive with borrowed authentication bytes. */
    static Archive createMpqe(string path, const(ubyte)[] authCode,
                              ArchiveCreateOptions options = ArchiveCreateOptions.v1()) {
        auto nativeOptions = options.nativeOptions();
        mpq_archive_s* result;
        auto authPointer = authCode.length == 0 ? null : authCode.ptr;
        checkStatus(libmpq__archive_create_mpqe(&result, toStringz(path), authPointer,
                                                 authCode.length, &nativeOptions),
                    "libmpq__archive_create_mpqe");
        return new Archive(result);
    }

    /** Materialize borrowed ordered layers as an independently owned archive.
     * Supply one prefix per layer, or null to infer all. Null entries infer
     * individual prefixes. An empty slice with a nonnull pointer selects root.
     * Keep inputs alive during the call. The result retains no input sources.
     */
    static Archive openPatch(Archive base, Archive[] patches, const(string)[] prefixes = null) {
        if (base is null) throw new MPQException("null base", ERROR_EXIST);
        auto inputs = preparePatchInputs(base, patches, prefixes);
        GC.addRoot(cast(void*) inputs);
        scope(exit) GC.removeRoot(cast(void*) inputs);
        mpq_archive_s* result;
        checkStatus(libmpq__archive_open_patch(&result, base.nativeHandle(),
                    inputs.handles.ptr, inputs.names.ptr, patches.length),
                    "libmpq__archive_open_patch");
        scope(failure) libmpq__archive_close(result);
        return new Archive(result);
    }

    private static struct PatchInputs {
        Archive base;
        Archive[] layers;
        mpq_archive_s*[] handles;
        const(char)*[] names;
        const(char)* filename;
    }

    private static PatchInputs* preparePatchInputs(
        Archive base, Archive[] patches, const(string)[] prefixes
    ) {
        if (prefixes.ptr !is null && prefixes.length != patches.length)
            throw new MPQException("prefix count must match patch count", ERROR_SIZE);
        auto inputs = new PatchInputs;
        inputs.base = base;
        inputs.layers = patches.dup;
        inputs.handles.length = patches.length;
        if (prefixes.ptr !is null) inputs.names.length = patches.length;
        foreach (i, layer; inputs.layers) {
            if (layer is null) throw new MPQException("null patch layer", ERROR_EXIST);
            inputs.handles[i] = layer.nativeHandle();
            if (prefixes.ptr !is null && prefixes[i].ptr !is null) {
                foreach (character; prefixes[i])
                    if (character == 0) throw new MPQException("NUL prefix", ERROR_FORMAT);
                inputs.names[i] = toStringz(prefixes[i]);
            }
        }
        return inputs;
    }

    /**
     * Open using ordinary lookup in the final patched view. Prefixes follow
     * openPatch. Opening reconstructs and verifies the selected result in
     * private scratch storage. The inputs can close after successful open.
     * Closing the stream releases that storage.
     */
    MpqStream openPatchStream(string name, Archive[] patches, const(string)[] prefixes = null) {
        return openPatchStreamImpl(name, patches, prefixes, false, 0, 0);
    }

    /** Open the exact tuple, including (0, 0), without fallback. Prefixes
     * follow openPatch, and the result owns its private scratch storage. */
    MpqStream openPatchStream(string name, ushort locale, ushort platform, Archive[] patches,
                              const(string)[] prefixes = null) {
        return openPatchStreamImpl(name, patches, prefixes, true, locale, platform);
    }

    private MpqStream openPatchStreamImpl(string name, Archive[] patches, const(string)[] prefixes,
                                          bool exact, ushort locale, ushort platform) {
        if (name.length == 0) throw new MPQException("empty filename", ERROR_EXIST);
        foreach (character; name)
            if (character == 0) throw new MPQException("NUL filename", ERROR_FORMAT);
        auto inputs = preparePatchInputs(this, patches, prefixes);
        GC.addRoot(cast(void*) inputs);
        scope(exit) GC.removeRoot(cast(void*) inputs);
        inputs.filename = toStringz(name);
        mpq_stream_s* stream;
        if (exact)
            checkStatus(libmpq__stream_open_patch_identity(nativeHandle(), inputs.handles.ptr,
                        inputs.names.ptr, patches.length, inputs.filename, locale, platform, &stream),
                        "libmpq__stream_open_patch_identity");
        else
            checkStatus(libmpq__stream_open_patch(nativeHandle(), inputs.handles.ptr,
                        inputs.names.ptr, patches.length, inputs.filename, &stream),
                        "libmpq__stream_open_patch");
        scope(failure) libmpq__stream_close(stream);
        return new MpqStream(stream);
    }

    /** Configure v4 raw MD5 before member begin, signing or finalization. */
    void setRawChunkSize(uint size) {
        ensureOpen();
        checkStatus(libmpq__archive_raw_chunk_size_set(handle, size),
                    "libmpq__archive_raw_chunk_size_set");
    }

    /** Return configured/loaded raw size; older archive generations return zero. */
    uint getRawChunkSize() {
        ensureOpen();
        uint result;
        checkStatus(libmpq__archive_raw_chunk_size_get(handle, &result),
                    "libmpq__archive_raw_chunk_size_get");
        return result;
    }

    /** Return an independently parsed clone of this archive. */
    Archive clone() {
        ensureOpen();
        mpq_archive_s* result;
        checkStatus(libmpq__archive_clone(&result, handle),
                    "libmpq__archive_clone");
        auto clone = new Archive(result);
        clone.sourceState = sourceState;
        return clone;
    }

    /** Close the native handle; repeated calls are harmless. */
    void close() {
        if (closed) return;
        auto status = libmpq__archive_close(handle);
        closed = true;
        handle = null;
        sourceState = null;
        releaseSink();
        checkStatus(status, "libmpq__archive_close");
    }

    /** Best-effort destructor cleanup; errors cannot be thrown here. */
    ~this() {
        if (!closed && handle !is null) {
            if (sinkState !is null)
                sinkState.closed = true;
            libmpq__archive_close(handle);
        }
        releaseSink();
    }

    private void releaseSink() {
        if (sinkState !is null) {
            sinkState.closed = true;
            sinkState.writeAt = null;
            sinkState.readAt = null;
            sinkState.flush = null;
            GC.removeRoot(cast(void*) sinkState);
            sinkState = null;
        }
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
    /** Return the archive origin in the backing source, which can be nonzero for embedded MPQs. */ off_t offset() { return metadata().offset; }
    /** Return the MPQ generation (1 through 4). */ uint version_() { return metadata().version_; }
    /** Return the count of live canonical entries, including stored internal members where present. */ uint fileCount() { return metadata().fileCount; }

    /** Enumerate reachable identities in their original classic slot order. */
    FileIdentity[] variants(string name) {
        ensureOpen();
        FileIdentity[] result;
        auto encoded = toStringz(name);
        for (ulong ordinal = 0; ordinal <= uint.max; ordinal++) {
            mpq_file_identity_s identity;
            auto status = libmpq__file_identity(handle, encoded, cast(uint)ordinal, &identity);
            if (status == ERROR_EXIST) return result;
            checkStatus(status, "libmpq__file_identity");
            result ~= FileIdentity(identity.file_number, identity.flags, identity.locale, identity.platform);
        }
        throw new MPQException("Archive.variants", ERROR_SIZE);
    }

    /**
     * Select the exact locale/platform tuple using classic and supported
     * HET/BET identities. A HET/BET-only identity accepts only (0, 0).
     * No selector fallback is applied.
     */
    uint fileNumber(string name, ushort locale, ushort platform) {
        ensureOpen();
        uint result;
        checkStatus(libmpq__file_number_from_identity(handle, toStringz(name), locale, platform, &result),
                    "libmpq__file_number_from_identity");
        return result;
    }

    /** Open the exact tuple on an owned clone sharing any caller-owned source. */
    MpqStream openStream(string name, ushort locale, ushort platform) {
        ensureOpen();
        mpq_stream_s* result;
        checkStatus(libmpq__stream_open_name_identity(handle, toStringz(name), locale, platform, &result),
                    "libmpq__stream_open_name_identity");
        return new MpqStream(result, sourceState);
    }

    /** Resolve a filename through HET/BET when present, falling back to classic lookup on a miss. */
    uint fileNumber(string name) {
        ensureOpen(); uint result;
        checkStatus(libmpq__file_number(handle, toStringz(name), &result),
                    "libmpq__file_number");
        return result;
    }

    /**
     * Resolve precomputed Storm hashes using only the classic hash table.
     * HET/BET needs the filename to compute a separate hash. Use the
     * filename overload for filename-aware lookup.
     */
    uint fileNumber(StormHash hash) {
        ensureOpen(); uint result;
        checkStatus(libmpq__file_number_from_hash(handle, hash.hash1, hash.hash2,
                                                  hash.hash3, &result),
                    "libmpq__file_number_from_hash");
        return result;
    }

    /** Return a file wrapper resolved by name. */ File file(string name) { return new File(this, name); }
    /** Return a file wrapper resolved by numeric entry. */ File file(uint number) { return new File(this, number); }
    /** Index an archive by name. */ File opIndex(string name) { return file(name); }
    /** Index an archive by mutable name. */ File opIndex(char[] name) { return file(name.idup); }
    /** Index an archive by entry number. */ File opIndex(uint number) { return file(number); }
    /** Index an archive by signed integer, rejecting negative indices. */
    File opIndex(int number) {
        if (number < 0) throw new MPQException("Archive.opIndex", ERROR_EXIST);
        return file(cast(uint) number);
    }

    /** Open by file number on an owned clone sharing any caller-owned source. */
    MpqStream openStream(uint number) {
        ensureOpen();
        mpq_stream_s* result;
        checkStatus(libmpq__stream_open(handle, number, &result), "libmpq__stream_open");
        return new MpqStream(result, sourceState);
    }

    /** Open by ordinary filename lookup on an owned clone sharing any caller-owned source. */
    MpqStream openStream(string name) {
        ensureOpen();
        mpq_stream_s* result;
        checkStatus(libmpq__stream_open_name(handle, toStringz(name), &result),
                    "libmpq__stream_open_name");
        return new MpqStream(result, sourceState);
    }

    /** Add a complete in-memory file to a writer archive. */
    void add(string name, const(ubyte)[] data, FileOptions options = FileOptions.raw()) {
        ensureOpen(); auto nativeOptions = options.nativeOptions();
        checkStatus(libmpq__archive_add_data(handle, toStringz(name), data.ptr,
                                     cast(off_t) data.length, &nativeOptions),
                    "libmpq__archive_add_data");
    }

    /** Add a filesystem file under a chosen archive name. */
    void addPath(string name, string sourcePath, FileOptions options = FileOptions.raw()) {
        ensureOpen(); auto nativeOptions = options.nativeOptions();
        checkStatus(libmpq__archive_add_path(handle, toStringz(name), toStringz(sourcePath),
                                          &nativeOptions), "libmpq__archive_add_path");
    }

    /** Begin a streaming file writer with a declared unpacked size. */
    MpqFileWriter begin(string name, off_t size, FileOptions options = FileOptions.raw()) {
        ensureOpen(); auto nativeOptions = options.nativeOptions(); mpq_writer_s* writer;
        checkStatus(libmpq__writer_begin(handle, toStringz(name), size, &nativeOptions, &writer),
                    "libmpq__writer_begin");
        return new MpqFileWriter(writer, size, sinkState);
    }

    /** Return the raw native handle for advanced ABI integrations. */
    mpq_archive_s* nativeHandle() { ensureOpen(); return handle; }

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

    private void ensureOpen() {
        if (closed || handle is null)
            throw new MPQException("Archive", ERROR_NOT_INITIALIZED);
    }
}

/** Seek origins accepted by MpqStream.seek. */
enum SeekOrigin : int {
    set = LIBMPQ_SEEK_SET,
    current = LIBMPQ_SEEK_CUR,
    end = LIBMPQ_SEEK_END
}

/**
 * Incremental, seekable decoded member stream.
 *
 * The native stream owns a private archive clone, so it remains usable after
 * its originating Archive is closed.
 */
class MpqStream {
    private mpq_stream_s* handle;
    private bool closed;
    private SourceState sourceState;

    private this(mpq_stream_s* handle, SourceState sourceState = null) {
        this.handle = handle;
        this.sourceState = sourceState;
    }

    /** Read up to the supplied buffer length and return the copied byte count. */
    size_t read(ubyte[] buffer) {
        ensureOpen();
        off_t transferred;
        auto pointer = buffer.length == 0 ? null : buffer.ptr;
        checkStatus(libmpq__stream_read(handle, pointer, cast(off_t) buffer.length, &transferred),
                    "libmpq__stream_read");
        if (transferred < 0 || cast(ulong) transferred > buffer.length)
            throw new MPQException("MpqStream.read", ERROR_SIZE);
        return cast(size_t) transferred;
    }

    /** Seek to a position from the selected origin. */
    void seek(off_t offset, SeekOrigin origin = SeekOrigin.set) {
        ensureOpen();
        checkStatus(libmpq__stream_seek(handle, offset, cast(int) origin),
                    "libmpq__stream_seek");
    }

    /** Return the current logical position without archive I/O. */
    off_t tell() {
        ensureOpen();
        off_t result;
        checkStatus(libmpq__stream_tell(handle, &result), "libmpq__stream_tell");
        return result;
    }

    /** Return the immutable unpacked member size without archive I/O. */
    off_t size() {
        ensureOpen();
        off_t result;
        checkStatus(libmpq__stream_size(handle, &result), "libmpq__stream_size");
        return result;
    }

    /** Consume the native stream; repeated calls are harmless. */
    void close() {
        if (closed) return;
        auto current = handle;
        handle = null;
        closed = true;
        auto status = libmpq__stream_close(current);
        sourceState = null;
        checkStatus(status, "libmpq__stream_close");
    }

    /** Best-effort cleanup because D destructors cannot report errors. */
    ~this() {
        if (!closed && handle !is null) libmpq__stream_close(handle);
    }

    private void ensureOpen() {
        if (closed || handle is null)
            throw new MPQException("MpqStream", ERROR_NOT_INITIALIZED);
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

    /** Resolve an entry by mutable name. */
    this(Archive archive, char[] name) { this(archive, name.idup); }

    /** Return the public numeric entry index. */ uint no() const { return number; }

    /** Return member coverage; optional filename supplies synchronous key context. */
    VerificationResult verifyResult(uint flags = VERIFY_ALL, string filename = null) {
        VerificationResult result;
        import std.algorithm.searching : canFind;
        if (filename.canFind('\0'))
            throw new MPQException("File.verifyResult", ERROR_FORMAT);
        checkStatus(libmpq__file_verify_ex(archiveRef.nativeHandle(), number,
                    filename is null ? null : filename.toStringz, flags,
                    &result.checked, &result.unavailable, &result.mismatches),
                    "libmpq__file_verify_ex");
        return result;
    }

    /** Return mismatches as a subset of flags; missing values are skipped.
     * File checks require attributes; sector-only checks do not. Errors throw. */
    uint verify(uint flags = VERIFY_ALL) {
        uint mismatches;
        checkStatus(libmpq__file_verify(archiveRef.nativeHandle(), number, flags, &mismatches),
                    "libmpq__file_verify");
        return mismatches;
    }

    /** Verify one sector. Missing/unused checksums throw ERROR_EXIST. */
    BlockVerification verifyBlock(uint block) {
        BlockVerification value;
        checkStatus(libmpq__block_verify(archiveRef.nativeHandle(), number, block,
                                        &value.checksum, &value.mismatches),
                    "libmpq__block_verify");
        return value;
    }

    /**
     * Return stored member attributes without verifying them.
     * MPQException carries ERROR_FORMAT when a valid classic block-table row
     * is missing, even if a BET-only member is readable. A valid classic row
     * without an applicable attributes file yields ERROR_EXIST.
     */
    FileAttributes attributes() {
        mpq_file_attributes_s value;
        checkStatus(libmpq__file_attributes(archiveRef.nativeHandle(), number, &value),
                    "libmpq__file_attributes");
        return FileAttributes(value.flags, value.crc32, value.filetime, value.md5,
                              value.patch_bit != 0);
    }
    /** Return the requested name, when created by name. */ string name() const { return entryName; }

    /** Return the stored MPQ block-table flags. */
    uint flags() {
        uint value;
        checkStatus(libmpq__file_flags(archiveRef.nativeHandle(), number, &value),
                    "libmpq__file_flags");
        return value;
    }

    /** Query all native metadata for this entry. */
    FileMetadata metadata() {
        auto archive = archiveRef.nativeHandle(); FileMetadata result;
        checkStatus(libmpq__file_size_packed(archive, number, &result.packedSize), "libmpq__file_size_packed");
        checkStatus(libmpq__file_size_unpacked(archive, number, &result.unpackedSize), "libmpq__file_size_unpacked");
        checkStatus(libmpq__file_offset(archive, number, &result.offset), "libmpq__file_offset");
        checkStatus(libmpq__file_blocks(archive, number, &result.blockCount), "libmpq__file_blocks");
        auto storage = flags();
        result.encrypted = (storage & FILE_FLAG_ENCRYPTED) != 0;
        result.compressed = (storage & FILE_FLAG_COMPRESS) != 0;
        result.imploded = (storage & FILE_FLAG_IMPLODE) != 0;
        return result;
    }

    /** Return packed size. */ off_t packedSize() { return metadata().packedSize; }
    /** Return unpacked size. */ off_t unpackedSize() { return metadata().unpackedSize; }
    /** Return the stored payload offset relative to the start of the MPQ. */ off_t offset() { return metadata().offset; }
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

    /** Return decoded PTCH size, distinct from the final patched target size. */
    off_t patchPayloadSize() {
        off_t size;
        checkStatus(libmpq__patch_payload_size(archiveRef.nativeHandle(), number, &size),
                    "libmpq__patch_payload_size");
        return size;
    }

    /** Return caller-owned validated PTCH bytes, without its prefix or patch application.
     * Supply the physical member filename when encryption needs a named key.
     */
    ubyte[] readPatchPayload(string filename = null) {
        auto archive = archiveRef.nativeHandle();
        auto expected = patchPayloadSize();
        if (expected < 0 || cast(ulong) expected > size_t.max)
            throw new MPQException("File.readPatchPayload", ERROR_SIZE);
        ubyte[] result; result.length = cast(size_t) expected;
        off_t transferred;
        checkStatus(libmpq__patch_payload_read(archive, number,
                    filename is null ? null : toStringz(filename),
                    result.length == 0 ? null : result.ptr, expected, &transferred),
                    "libmpq__patch_payload_read");
        if (transferred < 0 || cast(ulong) transferred > result.length)
            throw new MPQException("File.readPatchPayload", ERROR_SIZE);
        result.length = cast(size_t) transferred;
        return result;
    }

    /** Return stored data bytes for one block, excluding offset/checksum tables. */
    off_t blockSizePacked(uint blockNumber) {
        off_t value;
        checkStatus(libmpq__block_size_packed(archiveRef.nativeHandle(), number, blockNumber,
                                            &value), "libmpq__block_size_packed");
        return value;
    }

    /** Return the stored method byte (not a writer selector), or zero for raw storage. */
    uint blockCompression(uint blockNumber) {
        uint value;
        checkStatus(libmpq__block_compression(archiveRef.nativeHandle(), number, blockNumber,
                                            &value), "libmpq__block_compression");
        return value;
    }

    /** Read one unpacked block; native code manages its offset cache. */
    ubyte[] readBlock(uint blockNumber) {
        auto archive = archiveRef.nativeHandle();
        off_t expected;
        checkStatus(libmpq__block_size_unpacked(archive, number, blockNumber, &expected), "libmpq__block_size_unpacked");
        if (expected < 0 || cast(ulong) expected > size_t.max) throw new MPQException("File.readBlock", ERROR_SIZE);
        ubyte[] result; result.length = cast(size_t) expected; off_t transferred;
        auto pointer = result.length == 0 ? null : result.ptr;
        checkStatus(libmpq__block_read(archive, number, blockNumber, pointer, expected, &transferred), "libmpq__block_read");
        if (transferred < 0 || cast(ulong) transferred > result.length) throw new MPQException("File.readBlock", ERROR_SIZE);
        result.length = cast(size_t) transferred; return result;
    }

}

/** A streaming writer returned by `Archive.begin`. */
class MpqFileWriter {
    /** Set Windows FILETIME, not Unix time; the archive must enable its generation. */
    void timestamp(ulong filetime) {
        ensureActive();
        checkStatus(libmpq__writer_timestamp(handle, filetime), "libmpq__writer_timestamp");
    }
    private mpq_writer_s* handle; private off_t declaredSize; private off_t writtenSize; private bool finishedState;
    private SinkState sinkState;
    private this(mpq_writer_s* handle, off_t declaredSize, SinkState sinkState) {
        this.handle = handle;
        this.declaredSize = declaredSize;
        this.sinkState = sinkState;
    }

    /** Append bytes; the input array is borrowed only for this call. */
    void write(const(ubyte)[] data) {
        ensureActive();
        if (writtenSize > declaredSize || data.length > cast(size_t) (declaredSize - writtenSize))
            throw new MPQException("MpqFileWriter.write", ERROR_SIZE);
        checkStatus(libmpq__writer_write(handle, data.ptr, cast(off_t) data.length), "libmpq__writer_write");
        writtenSize += cast(off_t) data.length;
    }
    /** Finish and publish the entry, invalidating state before native cleanup. */
    void finish() {
        ensureActive();
        auto current = handle;
        handle = null;
        finishedState = true;
        checkStatus(libmpq__writer_finish(current), "libmpq__writer_finish");
    }
    /** Return whether the writer was finalized. */ bool finished() const { return finishedState; }
    /** Return bytes submitted so far. */ off_t written() const { return writtenSize; }
    /** Return the declared unpacked size. */ off_t declared() const { return declaredSize; }
    /** Finish an active stream, matching D's explicit resource-close pattern. */
    void close() {
        if (finishedState || (sinkState !is null && sinkState.closed)) return;
        auto current = handle;
        handle = null;
        finishedState = true;
        checkStatus(libmpq__writer_finish(current), "libmpq__writer_finish");
    }
    /** Best-effort destructor cleanup; destructors cannot report errors. */
    ~this() {
        if (sinkState is null && !finishedState && handle !is null)
            libmpq__writer_finish(handle);
    }
    private void ensureActive() {
        if (finishedState || handle is null || (sinkState !is null && sinkState.closed))
            throw new MPQException("MpqFileWriter", ERROR_NOT_INITIALIZED);
    }
}
