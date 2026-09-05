# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

"""Typed Python 3.11+ ctypes bindings for the public libmpq API."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from dataclasses import dataclass

ERROR_OPEN = -1
ERROR_CLOSE = -2
ERROR_SEEK = -3
ERROR_READ = -4
ERROR_WRITE = -5
ERROR_MALLOC = -6
ERROR_FORMAT = -7
ERROR_NOT_INITIALIZED = -8
ERROR_SIZE = -9
ERROR_EXIST = -10
ERROR_DECRYPT = -11
ERROR_UNPACK = -12

ARCHIVE_VERSION_ONE = 0
ARCHIVE_VERSION_TWO = 1
ARCHIVE_CREATE_LISTFILE = 0x00000001
FILE_FLAG_IMPLODE = 0x00000100
FILE_FLAG_COMPRESS = 0x00000200
FILE_FLAG_ENCRYPTED = 0x00010000
FILE_FLAG_SINGLE = 0x01000000
COMPRESSION_HUFFMAN = 0x01
COMPRESSION_ZLIB = 0x02
COMPRESSION_PKZIP = 0x08
COMPRESSION_BZIP2 = 0x10
COMPRESSION_WAVE_MONO = 0x40
COMPRESSION_WAVE_STEREO = 0x80

_OFF_T = ctypes.c_int64
_BYTE_PTR = ctypes.POINTER(ctypes.c_uint8)
_VOID_PTR = ctypes.c_void_p


def _native_buffer(size):
    """Allocate a writable uint8 array accepted by ctypes pointer arguments."""
    return (_BYTE_PTR._type_ * max(1, int(size)))()


def _candidate_library_names():
    """Return platform shared-library names in preferred loading order."""
    if os.name == "nt":
        return ("libmpq.dll", "mpq.dll")
    if os.uname().sysname == "Darwin":
        return ("libmpq.dylib", "libmpq.so")
    return ("libmpq.so", "libmpq.so.1")


def _load_library():
    """Load libmpq from an override, wheel, system, or source-tree path."""
    explicit = os.environ.get("LIBMPQ_LIBRARY")
    candidates = [explicit] if explicit else []
    module_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.extend(os.path.join(module_dir, "mpq_libs", name)
                      for name in _candidate_library_names())
    discovered = ctypes.util.find_library("mpq")
    if discovered:
        candidates.append(discovered)
    candidates.extend(_candidate_library_names())
    source_dir = os.path.abspath(os.path.join(module_dir, "..", "..", "src", ".libs"))
    candidates.extend(os.path.join(source_dir, name) for name in _candidate_library_names())

    failures = []
    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            return ctypes.CDLL(candidate)
        except OSError as error:
            failures.append("{}: {}".format(candidate, error))
    message = "could not find libmpq; set LIBMPQ_LIBRARY or install libmpq"
    if failures:
        message += " ({} )".format("; ".join(failures))
    raise ImportError(message)


libmpq = _load_library()


def _decode(value):
    """Decode a native byte string for Python callers."""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


class LibmpqError(Exception):
    """Base exception preserving a negative native status and its message."""

    def __init__(self, code, message):
        self.code = int(code)
        self.message = str(message)
        super().__init__("{} ({})".format(self.message, self.code))


class LibmpqIOError(LibmpqError, OSError):
    """Native open, close, seek, read, or write failure."""


class LibmpqNotFoundError(LibmpqError, IndexError):
    """Archive or file lookup failure compatible with ``IndexError``."""


class LibmpqMemoryError(LibmpqError, MemoryError):
    """Native allocation failure."""


class LibmpqFormatError(LibmpqError):
    """Invalid or unsupported archive format."""


class LibmpqStateError(LibmpqError):
    """Operation attempted with an invalid or closed native handle."""


class LibmpqSizeError(LibmpqError):
    """Caller-provided size or output buffer is invalid."""


class LibmpqDecryptError(LibmpqError):
    """Encrypted data could not be decrypted."""


class LibmpqUnpackError(LibmpqError):
    """Compressed data could not be unpacked."""


Error = LibmpqError
_ERROR_TYPES = {
    ERROR_OPEN: LibmpqIOError, ERROR_CLOSE: LibmpqIOError,
    ERROR_SEEK: LibmpqIOError, ERROR_READ: LibmpqIOError,
    ERROR_WRITE: LibmpqIOError, ERROR_MALLOC: LibmpqMemoryError,
    ERROR_FORMAT: LibmpqFormatError, ERROR_NOT_INITIALIZED: LibmpqStateError,
    ERROR_SIZE: LibmpqSizeError, ERROR_EXIST: LibmpqNotFoundError,
    ERROR_DECRYPT: LibmpqDecryptError, ERROR_UNPACK: LibmpqUnpackError,
}


def _as_bytes(value):
    """Convert text or path-like values to UTF-8 C-string bytes."""
    value = os.fspath(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise TypeError("expected str, bytes, or path-like value")


def _auth_code_bytes(value):
    """Return an owned byte copy of a bytes-like MPQE authentication code."""
    try:
        return memoryview(value).tobytes()
    except TypeError as error:
        raise TypeError("auth_code must be bytes-like") from error


def strerror(code):
    """Return libmpq's static diagnostic text for a native return code."""
    return _decode(libmpq.libmpq__strerror(int(code)))


def _check_error(result, function, arguments):
    """Translate a negative ctypes result into a typed ``LibmpqError``."""
    result = int(result)
    if result >= 0:
        return result
    error_type = _ERROR_TYPES.get(result, LibmpqError)
    raise error_type(result, strerror(result))


def _configure(name, restype, *argtypes):
    """Declare one public C function's ABI and install status checking."""
    function = getattr(libmpq, name)
    function.restype = restype
    function.argtypes = list(argtypes)
    if restype is ctypes.c_int32:
        function.errcheck = _check_error
    return function


_configure("libmpq__version", ctypes.c_char_p)
_configure("libmpq__strerror", ctypes.c_char_p, ctypes.c_int32)
_configure("libmpq__archive_open", ctypes.c_int32, ctypes.POINTER(_VOID_PTR), ctypes.c_char_p, _OFF_T)
_configure("libmpq__archive_open_mpqe", ctypes.c_int32, ctypes.POINTER(_VOID_PTR), ctypes.c_char_p, _OFF_T, _BYTE_PTR, ctypes.c_size_t)
_configure("libmpq__archive_create", ctypes.c_int32, ctypes.POINTER(_VOID_PTR), ctypes.c_char_p, _VOID_PTR)
_configure("libmpq__archive_create_mpqe", ctypes.c_int32, ctypes.POINTER(_VOID_PTR), ctypes.c_char_p, _BYTE_PTR, ctypes.c_size_t, _VOID_PTR)
_configure("libmpq__file_begin", ctypes.c_int32, _VOID_PTR, ctypes.c_char_p, _OFF_T, _VOID_PTR, ctypes.POINTER(_VOID_PTR))
_configure("libmpq__file_write", ctypes.c_int32, _VOID_PTR, _BYTE_PTR, _OFF_T)
_configure("libmpq__file_finish", ctypes.c_int32, _VOID_PTR)
_configure("libmpq__file_add", ctypes.c_int32, _VOID_PTR, ctypes.c_char_p, _BYTE_PTR, _OFF_T, _VOID_PTR)
_configure("libmpq__file_add_path", ctypes.c_int32, _VOID_PTR, ctypes.c_char_p, ctypes.c_char_p, _VOID_PTR)
_configure("libmpq__archive_clone", ctypes.c_int32, ctypes.POINTER(_VOID_PTR), _VOID_PTR)
_configure("libmpq__archive_close", ctypes.c_int32, _VOID_PTR)
for _name in ("packed", "unpacked"):
    _configure("libmpq__archive_size_" + _name, ctypes.c_int32, _VOID_PTR, ctypes.POINTER(_OFF_T))
_configure("libmpq__archive_offset", ctypes.c_int32, _VOID_PTR, ctypes.POINTER(_OFF_T))
_configure("libmpq__archive_version", ctypes.c_int32, _VOID_PTR, ctypes.POINTER(ctypes.c_uint32))
_configure("libmpq__archive_files", ctypes.c_int32, _VOID_PTR, ctypes.POINTER(ctypes.c_uint32))
_configure("libmpq__file_size_packed", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.POINTER(_OFF_T))
_configure("libmpq__file_size_unpacked", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.POINTER(_OFF_T))
_configure("libmpq__file_offset", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.POINTER(_OFF_T))
for _name in ("blocks", "encrypted", "compressed", "imploded"):
    _configure("libmpq__file_" + _name, ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
_configure("libmpq__file_number", ctypes.c_int32, _VOID_PTR, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32))
_configure("libmpq__file_hash", None, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32))
_configure("libmpq__file_number_from_hash", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
_configure("libmpq__file_read", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, _BYTE_PTR, _OFF_T, ctypes.POINTER(_OFF_T))
_configure("libmpq__block_open_offset", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32)
_configure("libmpq__block_close_offset", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32)
_configure("libmpq__block_size_unpacked", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(_OFF_T))
_configure("libmpq__block_read", ctypes.c_int32, _VOID_PTR, ctypes.c_uint32, ctypes.c_uint32, _BYTE_PTR, _OFF_T, ctypes.POINTER(_OFF_T))


def version():
    """Return the version string compiled into the loaded native library."""
    return _decode(libmpq.libmpq__version())


__version__ = version()


def file_hash(filename):
    """Return the three unsigned Storm hashes for an MPQ filename."""
    hash1, hash2, hash3 = ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32()
    libmpq.libmpq__file_hash(_as_bytes(filename), ctypes.byref(hash1), ctypes.byref(hash2), ctypes.byref(hash3))
    return hash1.value, hash2.value, hash3.value


class ArchiveCreateOptions(ctypes.Structure):
    """Native options controlling MPQ version, capacity, sectors, and flags."""

    _fields_ = [("version", ctypes.c_uint32), ("max_files", ctypes.c_uint32), ("sector_size", ctypes.c_uint32), ("flags", ctypes.c_uint32)]

    @classmethod
    def defaults(cls):
        """Return options selecting libmpq's documented defaults."""
        return cls(ARCHIVE_VERSION_ONE, 0, 0, 0)

    @classmethod
    def v1(cls):
        """Return options for a default v1 archive."""
        return cls.defaults()

    @classmethod
    def v2(cls):
        """Return options for a default v2 archive."""
        return cls(ARCHIVE_VERSION_TWO, 0, 0, 0)


class FileCreateOptions(ctypes.Structure):
    """Native options controlling file flags, codecs, locale, and platform."""

    _fields_ = [("flags", ctypes.c_uint32), ("compression_first", ctypes.c_uint32), ("compression_next", ctypes.c_uint32), ("locale", ctypes.c_uint16), ("platform", ctypes.c_uint16)]

    @classmethod
    def raw(cls):
        """Return options for raw unencrypted storage."""
        return cls(0, 0, 0, 0, 0)

    @classmethod
    def compressed(cls, first_mask, next_mask):
        """Return options requesting the supplied MPQ compression masks."""
        return cls(FILE_FLAG_COMPRESS, first_mask, next_mask, 0, 0)

    def encrypted(self):
        """Return a copy of these options with encryption enabled."""
        return type(self)(self.flags | FILE_FLAG_ENCRYPTED, self.compression_first, self.compression_next, self.locale, self.platform)


@dataclass(frozen=True)
class ArchiveMetadata:
    """Immutable archive metadata snapshot."""

    packed_size: int
    unpacked_size: int
    offset: int
    version: int
    files: int


@dataclass(frozen=True)
class FileMetadata:
    """Immutable metadata snapshot for one MPQ file entry."""

    packed_size: int
    unpacked_size: int
    offset: int
    blocks: int
    encrypted: bool
    compressed: bool
    imploded: bool


def _read_value(function, pointer_type, *arguments):
    """Call an output-parameter function and return its scalar value."""
    value = pointer_type()
    function(*arguments, ctypes.byref(value))
    return value.value


class WriterFile:
    """Explicitly closeable stream for one file being added to an archive."""

    def __init__(self, archive, name, size, options):
        """Begin a fixed-size file stream using copied storage options."""
        if size < 0:
            raise ValueError("size must not be negative")
        self._archive, self._writer = archive, _VOID_PTR()
        self.expected_size, self.written_size = int(size), 0
        libmpq.libmpq__file_begin(archive._mpq, _as_bytes(name), size, ctypes.byref(options), ctypes.byref(self._writer))

    def write(self, data):
        """Append bytes and reject writes beyond the declared logical size."""
        self._ensure_open()
        data = bytes(data)
        if len(data) > self.expected_size - self.written_size:
            raise ValueError("write exceeds declared file size")
        pointer = None if not data else (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        libmpq.libmpq__file_write(self._writer, pointer, len(data))
        self.written_size += len(data)

    def finish(self):
        """Finalize the stream; native state becomes invalid even on failure."""
        if self._writer:
            writer, self._writer = self._writer, None
            libmpq.libmpq__file_finish(writer)

    def close(self):
        """Finish the stream and report native errors for incomplete streams."""
        self.finish()

    def _ensure_open(self):
        """Reject writes after native finalization."""
        if not self._writer:
            raise LibmpqStateError(ERROR_NOT_INITIALIZED, "writer is closed")

    def __enter__(self):
        """Return this writer for a context-managed operation."""
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Finalize the writer when leaving its context."""
        try:
            self.close()
        except LibmpqError:
            if exc_type is None:
                raise


class Writer:
    """Closeable seekable archive creator preserving the legacy Writer API."""

    def __init__(self, filename, version=ARCHIVE_VERSION_ONE, max_files=0, sector_size=0, flags=0):
        """Create an archive with explicit layout, capacity, sector, and flags."""
        options = ArchiveCreateOptions(version, max_files, sector_size, flags)
        self._mpq = _VOID_PTR()
        libmpq.libmpq__archive_create(ctypes.byref(self._mpq), _as_bytes(filename), ctypes.byref(options))
        self.filename, self._opened = filename, True

    @classmethod
    def create_mpqe(cls, filename, auth_code, version=ARCHIVE_VERSION_ONE,
                    max_files=0, sector_size=0, flags=0):
        """Create an MPQE-wrapped archive using caller-supplied authentication bytes."""
        code = _auth_code_bytes(auth_code)
        options = ArchiveCreateOptions(version, max_files, sector_size, flags)
        writer = cls.__new__(cls)
        writer._mpq = _VOID_PTR()
        pointer = (ctypes.c_uint8 * len(code)).from_buffer_copy(code) if code else None
        libmpq.libmpq__archive_create_mpqe(
            ctypes.byref(writer._mpq), _as_bytes(filename), pointer, len(code), ctypes.byref(options)
        )
        writer.filename, writer._opened = filename, True
        return writer

    def add(self, name, data, options=None):
        """Add complete bytes using raw storage or supplied options."""
        self._ensure_open()
        options, data = options or FileCreateOptions.raw(), bytes(data)
        pointer = None if not data else (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        return libmpq.libmpq__file_add(self._mpq, _as_bytes(name), pointer, len(data), ctypes.byref(options))

    def begin(self, name, size, options=None):
        """Begin a fixed-size streaming entry."""
        self._ensure_open()
        return WriterFile(self, name, size, options or FileCreateOptions.raw())

    def add_path(self, name, source, options=None):
        """Add a filesystem file under an archive name."""
        self._ensure_open()
        options = options or FileCreateOptions.raw()
        return libmpq.libmpq__file_add_path(self._mpq, _as_bytes(name), _as_bytes(source), ctypes.byref(options))

    def close(self):
        """Finalize and close the archive; repeated calls are harmless."""
        if self._opened:
            archive, self._mpq, self._opened = self._mpq, _VOID_PTR(), False
            libmpq.libmpq__archive_close(archive)

    def _ensure_open(self):
        """Reject archive writes after close."""
        if not self._opened:
            raise LibmpqStateError(ERROR_NOT_INITIALIZED, "archive is closed")

    def __enter__(self):
        """Return this writer for context-managed archive creation."""
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Finalize the archive when leaving its context."""
        self.close()

    def __del__(self):
        """Best-effort cleanup that never raises during garbage collection."""
        try:
            self.close()
        except Exception:
            pass


class Reader:
    """Buffered decoded reader over one file's MPQ sectors."""

    def __init__(self, file):
        """Open and retain the native offset-table reference."""
        self._file, self._pos, self._buf, self._cur_block = file, 0, [], 0
        self._closed = False
        libmpq.libmpq__block_open_offset(file._archive._mpq, file.number)

    def close(self):
        """Release the native offset-table reference exactly once."""
        if not self._closed:
            self._closed = True
            libmpq.libmpq__block_close_offset(self._file._archive._mpq, self._file.number)

    def __enter__(self):
        """Return this reader for context-managed block access."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Release the offset table on context exit."""
        self.close()

    def __iter__(self):
        """Return this reader as its own line iterator."""
        return self

    def __next__(self):
        """Return the next line or raise StopIteration at end of file."""
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    next = __next__

    def __repr__(self):
        """Return a concise debugging representation."""
        return "iter(%r)" % self._file

    def seek(self, offset, whence=os.SEEK_SET):
        """Move through decoded bytes, replaying sectors when rewinding."""
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self._pos + offset
        elif whence == os.SEEK_END:
            target = self._file.unpacked_size + offset
        else:
            raise ValueError("invalid whence")
        if target < 0:
            raise ValueError("negative seek position")
        if target < self._pos:
            self._pos, self._buf, self._cur_block = 0, [], 0
        self.read(target - self._pos)

    def tell(self):
        """Return the current decoded byte position."""
        return self._pos

    def _read_block(self):
        """Decode the next sector and append it to the local queue."""
        size = _OFF_T()
        libmpq.libmpq__block_size_unpacked(self._file._archive._mpq, self._file.number, self._cur_block, ctypes.byref(size))
        buffer = _native_buffer(size.value)
        transferred = _OFF_T()
        libmpq.libmpq__block_read(self._file._archive._mpq, self._file.number, self._cur_block, buffer, size.value, ctypes.byref(transferred))
        self._buf.append(bytes(buffer[:transferred.value]))
        self._cur_block += 1

    def read(self, size=-1):
        """Read up to ``size`` decoded bytes, or all remaining bytes for -1."""
        if size < -1:
            raise ValueError("size must be -1 or nonnegative")
        while (size < 0 or sum(map(len, self._buf)) < size) and self._cur_block < self._file.blocks:
            self._read_block()
        data = b"".join(self._buf)
        if size < 0:
            result, self._buf = data, []
        else:
            result, self._buf = data[:size], [data[size:]]
        self._pos += len(result)
        return result

    def readline(self):
        """Read one line, retaining its newline bytes when present."""
        result = bytearray()
        while True:
            value = self.read(1)
            if not value:
                return bytes(result)
            result.extend(value)
            if value == b"\n":
                return bytes(result)

    def readlines(self, sizehint=-1):
        """Read lines until EOF or the accumulated size hint."""
        lines = []
        while sizehint < 0 or sum(map(len, lines)) < sizehint:
            line = self.readline()
            if not line:
                break
            lines.append(line)
        return lines

    xreadlines = __iter__

    def __del__(self):
        """Best-effort offset-table cleanup that never raises during GC."""
        try:
            self.close()
        except Exception:
            pass


class File:
    """Metadata and complete/block access wrapper for one MPQ entry."""

    def __init__(self, archive, number):
        """Load metadata for one public numeric file number."""
        self._archive, self.number = archive, int(number)
        self.packed_size = _read_value(libmpq.libmpq__file_size_packed, _OFF_T, archive._mpq, self.number)
        self.unpacked_size = _read_value(libmpq.libmpq__file_size_unpacked, _OFF_T, archive._mpq, self.number)
        self.offset = _read_value(libmpq.libmpq__file_offset, _OFF_T, archive._mpq, self.number)
        self.blocks = _read_value(libmpq.libmpq__file_blocks, ctypes.c_uint32, archive._mpq, self.number)
        self.encrypted = bool(_read_value(libmpq.libmpq__file_encrypted, ctypes.c_uint32, archive._mpq, self.number))
        self.compressed = bool(_read_value(libmpq.libmpq__file_compressed, ctypes.c_uint32, archive._mpq, self.number))
        self.imploded = bool(_read_value(libmpq.libmpq__file_imploded, ctypes.c_uint32, archive._mpq, self.number))
        self.size_packed, self.size_unpacked = self.packed_size, self.unpacked_size

    def metadata(self):
        """Return an immutable metadata snapshot for this entry."""
        return FileMetadata(self.packed_size, self.unpacked_size, self.offset, self.blocks, self.encrypted, self.compressed, self.imploded)

    def read(self):
        """Read and decode the complete entry into Python bytes."""
        buffer = _native_buffer(self.unpacked_size)
        transferred = _OFF_T()
        libmpq.libmpq__file_read(self._archive._mpq, self.number, None if not self.unpacked_size else buffer, self.unpacked_size, ctypes.byref(transferred))
        return bytes(buffer[:transferred.value])

    read_bytes = read

    def read_block(self, block):
        """Open the offset table, decode one block, and close the table."""
        if block < 0 or block >= self.blocks:
            raise IndexError("block not in file")
        with self.open_reader() as reader:
            reader._cur_block = block
            reader._read_block()
            return reader._buf.pop()

    def block_size(self, block):
        """Return one decoded block's logical size with balanced table lifetime."""
        with self.open_reader():
            size = _OFF_T()
            libmpq.libmpq__block_size_unpacked(self._archive._mpq, self.number, block, ctypes.byref(size))
            return size.value

    def open_reader(self):
        """Return a context-managed buffered reader over this entry."""
        return Reader(self)

    def __bytes__(self):
        """Return the complete unpacked payload as bytes."""
        return self.read()

    def __str__(self):
        """Decode the payload as Latin-1 for legacy compatibility."""
        return self.read().decode("latin-1")

    def __repr__(self):
        """Return a debugging representation containing archive and number."""
        return "%r[%i]" % (self._archive, self.number)

    def __iter__(self):
        """Return a buffered reader over this entry."""
        return self.open_reader()


class Archive:
    """Opened MPQ archive with metadata, lookup, extraction, and clone support."""

    def __init__(self, source, offset=-1):
        """Open a path or an unencrypted, uncompressed embedded :class:`File`."""
        self._source = source
        if isinstance(source, File):
            if source.encrypted or source.compressed or source.imploded:
                raise ValueError("embedded archives must be stored raw")
            self.filename = source._archive.filename
            offset = source._archive.offset + source.offset
        else:
            self.filename = os.fspath(source)
        self._mpq = _VOID_PTR()
        libmpq.libmpq__archive_open(ctypes.byref(self._mpq), _as_bytes(self.filename), offset)
        self._opened = True
        self._load_metadata()

    @classmethod
    def open(cls, source, offset=-1):
        """Open a path with an explicit offset or embedded-header scanning."""
        return cls(source, offset)

    @classmethod
    def open_mpqe(cls, path, auth_code, offset=-1):
        """Open a caller-authenticated MPQE stream containing an MPQ archive."""
        code = _auth_code_bytes(auth_code)
        archive = object.__new__(cls)
        archive._source = path
        archive.filename = os.fspath(path)
        archive._mpq = _VOID_PTR()
        buffer = None if not code else (ctypes.c_uint8 * len(code)).from_buffer_copy(code)
        pointer = None if buffer is None else ctypes.cast(buffer, _BYTE_PTR)
        libmpq.libmpq__archive_open_mpqe(
            ctypes.byref(archive._mpq), _as_bytes(archive.filename), offset, pointer, len(code)
        )
        archive._opened = True
        archive._load_metadata()
        return archive

    def _load_metadata(self):
        """Populate compatibility attributes from native metadata queries."""
        packed, unpacked, offset = _OFF_T(), _OFF_T(), _OFF_T()
        version, files = ctypes.c_uint32(), ctypes.c_uint32()
        libmpq.libmpq__archive_size_packed(self._mpq, ctypes.byref(packed))
        libmpq.libmpq__archive_size_unpacked(self._mpq, ctypes.byref(unpacked))
        libmpq.libmpq__archive_offset(self._mpq, ctypes.byref(offset))
        libmpq.libmpq__archive_version(self._mpq, ctypes.byref(version))
        libmpq.libmpq__archive_files(self._mpq, ctypes.byref(files))
        self.size_packed, self.size_unpacked = packed.value, unpacked.value
        self.packed_size, self.unpacked_size = self.size_packed, self.size_unpacked
        self.offset, self.version, self.files = offset.value, version.value, files.value

    def metadata(self):
        """Return an immutable snapshot of archive-level metadata."""
        return ArchiveMetadata(self.packed_size, self.unpacked_size, self.offset, self.version, self.files)

    def clone(self):
        """Return an independently closable native handle for this archive."""
        self._ensure_open()
        clone = object.__new__(type(self))
        clone._source, clone.filename, clone._mpq = self._source, self.filename, _VOID_PTR()
        libmpq.libmpq__archive_clone(ctypes.byref(clone._mpq), self._mpq)
        clone._opened = True
        clone._load_metadata()
        return clone

    def close(self):
        """Close the native archive handle; repeated calls are harmless."""
        if self._opened:
            archive, self._mpq, self._opened = self._mpq, _VOID_PTR(), False
            libmpq.libmpq__archive_close(archive)

    def _ensure_open(self):
        """Reject operations after archive close."""
        if not self._opened:
            raise LibmpqStateError(ERROR_NOT_INITIALIZED, "archive is closed")

    def __enter__(self):
        """Return this archive for context-managed reading."""
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Close the native archive on context exit."""
        self.close()

    def __len__(self):
        """Return the number of public file entries."""
        return self.files

    def __contains__(self, item):
        """Return whether a filename or numeric file number is present."""
        self._ensure_open()
        if isinstance(item, (str, bytes, os.PathLike)):
            number = ctypes.c_uint32()
            try:
                libmpq.libmpq__file_number(self._mpq, _as_bytes(item), ctypes.byref(number))
            except LibmpqNotFoundError:
                return False
            return True
        return isinstance(item, int) and 0 <= item < self.files

    def __getitem__(self, item):
        """Return a :class:`File` selected by name or public numeric number."""
        self._ensure_open()
        if isinstance(item, (str, bytes, os.PathLike)):
            number = ctypes.c_uint32()
            libmpq.libmpq__file_number(self._mpq, _as_bytes(item), ctypes.byref(number))
            item = number.value
        if not isinstance(item, int) or not 0 <= item < self.files:
            raise IndexError("file not in archive")
        return File(self, item)

    def __iter__(self):
        """Iterate over public file wrappers in numeric order."""
        for number in range(self.files):
            yield File(self, number)

    def __repr__(self):
        """Return a debugging representation containing the source path."""
        return "mpq.Archive(%r)" % self._source

    def __del__(self):
        """Best-effort archive cleanup that never raises during garbage collection."""
        try:
            self.close()
        except Exception:
            pass


if __name__ == "__main__":
    import sys
    with Archive(sys.argv[1]) as archive:
        print(repr(archive))
        for file in archive:
            print(file, file.metadata())
