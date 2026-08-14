"""Python 2 ctypes wrapper for libmpq archive and file access."""

# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this file; if not, see <https://www.gnu.org/licenses/>.

import ctypes
import ctypes.util
import os

libmpq = ctypes.CDLL(ctypes.util.find_library("mpq"))

class Error(Exception):
    """Base exception for libmpq-specific failures."""

    pass

# Map libmpq return codes to Python exception types used by errcheck hooks.
errors = {
    -1: (IOError, "open"),
    -2: (IOError, "close"),
    -3: (IOError, "seek"),
    -4: (IOError, "read"),
    -5: (IOError, "write"),
    -6: (MemoryError,),
    -7: (Error, "file is not an mpq or is corrupted"),
    -8: (AssertionError, "not initialized"),
    -9: (AssertionError, "buffer size too small"),
    -10: (IndexError, "file not in archive"),
    -11: (AssertionError, "decrypt"),
    -12: (AssertionError, "unpack"),
}

def check_error(result, func, arguments, errors=errors):
    """Raise the mapped Python exception for a negative libmpq result."""
    if result == -10 and getattr(func, "__name__", "") == "libmpq__archive_open":
        raise IOError("archive does not exist")

    try:
        error = errors[result]
    except KeyError:
        return result
    else:
        raise error[0](*error[1:])

libmpq.libmpq__version.restype = ctypes.c_char_p

libmpq.libmpq__archive_open.errcheck = check_error
libmpq.libmpq__archive_close.errcheck = check_error
libmpq.libmpq__archive_size_packed.errcheck = check_error
libmpq.libmpq__archive_size_unpacked.errcheck = check_error
libmpq.libmpq__archive_offset.errcheck = check_error
libmpq.libmpq__archive_version.errcheck = check_error
libmpq.libmpq__archive_files.errcheck = check_error

libmpq.libmpq__file_size_packed.errcheck = check_error
libmpq.libmpq__file_size_unpacked.errcheck = check_error
libmpq.libmpq__file_offset.errcheck = check_error
libmpq.libmpq__file_blocks.errcheck = check_error
libmpq.libmpq__file_encrypted.errcheck = check_error
libmpq.libmpq__file_compressed.errcheck = check_error
libmpq.libmpq__file_imploded.errcheck = check_error
libmpq.libmpq__file_number.errcheck = check_error
libmpq.libmpq__file_read.errcheck = check_error

libmpq.libmpq__block_open_offset.errcheck = check_error
libmpq.libmpq__block_close_offset.errcheck = check_error
libmpq.libmpq__block_size_unpacked.errcheck = check_error
libmpq.libmpq__block_read.errcheck = check_error

__version__ = libmpq.libmpq__version()


class Reader(object):
    """Buffered block reader for one MPQ file entry."""

    def __init__(self, file, libmpq=libmpq):
        """Open the block offset table and initialize buffered read state."""
        self._file = file
        self._pos = 0
        self._buf = []
        self._cur_block = 0
        libmpq.libmpq__block_open_offset(self._file._archive._mpq,
            self._file.number)

    def __iter__(self):
        """Return the reader as its own iterator."""
        return self

    def __repr__(self):
        """Return a debugging representation for this reader."""
        return "iter(%r)" % self._file

    def seek(self, offset, whence=os.SEEK_SET, os=os):
        """Move the read position, rewinding and replaying blocks when needed."""
        if whence == os.SEEK_SET:
            pass
        elif whence == os.SEEK_CUR:
            offset += self._pos
        elif whence == os.SEEK_END:
            offset += self._file.size_unpacked
        else:
            raise ValueError, "invalid whence"

        if offset >= self._pos:
            self.read(offset - self._pos)
        else:
            self._pos = 0
            self._buf = []
            self._cur_block = 0
            self.read(offset)

    def tell(self):
        """Return the current read position in the unpacked file."""
        return self._pos

    def _read_block(self, ctypes=ctypes, libmpq=libmpq):
        """Read the next archive block into the local buffer queue."""
        block_size = ctypes.c_int64()
        libmpq.libmpq__block_size_unpacked(self._file._archive._mpq,
            self._file.number, self._cur_block, ctypes.byref(block_size))
        block_data = ctypes.create_string_buffer(block_size.value)
        libmpq.libmpq__block_read(self._file._archive._mpq,
            self._file.number, self._cur_block,
            block_data, ctypes.c_int64(len(block_data)), None)
        self._buf.append(block_data.raw)
        self._cur_block += 1

    def read(self, size=-1):
        """Read up to size bytes, or the rest of the file when size is negative."""
        while size < 0 or sum(map(len, self._buf)) < size:
            if self._cur_block == self._file.blocks:
                break
            self._read_block()
        buf = "".join(self._buf)
        if size < 0:
            ret = buf
            self._buf = []
        else:
            ret = buf[:size]
            self._buf = [buf[size:]]
        self._pos += len(ret)
        return ret

    def readline(self, os=os):
        """Read one text line while preserving MPQ file iterator semantics."""
        line = []
        while True:
            char = self.read(1)
            if char == "":
                break
            if char not in '\r\n' and line and line[-1] in '\r\n':
                self.seek(-1, os.SEEK_CUR)
                break
            line.append(char)
        return ''.join(line)

    def next(self):
        """Return the next line for Python 2 iterator protocol."""
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def readlines(self, sizehint=-1):
        """Return lines until EOF or the optional size hint is reached."""
        res = []
        while sizehint < 0 or sum(map(len, res)) < sizehint:
            line = self.readline()
            if not line:
                break
            res.append(line)
        return res

    xreadlines = __iter__

    def __del__(self, libmpq=libmpq):
        """Release the cached block offset table held by this reader."""
        libmpq.libmpq__block_close_offset(self._file._archive._mpq,
            self._file.number)


class File(object):
    """Metadata and full-file access wrapper for one MPQ file entry."""

    def __init__(self, archive, number, ctypes=ctypes, libmpq=libmpq):
        """Load metadata for one numeric archive entry."""
        self._archive = archive
        self.number = number

        for name, atype in [
            ("size_packed", ctypes.c_int64),
            ("size_unpacked", ctypes.c_int64),
            ("offset", ctypes.c_int64),
            ("blocks", ctypes.c_uint32),
            ("encrypted", ctypes.c_uint32),
            ("compressed", ctypes.c_uint32),
            ("imploded", ctypes.c_uint32),
        ]:
            data = atype()
            func = getattr(libmpq, "libmpq__file_"+name)
            func(self._archive._mpq, self.number, ctypes.byref(data))
            setattr(self, name, data.value)

    packed_size = property(lambda self: self.size_packed)
    unpacked_size = property(lambda self: self.size_unpacked)

    def __str__(self, ctypes=ctypes, libmpq=libmpq):
        """Return the complete unpacked file payload."""
        data = ctypes.create_string_buffer(self.size_unpacked)
        libmpq.libmpq__file_read(self._archive._mpq, self.number,
            data, ctypes.c_int64(len(data)), None)
        return data.raw

    def __repr__(self):
        """Return a debugging representation for this file entry."""
        return "%r[%i]" % (self._archive, self.number)

    def __iter__(self, Reader=Reader):
        """Return a buffered reader over this file entry."""
        return Reader(self)


class Archive(object):
    """Opened MPQ archive with metadata and index/name lookup helpers."""

    def __init__(self, source, ctypes=ctypes, File=File, libmpq=libmpq):
        """Open a top-level archive or an embedded archive stored in a File."""
        self._source = source
        if isinstance(source, File):
            assert not source.encrypted
            assert not source.compressed
            assert not source.imploded
            self.filename = source._archive.filename
            offset = source._archive.offset + source.offset
        else:
            self.filename = source
            offset = -1

        self._mpq = ctypes.c_void_p()
        libmpq.libmpq__archive_open(ctypes.byref(self._mpq), self.filename,
            ctypes.c_int64(offset))
        self._opened = True

        for field_name, field_type in [
            ("size_packed", ctypes.c_int64),
            ("size_unpacked", ctypes.c_int64),
            ("offset", ctypes.c_int64),
            ("version", ctypes.c_uint32),
            ("files", ctypes.c_uint32),
        ]:
            func = getattr(libmpq, "libmpq__archive_" + field_name)
            data = field_type()
            func(self._mpq, ctypes.byref(data))
            setattr(self, field_name, data.value)

    packed_size = property(lambda self: self.size_packed)
    unpacked_size = property(lambda self: self.size_unpacked)

    def __del__(self, libmpq=libmpq):
        """Close the underlying libmpq archive handle if it was opened."""
        if getattr(self, "_opened", False):
            libmpq.libmpq__archive_close(self._mpq)

    def __len__(self):
        """Return the number of extractable file entries."""
        return self.files

    def __contains__(self, item, ctypes=ctypes, libmpq=libmpq):
        """Return whether a file name or numeric index exists in the archive."""
        if isinstance(item, str):
            data = ctypes.c_uint32()
            try:
                libmpq.libmpq__file_number(self._mpq, ctypes.c_char_p(item),
                    ctypes.byref(data))
            except IndexError:
                return False
            return True
        return 0 <= item < self.files

    def __getitem__(self, item, ctypes=ctypes, File=File, libmpq=libmpq):
        """Return a File wrapper for a file name or numeric index."""
        if isinstance(item, str):
            data = ctypes.c_int()
            libmpq.libmpq__file_number(self._mpq, ctypes.c_char_p(item),
                ctypes.byref(data))
            item = data.value
        else:
            if not 0 <= item < self.files:
                raise IndexError, "file not in archive"
        return File(self, item)

    def __repr__(self):
        """Return a debugging representation for this archive."""
        return "mpq.Archive(%r)" % self._source

# Remove clutter - everything except Error and Archive.
del os, check_error, ctypes, errors, File, libmpq, Reader

if __name__ == "__main__":
    import sys, random
    archive = Archive(sys.argv[1])
    print repr(archive)
    for k, v in archive.__dict__.iteritems():
        print " " * (4 - 1), k, v
    assert '(listfile)' in archive
    assert 0 in archive
    assert len(archive) == archive.files
    files = [x.strip() for x in archive['(listfile)']]
    files.extend(xrange(archive.files))
    for key in files:
        file = archive[key]
        print
        print " " * (4 - 1), repr(file)
        for k, v in file.__dict__.iteritems():
            print " " * (8 - 1), k, v

        a = str(file)

        b = iter(file).read()

        reader = iter(file)
        c = []
        while True:
            l = random.randrange(1, 10)
            d = reader.read(l)
            if not d: break
            assert len(d) <= l
            c.append(d)
        c = "".join(c)

        d = []
        reader.seek(0)
        for line in reader:
            d.append(line)
        d = "".join(d)

        assert a == b == c == d, map(hash, [a,b,c,d])
        assert len(a) == file.size_unpacked

        repr(iter(file))


        reader.seek(0)
        a = reader.readlines()

        reader.seek(0)
        b = list(reader)

        assert a == b
