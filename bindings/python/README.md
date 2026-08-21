# libmpq Python bindings

The `mpq` module provides Python 3.11+ ctypes bindings for libmpq. It keeps
the historical `import mpq` API while adding explicit archive and reader
lifecycle management, typed native errors, archive creation, cloning,
metadata, block access, compression, encryption, and streaming writes.

The binding does not currently bundle native binaries in source-tree or
Autotools installs. Set `LIBMPQ_LIBRARY` to an absolute shared-library path,
or build libmpq in the source tree and let the development fallback locate
`src/.libs/libmpq.so`.

```sh
./configure
make
LIBMPQ_LIBRARY="$PWD/src/.libs/libmpq.so" python -m pytest bindings/python/tests
```

Typical usage is explicitly closeable and safe with context managers:

```python
import mpq

with mpq.Archive("data.mpq", offset=0) as archive:
    entry = archive["readme.txt"]
    print(entry.read())

with mpq.Writer("created.mpq", version=mpq.ARCHIVE_VERSION_TWO) as writer:
    writer.add("payload.bin", b"payload", mpq.FileCreateOptions.raw())
```

Native failures raise `LibmpqError` subclasses with `.code` and `.message`
attributes. I/O and missing-file subclasses remain compatible with the
corresponding Python built-in exception categories.
