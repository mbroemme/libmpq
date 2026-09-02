# libmpq Python bindings

The `mpq` module provides Python 3.11+ ctypes bindings for libmpq. It keeps
the historical `import mpq` API while adding explicit archive and reader
lifecycle management, typed native errors, archive creation, cloning,
metadata, block access, compression, encryption, and streaming writes.

The canonical release installation path is [PyPI](https://pypi.org/project/libmpq/):

```sh
python -m pip install libmpq
```

The binding is distributed through Python packaging rather than Autotools.
Autotools includes the binding sources in source archives but does not install
the Python package. For a local package installation, use the PEP 517 build
backend through `pip`:

```sh
python -m pip install .
```

For source-tree development, set `LIBMPQ_LIBRARY` to an absolute
shared-library path, or build libmpq in the source tree and let the
development fallback locate `src/.libs/libmpq.so`.

```sh
./configure
make
LIBMPQ_LIBRARY="$PWD/src/.libs/libmpq.so" python -m pytest bindings/python/tests
```

Release wheels contain a private native library at `mpq_libs/libmpq.so`. It
is loaded by its exact package path through `ctypes`, intentionally has no ELF
`DT_SONAME`, and does not require a separate system libmpq installation. The
release Python ZIP contains the sdist and all generated manylinux/musllinux
wheels as a supplementary GitHub Release download. The sdist contains the
canonical C and header sources and is free of native build products.

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
