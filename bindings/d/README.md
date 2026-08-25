# libmpq D bindings

These bindings expose the public libmpq archive API through the `libmpq.mpq`
module. The high-level `Archive`, `File`, and `MpqFileWriter` classes translate
negative C status values into `MPQException` while retaining the low-level
`extern(C)` declarations for applications that need direct ABI access.

## Requirements

The native libmpq library and its zlib and bzip2 dependencies must be installed
or available to the linker. From a libmpq checkout, build the native library
first:

```sh
sh autogen.sh
./configure --prefix=/usr
make
```

Then run the D tests with either supported compiler:

```sh
LIBRARY_PATH="$PWD/src/.libs" LD_LIBRARY_PATH="$PWD/src/.libs" \
    dub run --config=tests --compiler=dmd
LIBRARY_PATH="$PWD/src/.libs" LD_LIBRARY_PATH="$PWD/src/.libs" \
    dub run --config=tests --compiler=ldc2
```

The source/DUB package does not load a private copy of the native library.
`libs "mpq"` uses the platform linker, so source-package consumers should
install libmpq or provide the equivalent library and runtime search path.

Release downloads also provide compiler-specific binary packages. They contain
the D interface files, a precompiled static D archive, and the complete
`libmpq.so` SONAME chain. The binary DUB recipe supplies the bundled library
directory to the linker automatically; the dynamic loader still needs to find
the bundled library at runtime, for example through `LD_LIBRARY_PATH`. The
compiler and native build metadata, including the libc build version, build
environment, and maximum required glibc symbol version, is recorded in
`BUILDINFO`; use the source package when the recorded compiler or platform does
not match the consumer environment. The release currently provides
`linux-glibc-x86_64` and `linux-musl-x86_64` packages for both DMD and LDC.

## Example

```d
import libmpq.mpq;

auto archive = Archive.open("example.mpq");
scope(exit) archive.close();
auto entry = archive.file("(listfile)");
auto data = entry.read();
```

Creation uses typed options and supports both archive versions:

```d
auto archive = Archive.create("new.mpq", ArchiveCreateOptions.v2());
scope(exit) archive.close();
archive.add("hello.txt", cast(const(ubyte)[])"hello\n");
```

All arrays passed to the writer are borrowed for the duration of the call.
Arrays returned by `read` and `readBlock` are owned by the caller. Always close
archives explicitly; a destructor performs only best-effort cleanup because D
destructors cannot report native close errors.

## DUB distribution

The repository root contains the DUB manifest so the binding can be consumed
as the `libmpq` package from a source checkout or a tagged repository release.
For registry publication, code.dlang.org discovers versions from Git tags such
as `v0.6.0`; registration and registry credentials are intentionally kept out
of the build and release workflows. See the [DUB publishing guide](https://dub.pm/dub-guide/publishing/).

Autotools includes the D sources in libmpq source archives but does not install
the D package. DUB and code.dlang.org own D package installation and
publication. The repository/source package contains the D source files and
expects a system libmpq installation. The precompiled release packages are a
separate distribution format: they contain `.di` interfaces,
compiler-specific static archives, and the native shared-library files needed
at runtime. The outer D release ZIP also contains the source package so
consumers can rebuild when a precompiled package is not suitable.
