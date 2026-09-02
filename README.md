# libmpq

[![CI](https://github.com/mbroemme/libmpq/actions/workflows/ci.yml/badge.svg)](https://github.com/mbroemme/libmpq/actions/workflows/ci.yml)
[![Coverage](https://mbroemme.github.io/libmpq/coverage.svg)](https://mbroemme.github.io/libmpq/)
[![GitHub release](https://img.shields.io/github/release/mbroemme/libmpq?style=flat&label=release&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/releases)
[![GitHub issues](https://img.shields.io/github/issues/mbroemme/libmpq?style=flat&label=issues&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/issues)
[![GitHub forks](https://img.shields.io/github/forks/mbroemme/libmpq?style=flat&label=forks&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/network/members)
[![GitHub stars](https://img.shields.io/github/stars/mbroemme/libmpq?style=flat&label=stars&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/stargazers)
[![License: LGPL-2.1-or-later](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue.svg)](COPYING.LESSER)
[![GitHub downloads](https://img.shields.io/github/downloads/mbroemme/libmpq/total?style=flat&label=downloads&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/releases)

A portable C library for creating, reading, decrypting, decompressing, and
extracting files from MoPaQ (MPQ) archives.

## Overview

MPQ is a proprietary archive format created by Mike O'Brien in 1996. It is
used by Blizzard games including Diablo, Diablo II, StarCraft, Warcraft II:
Battle.net Edition, Warcraft III, and World of Warcraft.

libmpq provides a C API for applications that need to inspect, create, and
extract MPQ archives. Creation supports seekable v1 and v2 archives, streaming
or buffer/path file addition, encrypted tables and payloads, optional listfiles,
raw and single-unit files, PKWARE implode, and multi-compression sectors using
Huffman, zlib, PKWARE, bzip2, or mono/stereo WAVE ADPCM.

## Features

* Read MPQ archives and embedded archives located at a file offset.
* Read archive metadata, file names, file sizes, flags, and block information.
* Create seekable MPQ v1 and v2 archives with fixed file-table capacity.
* Add files through streaming, memory-buffer, or filesystem-path APIs.
* Decrypt encrypted hash tables, block tables, and file payloads.
* Create encrypted hash and block tables, file payloads, and sector offsets.
* Create raw, single-unit, sectorized, and multi-sector file entries.
* Compress file sectors with PKWARE implode, Huffman, zlib, bzip2, or WAVE
  ADPCM using separate first-sector and later-sector masks.
* Decompress zlib, bzip2, Huffman, PKWARE implode, Blizzard multi-compression,
  and mono or stereo WAVE ADPCM payloads.
* Generate an optional `(listfile)` entry during archive creation.
* Provide a stable C API with installed headers under `include/libmpq`.
* Support big-endian hosts through explicit little-endian serialization; CI
  runs the full test suite on emulated s390x.
* Provide optional Python 3.11+, D, and Java bindings.
* Install API manual pages for the library functions and `libmpq-config`.

## Requirements

The build system requires:

* A C99-capable C compiler.
* GNU Autoconf, Automake, and Libtool.
* zlib development headers and libraries.
* bzip2 development headers and libraries.

The Python, D, and Java bindings are maintained and distributed through their
native package ecosystems. They are included in source distributions but are
not installed by the native Autotools build.

The Java binding is built independently with Maven and requires JDK 22 or
newer. It uses the Foreign Function and Memory API, maps the stable public C
API, and uses an externally supplied native library. See the binding-specific
documentation below for build, test, and library-loading instructions.

## Building

For build and install use the commands below. If `--prefix=/usr` is used, the
`make install` command must be run as root. It installs the native shared
library, public headers, tools, and manual pages. Language bindings are built
and installed separately with their native package managers.

```sh
./configure --prefix=/usr &&
make &&
make install
```

### Debian or Ubuntu

Install the build tools and compression-library development packages with:

```sh
sudo apt install build-essential autoconf automake libtool \
  zlib1g-dev libbz2-dev
```

### Fedora

Install the compiler, Autotools, and compression-library development packages
with:

```sh
sudo dnf install gcc make autoconf automake libtool \
  zlib-devel bzip2-devel
```

### openSUSE

Install the compiler, Autotools, and compression-library development packages
with:

```sh
sudo zypper install gcc make autoconf automake libtool \
  zlib-devel libbz2-devel
```

### Arch Linux

Install the base build tools and required libraries with:

```sh
sudo pacman -S --needed base-devel autoconf automake libtool \
  zlib bzip2
```

Use `./configure --prefix=DIR` to select a different installation prefix. Use
`./configure --help` to list the available configuration options. C99 is the
default language standard; callers may select another supported dialect through
`CFLAGS`, for example `CFLAGS="-std=c17"`.

## Usage

The public header is installed as `libmpq/mpq.h`. The following example opens
an archive, reads the first file into memory, and reports library errors:

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmpq/mpq.h>

int
main(int argc, char **argv)
{
    mpq_archive_s *archive = NULL;
    libmpq__off_t file_size = 0;
    uint8_t *file_data = NULL;
    int32_t result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ARCHIVE\n", argv[0]);
        return EXIT_FAILURE;
    }

    result = libmpq__archive_open(&archive, argv[1], -1);
    if (result < 0) {
        fprintf(stderr, "archive_open: %s\n", libmpq__strerror(result));
        return EXIT_FAILURE;
    }

    result = libmpq__file_size_unpacked(archive, 0, &file_size);
    if (result < 0) {
        fprintf(stderr, "file_size_unpacked: %s\n", libmpq__strerror(result));
        libmpq__archive_close(archive);
        return EXIT_FAILURE;
    }

    file_data = malloc((size_t)file_size);
    if (file_data == NULL && file_size != 0) {
        libmpq__archive_close(archive);
        return EXIT_FAILURE;
    }

    result = libmpq__file_read(archive, 0, file_data, file_size, NULL);
    if (result < 0) {
        fprintf(stderr, "file_read: %s\n", libmpq__strerror(result));
        free(file_data);
        libmpq__archive_close(archive);
        return EXIT_FAILURE;
    }

    free(file_data);
    libmpq__archive_close(archive);
    return EXIT_SUCCESS;
}
```

If `pkg-config` is available, compile the example with the installed header
and shared library:

```sh
cc -std=c99 -Wall -Wextra mpq-example.c -o mpq-example \
  $(pkg-config --cflags --libs libmpq)
```

The legacy `libmpq-config` helper is also available:

```sh
cc -std=c99 -Wall -Wextra mpq-example.c -o mpq-example \
  $(libmpq-config --cflags) $(libmpq-config --libs)
```

## Native C SDK packages

The native binary release, `libmpq-native-X.Y.Z.zip`, contains relocatable
x86_64 Linux SDK archives:

* `libmpq-X.Y.Z-linux-glibc-x86_64.tar.gz` for glibc 2.17 and later.
* `libmpq-X.Y.Z-linux-musl-x86_64.tar.gz` for musl 1.2 and later.

The SDKs use the host's zlib and bzip2 shared libraries; those runtime and
development dependencies are not bundled. Each archive extracts a single
package directory containing the executable helper, public headers, shared
library, pkg-config metadata, manual pages, licenses, README, and BUILDINFO.

Extract the selected SDK anywhere convenient:

```sh
export LIBMPQ_ROOT="$PWD/libmpq-X.Y.Z"
export PATH="${LIBMPQ_ROOT}/bin:${PATH}"
export PKG_CONFIG_PATH="${LIBMPQ_ROOT}/lib/pkgconfig"
export LD_LIBRARY_PATH="${LIBMPQ_ROOT}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export MANPATH="${LIBMPQ_ROOT}/share/man${MANPATH:+:${MANPATH}}"

pkg-config --cflags --libs libmpq
libmpq-config --prefix="${LIBMPQ_ROOT}" --cflags
libmpq-config --prefix="${LIBMPQ_ROOT}" --libs
man 1 libmpq-config
man 3 libmpq
```

## Bindings

The source tree contains bindings for the public C API. Each binding has its
own package metadata, tests, and distribution workflow.

### Python

The Python binding is a Python 3.11+ `ctypes` package. Its implementation is
in `bindings/python/mpq.py`, package metadata is in
`bindings/python/pyproject.toml`, and tests are in `bindings/python/tests`.
Autotools does not detect or install the Python package; use the PEP 517
backend and pip/PyPI instead.

For development from a source checkout, build the native library and run the
tests with an explicit native-library override:

```sh
sh autogen.sh
./configure
make
LIBMPQ_LIBRARY="$PWD/src/.libs/libmpq.so" \
    python -m pytest bindings/python/tests
```

The release wheels are built with cibuildwheel and repaired for
`manylinux_2_17_x86_64` and `musllinux_1_2_x86_64`. They contain a private
native library at `mpq_libs/libmpq.so`, loaded directly by package path; the
wheel does not require a separately installed libmpq library. This private
library intentionally has no ELF SONAME. The Python release archive,
`libmpq-python-X.Y.Z.zip`, contains the sdist and all generated wheels.

See [`bindings/python/README.md`](bindings/python/README.md) for API examples,
package installation, native-library behavior, and test instructions.

### D

The D binding is a DUB package named `libmpq`. The manifest is
[`dub.sdl`](dub.sdl), and the modules are under
`bindings/d/source/libmpq`. Import the high-level API with:

```d
import libmpq.mpq;
```

Autotools includes the D sources in source distributions but does not install
them. DUB/code.dlang.org owns D package installation. From a checkout, build
the native library and run the tests with DMD or LDC:

```sh
sh autogen.sh
./configure
make
LIBRARY_PATH="$PWD/src/.libs" LD_LIBRARY_PATH="$PWD/src/.libs" \
    dub run --config=tests --compiler=dmd
LIBRARY_PATH="$PWD/src/.libs" LD_LIBRARY_PATH="$PWD/src/.libs" \
    dub run --config=tests --compiler=ldc2
```

The D release archive is `libmpq-d-X.Y.Z.zip`. It contains the D source
package and compiler-specific binary packages for DMD and LDC on Linux
x86_64, with separate glibc and musl variants. Binary packages include the
precompiled D archive and the complete `libmpq.so` SONAME chain. Their bundled
library directory is supplied automatically at link time; runtime loading may
still require `LD_LIBRARY_PATH`. `BUILDINFO` records compiler and native build
metadata.

See [`bindings/d/README.md`](bindings/d/README.md) for DUB usage, compiler
requirements, binary package details, and examples.

### Java

The Java binding is a Maven project under `bindings/java` and requires JDK 22
or newer. It uses the Java Foreign Function and Memory API and exposes both
the low-level `org.libmpq.ffi.LibmpqNative` mapping and higher-level
`AutoCloseable` classes such as `Archive` and `MpqFileWriter`.

The Java JAR is platform-independent and does not contain `libmpq.so`. Supply
the native library explicitly:

```sh
mvn -B -f bindings/java/pom.xml test \
    -Dorg.libmpq.library="$PWD/src/.libs/libmpq.so" \
    -Dlibmpq.sourceDir="$PWD"
```

The binding also supports the normal system loader path:

```sh
LD_LIBRARY_PATH="$PWD/src/.libs" \
    mvn -B -f bindings/java/pom.xml test \
    -Dorg.libmpq.test.loaderPath=true \
    -Dlibmpq.sourceDir="$PWD"
```

The Java release archive, `libmpq-java-X.Y.Z.zip`, contains the runtime,
sources, and Javadoc JARs, together with `COPYING`, `COPYING.LESSER`, and the
Java binding README. The release workflow validates the packaged runtime JAR
with an external consumer before uploading it.

See [`bindings/java/README.md`](bindings/java/README.md) and
[`bindings/java/pom.xml`](bindings/java/pom.xml) for Maven configuration,
project metadata, and API information.

### Release package summary

The top-level release workflow publishes outer archives for the language
bindings and the native binary SDK. These archives are included in the signed
global `SHA256SUMS`:

| Package | Release archive | Contents |
| --- | --- | --- |
| Native C SDK | `libmpq-native-X.Y.Z.zip` | glibc and musl x86_64 SDK packages |
| Python | `libmpq-python-X.Y.Z.zip` | Python sdist and all wheels |
| Java | `libmpq-java-X.Y.Z.zip` | Runtime, sources, Javadoc, licenses, and README |
| D | `libmpq-d-X.Y.Z.zip` | D source and compiler/platform packages |

The native source archives remain separate top-level assets:
`libmpq-X.Y.Z.tar.gz` and `libmpq-X.Y.Z.tar.bz2`. The release workflow builds,
tests, collects, and validates all packages before generating the single
global checksum manifest and its GPG signature.

### Registry publication dispatch

Registry workflows are separate from the signed GitHub Release workflow and
are dispatched manually. Test Python packaging or Maven Central credentials
from a branch:

```sh
gh workflow run publish-python.yml --ref <branch> -f target=testpypi
gh workflow run publish-java.yml --ref <branch> -f mode=validate
gh workflow run publish-d.yml --ref <branch> -f mode=validate
```

For a production registry release, select the exact tag ref:

```sh
gh workflow run publish-python.yml --ref vX.Y.Z -f target=pypi
gh workflow run publish-java.yml --ref vX.Y.Z -f mode=release
gh workflow run publish-d.yml --ref vX.Y.Z -f mode=release
```

Both Maven modes create a real Central Portal deployment and wait for
`VALIDATED`; there is no sandbox. A `validate` deployment is for testing and
must be dropped in the Central Portal. A `release` deployment remains
USER_MANAGED until a maintainer manually chooses Publish or Drop.

The Python publishing workflow reuses the same wheel, source-distribution, and
metadata-validation pipeline as the signed GitHub Release. Likewise, Java
release packaging and Maven Central validation share one package build and
consumer-validation script.

D `validate` may run from a branch or tag and validates the complete D release
package set: source, DMD/glibc, DMD/musl, LDC/glibc, and LDC/musl. It performs
no registry activity. D `release` requires an exact `v*` tag where the tag,
native project, and DUB versions agree; code.dlang.org independently discovers
that tag, and the workflow waits until the exact package version appears. It
does not upload anything to code.dlang.org. Both modes reuse the canonical D
package pipeline used by the signed GitHub Release.

## Documentation

The documentation includes manual pages for all available public API
functions, together with a helper for retrieving the compiler and linker flags
required to use libmpq.

For an implementation-oriented overview of MPQ v1 through v4 headers, tables,
encryption, sectors, and compression, see [MPQ format guide](MPQ.md).

## Limitations

* Archive creation is currently limited to seekable MPQ v1 and v2 archives.
  MPQ v3/v4, HET/BET tables, and related format extensions are not supported.
* Sparse and LZMA compression, attributes, signatures, checksums, patch
  metadata, and StormLib-specific key modes are not supported by the writer.
* Windows support is not currently tested or documented by the Autotools build.

## Contributing

Bug reports, compatibility reports, patches, and testing results are welcome
in the [GitHub issue tracker](https://github.com/mbroemme/libmpq/issues).
Testing against a broad collection of MPQ archives is especially useful.

## Authors

The project was initiated by Maik Broemme. Current and past contributors
include:

* Maik Broemme
* Gleb Mazovetskiy
* Tilman Sauerbeck
* Forrest Voight
* Georg Lukas

libmpq also preserves attribution for the StormLib, ShadowFlare, PKWARE, and
other MPQ-related work on which parts of the implementation are based.

## Thanks

Thanks to the contributors whose earlier work helped make libmpq possible:

* Ladislav Zezula, creator of StormLib.
* Marko Friedemann, initial porter of StormLib to Linux.
* Tom Amigo, one of the first people to decrypt the MoPaQ archive format.
* ShadowFlare, creator of the ShadowFlare MPQ API.
* Justin Olbrantz (Quantam), creator of a client using the ShadowFlare MPQ API.

## Licensing

libmpq is licensed under the GNU Lesser General Public License, version 2.1
or later. See [`COPYING.LESSER`](COPYING.LESSER) for the library license and
[`COPYING`](COPYING) for the corresponding GNU GPL license text. The
relicensing history and approval record are available in
[`RELICENSING.md`](RELICENSING.md).
