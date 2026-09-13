# libmpq

[![CI](https://github.com/mbroemme/libmpq/actions/workflows/ci.yml/badge.svg)](https://github.com/mbroemme/libmpq/actions/workflows/ci.yml)
[![Coverage](https://mbroemme.github.io/libmpq/coverage.svg)](https://mbroemme.github.io/libmpq/)
[![GitHub
release](https://img.shields.io/github/release/mbroemme/libmpq?style=flat&label=release&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/releases)
[![GitHub
issues](https://img.shields.io/github/issues/mbroemme/libmpq?style=flat&label=issues&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/issues)
[![GitHub
forks](https://img.shields.io/github/forks/mbroemme/libmpq?style=flat&label=forks&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/network/members)
[![GitHub
stars](https://img.shields.io/github/stars/mbroemme/libmpq?style=flat&label=stars&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/stargazers)
[![License:
LGPL-2.1-or-later](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue.svg)](COPYING.LESSER)
[![GitHub
downloads](https://img.shields.io/github/downloads/mbroemme/libmpq/total?style=flat&label=downloads&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/releases)

A portable C library for creating, reading, decrypting, decompressing, and
extracting files from MoPaQ (MPQ) archives.

## Overview

MPQ is a proprietary archive format created by Mike O'Brien in 1996. It is
used by Blizzard games including Diablo, Diablo II, StarCraft, Warcraft II:
Battle.net Edition, Warcraft III, and World of Warcraft.

libmpq provides a C API for applications that need to inspect, create, and
extract MPQ archives. Creation supports seekable v1 and v2 archives, streaming
or buffer/path file addition, encrypted tables and payloads, optional listfiles,
raw and single-unit files, PKWARE implode, multi-compression sectors using
Huffman, zlib, PKWARE, bzip2, or mono/stereo WAVE ADPCM, and the exclusive
MPQ v2+ LZMA method.

## Features

* Read MPQ archives and embedded archives located at a file offset.
* Read MPQE-wrapped MPQ streams and create new MPQE archives with a
  caller-supplied authentication code.
* Read archive metadata, file names, file sizes, flags, and block information.
* Create seekable MPQ v1 and v2 archives with fixed file-table capacity.
* Add files through streaming, memory-buffer, or filesystem-path APIs.
* Decrypt encrypted hash tables, block tables, and file payloads.
* Create encrypted hash and block tables, file payloads, and sector offsets.
* Create raw, single-unit, sectorized, and multi-sector file entries.
* Compress file sectors with PKWARE implode, Huffman, zlib, bzip2, SPARSE,
  or WAVE ADPCM using separate first-sector and later-sector masks.
* Compress MPQ v2+ file sectors with the exclusive LZMA compression method.
* Decompress zlib, bzip2, SPARSE, MPQ v2+ LZMA, Huffman, PKWARE implode, Blizzard
  multi-compression, and mono or stereo WAVE ADPCM payloads.
* Generate an optional `(listfile)` entry during archive creation.
* Read and create optional version-100 `(attributes)` metadata in MPQ v1+:
  CRC32, explicit FILETIME, MD5, and read-only patch-bit information.
* Support big-endian hosts through explicit little-endian serialization; CI
  runs the full test suite on emulated s390x.
* Provide optional Python 3.11+, D, and Java bindings.
* Install API manual pages for the library functions and `libmpq-config`.
* Provide a stable C API with installed headers under `include/libmpq`.

See the [developer guide](DEVELOPER.md) for API examples, optional metadata,
checksum verification, and writer compression policies.

## Requirements

The build system requires:

* A C99-capable C compiler.
* GNU Autoconf, Automake, and Libtool.
* zlib development headers and libraries.
* bzip2 development headers and libraries.
* xz development headers and libraries.

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
  zlib1g-dev libbz2-dev liblzma-dev
```

### Fedora

Install the compiler, Autotools, and compression-library development packages
with:

```sh
sudo dnf install gcc make autoconf automake libtool \
  zlib-devel bzip2-devel xz-devel
```

### openSUSE

Install the compiler, Autotools, and compression-library development packages
with:

```sh
sudo zypper install gcc make autoconf automake libtool \
  zlib-devel libbz2-devel liblzma-devel
```

### Arch Linux

Install the base build tools and required libraries with:

```sh
sudo pacman -S --needed base-devel autoconf automake libtool \
  zlib bzip2 xz
```

Use `./configure --prefix=DIR` to select a different installation prefix. Use
`./configure --help` to list the available configuration options. C99 is the
default language standard; callers may select another supported dialect through
`CFLAGS`, for example `CFLAGS="-std=c17"`.

## Usage

Include `<libmpq/mpq.h>` and link against libmpq. With `pkg-config`, compile
an application using:

```sh
cc -std=c99 -Wall -Wextra mpq-example.c -o mpq-example \
  $(pkg-config --cflags --libs libmpq)
```

See the [native API example](DEVELOPER.md#native-api-example) for opening an
archive, reading a file, and handling errors. Installed API documentation is
available through `man 3 libmpq`.

## Native C SDK packages

Release downloads provide relocatable x86_64 Linux SDKs for glibc and musl.
They include headers, shared libraries, manual pages, and build metadata;
zlib, bzip2, and liblzma remain system dependencies. See the
[SDK setup instructions](DEVELOPER.md#native-c-sdk-packages).

## Bindings

Optional language bindings are distributed through their native ecosystems:

* [Python](bindings/python/README.md): Python 3.11+ ctypes bindings on PyPI.
* [D](bindings/d/README.md): high-level wrappers and native declarations on DUB.
* [Java](bindings/java/README.md): JDK 22+ FFM bindings on Maven Central.

Autotools does not install the bindings. See each binding's README for usage
and installation, or the [developer guide](DEVELOPER.md#binding-development)
for local builds, tests, and release packaging.

## Documentation

The documentation includes manual pages for all available public API
functions, together with a helper for retrieving the compiler and linker flags
required to use libmpq.

See the [developer guide](DEVELOPER.md) for API integration and release
workflows. For an implementation-oriented overview of MPQ v1 through v4
headers, tables, encryption, sectors, and compression, see the
[MPQ format guide](MPQ.md).

## Limitations

* Archive creation is currently limited to seekable MPQ v1 and v2 archives.
  MPQ v3/v4, HET/BET tables, and related format extensions are not supported.
* MPQE supports reading and creation of new archives with a caller-supplied
  authentication code. Existing MPQE archives cannot be modified and encrypted
  random-access writing is unsupported. Creation uses an owner-only plaintext
  temporary file; the completed archive uses normal caller-umask permissions.
  Cleanup is best effort, so a crash can leave the plaintext temporary behind.
* Signature generation, patch creation/application, and StormLib-specific key
  modes are not supported. Stored attributes are not automatically verified.
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
