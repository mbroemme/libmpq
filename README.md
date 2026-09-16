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

* Read, inspect, and extract MPQ archives, including embedded archives at a
  file offset.
* Read, inspect, and extract MPQE-wrapped MPQ archives, and create new MPQE
  archives with a caller-supplied authentication code.
* Create seekable MPQ v1 and v2 archives with fixed file-table capacity,
  optional `(listfile)` generation, and encrypted tables and file payloads.
* Add raw, single-unit, sectorized, and multi-sector files through streaming,
  memory-buffer, and filesystem-path APIs.
* Inspect archive, file, and block metadata, including names, sizes, flags,
  packed block sizes, and effective per-block compression methods.
* Read and write encrypted hash tables, block tables, sector offsets, and file
  payloads.
* Read and write PKWARE implode, Huffman, zlib, bzip2, SPARSE, and mono or
  stereo WAVE ADPCM compression. MPQ v2+ also supports the exclusive LZMA
  method; readers accept Blizzard multi-compression payloads.
* Read and create version-100 `(attributes)` metadata in MPQ v1+: CRC32,
  explicit FILETIME, MD5, and read-only patch-bit information.
* Explicitly verify stored sector Adler-32 checksums and available attributes
  CRC32 or MD5 values without changing normal extraction behavior.
* Support big-endian hosts through explicit little-endian serialization; CI
  runs the full test suite on emulated s390x.
* Provide optional Python 3.11+, D, and Java bindings.
* Install API manual pages for the library functions and `libmpq-config`.
* Provide a stable C API with installed headers under `include/libmpq`.

See the [developer guide](DEVELOPER.md) for API examples, optional metadata,
checksum verification, and writer compression policies.

## Requirements

The native library requires a C compiler and development headers and libraries
for zlib, bzip2, and lzma. Build tools depend on the platform:

* Linux and other Unix systems: a C99-capable compiler, GNU Autoconf,
  Automake, and Libtool.
* macOS: Xcode or the standalone Command Line Tools for Xcode, providing
  Apple Clang, the Apple linker, make, and the macOS SDK. Git checkouts also
  require GNU Autoconf, Automake, and GNU Libtool; the CI-tested setup obtains
  these build-generation tools through Homebrew.
* MinGW-w64: a C99-capable compiler, GNU Autoconf, Automake, and Libtool.
* Native MSVC: Visual Studio's C++ build tools, CMake 3.21 or newer, and vcpkg.

The Python, D, and Java bindings are maintained and distributed through their
native package ecosystems. They are included in source distributions but are
not installed by the native Autotools build.

The Java binding is built independently with Maven and requires JDK 22 or
newer. It uses the Foreign Function and Memory API, maps the stable public C
API, and uses an externally supplied native library. See the binding-specific
documentation below for build, test, and library-loading instructions.

## Building

### Unix (Autotools)

For build and install use the commands below. If `--prefix=/usr` is used, the
`make install` command must be run as root. It installs the native shared
library, public headers, tools, and manual pages. Language bindings are built
and installed separately with their native package managers.

```sh
./configure --prefix=/usr &&
make &&
make install
```

Use `./configure --prefix=DIR` to select a different installation prefix. Use
`./configure --help` to list the available configuration options. C99 is the
default language standard; callers may select another supported dialect through
`CFLAGS`, for example `CFLAGS="-std=c17"`.

Git checkouts require `sh autogen.sh` before `./configure`. Release source
archives already include the generated Autotools files, including `configure`,
so their users do not need to run `autogen.sh`.

#### Debian or Ubuntu

Install the build tools and compression-library development packages with:

```sh
sudo apt install build-essential autoconf automake libtool \
  zlib1g-dev libbz2-dev liblzma-dev
```

#### Fedora

Install the compiler, Autotools, and compression-library development packages
with:

```sh
sudo dnf install gcc make autoconf automake libtool \
  zlib-devel bzip2-devel xz-devel
```

#### openSUSE

Install the compiler, Autotools, and compression-library development packages
with:

```sh
sudo zypper install gcc make autoconf automake libtool \
  zlib-devel libbz2-devel liblzma-devel
```

#### Arch Linux

Install the base build tools and required libraries with:

```sh
sudo pacman -S --needed base-devel autoconf automake libtool \
  zlib bzip2 xz
```

### macOS (Apple toolchain with Autotools)

libmpq builds natively with Apple Clang, the Apple linker, the macOS SDK,
and the Apple-provided `/usr/bin/make`. GNU Autotools supplies the build frontend.
Use either full Xcode or the standalone Command Line Tools for Xcode. If you
do not need the Xcode IDE, install the standalone tools:

```sh
xcode-select --install
```

The supported SDK lacks the liblzma development headers. Install them through
Homebrew and add only their include directory, keeping system library linking:

```sh
brew install xz
export CPPFLAGS="-I$(brew --prefix xz)/include ${CPPFLAGS:-}"
```

Release source archives include the generated Autotools files and need no
Homebrew bootstrap tools. With the headers available, configure, build, test,
and optionally install:

```sh
./configure --prefix="${HOME}/.local"
/usr/bin/make -j"$(sysctl -n hw.ncpu)"
/usr/bin/make check
/usr/bin/make install
```

For a Git checkout, first install the GNU build-generation tools through
Homebrew and make GNU Libtool's commands available:

```sh
brew install autoconf automake libtool
export PATH="$(brew --prefix libtool)/libexec/gnubin:${PATH}"
```

Then bootstrap and build libmpq with the Apple toolchain:

```sh
sh autogen.sh
./configure --prefix="${HOME}/.local"
/usr/bin/make -j"$(sysctl -n hw.ncpu)"
/usr/bin/make check
/usr/bin/make install
```

Homebrew places the GNU Libtool commands in `libexec/gnubin` so they do not
conflict with Apple's `/usr/bin/libtool`. The `autogen.sh` script requires GNU
Libtool's `libtoolize` command.

CI also installs `pkg-config` through Homebrew to validate the native SDK
metadata and external consumers. It is not required by `autogen.sh` or the
normal source configuration.

The supported macOS CI configuration uses Homebrew's liblzma headers and links
zlib, bzip2, and liblzma from its macOS SDK/system environment. No Homebrew
library directory is added to the linker search path. The official macOS SDK
archives do not bundle private copies of these codec libraries.

### Windows

The native C library supports MSVC x64 and ARM64 through CMake. Native CI
runners build both architectures, run the C regression suite through CTest,
and compile and execute installed consumers. Autotools remains the POSIX and
MinGW-w64 x86_64 build frontend. Windows language bindings are not included
in this support.

#### MSVC (CMake)

Install CMake, Visual Studio's C++ build tools, and vcpkg. From a Developer
PowerShell, install the native dependencies and build (x64 example):

```powershell
vcpkg install zlib:x64-windows bzip2:x64-windows liblzma:x64-windows
cmake -S . -B build -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

For a native ARM64 build, use an ARM64 developer environment, replace
`x64-windows` with `arm64-windows`, and use `-A ARM64`. MinGW ARM64 is not
supported yet.

Consumers include `libmpq/mpq.h` and link the DLL import library or static
library, without special preprocessor definitions. Use `-DBUILD_SHARED_LIBS=OFF`
for a static CMake build. Static consumers also link the codec and Windows
system libraries.

#### MinGW-w64 (Autotools)

MinGW-w64 uses Autotools, including in the separate Windows CI job:

```sh
sh autogen.sh
./configure --host=x86_64-w64-mingw32 --enable-shared --disable-static
make
make check
make install
```

Provide MinGW-built zlib, bzip2, and lzma libraries, not Unix libraries. For
cross-builds, set dependency include/library search paths as needed and run
`make check LOG_COMPILER=wine` with the DLL directories in `WINEPATH`.
For a static-only build use `--disable-shared --enable-static`; the generated
`libmpq-config --cflags --libs` supplies the include path and required libraries.

#### Filesystem behavior

Public filesystem paths are UTF-8 on Windows, converted to UTF-16 for native
filesystem calls. Both slash styles and absolute or relative paths are
accepted. Archive streams always use binary mode. Clone identity checks use
the opened file's volume and file ID.

MPQE creation retains the destination directory independently of cwd changes.
Windows temporary files use exclusive creation, system-generated randomness,
and non-inheritable handles. Plaintext has a protected owner-only ACL; encrypted
output inherits the destination directory's normal ACL. Publication replaces
the destination in one same-directory operation, only after finalization and
plaintext cleanup. Handled failures attempt cleanup; crashes can leave temps.

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

Individual release downloads provide prebuilt native C SDKs for Linux glibc
and musl (both x86_64 and aarch64), macOS arm64 and x86_64, Windows MSVC
x64 and ARM64, and Windows MinGW-w64 x86_64. Each SDK includes public headers,
a shared library, platform-appropriate import libraries or development
metadata, licenses, and documentation. The macOS SDKs are relocatable,
architecture-specific `.tar.gz` development archives, not application installers.

Linux and macOS SDKs use their relevant system runtime and codec dependencies.
Windows SDK ZIPs bundle the required non-system runtime DLLs under `bin/`;
choose the MSVC or MinGW-w64 package to match your compiler. No special
libmpq consumer preprocessor define is required. See the
[SDK setup instructions](DEVELOPER.md#native-c-sdk-packages) and
[release package summary](DEVELOPER.md#release-package-summary).

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
  temporary file; completed POSIX archives use normal caller-umask permissions.
  Cleanup is best effort, so a crash can leave the plaintext temporary behind.
* Signature generation, patch creation/application, and StormLib-specific key
  modes are not supported. Stored attributes are not automatically verified.

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
