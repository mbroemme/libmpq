# libmpq

[![CI](https://github.com/mbroemme/libmpq/actions/workflows/ci.yml/badge.svg)](https://github.com/mbroemme/libmpq/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/release/mbroemme/libmpq?style=flat&label=release&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/releases)
[![GitHub issues](https://img.shields.io/github/issues/mbroemme/libmpq?style=flat&label=issues&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/issues)
[![GitHub forks](https://img.shields.io/github/forks/mbroemme/libmpq?style=flat&label=forks&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/network/members)
[![GitHub stars](https://img.shields.io/github/stars/mbroemme/libmpq?style=flat&label=stars&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/stargazers)
[![License: LGPL-2.1-or-later](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue.svg)](COPYING.LESSER)
[![GitHub downloads](https://img.shields.io/github/downloads/mbroemme/libmpq/total?style=flat&label=downloads&cacheSeconds=21600)](https://github.com/mbroemme/libmpq/releases)

A portable C library for reading, decrypting, decompressing, and extracting
files from MoPaQ (MPQ) archives.

## Overview

MPQ is a proprietary archive format created by Mike O'Brien in 1996. It is
used by Blizzard games including Diablo, Diablo II, StarCraft, Warcraft II:
Battle.net Edition, Warcraft III, and World of Warcraft.

libmpq provides a C API for applications that need to inspect MPQ archives and
extract their file contents. Archive creation is not supported.

## Features

* Read MPQ archives and embedded archives located at a file offset.
* Read archive metadata, file names, file sizes, flags, and block information.
* Decrypt encrypted hash tables, block tables, and file payloads.
* Decompress zlib, bzip2, Huffman, PKWARE implode, Blizzard multi-compression,
  and mono or stereo WAVE ADPCM payloads.
* Provide a stable C API with installed headers under `include/libmpq`.
* Provide optional Python 2 ctypes and D language bindings.
* Install API manual pages for the library functions and `libmpq-config`.

## Requirements

The build system requires:

* A C99-capable C compiler.
* GNU Autoconf, Automake, and Libtool.
* zlib development headers and libraries.
* bzip2 development headers and libraries.

The Python binding is optional and is enabled when a Python interpreter version
2.4 or newer is found. The D binding is installed as a D module and does not
form part of the C library build.

## Building

For build and install use the commands below and if `--prefix=/usr` is used,
the `make install` command must be run as root user. It installs the shared
library, public header, bindings, and manual pages.

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

Pass `-lz -lbz2` explicitly when linking in environments that do not resolve
the shared library's transitive dependencies automatically.

## Bindings

The source tree contains bindings for the public C API:

* `bindings/python/mpq.py` provides a Python 2 ctypes wrapper and buffered
  archive/file readers.
* `bindings/d/mpq.d` provides D declarations and helper classes for Phobos.

The Python binding is included automatically when the required interpreter is
found during configuration. The D binding is installed under the configured D
include directory.

## Documentation

The documentation includes manual pages for all available public API
functions, together with a helper for retrieving the compiler and linker flags
required to use libmpq.

## Limitations

* MPQ archive creation is not supported.
* Big-endian systems are not currently supported.
* Windows support is not currently tested or documented by the Autotools build.
* The Python binding uses Python 2 syntax and is retained for compatibility.

## Contributing

Bug reports, compatibility reports, patches, and testing results are welcome
in the [GitHub issue tracker](https://github.com/mbroemme/libmpq/issues).
Testing against a broad collection of MPQ archives is especially useful.

## Authors

The project was initiated by Maik Broemme. Current and past contributors
include:

* Maik Broemme <mbroemme@libmpq.org>
* Tilman Sauerbeck <tilman@code-monkey.de>
* Forrest Voight <voights@gmail.com>
* Georg Lukas <georg@op-co.de>

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
