# libmpq

libmpq is a C library for extracting and manipulating MoPaQ MPQ archives.

MPQ, or MoPaQ, is a proprietary archive format created by Mike O'Brien in
1996. It is used by Blizzard games including Diablo, Diablo II, StarCraft,
Warcraft II: Battle.net Edition, Warcraft III, and World of Warcraft.

## Features

libmpq can be used by applications to extract and manipulate MPQ archives.
Creating MPQ archives is not currently supported.

Since version 0.4.0, the package includes manual pages for every library
function.

## Installation

Generate the Autotools build files, configure, build, and install:

```sh
./autogen.sh
./configure
make
make check
make install
```

Use `./configure --prefix=PATH` to install under a prefix other than
`/usr/local`. Use `./configure --help` for the full list of supported build and
installation options.

To remove build artifacts from the source tree:

```sh
make clean
```

To also remove files created by `configure`:

```sh
make distclean
```

## Usage Example

The example below takes the first command-line argument as an MPQ archive and
extracts the first file to a buffer.

Compile on 32-bit systems with:

```sh
gcc \
  -D_FILE_OFFSET_BITS=64 \
  -D_LARGE_FILES=1 \
  -D_LARGEFILE_SOURCE=1 \
  mpq-example.c -o mpq-example -lmpq -lz -lbz2 -I/usr/local/include/libmpq
```

Compile on 64-bit systems with:

```sh
gcc \
  -D_LARGE_FILES=1 \
  mpq-example.c -o mpq-example -lmpq -lz -lbz2 -I/usr/local/include/libmpq
```

```c
#include <limits.h>
#include <mpq.h>
#include <stdlib.h>

int main(int argc, char **argv) {
        mpq_archive_s *mpq_archive;
        off_t out_size;
        char *out_buf;

        /* open the mpq archive given as first parameter. */
        libmpq__archive_open(&mpq_archive, argv[1], -1);

        /* get size of first file (0) and malloc output buffer. */
        libmpq__file_size_unpacked(mpq_archive, 0, &out_size);
        out_buf = malloc(out_size);

        /* read, decrypt and unpack file to output buffer. */
        libmpq__file_read(mpq_archive, 0, out_buf, out_size, NULL);

        /* close the mpq archive. */
        libmpq__archive_close(mpq_archive);

        free(out_buf);
        return 0;
}
```

## FAQ

### What is libmpq?

libmpq is a library for manipulating MoPaQ MPQ archives mostly used by Blizzard
games.

### What can I do with libmpq?

You can write applications that extract and manipulate MPQ archives.

### Is it legal?

The original FAQ answered yes, based on the archive format information being
publicly available.

### Is there a description of the functions?

Yes. Since version 0.4.0, libmpq includes API documentation as manual pages.

### Can I help?

Yes. Help is useful not only with development, but also with testing. A good
starting point is testing a recent libmpq version with every MPQ archive you can
get.

## Planned Work

Features and functionality that should be added in the future:

* Porting for big endian systems.
* Porting for Windows.
* Creating MPQ archives.
* Brute forcing unknown filenames used by Blizzard archives.

## Authors

Project initiator:

* Maik Broemme <mbroemme@libmpq.org>

Developers:

* Maik Broemme <mbroemme@libmpq.org>
* Tilman Sauerbeck <tilman@code-monkey.de>
* Forrest Voight <voights@gmail.com>
* Georg Lukas <georg@op-co.de>

## Thanks

libmpq was originally created by Maik Broemme <mbroemme@libmpq.org>. Thanks to:

* Ladislav Zezula <ladik@zezula.net>, StormLib creator.
* Marko Friedemann <marko.friedemann@bmx-chemnitz.de>, initial porter of
  StormLib to Linux.
* Tom Amigo <tomamigo@apexmail.com>, one of the first people to decrypt the
  MoPaQ archive format.
* ShadowFlare <BlakFlare@hotmail.com>, creator of the ShadowFlare MPQ API.
* Justin Olbrantz (Quantam) <omega@dragonfire.net>, creator of the client using
  the ShadowFlare MPQ API.

## Reporting Bugs

Bug reports for libmpq can be sent to:

* Maik Broemme <mbroemme@libmpq.org>

## License

libmpq is licensed under the GNU Lesser General Public License version 2.1 or
later. See `COPYING`, `COPYING.LESSER`, and `RELICENSING.md`.
