# libmpq developer guide

This guide covers native API usage, binding development, SDK packaging, and
release workflows. See [README.md](README.md) for requirements, building, and
limitations, and [MPQ.md](MPQ.md) for the archive-format reference.

## Native API example

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

## Streaming and one-shot writers

`libmpq__writer_begin()` starts an archive member and returns `mpq_writer_s`.
Use `libmpq__writer_write()`, `libmpq__writer_timestamp()`, and
`libmpq__writer_finish()` on that handle. Finishing consumes it, even on error.
Use `libmpq__archive_add_data()` to add an in-memory source in one call, or
`libmpq__archive_add_path()` to add a filesystem-path source.

## Optional attributes

Select optional metadata separately from archive creation flags:

```c
mpq_archive_create_options_s options = {0};
options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE |
                LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED;
options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_FILETIME |
                     LIBMPQ_ATTRIBUTE_MD5;
```

Zero `options.attributes` disables generation. Any nonzero combination
creates one `(attributes)` file and consumes one reserved file slot.
Use `libmpq__archive_attributes()` to query available arrays and
`libmpq__file_attributes()` to read a file's stored values. FILETIME is
explicit/default-zero; set it through `libmpq__writer_timestamp()` using Windows
FILETIME, not Unix time.

## Explicit checksum verification and block metadata

Explicitly compare available stored checksums after opening an archive:

```c
uint32_t mismatches = 0;
int32_t status = libmpq__file_verify(archive, file_number,
                                    LIBMPQ_VERIFY_ALL, &mismatches);
/* status < 0: operation failed; otherwise inspect the requested VERIFY_* bits. */
```

`LIBMPQ_VERIFY_ALL` requests sector Adler-32 and file CRC32/MD5 checks.
The returned mismatch mask uses those same bits and is a subset of the request.
A set bit means an available checksum mismatched; a clear bit means it matched
or was unavailable/skipped. Operational errors leave the mask zero.
Sector checks cover decrypted packed bytes before decompression; absent tables
and unavailable entries are skipped. Use `LIBMPQ_VERIFY_SECTOR_CRC` alone to
verify sectors without requiring `(attributes)`.

Use `libmpq__block_verify(archive, file_number, block_number, &checksum,
&mismatches)` to verify one sector and retrieve its stored Adler-32.
It returns `LIBMPQ_ERROR_EXIST` for unavailable checksums; success returns
zero or `LIBMPQ_VERIFY_SECTOR_CRC` in `mismatches`. Both outputs stay zero
on errors. No calculated checksum is exposed.

Use `libmpq__block_compression()` to inspect the stored method without
decoding. Use `libmpq__file_flags()` to retrieve a member's complete stored
block-table flags and inspect the `LIBMPQ_FILE_FLAG_*` bits for file-level
storage properties. Zero means raw storage/fallback; LZMA is returned as
on-disk `0x12`, not the writer selector. In MPQ v1, `0x12` retains its legacy
bzip2/zlib meaning.

`libmpq__block_size_packed()` reports a block's stored data bytes, excluding
offset and checksum tables. `libmpq__block_size_unpacked()` reports the
decoded size needed for a `libmpq__block_read()` output buffer.

To generate sector checksums, add `LIBMPQ_FILE_FLAG_SECTOR_CRC` to the file
options alongside `LIBMPQ_FILE_FLAG_COMPRESS` or `LIBMPQ_FILE_FLAG_IMPLODE`.
This is opt-in for sectorized files, including encrypted files. Empty, raw,
and single-unit files do not generate checksum tables. Tables are stored
unencrypted and compressed with zlib only when smaller.

File checksum requests without `(attributes)` return `LIBMPQ_ERROR_EXIST`.
Missing individual CRC32/MD5 values are skipped, so zero mismatch bits do not
prove that hashes were present. Normal extraction never verifies implicitly.
Lossy ADPCM output can differ from the writer's source-byte checksums.

## Writer compression policy

For MPQ v2+ creation, `LIBMPQ_COMPRESSION_LZMA` is an exclusive API selector,
not a chainable multi-compression bit. It maps to serialized method `0x12`;
that byte retains its legacy bzip2-plus-zlib meaning in MPQ v1.

Writer compression defaults to `LIBMPQ_COMPRESSION_POLICY_STANDARD`, favoring
interoperability. For MPQ v2+, this permits zlib, PKWARE, bzip2, LZMA, SPARSE
alone or paired with zlib/bzip2, and Huffman paired with mono or stereo WAVE
ADPCM. The fixed SPARSE forms are `0x20`, `0x22`, and `0x30`. MPQ v1 retains
normal compression-mask semantics under either policy, allowing other valid
combinations such as SPARSE with Huffman (`0x21`) or PKWARE (`0x28`). Add
`LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED` to the archive creation flags to
permit broader valid lossless SPARSE combinations and other implemented forms,
including standalone Huffman, in MPQ v2+. `EXTENDED` output may be less
interoperable with StormLib and other MPQ implementations; it is not
classified as invalid MPQ. Readers stay permissive.

Use `libmpq__archive_compression_allowed(version, mask, policy)` to query
whether a compression selection is allowed by the writer policy. Version uses
the zero-based `LIBMPQ_ARCHIVE_VERSION_*` selectors. Both policies reject
unknown bits, conflicting ADPCM channels, and v2 chains containing both zlib
and bzip2, whose surviving stages could collide with LZMA's `0x12`. Both
policies reject SPARSE combined with WAVE ADPCM: lossy ADPCM cannot preserve
SPARSE control bytes. If skipped stages leave a method disallowed by the
selected policy, the original sector is stored raw. The first WAVE sector
stays lossless (zlib for STANDARD v2).

## Native C SDK packages

Prebuilt SDKs provide public headers, a shared library, development metadata,
licenses, and documentation. Choose the package matching your platform and
compiler; see the [release package summary](#release-package-summary) for the
complete download list.

### Linux

The native binary release, `libmpq-native-X.Y.Z.zip`, contains relocatable
x86_64 Linux SDK archives:

* `libmpq-X.Y.Z-linux-glibc-x86_64.tar.gz` for glibc 2.17 and later.
* `libmpq-X.Y.Z-linux-musl-x86_64.tar.gz` for musl 1.2 and later.

The SDKs use the host's zlib, bzip2, and liblzma shared libraries; those
runtime and development dependencies are not bundled. The glibc baseline
applies to libmpq itself. Each archive extracts a single package directory
containing the executable helper, public headers, shared library, pkg-config
metadata, manual pages, licenses, README, and BUILDINFO.

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

### Windows MSVC

Extract `libmpq-X.Y.Z-windows-msvc-x64.zip`. The SDK contains
`bin/libmpq.dll`, the `lib/libmpq.lib` import library, and the public header
`include/libmpq/mpq.h`. Required non-system runtime DLLs are bundled under
`bin/`, together with `libmpq.pdb` when available.

Add the SDK's `include/` directory to your compiler's include search path and
link against `lib/libmpq.lib`. Put the SDK's `bin/` directory on `PATH` when
running applications. No libmpq-specific consumer preprocessor define is
required.

### Windows MinGW-w64

Extract `libmpq-X.Y.Z-windows-mingw-x86_64.zip`. The SDK contains
`bin/libmpq*.dll`, the `lib/libmpq.dll.a` import library, and the public header
`include/libmpq/mpq.h`. Required non-system runtime DLLs are bundled under
`bin/`. No libmpq-specific consumer preprocessor define is required.

Add `lib/pkgconfig/` to `PKG_CONFIG_PATH` and use
`pkg-config --cflags --libs libmpq` for compiler and linker flags. The SDK also
provides `bin/libmpq-config` for use from a shell such as MSYS2 Bash. Put the
SDK's `bin/` directory on `PATH` when running applications.

## Binding development

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
[`dub.sdl`](dub.sdl), and the modules are under `bindings/d/source/libmpq`.
Import the high-level API with:

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

## Release package summary

Pushing a `vX.Y.Z` tag runs the top-level release workflow. It rejects tags that
do not exactly match `AC_INIT` and the CMake project version. Build jobs remain
read-only; only the final job receives `contents: write` through `GITHUB_TOKEN`.

All source, binding, Linux, and Windows packages are built before publication.
The Windows SDKs add to the existing release set; they do not replace the Linux
SDK or binding archives. The signed GitHub Release includes `SHA256SUMS`
covering every archive, its detached signature `SHA256SUMS.asc`, and the public
key `libmpq-release-signing-key.asc`.

| Package | Release archive | Contents |
| --- | --- | --- |
| Source distributions | `libmpq-X.Y.Z.tar.gz`, `libmpq-X.Y.Z.tar.bz2` | Configure-ready Automake distributions |
| Native C SDK — Linux | `libmpq-native-X.Y.Z.zip` | glibc and musl x86_64 SDK packages |
| Native C SDK — Windows MSVC | `libmpq-X.Y.Z-windows-msvc-x64.zip` | Shared DLL, `.lib` import library, headers, runtime DLLs, licenses, optional PDB |
| Native C SDK — Windows MinGW | `libmpq-X.Y.Z-windows-mingw-x86_64.zip` | Shared DLL, `.dll.a` import library, headers, relocatable metadata, runtime DLLs, licenses |
| Python package | `libmpq-python-X.Y.Z.zip` | Python sdist and all wheels |
| Java package | `libmpq-java-X.Y.Z.zip` | Runtime, sources, Javadoc, licenses, and README |
| D package | `libmpq-d-X.Y.Z.zip` | D source and compiler/platform packages |

### Windows release packaging

MSVC uses CMake and MinGW uses Autotools. Both Windows SDKs contain shared
libraries only; MSVC includes the Release PDB when available. Bash packaging
helpers inspect PE imports recursively with `dumpbin` or `objdump`. Non-system
DLLs are bundled from the selected toolchain. Their licenses are copied using
vcpkg ownership metadata or MSYS2 `pacman` package records. Windows system DLLs
and API sets are excluded. A final dependency scan resolves non-system imports
only from the staged SDK, not the toolchain or `PATH`.

Installed consumer smoke tests link against each staged SDK and run with only
its `bin/` and Windows system directories on `PATH`; build-tree or toolchain
DLLs cannot hide a missing bundled dependency. ZIP integrity and single-root
layout checks run before upload. The Bash helper tests also run in normal CI.

### Source validation and release publication

Source packaging uses `make distcheck` followed by `make dist-bzip2` to produce
gzip and bzip2 archives, and runs CMake/CTest from an extracted source archive.
The final job requires all eight archives listed above and generates one
filename-sorted `SHA256SUMS` covering them. The existing `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE` secrets sign that manifest; publication fails rather than
falling back to unsigned checksums.
The release includes `SHA256SUMS`, its detached signature `SHA256SUMS.asc`, and
the exported public key `libmpq-release-signing-key.asc`.

After verifying the checksums and signature, the final job creates a draft
release with all archives and signing assets, using `--notes-from-tag`, then
publishes it. If a published release already exists, the job uploads the assets
without replacing existing files. An existing draft causes a safe failure;
inspect and publish or remove it before retrying.

## Registry publication dispatch

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
