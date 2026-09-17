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

Linux SDKs are available as individual relocatable x86_64 and aarch64 release
archives, built and tested on native runners:

* `libmpq-X.Y.Z-linux-glibc-x86_64.tar.gz` for glibc 2.17 and later.
* `libmpq-X.Y.Z-linux-glibc-aarch64.tar.gz` for glibc 2.17 and later.
* `libmpq-X.Y.Z-linux-musl-x86_64.tar.gz` for musl 1.2 and later.
* `libmpq-X.Y.Z-linux-musl-aarch64.tar.gz` for musl 1.2 and later.

The SDKs use the host's zlib, bzip2, and liblzma shared libraries; those
runtime and development dependencies are not bundled. The glibc baseline
applies to libmpq itself. Each archive extracts a single package directory
containing the executable helper, public headers, shared library, pkg-config
metadata, manual pages, licenses, README, and BUILDINFO.

For example, after extracting the glibc SDK, set:

```sh
export LIBMPQ_ROOT="$PWD/libmpq-X.Y.Z-linux-glibc-x86_64"
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

For the musl SDK, use `libmpq-X.Y.Z-linux-musl-x86_64` as
`LIBMPQ_ROOT` instead. On aarch64, select the corresponding directory ending
in `-aarch64` for either libc.

### macOS

macOS SDKs are available as individual relocatable archives for Apple silicon
and Intel systems:

* `libmpq-X.Y.Z-macos-arm64.tar.gz`
* `libmpq-X.Y.Z-macos-x86_64.tar.gz`

Each package contains `bin/libmpq-config`, `include/libmpq/mpq.h`, a versioned
`lib/libmpq.*.dylib` with a `libmpq.dylib` symlink, `lib/pkgconfig/libmpq.pc`,
manual pages, licenses, and project documentation. The dylib uses an `@rpath`
install name and the package metadata derives paths relative to the extracted
SDK. Select the archive that matches the native architecture; packages are not
Universal 2 binaries.

Set `LIBMPQ_ROOT` to the extracted `libmpq-X.Y.Z-macos-arm64` or
`libmpq-X.Y.Z-macos-x86_64` directory, matching the selected package.

The SDK depends on macOS-provided zlib, bzip2, and liblzma. Add its `bin/`
directory to `PATH` to locate `libmpq-config`, then pass the extracted SDK
root explicitly: `libmpq-config --prefix="${LIBMPQ_ROOT}" --cflags` and
`libmpq-config --prefix="${LIBMPQ_ROOT}" --libs`. Add `lib/pkgconfig/` to
`PKG_CONFIG_PATH` for compiler and linker flags. Consumers should add an
application-appropriate runtime rpath for the SDK's `lib/` directory when
linking, for example `-Wl,-rpath,"${LIBMPQ_ROOT}/lib"`.

### Windows MSVC

Extract `libmpq-X.Y.Z-windows-msvc-x64.zip` for x64 or
`libmpq-X.Y.Z-windows-msvc-arm64.zip` for ARM64. Both are built and tested
on native Windows runners. The SDK contains
`bin/libmpq.dll`, the `lib/libmpq.lib` import library, and the public header
`include/libmpq/mpq.h`. Required non-system runtime DLLs are bundled under
`bin/`, together with `libmpq.pdb` when available.

Add the SDK's `include/` directory to your compiler's include search path and
link against `lib/libmpq.lib`. Put the SDK's `bin/` directory on `PATH` when
running applications. No libmpq-specific consumer preprocessor define is
required.

### Windows MinGW-w64

Extract `libmpq-X.Y.Z-windows-mingw-x86_64.zip` for MINGW64 x86_64 or
`libmpq-X.Y.Z-windows-mingw-aarch64.zip` for native Windows ARM64 using
MSYS2 CLANGARM64. The SDK contains
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
`manylinux_2_17_x86_64`, `manylinux_2_17_aarch64`, `musllinux_1_2_x86_64`,
`musllinux_1_2_aarch64`, `win_amd64`, `win_arm64`, `macosx_11_0_x86_64`,
and `macosx_11_0_arm64`. Builds and
bundled-library tests run natively on each architecture using CPython 3.11,
while wheel tags remain `py3-none`. Linux wheels contain a private
native library at `mpq_libs/libmpq.so`, loaded directly by package path; the
wheel does not require a separately installed libmpq library. This private
library intentionally has no ELF SONAME. The Python release archive,
`libmpq-python-X.Y.Z.zip`, contains one sdist and all eight Linux/Windows/macOS wheels.

Windows wheels reuse the shared MSVC/CMake build with matching `x64-windows`
or `arm64-windows` vcpkg dependencies. The backend receives `LIBMPQ_LIBRARY`
and bundles `mpq_libs/libmpq.dll`; delvewheel uses `--analyze-existing`,
`--custom-patch`, and the matching runtime directory through `--add-path`
to bundle required non-system dependencies. No separate libmpq SDK is
required. Release validation checks the repaired wheel tags and every
bundled DLL's PE architecture. Native installed-wheel tests clear the
library override and exclude vcpkg/build paths from `PATH` before importing
the binding and running the full Python suite.

macOS wheels reuse the native SDK's Apple Clang/SDK and Autotools build,
including the full C regression suite and Apple-provided `/usr/bin/make`.
Both architectures preserve its macOS 11.0 baseline, declared once in the
Python workflow and checked against the actual Mach-O deployment target.
Homebrew xz supplies headers only; zlib, bzip2, and liblzma resolve to the
system libraries. The installed dylib is passed through `LIBMPQ_LIBRARY`
and bundled as `mpq_libs/libmpq.dylib`. Delocate repairs any non-system
dependencies without copying macOS system libraries. No separate SDK is
required, and no universal2 wheel is produced.

Inline macOS wheel checks validate tags, every dylib's architecture,
signatures, and obvious absolute build/Homebrew runtime paths. Native Intel
and Apple Silicon jobs install the repaired wheel
into a clean virtual environment and run all Python tests without build
overrides, Homebrew paths, or dynamic-library search environment variables.

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
x86_64, plus LDC on Linux aarch64, with separate glibc and musl variants.
DMD remains x86_64-only in the existing release toolchains. All packages are
built and tested natively, using Ubuntu 24.04 for glibc and Alpine 3.22 for
musl. Binary archives use
`libmpq-d-X.Y.Z-<compiler>-linux-<libc>-<architecture>.tar.gz`; the D release ZIP
requires all six binary archives plus the source package. Binary packages
include the precompiled D archive and the complete `libmpq.so` SONAME chain.
Their bundled library directory is supplied automatically at link time; runtime loading may
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

All source, binding, Linux, macOS, and Windows packages are built before
publication. The macOS and Windows SDKs add to the existing release set; they
do not replace the Linux SDK or binding archives. The signed GitHub Release
includes `SHA256SUMS` covering every archive, its detached signature
`SHA256SUMS.asc`, and the public key `libmpq-release-signing-key.asc`.

| Package | Release archive | Contents |
| --- | --- | --- |
| Source distributions | `libmpq-X.Y.Z.tar.gz`, `libmpq-X.Y.Z.tar.bz2` | Configure-ready Automake distributions |
| Native C SDK - Linux glibc x86_64 | `libmpq-X.Y.Z-linux-glibc-x86_64.tar.gz` | Relocatable glibc SDK |
| Native C SDK - Linux glibc aarch64 | `libmpq-X.Y.Z-linux-glibc-aarch64.tar.gz` | Relocatable glibc SDK |
| Native C SDK - Linux musl x86_64 | `libmpq-X.Y.Z-linux-musl-x86_64.tar.gz` | Relocatable musl SDK |
| Native C SDK - Linux musl aarch64 | `libmpq-X.Y.Z-linux-musl-aarch64.tar.gz` | Relocatable musl SDK |
| Native C SDK - macOS arm64 | `libmpq-X.Y.Z-macos-arm64.tar.gz` | Relocatable arm64 dylib SDK |
| Native C SDK - macOS x86_64 | `libmpq-X.Y.Z-macos-x86_64.tar.gz` | Relocatable x86_64 dylib SDK |
| Native C SDK - Windows MSVC x64 | `libmpq-X.Y.Z-windows-msvc-x64.zip` | Shared DLL, `.lib` import library, headers, runtime DLLs, licenses, optional PDB |
| Native C SDK - Windows MSVC ARM64 | `libmpq-X.Y.Z-windows-msvc-arm64.zip` | Shared DLL, `.lib` import library, headers, runtime DLLs, licenses, optional PDB |
| Native C SDK - Windows MinGW x86_64 | `libmpq-X.Y.Z-windows-mingw-x86_64.zip` | Shared DLL, `.dll.a` import library, headers, relocatable metadata, runtime DLLs, licenses |
| Native C SDK - Windows MinGW aarch64 | `libmpq-X.Y.Z-windows-mingw-aarch64.zip` | Native MSYS2 CLANGARM64 SDK with the same MinGW layout |
| Python package | `libmpq-python-X.Y.Z.zip` | Python sdist and all wheels |
| Java package | `libmpq-java-X.Y.Z.zip` | Runtime, sources, Javadoc, licenses, and README |
| D package | `libmpq-d-X.Y.Z.zip` | D source and compiler/platform packages |

### Windows release packaging

MSVC x64 and ARM64 use CMake; MinGW x86_64 and aarch64 use Autotools with
MINGW64 and CLANGARM64 respectively. Windows SDKs contain shared libraries
only; MSVC includes the Release PDB when available.
Bash packaging helpers inspect PE imports recursively with `dumpbin` or
`objdump`. Non-system DLLs are bundled from the selected toolchain. Their
licenses are copied using vcpkg ownership metadata or MSYS2 `pacman` package
records. Windows packaging checks the PE architecture of libmpq and every
bundled runtime DLL against the requested architecture. Windows system DLLs
and API sets are excluded.
A final dependency scan resolves non-system imports only from the staged SDK,
not the toolchain or `PATH`.

CLANGARM64 builds use native Clang and LLVM tools from `/clangarm64/bin`.
Runtime DLLs come only from `/clangarm64`, not `/mingw64`. Both MinGW targets
run the full C suite and an installed consumer natively. The ARM64 package
uses the GNU architecture token `aarch64`; MSVC keeps `arm64`.

Installed consumer smoke tests link against each staged SDK and run with only
its `bin/` and Windows system directories on `PATH`; build-tree or toolchain
DLLs cannot hide a missing bundled dependency. ZIP integrity and single-root
layout checks run before upload. The Bash helper tests also run in normal CI.

### macOS release packaging

macOS SDKs are built natively for arm64 and x86_64 using Apple Clang, the Apple
linker, the macOS SDK selected through `xcrun`, and `/usr/bin/make`. GNU
Autotools supplies the build frontend; Homebrew supplies Autoconf, Automake,
and GNU Libtool for build-system bootstrap, and pkg-config for package
validation. Homebrew's xz supplies missing liblzma development headers through
`CPPFLAGS` only; library linking still uses the macOS SDK/system environment,
without a Homebrew library search path. The macOS build/package steps use
`MACOSX_DEPLOYMENT_TARGET=11.0`. The package helper uses the installed
GNU Libtool dylib names, normalizes each dylib ID to `@rpath`, and rejects
Homebrew, MacPorts, build-tree, and temporary-path dependency leaks. Package
tests validate the architecture, ad-hoc dylib signature, deployment target,
dylib ID, dependency paths, `LC_RPATH` entries, relocatable pkg-config and
explicit-prefix `libmpq-config` metadata, external consumers, and a second
extraction location. macOS packages do not bundle system codec libraries.

### Source validation and release publication

Source packaging uses `make distcheck` followed by `make dist-bzip2` to produce
gzip and bzip2 archives, and runs CMake/CTest from an extracted source archive.
The final job requires all archives listed above and generates one
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
