# libmpq release guide

This guide covers release packaging, validation, publication, and registry
workflows. See [DEVELOPER.md](DEVELOPER.md) for native API, SDK, and binding
development details.

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

## Native package creation

### Linux

The release set includes the four native Linux glibc and musl SDK archives
listed above, built and tested on native x86_64 and aarch64 runners. See
[DEVELOPER.md](DEVELOPER.md#native-c-sdk-packages) for SDK layout and use.

### macOS

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

### Windows MSVC and MinGW-w64

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

## Binding package creation

### Python

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

### D

The D release archive is `libmpq-d-X.Y.Z.zip`. It contains the D source
package and compiler-specific binary packages for DMD and LDC on Linux
x86_64, plus LDC on Linux aarch64, with separate glibc and musl variants.
DMD remains Linux x86_64-only in the existing release toolchains. Linux packages
are built and tested natively, using Ubuntu 24.04 for glibc and Alpine 3.22 for
musl. Linux binary archives use
`libmpq-d-X.Y.Z-<compiler>-linux-<libc>-<architecture>.tar.gz`. Binary packages
include the precompiled D archive and the complete `libmpq.so` SONAME chain.
Their bundled library directory is supplied automatically at link time; runtime loading may
still require `LD_LIBRARY_PATH`. `BUILDINFO` records compiler and native build
metadata.

macOS adds `libmpq-d-X.Y.Z-<compiler>-macos-<architecture>.tar.gz` for
`dmd` on `x86_64` and `ldc` on `x86_64` and `arm64`. Intel uses `macos-15-intel` and
Apple Silicon uses `macos-15`. The existing native SDK installation, `@rpath`
normalization, ad-hoc signing, deployment-target and dependency validation are
reused; only its dylib/symlink chain is copied into the D package. The macOS
11.0 target is recorded in `BUILDINFO`, without Linux libc fields.

Stable DMD 2.113.0 does not provide the required macOS ARM64 `-marm64` target.
The DMD arm64 binary package is not published until a stable DMD release
provides that support. LDC remains supported on macOS arm64.
DUB's internal ARM platform token is `aarch64`,
while macOS archive names use `arm64`. LDC uses the native Apple Silicon slice.
All generated Mach-O artifacts must be single-architecture. Extracted consumers
run with the requested native architecture, check the version, and trace loading
of the packaged dylib. Compiler versions remain selected by
`dlang-community/setup-dlang@v2` and recorded in each package's `BUILDINFO`.

Windows adds `libmpq-d-X.Y.Z-<compiler>-windows-x86_64.zip` for DMD and LDC
on `windows-latest`. The existing MSVC x64 CMake/vcpkg shared build runs CTest
before installation. The Windows SDK helper supplies recursive runtime DLL
discovery, architecture validation, and dependency licenses. Each D package
contains `bin/libmpq.dll` and its non-system dependencies, `lib/libmpq.lib`,
and the precompiled `lib/libmpq-<compiler>.lib` in MS-COFF format.
DUB's `windows-x86_64-<compiler>` configuration selects both packaged libraries.
PE/COFF checks require the package architecture for every DLL, library object,
and consumer.
The extracted-package consumer executes with only package and Windows system
directories on `PATH`, excluding vcpkg and native build paths. `BUILDINFO`
records the compiler version, Windows architecture, MSVC native toolchain,
and `x64-windows` triplet, without libc or macOS fields.

LDC additionally produces `libmpq-d-X.Y.Z-ldc-windows-arm64.zip` on
`windows-11-vs2026-arm`, reusing MSVC ARM64 and `arm64-windows` dependencies.
The existing setup action installs official LDC multilib. Its compiler PE
architecture selects the VS host tools: x64 under Windows-on-ARM emulation or
native ARM64, always targeting ARM64. DUB receives
`--arch=aarch64-windows-msvc`, which passes LDC's explicit `-mtriple` option
to target probing and compilation; direct interface generation uses the same
triple. DUB must report `windows`, `aarch64`, and `ldc`. Release filenames
retain `arm64`, while the binary selector is `windows-aarch64-ldc`.
All packaged PE/COFF members and the native extracted consumer must be AA64,
not x64. `BUILDINFO` additionally records `d_target` and the actual
`compiler_host_architecture`. Windows ARM64 does not support DMD packages.
The source recipe remains `libs "mpq"`: only source-tree builds see a temporary
`mpq.lib` compatibility copy. Binary recipes select `libmpq.lib` explicitly,
and extracted consumers restore the original MSVC `LIB` before linking.

The D release ZIP requires the exact set of six Linux binary packages, three
macOS binary packages, three Windows binary packages, and one source package.

### Java

The Java release archive, `libmpq-java-X.Y.Z.zip`, contains the runtime,
sources, and Javadoc JARs, together with `COPYING`, `COPYING.LESSER`, and the
Java binding README. The release workflow validates the packaged runtime JAR
with an external consumer before uploading it.

## Release validation

Source packaging uses `make distcheck` followed by `make dist-bzip2` to produce
gzip and bzip2 archives, and runs CMake/CTest from an extracted source archive.

## Source release publication

The configure-ready source distributions are
`libmpq-X.Y.Z.tar.gz` and `libmpq-X.Y.Z.tar.bz2`. Both are included in
the signed GitHub Release after the validation above.

## Binary release publication

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

## Registry publication

### PyPI

The Python publishing workflow reuses the same wheel, source-distribution, and
metadata-validation pipeline as the signed GitHub Release.

### Maven Central

Both Maven modes create a real Central Portal deployment and wait for
`VALIDATED`; there is no sandbox. A `validate` deployment is for testing and
must be dropped in the Central Portal. A `release` deployment remains
USER_MANAGED until a maintainer manually chooses Publish or Drop.
Java release packaging and Maven Central validation share one package build
and consumer-validation script.

### DUB

D `validate` may run from a branch or tag and validates the complete D release
package set: source and the compiler-specific Linux, macOS, and Windows
packages described above. It performs
no registry activity. D `release` requires an exact `v*` tag where the tag,
native project, and DUB versions agree; code.dlang.org independently discovers
that tag, and the workflow waits until the exact package version appears. It
does not upload anything to code.dlang.org. Both modes reuse the canonical D
package pipeline used by the signed GitHub Release.

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
