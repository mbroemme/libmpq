# libmpq D bindings

Weak MPQ signatures are supported with caller-supplied raw RSA-512 keys.
Use `Archive.sign(privateKey)` before writer close, and
`Archive.signatures()` / `Archive.verify(publicKey)` on reopened archives.
Verification returns mismatch bits; malformed keys/archives raise normal binding
errors. Keys are exactly 128 bytes: 64-byte big-endian modulus followed by a
64-byte big-endian exponent. Signing supports v1 and v2; no keys are built
in. MD5/RSA-512 is legacy compatibility, not modern authenticity protection.
See [the format guide](../../MPQ.md) for details.

These bindings expose the public libmpq archive API through the `libmpq.mpq`
module. The high-level `Archive`, `File`, and `MpqFileWriter` classes translate
negative C status values into `MPQException` while retaining the low-level
`extern(C)` declarations for applications that need direct ABI access.

Low-level calls use `libmpq__*` names. Use `Mpq.version_()` for the version
string and the high-level wrappers for checked calls. Metadata is available
through `packedSize()`, `unpackedSize()`, `fileCount()`, `blockCount()`, and
`no()`. Archives provide `clone()`, `nativeHandle()`, and `fileList()` for
independent readers, native access, and filename discovery.

Creation defaults to `COMPRESSION_POLICY_STANDARD`. Set
`ARCHIVE_CREATE_COMPRESSION_EXTENDED` in `ArchiveCreateOptions.flags` for
additional, potentially less interoperable compression forms. Use
`Mpq.archiveCompressionAllowed(version, mask, policy)` to query whether a
compression selection is allowed by the writer policy, using zero-based
`ARCHIVE_VERSION_*` selectors. Readers remain permissive.

`COMPRESSION_SPARSE` selects lossless zero-run compression. In MPQ v2+,
STANDARD allows the fixed SPARSE forms: alone (`0x20`), with
`COMPRESSION_ZLIB` (`0x22`), or with `COMPRESSION_BZIP2` (`0x30`). MPQ v1
retains normal compression-mask semantics under either policy, allowing
other valid combinations such as SPARSE with Huffman (`0x21`) or PKWARE
(`0x28`). In MPQ v2+, EXTENDED permits the broader valid lossless SPARSE
combinations. Neither policy allows SPARSE with WAVE ADPCM. The shared
`sparse*.txt` fixtures use UTF-32LE with a BOM; extraction returns those
bytes without transcoding.

## Requirements

The native libmpq library and its zlib, bzip2, and lzma dependencies must be
installed or available to the linker. From a libmpq checkout, build the native
library first:

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
the D interface files, a precompiled static D archive, and the native shared
library (`libmpq.so` on Linux, `libmpq.dylib` on macOS, `libmpq.dll` on Windows).
Unix packages preserve the shared-library symlinks.
The binary package supplies the bundled native library to the linker.
At runtime, its library directory must be available through the platform's
loader search mechanism: `LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH` on
macOS, or `PATH` on Windows (using the package's `bin/` directory). The
compiler and native build metadata, including the libc build version, build
environment, and maximum required glibc symbol version, is recorded in
`BUILDINFO`; use the source package when the recorded compiler or platform does
not match the consumer environment. Binary packages are built and tested
for the following compiler/architecture matrix:

| Compiler | Linux glibc (Ubuntu 24.04) | Linux musl (Alpine 3.22) | macOS | Windows |
| --- | --- | --- | --- | --- |
| DMD | x86_64 | x86_64 | x86_64 | x86_64 |
| LDC | x86_64, aarch64 | x86_64, aarch64 | x86_64, arm64 | x86_64, arm64 |

Archives are named
`libmpq-d-X.Y.Z-<compiler>-linux-<libc>-<architecture>.tar.gz`, for example
`libmpq-d-X.Y.Z-ldc-linux-glibc-aarch64.tar.gz` and
`libmpq-d-X.Y.Z-ldc-linux-musl-aarch64.tar.gz`. DMD remains x86_64-only because
the existing release toolchains do not provide native Linux aarch64 DMD
packages. Linux builds and tests run natively without emulation.

macOS archives use these names:

* `libmpq-d-X.Y.Z-dmd-macos-x86_64.tar.gz`
* `libmpq-d-X.Y.Z-ldc-macos-x86_64.tar.gz`
* `libmpq-d-X.Y.Z-ldc-macos-arm64.tar.gz`

They contain the same D interfaces and compiler-specific archive, with the
native SDK's versioned `libmpq.dylib` symlinks instead of `libmpq.so`. The dylib
uses an `@rpath` install ID, ad-hoc signing, system codec dependencies, and the
native SDK's macOS 11.0 deployment target, recorded in `BUILDINFO`. Applications
must provide a runtime search path to the extracted `lib` directory, for example
through `DYLD_LIBRARY_PATH`.

Stable DMD 2.113.0 does not provide the required macOS ARM64 `-marm64` target.
The DMD arm64 binary package is not published until a stable DMD release
provides that support. LDC remains supported and runs natively on macOS arm64.
The x86_64 DUB suffix is
`osx-x86_64-<compiler>`; LDC arm64 uses `osx-aarch64-ldc`.

Windows archives are `libmpq-d-X.Y.Z-dmd-windows-x86_64.zip` and
`libmpq-d-X.Y.Z-ldc-windows-x86_64.zip`. Each contains a single
`libmpq-d-X.Y.Z/` directory, using the MSVC x64 native SDK. Its `lib/`
directory contains the compiler-specific `libmpq-dmd.lib` or `libmpq-ldc.lib`
and the MSVC import library `libmpq.lib`. The `bin/` directory contains
`libmpq.dll` and its required non-system runtime DLLs, with their licenses
under `licenses/`. Add the extracted `bin/` directory to `PATH` when running
applications. DUB selects the precompiled library through
`windows-x86_64-<compiler>` metadata. Both compilers are tested using an
extracted-package consumer with no vcpkg or native build directories on
the runtime `PATH`.

Windows ARM64 is supported by LDC only, as
`libmpq-d-X.Y.Z-ldc-windows-arm64.zip`. It uses the MSVC ARM64 native SDK
and `arm64-windows` dependencies. All D compilation uses the explicit target
`aarch64-windows-msvc` (`dub --arch=aarch64-windows-msvc`), with validated
`windows-aarch64-ldc` binary metadata. The release token is `arm64`; DUB's
internal architecture is `aarch64`. The LDC multilib compiler executable may
itself be x64 and run through Windows-on-ARM emulation, but the packaged DLLs,
library objects, and extracted consumer must be genuine ARM64. The consumer
executes natively on the ARM64 runner. `BUILDINFO` records the target triple
and inspected compiler-host architecture. DMD Windows ARM64 is not supported.

Packaging requires explicit `LIBMPQ_D_OS` and `LIBMPQ_D_ARCHITECTURE` values:
`linux` with `x86_64`/`aarch64`, `macos` with `x86_64`/`arm64`, or `windows`
with `x86_64` or LDC-only `arm64`, matching the native host OS. ELF/Mach-O/PE
checks validate the native shared library, every D archive member, and the
extracted consumer. macOS consumers execute with the requested native
architecture and verify that the extracted dylib is loaded.

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

`Archive.createMpqe` creates a new encrypted MPQE stream from borrowed
authentication bytes. It finalizes a private plaintext temporary file before
atomically replacing the destination; existing MPQE streams cannot be modified
and crash cleanup is best effort.

All arrays passed to the writer are borrowed for the duration of the call.
Arrays returned by `read` and `readBlock` are owned by the caller. Always close
archives explicitly; a destructor performs only best-effort cleanup because D
destructors cannot report native close errors.

## DUB distribution

The repository root contains the DUB manifest so the binding can be consumed
as the `libmpq` package from a source checkout or a tagged repository release.
The canonical release installation path is
[code.dlang.org](https://code.dlang.org/packages/libmpq):

```sdl
dependency "libmpq" version="~>0.8.0"
```

code.dlang.org discovers versions from Git tags such as `v0.8.0`; registration
and registry credentials are intentionally kept out of the build and release
workflows. See the [DUB publishing guide](https://dub.pm/dub-guide/publishing/).

Autotools includes the D sources in libmpq source archives but does not install
the D package. DUB and code.dlang.org own D package installation and
publication. The repository/source package contains the D source files and
expects a system libmpq installation. The supplementary GitHub Release ZIP
contains precompiled package downloads. They contain `.di` interfaces,
compiler-specific static archives, and the native shared-library files needed
at runtime. The outer D release ZIP also contains the source package so
consumers can rebuild when a precompiled package is not suitable.

## Optional attributes

Set `FILE_FLAG_SECTOR_CRC` in file options alongside COMPRESS or IMPLODE
to generate sector Adler-32 tables, including for encrypted files. Empty,
raw, and single-unit files ignore this flag. Generation is opt-in and
verification remains explicit.

`archive.file("file.txt").verify()` explicitly compares sector Adler-32 and
file CRC32/MD5. For one sector,
`archive.file("file.txt").verifyBlock(blockNumber)` returns
`BlockVerification` with `checksum` (stored Adler-32) and `mismatches` (zero
or `VERIFY_SECTOR_CRC`). Unavailable checksums throw `ERROR_EXIST`.

Use `VERIFY_SECTOR_CRC`, `VERIFY_FILE_CRC32`, or `VERIFY_FILE_MD5` to select
checks. Sector checks cover decrypted packed bytes; file hashes cover
extracted bytes. Missing values/tables are skipped. File checksum requests
require attributes; sector-only requests do not. `VERIFY_ALL` selects all
checks. The returned mismatch mask uses the same `VERIFY_*` bits and is a
subset of the request. Set bits mean available checksums mismatched; clear
bits mean matched or unavailable/skipped. Operation errors throw existing
exceptions. Zero does not prove availability. Normal extraction is unchanged;
lossy ADPCM may differ from source hashes.

`file.flags()` returns the stored block-table flags. Inspect `FILE_FLAG_*`
bits; metadata convenience booleans are derived from these flags.

`file.blockCompression(block)` returns the stored method byte, or zero for
raw storage/fallback, without decoding. LZMA is `0x12`, not the writer selector.

`file.blockSizePacked(blockNumber)` returns stored data bytes, excluding
offset and checksum tables, without decoding the sector.

`Archive.attributes()` returns `Nullable!uint`; absence is null.
`MpqFile.attributes()` returns an owned `FileAttributes` value. Call
`MpqFileWriter.timestamp(filetime)` before finishing a streaming file.
Supply Windows FILETIME, not Unix time.

Creation is opt-in: combine `ATTRIBUTE_CRC32`, `ATTRIBUTE_FILETIME`,
`ATTRIBUTE_MD5`, and `ATTRIBUTE_PATCH_BIT` in the `attributes` field of
`ArchiveCreateOptions`. Zero disables generation; any nonzero combination
creates one `(attributes)` file and consumes one reserved slot. Unknown bits
are rejected. Creation flags remain separate. These options work for both MPQ
v1 and v2, including MPQE creation. Payload version 100 is independent of the
archive format version.

Per-file flags distinguish unavailable fields from zero. Malformed optional
metadata raises the existing format exception only when queried, not during
ordinary extraction. CRC32 and MD5 cover source bytes before compression,
so lossy ADPCM output may differ; they are not authentication and are not
automatically verified. FILETIME defaults to zero, never filesystem mtime.
PATCH_BIT is read as metadata; creation writes zeros and does not make patches.
