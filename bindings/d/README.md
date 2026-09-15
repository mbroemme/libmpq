# libmpq D bindings

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
dependency "libmpq" version="~>0.7.1"
```

code.dlang.org discovers versions from Git tags such as `v0.7.1`; registration
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
