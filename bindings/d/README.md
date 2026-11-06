# libmpq D bindings

These bindings expose the public libmpq archive API through the `libmpq.mpq`
module. The high-level `Archive`, `File`, and `MpqFileWriter` classes translate
negative C status values into `MPQException` while retaining the low-level
`extern(C)` declarations for applications that need direct ABI access.

## Requirements and installation

The native libmpq library and its zlib, bzip2, and lzma dependencies must be
installed or available to the linker.

The source/DUB package does not load a private copy of the native library.
`libs "mpq"` uses the platform linker, so source-package consumers should
install libmpq or provide the equivalent library and runtime search path.

The repository root contains the DUB manifest so the binding can be consumed
as the `libmpq` package from a source checkout or a tagged repository release.
The canonical release installation path is
[code.dlang.org](https://code.dlang.org/packages/libmpq):

```sdl
dependency "libmpq" version="~>0.9.0"
```

code.dlang.org discovers versions from Git tags such as `v0.9.0`; registration
and registry credentials are intentionally kept out of the build and release
workflows. See the [DUB publishing guide](https://dub.pm/dub-guide/publishing/).

## Basic archive usage

```d
import libmpq.mpq;

auto archive = Archive.open("example.mpq");
scope(exit) archive.close();
auto entry = archive.file("(listfile)");
auto data = entry.read();
```

All arrays passed to the writer are borrowed for the duration of the call.
Arrays returned by `read` and `readBlock` are owned by the caller. Always close
archives explicitly; a destructor performs only best-effort cleanup because D
destructors cannot report native close errors.

Low-level calls use `libmpq__*` names. Use `Mpq.version_()` for the version
string and the high-level wrappers for checked calls. Archives provide
`clone()`, `nativeHandle()`, and `fileList()` for independent readers, native
access, and filename discovery.

`Archive.version_()` reports the MPQ generation (1 through 4).
`Archive.fileCount()` counts live canonical entries, including stored internal
members where present, independently of classic hash-table capacity.
`Archive.offset()` is the archive origin in the backing source and can be
nonzero for embedded archives. `File.offset()` is the stored member position
relative to the start of the MPQ. Archive `packedSize()` and `unpackedSize()`
sum stored and logical entry sizes, respectively. The archive's physical
extent also accounts for layout and tables. The `metadata()` snapshots use the
same units and coordinates. File wrappers also expose `blockCount()` and `no()`.

`Archive.fileNumber(name)` tries HET/BET when present and falls back to
classic lookup on a miss. The locale/platform overload uses classic or
supported HET/BET identities and selects the exact tuple. HET/BET-only
identities accept only `(0, 0)`. The `StormHash` overload probes only the
classic table. HET/BET lookup requires the filename to compute a separate hash.

### Logical member streams

Open an ordinary stream by file number with `openStream(number)`, by
filename with `openStream(name)`, or by exact identity with
`openStream(name, locale, platform)`. Named streams provide the
filename for decryption when the key requires it. These streams own a
native archive clone and can outlive the original archive. Callback-backed
clones and ordinary streams still use the caller's source. Keep the callback,
its context and stable backing storage valid until all dependent handles
close. Stream reads check usable sector Adler-32 values. Whole-member
CRC32/MD5 verification is separate. See [Read one patched member](#read-one-patched-member)
for `openPatchStream()`.

    auto stream = archive.openStream("data/file.bin");
    ubyte[] buffer = new ubyte[4096];
    auto count = stream.read(buffer);
    stream.seek(0, SeekOrigin.set);
    stream.close();

### Custom random-access I/O

Implement `MpqSource` to open a caller-owned random-access source. Archives
and derived streams retain the source object while needed but never own an
external resource represented by it.

    auto archive = Archive.openSource(new MemorySource(data), "data.mpq");

`FILE_FLAG_SINGLE` storage is independent of the archive sector size. A newly oversized
unit buffers its complete declared input, is encoded/encrypted once, and remains
one logical block without a sector-offset or sector-CRC table. The new path is
limited to min(INT32_MAX, UINT32_MAX, SIZE_MAX) by current representation and
one-block reader transfer types, with additional codec and output-extent checks.
Existing inputs fitting a configured sector retain their prior behavior.
Encoding may require several times the input size in memory. There is no fixed
MiB cap or library-managed memory budget. Applications handling untrusted sizes
should apply their own resource limits. Normal allocation failures are reported
where the runtime returns control; this does not guarantee survival of OOM
termination. Existing codec/version restrictions and ADPCM SINGLE rejection,
KEY adjustments, generated listfile defaults and physical patch defaults remain.

## Archive creation

Creation supports MPQ v1 through v4. `ArchiveCreateOptions.version_` uses
`ARCHIVE_VERSION_*` selectors (0 through 3):

```d
auto options = ArchiveCreateOptions.v2();
options.version_ = ARCHIVE_VERSION_THREE;
auto archive = Archive.create("new.mpq", options);
scope(exit) archive.close();
archive.add("hello.txt", cast(const(ubyte)[])"hello\n");
```

Use `ARCHIVE_VERSION_FOUR` with the same creation APIs for v4 MPQ or MPQE
output with 16 KiB raw chunks by default. V4 updates preserve the source raw-chunk size.

`Archive.createMpqe` creates a new encrypted MPQE stream from borrowed
authentication bytes. It finalizes a private plaintext temporary file before
atomically replacing the destination. Use `Update.beginMpqe` for changes to an
existing MPQE archive. Crash cleanup is best effort. `Update.addData` and
`addPath` add absent staged names, with optional `FileOptions`; duplicates
fail and replacement remains existing-only. V3/v4 updates can retain unrelated
unnamed members with sufficient stored identities; see the
[transaction limits](../../DEVELOPER.md#transactional-modification).
Remove-then-add uses the same ordinary or MPQE transaction.

### Compression policy

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

### Optional attributes and integrity

Set `FILE_FLAG_SECTOR_CRC` in file options alongside COMPRESS or IMPLODE
to generate sector Adler-32 tables, including for encrypted files. Empty,
raw, and single-unit files ignore this flag. Generation is opt-in and
complete reads automatically verify usable sector entries.

`File.verify()` and `File.verifyResult()` default to `VERIFY_ALL`. For one
sector, `archive.file("file.txt").verifyBlock(blockNumber)` returns
`BlockVerification` with `checksum` (stored Adler-32) and `mismatches` (zero
or `VERIFY_SECTOR_CRC`). Unavailable checksums throw `ERROR_EXIST`.

Member checks are `VERIFY_SECTOR_CRC` (`0x1`, sector Adler-32 over
decrypted packed bytes), `VERIFY_FILE_CRC32` (`0x2`) and
`VERIFY_FILE_MD5` (`0x4`) over logical member bytes, and
`VERIFY_RAW_MD5` (`0x8`) hashes stored MPQ v4 member chunks before member
decryption or decompression, after MPQE transport decoding. It applies to
nonempty stored members with a nonzero raw chunk size, excluding delete
markers. For physical patch members it checks the stored patch payload.

`VERIFY_ALL` was `0x7` in v0.8.1. In v0.9.0 it is `0xF`, adding RAW MD5.
D compiles this enum value and omitted default arguments into the caller.
Rebuilding with the v0.9.0 declarations uses the new value. Existing
binaries that pass a compiled `0x7` keep that mask.
Passing `0x7` explicitly keeps the original three checks.
The extra RAW check can add I/O or report a mismatch. An inapplicable RAW
check is skipped by mismatch-only verification and reported as unavailable
by the detailed result. A digest mismatch is a result bit. Malformed
required digest storage or a read failure can raise a native error.

The mismatch-only call requires stored attributes for logical checksum
requests and returns the mismatch mask for checks it performed. A clear
bit can mean a match or an unavailable check. Complete lossless reads
also compare usable CRC32/MD5 attributes automatically.

`file.flags()` returns the stored block-table flags. Inspect `FILE_FLAG_*`
bits; metadata convenience booleans are derived from these flags.

`file.blockCompression(block)` returns the stored method byte, or zero for
raw storage/fallback, without decoding. LZMA is `0x12`, not the writer selector.

`file.blockSizeUnpacked(blockNumber)` returns one block's logical size from
metadata without reading its payload. `file.blockSizePacked(blockNumber)`
returns the stored data bytes, excluding offset and checksum tables.

```d
off_t logicalBytes = file.blockSizeUnpacked(0);
off_t storedBytes = file.blockSizePacked(0);
```

`Archive.attributes()` returns archive-wide flags in a `Nullable!uint`, null
if absent. `File.attributes()` returns a `FileAttributes` value and requires
the member to have a valid classic block-table row. A readable BET-only
member can throw `MPQException` with `ERROR_FORMAT` from this query.

Call `MpqFileWriter.timestamp(filetime)` before finishing a streaming file.
Supply Windows FILETIME, not Unix time.

Creation is opt-in: combine `ATTRIBUTE_CRC32`, `ATTRIBUTE_FILETIME`,
`ATTRIBUTE_MD5`, and `ATTRIBUTE_PATCH_BIT` in the `attributes` field of
`ArchiveCreateOptions`. Zero disables generation; any nonzero combination
creates one `(attributes)` file and consumes one reserved slot. Unknown bits
are rejected. Creation flags remain separate. These options work for both MPQ
v1, v2, v3, and v4, including MPQE creation. Payload version 100 is
independent of the archive format version.

Per-file flags distinguish unavailable fields from zero. Complete lossless
reads automatically verify available CRC32 and MD5 metadata against decoded
bytes; malformed optional metadata is skipped during extraction but still
raises the existing format exception when queried. CRC32 and MD5 cover source
bytes before compression, so lossy ADPCM is not automatically compared.
FILETIME defaults to zero, never filesystem mtime, and PATCH_BIT remains
metadata only. Complete reads verify usable sector Adler-32 values over
decrypted packed sectors before decoding, including lossy ADPCM. Malformed
optional sector tables are skipped during extraction; lossy ADPCM skips only
file-level CRC32/MD5 comparison.

## Transactional updates

`Update.timestamp` sets existing Windows FILETIME metadata, expressed in
100-nanosecond ticks since 1601-01-01 UTC. Omit locale/platform for ordinary
lookup. For exact selection without fallback, place locale and platform
immediately after the filename.

```d
update.timestamp("voice.bin", 0, 0, 132537600000000000UL);
```

Zero is an available timestamp; `ulong` retains all FILETIME bits and
selectors use `ushort`.
Existing valid FILETIME and classic provenance are required. Actual changes
to shared rows are rejected; validated same-value requests preserve staged
bytes and signatures, including shared rows. Eligible changes preserve packed
payloads and invalidate signatures. Missing arrays are not created. Ordinary
replacement resets timestamps to zero; exact replacement retains them. Normal
transaction staging, abort and publication guarantees apply.

Transactional updates stage edits until commit. `Update` aborts any active
transaction when it is destroyed or closed:

```d
auto update = Update.begin("archive.mpq");
scope(exit) update.close();
update.replaceData("foo.txt", cast(const(ubyte)[])"new contents");
update.rename("old.txt", "new.txt");
update.commit();
```

Use the same `Update` methods for MPQE transactions. The transport has no independent
authentication tag. A wrong code can still yield a structurally plausible MPQ.

```d
auto update = Update.beginMpqe("archive.mpqe", authCode);
scope(exit) update.close();
update.replaceData("foo.txt", cast(const(ubyte)[])"new contents");
update.commit();
```

`replacePath`, `remove`, and `abort` are also available. Commit and abort
consume the handle even on error. The no-options overload passes a native
NULL options pointer, so libmpq uses defaults and preserves the member's
locale/platform identity. Supply explicit `FileOptions` for custom storage,
for example `update.replaceData("foo.txt", data, options);`. These options
can select distinct first/later compression masks, but locale/platform must
match the existing member. Ordinary MPQs and embedded W3X/W3M containers use
`Update.begin`; MPQE uses `Update.beginMpqe` with explicit authentication bytes
borrowed only during begin. Both paths abort automatically without commit.

## Patch creation

`File.patchPayloadSize()` returns decoded PTCH size, distinct from the final
patched target size returned by `unpackedSize()`. `readPatchPayload()` or
`readPatchPayload(filename)` returns a caller-owned `ubyte[]` beginning with
`PTCH`, without the plaintext patch-info prefix or patch application. Supply
the physical member filename when encryption requires a name-derived key.
Native errors, including non-patch members and integrity failures, use
`MPQException`; unrepresentable array sizes are rejected. The owning archive
must remain open. Test `flags()` with `FILE_FLAG_PATCH_FILE` (`0x00100000`) and
`FILE_FLAG_DELETE_MARKER` (`0x02000000`); the native-prefixed constants are also
available.

Create a patch without changing its base archive:

```d
auto patch = Patch.begin("base.mpq", "changes.mpq");
scope(exit) patch.close();
patch.addData("new.txt", cast(const(ubyte)[])"ordinary addition");
patch.addPath("from-path.bin", "source.bin");
patch.replaceData("foo.txt", cast(const(ubyte)[])"new contents");
patch.remove("old.txt");
patch.sign(privateKey); // or patch.sign(strongKey, SIGNATURE_STRONG)
patch.finish();
```

`Patch.addData(name, data, options)` and `addPath(name, sourcePath, options)`
create ordinary new members, with no-options overloads using ordinary writer
defaults. Names must be absent from the base and staged identities. Existing
names and ambiguous hash/locale identities raise `MPQException`. Empty slices
are valid; inputs are borrowed only during the call. Use replacement for an
existing base member, even after removal. A staged addition cannot then be
replaced or removed. Existing `FileOptions` support compression,
encryption/KEY and sector CRC; patch/delete flags are rejected. Validation
before output preserves valid stages; partial output failures prevent
publication. Addition-only artifacts compose through `Archive.openPatch()`
without a metadata marker.

`Patch.begin` creates an ordinary MPQ patch. Use `Patch.beginMpqe` to create
an MPQE-wrapped patch with a caller-supplied authentication code:

```d
auto patch = Patch.beginMpqe("base.mpq", "changes.mpqe", authCode);
scope(exit) patch.close();
patch.replaceData("foo.txt", cast(const(ubyte)[])"new contents");
patch.finish();
```

The same `Patch` owns either output type. Authentication bytes are borrowed
only during begin; an unfinished patch is aborted rather than published.

`replacePath` is also available. `finish()` publishes the patch; `abort()`
discards it, and destruction of an unfinished patch aborts automatically.
Omitting `FileOptions` passes native NULL and uses native patch defaults;
the explicit-options overload configures patch-member storage. Patch rename is not supported; explicit locale/platform must match the base
member. Signing configures the active patch without consuming it; an
ordinary MPQ v1/v2/v3 patch may configure weak and strong signatures
separately; its MPQE variant supports weak signing only. V4 patches default to raw-chunk MD5, preventing weak signing.
Call `Patch.setRawChunkSize(0)` before signing to allow weak signatures on
plain or MPQE output. MPQE strong signing remains unsupported. After
`finish()`, use `Archive.signatures()` and `Archive.verify()` on the
finished artifact.

## Signatures

Weak MPQ signatures are supported with caller-supplied raw RSA-512 keys.
Strong verification uses a 512-byte raw public key: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
public exponent. Strong signing uses the same layout with the private exponent
and emits only the plain SHA-1 archive-range variant. Weak signatures are
supported inside MPQE-wrapped MPQs. External strong signatures are not defined
for MPQE transport streams. Use `Archive.sign(privateKey)` for weak signing or
`Archive.sign(privateKey, SIGNATURE_STRONG)` for strong signing before writer
close, and `Archive.signatures()` / `Archive.verify(publicKey)` on reopened
archives. Verification returns mismatch bits; malformed keys/archives raise
normal binding errors. Weak keys are exactly 128 bytes: 64-byte big-endian
modulus followed by a 64-byte big-endian exponent. Weak-signature creation is
unsupported for MPQ v4 output with raw-chunk MD5 enabled. Public v4 creation defaults to raw chunks.
Call `Archive.setRawChunkSize(0)` before signing to enable weak signatures,
including on MPQE output. Plain MPQ strong signing supports any raw size;
MPQE strong signing remains unsupported.
libmpq does not ship Blizzard- or product-specific public verification keys
or private signing keys; all signature key material is supplied explicitly
by the caller.
MD5/RSA-512 is legacy compatibility, not modern authenticity protection. See
[the format guide](../../MPQ.md) for details.

`Archive.signatures()` reports weak MD5/RSA-512 internal signatures and strong
SHA-1/RSA-2048 external `NGIS` trailers. `Archive.verify` accepts a signature
type and a caller public key. Strong signatures are legacy compatibility data.
`Archive.sign(key, SIGNATURE_STRONG)` creates the plain
SHA-1 archive-range strong variant from a 512-byte raw private key.

## Development and testing

From a libmpq checkout, build the native library first:

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

## Distribution packages

Release downloads also provide compiler-specific binary packages. They contain
the D interface files, a precompiled static D archive, and the native shared
library (`libmpq.so` on Linux, `libmpq.dylib` on macOS, `libmpq.dll` on
Windows). Unix packages preserve the shared-library symlinks. The binary
package supplies the bundled native library to the linker. At runtime, its
library directory must be available through the platform's loader search
mechanism: `LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH` on macOS, or `PATH`
on Windows (using the package's `bin/` directory). The compiler and native
build metadata, including the libc build version, build environment, and
maximum required glibc symbol version, is recorded in `BUILDINFO`; use the
source package when the recorded compiler or platform does not match the
consumer environment. Binary packages are built and tested for the following
compiler/architecture matrix:

| Compiler | Linux glibc (Ubuntu 24.04) | Linux musl (Alpine 3.22) | macOS | Windows |
| --- | --- | --- | --- | --- |
| DMD | x86_64 | x86_64 | x86_64 | x86_64 |
| LDC | x86_64, aarch64 | x86_64, aarch64 | x86_64, arm64 | x86_64, arm64 |

Archives are named
`libmpq-d-X.Y.Z-<compiler>-linux-<libc>-<architecture>.tar.gz`, for example
`libmpq-d-X.Y.Z-ldc-linux-glibc-aarch64.tar.gz` and
`libmpq-d-X.Y.Z-ldc-linux-musl-aarch64.tar.gz`. DMD remains x86_64-only
because the existing release toolchains do not provide native Linux aarch64
DMD packages. Linux builds and tests run natively without emulation.

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
The x86_64 DUB suffix is `osx-x86_64-<compiler>`; LDC arm64 uses
`osx-aarch64-ldc`.

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
`libmpq-d-X.Y.Z-ldc-windows-arm64.zip`. It uses the MSVC ARM64 native SDK and
`arm64-windows` dependencies. All D compilation uses the explicit target
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

Autotools includes the D sources in libmpq source archives but does not install
the D package. DUB and code.dlang.org own D package installation and
publication. The repository/source package contains the D source files and
expects a system libmpq installation. The supplementary GitHub Release ZIP
contains precompiled package downloads. They contain `.di` interfaces,
compiler-specific static archives, and the native shared-library files needed
at runtime. The outer D release ZIP also contains the source package so
consumers can rebuild when a precompiled package is not suitable.

See [RELEASING.md](../../RELEASING.md) for maintainer release procedures.

### Composing opened archives

```d
Archive result;
{
    auto base = Archive.open("base.mpq");
    scope(exit) base.close();
    auto patch = Archive.open("patch.mpq");
    scope(exit) patch.close();
    result = Archive.openPatch(base, [patch]);
}
scope(exit) result.close();
auto contents = result.file("document.txt").read();
```

Pass opened patch archives in application order. An empty patch array
creates an independent snapshot. If supplied, the prefix array has one entry
per layer. A null array or string requests inference. A nonempty string
selects that namespace. To select root, use an empty slice with a nonnull
pointer, such as `cast(string)(new char[1])[0 .. 0]`. An empty `.idup` may
have a null pointer and request inference.
Explicit addition-only layers need no metadata marker. The read-only result
is independent of its inputs after successful open. Keep input callback
resources alive for any other dependent handles. Result clones and streams
retain the result's own storage after parent closure. Named modern
materialization requires unambiguous names and metadata. Verify physical
signatures and raw checksums on input archives, separately from reconstructed
logical content. Temporary storage survives until the last dependent closes;
cleanup is best effort on persistent I/O failure.

### Read one patched member

```d
MpqStream stream;
{
    auto base = Archive.open("base.mpq");
    scope(exit) base.close();
    auto patch = Archive.open("layer.mpq");
    scope(exit) patch.close();
    stream = base.openPatchStream("member.bin", 0, 0, [patch]);
}
scope(exit) stream.close();
ubyte[4096] buffer;
auto count = stream.read(buffer[]);
```

Use `openPatchStream(name, patches, prefixes)` for ordinary lookup in the
final patched view. The overload with locale and platform immediately after
the name selects that exact tuple, as in the neutral example above.

Use the same layer order and prefix rules as for a full patched archive.
Opening reconstructs and verifies the selected result synchronously in
private seekable scratch storage. A missing or finally deleted identity
returns the existing missing-member error. Patch or scratch-storage failures
can prevent the stream from opening. After success the inputs can close, as
shown above. Keep their callback resources valid for any other dependent
handles. Closing the returned stream releases its scratch resources.

Verification covers the selected payloads. Unrelated payloads may remain
unread. Temporary disk use depends on the selected results and BSD0
transform. SINGLE members can also require whole-unit memory.

### V4 raw-chunk policy

```d
auto options = ArchiveCreateOptions.v1();
options.version_ = ARCHIVE_VERSION_FOUR;
auto archive = Archive.create("output.mpq", options);
scope(exit) archive.close();
archive.setRawChunkSize(17); // 0 disables trailing raw MD5
assert(archive.getRawChunkSize() == 17);
archive.add("data.txt", cast(const(ubyte)[])"content");
```

`Archive.setRawChunkSize(size)` and `Patch.setRawChunkSize(size)` configure
plain or MPQE v4 output. The default remains `0x4000` (16 KiB). Zero disables
member and HET/BET trailing raw arrays; all uint32 values, including 1, 17 and
`0xffffffff`, are accepted without a power-of-two restriction. Processing
uses bounded buffers. Configure before any member begins, signing succeeds or
finalization starts. Repeated early calls are allowed; failed validation or
signing preserves configurability, but an accepted begin fixes policy even
if that member is later aborted or fails. Lifecycle errors use the existing
binding exception mapping and leave the prior size unchanged.

`Archive.getRawChunkSize()` reports loaded or configured policy on readers or
writers. Older generations return zero. This is policy
inspection, not proof of checksum presence or success. Physical raw MD5
hashes stored bytes separately from logical file checks. Updates preserve
the source policy; these setters do not configure transactions. Zero raw size
permits weak signing on v4, including MPQE; nonzero raw size rejects weak
signing. Successful signing freezes raw configuration. Plain strong signing
is supported at any raw size, while MPQE strong signing is unsupported.

`Patch.getRawChunkSize()` reports a live patch writer's configured policy,
including after its setters lock.

### Exact filename identities

```d
FileIdentity[] identities = archive.variants("dir/file.bin");
uint number = archive.fileNumber("dir/file.bin", 0x409, 1);
auto stream = archive.openStream("dir/file.bin", 0x409, 1);
scope(exit) stream.close();
ubyte[32] bytes;
auto count = stream.read(bytes[]);
```

Identity values contain fileNumber, flags, locale and platform, without the
native reserved field. Native identity layout is checked as 16 bytes.
`IDENTITY_CLASSIC` and `IDENTITY_BET` describe stored provenance, not storage
flags. Variants use original classic slot order; aliases may share a member
number. BET-only identities are unqualified `(0, 0)`. The exact overloads
accept `ushort` selectors without fallback; existing overloads are unchanged.
Ambiguous or reduced-hash metadata raises `MPQException`. Exact named streams
preserve the filename for decryption and own their archive clone, surviving
parent close. Custom-source lifetime follows the existing stream contract.

Exact update overloads use `ushort` locale/platform selectors, without
neutral fallback:

```d
auto update = Update.begin(path);
scope(exit) update.close();
update.replaceData("voice.bin", 0x409, 1, replacement);
update.rename("voice.bin", 0x409, 1, "renamed.bin");
update.replacePath("renamed.bin", 0x409, 1, sourcePath);
update.remove("obsolete.bin", 0, 0);
update.commit();
```

Classic-only archives detach the selected shared alias on replacement and
retain other aliases on removal or rename. Explicit replacement options must
match the selectors; omitted options use default storage with those selectors.
Mixed classic/HET/BET targets require consistent one-to-one mappings and
complete hashes. Unique HET/BET-only targets accept zero selectors only.
Unsupported or ambiguous metadata is rejected. A rejected operation preserves
the previous valid stage; commit/abort consume the transaction. Exact rebuilds
preserve discoverable embedded prefixes and the original MPQ origin, reject
unsupported trailers, and preserve source raw-chunk policy. Ordinary legacy
v1/v2 updates retain their existing unrelated-suffix preservation.

`Update.changeIdentity(name, locale, platform, newLocale, newPlatform)` uses
`ushort` values: `locale` and `platform` select the old identity, while
`newLocale` and `newPlatform` specify its destination tuple. Only that tuple
changes; the filename and payload stay unchanged. `rename()` changes
the filename and keeps the selected tuple:

```d
auto update = Update.begin(path);
scope(exit) update.close();
ushort oldLocale = 0, oldPlatform = 0;
ushort newLocale = 0x409, newPlatform = 1;
update.changeIdentity("voice.bin", oldLocale, oldPlatform, newLocale, newPlatform);
update.commit();
```

There is no neutral fallback. Equal tuples validate the source and are no-ops;
missing sources and occupied destinations use the existing EXIST error mapping.
Classic-only archives preserve shared aliases and their packed payloads at the
same offsets. Mixed targets require consistent one-to-one mappings with full
hashes; HET/BET-only entries cannot acquire qualifiers. Unsupported metadata,
special-member mutations and reconstruction layouts are rejected. Attributes,
timestamps, raw policy and transaction ownership are unchanged, and rejected
calls preserve the previous valid stage.

A filename can have multiple identities. Ordinary overloads use the native
filename selection rules. Exact overloads require the requested tuple, and
`(0, 0)` selects the neutral identity. Exact update selectors follow the
filename, as in `rename(oldName, locale, platform, newName)` and
`timestamp(name, locale, platform, filetime)`. Replacement options must
match the selected tuple.

Add operations create an absent filename using the locale/platform in
`FileOptions`, without a selector. Replacement
selects an existing identity, retaining its tuple; storage options must match
that tuple and cannot redirect selection. Change the tuple explicitly with
`changeIdentity()`.

Physical compaction is an immediate transaction stage:

```d
update.compact();
update.compact(["voice", "left/data"]);
```

Optional filename context augments transaction knowledge and the internal
listfile without editing that listfile. The native call strictly validates the
whole batch before reconstruction; missing/empty names, ambiguous identities
and incompatible encrypted aliases are rejected atomically. Valid names alone
do not guarantee relocation eligibility or plaintext correctness. Distinct
classic slash spellings and locale/platform variants retain existing rules.
Caller buffers are borrowed only until return. Actual adoption retains owned
copies of all still-valid spellings; failures and true no-ops retain no new
names. No-ops preserve bytes, path, signatures and prior dirty state. Later calls
may require the same names again. Existing pre-adoption preservation and
abort-only adoption boundaries remain.

The array overload accepts a const(string)[] view, with null/empty slices
representing no names. Empty/NUL entries are rejected. Native string/pointer
storage is rooted through the synchronous call; size_t is passed without narrowing.

Call it after other mutations when final placement matters, then commit to
publish. Supported packed representations, shared aliases and attributes are
preserved. Required metadata capacity remains; no minimum size or reduction is
guaranteed. Proven no-ops preserve bytes and signatures. Actual rebuilds remove
stale signatures and regenerate integrity using the original raw-chunk policy.

Unknown position-independent ciphertext can move opaquely; this does not verify
plaintext. KEY relocation requires a usable key when its adjustment changes.
Discoverable embedded prefixes retain all bytes and the MPQ-header position.
Discovery uses 512-byte probes or a validated user-data pointer, which can
identify an unaligned MPQ. KEY remains relative to the MPQ header. This is
byte preservation, not a guarantee of arbitrary container validity. Unsupported
identities, contradictory prefixes, ambiguous shared encryption and unrelated
trailers are rejected. Named mutations support the same discoverable prefixes
within existing identity and metadata restrictions; compact last for density.

Budget disk space for a working stage and full candidate. Embedded assembly
also needs a completed zero-origin MPQ temporary; MPQE publication may require
an encrypted candidate. MPQE prefix preservation refers to decoded bytes.
Native errors and transaction ownership follow existing update conventions.

Transactional signing applies immediately to the private stage. Commit alone
publishes it; abort discards it. Supply raw big-endian `n || d` private keys:
128 bytes for weak RSA-512/MD5 or 512 bytes for strong RSA-2048/SHA-1.
Keys are consumed synchronously and are not retained for commit.

```d
auto update = Update.begin(path);
update.sign(privateKey); // weak by default
update.sign(strongKey, SIGNATURE_STRONG);
update.commit();
```

Weak then strong retains both signatures. Strong then weak removes the stale
strong trailer. Repeating a type replaces it. Sign last, since later actual
mutations invalidate signatures; validated no-ops preserve them. V4 weak
signing requires raw chunks disabled. MPQE supports eligible weak signing
only. Supported embedded archives retain their prefixes and origins, with
HM3W prefix-inclusive hashing. Existing identity and storage restrictions
apply, including preservation of supported `(listfile)` storage policy.

Generation success does not establish public-key verification or external
trust. Independently verify with the matching public key and require zero
mismatches as well as a successful call. Opaque ciphertext preservation does
not establish plaintext correctness. Native temporary key copies are cleared
where used; this does not promise erasure of managed-runtime key copies.

Member checksum coverage is available separately from the legacy mismatch
result:

```d
auto result = archive.file(number).verifyResult(VERIFY_ALL, "voice.bin");
```

The result contains `checked`, `unavailable` and `mismatches` masks. Complete
matching coverage requires checked equal to the request and both other masks
zero. Partial sector coverage may be both checked and unavailable. Missing
logical metadata is unavailable; malformed metadata and read, key or decode
failures raise the existing native error. Filename is optional key context for the
selected number, never fallback selection; it is not cached in the parent.
Circular internal zero placeholders and logical lossy ADPCM checks without
decoded-byte provenance are unavailable. Ordinary CRC32 zero remains valid.
Member verification establishes neither signature trust nor whole-archive
integrity.

For eligible nonempty v4 members, a nonzero raw chunk size declares required
trailing RAW MD5 storage. Missing, truncated or overlapping arrays raise the
existing native errors; adjacency and zero-filled bytes do not prove absence.
RAW is unavailable only for older versions, zero raw size, empty stored data
or delete markers. A matching unkeyed MD5 is not proof of provenance or
cryptographic authenticity. Complete coverage requires successful native
status, checked equal to the request, no unavailable checks and no mismatches.

## Archive metadata verification

```d
auto result = archive.verifyEx(VERIFY_METADATA_ALL);
```

`Archive.verify()` verifies digital signatures. `Archive.verifyEx()` verifies
archive structural and RAW metadata. It uses the native `archive_verify_ex()` and the eight
`LIBMPQ_VERIFY_METADATA_*` bits, combined by `LIBMPQ_VERIFY_METADATA_ALL`.
It performs fresh bounded reads of stored header/table representations against
opened descriptors, checking both object digests and stored reference fields.
Present empty tables with supplied digests compare MD5(empty). Missing optional
metadata is unavailable; required nonzero-v4 HET/BET RAW arrays that are missing,
truncated or overlapping are errors. Changed reference fields mismatch rather
than becoming unavailable. No newly changed geometry is adopted.

The result masks partition requested checks into checked and unavailable, with
mismatches a subset of checked. Complete matching coverage requires successful
status, checked equal to the request, no unavailable checks and no mismatches.
Errors clear all outputs. Zero flags perform no comparisons.
`Archive.verifyEx()` defaults to `VERIFY_METADATA_ALL` (`0xFF00`),
the separate mask for archive header, table and table RAW checks. Archive
metadata verification rejects member flags such as `VERIFY_ALL`.

The source must remain stable; source reads do not promise uncached filesystem
access or an atomic snapshot of concurrent writes. Embedded offsets and MPQE
logical reads use existing source handling. Unkeyed MD5 establishes neither
provenance nor authenticity, MPQE transport authenticity or whole-archive
integrity. `archive_verify()` remains public-key signature verification;
`file_verify_ex()` remains member verification.

`FILE_FLAG_KEY` (`0x00020000`) selects offset- and size-adjusted
encryption-key derivation. It modifies `ENCRYPTED`; it does not enable encryption
on its own. The effective key is `(basename_key + uint32(MPQ-relative offset))
XOR uint32(uncompressed size)`, with modulo-2^32 arithmetic. Embedded prefixes
are excluded from this offset. The flag provides no integrity guarantee.

### Caller-owned output

`Archive.createSink(writeAt, options, readAt, flush)` accepts exact
positioned delegates for a fresh empty sink. The final two delegates are
optional, but v4 and signing require read-back. Borrowed slices must not
escape a callback. Reads must observe prior writes and zero-filled gaps.
An optional flush runs after successful finalization. Close explicitly to
receive failures and release rooted delegate state. The caller retains
ownership, and chooses persistence and publication. Failed operations can
leave partial output. Oversized SINGLE still buffers the complete input
unit.

### Writing MPQE to a sink

```d
auto writer = Archive.createMpqeSink(writeAt, authCode, options, flush);
writer.add("payload.bin", payload);
writer.close();
```

The optional flush delegate runs after successful transport output. A private
plaintext stage supplies read-back, including v4 verification data. Keep the
caller-owned sink available through explicit close and release it separately.
MPQE encoding does not independently authenticate the archive.

### Fixed-size range replacement

An update can replace several plaintext ranges in one staged operation.
Offsets are zero-based and must fit inside the existing member. Later ranges
win when they overlap, and commit publishes the result.

```d
update.replaceRanges("member.bin", [ReplaceRange(100, [cast(ubyte) 1, 2])]);
update.replaceRanges("member.bin", 1033, 0, [ReplaceRange(4096, [cast(ubyte) 3])]);
```

Supported lossless members retain encryption and storage policies; the native
writer rebuilds the selected member. SINGLE requires full-unit buffering.
