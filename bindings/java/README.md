# libmpq Java bindings

These bindings use the Java Foreign Function and Memory API and require JDK
22 or newer. They provide a complete mapping of libmpq's public C API
through `org.libmpq.ffi.LibmpqNative` and safer `AutoCloseable` wrappers in
`org.libmpq`.

## Installation

The JAR does not contain a native library. Autotools does not install the
Java binding; Maven builds the platform-independent runtime, sources, and
Javadoc JARs. Build and install libmpq separately, then either set
`org.libmpq.library` to the absolute native-library path or make `mpq`
available through the platform library search path.

The canonical release installation path is Maven Central:

```xml
<dependency>
  <groupId>org.libmpq</groupId>
  <artifactId>libmpq-java</artifactId>
  <version>0.9.0</version>
</dependency>
```

## Basic archive usage

Use `Mpq.ARCHIVE_VERSION_THREE` in existing `ArchiveCreateOptions` to create
mixed HET/BET plus classic v3 archives, or `Mpq.ARCHIVE_VERSION_FOUR` for v4.
V4 MPQ and MPQE creation uses 16 KiB raw chunks; v4 updates preserve the
source raw-chunk size. V3/v4 transactions can retain unrelated unnamed
members when their stored identities are sufficient; see the
[transaction limits](../../DEVELOPER.md#transactional-modification).
`MpqUpdate.addData()` and `addPath()` add absent staged names;
duplicate names fail and replacement remains existing-only. Remove-then-add is
supported.

The high-level API uses `Archive.open`, `Archive.openMpqe`, `Archive.create`,
`Archive.createMpqe`, and `MpqFileWriter`. All negative libmpq return codes
are reported as `LibmpqException` values containing the original code and
diagnostic text.

`Archive.version()` reports the MPQ generation (1 through 4).
`ArchiveCreateOptions.version()` uses the `Mpq.ARCHIVE_VERSION_*` selectors
(0 through 3). `Archive.fileCount()` counts live canonical entries, including
stored internal members where present, independently of classic hash-table
capacity. `Archive.offset()` is the archive origin in the backing source and
can be nonzero for embedded archives. `Archive.fileOffset(number)` is the
stored member position relative to the start of the MPQ. Archive packed and
unpacked sizes sum stored and logical entry sizes, respectively. The archive's
physical extent also accounts for layout and tables. The metadata snapshots
use the same units and coordinates.

`Archive.fileNumber(name)` tries HET/BET when present and falls back to
classic lookup on a miss. The locale/platform overload uses classic or
supported HET/BET identities and selects the exact tuple. HET/BET-only
identities accept only `(0, 0)`. The `Mpq.StormHash` overload probes only
the classic table. HET/BET lookup requires the filename to compute a separate
hash.

### Byte-exact names and host paths

The existing `String` methods encode MPQ names, prefixes and source labels as
strict UTF-8. They reject NUL and unpaired surrogates and preserve the original
Unicode spelling. Use `MpqName.ofBytes(byte[])` for native spellings that need
to retain their bytes, including names that aren't UTF-8. The native hashing,
case and separator rules still apply. The corresponding `…Bytes` methods
accept `MpqName`, including for lookup, exact selectors, writing, updates,
name-aware verification and compaction. Use `MpqName.ofUtf8(String)` to pass a
UTF-8 name to these methods. An optional null name stays null. For a patch
prefix, null requests inference and an empty `MpqName` explicitly selects root.

```java
MpqName name = MpqName.ofBytes(new byte[] {'m', (byte) 0xff});
try (Archive archive = Archive.open(path);
     MpqStream stream = archive.openStreamBytes(name, 0, 0)) {
    int count = stream.read(new byte[4096]);
}
```

Filesystem paths have a separate encoding policy. Existing `Path` methods
accept default-filesystem paths, resolve relative paths to absolute paths
without normalizing their components, and on POSIX check that their UTF-8 bytes
recreate the same `Path`. A path that fails this check raises
`IllegalArgumentException` before native filesystem access. Java exposes no
portable raw-byte accessor on `Path`. For a non-UTF-8 POSIX path, supply the
original path bytes with `NativePath.ofBytes(byte[])`. Native byte methods
cover plain and MPQE open/create, transaction and patch factories, and source
paths for member add and replacement. `NativePath.of(Path)` lets these methods
combine a checked default-filesystem path with a byte-exact MPQ name.

```java
NativePath host = NativePath.ofBytes(nativePathBytes);
try (Archive archive = Archive.openBytes(host, 0)) {
    long count = archive.fileCount();
}
```

Both byte carriers copy their input arrays and reject embedded NUL. On Windows,
libmpq's C filesystem APIs require UTF-8 and convert it to Win32 wide paths.
Supply UTF-8 to `NativePath.ofBytes` on Windows. Arbitrary non-UTF-8 Windows
path bytes or wide paths with unpaired surrogates cannot be represented by
this native interface. MPQ member names retain their byte semantics regardless
of the filesystem.

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

    try (MpqStream stream = archive.openStream("data/file.bin")) {
        byte[] buffer = new byte[4096];
        int count = stream.read(buffer);
    }

A native read can fail after advancing the stream. The caller's array contains
the valid prefix at the requested offset, and `LibmpqException.transferred()`
reports its length, which can be zero. `code()` still gives the native status.
Successful reads still return the byte count, with `-1` at EOF for a positive
request and zero for a zero-length request.

```java
byte[] buffer = new byte[8192];
try {
    int count = stream.read(buffer);
} catch (LibmpqException error) {
    int count = error.transferred(); // Valid bytes are in buffer[0..count).
    long position = stream.position();
}
```

### Whole-buffer operations with native memory

`Archive.readFile(number, destination)` and
`Archive.readPatchPayload(number, filename, destination)` write into a
caller-owned native `MemorySegment` and return a `long` transferred count.
Use `readPatchPayloadBytes(number, mpqName, destination)` for byte-exact
physical names. Supply capacity for the whole logical member or decoded
PTCH body, respectively. Query it with `fileUnpackedSize(number)` or
`patchPayloadSize(number)`. The whole-file read retains native integrity
checks for the complete member that incremental stream reads do not perform.
A failed whole-file read can leave bytes in the destination.

```java
try (Arena arena = Arena.ofConfined()) {
    long size = archive.fileUnpackedSize(number);
    MemorySegment destination = arena.allocate(Math.max(1L, size)).asSlice(0, size);
    long count = archive.readFile(number, destination);
}
```

`MpqUpdate` and `MpqPatch` accept native data through `addDataSegment` and
`replaceDataSegment`. `MpqUpdate.replaceDataSegment` also takes the exact
locale and platform selectors immediately after the name. The corresponding
`addDataSegmentBytes` and `replaceDataSegmentBytes` methods accept `MpqName`.
The distinct mutation names preserve overload resolution for existing
array calls that pass `null`.

```java
try (Arena arena = Arena.ofConfined()) {
    MemorySegment payload = arena.allocateFrom(ValueLayout.JAVA_BYTE, (byte) 42);
    update.replaceDataSegment("member.bin", payload, null);
}
```

Import `Arena`, `MemorySegment` and `ValueLayout` from `java.lang.foreign`.
The segment must describe a valid contiguous native range accessible to the
calling thread. Destinations must be writable. Keep the segment alive and
synchronize any closure or mutation with the call. The binding borrows
the range synchronously, so the caller can release it after the method returns,
including before update commit or patch finish. Heap segments are rejected.
The binding passes the payload address directly. Native PTCH decoding and
patch generation may still allocate their own working buffers.

Array methods remain available up to Java's array and allocation limits.
Segment lengths use the native signed 64-bit capacity or length. Actual
members remain subject to native format and resource limits. Whole-file
reads, staged data changes and patch additions use the format's 32-bit
member-size fields. SINGLE storage also has a signed 32-bit block limit.
Decoded PTCH sizes come from the patch-info header's unsigned 32-bit field
and still require native staging memory. Physical patch replacement limits
the target size to `min(UINT32_MAX, SIZE_MAX) - 96` bytes for the patch
headers. Archive generation, stored sizes, layout and codec restrictions
can impose lower limits.

### Custom random-access I/O

Use `Archive.openSource(channel, sourceName)` for a caller-owned
`SeekableByteChannel`. The binding retains it while archives or derived streams
need it, serializes seek/read callbacks, and never closes the channel.

    Archive archive = Archive.openSource(channel, "data.mpq");

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

## Archive creation and compression policy

MPQE creation uses a private plaintext temporary file before atomically
replacing the destination. Use `MpqUpdate.beginMpqe` to stage changes
to MPQE archives. Crash cleanup is best effort.

Creation defaults to `Mpq.COMPRESSION_POLICY_STANDARD`. Set
`Mpq.ARCHIVE_CREATE_COMPRESSION_EXTENDED` in `ArchiveCreateOptions.flags`
for additional, potentially less interoperable compression forms. Use
`Mpq.archiveCompressionAllowed(version, mask, policy)` to query whether a
compression selection is allowed by the writer policy, using zero-based
`Mpq.ARCHIVE_VERSION_*` selectors. Readers remain permissive.

`Mpq.COMPRESSION_SPARSE` selects lossless zero-run compression. In MPQ v2+,
STANDARD allows the fixed SPARSE forms: alone (`0x20`), with zlib (`0x22`),
or with bzip2 (`0x30`). MPQ v1 retains normal compression-mask semantics
under either policy, allowing other valid combinations such as SPARSE
with Huffman (`0x21`) or PKWARE (`0x28`). In MPQ v2+, EXTENDED permits the
broader valid lossless SPARSE combinations. Neither policy allows SPARSE
with WAVE ADPCM. The shared `sparse*.txt` fixtures use UTF-32LE with a BOM;
extraction returns those bytes without transcoding.

### Optional attributes and integrity

Set `Mpq.FILE_FLAG_SECTOR_CRC` in file options alongside COMPRESS or IMPLODE
to generate sector Adler-32 tables, including for encrypted files. Empty,
raw, and single-unit files ignore this flag. Generation is opt-in and
complete reads automatically verify usable sector entries.

`archive.verify(fileNumber)` defaults to `Mpq.VERIFY_ALL`.
`verifyFileResult(fileNumber, flags)` takes an explicit member mask. For one
sector, `archive.verifyBlock(fileNumber, blockNumber)`
returns `Archive.BlockVerification` with `checksum()` (unsigned stored
Adler-32 as `long`) and `mismatches()` (zero or `Mpq.VERIFY_SECTOR_CRC`).
Unavailable checksums throw `LibmpqException` with `Mpq.ERROR_EXIST`.

Member checks are `Mpq.VERIFY_SECTOR_CRC` (`0x1`, sector Adler-32 over
decrypted packed bytes), `Mpq.VERIFY_FILE_CRC32` (`0x2`) and
`Mpq.VERIFY_FILE_MD5` (`0x4`) over logical member bytes, and
`Mpq.VERIFY_RAW_MD5` (`0x8`) hashes stored MPQ v4 member chunks before member
decryption or decompression, after MPQE transport decoding. It applies to
nonempty stored members with a nonzero raw chunk size, excluding delete
markers. For physical patch members it checks the stored patch payload.

`Mpq.VERIFY_ALL` was `0x7` in v0.8.1. In v0.9.0 it is `0xF`, adding RAW MD5.
Client code rebuilt against the v0.9.0 binding uses the expanded constant.
Existing client bytecode with an inlined constant can keep passing `0x7`.
The no-flags `verify(fileNumber)` overload uses the loaded binding's default.
Passing `0x7` explicitly keeps the original three checks.
The extra RAW check can add I/O or report a mismatch. An inapplicable RAW
check is skipped by mismatch-only verification and reported as unavailable
by the detailed result. A digest mismatch is a result bit. Malformed
required digest storage or a read failure can raise a native error.

The mismatch-only call requires stored attributes for logical checksum
requests and returns the mismatch mask for checks it performed. A clear
bit can mean a match or an unavailable check. Complete lossless reads
also compare usable CRC32/MD5 attributes automatically.

`archive.fileFlags(fileNumber)` returns the unsigned stored block-table flags
as a `long`. Inspect `Mpq.FILE_FLAG_*` bits; convenience booleans use this
query.

`archive.blockCompression(fileNumber, blockNumber)` returns the stored method
byte, or zero for raw storage/fallback, without decoding. LZMA is `0x12`, not
the writer selector.

`archive.blockSizePacked(fileNumber, blockNumber)` returns stored data bytes,
excluding offset and checksum tables.
`archive.blockSizeUnpacked(fileNumber, blockNumber)` returns the expected
logical size from metadata. `archive.readBlock(fileNumber, blockNumber)` returns
the actual decoded bytes, which can be fewer than the expected size.
`archive.blockSize(fileNumber, blockNumber)` remains a supported compatibility
alias for `archive.blockSizeUnpacked(fileNumber, blockNumber)`.

```java
long stored = archive.blockSizePacked(fileNumber, 0);
long expected = archive.blockSizeUnpacked(fileNumber, 0);
byte[] decoded = archive.readBlock(fileNumber, 0);
```

`Archive.attributes()` returns archive-wide flags in an `OptionalInt`, empty
if absent. `Archive.attributes(fileNumber)` returns a `FileAttributes` record
and requires the member to have a valid classic block-table row. A readable
BET-only member can throw `LibmpqException` with `Mpq.ERROR_FORMAT` from this
query.

Call `MpqFileWriter.timestamp(filetime)` before finishing a streaming file.
Supply Windows FILETIME, not Unix time. Java retains its unsigned native
bits in a `long`.

Creation is opt-in: combine `ATTRIBUTE_CRC32`, `ATTRIBUTE_FILETIME`,
`ATTRIBUTE_MD5`, and `ATTRIBUTE_PATCH_BIT` in the `attributes` field of
`ArchiveCreateOptions`. Constants live on `Mpq`. Zero disables generation; any
nonzero combination creates one `(attributes)` file and consumes one reserved
slot. Unknown bits are rejected. Creation flags remain separate. These options
work for MPQ v1, v2, v3, and v4, including MPQE creation. Payload version 100
is independent of the archive format version.

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

`MpqUpdate.timestamp` sets existing Windows FILETIME metadata, expressed in
100-nanosecond ticks since 1601-01-01 UTC. Omit locale/platform for ordinary
lookup. For exact selection without fallback, place locale and platform
immediately after the filename.

```java
update.timestamp("voice.bin", 0, 0, 132537600000000000L);
```

Zero is an available timestamp; all Java `long` bit patterns are accepted,
including negative ones.
Existing valid FILETIME and classic provenance are required. Actual changes
to shared rows are rejected; validated same-value requests preserve staged
bytes and signatures, including shared rows. Eligible changes preserve packed
payloads and invalidate signatures. Missing arrays are not created. Ordinary
replacement resets timestamps to zero; exact replacement retains them. Normal
transaction staging, abort and publication guarantees apply.

Updates are separate transactions. Closing without commit aborts staged edits:

```java
try (MpqUpdate update = MpqUpdate.begin(Path.of("archive.mpq"))) {
    update.replaceData("foo.txt", "new contents".getBytes(), null);
    update.rename("old.txt", "new.txt");
    update.commit();
}
```

The same `MpqUpdate` methods work for MPQE updates. The transport has no independent
authentication tag. A wrong code can still yield a structurally plausible MPQ.

```java
try (MpqUpdate update = MpqUpdate.beginMpqe(Path.of("archive.mpqe"), authCode)) {
    update.replaceData("foo.txt", "new contents".getBytes(), null);
    update.commit();
}
```

`replacePath`, `remove`, and explicit `abort` are also available. Commit and
abort consume the handle even on error. Java uses `null` for no replacement
options: it passes a native NULL pointer, so libmpq uses defaults and
preserves the member's locale/platform identity. Pass explicit `FileOptions`
for custom storage, including distinct first/later compression masks; their
locale/platform must match the existing member. Embedded MPQ containers retain
their prefix and unrelated trailing bytes. Ordinary MPQs and embedded W3X/W3M
containers use `MpqUpdate.begin`; MPQE uses `beginMpqe` with an explicit code
needed only during begin. Closing either active update aborts it.

## Patch creation

`Archive.patchPayloadSize(number)` reports decoded PTCH size, not the final
patched target size returned by `fileUnpackedSize(number)`.
`readPatchPayload(number)` or `readPatchPayload(number, filename)` returns a
caller-owned `byte[]` beginning with `PTCH`, excluding the plaintext patch-info
prefix and without applying the patch. Supply the physical member filename
when encryption needs a name-derived key. Native decoding/integrity errors and
non-patch members throw `LibmpqException`; sizes outside the Java array range
throw `IllegalArgumentException`. The archive must remain open.
`Mpq.FILE_FLAG_PATCH_FILE` (`0x00100000`) and `Mpq.FILE_FLAG_DELETE_MARKER`
(`0x02000000`) can be tested against `fileFlags(number)`.

Create a patch artifact while leaving its base archive unchanged:

```java
try (MpqPatch patch = MpqPatch.begin(Path.of("base.mpq"), Path.of("changes.mpq"))) {
    patch.addData("new.txt", "ordinary addition".getBytes());
    patch.addPath("from-path.bin", Path.of("source.bin"));
    patch.replaceData("foo.txt", "new contents".getBytes());
    patch.remove("old.txt");
    patch.sign(weakPrivateKey); // or patch.sign(Mpq.SIGNATURE_STRONG, strongPrivateKey)
    patch.finish();
}
```

`MpqPatch.addData(name, data, options)` and `addPath(name, source, options)`
write ordinary new members; the overloads without options use ordinary writer
defaults. These calls require base-absent, unstaged identities. Existing names
or ambiguous hash/locale identities throw `LibmpqException`; name NULs are
rejected before the native call. Empty byte arrays are valid. Use replacement
for an existing base member, even after removal. Staged additions cannot be
replaced or removed. Compression, encryption/KEY and sector CRC reuse
`FileOptions`; patch/delete flags are rejected. Native arenas own the borrowed
bytes and strings during each call. Validation preserves earlier valid stages;
partial output failures prevent publication. Addition-only artifacts compose
through `Archive.openPatch()` without a metadata marker.

`MpqPatch.begin` creates an ordinary MPQ patch. Use `beginMpqe` and an
explicit caller-supplied authentication code for MPQE output:

```java
try (MpqPatch patch = MpqPatch.beginMpqe(
        Path.of("base.mpq"), Path.of("changes.mpqe"), authCode)) {
    patch.replaceData("foo.txt", "new contents".getBytes());
    patch.finish();
}
```

The same `MpqPatch` handles either output. Authentication bytes are needed
only during begin; closing without finish aborts instead of publishing.

`replacePath` is also available. `finish()` publishes the patch; `abort()`
discards it, and closing an unfinished patch aborts automatically. Omitted
`FileOptions` pass native NULL and use native patch defaults; explicit
options configure patch-member storage. Patch rename is not supported. Explicit locale/platform must match the base member. Signing
configures the active patch without consuming it. Plain v1/v2/v3 patches may
configure weak and strong signatures separately; their MPQE variants support
weak signing only. V4 patches default to raw-chunk MD5, preventing weak signing.
Call `MpqPatch.setRawChunkSize(0)` before signing to allow weak signatures on
plain or MPQE output. MPQE strong signing remains unsupported. After `finish()`, use
`Archive.signatures()` and `Archive.verify()` on the finished artifact.

## Signatures

Weak MPQ signatures are supported with caller-supplied raw RSA-512 keys.
Strong verification uses a 512-byte raw public key: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
public exponent. Strong signing uses the same layout with the private exponent
and emits only the plain SHA-1 archive-range variant. Weak signatures are
supported inside MPQE-wrapped MPQs. External strong signatures are not defined
for MPQE transport streams. Use `Archive.sign(privateKey)` for weak signing or
`Archive.sign(SIGNATURE_STRONG, privateKey)` for strong signing before writer
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
SHA-1/RSA-2048 external `NGIS` trailers. `Archive.verify(byte[])` remains the
weak convenience overload; `verify(int, byte[])` accepts `SIGNATURE_STRONG`
and a 512-byte raw public key. Strong signatures are legacy compatibility data.
`Archive.sign(SIGNATURE_STRONG, key)` creates the plain SHA-1 archive-range
strong variant from a 512-byte raw private key.

## Development and testing

For example:

```sh
mvn test -Dorg.libmpq.library=/path/to/libmpq/src/.libs/libmpq.so
```

To exercise the loader-path fallback explicitly, provide the native library
directory through the platform loader and enable the integration test mode:

```sh
LD_LIBRARY_PATH=/path/to/libmpq/src/.libs \
    mvn test -Dorg.libmpq.test.loaderPath=true
```

## Distribution packages

The GitHub Release Java ZIP is a supplementary download containing the
runtime, sources, and Javadoc JARs together with `COPYING`, `COPYING.LESSER`,
and this README.

See [RELEASING.md](../../RELEASING.md) for maintainer release procedures.

### Composing opened archives

```java
Archive result;
try (Archive base = Archive.open(Path.of("base.mpq"));
     Archive patch = Archive.open(Path.of("patch.mpq"))) {
    result = Archive.openPatch(base, List.of(patch));
}
try (result; MpqStream stream = result.openStream("document.txt")) {
    byte[] bytes = new byte[4096];
    int count = stream.read(bytes);
}
```

Import `java.util.List` for the layers in application order. The optional
third argument supplies one prefix per layer. A null list or entry requests
inference, `""` selects root, and a nonempty string selects that namespace.
To supply a null entry in Java, use a list implementation that permits nulls.
An empty patch list creates an independent snapshot. Explicit addition-only
layers need no metadata marker. The read-only result is independent of its
inputs after successful open. Keep input callback resources alive for any
other dependent handles. Result clones and streams retain the result's own
storage after parent closure. Named modern materialization requires
unambiguous names and metadata. Verify physical signatures and raw checksums
on input archives separately; they do not confer trust on logical output.
Temporary storage is released after the final dependent closes, with
best-effort cleanup on persistent I/O failure.

### Read one patched member

```java
MpqStream stream;
try (Archive base = Archive.open(basePath); Archive layer = Archive.open(patchPath)) {
    stream = base.openPatchStream("member.bin", 0, 0, List.of(layer), null);
}
try (stream) {
    stream.read(new byte[4096]);
}
```

Use `openPatchStream(filename, patches, prefixes)` for ordinary lookup in the
final patched view. The overload with locale and platform immediately after
the filename selects that exact tuple, as in the neutral example above.

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

```java
try (Archive archive = Archive.create(Path.of("output.mpq"),
        new ArchiveCreateOptions(Mpq.ARCHIVE_VERSION_FOUR, 8, 4096,
                                 Mpq.ARCHIVE_CREATE_LISTFILE))) {
    archive.setRawChunkSize(17); // 0 disables trailing raw MD5
    long configured = archive.getRawChunkSize();
    archive.add("data.txt", "content".getBytes(), null);
}
```

`Archive.setRawChunkSize(size)` and `MpqPatch.setRawChunkSize(size)` configure
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
`MpqPatch.getRawChunkSize()` reports a live patch writer's configured policy,
including after its setters lock.

Java uses unsigned values represented as `long`, validating
`0 <= size <= 0xffffffffL` before narrowing.

### Exact filename identities

```java
List<FileIdentity> identities = archive.variants("dir/file.bin");
int number = archive.fileNumber("dir/file.bin", 0x409, 1);
try (MpqStream stream = archive.openStream("dir/file.bin", 0x409, 1)) {
    byte[] bytes = new byte[32];
    int count = stream.read(bytes);
}
```

`variants()` returns an immutable list of `FileIdentity` records in native
classic slot order. Aliases may share a canonical file number. The
`Mpq.IDENTITY_CLASSIC` and `Mpq.IDENTITY_BET` bits describe stored provenance,
not storage flags. BET-only identities are unqualified `(0, 0)`. Exact
selectors must be in `0..65535`; these overloads never perform locale fallback.
Existing overloads keep their behavior. Duplicate, ambiguous or reduced-hash
layouts raise the existing native error exception. Exact named streams retain
the encryption filename and their own archive clone; parent close is safe.
Callback sources retain the existing dependent-stream lifetime contract.

Exact update overloads select a filename/locale/platform identity without
neutral fallback. Selectors must be in `0..65535`:

```java
try (MpqUpdate update = MpqUpdate.begin(path)) {
    update.replaceData("voice.bin", 0x409, 1, replacement, null);
    update.rename("voice.bin", 0x409, 1, "renamed.bin");
    update.replacePath("renamed.bin", 0x409, 1, source, null);
    update.remove("obsolete.bin", 0, 0);
    update.commit();
}
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

`MpqUpdate.changeIdentity(name, locale, platform, newLocale, newPlatform)` changes
only the selected tuple. `locale` and `platform` select the old identity;
`newLocale` and `newPlatform` specify its destination tuple. The filename and
payload stay unchanged. `rename()` changes the filename and keeps the
selected tuple. All four selector values must be in `0..65535`:

```java
try (MpqUpdate update = MpqUpdate.begin(path)) {
    int oldLocale = 0, oldPlatform = 0;
    int newLocale = 0x409, newPlatform = 1;
    update.changeIdentity("voice.bin", oldLocale, oldPlatform, newLocale, newPlatform);
    update.commit();
}
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

```java
update.compact();
update.compact(List.of("voice", "left/data"));
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

The List overload rejects a null list or null/empty/NUL entries; an empty
list is ordinary compaction. Conversion uses a snapshot and one confined Arena
with the existing native size_t representation.

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

```java
try (MpqUpdate update = MpqUpdate.begin(path)) {
    update.sign(privateKey); // weak by default
    update.sign(Mpq.SIGNATURE_STRONG, strongKey);
    update.commit();
}
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

```java
var result = archive.verifyFileResult(number, Mpq.VERIFY_ALL, "voice.bin");
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

```java
var result = archive.verifyEx(Mpq.VERIFY_METADATA_ALL);
```

The `Archive.verify` overloads taking a public key verify digital signatures.
`Archive.verifyEx()` verifies archive structural and RAW metadata using
the native `archive_verify_ex()` and the eight
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
`Archive.verifyEx()` defaults to `Mpq.VERIFY_METADATA_ALL` (`0xFF00`),
the separate mask for archive header, table and table RAW checks. Archive
metadata verification rejects member flags such as `VERIFY_ALL`.

The source must remain stable; source reads do not promise uncached filesystem
access or an atomic snapshot of concurrent writes. Embedded offsets and MPQE
logical reads use existing source handling. Unkeyed MD5 establishes neither
provenance nor authenticity, MPQE transport authenticity or whole-archive
integrity. `archive_verify()` remains public-key signature verification;
`file_verify_ex()` remains member verification.

`Mpq.FILE_FLAG_KEY` (`0x00020000`) selects offset- and size-adjusted
encryption-key derivation. It modifies `ENCRYPTED`; it does not enable encryption
on its own. The effective key is `(basename_key + uint32(MPQ-relative offset))
XOR uint32(uncompressed size)`, with modulo-2^32 arithmetic. Embedded prefixes
are excluded from this offset. The flag provides no integrity guarantee.

### Caller-owned output

Use `Archive.createSink(channel, readBack, options)` with an initially
empty seekable channel that provides zero-filled gaps. Set `readBack` to
true only for a readable channel. V4 and signing require it. The adapter
performs exact positioned transfers and keeps the channel open through
archive close and afterward. Use try-with-resources for checked archive
finalization. This overload supplies no native flush callback. The caller
may flush, publish or close the channel separately.
Failed output may contain partial bytes. Oversized SINGLE still buffers
the complete input unit.

The overloads `createSink(channel, readBack, options, flush)` and
`createMpqeSink(channel, authCode, options, flush)` accept an optional
`Archive.FlushCallback`. Native close calls it synchronously once after
successful final writes. An earlier finalization failure skips the callback.
Use it to flush, synchronize or finalize application-managed sink state.
The callback must not re-enter the writer. An ordinary exception
makes archive close throw `LibmpqException` with `Mpq.ERROR_CLOSE`. Close
consumes the archive even on error and leaves the channel caller-owned.
Passing `null` gives the same behavior as the overloads without a callback.

Throw `LibmpqCallbackException` from a channel's positioned read or write,
or from the final flush, to report a documented negative `Mpq.ERROR_*` code
to libmpq. The type extends `IOException` and works with the existing callback
signatures. Other channel exceptions and incomplete transfers still map to
`ERROR_READ` or `ERROR_WRITE`. Native code can translate the callback status as
part of the enclosing operation. The writer latches its first output failure
and skips flush after an earlier failure.

```java
Archive.FlushCallback flush = () -> {
    if (scratchUnavailable) {
        throw new LibmpqCallbackException(Mpq.ERROR_MALLOC);
    }
};
```

The channel remains caller-owned. Keep a source open through close of all
dependent archives and streams, and keep the sink open through writer close.

For example, when the application owns a `FileChannel` and chooses to force
its writes:

```java
try (Archive writer = Archive.createSink(fileChannel, true, options,
        () -> fileChannel.force(true))) {
    writer.add("payload.bin", payload, FileOptions.raw());
}
```

The binding leaves persistence to the application.

### Writing MPQE to a channel

```java
try (Archive writer = Archive.createMpqeSink(channel, authCode, options)) {
    writer.add("payload.bin", payload, FileOptions.raw());
}
```

Supply an empty caller-owned channel. Write access is sufficient for every
archive generation. Close emits the final MPQE transport and leaves the channel
open. The caller controls persistence and publication. MPQE encoding does not
independently authenticate the archive.

### Fixed-size range replacement

An update can replace several plaintext ranges in one staged operation.
Offsets are zero-based and must fit inside the existing member. Later ranges
win when they overlap, and commit publishes the result.

```java
update.replaceRanges("member.bin", List.of(new MpqUpdate.ReplaceRange(100, new byte[] {1, 2})));
update.replaceRanges("member.bin", 1033, 0, List.of(new MpqUpdate.ReplaceRange(4096, new byte[] {3})));
```

Supported lossless members retain encryption and storage policies; the native
writer rebuilds the selected member. SINGLE requires full-unit buffering.
