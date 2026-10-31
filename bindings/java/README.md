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

### Logical member streams

Use Archive.openStream(name) for incremental seekable member access. The stream
owns an independent native archive clone and remains usable after the
originating archive closes. Stream reads validate available sector Adler-32
checksums but do not implicitly verify whole-file CRC32/MD5 values.

    try (MpqStream stream = archive.openStream("data/file.bin")) {
        byte[] buffer = new byte[4096];
        int count = stream.read(buffer);
    }

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

`archive.verify(fileNumber)` explicitly compares sector Adler-32 and file
CRC32/MD5. For one sector, `archive.verifyBlock(fileNumber, blockNumber)`
returns `Archive.BlockVerification` with `checksum()` (unsigned stored
Adler-32 as `long`) and `mismatches()` (zero or `Mpq.VERIFY_SECTOR_CRC`).
Unavailable checksums throw `LibmpqException` with `Mpq.ERROR_EXIST`.

Use `Mpq.VERIFY_SECTOR_CRC`, `Mpq.VERIFY_FILE_CRC32`, `Mpq.VERIFY_FILE_MD5`, or
`Mpq.VERIFY_RAW_MD5` to select checks. Sector checks cover decrypted packed
bytes; file hashes cover extracted bytes. Missing values/tables are skipped.
File checksum requests require attributes; sector/raw-only requests do not.
`Mpq.VERIFY_ALL` selects all checks. The returned mismatch mask uses the same
`Mpq.VERIFY_*` bits and is a subset of the request. Set bits mean available
checksums mismatched; clear bits mean matched or unavailable/skipped.
Operation errors throw existing exceptions. Zero does not prove availability.
Complete lossless reads automatically compare available CRC32/MD5 values;
lossy ADPCM is not compared because decoded bytes may differ from source hashes.

`Mpq.VERIFY_RAW_MD5` hashes v4 stored member chunks before file decryption or
decompression, after MPQE transport decoding. It is skipped for older versions,
disabled raw chunks and empty stored payloads. It checks physical patch members,
not reconstructed patch-view output.

`archive.fileFlags(fileNumber)` returns the unsigned stored block-table flags
as a `long`. Inspect `Mpq.FILE_FLAG_*` bits; convenience booleans use this
query.

`archive.blockCompression(fileNumber, blockNumber)` returns the stored method
byte, or zero for raw storage/fallback, without decoding. LZMA is `0x12`, not
the writer selector.

`archive.blockSizePacked(fileNumber, blockNumber)` returns stored data bytes,
excluding offset and checksum tables. `archive.blockSize(...)` remains the
decoded size used for read buffers.

`Archive.attributes()` returns `OptionalInt`; absence is empty.
`Archive.attributes(fileNumber)` returns an owned `FileAttributes` record.
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
lookup or supply both for exact selection without fallback:

```java
update.timestamp("voice.bin", 132537600000000000L, 0, 0);
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

Import `java.util.List` for the ordered layer list. The optional third
argument is a prefix list: a null list or entry requests inference, while
`""` selects the root namespace. An empty patch list creates an independent
snapshot. Explicit addition-only layers need no metadata marker. The normal
owned Archive result retains neither inputs nor callback channels. Its clones
and streams survive parent closure. Named modern materialization requires
unambiguous names and metadata. Verify physical signatures and raw checksums
on input archives separately; they do not confer trust on logical output.
Temporary storage is released after the final dependent closes, with
best-effort cleanup on persistent I/O failure.

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
    update.rename("voice.bin", "renamed.bin", 0x409, 1);
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
payload stay unchanged. All four values must be in `0..65535`:

```java
try (MpqUpdate update = MpqUpdate.begin(path)) {
    update.changeIdentity("voice.bin", 0, 0, 0x409, 1);
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

Filename operations retain their default and locale/platform overloads. The
default overload calls the ordinary C operation; the qualified overload calls
the explicit identity operation with scalar locale/platform values, including
`(0,0)`, without fallback. Replacement options remain independent and must
match the selected tuple. Use the v0.9.0 native
library with these bindings to provide the explicit identity functions.

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
integrity. Existing verification methods retain their behavior.

For eligible nonempty v4 members, a nonzero raw chunk size declares required
trailing RAW MD5 storage. Missing, truncated or overlapping arrays raise the
existing native errors; adjacency and zero-filled bytes do not prove absence.
RAW is unavailable only for older versions, zero raw size, empty stored data
or delete markers. A matching unkeyed MD5 is not proof of provenance or
cryptographic authenticity. Complete coverage requires successful native
status, checked equal to the request, no unavailable checks and no mismatches.

## Archive metadata verification

```java
var result = archive.verifyResult(Mpq.VERIFY_METADATA_ALL);
```

Archive metadata verification uses the native `archive_verify_ex()` and the eight
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
Errors clear all outputs. Zero flags perform no comparisons. Existing member
`VERIFY_ALL` remains unchanged and is rejected by archive metadata verification.

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
finalization. The caller may flush, publish or close the channel separately.
Failed output may contain partial bytes. Oversized SINGLE still buffers
the complete input unit.

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
