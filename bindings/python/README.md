# libmpq Python bindings

The `mpq` module provides Python 3.11+ ctypes bindings for libmpq, with
explicit archive and reader lifecycle management, typed native errors,
archive creation, cloning, metadata, block access, compression, encryption,
and streaming writes.

## Installation

The canonical release installation path is [PyPI](https://pypi.org/project/libmpq/):

```sh
python -m pip install libmpq
```

The binding is distributed through Python packaging rather than Autotools.
Autotools includes the binding sources in source archives but does not install
the Python package. For a local package installation, use the PEP 517 build
backend through `pip`:

```sh
python -m pip install .
```

## Basic archive usage

Typical usage is explicitly closeable and safe with context managers:

```python
import mpq

with mpq.Archive("data.mpq", offset=0) as archive:
    entry = archive["readme.txt"]
    print(entry.read())
```

Native failures raise `LibmpqError` subclasses with `.code` and `.message`
attributes. I/O and missing-file subclasses remain compatible with the
corresponding Python built-in exception categories.

Native string inputs, including paths, member names, source labels and patch
prefixes, raise `ValueError` if they contain an embedded NUL. Text is encoded
as UTF-8 and NUL-free `bytes` inputs retain their original bytes. A `None` patch
prefix requests inference. An empty string or `b""` selects the root namespace.

### Reading and writing

Use `packed_size` and `unpacked_size` for stored and logical entry sizes.
At archive level these are sums across entries. The archive's physical extent
also accounts for layout and tables. Use `file.read()` for payload bytes and
decode text explicitly, for example `file.read().decode("utf-8")`.

`archive.version` reports the MPQ generation (1 through 4). The
`ArchiveCreateOptions.version` field and writer creation use
`ARCHIVE_VERSION_*` selectors (0 through 3). `archive.files` counts live
canonical entries, including stored internal members where present,
independently of classic hash-table capacity. `archive.offset` is the archive
origin in the backing source and can be nonzero for embedded archives.
`file.offset` is the stored member position relative to the start of the MPQ.
The corresponding `metadata()` snapshots use the same units and coordinates.

Use `Archive(file)` to open a raw, contiguous MPQ member of a live plain MPQ
opened from a host path. The embedded origin is the parent origin plus the
member offset. Keep the original host path and its backing file stable while
reopening. A live clone of a path-backed parent also supports this operation.

```python
with mpq.Archive("container.mpq") as parent:
    with mpq.Archive(parent["nested.mpq"]) as nested:
        data = nested["payload.bin"].read()
```

`Archive(file)` raises `ValueError` for callback, MPQE, and materialized patch
parents. Callback display names are labels, and MPQE or patch-result
coordinates belong to their respective backing sources. For a caller-owned
source that presents the embedded MPQ bytes at a known position, use
`Archive.open_io(source, size, offset=position)` to open that source directly.

`Archive.file_number(name)` tries HET/BET when present and falls back to
classic lookup on a miss. Supplying `locale` and `platform` selects an exact
identity through classic or supported HET/BET metadata. HET/BET-only
identities accept only `(0, 0)`. For precomputed classic Storm hashes, pass the
three unsigned 32-bit values in `mpq.file_hash()` order:

```python
hashes = mpq.file_hash("overview.txt")
number = archive.file_number_from_hash(hashes)
```

`file_number_from_hash()` probes the classic hash table. A missing table or
entry raises `LibmpqNotFoundError` (`ERROR_EXIST`). Filename-based
`file_number()` can still resolve members reachable only through HET/BET.

### Logical member streams

Open an ordinary stream by file number with `open_stream(number)`, by
filename with `open_stream(name)`, or by exact identity with
`open_stream(name, locale=locale, platform=platform)`. Named streams provide the
filename for decryption when the key requires it. These streams own a
native archive clone and can outlive the original archive. Callback-backed
clones and ordinary streams still use the caller's source. Keep the callback,
its context and stable backing storage valid until all dependent handles
close. Stream reads check usable sector Adler-32 values. Whole-member
CRC32/MD5 verification is separate. See [Read one patched member](#read-one-patched-member)
for `open_patch_stream()`.

    with archive.open_stream("data/file.bin") as stream:
        chunk = stream.read(4096)
        stream.seek(0)

A native read can fail after advancing the stream by the bytes it copied.
The existing `LibmpqError` subclass carries `code`, `transferred` and
`partial_data` for that read. A failure before copying has an empty prefix.
Successful reads still return `bytes`, with empty bytes at EOF or for a
zero-length request.

```python
try:
    chunk = stream.read(8192)
except mpq.LibmpqError as error:
    partial = error.partial_data
    count = error.transferred
    position = stream.tell()
```

### Reading into caller-owned storage

Use a writable C-contiguous buffer such as a `bytearray`, writable
`memoryview`, an appropriately sliced view, or a writable `mmap`. The
binding passes the view's address and byte capacity directly to C without
copying the destination. It uses the length in bytes even for a view with
multi-byte elements, and checks that capacity fits a signed 64-bit integer.
Read-only, strided and released views are rejected. The caller owns the
storage and must keep it available throughout the call. Do not resize,
unmap, close or concurrently mutate the destination while C is using it.

```python
import mpq

with mpq.Archive("archive.mpq") as archive:
    entry = archive["overview.txt"]
    content = bytearray(entry.unpacked_size)
    file_count = entry.read_into(content)

    block = bytearray(entry.block_size_unpacked(0))
    block_count = entry.read_block_into(0, block)

    with archive.open_stream("overview.txt") as stream:
        chunk = bytearray(4096)
        stream_count = stream.read_into(chunk)

with mpq.Archive("changes.mpq") as patch:
    entry = patch["overview.txt"]
    payload = bytearray(entry.patch_payload_size)
    payload_count = entry.read_patch_payload_into(payload, filename="overview.txt")
```

Each method returns the actual count in bytes from one native read. Whole-file
reads perform the usual integrity checks. Block reads require nominal block
capacity and can return fewer bytes after decoding. They use the ordinary
block decoder without separate checksum verification. PTCH reads return the
validated physical payload and accept the optional physical member name for
key derivation. Use the relevant size query to prepare storage when its
capacity is unknown.

`MpqStream.read_into()` returns zero at EOF or for a zero-capacity
destination. On failure, the native status is in `error.code`, and the
first `error.transferred` bytes of the destination remain valid. The cursor
includes those bytes. The exception omits `partial_data` because the prefix
is in the supplied buffer. Whole-file, block and PTCH reads provide a byte
count on success only. Use `read()`, `read_block()` and
`read_patch_payload()` for return-bytes reads, including the existing
`partial_data` convention on `MpqStream.read()` errors.

### Custom random-access I/O

Use `Archive.open_io(source, size, source_name=...)` for a caller-owned
seekable source such as `io.BytesIO`. The binding retains the source while
archives or derived streams are alive, but never closes it.

    archive = mpq.Archive.open_io(io.BytesIO(data), len(data), source_name="data.mpq")

### Integer arguments

The binding checks integers and objects implementing `__index__` against the
corresponding C width before native conversion, including when setting fields
on creation options. Archive offsets are nonnegative signed 64-bit positions
or `-1` for header discovery. Stream seeks use signed 64-bit offsets and allow
negative relative offsets. Caller-supplied source sizes and declared member
lengths are nonnegative signed 64-bit values.

File and block numbers, flags, and masks use unsigned 32-bit values. Exact
locale and platform each use unsigned 16-bit values. FILETIME accepts the
full unsigned 64-bit range. Noninteger and out-of-range arguments are rejected
instead of being truncated. Values that fit the C type still have to meet
the native operation's format and resource limits.

```python
import os
import mpq

with mpq.Archive.open("archive.mpq", offset=-1) as archive:
    with archive.open_stream("member.bin") as stream:
        if stream.size:
            stream.seek(-1, os.SEEK_END)
            last_byte = stream.read(1)
```

## Archive creation

Use the same context-manager pattern for ordinary and MPQE writers:

```python
with mpq.Writer("created.mpq", version=mpq.ARCHIVE_VERSION_THREE) as writer:
    writer.add_data("payload.bin", b"payload", mpq.FileCreateOptions.raw())

with mpq.Writer.create_mpqe(
    "created.mpqe", b"LIBMPQ-MPQE-EXAMPLE-AUTH-CODE-01"
) as writer:
    writer.add_data("payload.bin", b"payload")
```

`Writer.add_data(name, data, options=None)` adds a complete member from
memory. `Writer.add()` remains a supported compatibility alias with the
same arguments. Use `Writer.add_path()` to add a filesystem file.

MPQE creation writes a private plaintext temporary file before atomically
replacing the destination with the encrypted archive. Use `Update.begin_mpqe`
to modify an existing MPQE archive. Cleanup is best effort if the process
crashes. The example authentication code is illustrative and non-secret; real
callers must provide their own authentication code of at least 32 bytes.

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

### Compression policy

Creation defaults to `COMPRESSION_POLICY_STANDARD`. Pass
`flags=mpq.ARCHIVE_CREATE_COMPRESSION_EXTENDED` to `Writer` or
`Writer.create_mpqe` for additional, potentially less interoperable methods.
Use `mpq.archive_compression_allowed(version, mask, policy)` to query whether
a compression selection is allowed by the writer policy. Version uses
`ARCHIVE_VERSION_ONE`, `ARCHIVE_VERSION_TWO`, `ARCHIVE_VERSION_THREE`, or
`ARCHIVE_VERSION_FOUR`. V3/v4 creation emits HET/BET plus classic tables.
Transactions can retain unrelated unnamed members with sufficient stored
identities; see the
[transaction limits](../../DEVELOPER.md#transactional-modification).
V4 creation, including MPQE, uses 16 KiB raw chunks; v4 updates preserve the
source raw-chunk size. `Update.add_data()` and `Update.add_path()` add absent staged
names; duplicates fail and replacement remains existing-only. Removal followed
by addition is supported. Readers remain permissive regardless of the
creation policy.

`COMPRESSION_SPARSE` selects lossless zero-run compression. In MPQ v2+,
STANDARD allows the fixed SPARSE forms: alone (`0x20`), with
`COMPRESSION_ZLIB` (`0x22`), or with `COMPRESSION_BZIP2` (`0x30`). MPQ v1
retains normal compression-mask semantics under either policy, allowing
other valid combinations such as SPARSE with Huffman (`0x21`) or PKWARE
(`0x28`). In MPQ v2+, EXTENDED permits the broader valid lossless SPARSE
combinations. Neither policy allows SPARSE with WAVE ADPCM. The shared
`sparse*.txt` fixtures use UTF-32LE with a BOM; `.read()` returns bytes,
which can be decoded with `.decode("utf-32")`.

### Optional attributes and integrity

Set `FILE_FLAG_SECTOR_CRC` in file options alongside COMPRESS or IMPLODE
to generate sector Adler-32 tables, including for encrypted files. Empty,
raw, and single-unit files ignore this flag. Generation is opt-in and
complete reads automatically verify usable sector entries.

`File.verify()` returns a member checksum mismatch mask.
`File.verify_result()` also reports which checks ran and which were unavailable.
Both default to `VERIFY_ALL`. For one sector,
`archive["file.txt"].verify_block(block_number)` returns `(stored_adler32, mismatches)`. Mismatches is zero or
`VERIFY_SECTOR_CRC`; an unavailable checksum raises `LibmpqNotFoundError`
rather than reporting a match.

Member checks are `VERIFY_SECTOR_CRC` (`0x1`, sector Adler-32 over
decrypted packed bytes), `VERIFY_FILE_CRC32` (`0x2`) and
`VERIFY_FILE_MD5` (`0x4`) over logical member bytes, and
`VERIFY_RAW_MD5` (`0x8`) hashes stored MPQ v4 member chunks before member
decryption or decompression, after MPQE transport decoding. It applies to
nonempty stored members with a nonzero raw chunk size, excluding delete
markers. For physical patch members it checks the stored patch payload.

`VERIFY_ALL` was `0x7` in v0.8.1. In v0.9.0 it is `0xF`, adding RAW MD5.
Python code that looks up the constant or uses the method default in the
v0.9.0 module requests the expanded mask on the next run.
Passing `0x7` explicitly keeps the original three checks.
The extra RAW check can add I/O or report a mismatch. An inapplicable RAW
check is skipped by mismatch-only verification and reported as unavailable
by the detailed result. A digest mismatch is a result bit. Malformed
required digest storage or a read failure can raise a native error.

The mismatch-only call requires stored attributes for logical checksum
requests and returns the mismatch mask for checks it performed. A clear
bit can mean a match or an unavailable check. Complete lossless reads
also compare usable CRC32/MD5 attributes automatically.

`file.flags` contains the stored block-table flags. Inspect `FILE_FLAG_*`
bits; `encrypted`, `compressed`, and `imploded` are derived convenience
booleans.

`file.block_compression(block)` returns the stored method byte, or zero for
raw storage/fallback, without decoding. LZMA is `0x12`, not the writer selector.

`file.block_size_packed(block)` returns stored data bytes, excluding offset
and checksum tables. `file.block_size_unpacked(block)` returns the expected
logical size from metadata. `file.read_block(block)` returns the actual decoded
bytes, which may be fewer than the expected size. `file.block_size(block)`
remains a supported compatibility alias for `file.block_size_unpacked(block)`.

```python
stored = file.block_size_packed(0)
expected = file.block_size_unpacked(0)
decoded = file.read_block(0)
```

`Archive.attributes()` returns archive-wide flags or `None` if absent.
`File.attributes()` returns a `FileAttributes` result and requires the
member to have a valid classic block-table row. A readable BET-only member
can raise `LibmpqFormatError` with `ERROR_FORMAT` from this query.

Use `WriterFile.timestamp(filetime)` before finishing a streaming file.
Supply Windows FILETIME, not Unix time.

Creation is opt-in: combine `ATTRIBUTE_CRC32`, `ATTRIBUTE_FILETIME`,
`ATTRIBUTE_MD5`, and `ATTRIBUTE_PATCH_BIT` in the `attributes=` argument of
`Writer` or `Writer.create_mpqe()`. Zero disables generation; any nonzero
combination creates one `(attributes)` file and consumes one reserved slot.
Unknown bits are rejected. Creation flags remain separate. These options work
for MPQ v1, v2, v3, and v4, including MPQE creation. Payload version 100 is
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
lookup or supply both for exact selection without fallback:

```python
update.timestamp("voice.bin", 132537600000000000, locale=0, platform=0)
```

Zero is an available timestamp; integers in `0..UINT64_MAX` are accepted.
Existing valid FILETIME and classic provenance are required. Actual changes
to shared rows are rejected; validated same-value requests preserve staged
bytes and signatures, including shared rows. Eligible changes preserve packed
payloads and invalidate signatures. Missing arrays are not created. Ordinary
replacement resets timestamps to zero; exact replacement retains them. Normal
transaction staging, abort and publication guarantees apply.

Transactional updates use a separate handle. Edits stay private until commit;
leaving the context without committing aborts them automatically:

```python
with mpq.Update.begin("archive.mpq") as update:
    update.replace_data("foo.txt", b"new contents")
    update.rename("old.txt", "new.txt")
    update.commit()
```

MPQE transport decoding/encryption does not independently authenticate an archive
or guarantee detection of an incorrect authentication code. Use the same
`Update` methods for MPQE after transport decoding:

```python
with mpq.Update.begin_mpqe("archive.mpqe", auth_code) as update:
    update.replace_data("foo.txt", b"new contents")
    update.commit()
```

`replace_path`, `remove`, and explicit `abort` are also available. Commit and
abort consume the update handle even on error. Omitting replacement options
passes a native NULL options pointer, so libmpq uses defaults and preserves
the member's locale/platform identity. Supply `FileCreateOptions` as the
optional third argument for custom storage; its locale/platform must match
the existing member. Ordinary MPQs and embedded W3X/W3M containers use
`Update.begin`; MPQE uses `Update.begin_mpqe` with an explicit code. The code
is needed only during begin. Both paths abort automatically without commit.

## Patch creation

Read a patch member without applying it with `File.patch_payload_size` and
`File.read_patch_payload(filename=None)`. The latter returns caller-owned
`bytes` containing the validated decoded PTCH body, beginning with `PTCH`,
without the plaintext patch-info prefix. Its size is distinct from
`File.unpacked_size`, which describes the final patched target. Supply the
physical member filename when encryption requires a name-derived key; numeric
selection does not invent a name. Native errors, including non-patch members
and integrity failures, raise the existing `LibmpqError` subclasses. Closed
archives cannot be used. `FILE_FLAG_PATCH_FILE` (`0x00100000`) and
`FILE_FLAG_DELETE_MARKER` (`0x02000000`) are available through `File.flags`.

Create a separate patch artifact without modifying its base archive:

```python
with mpq.Patch.begin("base.mpq", "changes.mpq") as patch:
    patch.add_data("new.txt", b"ordinary addition")
    patch.add_path("from-path.bin", "source.bin")
    patch.replace_data("foo.txt", b"new contents")
    patch.remove("old.txt")
    patch.sign(private_key)  # or patch.sign(strong_key, mpq.SIGNATURE_STRONG)
    patch.finish()
```

`Patch.add_data(name, data, options=None)` and
`Patch.add_path(name, source_path, options=None)` create ordinary members,
not PTCH payloads. Names must be absent from the base and staged identities;
duplicates raise the existing not-found/existence exception, while ambiguous
hash/locale identities raise a format exception. Use replacement for existing
base members, even after removal. A staged addition cannot then be replaced
or removed. Empty bytes are valid. Existing storage options support compression
and encryption/KEY; patch/delete flags are rejected. Inputs are borrowed
only during the call. Before-output validation preserves valid stages;
partial output errors prevent publication. Addition-only patches compose
through `Archive.open_patch()` without a metadata marker.

`Patch.begin()` creates an ordinary MPQ patch. For an MPQE-wrapped patch, use
the same `Patch` wrapper with an explicit caller-supplied authentication code:

```python
with mpq.Patch.begin_mpqe("base.mpq", "changes.mpqe", auth_code) as patch:
    patch.replace_data("foo.txt", b"new contents")
    patch.finish()
```

The auth bytes are needed only during begin. Authenticated readers need the
same code to open the result; unfinished patches are aborted on cleanup, not
published.

`replace_path` accepts a filesystem source. `finish()` publishes the patch;
`abort()` discards it, and leaving the context unfinished aborts
automatically. Omitting replacement options passes native NULL and uses native
patch defaults; pass `FileCreateOptions` explicitly to configure patch-member
storage. Patch options must match the base member's locale/platform identity.
Patch rename is not supported. Signing configures the active patch
without consuming it. Plain v1/v2/v3 patches may configure weak and strong
signatures separately; their MPQE variants support weak signing only. V4 patches default to raw-chunk MD5, preventing weak signing.
Call `patch.raw_chunk_size = 0` before signing to allow weak signatures on
plain or MPQE output. MPQE strong signing remains unsupported.
After `finish()`, use `Archive.signatures()` and `Archive.verify()`
on the finished artifact, as for any other archive.

## Signatures

Weak MPQ signatures are supported with caller-supplied raw RSA-512 keys.
Strong verification uses a 512-byte raw public key: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
public exponent. Strong signing uses the same layout with the private exponent
and emits only the plain SHA-1 archive-range variant. Weak signatures are
supported inside MPQE-wrapped MPQs. External strong signatures are not defined
for MPQE transport streams. Use `Writer.sign(privateKey)` for weak signing or
`Writer.sign(privateKey, SIGNATURE_STRONG)` for strong signing before writer
close, and `Archive.signatures()` / `Archive.verify(publicKey)` on reopened
archives. Verification returns mismatch bits; malformed keys/archives raise
normal binding errors. Weak keys are exactly 128 bytes: 64-byte big-endian
modulus followed by a 64-byte big-endian exponent. Weak-signature creation is
unsupported for MPQ v4 output with raw-chunk MD5 enabled. Public v4 creation defaults to raw chunks.
Call `writer.raw_chunk_size = 0` before signing to enable weak signatures,
including on MPQE output. Plain MPQ strong signing supports any raw size;
MPQE strong signing remains unsupported.
libmpq does not ship Blizzard- or product-specific public verification keys
or private signing keys; all signature key material is supplied explicitly
by the caller.
MD5/RSA-512 is legacy compatibility, not modern authenticity protection. See
[the format guide](../../MPQ.md) for details.

`Archive.signatures()` reports weak MD5/RSA-512 internal signatures and strong
SHA-1/RSA-2048 external `NGIS` trailers. `Archive.verify(key)` remains the
weak convenience form. Pass `signature_type=SIGNATURE_STRONG` and a 512-byte
raw public key for strong verification. Strong signatures are legacy
compatibility data. `Writer.sign(key, SIGNATURE_STRONG)` creates the
plain SHA-1 archive-range strong variant from a 512-byte raw private key.

## Development and testing

For source-tree development, set `LIBMPQ_LIBRARY` to an absolute
shared-library path, or build libmpq in the source tree and let the
development fallback locate `src/.libs/libmpq.so`.

```sh
./configure
make
LIBMPQ_LIBRARY="$PWD/src/.libs/libmpq.so" python -m pytest bindings/python/tests
```

## Distribution packages

Linux release wheels target `manylinux_2_17_x86_64`, `manylinux_2_17_aarch64`,
`musllinux_1_2_x86_64`, and `musllinux_1_2_aarch64`. Windows release wheels
target `win_amd64` and `win_arm64`. macOS wheels target `macosx_11_0_x86_64`
and `macosx_11_0_arm64`, with native Intel and Apple Silicon builds. All eight
wheels use the `py3-none` ABI.

Use a wheel whose platform and architecture match the Python interpreter.
The bundled native library exposes libmpq's public C API. Private native
implementation symbols are outside the wheel ABI.

Linux release wheels contain a private native library at `mpq_libs/libmpq.so`. It
is loaded by its exact package path through `ctypes`, intentionally has no ELF
`DT_SONAME`, and does not require a separate system libmpq installation. The
release Python ZIP contains one sdist and all eight Linux/Windows/macOS
wheels as a supplementary GitHub Release download. The sdist contains the
canonical C and header sources and is free of native build products.

Windows wheels bundle `mpq_libs/mpq.dll` and its required non-system
runtime DLLs, so no separately installed libmpq SDK is needed. Local Windows
wheel builds must set `LIBMPQ_LIBRARY` to a prebuilt shared CMake DLL; the
backend does not compile Windows sources itself.

macOS wheels contain `mpq_libs/libmpq.dylib` and any required non-system
dylibs bundled by delocate. No separately installed libmpq SDK is needed.
Both architectures retain the native SDK's macOS 11.0 deployment baseline;
there is no universal2 wheel. The wheels use system zlib, bzip2, and liblzma.

See [RELEASING.md](../../RELEASING.md) for maintainer release procedures.

### Composing opened archives

```python
with Archive("base.mpq") as base, Archive("patch.mpq") as patch:
    result = Archive.open_patch(base, [patch], prefixes=[None])
with result:
    with result.open_stream("document.txt") as stream:
        contents = stream.read()
```

Pass opened patch archives in application order. If supplied, `prefixes`
has one entry per layer. A `None` list or entry requests inference,
`""` selects root, and a nonempty string selects that namespace.
`Archive.open_patch(base, [])` creates an independent snapshot.
Explicit ordinary addition-only layers are accepted. The read-only result
is independent of its inputs after successful open. Keep input callback
resources alive for any other dependent handles. Result clones and streams
retain the result's own storage after parent closure. Named modern
materialization still requires unambiguous filenames and metadata. Verify
physical signatures and raw checksums on the original input archives; these
checks do not establish trust in reconstructed content. Temporary storage is
cleaned up after the final dependent closes, with best-effort I/O cleanup.

### Read one patched member

```python
with Archive("base.mpq") as base, Archive("layer.mpq") as layer:
    stream = base.open_patch_stream("member.bin", [layer], prefixes=[None],
                                    locale=0, platform=0)
with stream:
    data = stream.read(4096)
```

Omit both selectors for ordinary lookup in the final patched view. Passing
both requests the exact tuple, as in the neutral example above.

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

```python
with mpq.Writer("output.mpq", version=mpq.ARCHIVE_VERSION_FOUR) as writer:
    writer.raw_chunk_size = 17  # 0 disables trailing raw MD5
    assert writer.raw_chunk_size == 17
    writer.add_data("data.txt", b"content")
```

`Writer.raw_chunk_size` and `Patch.raw_chunk_size` are writable properties for
plain or MPQE v4 output. The default remains `0x4000` (16 KiB). Zero disables
member and HET/BET trailing raw arrays; all uint32 values, including 1, 17 and
`0xffffffff`, are accepted without a power-of-two restriction. Processing
uses bounded buffers. Configure before any member begins, signing succeeds or
finalization starts. Repeated early calls are allowed; failed validation or
signing preserves configurability, but an accepted begin fixes policy even
if that member is later aborted or fails. Lifecycle errors use the existing
binding exception mapping and leave the prior size unchanged.

`Archive.raw_chunk_size` is read-only and reports loaded policy. Reading
`Writer.raw_chunk_size` or `Patch.raw_chunk_size` reports configured policy,
including after configuration locks. Older generations return zero. This is policy
inspection, not proof of checksum presence or success. Physical raw MD5
hashes stored bytes separately from logical file checks. Updates preserve
the source policy; these setters do not configure transactions. Zero raw size
permits weak signing on v4, including MPQE; nonzero raw size rejects weak
signing. Successful signing freezes raw configuration. Plain strong signing
is supported at any raw size, while MPQE strong signing is unsupported.

Python setters require an integer in `0..0xffffffff`; invalid ranges or types
raise `ValueError` or `TypeError` before native conversion.

### Exact filename identities

```python
first = archive.file_identity("dir/file.bin", 0)
identities = archive.variants("dir/file.bin")
for identity in identities:
    print(identity.file_number, identity.flags, identity.locale, identity.platform)
number = archive.file_number("dir/file.bin", locale=0x409, platform=1)
with archive.open_stream("dir/file.bin", locale=0x409, platform=1) as stream:
    content = stream.read()
```

`file_identity(name, identity_index)` makes one native query and returns one
immutable `FileIdentity`. The index is a zero-based unsigned 32-bit ordinal in
native order, which is independent of locale priority. An unavailable ordinal
raises `LibmpqNotFoundError` with `ERROR_EXIST`. Use `variants(name)` for the
complete enumeration.

`variants()` returns a tuple of immutable `FileIdentity` records in native
classic slot order. Aliases can share a file number. `IDENTITY_CLASSIC` and
`IDENTITY_BET` flags describe stored provenance, not storage flags. BET-only
identities are unqualified `(0, 0)`; exact calls never fall back to another
locale/platform. Both selectors must be integers in `0..65535`. Ambiguous,
contradictory or reduced-hash layouts raise the existing format exception.
A filename can have multiple identities. Ordinary selection uses the native
filename lookup rules. Exact selection of `(0, 0)` requests only the neutral
identity.

Exact updates select one filename/locale/platform identity in the current
stage, without neutral fallback:

```python
with mpq.Update.begin(path) as update:
    update.replace_data("voice.bin", b"replacement", locale=0x409, platform=1)
    update.rename("voice.bin", "renamed.bin", locale=0x409, platform=1)
    update.replace_path("renamed.bin", source_path, locale=0x409, platform=1)
    update.remove("obsolete.bin", locale=0, platform=0)
    update.commit()
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

Use `Update.change_identity(name, locale, platform, new_locale, new_platform)`
to change only a stored tuple. `locale` and `platform` select the old
identity; `new_locale` and `new_platform` specify its destination tuple. The
filename and payload stay unchanged. `rename()` changes the filename and
keeps the selected tuple. All four selector values must be in `0..65535`:

```python
with mpq.Update.begin(path) as update:
    update.change_identity("voice.bin", locale=0, platform=0,
                           new_locale=0x409, new_platform=1)
    update.commit()
```

There is no neutral fallback. Equal tuples validate the source and are no-ops;
missing sources and occupied destinations use the existing EXIST error mapping.
Classic-only archives preserve shared aliases and their packed payloads at the
same offsets. Mixed targets require consistent one-to-one mappings with full
hashes; HET/BET-only entries cannot acquire qualifiers. Unsupported metadata,
special-member mutations and reconstruction layouts are rejected. Attributes,
timestamps, raw policy and transaction ownership are unchanged, and rejected
calls preserve the previous valid stage.

Filename selection uses keyword-only `locale` and `platform` arguments on
`file_number`, `open_stream`, `open_patch_stream`, `replace_data`,
`replace_path`, `replace_ranges`, `remove`, `rename` and `timestamp`. Omit both
or pass both as `None` for ordinary selection. Supply both for an exact match,
including `(0, 0)`. Partial or out-of-range selectors raise `ValueError`.
Numeric stream opens take a file number alone. Indexing and containment
retain ordinary selection.

Add operations create an absent filename using the locale/platform in
`FileCreateOptions`, without a selector. Replacement
selects an existing identity, retaining its tuple; storage options must match
that tuple and cannot redirect selection. Change the tuple explicitly with
`change_identity()`.

Physical compaction is an immediate transaction stage:

```python
update.compact()
update.compact(["voice", "left/data"])
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

`filenames=None` preserves the no-argument call. A finite iterable is
materialized once; scalar strings/bytes/path-like collections, None entries,
empty names and embedded NUL are rejected before native compaction.

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

```python
with mpq.Update.begin(path) as update:
    update.sign(private_key)  # weak by default
    update.sign(strong_key, mpq.SIGNATURE_STRONG)
    update.commit()
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

```python
result = entry.verify_result(mpq.VERIFY_ALL, filename="voice.bin")
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

```python
result = archive.verify_ex(mpq.VERIFY_METADATA_ALL)
```

`Archive.verify()` verifies digital signatures. `Archive.verify_ex()` verifies
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
`Archive.verify_ex()` defaults to `mpq.VERIFY_METADATA_ALL` (`0xFF00`),
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

Use `Writer.create_io(sink, ...)` with the same options as `Writer`.
The empty sink implements `write_at(offset, data)` and returns the exact
byte count. V4 and signing require `read_at(offset, size)` to return the
complete range. An optional `flush()` runs after successful finalization.
Backfills preserve unrelated bytes, unwritten gaps read as zeros, and
read-back sees previous writes immediately. Close the writer explicitly
or use `with`. The caller retains and closes the sink. Failed output may be partial. The writer provides
no atomic publication or durability guarantee. An oversized SINGLE still
buffers the complete input unit.

### Reporting a native callback status

Raise `mpq.LibmpqCallbackError(code)` from a source read, sink write or
read-back, or final flush to report a documented negative `mpq.ERROR_*`
code to libmpq. Ordinary exceptions map to `ERROR_READ`, `ERROR_WRITE`, or
`ERROR_CLOSE` according to the callback. Return the full requested bytes
from a read and the exact number written from a write. Short transfers
report the corresponding I/O error.

```python
def flush(self):
    if self.scratch_unavailable:
        raise mpq.LibmpqCallbackError(mpq.ERROR_MALLOC)
```

Libmpq latches the first output failure and skips flush after an earlier
failure. Higher-level native operations can translate a callback status
before returning it. Keep the caller-owned source available until dependent
archives and streams close, and the sink available through writer close.
Close consumes the writer even on failure. The caller closes its own storage.

### Writing MPQE to a caller-owned sink

Use `Writer.create_mpqe_io(sink, auth_code, ...)` with the same writer options.
For example, with a sink implementing `write_at` and optionally `flush`:

```python
with Writer.create_mpqe_io(sink, auth_code, version=ARCHIVE_VERSION_FOUR) as archive:
    archive.add_data("payload.bin", payload)
```

Close emits only MPQE transport. The private plaintext stage supplies read-back,
so the sink can be write-only even for v4. Keep the sink available through close.
The caller owns the storage and decides how to publish it. MPQE encoding does
not independently authenticate the archive.

### Fixed-size range replacement

An update can replace several plaintext ranges in one staged operation.
Offsets are zero-based and must fit inside the existing member. Later ranges
win when they overlap, and commit publishes the result.

```python
update.replace_ranges("member.bin", [(100, b"ABC"), (101, b"xy")])
update.replace_ranges("member.bin", [(4096, b"XYZ")], locale=1033, platform=0)
```

Supported lossless members retain encryption and storage policies; the native
writer rebuilds the selected member. SINGLE requires full-unit buffering.
