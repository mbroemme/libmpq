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

### Reading and writing

Use `packed_size` and `unpacked_size` for archive/file sizes and `file.read()`
for payload bytes. Decode text explicitly, for example
`file.read().decode("utf-8")`.

### Logical member streams

Use archive.open_stream(name) for incremental seekable member access. Streams
retain an independent native archive clone, so they remain usable after the
originating archive closes. Stream reads validate available sector Adler-32
checksums, but do not implicitly verify whole-file CRC32/MD5 attributes.

    with archive.open_stream("data/file.bin") as stream:
        chunk = stream.read(4096)
        stream.seek(0)

### Custom random-access I/O

Use `Archive.open_io(source, size, source_name=...)` for a caller-owned
seekable source such as `io.BytesIO`. The binding retains the source while
archives or derived streams are alive, but never closes it.

    archive = mpq.Archive.open_io(io.BytesIO(data), len(data), source_name="data.mpq")

## Archive creation

Use the same context-manager pattern for ordinary and MPQE writers:

```python
with mpq.Writer("created.mpq", version=mpq.ARCHIVE_VERSION_THREE) as writer:
    writer.add("payload.bin", b"payload", mpq.FileCreateOptions.raw())

with mpq.Writer.create_mpqe(
    "created.mpqe", b"LIBMPQ-MPQE-EXAMPLE-AUTH-CODE-01"
) as writer:
    writer.add("payload.bin", b"payload")
```

MPQE creation writes a private plaintext temporary file before atomically
replacing the destination with the encrypted archive. Use `Update.begin_mpqe`
to modify an existing MPQE archive. Cleanup is best effort if the process
crashes. The example authentication code is illustrative and non-secret; real
callers must provide their own authentication code of at least 32 bytes.

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

`archive["file.txt"].verify()` explicitly compares sector Adler-32 and file
CRC32/MD5. For one sector, `archive["file.txt"].verify_block(block_number)`
returns `(stored_adler32, mismatches)`. Mismatches is zero or
`VERIFY_SECTOR_CRC`; an unavailable checksum raises `LibmpqNotFoundError`
rather than reporting a match.

Use `VERIFY_SECTOR_CRC`, `VERIFY_FILE_CRC32`, `VERIFY_FILE_MD5`, or
`VERIFY_RAW_MD5` to select checks. Sector checks cover decrypted packed bytes;
file hashes cover extracted bytes. Missing values/tables are skipped. File checksum requests
require attributes; sector/raw-only requests do not. `VERIFY_ALL` selects all
checks. The returned mismatch mask uses the same `VERIFY_*` bits and is a
subset of the request. Set bits mean available checksums mismatched; clear
bits mean matched or unavailable/skipped. Operation errors raise existing
exceptions. Zero does not prove availability. Complete lossless reads
automatically compare available CRC32/MD5 values; lossy ADPCM is not compared
because decoded bytes may differ from source hashes.

`VERIFY_RAW_MD5` hashes v4 stored member chunks before file decryption or
decompression, after MPQE transport decoding. It is skipped for older versions,
disabled raw chunks and empty stored payloads. It checks physical patch members,
not reconstructed patch-view output.

`file.flags` contains the stored block-table flags. Inspect `FILE_FLAG_*`
bits; `encrypted`, `compressed`, and `imploded` are derived convenience
booleans.

`file.block_compression(block)` returns the stored method byte, or zero for
raw storage/fallback, without decoding. LZMA is `0x12`, not the writer selector.

`file.block_size_packed(block)` returns stored data bytes, excluding offset
and checksum tables. Use `file.block_size(block)` for the decoded size.

`Archive.attributes()` returns `None` when absent. `File.attributes()`
returns an owned `FileAttributes` result. Use `WriterFile.timestamp(filetime)`
before finishing a streaming file. Supply Windows FILETIME, not Unix time.

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

Transactional updates use a separate handle. Edits stay private until commit;
leaving the context without committing aborts them automatically:

```python
with mpq.Update.begin("archive.mpq") as update:
    update.replace_data("foo.txt", b"new contents")
    update.rename("old.txt", "new.txt")
    update.commit()
```

Use the same `Update` methods for MPQE after an authenticated begin:

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
and encryption/FIX_KEY; patch/delete flags are rejected. Inputs are borrowed
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

Linux release wheels contain a private native library at `mpq_libs/libmpq.so`. It
is loaded by its exact package path through `ctypes`, intentionally has no ELF
`DT_SONAME`, and does not require a separate system libmpq installation. The
release Python ZIP contains one sdist and all eight Linux/Windows/macOS
wheels as a supplementary GitHub Release download. The sdist contains the
canonical C and header sources and is free of native build products.

Windows wheels bundle `mpq_libs/libmpq.dll` and its required non-system
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

The result is an independently owned read-only Archive. Layers are ordered;
`Archive.open_patch(base, [])` creates an independent snapshot. A `None`
prefix list or entry requests inference; `""` selects the root namespace.
Explicit ordinary addition-only layers are accepted. Input wrappers and their
callback sources are needed only during the call and their normal input
lifetimes. Result clones and streams survive parent closure. Named modern
materialization still requires unambiguous filenames and metadata. Verify
physical signatures and raw checksums on the original input archives; these
checks do not establish trust in reconstructed content. Temporary storage is
cleaned up after the final dependent closes, with best-effort I/O cleanup.

### V4 raw-chunk policy

```python
with mpq.Writer("output.mpq", version=mpq.ARCHIVE_VERSION_FOUR) as writer:
    writer.raw_chunk_size = 17  # 0 disables trailing raw MD5
    assert writer.raw_chunk_size == 17
    writer.add("data.txt", b"content")
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
identities = archive.variants("dir/file.bin")
for identity in identities:
    print(identity.file_number, identity.flags, identity.locale, identity.platform)
number = archive.file_number_identity("dir/file.bin", locale=0x409, platform=1)
with archive.open_stream_identity("dir/file.bin", locale=0x409, platform=1) as stream:
    content = stream.read()
```

`variants()` returns a tuple of immutable `FileIdentity` records in native
classic slot order. Aliases can share a file number. `IDENTITY_CLASSIC` and
`IDENTITY_BET` flags describe stored provenance, not storage flags. BET-only
identities are unqualified `(0, 0)`; exact calls never fall back to another
locale/platform. Both selectors must be integers in `0..65535`. Ambiguous,
contradictory or reduced-hash layouts raise the existing format exception.
Ordinary lookup retains its existing behavior. Exact named streams supply
the encryption filename and own their native clone, so they survive parent
closure. Custom source ownership follows the existing stream contract.

Exact updates select one filename/locale/platform identity in the current
stage, without neutral fallback:

```python
with mpq.Update.begin(path) as update:
    update.replace_data_identity("voice.bin", 0x409, 1, b"replacement")
    update.rename_identity("voice.bin", 0x409, 1, "renamed.bin")
    update.replace_path_identity("renamed.bin", 0x409, 1, source_path)
    update.remove_identity("obsolete.bin", 0, 0)
    update.commit()
```

Classic-only archives detach the selected shared alias on replacement and
retain other aliases on removal or rename. Explicit replacement options must
match the selectors; omitted options use default storage with those selectors.
Mixed classic/HET/BET targets require consistent one-to-one mappings and
complete hashes. Unique HET/BET-only targets accept zero selectors only.
Unsupported or ambiguous metadata is rejected. A rejected operation preserves
the previous valid stage; commit/abort consume the transaction. Exact rebuilds
reject embedded archives and unsupported trailers, preserve source raw-chunk
policy, and do not change existing name-based operations.
