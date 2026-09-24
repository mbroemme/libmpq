# libmpq Python bindings

Transactional updates use a separate handle. Edits stay private until commit;
leaving the context without committing aborts them automatically:

```python
with mpq.Update.begin("archive.mpq") as update:
    update.replace_data("foo.txt", b"new contents")
    update.rename("old.txt", "new.txt")
    update.commit()
```

`replace_path`, `remove`, and explicit `abort` are also available. Commit and
abort consume the update handle even on error. Omitting replacement options
passes a native NULL options pointer, so libmpq uses defaults and preserves
the member's locale/platform identity. Supply `FileCreateOptions` as the
optional third argument for custom storage; its locale/platform must match
the existing member. MPQE and embedded archive modification remain
unsupported.

Weak MPQ signatures are supported with caller-supplied raw RSA-512 keys.
Strong verification uses a 512-byte raw public key: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
public exponent. Strong signing uses the same layout with the private exponent
and emits only the plain SHA-1 archive-range variant. External strong NGIS
signatures are not detected or verified for MPQE transport streams.
Use `Writer.sign(privateKey)` for weak signing or
`Writer.sign(privateKey, SIGNATURE_STRONG)` for strong signing before writer close, and
`Archive.signatures()` / `Archive.verify(publicKey)` on reopened archives.
Verification returns mismatch bits; malformed keys/archives raise normal binding
errors. Weak keys are exactly 128 bytes: 64-byte big-endian modulus followed by a
64-byte big-endian exponent. Signing supports v1 and v2; no keys are built
in. MD5/RSA-512 is legacy compatibility, not modern authenticity protection.
See [the format guide](../../MPQ.md) for details.

The `mpq` module provides Python 3.11+ ctypes bindings for libmpq, with
explicit archive and reader lifecycle management, typed native errors,
archive creation, cloning, metadata, block access, compression, encryption,
and streaming writes.

Use `packed_size` and `unpacked_size` for archive/file sizes and `file.read()`
for payload bytes. Decode text explicitly, for example
`file.read().decode("utf-8")`.

Use archive.open_stream(name) for incremental seekable member access. Streams
retain an independent native archive clone, so they remain usable after the
originating archive closes. Stream reads validate available sector Adler-32
checksums, but do not implicitly verify whole-file CRC32/MD5 attributes.

    with archive.open_stream("data/file.bin") as stream:
        chunk = stream.read(4096)
        stream.seek(0)

Use `Archive.open_io(source, size, source_name=...)` for a caller-owned
seekable source such as `io.BytesIO`. The binding retains the source while
archives or derived streams are alive, but never closes it.

    archive = mpq.Archive.open_io(io.BytesIO(data), len(data), source_name="data.mpq")

Creation defaults to `COMPRESSION_POLICY_STANDARD`. Pass
`flags=mpq.ARCHIVE_CREATE_COMPRESSION_EXTENDED` to `Writer` or
`Writer.create_mpqe` for additional, potentially less interoperable methods.
Use `mpq.archive_compression_allowed(version, mask, policy)` to query whether
a compression selection is allowed by the writer policy. Version uses
`ARCHIVE_VERSION_ONE` or `ARCHIVE_VERSION_TWO`. Readers remain permissive
regardless of the creation policy.

`COMPRESSION_SPARSE` selects lossless zero-run compression. In MPQ v2+,
STANDARD allows the fixed SPARSE forms: alone (`0x20`), with
`COMPRESSION_ZLIB` (`0x22`), or with `COMPRESSION_BZIP2` (`0x30`). MPQ v1
retains normal compression-mask semantics under either policy, allowing
other valid combinations such as SPARSE with Huffman (`0x21`) or PKWARE
(`0x28`). In MPQ v2+, EXTENDED permits the broader valid lossless SPARSE
combinations. Neither policy allows SPARSE with WAVE ADPCM. The shared
`sparse*.txt` fixtures use UTF-32LE with a BOM; `.read()` returns bytes,
which can be decoded with `.decode("utf-32")`.

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

For source-tree development, set `LIBMPQ_LIBRARY` to an absolute
shared-library path, or build libmpq in the source tree and let the
development fallback locate `src/.libs/libmpq.so`.

```sh
./configure
make
LIBMPQ_LIBRARY="$PWD/src/.libs/libmpq.so" python -m pytest bindings/python/tests
```

Linux release wheels target `manylinux_2_17_x86_64`,
`manylinux_2_17_aarch64`, `musllinux_1_2_x86_64`, and
`musllinux_1_2_aarch64`. Each is built and tested natively using CPython 3.11.
Windows release wheels target `win_amd64` and `win_arm64`, also built and
tested natively using CPython 3.11. macOS wheels target `macosx_11_0_x86_64`
and `macosx_11_0_arm64`, with native Intel and Apple Silicon builds. All
eight wheels use the `py3-none` ABI.

Linux release wheels contain a private native library at `mpq_libs/libmpq.so`. It
is loaded by its exact package path through `ctypes`, intentionally has no ELF
`DT_SONAME`, and does not require a separate system libmpq installation. The
release Python ZIP contains one sdist and all eight Linux/Windows/macOS
wheels as a supplementary GitHub Release download. The sdist contains the
canonical C and header sources and is free of native build products.

Windows wheels bundle `mpq_libs/libmpq.dll` and its required non-system
runtime DLLs, so no separately installed libmpq SDK is needed. The release
build reuses MSVC/CMake and architecture-matched vcpkg dependencies, then
delvewheel repairs the wheel using existing-DLL analysis and a custom patch
before `ctypes` loads the library. Installed-wheel tests run with vcpkg and
native build directories excluded from `PATH`. Local Windows wheel builds
must set `LIBMPQ_LIBRARY` to a prebuilt shared CMake DLL; the backend does
not compile Windows sources itself.

macOS wheels contain `mpq_libs/libmpq.dylib` and any required non-system
dylibs bundled by delocate. No separately installed libmpq SDK is needed.
Both architectures retain the native SDK's macOS 11.0 deployment baseline;
there is no universal2 wheel. The release build uses the Apple toolchain
with Autotools and passes the installed dylib through `LIBMPQ_LIBRARY`.
It uses system zlib, bzip2, and liblzma, with Homebrew xz supplying only
headers. Repaired wheels are checked for architecture, deployment target,
and relocatable runtime paths, then tested with native Python and no
build overrides or Homebrew library search paths.

Typical usage is explicitly closeable and safe with context managers:

```python
import mpq

with mpq.Archive("data.mpq", offset=0) as archive:
    entry = archive["readme.txt"]
    print(entry.read())

with mpq.Writer("created.mpq", version=mpq.ARCHIVE_VERSION_TWO) as writer:
    writer.add("payload.bin", b"payload", mpq.FileCreateOptions.raw())

with mpq.Writer.create_mpqe(
    "created.mpqe", b"LIBMPQ-MPQE-EXAMPLE-AUTH-CODE-01"
) as writer:
    writer.add("payload.bin", b"payload")
```

MPQE creation writes a private plaintext temporary file before atomically
replacing the destination with the encrypted archive. It cannot modify an
existing MPQE archive; cleanup is best effort if the process crashes. The
example authentication code is illustrative and non-secret; real callers must
provide their own authentication code of at least 32 bytes.

Native failures raise `LibmpqError` subclasses with `.code` and `.message`
attributes. I/O and missing-file subclasses remain compatible with the
corresponding Python built-in exception categories.

## Optional attributes

Set `FILE_FLAG_SECTOR_CRC` in file options alongside COMPRESS or IMPLODE
to generate sector Adler-32 tables, including for encrypted files. Empty,
raw, and single-unit files ignore this flag. Generation is opt-in and
complete reads automatically verify usable sector entries.

`archive["file.txt"].verify()` explicitly compares sector Adler-32 and file
CRC32/MD5. For one sector, `archive["file.txt"].verify_block(block_number)`
returns `(stored_adler32, mismatches)`. Mismatches is zero or
`VERIFY_SECTOR_CRC`; an unavailable checksum raises `LibmpqNotFoundError`
rather than reporting a match.

Use `VERIFY_SECTOR_CRC`, `VERIFY_FILE_CRC32`, or `VERIFY_FILE_MD5` to select
checks. Sector checks cover decrypted packed bytes; file hashes cover
extracted bytes. Missing values/tables are skipped. File checksum requests
require attributes; sector-only requests do not. `VERIFY_ALL` selects all
checks. The returned mismatch mask uses the same `VERIFY_*` bits and is a
subset of the request. Set bits mean available checksums mismatched; clear
bits mean matched or unavailable/skipped. Operation errors raise existing
exceptions. Zero does not prove availability. Complete lossless reads
automatically compare available CRC32/MD5 values; lossy ADPCM is not compared
because decoded bytes may differ from source hashes.

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
for both MPQ v1 and v2, including MPQE creation. Payload version 100 is
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

`Archive.signatures()` reports weak MD5/RSA-512 internal signatures and strong
SHA-1/RSA-2048 external `NGIS` trailers. `Archive.verify(key)` remains the
weak convenience form. Pass `signature_type=SIGNATURE_STRONG` and a 512-byte
raw public key for strong verification. Strong signatures are legacy
compatibility data. `Writer.sign(key, SIGNATURE_STRONG)` creates the
plain SHA-1 archive-range strong variant from a 512-byte raw private key.
