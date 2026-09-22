# libmpq Java bindings

Weak MPQ signatures are supported with caller-supplied raw RSA-512 keys.
Strong verification uses a 512-byte raw public key: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
public exponent. Strong signing uses the same layout with the private exponent
and emits only the plain SHA-1 archive-range variant. External strong NGIS
signatures are not detected or verified for MPQE transport streams.
Use `Archive.sign(privateKey)` for weak signing or
`Archive.sign(SIGNATURE_STRONG, privateKey)` for strong signing before writer close, and
`Archive.signatures()` / `Archive.verify(publicKey)` on reopened archives.
Verification returns mismatch bits; malformed keys/archives raise normal binding
errors. Weak keys are exactly 128 bytes: 64-byte big-endian modulus followed by a
64-byte big-endian exponent. Signing supports v1 and v2; no keys are built
in. MD5/RSA-512 is legacy compatibility, not modern authenticity protection.
See [the format guide](../../MPQ.md) for details.

These bindings use the Java Foreign Function and Memory API and require JDK
22 or newer. They provide a complete mapping of libmpq's stable public C API
through `org.libmpq.ffi.LibmpqNative` and safer `AutoCloseable` wrappers in
`org.libmpq`.

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
  <version>0.8.0</version>
</dependency>
```

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

The GitHub Release Java ZIP is a supplementary download containing the
runtime, sources, and Javadoc JARs together with `COPYING`, `COPYING.LESSER`,
and this README. Release validation also builds an external consumer using
only the packaged runtime JAR and tests both native-library loading modes.

The high-level API uses `Archive.open`, `Archive.openMpqe`, `Archive.create`,
`Archive.createMpqe`, and `MpqFileWriter`. MPQE creation uses a private
plaintext temporary file before atomically replacing the destination; it
cannot modify an existing MPQE archive and crash cleanup is best effort. All
negative libmpq return codes are reported as `LibmpqException` values
containing the original code and diagnostic text.

## Optional attributes

Set `Mpq.FILE_FLAG_SECTOR_CRC` in file options alongside COMPRESS or IMPLODE
to generate sector Adler-32 tables, including for encrypted files. Empty,
raw, and single-unit files ignore this flag. Generation is opt-in and
verification remains explicit.

`archive.verify(fileNumber)` explicitly compares sector Adler-32 and file
CRC32/MD5. For one sector, `archive.verifyBlock(fileNumber, blockNumber)`
returns `Archive.BlockVerification` with `checksum()` (unsigned stored
Adler-32 as `long`) and `mismatches()` (zero or `Mpq.VERIFY_SECTOR_CRC`).
Unavailable checksums throw `LibmpqException` with `Mpq.ERROR_EXIST`.

Use `Mpq.VERIFY_SECTOR_CRC`, `Mpq.VERIFY_FILE_CRC32`, or
`Mpq.VERIFY_FILE_MD5` to select checks. Sector checks cover decrypted packed
bytes; file hashes cover extracted bytes. Missing values/tables are skipped.
File checksum requests require attributes; sector-only requests do not.
`Mpq.VERIFY_ALL` selects all checks. The returned mismatch mask uses the same
`Mpq.VERIFY_*` bits and is a subset of the request. Set bits mean available
checksums mismatched; clear bits mean matched or unavailable/skipped.
Operation errors throw existing exceptions. Zero does not prove availability.
Complete lossless reads automatically compare available CRC32/MD5 values;
lossy ADPCM is not compared because decoded bytes may differ from source hashes.

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
work for both MPQ v1 and v2, including MPQE creation. Payload version 100 is
independent of the archive format version.

Per-file flags distinguish unavailable fields from zero. Complete lossless
reads automatically verify available CRC32 and MD5 metadata against decoded
bytes; malformed optional metadata is skipped during extraction but still
raises the existing format exception when queried. CRC32 and MD5 cover source
bytes before compression, so lossy ADPCM is not automatically compared.
FILETIME defaults to zero, never filesystem mtime, and PATCH_BIT remains
metadata only. Sector Adler-32 verification remains explicit.

`Archive.signatures()` reports weak MD5/RSA-512 internal signatures and strong
SHA-1/RSA-2048 external `NGIS` trailers. `Archive.verify(byte[])` remains the
weak convenience overload; `verify(int, byte[])` accepts `SIGNATURE_STRONG`
and a 512-byte raw public key. Strong signatures are legacy compatibility data.
`Archive.sign(SIGNATURE_STRONG, key)` creates the plain SHA-1 archive-range
strong variant from a 512-byte raw private key.
