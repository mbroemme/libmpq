# MPQ archive format guide

MPQ (Mo'PaQ, "Mike O'Brien Pack") is a little-endian random-access archive
format used by Blizzard games. This document is a practical starting point for
implementing a reader or writer from scratch.

This is not a normative Blizzard specification. Game families contain format
variations, so validate every offset, size, count, and arithmetic operation
before using it.

## Conventions and archive location

All multi-byte values are unsigned little-endian unless stated otherwise.
Structure offsets are relative to the MPQ header, not necessarily the
containing file. The header signature is `MPQ\x1A`.

An archive can be embedded after a stub or a user-data block and commonly
starts on a 512-byte boundary. An optional `MPQ\x1B` user-data header precedes
the real header and contains a user-data size and header offset. Locate and
validate the actual `MPQ\x1A` header before resolving archive-relative values.
Table placement is not fixed; do not infer it from file order.

## MPQE-wrapped streams

Some installer archives encrypt the complete outer byte stream in 64-byte MPQE
chunks before the usual `MPQ\x1A` header. MPQE is a stream provider, not a
new MPQ header version: decrypt it first, then parse the contained MPQ using
the normal header and table rules. The chunk transform depends on a
caller-supplied authentication code and the absolute chunk position. Keep
authentication-code provisioning outside archive parsing; libmpq's C API does
not embed, discover, log, or persist such codes. A missing or too-short code
buffer is rejected as a decryption error. MPQE has no authentication check, so
a well-formed but incorrect code is parsed as ordinary invalid MPQ data and
can produce a format or another parser error.

## Header versions

The common 32-byte prefix is:

| Offset | Field | Meaning |
| --- | --- | --- |
| `00` | `char[4]` | Signature `MPQ\x1A` |
| `04` | `u32` | Header size |
| `08` | `u32` | Legacy archive size |
| `0C` | `u16` | Format version: 0 through 3 |
| `0E` | `u16` | Sector shift; sector size is `512 << shift` |
| `10` | `u32` | Low hash-table position |
| `14` | `u32` | Low block-table position |
| `18` | `u32` | Hash-table capacity (power of two) |
| `1C` | `u32` | Classic block-table entry count |

| MPQ | Version | Header size | Additional fields |
| --- | ---: | ---: | --- |
| v1 | 0 | `0x20` | Common prefix |
| v2 | 1 | `0x2C` | Hi-block table position; high 16 bits of classic table positions |
| v3 | 2 | `0x44` | 64-bit archive size; BET and HET positions |
| v4 | 3 | `0xD0` | 64-bit table sizes, raw-chunk size, table and header MD5 digests |

For v2 combine a classic table position as `(high16 << 32) | low32`. The
hi-block table is a `u16` array indexed by classic block index and supplies
bits 32-47 of file positions. v4 records raw-table MD5 values; verify them
only after normal structural bounds checks.

## Classic tables

Classic hash and block tables are encrypted streams of 32-bit words. Decrypt
the hash table with `HashString("(hash table)", FILE_KEY)` and the block table
with `HashString("(block table)", FILE_KEY)` before parsing.

Each 16-byte hash entry contains `u32 name_hash_a`, `u32 name_hash_b`, `u16
locale`, `u16 platform`, and `u32 block_index`. `0xffffffff` means never used;
`0xfffffffe` means deleted. Lookup uses open addressing: initial slot is
`HashString(path, TABLE_OFFSET) & (capacity - 1)`, followed by linear probing.
An empty entry stops lookup; a deleted entry does not. A file is identified by
path, locale, and platform, although zero is the usual default for both.

Each 16-byte block entry contains `u32 file_pos`, `u32 compressed_size`, `u32
file_size`, and `u32 flags`. Common flags are `0x80000000` exists,
`0x01000000` single unit, `0x00010000` encrypted, `0x00020000` adjusted key,
`0x00000200` compressed, and `0x00000100` PKWARE-imploded. Later games add
sector-CRC, patch, deletion, and signature flags; preserve unknown flags when
rewriting an archive.

## File sectors, encryption, and compression

Unless marked single-unit, a file has `ceil(file_size / sector_size)` sectors.
A compressed or imploded multi-sector file starts with `u32[sector_count + 1]`
offsets relative to its payload. The final value is the stored-data end. Raw
multi-sector files usually omit the table because their offsets are calculable.
Require monotonic, in-range offsets before reading a sector.

For an encrypted file, hash the basename, not its directory, with the file-key
hash. If the adjusted-key flag is set, use `(base_key + file_pos) ^ file_size`.
Decrypt the offset table with `key - 1` and sector *i* with `key + i`.
Encryption processes little-endian 32-bit words; use explicit `uint32_t`
wraparound. A filename is normally required to decrypt file data.

A multi-compressed sector starts with a method/mask byte. Reverse the selected
transforms when decoding; a sector may instead be stored raw when compression
loses. The table lists every codec, all MPQ v2+ STANDARD combinations, and
additional SPARSE combinations covered by libmpq tests. Combined masks are
codec chains, not separate codecs; `+` below does not specify decoding order.

The policy columns apply to MPQ v2+ writing. STANDARD is the default,
interoperability-oriented policy. EXTENDED permits additional valid
libmpq-supported compression forms that other MPQ implementations may not
accept. Neither policy restricts decoding.

| Method/mask | Codec or combination | STANDARD | EXTENDED |
| ---: | --- | :---: | :---: |
| `0x01` | Blizzard Huffman | - | X |
| `0x02` | zlib deflate | X | X |
| `0x08` | PKWARE DCL implode | X | X |
| `0x10` | bzip2 | X | X |
| `0x12` | LZMA (exclusive method) | X | X |
| `0x20` | SPARSE lossless zero-run transform | X | X |
| `0x21` | SPARSE + Huffman | - | X |
| `0x22` | SPARSE + zlib | X | X |
| `0x28` | SPARSE + PKWARE | - | X |
| `0x30` | SPARSE + bzip2 | X | X |
| `0x40` | IMA ADPCM mono | - | X |
| `0x41` | Huffman + IMA ADPCM mono | X | X |
| `0x80` | IMA ADPCM stereo | - | X |
| `0x81` | Huffman + IMA ADPCM stereo | X | X |

MPQ v1 permits ordinary masks under either policy, including the combinations
above except LZMA: `0x12` means bzip2 + zlib in v1. Other combinations are
formed by OR-ing stage bits, subject to the rules below; the table is not an
exhaustive list of every possible mask. Neither policy allows unknown bits,
both ADPCM channel bits together, or SPARSE with ADPCM. MPQ v2+ additionally
rejects writer masks containing both zlib and bzip2. Input-specific WAVE and
file-storage constraints still apply.

Raw storage has no method byte; `libmpq__block_compression()` reports zero for
it. Standalone IMPLODE storage also has no method byte; that API reports
`0x08` for an actually imploded block and zero for its raw fallback.

For MPQ v1, `0x12` retains its legacy BZIP2 + zlib chain meaning. For MPQ v2+,
it is LZMA and its payload is `useFilter` zero, five LZMA1 property bytes, an
advisory little-endian 64-bit original size, and raw LZMA1 data normally
without an end marker. StormLib normally writes those no-EOPM streams; libmpq
writes LZMA1 streams with an EOPM and accepts both forms when reading. libmpq
also rejects LZMA properties that require more than 64 MiB of decoder memory.
Bound every decoder by the expected unpacked sector length.

Writer compatibility is separate from permissive decoder support. STANDARD is
the default and, in MPQ v2+, follows the fixed method set: `0x02`, `0x08`,
`0x10`, `0x12`, `0x20`, `0x22`, `0x30`, `0x41`, and `0x81`. Its fixed SPARSE
forms are alone (`0x20`), with zlib (`0x22`), and with bzip2 (`0x30`). MPQ v1
retains normal compression-mask semantics under either policy, allowing other
valid combinations such as SPARSE with Huffman (`0x21`) or PKWARE (`0x28`). In
MPQ v2+, EXTENDED permits the broader valid lossless SPARSE combinations and
standalone Huffman; these may be less interoperable with other readers.
Neither policy permits v2 chains containing both zlib and bzip2, since stage
omission could emit reserved method `0x12`. The reader has no compatibility
setting and is unchanged.

SPARSE is a lossless zero-run stage applied before other compression stages
and decoded last. Its payload starts with a four-byte **big-endian** unpacked
length, unlike MPQ header/table fields. Tokens `0x00..0x7f` emit 3..130 zeros;
tokens `0x80..0xff` copy 1..128 literal bytes. The outer method byte includes
`0x20`, for example `0x22` with zlib or `0x30` with bzip2. Other combinations
follow the version and policy rules above.

The decoder checks the declared length against caller-owned output storage
without allocating from that length. Oversized final tokens are clipped to
the remaining declared output for Storm-style streams; all required literal
bytes must exist. Missing output, truncated literals, and trailing input
are rejected. The writer emits exact token lengths and retains SPARSE only
when it reduces the stage size. Both writer policies reject SPARSE with
either WAVE ADPCM bit: ADPCM would lossily transform the SPARSE control stream.

## Hashing and the table cipher

The traditional algorithm builds a 0x500-word crypt table from seed
`0x00100001`. Hashing starts with `0x7fed7fed` and `0xeeeeeeee`, uppercases
input bytes, and uses crypt-table pages for table offset, name A, name B, and
file key. The cipher uses page four and evolves a key and seed per word.
Implement it with fixed-width unsigned arithmetic, never native `long`, and
test known hash/table-key/cipher vectors.

## v3/v4 HET and BET tables

HET (`HET\x1A`) and BET (`BET\x1A`) provide compact, bit-packed replacements
for classic lookup and file metadata. Their common prefix is signature,
version, and contained-data size. HET maps a Jenkins-style 64-bit filename
hash to a BET index using a bitmap/index table and reduced hash bits. BET
stores reduced name hashes plus bit fields for position, unpacked size, packed
size, flag-array index, and an unknown field.

Implement these with a checked bit reader, not C bitfields. The HET/BET headers
declare each field's bit offset and width; reject ranges beyond the record or
table, and require their entry counts to agree. Modern archives can carry
classic tables too, so retain both paths. StormLib's `TMPQHetHeader` and
`TMPQBetHeader` are the public field map to use with v3/v4 fixtures.

## Internal files and integrity data

`(listfile)` is optional text metadata containing names separated by CR/LF or
semicolons; it is not a complete inventory. `(attributes)` can hold parallel
per-block CRC32, Windows FILETIME, MD5, and patch-bit arrays. Its payload
version is 100, independent of the MPQ archive version; it is valid in v1 too.
The little-endian header contains a 32-bit version and flags. Flags 1, 2,
4, and 8 select CRC32 (LE32), FILETIME (LE64), MD5 (16 bytes), and patch bits,
in that order. Rows use physical block-table indices, including unused slots,
not the public compact file numbering. Patch bits are most-significant-bit
first within each byte.

libmpq loads this optional file lazily through normal file decoding. Absence
returns EXIST; malformed metadata returns FORMAT when explicitly queried, while
ordinary extraction skips unusable optional metadata. The reader accepts full
arrays and recognized legacy layouts:
one-entry-short arrays, omitted self patch bits, missing patch arrays, and
all-zero legacy DWORD patch regions. Unavailable rows/patch values have their
availability flags cleared rather than inventing checksum values. Unknown
versions/flags and other payload sizes are rejected when queried.

Creation is opt-in with `LIBMPQ_ATTRIBUTE_*` bits in `options.attributes`.
The native creation-options structure is 20 bytes: `version`, `max_files`,
`sector_size`, `flags`, and `attributes` occupy offsets 0, 4, 8, 12, and 16.
The native per-file result is 40 bytes: `flags`, `crc32`, `filetime`, `md5`,
and `patch_bit` begin at offsets 0, 4, 8, 16, and 32. Explicit `reserved[4]`
bytes at offset 36 are always returned as zero. These naturally aligned,
host-endian API structures are separate from the little-endian disk payload.

Zero disables generation; any nonzero combination creates one `(attributes)`
file and consumes one reserved slot. Unknown attribute bits are rejected. The
separate `options.flags` field still selects listfile and compression policy.
CRC32 and MD5 cover source bytes before compression, including lossy ADPCM,
not stored ciphertext. FILETIME defaults to zero and is set explicitly on a
file writer; filesystem timestamps are never imported. Finalization adds the
listfile, then attributes, then serializes the final tables. Unused rows and
the attributes entry itself are zero. Patch-bit creation emits zeros only and
does not create or apply patches. Checksums are metadata, not cryptographic
authentication. Complete lossless file reads automatically compare available
CRC32 and MD5 values against decoded contents; FILETIME and PATCH_BIT remain
metadata only. Lossy ADPCM decoded bytes can differ from source-byte metadata,
so those members are not automatically compared. Complete file reads also
verify available sector Adler-32 values over decrypted packed sectors before
decoding, including ADPCM. Unusable optional sector tables are skipped during
ordinary extraction.

`libmpq__file_verify()` explicitly compares sector checksums and file CRC32/MD5.
MPQ sector CRCs are Adler-32 checksums over decrypted packed sectors, before
decompression. Their optional table follows the sectors, may be compressed,
and is not encrypted. Zero and all-ones entries are unavailable and skipped;
single-unit files have no sector checksum table. `LIBMPQ_VERIFY_SECTOR_CRC`
requests only this check and does not require `(attributes)`. Complete reads
automatically check usable entries, while explicit verification continues to
report table errors and per-check mismatches.

The writer generates these tables when `LIBMPQ_FILE_FLAG_SECTOR_CRC` is
requested for sectorized COMPRESS or IMPLODE files. It checksums packed bytes
before encryption and appends one LE32 value per sector. The extra offset
points past the checksum table. The table is never encrypted and uses zlib
only when this reduces its size. Empty, raw, and single-unit files ignore the
flag. Ordinary writing without this flag and normal extraction are unchanged.

File CRC32/MD5 cover complete extracted contents. These requests require
`(attributes)`; unavailable requested row values are skipped.
`LIBMPQ_VERIFY_ALL` requests sector checks and both file checks. The mismatch
mask uses the same bits and is a subset of the request: set means available
and mismatched, while clear means matched or unavailable/skipped. Negative
operation errors leave the result zero; mismatch bits are published only after
complete success. Zero bits do not establish checksum availability. Lossy
ADPCM can legitimately differ from the writer's source-byte checksums.
FILETIME and PATCH_BIT are not verified, and normal extraction is unchanged.

For v1 creation with attributes enabled, a 16-byte gap separates the header
and hash table. This avoids StormLib's malformed-map heuristic, which skips
attributes when a table begins exactly at the end of the v1 header. Writers
without attributes retain their existing layout.

Weak `(signature)` files contain exactly 72 uncompressed, unencrypted bytes:
eight zero bytes followed by a little-endian RSA-512 signature integer.
libmpq hashes from the archive offset through the v1 declared archive size or
the v2 metadata-derived required extent, treating all 72 signature bytes as
zero, and checks the complete PKCS#1 v1.5 MD5 DigestInfo encoding. Bytes before
or after that MPQ range are not hashed. For archives physically beginning with
`HM3W`, weak and strong signature hashing starts at physical offset zero and
ends at the logical MPQ end; weak hashing still excludes the internal
`(signature)` file.

For MPQ v2 archives, libmpq derives the weak-signature extent from the parsed
64-bit archive structures rather than using the deprecated 32-bit
`dwArchiveSize` field as the authoritative archive boundary.

`libmpq__archive_signatures` returns `LIBMPQ_SIGNATURE_WEAK` for an internal
weak signature and `LIBMPQ_SIGNATURE_STRONG` for an external strong trailer.
It reports structure, not cryptographic validity. Strong trailers are `NGIS`
followed by a 256-byte RSA-2048 value immediately after the logical MPQ range.
`libmpq__archive_verify` accepts one signature type at a time because weak and
strong public keys have different sizes. Strong verification accepts SHA-1 of
the archive range, the range plus uppercase archive basename, or the range plus
`ARCHIVE`. For an `HM3W` wrapper, both signature hashes start at physical
offset zero and still end at the logical MPQ end.

Weak signatures use MD5/RSA-512 and support creation and verification. Strong
signatures use SHA-1/RSA-2048 and support creation and verification. The writer
currently emits only the plain SHA-1 archive-range variant; basename and
`ARCHIVE` variants are accepted during verification only. Both are legacy
compatibility mechanisms, not modern cryptographic trust primitives.

External strong `NGIS` signatures are not detected or verified for MPQE
transport streams because MPQE encrypts the complete transport and no external
strong-trailer representation is defined.

Weak public and private keys are exactly 128 bytes: a 64-byte unsigned big-endian
modulus followed by a 64-byte zero-padded unsigned big-endian exponent value.
Use a public key to verify a
signature and a private key to create one. The modulus must be full-width and
odd; the exponent must be odd, at least 3, and less than the modulus. These
checks validate representation,
not the mathematical validity of the caller's RSA key pair. No PEM,
certificates, ASN.1 parser, default public key, or private key is built in.

Strong public and private keys are exactly 512 bytes: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
exponent. Use the public exponent for verification and the private exponent
for creation. The writer emits only the plain SHA-1 archive-range variant.

On a new v1 or v2 writer, call `libmpq__archive_sign` once for each requested
signature type before closing, with no active file writer. It copies the private
key. Weak signing reserves one file-table slot and a zero signature payload
immediately. Close finalizes listfile, attributes, tables, and header before
hashing, overwriting the weak signature bytes, then appending any strong trailer.
The signature entry's generated attribute values remain zero; retained keys are
cleared on close, including error paths. Other files may be added after
configuring signing. Readers do not impose the writer's version restriction.

MD5 and RSA-512 are obsolete and unsuitable for modern authentication. The
private fixed-width RSA code is deliberately limited to this legacy format,
not a general-purpose hardened cryptographic service. Strong verification
also uses historical cryptography. Never treat a matching signature as
a substitute for range validation.

## Implementation order

1. Locate and range-check the header with checked 64-bit arithmetic.
2. Implement v1 classic lookup and raw/single-unit file reading.
3. Add table and sector encryption with known-name vectors.
4. Add codecs incrementally with bounded output.
5. Add v2 high offsets, then v3/v4 HET/BET and MD5 validation.
6. Test collisions, deleted entries, embedded headers, mixed sectors, every
   codec, high offsets, malformed tables, and integer-overflow boundaries.
