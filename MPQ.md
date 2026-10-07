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

## Patch namespace paths

A patch layer can store a physical member such as `Base\Foo` below a `Base\`
prefix. Removing that prefix gives the logical identity `Foo` used to match
the base archive and other layers. A `(patch_metadata)` path is a namespace
marker, not a rich metadata structure: if its plaintext path is available,
typically through `(listfile)`, the directory portion can identify the prefix.
When only irreversible MPQ filename hashes are available, a prefix cannot be
inferred generically from them.

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

The reader supports MPQ v3 (on-disk version 2) through classic hash/block
tables. Its normal `0x44`-byte header adds three little-endian `u64` fields
after the v2 extension: archive size at `0x2C`, BET position at `0x34`, and
HET position at `0x3C`. The 64-bit size is authoritative, including when the
legacy size differs. Classic high table/file offsets retain the v2 layout.

For compatibility, a base-only `0x20`-byte v3 header or a declared header
from `0x2C` through `0x43` uses the legacy archive size and absent/zero HET/BET
positions; no partial extension is read. Rejecting partial v2 extensions
(`0x21` through `0x2B`) is an intentional libmpq validation choice rather
than accepting arbitrary short sizes for StormLib compatibility. A declared
full header must contain all `0x44` bytes. HET/BET
positions are bounded by the archive extent but those tables are not decoded.
Mixed-table archives can use classic lookup when a classic hash entry maps
to a live block; other live blocks need not be hash-referenced. This does not
assert equivalence with HET/BET, whose lookup remains unavailable. Archives
requiring HET/BET because classic lookup is absent or unusable fail with a
format error. Compressed classic tables, HET/BET lookup, v3 creation and
rebuilding, and MPQ v4 remain outside the current implementation.

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

Internally, decoded classic rows populate archive-owned `mpq_entry_s` metadata
with 64-bit positions and sizes. Public file numbers map to these entries;
reader, stream, metadata, and verification paths consume them rather than the
classic block table. Classic hash rows translate through an explicit
classic-row-to-entry mapping; canonical entry ordering is independent.
Source provenance distinguishes classic rows from uninitialized entries.
Classic attributes remain indexed and sized by block-table rows, not canonical
entries. Writers and rebuild serialization still own classic wire
tables. Isolated BET decoding also produces canonical entries with explicit
BET provenance, but archive loading does not yet populate them. Sector offset
and codec-length limits remain unchanged.

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

Private structural decoders and HET candidate lookup accept already-decrypted/
decompressed table bytes. They are not connected to archive opening: normal
filename lookup still uses classic tables. In-memory HET/BET lookup and BET
conversion into canonical `mpq_entry_s` entries are implemented internally.
MPQ v4 remains unsupported.
Future loading must retain the plaintext common
envelope and decrypt/decompress its contained data before structural decoding.

The common envelope is three little-endian DWORDs: signature at byte 0,
version at byte 4 (supported value 1), and `data_size` at byte 8. `data_size`
excludes this 12-byte envelope but includes the table-specific header and
arrays. A valid HET or BET requires table-specific `dwTableSize` to equal
`ExtHdr.dwDataSize` (`table_size == envelope.data_size`); both exclude the
12-byte common envelope. Declared data must fit the supplied buffer; bytes
beyond the declared payload are not interpreted as table data. The parsers
allocate nothing and report byte ranges relative to the beginning of the
complete decoded envelope.

The HET-specific header contains eight DWORDs, in wire order:

```text
table_size, entry_count, total_count, name_hash_bit_size,
index_size_total, index_size_extra, index_size, index_table_size
```

Its 32-byte header is followed by `total_count` one-byte NameHash1 slots, then
the declared index array. Name hashes have 8..64 bits; only their high byte is
stored here. Occupied count cannot exceed total count. Index widths are at
most 64 bits, effective and extra widths must fit the total, and nonempty slot
tables require a nonzero effective width. The index array storage must be
exactly `ceil(total_count * index_size_total / 8)` bytes, with no padding.
Header, slots, and declared index storage must account for `table_size`
exactly.

The BET-specific header contains nineteen DWORDs (76 bytes), in wire order:

```text
table_size, entry_count, unknown, table_entry_size,
bit_index_file_position, bit_index_file_size, bit_index_compressed_size,
bit_index_flag_index, bit_index_unknown,
bit_count_file_position, bit_count_file_size, bit_count_compressed_size,
bit_count_flag_index, bit_count_unknown,
name_hash2_total, name_hash2_extra, name_hash2_size,
name_hash_array_size, flag_count
```

The header is followed by `flag_count` little-endian DWORD flags, packed file
records, then packed NameHash2 values. Reserved fields are preserved rather
than interpreted. Each record field is at most 64 bits, fits its nonzero
record width, and cannot overlap another nonempty field. The flag index is
at most 32 bits and must be wide enough to address the flags array; actual
index values remain for later entry decoding to validate. NameHash2 effective
and extra widths must fit its total (at most 64 bits). Nonempty file tables
require flags and a nonzero effective hash width. Checked, rounded-up record
and hash storage must fit. NameHash2 storage must be exactly
`ceil(entry_count * name_hash2_total / 8)` bytes, with no padding, and all
declared arrays must account for the table size exactly. HET/BET counts are
not compared by these independent parsers.

Bit zero is the low bit of byte zero. Fields proceed from low to high bits
within a byte and then into the next byte; the first field bit is the value's
least significant bit, independently of host endianness. Checked bit helpers
support 0..64-bit reads/writes across byte boundaries, preserve surrounding
bits on writes, and reject overflow, overruns, and values exceeding the given
width. Zero-width reads produce zero; zero-width writes accept only zero.
Multiplication and conversion to byte storage are checked without overflowing
the rounding operation. No C bitfields or unaligned integer casts are used.

### Internal HET filename lookup

HET uses Jenkins `hashlittle2`, not the classic Storm filename hash. Normalize
the first at most 264 filename bytes by converting ASCII `A`..`Z` to lowercase
and `/` to `\`; all other bytes, including bytes above `0x7F`, are unchanged.
Normalization is locale-independent. An empty filename has a defined hash;
NULL is rejected by the private helper. The two lookup3 seeds are 2 for the
low result and 1 for the high result. Combine the outputs as
`(high << 32) | low`, using explicit little-endian byte loads.

For declared hash width `N` (8..64), retain the low `N` bits and force bit
`N - 1` to one. This adjusted hash determines all three lookup values:

```text
NameHash1    = hash >> (N - 8)           # high eight retained bits
NameHash2    = hash & ((1 << (N-8)) - 1) # remaining low bits
initial slot = hash % total_count
```

The private partition helper handles full-width masks without a shift by 64.
The table view borrows validated NameHash1 and packed-index arrays; the caller
must keep the decoded buffer alive and immutable. A zero-slot header may be
structurally decoded, but cannot initialize a lookup view.

Probe successive slots, wrapping to zero, for at most `total_count` visits.
NameHash1 zero terminates a missing lookup. Nonzero values must have their
high bit set. In particular, `0x80` must not be treated unconditionally as
empty or deleted: it is also a possible valid NameHash1. The caller can reject
deleted candidates while confirming their hashes. A full table never causes
an unbounded probe loop.

On a NameHash1 match, read `index_size` low bits starting at
`slot * index_size_total`. Extra bits belong to the high end of the slot's
stride and are not part of the BET index; they do not shift its start.
Extraction uses checked bit access and returns a 64-bit index without
truncation. Lookup checks candidates against the caller's BET entry count.

NameHash1 alone is insufficient to identify a filename. The private lookup
therefore requires a caller-supplied matcher that confirms the candidate's
NameHash2, continuing on hash collisions and propagating matcher errors.
The BET matcher decodes the candidate's NameHash2; normal archive opening
and public filename lookup remain unchanged.

### Internal BET record decoding

The borrowed BET view references validated flags, records, and NameHash2
regions in caller-owned, immutable decoded table bytes. No payload is copied.
For an index below `entry_count`, record fields start at
`index * table_entry_size + field.bit_index` and use each declared bit count.
Positions, packed/unpacked sizes, and the uninterpreted unknown field remain
64-bit values; zero-width fields yield zero. Checked bit access bounds every
read. A record's flag index must be below `flag_count`, then selects a
little-endian DWORD from the flags array.

NameHash2 starts at `index * name_hash2_total`; only `name_hash2_size` low
bits are extracted. Extra bits are high stride bits, not a start adjustment.
Candidate matching masks the expected hash to the effective width and requires
equality, independently of NameHash1. A mismatch is not a valid candidate.

Confirmed records convert to `mpq_entry_s` with full-width metadata,
`LIBMPQ_ENTRY_SOURCE_BET`, and `source_index` equal to the BET index. No classic
block row or public file number is fabricated (`file_number` is `UINT32_MAX`).
Archive-level loading/decryption/decompression and public HET lookup are not
integrated yet; BET decoding is isolated from classic tables and attributes.

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
the attributes entry itself are zero. Ordinary archive creation emits zero
patch bits; the patch writer sets them for patch-file entries. Checksums are
metadata, not cryptographic authentication. Complete lossless file reads
automatically compare available CRC32 and MD5 values against decoded contents;
an all-zero MD5 row is an unavailable placeholder, not a digest to compare.
FILETIME and PATCH_BIT remain
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

Weak signatures are internal `(signature)` MPQ members and remain available
inside MPQE-wrapped MPQs. Strong signatures are external `NGIS`/RSA trailers
outside the MPQ extent. libmpq defines no external strong-trailer
representation for the encrypted MPQE transport, so MPQE weak signing and
verification are supported but external strong MPQE signatures are not.

Weak public and private keys are exactly 128 bytes: a 64-byte unsigned big-endian
modulus followed by a 64-byte zero-padded unsigned big-endian exponent value.
Use a public key to verify a
signature and a private key to create one. The modulus must be full-width and
odd; the exponent must be odd, at least 3, and less than the modulus. These
checks validate representation,
not the mathematical validity of the caller's RSA key pair. No PEM,
certificates, ASN.1 parser, default public key, or private key is built in.
libmpq does not ship Blizzard- or product-specific verification or signing
keys; all signature key material is caller-supplied.

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
