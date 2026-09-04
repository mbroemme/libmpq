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

A compressed sector starts with a mask byte. Reverse the selected transforms
when decoding; a sector may instead be stored raw when compression loses.

| Mask | Codec |
| ---: | --- |
| `0x01` | Blizzard Huffman |
| `0x02` | zlib deflate |
| `0x08` | PKWARE DCL implode |
| `0x10` | bzip2 |
| `0x20` | sparse/run-length transform |
| `0x40` | IMA ADPCM mono |
| `0x80` | IMA ADPCM stereo |
| `0x12` | LZMA; a special value, not `0x02 \| 0x10` |

The sparse, ADPCM, and LZMA variants are game-specific later extensions. Do
not decode a mask until every required transform is implemented. Bound every
decoder by the expected unpacked sector length.

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
per-block CRC32, Windows FILETIME, and MD5 arrays. Older archives can contain
an internal weak `(signature)` file; a strong signature can follow the archive
as `NGIS` plus a 2048-bit RSA signature. Use a maintained cryptographic
library for signature verification and never treat a valid signature as a
substitute for range validation.

## Implementation order

1. Locate and range-check the header with checked 64-bit arithmetic.
2. Implement v1 classic lookup and raw/single-unit file reading.
3. Add table and sector encryption with known-name vectors.
4. Add codecs incrementally with bounded output.
5. Add v2 high offsets, then v3/v4 HET/BET and MD5 validation.
6. Test collisions, deleted entries, embedded headers, mixed sectors, every
   codec, high offsets, malformed tables, and integer-overflow boundaries.
