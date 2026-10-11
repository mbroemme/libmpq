# MPQ archive format guide

MPQ (Mo'PaQ, "Mike O'Brien Pack") is a little-endian random-access archive
format used by Blizzard games. This guide describes its wire structures,
algorithms, and libmpq's reading, validation, and writing behavior.

This is not a normative Blizzard specification. Game families contain format
variations, so validate every offset, size, count, and arithmetic operation
before using it. For practical API examples and development workflows, see
[DEVELOPER.md](DEVELOPER.md).

## Conventions and archive location

All multi-byte values are unsigned little-endian unless stated otherwise.
Structure offsets are relative to the MPQ header, not necessarily the
containing file. The header signature is `MPQ\x1A`.

An archive can be embedded after a stub or a user-data block and commonly
starts on a 512-byte boundary. An optional `MPQ\x1B` user-data header precedes
the real header and contains a user-data size and header offset. Locate and
validate the actual `MPQ\x1A` header before resolving archive-relative values.
Table placement is not fixed; do not infer it from file order.

## Header versions

The common 32-byte prefix is:

| Offset | Field | Meaning |
| --- | --- | --- |
| `00` | `char[4]` | Signature `MPQ\x1A` |
| `04` | `uint32_t` | Header size |
| `08` | `uint32_t` | Legacy archive size |
| `0C` | `uint16_t` | Format version: 0 through 3 |
| `0E` | `uint16_t` | Sector shift; sector size is `512 << shift` |
| `10` | `uint32_t` | Low hash-table position |
| `14` | `uint32_t` | Low block-table position |
| `18` | `uint32_t` | Hash-table capacity (power of two) |
| `1C` | `uint32_t` | Classic block-table entry count |

| MPQ | Version | Header size | Additional fields |
| --- | ---: | ---: | --- |
| v1 | 0 | `0x20` | Common prefix |
| v2 | 1 | `0x2C` | Hi-block table position; high 16 bits of classic table positions |
| v3 | 2 | `0x44` | 64-bit archive size; BET and HET positions |
| v4 | 3 | `0xD0` | 64-bit table sizes, raw-chunk size, table and header MD5 digests |

For v2 combine a classic table position as `(high16 << 32) | low32`. The
hi-block table is a `uint16_t` array indexed by classic block index and supplies
bits 32-47 of file positions. v4 records raw-table MD5 values; verify them
only after normal structural bounds checks.

The reader supports MPQ v3 (on-disk version 2) through classic hash/block
tables or HET/BET. Its normal `0x44`-byte header adds three little-endian
`uint64_t` fields after the v2 extension: archive size at `0x2C`, BET position
at `0x34`, and HET position at `0x3C`. The 64-bit size is authoritative,
including when the legacy size differs. Classic high table/file offsets retain
the v2 layout.

For compatibility, a base-only `0x20`-byte v3 header or a declared header from
`0x2C` through `0x43` uses the legacy archive size and absent/zero HET/BET
positions; no partial extension is read. Rejecting partial v2 extensions
(`0x21` through `0x2B`) is an intentional libmpq validation choice rather than
accepting arbitrary short sizes for StormLib compatibility. A declared full
header must contain all `0x44` bytes. HET/BET positions and stored extents are
bounded by the archive extent. Mixed-table archives can use classic lookup
when a classic hash entry maps to a live block; other live blocks need not be
hash-referenced. This does not assert equivalence with HET/BET. Declared
extended tables must form a valid pair; malformed tables fail opening rather
than downgrading to classic lookup. Compressed classic tables remain unsupported.
MPQ v4 supports read-only loading with explicit stored-table extents;
creation and updates remain unsupported.

### MPQ v4 header

MPQ v4 uses on-disk version 3 and a `0xD0`-byte header. Its `0x8C`-byte
extension follows the complete v3 header; offsets below are archive-relative
header byte positions. Table sizes describe stored table bytes, not entry counts.

| Offset | Type | Field |
| --- | --- | --- |
| `0x44` | `uint64_t` | Hash-table size |
| `0x4C` | `uint64_t` | Block-table size |
| `0x54` | `uint64_t` | Hi-block-table size |
| `0x5C` | `uint64_t` | HET size |
| `0x64` | `uint64_t` | BET size |
| `0x6C` | `uint32_t` | Raw chunk size, including zero when unused |
| `0x70` | `uint8_t[16]` | Block-table MD5 |
| `0x80` | `uint8_t[16]` | Hash-table MD5 |
| `0x90` | `uint8_t[16]` | Hi-block-table MD5 |
| `0xA0` | `uint8_t[16]` | BET MD5 |
| `0xB0` | `uint8_t[16]` | HET MD5 |
| `0xC0` | `uint8_t[16]` | Header MD5 |

The header MD5 input is `[0x00, 0xC0)`; `[0xC0, 0xD0)` stores the digest itself.
The private `mpq_header_v4_s` keeps these fields separate from v3 metadata.

`libmpq__header_v4_decode()` and `libmpq__header_v4_encode()` process the v4
extension using explicit little-endian integers and exact digest-byte copies.
The private full-header helpers, `libmpq__header_v4_full_decode()` and
`libmpq__header_v4_full_encode()`, combine the header generations and validate
the signature, version and declared header size. They do not calculate or
verify MD5 digests; normal archive opening performs verification separately.

V4 structural MD5 checks are automatic. A zero digest means no checksum is
supplied; a nonzero digest must match or opening fails with
`LIBMPQ_ERROR_FORMAT`. The header is checked over its original bytes before
trusting table extents. Each of the five table digests covers its exact declared
stored extent, including any extended-table envelope, before decryption,
decompression or endian conversion. Absent tables must have zero digests.
These checks use logical MPQ bytes after MPQE transport decryption and are
independent of the public file-content verification flags.

Normal v4 opening uses the full-header decoder and retains the five explicit
stored-table sizes. Each position/size pair is checked independently against the
declared 64-bit archive extent and physical source, including embedded archive
origins, before table I/O or allocation. Tables need not be adjacent or ordered.
Classic decoded lengths still come from entry counts. Equal stored and decoded
lengths use the existing uncompressed hash/block/hi-block readers. Shorter stored
extents may indicate compression or another unsupported/malformed encoding;
size alone does not identify compression. They return UNPACK because the loader
cannot decode them. HET/BET reuse the existing decrypt/decompress loaders, with
the envelope-inclusive 1 MiB limit unchanged. Missing tables are allowed when
the remaining representation permits lookup; malformed present tables do not
disappear behind fallback.

V4 archive access is read-only: creation, transactional updates and patch-view
rebuilds remain unsupported. Raw chunk metadata is retained, but raw file-data
chunk MD5 verification is unsupported; no default raw chunk size is selected.
Existing member compression and encryption decoding is reused without enabling
v4 writer codecs.

## Archive creation and finalization

V3 output reserves a 68-byte (`0x44`) header, writes file payloads at
their final archive-relative positions, then appends HET, BET, classic hash,
classic block, and (when file positions require it) hi-block tables. Stored
tables are adjacent, without padding. The existing in-memory builders,
serializers, and compress/encrypt encoder run only after payloads and generated
internal files are finished.

BET row N and classic block row N come from the same completed writer metadata
and retain insertion order. Classic block count is the completed row count,
not reserved capacity. Corresponding offsets, sizes, and flags must match;
reader precedence is not used to repair writer inconsistencies. Classic
`uint32_t` size limits remain enforced. File positions retain their high
`uint16_t` word in the optional hi-block table and their full `uint64_t` BET
value. Table positions are checked before narrowing into low/high header words.
Every table range advances through checked `uint64_t` multiplication and
addition bounded by `INT64_MAX`. Both classic hash/block offsets are checked
against their 48-bit low/high representation; HET/BET and hi-block offsets
remain full-width. Legacy v1/v2 finalization still serializes reserved block
capacity, while v3 uses completed rows, including the valid zero-row case.

Finalization rewrites the base, v2 extension, and v3 extension using the
canonical little-endian header encoders, then follows existing flush/signature
handling. The v3 archive-size field is authoritative; the legacy size word
stores its low 32 bits explicitly. V3 FIX_KEY encryption uses the final file
offset and unpacked size, and payloads are never moved afterward. Legacy v1/v2
writer behavior remains unchanged.

## Classic tables

Classic hash and block tables are encrypted streams of 32-bit words. Decrypt
the hash table with `HashString("(hash table)", FILE_KEY)` and the block table
with `HashString("(block table)", FILE_KEY)` before parsing.

Each 16-byte hash entry contains these fields, in wire order:

| Field | Type |
| --- | --- |
| `name_hash_a` | `uint32_t` |
| `name_hash_b` | `uint32_t` |
| `locale` | `uint16_t` |
| `platform` | `uint16_t` |
| `block_index` | `uint32_t` |

For `block_index`, `0xffffffff` means never used; `0xfffffffe` means deleted.
Lookup uses open addressing: initial slot is
`HashString(path, TABLE_OFFSET) & (capacity - 1)`, followed by linear probing.
An empty entry stops lookup; a deleted entry does not. A file is identified by
path, locale, and platform, although zero is the usual default for both.

Each 16-byte block entry contains these fields, in wire order:

| Field | Type |
| --- | --- |
| `file_pos` | `uint32_t` |
| `compressed_size` | `uint32_t` |
| `file_size` | `uint32_t` |
| `flags` | `uint32_t` |

Common flags are `0x80000000` exists, `0x01000000` single unit, `0x00010000`
encrypted, `0x00020000` adjusted key, `0x00000200` compressed, and
`0x00000100` PKWARE-imploded. Later games add sector-CRC, patch, deletion, and
signature flags; preserve unknown flags when rewriting an archive.

Internally, decoded classic rows populate archive-owned `mpq_entry_s` metadata
with 64-bit positions and sizes. Public file numbers map to these entries;
reader, stream, metadata, and verification paths consume them rather than the
classic block table. Classic hash rows translate through an explicit
classic-row-to-entry mapping; canonical entry ordering is independent. Source
provenance distinguishes classic rows from uninitialized entries. Classic
attributes remain indexed and sized by block-table rows, not canonical
entries. Writers and rebuild serialization still own classic wire tables.
Isolated BET decoding also produces canonical entries with explicit BET
provenance; archive loading owns both producers and their explicit maps.
Sector offset and codec-length limits remain unchanged.

### Classic hashing and table cipher

The traditional algorithm builds a 0x500-entry crypt table from seed
`0x00100001`. Hashing starts with `0x7fed7fed` and `0xeeeeeeee`, uppercases
input bytes, and uses crypt-table pages for table offset, name A, name B, and
file key. The cipher uses page four and evolves a key and seed per word.
Implement it with fixed-width unsigned arithmetic, never native `long`, and
test known hash/table-key/cipher vectors.

## HET/BET extended tables

HET (`HET\x1A`) and BET (`BET\x1A`) provide compact, bit-packed replacements
for classic lookup and file metadata. Their common prefix is signature,
version, and contained-data size. HET maps a Jenkins-style 64-bit filename
hash to a BET index using a bitmap/index table and reduced hash bits. BET
stores reduced name hashes plus bit fields for position, unpacked size, packed
size, flag-array index, and an unknown field.

Private structural decoders and HET candidate lookup accept already-decrypted/
decompressed table bytes. Archive opening loads the tables and populates BET
canonical entries. Normal filename lookup tries HET/BET first and falls back
to classic lookup only on a valid miss, not a malformed table or mapping.
V4 supplies explicit stored extents; v3 derives them from table order.
Loading retains the plaintext common envelope and
decrypts/decompresses its contained data before structural decoding.

The common envelope is three little-endian `uint32_t` values: signature at
byte 0, version at byte 4 (supported value 1), and `data_size` at byte 8.
`data_size` excludes this 12-byte envelope but includes the table-specific
header and arrays. A valid HET or BET requires
`table_size == envelope.data_size`; both exclude the 12-byte common envelope.
Declared data must fit the supplied buffer; bytes beyond the declared payload
are not interpreted as table data. The parsers allocate nothing and report
byte ranges relative to the beginning of the complete decoded envelope.

The HET-specific header contains eight `uint32_t` values, in wire order:

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

The BET-specific header contains nineteen `uint32_t` values (76 bytes), in
wire order:

```text
table_size, entry_count, unknown, table_entry_size,
bit_index_file_position, bit_index_file_size, bit_index_compressed_size,
bit_index_flag_index, bit_index_unknown,
bit_count_file_position, bit_count_file_size, bit_count_compressed_size,
bit_count_flag_index, bit_count_unknown,
name_hash2_total, name_hash2_extra, name_hash2_size,
name_hash_array_size, flag_count
```

The header is followed by `flag_count` little-endian `uint32_t` flags, packed file
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
The BET matcher decodes the candidate's NameHash2 and rejects non-live entries.

### Internal BET record decoding

The borrowed BET view references validated flags, records, and NameHash2
regions in caller-owned, immutable decoded table bytes. No payload is copied.
For an index below `entry_count`, record fields start at
`index * table_entry_size + field.bit_index` and use each declared bit count.
Positions, packed/unpacked sizes, and the uninterpreted unknown field remain
64-bit values; zero-width fields yield zero. Checked bit access bounds every
read. A record's flag index must be below `flag_count`, then selects a
little-endian `uint32_t` from the flags array.

NameHash2 starts at `index * name_hash2_total`; only `name_hash2_size` low
bits are extracted. Extra bits are high stride bits, not a start adjustment.
Candidate matching masks the expected hash to the effective width and requires
equality, independently of NameHash1. A mismatch is not a valid candidate.

Confirmed records convert to `mpq_entry_s` with full-width metadata,
`source_mask` containing `LIBMPQ_ENTRY_SOURCE_BET`, and `bet_source_index`
equal to the BET index. `classic_source_index` is `UINT32_MAX`; no classic
block row is fabricated. Isolated conversion leaves `file_number` at
`UINT32_MAX`; archive loading assigns compact public numbers to live entries.
BET decoding remains isolated from classic tables and attributes.

### Archive-level HET/BET reading

Present v3 structures must follow HET, BET, classic hash, classic block,
hi-block, archive end. Missing structures are skipped. Each v3 extended table's
stored extent ends at the next present structure, or the effective 64-bit
archive end; fixed-size classic tables must not overlap that next structure.
All relative positions are checked against the declared archive and backing
source before I/O. Each stored and decoded extended table has an inclusive
defensive limit of `0x00100000` bytes (1 MiB), including its 12-byte common
envelope. Oversized stored extents are rejected before reading the envelope;
oversized decoded lengths are rejected after reading only the envelope, before
payload allocation, reading, or decompression. Size arithmetic remains
checked. The HET and BET entry counts must match exactly. An empty pair has
zero entries in both tables; the HET runtime view still needs a nonzero slot
count and index width. Zero-slot HET headers may be structurally decoded but
are not usable archive lookup tables. Empty classic-only archives remain valid
without extended tables.

The common 12-byte envelope is plaintext. The contained payload is decrypted
with the existing `(hash table)` key for HET (`0xC3AF3770`) or `(block table)`
key for BET (`0xEC83B3A3`); trailing partial `uint32_t` values retain their
cipher semantics. If the stored payload is shorter than `data_size`,
production MPQ compression dispatch decompresses it and must produce exactly
`data_size` bytes. Framed zlib/bzip2 stages reject trailing input; existing
LZMA validation also requires complete input consumption. Structural parsing
follows transformation. There is no heuristic plaintext fallback for a damaged
encrypted payload.

The archive owns decoded HET/BET buffers, borrowed views, and explicit classic
and BET source-row-to-entry mappings. Normal, non-defragmented mixed archives
use StormLib-compatible unified rows: classic row N and BET row N represent
the same canonical row. The canonical row count is the maximum of the two
source counts, not their sum. BET initializes metadata; a live classic row
then overlays offset, sizes, and flags. An unused classic row does not erase
live BET metadata. Matching metadata on different row numbers never causes
heuristic deduplication.

Each canonical entry records a `source_mask` and separate `classic_source_index`
and `bet_source_index` values; an absent source index is `UINT32_MAX`. Both
explicit mappings resolve a shared row, so classic and HET filename lookup
converge on its public file number. Enumeration counts each live canonical row
once and skips rows without EXISTS. Classic-only public numbering is unchanged.
Classic `(attributes)` remain indexed by `classic_source_index` and sized by
classic block count, including shared rows; BET-only entries have no classic
attributes row. HET/BET hash information remains in the table views.

### In-memory extended-table writer builders

The private `libmpq__ext_tables_build(files, count, het, bet)` builds
separately owned HET/BET tables from completed logical writer records with
filenames and full-width positions/sizes. The builders do not depend on
classic block rows. Building alone does not serialize a common envelope or
write archive bytes.

BET fields use consecutive position, unpacked-size, packed-size, flag-index,
and reserved-field ordering. Each width is the minimum needed by the input;
zero values may use zero bits. If all record fields have zero width, the builder
uses a one-bit minimum record size. Reserved fields are zero. Unique flags are
sorted numerically and stored as little-endian `uint32_t` values: each logical
flag occupies four bytes in the wire representation. One unique flags value
requires a zero-bit flag index, including when multiple files share that value.
Multiple unique flags values use the minimum width needed to represent their
indices.

Zero files produce empty logical HET/BET tables with zero entry counts and no
BET flags, records, or NameHash2 values. HET retains its minimum free-slot
storage and nonzero index width; the BET header retains the one-bit minimum
record size.

HET reuses the reader's normalized Jenkins hash and full 64-bit partition:
the high byte is NameHash1 and the low 56 bits are NameHash2. BET stores exactly
56 NameHash2 bits per row with no extra bits. HET capacity is the smallest odd
number at least three and at least ceil(4 * file_count / 3), limiting occupancy
to 75 percent. Input-order insertion uses bounded linear probing and zero
empty markers.

Filenames are normalized by the existing HET hashing implementation, preserving
its case/separator normalization and 264-byte filename-length limit. Identical
normalized names produce identical hashes, including names made indistinguishable
by that length limit. Distinct filenames can also theoretically produce the same
64-bit HET hash. The builder conservatively rejects duplicate full normalized
HET hashes in either case, rather than creating indistinguishable entries; this
is not merely duplicate filename rejection.

Identical inputs generate identical headers and packed arrays. Both decoded
table sizes respect the existing 1 MiB envelope-inclusive defensive limit.
Zero-initialize builder outputs before their first use. Successful builds
replace prior outputs; failures preserve them. `libmpq__het_builder_free()`
and `libmpq__bet_builder_free()` release their allocations safely, including
empty or partially built tables. Synthetic tests validate the builders against
the existing parsers, HET lookup, and BET record decoder. Both table
serializers operate only on owned memory buffers. A separate private encoder
compresses/encrypts these buffers; the shared public writer places them during
v3 archive finalization.

### Private BET wire serialization

`libmpq__bet_serialize()` converts an existing owned BET builder into an owned
`uint8_t` buffer containing an uncompressed, unencrypted table. The caller
releases the returned buffer with `free()`. Failure resets the buffer to NULL
and its size to zero; the builder is never modified.

The wire layout is the 12-byte common envelope, the 76-byte BET-specific header,
then the flags array, packed file records, and packed NameHash2 values. The
envelope signature/version and all nineteen `uint32_t` header values are
encoded explicitly in little-endian order. Both `data_size` and `table_size`
equal the complete output size minus the 12-byte common envelope.

Serialization preserves the builder's flag ordering, storing each logical
`uint32_t` value as four little-endian bytes. It does not deduplicate flags,
recalculate record geometry, or hash filenames. Existing `uint64_t` field
values are decoded from the builder and written with checked bit access at
the declared bit indexes/counts. Zero-width fields remain zero. NameHash2 uses
the declared total width as its stride and the effective width as its value
width; extra bits and unused padding are emitted as zero.

Packed byte counts, array ranges, envelope sizing, and conversions are checked
before output allocation. The existing 1 MiB limit includes the envelope.
The canonical BET parser validates the encoded header before packed source
arrays are accessed; invalid field layouts or flag indices fail without
publishing a partial buffer. Output starts zeroed for deterministic padding.
Synthetic tests include an independent complete wire vector and round trips
through the header, record, and NameHash2 readers. No tables are written into
MPQ archives by this serializer alone.

### Private HET wire serialization

`libmpq__het_serialize()` returns a caller-owned `uint8_t` buffer containing
the complete plaintext, uncompressed HET table. The caller frees this allocation
with `free()`; builder allocations remain separately owned and unchanged.
Failures reset the output buffer/size to NULL/zero and free partial output.

The layout is the 12-byte common envelope, eight little-endian `uint32_t`
header fields (32 bytes), exactly `total_count` NameHash1 bytes, and the packed
BET-index array. Both envelope `data_size` and HET `table_size` exclude the
12-byte envelope. The serializer preserves the builder's capacity, widths,
slot placement, and hash bytes without recomputing filename hashes. A nonzero
NameHash1 of `0x80` is occupied, not a deleted marker.

Slot indices use bit offset `slot * index_size_total` and effective width
`index_size`. Extra bits are included in the stride, not used to shift the
index value. Output starts zeroed; empty slots, extra bits, and final padding
remain zero even when builder storage contains nonzero unused bits.
Writer serialization requires `index_size_total == index_size + index_size_extra`:
the total stride consists exactly of the effective index and extra bits.
The reader's more permissive width validation remains unchanged for external
tables. Any nonzero NameHash1 byte, including `0x7f` and `0x80`, is structurally
occupied; only `0x00` is free.

Before allocation, the serializer validates widths, exact packed storage,
array ranges, envelope/table sizes, and occupied-slot count against
`entry_count`. The existing envelope-inclusive 1 MiB limit bounds all size
calculations. Occupied indices are decoded with the existing reader's checked
bit access; this layer does not know BET bounds and does not require indices
to be below HET `entry_count`.

Synthetic tests cover a fixed complete wire vector, sparse slots, `0x80`,
extra/non-byte-aligned strides, 64-bit indices, deterministic padding, and
malformed states. Existing builder tests now use both production serializers
before HET header/view decoding and filename lookup with BET NameHash2
confirmation. The serializers themselves do not encrypt, compress, or write
archives. The shared writer performs v3 archive I/O separately.

### Private stored extended-table encoding

`libmpq__ext_table_encode()` accepts a complete structurally validated HET or
BET wire buffer and returns a separate caller-owned allocation, freed with
`free()`. Errors clear the output pointer and size to NULL/zero. Input bytes
are unchanged. The envelope-inclusive 1 MiB limit and exact declared payload
size are checked before allocation, using the existing HET/BET header parsers.

The 12-byte common envelope remains plaintext and describes the uncompressed
payload. Optional zlib encoding reuses the existing MPQ compression dispatcher
and leading method marker. Compressed payloads are used only when strictly
smaller; equal-sized or expanded results fall back to the original payload.
The compatible v2 zlib encoding policy is reused internally without enabling
any new public codec tuning option.

Compression precedes encryption. The validated signature selects the existing
hash-table key (`0xc3af3770`) for HET or block-table key (`0xec83b3a3`) for BET;
callers cannot supply an arbitrary key. Encryption uses complete little-endian
`uint32_t` words. Trailing 1-3 bytes remain unchanged, with no added padding.
Stored buffers decode through the existing table loader's decrypt/decompress
path. Tests include independent fixed encrypted vectors, fallback boundaries,
deterministic output, and synthetic archive-loader/read/stream round trips.
This encoder performs no archive I/O; creation and rebuilding place its output
through the shared writer.

## File sectors and compression

Unless marked single-unit, a file has `ceil(file_size / sector_size)` sectors.
A compressed or imploded multi-sector file starts with `uint32_t[sector_count + 1]`
offsets relative to its payload. The final value is the stored-data end. Raw
multi-sector files usually omit the table because their offsets are calculable.
Require monotonic, in-range offsets before reading a sector.

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

### Sector checksums

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

## File encryption and FIX_KEY

For an encrypted file, the file-key hash uses only the basename after the
final `/` or `\`, with classic hash case normalization. Directory components
do not participate. If FIX_KEY is set, use
`(base_key + (uint32_t)file_pos) ^ (uint32_t)file_size`. Decrypt the offset
table with `key - 1` and sector *i* with `key + i`. Encryption processes
little-endian 32-bit words; use explicit `uint32_t` wraparound. A filename is
normally required to decrypt file data.

Filename lookup and table generation still hash the complete archive member path.

Encrypted PTCH bodies retain the original member's key before the plaintext
patch-info prefix is excluded; see the patch section below.

## Patch archives and PTCH/BSD0

A patch layer can store a physical member such as `Base\Foo` below a `Base\`
prefix. Removing that prefix gives the logical identity `Foo` used to match
the base archive and other layers. A `(patch_metadata)` path is a namespace
marker, not a rich metadata structure: if its plaintext path is available,
typically through `(listfile)`, the directory portion can identify the prefix.
When only irreversible MPQ filename hashes are available, a prefix cannot be
inferred generically from them.

### Payload representation

A PATCH_FILE member begins with a plaintext patch-info prefix: little-endian
`uint32_t` length, flags (including `0x80000000`), decoded PTCH data size, and
16-byte MD5 of the decoded PTCH body. The fixed prefix is 28 bytes; its declared
length may include extensions and must fit the stored member extent. The
block's unpacked size describes the final patched target, not the PTCH body.

The decoded PTCH header is 68 bytes:

| Offset | Field |
| --- | --- |
| `0x00` | `PTCH` tag |
| `0x04` | `uint32_t` complete size after any inner RLE expansion |
| `0x08`, `0x0C` | `uint32_t` before/after target sizes |
| `0x10`, `0x14` | `MD5_` tag and `uint32_t` block size (40) |
| `0x18`, `0x28` | 16-byte before/after target MD5 values |
| `0x38`, `0x3C` | `XFRM` tag and `uint32_t` transform block size |
| `0x40` | `COPY` or `BSD0` tag |
| `0x44` | Transform data |

COPY supplies the complete replacement. BSD0 uses a `BSDIFF40` header with
little-endian `uint64_t` control-block length, delta-block length and target
length, followed by controls, deltas and extra bytes. libmpq's controls are
12-byte tuples: `uint32_t` add count, copy count and sign-magnitude source move.
Add combines base and delta bytes modulo 256; copy takes literal extra bytes.
An inner zero-skipping RLE wrapper may compress the transform. All ranges,
output lengths and before/after MD5 values are checked during application.
The writer validates each BSD0 candidate with this decoder before selecting
it over COPY; compatibility with generic bsdiff encodings is not implied.

`libmpq__patch_payload_size()` reports decoded PTCH body size;
`libmpq__patch_payload_read()` returns that body beginning with `PTCH`, excludes
the plaintext prefix and verifies its MD5. Neither API applies the patch or
returns the final target. The caller supplies output storage and, when needed
for decryption, the actual member filename. Delete markers (`0x02000000`) hide
lower-layer names; patch members carry `0x00100000`.

### Creation and ordered materialization

The dedicated patch writer can create MPQ v3 patch archives from standalone v3
bases with classic-backed, mixed, or BET-only replacement/deletion targets
when their filenames are supplied by the caller. Classic-backed targets retain
their unambiguous classic locale/platform identity; BET-only targets use zero
for both because BET carries neither field. Filenames are never reconstructed
from hashes. Physical metadata and encryption/FIX_KEY reads use canonical
entries and validated source mappings, without fabricating classic rows.
The existing v3 writer emits the 0x44-byte header, HET/BET and classic tables
with shared row identity, patch-info prefixes, PTCH bodies, and delete markers.
Existing compression, encryption and signature options retain their meanings.
Ordered patch-view materialization supports v3 bases with classic-backed,
mixed, or BET-only members. Names come from `(listfile)`, recognized internal
names, and the patch's logical namespace; hashes are never inverted into names.
Incomplete coverage, ambiguous aliases/locales, unresolved listed names, and
nonzero reserved BET metadata are rejected instead of dropping information.
Patch prefixes, COPY/BSD0 transforms, normal replacements, additions and delete
markers retain their existing semantics and integrity checks.

Unchanged packed members retain their original archive-relative offsets,
compression and encryption. Modified contents pass through the normal writer,
including basename-derived keys and FIX_KEY adjustment at final output offsets.
Representable compression masks and classic locale/platform identities are
preserved; modified files requiring lossy recompression or incompatible
later-sector compression masks are rejected. Existing writer size limits also
apply, including its single-unit sector-size limit. Classic attributes are
read only for classic-backed rows; output checksums and supported timestamps
are regenerated or retained as appropriate. Modified views omit stale signature
members and trailers. A metadata-only layer leaves the original private view
unchanged.

Materialized output is a private standalone v3 archive with newly generated
HET/BET and classic tables sharing row identity. It is reopened before
replacing the private view; failed opens attempt to remove temporary output
without modifying either source. Input container prefixes/suffixes are not
carried into rebuilt v3 views. An open failure is terminal and leaves the
returned view pointer NULL, not a partially usable or retryable view. Archive
close consumes its handle even when it reports an error; cleanup never closes
that handle again. If removal of the old private placeholder fails after the
source has closed, the candidate is discarded and outer cleanup retries
removal of the placeholder. Private-file deletion is best effort: persistent
filesystem refusal can leave temporary files, but no partial view is returned
and the original sources remain unchanged. Multiple layers are applied in
caller-specified order. Each changed layer rebuilds a complete v3 intermediate
through the same writer; subsequent COPY or BSD0 transforms use the preceding
layer's contents. No-op layers retain the current intermediate unchanged.
Generated listfiles carry the known logical namespace forward, subject to the
same conservative naming and metadata requirements at every layer. Failure at
any layer is terminal: no partial chain is returned, and intermediate cleanup
is best effort.

Internal patch-view source descriptors accept plain MPQ or MPQE independently
for the base and each layer, including mixed chains. Each MPQE source requires
its own authentication code; path-only composition cannot authenticate wrapped
patch layers. Authentication failure returns no view. Materialized views are
private decoded MPQ archives, not newly published MPQE containers. The patch-view
composition entry points remain private; public patch creation accepts a
standalone plain MPQ base and may produce MPQE output.

Encrypted PTCH reads reopen independent member caches and derive FIX_KEY from
the original member before shifting past its plaintext patch-info prefix.
Modified output members use basename keys and final archive-relative offsets,
including when input archives have container prefixes. The public dedicated
patch writer accepts normal encryption but not explicit FIX_KEY storage options;
FIX_KEY patch members remain readable through the existing decoder.

Signature presence is not proof of validity. Callers must explicitly verify
input archives with the required public key; patch-view composition does not
enforce signature verification. Supported weak/strong signatures on plain v3
inputs and weak signatures on MPQE inputs use the ordinary archive verifier.
Changed intermediates and final views omit old signatures and are unsigned:
composition has no signing configuration and does not regenerate signatures.
Strong-signature creation and trailer detection remain unsupported for MPQE.
No-op chains preserve unchanged input signatures without claiming verification.
Corrupt PTCH integrity metadata is rejected independently of archive signature
policy.

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

## Attributes, signatures and integrity

### Internal files and attributes

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
returns EXIST; malformed metadata returns FORMAT when explicitly queried,
while ordinary extraction skips unusable optional metadata. The reader accepts
full arrays and recognized legacy layouts: one-entry-short arrays, omitted
self patch bits, missing patch arrays, and all-zero legacy `uint32_t` patch
regions. Unavailable rows/patch values have their availability flags cleared
rather than inventing checksum values. Unknown versions/flags and other
payload sizes are rejected when queried.

Creation is opt-in with `LIBMPQ_ATTRIBUTE_*` bits in `options.attributes`.

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
FILETIME and PATCH_BIT remain metadata only. Lossy ADPCM decoded bytes can
differ from source-byte metadata, so those members are not automatically
compared. Complete file reads also verify available sector Adler-32 values
over decrypted packed sectors before decoding, including ADPCM. Unusable
optional sector tables are skipped during ordinary extraction.

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

### Archive signatures

Weak `(signature)` files contain exactly 72 uncompressed, unencrypted bytes:
eight zero bytes followed by a little-endian RSA-512 signature integer. libmpq
hashes from the archive offset through the v1 declared archive size or the v2
metadata-derived required extent or authoritative v3 archive size, treating
all 72 signature bytes as zero, and checks the complete PKCS#1 v1.5 MD5
DigestInfo encoding. Bytes before or after that MPQ range are not hashed. For
archives physically beginning with `HM3W`, weak and strong signature hashing
starts at physical offset zero and ends at the logical MPQ end; weak hashing
still excludes the internal `(signature)` file.

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

Weak public and private keys are exactly 128 bytes: a 64-byte unsigned
big-endian modulus followed by a 64-byte zero-padded unsigned big-endian
exponent value. Use a public key to verify a signature and a private key to
create one. The modulus must be full-width and odd; the exponent must be odd,
at least 3, and less than the modulus. These checks validate representation,
not the mathematical validity of the caller's RSA key pair. No PEM,
certificates, ASN.1 parser, default public key, or private key is built in.
libmpq does not ship Blizzard- or product-specific verification or signing
keys; all signature key material is caller-supplied.

Strong public and private keys are exactly 512 bytes: a 256-byte unsigned
big-endian modulus followed by a 256-byte zero-padded unsigned big-endian
exponent. Use the public exponent for verification and the private exponent
for creation. The writer emits only the plain SHA-1 archive-range variant.

On a new v1, v2, or v3 writer, call `libmpq__archive_sign` once for each requested
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

Weak and strong signatures stream their entire signed range using `uint64_t`
positions and bounded read buffers. Sparse holes are hashed too: signing a
large sparse archive is linear in its logical extent, not its allocated disk
size. High-offset regression tests cover range/lookup and I/O failure handling;
they do not substitute for a complete multi-gigabyte sign/verify operation.

## Compatibility and implementation limits

Automated compatibility coverage is entirely self-contained: deterministic
synthetic v3 fixtures, independently verified fixed HET hash vectors, malformed
archive tests, fuzzing, and reader/stream/integrity tests. The library and its
native tests remain C-only. StormLib is an external reference, not a build,
test, vendored, or CI dependency; no installation or download is required.

Independent implementations such as StormLib may be used manually for local
comparison. Compare archive-open success, live file enumeration/count, filename
lookup hits/misses, flags, packed/unpacked sizes, offsets, and extracted payload
bytes/checksums. Public file numbers need not equal another implementation's
physical table indices. Standalone Huffman and Huffman+zlib EXTENDED masks are
known reference limitations: StormLib's v2+ dispatcher rejects them, while
libmpq's synthetic tests verify them. For lossy WAVE members, compare decoded
bytes between readers rather than requiring equality with source PCM.

Current sector/codec lengths are 32-bit even though canonical BET metadata and
positions are 64-bit. Unrepresentable member reads and block counts fail with
SIZE rather than truncating. V3 modification requires complete filename
reconstruction. Creation and transactional rebuilding use
the existing writer, preserving explicit source mappings and independently
validated generated tables.

The v3 `max_files` ceiling of `0x04000000` is an implementation limit, not
an MPQ format maximum. The classic hash capacity is the next power of two
at least twice the requested capacity. At this ceiling its wire storage is
2 GiB; the next capacity step needs 4 GiB, which cannot fit the classic
cipher's `uint32_t` length. Validation itself does not allocate these tables.
Actual creation still requires memory for reserved tables and can fail with
an allocation error. Completed HET/BET tables must also fit the separate
1 MiB limit, so this ceiling is not a promise of that many writable files.

Creation supports MPQ v1/v2/v3, including MPQE wrapping. V4 is read-only;
compressed classic tables and v4 modifications remain unsupported. The v3 writer
emits mixed HET/BET and classic tables, not BET-only output. V3 transactional reconstruction requires a complete,
unambiguous named file set and representable metadata. It rebuilds all tables
through the same writer; incomplete source information is rejected rather than
silently losing members. Practical transaction rules and supported source
boundaries are described in [DEVELOPER.md](DEVELOPER.md#transactional-modification).
