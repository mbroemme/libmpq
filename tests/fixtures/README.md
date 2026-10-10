# MPQ regression fixtures

## Overview

All checked-in archives are deterministic, project-owned synthetic test
material, not Blizzard archives or extracted game data. Fixtures are grouped
by MPQ version, with a SHA-256 checksum for each binary in its version's
inventory. Normal tests read committed archives and may compare
runtime-generated copies; rewriting fixture files is explicit.

Regeneration commands assume a prepared disposable test directory, as
described in Verification. Shared payloads, signing material, and MPQE
authentication conventions are documented once in Shared fixture details.

## MPQ v1 fixtures

### Fixture inventory

| Fixture | Purpose | SHA-256 |
| --- | --- | --- |
| `mpq-v1-features.mpq` | Classic v1 codecs, attributes, weak and strong signatures | `43bd0c32301f03647688eb84d21031826620cba1ce8617040362345f4e3ac3bc` |
| `mpq-v1-features.mpqe` | MPQE-wrapped v1 features, weak signature only | `1961416258e68cf7b10c271b338ed2c3d45c56619e9446cd8a97caccc56481c7` |
| `mpq-v1-features.w3x` | HM3W-wrapped v1 features, weak and strong signatures | `f45e7148b86b7a65bce5b92feae046683726dd79efa8f8e87f66afd02b56bdba` |
| `mpq-v1-features-patch.mpq` | First v1 COPY layer, deletion and addition | `3bfedc1ef08745b9dca37dfc5daca70ec54ffb8f0cfcbe5235d4aa5de46451de` |
| `mpq-v1-features-patch.w3x` | Second v1 COPY layer with a non-HM3W container prefix | `6c3d45c2b0339bda90c687371c8fc77f0227cec86d14a753001d6e52146bbff0` |

### Base archive

`mpq-v1-features.mpq` contains the shared synthetic feature payloads below,
`(listfile)`, `(attributes)`, and `(signature)`. It has 32 physical block-table
rows, including zero-filled unused rows, and 4096-byte sectors.

The user members and their storage methods are listed in Shared fixture
details. The standalone archive has an embedded RSA-512 weak signature and
an independently generated plain `NGIS` strong trailer.

The attributes payload has version 100, flags `0x07` (CRC32, FILETIME, MD5),
and length 904 bytes.

The v1 recipe reserves 16 bytes after the header before the
hash table when attributes are enabled, avoiding StormLib's malformed-map
heuristic that skips attributes when a table starts exactly at header end.

Every nonempty sectorized compressed or imploded entry carries sector
Adler-32 checksums: 13 entries in v1, including compressed attributes,
PKWARE, encrypted text, and both WAVE members. Raw overview and the single-unit
listfile have no sector checksum tables. Sectorized entries may have only one
sector and are distinct from single-unit storage.

### MPQE variant

`mpq-v1-features.mpqe` reproduces the logical v1 base through the existing
MPQE writer. It retains the payloads, sector checksums, decoded WAVE bytes,
and weak signature, but omits the raw MPQ's external strong trailer.
Tests compare the decrypted MPQ extent with the raw counterpart, excluding
that trailer. It uses the shared non-secret authentication code.

### Warcraft III wrapper and signatures

`mpq-v1-features.w3x` containsa 1024-byte HM3W prefix and embedded v1 MPQ.
Its weak and strong digests include the wrapper, unlike standalone MPQs.
Strong verification uses the fixture basename and recognizes both separator
styles and ASCII case. Tests tamper a byte after the HM3W marker and require
both signatures to detect it. Warcraft III `.w3m` and `.w3x` share this
outer signature behavior, so only one signed `.w3x` feature fixture is retained.
The patch `.w3x` described below has a zero prefix, not HM3W, and is unsigned.

### Patch archives

#### MPQ patch

`mpq-v1-features-patch.mpq` targets `mpq-v1-features.mpq`. It replaces
`overview.txt` with a PTCH COPY yielding `Patch layer one\n`, deletes
`pkware.txt`, and adds `patch-only.txt` containing `Patch-only member\n`.
Members use single-unit storage and include a `(patch_metadata)` member
containing `test`. There is no signature or true PATCH_BIT attribute.

#### W3X patch

`mpq-v1-features-patch.w3x` is the second v1 layer, not a container copy of
the first patch. Its COPY expects `Patch layer one\n` and produces
`Patch layer two\n`; it deletes `bzip2.txt` and contains the same addition.
A deterministic 512-byte zero prefix precedes its embedded MPQ, without
HM3W-specific signature semantics.

Apply the first v1 patch before this layer. Tests cover the chain on both plain
v1 and signed HM3W bases, exact final bytes, missing/deleted members, streaming,
and container-prefix preservation.

### Regeneration

The refresh modes require the existing canonical v1 and v2 bases. They
regenerate both versions together; there is no v1-only selector. Refresh
the bases and MPQE variants before the legacy patch archives:

```sh
./test-fixtures --refresh
./test-patch-reader --refresh
```

The first command recreates v1/v2 MPQs and MPQE variants. It reconstructs
original WAVE samples from the shared formula, uses EXTENDED policy and fixed
timestamps, and signs through the public writer before MPQE
encryption. Private attributes serialization preserves explicit sector-CRC
storage without changing production defaults. Raw MPQs receive the fixed
independent strong trailers; MPQE output does not. Repeating the recipe
produces identical bytes. Test manifests pin archive/listfile and regular-file
hashes.

The second recreates the first v1 patch, its second zero-prefixed W3X
layer, and the v2 patch using their corresponding base payloads.

There is no dedicated checked-in command-line regeneration mode for the signed
`mpq-v1-features.w3x`. Neither refresh mode overwrites it. Preserve its bytes
and independently verified signatures; do not assume that adding an HM3W prefix
to a standalone signed archive preserves signature validity.

## MPQ v2 fixtures

### Fixture inventory

| Fixture | Purpose | SHA-256 |
| --- | --- | --- |
| `mpq-v2-features.mpq` | Classic v2 features including LZMA, attributes and both signatures | `5b6c8a1a91fcc21bfe871a770da78724b8aaf247fa0077efedaf4d8cf0ba0ff0` |
| `mpq-v2-features.mpqe` | MPQE-wrapped v2 features, weak signature only | `8b139dbba5ac1b7b1f78220a49d2328ea7db91069f906676af7ab675182db2af` |
| `mpq-v2-features-patch.mpq` | V2 COPY layer, deletion, addition and zero PATCH_BIT array | `d18803a69560195efa09caade732fb027250711289073d88c274458947a574e9` |

### Base archive

`mpq-v2-features.mpq` shares the v1 payloads and adds `lzma.txt` after the
SPARSE members. It uses exclusive MPQ method `0x12`; its descriptive text
is repeated 32 times to avoid raw fallback.

The v2 attributes payload is 908 bytes with flags `0x0f`, adding an all-zero
PATCH_BIT array. This tests optional arrays, not a version restriction.
The same 32 physical rows, source checksums, timestamps, and storage conventions
apply; 14 entries carry sector Adler-32 tables, including attributes.
The raw archive contains weak and strong signatures.

The v2 recipe uses `LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED`:
standalone Huffman and Huffman + zlib remain readable by libmpq but may not
be accepted by StormLib's v2 reader. STANDARD v2 creation rejects these masks.

The strong trailer uses the `ARCHIVE` `NGIS` variant. Shared payload
construction, attributes conventions, and signing vectors are described
in Shared fixture details.

### MPQE variant

`mpq-v2-features.mpqe` reproduces the logical v2 base, including its LZMA
member, sector checksums, decoded WAVE bytes, and weak signature.
It omits the raw MPQ's external strong trailer. Tests compare the decrypted
MPQ extent against the raw counterpart without that trailer. Authentication
uses the same public test code as v1 and v3.

### Patch archive

`mpq-v2-features-patch.mpq` targets `mpq-v2-features.mpq` with COPY output
`Version two patch\n`, deletion of `pkware.txt`, and the same patch-only
addition and metadata marker. Its PATCH_BIT attributes array is all zero:
the legacy fixture recipe changes block flags without writing true patch bits.

The legacy patch payload/API regression checks are described in Shared
fixture details.

### Regeneration

Use the coupled refresh procedure in MPQ v1 fixtures: the existing switches
regenerate both v1 and v2 bases/MPQE variants, then all legacy patch fixtures.
There is no v2-only selector. Both canonical base inputs must exist before
refreshing; refresh bases before patches. The resulting v2 MPQ is also the
input required by the independent v3 base recipe.

## MPQ v3 fixtures

### Fixture inventory

| Fixture | Purpose | SHA-256 |
| --- | --- | --- |
| `mpq-v3-features.mpq` | Mixed classic/HET-BET codecs, BET-only empty tail and weak signature | `1a9912f063fa2a2090f561ffd01c7163d0657b4b38cac6e67b72aa359b1e3c15` |
| `mpq-v3-features.mpqe` | MPQE -> v3 -> HET/BET read/stream composition | `b75e011f111b05e6fdaa53c70252540f13ca683ac0fee6c17dd78add8fed2f03` |
| `mpq-v3-features-patch.mpq` | V3 COPY/BSD0 layer, BET-only deletion and encrypted FIX_KEY members | `031ae2155f0c126f02711f8078b259b2b23f2607fcbfbfe02e1ae1956a1885e5` |

### Base archive

`mpq-v3-features.mpq` retains project-owned v2 payload bytes and positions,
replaces format tables, and writes a 0x44-byte header with wire version 2.
Its private recipe is independent of the public v3 writer, which is also
tested separately.

The mixed archive has an encrypted 67-slot non-power-of-two HET and BET with
64-bit-capable offsets, 134-bit records, and 58-bit NameHash2 strides containing
two extra bits. Classic and BET shared rows reconcile once; unused rows remain
unused. `zero.bin` is a BET-only zero-byte tail absent from the listfile.
Listfile, attributes, and a freshly computed test-key weak signature are present;
there is no strong trailer. Encrypted sector bytes, source checksum metadata,
and all v2 codec masks, including LZMA and lossy WAVE, are preserved.

Normal tests compare every decoded member against the v2 reference, including
WAVE's existing decoded bytes, and check byte-for-byte recipe reproducibility.
They exercise special-file discovery, weak verification with the supplied
test key, zero-length members, repeated small reads, seeks, streams, and
HET/classic lookup equivalence.

HET/BET-only and compressed-table variants are generated at runtime, not
committed fixtures. Classic-only tails, conflicting metadata, FIX_KEY reads,
offsets above 4 GiB, malformed mappings, strict table limits, table keys, and
extent ordering are covered by separate runtime reader tests. A 64-bit field
in the committed BET is not a multi-gigabyte fixture.

### MPQE variant

`mpq-v3-features.mpqe` wraps the exact committed v3 MPQ bytes without rebuilding
them. It remains independent of public v3 writer generation and covers
MPQE -> MPQ v3 -> HET/BET -> canonical read/stream composition, including
the BET-only empty tail and incorrect-authentication rejection.

It uses the shared test authentication code and contains the same weak
signature as the base, without an external strong trailer.

### Patch archive

`mpq-v3-features-patch.mpq` is a 1,611-byte synthetic layer targeting the
unchanged v3 feature base. Its 0x44-byte/wire-version-2 header, HET/BET, and
classic tables share row identity. The seven logical entries include generated
listfile and attributes plus these operations:

| Member | Operation / expected materialized bytes |
| --- | --- |
| `overview.txt` | COPY -> `Version three patch\n` |
| `zlib.txt` | BSD0 -> original bytes with byte 17 XORed by `0x5a` |
| `encrypted-compress.txt` | Compressed FIX_KEY COPY -> `Encrypted synthetic v3 patch member.\n` repeated 32 times |
| `zero.bin` | Delete the unlisted BET-only base tail |
| `folder/reference.bin` | Add 32 `B` bytes, encrypted single-unit FIX_KEY storage |

The deletion supplies the unlisted tail's required name for complete base
reconstruction. The recipe reuses private fixture/PTCH writers and the BSD0
encoder with the normal v3 archive writer; the dedicated public patch writer
cannot add new members or request FIX_KEY. No public API is extended.

CRC32/MD5 describe final replacement bytes. Replacement/addition FILETIME
values are fixed at `132537600000000000 + index * 10000000`; internal and
deletion timestamps are zero. PATCH_BIT is set for stored patch replacements,
not ordinary materialized rows.

Normal tests compare the regenerated recipe with committed bytes, validate
public PTCH size/read/integrity, and materialize 17 logical entries.
Replacements/addition match the table; `zero.bin` and stale signatures are absent.
Eleven unchanged codec/audio members retain exact decoded bytes, flags, and
packed sizes. Tests check streams, HET/classic identity, and independent FIX_KEY
ciphertext before/after relocation. This fixture also seeds archive-open fuzzing.

The v3 patch fixture is unsigned, like the legacy patch fixtures.

### Regeneration

The canonical v2 MPQ must exist first. Build the independent mixed v3 base,
wrap that exact base in MPQE, then generate its patch archive:

```sh
./test-fixtures --v3-output fixtures/mpq-v3-features.mpq
./test-mpqe --v3-output fixtures/mpq-v3-features.mpqe
./test-patch-reader --v3-output /tmp/v3-patch-first.mpq
./test-patch-reader --v3-output /tmp/v3-patch-second.mpq
```

The two patch outputs support the common byte comparison in Verification.
The same patch generator can write `fixtures/mpq-v3-features-patch.mpq`
explicitly in the disposable copy. No additional v3 patch or MPQE fixture
is needed. The v3 base recipe recomputes its weak signature; MPQE wraps the
result without rebuilding it.

Optional HET/BET-only and compressed-table variants use the same v2 input
and base recipe; they are runtime-only archives, not inventory entries:

```sh
./test-fixtures --v3-only-output /tmp/synthetic-v3-bet.mpq
./test-fixtures --v3-packed-output /tmp/synthetic-v3-packed.mpq
```

## Shared fixture details

### Synthetic text and storage methods

The following members are shared by the v1/v2 bases and retained by the
independent v3 base recipe. The v2/v3-only LZMA member is described with v2.

Compressed lossless text members are deliberately repeated and compressible,
so the advertised codec is stored instead of raw fallback:

| Member | Stored feature |
| --- | --- |
| `overview.txt` | Raw text |
| `implode.txt` | Standalone PKWARE implode |
| `huffman.txt` | Masked Huffman, `0x01` |
| `zlib.txt` | zlib, `0x02` |
| `pkware.txt` | Masked PKWARE, `0x08` |
| `bzip2.txt` | bzip2, `0x10` |
| `chain.txt` | Huffman + zlib, `0x03` |
| `encrypted-compress.txt` | Encrypted zlib-compressed text |
| `wave-mono.wav`, `wave-stereo.wav` | zlib first sector, Huffman + ADPCM later sectors |
| `sparse.txt`, `sparse-zlib.txt`, `sparse-bzip2.txt` | SPARSE methods `0x20`, `0x22`, `0x30` |

`pkware.txt` and `implode.txt` each contain their descriptive sentence and LF
repeated 32 times, without single-byte padding runs. They exercise general
PKWARE length/distance matches. Member descriptions explain creation and
extraction, encryption ordering, standalone versus masked PKWARE, and valid
compression chains.

### Attributes and sector checksums

User FILETIME values are `132537600000000000 + index * 10000000` in insertion
order. The listfile has computed checksums and FILETIME zero; attributes and
signature rows are zero to avoid self-reference. Source CRC32/MD5 vectors in
`tests/test-mpq-fixtures.c` were independently calculated with Python
`zlib`/`hashlib`. Checksums cover source bytes, so lossy WAVE members need not
match their decoded samples.

Creation selects arrays through `options.attributes`, not archive creation
flags. Any nonzero combination creates one attributes member and consumes a
reserved slot.

Checksums cover packed sector bytes before encryption. The offset table has
an extra terminal entry; the unencrypted checksum table follows sector data.
These small tables use raw little-endian `uint32_t` values rather than
compressed storage. Tests check the CRC flag, extra offset, nonzero values,
and explicit sector verification, including lossy WAVE members.

### SPARSE and WAVE data

The three SPARSE members are genuine UTF-32LE, not padded UTF-8. Each begins
with BOM `FF FE 00 00`, followed by this line 16 times with LF endings:

```text
This text uses SPARSE compression and decompression.
```

ASCII UTF-32LE characters supply three zero bytes each. Both stages of the
combined methods reduce the payload; tests inspect stored method bytes to
prevent raw or single-stage fallback. Extraction preserves UTF-32LE bytes;
an editor supporting that encoding or `iconv -f UTF-32 -t UTF-8 sparse.txt`
can display the text. These members follow stereo WAVE in insertion order
and use identical first/next masks `0x20`, `0x22`, and `0x30`.

The WAVE members are playable RIFF/WAVE PCM16 with 7000 sample frames at
22050 Hz, one or two channels, and little-endian interleaved samples.
Source sizes are 14044 and 28044 bytes, spanning four and seven sectors.
The first sector uses zlib (`0x02`) and is byte-exact, including the 44-byte
header. Later sectors, including the partial last sector, use Huffman +
mono ADPCM (`0x41`) or stereo ADPCM (`0x81`). These selections are allowed
by STANDARD in v1/v2; the recipes use EXTENDED for the Huffman/chain text cases.

Source samples match `make_wave(7000, channels)` in `tests/test-mpq-wave.c`:
for frame `i`, `phase = (i * 17) % 4096` and
`base = phase < 2048 ? phase - 1024 : 3072 - phase`. The left/mono sample is
`base * 24`; the right sample adds 1800. A standard 44-byte PCM header
precedes the samples. Mono then stereo follow encrypted text and precede
SPARSE.

ADPCM is lossy. Tests check every sector's method, the exact first sector,
mean absolute sample error below 6000, and maximum error below 16000.
Archive and extracted-payload hashes pin the committed contents.

### Signature vectors and signing material

The shared RSA-512 test key pair is in `tests/test-mpq-helper.h`.
Weak-signature known answers in the signature test were computed independently
with Python `hashlib.md5` and `pow(message, d, n)`; the Python binding tests
also check digest/RSA results independently. The 72-byte weak member has an
eight-byte zero prefix followed by a 64-byte little-endian RSA value and a
zero attributes row.

Canonical strong trailers were generated independently with
`hashlib.sha1()` and `pow(m, d, n)` using fixed test-only RSA-2048 material,
rather than libmpq's signer. Matching disposable key material also exercises
strong-signature creation. These are not Blizzard or product-specific keys;
never use test private keys for real signing.

Standalone v1/v2 weak signatures are recreated through the public writer;
the independent v3 base recipe recomputes its weak signature. Version-local
descriptions identify the strong-trailer variant or its absence. All checked-in
patch fixtures are unsigned.

### MPQE authentication conventions

All three MPQE feature variants use the deliberately non-secret 32-byte test
authentication code:

```text
LIBMPQ-MPQE-TEST-AUTH-CODE-00001
```

They are public MPQE interoperability vectors, not installer credentials.
The existing transform handles each 64-byte logical chunk separately, including
a final partial physical chunk; only physical bytes are stored. General MPQE
format and cryptography are documented in [MPQ.md](../../MPQ.md).

### Patch payload regressions

Native fixture tests check fixed decoded PTCH bytes, size distinct from member
metadata, the `PTCH` prefix, transferred counts, insufficient buffers, invalid
numbers, NULL arguments, non-patch errors, and corrupted patch-info MD5.
Binding tests reuse the legacy patch fixtures. Runtime tests retain separate
prefix, malformed-input, encrypted-member, and extended-sector-offset cases;
these do not require additional committed binaries.

## Verification

### Common preparation

Use a disposable source copy that already contains the canonical fixtures.
The v1/v2 refresh recipes read existing lossless payloads and storage options;
they are not bootstrap generators for an empty fixture directory.
Build with the existing zlib, bzip2, and liblzma prerequisites. No StormLib is
required. For an Autotools build in that copy:

```sh
sh autogen.sh
./configure
make
make -C tests test-fixtures test-mpqe test-signature test-patch-reader
cd tests
```

All version-local regeneration and verification commands assume that working
directory so relative `FIXTURE_DIR` paths resolve correctly. With CMake, build
the same named executables against a disposable source copy and use their
paths in the build directory; supply appropriate output paths for commands
that take them. Normal runs never refresh committed archives implicitly.

### Checksums and deterministic comparison

From the test directory, recalculate every binary checksum and compare it
against the three version-local inventories:

```sh
(cd fixtures && sha256sum *.mpq *.mpqe *.w3x)
```

Run a selected version-local recipe twice, retaining the first output before
the second run, and compare the bytes. The v3 patch procedure already writes
two explicit outputs, which can also be checked against the committed fixture:

```sh
cmp /tmp/v3-patch-first.mpq /tmp/v3-patch-second.mpq
cmp /tmp/v3-patch-first.mpq fixtures/mpq-v3-features-patch.mpq
sha256sum /tmp/v3-patch-first.mpq
```

### Regression checks

From the test directory, exercise committed contents, MPQE composition,
independent signatures/HM3W behavior, and patch materialization without
refresh switches:

```sh
./test-fixtures
./test-mpqe
./test-signature
./test-patch-reader
```

Do not copy regenerated binaries back to the live checkout without reviewing
the intended change and verifying reproducibility and checksums.
