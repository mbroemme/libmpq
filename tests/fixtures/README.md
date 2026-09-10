# MPQ regression fixtures

`mpq-v1-features.mpq` and `mpq-v2-features.mpq` are deterministic archives
created with libmpq. They share the feature descriptions and payloads, with
an additional LZMA member in the v2 archive.

Both archives also contain `(attributes)` with payload version 100. The v1
fixture selects CRC32, FILETIME, and MD5 (flags `0x07`); v2 additionally
selects PATCH_BIT (`0x0f`), with every patch bit zero. This flag difference
tests optional arrays, not an archive-version restriction. Both use 32
physical block-table entries, including zero-filled unused rows. The
attributes payloads are 904 and 908 bytes, respectively.
Creation selects these arrays through the dedicated options.attributes mask,
not archive creation flags. Any nonzero combination creates one (attributes)
file and consumes one reserved slot.
The v1 writer reserves 16 bytes after its header before the hash table when
attributes are enabled. This avoids StormLib's malformed-map heuristic,
which otherwise skips attributes when a table starts exactly at header end.

User entries have FILETIME `132537600000000000 + index * 10000000` in insertion
order. The generated listfile has its computed checksums and FILETIME zero;
the attributes entry has all values zero to avoid self-reference. Checksums
cover the original source bytes. Consequently the lossy WAVE members' stored
CRC32/MD5 need not match their decoded samples. `tests/test-mpq-fixtures.c`
contains fixed source checksums independently calculated using Python
`zlib`/`hashlib`.

Every nonempty sectorized compressed or imploded entry also carries sector
Adler-32 checksums: 13 entries in v1 and 14 in v2, including the compressed
`(attributes)` file. This includes PKWARE, encrypted compressed text, and both
WAVE members. Raw `overview.txt` and the single-unit `(listfile)` do not have
sector checksum tables. Sectorized entries can have just one sector; they
are distinct from single-unit storage.

Each checksum covers packed sector bytes before file encryption. The offset
table has one extra terminal entry, and the checksum table follows the sector
data without encryption. These fixtures use raw little-endian checksum words;
their small tables do not benefit from compression. Tests assert the CRC flag,
the extra offset, nonzero checksum values, and successful explicit sector
verification, including WAVE sectors whose file CRC32/MD5 may differ after
lossy decoding. The MPQE fixtures wrap the same updated archive bytes.

Tests use these exact checked-in MPQ and MPQE archives without regenerating
them. Archive and extracted-payload hashes in the tests pin their contents.

Both formats also contain `sparse.txt`, `sparse-zlib.txt`, and
`sparse-bzip2.txt`, using serialized methods `0x20`, `0x22`, and `0x30`.
These are genuine UTF-32LE text files, not UTF-8 text with padding. Each
starts with the BOM `FF FE 00 00`, followed by this line repeated 16 times
with LF endings, encoded as UTF-32LE:

```text
This text uses SPARSE compression and decompression.
```

ASCII characters in UTF-32LE supply three zero bytes each. Both stages of
the combined methods actually reduce the payload; regression tests inspect
the stored method bytes to prevent unnoticed raw or single-stage fallback.
Extraction preserves UTF-32LE bytes. Use an editor supporting that encoding
or `iconv -f UTF-32 -t UTF-8 sparse.txt` to display the text.

The three SPARSE entries follow `wave-stereo.wav` and precede the v2-only
`lzma.txt`. They use COMPRESS with identical first/next masks of `0x20`,
`0x22`, and `0x30`, respectively, and 4096-byte sectors. Tests compare the
complete decrypted MPQE stream against its raw MPQ counterpart.

The existing v2 MPQ and MPQE fixtures illustrate EXTENDED writer compression:
`huffman.txt` uses standalone Huffman and `chain.txt` uses Huffman + zlib.
These methods remain readable by libmpq but may not be accepted by StormLib's
v2 reader. They were created with `LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED`;
STANDARD v2 creation rejects these selections.

The archives contain `.txt` fixtures for raw storage, PKWARE implode, masked
Huffman, zlib, PKWARE, bzip2, LZMA in the v2 fixture, chained compression,
and encrypted compression. Codec fixture text is deliberately repeated and
compressible so it is stored using its advertised codec rather than raw
fallback.

`wave-mono.wav` and `wave-stereo.wav` contain deterministic mono and stereo
PCM16 audio. They are playable RIFF/WAVE files after extraction, with
7000 sample frames at 22050 Hz, one or two channels, and
little-endian interleaved samples. Their original sizes are 14044 and
28044 bytes, spanning four and seven 4096-byte sectors respectively.

The first sector uses zlib (`0x02`) and remains byte-exact, including the
44-byte WAVE header. Every later sector, including the final partial one,
uses Huffman + mono ADPCM (`0x41`) or Huffman + stereo ADPCM (`0x81`).
These methods are allowed by STANDARD in both versions. The archives
still use EXTENDED for their existing Huffman/chain text examples.

The source waveform matches `make_wave(7000, channels)` in
`tests/test-mpq-wave.c`: for frame `i`, let `phase = (i * 17) % 4096` and
`base = phase < 2048 ? phase - 1024 : 3072 - phase`. The left/mono sample
is `base * 24`; the right sample adds 1800. A standard 44-byte PCM header
precedes the samples. The members use COMPRESS with first mask `0x02` and
next mask `0x41` or `0x81`. Mono then stereo follow `encrypted-compress.txt`
and precede the SPARSE entries.

ADPCM is lossy, so extracted samples after the first sector differ from
the source waveform. Tests verify the stored method of every sector,
the exact first sector, and mean absolute sample error below 6000 with
maximum error below 16000. The MPQE fixtures contain the corresponding
fully encrypted archives and extract the same decoded WAVE bytes.

`pkware.txt` and `implode.txt` each contain their descriptive sentence and
newline repeated 32 times, without single-byte padding runs. They exercise
general PKWARE length/distance matches for masked COMPRESS and standalone
implode storage.

The descriptions inside the archives document archive creation and
extraction, supported features, encryption ordering, standalone versus masked
PKWARE, and valid compression chains.

`mpq-v1-features.mpqe` and `mpq-v2-features.mpqe` are the corresponding full
MPQE-encrypted byte streams. They use the deliberately non-secret 32-byte test
authentication code `LIBMPQ-MPQE-TEST-AUTH-CODE-00001`. Each 64-byte logical
chunk, including the final partial physical chunk, is transformed separately;
only the physical bytes are stored. These fixtures are public interoperability
vectors for MPQE stream implementations and are not installer credentials.

`mpq-v2-features.mpq` and `mpq-v2-features.mpqe` additionally contain
`lzma.txt`, stored using MPQ method `0x12`. Its text describes LZMA as an
exclusive MPQ compression method and is repeated 32 times to prevent raw
fallback, so both raw and MPQE fixture paths exercise the same LZMA member.
