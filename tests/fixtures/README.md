# MPQ regression fixtures

`mpq-v1-features.mpq` and `mpq-v2-features.mpq` are deterministic archives
created with libmpq. They share the feature descriptions and payloads, with
an additional LZMA member in the v2 archive.

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

To recreate these additions, retain the existing entries and their options,
then add the three SPARSE entries after `wave-adpcm.txt` and before the
v2-only `lzma.txt`. Use COMPRESS, with identical first/next masks of `0x20`,
`0x22`, and `0x30`, respectively. Preserve the existing 4096-byte sectors
and file-table capacity, enable listfile creation and EXTENDED policy, and
create the matching MPQE archives with the synthetic code below. Verify
the complete decrypted MPQE stream against its raw MPQ counterpart.

The existing v2 MPQ and MPQE fixtures illustrate EXTENDED writer compression:
`huffman.txt` uses standalone Huffman and `chain.txt` uses Huffman + zlib.
These methods remain readable by libmpq but may not be accepted by StormLib's
v2 reader. Recreating them requires `LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED`;
STANDARD v2 creation rejects these selections.

The archives contain `.txt` fixtures for raw storage, PKWARE implode, masked
Huffman, zlib, PKWARE, bzip2, LZMA in the v2 fixture, chained compression,
and encrypted compression. Codec fixture text is deliberately repeated and
compressible so it is stored using its advertised codec rather than raw
fallback. The `wave-adpcm.txt` entry is only a description of valid 16-bit PCM
WAVE input, mono/stereo IMA ADPCM, and the first-sector lossless requirement.
The dedicated WAVE regression test generates binary input and verifies the
lossy ADPCM path; no binary WAVE payload is stored in these archives.

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
