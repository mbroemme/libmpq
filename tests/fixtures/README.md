# MPQ regression fixtures

`mpq-v1-features.mpq` and `mpq-v2-features.mpq` are deterministic archives
created with libmpq. They contain the same feature descriptions and payloads,
with only the MPQ archive format version differing.

The archives contain only `.txt` fixtures for raw storage, PKWARE implode,
masked Huffman, zlib, PKWARE, bzip2, chained compression, and encrypted
compression. The `wave-adpcm.txt` description documents valid 16-bit PCM
WAVE input, mono/stereo IMA ADPCM, and the first-sector lossless requirement;
no binary WAVE payload is stored in these text-only regression archives.

The descriptions inside the archives document archive creation and
extraction, supported features, encryption ordering, standalone versus masked
PKWARE, and valid compression chains.

`mpq-v1-features.mpqe` and `mpq-v2-features.mpqe` are the corresponding full
MPQE-encrypted byte streams. They use the deliberately non-secret 32-byte test
authentication code `LIBMPQ-MPQE-TEST-AUTH-CODE-00001`. Each 64-byte logical
chunk, including the final 62-byte physical chunk, is transformed separately;
only the physical bytes are stored. These fixtures are public interoperability
vectors for MPQE stream implementations and are not installer credentials.
