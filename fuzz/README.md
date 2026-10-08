# libFuzzer targets

The fuzzers are opt-in and do not change ordinary library or release builds.
Build them with Clang and sanitizers:

```bash
sh autogen.sh
./configure --enable-fuzzing CC=clang \
  CFLAGS='-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined' \
  LDFLAGS='-fsanitize=address,undefined'
make -j"$(nproc)"
scripts/generate-fuzz-corpus.sh /tmp/libmpq-fuzz-corpus
```

Run bounded campaigns for the archive, API, and codec targets:

```bash
fuzz/fuzz-archive-open -max_total_time=60 /tmp/libmpq-fuzz-corpus/archive-open
fuzz/fuzz-attributes -max_total_time=60 /tmp/libmpq-fuzz-corpus/attributes
fuzz/fuzz-patch-apply -max_total_time=60 /tmp/libmpq-fuzz-corpus/patch-apply
fuzz/fuzz-mpqe-open -max_total_time=60 /tmp/libmpq-fuzz-corpus/mpqe-open
fuzz/fuzz-file-read -max_total_time=60 /tmp/libmpq-fuzz-corpus/file-read
fuzz/fuzz-writer-roundtrip -max_total_time=60 /tmp/libmpq-fuzz-corpus/writer-roundtrip
fuzz/fuzz-encrypted-archive -max_total_time=60 /tmp/libmpq-fuzz-corpus/encrypted-archive
fuzz/fuzz-sector-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/sector-decode
fuzz/fuzz-ext-table -max_total_time=60 /tmp/libmpq-fuzz-corpus/ext-table
fuzz/fuzz-pkware-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/pkware-decode
fuzz/fuzz-huffman-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/huffman-decode
fuzz/fuzz-zlib-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/zlib-decode
fuzz/fuzz-bzip2-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/bzip2-decode
fuzz/fuzz-lzma-decode -max_total_time=60 \
    /tmp/libmpq-fuzz-corpus/lzma-decode
fuzz/fuzz-sparse-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/sparse-decode
fuzz/fuzz-wave-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/wave-decode
```

`fuzz-archive-open` writes each input to a temporary file and exercises
direct/embedded v3 loading through the normal archive reader. The synthetic v3
seed also reaches HET lookup and a bounded stream read. `fuzz-ext-table` accepts
already-decoded bytes so encryption does not obstruct envelope/HET/BET geometry,
bounded probing, packed-record, flags, NameHash2, and canonical-entry fuzzing.

The extra stream read is bounded by both packed and unpacked metadata, because
single-unit caching can require a full member allocation even for a small read.
`fuzz-mpqe-open` uses the public,
non-secret synthetic MPQE v1/v2/v3 fixtures and authentication code to exercise
MPQE chunk decryption before the contained MPQ parser. `fuzz-file-read` starts from a
valid generated archive and mutates filename and file-index read paths.
`fuzz-writer-roundtrip` creates a bounded v1/v2 archive from fuzzed content,
then reopens and verifies it. `fuzz-encrypted-archive` mutates a valid archive
with encrypted files, hash/block tables, and known-key reads.

`fuzz-patch-apply` uses a bounded two-byte frame split into base and patch
bytes, and exercises private patch-prefix parsing and PTCH/COPY/BSD0
application. It caps declared output and decoded-stream sizes before patch
application.

`fuzz-sector-decode` remains the multi-codec integration target. The focused
PKWARE, Huffman, zlib, bzip2, LZMA, SPARSE, and ADPCM WAVE targets use a
little-endian 16-bit output-size-minus-one frame and reject output allocations
above 64 KiB.
The WAVE frame begins with a mono/stereo selector byte. This keeps malformed
codec state easy to isolate without removing integration coverage.

The corpus generator copies checked-in synthetic v1/v2/v3 fixtures and creates
structured v1/v2 headers, table offsets, truncation, oversized-field,
encrypted-mutation, and codec frame inputs. It also replays reviewed seeds from
`fuzz/corpus/`.
On failure, CI minimizes crash, leak, and timeout inputs before uploading them
under `minimized/`; if minimization cannot reproduce the failure, it preserves
the original input there. A maintainer must review and commit an accepted seed.
CI never commits untrusted inputs.
