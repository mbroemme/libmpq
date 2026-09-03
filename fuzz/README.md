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
fuzz/fuzz-mpqe-open -max_total_time=60 /tmp/libmpq-fuzz-corpus/mpqe-open
fuzz/fuzz-file-read -max_total_time=60 /tmp/libmpq-fuzz-corpus/file-read
fuzz/fuzz-writer-roundtrip -max_total_time=60 /tmp/libmpq-fuzz-corpus/writer-roundtrip
fuzz/fuzz-encrypted-archive -max_total_time=60 /tmp/libmpq-fuzz-corpus/encrypted-archive
fuzz/fuzz-sector-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/sector-decode
fuzz/fuzz-pkware-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/pkware-decode
fuzz/fuzz-huffman-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/huffman-decode
fuzz/fuzz-zlib-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/zlib-decode
fuzz/fuzz-bzip2-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/bzip2-decode
fuzz/fuzz-wave-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/wave-decode
```

`fuzz-archive-open` writes each input to a temporary file and exercises both
direct and embedded-header archive parsing. `fuzz-mpqe-open` uses the public,
non-secret MPQE v1/v2 fixtures and authentication code to exercise MPQE chunk
decryption before the contained MPQ parser. `fuzz-file-read` starts from a
valid generated archive and mutates filename and file-index read paths.
`fuzz-writer-roundtrip` creates a bounded v1/v2 archive from fuzzed content,
then reopens and verifies it. `fuzz-encrypted-archive` mutates a valid archive
with encrypted files, hash/block tables, and known-key reads.

`fuzz-sector-decode` remains the multi-codec integration target. The focused
PKWARE, Huffman, zlib, bzip2, and ADPCM WAVE targets use a little-endian
16-bit output-size-minus-one frame and reject output allocations above 64 KiB.
The WAVE frame begins with a mono/stereo selector byte. This keeps malformed
codec state easy to isolate without removing integration coverage.

The corpus generator copies checked-in v1/v2 fixtures and creates structured
v1/v2 headers, table offsets, truncation, oversized-field, encrypted-mutation,
and codec frame inputs. It also replays reviewed seeds from `fuzz/corpus/`.
On failure, CI minimizes crash, leak, and timeout inputs before uploading them
under `minimized/`; if minimization cannot reproduce the failure, it preserves
the original input there. A maintainer must review and commit an accepted seed.
CI never commits untrusted inputs.
