# libFuzzer targets

Fuzzers are opt-in, non-installed targets and are not part of `make check`.
Run the following commands from a disposable source copy.

## Build and run

Build with Clang and ASan/UBSan, then generate the runtime corpora:

```bash
sh autogen.sh
./configure --enable-fuzzing CC=clang \
  CFLAGS='-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined' \
  LDFLAGS='-fsanitize=address,undefined'
make -j"$(nproc)"
scripts/generate-fuzz-corpus.sh /tmp/libmpq-fuzz-corpus
```

Choose a target suffix and the input limit from the table below:

```bash
target=archive-open
max_len=1048576
fuzz/fuzz-${target} -max_total_time=60 -max_len=${max_len} \
  -rss_limit_mb=1024 -timeout=5 /tmp/libmpq-fuzz-corpus/${target}
```

Every target uses its suffix as the corpus directory name. See
[corpus management](corpus/README.md) for generated inputs and retained seeds.

## Targets and input contracts

Input limits below match CI. Framed lengths are little-endian; decoder
output allocations are capped at 64 KiB unless stated otherwise.

| Subsystem | Targets | Input / behavior | CI input limit |
| --- | --- | --- | --- |
| Archive readers | `fuzz-archive-open`, `fuzz-mpqe-open` | Raw MPQ/MPQE bytes; direct/embedded opening and authenticated MPQE chunk decoding | 1 MiB |
| Encrypted archives | `fuzz-encrypted-archive` | Mutations of a valid encrypted archive, including hash/block tables and known-key reads | 1 MiB |
| File API | `fuzz-file-read` | Names/index selectors against a generated valid archive; names capped at 255 bytes | 64 KiB |
| Writer API | `fuzz-writer-roundtrip` | Three selector bytes for archive options, file storage and sector size, then payload; creates/reopens/verifies v1/v2/v3/v4 MPQ or MPQE | 64 KiB |
| Attributes | `fuzz-attributes` | Two count/self selector bytes, then serialized attributes; at most 32 rows | 4 KiB |
| Extended tables | `fuzz-ext-table` | Decoded HET/BET wire bytes, bypassing encryption; envelope/geometry, bounded probing, records, flags, NameHash2 and canonical entries | 1 MiB |
| Patches | `fuzz-patch-apply` | `uint16_t` base-length selector modulo `input_size - 1`, then base and PTCH bytes; prefix parsing and COPY/BSD0 application | 8 KiB |
| Sector integration | `fuzz-sector-decode` | Mode/version byte, `uint16_t` output-size-minus-one, then sector data; PKWARE or multi-codec decoding with v1/v2 semantics | 128 KiB |
| Focused codecs | `fuzz-pkware-decode`, `fuzz-huffman-decode`, `fuzz-zlib-decode`, `fuzz-bzip2-decode`, `fuzz-lzma-decode`, `fuzz-sparse-decode` | `uint16_t` output-size-minus-one, then codec data; LZMA uses MPQ multi-compression framing with v2 semantics | 128 KiB |
| ADPCM | `fuzz-wave-decode` | Mono/stereo selector byte, `uint16_t` output-size-minus-one, then WAVE codec data | 128 KiB |

Archive-open member reads require both packed and unpacked sizes at most
64 KiB: even small stream reads may cache a whole single-unit member.
Patch members use public PTCH reads with a separate 64 KiB payload cap.
Patch-apply caps declared target and decoded-transform sizes at 64 KiB.
Encrypted-archive extraction permits up to 1 MiB of output.

## CI

[The fuzz workflow](../.github/workflows/fuzz.yml) shares a bounded time budget
across all 16 targets, with the limits above, a 1024 MiB RSS limit and a
five-second input timeout. It runs ASan/UBSan with leak detection and uploads
failure artifacts. Reproduction, minimization and seed retention are documented
in the corpus guide; CI never adds inputs to the repository automatically.
