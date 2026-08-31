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

Run a bounded campaign for each target:

```bash
fuzz/fuzz-archive-open -max_total_time=60 /tmp/libmpq-fuzz-corpus/archive-open
fuzz/fuzz-sector-decode -max_total_time=60 /tmp/libmpq-fuzz-corpus/sector-decode
```

`fuzz-archive-open` writes each input to a temporary file and exercises both
direct and embedded-header archive parsing. `fuzz-sector-decode` consumes a
three-byte frame: a mode byte (`0` for multi-compression, `1` for standalone
PKWARE), a little-endian 16-bit output size minus one, and a sector payload.

The corpus generator copies the checked-in v1/v2 fixtures and creates minimal
v1/v2 and embedded-header inputs plus sector mask/truncation inputs. Preserve
new minimized crash reproducers only after review; CI never updates a corpus.
