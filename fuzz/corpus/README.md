# Fuzz corpus management

Checked-in files are reviewed regression seeds. Generated runtime corpora
combine these seeds with deterministic baseline inputs and belong outside
the source tree, normally under `/tmp`.

| Retained seed | Purpose |
| --- | --- |
| `writer-roundtrip/pkware-short-runs.txt` | Writer round-trip regression with short repeated byte runs |

`scripts/generate-fuzz-corpus.sh` first copies this directory into the output,
preserving target subdirectories, then adds synthetic MPQ v1/v2/v3 archives,
the v3 patch archive, MPQE v1/v2/v3 archives, and framed structural/codec
inputs. Generated cases include malformed headers/offsets, truncation,
COPY/BSD0, SPARSE zero runs, clipped literals and oversized lengths, malformed
LZMA headers, and zero-rich SPARSE/combined-codec writer inputs. Fixture
contents, checksums and regeneration belong in
[tests/fixtures/README.md](../../tests/fixtures/README.md). Build/run commands
and input contracts are in [the fuzzing guide](../README.md).

To retain a failure, reproduce it with the matching target, minimize it,
review its expected behavior, and save it under that target's corpus directory.
From the repository root, for a single crash input:

```bash
scripts/minimize-fuzz-crash.sh fuzz-archive-open crash-* \
  fuzz/corpus/archive-open/descriptive-name
```

Use a descriptive name and include the seed in `fuzz/Makefile.am`'s
`EXTRA_DIST` when committing it. CI minimizes crash, leak and timeout artifacts
under `minimized/`; if minimization cannot reproduce a failure, it retains the
original input there. Download and review artifacts before adding them.
CI never commits untrusted inputs automatically.
