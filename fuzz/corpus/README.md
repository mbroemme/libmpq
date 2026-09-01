# Reviewed fuzz regression seeds

This directory holds minimized, reviewed crash reproducers. The corpus
generator copies them into the matching target directory before adding its
generated baseline inputs, so CI replays every retained seed.

CI automatically minimizes crash, leak, and timeout artifacts. Download its
`minimized/` output, reproduce it locally, and use this command if further
minimization is useful:

```bash
scripts/minimize-fuzz-crash.sh fuzz-archive-open crash-* \
  fuzz/corpus/archive-open/descriptive-name
```

Review the minimized input and its expected behavior before committing it.
CI never commits untrusted fuzz inputs automatically.
