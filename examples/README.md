# credtype examples

Everything here is **synthetic** — the tokens are hand-built to have valid
structure and (where applicable) valid checksums, so credtype has something
real to verify. None of them is a live credential.

- `sample-tokens.txt` — one token per line, one of each recognised family
  (comments and blank lines are ignored by the runner).
- `classify-all.sh` — pipes each token through `credtype --json` and prints a
  compact `id → checksum` summary. A tiny recipe for wiring credtype into a
  pre-commit hook or a triage script.

Run from the repository root:

```bash
cargo build --quiet
alias credtype=target/debug/credtype

# Classify a single token (a fabricated one — credtype flags its bad checksum)
credtype ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# Explain everything credtype can tell you, including alternates
credtype --explain AKIAIOSFODNN7EXAMPLE

# Machine-readable, for scripts
credtype --json 4111111111111111

# Classify every sample and summarise
bash examples/classify-all.sh
```

The `classify-all.sh` output is stable, so it doubles as a quick regression
check while hacking on a detector.
