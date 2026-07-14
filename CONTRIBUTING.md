# Contributing to credtype

Thanks for your interest in improving credtype. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain). credtype has zero runtime dependencies.

```bash
git clone https://github.com/JaydenCJ/credtype.git
cd credtype
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` drives the compiled CLI end to end over every validation path — a checksum-valid GitHub token, a tampered one, an AWS account-id decode, an unsigned JWT, a Luhn-checked card, JSON output and redaction. It runs offline against a temporary directory, finishes in a couple of seconds, and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. Recognisers live in pure, per-family modules (`github`, `aws`, `jwt`, `card`, `uuid`, `pem`, `vendors`) that are trivial to unit-test; please keep new logic there rather than in the CLI layer.

## Ground rules

- Keep dependencies minimal. credtype is std-only by design; adding a dependency needs a clear justification in the PR description and must not introduce a network path.
- No network calls, ever. credtype validates tokens entirely offline; a checksum that would require a remote call (e.g. a live API probe) is out of scope on purpose.
- Be honest about checksums. A detector reports `valid`/`invalid` only when it recomputes a real, self-contained checksum; otherwise it reports `absent`. Never imply verification you did not perform.
- Never print a raw secret by default. New output paths must go through the redaction helper unless `--no-redact` is set.
- Code comments and doc comments are written in English.

## Adding a token family

Most vendor keys are one row in the `SPECS` table in `src/vendors.rs` (prefix + alphabet + length). Families with a real checksum or a structural decode (like `github`, `aws`, `jwt`) get their own module and register in `src/registry.rs::DETECTORS`. Include test vectors that are synthetic and self-consistent — never a real leaked credential.

## Reporting bugs

Please include the `credtype --version` output, the token *family* and a redacted or synthetic example that reproduces the misclassification, and the `--json` output you got versus what you expected. A synthetic token that triggers the bug is worth a thousand words.

## Security

If you find a security issue (for example a detector that echoes a secret into logs, or a panic on crafted input), please do not open a public issue. Use GitHub's private vulnerability reporting on this repository instead.
