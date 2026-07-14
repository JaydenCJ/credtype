# credtype

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Rust ≥1.75](https://img.shields.io/badge/rust-%E2%89%A51.75-orange)](Cargo.toml) [![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md) [![Tests](https://img.shields.io/badge/tests-91%20passed-brightgreen)](tests/) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**file(1) for secrets: identify and structurally validate one leaked token by prefix, format, and embedded checksum — fully offline.**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/credtype.git && cargo install --path credtype
```

## Why credtype?

You find a token in a log, a `.env`, a pasted snippet, or a bug report, and you need two answers fast: *what is this?* and *is it real, or truncated garbage?* Repository scanners like gitleaks and trufflehog are built for the opposite job — sweeping a whole tree for anything that looks secret-shaped — and they neither classify a single string you hand them nor tell you whether its checksum verifies. credtype is the other tool: point it at exactly one token and it names the family (GitHub PAT, AWS key, JWT, Stripe key, payment card, private key, …) and, where the format embeds a self-contained checksum, recomputes it and tells you `valid` or `invalid`. It is `file(1)` for secrets — one input, one honest answer — with zero dependencies, no network, and no telemetry, so it is safe to run on a credential you would never paste into a website.

|  | credtype | gitleaks | trufflehog |
|---|---|---|---|
| Job | classify + validate one token | scan a repo/tree for secrets | scan a repo/tree for secrets |
| Recomputes embedded checksums | yes (GitHub CRC-32, Luhn, OpenSSH magic) | no | no (offline mode) |
| Structural decode | AWS account id, JWT claims, UUID version | regex match only | regex match only |
| Verifies live keys online | never (offline by design) | no | yes (network calls) |
| Runtime dependencies | none (std-only) | many (Go modules) | many (Go modules) |
| Redacts secrets in output | yes, by default | n/a | n/a |
| Scriptable exit code per verdict | yes (0/1/2/3) | findings count | findings count |

## Features

- **Answers "is it real?", not just "what is it?"** — for formats that carry a self-contained checksum (GitHub's Base62 CRC-32, payment-card Luhn, the OpenSSH `openssh-key-v1` magic) credtype recomputes it and reports `valid`/`invalid`, catching truncated or fabricated tokens.
- **Structural decode where there is no checksum** — it recovers the AWS account id from an access key, the `alg`/`iss`/`exp` claims from a JWT, and the version/variant from a UUID, so "absent checksum" still comes with real evidence.
- **Honest by construction** — a detector only says `valid`/`invalid` when it actually verified a checksum; otherwise it says `absent`. credtype never implies verification it did not perform.
- **Safe to run on real secrets** — tokens are redacted by default in both text and JSON output (`--no-redact` to reveal), and nothing ever leaves the machine: no network, no telemetry, standard library only.
- **Scriptable** — a clear exit code per verdict (`0` valid/absent, `1` checksum failed, `2` unrecognised, `3` usage), `--json` for machines, `--quiet` for one-word output, and `--stdin` for pipes.
- **Broad coverage in a tiny binary** — GitHub, AWS, JWT, payment cards, UUIDs, PEM/OpenSSH keys, and a table of vendor keys (Stripe, Slack, Google, SendGrid, npm, PyPI, GitLab, OpenAI, Anthropic, Shopify, Square, Twilio, DigitalOcean).

## Quickstart

Install (requires Rust 1.75+):

```bash
git clone https://github.com/JaydenCJ/credtype.git && cargo install --path credtype
```

Identify a token and verify its checksum — this fabricated all-`A` token fails it:

```bash
credtype ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Output (the token is redacted by default):

```text
GitHub personal access token (classic)  [checksum FAILED]
  id:         github-pat
  category:   vendor
  confidence: medium
  structure:  valid
  checksum:   INVALID
  token:      ghp_AAAA****************************AAAA (40 chars)
  details:
    checksum: crc32/base62
  note: embedded CRC-32 checksum does NOT verify — truncated, mistyped or fabricated
```

A cloud key is decoded, not just matched; JSON output is one line, secret-free:

```bash
credtype --json AKIAIOSFODNN7EXAMPLE
```

```text
{"input_length":20,"is_fallback":false,"best":{"id":"aws-access-key-id","name":"AWS access key ID","category":"cloud","confidence":"medium","structural_ok":true,"checksum":"absent","length":20,"redacted":"AKIAIOSF********MPLE","details":{"key_type":"long-term IAM user access key","account_id":"581039954779","checksum":"none (structure + account-id decode only)"},"notes":["AWS keys carry no self-contained checksum; validity confirmed structurally"]},"alternates":[]}
```

## Token families

`credtype list` prints the full set. Checksum-validated families are marked; the rest are recognised structurally (prefix, alphabet, length) and honestly reported as checksum-`absent`.

| Family | id | Checksum | What credtype extracts |
|---|---|---|---|
| GitHub token (classic) | `github-pat`, `gho`, `ghu`, `ghs`, `ghr` | CRC-32 (checked) | prefix kind, checksum verdict |
| AWS access key ID | `aws-access-key-id` | none (structural) | key type, 12-digit account id |
| JSON Web Token | `jwt` | `alg=none` flagged | alg, typ, iss, sub, exp |
| Payment card | `payment-card` | Luhn (checked) | issuer (IIN), digit count |
| UUID / GUID | `uuid` | none (structural) | version, variant, nil/max |
| Private key | `pem-*`, `openssh-private` | OpenSSH magic (checked) | armour kind |
| Vendor API keys | `stripe-*`, `slack-token`, `npm-token`, … | none (structural) | prefix, alphabet, length |

## Exit codes

credtype is designed to slot into a `pre-commit` hook or a triage script.

| Code | Meaning |
|---|---|
| `0` | recognised, and the checksum is valid or absent |
| `1` | recognised, but an embedded checksum FAILED |
| `2` | not recognised (generic entropy fallback) |
| `3` | usage error |

## Architecture

```mermaid
flowchart LR
    T[one token] --> R[registry]
    R --> D[detectors: github / aws / jwt / card / uuid / pem / vendors]
    D --> C[checksum: CRC-32 / Luhn / magic]
    D --> S[structural decode: account id / claims / version]
    C --> K[ranked classification]
    S --> K
    R --> F[entropy fallback]
    K --> O[report: text / JSON, redacted]
    F --> O
```

## Roadmap

- [x] v0.1.0: single-token classifier with GitHub CRC-32, AWS account-id decode, JWT decode + `alg=none`, Luhn cards, UUIDs, PEM/OpenSSH, a vendor-key table, redaction, JSON, scriptable exit codes, 91 tests and `scripts/smoke.sh`
- [ ] More checksum-bearing formats (Google `AIza` variants, Azure, GCP service-account key ids)
- [ ] `--batch` mode: classify a file of tokens, summarise counts by family
- [ ] Library API stabilisation and publication to crates.io
- [ ] Optional, explicit `--probe` to test a key against its provider (opt-in, off by default)

See the [open issues](https://github.com/JaydenCJ/credtype/issues) for the full list.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md), start with a [good first issue](https://github.com/JaydenCJ/credtype/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or open a [discussion](https://github.com/JaydenCJ/credtype/discussions). This repository ships no CI; every claim above is verified by local runs of `cargo test` and `scripts/smoke.sh`.

## License

[MIT](LICENSE)
