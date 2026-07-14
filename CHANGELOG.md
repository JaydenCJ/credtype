# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Single-token classifier: `credtype <TOKEN>` identifies one credential by prefix, alphabet and length, then ranks candidates by confidence and checksum verdict, with an entropy-described fallback for unrecognised blobs.
- GitHub token detector with real integrity checking: recomputes the Base62-encoded CRC-32 embedded in classic `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` tokens and reports `valid`/`invalid`; recognises `github_pat_` fine-grained tokens structurally.
- AWS access key ID detector: validates the 4-char type prefix (`AKIA`, `ASIA`, `AROA`, …) and 16-char Base32 body, and decodes the embedded 12-digit AWS account ID.
- JSON Web Token detector: Base64url-decodes header and payload, surfaces `alg`/`typ`/`iss`/`sub`/`exp`, and flags the dangerous `alg=none` (unsigned) case.
- Payment card detector: normalises spaces/dashes, identifies the issuer by IIN range, and validates the Luhn (mod-10) checksum.
- UUID detector: validates the 8-4-4-4-12 layout and reports RFC 4122 / RFC 9562 version and variant, including the nil and max UUIDs.
- Private-key detector: recognises PEM and OpenSSH armour and confirms the `openssh-key-v1` magic after Base64 decode.
- Table-driven vendor detector covering Stripe, Slack, Google, SendGrid, npm, PyPI, GitLab, OpenAI, Anthropic, Shopify, Square, Twilio and DigitalOcean key formats (structural recognition, honestly reported as checksum-absent).
- Output surfaces: human text report, `--json` machine output, `--explain` verbose mode, `--quiet` id-only, and `list` to enumerate recognised families.
- Safety: tokens are redacted by default in all output (`--no-redact` to reveal); JSON never contains the raw secret.
- Scriptable exit codes: `0` recognised (checksum valid/absent), `1` checksum failed, `2` unrecognised, `3` usage error; stdin input via `--stdin` or `-`.
- Zero runtime dependencies (standard library only); fully offline and deterministic.
- Test suite: 79 unit tests, 12 CLI integration tests driving the compiled binary, and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/credtype/releases/tag/v0.1.0
