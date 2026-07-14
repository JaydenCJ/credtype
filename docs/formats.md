# Token formats and what credtype checks

credtype makes a sharp distinction between three verdicts:

- **valid** — the token embeds a self-contained checksum that credtype
  recomputed and matched.
- **invalid** — it embeds such a checksum and it did **not** match (truncated,
  mistyped, or fabricated), or it is structurally unsound (e.g. `alg=none`).
- **absent** — the family defines no checksum credtype can verify offline, so
  credtype only confirms the *structure* (prefix, alphabet, length) and decodes
  what it can.

This document records the checks per family. Everything is offline: no family
requires a network call, and credtype never makes one.

## GitHub tokens — CRC-32 (checked)

Classic GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) are:

```
<prefix>  <30 Base62 body chars>  <6 Base62 checksum chars>
```

The last six characters are the CRC-32 (IEEE, polynomial `0xEDB88320`) of the
30-char body, encoded in Base62 (`0-9A-Za-z`). credtype recomputes the CRC-32
and compares it to the embedded value. A single mistyped character in the body
breaks the match — which is exactly what makes this a useful "is it real?"
signal. Fine-grained `github_pat_` tokens use a longer multi-segment layout with
no single self-contained checksum, so they are recognised structurally only.

## AWS access key IDs — account-id decode (structural)

An access key ID is a 4-character type prefix (`AKIA`, `ASIA`, `AROA`, `AIDA`,
…) followed by 16 Base32 (`A-Z2-7`) characters. Those characters are not
random: the first six bytes of the Base32-decoded body encode the AWS account
ID. credtype decodes it with the documented transform — take the first six
decoded bytes as a big-endian integer `z`, then `(z & 0x7fffffffff80) >> 7` — and
prints the 12-digit account ID. There is no CRC to check, so the verdict is
`absent`, but a well-formed account-id decode is a strong structural signal.

## JSON Web Tokens — decode + `alg=none` flag

A compact JWT is three (JWS) or five (JWE) Base64url segments separated by dots.
credtype decodes the header and payload, confirms they are JSON objects, and
surfaces `alg`, `typ`, `iss`, `sub` and `exp`. The signature cannot be verified
without the signing key, so the verdict is `absent` — **except** `alg=none`,
which means the token is unsigned; credtype reports that as `invalid` and exits
non-zero so scripts notice.

## Payment cards — Luhn (checked)

A 12–19 digit primary account number (spaces and dashes tolerated). credtype
identifies the issuer from the IIN range (Visa, Mastercard including the 2-series
range, Amex, Discover, Diners, JCB, UnionPay) and validates the Luhn mod-10
check digit — a real, self-contained checksum, so the verdict is `valid` or
`invalid`.

## UUIDs — version + variant (structural)

The `8-4-4-4-12` hex layout, with the RFC 4122 / RFC 9562 version nibble and
variant bits reported. The nil and max UUIDs are named. UUIDs carry no checksum,
so the verdict is `absent`.

## Private keys — armour + OpenSSH magic

PEM (`-----BEGIN … PRIVATE KEY-----`) and OpenSSH armour is recognised by kind.
For OpenSSH keys credtype Base64-decodes the body and confirms the
`openssh-key-v1` magic, a genuine structural self-check (`valid`); classic PEM
bodies are opaque DER, so their verdict is `absent`.

## Vendor keys — prefix + alphabet + length (structural)

Stripe, Slack, Google, SendGrid, npm, PyPI, GitLab, OpenAI, Anthropic, Shopify,
Square, Twilio and DigitalOcean keys are recognised by their distinctive prefix,
character set and length. None publishes a self-contained checksum, so credtype
reports `absent` and never pretends otherwise.
