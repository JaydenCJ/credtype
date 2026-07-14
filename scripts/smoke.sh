#!/usr/bin/env bash
# Smoke test: builds credtype, then drives the real CLI end to end over every
# validation path — a checksum-valid GitHub token, a tampered one (exit 1), an
# AWS key with account-id decode, an unsigned JWT, a Luhn-valid card, the JSON
# surface, redaction, stdin input, `list`, and the unknown fallback (exit 2).
# Self-contained: no network, temp dir only, idempotent. Prints "SMOKE OK".
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN="$PWD/target/debug/credtype"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/credtype-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- 1. version / help / list sanity -----------------------------------------
"$BIN" --version | grep -q '^credtype 0\.1\.0$' || fail "--version mismatch"
"$BIN" --help | grep -q 'EXIT CODES:' || fail "--help missing sections"
"$BIN" list | grep -q 'payment-card' || fail "list missing payment-card"
"$BIN" list | grep -q 'CRC-32' || fail "list missing checksum summary"
echo "[smoke] version/help/list OK"

# A structurally valid classic GitHub token (never a real secret): the last six
# characters are the Base62-encoded CRC-32 of the 30-char body.
GH_VALID="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"

# --- 2. valid GitHub token: identified, checksum OK, exit 0 -------------------
OUT=$("$BIN" "$GH_VALID")
echo "$OUT" | grep -q 'GitHub personal access token' || fail "github token not identified"
echo "$OUT" | grep -q '\[checksum OK\]' || fail "github checksum not verified"
echo "$OUT" | grep -q "$GH_VALID" && fail "raw token leaked in default output"
"$BIN" "$GH_VALID" >/dev/null; [ $? -eq 0 ] || fail "valid token did not exit 0"
echo "[smoke] valid GitHub token OK (redacted, exit 0)"

# --- 3. tampered GitHub token: checksum FAILED, exit 1 -----------------------
GH_BAD="ghp_XAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPlr"   # first body char flipped
set +e
OUT=$("$BIN" "$GH_BAD"); CODE=$?
set -e
echo "$OUT" | grep -q '\[checksum FAILED\]' || fail "tampered token not flagged"
[ "$CODE" -eq 1 ] || fail "tampered token exit $CODE (want 1)"
echo "[smoke] tampered GitHub token OK (exit 1)"

# --- 4. AWS access key: structure + account-id decode ------------------------
"$BIN" --json AKIAIOSFODNN7EXAMPLE > "$WORK/aws.json"
grep -q '"id":"aws-access-key-id"' "$WORK/aws.json" || fail "aws key not identified"
grep -q '"account_id":"[0-9]\{12\}"' "$WORK/aws.json" || fail "aws account id not decoded"
echo "[smoke] AWS key account-id decode OK"

# --- 5. unsigned JWT: alg=none flagged, exit 1 -------------------------------
set +e
OUT=$("$BIN" 'eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.'); CODE=$?
set -e
echo "$OUT" | grep -q 'UNSIGNED' || fail "alg=none JWT not flagged"
[ "$CODE" -eq 1 ] || fail "alg=none JWT exit $CODE (want 1)"
echo "[smoke] unsigned JWT OK (exit 1)"

# --- 6. payment card: Luhn valid vs invalid ----------------------------------
"$BIN" 4111111111111111 | grep -q '\[checksum OK\]' || fail "valid card not accepted"
set +e
"$BIN" 4111111111111112 >/dev/null; CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "invalid card exit $CODE (want 1)"
echo "[smoke] payment-card Luhn OK"

# --- 7. stdin input + JSON never leaks the raw token -------------------------
printf '%s\n' "$GH_VALID" | "$BIN" --stdin | grep -q '\[checksum OK\]' \
  || fail "stdin path did not validate"
"$BIN" --json "$GH_VALID" > "$WORK/gh.json"
grep -q "$GH_VALID" "$WORK/gh.json" && fail "raw token leaked in JSON"
grep -q '"checksum":"valid"' "$WORK/gh.json" || fail "JSON missing checksum verdict"
echo "[smoke] stdin + JSON redaction OK"

# --- 8. unknown input: fallback, exit 2 --------------------------------------
set +e
OUT=$("$BIN" "this is definitely not a token"); CODE=$?
set -e
echo "$OUT" | grep -q 'Unrecognised' || fail "unknown token not reported as unrecognised"
[ "$CODE" -eq 2 ] || fail "unknown token exit $CODE (want 2)"
echo "[smoke] unknown fallback OK (exit 2)"

# --- 9. usage error: exit 3 --------------------------------------------------
set +e
"$BIN" --bogus-flag >/dev/null 2>&1; CODE=$?
set -e
[ "$CODE" -eq 3 ] || fail "bad flag exit $CODE (want 3)"
echo "[smoke] usage error OK (exit 3)"

echo "SMOKE OK"
