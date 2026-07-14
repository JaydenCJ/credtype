#!/usr/bin/env bash
# Classify every token in sample-tokens.txt and print a compact
# "id -> checksum (confidence)" summary. Offline, deterministic.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN="${CREDTYPE_BIN:-target/debug/credtype}"
[ -x "$BIN" ] || { echo "build first: cargo build" >&2; exit 1; }

printf '%-26s %-10s %s\n' "ID" "CHECKSUM" "CONFIDENCE"
printf '%-26s %-10s %s\n' "--" "--------" "----------"

while IFS= read -r line; do
  # Skip comments and blank lines.
  case "$line" in ''|\#*) continue;; esac

  # credtype exits non-zero for failed-checksum tokens (e.g. alg=none); that is
  # expected here, so don't let `set -e` abort the loop.
  json=$("$BIN" --json "$line" || true)
  # Pull the first occurrence of each key (the top-level "best" object) with
  # grep -o, no jq dependency. grep may exit 1 on no match, so guard with `|| true`.
  first() { printf '%s' "$json" | grep -o "\"$1\":\"[^\"]*\"" | head -n1 | sed 's/.*:"//; s/"$//'; }
  id=$(first id || true)
  chk=$(first checksum || true)
  conf=$(first confidence || true)
  printf '%-26s %-10s %s\n' "$id" "$chk" "$conf"
done < examples/sample-tokens.txt
