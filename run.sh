#!/usr/bin/env bash
# Generate report.md from report.json using the AST-based fingerprinter.
#
#   ./run.sh            # count >= 40 (default)
#   ./run.sh 10         # count >= 10
#
# Uses the prebuilt static binary (no Go toolchain needed at runtime).
# To rebuild the binary after editing the Go sources, see ./build.sh.
set -euo pipefail
cd "$(dirname "$0")"

MIN_COUNT="${1:-40}"
BIN="fp/slowquery-fingerprint"

if [[ ! -x "$BIN" ]]; then
  echo "Binary $BIN not found — run ./build.sh first." >&2
  exit 1
fi

"$BIN" report.json report.md "$MIN_COUNT"
