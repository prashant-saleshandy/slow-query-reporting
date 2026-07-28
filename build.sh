#!/usr/bin/env bash
# Rebuild the fingerprinter binary using the local Go toolchain in .toolchain/.
# Only needed after editing the Go sources under fp/.
set -euo pipefail
cd "$(dirname "$0")"

export GOROOT="$PWD/.toolchain/go"
export PATH="$GOROOT/bin:$PATH"
export GOFLAGS=-mod=mod
export GOTOOLCHAIN=auto   # Vitess requires a newer Go; fetched automatically

cd fp
go build -o slowquery-fingerprint .
echo "Built fp/slowquery-fingerprint"
