#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PKG="$ROOT/swift/PortableFSKit"
OUT="$PKG/Sources/PortableFSKit/Generated"
PROTO="$ROOT/pfslocal/pfslocal.proto"
PROTOC="${PROTOC:-protoc}"

if ! command -v "$PROTOC" >/dev/null 2>&1; then
  echo "error: protoc not found. Install protobuf or set PROTOC=/path/to/protoc." >&2
  exit 1
fi

if ! command -v protoc-gen-swift >/dev/null 2>&1; then
  echo "error: protoc-gen-swift not found. Install apple/swift-protobuf's plugin and put it on PATH." >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
"$PROTOC" -I "$ROOT" --swift_out "$OUT" --swift_opt=Visibility=Public "$PROTO"
