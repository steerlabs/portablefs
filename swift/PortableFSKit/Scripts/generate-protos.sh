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

# Package.swift pins the runtime exactly. Generated code is an executable part
# of that same contract: a plugin newer than the pin can emit runtime APIs the
# pinned package does not have. That is not hypothetical — generating with 1.38
# while the runtime was still pinned to 1.29 emitted the bytecode NameMap and
# broke this package outright, which is why the two move together or not at
# all. Keep the check beside generation so a developer's Homebrew PATH cannot
# silently make an unbuildable or non-reproducible binding.
EXPECTED_SWIFT_PROTOBUF_VERSION="$(
  sed -nE 's/.*swift-protobuf\.git", exact: "([^"]+)".*/\1/p' "$PKG/Package.swift"
)"
if [[ -z "$EXPECTED_SWIFT_PROTOBUF_VERSION" ]]; then
  echo "error: could not read the exact swift-protobuf version from Package.swift." >&2
  exit 1
fi
ACTUAL_SWIFT_PROTOBUF_VERSION="$(protoc-gen-swift --version | awk '{print $2}')"
if [[ "$ACTUAL_SWIFT_PROTOBUF_VERSION" != "$EXPECTED_SWIFT_PROTOBUF_VERSION" ]]; then
  echo "error: protoc-gen-swift $EXPECTED_SWIFT_PROTOBUF_VERSION is required; found $ACTUAL_SWIFT_PROTOBUF_VERSION." >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
"$PROTOC" -I "$ROOT" --swift_out "$OUT" --swift_opt=Visibility=Public "$PROTO"
