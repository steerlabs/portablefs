#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${GOOS:=$(go env GOOS)}"
: "${GOARCH:=$(go env GOARCH)}"

echo "building PortableFS binaries for ${GOOS}/${GOARCH}"
GOOS="$GOOS" GOARCH="$GOARCH" go build -C "$ROOT/vcs" -o "$ROOT/vcs-bin" ./cmd/vcs
GOOS="$GOOS" GOARCH="$GOARCH" go build -C "$ROOT/vcs" -o "$ROOT/portablefsd-bin" ./cmd/portablefsd
