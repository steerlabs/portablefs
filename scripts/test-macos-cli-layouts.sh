#!/usr/bin/env bash
# Build and exercise each compiled macOS CLI contract independently. No signed
# app, service registration or live mount is created by this native gate.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "SKIP: compiled macOS CLI layout tests require Darwin; the native macOS CI lane runs them"
  exit 0
fi
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_embed_portablefs_tools.py
work="$(mktemp -d "${TMPDIR:-/tmp}/portablefs-cli-layouts.XXXXXX")"
trap 'rm -rf "$work"' EXIT
for variant in production development; do
  tags=
  if [[ "$variant" == development ]]; then
    tags=portablefs_devhost
  fi
  echo "macOS CLI layout: $variant"
  CGO_ENABLED=1 GOOS=darwin go -C vcs build -tags "$tags" -o "$work/portablefs-$variant" ./cmd/portablefs
  CGO_ENABLED=1 GOOS=darwin go -C vcs vet -tags "$tags" ./cmd/portablefs/internal/cli
  CGO_ENABLED=1 GOOS=darwin go -C vcs test -count=1 -tags "$tags" ./cmd/portablefs/internal/cli
  CGO_ENABLED=1 GOOS=darwin go -C vcs test -race -count=1 -tags "$tags" ./cmd/portablefs/internal/cli
done
