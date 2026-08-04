#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

command -v protoc >/dev/null || { echo "protoc is required" >&2; exit 1; }
command -v protoc-gen-go >/dev/null || { echo "protoc-gen-go is required" >&2; exit 1; }

protoc \
  --proto_path=. \
  --go_out=vcs \
  --go_opt=module=github.com/steerlabs/portablefs/vcs \
  proto/authority/v1/authority.proto

