#!/usr/bin/env bash
# verify-local.sh — the repository's single local merge gate.
#
# PortableFS is a two-language tree: the Go data plane under vcs/ and the Swift
# FSKit/app package under swift/PortableFSKit. There is no build system above
# them and no package manager to install: this script is the gate, and it is
# plain bash so that it runs identically on a developer Mac and on a Linux CI
# runner.
#
# Run it from anywhere; it operates on the repository root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { printf '\n== %s ==\n' "$1"; }

# 1. Cross-platform compile. The daemon, the mount clients and the frontend
# adapters all carry per-GOOS files, so building only the host platform hides
# breakage on the other one until a release job runs. Both targets are built
# before anything is executed: a compile error should surface in seconds.
step "build (GOOS=darwin, GOOS=linux)"
GOOS=darwin go -C vcs build ./...
GOOS=linux go -C vcs build ./...

step "vet (GOOS=darwin, GOOS=linux)"
GOOS=darwin go -C vcs vet ./...
GOOS=linux go -C vcs vet ./...

# 2. and 3. The Go suites run natively — the tests exercise real syscalls,
# sockets and mounts, so they are only meaningful on the host platform.
step "go suite (native)"
go -C vcs test ./...

step "go race suite (native)"
go -C vcs test -race ./...

# 4. The Swift suite. --num-workers 1 is REQUIRED and not a performance knob:
# several tests bind fixed per-process resources (sockets, mount points, the
# shared app-group container), and multiple SwiftPM workers running them
# concurrently deadlock rather than fail. Skipped, loudly, when no Swift
# toolchain is present (a Linux runner); the macOS CI job always runs it.
step "swift suite (PortableFSKit)"
if command -v swift >/dev/null 2>&1; then
  swift test --package-path swift/PortableFSKit --parallel --num-workers 1
else
  echo "SKIP: no swift toolchain on this host; the macOS CI job covers this suite"
fi

# 5. Release-trust policy. Both checkers are dependency-free single-file node
# programs (the repository carries no JavaScript packages); they read the
# installer, the workflows and .goreleaser.yaml as text.
step "release trust policy"
if [ -f scripts/install.sh ]; then
  sh -n scripts/install.sh
fi
if [ -f scripts/check-workflow-pins.mjs ]; then
  node scripts/check-workflow-pins.mjs .github/workflows
fi
if [ -f scripts/check-install-release-trust.mjs ]; then
  node scripts/check-install-release-trust.mjs
fi

# 6. Stale-architecture scan. v3 is the direct-store system: a Go data plane
# addressing an XFS-backed authority, with the FSKit frontend on top. The
# journal-era v2 architecture (a remote append-only journal, a TypeScript
# control plane, and the client/writeback/history stack layered on them) was
# deleted wholesale. These identifiers are that architecture's actual API and
# package surface, so a match means it is growing back rather than that a
# comment mentions history.
#
# The package identifiers are matched as import paths (internal/<pkg>), not as
# bare words: "writeback" and "fsproto" are also ordinary nouns in the current
# system's vocabulary — pfsbench has a -writeback flag for the kernel writeback
# cache, and pfslocal.proto's prose refers to the retired fsproto wire — and a
# bare-word scan would fail on those forever.
#
# Excluded: docs/ and CHANGELOG.md (history is supposed to name the thing it
# replaced), this script, and scripts/package-manager-matrix.sh, which really
# does drive pnpm as one of the package managers under test.
step "stale architecture scan"
if rg --hidden -n \
  -e 'JournalRecord\b' \
  -e '\bremotejournal\b' \
  -e '\bclientcore\b' \
  -e 'internal/fsproto\b' \
  -e 'internal/writeback\b' \
  -e '\bhistworker\b' \
  -e '\bpfj3\b' \
  -e 'volume-api' \
  -e 'authority-manager' \
  -e '\bpnpm\b' \
  . \
  -g '!.git' \
  -g '!docs' \
  -g '!CHANGELOG.md' \
  -g '!scripts/verify-local.sh' \
  -g '!scripts/package-manager-matrix.sh'
then
  echo "stale v2 (journal-era) references found" >&2
  exit 1
fi

echo
echo "verify-local: ok"
