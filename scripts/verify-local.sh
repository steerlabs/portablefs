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

# 1. Cross-platform compile. Linux releases are static CGO-disabled binaries.
# Darwin helpers call Foundation's app-group API through cgo; only a native
# macOS build can compile and link that product boundary. A Linux host still
# compiles the deliberate Darwin !cgo refusal stub, but labels it honestly —
# CI's macOS lane is the required Foundation proof.
case "$(uname -s)" in
  Darwin)
    step "build (Darwin Foundation/cgo, Linux static)"
    CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...
    CGO_ENABLED=0 GOOS=linux go -C vcs build ./...

    step "vet (Darwin Foundation/cgo, Linux static)"
    CGO_ENABLED=1 GOOS=darwin go -C vcs vet ./...
    CGO_ENABLED=0 GOOS=linux go -C vcs vet ./...
    ;;
  Linux)
    step "build (Linux static, Darwin fail-closed !cgo stub)"
    CGO_ENABLED=0 GOOS=linux go -C vcs build ./...
    CGO_ENABLED=0 GOOS=darwin go -C vcs build ./...

    step "vet (Linux static, Darwin fail-closed !cgo stub)"
    CGO_ENABLED=0 GOOS=linux go -C vcs vet ./...
    CGO_ENABLED=0 GOOS=darwin go -C vcs vet ./...
    ;;
  *)
    echo "unsupported verification host: $(uname -s)" >&2
    exit 1
    ;;
esac

# 2. and 3. The Go suites run natively — the tests exercise real syscalls,
# sockets and mounts, so they are only meaningful on the host platform.
step "go suite (native)"
go -C vcs test ./...

step "go race suite (native)"
go -C vcs test -race ./...

# 4. The Swift suite. Explicit serialization is REQUIRED and not a performance
# knob: Swift Testing may run the whole corpus concurrently even when SwiftPM
# is given one worker. Several tests bind shared process resources and exercise
# hard protocol deadlines, so concurrent cases can starve one another and turn
# one timeout into a mock-daemon/socket cascade. Skipped, loudly, when no Swift
# toolchain is present (a Linux runner); the macOS CI job always runs it.
step "swift suite (PortableFSKit)"
if command -v swift >/dev/null 2>&1; then
  swift test --package-path swift/PortableFSKit --no-parallel
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
# cache, pfslocal.proto's prose refers to the retired fsproto wire, and Go
# comments legitimately explain "no fallback to the retired clientcore engine"
# — so package terms are matched as import paths, which is what resurrection
# actually looks like.
#
# Excluded: docs/ and CHANGELOG.md (history is supposed to name the thing it
# replaced), this script, and scripts/package-manager-matrix.sh, which really
# does drive pnpm as one of the package managers under test.
step "stale architecture scan"
if rg --hidden -n \
  -e 'JournalRecord\b' \
  -e '\bremotejournal\b' \
  -e 'internal/clientcore\b' \
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
