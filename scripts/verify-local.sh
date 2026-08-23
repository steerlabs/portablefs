#!/usr/bin/env bash
# verify-local.sh — the repository's local merge gate.
#
# PortableFS is a two-language tree: the Go data plane under vcs/ and the Swift
# FSKit/app package under swift/PortableFSKit. There is no build system above
# them and no package manager to install: this script is the gate, and it is
# plain bash so that it runs identically on a developer Mac and on a Linux CI
# runner.
#
# It has two modes, and the difference is not cosmetic.
#
#   default   Everything that runs without Docker and without a privileged
#             container: cross-platform build and vet, govulncheck, the native
#             Go suites, the go-fuse reply-ordering seam, the Swift suite on
#             macOS, workflow/release-trust policy, and the architecture scans.
#             It does NOT run either real-mount suite. The closing banner names
#             what it skipped; this mode alone is not merge evidence for a
#             change to the authority, a frontend, or the coherence protocol.
#
#   full      Everything above, plus the two privileged real-mount suites that
#             CI runs on its ubuntu-24.04 lanes:
#               scripts/xfs-fuse-integration.sh    (real XFS + real kernel FUSE)
#               scripts/coherence-matrix-linux.sh  (two real mounts, one volume)
#             Both need a working Docker daemon and free loop devices. On macOS
#             they run inside the Docker VM, which is why this is opt-in rather
#             than the default: the default mode stays fast for macOS-only work.
#
#   bash scripts/verify-local.sh            # default (fast, no Docker)
#   bash scripts/verify-local.sh --full     # + both real-mount suites
#   VERIFY_LOCAL_FULL=1 bash scripts/verify-local.sh   # same as --full
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERIFY_LOCAL_FULL="${VERIFY_LOCAL_FULL:-0}"
for arg in "$@"; do
  case "$arg" in
    --full) VERIFY_LOCAL_FULL=1 ;;
    --help|-h)
      sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "verify-local: unknown argument: $arg (expected --full)" >&2
      exit 2
      ;;
  esac
done

# Login shells initialized by fnm already expose Node.  Non-interactive gate
# runners do not necessarily source that shell setup, so resolve fnm's explicit
# default installation before the release-policy checks need it.
if ! command -v node >/dev/null 2>&1; then
  PFS_FNM_ROOT="${FNM_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/fnm}"
  PFS_NODE_BIN="$PFS_FNM_ROOT/aliases/default/bin/node"
  if [[ -x "$PFS_NODE_BIN" ]]; then
    PATH="$(dirname "$PFS_NODE_BIN"):$PATH"
    export PATH
  fi
fi

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

# 2. The vulnerability gate uses the same exact tool version as CI. Running it
# through `go run` keeps the checker reproducible without installing a global
# executable; the application toolchain itself is pinned by vcs/go.mod.
step "dependency vulnerability gate"
go -C vcs run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

# 3. and 4. The Go suites run natively — the tests exercise real syscalls,
# sockets and mounts, so they are only meaningful on the host platform.
step "go suite (native)"
go -C vcs test ./...

step "go race suite (native)"
go -C vcs test -race ./...

# The maintained go-fuse fork is a nested module, so the suite above does not
# enter it. Protocol 6 retains one stock-FUSE-neutral seam: ReplyWriteLifecycle
# serializes selected physical replies and notifications through writeMu. Gate
# that ordering hook without running the retired private-ABI tests.
step "maintained go-fuse reply ordering seam"
go -C vcs/third_party/go-fuse build ./fuse
go -C vcs/third_party/go-fuse vet ./fuse
go -C vcs/third_party/go-fuse test ./fuse -run 'Test(OrderedReplyLifecycle|UnselectedReply)'
go -C vcs/third_party/go-fuse test -race ./fuse -run 'Test(OrderedReplyLifecycle|UnselectedReply)'

# 5. The Swift suite. On macOS the shared gate uses Xcode's native test runner,
# separately enumerates the complete inventory, and requires the xcresult to
# contain the same unique all-passing set. Other hosts skip this macOS-only
# package loudly; the macOS CI job always runs it.
step "swift suite (PortableFSKit)"
if [[ "$(uname -s)" == Darwin ]]; then
  bash scripts/test-swift-xcode.sh
else
  echo "SKIP: Xcode-native Swift verification requires macOS; the macOS CI job covers this suite"
fi

# 6. Workflow semantics and release-trust policy. actionlint is version-pinned
# exactly like CI and reads .github/actionlint.yaml for the one approved custom
# runner label. The two project checkers are dependency-free single-file node
# programs (the repository carries no JavaScript packages); they read the
# installer, the workflows and .goreleaser.yaml as text.
step "release trust policy"
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.10 .github/workflows/*.yml
if [ -f scripts/install.sh ]; then
  sh -n scripts/install.sh
fi
if [ -f scripts/check-workflow-pins.mjs ]; then
  node scripts/check-workflow-pins.mjs .github/workflows
fi
if [ -f scripts/check-install-release-trust.mjs ]; then
  node scripts/check-install-release-trust.mjs
fi
if [ -f deploy/opensteer/release-inventory.test.mjs ]; then
  node --test deploy/opensteer/release-inventory.test.mjs
fi
if [ -f deploy/files/test_release_registry.py ]; then
  python3 deploy/files/test_release_registry.py
fi

# 7. Stale-architecture scan. v3 is the direct-store system: a Go data plane
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
# replaced), this script, and the two harnesses that really do drive pnpm as
# one of the package managers under test -- scripts/package-manager-matrix.sh
# locally and deploy/opensteer/staging-qualification.sh against live staging.
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
  -g '!scripts/package-manager-matrix.sh' \
  -g '!deploy/opensteer/staging-qualification.sh'
then
  echo "stale v2 (journal-era) references found" >&2
  exit 1
fi

# Protocol 6 has one coherent lease contract. The old non-participant profile
# and both retired namespace-repair models keep their names reserved in the
# source schema (and therefore in generated descriptor bytes), while docs and
# the changelog may describe their retirement. None may re-enter executable
# code, tests, scripts, or configuration.
if rg --hidden -n \
  -e 'CoherenceUncached' \
  -e 'COHERENCE_PROFILE_UNCACHED' \
  -e 'PORTABLEFS_COHERENCE' \
  -e '--coherence uncached' \
  -e 'LOCKLESS_EXPIRATION' \
  -e 'NamespaceRepairLocklessExpiration' \
  -e 'PARENT_EXCLUSIVE' \
  -e 'NamespaceRepairParentExclusive' \
  -e 'blocked_parent_kernel_inos' \
  -e 'BlockedParentKernelInos' \
  . \
  -g '!.git' \
  -g '!docs' \
  -g '!CHANGELOG.md' \
  -g '!proto/authority/v1/authority.proto' \
  -g '!vcs/internal/authoritypb/authority.pb.go' \
  -g '!scripts/verify-local.sh'
then
  echo "retired non-participant coherence profile references found" >&2
  exit 1
fi

# Active product material must describe the protocol-6 stock-FUSE architecture.
# Historical qualification receipts are intentionally outside this list: they
# remain evidence, not a build or runtime dependency. The patch series for the
# retired private ABI is no longer in the tree at all; git history holds it.
# Keeping the input list explicit makes a newly active contract an
# intentional review event rather than silently granting all docs authority.
step "active stock-FUSE contract scan"
if rg -n \
  -e 'portablefs-authority-v5' \
  -e 'authority protocol major `5`' \
  -e '\bCAP_PFS_' \
  -e '\bFUSE_PFS_' \
  -e 'exact patched kernel' \
  -e 'pinned Linux 6\.12\.100' \
  README.md COMPATIBILITY.md \
  docs/architecture.md docs/consistency-model.md docs/failure-modes.md \
  docs/local-dev.md docs/xfs-authority-deployment.md \
  .github/workflows scripts/coherence-matrix-linux.sh \
  scripts/xfs-fuse-integration.sh
then
  echo "retired private-kernel contract found in active product material" >&2
  exit 1
fi

# 8. The two privileged real-mount suites. These are the only gates in this
# repository that observe a real kernel FUSE mount against real XFS, so no
# amount of green from the steps above substitutes for them. They are opt-in
# locally and mandatory in CI.
#
# scripts/package-manager-matrix.sh is a third Docker suite in the same
# container, and it is deliberately not here and no longer in CI either: it is a
# workload soak rather than a coherence gate, and it roughly doubles the wall
# time of a full local run. Run it on demand; the concurrent-reader shape it
# drives is qualified after deploy by phase 8 of
# deploy/opensteer/staging-qualification.sh. The closing banner names it so a
# --full pass is not read as "every instrument in the tree".
if [[ "$VERIFY_LOCAL_FULL" == "1" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "verify-local --full requires docker; none found on PATH" >&2
    exit 1
  fi

  step "privileged XFS (prjquota) and kernel FUSE integration suite"
  bash scripts/xfs-fuse-integration.sh

  step "two-mount cross-mount coherence matrix"
  bash scripts/coherence-matrix-linux.sh

  echo
  echo "verify-local: ok (full)"
  echo "  ran: build/vet, govulncheck, native go suites, go-fuse reply seam,"
  echo "       Swift suite (macOS host only), workflow/release-trust policy,"
  echo "       architecture scans, xfs-fuse-integration.sh, coherence-matrix-linux.sh"
  echo "  still NOT run by --full:"
  echo "    - scripts/package-manager-matrix.sh   third Docker suite; a workload"
  echo "                                         soak, run on demand, not in CI"
  echo "    - scripts/coherence-matrix-macos.sh   live macOS FSKit mount matrix;"
  echo "                                         needs a user-enabled extension"
  echo "    - deploy/opensteer/staging-qualification.sh against a live cell"
  exit 0
fi

echo
echo "verify-local: ok (default mode) — this is NOT full verification"
echo
echo "NOT RUN by this invocation:"
echo "  - scripts/xfs-fuse-integration.sh   real XFS + real kernel FUSE mounts"
echo "  - scripts/coherence-matrix-linux.sh two real mounts against one volume"
echo "  - scripts/package-manager-matrix.sh concurrent package-manager readers"
echo "                                     (on demand; not a CI lane)"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "  - scripts/test-swift-xcode.sh      Xcode-native Swift suite (macOS only)"
fi
echo "  - scripts/coherence-matrix-macos.sh live macOS FSKit mount matrix"
echo "  - deploy/opensteer/staging-qualification.sh real-workload staging corpus"
echo
echo "CI runs both privileged Linux suites on its ubuntu-24.04 lanes"
echo "(linux-xfs-fuse and linux-coherence-matrix in .github/workflows/ci.yml),"
echo "so a merge is still gated on them. To run them here:"
echo "  bash scripts/verify-local.sh --full"
