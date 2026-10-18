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
#             Go suites, the go-fuse reply and unmount seams, the Swift suite on
#             macOS, workflow/release-trust policy, and the current-architecture
#             check.
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
      sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
# enter it. ReplyWriteLifecycle tracks selected physical replies while
# descriptor lifetime is shared with notifications. Normal unmount makes one
# helper attempt and joins workers only after success. Gate both maintained
# seams; the fork's other tests are not part of this product's contract.
step "maintained go-fuse reply and unmount seams"
go -C vcs/third_party/go-fuse build ./fuse
go -C vcs/third_party/go-fuse vet ./fuse
go -C vcs/third_party/go-fuse test ./fuse -run 'Test(TrackedReplyLifecycle.*|UntrackedReply.*|BlockedNotificationAllowsTrackedReply|FailedTrackedReplyFinalizesAfterDescriptorUnlock|CloseWaitsForNotificationAndRejectsLateWrites|NormalUnmountMakesOneAttemptAndPreservesTheError|NormalUnmountJoinsWorkersOnlyAfterSuccess)$'
go -C vcs/third_party/go-fuse test -race ./fuse -run 'Test(TrackedReplyLifecycle.*|UntrackedReply.*|BlockedNotificationAllowsTrackedReply|FailedTrackedReplyFinalizesAfterDescriptorUnlock|CloseWaitsForNotificationAndRejectsLateWrites|NormalUnmountMakesOneAttemptAndPreservesTheError|NormalUnmountJoinsWorkersOnlyAfterSuccess)$'

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
if [[ "$(uname -s)" == Darwin ]]; then
  sh scripts/test-macos-installer-zip-namespace.sh
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

# 7. Current-architecture check. These are positive structural assertions,
# not a blacklist of retired names: the exact authority major and ALPN, the
# four frontend profiles, the handshake and private-frontend grammar, the
# shared golden frames, exact pfslocal/control/lifecycle pairing on both sides
# of each boundary, the single mount-membership codec, which production
# frontend selects which profile, the exact product executables and language
# roots, every launcher/script/doc command line against the executable's real
# flags, the privileged required-test inventories, COMPATIBILITY.md agreeing
# with the code, and every relative documentation link. The expected values
# live in the checker's manifest; changing one is a deliberate contract change.
# Its parsers have their own unit tests, run first so a checker defect cannot
# masquerade as a tree defect.
step "current architecture check"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_check_current_architecture.py
python3 scripts/check-current-architecture.py

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
  echo "  ran: build/vet, govulncheck, native go suites, go-fuse reply/unmount seams,"
  echo "       Swift suite (macOS host only), workflow/release-trust policy,"
  echo "       current-architecture check, xfs-fuse-integration.sh,"
  echo "       coherence-matrix-linux.sh"
  echo "  still NOT run by --full:"
  echo "    - scripts/package-manager-matrix.sh   third Docker suite; a workload"
  echo "                                         soak, run on demand, not in CI"
  echo "    - scripts/coherence-matrix-macos.sh   live macOS FSKit mount matrix;"
  echo "                                         needs a user-enabled extension"
  echo "    - scripts/run-powerloss.sh            dm-log-writes power-cut harness"
  echo "                                         (Linux and FSKit-handler cuts);"
  echo "                                         privileged runner, weekly in CI"
  echo "    - native macOS 26/27 acceptance and the LAN workload"
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
echo "  - scripts/run-powerloss.sh          dm-log-writes power-cut harness"
echo "  - native macOS 26/27 acceptance and the LAN workload"
echo "  - deploy/opensteer/staging-qualification.sh real-workload staging corpus"
echo
echo "CI runs both privileged Linux suites on its ubuntu-24.04 lanes"
echo "(linux-xfs-fuse and linux-coherence-matrix in .github/workflows/ci.yml),"
echo "so a merge is still gated on them. To run them here:"
echo "  bash scripts/verify-local.sh --full"
