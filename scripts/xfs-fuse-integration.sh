#!/usr/bin/env bash
# Runs the privileged Linux integration suite (real XFS with project quotas plus
# real kernel FUSE mounts) inside a throwaway privileged container.
#
# The same script is the CI entry point and the local reproduction, so a green
# CI run and a developer run execute byte-identical provisioning. Every gate is
# fail-closed: a filesystem that cannot be provisioned, a test that skips, and a
# required test that never ran are all hard failures, because a silently skipped
# privileged test is exactly how this coverage gap survived unnoticed.
#
#   scripts/xfs-fuse-integration.sh                 # host side (needs docker)
#   scripts/xfs-fuse-integration.sh --in-container  # container side (needs root)
set -euo pipefail

# Digest-pinned like every other third-party image in this repository.
# Evidence: golang:1.26.6-bookworm (matches the toolchain in vcs/go.mod).
: "${PORTABLEFS_CI_IMAGE:=golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36}"
: "${PORTABLEFS_XFS_IMAGE_SIZE:=1G}"
: "${PORTABLEFS_SERVICE_UID:=200001}"
: "${PORTABLEFS_SERVICE_GID:=200001}"
: "${PORTABLEFS_PROJECT_ID:=42001}"
: "${PORTABLEFS_VOLUME_NAME:=ci-volume}"

# Every test that must actually run and pass. A rename or deletion here fails
# the job instead of quietly shrinking privileged coverage.
REQUIRED_TESTS=(
  "github.com/steerlabs/portablefs/vcs/internal/xfsstore:TestProductionXFSProjectGate"
  "github.com/steerlabs/portablefs/vcs/internal/xfsstore:TestProductionXFSGateRefusesAForeignProjectID"
  "github.com/steerlabs/portablefs/vcs/internal/authorityrpc:TestVolumeHandlerEndToEndOnXFS"
  "github.com/steerlabs/portablefs/vcs/internal/authorityrpc:TestBlockedLockWaitDoesNotHoldTheTopologyGuard"
  "github.com/steerlabs/portablefs/vcs/internal/authorityrpc:TestRoutesControllerRefusesGitTrackedContentOnXFS"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelFUSEProbeCompletesInit"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestTwoKernelMountsShareAuthoritativeXFS"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCreateWithAReadOnlyModeReturnsAWritableHandle"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountContentCoherence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountSizeCoherence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountAttributeCoherence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountPositiveDentryInvalidation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountNegativeDentryInvalidation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountRenameCoherence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCrossMountDirectoryListingCoherence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestDirectoryWithNonPortableInodeRemainsListable"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestPagedReaddirReturnsEveryNameExactlyOnce"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestPagedReaddirRefusesToPageAcrossARemoteMutation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestConcurrentCrossMountWritersToOneFile"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestAuthorityLossFailsCleanlyInsteadOfHanging"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestSessionExpiryReleasesABlockedLockWait"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestUnmountRemountObservesDurableState"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestLazyUnmountWaitsForRetainedFUSEReferenceBeforeCleanDetach"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestFailedKernelMountDischargesStrictMembership"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkloadGitAcrossMounts"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkloadSQLiteAcrossMounts"
  # Retained real-VFS regression coverage. These test names predate protocol 6
  # and do not, by themselves, prove lease grant/recall/discharge. Keep them
  # required for the behavior they exercise until dedicated v6 tests land; add
  # those tests by exact name rather than relabeling this block as lease proof.
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictMountAnswersRepeatedPathWalksWithoutTheAuthority"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestRemoteRemovalIsRepairedBeforeTheMutatorsCallReturns"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestRemoteWriteIsRepairedBeforeTheWritersCallReturns"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestTheInitiatingMountDoesNotDeadlockOnItsOwnMutation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestVisibilityAcknowledgmentSurvivesSaturatedIO"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestMetadataWorkloadRPCCost"
  # Machine-local routing must be proven against the real kernel and the real
  # authority transport. Keep the zero-RPC tests here in particular: the
  # cross-process matrix proves two-machine isolation, but intentionally does
  # not infer request counts from noisy whole-process I/O counters.
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestGraftedSubtreeReachesTheAuthorityZeroTimes"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestGraftDentriesRemainUsableAcrossRenameUnlinkAndHardlink"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestAGraftIsInvisibleToTheOtherMachine"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestTheWholesaleRebuildShapeWorksUnderAFloatingPattern"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestMkdirAtDepthInstantiatesARoute"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestRenamingAnAncestorOfAnActiveGraftIsEBUSY"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestTheGraftBoundaryIsEXDEV"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestCreateAtAnUncreatedRouteRootIsEISDIR"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestARouteRootShadowsTheVolumeSubtreeOfTheSameName"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestSharedPathsKeepTheirCoherenceWithRoutesConfigured"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestARoutingChangeIsRefusedWhileAnyMountIsLive"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestGraftedFileDescriptorsSurviveTheRootBeingRebuilt"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestGraftsCarryARealWorkloadWithoutTheAuthority"
  # The files gateway is the only synchronous-repair frontend shipped on Linux
  # and the only participant that is not a mount. Keep its real handshake with
  # the real volume handler required: every other readonlyfs test drives a fake,
  # which cannot observe attach negotiation, a real barrier, or whether a
  # cacheless reader can stall a writing mount.
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestFilesGatewayAttachesToRealXFSWithoutObstructingAMountingPeer"
  # The gateway is a sidecar, so it leaves whenever its pod restarts, and
  # leaving used to cost a writing mount its mutation. Keep the test that
  # measures what a clean departure costs required.
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestFilesGatewayCloseDoesNotStallAMutatingMount"
)

# This boundary is root-owned provisioning work and therefore cannot run under
# the unprivileged authority identity used for the data-plane suite. Keeping an
# exact required list prevents a renamed or skipped test from masquerading as
# qualification.
REQUIRED_ROOT_TESTS=(
  "github.com/steerlabs/portablefs/vcs/internal/cellhost:TestWriteStagingIsAtomicPinnedAndSharesTheVolumeProjectQuota"
)

fail() {
  echo "xfs-fuse-integration: $1" >&2
  exit "${2:-1}"
}

repository_root() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd
}

run_host() {
  command -v docker >/dev/null || fail "docker is required to run the privileged integration suite" 69
  local root
  root=$(repository_root)
  echo "xfs-fuse-integration: launching ${PORTABLEFS_CI_IMAGE}"
  # The working tree is mounted read-only: the container provisions its own XFS
  # image and must never be able to mutate the checkout it is testing.
  run_container() {
    docker run --rm --privileged \
      --tmpfs /var/tmp:exec,mode=1777 \
      -v "${root}/vcs:/work/vcs:ro" \
      -v "${root}/scripts:/work/scripts:ro" \
      "$@" \
      -e "PORTABLEFS_XFS_IMAGE_SIZE=${PORTABLEFS_XFS_IMAGE_SIZE}" \
      -e "PORTABLEFS_SERVICE_UID=${PORTABLEFS_SERVICE_UID}" \
      -e "PORTABLEFS_SERVICE_GID=${PORTABLEFS_SERVICE_GID}" \
      -e "PORTABLEFS_PROJECT_ID=${PORTABLEFS_PROJECT_ID}" \
      -e "PORTABLEFS_VOLUME_NAME=${PORTABLEFS_VOLUME_NAME}" \
      -e "PORTABLEFS_GO_TEST_FLAGS=${PORTABLEFS_GO_TEST_FLAGS:-}" \
      -e "PORTABLEFS_FUSE_DEBUG=${PORTABLEFS_FUSE_DEBUG:-}" \
      -w /work \
      "${PORTABLEFS_CI_IMAGE}" \
      bash /work/scripts/xfs-fuse-integration.sh --in-container
  }
  if [[ -d /lib/modules/$(uname -r) ]]; then
    run_container -v /lib/modules:/lib/modules:ro
  else
    run_container
  fi
}

install_container_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # xfsprogs: mkfs.xfs and xfs_quota. fuse3: the setuid fusermount3 helper the
  # unprivileged test process needs. sqlite3/git: the real application workload.
  apt-get install -y -qq --no-install-recommends xfsprogs fuse3 sqlite3 git util-linux kmod >/dev/null
}

# The FUSE control filesystem is the kernel interface a strict mount's
# revocation ladder uses to abort its own serving connection, which is what
# releases every request parked in the kernel when the authority is gone. A
# production host has it mounted; a container does not inherit it, and without
# it the abort step silently cannot run - so the mount-owner detach helper waits
# on a request nothing can answer and teardown never completes. Provisioning it
# here is what makes the container the same kernel surface production is.
provision_fuse_control() {
  [[ -d /sys/fs/fuse/connections ]] || fail "/sys/fs/fuse/connections is missing; this kernel has no FUSE control interface" 69
  mountpoint -q /sys/fs/fuse/connections ||
    mount -t fusectl none /sys/fs/fuse/connections ||
    fail "cannot mount the FUSE control filesystem; connection aborts would be unavailable" 69
}

provision_xfs() {
  local image=/var/tmp/portablefs-xfs.img
  [[ -e /dev/fuse ]] || fail "/dev/fuse is missing; the container cannot mount a kernel FUSE filesystem" 69
  [[ -e /dev/loop-control ]] || fail "/dev/loop-control is missing; the container cannot create a loop-backed XFS" 69
  install -d -m 0755 -o 0 -g 0 /srv/portablefs
  rm -f -- "$image"
  truncate -s "$PORTABLEFS_XFS_IMAGE_SIZE" "$image"
  mkfs.xfs -q -f "$image"
  mount -o "loop,prjquota,nodev,nosuid,noexec,noatime" "$image" /srv/portablefs
  local options
  options=$(findmnt -n -r -o OPTIONS -T /srv/portablefs)
  [[ ,$options, == *,prjquota,* ]] || fail "XFS mounted without prjquota (options: $options)"
  [[ $(findmnt -n -r -o FSTYPE -T /srv/portablefs) == xfs ]] || fail "provisioned filesystem is not XFS"
}

provision_volume() {
  # The production provisioner is the single source of truth for project-quota
  # setup. CI exercising a private copy would prove nothing about production.
  bash /work/scripts/provision-xfs-volume.sh \
    /srv/portablefs "$PORTABLEFS_VOLUME_NAME" "$PORTABLEFS_PROJECT_ID" \
    "$PORTABLEFS_SERVICE_UID" "$PORTABLEFS_SERVICE_GID" 512m 200000
}

create_service_identity() {
  groupadd -g "$PORTABLEFS_SERVICE_GID" portablefs
  useradd -u "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" -M -d /home/portablefs -s /bin/bash portablefs
  install -d -m 0700 -o "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" \
    /home/portablefs /home/portablefs/gocache /home/portablefs/gomodcache /home/portablefs/tmp
}

run_suite() {
  local volume=/srv/portablefs/$PORTABLEFS_VOLUME_NAME
  local log=/home/portablefs/tmp/go-test.log
  local status=0
  local -a extra_go_test_flags=()
  if [[ -n ${PORTABLEFS_GO_TEST_FLAGS:-} ]]; then
    read -r -a extra_go_test_flags <<<"$PORTABLEFS_GO_TEST_FLAGS"
  fi
  # Deliberately unprivileged: the permission assertions in the suite are only
  # meaningful when DAC actually applies, and the production data plane never
  # runs as root. PORTABLEFS_XFS_TEST_REQUIRED turns every gate skip into a
  # failure so a broken provisioner cannot present as a green run. -p 1 keeps
  # the three privileged packages from opening the one provisioned XFS cell
  # concurrently, which its exclusive volume lock forbids.
  #
  # -timeout is set below the CI job timeout on purpose (the whole lane
  # completes in about two minutes). A hung mount must be killed by the test
  # binary, which prints every goroutine's stack, rather than by the job
  # timeout, which kills the runner and leaves nothing to read.
  set +e
  runuser -u portablefs -- env -i \
    HOME=/home/portablefs \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    TMPDIR=/home/portablefs/tmp \
    GOCACHE=/home/portablefs/gocache \
    GOMODCACHE=/home/portablefs/gomodcache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    PORTABLEFS_XFS_TEST_ROOT="$volume" \
    PORTABLEFS_XFS_TEST_PROJECT="$PORTABLEFS_PROJECT_ID" \
    PORTABLEFS_CELLHOST_XFS_TEST_ROOT=/srv/portablefs \
    PORTABLEFS_SERVICE_UID="$PORTABLEFS_SERVICE_UID" \
    PORTABLEFS_SERVICE_GID="$PORTABLEFS_SERVICE_GID" \
    PORTABLEFS_XFS_TEST_CELL=/srv/portablefs \
    PORTABLEFS_FUSE_TEST=1 \
    PORTABLEFS_WORKLOAD_TEST=1 \
    PORTABLEFS_XFS_TEST_REQUIRED=1 \
	PORTABLEFS_FUSE_DEBUG="${PORTABLEFS_FUSE_DEBUG:-}" \
    go -C /work/vcs test -v -count=1 -p 1 -timeout 10m "${extra_go_test_flags[@]}" \
    ./internal/fusev3/... ./internal/xfsstore/... ./internal/authorityrpc/... \
    >"$log" 2>&1
  status=$?
  set -e
  cat -- "$log"
  [[ $status -eq 0 ]] || fail "go test exited $status" "$status"
  verify_required_tests "$log"
}

run_root_boundary_suite() {
  local cellhost_log=/var/tmp/portablefs-cellhost-boundary.log
  local combined_log=/var/tmp/portablefs-root-boundary.log
  local status=0
  # Write-staging creation is the cell helper's root-only responsibility, not a
  # capability of the authority service identity. Run that exact boundary as
  # root against the same provisioned XFS cell while retaining the production
  # service UID/GID as the directory ownership being verified.
  set +e
  env -i \
    HOME=/root \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TMPDIR=/var/tmp \
    GOCACHE=/var/tmp/portablefs-cellhost-gocache \
    GOMODCACHE=/home/portablefs/gomodcache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    PORTABLEFS_CELLHOST_XFS_TEST_ROOT=/srv/portablefs \
    PORTABLEFS_SERVICE_UID="$PORTABLEFS_SERVICE_UID" \
    PORTABLEFS_SERVICE_GID="$PORTABLEFS_SERVICE_GID" \
    go -C /work/vcs test -v -count=1 -p 1 -timeout 5m \
    -run '^TestWriteStagingIsAtomicPinnedAndSharesTheVolumeProjectQuota$' \
    ./internal/cellhost >"$cellhost_log" 2>&1
  status=$?
  set -e
  cat -- "$cellhost_log"
  [[ $status -eq 0 ]] || fail "root cell-helper boundary test exited $status" "$status"
  cp "$cellhost_log" "$combined_log"
  verify_exact_tests "$combined_log" "${REQUIRED_ROOT_TESTS[@]}"
  echo "xfs-fuse-integration: all ${#REQUIRED_ROOT_TESTS[@]} required root boundary tests passed"
}

# go test reports a skipped test as "--- SKIP" and a passing one as "--- PASS".
# Matching the exact package/test pairs catches a renamed, deleted, or silently
# skipped privileged test, which a plain exit code cannot.
verify_required_tests() {
  local log=$1
  verify_exact_tests "$log" "${REQUIRED_TESTS[@]}"
  echo "xfs-fuse-integration: all ${#REQUIRED_TESTS[@]} required privileged tests passed"
}

verify_exact_tests() {
  local log=$1 entry package name missing=0
  shift
  for entry in "$@"; do
    package=${entry%%:*}
    name=${entry##*:}
    if ! grep -Fq -- "--- PASS: ${name} (" "$log"; then
      echo "xfs-fuse-integration: required test did not pass: ${package}.${name}" >&2
      missing=1
    fi
  done
  [[ $missing -eq 0 ]] || fail "required privileged tests did not run to a PASS" 70
}

run_container() {
  [[ $EUID -eq 0 ]] || fail "container side must start as root to provision XFS" 77
  install_container_dependencies
  create_service_identity
  provision_fuse_control
  provision_xfs
  provision_volume
  run_suite
  run_root_boundary_suite
}

case "${1:-}" in
  --in-container) run_container ;;
  "") run_host ;;
  *) fail "usage: $0 [--in-container]" 64 ;;
esac
