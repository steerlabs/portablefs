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
# Evidence: golang:1.26.5-bookworm (matches the toolchain in vcs/go.mod).
: "${PORTABLEFS_CI_IMAGE:=golang@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651}"
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
  # The strict-profile cache-coherence battery. These are the only tests that
  # execute the two-phase visibility barrier against a real kernel FUSE mount:
  # everything else about strict coherence is either unit-level (no kernel) or
  # black box through the coherence matrix (no RPC accounting). They are listed
  # here for the same reason the rest are - a privileged test that is renamed or
  # deleted must fail this job rather than quietly shrink the coverage that
  # justifies caching names and attributes at all.
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictMountAnswersRepeatedPathWalksWithoutTheAuthority"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestRemoteRemovalIsRepairedBeforeTheMutatorsCallReturns"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestRemoteWriteIsRepairedBeforeTheWritersCallReturns"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestTheInitiatingMountDoesNotDeadlockOnItsOwnMutation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestVisibilityAcknowledgmentSurvivesSaturatedIO"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestMetadataWorkloadRPCCost"
  # The patched-kernel syscall surface must be exercised through real VFS
  # syscalls. Unit calls into rawFileSystem do not prove kernel negotiation,
  # transaction fragmentation, post-VFS publication, or stock/private opcode
  # routing.
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictKernelLargeWriteTransactionsPreservePositionedAndAppendData"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictKernelSharedFallocateMutations"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictKernelSharedCopyFileRangeAndCrossClassBoundary"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictKernelTmpfileFirstLinkAndExclusiveNonlinkable"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictKernelSyncfsSucceeds"
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
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestARoutingChangeRevokesEveryMountWithARemountMessage"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestGraftedFileDescriptorsSurviveTheRootBeingRebuilt"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestGraftsCarryARealWorkloadWithoutTheAuthority"
)

# These boundaries require CAP_SYS_ADMIN and therefore cannot run under the
# capability-free identity used for the POSIX/DAC suite above. They still run
# in the same throwaway container, as the same production uid against the same
# authority/frontend code and provisioned XFS volume. The process receives
# SYS_ADMIN for the admission calls and DAC_OVERRIDE solely to open the
# root-owned loop control devices. Keeping an exact required list prevents a missing
# module, renamed test, or accidental skip from masquerading as qualification.
REQUIRED_ROOT_TESTS=(
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestStrictKernelRefusesStackingExportAndLoopBacking"
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
  local -a host_kernel_mounts=()
  if [[ -d /lib/modules/$(uname -r) ]]; then
    host_kernel_mounts=(-v /lib/modules:/lib/modules:ro)
  fi
  echo "xfs-fuse-integration: launching ${PORTABLEFS_CI_IMAGE}"
  # The working tree is mounted read-only: the container provisions its own XFS
  # image and must never be able to mutate the checkout it is testing.
  docker run --rm --privileged \
    --tmpfs /var/tmp:exec,mode=1777 \
    -v "${root}/vcs:/work/vcs:ro" \
    -v "${root}/scripts:/work/scripts:ro" \
    -v "${root}/kernel/linux-6.12.100-portablefs-append:/work/kernel/linux-6.12.100-portablefs-append:ro" \
    "${host_kernel_mounts[@]}" \
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

install_container_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # xfsprogs: mkfs.xfs and xfs_quota. fuse3: the setuid fusermount3 helper the
  # unprivileged test process needs. sqlite3/git: the real application workload.
  apt-get install -y -qq --no-install-recommends xfsprogs fuse3 sqlite3 git util-linux kmod >/dev/null
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
    PORTABLEFS_XFS_TEST_CELL=/srv/portablefs \
    PORTABLEFS_FUSE_TEST=1 \
    PORTABLEFS_WORKLOAD_TEST=1 \
    PORTABLEFS_XFS_TEST_REQUIRED=1 \
	PORTABLEFS_FUSE_DEBUG="${PORTABLEFS_FUSE_DEBUG:-}" \
    go -C /work/vcs test -v -count=1 -p 1 -timeout 25m "${extra_go_test_flags[@]}" \
    ./internal/fusev3/... ./internal/xfsstore/... ./internal/authorityrpc/... \
    >"$log" 2>&1
  status=$?
  set -e
  cat -- "$log"
  [[ $status -eq 0 ]] || fail "go test exited $status" "$status"
  verify_required_tests "$log"
}

run_root_boundary_suite() {
  local volume=/srv/portablefs/$PORTABLEFS_VOLUME_NAME
  local log=/var/tmp/portablefs-root-boundary.log
  local status=0
  # Load the only optional module before dropping to the production uid.  The
  # test process then receives CAP_SYS_ADMIN plus DAC_OVERRIDE for the
  # root-owned loop device nodes, and no broader root identity. It can exercise
  # mount/backend admission while xfsstore continues to prove the exact service
  # owner on every private ancestor.
  modprobe overlay
  modprobe loop
  set +e
  setpriv \
    --reuid="$PORTABLEFS_SERVICE_UID" \
    --regid="$PORTABLEFS_SERVICE_GID" \
    --clear-groups \
    --inh-caps=+sys_admin,+dac_override \
    --ambient-caps=+sys_admin,+dac_override \
    env -i \
    HOME=/home/portablefs \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TMPDIR=/var/tmp \
    GOCACHE=/var/tmp/portablefs-root-gocache \
    GOMODCACHE=/home/portablefs/gomodcache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    PORTABLEFS_XFS_TEST_ROOT="$volume" \
    PORTABLEFS_XFS_TEST_PROJECT="$PORTABLEFS_PROJECT_ID" \
    PORTABLEFS_FUSE_TEST=1 \
    PORTABLEFS_STRICT_STACK_TEST_SCRIPT=/work/kernel/linux-6.12.100-portablefs-append/tests/test_strict_stacking.py \
    go -C /work/vcs test -v -count=1 -p 1 -timeout 5m \
    -run '^TestStrictKernelRefusesStackingExportAndLoopBacking$' \
    ./internal/fusev3/... >"$log" 2>&1
  status=$?
  set -e
  cat -- "$log"
  [[ $status -eq 0 ]] || fail "root kernel-boundary test exited $status" "$status"
  verify_exact_tests "$log" "${REQUIRED_ROOT_TESTS[@]}"
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
