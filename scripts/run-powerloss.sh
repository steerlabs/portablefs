#!/usr/bin/env bash
# Power-loss and crash-consistency harness for the PortableFS v3 authority.
#
# This is the automated evidence for one sentence in
# docs/direct-store-consensus-evaluation.md: "Successful fsync and directory
# fsync are assumptions until power-cut testing confirms them."
#
# It stacks dm-log-writes under the XFS a real portablefs-authority serves,
# drives a real kernel FUSE mount through a workload with known fsync points,
# kills the authority and the mount outright, and then replays the recorded
# write log to each of those points. Replaying to entry N reconstructs the
# platter state a power cut after the Nth bio would have left - dirty page
# cache is NOT replayed, because a power cut does not write it back. Every
# reconstructed device is mounted (which runs XFS log recovery), checked
# against the durability contract, and then checked with xfs_repair -n.
#
#   scripts/run-powerloss.sh                 # host side (needs docker)
#   scripts/run-powerloss.sh --in-container  # container side (root)
#
# Every gate is fail-closed. PORTABLEFS_POWERLOSS_REQUIRED=1 is exported for
# the Go suite, which turns every skip into a hard failure: a missing
# prerequisite must stop the job, never quietly reduce it to nothing. The
# harness also greps the run for the exact test names that had to execute, so a
# renamed or silently skipped test fails the job even at exit zero.
set -euo pipefail

# Digest-pinned like every other third-party image in this repository, and the
# same image the privileged XFS/FUSE and coherence jobs use.
: "${PORTABLEFS_CI_IMAGE:=golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36}"
# The device the authority serves, and the log device that records every write
# to it. The log must be larger than the target: it holds a copy of every
# written block plus one metadata block each, and dm-log-writes stops recording
# when it fills - which would silently understate what reached the device.
: "${PORTABLEFS_POWERLOSS_IMAGE_SIZE:=2147483648}"
: "${PORTABLEFS_SERVICE_UID:=200001}"
: "${PORTABLEFS_SERVICE_GID:=200001}"
: "${PORTABLEFS_POWERLOSS_VOLUME:=powerloss-volume}"
: "${PORTABLEFS_POWERLOSS_PROJECT_ID:=42101}"
: "${PORTABLEFS_POWERLOSS_AUTHORITY_PORT:=17643}"
# Fsynced checkpoints the power-cut workload writes. Every one of them becomes
# a replay point, and each replay point costs one full device replay, one mount
# and one xfs_repair pass.
: "${PORTABLEFS_POWERLOSS_CHECKPOINTS:=12}"
# Additional cuts taken at flush/FUA barriers the filesystem issued on its own,
# spread across the whole log. These are the ones that look for a cut position
# nobody designed for.
: "${PORTABLEFS_POWERLOSS_BARRIER_POINTS:=8}"
# Rounds of the process-level instrument, each killing the authority a
# different distance into a sustained write workload.
: "${PORTABLEFS_POWERLOSS_KILL_ROUNDS:=3}"
: "${PORTABLEFS_POWERLOSS_TIMEOUT:=45m}"
# The capability window the credential set is minted with, and the window the
# authority is told to honour. The shipped authority default is 15 minutes; a
# run that replays a multi-gigabyte device once per cut outlives that, and an
# attach refused for an expired capability would be reported as a durability
# failure. This bound is not what the harness measures.
: "${PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME:=4h}"
# Where the container leaves the suite output and the data-plane process logs.
# The container's own /var/tmp is a tmpfs that disappears with it, so a failed
# run would otherwise take its only evidence with it.
: "${PORTABLEFS_POWERLOSS_EVIDENCE_DIR:=}"

# The exact tests that must have run and passed. A harness whose coverage can
# silently shrink is not a gate, so a green `go test` that did not execute all
# of these fails the job.
REQUIRED_TESTS=(
  TestReplayReproducesTheDeviceTheKernelWrote
  TestXFSHonoursFsyncAtEveryCut
  TestFsyncedWritesSurvivePowerLoss
  TestAuthorityKillDuringWritesKeepsFsyncedData
)

fail() {
  echo "run-powerloss: $1" >&2
  exit "${2:-1}"
}

repository_root() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd
}

run_host() {
  command -v docker >/dev/null || fail "docker is required to run the privileged power-loss harness" 69
  local root
  root=$(repository_root)
  local evidence="${PORTABLEFS_POWERLOSS_EVIDENCE_DIR:-${root}/powerloss-evidence}"
  mkdir -p -- "$evidence"
  echo "run-powerloss: launching ${PORTABLEFS_CI_IMAGE}, evidence in ${evidence}"
  # The working tree is mounted read-only: the container provisions its own
  # devices and must never mutate the checkout it is testing. /lib/modules is
  # mounted so modprobe can load dm-log-writes; the module itself must exist on
  # the host kernel, and this harness cannot supply it.
  docker run --rm --privileged \
    --tmpfs /var/tmp:exec,mode=1777 \
    -v "${root}/vcs:/work/vcs:ro" \
    -v "${root}/scripts:/work/scripts:ro" \
    -v /lib/modules:/lib/modules:ro \
    -v "${evidence}:/evidence" \
    -e "PORTABLEFS_POWERLOSS_IMAGE_SIZE=${PORTABLEFS_POWERLOSS_IMAGE_SIZE}" \
    -e "PORTABLEFS_SERVICE_UID=${PORTABLEFS_SERVICE_UID}" \
    -e "PORTABLEFS_SERVICE_GID=${PORTABLEFS_SERVICE_GID}" \
    -e "PORTABLEFS_POWERLOSS_VOLUME=${PORTABLEFS_POWERLOSS_VOLUME}" \
    -e "PORTABLEFS_POWERLOSS_PROJECT_ID=${PORTABLEFS_POWERLOSS_PROJECT_ID}" \
    -e "PORTABLEFS_POWERLOSS_AUTHORITY_PORT=${PORTABLEFS_POWERLOSS_AUTHORITY_PORT}" \
    -e "PORTABLEFS_POWERLOSS_CHECKPOINTS=${PORTABLEFS_POWERLOSS_CHECKPOINTS}" \
    -e "PORTABLEFS_POWERLOSS_BARRIER_POINTS=${PORTABLEFS_POWERLOSS_BARRIER_POINTS}" \
    -e "PORTABLEFS_POWERLOSS_KILL_ROUNDS=${PORTABLEFS_POWERLOSS_KILL_ROUNDS}" \
    -e "PORTABLEFS_POWERLOSS_TIMEOUT=${PORTABLEFS_POWERLOSS_TIMEOUT}" \
    -e "PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME=${PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME}" \
    -e "PORTABLEFS_POWERLOSS_EVIDENCE_DIR=/evidence" \
    -w /work \
    "${PORTABLEFS_CI_IMAGE}" \
    bash /work/scripts/run-powerloss.sh --in-container
}

install_container_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # xfsprogs: mkfs.xfs, xfs_repair, xfs_io and xfs_quota. dmsetup: the
  # dm-log-writes target. kmod: modprobe, to load it. fuse3: the setuid
  # fusermount3 helper an unprivileged mount process needs. util-linux:
  # losetup, blockdev, findmnt.
  apt-get install -y -qq --no-install-recommends \
    xfsprogs dmsetup kmod fuse3 util-linux procps >/dev/null
}

# ensure_loop_nodes pre-creates the loop device nodes.
#
# A container has no udev, so a loop device the kernel allocates through
# /dev/loop-control gets no node in /dev, and losetup then reports ENOENT for a
# device that exists. That presents as an unexplained mid-run failure once the
# image's handful of pre-made nodes are used up. This is a container artefact,
# not anything the harness measures.
ensure_loop_nodes() {
  local index
  for index in $(seq 0 63); do
    [[ -e /dev/loop$index ]] || mknod -m 0660 "/dev/loop$index" b 7 "$index"
  done
}

# require_log_writes loads the target and fails with a named reason if the
# kernel does not carry it. This is the one prerequisite no userspace can
# supply, so it is checked before anything is built.
require_log_writes() {
  modprobe dm-log-writes 2>/dev/null || true
  if ! dmsetup targets | grep -q '^log-writes'; then
    echo "run-powerloss: the running kernel ($(uname -r)) does not provide the dm-log-writes target." >&2
    echo "run-powerloss: it is CONFIG_DM_LOG_WRITES and must be present on the runner's kernel." >&2
    echo "run-powerloss: without it there is no power-cut simulation, only a process kill, and this" >&2
    echo "run-powerloss: job must not report green for the weaker of the two instruments." >&2
    fail "the dm-log-writes target is not available" 69
  fi
  echo "run-powerloss: kernel $(uname -r) provides: $(dmsetup targets | tr '\n' ' ')"
}

create_service_identity() {
  groupadd -g "$PORTABLEFS_SERVICE_GID" portablefs
  useradd -u "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" \
    -M -d /home/portablefs -s /bin/bash portablefs
  install -d -m 0700 -o "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" \
    /home/portablefs /home/portablefs/gocache /home/portablefs/gomodcache /home/portablefs/tmp
  # The scratch directory belongs to root: it holds the device images and the
  # mount points, and only root touches those. The binaries and credentials are
  # built and minted by the volume identity and executed as it, so they belong
  # to it. Root reads both regardless.
  install -d -m 0755 -o 0 -g 0 /var/tmp/powerloss
  install -d -m 0700 -o "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" \
    /var/tmp/powerloss-bin /var/tmp/powerloss-creds
}

# as_service runs a command as the unprivileged volume identity with a clean
# environment. The data plane never runs as root, and root would bypass every
# DAC decision the mount delegates to the kernel.
as_service() {
  runuser -u portablefs -- env -i \
    HOME=/home/portablefs \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    TMPDIR=/home/portablefs/tmp \
    GOCACHE=/home/portablefs/gocache \
    GOMODCACHE=/home/portablefs/gomodcache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    "$@"
}

build_binaries() {
  echo "run-powerloss: building the authority, mount, credential and workload binaries"
  as_service go -C /work/vcs build -o /var/tmp/powerloss-bin/ \
    ./cmd/portablefs-authority ./cmd/portablefs-mount-v3 \
    ./test/coherence/cmd/pfs-coherence-credentials \
    ./test/powerloss/cmd/pfs-powerloss-driver ||
    fail "building the harness binaries failed" 70
}

# mint_credentials reuses the coherence harness's credential tool rather than
# minting a second, subtly different credential set. It signs with the
# production signer (volumecap.Sign), so a run cannot pass against a credential
# production would refuse.
#
# Tokens are single use. The power-cut instrument takes one, and each
# process-kill round takes two: one for the mount it kills and one for the
# mount it attaches after the restart.
mint_credentials() {
  local tokens=$((1 + 2 * PORTABLEFS_POWERLOSS_KILL_ROUNDS + 2))
  as_service /var/tmp/powerloss-bin/pfs-coherence-credentials \
    --dir /var/tmp/powerloss-creds \
    --volume-id "$PORTABLEFS_POWERLOSS_VOLUME" \
    --tokens "$tokens" \
    --admin-tokens 1 \
    --lifetime "$PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME" ||
    fail "minting the credential set failed" 70
}

# collect_evidence copies the run's output somewhere that outlives the
# container. The device images are deliberately NOT copied: the log image alone
# is twice the size of the device, and the suite log plus the data-plane logs
# are what a failure is actually read from.
collect_evidence() {
  local destination=${PORTABLEFS_POWERLOSS_EVIDENCE_DIR:-}
  [[ -n $destination && -d $destination ]] || return 0
  cp -f /var/tmp/powerloss-suite.log "$destination/" 2>/dev/null || true
  if [[ -d /var/tmp/powerloss/logs ]]; then
    mkdir -p -- "$destination/process-logs"
    cp -f /var/tmp/powerloss/logs/. "$destination/process-logs/" -r 2>/dev/null || true
  fi
}

# verify_exact_tests is the gate on the gate. `go test` exits zero for a suite
# that skipped everything, and the whole point of this job is that a missing
# prerequisite must be loud.
verify_exact_tests() {
  local log=$1 missing=0 name
  for name in "${REQUIRED_TESTS[@]}"; do
    if ! grep -q -- "--- PASS: ${name} (" "$log"; then
      echo "run-powerloss: ${name} did not run and pass" >&2
      missing=1
    fi
  done
  if grep -q -- "--- SKIP" "$log"; then
    echo "run-powerloss: the suite reported a skip, which PORTABLEFS_POWERLOSS_REQUIRED=1 should have made impossible:" >&2
    grep -- "--- SKIP" -A2 "$log" >&2 || true
    missing=1
  fi
  (( missing == 0 )) || fail "the power-loss suite did not execute every test this job exists to run" 72
}

run_container() {
  [[ $EUID -eq 0 ]] || fail "container side must start as root to drive loop devices, device mapper and mounts" 77
  install_container_dependencies
  ensure_loop_nodes
  require_log_writes
  create_service_identity
  build_binaries
  mint_credentials

  # The Go suite owns every device, process and assertion from here. It runs as
  # root because it creates the device-mapper stack and the mounts; it spawns
  # the authority, the mount and the workload driver as the unprivileged
  # identity, exactly as a deployment runs them.
  export PORTABLEFS_POWERLOSS_TEST=1
  export PORTABLEFS_POWERLOSS_REQUIRED=1
  export PORTABLEFS_POWERLOSS_WORK_DIR=/var/tmp/powerloss
  export PORTABLEFS_POWERLOSS_BIN_DIR=/var/tmp/powerloss-bin
  export PORTABLEFS_POWERLOSS_CREDS_DIR=/var/tmp/powerloss-creds
  export PORTABLEFS_POWERLOSS_PROVISIONER=/work/scripts/provision-xfs-volume.sh
  export PORTABLEFS_POWERLOSS_SERVICE_UID="$PORTABLEFS_SERVICE_UID"
  export PORTABLEFS_POWERLOSS_SERVICE_GID="$PORTABLEFS_SERVICE_GID"
  export PORTABLEFS_POWERLOSS_VOLUME
  export PORTABLEFS_POWERLOSS_PROJECT_ID
  export PORTABLEFS_POWERLOSS_AUTHORITY_PORT
  export PORTABLEFS_POWERLOSS_IMAGE_SIZE
  export PORTABLEFS_POWERLOSS_CHECKPOINTS
  export PORTABLEFS_POWERLOSS_BARRIER_POINTS
  export PORTABLEFS_POWERLOSS_KILL_ROUNDS
  export PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME
  export DM_DISABLE_UDEV=1
  export GOCACHE=/var/tmp/gocache
  export GOTOOLCHAIN=local
  export GOFLAGS=-mod=readonly

  echo "======================================================================"
  echo "power-loss harness: kernel $(uname -r), $(go version)"
  echo "  device instrument : dm-log-writes under the XFS the authority serves"
  echo "  process instrument: SIGKILL of the authority, ${PORTABLEFS_POWERLOSS_KILL_ROUNDS} rounds"
  echo "======================================================================"
  local log=/var/tmp/powerloss-suite.log
  local status=0
  trap collect_evidence EXIT
  local selector=()
  if [[ -n ${PORTABLEFS_POWERLOSS_ONLY:-} ]]; then
    # A single-test selector exists for diagnosing this harness itself. It
    # deliberately also disables the exact-test gate below, so a run narrowed
    # by hand can never be mistaken for a complete one.
    echo "run-powerloss: NARROWED to ${PORTABLEFS_POWERLOSS_ONLY}; this run is a diagnostic, not a gate" >&2
    selector=(-run "$PORTABLEFS_POWERLOSS_ONLY")
  fi
  go -C /work/vcs test -count=1 -v -timeout "$PORTABLEFS_POWERLOSS_TIMEOUT" "${selector[@]}" ./test/powerloss/... 2>&1 | tee "$log" || status=$?
  if [[ -n ${PORTABLEFS_POWERLOSS_ONLY:-} ]]; then
    (( status == 0 )) || fail "the narrowed diagnostic run failed" "$status"
    fail "PORTABLEFS_POWERLOSS_ONLY was set, so this run is not a gate and does not report success" 64
  fi
  verify_exact_tests "$log"
  (( status == 0 )) || fail "the power-loss suite failed" "$status"
  echo "run-powerloss: every required test executed and passed"
}

# Dispatch only when this file is EXECUTED, so a future script can source the
# helpers above without launching a run as a side effect.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    --in-container) run_container ;;
    "") run_host ;;
    *) fail "usage: $0 [--in-container]" 64 ;;
  esac
fi
