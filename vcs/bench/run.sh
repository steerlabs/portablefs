#!/usr/bin/env bash
# PortableFS benchmark orchestrator.
#
#   ./run.sh [results-dir]          full profile, N=3, local + core (+ fuse if available)
#   PROFILE=quick N=2 ./run.sh      CI-sized run
#   WORKLOADS=W1,W2 ./run.sh        subset
#
# Produces per-config JSON under results/ and prints the markdown report.
# FUSE runs require /dev/fuse (Linux-only); they are skipped cleanly when
# unavailable (PFSBENCH_MOUNT_ONLY=skip is set for the fuse runs).
set -euo pipefail

cd "$(dirname "$0")/.."   # vcs/

RESULTS="${1:-bench/results}"
PROFILE="${PROFILE:-full}"
N="${N:-3}"
WORKLOADS="${WORKLOADS:-W1,W2,W3,W4,W5}"
BIN="$(mktemp -d)/pfsbench"
MOUNT_BIN="$(dirname "$BIN")/pfsmount"

echo "== building harness"
go build -o "$BIN" ./bench/cmd/pfsbench
go build -o "$MOUNT_BIN" ./bench/cmd/benchmount
mkdir -p "$RESULTS"

run() { # label transport extra-flags...
  local label="$1" transport="$2"; shift 2
  echo "== $label / $transport"
  "$BIN" run -transport "$transport" -profile "$PROFILE" -n "$N" -workloads "$WORKLOADS" \
    -label "$label" -out "$RESULTS/${PROFILE}-${label}-${transport}.json" "$@"
}

# Baseline: local disk vs PortableFS with default mount configuration.
run default local
run default core

# Optimization A/Bs (write-back = the delegation/checkout mode agents use for
# hot working sets; negcache = version-gated ENOENT caching).
run writeback        core -writeback
run negcache         core -negcache
run writeback-neg    core -writeback -negcache

# FUSE (kernel path) when this host can mount; cleanly skipped otherwise.
PFSBENCH_MOUNT_ONLY=skip run default fuse -mount-bin "$MOUNT_BIN"
PFSBENCH_MOUNT_ONLY=skip run writeback-neg fuse -writeback -negcache -mount-bin "$MOUNT_BIN"

echo
"$BIN" report -dir "$RESULTS"
