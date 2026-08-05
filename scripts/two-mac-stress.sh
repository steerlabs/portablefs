#!/bin/bash
# Legacy v2 two-Mac stress driver for PortableFS FSKit builds.
#
# This script documents and reproduces the retired v2 behavior, including its
# declared failures. It is not the v3 coherence matrix and must not be used as
# evidence that a production macOS v3 frontend exists. Use
# scripts/coherence-matrix-macos.sh for the fail-closed v3 release gate.
# Runs the pfs-mount-stress workload simultaneously from this Mac and a peer
# Mac over ssh, against an isolated branch of a production volume. The two
# sides rendezvous in-band through the mounted volume (ready/ + done/), which
# is itself part of what is under test.
#
# Usage: two-mac-stress.sh <build-tag>          e.g. two-mac-stress.sh c037ebf
#        two-mac-stress.sh --classify <results-dir> <local-exit> <remote-exit>
#          re-runs only the pass/fail decision over an existing results
#          directory, so the rules below are testable without two Macs.
#
# Env:
#   PFS_VOLUME  (default portablefs-cloud-3)
#   PFS_REMOTE  (default user@mac-b.local)
#   PFS_FILES/PFS_APPENDS/PFS_BIG_MIB/PFS_LOCK_ITERS/PFS_TIMEOUT  workload knobs
#   PFS_EXPECT_FILE  overrides the declared platform expectations
#
# Preconditions: both Macs freshly clean of wedged kernel mounts; binaries and
# pfs-mount-stress staged at ~/Developer/steerlabs/.portablefs-stress-<tag>-prod/bin
# (local) and ~/.portablefs-stress-<tag>-prod/bin (remote); FSKit extension
# installed+enabled on both.
#
# Platform expectations: a small number of checks assert semantics macOS FSKit
# cannot provide to any filesystem. They are declared by name with a stated
# reason in the EXPECTATIONS list below, are reported individually, and are the
# only failures this driver tolerates. Everything else fails the run, an
# unattributable failure fails the run, and a declared expectation that stops
# failing also fails the run so the list cannot rot into a blanket excuse.
set -u

fail() { echo "FATAL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Declared platform expectations.
#
# Two checks assert semantics macOS FSKit cannot provide to any filesystem:
# cross-host fcntl exclusion (no lock operations in the extension API) and
# cross-host O_APPEND atomicity (the kernel resolves append offsets from its
# cached EOF before the extension sees the write; FSVolumeOpenModes carries no
# append intent).
#
# Every other failure is a failure. In particular:
#
#   * a nonzero exit whose cause cannot be attributed to a declared expectation
#     is FAIL, including the case where nothing in the output could be
#     classified at all. A driver that cannot explain a failure has not proved
#     the failure was benign. The previous version of this script treated that
#     exact case as a pass;
#   * a declared expectation that does NOT fail is reported as an unexpected
#     pass and fails the run, because a platform limitation that quietly
#     started working must be re-examined and removed from this list rather
#     than left as a permanent excuse.
#
# Format: <name>|<extended regex matching the failing check>|<reason>
# ---------------------------------------------------------------------------
EXPECTATIONS=(
  "cross_host_fcntl_exclusion|locked counter|FSKit exposes no advisory-lock operation, so cross-machine fcntl exclusion does not exist on an FSKit mount"
  "cross_host_append_atomicity|shared append|the kernel resolves the O_APPEND offset from its cached EOF before the extension sees the write, and FSVolumeOpenModes carries no append intent"
)

load_expectations() {
  [ -n "${PFS_EXPECT_FILE:-}" ] || return 0
  [ -r "$PFS_EXPECT_FILE" ] || fail "PFS_EXPECT_FILE is not readable: $PFS_EXPECT_FILE"
  EXPECTATIONS=()
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    EXPECTATIONS+=("$line")
  done < "$PFS_EXPECT_FILE"
}

# classify reads $OUT/stress-{local,remote}.json plus the exit codes $L and $R
# and sets UNEXPECTED_FAILURES, UNEXPECTED_PASSES and EXPECTED_HITS.
classify() {
  load_expectations
  [ ${#EXPECTATIONS[@]} -gt 0 ] || fail "no expectations are declared; an empty list cannot classify a failure"

  local local_result="$OUT/stress-local.json" remote_result="$OUT/stress-remote.json"
  for file in "$local_result" "$remote_result"; do
    [ -r "$file" ] || fail "missing workload result $file; a run whose output cannot be read cannot be declared a pass"
  done

  # Every line from either side that reports a problem.
  FAILURE_LINES="$(grep -hiE "verify|error|fail|timed out|lost|mismatch" "$local_result" "$remote_result" 2>/dev/null)"

  UNEXPECTED_FAILURES=""
  UNEXPECTED_PASSES=""
  EXPECTED_HITS=""
  local match_all="" entry name rest pattern reason

  echo "== declared platform expectations =="
  for entry in "${EXPECTATIONS[@]}"; do
    name="${entry%%|*}"; rest="${entry#*|}"
    pattern="${rest%%|*}"; reason="${rest#*|}"
    match_all="${match_all:+$match_all|}$pattern"
    if printf '%s\n' "$FAILURE_LINES" | grep -qiE -- "$pattern"; then
      echo "EXPECTED-FAIL   $name: $reason"
      EXPECTED_HITS="$EXPECTED_HITS $name"
    elif [ "$L" -eq 0 ] && [ "$R" -eq 0 ]; then
      echo "UNEXPECTED-PASS $name: declared to fail on this platform but the run reported no such failure. Re-examine it and remove the expectation if the limitation is gone."
      UNEXPECTED_PASSES="$UNEXPECTED_PASSES $name"
    else
      echo "NOT-OBSERVED    $name: the run failed for other reasons before this check reported"
    fi
  done

  if [ "$L" -ne 0 ] || [ "$R" -ne 0 ]; then
    if [ -n "$FAILURE_LINES" ]; then
      UNEXPECTED_FAILURES="$(printf '%s\n' "$FAILURE_LINES" | grep -ivE -- "$match_all" | grep -vE '^[[:space:]]*$')"
    else
      # The workload exited nonzero and printed nothing this driver can
      # attribute. Silently calling that a platform limitation is exactly how a
      # real defect ships, so it is an undeclared failure.
      UNEXPECTED_FAILURES="the workload exited nonzero (local=$L remote=$R) without any output this driver could attribute to a declared expectation"
    fi
  fi
}

report_result() {
  echo "== result =="
  echo "local-exit=$L remote-exit=$R"
  if [ -n "$UNEXPECTED_FAILURES" ]; then
    echo "undeclared failures:"
    printf '%s\n' "$UNEXPECTED_FAILURES" | head -20 | sed 's/^/  /'
  fi
  if [ -n "$UNEXPECTED_PASSES" ]; then
    echo "expectations that did not fail:$UNEXPECTED_PASSES"
  fi
  if [ -n "$UNEXPECTED_FAILURES" ] || [ -n "$UNEXPECTED_PASSES" ]; then
    echo "RESULT: FAIL"
    exit 1
  fi
  if [ "$L" -eq 0 ] && [ "$R" -eq 0 ]; then
    echo "RESULT: PASS (no failures; no declared expectation was needed)"
    exit 0
  fi
  echo "RESULT: PASS-WITH-DECLARED-EXPECTED-FAILURES ($(echo "$EXPECTED_HITS" | tr -s ' ' | sed 's/^ //'))"
  echo "Those named checks are known not to hold on macOS FSKit. Every other check passed."
  exit 0
}

reconcile_stale() { # $1 = mounts json, prints stale mountPaths
  python3 -c 'import json,sys; d=json.load(sys.stdin); [print(m["mountPath"]) for m in d.get("mounts",[]) if not m.get("alive")]' <<<"$1"
}

live_run() {
  TAG="${1:?usage: two-mac-stress.sh <build-tag>}"
  VOL="${PFS_VOLUME:-portablefs-cloud-3}"
  REMOTE="${PFS_REMOTE:-user@mac-b.local}"
  FILES="${PFS_FILES:-500}"
  APPENDS="${PFS_APPENDS:-1500}"
  BIG_MIB="${PFS_BIG_MIB:-64}"
  LOCK_ITERS="${PFS_LOCK_ITERS:-200}"
  TIMEOUT="${PFS_TIMEOUT:-5m}"

  LROOT="$HOME/Developer/steerlabs/.portablefs-stress-$TAG-prod"
  RROOT=".portablefs-stress-$TAG-prod"     # relative to remote $HOME
  BIN="$LROOT/bin/portablefs"
  STAMP="$(date +%Y%m%d-%H%M)"
  BRANCH="stress-$TAG-2mac-$STAMP"
  RUN_ID="$TAG-2mac-$STAMP"
  OUT="$LROOT/results"; mkdir -p "$OUT"
  SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE")

  [ -x "$BIN" ] || fail "missing $BIN"
  "${SSH[@]}" "test -x \$HOME/$RROOT/bin/pfs-mount-stress" || fail "remote harness missing"

  echo "== preflight: reconcile stale records, refuse live mounts =="
  LJSON="$("$BIN" mounts --json | tee "$OUT/preflight-local.json")"
  grep -q '"alive": true' <<<"$LJSON" && fail "local live mount present; clean up first"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    echo "reconciling stale local record: $p"
    "$BIN" umount "$p" || "$BIN" umount --force "$p" || fail "reconcile stale local record $p"
  done < <(reconcile_stale "$LJSON")
  RJSON="$("${SSH[@]}" "\$HOME/$RROOT/bin/portablefs mounts --json" | tee "$OUT/preflight-remote.json")"
  grep -q '"alive": true' <<<"$RJSON" && fail "remote live mount present; clean up first"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    echo "reconciling stale remote record: $p"
    "${SSH[@]}" "\$HOME/$RROOT/bin/portablefs umount '$p' || \$HOME/$RROOT/bin/portablefs umount --force '$p'" || fail "reconcile stale remote record $p"
  done < <(reconcile_stale "$RJSON")

  echo "== branch $BRANCH =="
  "$BIN" branch "$VOL" "$BRANCH" || fail "branch create"

  echo "== mounting both Macs concurrently =="
  mkdir -p "$LROOT/mount"
  "$BIN" mount "$VOL" "$LROOT/mount" --branch "$BRANCH" --strategy fskit > "$OUT/mount-local.txt" 2>&1 &
  LMPID=$!
  "${SSH[@]}" "mkdir -p \$HOME/$RROOT/mount && \$HOME/$RROOT/bin/portablefs mount $VOL \$HOME/$RROOT/mount --branch $BRANCH --strategy fskit" > "$OUT/mount-remote.txt" 2>&1 &
  RMPID=$!
  LOK=0; ROK=0
  wait $LMPID && LOK=1
  wait $RMPID && ROK=1
  if [ $LOK -ne 1 ] || [ $ROK -ne 1 ]; then
    cat "$OUT/mount-local.txt" "$OUT/mount-remote.txt"
    # Roll back whichever side mounted so a rerun starts clean.
    [ $LOK -eq 1 ] && "$BIN" umount "$LROOT/mount"
    [ $ROK -eq 1 ] && "${SSH[@]}" "\$HOME/$RROOT/bin/portablefs umount \$HOME/$RROOT/mount"
    fail "mount phase (local=$LOK remote=$ROK)"
  fi
  cat "$OUT/mount-local.txt" "$OUT/mount-remote.txt"

  T0="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "== simultaneous workload run=$RUN_ID =="
  "$LROOT/bin/pfs-mount-stress" -root "$LROOT/mount" -run "$RUN_ID" \
    -host local -peer remote -files "$FILES" -appends "$APPENDS" \
    -big-mib "$BIG_MIB" -lock-iters "$LOCK_ITERS" -timeout "$TIMEOUT" \
    > "$OUT/stress-local.json" 2>&1 &
  LSPID=$!
  "${SSH[@]}" "\$HOME/$RROOT/bin/pfs-mount-stress -root \$HOME/$RROOT/mount -run $RUN_ID \
    -host remote -peer local -files $FILES -appends $APPENDS \
    -big-mib $BIG_MIB -lock-iters $LOCK_ITERS -timeout $TIMEOUT" \
    > "$OUT/stress-remote.json" 2>&1 &
  RSPID=$!
  wait $LSPID; L=$?
  wait $RSPID; R=$?

  echo "local-exit=$L remote-exit=$R"
  echo "--- local result ---";  tail -40 "$OUT/stress-local.json"
  echo "--- remote result ---"; tail -40 "$OUT/stress-remote.json"

  classify

  echo "== unmount both =="
  "$BIN" umount "$LROOT/mount" && echo "local unmount OK" || echo "LOCAL UNMOUNT FAILED"
  "${SSH[@]}" "\$HOME/$RROOT/bin/portablefs umount \$HOME/$RROOT/mount" && echo "remote unmount OK" || echo "REMOTE UNMOUNT FAILED"

  echo "== FSKit error scan since $T0 =="
  /usr/bin/log show --style compact --start "$T0" \
    --predicate 'process == "PortableFSDev"' 2>/dev/null \
    | grep -iE "incomplete|ESTALE|reply:error" | head -20
}

# Entry points. --classify re-runs only the decision logic over an existing
# results directory, so the pass/fail rules themselves are testable without two
# Macs and without a live volume.
case "${1:-}" in
  --classify)
    OUT="${2:?usage: two-mac-stress.sh --classify <results-dir> <local-exit> <remote-exit>}"
    L="${3:?usage: two-mac-stress.sh --classify <results-dir> <local-exit> <remote-exit>}"
    R="${4:?usage: two-mac-stress.sh --classify <results-dir> <local-exit> <remote-exit>}"
    classify
    report_result
    ;;
  *)
    live_run "$@"
    report_result
    ;;
esac
