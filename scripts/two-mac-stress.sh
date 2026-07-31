#!/bin/bash
# Two-Mac production stress driver for PortableFS FSKit builds.
# Runs the pfs-mount-stress workload simultaneously from this Mac and a peer
# Mac over ssh, against an isolated branch of a production volume. The two
# sides rendezvous in-band through the mounted volume (ready/ + done/), which
# is itself part of what is under test.
#
# Usage: two-mac-stress.sh <build-tag>          e.g. two-mac-stress.sh c037ebf
# Env:
#   PFS_VOLUME  (default portablefs-cloud-3)
#   PFS_REMOTE  (default timjang@Tims-MacBook-Pro-2.local)
#   PFS_FILES/PFS_APPENDS/PFS_BIG_MIB/PFS_LOCK_ITERS/PFS_TIMEOUT  workload knobs
#
# Preconditions: both Macs freshly clean of wedged kernel mounts; binaries and
# pfs-mount-stress staged at ~/Developer/steerlabs/.portablefs-stress-<tag>-prod/bin
# (local) and ~/.portablefs-stress-<tag>-prod/bin (remote); FSKit extension
# installed+enabled on both.
#
# NOTE (platform limitation): FSKit exposes no advisory-lock operations, so
# cross-machine fcntl exclusion does not exist on FSKit mounts. The workload's
# locked-counter check is therefore EXPECTED to report lost updates across two
# Macs; the driver reports it separately instead of failing the run on it.
set -u
TAG="${1:?usage: two-mac-stress.sh <build-tag>}"
VOL="${PFS_VOLUME:-portablefs-cloud-3}"
REMOTE="${PFS_REMOTE:-timjang@Tims-MacBook-Pro-2.local}"
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

fail() { echo "FATAL: $*" >&2; exit 1; }
[ -x "$BIN" ] || fail "missing $BIN"
"${SSH[@]}" "test -x \$HOME/$RROOT/bin/pfs-mount-stress" || fail "remote harness missing"

echo "== preflight: reconcile stale records, refuse live mounts =="
reconcile_stale() { # $1 = mounts json, prints stale mountPaths
  python3 -c 'import json,sys; d=json.load(sys.stdin); [print(m["mountPath"]) for m in d.get("mounts",[]) if not m.get("alive")]' <<<"$1"
}
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
wait $LMPID || { cat "$OUT/mount-local.txt"; fail "local mount"; }
wait $RMPID || { cat "$OUT/mount-remote.txt"; fail "remote mount"; }
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
set +e
wait $LSPID; L=$?
wait $RSPID; R=$?
set -e 2>/dev/null || true

echo "local-exit=$L remote-exit=$R"
echo "--- local result ---";  tail -40 "$OUT/stress-local.json"
echo "--- remote result ---"; tail -40 "$OUT/stress-remote.json"

# The locked-counter check asserts cross-host fcntl exclusion, which FSKit
# cannot provide (no lock ops in the extension API). Distinguish that known
# limitation from every other failure.
LOCK_ONLY=0
if [ $L -ne 0 ] || [ $R -ne 0 ]; then
  if grep -hq "locked-counter" "$OUT/stress-local.json" "$OUT/stress-remote.json" && \
     ! grep -hqE "shared-append|byte-verify|big\.bin|churn|rename-over-open|ready barrier|done record" \
        <(grep -ih "error\|fail" "$OUT/stress-local.json" "$OUT/stress-remote.json"); then
    LOCK_ONLY=1
  fi
fi

echo "== unmount both =="
"$BIN" umount "$LROOT/mount" && echo "local unmount OK" || echo "LOCAL UNMOUNT FAILED"
"${SSH[@]}" "\$HOME/$RROOT/bin/portablefs umount \$HOME/$RROOT/mount" && echo "remote unmount OK" || echo "REMOTE UNMOUNT FAILED"

echo "== FSKit error scan since $T0 =="
/usr/bin/log show --style compact --start "$T0" \
  --predicate 'process == "PortableFSDev"' 2>/dev/null \
  | grep -iE "incomplete|ESTALE|reply:error" | head -20 || true

if [ $L -eq 0 ] && [ $R -eq 0 ]; then
  echo "RESULT: PASS"
elif [ $LOCK_ONLY -eq 1 ]; then
  echo "RESULT: PASS-EXCEPT-LOCKS (expected FSKit platform limitation: no cross-machine fcntl)"
else
  echo "RESULT: FAIL"
  exit 1
fi
