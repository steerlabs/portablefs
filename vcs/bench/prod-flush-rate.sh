#!/usr/bin/env bash
# Measure the AUTHORITY-DURABLE upload rate of the write-back flusher against a
# live mount, and separate it from the rate write(2) alone acknowledges at.
#
# write(2) on a delegated scope acknowledges from the local WAL, so the write
# phase's rate says nothing about when the bytes reached the authority. fsync(2)
# is not a local operation on this filesystem: Volume.fsync first drains the
# write-back tail to the authority and then runs an authority barrier RPC, and
# it fails rather than ever returning a local-only success. So a rate measured
# from "the writer process exited" is already an end-to-end durable rate — the
# fsync barrier is inside it — and reporting it as an ack rate hides the split.
#
# This script therefore reports both, each measured where it actually happens:
#
#   * the write-acked and fsync-barrier split as fsops itself timed them
#     (fsops emits them on its stable `fsops-bulk key=value` line)
#   * bytes / (first write until the flusher's pending queue stays empty),
#     the end-to-end durable rate, measured by sampling `portablefs mounts`
#
# so this script starts a sampler BEFORE the write, writes the payload, and
# keeps sampling until `portablefs mounts` stops reporting pending write-back
# records for a sustained settle window.
#
#   PFS=/path/to/portablefs MOUNT=/tmp/bench-m1 MB=512 ./bench/prod-flush-rate.sh
#
# Requires bench/cmd/fsops to be built (the script builds it).
set -euo pipefail

PFS="${PFS:?set PFS to the portablefs binary}"
MOUNT="${MOUNT:?set MOUNT to a live mount path}"
MB="${MB:-512}"
CHUNK="${CHUNK:-1048576}"
SETTLE="${SETTLE:-6}"          # consecutive clean samples required
INTERVAL="${INTERVAL:-0.5}"

cd "$(dirname "$0")/.."        # vcs/
BIN="$(mktemp -d)/fsops"
go build -o "$BIN" ./bench/cmd/fsops

# fsops treats this as a workspace and works inside a uniquely-owned child of
# it; the script owns and removes the workspace itself.
SUB="$MOUNT/bench-flushrate-$$"
SAMPLES="$(mktemp)"
FSOPS_OUT="$(mktemp)"
trap 'rm -rf "$SUB" "$SAMPLES" "$FSOPS_OUT" 2>/dev/null || true' EXIT

# Sampler: timestamp + pending-record count, started before the first write so
# the ramp is captured, not just the tail.
(
  while :; do
    line="$("$PFS" mounts 2>/dev/null | grep -F "$MOUNT" || true)"
    pend="$(printf '%s' "$line" | sed -n 's/.*write-back:\([0-9]*\) records.*/\1/p')"
    printf '%s %s\n' "$(date +%s.%N)" "${pend:-0}" >> "$SAMPLES"
    sleep "$INTERVAL"
  done
) &
SAMPLER=$!
trap 'kill $SAMPLER 2>/dev/null || true; rm -rf "$SUB" "$SAMPLES" "$FSOPS_OUT" 2>/dev/null || true' EXIT

sleep 1
T0="$(date +%s.%N)"
echo "== writing ${MB}MiB of incompressible data into a work dir under $SUB"
"$BIN" -dir "$SUB" -bulk "$MB" -bulkchunk "$CHUNK" -keep | tee "$FSOPS_OUT"

echo "== waiting for the flusher's pending queue to drain"
clean=0
while [ "$clean" -lt "$SETTLE" ]; do
  line="$("$PFS" mounts 2>/dev/null | grep -F "$MOUNT" || true)"
  if printf '%s' "$line" | grep -q 'write-back:'; then clean=0; else clean=$((clean + 1)); fi
  sleep "$INTERVAL"
done
T1="$(date +%s.%N)"
kill $SAMPLER 2>/dev/null || true

python3 - "$T0" "$T1" "$MB" "$SETTLE" "$INTERVAL" "$SAMPLES" "$FSOPS_OUT" <<'PY'
import sys
t0, t1, mb, settle, interval = (float(x) for x in sys.argv[1:6])
# The settle window is dead time after the queue was already empty.
t1 -= settle * interval
drain = t1 - t0

# fsops' own phase timings: it, not this script, knows where write(2) stopped
# acknowledging and the fsync barrier began.
fields = {}
for line in open(sys.argv[7]):
    if line.startswith('fsops-bulk '):
        fields = dict(kv.split('=', 1) for kv in line.split()[1:])
if not fields:
    sys.exit("fsops emitted no 'fsops-bulk' phase line; cannot report the write/fsync split")
acked = float(fields['write_acked_s'])
barrier = float(fields['fsync_barrier_s'])
durable = float(fields['durable_total_s'])

print(f"payload         {mb:.0f} MiB")
print(f"write-acked     {acked:.2f}s  = {mb/acked:8.2f} MB/s (write(2) returns; local WAL ack, no barrier)")
print(f"fsync-barrier   {barrier:.2f}s             (drain write-back tail to authority + authority barrier RPC)")
print(f"fsops durable   {durable:.2f}s  = {mb/durable:8.2f} MB/s (write + fsync barrier, as fsops timed it)")
print(f"authority-drain {drain:.2f}s  = {mb/drain:8.2f} MB/s (end-to-end: first write until pending queue stayed empty)")
print(f"post-ack tail   {drain-acked:.2f}s spent shipping after the last write(2) returned (barrier included)")
rows = [l.split() for l in open(sys.argv[6]) if l.strip()]
peak = max((int(r[1]) for r in rows), default=0)
print(f"peak pending    {peak} records")
PY
