#!/usr/bin/env bash
# Measure the AUTHORITY-DURABLE upload rate of the write-back flusher against a
# live mount.
#
# write(2) on a delegated scope acknowledges from the local WAL, and fsync(2)
# returns once the local WAL is synced — neither one tells you when the bytes
# reached the authority. The only honest end-to-end number is:
#
#     bytes / (time from first write until the flusher's pending queue is empty)
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

SUB="$MOUNT/bench-flushrate-$$"
SAMPLES="$(mktemp)"
trap 'rm -rf "$SUB" "$SAMPLES" 2>/dev/null || true' EXIT

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
trap 'kill $SAMPLER 2>/dev/null || true; rm -rf "$SUB" "$SAMPLES" 2>/dev/null || true' EXIT

sleep 1
T0="$(date +%s.%N)"
echo "== writing ${MB}MiB of incompressible data into $SUB"
"$BIN" -dir "$SUB" -bulk "$MB" -bulkchunk "$CHUNK" -keep
TW="$(date +%s.%N)"

echo "== waiting for the flusher's pending queue to drain"
clean=0
while [ "$clean" -lt "$SETTLE" ]; do
  line="$("$PFS" mounts 2>/dev/null | grep -F "$MOUNT" || true)"
  if printf '%s' "$line" | grep -q 'write-back:'; then clean=0; else clean=$((clean + 1)); fi
  sleep "$INTERVAL"
done
T1="$(date +%s.%N)"
kill $SAMPLER 2>/dev/null || true

python3 - "$T0" "$TW" "$T1" "$MB" "$SETTLE" "$INTERVAL" "$SAMPLES" <<'PY'
import sys
t0, tw, t1, mb, settle, interval = (float(x) for x in sys.argv[1:7])
# The settle window is dead time after the queue was already empty.
t1 -= settle * interval
acked, durable = tw - t0, t1 - t0
print(f"payload         {mb:.0f} MiB")
print(f"write-acked     {acked:.2f}s  = {mb/acked:8.2f} MB/s (local WAL ack rate)")
print(f"authority-drain {durable:.2f}s  = {mb/durable:8.2f} MB/s (end-to-end durable rate)")
print(f"post-ack tail   {durable-acked:.2f}s spent shipping after the last write(2) returned")
rows = [l.split() for l in open(sys.argv[7]) if l.strip()]
peak = max((int(r[1]) for r in rows), default=0)
print(f"peak pending    {peak} records")
PY
