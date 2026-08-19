#!/usr/bin/env bash
# staging-qualification.sh — the real-workload qualification corpus for one
# PortableFS release, run against a live mount on a staging cell.
#
# This is the gate the candidate-template smoke deliberately is not. The smoke
# (deploy/opensteer/e2b-release.mjs smoke) runs with no manager and no
# authority, so all it can prove is that the shipped client completes a kernel
# FUSE INIT handshake. Everything a tenant actually does — appending to a file,
# committing a git tree, two processes writing the same file, reading a file
# another process is rewriting — needs a real authority behind a real mount,
# which is what this script drives.
#
# It runs anywhere Linux, /dev/fuse and the release client are available: an
# e2b sandbox built from the candidate template, a cell host, or a scratch VM.
# It never installs, promotes, or mutates a deployment; it mounts a volume you
# name, exercises it, and unmounts.
#
# USAGE
#   deploy/opensteer/staging-qualification.sh \
#     --volume-id VOLUME --addr host:port \
#     --data-plane-transport tls-private-ca|tls-system-pki \
#     --data-plane-server-name NAME [--data-plane-ca /abs/ca.pem] \
#     --client-cert /abs/cert.pem --client-key /abs/key.pem \
#     [--portablefs /abs/portablefs] [--mount-path /abs/mountpoint] \
#     [--rounds N] [--hot-file-readers N] [--hot-file-rounds N] \
#     [--keep-mount]
#
#   PORTABLEFS_MOUNT_TOKEN must hold the single-use mount capability. It is
#   read from the environment only, never from a flag, so it never appears in
#   process arguments.
#
#   Optional hosted enrollment group, all-or-none, passed through to
#   `portablefs mount` unchanged:
#     --manager-url --manager-server-name --manager-ca
#     --mount-enrollment-id --mount-enrollment-cert
#     --mount-enrollment-expires-at-ms --authority-generation
#     --auth-expires-at-ms
#
# EXIT
#   0  every phase passed
#   1  a phase observed wrong data, a failed operation, or an unclean unmount
#   64 usage error
#
# WHAT EACH PHASE ASSERTS is documented at the phase. Read phase 7 before
# interpreting a hot-file failure: it is the one phase with a documented,
# deliberately tolerated residual.
set -euo pipefail

fail() { echo "staging-qualification: $*" >&2; exit 1; }
usage() { echo "staging-qualification: $*" >&2; exit 64; }
phase() { printf '\n== %s ==\n' "$*"; }
ok() { printf '   ok: %s\n' "$*"; }

portablefs=/opt/opensteer/portablefs/portablefs
mount_path=
volume_id=
rounds=200
hot_readers=4
hot_rounds=200
keep_mount=0
mount_args=()

while (( $# )); do
  case "$1" in
    --portablefs) portablefs=$2; shift 2 ;;
    --mount-path) mount_path=$2; shift 2 ;;
    --rounds) rounds=$2; shift 2 ;;
    --hot-file-readers) hot_readers=$2; shift 2 ;;
    --hot-file-rounds) hot_rounds=$2; shift 2 ;;
    --keep-mount) keep_mount=1; shift ;;
    --volume-id) volume_id=$2; shift 2 ;;
    --addr|--data-plane-transport|--data-plane-server-name|--data-plane-ca|\
    --client-cert|--client-key|--manager-url|--manager-server-name|--manager-ca|\
    --mount-enrollment-id|--mount-enrollment-cert|--mount-enrollment-expires-at-ms|\
    --authority-generation|--auth-expires-at-ms)
      mount_args+=("$1" "$2"); shift 2 ;;
    --no-local-dirs) mount_args+=("$1"); shift ;;
    -h|--help) sed -n '2,47p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage "unknown argument: $1" ;;
  esac
done

[[ -n $volume_id ]] || usage "--volume-id is required"
[[ -x $portablefs ]] || usage "client binary is not executable: $portablefs"
[[ -n ${PORTABLEFS_MOUNT_TOKEN:-} ]] || usage "PORTABLEFS_MOUNT_TOKEN must be set"
[[ $rounds =~ ^[0-9]+$ && $rounds -ge 10 ]] || usage "--rounds must be at least 10"
[[ $hot_readers =~ ^[0-9]+$ && $hot_readers -ge 2 ]] || usage "--hot-file-readers must be at least 2"
[[ $hot_rounds =~ ^[0-9]+$ && $hot_rounds -ge 10 ]] || usage "--hot-file-rounds must be at least 10"
[[ $(uname -s) == Linux ]] || fail "this corpus drives a Linux FUSE mount; run it on Linux"

if [[ -z $mount_path ]]; then
  mount_path=$(mktemp -d /tmp/portablefs-qualification.XXXXXXXX)
else
  [[ $mount_path == /* ]] || usage "--mount-path must be absolute"
  mkdir -p -- "$mount_path"
fi

work=$(mktemp -d /tmp/portablefs-qualification-work.XXXXXXXX)
mounted=0
cleanup() {
  local status=$?
  if (( mounted && !keep_mount )); then
    "$portablefs" umount "$mount_path" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Phase 1 — preflight. The client agrees about its own identity, and it can
# complete a real kernel FUSE INIT handshake on this host. A failure here is a
# host or binary problem, not a volume problem, and reporting it separately
# keeps a broken sandbox from being read as a coherence failure.
# ---------------------------------------------------------------------------
phase "1. client and host preflight"
"$portablefs" version
"$portablefs" mount-check --strategy fuse --probe-mount --json >"$work/probe.json" ||
  fail "the client cannot complete a kernel FUSE INIT handshake on this host"
ok "client completed a throwaway FUSE mount and INIT handshake"

# ---------------------------------------------------------------------------
# Phase 2 — mount. Everything after this point is the product's actual claim.
# ---------------------------------------------------------------------------
phase "2. mount the staging volume"
"$portablefs" mount "$volume_id" "$mount_path" "${mount_args[@]}" --strategy fuse
mounted=1
mountpoint -q -- "$mount_path" || fail "mount reported success but $mount_path is not a mount point"
ok "mounted $volume_id at $mount_path"

run_root="$mount_path/qualification-$$-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p -- "$run_root"

# ---------------------------------------------------------------------------
# Phase 3 — serial append with `echo >>`. Each round reopens the file with
# O_APPEND, writes one line, and closes. Pass criteria: after every round the
# file holds exactly the rounds written so far, in order, with no duplicate,
# missing, reordered, or truncated line.
# ---------------------------------------------------------------------------
phase "3. serial append (echo >>), $rounds rounds"
append_file="$run_root/serial-append.txt"
: >"$append_file"
for (( i = 1; i <= rounds; i++ )); do
  echo "line-$i" >>"$append_file"
done
seq 1 "$rounds" | sed 's/^/line-/' >"$work/expected-serial"
diff -u "$work/expected-serial" "$append_file" >/dev/null ||
  fail "serial append produced content that is not the exact sequence written"
ok "$rounds appended lines read back exactly"

# ---------------------------------------------------------------------------
# Phase 4 — `tee -a`. Same shape, different syscall path: tee opens O_APPEND
# and writes through its own buffering, which is how a lot of real tooling
# appends. Pass criteria are identical to phase 3.
# ---------------------------------------------------------------------------
phase "4. append through tee -a, $rounds rounds"
tee_file="$run_root/tee-append.txt"
: >"$tee_file"
for (( i = 1; i <= rounds; i++ )); do
  echo "tee-$i" | tee -a "$tee_file" >/dev/null
done
seq 1 "$rounds" | sed 's/^/tee-/' >"$work/expected-tee"
diff -u "$work/expected-tee" "$tee_file" >/dev/null ||
  fail "tee -a produced content that is not the exact sequence written"
ok "$rounds tee-appended lines read back exactly"

# ---------------------------------------------------------------------------
# Phase 5 — git. A repository is the densest ordinary workload this filesystem
# has: rename-heavy, lock-file-heavy, fsync-heavy, and it verifies its own
# object store. `git fsck` failing is unambiguous corruption, not a timing
# observation.
# ---------------------------------------------------------------------------
phase "5. git init / add / commit / fsck"
repo="$run_root/repo"
mkdir -p -- "$repo"
git -C "$repo" init --quiet
git -C "$repo" config user.email qualification@portablefs.invalid
git -C "$repo" config user.name "PortableFS Qualification"
for (( i = 1; i <= 20; i++ )); do
  printf 'content %d\n' "$i" >"$repo/file-$i.txt"
done
git -C "$repo" add -A
git -C "$repo" commit --quiet -m "qualification commit"
printf 'appended\n' >>"$repo/file-1.txt"
git -C "$repo" add -A
git -C "$repo" commit --quiet -m "qualification second commit"
[[ $(git -C "$repo" rev-list --count HEAD) == 2 ]] || fail "git history is not the two commits written"
git -C "$repo" fsck --strict >/dev/null || fail "git fsck found a damaged object store on the mount"
if git -C "$repo" status --porcelain | grep -q .; then
  fail "git reports a dirty tree immediately after committing it"
fi
ok "git created, committed, and verified a repository on the mount"

# ---------------------------------------------------------------------------
# Phase 6 — two concurrent appending processes, one file. Each process appends
# its own tagged lines with O_APPEND. Pass criteria:
#   - every line written by either process is present exactly once;
#   - no line is torn, merged with another line, or partially written.
# O_APPEND is the contract being tested: the authority owns the end-of-file
# position, so two writers must not overwrite each other's bytes. Ordering
# between the two processes is deliberately not asserted — it is not promised.
# ---------------------------------------------------------------------------
phase "6. two concurrent O_APPEND writers, $rounds rounds each"
shared="$run_root/concurrent-append.txt"
: >"$shared"
appender() {
  local tag=$1 n=$2 i
  for (( i = 1; i <= n; i++ )); do
    printf '%s-%06d\n' "$tag" "$i" >>"$shared"
  done
}
appender alpha "$rounds" &
alpha_pid=$!
appender bravo "$rounds" &
bravo_pid=$!
wait "$alpha_pid" || fail "concurrent appender alpha failed"
wait "$bravo_pid" || fail "concurrent appender bravo failed"

total=$(wc -l <"$shared")
(( total == 2 * rounds )) || fail "concurrent append wrote $total lines, expected $(( 2 * rounds ))"
malformed=$(grep -cvE '^(alpha|bravo)-[0-9]{6}$' "$shared" || true)
(( malformed == 0 )) || fail "concurrent append produced $malformed torn or merged lines"
for tag in alpha bravo; do
  distinct=$(grep -c "^$tag-" "$shared" || true)
  (( distinct == rounds )) || fail "writer $tag contributed $distinct lines, expected $rounds"
  duplicates=$(grep "^$tag-" "$shared" | sort | uniq -d | wc -l)
  (( duplicates == 0 )) || fail "writer $tag has $duplicates duplicated lines"
done
ok "both writers' lines are present exactly once and none is torn"

# ---------------------------------------------------------------------------
# Phase 7 — hot file: several readers on a file another process rewrites.
#
# Two sub-phases, because "rewrite" has two shapes and only one of them lets a
# reader demand an all-or-nothing view.
#
# In both, a generation's body is a fixed number of identical lines, each naming
# that generation, so any observation is self-describing.
#
# 7a. ATOMIC REPLACEMENT. The writer builds generation N beside the file and
#     renames it over. rename(2) is atomic, so a reader that opens the path gets
#     exactly one inode holding exactly one complete generation. Here a mixed
#     read is unambiguously wrong data and fails.
#
#       PASS: every read is one complete generation, including a stale one.
#       FAIL: a read mixes two generations, contains a malformed line, or names
#             a generation the writer never wrote.
#
#     Observing a stale generation is the tolerated case. It is the documented
#     §7.3b residual (docs/portable-coherence.md): stock FUSE does not report
#     the result of data-page invalidation, so a purge can silently fail to
#     remove a folio and a reader keeps serving older clean pages for a bounded
#     time. That is a liveness residual, not wrong data, and this phase reports
#     how stale readers got instead of failing on it.
#
# 7b. IN-PLACE REWRITE. The writer truncates the file and writes generation N
#     into it. That is not atomic on ANY POSIX filesystem — a reader can
#     legitimately catch the new head against the old tail — so a mixed read
#     here is NOT a defect and must not fail the gate. What still must hold is
#     that every byte came from some generation the writer really wrote.
#
#       PASS: every line is well-formed and names a generation <= the newest.
#             Torn reads are counted and reported.
#       FAIL: a malformed line, or a generation that was never written. Either
#             means bytes appeared that no writer produced.
#
#     7b is the phase that actually exercises data-page invalidation on a live
#     inode, which is why it is here despite being the weaker assertion.
# ---------------------------------------------------------------------------
phase "7. hot file: $hot_readers readers against a rewriting writer, $hot_rounds generations"
hot_lines=64

# hot_reader reads the file in a loop and classifies every observation.
# $1 id, $2 path, $3 "strict" (mixed reads fail) or "tolerant" (mixed reads are
# counted). It appends one line per fully consistent read to reader-$1.seen and
# one line per torn read to reader-$1.torn.
hot_reader() {
  local id=$1 path=$2 mode=$3 observed line seen torn i
  : >"$work/reader-$id.seen"
  : >"$work/reader-$id.torn"
  for (( i = 1; i <= hot_rounds * 4; i++ )); do
    observed=$(cat "$path" 2>/dev/null || true)
    [[ -n $observed ]] || continue
    seen=
    torn=0
    while IFS= read -r line; do
      if [[ ! $line =~ ^gen-[0-9]{6}$ ]]; then
        echo "reader $id observed a malformed line: $line" >&2
        return 1
      fi
      if (( 10#${line#gen-} > hot_rounds )); then
        echo "reader $id observed $line, a generation that was never written" >&2
        return 1
      fi
      if [[ -z $seen ]]; then
        seen=$line
      elif [[ $line != "$seen" ]]; then
        torn=1
        if [[ $mode == strict ]]; then
          echo "reader $id observed two generations in one atomically replaced read: $seen and $line" >&2
          return 1
        fi
      fi
    done <<<"$observed"
    if (( torn )); then
      printf '%s\n' "$seen" >>"$work/reader-$id.torn"
    else
      printf '%s\n' "$seen" >>"$work/reader-$id.seen"
    fi
  done
  return 0
}

hot_report() {
  local label=$1 r seen torn newest=0 number stalest=$hot_rounds distinct
  seen=0
  torn=0
  for (( r = 1; r <= hot_readers; r++ )); do
    seen=$(( seen + $(wc -l <"$work/reader-$r.seen") ))
    torn=$(( torn + $(wc -l <"$work/reader-$r.torn") ))
  done
  distinct=$(cat "$work"/reader-*.seen 2>/dev/null | sort -u | grep -c . || true)
  while IFS= read -r number; do
    [[ -n $number ]] || continue
    number=$(( 10#${number#gen-} ))
    (( number > newest )) && newest=$number
    (( number < stalest )) && stalest=$number
  done < <(cat "$work"/reader-*.seen 2>/dev/null || true)
  echo "   $label: $seen consistent reads over $distinct distinct generations" \
       "(oldest observed gen-$stalest, newest gen-$newest of $hot_rounds), $torn torn reads"
  if (( distinct <= 1 )); then
    echo "   note: readers observed $distinct distinct generation(s) in $label. That is" >&2
    echo "         a pass, but it means this run barely exercised the invalidation" >&2
    echo "         path; raise --hot-file-rounds before treating it as evidence." >&2
  fi
}

# hot_body writes one generation's complete body to $2. printf's format is
# deliberately not reused across arguments here: a format with two conversions
# would cycle and emit a file that names several generations, which is exactly
# the defect this phase is supposed to detect. The generator must not be able
# to manufacture its own failure.
hot_body() {
  local line k
  line=$(printf 'gen-%06d' "$1")
  {
    for (( k = 0; k < hot_lines; k++ )); do
      printf '%s\n' "$line"
    done
  } >"$2"
}

run_hot_phase() {
  local label=$1 path=$2 mode=$3 writer=$4 g tmp status=0
  hot_body 0 "$path"
  (
    for (( g = 1; g <= hot_rounds; g++ )); do
      tmp="$work/hot-gen"
      hot_body "$g" "$tmp"
      if [[ $writer == rename ]]; then
        cp -- "$tmp" "$path.next"
        mv -f -- "$path.next" "$path"
      else
        cat "$tmp" >"$path"
      fi
    done
  ) &
  local writer_pid=$! reader_pids=() pid r
  for (( r = 1; r <= hot_readers; r++ )); do
    hot_reader "$r" "$path" "$mode" &
    reader_pids+=("$!")
  done
  wait "$writer_pid" || fail "$label writer failed"
  for pid in "${reader_pids[@]}"; do
    wait "$pid" || status=1
  done
  (( status == 0 )) || fail "$label: a reader observed bytes that no generation ever contained"
  hot_report "$label"
}

run_hot_phase "7a atomic replacement" "$run_root/hot-atomic.txt" strict rename
ok "7a: every read was one complete generation"
run_hot_phase "7b in-place rewrite" "$run_root/hot-inplace.txt" tolerant inplace
ok "7b: every observed byte came from a generation the writer wrote"

# ---------------------------------------------------------------------------
# Phase 8 — read-back after unmount and remount. Everything written above must
# be durable in the volume, not merely visible through the mount that wrote it.
# ---------------------------------------------------------------------------
phase "8. unmount, remount, and verify durability"
serial_digest=$(sha256sum <"$append_file" | cut -d' ' -f1)
tee_digest=$(sha256sum <"$tee_file" | cut -d' ' -f1)
shared_digest=$(sha256sum <"$shared" | cut -d' ' -f1)
head_commit=$(git -C "$repo" rev-parse HEAD)

"$portablefs" umount "$mount_path" || fail "unmount failed"
mounted=0
! mountpoint -q -- "$mount_path" || fail "unmount returned success but $mount_path is still a mount point"
[[ -z $(ls -A -- "$mount_path") ]] || fail "the mountpoint is not empty after unmount; volume content is leaking to local disk"
ok "unmounted cleanly and the mountpoint is empty"

"$portablefs" mount "$volume_id" "$mount_path" "${mount_args[@]}" --strategy fuse
mounted=1
[[ $(sha256sum <"$append_file" | cut -d' ' -f1) == "$serial_digest" ]] || fail "serial append content changed across remount"
[[ $(sha256sum <"$tee_file" | cut -d' ' -f1) == "$tee_digest" ]] || fail "tee append content changed across remount"
[[ $(sha256sum <"$shared" | cut -d' ' -f1) == "$shared_digest" ]] || fail "concurrent append content changed across remount"
[[ $(git -C "$repo" rev-parse HEAD) == "$head_commit" ]] || fail "git HEAD changed across remount"
git -C "$repo" fsck --strict >/dev/null || fail "git object store is damaged after remount"
ok "every artifact survived unmount and remount byte-identically"

phase "qualification passed"
cat <<'NOTES'
This corpus proves the workloads it ran, on this volume, during this run. It
does not prove the volume under a load it did not apply, and it deliberately
tolerates one documented residual (phase 7).

WATCH THESE WHILE THE CORPUS RUNS — a pass here with either of these firing is
not a clean result, it is a result the authority paid for:

  1. RecallBudget exhaustion. When a peer mount does not discharge a recall
     within the authority's recall budget, the authority fences that peer's
     session and the mutation waits out the old conservative expiry bound. It
     delays one mutation and does not fence the volume, so it is invisible from
     inside this script. Watch the authority's admin endpoint:

       portablefs_authority_fence_events_total{reason="repair_deadline"}
       portablefs_authority_fence_events_total{reason="other"}
       portablefs_authority_visibility_barrier_duration_seconds

     Any nonzero increment of the fence counters during a run means a peer was
     too slow to give a lease back. Rising barrier duration without fences is
     the same problem before it becomes one.

  2. Uncertain-outcome revocations. When the authority cannot establish the
     exact result of an operation, it reports uncertainty or ends the session
     rather than guessing. On the client that shows up as a mount that has
     revoked itself:

       portablefs mounts --json          # a revoked mount reports it here
       ~/.local/state/portablefs/mounts/ # per-mount log for this mount

     and on the authority as coherence outcomes:

       portablefs_authority_rpc_requests_total{outcome="coherence"}

     A revocation during this corpus invalidates the run: every phase after it
     was running against a mount the authority had already given up on.
NOTES
