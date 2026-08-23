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
#   PHASE 9 NEEDS A SECOND CAPABILITY. An initial grant is single-use and
#   creates a session at authorization sequence zero (docs/hosted-control-plane.md,
#   "Automatic long-lived mounts"), so the remount that phase 9 exists to
#   perform CANNOT reuse PORTABLEFS_MOUNT_TOKEN: the authority refuses the
#   second attach with errno 1. Supply one of these, or phase 9 is skipped
#   loudly and the run is not durability-qualified:
#
#     --mount-token-command CMD   run CMD and read a freshly minted capability
#                                 from its stdout, each time one is needed. CMD
#                                 is passed to `sh -c` with no arguments and
#                                 must print the capability and nothing else.
#                                 Preferred: a grant is short-lived, and a token
#                                 minted before phase 1 can expire before phase
#                                 9 reaches it.
#     PORTABLEFS_REMOUNT_TOKEN    a second capability, pre-minted. Environment
#                                 only, for the same reason as the first.
#
#   The command appears in process arguments; its output does not. Do not put a
#   capability in CMD itself.
#
#   Optional hosted enrollment group, all-or-none, passed through to
#   `portablefs mount` unchanged:
#     --manager-url --manager-server-name --manager-ca
#     --mount-enrollment-id --mount-enrollment-cert
#     --authority-generation --auth-expires-at-ms
#
# EXIT
#   0  every phase passed
#   1  a phase observed wrong data, a failed operation, or an unclean unmount
#   64 usage error
#
# WHAT EACH PHASE ASSERTS is documented at the phase. Read phase 7 before
# interpreting a hot-file failure: it is the one phase with a documented,
# deliberately tolerated residual.
#
# Phase 8 is the concurrent-reader workload the merge gate deliberately does not
# run: a dependency tree installed package-by-package while several readers
# enumerate and read it. `scripts/package-manager-matrix.sh` drives the same
# shape harder — real npm/pnpm/yarn/bun installs against two kernel FUSE mounts
# of one volume in a container — and is run on demand, not in CI, because it is
# a workload soak rather than a merge gate.
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
mount_token_command=
mount_args=()

while (( $# )); do
  case "$1" in
    --portablefs) portablefs=$2; shift 2 ;;
    --mount-path) mount_path=$2; shift 2 ;;
    --rounds) rounds=$2; shift 2 ;;
    --hot-file-readers) hot_readers=$2; shift 2 ;;
    --hot-file-rounds) hot_rounds=$2; shift 2 ;;
    --keep-mount) keep_mount=1; shift ;;
    --mount-token-command) mount_token_command=$2; shift 2 ;;
    --volume-id) volume_id=$2; shift 2 ;;
    --addr|--data-plane-transport|--data-plane-server-name|--data-plane-ca|\
    --client-cert|--client-key|--manager-url|--manager-server-name|--manager-ca|\
    --mount-enrollment-id|--mount-enrollment-cert|\
    --authority-generation|--auth-expires-at-ms)
      mount_args+=("$1" "$2"); shift 2 ;;
    --no-local-dirs) mount_args+=("$1"); shift ;;
    # The header is printed to its own end rather than to a line number, so
    # documenting a new option cannot silently truncate --help.
    -h|--help) awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) usage "unknown argument: $1" ;;
  esac
done

[[ -n $volume_id ]] || usage "--volume-id is required"
[[ -x $portablefs ]] || usage "client binary is not executable: $portablefs"
[[ -n ${PORTABLEFS_MOUNT_TOKEN:-} ]] || usage "PORTABLEFS_MOUNT_TOKEN must be set"
if [[ -n $mount_token_command && -n ${PORTABLEFS_REMOUNT_TOKEN:-} ]]; then
  usage "--mount-token-command and PORTABLEFS_REMOUNT_TOKEN are alternatives; set exactly one"
fi

# next_mount_token prints the capability the NEXT attach must use. Every attach
# consumes one: an initial grant is single-use and lands the session at
# authorization sequence zero, so reusing one is refused with errno 1 rather
# than tolerated. Phase 9 is the only phase that attaches twice.
next_mount_token() {
  if [[ -n $mount_token_command ]]; then
    local minted
    minted=$(sh -c "$mount_token_command") ||
      fail "--mount-token-command exited nonzero; it must print one freshly minted capability"
    # A mint command that prints nothing has failed in the one way that would
    # otherwise present as an authorization error a phase later.
    [[ -n $minted ]] || fail "--mount-token-command printed no capability"
    printf '%s' "$minted"
    return 0
  fi
  printf '%s' "${PORTABLEFS_REMOUNT_TOKEN:-}"
}

remount_capable=0
if [[ -n $mount_token_command || -n ${PORTABLEFS_REMOUNT_TOKEN:-} ]]; then
  remount_capable=1
fi
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
# Phase 8 — dependency-tree install racing concurrent readers.
#
# Phase 7 is several readers against ONE file. This is the other concurrent-read
# shape, and the one every dependency installer produces: a metadata-heavy tree
# arriving package by package while other processes enumerate and read it. npm,
# pnpm, yarn and bun all unpack a package beside its destination and rename(2)
# it into place, so a directory that appears in the tree is a directory that is
# already complete. That is the contract asserted here.
#
# The writer installs $tree_packages packages of $tree_files files each, each
# one built in a staging directory ON THE MOUNT (so the move is a real rename,
# not a copy) and renamed into node_modules/. The readers enumerate that tree
# throughout and fully read every package they can see.
#
#   PASS: every package a reader observed held exactly its own complete,
#         byte-exact contents, and the finished tree is exactly what was
#         installed.
#   FAIL: a reader saw a package directory that was incomplete, held bytes no
#         writer produced, or held an entry count nobody wrote. Any of those is
#         a half-visible rename, which no POSIX filesystem may show.
#
# A reader observing FEWER packages than are installed is not a failure: that is
# the same bounded §7.3b staleness phase 7a documents. What must never happen is
# a package that is visible but not whole.
#
# This is the shape scripts/package-manager-matrix.sh drives with real
# installers on two mounts in a container. This phase is its qualification
# stand-in on a live cell: same concurrency, no npm registry, one mount.
# ---------------------------------------------------------------------------
tree_packages=24
tree_files=8
phase "8. dependency-tree install ($tree_packages packages) racing $hot_readers readers"
tree_root="$run_root/node_modules"
tree_staging="$run_root/.tree-staging"
mkdir -p -- "$tree_root"

# tree_body prints the exact complete contents of package $1, in the exact order
# a reader concatenates them. Writer and reader both derive their bytes from it,
# so a package can only match if every one of its files is present and exact.
tree_body() {
  local p=$1 k
  printf '{"name":"pkg-%03d"}\n' "$p"
  for (( k = 1; k <= tree_files; k++ )); do
    printf 'package %03d file %02d\n' "$p" "$k"
  done
}

tree_installer() {
  local p k
  for (( p = 1; p <= tree_packages; p++ )); do
    rm -rf -- "$tree_staging"
    mkdir -p -- "$tree_staging"
    printf '{"name":"pkg-%03d"}\n' "$p" >"$tree_staging/package.json"
    for (( k = 1; k <= tree_files; k++ )); do
      printf 'package %03d file %02d\n' "$p" "$k" >"$tree_staging/file-$k.txt"
    done
    mv -T -- "$tree_staging" "$(printf '%s/pkg-%03d' "$tree_root" "$p")"
  done
}

# tree_read_package returns 0 when $1 is a complete, byte-exact package and 1
# when it is not. It never treats an absent package as a fault; only a present
# one that is wrong.
tree_read_package() {
  local dir=$1 name number entries observed expected k
  name=${dir%/}
  name=${name##*/}
  [[ $name =~ ^pkg-[0-9]{3}$ ]] || {
    echo "reader observed an entry no installer wrote: $name" >&2
    return 1
  }
  number=$(( 10#${name#pkg-} ))
  entries=$(find "$dir" -mindepth 1 2>/dev/null | wc -l)
  if (( entries != tree_files + 1 )); then
    echo "reader observed $name with $entries entries, not the $(( tree_files + 1 )) that were renamed into place" >&2
    return 1
  fi
  observed=$( { cat "$dir/package.json"; for (( k = 1; k <= tree_files; k++ )); do cat "$dir/file-$k.txt"; done; } 2>/dev/null )
  expected=$(tree_body "$number")
  if [[ $observed != "$expected" ]]; then
    echo "reader observed $name holding bytes the installer never wrote" >&2
    return 1
  fi
  return 0
}

tree_reader() {
  local id=$1 rounds=0 verified=0 dir
  while [[ ! -e "$work/tree-installed" ]]; do
    rounds=$(( rounds + 1 ))
    for dir in "$tree_root"/*/; do
      [[ -d $dir ]] || continue
      tree_read_package "$dir" || return 1
      verified=$(( verified + 1 ))
    done
  done
  printf '%d %d\n' "$rounds" "$verified" >"$work/tree-reader-$id"
  return 0
}

rm -f -- "$work/tree-installed"
tree_reader_pids=()
for (( r = 1; r <= hot_readers; r++ )); do
  tree_reader "$r" &
  tree_reader_pids+=("$!")
done
# The readers stop when the marker appears, so it is written even when the
# installer fails: a reader left spinning on the mount would outlive this script
# and hang the unmount its cleanup performs.
install_status=0
tree_installer || install_status=1
: >"$work/tree-installed"
tree_status=0
for pid in "${tree_reader_pids[@]}"; do
  wait "$pid" || tree_status=1
done
(( install_status == 0 )) || fail "the dependency-tree installer failed"
(( tree_status == 0 )) || fail "phase 8: a reader observed a package that was visible but not whole"

tree_rounds=0
tree_verified=0
for (( r = 1; r <= hot_readers; r++ )); do
  [[ -r "$work/tree-reader-$r" ]] || fail "phase 8: reader $r produced no observation record"
  read -r round_count verified_count <"$work/tree-reader-$r"
  tree_rounds=$(( tree_rounds + round_count ))
  tree_verified=$(( tree_verified + verified_count ))
done
(( tree_verified > 0 )) ||
  fail "phase 8: the readers finished without verifying a single package; the phase proved nothing"
echo "   readers: $tree_verified complete package reads over $tree_rounds enumeration rounds"

# The installed tree itself, from the mount that wrote it: exactly the packages
# installed, each exactly its own contents, nothing extra.
installed=$(find "$tree_root" -mindepth 1 -maxdepth 1 | wc -l)
(( installed == tree_packages )) ||
  fail "phase 8: the finished tree holds $installed packages, expected $tree_packages"
[[ ! -e $tree_staging ]] || fail "phase 8: the installer's staging directory survived its own rename"
for (( p = 1; p <= tree_packages; p++ )); do
  tree_read_package "$(printf '%s/pkg-%03d' "$tree_root" "$p")" ||
    fail "phase 8: the finished tree is not what the installer wrote"
done
printf 'serves\n' >"$run_root/after-install"
[[ $(cat "$run_root/after-install") == serves ]] || fail "phase 8: the mount stopped serving after the install"
ok "every observed package was complete and the finished tree is exactly what was installed"

# ---------------------------------------------------------------------------
# Phase 9 — read-back after unmount and remount. Everything written above must
# be durable in the volume, not merely visible through the mount that wrote it.
# ---------------------------------------------------------------------------
phase "9. unmount, remount, and verify durability"
serial_digest=$(sha256sum <"$append_file" | cut -d' ' -f1)
tee_digest=$(sha256sum <"$tee_file" | cut -d' ' -f1)
shared_digest=$(sha256sum <"$shared" | cut -d' ' -f1)
head_commit=$(git -C "$repo" rev-parse HEAD)
tree_manifest() {
  find "$tree_root" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
}
tree_digest=$(tree_manifest)

if (( ! remount_capable )); then
  # A loud skip, not a quiet pass. The remount needs a capability this run was
  # not given, and reusing the first one is refused by the authority -- so
  # asserting durability here would mean asserting it without having remounted.
  echo "   SKIP: phase 9 needs a second mount capability and none was supplied." >&2
  echo "         An initial grant is single-use, so the remount cannot reuse" >&2
  echo "         PORTABLEFS_MOUNT_TOKEN. Pass --mount-token-command CMD or set" >&2
  echo "         PORTABLEFS_REMOUNT_TOKEN. THIS RUN DID NOT QUALIFY DURABILITY." >&2
  phase "qualification passed (phases 1-8; phase 9 skipped)"
else

"$portablefs" umount "$mount_path" || fail "unmount failed"
mounted=0
! mountpoint -q -- "$mount_path" || fail "unmount returned success but $mount_path is still a mount point"
[[ -z $(ls -A -- "$mount_path") ]] || fail "the mountpoint is not empty after unmount; volume content is leaking to local disk"
ok "unmounted cleanly and the mountpoint is empty"

remount_token=$(next_mount_token)
[[ -n $remount_token ]] || fail "no capability available for the phase 9 remount"
PORTABLEFS_MOUNT_TOKEN="$remount_token" \
  "$portablefs" mount "$volume_id" "$mount_path" "${mount_args[@]}" --strategy fuse ||
  fail "remount failed; an initial grant is single-use, so this needs a capability distinct from the one phase 2 consumed"
mounted=1
[[ $(sha256sum <"$append_file" | cut -d' ' -f1) == "$serial_digest" ]] || fail "serial append content changed across remount"
[[ $(sha256sum <"$tee_file" | cut -d' ' -f1) == "$tee_digest" ]] || fail "tee append content changed across remount"
[[ $(sha256sum <"$shared" | cut -d' ' -f1) == "$shared_digest" ]] || fail "concurrent append content changed across remount"
[[ $(tree_manifest) == "$tree_digest" ]] || fail "the installed dependency tree changed across remount"
[[ $(git -C "$repo" rev-parse HEAD) == "$head_commit" ]] || fail "git HEAD changed across remount"
git -C "$repo" fsck --strict >/dev/null || fail "git object store is damaged after remount"
ok "every artifact survived unmount and remount byte-identically"

phase "qualification passed"
fi
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
