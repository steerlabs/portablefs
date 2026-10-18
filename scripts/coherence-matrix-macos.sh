#!/bin/bash
# Cross-mount POSIX coherence matrix between a Mac and a Linux peer.
#
# It runs exactly the same named cases as scripts/coherence-matrix-linux.sh,
# using the same driver binary, so a macOS result and a Linux result are
# directly comparable line for line. Mount A is the FSKit mount on this Mac;
# mount B is a Linux kernel-FUSE mount of the same volume on a remote peer,
# driven over ssh with a Linux-built driver:
#
#   scripts/coherence-matrix-macos.sh --mount-a /path/a \
#       --remote user@linux-host --remote-mount /path/b \
#       [--remote-binary /path/to/linux/pfs-coherence-matrix]
#
# While the Mac is attached it is the volume's only writer, so the driver runs
# in --exclusive-writer mode: every shared case performs its mutations on the
# Mac and its pathname observations on the Linux peer (a descriptor stays on the
# mount that opened it), and the writer_exclusion_refuses_reader_mutations case
# attempts every kind of Linux mutation and write-intent open, requires each to
# fail with EBUSY, and requires both mounts to keep reading an unchanged
# fixture. An unexpected error, a hang, or a failed observation fails the run;
# no case is declared to fail.
#
# There is no Mac-to-Mac form. A second Mac mount of the volume - on this Mac or
# another - is refused at activation by writer exclusion, so two Mac mounts of
# one volume are not a configuration this matrix can measure. That refusal, and
# a clean detach letting a new Mac mount activate, are not asserted here:
# proving them requires attempting mounts, and this script never mounts
# anything (see below).
#
# What this script will NOT do:
#
#   * it never mounts, unmounts or otherwise drives the portablefsd daemon,
#     its control socket or its state directory under ~/.opensteer. That is a
#     separate production system. Mount the volumes yourself, or with your own
#     tooling, and pass the mountpoints in;
#   * it never runs the matrix against ordinary directories. A plain APFS
#     directory is perfectly coherent with itself, so a run like that would
#     report a wall of green that means nothing. Both paths must be real
#     PortableFS mountpoints or the script exits without running a single case;
#   * it never reports a pass for a case it could not observe. Anything it
#     cannot honestly assert - most importantly every case that needs the
#     second, Linux mount - is skipped with a loud message and a nonzero exit.
#
# Env:
#   PFS_MATRIX_BIN     prebuilt pfs-coherence-matrix (else built with go)
#   PFS_EXPECT_FSTYPE  extended regex both mount types must match (default the
#                      FSKit type pfs and the Linux type fuse.portablefs)
#   PFS_ALT_GID        an alternate GID this user belongs to, for the
#                      ownership case; the single-principal volume refuses the
#                      change, so that case skips either way
#   PFS_FENCE_COMMAND  shell command, run on this Mac, that kills the remote
#                      Linux mount uncleanly; without it the peer-loss case skips
set -u

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MOUNT_A=""
REMOTE=""
REMOTE_MOUNT=""
REMOTE_BIN="pfs-coherence-matrix"
ROUNDS=20
: "${PFS_EXPECT_FSTYPE:=^(pfs|fuse\.portablefs)$}"

fail() { echo "FATAL: $*" >&2; exit 1; }

skip_loudly() {
  echo
  echo "######################################################################"
  echo "# SKIPPED: the macOS coherence matrix did not run."
  echo "#"
  for line in "$@"; do echo "# $line"; done
  echo "#"
  echo "# No case was executed, so NOTHING about Mac/Linux cross-mount coherence"
  echo "# has been demonstrated by this invocation. Do not read this as a pass."
  echo "######################################################################"
  exit 78
}

usage() {
  echo "usage: $0 --mount-a <path> --remote <user@linux-host> --remote-mount <path> [--remote-binary <path>]" >&2
  exit 64
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mount-a) MOUNT_A="${2:-}"; shift 2 ;;
    --remote) REMOTE="${2:-}"; shift 2 ;;
    --remote-mount) REMOTE_MOUNT="${2:-}"; shift 2 ;;
    --remote-binary) REMOTE_BIN="${2:-}"; shift 2 ;;
    --atomic-replace-rounds) ROUNDS="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || fail "this matrix is the macOS half; run scripts/coherence-matrix-linux.sh on Linux"

# ---------------------------------------------------------------------------
# Preconditions. Each one that is missing produces a loud skip naming exactly
# what is absent and what it would have proved.
# ---------------------------------------------------------------------------
if [ -z "$MOUNT_A" ]; then
  skip_loudly \
    "No first mountpoint was given (--mount-a)." \
    "" \
    "This matrix drives two live mounts of one PortableFS volume. It deliberately" \
    "does not mount anything itself: mounting on this machine would go through the" \
    "portablefsd daemon and its state under ~/.opensteer, which is a separate" \
    "production system this harness must not touch." \
    "" \
    "Mount the volume once here and once on a Linux peer with your own tooling," \
    "then re-run with the mountpoints."
fi
if [ -z "$REMOTE" ] || [ -z "$REMOTE_MOUNT" ]; then
  usage
fi

# The whole point of a two-mount matrix is that the two mounts are independent
# views of one volume. A directory on the boot volume is not that.
verify_real_mount() {
  local path="$1" label="$2" line type
  [ -d "$path" ] || skip_loudly "$label $path is not a directory."
  line="$(/sbin/mount | grep -F " on $path (" | head -1)"
  if [ -z "$line" ]; then
    skip_loudly \
      "$label $path is not a mountpoint; it is an ordinary directory." \
      "" \
      "Running the matrix against ordinary directories on one local filesystem" \
      "would report every case green while proving nothing at all about" \
      "cross-mount coherence, so this run stops here." \
      "" \
      "Mount the PortableFS volume at $path and re-run."
  fi
  type="$(printf '%s' "$line" | sed -n 's/.*(\([^,)]*\).*/\1/p')"
  if ! printf '%s' "$type" | grep -qiE "$PFS_EXPECT_FSTYPE"; then
    skip_loudly \
      "$label $path is mounted, but its type is '$type'." \
      "" \
      "That is not a PortableFS mount. Asserting cross-mount POSIX coherence" \
      "against some other filesystem would be measuring the wrong product." \
      "" \
      "Set PFS_EXPECT_FSTYPE if this really is a PortableFS mount under a type" \
      "name this script does not know yet."
  fi
  echo "precondition: $label $path is a live '$type' mount"
}

verify_real_mount "$MOUNT_A" "mount-A"
echo "precondition: mount-B is remote ($REMOTE:$REMOTE_MOUNT); verifying reachability"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" true 2>/dev/null || skip_loudly \
  "The remote peer $REMOTE is not reachable over ssh with BatchMode." \
  "" \
  "Every case in this matrix needs two live mounts. With only one reachable" \
  "mount none of them can be asserted, so none of them ran."
case "$REMOTE_MOUNT" in
  *"'"*|*$'\n'*|*$'\r'*) fail "--remote-mount cannot contain quotes or newlines" ;;
esac
case "$REMOTE_BIN" in
  ""|*[!A-Za-z0-9_./-]*) fail "--remote-binary must be a command name or path containing only letters, digits, '.', '/', '_', and '-'" ;;
esac
ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" "command -v '$REMOTE_BIN' >/dev/null || test -x '$REMOTE_BIN'" 2>/dev/null || skip_loudly \
  "The remote peer $REMOTE does not have the matrix driver at '$REMOTE_BIN'." \
  "" \
  "Copy a Linux-built pfs-coherence-matrix binary there (it links nothing but" \
  "the Go standard library) and pass its path with --remote-binary."
remote_os=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" uname -s 2>/dev/null) || skip_loudly \
  "The remote peer $REMOTE did not report its operating system."
case "$remote_os" in
  Linux) ;;
  Darwin)
    fail "the remote peer $REMOTE is a Mac. A second Mac mount of the volume is refused at activation by writer exclusion, so there is no Mac-to-Mac matrix; use a Linux peer"
    ;;
  *)
    skip_loudly "The remote peer reports unsupported operating system '$remote_os'; expected Linux."
    ;;
esac
remote_type=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" "findmnt -n -r -o FSTYPE --target '$REMOTE_MOUNT'" 2>/dev/null) || skip_loudly \
  "The remote Linux path $REMOTE:$REMOTE_MOUNT is not a live mount, or findmnt is unavailable." \
  "A reachable host and driver binary do not prove the path under test is PortableFS."
remote_version=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" uname -r 2>/dev/null) || remote_version="unknown"
[ -n "$remote_type" ] || skip_loudly \
  "The remote peer's path $REMOTE:$REMOTE_MOUNT did not report a filesystem type." \
  "A reachable host and driver binary do not prove the path under test is PortableFS."
if ! printf '%s' "$remote_type" | grep -qiE "$PFS_EXPECT_FSTYPE"; then
  skip_loudly \
    "The remote peer's path $REMOTE:$REMOTE_MOUNT has filesystem type '$remote_type', which does not match '$PFS_EXPECT_FSTYPE'." \
    "That is not a verified PortableFS peer mount; no cross-machine case ran."
fi
echo "precondition: remote mount-B $REMOTE:$REMOTE_MOUNT is a live '$remote_type' mount"

# ---------------------------------------------------------------------------
# Driver binary.
# ---------------------------------------------------------------------------
MATRIX_BIN="${PFS_MATRIX_BIN:-}"
if [ -z "$MATRIX_BIN" ]; then
  command -v go >/dev/null || skip_loudly \
    "No Go toolchain and no prebuilt driver (PFS_MATRIX_BIN)." \
    "The matrix driver could not be produced, so no case ran."
  MATRIX_BIN="$(mktemp -d)/pfs-coherence-matrix"
  ( cd "$REPO_ROOT/vcs" && go build -o "$MATRIX_BIN" ./test/coherence/cmd/pfs-coherence-matrix ) ||
    fail "building the matrix driver failed"
fi
[ -x "$MATRIX_BIN" ] || fail "matrix driver is not executable: $MATRIX_BIN"

# ---------------------------------------------------------------------------
# Declared expectations.
#
# Only cases whose premise this form cannot provide are declared, and only as
# SKIP with the reason; each of them skips by itself with that same reason, so
# a declaration can never hide a failure. No case is declared to FAIL: the
# defects the hand-run matrix once found on macOS - a remote create that never
# became visible, atomic replacement failing every round, a rename leaving both
# names on one inode, a remotely deleted file that could still be reopened,
# stale mode bits - must show up red until they are fixed.
# ---------------------------------------------------------------------------
EXPECT=(
  --expect "remote_chown_visible=SKIP:the v3 volume model is single-principal, so a chown to another principal is refused by the volume itself and there is no ownership change to observe"
)
# These cases drive Linux-side harness machinery this form does not supply: a
# stale-revision routes client, the cacheless gateway, mount pause/resume for a
# missed recall, authority replacement, and machine-local route backing (which
# macOS does not serve at all).
for case_name in \
  routes_revision_mismatch \
  gateway_reads_delegated_data_without_obstructing_writer \
  recall_budget_loss_fails_barrier \
  epoch_change_stales_handles_and_new_barrier_passes \
  local_route_isolation; do
  EXPECT+=(--expect "${case_name}=SKIP:requires Linux-side harness commands or machine-local routes that the Mac plus Linux-peer form does not provide")
done

ARGS=(--a "$MOUNT_A" --exclusive-writer --atomic-replace-rounds "$ROUNDS")
ARGS+=(--b "$REMOTE_MOUNT" --b-ssh "$REMOTE" --b-ssh-binary "$REMOTE_BIN")
ARGS+=(--label "macOS $(sw_vers -productVersion) + Linux $remote_version: two hosts, one volume")
if [ -n "${PFS_ALT_GID:-}" ]; then
  ARGS+=(--alt-gid "$PFS_ALT_GID")
fi
if [ -n "${PFS_FENCE_COMMAND:-}" ]; then
  ARGS+=(--fence-command "$PFS_FENCE_COMMAND")
else
  EXPECT+=(--expect "peer_loss_does_not_break_surviving_mount=SKIP:no PFS_FENCE_COMMAND was supplied, so nothing killed the remote Linux mount uncleanly. Its mount process lives on another host, so this case requires an operator-supplied exact fence command.")
fi

echo
"$MATRIX_BIN" "${ARGS[@]}" "${EXPECT[@]}" --json "${PFS_MATRIX_JSON:-/dev/null}"
status=$?
echo
echo "Shared case names are comparable within each matrix's declared actor roles."
echo "This mode has 30 cases versus Linux's 29, adding"
echo "writer_exclusion_refuses_reader_mutations. Shared cases write through the Mac"
echo "and observe from Linux; two-writer cross-mount behavior is measured by Linux."
exit $status
