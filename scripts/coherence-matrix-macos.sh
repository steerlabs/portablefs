#!/bin/bash
# Cross-mount POSIX coherence matrix on macOS.
#
# This is the permanent, re-runnable form of the macOS-peer matrix that was
# previously executed by hand. It runs exactly the same named cases as
# scripts/coherence-matrix-linux.sh, using the same driver binary, so a macOS
# result and a Linux result are directly comparable line for line.
#
#   scripts/coherence-matrix-macos.sh --mount-a /path/a --mount-b /path/b
#       both mounts on this Mac
#
#   scripts/coherence-matrix-macos.sh --mount-a /path/a \
#       --remote timjang@Tims-MacBook-Pro-2.local --remote-mount /path/b
#       one mount here, one on a remote peer, driven over ssh
#
# The remote peer may also be Linux. Supply a Linux-built driver with
# --remote-binary; the case bodies and authority contract are byte-identical.
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
#     non-APFS mountpoints or the script exits without running a single case;
#   * it never reports a pass for a case it could not observe. Anything it
#     cannot honestly assert - most importantly every case that needs a second
#     real mount - is skipped with a loud message and a nonzero exit.
#
# Env:
#   PFS_MATRIX_BIN     prebuilt pfs-coherence-matrix (else built with go)
#   PFS_EXPECT_FSTYPE  extended regex the mount type must match (default the
#                      known PortableFS/FSKit types)
#   PFS_ALT_GID        an alternate GID this user belongs to, for the
#                      ownership case; without it that case skips
#   PFS_FENCE_COMMAND  shell command that kills the second mount uncleanly;
#                      without it the peer-loss case skips
set -u

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MOUNT_A=""
MOUNT_B=""
REMOTE=""
REMOTE_MOUNT=""
REMOTE_BIN="pfs-coherence-matrix"
ROUNDS=20
: "${PFS_EXPECT_FSTYPE:=^(pfs|fuse\.portablefs|portablefs|fskit|macfuse|osxfuse)$}"

fail() { echo "FATAL: $*" >&2; exit 1; }

skip_loudly() {
  echo
  echo "######################################################################"
  echo "# SKIPPED: the macOS coherence matrix did not run."
  echo "#"
  for line in "$@"; do echo "# $line"; done
  echo "#"
  echo "# No case was executed, so NOTHING about macOS cross-mount coherence"
  echo "# has been demonstrated by this invocation. Do not read this as a pass."
  echo "######################################################################"
  exit 78
}

usage() {
  echo "usage: $0 --mount-a <path> (--mount-b <path> | --remote <user@host> --remote-mount <path>)" >&2
  exit 64
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mount-a) MOUNT_A="${2:-}"; shift 2 ;;
    --mount-b) MOUNT_B="${2:-}"; shift 2 ;;
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
    "Mount the volume twice (or once here and once on a remote peer) with your own" \
    "tooling, then re-run with the mountpoints."
fi

REMOTE_PEER=0
if [ -n "$REMOTE" ]; then
  REMOTE_PEER=1
  [ -n "$REMOTE_MOUNT" ] || fail "--remote requires --remote-mount"
elif [ -z "$MOUNT_B" ]; then
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
if [ $REMOTE_PEER -eq 0 ]; then
  verify_real_mount "$MOUNT_B" "mount-B"
  [ "$MOUNT_A" != "$MOUNT_B" ] || skip_loudly \
    "mount-A and mount-B are the same path." \
    "One mount cannot demonstrate cross-mount coherence with itself."
else
  echo "precondition: mount-B is remote ($REMOTE:$REMOTE_MOUNT); verifying reachability"
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" true 2>/dev/null || skip_loudly \
    "The remote peer $REMOTE is not reachable over ssh with BatchMode." \
    "" \
    "Every case in this matrix needs two live mounts. With only one reachable" \
    "mount none of them can be asserted, so none of them ran." \
    "" \
    "Bring the peer up, or run the two-mount-on-one-Mac form instead and" \
    "be aware that it does not exercise a second machine's kernel."
  case "$REMOTE_MOUNT" in
    *"'"*|*$'\n'*|*$'\r'*) fail "--remote-mount cannot contain quotes or newlines" ;;
  esac
  case "$REMOTE_BIN" in
    ""|*[!A-Za-z0-9_./-]*) fail "--remote-binary must be a command name or path containing only letters, digits, '.', '/', '_', and '-'" ;;
  esac
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" "command -v '$REMOTE_BIN' >/dev/null || test -x '$REMOTE_BIN'" 2>/dev/null || skip_loudly \
    "The remote peer $REMOTE does not have the matrix driver at '$REMOTE_BIN'." \
    "" \
    "Copy the pfs-coherence-matrix binary there (it links nothing but the Go" \
    "standard library) and pass its path with --remote-binary."
  remote_os=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" uname -s 2>/dev/null) || skip_loudly \
    "The remote peer $REMOTE did not report its operating system."
  case "$remote_os" in
    Darwin)
      remote_type=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" "stat -f %T -- '$REMOTE_MOUNT'" 2>/dev/null) || skip_loudly \
        "The remote macOS path $REMOTE:$REMOTE_MOUNT is not a live mount." \
        "A reachable host and driver binary do not prove the path under test is PortableFS."
      remote_version=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" sw_vers -productVersion 2>/dev/null) || remote_version="unknown"
      remote_label="macOS $remote_version"
      ;;
    Linux)
      remote_type=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" "findmnt -n -r -o FSTYPE --target '$REMOTE_MOUNT'" 2>/dev/null) || skip_loudly \
        "The remote Linux path $REMOTE:$REMOTE_MOUNT is not a live mount, or findmnt is unavailable." \
        "A reachable host and driver binary do not prove the path under test is PortableFS."
      remote_version=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE" uname -r 2>/dev/null) || remote_version="unknown"
      remote_label="Linux $remote_version"
      ;;
    *)
      skip_loudly "The remote peer reports unsupported operating system '$remote_os'; expected Darwin or Linux."
      ;;
  esac
  [ -n "$remote_type" ] || skip_loudly \
    "The remote peer's path $REMOTE:$REMOTE_MOUNT did not report a filesystem type." \
    "A reachable host and driver binary do not prove the path under test is PortableFS."
  if ! printf '%s' "$remote_type" | grep -qiE "$PFS_EXPECT_FSTYPE"; then
    skip_loudly \
      "The remote peer's path $REMOTE:$REMOTE_MOUNT has filesystem type '$remote_type', which does not match '$PFS_EXPECT_FSTYPE'." \
      "That is not a verified PortableFS peer mount; no cross-machine case ran."
  fi
  echo "precondition: remote mount-B $REMOTE:$REMOTE_MOUNT is a live '$remote_type' mount"
fi

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
# Only genuine, explained platform limits belong here. The defects the hand-run
# matrix found on macOS - a remote create that never became visible, atomic
# replacement failing every round, a rename leaving both names on one inode, a
# remotely deleted file that could still be reopened, stale mode bits - are NOT
# declared. They are defects, and they must show up red until they are fixed.
# ---------------------------------------------------------------------------
EXPECT=(
  --expect "concurrent_same_file_append_atomicity=FAIL:FSKit resolves the O_APPEND offset from the kernel's cached EOF before the extension sees the write, and FSVolumeOpenModes carries no append intent, so cross-mount append atomicity is not available on this platform"
)

ARGS=(--a "$MOUNT_A" --atomic-replace-rounds "$ROUNDS")
if [ $REMOTE_PEER -eq 1 ]; then
  ARGS+=(--b "$REMOTE_MOUNT" --b-ssh "$REMOTE" --b-ssh-binary "$REMOTE_BIN")
  ARGS+=(--label "macOS $(sw_vers -productVersion) + $remote_label: two hosts, one volume")
else
  ARGS+=(--b "$MOUNT_B")
  ARGS+=(--label "macOS $(sw_vers -productVersion): two mounts on one Mac, one volume")
  echo
  echo "NOTE: both mounts are on this Mac. Everything below is a real two-mount"
  echo "NOTE: result, but it does not exercise a second machine's kernel. Use"
  echo "NOTE: --remote for the cross-host macOS/macOS or macOS/Linux form."
fi
if [ -n "${PFS_ALT_GID:-}" ]; then
  ARGS+=(--alt-gid "$PFS_ALT_GID")
fi
if [ -n "${PFS_FENCE_COMMAND:-}" ]; then
  ARGS+=(--fence-command "$PFS_FENCE_COMMAND")
else
  EXPECT+=(--expect "peer_loss_does_not_break_surviving_mount=SKIP:no PFS_FENCE_COMMAND was supplied, so nothing killed the second mount uncleanly. A local macOS mount is served by a system extension rather than a per-mount process, and a remote peer has host-specific fencing; this case therefore requires an operator-supplied exact fence command.")
fi

echo
"$MATRIX_BIN" "${ARGS[@]}" "${EXPECT[@]}" --json "${PFS_MATRIX_JSON:-/dev/null}"
status=$?
echo
echo "The case names above are identical to scripts/coherence-matrix-linux.sh."
echo "Compare the two matrices directly; a case that is green on Linux and red"
echo "here is a macOS frontend defect, not a difference in what was measured."
exit $status
