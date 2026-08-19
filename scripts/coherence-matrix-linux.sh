#!/usr/bin/env bash
# Two-mount cross-mount POSIX coherence matrix on a real Linux kernel.
#
# This is the automated proof of the product's central claim: one volume,
# mounted on two independent kernel FUSE mounts of one authority, with full
# read/write POSIX semantics on both. It provisions a real XFS cell with project
# quotas, starts the real portablefs-authority process, starts two real
# portablefs-mount-v3 processes, and then drives both mountpoints with ordinary
# syscalls from a separate black-box program.
#
# Nothing here is in-process and nothing is faked. That matters for two reasons.
# A suite that injects a fake kernel can agree with itself; this one cannot. And
# a mount that lives inside the test binary cannot be killed uncleanly, so the
# "a dead participant must not break the survivor" case can only exist when the
# mounts are separate processes, as they are here.
#
#   scripts/coherence-matrix-linux.sh                 # host side (needs docker)
#   scripts/coherence-matrix-linux.sh --in-container  # container side (root)
#
# Every gate is fail-closed. A filesystem that cannot be provisioned, a mount
# that does not appear, and a case that neither passes nor is declared as a
# named expectation are all hard failures. A harness that cannot honestly assert
# something must say so loudly, never report a quiet pass.
set -euo pipefail

# Digest-pinned like every other third-party image in this repository, and the
# same image the privileged XFS/FUSE integration job uses.
: "${PORTABLEFS_CI_IMAGE:=golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36}"
: "${PORTABLEFS_XFS_IMAGE_SIZE:=1G}"
: "${PORTABLEFS_SERVICE_UID:=200001}"
: "${PORTABLEFS_SERVICE_GID:=200001}"
# A second group the volume identity belongs to. Without it the ownership case
# has nothing observable to change and skips loudly instead of asserting a
# chown to the identity the file already has.
: "${PORTABLEFS_ALT_GID:=200002}"
: "${PORTABLEFS_PROJECT_ID:=42001}"
: "${PORTABLEFS_VOLUME_NAME:=coherence-volume}"
: "${PORTABLEFS_AUTHORITY_PORT:=17443}"
: "${PORTABLEFS_ATOMIC_REPLACE_ROUNDS:=20}"
# This black-box harness proves only the syscall behavior its cases observe. It
# does not inspect or prove protocol-6 lease grants, recalls, or discharge. The
# legacy-named bounds remain explicit while their command-line admission surface
# is retired; if mount and authority disagree, Attach must fail rather than let
# the harness paper over it. Dedicated v6 tests must cover the mechanism.
: "${PORTABLEFS_CACHED_NAME_CAPACITY:=65536}"
: "${PORTABLEFS_REPAIR_BUDGET:=15s}"
# The driver's per-case wall bound. It is deliberately larger than
# same_dir_concurrent_mutations' own storm bound (3m, stated in cases.go) so that
# a deadlocked storm is reported by the case - which names what hung and still
# runs its liveness probes - rather than by the outer guillotine, which can only
# say "the case did not finish".
: "${PORTABLEFS_CASE_TIMEOUT:=8m}"
# The volume's machine-local route declaration, installed through the admin
# ApplyRoutes call between provisioning and mounting. It is what makes
# local_route_isolation and routes_revision_mismatch assertable: without a
# declaration there is no routed subtree to isolate and no revision to disagree
# with. `node_modules/` matches that name at any depth, which is the rule a real
# workspace writes.
: "${PORTABLEFS_ROUTE_RULES:=node_modules/}"
# The single directory name the matrix drives as machine-local. It must be a
# name PORTABLEFS_ROUTE_RULES matches.
: "${PORTABLEFS_LOCAL_ROUTE:=node_modules}"
# Cases the first-success pathname replay control must turn red. If one of these
# starts surviving a deliberately stale repeated observation, that case has
# stopped asserting the transition it claims and must not be trusted until it
# is fixed.
FALSIFIABLE_CASES=(
  remote_create_visible
  remote_unlink_name_gone
  # remote_unlink_open_fd_posix deliberately survives this control: its core
  # contract is that an already-open descriptor keeps working after unlink,
  # and staleActor perturbs pathname observations rather than stateful handles.
  # The disjoint-namespace control still turns that case red. Replaying an
  # `open` response here would manufacture an invalid handle, not a stale view.
  atomic_replace_new_inode
  rename_old_gone_new_present_same_inode
  remote_chmod_visible
  # remote_chown_visible is deliberately absent: the v3 volume model is
  # single-principal, the volume refuses the ownership change itself, and the
  # case skips with that reason on every mount. A case that cannot run cannot
  # demonstrate that it detects a stale view either.
  remote_utimes_visible
  remote_truncate_grow_readable_eof
  remote_truncate_shrink_readable_eof
  dir_listing_reflects_remote_creates_and_deletes
  concurrent_writers_distinct_files
  # Protocol 6 refuses writable O_APPEND because stock FUSE cannot preserve
  # append intent or return an authority-assigned offset. The real matrix
  # declares that case FAIL; a case which is intentionally unavailable cannot
  # also serve as evidence that the stale-view control detects a bug.
  concurrent_same_file_overwrite_integrity
  hardlink_visible_same_inode
  symlink_visible_and_resolves
  deep_nesting
  open_after_unlink_cross_mount_contents
  rename_over_open_fd
  same_dir_concurrent_mutations
  local_route_isolation
  # routes_revision_mismatch is deliberately absent, and unlike the others it is
  # absent permanently. It asserts an ATTACH-TIME authority contract - what a
  # routing refusal carries, and that adopting it works on the same capability -
  # observed through a client that never touches either mountpoint. Neither
  # control can turn that red: freezing one mount's view of a directory and
  # pointing the other at an unrelated directory both change what the mounts
  # SEE, and this case looks at neither. Declaring it falsifiable by those
  # controls would be a claim the controls cannot support.
)


fail() {
  echo "coherence-matrix-linux: $1" >&2
  exit "${2:-1}"
}

repository_root() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd
}

run_host() {
  command -v docker >/dev/null || fail "docker is required to run the privileged coherence matrix" 69
  local root
  root=$(repository_root)
  echo "coherence-matrix-linux: launching ${PORTABLEFS_CI_IMAGE}"
  # The working tree is mounted read-only: the container provisions its own XFS
  # image and must never mutate the checkout it is testing.
  docker run --rm --privileged \
    --tmpfs /var/tmp:exec,mode=1777 \
    -v "${root}/vcs:/work/vcs:ro" \
    -v "${root}/scripts:/work/scripts:ro" \
    -e "PORTABLEFS_XFS_IMAGE_SIZE=${PORTABLEFS_XFS_IMAGE_SIZE}" \
    -e "PORTABLEFS_SERVICE_UID=${PORTABLEFS_SERVICE_UID}" \
    -e "PORTABLEFS_SERVICE_GID=${PORTABLEFS_SERVICE_GID}" \
    -e "PORTABLEFS_ALT_GID=${PORTABLEFS_ALT_GID}" \
    -e "PORTABLEFS_PROJECT_ID=${PORTABLEFS_PROJECT_ID}" \
    -e "PORTABLEFS_VOLUME_NAME=${PORTABLEFS_VOLUME_NAME}" \
    -e "PORTABLEFS_AUTHORITY_PORT=${PORTABLEFS_AUTHORITY_PORT}" \
    -e "PORTABLEFS_ATOMIC_REPLACE_ROUNDS=${PORTABLEFS_ATOMIC_REPLACE_ROUNDS}" \
    -e "PORTABLEFS_CACHED_NAME_CAPACITY=${PORTABLEFS_CACHED_NAME_CAPACITY}" \
    -e "PORTABLEFS_REPAIR_BUDGET=${PORTABLEFS_REPAIR_BUDGET}" \
    -e "PORTABLEFS_CASE_TIMEOUT=${PORTABLEFS_CASE_TIMEOUT}" \
    -e "PORTABLEFS_ROUTE_RULES=${PORTABLEFS_ROUTE_RULES}" \
    -e "PORTABLEFS_LOCAL_ROUTE=${PORTABLEFS_LOCAL_ROUTE}" \
    -w /work \
    "${PORTABLEFS_CI_IMAGE}" \
    bash /work/scripts/coherence-matrix-linux.sh --in-container
}

install_container_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # xfsprogs: mkfs.xfs and xfs_quota. fuse3: the setuid fusermount3 helper an
  # unprivileged mount process needs. util-linux: findmnt. procps: pkill, used
  # to kill exactly one mount process uncleanly.
  apt-get install -y -qq --no-install-recommends xfsprogs fuse3 util-linux procps >/dev/null
}

# The FUSE control filesystem is the kernel interface a strict mount's
# revocation ladder uses to abort its own serving connection. A production host
# has it mounted; a container does not inherit it, and a mount that cannot abort
# cannot release the requests parked in its kernel.
provision_fuse_control() {
  [[ -d /sys/fs/fuse/connections ]] || fail "/sys/fs/fuse/connections is missing; this kernel has no FUSE control interface" 69
  mountpoint -q /sys/fs/fuse/connections ||
    mount -t fusectl none /sys/fs/fuse/connections ||
    fail "cannot mount the FUSE control filesystem; connection aborts would be unavailable" 69
}

provision_xfs() {
  local image=/var/tmp/portablefs-coherence-xfs.img
  [[ -e /dev/fuse ]] || fail "/dev/fuse is missing; this container cannot mount a kernel FUSE filesystem" 69
  [[ -e /dev/loop-control ]] || fail "/dev/loop-control is missing; this container cannot create a loop-backed XFS" 69
  install -d -m 0755 -o 0 -g 0 /srv/portablefs
  rm -f -- "$image"
  truncate -s "$PORTABLEFS_XFS_IMAGE_SIZE" "$image"
  mkfs.xfs -q -f "$image"
  mount -o "loop,prjquota,nodev,nosuid,noexec,noatime" "$image" /srv/portablefs
  local options
  options=$(findmnt -n -r -o OPTIONS -T /srv/portablefs)
  [[ ,$options, == *,prjquota,* ]] || fail "XFS mounted without prjquota (options: $options)"
  [[ $(findmnt -n -r -o FSTYPE -T /srv/portablefs) == xfs ]] || fail "provisioned filesystem is not XFS"
}

create_service_identity() {
  groupadd -g "$PORTABLEFS_SERVICE_GID" portablefs
  groupadd -g "$PORTABLEFS_ALT_GID" portablefs-alt
  useradd -u "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" -G portablefs-alt \
    -M -d /home/portablefs -s /bin/bash portablefs
  install -d -m 0700 -o "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" \
    /home/portablefs /home/portablefs/gocache /home/portablefs/gomodcache \
    /home/portablefs/tmp /home/portablefs/bin /home/portablefs/creds \
    /home/portablefs/mount-a /home/portablefs/mount-b /home/portablefs/logs \
    /home/portablefs/write-staging
}

# as_service runs a command as the unprivileged volume identity with a clean
# environment. The data plane never runs as root, and root would bypass every
# DAC decision the mounts delegate to the kernel.
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
  echo "coherence-matrix-linux: building the authority, mount and matrix binaries"
  as_service go -C /work/vcs build -o /home/portablefs/bin/ \
    ./cmd/portablefs-authority ./cmd/portablefs-mount-v3 \
    ./test/coherence/cmd/pfs-coherence-matrix ./test/coherence/cmd/pfs-coherence-credentials \
    ./test/coherence/cmd/pfs-coherence-routes ||
    fail "building the harness binaries failed" 70
}

start_authority() {
  local volume=/srv/portablefs/$PORTABLEFS_VOLUME_NAME
  local control=/srv/portablefs/.portablefs-control/$PORTABLEFS_VOLUME_NAME
  local membership=$control/strict-membership
  local write_staging_source=$control/write-staging
  local write_staging=/home/portablefs/write-staging
  # Production gives the authority a private staging root through systemd's
  # BindPaths boundary.  Do the same here: the cell's root-owned 0711 control
  # directory is deliberately traversable-but-not-readable by the volume uid,
  # while privatepath.OpenExistingDir deliberately opens every component and
  # therefore must see only the service-owned 0700 presentation.  Both names
  # resolve to the same project-inheriting XFS inode, so quota accounting cannot
  # diverge from the visible volume.
  mount --bind "$write_staging_source" "$write_staging"
  WRITE_STAGING_BIND=$write_staging
  [[ $(stat -c '%u:%g:%a' -- "$write_staging") == \
      "$PORTABLEFS_SERVICE_UID:$PORTABLEFS_SERVICE_GID:700" ]] ||
    fail "bound write staging is not the exact service-owned 0700 directory" 70
  [[ $(findmnt -n -r -o TARGET --target "$write_staging") == "$write_staging" ]] ||
    fail "write staging bind mount is not installed at $write_staging" 70
  as_service /home/portablefs/bin/pfs-coherence-credentials \
    --dir /home/portablefs/creds --volume-id "$PORTABLEFS_VOLUME_NAME" --tokens 6 --admin-tokens 2 ||
    fail "minting the credential set failed" 70
  as_service /home/portablefs/bin/portablefs-authority \
    --listen "127.0.0.1:${PORTABLEFS_AUTHORITY_PORT}" \
    --volume-id "$PORTABLEFS_VOLUME_NAME" \
    --root "$volume" \
    --project-id "$PORTABLEFS_PROJECT_ID" \
    --tls-cert /home/portablefs/creds/server.crt \
    --tls-key /home/portablefs/creds/server.key \
    --client-ca /home/portablefs/creds/ca.pem \
    --capability-public-key /home/portablefs/creds/capability-public.pem \
    --visibility-membership-file "$membership" \
    --write-staging-dir "$write_staging" \
    --max-cached-name-capacity "$PORTABLEFS_CACHED_NAME_CAPACITY" \
    --max-repair-budget "$PORTABLEFS_REPAIR_BUDGET" \
    >/home/portablefs/logs/authority.log 2>&1 &
  AUTHORITY_PID=$!
  local waited=0
  until (exec 3<>/dev/tcp/127.0.0.1/"$PORTABLEFS_AUTHORITY_PORT") 2>/dev/null; do
    exec 3>&- 2>/dev/null || true
    kill -0 "$AUTHORITY_PID" 2>/dev/null || { cat /home/portablefs/logs/authority.log >&2; fail "the authority exited before it listened" 70; }
    sleep 0.2
    waited=$((waited + 1))
    (( waited < 100 )) || { cat /home/portablefs/logs/authority.log >&2; fail "the authority never listened on 127.0.0.1:${PORTABLEFS_AUTHORITY_PORT}" 70; }
  done
  exec 3>&- 2>/dev/null || true
  echo "coherence-matrix-linux: authority pid $AUTHORITY_PID serving $volume"
}

# start_mount brings up one independent kernel FUSE mount and waits for the
# kernel to actually carry it. A mount that never appears is a failure; the
# matrix must never run against a plain empty directory and call it a pass.
# resolve_authority_pid finds the authority process itself, not the runuser
# wrapper $! records. runuser forks, so its own /proc counters describe the
# wrapper and would report a flat zero for every window measured.
resolve_authority_pid() {
  AUTHORITY_PROC=$(pgrep -u portablefs -f portablefs-authority | head -1)
  [[ -n $AUTHORITY_PROC ]] || fail "cannot resolve the authority process; the route cases could not measure authority traffic" 70
  echo "coherence-matrix-linux: authority process pid ${AUTHORITY_PROC}"
}

# install_route_declaration installs the volume's machine-local routing through
# the admin ApplyRoutes call, which is the only way it can arrive: the authority
# owns .portablefs/local-dirs and refuses mount mutation of it.
#
# The admin capability is minted separately from the mounts' capabilities and is
# never given to a mount. "admin" implies write, but write does not imply admin,
# precisely because changing this file changes what every other machine can see.
install_route_declaration() {
  printf '%s\n' "$PORTABLEFS_ROUTE_RULES" > /home/portablefs/routes.txt
  chown "$PORTABLEFS_SERVICE_UID:$PORTABLEFS_SERVICE_GID" /home/portablefs/routes.txt
  # The output goes to a file and is echoed by hand, the same way the authority
  # and mount startups do it, because it was NOT reaching the run output on its
  # own: the step failed, the job exited with the right code, and neither the
  # helper's stderr nor the fail message appeared anywhere. A gate that fails
  # closed still has to say what failed, or the next person reads an exit code
  # and a blank space. teardown dumps this log unconditionally as well, so even
  # a failure that never reaches the branch below is visible.
  local log=/home/portablefs/logs/apply-routes.log
  if ! as_service /home/portablefs/bin/pfs-coherence-routes \
    --authority "127.0.0.1:${PORTABLEFS_AUTHORITY_PORT}" \
    --volume-id "$PORTABLEFS_VOLUME_NAME" \
    --access-token-file /home/portablefs/creds/admin-0.token \
    --tls-cert /home/portablefs/creds/client.crt \
    --tls-key /home/portablefs/creds/client.key \
    --tls-server-ca /home/portablefs/creds/ca.pem \
    --tls-server-name authority.portablefs.test \
    --apply-file /home/portablefs/routes.txt >"$log" 2>&1; then
    echo "coherence-matrix-linux: installing the volume's machine-local route declaration failed:" >&2
    cat -- "$log" >&2 || true
    fail "installing the volume's machine-local route declaration failed" 70
  fi
  # A green run must also show WHICH topology it measured, or the route cases
  # could be passing against a declaration nobody looked at.
  echo "coherence-matrix-linux: installed the volume's route declaration:"
  sed 's/^/coherence-matrix-linux:   /' -- "$log"
  ROUTES_CONTRACT_COMMAND="/home/portablefs/bin/pfs-coherence-routes \
    --authority 127.0.0.1:${PORTABLEFS_AUTHORITY_PORT} \
    --volume-id ${PORTABLEFS_VOLUME_NAME} \
    --access-token-file /home/portablefs/creds/access-2.token \
    --tls-cert /home/portablefs/creds/client.crt \
    --tls-key /home/portablefs/creds/client.key \
    --tls-server-ca /home/portablefs/creds/ca.pem \
    --tls-server-name authority.portablefs.test \
    --check-revision-contract"
}

# start_mount brings up one mount against the volume's ACTIVE routing. It passes
# no revision and no rule: the mount attaches with the empty rule set, the
# authority refuses it with the volume's canonical declaration attached, and the
# mount adopts it and attaches again on the same capability. Two attempts, one
# credential. That is the production path, and driving it here is what keeps the
# harness from measuring a shape no user runs.
start_mount() {
  local index=$1 point=$2 pidvar=$3 backing=$4
  as_service install -d -m 0700 "$backing"
  as_service /home/portablefs/bin/portablefs-mount-v3 \
    --authority "127.0.0.1:${PORTABLEFS_AUTHORITY_PORT}" \
    --volume-id "$PORTABLEFS_VOLUME_NAME" \
    --mountpoint "$point" \
    --access-token-file "/home/portablefs/creds/access-${index}.token" \
    --tls-cert /home/portablefs/creds/client.crt \
    --tls-key /home/portablefs/creds/client.key \
    --tls-server-ca /home/portablefs/creds/ca.pem \
    --tls-server-name authority.portablefs.test \
    --max-frame-bytes 16777216 \
    --coherence strict \
    --cached-name-capacity "$PORTABLEFS_CACHED_NAME_CAPACITY" \
    --repair-budget "$PORTABLEFS_REPAIR_BUDGET" \
    --local-backing "$backing" \
    >"/home/portablefs/logs/mount-${index}.log" 2>&1 &
  local pid=$!
  local waited=0
  until findmnt -n -r -o FSTYPE --target "$point" 2>/dev/null | grep -q '^fuse'; do
    kill -0 "$pid" 2>/dev/null || { cat "/home/portablefs/logs/mount-${index}.log" >&2; fail "mount $index exited before the kernel carried it" 70; }
    sleep 0.2
    waited=$((waited + 1))
    (( waited < 150 )) || { cat "/home/portablefs/logs/mount-${index}.log" >&2; fail "mount $index never appeared at $point" 70; }
  done
  # $! is runuser's PID and root owns it; the matrix runs as the unprivileged
  # volume identity and could not signal it. Resolve the mount process itself,
  # owned by that identity, so the fence case delivers a real SIGKILL to a live
  # mount instead of reporting a permission error as a dead peer.
  local real
  real=$(pgrep -u portablefs -f -- "--mountpoint $point" | head -1)
  [[ -n $real ]] || fail "cannot resolve the mount process serving $point" 70
  printf -v "$pidvar" '%s' "$real"
  echo "coherence-matrix-linux: mount $index pid $pid live at $point ($(findmnt -n -r -o FSTYPE,SOURCE --target "$point"))"
}

teardown() {
  local status=$?
  set +e
  for point in /home/portablefs/mount-a /home/portablefs/mount-b; do
    fusermount3 -u "$point" 2>/dev/null || fusermount3 -uz "$point" 2>/dev/null
  done
  [[ -n ${MOUNT_A_PID:-} ]] && kill "$MOUNT_A_PID" 2>/dev/null
  [[ -n ${MOUNT_B_PID:-} ]] && kill "$MOUNT_B_PID" 2>/dev/null
  [[ -n ${AUTHORITY_PID:-} ]] && kill "$AUTHORITY_PID" 2>/dev/null
  wait 2>/dev/null
  if [[ -n ${WRITE_STAGING_BIND:-} ]]; then
    umount "$WRITE_STAGING_BIND" 2>/dev/null || true
  fi
  echo "==== route declaration apply log ===="
  cat /home/portablefs/logs/apply-routes.log 2>/dev/null
  echo "==== authority log ===="
  cat /home/portablefs/logs/authority.log 2>/dev/null
  for index in 0 1; do
    echo "==== mount ${index} log ===="
    cat "/home/portablefs/logs/mount-${index}.log" 2>/dev/null
  done
  exit "$status"
}

# assert_mounts_serving is the control-on-the-controls.
#
# The disjoint-namespace phase declares that EVERY case must fail, and a mount
# that has revoked itself fails every case too - so a fenced mount satisfies that
# phase for entirely the wrong reason and the phase reports green. This run found
# exactly that: a strict mount-A revoked itself one second after mounting, and
# phase 1 still passed.
#
# So each phase is bracketed by a real create/read/unlink on both mountpoints. A
# mount that cannot complete one is named, and the job fails, instead of the run
# continuing to draw conclusions from a mount that is not there.
# Callers pass the mountpoints that are supposed to be alive at that moment.
# After the matrix only mount-a is: its last case kills mount-b on purpose.
assert_mounts_serving() {
  local when=$1
  shift
  local point name broken=0
  for point in "$@"; do
    name="${point}/.serving-probe-$$"
    if ! as_service sh -c "printf serving > '$name' && cat '$name' >/dev/null && rm -f '$name'"; then
      echo "coherence-matrix-linux: ${when}: $point cannot complete a create/read/unlink" >&2
      broken=1
    fi
  done
  if (( broken )); then
    echo "coherence-matrix-linux: a mount stopped serving ${when}." >&2
    echo "coherence-matrix-linux: every later phase would be drawing conclusions from a mount that is not there," >&2
    echo "coherence-matrix-linux: and the disjoint-namespace phase in particular would report green because a dead" >&2
    echo "coherence-matrix-linux: mount fails every case. Failing here instead." >&2
    fail "a mount stopped serving ${when}" 72
  fi
  echo "coherence-matrix-linux: both mounts still serve ${when}"
}

# run_disjoint_control points the second mount at a directory that is not the
# volume at all. Every single case must fail: a case that can pass without the
# two roots sharing one filesystem is not measuring cross-mount coherence and
# would be reporting green for free. Together with the stale-view control below,
# this is what makes the real matrix's green result mean something.
run_disjoint_control() {
  local arguments=() entry control_cases
  for entry in $(as_service /home/portablefs/bin/pfs-coherence-matrix --list | cut -f1); do
    case "$entry" in
      peer_loss_does_not_break_surviving_mount) continue ;;
      # routes_revision_mismatch asserts an attach-time authority contract
      # through a client that touches no mountpoint, so pointing the second root
      # at an unrelated directory cannot turn it red. It is expected to PASS
      # here, which is why it is simply not declared.
      routes_revision_mismatch|concurrent_same_file_append_atomicity) continue ;;
    esac
    arguments+=(--expect "${entry}=FAIL:a mount that shares no namespace with the other must fail this case")
  done
  # The revision probe is an attach-time protocol experiment, not a mountpoint
  # observation. Neither control can perturb it, and its successful retry
  # consumes one single-use capability. Exclude it here so the final matrix is
  # the one phase that owns and spends that credential.
  control_cases=$(as_service /home/portablefs/bin/pfs-coherence-matrix --list |
    cut -f1 | grep -Ev '^(routes_revision_mismatch|concurrent_same_file_append_atomicity)$' | paste -sd, -)
  echo
  echo "======================================================================"
  echo "PHASE 1/3  disjoint-namespace control (second root is not the volume)"
  echo "======================================================================"
  as_service install -d -m 0700 /home/portablefs/not-a-volume
  as_service /home/portablefs/bin/pfs-coherence-matrix \
    --a /home/portablefs/mount-a --b /home/portablefs/not-a-volume \
    --expect-disjoint-namespace \
    --only "$control_cases" \
    --alt-gid "$PORTABLEFS_ALT_GID" \
    --atomic-replace-rounds 2 \
    --case-timeout "$PORTABLEFS_CASE_TIMEOUT" \
    --local-route "$PORTABLEFS_LOCAL_ROUTE" \
    --routes-contract-command "$ROUTES_CONTRACT_COMMAND" \
    --label "disjoint-namespace control: mount-B is an ordinary directory" \
    --expect "peer_loss_does_not_break_surviving_mount=SKIP:the control must not destroy a mount it still needs" \
    "${arguments[@]}" \
    --json /home/portablefs/logs/disjoint.json ||
    fail "the disjoint-namespace control did not behave as declared: at least one case passed without the two roots sharing a filesystem and must not be trusted" 71
}

# run_falsifiability_control points the matrix at deliberately broken behaviour:
# the first mount answers every repeated, successful pathname observation with
# the first answer it ever gave. Every case declared in FALSIFIABLE_CASES must
# detect that fault. Stateful-handle and attach-time contracts are covered by
# their own direct assertions and other controls rather than this fault model.
run_falsifiability_control() {
  local arguments=() control_cases
  local name
  for name in "${FALSIFIABLE_CASES[@]}"; do
    arguments+=(--expect "${name}=FAIL:a replayed first-success pathname observation must be detected by this case")
  done
  control_cases=$(as_service /home/portablefs/bin/pfs-coherence-matrix --list |
    cut -f1 | grep -Ev '^(routes_revision_mismatch|concurrent_same_file_append_atomicity)$' | paste -sd, -)
  echo
  echo "======================================================================"
  echo "PHASE 2/3  first-success stale-view control (deliberately broken pathname observations)"
  echo "======================================================================"
  as_service /home/portablefs/bin/pfs-coherence-matrix \
    --a /home/portablefs/mount-a --b /home/portablefs/mount-b \
    --only "$control_cases" \
    --alt-gid "$PORTABLEFS_ALT_GID" \
    --atomic-replace-rounds 3 \
    --case-timeout "$PORTABLEFS_CASE_TIMEOUT" \
    --self-check-stale \
    --local-route "$PORTABLEFS_LOCAL_ROUTE" \
    --routes-contract-command "$ROUTES_CONTRACT_COMMAND" \
    --label "falsifiability control: mount-A replays first-success pathname observations" \
    --expect "peer_loss_does_not_break_surviving_mount=SKIP:the control must not destroy a mount it still needs" \
    --expect "remote_chown_visible=SKIP:the v3 volume model is single-principal, so there is no observable ownership change on this mount" \
    "${arguments[@]}" \
    --json /home/portablefs/logs/control.json ||
    fail "the falsifiability control did not behave as declared: at least one stale-sensitive case cannot detect a replayed pathname observation and must not be trusted" 71
}

run_matrix() {
  echo
  echo "======================================================================"
  echo "PHASE 3/3  cross-mount coherence matrix (two live kernel FUSE mounts)"
  echo "======================================================================"
  as_service /home/portablefs/bin/pfs-coherence-matrix \
    --a /home/portablefs/mount-a --b /home/portablefs/mount-b \
    --alt-gid "$PORTABLEFS_ALT_GID" \
    --atomic-replace-rounds "$PORTABLEFS_ATOMIC_REPLACE_ROUNDS" \
    --case-timeout "$PORTABLEFS_CASE_TIMEOUT" \
    --fence-command "$FENCE_COMMAND" \
    --local-route "$PORTABLEFS_LOCAL_ROUTE" \
    --routes-contract-command "$ROUTES_CONTRACT_COMMAND" \
    --expect "concurrent_same_file_append_atomicity=FAIL:protocol 6 refuses writable O_APPEND because stock FUSE does not preserve exact append intent or an authority-assigned result offset; RWF_APPEND is not forwarded and remains a production blocker" \
    --expect "remote_chown_visible=SKIP:the v3 volume model is single-principal (docs/xfs-authority-architecture.md), so a chown to another principal is refused by the volume itself and there is no ownership change to observe" \
    --label "linux ${KERNEL_RELEASE}: two stock-kernel FUSE mounts of one authoritative XFS volume" \
    --json /home/portablefs/logs/matrix.json
}

run_container() {
  [[ $EUID -eq 0 ]] || fail "container side must start as root to provision XFS" 77
  KERNEL_RELEASE=$(uname -r)
  install_container_dependencies
  create_service_identity
  provision_fuse_control
  provision_xfs
  # The production provisioner is the single source of truth for project-quota
  # setup, so the harness exercises exactly what a deployment runs.
  bash /work/scripts/provision-xfs-volume.sh \
    /srv/portablefs "$PORTABLEFS_VOLUME_NAME" "$PORTABLEFS_PROJECT_ID" \
    "$PORTABLEFS_SERVICE_UID" "$PORTABLEFS_SERVICE_GID" 512m 200000
  build_binaries
  trap teardown EXIT
  start_authority
  resolve_authority_pid
  # The declaration must be active BEFORE the mounts attach: a mount adopts the
  # routing that is live at attach, and installing it afterwards would refuse
  # every already-attached session instead of testing the adopt path.
  install_route_declaration
  start_mount 0 /home/portablefs/mount-a MOUNT_A_PID /home/portablefs/backing-a
  start_mount 1 /home/portablefs/mount-b MOUNT_B_PID /home/portablefs/backing-b
  # A numeric PID, never a pattern: the fence command appears verbatim in the
  # matrix process's own command line, so a pkill pattern would match and kill
  # the driver instead of the mount.
  FENCE_COMMAND="kill -9 ${MOUNT_B_PID}"
  echo "coherence-matrix-linux: stock kernel $KERNEL_RELEASE, two independent mounts of volume $PORTABLEFS_VOLUME_NAME (black-box behavior only)"
  local both=(/home/portablefs/mount-a /home/portablefs/mount-b)
  assert_mounts_serving "before any phase ran" "${both[@]}"
  run_disjoint_control
  assert_mounts_serving "after the disjoint-namespace control" "${both[@]}"
  run_falsifiability_control
  assert_mounts_serving "after the stale-view control" "${both[@]}"
  run_matrix
  # mount-b is gone by design: peer_loss_does_not_break_surviving_mount kills it
  # uncleanly as its whole point. What must still be true is that the survivor
  # serves, which is also what that case asserts - checking it here as well costs
  # one syscall and catches a survivor that died after the case finished.
  assert_mounts_serving "after the matrix" /home/portablefs/mount-a
}

# Dispatch only when this file is EXECUTED. scripts/package-manager-matrix.sh
# sources it to reuse the container provisioning below - the XFS cell, the
# service identity, the authority, and the two kernel FUSE mounts - so that the
# package-manager reality check runs against byte-identical infrastructure
# rather than a second, subtly different copy of it. Sourcing must not launch a
# matrix run as a side effect.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    --in-container) run_container ;;
    "") run_host ;;
    *) fail "usage: $0 [--in-container]" 64 ;;
  esac
fi
