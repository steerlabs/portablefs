#!/usr/bin/env bash
# Package-manager reality check on two live kernel FUSE mounts of one volume.
#
# The coherence matrix proves POSIX semantics one operation at a time. This
# script asks a different, coarser question that no per-operation case can
# answer: does a real dependency installer - npm, pnpm, yarn, bun - run to
# completion on a SHARED volume path while another machine is reading the same
# directory tree at the same time?
#
# Everything here is deliberately the worst case:
#
#   * the install target is a SHARED path, with no machine-local route over it.
#     Routing node_modules to local disk is the supported way to run these tools
#     fast; measuring that would prove nothing about the shared filesystem. What
#     is measured is the shape PortableFS must survive when a user has not
#     configured anything.
#   * a second mount enumerates and reads the same tree throughout the install,
#     so every install is racing a concurrent reader on another mount.
#
# ── THIS IS A RECORDING INSTRUMENT, NOT A PERFORMANCE GATE ──────────────────
#
# It asserts exactly three things, and thresholds nothing:
#
#   1. the installer exited zero;
#   2. the tree it produced is visible and readable from the OTHER mount, with
#      the same entry count and the same bytes;
#   3. neither mount failed - both still serve after the run.
#
# Wall time and the authority's work counters are RECORDED into a table. There
# is no pass/fail number attached to them, on purpose: a timing threshold in CI
# turns a shared runner's bad afternoon into a red build, and a number nobody
# can act on gets raised until it never fires. The table is for reading.
#
# Managers whose binary is not present SKIP LOUDLY and are named in the table.
# The script never downloads a package manager to make its own coverage look
# better; a skip that says "bun is not installed in this image" is worth more
# than a silent one.
#
#   scripts/package-manager-matrix.sh                 # host side (needs docker)
#   scripts/package-manager-matrix.sh --in-container  # container side (root)
set -euo pipefail

PFS_PM_SELF=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# The coherence matrix owns the container provisioning: the loop-backed XFS cell
# with project quotas, the unprivileged service identity, the real authority, and
# two real kernel FUSE mounts. Sourcing it means this script measures package
# managers on byte-identical infrastructure rather than on a second copy of the
# setup that could drift.
# These must be set BEFORE the source. The coherence matrix assigns its own
# defaults with `: "${VAR:=default}"`, which takes whatever is already set, so a
# default written after the source would silently lose to the matrix's - and this
# run would provision a volume named for a suite it is not running and bind the
# port that suite uses.
: "${PORTABLEFS_VOLUME_NAME:=pm-volume}"
: "${PORTABLEFS_AUTHORITY_PORT:=17444}"
# Installers are chatty; give the shared authority a larger fixture budget than
# the coherence matrix needs.
: "${PORTABLEFS_XFS_IMAGE_SIZE:=2G}"

# shellcheck source=scripts/coherence-matrix-linux.sh
source "${PFS_PM_SELF}/coherence-matrix-linux.sh"

# Binaries may be supplied explicitly by a richer image. An empty value means
# "look on PATH", and not finding it there is a loud skip, never a download.
: "${PORTABLEFS_NPM_BIN:=}"
: "${PORTABLEFS_PNPM_BIN:=}"
: "${PORTABLEFS_YARN_BIN:=}"
: "${PORTABLEFS_BUN_BIN:=}"

pm_fail() {
  echo "package-manager-matrix: $1" >&2
  exit "${2:-1}"
}

pm_run_host() {
  command -v docker >/dev/null || pm_fail "docker is required to run the privileged package-manager matrix" 69
  local root
  root=$(repository_root)
  echo "package-manager-matrix: launching ${PORTABLEFS_CI_IMAGE}"
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
    -e "PORTABLEFS_COHERENCE=${PORTABLEFS_COHERENCE}" \
    -e "PORTABLEFS_CACHED_NAME_CAPACITY=${PORTABLEFS_CACHED_NAME_CAPACITY}" \
    -e "PORTABLEFS_REPAIR_BUDGET=${PORTABLEFS_REPAIR_BUDGET}" \
    -e "PORTABLEFS_NPM_BIN=${PORTABLEFS_NPM_BIN}" \
    -e "PORTABLEFS_PNPM_BIN=${PORTABLEFS_PNPM_BIN}" \
    -e "PORTABLEFS_YARN_BIN=${PORTABLEFS_YARN_BIN}" \
    -e "PORTABLEFS_BUN_BIN=${PORTABLEFS_BUN_BIN}" \
    -w /work \
    "${PORTABLEFS_CI_IMAGE}" \
    bash /work/scripts/package-manager-matrix.sh --in-container
}

# install_manager_dependencies adds the JavaScript runtime from the distribution
# archive, exactly the way the coherence matrix adds xfsprogs and fuse3. It is
# deliberately best-effort and deliberately does NOT reach outside apt: a manager
# that is not packaged (pnpm and bun are not in Debian) stays missing and is
# reported as a skip. Fetching a release tarball to fill the table would make the
# table describe a machine nobody runs.
install_manager_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq --no-install-recommends nodejs npm yarnpkg >/dev/null 2>&1 || true
}

# ── HERMETIC FIXTURE ────────────────────────────────────────────────────────
#
# The dependency set is six tiny packages this script generates and packs
# itself, then installs from local tarballs. No registry is contacted, nothing
# is version-resolved over the network, and nothing compiles: the run is
# reproducible on a machine with no internet at all, and a registry outage can
# never be mistaken for a filesystem defect.
#
# They are still real installs. Each manager unpacks real tarballs, writes a real
# node_modules tree, and writes its own lockfile - which is the metadata storm
# this instrument exists to observe.
PM_FIXTURE_DEPS=(pfs-fixture-alpha pfs-fixture-beta pfs-fixture-gamma pfs-fixture-delta pfs-fixture-epsilon pfs-fixture-zeta)
PM_VENDOR=/home/portablefs/vendor

build_vendor_tarballs() {
  as_service install -d -m 0755 "$PM_VENDOR" /home/portablefs/fixture-src
  local name
  for name in "${PM_FIXTURE_DEPS[@]}"; do
    local src="/home/portablefs/fixture-src/${name}"
    as_service install -d -m 0755 "$src" "$src/lib"
    as_service tee "$src/package.json" >/dev/null <<EOF
{
  "name": "${name}",
  "version": "1.0.0",
  "description": "hermetic PortableFS package-manager fixture",
  "main": "lib/index.js",
  "license": "MIT",
  "private": false
}
EOF
    # A handful of small files per package, so the install writes a realistic
    # number of directory entries rather than one file.
    local index
    for index in $(seq 0 23); do
      as_service tee "$src/lib/module-${index}.js" >/dev/null <<EOF
// ${name} module ${index}
module.exports = function () { return "${name}:${index}"; };
EOF
    done
    as_service tee "$src/lib/index.js" >/dev/null <<EOF
module.exports = { name: "${name}" };
EOF
    # npm pack writes into the current directory, so run it from the vendor dir.
    as_service sh -c "cd '$PM_VENDOR' && '$PM_NPM' pack '$src' >/dev/null" ||
      pm_fail "packing the hermetic fixture tarball for ${name} failed" 70
  done
  echo "package-manager-matrix: vendored $(as_service sh -c "ls -1 $PM_VENDOR/*.tgz | wc -l") fixture tarballs (no registry contacted)"
}

write_fixture_manifest() {
  local dir=$1
  as_service install -d -m 0755 "$dir"
  {
    printf '{\n  "name": "pfs-package-manager-fixture",\n  "version": "1.0.0",\n  "private": true,\n  "dependencies": {\n'
    local index=0 name
    for name in "${PM_FIXTURE_DEPS[@]}"; do
      local comma=","
      (( index == ${#PM_FIXTURE_DEPS[@]} - 1 )) && comma=""
      printf '    "%s": "file:%s/%s-1.0.0.tgz"%s\n' "$name" "$PM_VENDOR" "$name" "$comma"
      index=$((index + 1))
    done
    printf '  }\n}\n'
  } | as_service tee "$dir/package.json" >/dev/null
}

# ── AUTHORITY WORK COUNTERS ─────────────────────────────────────────────────
#
# The authority exposes no per-request counter today (see the note in
# docs/cross-mount-coherence-matrix.md - it is recorded there as an unmet gate),
# so an honest "RPC count" column cannot be printed. What CAN be read for the
# authority process, and what is recorded instead, are three real kernel-measured
# quantities: bytes it read from and wrote to its sockets, and the number of
# times it voluntarily blocked. The last is the closest available proxy for
# "requests handled" - the authority blocks once per request it waits on - and it
# is labelled as a proxy everywhere it appears rather than dressed up as a count.
# PM_AUTHORITY_PID is the authority process itself, NOT the runuser wrapper that
# start_authority records in AUTHORITY_PID. runuser forks; reading its /proc
# counters reports the wrapper's own I/O, which is nothing, and the whole table
# would print zeroes that look like a measurement. The sourced matrix resolves
# the same pid for its own traffic counter; this reads it rather than repeating
# the lookup, so the two instruments can never disagree about which process they
# are measuring.
pm_bind_authority_pid() {
  PM_AUTHORITY_PID=$AUTHORITY_PROC
  [[ -n $PM_AUTHORITY_PID ]] || pm_fail "cannot resolve the authority process; its work counters would be unmeasurable" 70
  echo "package-manager-matrix: authority process pid ${PM_AUTHORITY_PID} (counters read from /proc/${PM_AUTHORITY_PID})"
}

authority_counters() {
  local rchar=0 wchar=0 switches=0
  if [[ -r /proc/$PM_AUTHORITY_PID/io ]]; then
    rchar=$(awk '/^rchar:/{print $2}' "/proc/$PM_AUTHORITY_PID/io" 2>/dev/null || echo 0)
    wchar=$(awk '/^wchar:/{print $2}' "/proc/$PM_AUTHORITY_PID/io" 2>/dev/null || echo 0)
  fi
  # Summed over every THREAD, not read from the process status file. The
  # per-process file reports only the group leader, and a Go server does its
  # blocking on other threads, so reading it printed a column of zeroes that
  # looked like a measurement. Summing /proc/<pid>/task/*/status is the real
  # quantity.
  switches=$(awk '/^voluntary_ctxt_switches:/{total += $2} END {print total + 0}' \
    /proc/"$PM_AUTHORITY_PID"/task/*/status 2>/dev/null || echo 0)
  printf '%s %s %s\n' "${rchar:-0}" "${wchar:-0}" "${switches:-0}"
}

# ── CONCURRENT READER ON THE SECOND MOUNT ───────────────────────────────────
#
# Started before the install and stopped after it, so the whole install races a
# reader on another mount of the same volume. It records what it actually
# observed - entries enumerated and bytes read - which is the quantity that makes
# "the second mount kept working" an assertion rather than an impression.
start_concurrent_reader() {
  local target=$1 outfile=$2
  # The body is single-quoted on purpose: the two values it needs arrive through
  # the environment, and expanding a mount path into a shell body is how a path
  # with a space becomes a silently different measurement.
  # shellcheck disable=SC2016
  as_service env TARGET="$target" OUT="$outfile" sh -c '
    entries=0
    bytes=0
    rounds=0
    while [ ! -e "$OUT.stop" ]; do
      n=$(find "$TARGET" -mindepth 1 2>/dev/null | wc -l || echo 0)
      entries=$((entries + n))
      b=$(find "$TARGET" -type f -name "*.json" 2>/dev/null | head -40 | xargs -r cat 2>/dev/null | wc -c || echo 0)
      bytes=$((bytes + b))
      rounds=$((rounds + 1))
    done
    printf "%s %s %s\n" "$rounds" "$entries" "$bytes" > "$OUT"
  ' &
  READER_PID=$!
}

stop_concurrent_reader() {
  local outfile=$1
  as_service touch "$outfile.stop"
  wait "$READER_PID" 2>/dev/null || true
  as_service rm -f "$outfile.stop"
}

# PM_ROWS accumulates the report. One row per manager, printed at the end so a
# failure part-way through still shows everything measured before it.
PM_ROWS=()
PM_FAILURES=0
PM_RAN=0
PM_SKIPPED=0

resolve_manager() {
  local explicit=$1 fallback=$2
  if [[ -n $explicit ]]; then
    command -v -- "$explicit" >/dev/null 2>&1 && { printf '%s\n' "$explicit"; return 0; }
    printf '\n'
    return 0
  fi
  command -v -- "$fallback" >/dev/null 2>&1 && { command -v -- "$fallback"; return 0; }
  printf '\n'
}

record_skip() {
  local manager=$1 reason=$2
  PM_SKIPPED=$((PM_SKIPPED + 1))
  PM_ROWS+=("$(printf '%-6s %-8s %10s %14s %14s %14s %10s %12s  %s' \
    "$manager" "SKIP" "-" "-" "-" "-" "-" "-" "$reason")")
  echo "package-manager-matrix: SKIP ${manager}: ${reason}" >&2
}

# run_manager is one complete measurement: fixture, concurrent reader, install,
# cross-mount verification, counters.
run_manager() {
  local manager=$1
  shift 1
  local workdir="/home/portablefs/mount-a/pm-${manager}"
  local peerdir="/home/portablefs/mount-b/pm-${manager}"
  local log="/home/portablefs/logs/pm-${manager}.log"
  local readerout="/home/portablefs/logs/pm-${manager}.reader"

  echo
  echo "----------------------------------------------------------------------"
  echo "package-manager-matrix: ${manager} installing on a SHARED volume path"
  echo "----------------------------------------------------------------------"
  write_fixture_manifest "$workdir"

  local before after
  before=$(authority_counters)
  start_concurrent_reader "$peerdir" "$readerout"

  local started ended status
  started=$(date +%s.%N)
  # `set +e` around the installer is load-bearing. Under `set -e` a failing
  # installer aborts the whole script before `status=$?` is read, and the table
  # this instrument exists to print never appears - which is exactly what
  # happened the first time a manager really failed here. A package manager that
  # breaks on a shared volume path is the most valuable row in the table; it must
  # be RECORDED, not fatal.
  set +e
  as_service env \
    HOME=/home/portablefs \
    npm_config_audit=false npm_config_fund=false npm_config_update_notifier=false \
    npm_config_offline=true \
    CI=1 \
    sh -c "cd '$workdir' && $*" >"$log" 2>&1
  status=$?
  set -e
  ended=$(date +%s.%N)
  stop_concurrent_reader "$readerout" || true
  after=$(authority_counters)

  local wall
  wall=$(awk -v a="$started" -v b="$ended" 'BEGIN{printf "%.1f", b-a}')

  local rb wb sb ra wa sa
  read -r rb wb sb <<<"$before"
  read -r ra wa sa <<<"$after"

  local reader_rounds=0 reader_entries=0 reader_bytes=0
  if [[ -r $readerout ]]; then
    read -r reader_rounds reader_entries reader_bytes <"$readerout"
  fi

  if [[ $status -ne 0 ]]; then
    PM_FAILURES=$((PM_FAILURES + 1))
    PM_RAN=$((PM_RAN + 1))
    tail -40 "$log" >&2
    PM_ROWS+=("$(printf '%-6s %-8s %10s %14s %14s %14s %10s %12s  %s' \
      "$manager" "FAIL" "$wall" "$((ra - rb))" "$((wa - wb))" "$((sa - sb))" \
      "-" "$reader_rounds" "installer exited ${status}; see ${log}")")
    return
  fi

  # The install completed. Compare the complete regular-file manifest from the
  # OTHER mount, not a sample: equal entry counts plus one equal file can hide a
  # missing or divergent package elsewhere in a large dependency tree.
  # Every probe below is on a filesystem that may have just revoked itself, so
  # none of them may be allowed to abort the run either.
  set +e
  local note="" ok=1
  local a_entries b_entries
  a_entries=$(as_service find "$workdir/node_modules" -mindepth 1 2>/dev/null | wc -l)
  b_entries=$(as_service find "$peerdir/node_modules" -mindepth 1 2>/dev/null | wc -l)
  if [[ $a_entries -eq 0 ]]; then
    ok=0
    note="the installer exited zero but wrote no node_modules entries"
  elif [[ $a_entries -ne $b_entries ]]; then
    ok=0
    note="mount-a enumerates ${a_entries} node_modules entries, mount-b enumerates ${b_entries}"
  fi
  if [[ $ok -eq 1 ]]; then
    local a_sum b_sum
    a_sum=$(as_service sh -c "cd '$workdir/node_modules' && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum" 2>/dev/null | cut -d' ' -f1)
    b_sum=$(as_service sh -c "cd '$peerdir/node_modules' && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum" 2>/dev/null | cut -d' ' -f1)
    if [[ -z $a_sum || $a_sum != "$b_sum" ]]; then
      ok=0
      note="the two mounts have different complete regular-file manifests"
    fi
  fi
  if [[ $ok -eq 1 && $reader_rounds -eq 0 ]]; then
    ok=0
    note="the concurrent reader completed no observation round"
  fi
  if [[ $ok -eq 1 ]]; then
    as_service sh -c "printf survives > '$peerdir/after-install' && cat '$workdir/after-install' >/dev/null" ||
      { ok=0; note="a mount stopped serving after the install"; }
  fi
  set -e

  PM_RAN=$((PM_RAN + 1))
  if [[ $ok -eq 1 ]]; then
    PM_ROWS+=("$(printf '%-6s %-8s %10s %14s %14s %14s %10s %12s  %s' \
      "$manager" "OK" "$wall" "$((ra - rb))" "$((wa - wb))" "$((sa - sb))" \
      "$a_entries" "$reader_rounds" "reader enumerated ${reader_entries} entries / read ${reader_bytes} bytes concurrently")")
  else
    PM_FAILURES=$((PM_FAILURES + 1))
    PM_ROWS+=("$(printf '%-6s %-8s %10s %14s %14s %14s %10s %12s  %s' \
      "$manager" "FAIL" "$wall" "$((ra - rb))" "$((wa - wb))" "$((sa - sb))" \
      "$a_entries" "$reader_rounds" "$note")")
  fi
}

print_table() {
  echo
  echo "======================================================================"
  echo "package-manager matrix: shared volume path, no machine-local routes"
  echo "kernel $(uname -r), ${PORTABLEFS_COHERENCE} coherence, two kernel FUSE mounts"
  echo "======================================================================"
  printf '%-6s %-8s %10s %14s %14s %14s %10s %12s  %s\n' \
    "mgr" "status" "wall(s)" "auth rchar" "auth wchar" "auth blocks" "entries" "rd rounds" "note"
  local row
  for row in "${PM_ROWS[@]}"; do
    printf '%s\n' "$row"
  done
  echo
  echo "wall(s)      installer wall clock, RECORDED not thresholded."
  echo "auth rchar   bytes the authority process read from its sockets during the install."
  echo "auth wchar   bytes it wrote."
  echo "auth blocks  voluntary context switches by the authority process. This is a PROXY"
  echo "             for request count, not a request count: the authority exposes no"
  echo "             per-RPC counter today, and printing a fabricated one would be worse"
  echo "             than printing a labelled proxy. Replace this column the day the"
  echo "             authority exports a real counter."
  echo "entries      node_modules entries the installing mount produced, which the other"
  echo "             mount had to enumerate identically for the row to be OK."
  echo "rd rounds    full enumeration+read passes the SECOND mount completed over the same"
  echo "             tree while the install was running."
  echo
  echo "ran=${PM_RAN} failed=${PM_FAILURES} skipped=${PM_SKIPPED}"
}

pm_run_container() {
  [[ $EUID -eq 0 ]] || pm_fail "container side must start as root to provision XFS" 77
  install_container_dependencies
  install_manager_dependencies
  create_service_identity
  provision_xfs
  bash /work/scripts/provision-xfs-volume.sh \
    /srv/portablefs "$PORTABLEFS_VOLUME_NAME" "$PORTABLEFS_PROJECT_ID" \
    "$PORTABLEFS_SERVICE_UID" "$PORTABLEFS_SERVICE_GID" 1024m 400000
  build_binaries
  trap teardown EXIT
  start_authority
  resolve_authority_pid
  pm_bind_authority_pid
  # No route declaration is installed here, on purpose. The whole point of this
  # instrument is the worst case: node_modules on the SHARED path, with no
  # machine-local route over it. Installing one would measure the configuration
  # the product recommends and prove nothing about the one it must survive.
  start_mount 0 /home/portablefs/mount-a MOUNT_A_PID /home/portablefs/backing-a
  start_mount 1 /home/portablefs/mount-b MOUNT_B_PID /home/portablefs/backing-b

  PM_NPM=$(resolve_manager "$PORTABLEFS_NPM_BIN" npm)
  local pnpm_bin yarn_bin bun_bin
  pnpm_bin=$(resolve_manager "$PORTABLEFS_PNPM_BIN" pnpm)
  yarn_bin=$(resolve_manager "$PORTABLEFS_YARN_BIN" yarn)
  [[ -z $yarn_bin ]] && yarn_bin=$(resolve_manager "$PORTABLEFS_YARN_BIN" yarnpkg)
  bun_bin=$(resolve_manager "$PORTABLEFS_BUN_BIN" bun)

  if [[ -z $PM_NPM ]]; then
    # npm packs the hermetic fixture tarballs every other manager consumes, so
    # without it there is no fixture and nothing to measure at all. That is a
    # loud, whole-script skip with a nonzero status, never a green empty table.
    pm_fail "npm is not installed in this image, so the hermetic fixture tarballs cannot be packed and no manager can be measured. Install nodejs+npm in the image or set PORTABLEFS_NPM_BIN." 69
  fi
  build_vendor_tarballs

  # npm ci is the real subject: it requires a lockfile, so the lockfile is
  # generated first with npm install and the tree is then removed, which is
  # exactly what a CI job does.
  run_manager npm \
    "'$PM_NPM' install --offline --no-audit --no-fund >/dev/null && rm -rf node_modules && '$PM_NPM' ci --offline --no-audit --no-fund"

  if [[ -n $pnpm_bin ]]; then
    run_manager pnpm "'$pnpm_bin' install --reporter=append-only"
  else
    record_skip pnpm "pnpm is not installed in this image and is not packaged by Debian; this script never downloads a package manager. Set PORTABLEFS_PNPM_BIN or use an image that ships it."
  fi

  if [[ -n $yarn_bin ]]; then
    run_manager yarn "'$yarn_bin' install --non-interactive"
  else
    record_skip yarn "yarn is not installed in this image; this script never downloads a package manager. Set PORTABLEFS_YARN_BIN or use an image that ships it."
  fi

  if [[ -n $bun_bin ]]; then
    run_manager bun "'$bun_bin' install"
  else
    record_skip bun "bun is not installed in this image and is not packaged by Debian; this script never downloads a package manager. Set PORTABLEFS_BUN_BIN or use an image that ships it."
  fi

  print_table
  # A skip is not a failure - it is a stated absence. A manager that ran and
  # broke is a failure.
  [[ $PM_FAILURES -eq 0 ]] || pm_fail "${PM_FAILURES} package manager(s) did not complete correctly on a shared volume path" 1
  [[ $PM_RAN -gt 0 ]] || pm_fail "no package manager was available to measure" 69
}

case "${1:-}" in
  --in-container) pm_run_container ;;
  "") pm_run_host ;;
  *) pm_fail "usage: $0 [--in-container]" 64 ;;
esac
