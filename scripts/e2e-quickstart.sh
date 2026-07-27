#!/usr/bin/env bash
# End-to-end golden-path gate against a disposable quickstart stack.
#
# Boots an ISOLATED compose project (own project name, ports, env file, CLI
# config), then walks the full user journey and asserts every step:
# login, create, adopt, mount, cross-mount coherence, history, named
# snapshot, fork, MOUNT THE FORK, fork isolation, branch, mount the branch,
# grep against the live branch, exec retirement, unmount,
# teardown. Exits non-zero on the first failed assertion; always tears the
# stack down. Nothing here touches a developer's default quickstart stack
# or ~/.config/portablefs.
#
# Usage: ./scripts/e2e-quickstart.sh [--keep]   (--keep skips teardown)
#
# Kernel mounts: on Linux the CLI mounts via FUSE and the mount steps always
# run. On macOS the CLI mounts via the PortableFS FSKit extension +
# portablefsd; that requires a registered extension whose daemon socket
# matches the CLI's PORTABLEFS_FSKIT_* configuration, which most dev machines
# do not have. Set PFS_E2E_FSKIT=1 on such a prepared macOS host to run the
# mount steps; otherwise they are SKIPped and every mount-independent step
# still runs and is asserted.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

MOUNTS_ENABLED=1
if [ "$(uname -s)" = "Darwin" ] && [ "${PFS_E2E_FSKIT:-}" != "1" ]; then
  MOUNTS_ENABLED=0
fi

PROJECT=pfse2e
API_PORT=28787
MANAGER_PORT=28788
ROUTER_PORT=22050
POSTGRES_PORT=25433
ENV_FILE=.env.quickstart.e2e
WORK=$(mktemp -d /tmp/pfs-e2e.XXXXXX)
CLI="$WORK/portablefs"
export XDG_CONFIG_HOME="$WORK/config"
export XDG_STATE_HOME="$WORK/state"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_STATE_HOME"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
step() { printf '\n== %s ==\n' "$*"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS  %s\n' "$*"; }
fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf 'FAIL  %s\n' "$*" >&2
}
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); printf 'SKIP  %s\n' "$*"; }
require() { # require <description> <command...>
  local desc=$1
  shift
  if "$@" >/dev/null 2>&1; then
    pass "$desc"
  else
    fail "$desc (command: $*)"
  fi
}

MOUNTS=()
cleanup() {
  set +e
  for m in "${MOUNTS[@]:-}"; do
    [ -n "$m" ] && "$CLI" umount "$m" >/dev/null 2>&1
  done
  if [ "$KEEP" = 0 ]; then
    # The env file may not exist if quickstart died before writing it; the
    # project name alone still addresses every container/volume for down.
    if [ -f "$ENV_FILE" ]; then
      COMPOSE_PROJECT_NAME=$PROJECT docker compose --env-file "$ENV_FILE" \
        -f docker-compose.quickstart.yml down -v >/dev/null 2>&1
    else
      COMPOSE_PROJECT_NAME=$PROJECT docker compose \
        -f docker-compose.quickstart.yml down -v >/dev/null 2>&1
    fi
    rm -f "$ENV_FILE"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

step "build CLI from source"
GOTOOLCHAIN=auto go -C vcs build -o "$CLI" ./cmd/portablefs || {
  fail "CLI build"
  exit 1
}
pass "CLI build"

# FSKit mounts spawn portablefsd; the CLI discovers it as a sibling binary.
if [ "$MOUNTS_ENABLED" = 1 ] && [ "$(uname -s)" = "Darwin" ]; then
  GOTOOLCHAIN=auto go -C vcs build -o "$WORK/portablefsd" ./cmd/portablefsd || {
    fail "portablefsd build"
    exit 1
  }
  pass "portablefsd build"
fi

step "boot isolated quickstart stack ($PROJECT)"
# quickstart.sh reads and writes .env.quickstart at the repo root
# unconditionally. Move a developer stack's file aside for the duration and
# restore it afterwards, so the e2e run can never clobber or inherit it.
DEV_ENV_BACKUP=""
if [ -f .env.quickstart ]; then
  DEV_ENV_BACKUP="$WORK/dev.env.quickstart.bak"
  mv .env.quickstart "$DEV_ENV_BACKUP"
fi
restore_dev_env() {
  if [ -f "$ENV_FILE" ]; then :; else cp .env.quickstart "$ENV_FILE" 2>/dev/null || true; fi
  rm -f .env.quickstart
  if [ -n "$DEV_ENV_BACKUP" ] && [ -f "$DEV_ENV_BACKUP" ]; then
    mv "$DEV_ENV_BACKUP" .env.quickstart
    DEV_ENV_BACKUP=""
  fi
}
QUICKSTART_OK=1
COMPOSE_PROJECT_NAME=$PROJECT \
  QUICKSTART_API_PORT=$API_PORT QUICKSTART_MANAGER_PORT=$MANAGER_PORT \
  QUICKSTART_ROUTER_PORT=$ROUTER_PORT QUICKSTART_POSTGRES_PORT=$POSTGRES_PORT \
  ./scripts/quickstart.sh > "$WORK/quickstart.log" 2>&1 || QUICKSTART_OK=0
if [ "$QUICKSTART_OK" = 0 ]; then
  # Preserve the boot log outside $WORK (the exit trap removes $WORK), then
  # let the trap tear down whatever partially started.
  cp "$WORK/quickstart.log" /tmp/pfs-e2e-boot-failure.log 2>/dev/null || true
  restore_dev_env
  fail "quickstart boot (log: /tmp/pfs-e2e-boot-failure.log)"
  tail -30 "$WORK/quickstart.log" >&2
  exit 1
fi
pass "quickstart boot"

# Adopt the generated env as the e2e-scoped env file, then put the
# developer's file back immediately — teardown uses $ENV_FILE only.
TENANT_TOKEN=$(sed -n 's/^PORTABLEFS_QUICKSTART_TENANT_TOKEN=//p' .env.quickstart)
MANAGER_TOKEN=$(sed -n 's/^QUICKSTART_MANAGER_TOKEN=//p' .env.quickstart)
cp .env.quickstart "$ENV_FILE"
restore_dev_env

step "login"
require "login" "$CLI" login --url "http://127.0.0.1:$API_PORT" --token "$TENANT_TOKEN" \
  --manager-url "http://127.0.0.1:$MANAGER_PORT" --manager-token "$MANAGER_TOKEN"

step "create empty volume"
require "create" "$CLI" create e2e-created

step "adopt a real repo"
FIXTURE="$WORK/fixture"
mkdir -p "$FIXTURE/src/nested"
(cd "$FIXTURE" && git init -q . &&
  echo "# e2e" > README.md &&
  echo "console.log('one')" > src/app.js &&
  echo "data" > src/nested/deep.txt &&
  ln -s src/app.js link-to-app 2>/dev/null || true
  git add -A && git -c user.email=e2e@x -c user.name=e2e commit -qm init)
require "adopt" "$CLI" adopt "$FIXTURE" --name e2e-repo

step "mount the adopted volume"
M1="$WORK/m1"
if [ "$MOUNTS_ENABLED" = 1 ]; then
  mkdir -p "$M1"
  if "$CLI" mount e2e-repo "$M1" >/dev/null 2>&1; then
    MOUNTS+=("$M1")
    pass "mount adopted volume"
  else
    fail "mount adopted volume"
  fi
  require "mounted content readable" test -f "$M1/README.md"
  require "nested content readable" grep -q data "$M1/src/nested/deep.txt"
else
  skip "mount adopted volume (darwin without PFS_E2E_FSKIT=1: no registered PortableFS FSKit extension for this CLI)"
  skip "mounted content readable (needs mount)"
  skip "nested content readable (needs mount)"
fi

step "cross-mount coherence"
if [ "$MOUNTS_ENABLED" = 1 ]; then
  M2="$WORK/m2"
  mkdir -p "$M2"
  if "$CLI" mount e2e-repo "$M2" >/dev/null 2>&1; then
    MOUNTS+=("$M2")
    pass "second mount"
  else
    fail "second mount"
  fi
  echo "coherent-$$" > "$M1/coherence.txt"
  COHERENT=0
  for _ in $(seq 1 20); do
    if grep -q "coherent-$$" "$M2/coherence.txt" 2>/dev/null; then
      COHERENT=1
      break
    fi
    sleep 1
  done
  [ "$COHERENT" = 1 ] && pass "write visible across mounts" || fail "write visible across mounts (20s)"
else
  skip "second mount (darwin without PFS_E2E_FSKIT=1)"
  skip "write visible across mounts (needs mounts)"
fi

step "history"
require "history lists commits" bash -c "'$CLI' history e2e-repo | grep -q ."

step "named snapshot on the live branch"
"$CLI" snapshot e2e-repo --name e2e-mark > "$WORK/snap.out" 2>&1
READY=0
for _ in $(seq 1 30); do
  if "$CLI" snapshots e2e-repo 2>/dev/null | grep -q "e2e-mark"; then
    READY=1
    break
  fi
  sleep 1
done
[ "$READY" = 1 ] && pass "snapshot --name persists and lists" || {
  fail "snapshot --name persists and lists"
  cat "$WORK/snap.out" >&2
  "$CLI" snapshots e2e-repo >&2 || true
}

step "fork the live volume"
require "fork" "$CLI" fork e2e-repo --name e2e-fork

step "MOUNT THE FORK (regression: PFT2-parented head)"
if [ "$MOUNTS_ENABLED" = 1 ]; then
  MF="$WORK/mf"
  mkdir -p "$MF"
  if "$CLI" mount e2e-fork "$MF" >/dev/null 2>&1; then
    MOUNTS+=("$MF")
    pass "mount fork"
  else
    fail "mount fork"
  fi
  require "fork content matches source" grep -q one "$MF/src/app.js"
else
  skip "mount fork (darwin without PFS_E2E_FSKIT=1)"
  skip "fork content matches source (needs mount)"
fi

step "fork isolation"
if [ "$MOUNTS_ENABLED" = 1 ]; then
  echo "fork-only" > "$MF/fork-note.txt"
  sleep 2
  if [ -f "$M1/fork-note.txt" ]; then
    fail "fork write leaked into source volume"
  else
    pass "fork writes stay in the fork"
  fi
else
  skip "fork writes stay in the fork (needs mounts)"
fi

step "branch from the live volume and mount it"
require "branch create" "$CLI" branch e2e-repo e2e-side
if [ "$MOUNTS_ENABLED" = 1 ]; then
  MB="$WORK/mb"
  mkdir -p "$MB"
  if "$CLI" mount e2e-repo "$MB" --branch e2e-side >/dev/null 2>&1; then
    MOUNTS+=("$MB")
    pass "mount branch"
  else
    fail "mount branch"
  fi
else
  skip "mount branch (darwin without PFS_E2E_FSKIT=1)"
fi

step "grep against the live branch"
if "$CLI" grep e2e-repo "console" > "$WORK/grep.out" 2>&1 && grep -q "app.js" "$WORK/grep.out"; then
  pass "grep finds live content"
else
  fail "grep finds live content"
  cat "$WORK/grep.out" >&2
fi

step "server-side exec is retired"
if "$CLI" exec e2e-repo -- true > "$WORK/exec.out" 2>&1; then
  fail "retired exec unexpectedly succeeded"
elif grep -q "retired" "$WORK/exec.out" && grep -q "mount" "$WORK/exec.out"; then
  pass "exec returns actionable retirement guidance"
else
  fail "exec retirement guidance"
  cat "$WORK/exec.out" >&2
fi

step "unmount everything"
if [ "$MOUNTS_ENABLED" = 1 ]; then
  # ${arr[@]:-} keeps bash 3.2 (macOS /bin/bash) from aborting under set -u
  # when every mount failed and the array is empty.
  for m in "${MOUNTS[@]:-}"; do
    [ -n "$m" ] || continue
    require "umount $m" "$CLI" umount "$m"
  done
else
  skip "unmount (nothing was mounted)"
fi
MOUNTS=()

printf '\n== RESULT: %d passed, %d failed, %d skipped ==\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
[ "$FAIL_COUNT" = 0 ]
