#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
lock_script="$root/deploy/opensteer/staging-release-lock.py"
state_file="${RUNNER_TEMP:?RUNNER_TEMP is required}/opensteer-staging-release-lock.json"
stop_file="$RUNNER_TEMP/opensteer-staging-release-lock-stop"
abort_file="$RUNNER_TEMP/opensteer-staging-release-lock-abort"
stopped_file="$RUNNER_TEMP/opensteer-staging-release-lock-stopped"
lost_file="$RUNNER_TEMP/opensteer-staging-release-lock-lost"
owner_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}:${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
source_commit=$(git -C "$root" rev-parse HEAD)
wait_seconds="${OPENSTEER_RELEASE_LOCK_WAIT_SECONDS:-9000}"

if [[ ${GITHUB_SHA:?GITHUB_SHA is required} != "$source_commit" ]]; then
  printf 'Checked-out commit differs from GITHUB_SHA; refusing an ambiguous release owner.\n' >&2
  exit 1
fi
if [[ ! $wait_seconds =~ ^[1-9][0-9]*$ ]] || ((wait_seconds > 9000)); then
  printf 'OPENSTEER_RELEASE_LOCK_WAIT_SECONDS must be from 1 through 9000.\n' >&2
  exit 1
fi

deadline=$((SECONDS + wait_seconds))
while :; do
  set +e
  python3 "$lock_script" acquire-once \
    --owner-kind github-actions \
    --owner-id "$owner_id" \
    --source-commit "$source_commit" \
    --hold-seconds 7200 \
    --state-file "$state_file"
  acquire_status=$?
  set -e
  if ((acquire_status == 0)); then
    break
  fi
  if ((acquire_status != 75)); then
    exit "$acquire_status"
  fi
  if ((SECONDS >= deadline)); then
    printf 'Timed out after %ss waiting for the global staging release lock.\n' \
      "$wait_seconds" >&2
    exit 75
  fi
  sleep 10
done

python3 "$lock_script" assert-owned --state-file "$state_file"
python3 "$lock_script" heartbeat-loop \
  --state-file "$state_file" \
  --stop-file "$stop_file" \
  --abort-file "$abort_file" \
  --stopped-file "$stopped_file" \
  --lost-file "$lost_file" \
  --interval-seconds 30 &
heartbeat_pid=$!
transaction_open=1

abort_transaction() {
  local status=$?
  trap - EXIT INT TERM
  if ((transaction_open)); then
    : >"$abort_file"
    wait "$heartbeat_pid" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap abort_transaction EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export OPENSTEER_RELEASE_LOCK_LOST_FILE="$lost_file"
export OPENSTEER_RELEASE_LOCK_STATE_FILE="$state_file"
set +e
"$root/deploy/opensteer/deploy-production.sh"
deploy_status=$?
set -e
if ((deploy_status != 0)); then
  exit "$deploy_status"
fi

: >"$stop_file"
set +e
wait "$heartbeat_pid"
heartbeat_status=$?
set -e
if ((heartbeat_status != 0)); then
  exit "$heartbeat_status"
fi
[[ -f $stopped_file && ! -f $lost_file ]] || {
  printf 'The release-lock heartbeat did not stop cleanly.\n' >&2
  exit 1
}
python3 "$lock_script" release --state-file "$state_file"
transaction_open=0
trap - EXIT INT TERM
