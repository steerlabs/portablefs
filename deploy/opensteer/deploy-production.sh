#!/usr/bin/env bash
set -euo pipefail

required=(
  E2B_API_KEY
  OPENSTEER_CELL_INSTANCE
  OPENSTEER_E2B_CANDIDATE
  OPENSTEER_EVIDENCE_DIR
  OPENSTEER_E2B_SDK_ROOT
  OPENSTEER_GCP_PROJECT
  OPENSTEER_GCP_ZONE
  OPENSTEER_MANAGER_INSTANCE
  OPENSTEER_RELEASE_DIR
  OPENSTEER_VOLUME_ID
)
for name in "${required[@]}"; do
  [[ -n ${!name:-} ]] || {
    echo "$name is required" >&2
    exit 64
  }
done

release_dir=$OPENSTEER_RELEASE_DIR
evidence_dir=$OPENSTEER_EVIDENCE_DIR
[[ $release_dir == /* && -d $release_dir && $evidence_dir == /* ]] || exit 64
release_id=$(<"$release_dir/release-id")
[[ $release_id =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ ]] || exit 64
[[ $OPENSTEER_VOLUME_ID =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 64
[[ $OPENSTEER_GCP_PROJECT =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ $OPENSTEER_GCP_ZONE =~ ^[a-z0-9-]+$ ]] || exit 64
[[ $OPENSTEER_MANAGER_INSTANCE =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64
[[ $OPENSTEER_CELL_INSTANCE =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
release_base=${release_dir##*/}
remote_stage=.portablefs-deploy/$release_id
gcloud_common=(--project "$OPENSTEER_GCP_PROJECT" --zone "$OPENSTEER_GCP_ZONE" --tunnel-through-iap --quiet)
mkdir -p -- "$evidence_dir"
"$root/deploy/gcp/verify-hosted-release.sh" "$release_dir" >/dev/null

ssh_run() {
  local instance=$1 command=$2
  gcloud compute ssh "$instance" "${gcloud_common[@]}" --command="$command"
}

copy_to() {
  local instance=$1
  shift
  gcloud compute scp "${gcloud_common[@]}" --compress --recurse "$@" "$instance:~/$remote_stage/"
}

cleanup_remote() {
  local command
  command="rm -rf -- \"\$HOME/$remote_stage\""
  ssh_run "$OPENSTEER_MANAGER_INSTANCE" "$command" >/dev/null 2>&1 || true
  ssh_run "$OPENSTEER_CELL_INSTANCE" "$command" >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT

prepare_host() {
  local instance=$1 role=$2 command
  command="set -euo pipefail; install -d -m 0700 \"\$HOME/.portablefs-deploy\" \"\$HOME/$remote_stage\""
  ssh_run "$instance" "$command" >/dev/null
  case "$role" in
    manager)
      copy_to "$instance" \
        "$release_dir" \
        "$root/deploy/gcp/activate-hosted-release.sh" \
        "$root/deploy/gcp/verify-hosted-release.sh" \
        "$root/deploy/opensteer/manager-api.sh"
      ;;
    cell)
      copy_to "$instance" \
        "$release_dir" \
        "$root/deploy/gcp/activate-hosted-release.sh" \
        "$root/deploy/gcp/verify-hosted-release.sh" \
        "$root/deploy/opensteer/cell-authority-state.sh"
      ;;
    *) exit 64 ;;
  esac
}

activate_host() {
  local instance=$1 role=$2 command
  command="set -euo pipefail
current=\$(readlink -f /opt/portablefs/current 2>/dev/null || true)
if [[ \$current != /opt/portablefs/releases/$release_id ]]; then
  sudo \"\$HOME/$remote_stage/activate-hosted-release.sh\" \"\$HOME/$remote_stage/$release_base\" $role
fi"
  ssh_run "$instance" "$command"
}

manager_call() {
  local command="sudo \"\$HOME/$remote_stage/manager-api.sh\""
  local argument
  for argument in "$@"; do
    command+=" $argument"
  done
  ssh_run "$OPENSTEER_MANAGER_INSTANCE" "$command"
}

cell_call() {
  local command="sudo \"\$HOME/$remote_stage/cell-authority-state.sh\""
  local argument
  for argument in "$@"; do
    command+=" $argument"
  done
  ssh_run "$OPENSTEER_CELL_INSTANCE" "$command"
}

e2b_release() {
  node "$root/deploy/opensteer/e2b-release.mjs" "$@"
}

echo "Staging and activating $release_id on the Manager and cell control processes"
prepare_host "$OPENSTEER_MANAGER_INSTANCE" manager
prepare_host "$OPENSTEER_CELL_INSTANCE" cell
activate_host "$OPENSTEER_MANAGER_INSTANCE" manager
activate_host "$OPENSTEER_CELL_INSTANCE" cell

volume=$(manager_call get "$OPENSTEER_VOLUME_ID")
state=$(jq -r '.state' <<<"$volume")
generation=$(jq -r '.authority_generation' <<<"$volume")
[[ $generation =~ ^[1-9][0-9]*$ ]] || {
  echo "Manager returned an invalid authority generation" >&2
  exit 65
}
authority_release=$(cell_call current-release "$OPENSTEER_VOLUME_ID" 2>/dev/null || true)

if [[ $state == READY && $authority_release == "$release_id" ]]; then
  echo "Authority already runs $release_id; skipping its restart"
else
  case "$state" in
    READY)
      e2b_release drain "$evidence_dir/pre-restart.json" pre-restart
      manager_call restart "$OPENSTEER_VOLUME_ID" "$release_id" >/dev/null
      minimum_generation=$((generation + 1))
      ;;
    FENCING)
      minimum_generation=$((generation + 1))
      ;;
    PROVISIONING)
      minimum_generation=$generation
      ;;
    *)
      echo "volume $OPENSTEER_VOLUME_ID is in non-deployable state $state" >&2
      exit 69
      ;;
  esac

  volume=$(manager_call get "$OPENSTEER_VOLUME_ID")
  state=$(jq -r '.state' <<<"$volume")
  if [[ $state == FENCING ]]; then
    e2b_release drain "$evidence_dir/strict-fence.json" strict-fence
    cell_call wait-absent "$OPENSTEER_VOLUME_ID" 300 >/dev/null
    evidence_sha=$(sha256sum "$evidence_dir/strict-fence.json" | awk '{print $1}')
    manager_call strict-fence "$OPENSTEER_VOLUME_ID" "$release_id" "$evidence_sha" >/dev/null
  elif [[ $state != PROVISIONING ]]; then
    echo "volume entered unexpected state $state during the restart" >&2
    exit 69
  fi

  manager_call wait-ready "$OPENSTEER_VOLUME_ID" "$minimum_generation" 300 >"$evidence_dir/ready-volume.json"
  cell_call wait-release "$OPENSTEER_VOLUME_ID" "$release_id" 300 >"$evidence_dir/authority-release.json"
fi

e2b_release promote "$OPENSTEER_E2B_CANDIDATE"
# A sandbox may have been requested between the strict drain and the atomic tag
# promotion. Removing that narrow race window guarantees every surviving or
# subsequently created Cloud Computer uses the promoted matched client.
e2b_release drain "$evidence_dir/post-promotion.json" post-promotion

printf '%s\n' \
  "PortableFS release: $release_id" \
  "E2B template: $OPENSTEER_E2B_CANDIDATE -> default" \
  "Volume: $OPENSTEER_VOLUME_ID"
