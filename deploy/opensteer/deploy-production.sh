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
  OPENSTEER_VOLUME_IDS
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
[[ $OPENSTEER_GCP_PROJECT =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ $OPENSTEER_GCP_ZONE =~ ^[a-z0-9-]+$ ]] || exit 64
[[ $OPENSTEER_MANAGER_INSTANCE =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64
[[ $OPENSTEER_CELL_INSTANCE =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64

volume_ids_input=$OPENSTEER_VOLUME_IDS
[[ $volume_ids_input != ,* && $volume_ids_input != *, && $volume_ids_input != *,,* ]] || {
  echo "OPENSTEER_VOLUME_IDS contains an empty volume ID" >&2
  exit 64
}
IFS=, read -r -a volume_ids <<<"$volume_ids_input"
declare -A seen_volume_ids=()
for volume_id in "${volume_ids[@]}"; do
  [[ $volume_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ && -z ${seen_volume_ids[$volume_id]:-} ]] || {
    echo "OPENSTEER_VOLUME_IDS must be a comma-separated list of unique volume IDs" >&2
    exit 64
  }
  seen_volume_ids[$volume_id]=1
done

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
release_base=${release_dir##*/}
remote_stage=.portablefs-deploy/$release_id
archive_dir=$(mktemp -d)
transfer_archive=$archive_dir/$release_id.tar.gz
gcloud_common=(--project "$OPENSTEER_GCP_PROJECT" --zone "$OPENSTEER_GCP_ZONE" --tunnel-through-iap --quiet)
mkdir -p -- "$evidence_dir"
"$root/deploy/gcp/verify-hosted-release.sh" "$release_dir" >/dev/null
tar -czf "$transfer_archive" \
  -C "${release_dir%/*}" "$release_base" \
  -C "$root/deploy/gcp" activate-hosted-release.sh verify-hosted-release.sh \
  -C "$root/deploy/opensteer" manager-api.sh cell-authority-state.sh

ssh_run() {
  local instance=$1 command=$2
  gcloud compute ssh "$instance" "${gcloud_common[@]}" --command="$command"
}

copy_to() {
  local instance=$1
  local command
  command="set -euo pipefail; tar -xzf - -C \"\$HOME/$remote_stage\""
  gcloud compute ssh "$instance" "${gcloud_common[@]}" --command="$command" <"$transfer_archive"
}

cleanup_remote() {
  local command
  command="rm -rf -- \"\$HOME/$remote_stage\""
  ssh_run "$OPENSTEER_MANAGER_INSTANCE" "$command" >/dev/null 2>&1 || true
  ssh_run "$OPENSTEER_CELL_INSTANCE" "$command" >/dev/null 2>&1 || true
}

cleanup() {
  rm -rf -- "$archive_dir"
  cleanup_remote
}
trap cleanup EXIT

prepare_host() {
  local instance=$1 role=$2 command
  command="set -euo pipefail; install -d -m 0700 \"\$HOME/.portablefs-deploy\" \"\$HOME/$remote_stage\""
  ssh_run "$instance" "$command" >/dev/null
  case "$role" in
    manager | cell) copy_to "$instance" ;;
    *) exit 64 ;;
  esac
}

activate_host() {
  local instance=$1 role=$2 unit command
  case "$role" in
    manager) unit=portablefs-manager.service ;;
    cell) unit=portablefs-cell-agent@.service ;;
    *) exit 64 ;;
  esac
  command="set -euo pipefail
current=\$(readlink -f /opt/portablefs/current 2>/dev/null || true)
unit=\$(readlink -f /etc/systemd/system/$unit 2>/dev/null || true)
if [[ \$current != /opt/portablefs/releases/$release_id || \$unit != /opt/portablefs/releases/$release_id/systemd/$unit ]]; then
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

echo "Staging and preflighting $release_id on the Manager and cell control processes"
prepare_host "$OPENSTEER_MANAGER_INSTANCE" manager
if [[ $OPENSTEER_CELL_INSTANCE != "$OPENSTEER_MANAGER_INSTANCE" ]]; then
  prepare_host "$OPENSTEER_CELL_INSTANCE" cell
fi

declare -A volume_states=() minimum_generations=() restart_volumes=()
restart_count=0
for volume_id in "${volume_ids[@]}"; do
  volume=$(manager_call get "$volume_id")
  state=$(jq -r '.state' <<<"$volume")
  generation=$(jq -r '.authority_generation' <<<"$volume")
  [[ $generation =~ ^[1-9][0-9]*$ ]] || {
    echo "Manager returned an invalid authority generation for $volume_id" >&2
    exit 65
  }
  authority_release=$(cell_call current-release "$volume_id" 2>/dev/null || true)
  if [[ $state == READY && $authority_release == "$release_id" ]]; then
    echo "Authority $volume_id already runs $release_id"
    continue
  fi
  case "$state" in
    READY)
      minimum_generations[$volume_id]=$((generation + 1))
      ;;
    FENCING)
      minimum_generations[$volume_id]=$((generation + 1))
      ;;
    PROVISIONING)
      minimum_generations[$volume_id]=$generation
      ;;
    *)
      echo "volume $volume_id is in non-deployable state $state" >&2
      exit 69
      ;;
  esac
  volume_states[$volume_id]=$state
  restart_volumes[$volume_id]=1
  ((restart_count += 1))
done

if ((restart_count > 0)); then
  e2b_release drain "$evidence_dir/pre-restart.json" pre-restart
fi

echo "Activating $release_id on the Manager and cell control processes"
activate_host "$OPENSTEER_MANAGER_INSTANCE" manager
activate_host "$OPENSTEER_CELL_INSTANCE" cell

if ((restart_count > 0)); then
  for volume_id in "${volume_ids[@]}"; do
    [[ -n ${restart_volumes[$volume_id]:-} ]] || continue
    if [[ ${volume_states[$volume_id]} == READY ]]; then
      manager_call restart "$volume_id" "$release_id" >/dev/null
    fi
  done

  e2b_release drain "$evidence_dir/strict-fence.json" strict-fence
  evidence_sha=$(sha256sum "$evidence_dir/strict-fence.json" | awk '{print $1}')
  for volume_id in "${volume_ids[@]}"; do
    [[ -n ${restart_volumes[$volume_id]:-} ]] || continue
    volume=$(manager_call get "$volume_id")
    state=$(jq -r '.state' <<<"$volume")
    if [[ $state == FENCING ]]; then
      cell_call wait-absent "$volume_id" 300 >/dev/null
      manager_call strict-fence "$volume_id" "$release_id" "$evidence_sha" >/dev/null
    elif [[ $state != PROVISIONING ]]; then
      echo "volume $volume_id entered unexpected state $state during the restart" >&2
      exit 69
    fi
  done

  for volume_id in "${volume_ids[@]}"; do
    [[ -n ${restart_volumes[$volume_id]:-} ]] || continue
    manager_call wait-ready "$volume_id" "${minimum_generations[$volume_id]}" 300 >"$evidence_dir/ready-volume-$volume_id.json"
    cell_call wait-release "$volume_id" "$release_id" 300 >"$evidence_dir/authority-release-$volume_id.json"
  done
fi

e2b_release promote "$OPENSTEER_E2B_CANDIDATE"
# A sandbox may have been requested between the strict drain and the atomic tag
# promotion. Removing that narrow race window guarantees every surviving or
# subsequently created Cloud Computer uses the promoted matched client.
e2b_release drain "$evidence_dir/post-promotion.json" post-promotion

printf '%s\n' \
  "PortableFS release: $release_id" \
  "E2B template: $OPENSTEER_E2B_CANDIDATE -> default" \
  "Volumes: ${volume_ids[*]}"
