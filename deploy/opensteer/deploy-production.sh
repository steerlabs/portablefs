#!/usr/bin/env bash
set -euo pipefail

declare -A host_instances=() host_zones=() host_roles=() prepared_hosts=()
declare -A cell_instances=() cell_zones=()

release_lock_check() {
  if [[ -n ${OPENSTEER_RELEASE_LOCK_LOST_FILE:-} && -f $OPENSTEER_RELEASE_LOCK_LOST_FILE ]]; then
    echo "global staging release lock was lost; refusing the next live mutation" >&2
    return 75
  fi
}

ssh_run() {
  local zone=$1 instance=$2 command=$3
  release_lock_check
  gcloud compute ssh "$instance" \
    --project "$gcp_project" --zone "$zone" --tunnel-through-iap --quiet \
    --command="$command"
}

copy_to() {
  local zone=$1 instance=$2
  local command="set -euo pipefail; tar -xzf - -C \"\$HOME/$remote_stage\""
  release_lock_check
  gcloud compute ssh "$instance" \
    --project "$gcp_project" --zone "$zone" --tunnel-through-iap --quiet \
    --command="$command" <"$transfer_archive"
}

prepare_host() {
  local host_key=$1 zone=${host_zones[$1]} instance=${host_instances[$1]}
  local command
  command="set -euo pipefail; install -d -m 0700 \"\$HOME/.portablefs-deploy\" \"\$HOME/$remote_stage\""
  ssh_run "$zone" "$instance" "$command" >/dev/null
  copy_to "$zone" "$instance"
  command="set -euo pipefail; \"\$HOME/$remote_stage/verify-hosted-release.sh\" \"\$HOME/$remote_stage/$release_base\""
  ssh_run "$zone" "$instance" "$command" >/dev/null
  prepared_hosts[$host_key]=1
}

activate_host() {
  local host_key=$1 role=${host_roles[$1]} zone=${host_zones[$1]} instance=${host_instances[$1]}
  local command
  case "$role" in
    manager | cell | manager-cell) ;;
    *) return 64 ;;
  esac
  command="set -euo pipefail; sudo \"\$HOME/$remote_stage/activate-hosted-release.sh\" \"\$HOME/$remote_stage/$release_base\" $role"
  ssh_run "$zone" "$instance" "$command"
}

append_remote_arguments() {
  local command=$1 argument quoted
  shift
  for argument in "$@"; do
    printf -v quoted '%q' "$argument"
    command+=" $quoted"
  done
  printf '%s' "$command"
}

sorted_lines() {
  if (($# > 0)); then
    printf '%s\n' "$@" | LC_ALL=C sort
  fi
}

manager_call() {
  local command
  release_lock_check
  command=$(append_remote_arguments "sudo \"\$HOME/$remote_stage/manager-api.sh\"" "$@")
  ssh_run "$manager_zone" "$manager_instance" "$command"
}

cell_call() {
  local cell_id=$1
  shift
  local command
  [[ -n ${cell_instances[$cell_id]:-} && -n ${cell_zones[$cell_id]:-} ]] || {
    echo "no declared host for cell $cell_id" >&2
    return 65
  }
  release_lock_check
  command=$(append_remote_arguments "sudo \"\$HOME/$remote_stage/cell-authority-state.sh\"" "$@")
  ssh_run "${cell_zones[$cell_id]}" "${cell_instances[$cell_id]}" "$command"
}

cleanup_remote() {
  local host_key command
  command="rm -rf -- \"\$HOME/$remote_stage\""
  for host_key in "${!prepared_hosts[@]}"; do
    if ! release_lock_check; then
      echo "Leaving staged remote release files because the global release fence was lost" >&2
      return
    fi
    ssh_run "${host_zones[$host_key]}" "${host_instances[$host_key]}" "$command" >/dev/null 2>&1 || true
  done
}

cleanup() {
  [[ -z ${archive_dir:-} ]] || rm -rf -- "$archive_dir"
  [[ -z ${remote_stage:-} ]] || cleanup_remote
}

e2b_release() {
  release_lock_check
  node "$root/deploy/opensteer/e2b-release.mjs" "$@"
}

main() {
  local -a required=(
    E2B_API_KEY
    OPENSTEER_CELL_INVENTORY_FILE
    OPENSTEER_E2B_CANDIDATE
    OPENSTEER_EVIDENCE_DIR
    OPENSTEER_E2B_SDK_ROOT
    OPENSTEER_GCP_PROJECT
    OPENSTEER_RELEASE_DIR
  )
  local name
  for name in "${required[@]}"; do
    [[ -n ${!name:-} ]] || {
      echo "$name is required" >&2
      exit 64
    }
  done

  root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
  release_dir=$OPENSTEER_RELEASE_DIR
  evidence_dir=$OPENSTEER_EVIDENCE_DIR
  inventory_file=$OPENSTEER_CELL_INVENTORY_FILE
  gcp_project=$OPENSTEER_GCP_PROJECT
  [[ $release_dir == /* && -d $release_dir && $evidence_dir == /* ]] || exit 64
  [[ $inventory_file == /* && -f $inventory_file && ! -L $inventory_file ]] || {
    echo "OPENSTEER_CELL_INVENTORY_FILE must name an absolute regular file" >&2
    exit 64
  }
  [[ $gcp_project =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
  if [[ $gcp_project == opensteer-staging ]]; then
    [[ ${OPENSTEER_RELEASE_LOCK_STATE_FILE:-} == /* && -f $OPENSTEER_RELEASE_LOCK_STATE_FILE &&
      ${OPENSTEER_RELEASE_LOCK_LOST_FILE:-} == /* ]] || {
      echo "opensteer-staging requires the global release-lock transaction wrapper" >&2
      exit 64
    }
    python3 "$root/deploy/opensteer/staging-release-lock.py" assert-owned \
      --state-file "$OPENSTEER_RELEASE_LOCK_STATE_FILE"
  fi
  node "$root/deploy/opensteer/release-inventory.mjs" validate "$inventory_file" >/dev/null

  release_id=$(<"$release_dir/release-id")
  [[ $release_id =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ ]] || exit 64
  release_base=${release_dir##*/}
  remote_stage=.portablefs-deploy/$release_id
  manager_instance=$(jq -r '.manager.instance' "$inventory_file")
  manager_zone=$(jq -r '.manager.zone' "$inventory_file")
  manager_host_key=$manager_zone/$manager_instance

  host_instances[$manager_host_key]=$manager_instance
  host_zones[$manager_host_key]=$manager_zone
  host_roles[$manager_host_key]=manager
  local cell_id cell_instance cell_zone host_key
  while IFS=$'\t' read -r cell_id cell_instance cell_zone; do
    cell_instances[$cell_id]=$cell_instance
    cell_zones[$cell_id]=$cell_zone
    host_key=$cell_zone/$cell_instance
    host_instances[$host_key]=$cell_instance
    host_zones[$host_key]=$cell_zone
    if [[ $host_key == "$manager_host_key" ]]; then
      host_roles[$host_key]=manager-cell
    else
      host_roles[$host_key]=cell
    fi
  done < <(jq -r '.cells[] | [.id,.instance,.zone] | @tsv' "$inventory_file")

  mkdir -p -- "$evidence_dir"
  install -m 0600 "$inventory_file" "$evidence_dir/release-inventory.json"
  sha256sum "$evidence_dir/release-inventory.json" >"$evidence_dir/release-inventory.sha256"
  "$root/deploy/gcp/verify-hosted-release.sh" "$release_dir" >/dev/null
  archive_dir=$(mktemp -d)
  transfer_archive=$archive_dir/$release_id.tar.gz
  tar -czf "$transfer_archive" \
    -C "${release_dir%/*}" "$release_base" \
    -C "$root/deploy/gcp" activate-hosted-release.sh verify-hosted-release.sh \
    -C "$root/deploy/opensteer" manager-api.sh cell-authority-state.sh
  trap cleanup EXIT

  echo "Staging and preflighting $release_id on every declared control host"
  while IFS= read -r host_key; do
    prepare_host "$host_key"
  done < <(sorted_lines "${!host_instances[@]}")

  # All remote bundles are verified before the first host changes. Cross-host
  # activation is necessarily forward-only, but an incomplete transfer can
  # never leave a partially promoted fleet.
  echo "Activating $release_id on the Manager control host"
  activate_host "$manager_host_key"

  local declaration
  while IFS=$'\t' read -r cell_id declaration; do
    manager_call converge-cell "$cell_id" "$declaration" >"$evidence_dir/converged-cell-$cell_id.json"
  done < <(jq -r '.cells[] | [.id, (.declaration | @json)] | @tsv' "$inventory_file")

  manager_call list-cells >"$evidence_dir/manager-cells.json"
  manager_call list-volumes >"$evidence_dir/manager-volumes-before-cell-activation.json"
  node "$root/deploy/opensteer/release-inventory.mjs" plan "$inventory_file" \
    "$evidence_dir/manager-cells.json" "$evidence_dir/manager-volumes-before-cell-activation.json" \
    >"$evidence_dir/release-plan-before-cell-activation.json"

  echo "Activating $release_id on every remaining cell control host"
  while IFS= read -r host_key; do
    [[ $host_key == "$manager_host_key" ]] || activate_host "$host_key"
  done < <(sorted_lines "${!host_instances[@]}")

  # Host activation operates on installed units; the inventory is the source
  # of truth for which concrete cell instances must exist. Prove both control
  # processes for every declared cell now execute the exact release.
  while IFS= read -r cell_id; do
    cell_call "$cell_id" verify-control-release "$cell_id" "$release_id" \
      >"$evidence_dir/cell-control-release-$cell_id.json"
    manager_call wait-cell-release "$cell_id" "$release_id" 300 \
      >"$evidence_dir/manager-cell-release-$cell_id.json"
  done < <(jq -r '.cells[].id' "$inventory_file")

  # This is the authoritative cutover inventory. A volume created after this
  # point starts under an already-activated cell and therefore already uses the
  # new release; every earlier placement is listed and coordinated below.
  manager_call list-cells >"$evidence_dir/manager-cells-after-cell-activation.json"
  manager_call list-volumes >"$evidence_dir/manager-volumes.json"
  manager_call capacity >"$evidence_dir/capacity-before-restart.json"
  node "$root/deploy/opensteer/release-inventory.mjs" plan "$inventory_file" \
    "$evidence_dir/manager-cells-after-cell-activation.json" "$evidence_dir/manager-volumes.json" \
    >"$evidence_dir/release-plan.json"

  declare -A volume_states=() minimum_generations=() restart_volumes=() cleanup_volumes=()
  local volume_id state generation authority_status authority_release restart_count=0
  while IFS=$'\t' read -r volume_id state generation cell_id; do
    [[ $generation =~ ^[1-9][0-9]*$ ]] || {
      echo "Manager returned an invalid authority generation for $volume_id" >&2
      exit 65
    }
    if [[ $cell_id == null ]]; then
      case "$state" in
        DESTROYING)
          cleanup_volumes[$volume_id]=1
          volume_states[$volume_id]=$state
          ;;
        ARCHIVED | DESTROYED) ;;
        *)
          echo "unplaced volume $volume_id is in unexpected state $state" >&2
          exit 69
          ;;
      esac
      continue
    fi
    authority_status=$(cell_call "$cell_id" inspect-release "$volume_id")
    jq -e --arg volume "$volume_id" '
      type == "object" and (keys == ["authority_running","release_id","volume_id"]) and
      .volume_id == $volume and (.authority_running | type == "boolean") and
      (if .authority_running then (.release_id | type == "string" and test("^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$"))
       else .release_id == null end)' <<<"$authority_status" >/dev/null || {
      echo "cell returned invalid authority release state for $volume_id" >&2
      exit 65
    }
    authority_release=$(jq -r '.release_id // ""' <<<"$authority_status")
    if [[ $state == READY && $authority_release == "$release_id" ]]; then
      echo "Authority $volume_id already runs $release_id"
      continue
    fi
    case "$state" in
      READY)
        manager_call get "$volume_id" >/dev/null
        minimum_generations[$volume_id]=$((generation + 1))
        restart_volumes[$volume_id]=1
        ((restart_count += 1))
        ;;
      FENCING)
        minimum_generations[$volume_id]=$((generation + 1))
        restart_volumes[$volume_id]=1
        ((restart_count += 1))
        ;;
      PROVISIONING)
        minimum_generations[$volume_id]=$generation
        restart_volumes[$volume_id]=1
        ((restart_count += 1))
        ;;
      DESTROYING)
        cleanup_volumes[$volume_id]=1
        ;;
      RESTORING)
        [[ -z $authority_release || $authority_release == "$release_id" ]] || {
          echo "restoring volume $volume_id still runs $authority_release; finish its lifecycle before release" >&2
          exit 69
        }
        ;;
      QUARANTINED | ARCHIVING | ARCHIVED | DESTROYED) ;;
      *)
        echo "volume $volume_id is in unknown state $state" >&2
        exit 69
        ;;
    esac
    volume_states[$volume_id]=$state
  done < <(jq -r '.volumes[] | [.id,.state,.authority_generation,(.placement.cell_id // "null")] | @tsv' \
    "$evidence_dir/manager-volumes.json")

  if ((restart_count > 0)); then
    e2b_release drain "$evidence_dir/pre-restart.json" pre-restart

    while IFS= read -r volume_id; do
      if [[ ${volume_states[$volume_id]} == READY ]]; then
        manager_call restart "$volume_id" "$release_id" >/dev/null
      fi
    done < <(sorted_lines "${!restart_volumes[@]}")

    e2b_release drain "$evidence_dir/strict-fence.json" strict-fence
    evidence_sha=$(sha256sum "$evidence_dir/strict-fence.json" | awk '{print $1}')
    while IFS= read -r volume_id; do
      volume=$(manager_call get-operator "$volume_id")
      state=$(jq -r '.state' <<<"$volume")
      cell_id=$(jq -r '.placement.cell_id' <<<"$volume")
      if [[ $state == FENCING ]]; then
        cell_call "$cell_id" wait-absent "$volume_id" 300 >/dev/null
        manager_call strict-fence "$volume_id" "$release_id" "$evidence_sha" >/dev/null
      elif [[ $state != PROVISIONING ]]; then
        echo "volume $volume_id entered unexpected state $state during the restart" >&2
        exit 69
      fi
    done < <(sorted_lines "${!restart_volumes[@]}")

    while IFS= read -r volume_id; do
      volume=$(manager_call get-operator "$volume_id")
      cell_id=$(jq -r '.placement.cell_id' <<<"$volume")
      manager_call wait-ready "$volume_id" "${minimum_generations[$volume_id]}" 300 \
        >"$evidence_dir/ready-volume-$volume_id.json"
      cell_call "$cell_id" wait-release "$volume_id" "$release_id" 300 \
        >"$evidence_dir/authority-release-$volume_id.json"
    done < <(sorted_lines "${!restart_volumes[@]}")
  fi

  while IFS= read -r volume_id; do
    manager_call wait-destroyed "$volume_id" 300 >"$evidence_dir/destroyed-volume-$volume_id.json"
  done < <(sorted_lines "${!cleanup_volumes[@]}")

  manager_call list-cells >"$evidence_dir/manager-cells-after-restart.json"
  manager_call list-volumes >"$evidence_dir/manager-volumes-after-restart.json"
  manager_call capacity >"$evidence_dir/capacity-after-restart.json"
  node "$root/deploy/opensteer/release-inventory.mjs" plan "$inventory_file" \
    "$evidence_dir/manager-cells-after-restart.json" "$evidence_dir/manager-volumes-after-restart.json" \
    >"$evidence_dir/release-plan-after-restart.json"

  # Client promotion is the final commit point. No failed host activation,
  # unknown placement, or incomplete Authority restart can move this tag.
  e2b_release promote "$OPENSTEER_E2B_CANDIDATE"
  e2b_release drain "$evidence_dir/post-promotion.json" post-promotion

  printf '%s\n' \
    "PortableFS release: $release_id" \
    "E2B template: $OPENSTEER_E2B_CANDIDATE -> default" \
    "Cells: ${#cell_instances[@]}" \
    "Volumes discovered: $(jq '.volumes | length' "$evidence_dir/manager-volumes.json")"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
