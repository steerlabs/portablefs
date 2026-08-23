#!/usr/bin/env bash
# jq programs below intentionally use jq-local variables inside single-quoted
# filters; they are not shell interpolation sites.
# shellcheck disable=SC2016
set -euo pipefail

usage() {
  cat >&2 <<EOF
usage: $0 list-cells | converge-cell CELL_ID DECLARATION_JSON |
          wait-cell-release CELL_ID RELEASE_ID TIMEOUT_SECONDS | list-volumes | capacity |
          get|get-operator VOLUME_ID | restart VOLUME_ID RELEASE_ID |
          strict-fence VOLUME_ID RELEASE_ID EVIDENCE_SHA256 |
          wait-ready VOLUME_ID MIN_GENERATION TIMEOUT_SECONDS |
          wait-destroyed VOLUME_ID TIMEOUT_SECONDS
EOF
  exit 64
}

[[ $(id -u) == 0 ]] || {
  echo "manager-api must run as root" >&2
  exit 77
}

config_base=/etc/portablefs/opensteer-deployer
config_root=$config_base/current
[[ -d $config_base && ! -L $config_base && -L $config_root && -d $config_root ]] || {
  echo "OpenSteer manager deployment identity is not installed" >&2
  exit 78
}
resolved_config=$(readlink -f "$config_root")
[[ $resolved_config == "$config_base"/credentials/* && -d $resolved_config && ! -L $resolved_config ]] || exit 78
config_root=$resolved_config
# shellcheck source=/dev/null
source "$config_root/manager.env"
: "${PORTABLEFS_MANAGER_SERVER_NAME:?missing manager server name}"

product_cert=$config_root/product.cert
product_key=$config_root/product.key
operator_cert=$config_root/operator.cert
operator_key=$config_root/operator.key
manager_ca=$config_root/manager-ca.pem
for file in "$product_cert" "$product_key" "$operator_cert" "$operator_key" "$manager_ca"; do
  [[ -f $file && ! -L $file ]] || exit 78
done

volume_pattern='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
release_pattern='^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$'
origin=https://$PORTABLEFS_MANAGER_SERVER_NAME:8443
common=(
  --cacert "$manager_ca"
  --resolve "$PORTABLEFS_MANAGER_SERVER_NAME:8443:127.0.0.1"
  --show-error
  --silent
)
response_root=$(mktemp -d)
trap 'rm -rf -- "$response_root"' EXIT

request() {
  local role=$1 method=$2 path=$3 expected_status=$4 body=${5-} key=${6-}
  local cert private_key response_file status
  case "$role" in
    product) cert=$product_cert; private_key=$product_key ;;
    operator) cert=$operator_cert; private_key=$operator_key ;;
    *) return 64 ;;
  esac
  local -a args=("${common[@]}" --cert "$cert" --key "$private_key" --request "$method")
  [[ -z $key ]] || args+=(--header "Idempotency-Key: $key")
  [[ -z $body ]] || args+=(--header 'Content-Type: application/json' --data-binary "$body")
  response_file=$response_root/response.$BASHPID.$RANDOM
  if ! status=$(curl "${args[@]}" --output "$response_file" --write-out '%{http_code}' "$origin$path"); then
    [[ ! -s $response_file ]] || cat "$response_file" >&2
    return 69
  fi
  if [[ $status != "$expected_status" ]]; then
    echo "$method $path returned HTTP $status, expected $expected_status" >&2
    [[ ! -s $response_file ]] || cat "$response_file" >&2
    return 69
  fi
  cat "$response_file"
}

require_json() {
  local value=$1 filter=$2 description=$3
  jq -e "$filter" <<<"$value" >/dev/null || {
    echo "Manager returned invalid $description JSON" >&2
    return 65
  }
}

validate_cell_inventory() {
  require_json "$1" '
    type == "object" and (keys == ["cells"]) and (.cells | type == "array") and
    ([.cells[].id] as $ids | ($ids | all(type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) and
      $ids == ($ids | sort) and ($ids | length) == ($ids | unique | length))' 'cell inventory'
}

[[ $# -ge 1 ]] || usage
command=$1

case "$command" in
  list-cells)
    [[ $# == 1 ]] || usage
    result=$(request operator GET /v1/cells 200)
    validate_cell_inventory "$result"
    printf '%s\n' "$result"
    ;;
  converge-cell)
    [[ $# == 3 && $2 =~ $volume_pattern ]] || usage
    cell_id=$2
    body=$3
    require_json "$body" '
      type == "object" and (keys == [
        "authority_dns_zone","authority_host","availability_zone","capacity_bytes","capacity_inodes",
        "first_port","first_project_id","first_service_uid","last_port","last_project_id","last_service_uid","pool"
      ]) and
      (.availability_zone | type == "string" and length > 0) and
      (.authority_host | type == "string" and length > 0) and
      (.authority_dns_zone | type == "string" and length > 0) and
      (.pool == "product" or .pool == "system" or .pool == "test") and
      (.capacity_bytes | type == "number" and . > 0 and floor == .) and
      (.capacity_inodes | type == "number" and . > 0 and floor == .) and
      (.first_project_id | type == "number" and . > 0 and floor == .) and
      (.last_project_id | type == "number" and . < 4294967295 and floor == .) and
      (.last_project_id >= .first_project_id) and
      (.first_service_uid | type == "number" and . >= 1000 and floor == .) and
      (.last_service_uid | type == "number" and . < 4294967295 and floor == .) and
      (.last_service_uid >= .first_service_uid) and
      (.first_port | type == "number" and . >= 1024 and floor == .) and
      (.last_port | type == "number" and . < 65535 and floor == .) and
      (.last_port >= .first_port)' 'cell declaration'
    result=$(request operator PUT "/v1/cells/$cell_id" 200 "$body")
    expected_project=$(jq '.last_project_id' <<<"$body")
    expected_uid=$(jq '.last_service_uid' <<<"$body")
    expected_port=$(jq '.last_port' <<<"$body")
    require_json "$result" ".id == \"$cell_id\" and (.registration_sha256 | type == \"string\" and length == 64)" \
      'converged cell'
    [[ $(jq '.last_project_id' <<<"$result") == "$expected_project" &&
      $(jq '.last_service_uid' <<<"$result") == "$expected_uid" &&
      $(jq '.last_port' <<<"$result") == "$expected_port" ]] || {
      echo "Manager converged cell $cell_id with different allocator ends" >&2
      exit 65
    }
    printf '%s\n' "$result"
    ;;
  wait-cell-release)
    [[ $# == 4 && $2 =~ $volume_pattern && $3 =~ $release_pattern && $4 =~ ^[1-9][0-9]*$ ]] || usage
    cell_id=$2
    release_id=$3
    deadline=$((SECONDS + $4))
    while ((SECONDS < deadline)); do
      result=$(request operator GET /v1/cells 200)
      validate_cell_inventory "$result"
      cell=$(jq -c --arg id "$cell_id" '[.cells[] | select(.id == $id)] | if length == 1 then .[0] else empty end' <<<"$result")
      [[ -n $cell ]] || {
        echo "Manager omitted declared cell $cell_id while waiting for release convergence" >&2
        exit 69
      }
      health=$(jq -r '.health' <<<"$cell")
      [[ $health != QUARANTINED ]] || {
        printf '%s\n' "$cell" >&2
        exit 69
      }
      if jq -e --arg release "$release_id" '
        .health == "HEALTHY" and .plan_release_id == $release and
        .last_manager_release == $release and .last_agent_release == $release and .last_helper_release == $release and
        (.registration_sha256 | type == "string" and length == 64) and
        ([.last_project_id,.last_service_uid,.last_port] | all(type == "number" and . > 0 and floor == .))' \
        <<<"$cell" >/dev/null; then
        printf '%s\n' "$cell"
        exit 0
      fi
      sleep 2
    done
    echo "timed out waiting for cell $cell_id to converge on $release_id" >&2
    exit 75
    ;;
  list-volumes)
    [[ $# == 1 ]] || usage
    result=$(request operator GET /v1/volumes 200)
    require_json "$result" '
      type == "object" and (keys == ["volumes"]) and (.volumes | type == "array") and
      ([.volumes[].id] as $ids | ($ids | all(type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) and
        $ids == ($ids | sort) and ($ids | length) == ($ids | unique | length))' 'volume inventory'
    printf '%s\n' "$result"
    ;;
  capacity)
    [[ $# == 1 ]] || usage
    result=$(request operator GET /v1/capacity 200)
    require_json "$result" '
      type == "object" and (keys == ["pools"]) and (.pools | type == "array") and
      ([.pools[].pool] as $names | $names == ($names | sort) and ($names | length) == ($names | unique | length)) and
      (.pools | all(
        (keys == ["archived_volumes","capacity_bytes","capacity_inodes","create_admissible","create_status",
          "measured_used_bytes","measured_used_inodes","pending_bytes","pending_inodes","placements","pool",
          "restore_admissible","restore_status"]) and
        (.pool == "product" or .pool == "system" or .pool == "test") and
        ([.capacity_bytes,.capacity_inodes,.measured_used_bytes,.measured_used_inodes,.pending_bytes,.pending_inodes,
          .placements,.archived_volumes] | all(type == "number" and . >= 0 and floor == .)) and
        (.create_admissible | type == "boolean") and
        (.restore_admissible | type == "boolean") and
        (.create_status == "ADMISSIBLE" or .create_status == "CELL_UNAVAILABLE" or .create_status == "CAPACITY_EXHAUSTED" or .create_status == "BUSY") and
        (.restore_status == "ADMISSIBLE" or .restore_status == "CELL_UNAVAILABLE" or .restore_status == "CAPACITY_EXHAUSTED" or .restore_status == "BUSY")
      ))' 'capacity report'
    printf '%s\n' "$result"
    ;;
  get | get-operator)
    [[ $# == 2 && $2 =~ $volume_pattern ]] || usage
    volume_id=$2
    role=product
    [[ $command == get-operator ]] && role=operator
    result=$(request "$role" GET "/v1/volumes/$volume_id" 200)
    require_json "$result" ".id == \"$volume_id\"" 'volume'
    printf '%s\n' "$result"
    ;;
  restart)
    [[ $# == 3 && $2 =~ $volume_pattern && $3 =~ $release_pattern ]] || usage
    volume_id=$2
    release_id=$3
    body=$(jq -cn --arg volume "$volume_id" --arg reason "OpenSteer matched release $release_id" \
      '{volume_id:$volume,reason:$reason}')
    result=$(request product POST "/v1/volumes/$volume_id/restart" 200 "$body" \
      "opensteer-$release_id-$volume_id-restart")
    require_json "$result" ".id == \"$volume_id\"" 'restarted volume'
    printf '%s\n' "$result"
    ;;
  strict-fence)
    [[ $# == 4 && $2 =~ $volume_pattern && $3 =~ $release_pattern && $4 =~ ^[0-9a-f]{64}$ ]] || usage
    volume_id=$2
    release_id=$3
    evidence_sha=$4
    body=$(jq -cn --arg volume "$volume_id" --arg evidence "$evidence_sha" \
      '{volume_id:$volume,evidence_sha256:$evidence}')
    result=$(request operator POST "/v1/volumes/$volume_id/strict-fence" 200 "$body" \
      "opensteer-$release_id-$volume_id-strict-${evidence_sha:0:16}")
    require_json "$result" ".id == \"$volume_id\"" 'strict-fenced volume'
    printf '%s\n' "$result"
    ;;
  wait-ready)
    [[ $# == 4 && $2 =~ $volume_pattern && $3 =~ ^[1-9][0-9]*$ && $4 =~ ^[1-9][0-9]*$ ]] || usage
    volume_id=$2
    minimum_generation=$3
    deadline=$((SECONDS + $4))
    while ((SECONDS < deadline)); do
      result=$(request operator GET "/v1/volumes/$volume_id" 200)
      require_json "$result" ".id == \"$volume_id\"" 'volume readiness'
      state=$(jq -r '.state' <<<"$result")
      generation=$(jq -r '.authority_generation' <<<"$result")
      if [[ $state == READY && $generation =~ ^[0-9]+$ ]] && ((generation >= minimum_generation)); then
        printf '%s\n' "$result"
        exit 0
      fi
      [[ $state != QUARANTINED ]] || {
        printf '%s\n' "$result" >&2
        exit 69
      }
      sleep 2
    done
    echo "timed out waiting for volume $volume_id to reach READY generation $minimum_generation" >&2
    exit 75
    ;;
  wait-destroyed)
    [[ $# == 3 && $2 =~ $volume_pattern && $3 =~ ^[1-9][0-9]*$ ]] || usage
    volume_id=$2
    deadline=$((SECONDS + $3))
    while ((SECONDS < deadline)); do
      result=$(request operator GET "/v1/volumes/$volume_id" 200)
      require_json "$result" ".id == \"$volume_id\"" 'volume deletion'
      state=$(jq -r '.state' <<<"$result")
      if [[ $state == DESTROYED ]]; then
        printf '%s\n' "$result"
        exit 0
      fi
      [[ $state == DESTROYING ]] || {
        printf '%s\n' "$result" >&2
        exit 69
      }
      sleep 2
    done
    echo "timed out waiting for volume $volume_id to reach DESTROYED" >&2
    exit 75
    ;;
  *) usage ;;
esac
