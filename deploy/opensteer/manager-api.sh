#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 get|get-operator VOLUME_ID | restart VOLUME_ID RELEASE_ID | strict-fence VOLUME_ID RELEASE_ID EVIDENCE_SHA256 | wait-ready VOLUME_ID MIN_GENERATION TIMEOUT_SECONDS | wait-destroyed VOLUME_ID TIMEOUT_SECONDS" >&2
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
  --fail-with-body
  --resolve "$PORTABLEFS_MANAGER_SERVER_NAME:8443:127.0.0.1"
  --show-error
  --silent
)

request() {
  local role=$1 method=$2 path=$3 body=${4-} key=${5-} cert private_key
  case "$role" in
    product) cert=$product_cert; private_key=$product_key ;;
    operator) cert=$operator_cert; private_key=$operator_key ;;
    *) exit 64 ;;
  esac
  args=("${common[@]}" --cert "$cert" --key "$private_key" --request "$method")
  [[ -z $key ]] || args+=(--header "Idempotency-Key: $key")
  [[ -z $body ]] || args+=(--header 'Content-Type: application/json' --data-binary "$body")
  curl "${args[@]}" "$origin$path"
}

[[ $# -ge 2 ]] || usage
command=$1
volume_id=$2
[[ $volume_id =~ $volume_pattern ]] || usage

case "$command" in
  get)
    [[ $# == 2 ]] || usage
    request product GET "/v1/volumes/$volume_id"
    ;;
  get-operator)
    [[ $# == 2 ]] || usage
    request operator GET "/v1/volumes/$volume_id"
    ;;
  restart)
    [[ $# == 3 && $3 =~ $release_pattern ]] || usage
    release_id=$3
    body=$(jq -cn --arg volume "$volume_id" --arg reason "OpenSteer matched release $release_id" \
      '{volume_id:$volume,reason:$reason}')
    request product POST "/v1/volumes/$volume_id/restart" "$body" \
      "opensteer-$release_id-$volume_id-restart"
    ;;
  strict-fence)
    [[ $# == 4 && $3 =~ $release_pattern && $4 =~ ^[0-9a-f]{64}$ ]] || usage
    release_id=$3
    evidence_sha=$4
    body=$(jq -cn --arg volume "$volume_id" --arg evidence "$evidence_sha" \
      '{volume_id:$volume,evidence_sha256:$evidence}')
    request operator POST "/v1/volumes/$volume_id/strict-fence" "$body" \
      "opensteer-$release_id-$volume_id-strict-${evidence_sha:0:16}"
    ;;
  wait-ready)
    [[ $# == 4 && $3 =~ ^[1-9][0-9]*$ && $4 =~ ^[1-9][0-9]*$ ]] || usage
    minimum_generation=$3
    deadline=$((SECONDS + $4))
    while ((SECONDS < deadline)); do
      result=$(request operator GET "/v1/volumes/$volume_id")
      state=$(jq -r '.state' <<<"$result")
      generation=$(jq -r '.authority_generation' <<<"$result")
      if [[ $state == READY && $generation =~ ^[0-9]+$ ]] && ((generation >= minimum_generation)); then
        printf '%s\n' "$result"
        exit 0
      fi
      [[ $state != QUARANTINED && $state != RETIRED ]] || {
        printf '%s\n' "$result" >&2
        exit 69
      }
      sleep 2
    done
    echo "timed out waiting for volume $volume_id to reach READY generation $minimum_generation" >&2
    exit 75
    ;;
  wait-destroyed)
    [[ $# == 3 && $3 =~ ^[1-9][0-9]*$ ]] || usage
    deadline=$((SECONDS + $3))
    while ((SECONDS < deadline)); do
      result=$(request operator GET "/v1/volumes/$volume_id")
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
