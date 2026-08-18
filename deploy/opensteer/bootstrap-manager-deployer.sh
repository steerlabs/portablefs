#!/usr/bin/env bash
set -euo pipefail

[[ $# == 6 ]] || {
  echo "usage: $0 GCP_PROJECT GCP_ZONE MANAGER_INSTANCE CELL_INSTANCE MANAGER_SERVER_NAME VOLUME_ID" >&2
  exit 64
}
project=$1
zone=$2
manager=$3
cell=$4
server_name=$5
volume_id=$6
[[ $project =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ $zone =~ ^[a-z0-9-]+$ ]] || exit 64
[[ $manager =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64
[[ $cell =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64
[[ $server_name =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || exit 64
[[ $volume_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 64

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
temporary=$(mktemp -d)
remote_name=.portablefs-bootstrap-$(openssl rand -hex 8)
gcloud_common=(--project "$project" --zone "$zone" --tunnel-through-iap --quiet)
cleanup() {
  rm -rf -- "$temporary"
  gcloud compute ssh "$manager" "${gcloud_common[@]}" \
    --command="rm -rf -- \"\$HOME/$remote_name\"" >/dev/null 2>&1 || true
}
trap cleanup EXIT

encoded_ca=$(gcloud compute ssh "$cell" "${gcloud_common[@]}" \
  --command='sudo base64 -w0 /etc/portablefs/trust/manager-ca.pem')
printf '%s' "$encoded_ca" | openssl base64 -d -A -out "$temporary/manager-ca.pem"
openssl x509 -in "$temporary/manager-ca.pem" -noout >/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 397 \
  -subj '/CN=OpenSteer PortableFS deployment CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$temporary/deploy-ca.key" -out "$temporary/deploy-ca.pem" >/dev/null 2>&1

issue() {
  local role=$1 uri=$2
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
    -subj "/CN=OpenSteer PortableFS $role deployer" \
    -keyout "$temporary/$role.key" -out "$temporary/$role.csr" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 365 \
    -in "$temporary/$role.csr" \
    -CA "$temporary/deploy-ca.pem" -CAkey "$temporary/deploy-ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature' \
      'extendedKeyUsage=clientAuth' \
      "subjectAltName=URI:$uri") \
    -out "$temporary/$role.cert" >/dev/null 2>&1
}
issue product spiffe://portablefs/control/product/portablefs-test
issue operator spiffe://portablefs/control/operator/opensteer-deployer
printf 'PORTABLEFS_MANAGER_SERVER_NAME=%s\n' "$server_name" >"$temporary/manager.env"
chmod 0400 "$temporary/manager.env" "$temporary/product.key" "$temporary/operator.key"
chmod 0444 "$temporary/deploy-ca.pem" "$temporary/manager-ca.pem" \
  "$temporary/product.cert" "$temporary/operator.cert"

gcloud compute ssh "$manager" "${gcloud_common[@]}" \
  --command="install -d -m 0700 \"\$HOME/$remote_name\"" >/dev/null
gcloud compute scp "${gcloud_common[@]}" \
  "$temporary/deploy-ca.pem" "$temporary/manager-ca.pem" "$temporary/manager.env" \
  "$temporary/product.cert" "$temporary/product.key" \
  "$temporary/operator.cert" "$temporary/operator.key" \
  "$root/deploy/opensteer/install-manager-deployer.sh" \
  "$root/deploy/opensteer/manager-api.sh" \
  "$manager:~/$remote_name/"
gcloud compute ssh "$manager" "${gcloud_common[@]}" \
  --command="sudo \"\$HOME/$remote_name/install-manager-deployer.sh\" \"\$HOME/$remote_name\" $volume_id"

echo "Manager deployment identity bootstrap completed; re-run before the one-year client certificates expire"
