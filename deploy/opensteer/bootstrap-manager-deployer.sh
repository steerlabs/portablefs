#!/usr/bin/env bash
set -euo pipefail

[[ $# == 7 ]] || {
  echo "usage: $0 GCP_PROJECT GCP_ZONE MANAGER_INSTANCE MANAGER_SERVER_NAME PRODUCT_ISSUER VOLUME_ID /absolute/credential-directory" >&2
  exit 64
}
project=$1
zone=$2
manager=$3
server_name=$4
product_issuer=$5
volume_id=$6
credential_dir=$7
operator_identity=opensteer-deployer
[[ $project =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ $zone =~ ^[a-z0-9-]+$ ]] || exit 64
[[ $manager =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || exit 64
[[ $server_name =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || exit 64
[[ $product_issuer =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || exit 64
[[ $volume_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 64
[[ $credential_dir == /* && -d $credential_dir && ! -L $credential_dir ]] || exit 64

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

for file in client-ca.pem client-ca.key manager-ca.pem product.cert product.key; do
  [[ -f $credential_dir/$file && ! -L $credential_dir/$file ]] || {
    echo "missing or unsafe credential member: $file" >&2
    exit 66
  }
  install -m 0600 "$credential_dir/$file" "$temporary/$file"
done

public_key_sha() {
  openssl pkey "$@" -pubout -outform DER | sha256sum | awk '{print $1}'
}
cert_key_sha=$(openssl x509 -in "$temporary/client-ca.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')
[[ $cert_key_sha == "$(public_key_sha -in "$temporary/client-ca.key")" ]] || {
  echo "client CA certificate does not match its private key" >&2
  exit 65
}
openssl verify -CAfile "$temporary/client-ca.pem" -purpose sslclient "$temporary/product.cert" >/dev/null
product_key_sha=$(openssl x509 -in "$temporary/product.cert" -pubkey -noout | \
  openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')
[[ $product_key_sha == "$(public_key_sha -in "$temporary/product.key")" ]] || {
  echo "product certificate does not match its private key" >&2
  exit 65
}
product_san=$(openssl x509 -in "$temporary/product.cert" -noout -ext subjectAltName | tail -n +2 | tr -d '[:space:]')
[[ $product_san == "URI:spiffe://portablefs/control/product/$product_issuer" ]] || {
  echo "product certificate has the wrong or additional subject alternative name" >&2
  exit 65
}
openssl x509 -in "$temporary/product.cert" -checkend 86400 -noout >/dev/null || {
  echo "product certificate expires within 24 hours" >&2
  exit 65
}
openssl x509 -in "$temporary/manager-ca.pem" -noout >/dev/null

openssl req -new -newkey ed25519 -noenc \
  -subj "/CN=OpenSteer PortableFS deployer" \
  -keyout "$temporary/operator.key" -out "$temporary/operator.csr" >/dev/null 2>&1
openssl x509 -req -days 30 \
  -in "$temporary/operator.csr" \
  -CA "$temporary/client-ca.pem" -CAkey "$temporary/client-ca.key" -CAcreateserial \
  -extfile <(printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=clientAuth' \
    "subjectAltName=URI:spiffe://portablefs/control/operator/$operator_identity") \
  -out "$temporary/operator.cert" >/dev/null 2>&1
printf '%s\n' \
  "PORTABLEFS_MANAGER_SERVER_NAME=$server_name" \
  "PORTABLEFS_PRODUCT_ISSUER=$product_issuer" \
  "PORTABLEFS_OPERATOR_IDENTITY=$operator_identity" \
  >"$temporary/manager.env"
chmod 0400 "$temporary/manager.env" "$temporary/product.key" "$temporary/operator.key"
chmod 0444 "$temporary/client-ca.pem" "$temporary/manager-ca.pem" \
  "$temporary/product.cert" "$temporary/operator.cert"

gcloud compute ssh "$manager" "${gcloud_common[@]}" \
  --command="install -d -m 0700 \"\$HOME/$remote_name\"" >/dev/null
gcloud compute scp "${gcloud_common[@]}" \
  "$temporary/client-ca.pem" "$temporary/manager-ca.pem" "$temporary/manager.env" \
  "$temporary/product.cert" "$temporary/product.key" \
  "$temporary/operator.cert" "$temporary/operator.key" \
  "$root/deploy/opensteer/install-manager-deployer.sh" \
  "$root/deploy/opensteer/manager-api.sh" \
  "$manager:~/$remote_name/"
gcloud compute ssh "$manager" "${gcloud_common[@]}" \
  --command="sudo \"\$HOME/$remote_name/install-manager-deployer.sh\" \"\$HOME/$remote_name\" $volume_id"

echo "Manager deployment identities installed; the operator certificate is renewable and valid for 30 days"
