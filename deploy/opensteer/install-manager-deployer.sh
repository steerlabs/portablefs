#!/usr/bin/env bash
set -euo pipefail

[[ $# == 2 && $1 == /* && -d $1 && $2 =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
  echo "usage: $0 /absolute/credential-stage VOLUME_ID" >&2
  exit 64
}
[[ $(id -u) == 0 ]] || {
  echo "install-manager-deployer must run as root" >&2
  exit 77
}

stage=$1
volume_id=$2
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for file in deploy-ca.pem manager-ca.pem manager.env operator.cert operator.key product.cert product.key; do
  [[ -f $stage/$file && ! -L $stage/$file ]] || {
    echo "missing or unsafe deployment credential member: $file" >&2
    exit 66
  }
done

# shellcheck source=/dev/null
source "$stage/manager.env"
: "${PORTABLEFS_MANAGER_SERVER_NAME:?missing manager server name}"
[[ $PORTABLEFS_MANAGER_SERVER_NAME =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || exit 65

verify_identity() {
  local role=$1 identity=$2
  local cert=$stage/$role.cert key=$stage/$role.key expected actual san
  openssl verify -CAfile "$stage/deploy-ca.pem" -purpose sslclient "$cert" >/dev/null
  expected=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')
  actual=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | awk '{print $1}')
  [[ $expected == "$actual" ]] || {
    echo "$role certificate does not match its private key" >&2
    exit 65
  }
  san=$(openssl x509 -in "$cert" -noout -ext subjectAltName | tail -n +2 | tr -d '[:space:]')
  [[ $san == "URI:spiffe://portablefs/control/$identity" ]] || {
    echo "$role certificate has the wrong or additional subject alternative name" >&2
    exit 65
  }
}
verify_identity product product/portablefs-test
verify_identity operator operator/opensteer-deployer

destination=/etc/portablefs/opensteer-deployer
install -d -o root -g root -m 0700 "$destination"
install -o root -g root -m 0444 "$stage/deploy-ca.pem" "$destination/deploy-ca.pem"
install -o root -g root -m 0444 "$stage/manager-ca.pem" "$destination/manager-ca.pem"
install -o root -g root -m 0400 "$stage/manager.env" "$destination/manager.env"
install -o root -g root -m 0444 "$stage/product.cert" "$destination/product.cert"
install -o root -g root -m 0400 "$stage/product.key" "$destination/product.key"
install -o root -g root -m 0444 "$stage/operator.cert" "$destination/operator.cert"
install -o root -g root -m 0400 "$stage/operator.key" "$destination/operator.key"

trust=/etc/portablefs/manager/trust/control-client-ca.pem
[[ -f $trust && ! -L $trust ]] || exit 66
replacement=$(mktemp "${trust}.new.XXXXXXXX")
trap 'rm -f -- "$replacement"' EXIT
{
  cat "$trust"
  cat "$stage/deploy-ca.pem"
} >"$replacement"
chmod 0444 "$replacement"
chown root:root "$replacement"
mv -f -- "$replacement" "$trust"
trap - EXIT

systemctl restart portablefs-manager.service
for _ in $(seq 1 30); do
  if systemctl --quiet is-active portablefs-manager.service && \
    "$script_root/manager-api.sh" get "$volume_id" >/dev/null 2>&1 && \
    "$script_root/manager-api.sh" get-operator "$volume_id" >/dev/null 2>&1; then
    echo "OpenSteer deployment identities installed and verified"
    exit 0
  fi
  sleep 1
done
systemctl status portablefs-manager.service --no-pager >&2 || true
echo "Manager did not become API-ready after installing deployment identities" >&2
exit 75
