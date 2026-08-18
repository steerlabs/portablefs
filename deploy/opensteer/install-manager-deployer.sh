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
for file in client-ca.pem manager-ca.pem manager.env operator.cert operator.key product.cert product.key; do
  [[ -f $stage/$file && ! -L $stage/$file ]] || {
    echo "missing or unsafe deployment credential member: $file" >&2
    exit 66
  }
done

# shellcheck source=/dev/null
source "$stage/manager.env"
: "${PORTABLEFS_MANAGER_SERVER_NAME:?missing manager server name}"
: "${PORTABLEFS_PRODUCT_ISSUER:?missing product issuer}"
: "${PORTABLEFS_OPERATOR_IDENTITY:?missing operator identity}"
[[ $PORTABLEFS_MANAGER_SERVER_NAME =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || exit 65
[[ $PORTABLEFS_PRODUCT_ISSUER =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || exit 65
[[ $PORTABLEFS_OPERATOR_IDENTITY =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || exit 65

verify_identity() {
  local role=$1 identity=$2
  local cert=$stage/$role.cert key=$stage/$role.key expected actual san
  openssl verify -CAfile "$stage/client-ca.pem" -purpose sslclient "$cert" >/dev/null
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
  openssl x509 -in "$cert" -checkend 86400 -noout >/dev/null || {
    echo "$role certificate expires within 24 hours" >&2
    exit 65
  }
}
verify_identity product "product/$PORTABLEFS_PRODUCT_ISSUER"
verify_identity operator "operator/$PORTABLEFS_OPERATOR_IDENTITY"
openssl x509 -in "$stage/manager-ca.pem" -noout >/dev/null

trust=/etc/portablefs/manager/trust/control-client-ca.pem
[[ -f $trust && ! -L $trust ]] || exit 66
openssl verify -CAfile "$trust" -purpose sslclient "$stage/product.cert" >/dev/null
openssl verify -CAfile "$trust" -purpose sslclient "$stage/operator.cert" >/dev/null

destination=/etc/portablefs/opensteer-deployer
credentials=$destination/credentials
install -d -o root -g root -m 0700 "$destination" "$credentials"
bundle_id=$(
  {
    openssl x509 -in "$stage/product.cert" -outform DER
    openssl x509 -in "$stage/operator.cert" -outform DER
    openssl x509 -in "$stage/manager-ca.pem" -outform DER
    printf '%s' "$PORTABLEFS_MANAGER_SERVER_NAME"
    printf '%s' "$PORTABLEFS_PRODUCT_ISSUER"
    printf '%s' "$PORTABLEFS_OPERATOR_IDENTITY"
  } | sha256sum | awk '{print $1}'
)
bundle=$credentials/$bundle_id
if [[ ! -e $bundle ]]; then
  incoming=$(mktemp -d "$credentials/.incoming.XXXXXXXX")
  cleanup() { rm -rf -- "$incoming"; }
  trap cleanup EXIT
  install -o root -g root -m 0444 "$stage/client-ca.pem" "$incoming/client-ca.pem"
  install -o root -g root -m 0444 "$stage/manager-ca.pem" "$incoming/manager-ca.pem"
  install -o root -g root -m 0400 "$stage/manager.env" "$incoming/manager.env"
  install -o root -g root -m 0444 "$stage/product.cert" "$incoming/product.cert"
  install -o root -g root -m 0400 "$stage/product.key" "$incoming/product.key"
  install -o root -g root -m 0444 "$stage/operator.cert" "$incoming/operator.cert"
  install -o root -g root -m 0400 "$stage/operator.key" "$incoming/operator.key"
  mv -T -- "$incoming" "$bundle"
  trap - EXIT
else
  [[ -d $bundle && ! -L $bundle ]] || exit 65
fi

previous=
if [[ -L $destination/current ]]; then
  previous=$(readlink "$destination/current")
elif [[ -e $destination/current ]]; then
  echo "deployment credential pointer is not a symlink" >&2
  exit 65
fi
temporary=$destination/.current.$$
ln -s -- "credentials/$bundle_id" "$temporary"
mv -Tf -- "$temporary" "$destination/current"

rollback() {
  if [[ -n $previous ]]; then
    temporary=$destination/.current.rollback.$$
    ln -s -- "$previous" "$temporary"
    mv -Tf -- "$temporary" "$destination/current"
  else
    rm -f -- "$destination/current"
  fi
}
trap rollback ERR
"$script_root/manager-api.sh" get "$volume_id" >/dev/null
"$script_root/manager-api.sh" get-operator "$volume_id" >/dev/null
trap - ERR

echo "OpenSteer deployment identities installed and verified"
