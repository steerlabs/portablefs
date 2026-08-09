#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIR MANAGER_DNS_NAME CELL_UUID PRODUCT_ISSUER OPERATOR_ID" >&2
  exit 64
}

[[ $# == 5 ]] || usage
output=$1
manager_dns=$2
cell_id=$3
product_issuer=$4
operator_id=$5

[[ $output == /* && $output != / && ! -e $output ]] || {
  echo "output must be a new absolute directory" >&2
  exit 64
}
[[ $manager_dns =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && $manager_dns == *.* ]] || usage
[[ $cell_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || usage
[[ $product_issuer =~ ^[A-Za-z0-9._-]{1,128}$ ]] || usage
[[ $operator_id =~ ^[A-Za-z0-9._-]{1,128}$ ]] || usage
command -v openssl >/dev/null
command -v shasum >/dev/null

umask 077
mkdir -p "$output"/{manager/{tls,trust,keys},cell,operator,product,offline,work}

new_ca() {
  local name=$1 subject=$2
  openssl genpkey -algorithm ED25519 -out "$output/offline/$name.key"
  openssl req -x509 -new -key "$output/offline/$name.key" \
    -out "$output/offline/$name.pem" -days 3650 -sha256 -subj "/CN=$subject" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash'
}

new_leaf() {
  local name=$1 subject=$2 extension=$3 destination=$4
  openssl genpkey -algorithm ED25519 -out "$destination/$name.key"
  openssl req -new -key "$destination/$name.key" -out "$output/work/$name.csr" -subj "/CN=$subject"
  openssl x509 -req -in "$output/work/$name.csr" \
    -CA "$output/offline/control-ca.pem" -CAkey "$output/offline/control-ca.key" \
    -CAserial "$output/work/control-ca.srl" -CAcreateserial \
    -out "$destination/$name.cert" -days 365 -sha256 -extfile "$extension"
}

new_signer() {
  local name=$1 destination=$2
  openssl genpkey -algorithm ED25519 -out "$destination/$name.key"
  openssl pkey -in "$destination/$name.key" -pubout -out "$destination/$name.pem"
}

new_ca control-ca "PortableFS hosted control CA"
new_ca authority-ca "PortableFS hosted authority CA"
new_ca mount-client-ca "PortableFS hosted mount client CA"

manager_ext="$output/work/manager.ext"
cat >"$manager_ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:${manager_dns}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
new_leaf manager "$manager_dns" "$manager_ext" "$output/manager/tls"

cell_ext="$output/work/cell.ext"
cat >"$cell_ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://portablefs/control/cell/${cell_id}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
new_leaf cell "$cell_id" "$cell_ext" "$output/cell"

operator_ext="$output/work/operator.ext"
cat >"$operator_ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://portablefs/control/operator/${operator_id}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
new_leaf operator "$operator_id" "$operator_ext" "$output/operator"

product_ext="$output/work/product.ext"
cat >"$product_ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://portablefs/control/product/${product_issuer}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
new_leaf product-client "$product_issuer" "$product_ext" "$output/product"

new_signer plan-signing "$output/manager/keys"
new_signer capability-signing "$output/manager/keys"
new_signer product-signing "$output/product"

cp "$output/offline/control-ca.pem" "$output/manager/trust/control-client-ca.pem"
cp "$output/offline/control-ca.pem" "$output/cell/manager-ca.pem"
cp "$output/offline/control-ca.pem" "$output/operator/manager-ca.pem"
cp "$output/offline/control-ca.pem" "$output/product/manager-ca.pem"
cp "$output/offline/authority-ca.pem" "$output/manager/trust/authority-ca.pem"
cp "$output/offline/authority-ca.key" "$output/manager/keys/authority-ca.key"
cp "$output/offline/mount-client-ca.pem" "$output/manager/trust/mount-client-ca.pem"
cp "$output/offline/mount-client-ca.key" "$output/manager/keys/mount-client-ca.key"
cp "$output/product/product-signing.pem" "$output/manager/trust/product-public.pem"
cp "$output/manager/keys/plan-signing.pem" "$output/cell/plan-public.pem"

openssl verify -purpose sslserver -CAfile "$output/offline/control-ca.pem" "$output/manager/tls/manager.cert" >/dev/null
openssl x509 -in "$output/manager/tls/manager.cert" -noout -checkhost "$manager_dns" >/dev/null
for certificate in "$output/cell/cell.cert" "$output/operator/operator.cert" "$output/product/product-client.cert"; do
  openssl verify -purpose sslclient -CAfile "$output/offline/control-ca.pem" "$certificate" >/dev/null
done
openssl x509 -in "$output/cell/cell.cert" -noout -ext subjectAltName | grep -Fq "URI:spiffe://portablefs/control/cell/$cell_id"
openssl x509 -in "$output/operator/operator.cert" -noout -ext subjectAltName | grep -Fq "URI:spiffe://portablefs/control/operator/$operator_id"
openssl x509 -in "$output/product/product-client.cert" -noout -ext subjectAltName | grep -Fq "URI:spiffe://portablefs/control/product/$product_issuer"
openssl verify -CAfile "$output/offline/authority-ca.pem" "$output/offline/authority-ca.pem" >/dev/null
openssl verify -CAfile "$output/offline/mount-client-ca.pem" "$output/offline/mount-client-ca.pem" >/dev/null

find "$output" -type d -exec chmod 0700 {} +
find "$output" -type f -name '*.key' -exec chmod 0600 {} +
find "$output" -type f ! -name '*.key' -exec chmod 0644 {} +

{
  printf 'manager_dns=%s\ncell_id=%s\nproduct_issuer=%s\noperator_id=%s\n' \
    "$manager_dns" "$cell_id" "$product_issuer" "$operator_id"
  find "$output" -type f ! -name '*.key' ! -path "$output/work/*" -print0 \
    | LC_ALL=C sort -z \
    | while IFS= read -r -d '' path; do
        printf '%s  %s\n' "$(shasum -a 256 "$path" | awk '{print $1}')" "${path#"$output/"}"
      done
} >"$output/PUBLIC-MANIFEST.txt"
chmod 0600 "$output/PUBLIC-MANIFEST.txt"

echo "generated and verified hosted PKI at $output"
