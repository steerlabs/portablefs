#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 && $1 == /* && -d $1 ]] || {
  echo "usage: $0 /absolute/manager-stage" >&2
  exit 64
}
[[ $(id -u) == 0 ]] || {
  echo "install-manager must run as root" >&2
  exit 77
}

stage=$1
for relative in \
  portablefs-manager portablefs-manager.service manager.env \
  pki/tls/manager.cert pki/tls/manager.key \
  pki/trust/control-client-ca.pem pki/trust/authority-ca.pem \
  pki/trust/mount-client-ca.pem pki/trust/mount-enrollment-ca.pem pki/trust/product-public.pem \
  pki/keys/plan-signing.key pki/keys/capability-signing.key \
  pki/keys/authority-ca.key pki/keys/mount-client-ca.key pki/keys/mount-enrollment-ca.key; do
  [[ -f $stage/$relative && ! -L $stage/$relative ]] || {
    echo "missing or unsafe staged file: $relative" >&2
    exit 66
  }
done

if ! getent group portablefs-manager >/dev/null; then
  groupadd --system portablefs-manager
fi
if ! getent passwd portablefs-manager >/dev/null; then
  useradd --system --gid portablefs-manager --home-dir /var/lib/portablefs-manager \
    --shell /usr/sbin/nologin portablefs-manager
fi
[[ $(id -u portablefs-manager) != 0 && $(id -gn portablefs-manager) == portablefs-manager ]] || {
  echo "portablefs-manager account is unsafe" >&2
  exit 65
}

install -o root -g root -m 0755 "$stage/portablefs-manager" /usr/local/bin/portablefs-manager
install -o root -g root -m 0644 "$stage/portablefs-manager.service" /etc/systemd/system/portablefs-manager.service
install -d -o root -g root -m 0755 /etc/portablefs/manager/{tls,trust,keys}
install -o root -g root -m 0600 "$stage/manager.env" /etc/portablefs/manager/manager.env

install -o portablefs-manager -g portablefs-manager -m 0400 \
  "$stage/pki/tls/manager.key" /etc/portablefs/manager/tls/manager.key
install -o root -g root -m 0444 "$stage/pki/tls/manager.cert" /etc/portablefs/manager/tls/manager.cert
for name in control-client-ca.pem authority-ca.pem mount-client-ca.pem mount-enrollment-ca.pem product-public.pem; do
  install -o root -g root -m 0444 "$stage/pki/trust/$name" "/etc/portablefs/manager/trust/$name"
done
for name in plan-signing.key capability-signing.key authority-ca.key mount-client-ca.key mount-enrollment-ca.key; do
  install -o portablefs-manager -g portablefs-manager -m 0400 "$stage/pki/keys/$name" "/etc/portablefs/manager/keys/$name"
done

systemd-analyze verify /etc/systemd/system/portablefs-manager.service
systemctl daemon-reload
systemctl enable --now portablefs-manager.service
systemctl --quiet is-active portablefs-manager.service
