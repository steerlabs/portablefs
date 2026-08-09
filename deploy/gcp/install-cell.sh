#!/usr/bin/env bash
set -euo pipefail

[[ $# == 4 && $1 == /* && -d $1 ]] || {
  echo "usage: $0 /absolute/cell-stage CELL_UUID AGENT_UID AGENT_GID" >&2
  exit 64
}
[[ $(id -u) == 0 ]] || {
  echo "install-cell must run as root" >&2
  exit 77
}

stage=$1
cell_id=$2
agent_uid=$3
agent_gid=$4
[[ $cell_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || exit 64
[[ $agent_uid =~ ^[1-9][0-9]{3,8}$ && $agent_gid =~ ^[1-9][0-9]{3,8}$ ]] || exit 64

for relative in \
  portablefs-cell-agent portablefs-cell-helper portablefs-authority portablefs-authority-launcher \
  portablefs-cell-agent@.service portablefs-cell-helper@.service \
  portablefs-authority@.socket portablefs-authority@.service \
  cell.cert cell.key manager-ca.pem plan-public.pem cell.env; do
  [[ -f $stage/$relative && ! -L $stage/$relative ]] || {
    echo "missing or unsafe staged file: $relative" >&2
    exit 66
  }
done

findmnt -n -o FSTYPE /srv/portablefs | grep -Fx xfs >/dev/null
for option in prjquota nodev nosuid noexec noatime; do
  findmnt -n -o OPTIONS /srv/portablefs | tr ',' '\n' | grep -Fx "$option" >/dev/null || {
    echo "/srv/portablefs is missing $option" >&2
    exit 65
  }
done

if ! getent group portablefs-agent >/dev/null; then
  groupadd --system --gid "$agent_gid" portablefs-agent
fi
if ! getent passwd portablefs-agent >/dev/null; then
  useradd --system --uid "$agent_uid" --gid "$agent_gid" --home-dir /var/lib/portablefs-agent \
    --shell /usr/sbin/nologin portablefs-agent
fi
[[ $(id -u portablefs-agent) == "$agent_uid" && $(id -g portablefs-agent) == "$agent_gid" ]] || {
  echo "portablefs-agent account identity does not match the deployment" >&2
  exit 65
}

install -o root -g root -m 0755 "$stage/portablefs-cell-agent" /usr/local/bin/portablefs-cell-agent
install -o root -g root -m 0755 "$stage/portablefs-authority" /usr/local/bin/portablefs-authority
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$stage/portablefs-cell-helper" /usr/local/libexec/portablefs-cell-helper
install -o root -g root -m 0755 "$stage/portablefs-authority-launcher" /usr/local/libexec/portablefs-authority-launcher

for unit in portablefs-cell-agent@.service portablefs-cell-helper@.service portablefs-authority@.socket portablefs-authority@.service; do
  install -o root -g root -m 0644 "$stage/$unit" "/etc/systemd/system/$unit"
done

install -d -o root -g root -m 0755 /etc/portablefs/{trust,cells,volumes}
install -d -o root -g root -m 0711 /var/lib/portablefs/volumes
install -d -o root -g root -m 0700 /var/lib/portablefs-cell-helper/sysusers.d
install -o root -g root -m 0444 "$stage/manager-ca.pem" /etc/portablefs/trust/manager-ca.pem
install -o root -g root -m 0444 "$stage/plan-public.pem" /etc/portablefs/trust/plan-public.pem
install -o root -g root -m 0444 "$stage/cell.cert" "/etc/portablefs/cells/$cell_id.cert"
install -o portablefs-agent -g portablefs-agent -m 0400 "$stage/cell.key" "/etc/portablefs/cells/$cell_id.key"
install -o root -g root -m 0600 "$stage/cell.env" "/etc/portablefs/cells/$cell_id.env"

# The authority socket deliberately has no template-level ListenStream. The
# helper supplies its signed, per-volume listener in a drop-in, so verifying an
# uninstantiated socket would correctly reject it as incomplete. Verify that
# concrete unit only after the first signed assignment has been reconciled.
systemd-analyze verify \
  /etc/systemd/system/portablefs-cell-agent@.service \
  /etc/systemd/system/portablefs-cell-helper@.service
systemctl daemon-reload
