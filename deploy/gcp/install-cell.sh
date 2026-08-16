#!/usr/bin/env bash
set -euo pipefail

[[ $# == 5 && $1 == /* && -d $1 && $2 == /* && -d $2 ]] || {
  echo "usage: $0 /absolute/hosted-release /absolute/cell-config-stage CELL_UUID AGENT_UID AGENT_GID" >&2
  exit 64
}
[[ $(id -u) == 0 ]] || {
  echo "install-cell must run as root" >&2
  exit 77
}

release=$1
stage=$2
cell_id=$3
agent_uid=$4
agent_gid=$5
[[ $cell_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || exit 64
[[ $agent_uid =~ ^[1-9][0-9]{3,8}$ && $agent_gid =~ ^[1-9][0-9]{3,8}$ ]] || exit 64

for relative in cell.cert cell.key manager-ca.pem plan-public.pem cell.env; do
  [[ -f $stage/$relative && ! -L $stage/$relative ]] || {
    echo "missing or unsafe staged file: $relative" >&2
    exit 66
  }
done

[[ $(findmnt -n -o TARGET --target /srv/portablefs) == /srv/portablefs ]] || {
  echo "/srv/portablefs is not a dedicated mountpoint" >&2
  exit 65
}
findmnt -n -o FSTYPE --target /srv/portablefs | grep -Fx xfs >/dev/null
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

install -d -o root -g root -m 0755 /etc/portablefs/{trust,cells,volumes}
install -d -o root -g root -m 0711 /var/lib/portablefs/volumes
install -d -o root -g root -m 0700 /var/lib/portablefs-cell-helper/sysusers.d
install -o root -g root -m 0444 "$stage/manager-ca.pem" /etc/portablefs/trust/manager-ca.pem
install -o root -g root -m 0444 "$stage/plan-public.pem" /etc/portablefs/trust/plan-public.pem
install -o root -g root -m 0444 "$stage/cell.cert" "/etc/portablefs/cells/$cell_id.cert"
install -o portablefs-agent -g portablefs-agent -m 0400 "$stage/cell.key" "/etc/portablefs/cells/$cell_id.key"
install -o root -g root -m 0600 "$stage/cell.env" "/etc/portablefs/cells/$cell_id.env"

"$(dirname -- "$0")/activate-hosted-release.sh" "$release" cell >/dev/null

# The authority socket deliberately has no template-level ListenStream. The
# helper supplies its signed, per-volume listener in a drop-in, so verifying an
# uninstantiated socket would correctly reject it as incomplete. Verify that
# concrete unit only after the first signed assignment has been reconciled.
systemd-analyze verify \
  /etc/systemd/system/portablefs-cell-agent@.service \
  /etc/systemd/system/portablefs-cell-helper@.service
systemctl enable --now "portablefs-cell-helper@$cell_id.service" "portablefs-cell-agent@$cell_id.service"
systemctl --quiet is-active "portablefs-cell-helper@$cell_id.service"
systemctl --quiet is-active "portablefs-cell-agent@$cell_id.service"
