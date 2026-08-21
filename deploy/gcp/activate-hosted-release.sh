#!/usr/bin/env bash
set -euo pipefail

[[ $# == 2 && $1 == /* && -d $1 && ( $2 == manager || $2 == cell ) ]] || {
  echo "usage: $0 /absolute/hosted-release-directory manager|cell" >&2
  exit 64
}
[[ $(id -u) == 0 ]] || {
  echo "activate-hosted-release must run as root" >&2
  exit 77
}

stage=$1
role=$2
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
release_id=$($script_root/verify-hosted-release.sh "$stage")
release_root=/opt/portablefs/releases
release_path=$release_root/$release_id
current=/opt/portablefs/current

install -d -o root -g root -m 0755 /opt/portablefs "$release_root"
if [[ -e $release_path ]]; then
  [[ -d $release_path && ! -L $release_path ]] || exit 65
  "$script_root/verify-hosted-release.sh" "$release_path" >/dev/null
else
  incoming=$(mktemp -d "$release_root/.incoming-$release_id.XXXXXXXX")
  cleanup() { rm -rf -- "$incoming"; }
  trap cleanup EXIT
  cp -a --no-preserve=ownership "$stage"/. "$incoming"/
  chown -R root:root "$incoming"
  find "$incoming" -type d -exec chmod 0755 {} +
  find "$incoming/bin" "$incoming/libexec" -type f -exec chmod 0755 {} +
  find "$incoming/systemd" -type f -exec chmod 0644 {} +
  chmod 0644 "$incoming/release-id" "$incoming/source-commit" "$incoming/architecture" "$incoming/SHA256SUMS"
  "$script_root/verify-hosted-release.sh" "$incoming" >/dev/null
  sync -f "$incoming"
  mv -T -- "$incoming" "$release_path"
	sync -f "$release_root"
  trap - EXIT
fi

previous=
if [[ -L $current ]]; then
  previous=$(readlink -f "$current")
  [[ $previous == "$release_root"/* && -d $previous ]] || {
    echo "current hosted release link is outside the release root" >&2
    exit 65
  }
elif [[ -e $current ]]; then
  echo "current hosted release is not a symlink" >&2
  exit 65
fi

rollback_dir=$(mktemp -d /run/portablefs-release-rollback.XXXXXXXX)
cleanup_rollback() { rm -rf -- "$rollback_dir"; }
trap cleanup_rollback EXIT
manager_state=/var/lib/portablefs-manager/manager.state
migration_backup=
migration_candidate=
migration_swapped=0

case "$role" in
  manager)
    units=(portablefs-manager.service)
    ;;
  cell)
    mapfile -t helper_units < <(systemctl list-units --all --plain --no-legend 'portablefs-cell-helper@*.service' | awk '{print $1}')
    mapfile -t agent_units < <(systemctl list-units --all --plain --no-legend 'portablefs-cell-agent@*.service' | awk '{print $1}')
    units=(portablefs-cell-agent@.service portablefs-cell-helper@.service portablefs-authority@.socket portablefs-authority@.service portablefs-archiver@.service portablefs-hydrator@.service)
    ;;
esac

for unit in "${units[@]}"; do
  if [[ -e /etc/systemd/system/$unit || -L /etc/systemd/system/$unit ]]; then
    cp -a --dereference "/etc/systemd/system/$unit" "$rollback_dir/$unit"
  else
    : >"$rollback_dir/$unit.absent"
  fi
done

activate_link() {
  local target=$1 temporary
  temporary=/opt/portablefs/.current.$$
  ln -s -- "$target" "$temporary"
  mv -Tf -- "$temporary" "$current"
  sync -f /opt/portablefs
}
activation_swapped=0
restore_previous() {
  trap - ERR
  if ((migration_swapped)); then
    systemctl stop portablefs-manager.service || true
    mv -- "$manager_state" "$migration_candidate"
    mv -- "$migration_backup" "$manager_state"
    sync -f "$manager_state"
    sync -f "${manager_state%/*}"
  elif [[ -n $migration_candidate ]]; then
    rm -f -- "$migration_candidate"
  fi
  if ((activation_swapped)); then
    if [[ -n $previous ]]; then
      activate_link "$previous"
    else
      rm -f -- "$current"
      sync -f /opt/portablefs
    fi
  fi
  for unit in "${units[@]}"; do
    if [[ -f $rollback_dir/$unit ]]; then
      install -o root -g root -m 0644 "$rollback_dir/$unit" "/etc/systemd/system/$unit"
    else
      rm -f -- "/etc/systemd/system/$unit"
    fi
  done
  sync -f /etc/systemd/system
  systemctl daemon-reload || true
  case "$role" in
    manager) systemctl restart portablefs-manager.service || true ;;
    cell)
      ((${#helper_units[@]} == 0)) || systemctl restart "${helper_units[@]}" || true
      ((${#agent_units[@]} == 0)) || systemctl restart "${agent_units[@]}" || true
      ;;
  esac
}
on_activation_error() {
  status=$?
  restore_previous
  echo "hosted release activation failed; prior release and units restored" >&2
  exit "$status"
}
trap on_activation_error ERR

case "$role" in
  manager)
    if systemctl --quiet is-active portablefs-manager.service; then
      systemctl stop portablefs-manager.service
      ! systemctl --quiet is-active portablefs-manager.service
    fi
    ;;
  cell)
    ((${#agent_units[@]} == 0)) || systemctl stop "${agent_units[@]}"
    ((${#helper_units[@]} == 0)) || systemctl stop "${helper_units[@]}"
	for unit in "${agent_units[@]}" "${helper_units[@]}"; do
	  [[ -z $unit ]] || ! systemctl --quiet is-active "$unit"
	done
    ;;
esac

if [[ $role == manager && -f $manager_state ]]; then
  state_schema=$(runuser --user portablefs-manager -- "$release_path/bin/portablefs-manager" state-version -state "$manager_state")
  case "$state_schema" in
    1)
      migration_backup=$manager_state.v1-$release_id
      migration_candidate=$manager_state.v2-$release_id
      [[ ! -e $migration_backup && ! -e $migration_candidate ]] || {
        echo "manager state migration artifact already exists for $release_id" >&2
        false
      }
      runuser --user portablefs-manager -- "$release_path/bin/portablefs-manager" migrate-state \
        -from "$manager_state" -to "$migration_candidate"
      mv -- "$manager_state" "$migration_backup"
      mv -- "$migration_candidate" "$manager_state"
      sync -f "$manager_state"
      sync -f "${manager_state%/*}"
      migration_swapped=1
      ;;
    2) ;;
    *)
      echo "unsupported manager state schema: $state_schema" >&2
      false
      ;;
  esac
fi

activate_link "$release_path"
activation_swapped=1
for unit in "${units[@]}"; do
  link=/etc/systemd/system/$unit
  temporary=/etc/systemd/system/.$unit.$$
  ln -s -- "/opt/portablefs/current/systemd/$unit" "$temporary"
  mv -Tf -- "$temporary" "$link"
done
sync -f /etc/systemd/system
systemctl daemon-reload

failed=0
verify_unit_release() {
  local unit=$1 pid executable
  pid=$(systemctl show --property=MainPID --value "$unit")
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  executable=$(readlink -f "/proc/$pid/exe")
  [[ $executable == "$release_path"/* ]]
}
case "$role" in
  manager)
    systemctl start portablefs-manager.service || failed=1
    systemctl --quiet is-active portablefs-manager.service || failed=1
    verify_unit_release portablefs-manager.service || failed=1
    ;;
  cell)
    ((${#helper_units[@]} == 0)) || systemctl start "${helper_units[@]}" || failed=1
    ((${#agent_units[@]} == 0)) || systemctl start "${agent_units[@]}" || failed=1
    for unit in "${helper_units[@]}" "${agent_units[@]}"; do
      [[ -z $unit ]] || systemctl --quiet is-active "$unit" || failed=1
      [[ -z $unit ]] || verify_unit_release "$unit" || failed=1
    done
    ;;
esac

((failed == 0))

trap - ERR
trap - EXIT
cleanup_rollback
echo "$release_id"
