#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 verify-control-release CELL_ID RELEASE_ID | inspect-release VOLUME_ID | current-release VOLUME_ID | wait-absent VOLUME_ID TIMEOUT_SECONDS | wait-release VOLUME_ID RELEASE_ID TIMEOUT_SECONDS" >&2
  exit 64
}

[[ $(id -u) == 0 ]] || {
  echo "cell-authority-state must run as root" >&2
  exit 77
}
[[ $# -ge 2 ]] || usage
command=$1
target_id=$2
[[ $target_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || usage
service=portablefs-authority@$target_id.service
socket=portablefs-authority@$target_id.socket

current_release() {
  local pid executable
  systemctl --quiet is-active "$service" || return 1
  pid=$(systemctl show --property=MainPID --value "$service")
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  executable=$(readlink -f "/proc/$pid/exe")
  [[ $executable == /opt/portablefs/releases/*/bin/portablefs-authority ]] || return 1
  "$executable" -version
}

verify_control_process() {
  local unit=$1 expected=$2 pid executable
  systemctl --quiet is-active "$unit" || {
    echo "$unit is not active" >&2
    return 1
  }
  pid=$(systemctl show --property=MainPID --value "$unit")
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  executable=$(readlink -f "/proc/$pid/exe")
  [[ $executable == "$expected" ]] || {
    echo "$unit runs ${executable:-no executable}, expected $expected" >&2
    return 1
  }
}

case "$command" in
  verify-control-release)
    [[ $# == 3 && $3 =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ ]] || usage
    release_id=$3
    verify_control_process "portablefs-cell-agent@$target_id.service" \
      "/opt/portablefs/releases/$release_id/bin/portablefs-cell-agent"
    verify_control_process "portablefs-cell-helper@$target_id.service" \
      "/opt/portablefs/releases/$release_id/libexec/portablefs-cell-helper"
    printf '{"cell_id":"%s","release_id":"%s"}\n' "$target_id" "$release_id"
    ;;
  inspect-release)
    [[ $# == 2 ]] || usage
    active_state=$(systemctl show --property=ActiveState --value "$service")
    case "$active_state" in
      active)
        release_id=$(current_release) || {
          echo "active authority $target_id has unverifiable release provenance" >&2
          exit 65
        }
        [[ $release_id =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ ]] || {
          echo "active authority $target_id returned invalid release identity: $release_id" >&2
          exit 65
        }
        printf '{"authority_running":true,"release_id":"%s","volume_id":"%s"}\n' "$release_id" "$target_id"
        ;;
      inactive | failed)
        printf '{"authority_running":false,"release_id":null,"volume_id":"%s"}\n' "$target_id"
        ;;
      *)
        echo "authority $target_id is in transitional systemd state $active_state" >&2
        exit 75
        ;;
    esac
    ;;
  current-release)
    [[ $# == 2 ]] || usage
    current_release
    ;;
  wait-absent)
    [[ $# == 3 && $3 =~ ^[1-9][0-9]*$ ]] || usage
    deadline=$((SECONDS + $3))
    while ((SECONDS < deadline)); do
      service_active=0
      socket_active=0
      systemctl --quiet is-active "$service" && service_active=1
      systemctl --quiet is-active "$socket" && socket_active=1
      control_group=$(systemctl show --property=ControlGroup --value "$service")
      populated=0
      if [[ -n $control_group && -f /sys/fs/cgroup$control_group/cgroup.procs && -s /sys/fs/cgroup$control_group/cgroup.procs ]]; then
        populated=1
      fi
      if ((service_active == 0 && socket_active == 0 && populated == 0)); then
        printf '{"authorityAbsent":true,"volumeId":"%s"}\n' "$target_id"
        exit 0
      fi
      sleep 2
    done
    echo "timed out waiting for authority $target_id service, socket, and cgroup to become absent" >&2
    exit 75
    ;;
  wait-release)
    [[ $# == 4 && $3 =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ && $4 =~ ^[1-9][0-9]*$ ]] || usage
    expected=$3
    deadline=$((SECONDS + $4))
    while ((SECONDS < deadline)); do
      actual=$(current_release 2>/dev/null || true)
      if [[ $actual == "$expected" ]]; then
        printf '{"releaseId":"%s","volumeId":"%s"}\n' "$actual" "$target_id"
        exit 0
      fi
      sleep 2
    done
    echo "timed out waiting for authority $target_id to run $expected" >&2
    exit 75
    ;;
  *) usage ;;
esac
