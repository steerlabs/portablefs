#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 current-release VOLUME_ID | wait-absent VOLUME_ID TIMEOUT_SECONDS | wait-release VOLUME_ID RELEASE_ID TIMEOUT_SECONDS" >&2
  exit 64
}

[[ $(id -u) == 0 ]] || {
  echo "cell-authority-state must run as root" >&2
  exit 77
}
[[ $# -ge 2 ]] || usage
command=$1
volume_id=$2
[[ $volume_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || usage
service=portablefs-authority@$volume_id.service
socket=portablefs-authority@$volume_id.socket

current_release() {
  local pid executable
  systemctl --quiet is-active "$service" || return 1
  pid=$(systemctl show --property=MainPID --value "$service")
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  executable=$(readlink -f "/proc/$pid/exe")
  [[ $executable == /opt/portablefs/releases/*/bin/portablefs-authority ]] || return 1
  "$executable" -version
}

case "$command" in
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
        printf '{"authorityAbsent":true,"volumeId":"%s"}\n' "$volume_id"
        exit 0
      fi
      sleep 2
    done
    echo "timed out waiting for authority $volume_id service, socket, and cgroup to become absent" >&2
    exit 75
    ;;
  wait-release)
    [[ $# == 4 && $3 =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ && $4 =~ ^[1-9][0-9]*$ ]] || usage
    expected=$3
    deadline=$((SECONDS + $4))
    while ((SECONDS < deadline)); do
      actual=$(current_release 2>/dev/null || true)
      if [[ $actual == "$expected" ]]; then
        printf '{"releaseId":"%s","volumeId":"%s"}\n' "$actual" "$volume_id"
        exit 0
      fi
      sleep 2
    done
    echo "timed out waiting for authority $volume_id to run $expected" >&2
    exit 75
    ;;
  *) usage ;;
esac
