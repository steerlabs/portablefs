#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 && $1 == /* && -d $1 ]] || {
  echo "usage: $0 /absolute/hosted-release-directory" >&2
  exit 64
}
stage=$1

expected=(
  architecture
  bin/portablefs
  bin/portablefs-authority
  bin/portablefs-cell-agent
  bin/portablefs-manager
  libexec/portablefs-authority-launcher
  libexec/portablefs-cell-helper
  release-id
  source-commit
  systemd/portablefs-authority@.service
  systemd/portablefs-authority@.socket
  systemd/portablefs-cell-agent@.service
  systemd/portablefs-cell-helper@.service
  systemd/portablefs-manager.service
)

for relative in "${expected[@]}" SHA256SUMS; do
  [[ -f $stage/$relative && ! -L $stage/$relative ]] || {
    echo "missing or unsafe hosted release member: $relative" >&2
    exit 66
  }
  mode=$(stat -c %a "$stage/$relative")
  permissions=$((8#$mode))
  (( (permissions & 18) == 0 )) || {
    echo "hosted release member is writable by group/other: $relative" >&2
    exit 65
  }
done

mapfile -t actual < <(cd "$stage" && find architecture bin libexec release-id source-commit systemd -type f -print | LC_ALL=C sort)
[[ ${#actual[@]} == ${#expected[@]} ]] || {
  echo "hosted release membership count is not exact" >&2
  exit 65
}
for index in "${!expected[@]}"; do
  [[ ${actual[$index]} == "${expected[$index]}" ]] || {
    echo "hosted release membership differs at ${actual[$index]}" >&2
    exit 65
  }
done

release_id=$(<"$stage/release-id")
source_commit=$(<"$stage/source-commit")
architecture=$(<"$stage/architecture")
[[ $release_id =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ && $source_commit =~ ^[0-9a-f]{40}$ && $release_id == *-"${source_commit:0:12}" ]] || {
  echo "hosted release identity is invalid" >&2
  exit 65
}
case "$(uname -m):$architecture" in
  x86_64:amd64|aarch64:arm64) ;;
  *) echo "hosted release architecture $architecture does not match $(uname -m)" >&2; exit 65 ;;
esac

manifest_members=$(awk '{print $2}' "$stage/SHA256SUMS")
[[ $manifest_members == "$(printf '%s\n' "${expected[@]}")" ]] || {
  echo "hosted release checksum membership is not exact" >&2
  exit 65
}
(cd "$stage" && sha256sum --check --strict SHA256SUMS >/dev/null)

for relative in \
  bin/portablefs-manager \
  bin/portablefs-cell-agent \
  bin/portablefs-authority \
  libexec/portablefs-cell-helper \
  libexec/portablefs-authority-launcher; do
  [[ $("$stage/$relative" -version) == "$release_id" ]] || {
    echo "hosted binary release identity mismatch: $relative" >&2
    exit 65
  }
done

[[ $("$stage/bin/portablefs" version) == "portablefs $release_id" ]] || {
  echo "hosted binary release identity mismatch: bin/portablefs" >&2
  exit 65
}

for unit in "$stage"/systemd/*.service; do
  grep -Fq '/opt/portablefs/current/' "$unit" || {
    echo "hosted unit does not execute through the atomic release root: ${unit##*/}" >&2
    exit 65
  }
done

echo "$release_id"
