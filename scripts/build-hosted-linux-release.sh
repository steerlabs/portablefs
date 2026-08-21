#!/usr/bin/env bash
set -euo pipefail

[[ $# == 3 && $1 == /* ]] || {
  echo "usage: $0 /absolute/output-directory RELEASE_ID amd64|arm64" >&2
  exit 64
}

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=$1
release_id=$2
arch=$3
[[ $arch == amd64 || $arch == arm64 ]] || exit 64
[[ $release_id =~ ^pfs-hosted-[0-9]{8}-[0-9a-f]{12}$ ]] || {
  echo "hosted release ID must be pfs-hosted-YYYYMMDD-<12 commit hex>" >&2
  exit 64
}

commit=$(git -C "$root" rev-parse --verify HEAD)
[[ $release_id == *-"${commit:0:12}" ]] || {
  echo "hosted release ID does not name HEAD $commit" >&2
  exit 65
}
[[ -z $(git -C "$root" status --porcelain=v1 --untracked-files=all) ]] || {
  echo "hosted releases require a clean committed tree" >&2
  exit 65
}

mkdir -p -- "$output"
stage=$(mktemp -d "$output/.portablefs-hosted-release.XXXXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT
install -d -m 0755 "$stage/bin" "$stage/libexec" "$stage/systemd"

ldflags="-s -w -X main.version=$release_id"
build() {
  local package=$1 destination=$2
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go -C "$root/vcs" build -trimpath -buildvcs=true -ldflags "$ldflags" -o "$stage/$destination" "$package"
  chmod 0755 "$stage/$destination"
}

build ./cmd/portablefs-manager bin/portablefs-manager
build ./cmd/portablefs-cell-agent bin/portablefs-cell-agent
build ./cmd/portablefs-authority bin/portablefs-authority
build ./cmd/portablefs-archiver bin/portablefs-archiver
build ./cmd/portablefs-hydrator bin/portablefs-hydrator
build ./cmd/portablefs bin/portablefs
build ./cmd/portablefs-cell-helper libexec/portablefs-cell-helper
build ./cmd/portablefs-authority-launcher libexec/portablefs-authority-launcher

for unit in \
  portablefs-manager.service \
  portablefs-cell-agent@.service \
  portablefs-cell-helper@.service \
  portablefs-authority@.socket \
  portablefs-authority@.service \
  portablefs-archiver@.service \
  portablefs-hydrator@.service; do
  install -m 0644 "$root/deploy/systemd/$unit" "$stage/systemd/$unit"
done

printf '%s\n' "$release_id" >"$stage/release-id"
printf '%s\n' "$commit" >"$stage/source-commit"
printf '%s\n' "$arch" >"$stage/architecture"
chmod 0644 "$stage/release-id" "$stage/source-commit" "$stage/architecture"
(
  cd "$stage"
  find architecture bin libexec release-id source-commit systemd -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 shasum -a 256 >SHA256SUMS
)
chmod 0644 "$stage/SHA256SUMS"

destination="$output/portablefs-hosted_${release_id}_linux_${arch}"
[[ ! -e $destination ]] || {
  echo "hosted release already exists: $destination" >&2
  exit 73
}
mv -- "$stage" "$destination"
trap - EXIT
echo "$destination"
