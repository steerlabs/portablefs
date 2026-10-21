#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
if [[ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
  echo 'refuse to label a dirty workspace executable as HEAD' >&2; exit 1
fi
export PFS_WORKSPACE_BUILD_COMMIT="$(git -C "$repo" rev-parse HEAD)"
swift build --package-path "$repo/swift/PortableFSKit" --product portablefs-workspace-dev
bin="$(swift build --package-path "$repo/swift/PortableFSKit" --show-bin-path)/portablefs-workspace-dev"
codesign --force --sign - --entitlements "$repo/deploy/linux-workspace/dev.entitlements" "$bin"
codesign --verify --strict "$bin"
echo "$bin"
