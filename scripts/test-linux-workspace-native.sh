#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo 'UNAVAILABLE: native-workspace-virtualization (Apple silicon macOS 26+ required)' >&2
  exit 3
fi
if (( $(sw_vers -productVersion | cut -d. -f1) < 26 )); then
  echo 'UNAVAILABLE: native-workspace-macos-26' >&2
  exit 3
fi
[[ $# == 2 || ( $# == 3 && "$3" == --defer-ui ) ]] || { echo "usage: $0 IMAGE_DIRECTORY EVIDENCE_DIRECTORY [--defer-ui]" >&2; exit 2; }
image="$1" evidence="$2"
hold_between_cases() { python3 "$repo/scripts/linux_workspace_native_hold.py"; }
shift 2
mkdir -p "$evidence"
evidence="$(cd "$evidence" && pwd -P)"
hold_between_cases
bash "$repo/scripts/test-linux-workspace-image.sh"
hold_between_cases
bash "$repo/scripts/build-linux-workspace-dev.sh"
bin="$(swift build --package-path "$repo/swift/PortableFSKit" --show-bin-path)/portablefs-workspace-dev"
"$bin" --check-virtualization
hold_between_cases
bash "$repo/scripts/build-linux-workspace-image.sh" "$image" --reuse
comparison="$(mktemp -d "$evidence/repro.XXXXXX")"
trap 'rm -r "$comparison"' EXIT
hold_between_cases
bash "$repo/scripts/build-linux-workspace-image.sh" "$comparison"
cmp "$image/manifest.json" "$comparison/manifest.json"
echo 'PASS: reproducible-image-build-twice'
hold_between_cases
bash "$repo/scripts/test-linux-workspace-rtc.sh" "$image" "$evidence"
hold_between_cases
bash "$repo/scripts/test-linux-workspace-g0.sh" "$image" "$evidence"
hold_between_cases
python3 "$repo/scripts/test-linux-workspace-native.py" "$bin" "$image" "$evidence" "$repo/scripts/linux-workspace-required-native-tests.txt" "$@"
