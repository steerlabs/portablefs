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
shift 2
mkdir -p "$evidence"
evidence="$(cd "$evidence" && pwd -P)"
run_phase() {
  while [[ -n "${PFS_TEST_HOLD_FILE:-}" && -e "$PFS_TEST_HOLD_FILE" ]]; do
    echo 'HOLD: waiting between native verification phases'
    sleep 30
  done
  "$@"
}
run_phase bash "$repo/scripts/test-linux-workspace-image.sh"
run_phase bash "$repo/scripts/build-linux-workspace-dev.sh"
bin="$(swift build --package-path "$repo/swift/PortableFSKit" --show-bin-path)/portablefs-workspace-dev"
run_phase "$bin" --check-virtualization
run_phase bash "$repo/scripts/build-linux-workspace-image.sh" "$image" --reuse
comparison="$(mktemp -d "$evidence/repro.XXXXXX")"
trap 'rm -r "$comparison"' EXIT
run_phase bash "$repo/scripts/build-linux-workspace-image.sh" "$comparison"
cmp "$image/manifest.json" "$comparison/manifest.json"
echo 'PASS: reproducible-image-build-twice'
run_phase bash "$repo/scripts/test-linux-workspace-rtc.sh" "$image" "$evidence"
run_phase bash "$repo/scripts/test-linux-workspace-g0.sh" "$image" "$evidence"
run_phase python3 "$repo/scripts/test-linux-workspace-native.py" "$bin" "$image" "$evidence" "$repo/scripts/linux-workspace-required-native-tests.txt" "$@"
