#!/usr/bin/env bash
# Execute the complete PortableFSKit Swift test inventory through Xcode's native
# test runner, then prove the xcresult is an exact all-passing realization of
# the separately enumerated inventory.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
package_path="$repo_root/swift/PortableFSKit"

if [[ "$(uname -s)" != Darwin ]]; then
  echo "test-swift-xcode: Xcode-native Swift verification requires macOS" >&2
  exit 1
fi
for command in xcodebuild xcrun python3 mktemp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "test-swift-xcode: required command is unavailable: $command" >&2
    exit 1
  fi
done

architecture="$(uname -m)"
case "$architecture" in
  arm64|x86_64) ;;
  *)
    echo "test-swift-xcode: unsupported host architecture: $architecture" >&2
    exit 1
    ;;
esac

temp_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if [[ ! -d "$temp_parent" ]]; then
  echo "test-swift-xcode: temporary parent is not a directory: $temp_parent" >&2
  exit 1
fi
temp_parent="$(cd "$temp_parent" && pwd -P)"
work_root="$(mktemp -d "$temp_parent/portablefs-xcode-tests.XXXXXX")"
case "$work_root" in
  "$temp_parent"/portablefs-xcode-tests.*) ;;
  *)
    echo "test-swift-xcode: mktemp returned an unexpected path: $work_root" >&2
    exit 1
    ;;
esac
chmod 700 "$work_root"

cleanup() {
  local status=$?
  if ((status == 0)); then
    rm -rf -- "$work_root"
  else
    echo "test-swift-xcode: retained failure evidence at $work_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

derived_data="$work_root/DerivedData"
enumeration="$work_root/enumerated-tests.json"
result_bundle="$work_root/PortableFSKit.xcresult"
result_json="$work_root/test-results.json"
destination="platform=macOS,arch=$architecture"
common=(
  -quiet
  -scheme PortableFSKit-Package
  -destination "$destination"
  -derivedDataPath "$derived_data"
  -parallel-testing-enabled NO
  -onlyUsePackageVersionsFromResolvedFile
)

PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test_verify_xcode_tests.py"

echo "test-swift-xcode: Xcode-native enumeration ($destination)"
(
  cd "$package_path"
  xcodebuild "${common[@]}" \
    -enumerate-tests \
    -test-enumeration-style flat \
    -test-enumeration-format json \
    -test-enumeration-output-path "$enumeration" \
    test
)
python3 "$repo_root/scripts/verify_xcode_tests.py" --enumeration "$enumeration"

echo "test-swift-xcode: Xcode-native single-process execution"
set +e
(
  cd "$package_path"
  xcodebuild "${common[@]}" -resultBundlePath "$result_bundle" test-without-building
)
xcode_status=$?
set -e

if [[ ! -d "$result_bundle" ]]; then
  echo "test-swift-xcode: Xcode produced no result bundle" >&2
  exit 1
fi
xcrun xcresulttool get test-results tests --path "$result_bundle" --compact >"$result_json"

set +e
python3 "$repo_root/scripts/verify_xcode_tests.py" \
  --enumeration "$enumeration" \
  --results "$result_json" \
  --architecture "$architecture"
evidence_status=$?
set -e
if ((xcode_status != 0 || evidence_status != 0)); then
  echo "test-swift-xcode: rejected Xcode execution (xcode=$xcode_status evidence=$evidence_status)" >&2
  exit 1
fi

echo "test-swift-xcode: ok"
