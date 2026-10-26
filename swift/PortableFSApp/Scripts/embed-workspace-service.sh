#!/bin/sh
# The VM executable is nested code with its own entitlement. Guest images and
# installer/update integration are owned by the subsequent packaging change.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
contents_dir="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH"
service_app="$contents_dir/Library/LaunchAgents/PortableFSWorkspaceService.app"
service_contents="$service_app/Contents"
service_macos="$service_contents/MacOS"
work="$TARGET_TEMP_DIR/portablefs-workspace-service"
mkdir -p "$service_macos" "$work"
export PFS_WORKSPACE_BUILD_COMMIT=$(git -C "$repo_root" rev-parse HEAD)
configuration=release
[ "${CONFIGURATION:-Release}" != Debug ] || configuration=debug
set --
for arch in ${ARCHS:-$(uname -m)}; do
  case "$arch" in arm64|x86_64) ;; *) echo "unsupported workspace architecture: $arch" >&2; exit 1 ;; esac
  scratch="$work/$arch"
  swift build --package-path "$repo_root/swift/PortableFSKit" --scratch-path "$scratch" \
    --configuration "$configuration" --triple "$arch-apple-macos26.0" --product portablefs-workspace-service
  bin=$(swift build --package-path "$repo_root/swift/PortableFSKit" --scratch-path "$scratch" \
    --configuration "$configuration" --triple "$arch-apple-macos26.0" --show-bin-path)
  set -- "$@" "$bin/portablefs-workspace-service"
done
if [ "$#" -gt 1 ]; then /usr/bin/lipo -create "$@" -output "$service_macos/portablefs-workspace-service"
else /bin/cp "$1" "$service_macos/portablefs-workspace-service"; fi
info="$service_contents/Info.plist"
/usr/bin/plutil -create xml1 "$info"
/usr/bin/plutil -insert CFBundleExecutable -string portablefs-workspace-service "$info"
/usr/bin/plutil -insert CFBundleIdentifier -string "$PRODUCT_BUNDLE_IDENTIFIER.WorkspaceService" "$info"
/usr/bin/plutil -insert CFBundleName -string PortableFSWorkspaceService "$info"
/usr/bin/plutil -insert CFBundlePackageType -string APPL "$info"
/usr/bin/plutil -insert CFBundleShortVersionString -string "$MARKETING_VERSION" "$info"
/usr/bin/plutil -insert CFBundleVersion -string "$CURRENT_PROJECT_VERSION" "$info"
/usr/bin/plutil -insert LSBackgroundOnly -bool YES "$info"
/usr/bin/plutil -insert LSMinimumSystemVersion -string 26.0 "$info"
/usr/bin/plutil -insert NSLocalNetworkUsageDescription -string "PortableFS connects your Linux workspace to filesystem authorities on your network." "$info"
plist="$contents_dir/Library/LaunchAgents/$PRODUCT_BUNDLE_IDENTIFIER.workspace.plist"
/usr/bin/plutil -create xml1 "$plist"
/usr/bin/plutil -insert Label -string "$PRODUCT_BUNDLE_IDENTIFIER.workspace" "$plist"
/usr/bin/plutil -insert BundleProgram -string "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/MacOS/portablefs-workspace-service" "$plist"
/usr/bin/plutil -insert RunAtLoad -bool YES "$plist"
/usr/bin/plutil -insert KeepAlive -bool YES "$plist"
if [ "${CODE_SIGNING_ALLOWED:-NO}" != NO ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] && [ "$EXPANDED_CODE_SIGN_IDENTITY" != - ]; then
  /usr/bin/codesign --force --options runtime --sign "${PORTABLEFS_SERVICE_SIGN_IDENTITY:-$EXPANDED_CODE_SIGN_IDENTITY}" \
    --entitlements "$script_dir/../Config/PortableFSWorkspaceService.entitlements" "$service_app"
fi
