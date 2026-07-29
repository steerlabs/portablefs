#!/bin/sh
# Build the macOS FSKit app locally. No GitHub Actions or remote build service.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=${1:-${PORTABLEFS_VERSION:-0.2.3}}
version=${version#v}
team_id=${PORTABLEFS_APPLE_TEAM_ID:-B47U2LLKHW}
configuration=${PORTABLEFS_XCODE_CONFIGURATION:-Release}
unsigned=${PORTABLEFS_UNSIGNED:-0}
out_root=${PORTABLEFS_PACKAGE_DIR:-"$repo_root/dist/macos"}
archive="$out_root/PortableFS-$version.xcarchive"
project="$repo_root/swift/PortableFSApp/PortableFSApp.xcodeproj"

mkdir -p "$out_root"

if [ "$unsigned" = "1" ]; then
  xcodebuild \
    -project "$project" \
    -scheme PortableFSApp \
    -configuration "$configuration" \
    -destination "generic/platform=macOS" \
    -archivePath "$archive" \
    ARCHS="arm64 x86_64" \
    ONLY_ACTIVE_ARCH=NO \
    MARKETING_VERSION="$version" \
    CODE_SIGNING_ALLOWED=NO \
    clean archive
else
  xcodebuild \
    -project "$project" \
    -scheme PortableFSApp \
    -configuration "$configuration" \
    -destination "generic/platform=macOS" \
    -archivePath "$archive" \
    ARCHS="arm64 x86_64" \
    ONLY_ACTIVE_ARCH=NO \
    DEVELOPMENT_TEAM="$team_id" \
    MARKETING_VERSION="$version" \
    CODE_SIGN_STYLE=Automatic \
    -allowProvisioningUpdates \
    clean archive
fi

app="$archive/Products/Applications/PortableFSApp.app"
if [ ! -d "$app" ]; then
  echo "archive did not produce $app" >&2
  exit 1
fi

# Export with Developer ID when requested. Xcode selects the restricted-
# entitlement provisioning profile and re-signs the app/extension together.
if [ "${PORTABLEFS_DEVELOPER_ID_EXPORT:-0}" = "1" ]; then
  if [ "$unsigned" = "1" ]; then
    echo "PORTABLEFS_DEVELOPER_ID_EXPORT=1 requires signed packaging" >&2
    exit 1
  fi
  export_options="$out_root/ExportOptions-$version.plist"
  plutil -create xml "$export_options"
  plutil -insert method -string developer-id "$export_options"
  plutil -insert signingStyle -string automatic "$export_options"
  plutil -insert teamID -string "$team_id" "$export_options"
  export_dir=$(mktemp -d "$out_root/export-$version.XXXXXX")
  xcodebuild \
    -exportArchive \
    -archivePath "$archive" \
    -exportPath "$export_dir" \
    -exportOptionsPlist "$export_options" \
    -allowProvisioningUpdates
  app="$export_dir/PortableFSApp.app"
fi

daemon="$app/Contents/Resources/portablefsd"
extension="$app/Contents/Extensions/PortableFSExt.appex"
[ -x "$daemon" ] || { echo "packaged app has no executable portablefsd" >&2; exit 1; }
[ -d "$extension" ] || { echo "packaged app has no FSKit extension" >&2; exit 1; }
/usr/bin/lipo "$app/Contents/MacOS/PortableFSApp" -verify_arch arm64 x86_64
/usr/bin/lipo "$daemon" -verify_arch arm64 x86_64

if [ "$unsigned" != "1" ]; then
  codesign --verify --deep --strict --verbose=2 "$app"
fi
"$daemon" -version | grep -Fx "$version" >/dev/null

zip="$out_root/portablefs_${version}_darwin_universal_app.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"

if [ -n "${PORTABLEFS_NOTARY_PROFILE:-}" ]; then
  if [ "$unsigned" = "1" ]; then
    echo "PORTABLEFS_NOTARY_PROFILE requires signed packaging" >&2
    exit 1
  fi
  xcrun notarytool submit "$zip" \
    --keychain-profile "$PORTABLEFS_NOTARY_PROFILE" \
    --wait
  xcrun stapler staple "$app"
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  spctl --assess --type execute --verbose=2 "$app"
fi

shasum -a 256 "$zip" >"$zip.sha256"
printf '%s\n' "$zip"
