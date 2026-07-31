#!/bin/sh
# Build the one distributable macOS product: PortableFS.app with its CLI,
# daemon, and FSKit extension nested in one signed code hierarchy.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=${1:-${PORTABLEFS_VERSION:-0.2.3}}
version=${version#v}
team_id=${PORTABLEFS_APPLE_TEAM_ID:-B47U2LLKHW}
app_group=${PORTABLEFS_APP_GROUP:-"$team_id.pfsoss"}
configuration=${PORTABLEFS_XCODE_CONFIGURATION:-Release}
unsigned=${PORTABLEFS_UNSIGNED:-0}
release=${PORTABLEFS_RELEASE:-0}
build_number=${PORTABLEFS_BUILD_NUMBER:-}
out_root=${PORTABLEFS_PACKAGE_DIR:-"$repo_root/dist/macos"}
archive="$out_root/PortableFS-$version.xcarchive"
project="$repo_root/swift/PortableFSApp/PortableFSApp.xcodeproj"

if [ "$release" = "1" ]; then
  [ "$unsigned" = "0" ] ||
    { echo "PORTABLEFS_RELEASE=1 requires signed packaging" >&2; exit 1; }
  [ "${PORTABLEFS_DEVELOPER_ID_EXPORT:-0}" = "1" ] ||
    { echo "PORTABLEFS_RELEASE=1 requires PORTABLEFS_DEVELOPER_ID_EXPORT=1" >&2; exit 1; }
  [ -n "${PORTABLEFS_NOTARY_PROFILE:-}" ] ||
    { echo "PORTABLEFS_RELEASE=1 requires PORTABLEFS_NOTARY_PROFILE" >&2; exit 1; }
  [ -n "$build_number" ] ||
    { echo "PORTABLEFS_RELEASE=1 requires a monotonic PORTABLEFS_BUILD_NUMBER" >&2; exit 1; }
fi

if ! printf '%s\n' "$version" |
  LC_ALL=C grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "macOS CFBundleShortVersionString requires stable MAJOR.MINOR.PATCH without leading zeroes; got $version" >&2
  exit 1
fi

if [ -z "$build_number" ]; then
  # Local builds get a deterministic value for a release version. CI passes
  # github.run_number, which is monotonically increasing for distributed
  # builds of this workflow.
  build_number=$(printf '%s' "$version" | awk -F. '{
    major=$1 + 0; minor=$2 + 0; patch=$3 + 0
    print 1 + (major * 1000000) + (minor * 1000) + patch
  }')
fi
case "$build_number" in
  "" | *[!0-9]* | 0) {
    echo "PORTABLEFS_BUILD_NUMBER must be a positive integer" >&2
    exit 1
  } ;;
esac

mkdir -p "$out_root"
verify_tmp=$(mktemp -d "$out_root/package-verify-$version.XXXXXX")
trap 'rm -rf "$verify_tmp"' EXIT HUP INT TERM

set -- xcodebuild \
  -project "$project" \
  -scheme PortableFSApp \
  -configuration "$configuration" \
  -destination "generic/platform=macOS" \
  -archivePath "$archive" \
  ARCHS="arm64 x86_64" \
  ONLY_ACTIVE_ARCH=NO \
  MARKETING_VERSION="$version" \
  CURRENT_PROJECT_VERSION="$build_number" \
  PORTABLEFS_APP_GROUP="$app_group"

if [ -n "${PORTABLEFS_APPLE_API_KEY_PATH:-}" ]; then
  [ -n "${PORTABLEFS_APPLE_API_KEY_ID:-}" ] ||
    { echo "PORTABLEFS_APPLE_API_KEY_ID is required with PORTABLEFS_APPLE_API_KEY_PATH" >&2; exit 1; }
  [ -n "${PORTABLEFS_APPLE_API_ISSUER_ID:-}" ] ||
    { echo "PORTABLEFS_APPLE_API_ISSUER_ID is required with PORTABLEFS_APPLE_API_KEY_PATH" >&2; exit 1; }
  set -- "$@" \
    -authenticationKeyPath "$PORTABLEFS_APPLE_API_KEY_PATH" \
    -authenticationKeyID "$PORTABLEFS_APPLE_API_KEY_ID" \
    -authenticationKeyIssuerID "$PORTABLEFS_APPLE_API_ISSUER_ID"
fi

if [ "$unsigned" = "1" ]; then
  "$@" CODE_SIGNING_ALLOWED=NO clean archive
else
  "$@" \
    DEVELOPMENT_TEAM="$team_id" \
    CODE_SIGN_STYLE=Automatic \
    -allowProvisioningUpdates \
    clean archive
fi

app="$archive/Products/Applications/PortableFS.app"
[ -d "$app" ] || { echo "archive did not produce $app" >&2; exit 1; }

# Xcode's Developer ID export re-signs the app, extension, and canonical
# nested helpers together with the distribution identity.
if [ "${PORTABLEFS_DEVELOPER_ID_EXPORT:-0}" = "1" ]; then
  [ "$unsigned" != "1" ] ||
    { echo "PORTABLEFS_DEVELOPER_ID_EXPORT=1 requires signed packaging" >&2; exit 1; }
  export_options="$verify_tmp/ExportOptions.plist"
  plutil -create xml "$export_options"
  plutil -insert method -string developer-id "$export_options"
  plutil -insert signingStyle -string automatic "$export_options"
  plutil -insert teamID -string "$team_id" "$export_options"
  export_dir="$verify_tmp/export"
  mkdir "$export_dir"

  set -- xcodebuild \
    -exportArchive \
    -archivePath "$archive" \
    -exportPath "$export_dir" \
    -exportOptionsPlist "$export_options" \
    -allowProvisioningUpdates
  if [ -n "${PORTABLEFS_APPLE_API_KEY_PATH:-}" ]; then
    set -- "$@" \
      -authenticationKeyPath "$PORTABLEFS_APPLE_API_KEY_PATH" \
      -authenticationKeyID "$PORTABLEFS_APPLE_API_KEY_ID" \
      -authenticationKeyIssuerID "$PORTABLEFS_APPLE_API_ISSUER_ID"
  fi
  "$@"
  app="$export_dir/PortableFS.app"
  [ -d "$app" ] || { echo "Developer ID export did not produce $app" >&2; exit 1; }
fi

app_executable="$app/Contents/MacOS/PortableFS"
cli="$app/Contents/Helpers/portablefs"
daemon="$app/Contents/Helpers/portablefsd"
extension="$app/Contents/Extensions/PortableFSExt.appex"
extension_executable="$extension/Contents/MacOS/PortableFSExt"
[ -x "$app_executable" ] || { echo "packaged app has no PortableFS executable" >&2; exit 1; }
[ -x "$cli" ] || { echo "packaged app has no executable portablefs helper" >&2; exit 1; }
[ -x "$daemon" ] || { echo "packaged app has no executable portablefsd helper" >&2; exit 1; }
[ -d "$extension" ] || { echo "packaged app has no FSKit extension" >&2; exit 1; }
[ -x "$extension_executable" ] ||
  { echo "packaged app has no PortableFSExt executable" >&2; exit 1; }

for executable in "$app_executable" "$cli" "$daemon" "$extension_executable"; do
  /usr/bin/lipo "$executable" -verify_arch arm64 x86_64
done

app_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist")
app_build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$app/Contents/Info.plist")
extension_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$extension/Contents/Info.plist")
extension_build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$extension/Contents/Info.plist")
extension_group=$(/usr/libexec/PlistBuddy -c "Print :PFSAppGroupIdentifier" "$extension/Contents/Info.plist")
extension_fs_type=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSShortName" "$extension/Contents/Info.plist")
extension_personality=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSPersonalities:PortableFSPersonality:FSName" "$extension/Contents/Info.plist")
extension_scheme=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportedSchemes:0" "$extension/Contents/Info.plist")
extension_generic_urls=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportsGenericURLResources" "$extension/Contents/Info.plist")
[ "$app_version" = "$version" ] || { echo "app version $app_version != $version" >&2; exit 1; }
[ "$extension_version" = "$version" ] || { echo "extension version $extension_version != $version" >&2; exit 1; }
[ "$app_build" = "$build_number" ] || { echo "app build $app_build != $build_number" >&2; exit 1; }
[ "$extension_build" = "$build_number" ] || { echo "extension build $extension_build != $build_number" >&2; exit 1; }
[ "$extension_group" = "$app_group" ] ||
  { echo "extension app group $extension_group != $app_group" >&2; exit 1; }
[ -n "$extension_fs_type" ] && [ "$extension_personality" = "$extension_fs_type" ] ||
  { echo "extension filesystem type and personality do not match" >&2; exit 1; }
printf '%s\n' "$extension_scheme" | LC_ALL=C grep -Eq '^[a-z][a-z0-9+.-]*$' ||
  { echo "extension resource scheme $extension_scheme is not canonical" >&2; exit 1; }
if /usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportedSchemes:1" "$extension/Contents/Info.plist" >/dev/null 2>&1; then
  echo "extension advertises more than one FSKit resource scheme" >&2
  exit 1
fi
[ "$extension_generic_urls" = "true" ] ||
  { echo "extension does not enable generic URL resources" >&2; exit 1; }

"$cli" version | grep -Fx "portablefs $version" >/dev/null
"$daemon" -version | grep -Fx "$version" >/dev/null
cli_identity="$verify_tmp/cli-identity.json"
daemon_identity="$verify_tmp/daemon-identity.json"
"$cli" lifecycle identity --json >"$cli_identity"
"$daemon" -identity-json >"$daemon_identity"
cli_group=$(plutil -extract appGroup raw -o - "$cli_identity")
daemon_group=$(plutil -extract appGroup raw -o - "$daemon_identity")
cli_fs_type=$(plutil -extract fsType raw -o - "$cli_identity")
daemon_fs_type=$(plutil -extract fsType raw -o - "$daemon_identity")
cli_scheme=$(plutil -extract resourceScheme raw -o - "$cli_identity")
daemon_scheme=$(plutil -extract resourceScheme raw -o - "$daemon_identity")
[ "$cli_group" = "$app_group" ] ||
  { echo "CLI stamped app group $cli_group != $app_group" >&2; exit 1; }
[ "$daemon_group" = "$app_group" ] ||
  { echo "daemon stamped app group $daemon_group != $app_group" >&2; exit 1; }
[ "$cli_fs_type" = "$extension_fs_type" ] && [ "$daemon_fs_type" = "$extension_fs_type" ] ||
  { echo "CLI/daemon filesystem type does not match extension $extension_fs_type" >&2; exit 1; }
[ "$cli_scheme" = "$extension_scheme" ] && [ "$daemon_scheme" = "$extension_scheme" ] ||
  { echo "CLI/daemon resource scheme does not match extension $extension_scheme" >&2; exit 1; }

if [ "$unsigned" != "1" ]; then
  codesign --verify --deep --strict --verbose=2 "$app"
  for code in "$app" "$extension" "$cli" "$daemon"; do
    code_identity=$(codesign -dv --verbose=4 "$code" 2>&1)
    printf '%s\n' "$code_identity" |
      grep -Fx "TeamIdentifier=$team_id" >/dev/null ||
      { echo "$code is not signed by team $team_id" >&2; exit 1; }
    if [ "$release" = "1" ]; then
      printf '%s\n' "$code_identity" |
        grep '^Authority=Developer ID Application: ' >/dev/null ||
        { echo "$code is not signed with a Developer ID Application identity" >&2; exit 1; }
      printf '%s\n' "$code_identity" |
        grep '^CodeDirectory .*flags=.*runtime' >/dev/null ||
        { echo "$code is not signed with the hardened runtime" >&2; exit 1; }
    fi
  done
  entitlements="$verify_tmp/extension-entitlements.plist"
  codesign -d --entitlements :- "$extension" >"$entitlements"
  entitlement_group=$(/usr/libexec/PlistBuddy \
    -c "Print :com.apple.security.application-groups:0" \
    "$entitlements")
  [ "$entitlement_group" = "$app_group" ] ||
    { echo "signed extension entitlement $entitlement_group != $app_group" >&2; exit 1; }
fi

if [ "$release" = "1" ]; then
  zip="$out_root/portablefs_${version}_darwin_universal_app.zip"
else
  zip="$out_root/portablefs_${version}_darwin_universal_app-dev.zip"
fi
rm -f "$zip" "$zip.sha256"
ditto -c -k --keepParent "$app" "$zip"

if [ -n "${PORTABLEFS_NOTARY_PROFILE:-}" ]; then
  [ "$unsigned" != "1" ] ||
    { echo "PORTABLEFS_NOTARY_PROFILE requires signed packaging" >&2; exit 1; }
  set -- xcrun notarytool submit "$zip" \
    --keychain-profile "$PORTABLEFS_NOTARY_PROFILE"
  if [ -n "${PORTABLEFS_NOTARY_KEYCHAIN:-}" ]; then
    set -- "$@" --keychain "$PORTABLEFS_NOTARY_KEYCHAIN"
  fi
  "$@" --wait --timeout 2h
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  spctl --assess --type execute --verbose=2 "$app"
fi

(
  cd "$out_root"
  shasum -a 256 "$(basename "$zip")" >"$(basename "$zip").sha256"
)
printf '%s\n' "$zip"
