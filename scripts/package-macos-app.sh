#!/bin/sh
# Build the one distributable macOS product: PortableFS.app with its CLI,
# daemon, and FSKit extension nested in one signed code hierarchy.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version_file="$repo_root/VERSION"
[ -f "$version_file" ] && [ ! -L "$version_file" ] ||
  { echo "PortableFS packaging requires a regular VERSION file" >&2; exit 1; }
version=$(/bin/cat "$version_file")
printf '%s\n' "$version" | /usr/bin/cmp -s - "$version_file" ||
  { echo "VERSION must contain exactly one newline-terminated version" >&2; exit 1; }
[ "$#" -le 1 ] ||
  { echo "usage: scripts/package-macos-app.sh [vMAJOR.MINOR.PATCH]" >&2; exit 1; }
if [ -n "${PORTABLEFS_VERSION:-}" ]; then
  echo "macOS packaging is versioned only by VERSION, not PORTABLEFS_VERSION" >&2
  exit 1
fi
if [ "$#" = 1 ]; then
  requested_version=${1#v}
  [ "$requested_version" = "$version" ] ||
    { echo "requested macOS package version $requested_version != VERSION $version" >&2; exit 1; }
fi
team_id=${PORTABLEFS_APPLE_TEAM_ID:-B47U2LLKHW}
app_group=${PORTABLEFS_APP_GROUP:-"$team_id.pfsoss"}
configuration=${PORTABLEFS_XCODE_CONFIGURATION:-Release}
unsigned=${PORTABLEFS_UNSIGNED:-0}
release=${PORTABLEFS_RELEASE:-0}
build_number=${PORTABLEFS_BUILD_NUMBER:-}
out_root=${PORTABLEFS_PACKAGE_DIR:-"$repo_root/dist/macos"}
archive="$out_root/PortableFS-$version.xcarchive"
project="$repo_root/swift/PortableFSApp/PortableFSApp.xcodeproj"
go_binary=${PORTABLEFS_GO:-}

if [ "$release" = "1" ] && [ -z "$go_binary" ]; then
  echo "PORTABLEFS_RELEASE=1 requires an explicit exact PORTABLEFS_GO" >&2
  exit 1
fi
if [ -z "$go_binary" ]; then
  go_candidate=$(command -v go || true)
  [ -n "$go_candidate" ] ||
    { echo "PortableFS packaging requires Go" >&2; exit 1; }
  # Resolve an exact module-selected toolchain once, outside Xcode's sanitized
  # Run Script environment. The embed phase then disables toolchain switching.
  go_root=$(GOTOOLCHAIN=auto "$go_candidate" -C "$repo_root/vcs" env GOROOT)
  go_binary=$(/bin/realpath "$go_root/bin/go")
fi
case "$go_binary" in
  /*) ;;
  *) echo "PORTABLEFS_GO must resolve to an absolute Go executable" >&2; exit 1 ;;
esac
[ -f "$go_binary" ] && [ ! -L "$go_binary" ] && [ -x "$go_binary" ] ||
  { echo "PORTABLEFS_GO must be a regular, non-symlink executable" >&2; exit 1; }
required_go_version=$(/usr/bin/awk '
  $1 == "go" && NF == 2 { print "go" $2; declarations += 1 }
  END { if (declarations != 1) exit 1 }
' "$repo_root/vcs/go.mod")
actual_go_version=$("$go_binary" version | /usr/bin/awk '{ print $3 }')
[ "$actual_go_version" = "$required_go_version" ] ||
  { echo "PORTABLEFS_GO is $actual_go_version but vcs/go.mod requires $required_go_version" >&2; exit 1; }

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
  PORTABLEFS_APP_GROUP="$app_group" \
  PORTABLEFS_NATIVE_QUALIFICATION= \
  PORTABLEFS_GO="$go_binary"

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
  plutil -create xml1 "$export_options"
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
service="$app/Contents/Library/LaunchAgents/PortableFSDService.app"
daemon="$service/Contents/MacOS/portablefsd"
launch_agent="$app/Contents/Library/LaunchAgents/dev.portablefs.PortableFSApp.portablefsd.plist"
extension="$app/Contents/Extensions/PortableFSExt.appex"
extension_executable="$extension/Contents/MacOS/PortableFSExt"
[ -x "$app_executable" ] || { echo "packaged app has no PortableFS executable" >&2; exit 1; }
[ -x "$cli" ] || { echo "packaged app has no executable portablefs helper" >&2; exit 1; }
[ -d "$service" ] || { echo "packaged app has no PortableFSDService.app" >&2; exit 1; }
[ -x "$daemon" ] || { echo "packaged service app has no executable portablefsd" >&2; exit 1; }
[ -f "$launch_agent" ] || { echo "packaged app has no sealed PortableFS LaunchAgent plist" >&2; exit 1; }
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
service_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$service/Contents/Info.plist")
service_build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$service/Contents/Info.plist")
service_bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$service/Contents/Info.plist")
service_executable=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$service/Contents/Info.plist")
launch_label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$launch_agent")
launch_program=$(/usr/libexec/PlistBuddy -c "Print :BundleProgram" "$launch_agent")
launch_run_at_load=$(/usr/libexec/PlistBuddy -c "Print :RunAtLoad" "$launch_agent")
launch_keep_alive=$(/usr/libexec/PlistBuddy -c "Print :KeepAlive" "$launch_agent")
host_group=$(/usr/libexec/PlistBuddy -c "Print :PFSAppGroupIdentifier" "$app/Contents/Info.plist")
extension_group=$(/usr/libexec/PlistBuddy -c "Print :PFSAppGroupIdentifier" "$extension/Contents/Info.plist")
extension_fs_type=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSShortName" "$extension/Contents/Info.plist")
extension_personality=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSPersonalities:PortableFSPersonality:FSName" "$extension/Contents/Info.plist")
extension_scheme=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportedSchemes:0" "$extension/Contents/Info.plist")
extension_generic_urls=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportsGenericURLResources" "$extension/Contents/Info.plist")
[ "$app_version" = "$version" ] || { echo "app version $app_version != $version" >&2; exit 1; }
[ "$extension_version" = "$version" ] || { echo "extension version $extension_version != $version" >&2; exit 1; }
[ "$service_version" = "$version" ] || { echo "daemon service version $service_version != $version" >&2; exit 1; }
[ "$app_build" = "$build_number" ] || { echo "app build $app_build != $build_number" >&2; exit 1; }
[ "$extension_build" = "$build_number" ] || { echo "extension build $extension_build != $build_number" >&2; exit 1; }
[ "$service_build" = "$build_number" ] || { echo "daemon service build $service_build != $build_number" >&2; exit 1; }
[ "$service_bundle_id" = "dev.portablefs.PortableFSApp.PortableFSDService" ] ||
  { echo "daemon service has unexpected bundle identifier $service_bundle_id" >&2; exit 1; }
[ "$service_executable" = portablefsd ] ||
  { echo "daemon service has unexpected executable $service_executable" >&2; exit 1; }
[ "$launch_label" = "dev.portablefs.PortableFSApp.portablefsd" ] ||
  { echo "LaunchAgent has unexpected label $launch_label" >&2; exit 1; }
[ "$launch_program" = "Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd" ] ||
  { echo "LaunchAgent has unexpected BundleProgram $launch_program" >&2; exit 1; }
[ "$launch_run_at_load" = true ] && [ "$launch_keep_alive" = true ] ||
  { echo "LaunchAgent must be RunAtLoad and KeepAlive" >&2; exit 1; }
if /usr/libexec/PlistBuddy -c "Print :Program" "$launch_agent" >/dev/null 2>&1; then
  echo "LaunchAgent must use only sealed BundleProgram" >&2
  exit 1
fi
[ ! -e "$service/Contents/embedded.provisionprofile" ] ||
  { echo "daemon service must not embed a provisioning profile" >&2; exit 1; }
[ "$host_group" = "$app_group" ] ||
  { echo "host app group $host_group != $app_group" >&2; exit 1; }
[ "$extension_group" = "$app_group" ] ||
  { echo "extension app group $extension_group != $app_group" >&2; exit 1; }
[ "$host_group" = "$extension_group" ] ||
  { echo "host and extension app groups do not match" >&2; exit 1; }
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
  for code in "$app" "$extension" "$service" "$cli" "$daemon"; do
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
  verify_app_group_entitlement() {
    entitlement_code=$1
    entitlement_label=$2
    entitlement_plist="$verify_tmp/$entitlement_label-entitlements.plist"
    codesign -d --entitlements :- "$entitlement_code" >"$entitlement_plist"
    entitlement_group=$(/usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups:0" \
      "$entitlement_plist") || {
        echo "could not read signed $entitlement_label app-group entitlement" >&2
        exit 1
      }
    [ "$entitlement_group" = "$app_group" ] || {
      echo "signed $entitlement_label entitlement $entitlement_group != $app_group" >&2
      exit 1
    }
    if /usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups:1" \
      "$entitlement_plist" >/dev/null 2>&1; then
      echo "signed $entitlement_label has more than one app-group entitlement" >&2
      exit 1
    fi
  }
  verify_no_app_group_entitlement() {
    entitlement_code=$1
    entitlement_label=$2
    entitlement_plist="$verify_tmp/$entitlement_label-entitlements.plist"
    codesign -d --entitlements :- "$entitlement_code" >"$entitlement_plist"
    if /usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups" \
      "$entitlement_plist" >/dev/null 2>&1; then
      echo "signed $entitlement_label must not carry an app-group entitlement" >&2
      exit 1
    fi
  }
  verify_exact_service_entitlements() {
    entitlement_plist="$verify_tmp/service-exact-entitlements.plist"
    codesign -d --entitlements :- "$service" >"$entitlement_plist"
    /usr/bin/plutil -remove com.apple.security.application-groups "$entitlement_plist"
    remaining=$(/usr/bin/plutil -convert json -o - "$entitlement_plist")
    [ "$remaining" = "{}" ] || {
      echo "signed daemon service carries entitlements beyond its exact app group: $remaining" >&2
      exit 1
    }
  }
  verify_app_group_entitlement "$app" host
  verify_app_group_entitlement "$extension" extension
  verify_app_group_entitlement "$daemon" daemon
  verify_exact_service_entitlements
  verify_no_app_group_entitlement "$cli" cli
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
