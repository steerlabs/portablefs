#!/bin/sh
# PortableFS CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh
#
# Linux installs the verified CLI/daemon pair. macOS installs the notarized,
# signed PortableFS.app to ~/Applications and links its embedded CLI into PATH.
# The embedded CLI owns the exclusive, race-free bundle replacement.
#
# Environment:
#   PORTABLEFS_VERSION       pin a release, e.g. v0.3.0 or 0.3.0 (default: latest)
#   PORTABLEFS_GITHUB_REPO   owner/repo to install from (default: steerlabs/portablefs)
#   PORTABLEFS_INSTALL_DIR   CLI activation-link directory on Linux or macOS
#                            (must be an absolute path inside the canonical
#                            account home)
#   PORTABLEFS_EXPECTED_TEAM_ID / _BUNDLE_ID / _APP_GROUP /
#   _FS_TYPE / _RESOURCE_SCHEME
#                            required code identities for a custom GitHub repo
set -eu

REPO="${PORTABLEFS_GITHUB_REPO:-steerlabs/portablefs}"
BINARY=portablefs
# Linux installs the daemon beside the CLI. The macOS archive instead seals it
# inside PortableFSDService.app for ServiceManagement.
DAEMON=portablefsd

# REPO becomes part of both GitHub URLs and the provenance policy passed to
# `gh attestation verify`. Accept exactly one owner/repository pair from the
# conservative GitHub-name alphabet; never let URL syntax, path traversal, or
# option-like values enter either trust decision.
case "$REPO" in
  "" | */*/* | /* | */ | *[!A-Za-z0-9._/-]*)
    printf '%s\n' "portablefs install: error: PORTABLEFS_GITHUB_REPO must be an owner/repository pair" >&2
    exit 1
    ;;
esac
repo_owner=${REPO%%/*}
repo_name=${REPO#*/}
[ "$repo_owner" != "$REPO" ] && [ -n "$repo_owner" ] && [ -n "$repo_name" ] ||
  { printf '%s\n' "portablefs install: error: PORTABLEFS_GITHUB_REPO must be an owner/repository pair" >&2; exit 1; }
case "$repo_owner" in
  -* | *- | *[!A-Za-z0-9-]*)
    printf '%s\n' "portablefs install: error: PORTABLEFS_GITHUB_REPO has an invalid owner" >&2
    exit 1
    ;;
esac
case "$repo_name" in
  "." | ".." | -* | *[!A-Za-z0-9._-]*)
    printf '%s\n' "portablefs install: error: PORTABLEFS_GITHUB_REPO has an invalid repository name" >&2
    exit 1
    ;;
esac

if [ "$REPO" = "steerlabs/portablefs" ]; then
  # The canonical distribution identity is policy, not configuration. An
  # inherited environment must never be able to bless another signer/bundle.
  EXPECTED_TEAM_ID=B47U2LLKHW
  EXPECTED_BUNDLE_ID=dev.portablefs.PortableFSApp
  EXPECTED_APP_GROUP=B47U2LLKHW.pfsoss
  EXPECTED_FS_TYPE=pfs
  EXPECTED_RESOURCE_SCHEME=dev.portablefs.oss
else
  [ -n "${PORTABLEFS_EXPECTED_TEAM_ID:-}" ] ||
    { printf '%s\n' "portablefs install: error: a custom PORTABLEFS_GITHUB_REPO requires PORTABLEFS_EXPECTED_TEAM_ID" >&2; exit 1; }
  [ -n "${PORTABLEFS_EXPECTED_BUNDLE_ID:-}" ] ||
    { printf '%s\n' "portablefs install: error: a custom PORTABLEFS_GITHUB_REPO requires PORTABLEFS_EXPECTED_BUNDLE_ID" >&2; exit 1; }
  [ -n "${PORTABLEFS_EXPECTED_APP_GROUP:-}" ] ||
    { printf '%s\n' "portablefs install: error: a custom PORTABLEFS_GITHUB_REPO requires PORTABLEFS_EXPECTED_APP_GROUP" >&2; exit 1; }
  [ -n "${PORTABLEFS_EXPECTED_FS_TYPE:-}" ] ||
    { printf '%s\n' "portablefs install: error: a custom PORTABLEFS_GITHUB_REPO requires PORTABLEFS_EXPECTED_FS_TYPE" >&2; exit 1; }
  [ -n "${PORTABLEFS_EXPECTED_RESOURCE_SCHEME:-}" ] ||
    { printf '%s\n' "portablefs install: error: a custom PORTABLEFS_GITHUB_REPO requires PORTABLEFS_EXPECTED_RESOURCE_SCHEME" >&2; exit 1; }
  EXPECTED_TEAM_ID=$PORTABLEFS_EXPECTED_TEAM_ID
  EXPECTED_BUNDLE_ID=$PORTABLEFS_EXPECTED_BUNDLE_ID
  EXPECTED_APP_GROUP=$PORTABLEFS_EXPECTED_APP_GROUP
  EXPECTED_FS_TYPE=$PORTABLEFS_EXPECTED_FS_TYPE
  EXPECTED_RESOURCE_SCHEME=$PORTABLEFS_EXPECTED_RESOURCE_SCHEME
fi

log() { printf '%s\n' "portablefs install: $*" >&2; }
die() { log "error: $*"; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"

# --- platform -----------------------------------------------------------------
os_raw=$(uname -s)
case "$os_raw" in
  Linux) goos=linux ;;
  Darwin) goos=darwin ;;
  *) die "unsupported operating system: $os_raw (releases cover Linux and macOS)" ;;
esac

if [ "$goos" = "linux" ]; then
  command -v tar >/dev/null 2>&1 || die "tar is required"
else
  command -v ditto >/dev/null 2>&1 || die "ditto is required"
  command -v zipinfo >/dev/null 2>&1 || die "zipinfo is required"
  command -v codesign >/dev/null 2>&1 || die "codesign is required"
  command -v spctl >/dev/null 2>&1 || die "spctl is required"
fi

arch_raw=$(uname -m)
case "$arch_raw" in
  x86_64 | amd64) goarch=amd64 ;;
  arm64 | aarch64) goarch=arm64 ;;
  *) die "unsupported architecture: $arch_raw (releases cover amd64 and arm64)" ;;
esac

# --- version ------------------------------------------------------------------
if [ -n "${PORTABLEFS_VERSION:-}" ]; then
  tag="$PORTABLEFS_VERSION"
  case "$tag" in
    v*) ;;
    *) tag="v$tag" ;;
  esac
else
  log "resolving the latest release of $REPO"
  latest_url="https://github.com/$REPO/releases/latest"
  effective_url=$(curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}' "$latest_url") ||
    die "could not resolve $latest_url; pin PORTABLEFS_VERSION=vX.Y.Z to skip the lookup"
  tag_prefix="https://github.com/$REPO/releases/tag/"
  case "$effective_url" in
    "$tag_prefix"*) tag=${effective_url#"$tag_prefix"} ;;
    *) die "latest release redirected outside the exact $REPO tag namespace: $effective_url" ;;
  esac
fi
printf '%s\n' "$tag" |
  LC_ALL=C grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  die "release tag must be stable SemVer vMAJOR.MINOR.PATCH without leading zeroes; got $tag"
version=${tag#v}

# --- macOS app installation ----------------------------------------------------
if [ "$goos" = "darwin" ]; then
  archive="${BINARY}_${version}_darwin_universal_app.zip"
  base_url="https://github.com/$REPO/releases/download/$tag"
  # The installer executes verified staged code. Keep that staging directory
  # under the platform's root-owned sticky /tmp rather than trusting a
  # caller-controlled TMPDIR whose parent another account could replace.
  tmp=$(mktemp -d "/tmp/portablefs-install.XXXXXX") || die "mktemp failed"
  cleanup() {
    rm -rf "$tmp"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  log "downloading $archive ($tag)"
  curl -fsSL --retry 3 -o "$tmp/$archive" "$base_url/$archive" ||
    die "download failed: $base_url/$archive
does release $tag publish the notarized macOS app?"
  curl -fsSL --retry 3 -o "$tmp/$archive.sha256" "$base_url/$archive.sha256" ||
    die "download failed: $base_url/$archive.sha256 (refusing to install without checksum verification)"

  expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/$archive.sha256")
  [ -n "$expected" ] ||
    die "$archive.sha256 has no entry for $archive; refusing to install"
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
  [ "$actual" = "$expected" ] ||
    die "sha256 mismatch for $archive
  expected: $expected
  actual:   $actual
the download is corrupt or has been tampered with; nothing was installed"
  log "sha256 verified"

  # `ditto -x` writes archive paths before code-signing validation can run.
  # Prove the ZIP namespace and Unix entry types first: one PortableFS.app
  # tree, no duplicate/traversing names, and only directories/regular files.
  zipinfo -1 "$tmp/$archive" >"$tmp/macos-members.txt" ||
    die "could not inspect $archive namespace"
  [ -s "$tmp/macos-members.txt" ] ||
    die "$archive is empty"
  duplicate_member=$(LC_ALL=C sort "$tmp/macos-members.txt" | uniq -d | head -n 1)
  [ -z "$duplicate_member" ] ||
    die "$archive contains duplicate member $duplicate_member"
  while IFS= read -r member; do
    case "$member" in
      PortableFS.app | PortableFS.app/ | PortableFS.app/*) ;;
      *) die "$archive contains an out-of-bundle member: $member" ;;
    esac
    case "/$member/" in
      *"/../"* | *"/./"* | *"//"* | *\\*)
        die "$archive contains an unsafe member name: $member"
        ;;
    esac
  done <"$tmp/macos-members.txt"
  zipinfo -l "$tmp/$archive" >"$tmp/macos-member-types.txt" ||
    die "could not inspect $archive member types"
  zip_type_count=$(awk '$1 ~ /^[bcdlps-]/ { count++ } END { print count+0 }' "$tmp/macos-member-types.txt")
  [ "$zip_type_count" = "$(wc -l <"$tmp/macos-members.txt" | tr -d ' ')" ] ||
    die "$archive member metadata is ambiguous"
  awk '$1 ~ /^[bcdlps-]/ && $1 !~ /^[-d]/ { exit 1 }' "$tmp/macos-member-types.txt" ||
    die "$archive contains a symlink or special filesystem entry"

  mkdir "$tmp/unpacked" || die "could not create unpack directory"
  ditto -x -k "$tmp/$archive" "$tmp/unpacked" ||
    die "could not extract $archive"
  source_app="$tmp/unpacked/PortableFS.app"
  source_cli="$source_app/Contents/Helpers/portablefs"
  source_service="$source_app/Contents/Library/LaunchAgents/PortableFSDService.app"
  source_daemon="$source_service/Contents/MacOS/portablefsd"
  source_launch_agent="$source_app/Contents/Library/LaunchAgents/$EXPECTED_BUNDLE_ID.portablefsd.plist"
  source_extension="$source_app/Contents/Extensions/PortableFSExt.appex"
  [ -d "$source_app" ] && [ ! -L "$source_app" ] ||
    die "$archive does not contain a real PortableFS.app directory"
  # Reject symlinks anywhere in the extracted bundle before inspecting or
  # executing a nested path. A terminal-file check alone does not protect
  # against a symlinked Contents, Helpers, or Extensions ancestor.
  bundle_symlink=$(find "$source_app" -type l -print -quit 2>/dev/null) ||
    die "could not inspect PortableFS.app for symlinks"
  [ -z "$bundle_symlink" ] ||
    die "PortableFS.app contains a symlink at $bundle_symlink; refusing installation"
  [ -f "$source_cli" ] && [ ! -L "$source_cli" ] && [ -x "$source_cli" ] ||
    die "PortableFS.app does not contain a real executable portablefs helper"
  [ -f "$source_daemon" ] && [ ! -L "$source_daemon" ] && [ -x "$source_daemon" ] ||
    die "PortableFS.app does not contain a real executable PortableFSDService daemon"
  [ -d "$source_service" ] && [ ! -L "$source_service" ] ||
    die "PortableFS.app does not contain a real PortableFSDService.app"
  [ -f "$source_launch_agent" ] && [ ! -L "$source_launch_agent" ] ||
    die "PortableFS.app does not contain its sealed LaunchAgent property list"
  [ -d "$source_extension" ] && [ ! -L "$source_extension" ] ||
    die "PortableFS.app does not contain a real PortableFSExt.appex directory"

  codesign --verify --deep --strict --verbose=2 "$source_app" ||
    die "PortableFS.app has an invalid code signature"
  signing=$(codesign -dv --verbose=4 "$source_app" 2>&1)
  printf '%s\n' "$signing" | grep -Fx "Identifier=$EXPECTED_BUNDLE_ID" >/dev/null ||
    die "PortableFS.app has an unexpected signing identifier"
  printf '%s\n' "$signing" | grep -Fx "TeamIdentifier=$EXPECTED_TEAM_ID" >/dev/null ||
    die "PortableFS.app was not signed by the expected release team"
  app_executable=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$source_app/Contents/Info.plist") ||
    die "could not read the app executable identity"
  [ "$app_executable" = "PortableFS" ] ||
    die "PortableFS.app has an unexpected executable identity"
  extension_bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit extension bundle identity"
  [ "$extension_bundle_id" = "$EXPECTED_BUNDLE_ID.PortableFSExt" ] ||
    die "PortableFS.app has an unexpected FSKit extension bundle identity"
  extension_executable=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit extension executable identity"
  [ "$extension_executable" = "PortableFSExt" ] ||
    die "PortableFS.app has an unexpected FSKit extension executable identity"
  service_bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$source_service/Contents/Info.plist") ||
    die "could not read the daemon service bundle identity"
  [ "$service_bundle_id" = "$EXPECTED_BUNDLE_ID.PortableFSDService" ] ||
    die "PortableFS.app has an unexpected daemon service bundle identity"
  service_executable=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$source_service/Contents/Info.plist") ||
    die "could not read the daemon service executable identity"
  [ "$service_executable" = portablefsd ] ||
    die "PortableFS.app has an unexpected daemon service executable identity"
  service_background=$(/usr/libexec/PlistBuddy -c "Print :LSBackgroundOnly" "$source_service/Contents/Info.plist") ||
    die "could not read the daemon service background identity"
  [ "$service_background" = true ] ||
    die "PortableFS.app daemon service is not background-only"
  [ ! -e "$source_service/Contents/embedded.provisionprofile" ] ||
    die "PortableFS.app daemon service unexpectedly embeds a provisioning profile"
  launch_label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$source_launch_agent") ||
    die "could not read the PortableFS LaunchAgent label"
  [ "$launch_label" = "$EXPECTED_BUNDLE_ID.portablefsd" ] ||
    die "PortableFS.app has an unexpected LaunchAgent label"
  launch_program=$(/usr/libexec/PlistBuddy -c "Print :BundleProgram" "$source_launch_agent") ||
    die "could not read the PortableFS LaunchAgent BundleProgram"
  [ "$launch_program" = "Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd" ] ||
    die "PortableFS.app has an unexpected LaunchAgent BundleProgram"
  launch_run_at_load=$(/usr/libexec/PlistBuddy -c "Print :RunAtLoad" "$source_launch_agent") ||
    die "could not read PortableFS LaunchAgent RunAtLoad"
  launch_keep_alive=$(/usr/libexec/PlistBuddy -c "Print :KeepAlive" "$source_launch_agent") ||
    die "could not read PortableFS LaunchAgent KeepAlive"
  [ "$launch_run_at_load" = true ] && [ "$launch_keep_alive" = true ] ||
    die "PortableFS.app LaunchAgent must be RunAtLoad and KeepAlive"
  if /usr/libexec/PlistBuddy -c "Print :Program" "$source_launch_agent" >/dev/null 2>&1; then
    die "PortableFS.app LaunchAgent must use only its sealed BundleProgram"
  fi
  extension_fs_type=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSShortName" "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit extension filesystem type"
  [ "$extension_fs_type" = "$EXPECTED_FS_TYPE" ] ||
    die "PortableFS.app has an unexpected FSKit filesystem type"
  extension_personality=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSPersonalities:PortableFSPersonality:FSName" "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit extension personality"
  [ "$extension_personality" = "$EXPECTED_FS_TYPE" ] ||
    die "PortableFS.app has an unexpected FSKit personality"
  extension_scheme=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportedSchemes:0" "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit extension resource scheme"
  [ "$extension_scheme" = "$EXPECTED_RESOURCE_SCHEME" ] ||
    die "PortableFS.app has an unexpected FSKit resource scheme"
  if /usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportedSchemes:1" "$source_extension/Contents/Info.plist" >/dev/null 2>&1; then
    die "PortableFS.app advertises more than one FSKit resource scheme"
  fi
  extension_generic_urls=$(/usr/libexec/PlistBuddy -c "Print :EXAppExtensionAttributes:FSSupportsGenericURLResources" "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit generic URL resource capability"
  [ "$extension_generic_urls" = "true" ] ||
    die "PortableFS.app does not enable FSKit generic URL resources"
  extension_signing=$(codesign -dv --verbose=4 "$source_extension" 2>&1) ||
    die "could not inspect the FSKit extension signing identity"
  printf '%s\n' "$extension_signing" | grep -Fx "Identifier=$extension_bundle_id" >/dev/null ||
    die "FSKit extension metadata and code-signing identifiers differ"
  service_signing=$(codesign -dv --verbose=4 "$source_service" 2>&1) ||
    die "could not inspect the daemon service signing identity"
  printf '%s\n' "$service_signing" | grep -Fx "Identifier=$service_bundle_id" >/dev/null ||
    die "daemon service metadata and code-signing identifiers differ"
  for signed_item in "$source_app" "$source_extension" "$source_service" "$source_cli" "$source_daemon"; do
    item_signing=$(codesign -dv --verbose=4 "$signed_item" 2>&1) ||
      die "could not inspect the code identity of $signed_item"
    printf '%s\n' "$item_signing" | grep -Fx "TeamIdentifier=$EXPECTED_TEAM_ID" >/dev/null ||
      die "$signed_item was not signed by the expected release team"
    printf '%s\n' "$item_signing" | grep '^Authority=Developer ID Application: ' >/dev/null ||
      die "$signed_item was not signed with a Developer ID Application identity"
    printf '%s\n' "$item_signing" | grep '^CodeDirectory .*flags=.*runtime' >/dev/null ||
      die "$signed_item was not signed with the hardened runtime"
  done
  spctl --assess --type execute --verbose=2 "$source_app" ||
    die "Gatekeeper rejected PortableFS.app; refusing installation"

  app_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$source_app/Contents/Info.plist") ||
    die "could not read PortableFS.app version"
  service_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$source_service/Contents/Info.plist") ||
    die "could not read PortableFSDService.app version"
  [ "$app_version" = "$version" ] ||
    die "PortableFS.app identifies as version $app_version, expected $version"
  [ "$service_version" = "$version" ] ||
    die "PortableFSDService.app identifies as version $service_version, expected $version"
  cli_version=$("$source_cli" version 2>/dev/null) ||
    die "PortableFS.app CLI failed its version smoke test"
  daemon_version=$("$source_daemon" -version 2>/dev/null) ||
    die "PortableFS.app daemon failed its version smoke test"
  [ "$cli_version" = "portablefs $version" ] ||
    die "PortableFS.app CLI identifies as '$cli_version', expected 'portablefs $version'"
  [ "$daemon_version" = "$version" ] ||
    die "PortableFS.app daemon identifies as '$daemon_version', expected '$version'"
  host_app_group=$(/usr/libexec/PlistBuddy \
    -c "Print :PFSAppGroupIdentifier" \
    "$source_app/Contents/Info.plist") ||
    die "could not read the host app-group identity"
  extension_app_group=$(/usr/libexec/PlistBuddy \
    -c "Print :PFSAppGroupIdentifier" \
    "$source_extension/Contents/Info.plist") ||
    die "could not read the FSKit extension app-group identity"
  [ "$host_app_group" = "$EXPECTED_APP_GROUP" ] ||
    die "PortableFS.app host has an unexpected app-group identity"
  [ "$extension_app_group" = "$EXPECTED_APP_GROUP" ] ||
    die "PortableFS.app FSKit extension has an unexpected app-group identity"
  [ "$host_app_group" = "$extension_app_group" ] ||
    die "PortableFS.app host and FSKit extension have different app-group identities"
  app_group=$extension_app_group
  verify_app_group_entitlement() {
    entitlement_code=$1
    entitlement_label=$2
    entitlement_plist="$tmp/$entitlement_label-entitlements.plist"
    codesign -d --entitlements :- "$entitlement_code" >"$entitlement_plist" ||
      die "could not read the signed $entitlement_label entitlements"
    entitlement_group=$(/usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups:0" \
      "$entitlement_plist") ||
      die "could not decode the signed $entitlement_label app-group entitlement"
    [ "$entitlement_group" = "$app_group" ] ||
      die "PortableFS.app $entitlement_label metadata and signed entitlement have different app-group identities"
    if /usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups:1" \
      "$entitlement_plist" >/dev/null 2>&1; then
      die "PortableFS.app $entitlement_label has more than one app-group entitlement"
    fi
  }
  verify_no_app_group_entitlement() {
    entitlement_code=$1
    entitlement_label=$2
    entitlement_plist="$tmp/$entitlement_label-entitlements.plist"
    codesign -d --entitlements :- "$entitlement_code" >"$entitlement_plist" ||
      die "could not read the signed $entitlement_label entitlements"
    if /usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups" \
      "$entitlement_plist" >/dev/null 2>&1; then
      die "PortableFS.app $entitlement_label must not carry an app-group entitlement"
    fi
  }
  verify_app_group_entitlement "$source_app" host
  verify_app_group_entitlement "$source_extension" extension
  verify_app_group_entitlement "$source_daemon" daemon
  service_exact_entitlements="$tmp/service-exact-entitlements.plist"
  codesign -d --entitlements :- "$source_service" >"$service_exact_entitlements" ||
    die "could not read the signed daemon service entitlements"
  /usr/bin/plutil -remove com.apple.security.application-groups "$service_exact_entitlements" ||
    die "daemon service has no exact app-group entitlement"
  service_remaining_entitlements=$(/usr/bin/plutil -convert json -o - "$service_exact_entitlements") ||
    die "could not prove exact daemon service entitlements"
  [ "$service_remaining_entitlements" = "{}" ] ||
    die "PortableFS.app daemon service carries entitlements beyond its exact app group"
  verify_no_app_group_entitlement "$source_cli" cli
  "$source_cli" lifecycle identity --json >"$tmp/cli-identity.json" ||
    die "PortableFS.app CLI failed its identity check"
  "$source_daemon" -identity-json >"$tmp/daemon-identity.json" ||
    die "PortableFS.app daemon failed its identity check"
  cli_group=$(plutil -extract appGroup raw -o - "$tmp/cli-identity.json") ||
    die "could not decode the CLI app-group identity"
  daemon_group=$(plutil -extract appGroup raw -o - "$tmp/daemon-identity.json") ||
    die "could not decode the daemon app-group identity"
  cli_fs_type=$(plutil -extract fsType raw -o - "$tmp/cli-identity.json") ||
    die "could not decode the CLI filesystem type"
  daemon_fs_type=$(plutil -extract fsType raw -o - "$tmp/daemon-identity.json") ||
    die "could not decode the daemon filesystem type"
  cli_scheme=$(plutil -extract resourceScheme raw -o - "$tmp/cli-identity.json") ||
    die "could not decode the CLI resource scheme"
  daemon_scheme=$(plutil -extract resourceScheme raw -o - "$tmp/daemon-identity.json") ||
    die "could not decode the daemon resource scheme"
  [ "$cli_group" = "$app_group" ] ||
    die "PortableFS.app CLI and FSKit extension have different app-group identities"
  [ "$daemon_group" = "$app_group" ] ||
    die "PortableFS.app daemon and FSKit extension have different app-group identities"
  [ "$cli_fs_type" = "$extension_fs_type" ] && [ "$daemon_fs_type" = "$extension_fs_type" ] ||
    die "PortableFS.app CLI, daemon, and FSKit extension have different filesystem types"
  [ "$cli_scheme" = "$extension_scheme" ] && [ "$daemon_scheme" = "$extension_scheme" ] ||
    die "PortableFS.app CLI, daemon, and FSKit extension have different resource schemes"

  # The signed command resolves the canonical account home through directory
  # services, validates the optional link directory, takes the exclusive
  # lifecycle lock, refuses nonempty legacy runtime state without mutating it,
  # and atomically installs the complete app plus CLI symlink. The shell never
  # trusts HOME or performs a
  # check-then-copy replacement.
  if [ -n "${PORTABLEFS_INSTALL_DIR:-}" ]; then
    "$source_cli" install-macos-app \
      --source-app "$source_app" \
      --link-dir "$PORTABLEFS_INSTALL_DIR" \
      --json >"$tmp/install-result.json" ||
      die "PortableFS.app was not installed; close PortableFS and cleanly unmount every volume, then retry"
  else
    "$source_cli" install-macos-app \
      --source-app "$source_app" \
      --json >"$tmp/install-result.json" ||
      die "PortableFS.app was not installed; close PortableFS and cleanly unmount every volume, then retry"
  fi
  plutil -lint "$tmp/install-result.json" >/dev/null ||
    die "PortableFS installer returned malformed JSON"
  result_schema=$(plutil -extract schemaVersion raw -o - "$tmp/install-result.json") ||
    die "PortableFS installer result has no schema version"
  [ "$result_schema" = "1" ] ||
    die "PortableFS installer returned unsupported schema version $result_schema"
  destination_app=$(plutil -extract appPath raw -o - "$tmp/install-result.json") ||
    die "PortableFS installer result has no app path"
  cli_link=$(plutil -extract cliLink raw -o - "$tmp/install-result.json") ||
    die "PortableFS installer result has no CLI link"
  installed_version=$(plutil -extract version raw -o - "$tmp/install-result.json") ||
    die "PortableFS installer result has no version"
  [ "$installed_version" = "$version" ] ||
    die "PortableFS installer reported version $installed_version, expected $version"

  "$cli_link" version >/dev/null 2>&1 ||
    die "installed PortableFS CLI failed its smoke test"

  printf '%s\n' ""
  printf 'PortableFS.app installed to %s\n' "$destination_app"
  printf '%s linked at %s\n' "$("$cli_link" version)" "$cli_link"

  link_dir=${cli_link%/*}
  case ":$PATH:" in
    *":$link_dir:"*) ;;
    *)
      printf '%s\n' "" \
        "note: $link_dir is not in your PATH. Add it to your shell profile:" \
        "  export PATH=\"$link_dir:\$PATH\""
      ;;
  esac

  open "$destination_app" ||
    die "PortableFS.app was installed but could not be opened"
  printf '%s\n' "" \
    "PortableFS opened its one-time File System Extension assistant." \
    "Enable the extension in System Settings, then try a real mount; only a successful mount verifies enablement."
  exit 0
fi

# Matches the goreleaser archives name_template:
#   {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}
archive="${BINARY}_${version}_${goos}_${goarch}.tar.gz"
base_url="https://github.com/$REPO/releases/download/$tag"

# --- download + verify ----------------------------------------------------------
# See the macOS lane above: executable staging never inherits TMPDIR.
tmp=$(mktemp -d "/tmp/portablefs-install.XXXXXX") || die "mktemp failed"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "downloading $archive ($tag)"
curl -fsSL --retry 3 -o "$tmp/$archive" "$base_url/$archive" ||
  die "download failed: $base_url/$archive
does release $tag publish ${goos}/${goarch} archives?"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base_url/checksums.txt" ||
  die "download failed: $base_url/checksums.txt (refusing to install without checksum verification)"
attestation_bundle="${archive}.attestation.jsonl"
curl -fsSL --retry 3 -o "$tmp/$attestation_bundle" "$base_url/$attestation_bundle" ||
  die "download failed: $base_url/$attestation_bundle (refusing to install without build provenance)"
[ -s "$tmp/$attestation_bundle" ] ||
  die "$attestation_bundle is empty; refusing to install"

expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[ -n "$expected" ] || die "checksums.txt in release $tag has no entry for $archive; refusing to install"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
else
  die "sha256sum or shasum is required to verify the download"
fi

if [ "$actual" != "$expected" ]; then
  die "sha256 mismatch for $archive
  expected: $expected
  actual:   $actual
the download is corrupt or has been tampered with; nothing was installed"
fi
log "sha256 verified"

# Checksums detect transport corruption, but a checksum downloaded beside its
# archive does not establish who built it. Bootstrap one exact GitHub CLI
# release from GitHub's official cli/cli repository, verify the complete
# download against its embedded digest, then require provenance binding this
# archive to the requested repository, exact release workflow, and exact tag.
gh_version=2.93.0
gh_prefix="gh_${gh_version}_linux_${goarch}"
gh_archive="${gh_prefix}.tar.gz"
case "$goarch" in
  amd64) gh_sha256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0 ;;
  arm64) gh_sha256=c55feb33684abba57e9909737340d5b39282257c0363e1edde6785ac4a413be7 ;;
  *) die "no trusted GitHub CLI bootstrap is pinned for $goarch" ;;
esac
gh_url="https://github.com/cli/cli/releases/download/v${gh_version}/${gh_archive}"
log "downloading the pinned GitHub CLI provenance verifier"
curl -fsSL --retry 3 -o "$tmp/$gh_archive" "$gh_url" ||
  die "download failed: $gh_url (refusing to install without provenance verification)"
if command -v sha256sum >/dev/null 2>&1; then
  gh_actual=$(sha256sum "$tmp/$gh_archive" | awk '{ print $1 }')
else
  gh_actual=$(shasum -a 256 "$tmp/$gh_archive" | awk '{ print $1 }')
fi
[ "$gh_actual" = "$gh_sha256" ] ||
  die "sha256 mismatch for the pinned GitHub CLI verifier
  expected: $gh_sha256
  actual:   $gh_actual
the verifier download is corrupt or has been tampered with; nothing was installed"

# Inspect the whole bootstrap archive before extracting any byte. The official
# archive contains only ordinary files and directories below one versioned
# directory. A symlink, hardlink, absolute/traversing name, control character,
# duplicate verifier, or any member outside that directory is malformed.
tar -tzf "$tmp/$gh_archive" >"$tmp/gh-members.txt" ||
  die "could not inspect the pinned GitHub CLI archive"
while IFS= read -r member; do
  case "$member" in
    "$gh_prefix" | "$gh_prefix"/*) ;;
    *) die "the pinned GitHub CLI archive contains an out-of-root member: $member" ;;
  esac
  case "$member" in
    *[!A-Za-z0-9._/-]* | *..* | *//*)
      die "the pinned GitHub CLI archive contains an unsafe member name: $member"
      ;;
  esac
done <"$tmp/gh-members.txt"
gh_member="$gh_prefix/bin/gh"
[ "$(awk -v p="$gh_member" '$0 == p { count++ } END { print count+0 }' "$tmp/gh-members.txt")" = "1" ] ||
  die "the pinned GitHub CLI archive does not contain exactly one verifier"
tar -tvzf "$tmp/$gh_archive" >"$tmp/gh-members-verbose.txt" ||
  die "could not inspect GitHub CLI archive member types"
awk '$1 !~ /^[-d]/ { exit 1 }' "$tmp/gh-members-verbose.txt" ||
  die "the pinned GitHub CLI archive contains a link or special member"
awk -v p="$gh_member" '
  $NF == p {
    count++
    if ($1 !~ /^-/) bad = 1
  }
  END { exit(count != 1 || bad) }
' "$tmp/gh-members-verbose.txt" ||
  die "the pinned GitHub CLI verifier member is not exactly one regular file"

# Stream only the verified regular member into a fresh file. No archive path is
# ever materialized, so an archive member cannot redirect the write.
tar -xOzf "$tmp/$gh_archive" "$gh_member" >"$tmp/gh" ||
  die "could not extract the pinned GitHub CLI verifier"
chmod 0755 "$tmp/gh"
"$tmp/gh" version | grep -F "gh version $gh_version " >/dev/null ||
  die "the pinned GitHub CLI verifier failed its version check"

log "verifying GitHub Actions build provenance"
provenance_result=$("$tmp/gh" attestation verify "$tmp/$archive" \
  --hostname github.com \
  --repo "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" \
  --deny-self-hosted-runners \
  --bundle "$tmp/$attestation_bundle" \
  --format json \
  --jq '
    if length == 1 and
       (.[0].verificationResult.statement.subject | length) == 1
    then "verified-single-subject"
    else "invalid-bundle-shape"
    end
  ') ||
  die "GitHub artifact attestation verification failed for $archive; nothing was installed"
[ "$provenance_result" = "verified-single-subject" ] ||
  die "the GitHub artifact attestation bundle is ambiguous; expected exactly one attestation with one archive subject"
log "build provenance verified"

# The attested installer archive has one exact contract: two top-level regular
# files named portablefs and portablefsd. Refuse extra payloads, link types,
# directories, duplicate names, and layout drift before extracting any byte.
tar -tzf "$tmp/$archive" | LC_ALL=C sort >"$tmp/portablefs-members.txt" ||
  die "could not inspect $archive membership"
printf '%s\n' "$BINARY" "$DAEMON" | LC_ALL=C sort >"$tmp/portablefs-members.expected"
cmp "$tmp/portablefs-members.expected" "$tmp/portablefs-members.txt" >/dev/null ||
  die "$archive does not contain exactly the PortableFS CLI/daemon pair"
tar -tvzf "$tmp/$archive" >"$tmp/portablefs-member-types.txt" ||
  die "could not inspect $archive member types"
awk -v cli="$BINARY" -v daemon="$DAEMON" '
  $1 !~ /^-/ { exit 1 }
  $NF != cli && $NF != daemon { exit 1 }
  { count[$NF]++ }
  END { exit(count[cli] != 1 || count[daemon] != 1) }
' "$tmp/portablefs-member-types.txt" ||
  die "$archive contains a link, special entry, or duplicate binary"

# Extract the exact CLI/daemon pair (the CLI resolves portablefsd as a sibling
# on the mount path).
tar -xzf "$tmp/$archive" -C "$tmp" "$BINARY" "$DAEMON" 2>/dev/null ||
  die "could not extract $BINARY and $DAEMON from $archive"
[ -f "$tmp/$BINARY" ] && [ ! -L "$tmp/$BINARY" ] ||
  die "$archive does not contain a real non-symlink $BINARY binary"
[ -f "$tmp/$DAEMON" ] && [ ! -L "$tmp/$DAEMON" ] ||
  die "$archive does not contain a real non-symlink $DAEMON binary"
chmod 0755 "$tmp/$BINARY" "$tmp/$DAEMON"

# Validate the downloaded pair before looking at or changing the destination.
# Both binaries are stamped from the same release; a mixed archive is never
# activated.
cli_version=$("$tmp/$BINARY" version 2>/dev/null) ||
  die "$archive contains a CLI that failed its version smoke test"
daemon_version=$("$tmp/$DAEMON" -version 2>/dev/null) ||
  die "$archive contains a daemon that failed its version smoke test"
[ "$cli_version" = "portablefs $version" ] ||
  die "$archive CLI identifies as '$cli_version', expected 'portablefs $version'"
[ "$daemon_version" = "$version" ] ||
  die "$archive daemon identifies as '$daemon_version', expected '$version'"

# --- guarded immutable activation ------------------------------------------------
# The verified staged CLI owns the Linux replacement transaction. It resolves
# the account home independently of HOME, prepares a content-addressed
# immutable CLI/daemon release, takes the fixed per-user exclusive lifecycle
# guard, rechecks the kernel mount table and exact process identities, then
# changes one activation symlink with renameat2. The shell never performs a
# check-then-copy binary replacement.
if [ -n "${PORTABLEFS_INSTALL_DIR:-}" ]; then
  "$tmp/$BINARY" install-linux-release \
    --source-dir "$tmp" \
    --link-dir "$PORTABLEFS_INSTALL_DIR" ||
    die "installation did not complete; review the signed installer's exact error above, cleanly unmount every PortableFS volume, stop the idle daemon, and retry"
else
  "$tmp/$BINARY" install-linux-release --source-dir "$tmp" ||
    die "installation did not complete; review the signed installer's exact error above, cleanly unmount every PortableFS volume, stop the idle daemon, and retry"
fi

printf '%s\n' "" "Next steps:" \
  "  portablefs login    # portablefs.com; self-hosted: portablefs login <url>" \
  "  portablefs adopt ~/code/myproject" \
  "  portablefs mount myproject ~/work"
