#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
vcs_root="$repo_root/vcs"
contents_dir="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH"
helper_dir="$contents_dir/Helpers"
launch_agents_dir="$contents_dir/Library/LaunchAgents"
service_app="$launch_agents_dir/PortableFSDService.app"
service_contents="$service_app/Contents"
service_macos="$service_contents/MacOS"
service_executable="$service_macos/portablefsd"
launch_agent_plist="$launch_agents_dir/$PRODUCT_BUNDLE_IDENTIFIER.portablefsd.plist"
service_bundle_identifier="$PRODUCT_BUNDLE_IDENTIFIER.PortableFSDService"
work="$TARGET_TEMP_DIR/portablefs-tools-universal"
helper_entitlements_source="$script_dir/../Config/PortableFSHelpers.entitlements"
helper_entitlements="$work/PortableFSHelpers.entitlements"

: "${PORTABLEFS_GO:?PORTABLEFS_GO must name the exact Go compiler used for PortableFS helpers}"
case "$PORTABLEFS_GO" in
  /*) ;;
  *)
    echo "PORTABLEFS_GO must be an absolute path" >&2
    exit 1
    ;;
esac
if [ -L "$PORTABLEFS_GO" ] || [ ! -f "$PORTABLEFS_GO" ] || [ ! -x "$PORTABLEFS_GO" ]; then
  echo "PORTABLEFS_GO must be a regular executable, not a symlink" >&2
  exit 1
fi
portablefs_go=$(/bin/realpath "$PORTABLEFS_GO")
if [ "$portablefs_go" != "$PORTABLEFS_GO" ]; then
  echo "PORTABLEFS_GO must be a canonical path without symlinked components" >&2
  exit 1
fi
go_owner=$(/usr/bin/stat -f '%u' "$portablefs_go")
current_uid=$(/usr/bin/id -u)
if [ "$go_owner" != 0 ] && [ "$go_owner" != "$current_uid" ]; then
  echo "PORTABLEFS_GO must be owned by root or the build account" >&2
  exit 1
fi
go_mode=$(/usr/bin/stat -f '%Lp' "$portablefs_go")
case "$go_mode" in
  *[2367][0-7]|*[0-7][2367])
    echo "PORTABLEFS_GO must not be group- or other-writable" >&2
    exit 1
    ;;
esac
go_version=$("$portablefs_go" version)
case "$go_version" in
  "go version go"*" darwin/"*) ;;
  *)
    echo "PORTABLEFS_GO is not a Darwin Go compiler" >&2
    exit 1
    ;;
esac
required_go_version=$(/usr/bin/awk '
  $1 == "go" && NF == 2 { print "go" $2; declarations += 1 }
  END { if (declarations != 1) exit 1 }
' "$vcs_root/go.mod")
actual_go_version=$(printf '%s\n' "$go_version" | /usr/bin/awk '{ print $3 }')
if [ "$actual_go_version" != "$required_go_version" ]; then
  echo "PORTABLEFS_GO is $actual_go_version but vcs/go.mod requires $required_go_version" >&2
  exit 1
fi

native_qualification=${PORTABLEFS_NATIVE_QUALIFICATION:-}
qualification_build_tags=
case "$native_qualification" in
  "") ;;
  sdk27-live-qualification-only)
    qualification_build_tags=portablefs_macos27_qualification
    ;;
  *)
    echo "PORTABLEFS_NATIVE_QUALIFICATION has an unsupported value" >&2
    exit 1
    ;;
esac

: "${PORTABLEFS_APP_GROUP:?PORTABLEFS_APP_GROUP is required to build PortableFS helpers}"
case "$PORTABLEFS_APP_GROUP" in
  *[!A-Za-z0-9.-]*)
    echo "PORTABLEFS_APP_GROUP contains unsupported characters" >&2
    exit 1
    ;;
esac

mkdir -p "$helper_dir" "$service_macos" "$work"
/bin/cp "$helper_entitlements_source" "$helper_entitlements"
/usr/libexec/PlistBuddy \
  -c "Set :com.apple.security.application-groups:0 $PORTABLEFS_APP_GROUP" \
  "$helper_entitlements"
/usr/bin/plutil -lint "$helper_entitlements" >/dev/null

build_universal() {
  tool=$1
  output=$2
  set --
  for arch in ${ARCHS:-$(uname -m)}; do
    case "$arch" in
      arm64) goarch=arm64 ;;
      x86_64) goarch=amd64 ;;
      *) echo "unsupported macOS architecture: $arch" >&2; exit 1 ;;
    esac
    binary="$work/$tool-$arch"
    qualification_ldflag=
    if [ "$tool" = portablefs ] && [ -n "$native_qualification" ]; then
      qualification_ldflag=" -X github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli.nativeFSKitPolicyQualification=$native_qualification"
    fi
    (
      cd "$vcs_root"
      # portablefs uses AppKit's exact-URL NSWorkspace launcher; portablefsd
      # uses Foundation's app-group resolver. Both shipped Darwin helpers
      # therefore require their real cgo platform boundary.
      if [ -n "$qualification_build_tags" ]; then
        set -- -tags "$qualification_build_tags"
      else
        set --
      fi
      GOFLAGS= GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=darwin GOARCH="$goarch" "$portablefs_go" build "$@" \
        -trimpath \
        -ldflags="-s -w -X main.version=$MARKETING_VERSION -X github.com/steerlabs/portablefs/vcs/internal/fskitidentity.AppGroup=$PORTABLEFS_APP_GROUP$qualification_ldflag" \
        -o "$binary" \
        "./cmd/$tool"
    )
    set -- "$@" "$binary"
  done

  if [ "$#" -gt 1 ]; then
    /usr/bin/lipo -create "$@" -output "$output"
  else
    /bin/cp "$1" "$output"
  fi
  /bin/chmod 0755 "$output"

  # The CLI is canonical nested code. The daemon is signed only after its
  # app-like service wrapper is complete below.
  if [ "${CODE_SIGNING_ALLOWED:-NO}" != "NO" ] &&
     [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] &&
     [ "${EXPANDED_CODE_SIGN_IDENTITY:-}" != "-" ]; then
    # The shell CLI is intentionally unentitled: it wakes the exact host and
    # uses the external private control socket, never the Data Vault.
    [ "$tool" = portablefs ] || return 0
    /usr/bin/codesign \
      --force \
      --sign "$EXPANDED_CODE_SIGN_IDENTITY" \
      --options runtime \
      "$output"
  fi
}

build_universal portablefs "$helper_dir/portablefs"
build_universal portablefsd "$service_executable"

# ServiceManagement launches the daemon through an app-like wrapper. This is
# the one proven macOS identity shape for a launchd job that carries the
# app-group entitlement needed to enter the Data Vault. No second daemon
# location is emitted.
service_info="$service_contents/Info.plist"
/usr/bin/plutil -create xml1 "$service_info"
/usr/bin/plutil -insert CFBundleDevelopmentRegion -string "${DEVELOPMENT_LANGUAGE:-en}" "$service_info"
/usr/bin/plutil -insert CFBundleExecutable -string portablefsd "$service_info"
/usr/bin/plutil -insert CFBundleIdentifier -string "$service_bundle_identifier" "$service_info"
/usr/bin/plutil -insert CFBundleInfoDictionaryVersion -string 6.0 "$service_info"
/usr/bin/plutil -insert CFBundleName -string PortableFSDService "$service_info"
/usr/bin/plutil -insert CFBundlePackageType -string APPL "$service_info"
/usr/bin/plutil -insert CFBundleShortVersionString -string "$MARKETING_VERSION" "$service_info"
/usr/bin/plutil -insert CFBundleVersion -string "$CURRENT_PROJECT_VERSION" "$service_info"
/usr/bin/plutil -insert LSBackgroundOnly -bool YES "$service_info"
/usr/bin/plutil -insert LSMinimumSystemVersion -string "$MACOSX_DEPLOYMENT_TARGET" "$service_info"
/usr/bin/plutil -lint "$service_info" >/dev/null

/usr/bin/plutil -create xml1 "$launch_agent_plist"
/usr/bin/plutil -insert Label -string "$PRODUCT_BUNDLE_IDENTIFIER.portablefsd" "$launch_agent_plist"
/usr/bin/plutil -insert BundleProgram -string "Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd" "$launch_agent_plist"
/usr/bin/plutil -insert RunAtLoad -bool YES "$launch_agent_plist"
/usr/bin/plutil -insert KeepAlive -bool YES "$launch_agent_plist"
/usr/bin/plutil -lint "$launch_agent_plist" >/dev/null

if [ "${CODE_SIGNING_ALLOWED:-NO}" != "NO" ] &&
   [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] &&
   [ "${EXPANDED_CODE_SIGN_IDENTITY:-}" != "-" ]; then
  : "${PORTABLEFS_SERVICE_SIGN_IDENTITY:?signed PortableFS builds require an explicit Developer ID Application identity for the daemon service}"
  case "$PORTABLEFS_SERVICE_SIGN_IDENTITY" in
    "Developer ID Application: "*) ;;
    *)
      echo "PORTABLEFS_SERVICE_SIGN_IDENTITY must name a Developer ID Application identity" >&2
      exit 1
      ;;
  esac
  # Development hosts are signed with Apple Development so FSKit can be
  # enabled locally, but ServiceManagement requires this app-like daemon
  # wrapper to carry the independent Developer ID restricted identity.
  /usr/bin/codesign \
    --force \
    --sign "$PORTABLEFS_SERVICE_SIGN_IDENTITY" \
    --options runtime \
    --entitlements "$helper_entitlements" \
    "$service_app"
fi
