#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$SRCROOT/../.." && pwd)
vcs_root="$repo_root/vcs"
output_dir="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Helpers"
work="$TARGET_TEMP_DIR/portablefs-tools-universal"

mkdir -p "$output_dir" "$work"

build_universal() {
  tool=$1
  output="$output_dir/$tool"
  set --
  for arch in ${ARCHS:-$(uname -m)}; do
    case "$arch" in
      arm64) goarch=arm64 ;;
      x86_64) goarch=amd64 ;;
      *) echo "unsupported macOS architecture: $arch" >&2; exit 1 ;;
    esac
    binary="$work/$tool-$arch"
    (
      cd "$vcs_root"
      CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build \
        -trimpath \
        -ldflags="-s -w -X main.version=$MARKETING_VERSION -X github.com/steerlabs/portablefs/vcs/internal/fskitidentity.AppGroup=$PORTABLEFS_APP_GROUP" \
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

  # Helpers are canonical nested code. Sign each before Xcode seals the outer
  # app so export and notarization validate one complete code hierarchy.
  if [ "${CODE_SIGNING_ALLOWED:-NO}" != "NO" ] &&
     [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] &&
     [ "${EXPANDED_CODE_SIGN_IDENTITY:-}" != "-" ]; then
    /usr/bin/codesign \
      --force \
      --sign "$EXPANDED_CODE_SIGN_IDENTITY" \
      --options runtime \
      "$output"
  fi
}

build_universal portablefs
build_universal portablefsd
