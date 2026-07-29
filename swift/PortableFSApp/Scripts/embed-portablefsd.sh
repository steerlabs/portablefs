#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$SRCROOT/../.." && pwd)
vcs_root="$repo_root/vcs"
output_dir="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH"
output="$output_dir/portablefsd"
work="$TARGET_TEMP_DIR/portablefsd-universal"

mkdir -p "$output_dir" "$work"

set --
for arch in ${ARCHS:-$(uname -m)}; do
  case "$arch" in
    arm64) goarch=arm64 ;;
    x86_64) goarch=amd64 ;;
    *) echo "unsupported macOS architecture: $arch" >&2; exit 1 ;;
  esac
  binary="$work/portablefsd-$arch"
  (
    cd "$vcs_root"
    CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build \
      -trimpath \
      -ldflags="-s -w -X main.version=$MARKETING_VERSION" \
      -o "$binary" \
      ./cmd/portablefsd
  )
  set -- "$@" "$binary"
done

if [ "$#" -gt 1 ]; then
  /usr/bin/lipo -create "$@" -output "$output"
else
  /bin/cp "$1" "$output"
fi
/bin/chmod 0755 "$output"

# Xcode signs the enclosing app after build phases run, but executable code
# nested in Resources also needs its own signature for hardened-runtime and
# notarization validation.
if [ "${CODE_SIGNING_ALLOWED:-NO}" != "NO" ] &&
   [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] &&
   [ "${EXPANDED_CODE_SIGN_IDENTITY:-}" != "-" ]; then
  /usr/bin/codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --options runtime "$output"
fi
