#!/bin/sh
# Drive the real installer through checksum and ZIP inspection without extraction.
set -eu

[ "$(uname -s)" = Darwin ] || { echo "macOS ZIP namespace test requires Darwin" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=$(cat "$repo_root/VERSION")
release_archive="portablefs_${version}_darwin_universal_app.zip"
work=$(mktemp -d /tmp/portablefs-installer-zip-test.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/shims"

cat >"$work/shims/curl" <<'SH'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  *.zip.sha256) cp "$PFS_TEST_ARCHIVE.sha256" "$output" ;;
  *.zip) cp "$PFS_TEST_ARCHIVE" "$output" ;;
  *) exit 2 ;;
esac
SH
cat >"$work/shims/ditto" <<'SH'
#!/bin/sh
touch "$PFS_TEST_EXTRACT_MARKER"
exit 77
SH
chmod +x "$work/shims/curl" "$work/shims/ditto"

run_case() {
  name=$1
  members=$2
  expected=$3
  archive="$work/$name.zip"
  marker="$work/$name-extraction-attempted"
  output="$work/$name.log"
  python3 - "$archive" "$members" <<'PY'
import stat
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1], "w") as archive:
    for member in sys.argv[2].split("|"):
        entry = zipfile.ZipInfo(member)
        entry.create_system = 3
        mode = stat.S_IFDIR | 0o755 if member.endswith("/") else stat.S_IFREG | 0o644
        entry.external_attr = mode << 16
        archive.writestr(entry, b"" if member.endswith("/") else b"fixture")
PY
  digest=$(shasum -a 256 "$archive" | awk '{ print $1 }')
  printf '%s  %s\n' "$digest" "$release_archive" >"$archive.sha256"
  status=0
  PFS_TEST_ARCHIVE="$archive" PFS_TEST_EXTRACT_MARKER="$marker" \
    PORTABLEFS_VERSION="v$version" PATH="$work/shims:$PATH" \
    sh "$repo_root/scripts/install.sh" >"$output" 2>&1 || status=$?
  [ "$status" -ne 0 ] || { echo "$name: installer unexpectedly succeeded" >&2; exit 1; }
  if [ "$expected" = reach ]; then
    [ -f "$marker" ] || { echo "$name: did not reach extraction boundary" >&2; cat "$output" >&2; exit 1; }
  else
    [ ! -e "$marker" ] || { echo "$name: unsafe ZIP reached extraction boundary" >&2; exit 1; }
    grep -F "$expected" "$output" >/dev/null || { echo "$name: wrong refusal" >&2; cat "$output" >&2; exit 1; }
  fi
  printf '%s: PASS\n' "$name"
}

run_case normal_directories 'PortableFS.app/|PortableFS.app/Contents/|PortableFS.app/Contents/file' reach
run_case repeated_root_slash 'PortableFS.app//' 'unsafe member name'
run_case repeated_nested_slash 'PortableFS.app/Contents//' 'unsafe member name'
run_case dot_component 'PortableFS.app/./Contents' 'unsafe member name'
run_case parent_component 'PortableFS.app/../escape' 'unsafe member name'
run_case absolute_member '/PortableFS.app/Contents' 'out-of-bundle member'
run_case outside_bundle 'elsewhere/file' 'out-of-bundle member'
run_case backslash_member 'PortableFS.app/Contents\file' 'unsafe member name'

if [ "$#" -gt 0 ]; then
  archive=$1
  [ -f "$archive" ] && [ -f "$archive.sha256" ] || {
    echo "signed archive and sidecar are required for the optional public-asset check" >&2
    exit 2
  }
  marker="$work/public-extraction-attempted"
  output="$work/public.log"
  status=0
  PFS_TEST_ARCHIVE="$archive" PFS_TEST_EXTRACT_MARKER="$marker" \
    PORTABLEFS_VERSION="v$version" PATH="$work/shims:$PATH" \
    sh "$repo_root/scripts/install.sh" >"$output" 2>&1 || status=$?
  [ "$status" -ne 0 ] && [ -f "$marker" ] || {
    echo "public signed archive did not reach extraction boundary" >&2
    cat "$output" >&2
    exit 1
  }
  printf '%s\n' 'public_signed_archive: PASS'
fi
