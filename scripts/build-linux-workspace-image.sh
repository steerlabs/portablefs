#!/usr/bin/env bash
# One clean commit produces the guest, notices and retained corresponding source.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 OUTPUT_DIRECTORY [--update-lock|--reuse]" >&2; exit 2; }
if [[ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
  echo 'refuse to label a dirty workspace image as HEAD' >&2; exit 1
fi
command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo 'UNAVAILABLE: native-workspace-docker' >&2; exit 3; }
mode="${2:-}"
[[ -z "$mode" || "$mode" == --update-lock || "$mode" == --reuse ]] || exit 2
mkdir -p "$1"
out="$(cd "$1" && pwd -P)"
lock="$repo/deploy/linux-workspace/image.lock.json"
builder="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["builder"])' "$lock")"
commit="$(git -C "$repo" rev-parse HEAD)"
if [[ "$mode" == --reuse && -f "$out/manifest.json" ]]; then
  python3 "$repo/deploy/linux-workspace/redistribute.py" check "$out"
  python3 - "$out/release.json" "$commit" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['commit'] == sys.argv[2], 'image is from another commit'
PY
  echo 'Reusing exact verified workspace image'
  exit 0
fi
[[ -z "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { echo 'output directory must be empty' >&2; exit 1; }
staging="$(mktemp -d "$out/.build.XXXXXX")"
name="portablefs-workspace-build-$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$staging"; }
trap cleanup EXIT
mkdir -p "$staging/bin"
version="$(cat "$repo/VERSION")"
for binary in portablefs portablefsd portablefs-workspaced; do
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C "$repo/vcs" build -trimpath -buildvcs=false \
    -ldflags="-buildid= -s -w -X main.version=$version" -o "$staging/bin/$binary" "./cmd/$binary"
done
python3 "$repo/deploy/linux-workspace/identity.py" "$repo" "$staging" "$commit"
python3 "$repo/deploy/linux-workspace/redistribute.py" prepare "$repo" "$staging"
docker run --name "$name" --platform linux/arm64 --memory 4g --cpus 4 \
  --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  -e "PFS_UPDATE_LOCK=$mode" -v "$repo/deploy/linux-workspace:/source:ro" -v "$staging:/output" \
  "$builder" bash /source/build-guest.sh
python3 - "$lock" "$staging" "$mode" <<'PY'
import json,pathlib,sys
lock,out=map(pathlib.Path,sys.argv[1:3])
value=json.loads(lock.read_text())
packages=json.loads((out/'packages.json').read_text())
sources=json.loads((out/'source-manifest.json').read_text())['debian']
if sys.argv[3] == '--update-lock':
    value['packages'],value['sources']=packages,sources
    lock.write_text(json.dumps(value,indent=2)+'\n')
else:
    assert value['packages'] == packages, 'exact package inventory differs from image.lock.json'
    assert value['sources'] == sources, 'exact source inventory differs from image.lock.json'
PY
python3 "$repo/deploy/linux-workspace/redistribute.py" check "$staging"
rm -rf "$staging/sources" "$staging/notices" "$staging/go-sources.json" "$staging/go-notices"
python3 "$repo/deploy/linux-workspace/distribute.py" "$staging"
for path in "$staging"/*; do mv "$path" "$out/"; done
echo "PASS: release guest and retained source: $out"
