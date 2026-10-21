#!/usr/bin/env bash
# Developer guest only. Release insertion of attested client bytes is Stage 2.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 OUTPUT_DIRECTORY [--update-lock|--reuse]" >&2; exit 2; }
out="$1"
update="${2:-}"
[[ -z "$update" || "$update" == --update-lock || "$update" == --reuse ]] || exit 2
mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
lock="$repo/deploy/linux-workspace/image.lock.json"
builder="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["builder"])' "$lock")"
old_digest="$(python3 -c 'import json,sys,pathlib;p=pathlib.Path(sys.argv[1]);print(json.loads(p.read_text())["image_digest"] if p.exists() else "")' "$out/release.json")"
mkdir -p "$out/bin"
commit="$(git -C "$repo" rev-parse HEAD)"
for binary in portablefs portablefsd portablefs-workspaced; do
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C "$repo/vcs" build -trimpath -buildvcs=false -ldflags="-buildid= -s -w" -o "$out/bin/$binary" "./cmd/$binary"
done
python3 "$repo/deploy/linux-workspace/identity.py" "$repo" "$out" "$commit"
if [[ "$update" == --reuse && -f "$out/manifest.json" ]]; then
  if python3 - "$lock" "$out" "$old_digest" <<'PYREUSE'
import json, pathlib, sys
p=pathlib.Path(sys.argv[2])
assert json.loads((p/'release.json').read_text())['image_digest'] == sys.argv[3]
assert json.load(open(sys.argv[1]))['packages'] == json.loads((p/'packages.json').read_text())
PYREUSE
  then
    echo "Reusing exact pinned workspace image: $old_digest"
    exit 0
  fi
fi
inputs="$(mktemp -d "$out/.build-inputs.XXXXXX")"
cp -R "$repo/deploy/linux-workspace/." "$inputs/"
python3 "$inputs/identity.py" "$repo" "$out" "$commit" "$inputs"
name="portablefs-workspace-build-$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$inputs"; }
trap cleanup EXIT
docker run --name "$name" --platform linux/arm64 --privileged \
  -v "$inputs:/source:ro" -v "$out:/output" \
  "$builder" bash /source/build-guest.sh
python3 - "$lock" "$out" "$update" <<'PY'
import json, pathlib, sys
lock, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
value = json.loads(lock.read_text())
packages = json.loads((out / 'packages.json').read_text())
if sys.argv[3] == '--update-lock':
    value['packages'] = packages
    lock.write_text(json.dumps(value, indent=2) + '\n')
else:
    if not value['packages'] or value['packages'] != packages:
        raise SystemExit('exact package inventory differs from image.lock.json')
PY
