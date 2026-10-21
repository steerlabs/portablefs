#!/usr/bin/env bash
# Developer guest only. Release insertion of attested client bytes is Stage 2.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
[[ $# -ge 1 && $# -le 2 ]] || { echo "usage: $0 OUTPUT_DIRECTORY [--update-lock|--reuse]" >&2; exit 2; }
if [[ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]]; then
  echo 'refuse to label a dirty workspace image as HEAD' >&2; exit 1
fi
command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo 'UNAVAILABLE: native-workspace-docker' >&2; exit 3; }
out="$1"
update="${2:-}"
[[ -z "$update" || "$update" == --update-lock || "$update" == --reuse ]] || exit 2
mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
lock="$repo/deploy/linux-workspace/image.lock.json"
builder="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["builder"])' "$lock")"
# Build into private staging so --reuse never rewrites verified output.
staging="$(mktemp -d "$out/.identity.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/bin" "$staging/go-notices"
commit="$(git -C "$repo" rev-parse HEAD)"
for binary in portablefs portablefsd portablefs-workspaced; do
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C "$repo/vcs" build -trimpath -buildvcs=false -ldflags="-buildid= -s -w" -o "$staging/bin/$binary" "./cmd/$binary"
done
python3 "$repo/deploy/linux-workspace/identity.py" "$repo" "$staging" "$commit"
if [[ "$update" == --reuse && -f "$out/manifest.json" ]]; then
  if python3 - "$lock" "$out" "$staging" <<'PYREUSE'
import hashlib,json,pathlib,sys
p,q=map(pathlib.Path,sys.argv[2:])
assert (p/'image-inputs.json').read_bytes() == (q/'image-inputs.json').read_bytes()
assert json.load(open(sys.argv[1]))['packages'] == json.loads((p/'packages.json').read_text())
for name,record in json.loads((p/'manifest.json').read_text())['files'].items():
    path=p/name
    assert path.stat().st_size==record['size']
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(4*1024*1024),b''): h.update(block)
    assert h.hexdigest()==record['sha256']
PYREUSE
  then
    echo 'Reusing exact verified workspace image'
    exit 0
  fi
fi
cp -R "$staging/bin" "$out/"
cp "$staging/image-inputs.json" "$staging/release.json" "$out/"
# Notices for the exact linked Go module graph accompany Debian's copyrights.
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C "$repo/vcs" list -m -json all >"$staging/modules.json"
python3 - "$staging" "$repo" <<'PYNOTICES'
import json,pathlib,shutil,sys
p=pathlib.Path(sys.argv[1]); raw=(p/'modules.json').read_text(); decoder=json.JSONDecoder(); modules=[]
while raw.strip():
    value,end=decoder.raw_decode(raw.lstrip()); raw=raw.lstrip()[end:]; modules.append(value)
for module in modules:
    source=pathlib.Path(module.get('Replace',module).get('Dir',sys.argv[2]+'/vcs'))
    dest=p/'go-notices'/module['Path']; dest.mkdir(parents=True,exist_ok=True)
    if module.get('Main'): source=pathlib.Path(sys.argv[2])
    for name in ('LICENSE','LICENSE.txt','COPYING','NOTICE','PATENTS'):
        if (source/name).is_file(): shutil.copyfile(source/name,dest/name)
(p/'go-notices'/'modules.json').write_text(json.dumps(modules,indent=2)+'\n')
PYNOTICES
rm -rf "$out/go-notices"
cp -R "$staging/go-notices" "$out/"
inputs="$(mktemp -d "$out/.build-inputs.XXXXXX")"
cp -R "$repo/deploy/linux-workspace/." "$inputs/"
python3 "$inputs/identity.py" "$repo" "$out" "$commit" "$inputs"
name="portablefs-workspace-build-$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$inputs" "$staging"; }
trap cleanup EXIT
docker run --name "$name" --platform linux/arm64 --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
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
