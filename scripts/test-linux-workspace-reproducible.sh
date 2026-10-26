#!/usr/bin/env bash
# Independent rootfs builds: no reused guest, container, or retained sources.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
[[ $# == 1 ]] || { echo "usage: $0 EVIDENCE_DIRECTORY" >&2; exit 2; }
mkdir -p "$1"
out="$(cd "$1" && pwd -P)"
for run in first second; do
  bash "$repo/scripts/build-linux-workspace-image.sh" "$out/$run"
done
python3 - "$out" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); first=root/'first'; second=root/'second'
names=sorted(str(p.relative_to(first)) for p in first.rglob('*') if p.is_file())
assert names == sorted(str(p.relative_to(second)) for p in second.rglob('*') if p.is_file())
proof={}
for name in names:
    hashes=[]
    for directory in (first,second):
        h=hashlib.sha256()
        with (directory/name).open('rb') as f:
            for block in iter(lambda:f.read(4<<20),b''): h.update(block)
        hashes.append(h.hexdigest())
    assert hashes[0] == hashes[1], 'nonreproducible output: '+name
    proof[name]=hashes[0]
(root/'reproducibility.json').write_text(json.dumps({'commit':json.loads((first/'release.json').read_text())['commit'],'identical_outputs':proof},indent=2)+'\n')
print('PASS: two independent builds, every output byte-identical')
PY
