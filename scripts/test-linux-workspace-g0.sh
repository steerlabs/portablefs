#!/usr/bin/env bash
# Native injected schedules; guest image/kernel provenance remains explicit.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
image="$1" evidence="$2"
work="$(mktemp -d "$evidence/g0-initramfs.XXXXXX")"
trap 'rm -rf "$work"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C "$repo/vcs" test -c -o "$work/init" ./internal/fusev3
python3 - "$work" <<'PY'
import gzip,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); archive=bytearray()
def entry(name,mode,data=b'',major=0,minor=0):
 name=name.encode()+b'\0'; fields=[1,mode,0,0,1,0,len(data),0,0,major,minor,len(name),0]
 archive.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in fields)+name)
 archive.extend(b'\0'*(-len(archive)%4));archive.extend(data);archive.extend(b'\0'*(-len(archive)%4))
for name in ('dev','proc','sys','tmp','run'):entry(name,stat.S_IFDIR|0o755)
entry('dev/console',stat.S_IFCHR|0o600,major=5,minor=1)
entry('entropy',stat.S_IFREG|0o400,os.urandom(64))
entry('init',stat.S_IFREG|0o755,(root/'init').read_bytes());entry('TRAILER!!!',0)
(root/'initramfs').write_bytes(gzip.compress(archive,mtime=0))
PY
swiftc -swift-version 5 "$repo/scripts/test-linux-workspace-g0.swift" -o "$work/g0-vm"
codesign --force --sign - --entitlements "$repo/deploy/linux-workspace/dev.entitlements" "$work/g0-vm"
"$work/g0-vm" "$image/kernel" "$work/initramfs" >"$evidence/g0-native-console.log" 2>&1
python3 - "$evidence" "$image" <<'PY'
import hashlib,json,pathlib,sys
root,image=map(pathlib.Path,sys.argv[1:]); lines=(root/'g0-native-console.log').read_text().splitlines()
records=[json.loads(v.split('G0_NATIVE_CASE=',1)[1]) for v in lines if v.startswith('G0_NATIVE_CASE=')]
assert len(records)==55 and len({v['case'] for v in records})==55 and all(v['pass'] for v in records)
assert all(v['no_host_round_trip_after_resume'] and v['rpc_delta']==0 for v in records)
assert any(v=='G0_NATIVE_DONE=0' for v in lines)
(root/'g0-native.json').write_text(json.dumps(dict(image_manifest_sha256=hashlib.sha256((image/'manifest.json').read_bytes()).hexdigest(),cases=records),indent=2)+'\n')
print('PASS: native G0 injected schedules (55 exact cases)')
PY
