#!/usr/bin/env bash
# Boot only the qualification test binary against the pinned product kernel.
# The product service and its lifetime RTC opening never run a benchmark.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
image="$1" evidence="$2"
work="$(mktemp -d "$evidence/rtc-initramfs.XXXXXX")"
trap 'rm -rf "$work"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C "$repo/vcs" test -c -o "$work/init" ./internal/workspaceclock
python3 - "$work" <<'PY'
import gzip,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); archive=bytearray()
def entry(name, mode, data=b'', major=0, minor=0):
    name=name.encode()+b'\0'
    fields=[1,mode,0,0,1,0,len(data),0,0,major,minor,len(name),0]
    archive.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in fields)+name)
    archive.extend(b'\0'*(-len(archive)%4)); archive.extend(data)
    archive.extend(b'\0'*(-len(archive)%4))
for name in ('dev','proc','sys'): entry(name,stat.S_IFDIR|0o755)
entry('dev/console',stat.S_IFCHR|0o600,major=5,minor=1)
entry('init',stat.S_IFREG|0o755,(root/'init').read_bytes())
entry('TRAILER!!!',0)
(root/'initramfs').write_bytes(gzip.compress(archive,mtime=0))
PY
swiftc -swift-version 5 "$repo/scripts/test-linux-workspace-rtc.swift" -o "$work/rtc-vm"
codesign --force --sign - --entitlements "$repo/deploy/linux-workspace/dev.entitlements" "$work/rtc-vm"
"$work/rtc-vm" "$image/kernel" "$work/initramfs" >"$evidence/rtc-contention-console.log" 2>&1
python3 - "$evidence" "$image" <<'PY'
import hashlib,json,os,pathlib,sys
root,image=map(pathlib.Path,sys.argv[1:])
lines=(root/'rtc-contention-console.log').read_text().splitlines()
results=[json.loads(line.split('RTC_QUALIFICATION=',1)[1]) for line in lines if line.startswith('RTC_QUALIFICATION=')]
assert len(results)==1 and 'PASS: rtc-contention-qualification' in lines
result=results[0]
result['vm']='fixture'
result['pause_seconds_before_reference_collection']=2
assert result['read_only'] and result['second_open_busy']
assert result['readers']==8 and result['samples']==8000
assert result['maximum_ns']<=250_000_000
result['kernel_sha256']=hashlib.sha256((image/'kernel').read_bytes()).hexdigest()
result['image_manifest_sha256']=hashlib.sha256((image/'manifest.json').read_bytes()).hexdigest()
resume=[json.loads(line.split('RTC_RESUME_QUALIFICATION=',1)[1]) for line in lines if line.startswith('RTC_RESUME_QUALIFICATION=')]
assert len(resume)==1 and resume[0]['operation_prestarted'] and not resume[0]['host_round_trip_after_resume']
assert resume[0]['read_age_ns']<=250_000_000
resume[0]['vm']='fixture'
resume[0]['pause_seconds_before_reference_collection']=2
(root/'rtc-first-resume.json').write_text(json.dumps(resume[0],indent=2)+'\n')
nts=[json.loads(line.split('RTC_NTS_REFERENCE=',1)[1]) for line in lines if line.startswith('RTC_NTS_REFERENCE=')]
if os.environ.get('PFS_RTC_NTS_REFERENCE'):
    assert len(nts)==1, 'missing authenticated first-resume reference evidence'
if nts:
    assert len(nts)==1
    nts[0]['vm']='fixture'
    nts[0]['pause_seconds_before_reference_collection']=2
    (root/'rtc-nts-reference.json').write_text(json.dumps(nts[0],indent=2)+'\n')
(root/'rtc-contention.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS: native-rtc-contention-qualification')
PY
