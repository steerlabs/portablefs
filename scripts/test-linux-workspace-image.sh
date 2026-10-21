#!/usr/bin/env bash
# Fault and namespace checks use only this invocation's disposable container.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo 'UNAVAILABLE: native-workspace-docker' >&2; exit 3; }
builder="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["builder"])' "$repo/deploy/linux-workspace/image.lock.json")"
name="portablefs-workspace-fault-$(uuidgen | tr '[:upper:]' '[:lower:]')"
trap 'docker rm --force "$name" >/dev/null 2>&1 || true' EXIT
docker run -i --name "$name" --platform linux/arm64 --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  -v "$repo/deploy/linux-workspace/rootfs/usr/local/libexec:/source:ro" "$builder" bash -s <<'TEST'
set -euo pipefail
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261001T000000Z/ trixie main\n' >/etc/apt/sources.list
find /etc/apt/sources.list.d -type f -delete
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 e2fsprogs util-linux >/tmp/install.log
source /source/portablefs-workspace-format
truncate -s 64G /tmp/data.ext4
printf 'PFS-WORKSPACE-DATA-8\n' >/tmp/header
dd if=/tmp/header of=/tmp/data.ext4 conv=notrunc status=none
python3 - <<'PY'
import os,signal,subprocess,time
p=subprocess.Popen(['mkfs.ext4','-q','-F','-L','portablefs-data','/tmp/data.ext4'])
deadline=time.monotonic()+5
while open('/tmp/data.ext4','rb').read(20).startswith(b'PFS-WORKSPACE-DATA-8'):
    assert p.poll() is None, 'mkfs completed before interrupted-format schedule'
    assert time.monotonic()<deadline, 'mkfs did not reach destructive writes'
    time.sleep(.001)
os.kill(p.pid,signal.SIGSTOP)
os.kill(p.pid,signal.SIGKILL)
p.wait()
assert p.returncode == -signal.SIGKILL
PY
if PFS_FORMAT_AUTHORIZED= format_workspace_disk /tmp/data.ext4; then exit 1; fi
PFS_FORMAT_AUTHORIZED=8 format_workspace_disk /tmp/data.ext4
e2fsck -fn /tmp/data.ext4
[[ "$(blkid -s LABEL -o value /tmp/data.ext4)" == portablefs-data ]]
echo 'PASS: interrupted-format-retries-only-with-host-authorization'
mkdir -p /tmp/workspaces
mount -t tmpfs -o mode=0755 tmpfs /tmp/workspaces
mkdir /tmp/workspaces/volume
chmod 000 /tmp/workspaces/volume
setpriv --reuid 1000 --regid 1000 --clear-groups sh -c 'test -x /tmp/workspaces && test ! -x /tmp/workspaces/volume && test ! -w /tmp/workspaces/volume'
mount -t tmpfs -o mode=0755 tmpfs /tmp/workspaces/volume
setpriv --reuid 1000 --regid 1000 --clear-groups sh -c 'test -x /tmp/workspaces/volume && test -r /tmp/workspaces/volume'
umount /tmp/workspaces/volume
setpriv --reuid 1000 --regid 1000 --clear-groups sh -c 'test ! -x /tmp/workspaces/volume'
umount /tmp/workspaces
echo 'PASS: per-volume-root-denied-unmounted-reachable-mounted'
TEST
