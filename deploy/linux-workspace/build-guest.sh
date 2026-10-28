#!/bin/bash
set -euo pipefail
trap 'chown -R "$PFS_OUTPUT_UID:$PFS_OUTPUT_GID" /output' EXIT
export DEBIAN_FRONTEND=noninteractive
snapshot=20261001T000000Z
export SOURCE_DATE_EPOCH=1790812800
export LC_ALL=C.UTF-8 TZ=UTC
export E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH"
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ trixie main\n' "$snapshot" >/etc/apt/sources.list
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ trixie-updates main\n' "$snapshot" >>/etc/apt/sources.list
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ trixie-security main\n' "$snapshot" >>/etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*
apt-get update
apt-get install -y --no-install-recommends mmdebstrap ca-certificates python3 e2fsprogs
security_snapshot="$(python3 -c 'import json;print(json.load(open("/source/image.lock.json"))["security_snapshot"])')"
mkdir -p /build
rm -rf /build/rootfs
# Retain the base snapshot and its security packages while selecting the kernel
# from a newer security snapshot. Pin every locked version before bootstrap so
# an unrelated security update cannot silently change the image inventory.
python3 - <<'PYPINS'
import json,pathlib
lock=json.load(open('/source/image.lock.json'))
pathlib.Path('/build/preferences').write_text(''.join(
    'Package: '+p['package']+'\nPin: version '+p['version']+'\nPin-Priority: 1001\n\n'
    for p in lock['packages']))
PYPINS
includes="$(python3 -c 'import json;print(",".join(json.load(open("/source/image.lock.json"))["include"]))')"
mmdebstrap --mode=root --architectures=arm64 --variant=minbase --include="$includes" \
  --setup-hook='cp /build/preferences "$1/etc/apt/preferences.d/portablefs-workspace"' \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  trixie /build/rootfs "deb https://snapshot.debian.org/archive/debian/$snapshot/ trixie main" \
  "deb https://snapshot.debian.org/archive/debian/$snapshot/ trixie-updates main" \
  "deb https://snapshot.debian.org/archive/debian-security/$snapshot/ trixie-security main" \
  "deb https://snapshot.debian.org/archive/debian-security/$security_snapshot/ trixie-security main"
root=/build/rootfs
# Debian's machine-id, Python bytecode headers, initramfs and ext4 metadata must
# describe the inputs, never the build container's hostname or wall time.
export SOURCE_DATE_EPOCH E2FSPROGS_FAKE_TIME

cp -a --no-preserve=ownership /source/rootfs/. "$root/"
install -m755 /output/bin/* "$root/usr/local/bin/"
install -Dm644 /output/release.json "$root/usr/lib/portablefs-workspace/release.json"
chroot "$root" groupadd -g 1000 workspace
chroot "$root" useradd -u 1000 -g 1000 -d /home/workspace -s /bin/bash workspace
# Password login is disabled, but OpenSSH also refuses a locked account.
chroot "$root" usermod -p '*' workspace
chroot "$root" chage -d 2026-10-01 workspace
rm -f "$root/etc/ssh/ssh_host_"* "$root/etc/machine-id" "$root/var/lib/dbus/machine-id"
touch "$root/etc/machine-id"
mkdir -p "$root/data" "$root/workspaces" "$root/home/workspace"
chmod 0755 "$root/workspaces"
printf 'portablefs-workspace\n' >"$root/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 portablefs-workspace\n::1 localhost ip6-localhost ip6-loopback\n' >"$root/etc/hosts"
mkdir -p "$root/etc/systemd/resolved.conf.d"
printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' >"$root/etc/systemd/resolved.conf.d/workspace.conf"
mkdir -p "$root/usr/share/doc/portablefs-go"
cp -R /output/go-notices/. "$root/usr/share/doc/portablefs-go/"
cat >"$root/etc/fstab" <<'EOF'
/dev/vda / ext4 ro 0 0
tmpfs /tmp tmpfs mode=1777,nosuid,nodev 0 0
tmpfs /var tmpfs mode=0755,nosuid,nodev 0 0
tmpfs /workspaces tmpfs mode=0755,nosuid,nodev 0 0
EOF
ln -sf /run/systemd/resolve/stub-resolv.conf "$root/etc/resolv.conf"
# This guest has one explicit vsock SSH socket after VM-bound provisioning.
mkdir -p "$root/etc/systemd/system-generators"
ln -s /dev/null "$root/etc/systemd/system-generators/systemd-ssh-generator"
chroot "$root" systemctl disable ssh.service ssh.socket apt-daily.timer apt-daily-upgrade.timer
chroot "$root" systemctl mask ssh.service ssh.socket systemd-remount-fs.service serial-getty@hvc0.service getty@tty1.service
chroot "$root" systemctl enable portablefs-workspace-bootstrap.service portablefs-workspaced.service portablefs-workspace-ssh.socket systemd-networkd.service systemd-resolved.service
kernel="$(basename "$(find "$root/lib/modules" -mindepth 1 -maxdepth 1 -type d)")"
[[ "$kernel" == "$(python3 -c 'import json;print(json.load(open("/source/image.lock.json"))["kernel_release"])')" ]]
chroot "$root" update-initramfs -u -k "$kernel"
cp "$root/boot/vmlinuz-$kernel" /output/kernel
python3 - <<'PYKERNEL'
with open('/output/kernel','rb') as f:
    header=f.read(64)
assert header[56:60] == b'ARM\x64', 'expected uncompressed Debian arm64 Image'
assert (int.from_bytes(header[24:32], 'little') >> 1) & 3 == 2, 'expected 16 KiB arm64 Image'
PYKERNEL
cp "$root/boot/initrd.img-$kernel" /output/initramfs
cp "$root/boot/config-$kernel" /output/kernel.config
python3 - <<'PYPAGES'
assert "CONFIG_ARM64_16K_PAGES=y\n" in open("/output/kernel.config").read(), "expected 16 KiB kernel config"
PYPAGES
chroot "$root" dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Built-Using}\t${Static-Built-Using}\n' > /output/packages.tsv
python3 - <<'PYINVENTORY'
import json,os,pathlib
lock=json.load(open('/source/image.lock.json'))
rows=[line.rstrip('\n').split('\t') for line in open('/output/packages.tsv')]
packages=[dict(zip(('package','version','source','source_version','built_using','static_built_using'),r)) for r in rows]
if os.environ.get('PFS_UPDATE_LOCK') != '--update-lock':
    assert packages == lock['packages'], 'exact binary package inventory differs from lock'
PYINVENTORY
python3 /source/redistribute.py collect "$root" /output /source/image.lock.json
if [[ "$PFS_UPDATE_LOCK" == --update-lock ]]; then exit 0; fi
chroot "$root" lsinitramfs "/boot/initrd.img-$kernel" >/output/initramfs.inventory
python3 - <<'PYMODULES'
import re
config = open('/output/kernel.config').read()
inventory = open('/output/initramfs.inventory').read()
for module, symbol in {'virtio_blk':'VIRTIO_BLK', 'virtio_net':'VIRTIO_NET', 'virtio_console':'VIRTIO_CONSOLE', 'vmw_vsock_virtio_transport':'VIRTIO_VSOCKETS', 'virtio_rng':'HW_RANDOM_VIRTIO', 'fuse':'FUSE_FS', 'ext4':'EXT4_FS'}.items():
    if 'CONFIG_' + symbol + '=y\n' in config:
        continue
    assert 'CONFIG_' + symbol + '=m\n' in config, symbol
    assert re.search('/' + module.replace('_', '[-_]') + r'\.ko(?:\.xz)?$', inventory, re.M), module
PYMODULES
rm -f "$root/var/lib/systemd/random-seed" "$root/etc/.pwd.lock" "$root/var/cache/ldconfig/aux-cache"
python3 - "$root" <<'PYACCOUNTS'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1])
path=root/'etc/shadow'
rows=[line.split(':') for line in path.read_text().splitlines()]
for row in rows:
    row[2]=str(int(os.environ['SOURCE_DATE_EPOCH'])//86400)
path.write_text(''.join(':'.join(row)+'\n' for row in rows))
for name in ('passwd-', 'shadow-', 'group-', 'gshadow-'):
    (root/'etc'/name).unlink(missing_ok=True)
PYACCOUNTS
rm -rf "$root/var/lib/apt/lists/"* "$root/var/cache/apt/archives/"* "$root/var/log/"*
find "$root" -xdev -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
rm -f /output/system.ext4
truncate -s 3G /output/system.ext4
mkfs.ext4 -q -F -U 884903af-1192-489e-b360-f68f4f4bc408 -L pfs-system \
  -E lazy_itable_init=0,lazy_journal_init=0,hash_seed=884903af-1192-489e-b360-f68f4f4bc408 \
  -d "$root" /output/system.ext4
e2fsck -fn /output/system.ext4
python3 - <<'PY'
import hashlib,json,pathlib
p=pathlib.Path('/output')
names=['kernel','initramfs','system.ext4','kernel.config','packages.json','packages.tsv','source-manifest.json','licenses.tar.gz','initramfs.inventory','image-inputs.json','release.json','bin/portablefs','bin/portablefsd','bin/portablefs-workspaced']
files={}
for name in names:
    h=hashlib.sha256()
    with (p/name).open('rb') as f:
        for block in iter(lambda:f.read(4*1024*1024), b''): h.update(block)
    files[name]={'sha256':h.hexdigest(),'size':(p/name).stat().st_size}
manifest={'format':8,'release':json.loads((p/'release.json').read_text()),'files':files}
(p/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
PY

python3 /source/distribute.py /output
