#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
snapshot=20261001T000000Z
export SOURCE_DATE_EPOCH=1790812800
export E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH"
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ trixie main\n' "$snapshot" >/etc/apt/sources.list
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ trixie-updates main\n' "$snapshot" >>/etc/apt/sources.list
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ trixie-security main\n' "$snapshot" >>/etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*
apt-get update
apt-get install -y --no-install-recommends mmdebstrap ca-certificates python3 e2fsprogs
mkdir -p /build
rm -rf /build/rootfs
includes="$(python3 -c 'import json;print(",".join(json.load(open("/source/image.lock.json"))["include"]))')"
mmdebstrap --mode=root --architectures=arm64 --variant=minbase --include="$includes" \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  trixie /build/rootfs "deb https://snapshot.debian.org/archive/debian/$snapshot/ trixie main" \
  "deb https://snapshot.debian.org/archive/debian/$snapshot/ trixie-updates main" \
  "deb https://snapshot.debian.org/archive/debian-security/$snapshot/ trixie-security main"
root=/build/rootfs
cp -a /source/rootfs/. "$root/"
install -m755 /output/bin/* "$root/usr/local/bin/"
install -Dm644 /output/release.json "$root/usr/lib/portablefs-workspace/release.json"
chroot "$root" groupadd -g 1000 workspace
chroot "$root" useradd -u 1000 -g 1000 -d /home/workspace -s /bin/bash workspace
# Password login is disabled, but OpenSSH also refuses a locked account.
chroot "$root" usermod -p '*' workspace
rm -f "$root/etc/ssh/ssh_host_"* "$root/etc/machine-id" "$root/var/lib/dbus/machine-id"
touch "$root/etc/machine-id"
mkdir -p "$root/data" "$root/workspaces" "$root/home/workspace"
chmod 0755 "$root/workspaces"
printf 'portablefs-workspace\n' >"$root/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 portablefs-workspace\n::1 localhost ip6-localhost ip6-loopback\n' >"$root/etc/hosts"
mkdir -p "$root/etc/systemd/resolved.conf.d"
printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' >"$root/etc/systemd/resolved.conf.d/workspace.conf"
mkdir -p "$root/usr/share/doc/portablefs-go"
cp -a /output/go-notices/. "$root/usr/share/doc/portablefs-go/"
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
[[ "$kernel" == 6.12.* ]]
chroot "$root" update-initramfs -u -k "$kernel"
cp "$root/boot/vmlinuz-$kernel" /output/kernel
python3 - <<'PYKERNEL'
with open('/output/kernel','rb') as f:
    header=f.read(64)
assert header[56:60] == b'ARM\x64', 'expected uncompressed Debian arm64 Image'
PYKERNEL
cp "$root/boot/initrd.img-$kernel" /output/initramfs
cp "$root/boot/config-$kernel" /output/kernel.config
chroot "$root" dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Built-Using}\t${Static-Built-Using}\n' > /output/packages.tsv
python3 - <<'PY'
import json,re,urllib.parse
rows = [line.rstrip('\n').split('\t') for line in open('/output/packages.tsv')]
open('/output/packages.json','w').write(json.dumps([dict(zip(('package','version','source','source_version','built_using','static_built_using'),r)) for r in rows],indent=2)+'\n')
sources = set((row[2], row[3]) for row in rows)
for row in rows:
    for field in row[4:]:
        for name,version in re.findall(r'([a-z0-9+.-]+) \(= ([^)]+)\)', field): sources.add((name,version))
sources = sorted(sources)
open('/output/source-manifest.json','w').write(json.dumps({'format':8, 'snapshot':'20261001T000000Z', 'sources':[{'package':name,'version':version,'archive':'https://snapshot.debian.org/package/'+urllib.parse.quote(name,safe='')+'/'+urllib.parse.quote(version,safe='')+'/'} for name,version in sources]},indent=2)+'\n')
PY
find "$root/usr/share/doc" \( -name copyright -o -path "$root/usr/share/doc/portablefs-go/*" -type f \) -printf '%P\0' | sort -z | \
  tar -C "$root/usr/share/doc" --null -T - --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 -czf /output/licenses.tar.gz
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
