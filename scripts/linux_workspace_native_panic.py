"""A root-only panic trigger added solely to a disposable native test disk."""
import hashlib
import json
import pathlib
import subprocess
import tempfile
import uuid


def install_panic_fixture(image, evidence):
    image, evidence = pathlib.Path(image), pathlib.Path(evidence)
    original = json.loads((image / 'manifest.json').read_text())
    # Keep the product kernel, initramfs, command line and binaries. Only this
    # cloned disk gains a root service; no trigger enters the shipped overlay.
    unit = '''[Unit]
After=portablefs-workspace-bootstrap.service
[Service]
Type=simple
ExecStart=/bin/sh -c 'while ! test -f /home/workspace/.pfs-native-panic; do sleep .1; done; rm -f /home/workspace/.pfs-native-panic; sync -f /home/workspace; echo c > /proc/sysrq-trigger'
'''
    with tempfile.TemporaryDirectory(prefix='panic-fixture-', dir=evidence) as temporary:
        temporary = pathlib.Path(temporary)
        (temporary / 'panic.service').write_text(unit)
        (temporary / 'commands').write_text(
            'write /fixture/panic.service /etc/systemd/system/pfs-native-panic.service\n'
            'symlink /etc/systemd/system/multi-user.target.wants/pfs-native-panic.service /etc/systemd/system/pfs-native-panic.service\n')
        (temporary / 'install.sh').write_text('''set -eu
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261001T000000Z/ trixie main\\n' > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*
apt-get update -qq
apt-get install -y -qq --no-install-recommends e2fsprogs
debugfs -w -f /fixture/commands /image/system.ext4
debugfs -R 'stat /etc/systemd/system/pfs-native-panic.service' /image/system.ext4
debugfs -R 'stat /etc/systemd/system/multi-user.target.wants/pfs-native-panic.service' /image/system.ext4
''')
        builder = json.loads((image / 'image-inputs.json').read_text())['lock']['builder']
        name = 'pfs-16k-panic-fixture-' + uuid.uuid4().hex[:10]
        try:
            result = subprocess.run(['docker', 'run', '--name', name, '--memory', '512m', '--cpus', '1',
                '-v', str(image.resolve()) + ':/image', '-v', str(temporary.resolve()) + ':/fixture:ro',
                builder, 'bash', '/fixture/install.sh'],
                text=True, capture_output=True, timeout=180)
            (evidence / 'panic-fixture.log').write_text(result.stdout + result.stderr)
            assert result.returncode == 0 and 'File not found' not in result.stderr and 'not found' not in result.stderr, result
            assert 'Type: regular' in result.stdout and 'Type: symlink' in result.stdout, result
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, check=False, timeout=30)
    h = hashlib.sha256()
    with (image / 'system.ext4').open('rb') as disk:
        for block in iter(lambda: disk.read(4 << 20), b''): h.update(block)
    manifest = json.loads((image / 'manifest.json').read_text())
    manifest['files']['system.ext4']['sha256'] = h.hexdigest()
    (image / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (evidence / 'panic-fixture.json').write_text(json.dumps({
        'original_manifest': original, 'fixture_manifest': manifest,
        'root_service': unit, 'trigger': 'guest-only SysRq c (kernel BUG)'}, indent=2) + '\n')
