"""Noncircular image identity: exact lock inputs, overlay and binary hashes.

The final manifest additionally binds the generated disk/kernel/initramfs bytes.
"""
import hashlib
import json
import pathlib
import sys

repo, out = map(pathlib.Path, sys.argv[1:3])
source = pathlib.Path(sys.argv[4]) if len(sys.argv) > 4 else repo / 'deploy/linux-workspace'
lock = json.loads((source / 'image.lock.json').read_text())
# Inventory is verified separately; refreshing it cannot alter the input digest.
lock.pop('packages')
files = {}
for path in sorted(source.rglob('*')):
    if path.is_file() and path.name != 'image.lock.json':
        files[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
for path in sorted((out / 'bin').iterdir()):
    files['bin/' + path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
identity = {'format': 8, 'app_version': 'dev', 'commit': sys.argv[3], 'lock': lock, 'files': files}
raw = json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()
(out / 'image-inputs.json').write_bytes(raw)
release = {'app_version': 'dev', 'commit': sys.argv[3], 'image_digest': hashlib.sha256(raw).hexdigest(), 'authority_major': 8}
(out / 'release.json').write_text(json.dumps(release, sort_keys=True) + '\n')
