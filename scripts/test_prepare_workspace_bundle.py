#!/usr/bin/env python3
"""Hostile workflow-archive controls must fail before creating bundle paths."""
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('prepare_workspace', ROOT / 'scripts/prepare-workspace-bundle.py')
prepare_workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_workspace)


class ArchiveBoundary(unittest.TestCase):
    def test_hostile_members_cannot_write_outside_destination(self):
        names = ['kernel', 'initramfs', 'system.ext4', 'kernel.config', 'packages.json', 'packages.tsv',
                 'source-manifest.json', 'licenses.tar.gz', 'initramfs.inventory', 'image-inputs.json',
                 'release.json', 'bin/portablefs', 'bin/portablefsd', 'bin/portablefs-workspaced']
        for fault in ('valid', 'manifest traversal', 'archive traversal', 'symlink', 'duplicate', 'directory'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                artifact = root / 'artifact'; artifact.mkdir()
                manifest = {'format': 8, 'release': {'commit': 'a' * 40, 'app_version': '0.5.0', 'authority_major': 8},
                            'files': {}}
                (artifact / 'corresponding-source.tar.gz').write_bytes(b'source archive')
                payloads = {name: b'x' for name in names}
                payloads['source-manifest.json'] = json.dumps({'archive': prepare_workspace.digest(artifact / 'corresponding-source.tar.gz')}).encode()
                (artifact / 'source-manifest.json').write_bytes(payloads['source-manifest.json'])
                manifest['files'] = {name: {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for name, raw in payloads.items()}
                if fault == 'manifest traversal':
                    manifest['files']['../escape'] = manifest['files'].pop('kernel')
                (artifact / 'manifest.json').write_text(json.dumps(manifest))
                payloads['manifest.json'] = (artifact / 'manifest.json').read_bytes()
                with tarfile.open(artifact / 'guest-image.tar.gz', 'w:gz') as archive:
                    for name in [*manifest['files'], 'manifest.json']:
                        raw = payloads.get(name, b'x')
                        if fault == 'archive traversal' and name == 'kernel': name = '../escape'
                        member = tarfile.TarInfo(name)
                        member.size = len(raw)
                        if fault == 'symlink' and name == 'kernel':
                            member.type = tarfile.SYMTYPE; member.linkname = '../escape'; member.size = 0
                        if fault == 'directory' and name == 'kernel':
                            member.type = tarfile.DIRTYPE; member.size = 0
                        archive.addfile(member, io.BytesIO(raw) if member.isfile() else None)
                        if fault == 'duplicate' and name == 'kernel': archive.addfile(member, io.BytesIO(raw))
                distribution = {'format': 8, 'commit': 'a' * 40,
                                'assets': {name: prepare_workspace.digest(artifact / name) for name in
                                           ('manifest.json', 'source-manifest.json', 'corresponding-source.tar.gz', 'guest-image.tar.gz')}}
                (artifact / 'distribution.json').write_text(json.dumps(distribution))
                destination = root / 'bundle'
                if fault == 'valid':
                    # Source-coverage semantics have their independent real-image
                    # gate; this positive control isolates archive publication.
                    with patch.object(prepare_workspace, 'check'):
                        prepare_workspace.prepare(artifact, destination, 'a' * 40, '0.5.0')
                    self.assertTrue((destination / 'kernel').is_file())
                else:
                    expected = 'invalid exact image manifest' if fault == 'manifest traversal' else 'invalid guest archive'
                    with self.assertRaisesRegex(AssertionError, expected):
                        prepare_workspace.prepare(artifact, destination, 'a' * 40, '0.5.0')
                    self.assertFalse(destination.exists())
                self.assertFalse((root / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
