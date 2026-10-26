#!/usr/bin/env python3
"""Consume only the paired guest-arm64 workflow artifact, before code signing."""
import argparse
import json
import os
import pathlib
import shutil
import sys
import tarfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy/linux-workspace'))
from redistribute import check, digest

if os.environ.get('PORTABLEFS_GO'):
    os.environ['PATH'] = str(pathlib.Path(os.environ['PORTABLEFS_GO']).parent) + os.pathsep + os.environ.get('PATH', '')


def prepare(artifact, destination, commit, version):
    manifest = json.loads((artifact / 'manifest.json').read_text())
    distribution = json.loads((artifact / 'distribution.json').read_text())
    assert distribution['format'] == 8 and distribution['commit'] == commit, 'distribution commit mismatch'
    for name, record in distribution['assets'].items():
        assert name in {'guest-image.tar.gz', 'corresponding-source.tar.gz', 'manifest.json', 'source-manifest.json'}, 'unexpected distribution asset'
        assert digest(artifact / name) == record, 'distribution asset mismatch: ' + name
    assert set(distribution['assets']) == {'guest-image.tar.gz', 'corresponding-source.tar.gz', 'manifest.json', 'source-manifest.json'}
    assert manifest['release']['commit'] == commit, 'guest image is from another commit'
    assert manifest['release']['app_version'] == version, 'guest image is from another version'
    assert manifest['release']['authority_major'] == manifest['format'] == 8
    assert not destination.exists(), 'bundle image destination must be absent'
    records = dict(manifest['files'])
    records['manifest.json'] = digest(artifact / 'manifest.json')
    # Validate every member before writing any path. The archive has only exact
    # regular files; no directory, duplicate, link or PAX path can add a member.
    with tarfile.open(artifact / 'guest-image.tar.gz', 'r:gz') as archive:
        members = archive.getmembers()
        assert len(members) == len(records) and {m.name for m in members} == set(records), 'invalid guest archive membership'
        assert all(m.isfile() and m.size == records[m.name]['size'] for m in members), 'invalid guest archive type/size'
        needed = sum(r['size'] for r in records.values()) + (2 << 30)
        assert shutil.disk_usage(destination.parent).free >= needed, 'Not enough disk space'
        destination.mkdir()
        try:
            for member in members:
                path = destination / member.name
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output, 4 << 20)
                assert digest(path) == records[member.name], 'Workspace image failed verification: ' + member.name
            # Source coverage requires the actual corresponding source bytes,
            # which are checked here but remain a separate release asset.
            source = destination / 'corresponding-source.tar.gz'
            source.symlink_to((artifact / 'corresponding-source.tar.gz').resolve())
            try:
                check(destination)
            finally:
                source.unlink()
            assert json.loads((destination / 'source-manifest.json').read_text())['archive'] == digest(artifact / 'corresponding-source.tar.gz')
        except BaseException:
            shutil.rmtree(destination)
            raise
    return records['manifest.json']['sha256']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=pathlib.Path)
    parser.add_argument('destination', type=pathlib.Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    print(prepare(args.artifact, args.destination, args.commit, args.version))
