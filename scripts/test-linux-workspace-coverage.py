#!/usr/bin/env python3
"""Reseal deliberate omissions so the semantic checker must reject them."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

repo = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'deploy/linux-workspace'))
from redistribute import digest, write

original = pathlib.Path(sys.argv[1]).resolve()
for field, expected in [('debian', 'incomplete Debian source coverage'), ('notices', 'incomplete Debian notice coverage')]:
    with tempfile.TemporaryDirectory(prefix='coverage-', dir=original.parent) as temp:
        out = pathlib.Path(temp)
        manifest = json.loads((original / 'manifest.json').read_text())
        for name in [*manifest['files'], 'corresponding-source.tar.gz']:
            dest = out / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if name != 'source-manifest.json':
                os.link(original / name, dest)
        sources = json.loads((original / 'source-manifest.json').read_text())
        if field == 'debian':
            sources[field].pop()
        else:
            del sources[field][next(iter(sources[field]))]
        write(out / 'source-manifest.json', sources)
        manifest['files']['source-manifest.json'] = digest(out / 'source-manifest.json')
        write(out / 'manifest.json', manifest)
        result = subprocess.run([sys.executable, str(repo / 'scripts/check-linux-workspace-image.py'), str(out)], capture_output=True, text=True)
        assert result.returncode != 0 and expected in result.stderr, result.stdout + result.stderr
        print('PASS: resealed missing ' + field + ' fails: ' + expected)
