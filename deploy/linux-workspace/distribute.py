"""Package the immutable guest separately from its retained source archive."""
import gzip
import json
import pathlib
import sys
import tarfile
from redistribute import digest, write

out = pathlib.Path(sys.argv[1])
manifest = json.loads((out / 'manifest.json').read_text())
names = sorted([*manifest['files'], 'manifest.json'])
epoch = json.loads((out / 'image-inputs.json').read_text())['lock']['source_date_epoch']
with (out / 'guest-image.tar.gz').open('wb') as raw:
    with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=6) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.GNU_FORMAT) as tar:
            for name in names:
                path = out / name
                info = tar.gettarinfo(str(path), name)
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = epoch
                info.mode = 0o755 if name.startswith('bin/') else 0o644
                with path.open('rb') as f:
                    tar.addfile(info, f)
expanded = sum((out / name).stat().st_size for name in names)
compressed = (out / 'guest-image.tar.gz').stat().st_size
write(out / 'distribution.json', {
    'format': 8, 'commit': manifest['release']['commit'],
    'assets': {name: digest(out / name) for name in ('guest-image.tar.gz', 'corresponding-source.tar.gz', 'manifest.json', 'source-manifest.json')},
    'space': {
        'compressed_image_bytes': compressed,
        'expected_compressed_installer_delta_bytes': compressed,
        'expanded_image_bytes': expanded,
        'peak_extraction_bytes': compressed + expanded,
        'peak_same_size_update_bytes': compressed + 2 * expanded,
        'additional_free_bytes': compressed + expanded + (2 << 30),
        'initial_data_reserve_bytes': 2 << 30,
        'data_disk_logical_bytes': 64 << 30,
    },
})
