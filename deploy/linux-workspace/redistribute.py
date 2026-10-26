"""Retain and check the corresponding source for one exact protocol-8 guest."""
import concurrent.futures
import gzip
import hashlib
import io
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.error
import urllib.request
import zipfile


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(4 << 20), b''):
            h.update(block)
    return {'sha256': h.hexdigest(), 'size': path.stat().st_size}


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def request(url):
    for attempt in range(4):
        try:
            return urllib.request.urlopen(url, timeout=180)
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == 3:
                raise
            time.sleep(2 ** attempt)


def download(url, path):
    with request(url) as response, path.open('wb') as out:
        shutil.copyfileobj(response, out)


def archive(source, target, epoch):
    # Neither host filesystem ownership nor gzip's wall time enters an asset.
    with target.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.GNU_FORMAT) as tar:
            for path in sorted(source.rglob('*')):
                if path.is_dir():
                    continue
                assert path.is_file() and not path.is_symlink(), path
                info = tar.gettarinfo(str(path), str(path.relative_to(source)))
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = epoch
                info.mode = 0o644
                with path.open('rb') as f:
                    tar.addfile(info, f)


def relations(value):
    if not value:
        return set()
    result = set()
    for part in value.split(','):
        match = re.fullmatch(r'\s*([a-z0-9+.-]+) \(= ([^)]+)\)\s*', part)
        assert match, 'unrecognized incorporated-source relation: ' + part
        result.add(match.groups())
    return result


def required_sources(packages):
    result = {(p['source'], p['source_version']) for p in packages}
    for p in packages:
        result |= relations(p['built_using']) | relations(p['static_built_using'])
    return result


def prepare(repo, out):
    lock = json.loads((repo / 'deploy/linux-workspace/image.lock.json').read_text())
    sources = out / 'sources'
    sources.mkdir()
    subprocess.run(['git', '-C', str(repo), 'archive', '--format=tar', '-o', str(sources / 'repository.tar'), 'HEAD'], check=True)
    runtime = lock['go']
    assert subprocess.check_output(['go', '-C', str(repo / 'vcs'), 'env', 'GOVERSION'], text=True).strip() == runtime['version']
    download('https://go.dev/dl/' + runtime['filename'], sources / runtime['filename'])
    assert digest(sources / runtime['filename'])['sha256'] == runtime['sha256'], 'Go source digest'
    modules = {}
    for binary in sorted((out / 'bin').iterdir()):
        lines = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True).splitlines()
        assert lines[0].endswith(runtime['version']), lines[0]
        current = None
        for line in lines[1:]:
            fields = line.split()
            if fields and fields[0] in ('mod', 'dep'):
                current = fields[1]
                modules[current] = {'path': current, 'version': fields[2]}
            elif fields and fields[0] == '=>':
                assert fields[1] == './third_party/go-fuse', 'unexpected local replacement'
                modules[current]['replacement'] = 'vcs/third_party/go-fuse'
    notices = out / 'go-notices'
    notices.mkdir()
    for name, module in sorted(modules.items()):
        if name == 'github.com/steerlabs/portablefs/vcs':
            source = repo
            module['source'] = 'repository.tar'
        elif 'replacement' in module:
            source = repo / module['replacement']
            module['source'] = 'repository.tar'
        else:
            data = json.loads(subprocess.check_output(['go', '-C', str(repo / 'vcs'), 'mod', 'download', '-json', name + '@' + module['version']], text=True))
            source = pathlib.Path(data['Dir'])
            module['sum'] = data['Sum']
            module['source'] = 'go/' + name + '@' + module['version'] + '.zip'
            dest = sources / module['source']
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(data['Zip'], dest)
        dest = notices / name
        dest.mkdir(parents=True)
        module['notices'] = []
        for filename in ('LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'NOTICE', 'PATENTS'):
            if (source / filename).is_file():
                shutil.copyfile(source / filename, dest / filename)
                module['notices'].append(name + '/' + filename)
        assert module['notices'], 'missing Go module notice: ' + name
    goroot = pathlib.Path(subprocess.check_output(['go', '-C', str(repo / 'vcs'), 'env', 'GOROOT'], text=True).strip())
    (notices / 'go-runtime').mkdir()
    for name in ('LICENSE', 'PATENTS'):
        shutil.copyfile(goroot / name, notices / 'go-runtime' / name)
    write(notices / 'modules.json', list(modules.values()))
    write(out / 'go-sources.json', {'runtime': runtime, 'modules': list(modules.values())})


def fetch_source(pair, sources):
    name, version = pair
    base = 'https://snapshot.debian.org'
    url = base + '/mr/package/' + urllib.parse.quote(name, safe='') + '/' + urllib.parse.quote(version, safe='') + '/srcfiles'
    with request(url) as response:
        hashes = json.load(response)['result']
    directory = pathlib.Path('debian') / name / version
    dest = sources / directory
    dest.mkdir(parents=True)
    indexed = {}
    for item in hashes:
        with request(base + '/mr/file/' + item['hash'] + '/info') as response:
            names = {x['name'] for x in json.load(response)['result']}
        for filename in names:
            assert filename not in indexed or indexed[filename] == item['hash']
            indexed[filename] = item['hash']
    dsc_name = name + '_' + version.split(':')[-1] + '.dsc'
    download(base + '/file/' + indexed[dsc_name], dest / dsc_name)
    text = (dest / dsc_name).read_text()
    checksums = re.search(r'^Checksums-Sha256:\n((?: .+\n)+)', text, re.M)
    assert checksums, 'missing source checksums: ' + dsc_name
    components = {line.split()[2]: {'sha256': line.split()[0], 'size': int(line.split()[1])}
                  for line in checksums[1].splitlines()}
    files = {}
    # A snapshot hash may have names in several versions. The .dsc selects the
    # original component names for this version, including multi-orig sources.
    for filename in [dsc_name, *sorted(components)]:
        assert pathlib.Path(filename).name == filename
        path = dest / filename
        if filename != dsc_name:
            download(base + '/file/' + indexed[filename], path)
        h = hashlib.sha1()
        with path.open('rb') as f:
            for block in iter(lambda: f.read(4 << 20), b''):
                h.update(block)
        assert h.hexdigest() == indexed[filename], path
        if filename in components:
            assert digest(path) == components[filename], 'source component digest mismatch'
        files[str(directory / filename)] = digest(path)
    print('retained source:', name, version, flush=True)
    return {'package': name, 'version': version, 'files': files}


def collect(root, out, lock):
    rows = [line.split('\t') for line in (out / 'packages.tsv').read_text().splitlines()]
    packages = [dict(zip(('package', 'version', 'source', 'source_version', 'built_using', 'static_built_using'), row)) for row in rows]
    write(out / 'packages.json', packages)
    sources = out / 'sources'
    pairs = sorted(required_sources(packages))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        debian = list(pool.map(lambda pair: fetch_source(pair, sources), pairs))
    notices = out / 'notices'
    notices.mkdir()
    notice_records = {}
    for package in packages:
        name = package['package']
        path = root / 'usr/share/doc' / name.split(':')[0] / 'copyright'
        # Debian copyright symlinks are relative. Refuse any escape from rootfs.
        resolved = path.resolve(strict=True)
        assert resolved.is_relative_to(root.resolve()), path
        relative = 'debian/' + name + '/copyright'
        dest = notices / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, dest)
        notice_records[name] = relative
    shutil.copytree(root / 'usr/share/common-licenses', notices / 'common-licenses', symlinks=False)
    shutil.copytree(out / 'go-notices', notices / 'go')
    archive(notices, out / 'licenses.tar.gz', lock['source_date_epoch'])
    # Debian .dsc and its original/debian tarballs retain packaging and patches.
    # repository.tar retains our recipe, overlay, kernel choices and local fork.
    shutil.copyfile(out / 'kernel.config', sources / 'kernel.config')
    archive(sources, out / 'corresponding-source.tar.gz', lock['source_date_epoch'])
    files = {str(p.relative_to(sources)): digest(p) for p in sorted(sources.rglob('*')) if p.is_file()}
    go = json.loads((out / 'go-sources.json').read_text())
    manifest = {'format': 8, 'commit': json.loads((out / 'release.json').read_text())['commit'],
                'packages_sha256': digest(out / 'packages.json')['sha256'], 'debian': debian,
                'go': go, 'notices': notice_records,
                'notice_files': {str(p.relative_to(notices)): digest(p) for p in sorted(notices.rglob('*')) if p.is_file()},
                'archive': digest(out / 'corresponding-source.tar.gz'), 'files': files}
    write(out / 'source-manifest.json', manifest)


def members(path):
    result = {}
    with tarfile.open(path, 'r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.name not in result, 'invalid archive member'
            assert not member.name.startswith('/') and '..' not in pathlib.PurePosixPath(member.name).parts
            f = tar.extractfile(member)
            h = hashlib.sha256()
            for block in iter(lambda: f.read(4 << 20), b''):
                h.update(block)
            result[member.name] = {'sha256': h.hexdigest(), 'size': member.size}
    return result


def check(out):
    manifest = json.loads((out / 'manifest.json').read_text())
    required = {'kernel', 'initramfs', 'system.ext4', 'kernel.config', 'packages.json', 'packages.tsv',
                'source-manifest.json', 'licenses.tar.gz', 'initramfs.inventory', 'image-inputs.json',
                'release.json', 'bin/portablefs', 'bin/portablefsd', 'bin/portablefs-workspaced'}
    assert set(manifest['files']) == required, 'invalid exact image manifest'
    for name, record in manifest['files'].items():
        path = out / name
        assert not path.is_symlink() and path.is_file() and digest(path) == record, 'artifact mismatch: ' + name
    sources = json.loads((out / 'source-manifest.json').read_text())
    assert sources['format'] == manifest['format'] == 8
    assert sources['commit'] == manifest['release']['commit']
    assert sources['packages_sha256'] == digest(out / 'packages.json')['sha256']
    packages = json.loads((out / 'packages.json').read_text())
    inputs = json.loads((out / 'image-inputs.json').read_text())
    assert digest(out / 'image-inputs.json')['sha256'] == manifest['release']['image_digest']
    assert json.loads((out / 'release.json').read_text()) == manifest['release']
    assert inputs['commit'] == sources['commit'] and inputs['app_version'] == manifest['release']['app_version']
    assert manifest['release']['authority_major'] == 8
    debian = {(p['package'], p['version']): p for p in sources['debian']}
    assert len(debian) == len(sources['debian']) and set(debian) == required_sources(packages), 'incomplete Debian source coverage'
    assert set(sources['notices']) == {p['package'] for p in packages}, 'incomplete Debian notice coverage'
    assert inputs['lock']['packages'] == packages, 'binary inventory differs from recipe lock'
    assert inputs['lock']['sources'] == sources['debian'], 'source inventory differs from recipe lock'
    assert inputs['lock']['go'] == sources['go']['runtime'], 'Go source differs from recipe lock'
    assert digest(out / 'corresponding-source.tar.gz') == sources['archive'], 'source archive mismatch'
    assert members(out / 'corresponding-source.tar.gz') == sources['files'], 'retained source file mismatch'
    assert members(out / 'licenses.tar.gz') == sources['notice_files'], 'notice archive mismatch'
    assert set(sources['notices']) == {p['package'] for p in packages}, 'incomplete Debian notice coverage'
    for name, notice in sources['notices'].items():
        assert notice == 'debian/' + name + '/copyright', 'incorrect Debian notice mapping'
        assert sources['notice_files'][notice]['size'] > 0, 'missing notice: ' + name
    with tarfile.open(out / 'corresponding-source.tar.gz', 'r:gz') as tar:
        for p in debian.values():
            assert p['files'] and all(sources['files'][n] == r for n, r in p['files'].items())
            dsc = [n for n in p['files'] if n.endswith('.dsc')]
            assert len(dsc) == 1, 'missing Debian source control'
            text = tar.extractfile(dsc[0]).read().decode()
            assert re.search(r'^Source: ' + re.escape(p['package']) + '$', text, re.M)
            assert re.search(r'^Version: ' + re.escape(p['version']) + '$', text, re.M)
            sha = re.search(r'^Checksums-Sha256:\n((?: .+\n)+)', text, re.M)
            assert sha, 'source control lacks SHA-256 coverage'
            expected = {dsc[0]}
            for line in sha[1].splitlines():
                digest_hex, size, name = line.split()
                path = str(pathlib.PurePosixPath(dsc[0]).parent / name)
                assert p['files'][path] == {'sha256': digest_hex, 'size': int(size)}, 'Debian source checksum mismatch'
                expected.add(path)
            assert expected == set(p['files']), 'incomplete Debian source control coverage'
        repo = tarfile.open(fileobj=tar.extractfile('repository.tar'), mode='r:')
        assert repo.pax_headers['comment'] == sources['commit'], 'recipe commit mismatch'
        for name, sha in inputs['files'].items():
            if not name.startswith('bin/'):
                data = repo.extractfile('deploy/linux-workspace/' + name).read()
                assert hashlib.sha256(data).hexdigest() == sha, 'recipe mismatch: ' + name
    assert sources['files']['kernel.config'] == digest(out / 'kernel.config')
    go = sources['go']
    assert sources['files'][go['runtime']['filename']]['sha256'] == go['runtime']['sha256']
    linked = {}
    sums = {}
    for binary in sorted((out / 'bin').iterdir()):
        text = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
        assert text.splitlines()[0].endswith(go['runtime']['version']), 'Go runtime mismatch'
        for line in text.splitlines()[1:]:
            fields = line.split()
            if fields and fields[0] in ('mod', 'dep'):
                linked[fields[1]] = fields[2]
                if len(fields) == 4:
                    sums[fields[1]] = fields[3]
    assert linked == {m['path']: m['version'] for m in go['modules']}, 'incomplete Go module coverage'
    for module in go['modules']:
        assert module['source'] in sources['files'] and module['notices'], 'missing Go source/notice'
        if module['source'] != 'repository.tar':
            assert module['sum'] == sums[module['path']], 'linked Go module checksum mismatch'
        for notice in module['notices']:
            assert notice.startswith(module['path'] + '/'), 'incorrect Go notice mapping'
            assert sources['notice_files']['go/' + notice]['size'] > 0
    for name in ('LICENSE', 'PATENTS'):
        assert sources['notice_files']['go/go-runtime/' + name]['size'] > 0
    print('PASS: exact binary, notice, incorporated-source, Go and recipe coverage')


if __name__ == '__main__':
    command, *args = sys.argv[1:]
    if command == 'prepare':
        prepare(*map(pathlib.Path, args))
    elif command == 'collect':
        root, out, lock = map(pathlib.Path, args)
        collect(root, out, json.loads(lock.read_text()))
    elif command == 'check':
        check(pathlib.Path(args[0]))
    else:
        raise SystemExit('unknown redistribution command')
