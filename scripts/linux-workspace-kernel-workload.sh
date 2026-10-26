#!/usr/bin/env bash
# Offline developer workload: package installs, Git, parallel builds and exits.
set -euo pipefail
work="$(mktemp -d "$HOME/kernel-workload.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cd "$work"
git init -q source
cd source
git config user.name 'Kernel stability fixture'
git config user.email 'kernel-fixture@example.invalid'
python3 - <<'PY'
import pathlib
for i in range(32):
    pathlib.Path(f'unit{i}.c').write_text(f'int unit{i}(void) {{ return {i}; }}\n')
pathlib.Path('main.c').write_text('int main(void) { return 0; }\n')
pathlib.Path('Makefile').write_text('CC=cc\nCFLAGS=-O2 -Wall -Werror\n'
    'objects=$(patsubst %.c,%.o,$(wildcard *.c))\n'
    'app: $(objects)\n\t$(CC) $(objects) -o $@\n')
PY
git add .
git commit -qm 'Build fixture'
cd ..
git clone -q source checkout
cd checkout
make -j4
./app
git diff --exit-code
git fsck --full
cd ..
mkdir node-package node-project
cat >node-package/package.json <<'JSON'
{"name":"kernel-fixture","version":"1.0.0","scripts":{"install":"node -e \"require('child_process').execFileSync('/bin/true')\""}}
JSON
printf '{"name":"kernel-workload","version":"1.0.0","private":true,"dependencies":{"kernel-fixture":"file:../node-package"}}\n' >node-project/package.json
(cd node-project; npm install --offline --no-audit --no-fund; npm ls; npm rebuild --offline)
python3 -m venv venv
# A real local wheel makes pip installation deterministic and network independent.
python3 - <<'PY'
import base64,hashlib,zipfile
name='kernel_fixture-1.0.0.dist-info/'
files={'kernel_fixture.py': b'VALUE = 42\n',
       name+'METADATA': b'Metadata-Version: 2.1\nName: kernel-fixture\nVersion: 1.0.0\n',
       name+'WHEEL': b'Wheel-Version: 1.0\nGenerator: portablefs-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
rows=[f'{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")},{len(data)}\n' for n,data in files.items()]
files[name+'RECORD']=(''.join(rows)+name+'RECORD,,\n').encode()
with zipfile.ZipFile('kernel_fixture-1.0.0-py3-none-any.whl','w') as z:
    for n,data in files.items(): z.writestr(n,data)
PY
venv/bin/python -m pip install --no-index --disable-pip-version-check ./kernel_fixture-1.0.0-py3-none-any.whl
venv/bin/python -c 'import kernel_fixture; assert kernel_fixture.VALUE == 42'
venv/bin/python -m pip check
python3 - <<'PY'
import concurrent.futures,subprocess
def churn(worker):
    # Fault private pages before each fork/exec so process teardown exercises
    # anonymous mappings rather than only spawning an empty shell.
    pages=bytearray(8*1024*1024)
    for iteration in range(128):
        pages[::4096]=bytes([iteration])*len(pages[::4096])
        subprocess.run(['/bin/sh','-c','git -C checkout status --porcelain >/dev/null; /bin/true'],check=True)
with concurrent.futures.ProcessPoolExecutor(max_workers=4) as pool:
    list(pool.map(churn,range(4)))
PY
sync
printf 'PASS: kernel workload (Git, npm, pip, 33 C units, 512 process-churn iterations)\n'
