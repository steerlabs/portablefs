"""Run the shipped developer tools and a source-built jemalloc on 16 KiB pages."""
import hashlib
import json
import pathlib
import subprocess
import time


def userspace_checks(guest, evidence, record):
    root = pathlib.Path(evidence)
    root.mkdir(parents=True, exist_ok=True)
    ssh = ['/usr/bin/ssh', '-F', guest.ready['ssh_config'], 'portablefs-workspace', 'bash -s']
    tools = pathlib.Path(__file__).with_name('linux-workspace-kernel-workload.sh').read_text()
    redis = r'''
set -euo pipefail
test "$(getconf PAGESIZE)" = 16384
work=$(mktemp -d "$HOME/redis-16k.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"
curl --fail --location --max-time 120 -o redis.tar.gz https://download.redis.io/releases/redis-8.2.3.tar.gz
echo 'd88f2361fdf3a3a8668fe5753e29915566109dca07b4cb036427ea6dc7783671  redis.tar.gz' | sha256sum -c -
tar -xzf redis.tar.gz
cd redis-8.2.3
make -j4
test "$(sed -n 's/^#define LG_PAGE //p' deps/jemalloc/include/jemalloc/internal/jemalloc_internal_defs.h)" = 14
src/redis-server --version | tee version.txt
rg 'malloc=jemalloc-' version.txt
src/redis-server --port 0 --unixsocket "$work/redis.sock" --save '' --appendonly no > "$work/server.log" 2>&1 &
server=$!
cleanup() { kill "$server" 2>/dev/null || true; wait "$server" || true; rm -rf "$work"; }
trap cleanup EXIT
for i in $(seq 1 100); do
    if test -S "$work/redis.sock"; then break; fi
    sleep .1
done
test "$(src/redis-cli -s "$work/redis.sock" set pagesize 16384)" = OK
test "$(src/redis-cli -s "$work/redis.sock" get pagesize)" = 16384
src/redis-cli -s "$work/redis.sock" shutdown nosave
wait "$server"
trap 'rm -rf "$work"' EXIT
printf 'PASS: Redis 8.2.3, source-built jemalloc LG_PAGE=14, set/get and shutdown\n'
'''
    results = []
    for name, workload, timeout in [('tools', tools, 300), ('redis', redis, 1200)]:
        guest.pressure.sample(name + '-start')
        started = time.monotonic()
        with (root / (name + '.log')).open('w') as output:
            result = subprocess.run(ssh, input=workload, text=True, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        results.append({'name': name, 'returncode': result.returncode,
                        'seconds': time.monotonic() - started,
                        'workload_sha256': hashlib.sha256(workload.encode()).hexdigest()})
        (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        assert result.returncode == 0, results[-1]
        guest.pressure.sample(name + '-end')
    record('guest-16k-userspace-builds')
