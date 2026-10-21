"""Real VZ execution, independent causal assertions, exact required inventory."""
import json
import pathlib
import queue
import subprocess
import sys
import threading
import time
import uuid
import tempfile
import re
import shutil

binary, image, evidence, inventory = sys.argv[1:]
root = pathlib.Path(evidence)
state = pathlib.Path(tempfile.mkdtemp(prefix='pfs-ws-', dir='/tmp'))
required = pathlib.Path(inventory).read_text().splitlines()
assert required and len(required) == len(set(required))
passed = []
measurements = []
events = (root / 'events.jsonl').open('w')
(root / 'results.json').unlink(missing_ok=True)


def record(name):
    assert name in required and name not in passed, name
    passed.append(name)
    print('PASS:', name, flush=True)


class Guest:
    def __init__(self):
        self.lines = queue.Queue()
        self.stderr = (root / ('owner-' + str(len(measurements)) + '.stderr')).open('w')
        self.p = subprocess.Popen([binary, image, str(state)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=self.stderr, text=True, bufsize=1)

        def read():
            for line in self.p.stdout:
                assert events.tell() + len(line) <= 8*1024*1024, 'event log bound exceeded'
                events.write(line); events.flush()
                self.lines.put(json.loads(line))
            self.lines.put({'event': 'eof', 'returncode': self.p.wait()})

        threading.Thread(target=read, daemon=True).start()
        try:
            self.starting = self.wait('starting')
            self.ready = self.wait('ready')
        except BaseException:
            self.cleanup()
            raise
        measurements.append({'boot_ns': self.ready['boot_ns'], 'pid': self.starting['pid']})

    def wait(self, expected, timeout=180):
        deadline = time.monotonic() + timeout
        while True:
            value = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            if value['event'] == expected:
                return value
            if value['event'] in ('failure', 'eof'):
                raise RuntimeError(value)

    def command(self, name):
        self.p.stdin.write(json.dumps({'command': name}) + '\n'); self.p.stdin.flush()

    def ssh(self, command):
        result = subprocess.run(['/usr/bin/ssh', '-F', self.ready['ssh_config'], 'portablefs-workspace', command],
                                text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, (command, result.returncode, result.stderr, result.stdout)
        return result.stdout.strip()

    def stop(self):
        self.ssh('sync')
        self.command('stop')
        value = self.wait('stopped', 30)
        assert value['operations'][-1] == 'shutdown-completed'
        assert self.p.wait(timeout=10) == 0
        self.stderr.close()

    def cleanup(self):
        if self.p.poll() is None:
            self.command('stop')
            try:
                self.p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.p.terminate(); self.p.wait(timeout=10)


guest = None
try:
    guest = Guest()
    corrupt = pathlib.Path(tempfile.mkdtemp(prefix='pfs-corrupt-', dir='/tmp')) / 'image'
    try:
        subprocess.run(['/bin/cp', '-cR', image, str(corrupt)], check=True)
        manifest = json.loads((corrupt/'manifest.json').read_text())
        manifest['files']['kernel']['sha256'] = '0'*64
        (corrupt/'manifest.json').write_text(json.dumps(manifest))
        refused = subprocess.run([binary, '--verify-artifact', str(corrupt)], text=True, capture_output=True, timeout=30)
        assert refused.returncode != 0 and 'artifact hash mismatch: kernel' in refused.stderr
    finally:
        shutil.rmtree(corrupt.parent)
    record('artifact-verification')
    operations = guest.starting['operations']
    assert operations.index('power-registered') < operations.index('start-request')
    record('power-before-start')
    assert guest.ready['mounts'] == 0
    repo = pathlib.Path(__file__).resolve().parent.parent
    subprocess.run(['go', '-C', str(repo/'vcs'), 'test', './internal/workspaceguest', '-run', '^TestTransportExactReleaseAndBootPairing$', '-count=1'], check=True)
    record('exact-handshake')
    fuse = json.loads(guest.ssh('timeout 15 portablefs-workspaced probe-fuse'))
    assert fuse['kernel_major'] == 7 and fuse['kernel_minor'] >= 31
    assert fuse['negotiated_major'] == 7 and fuse['negotiated_minor'] >= 31 and fuse['initialized'] is True
    measurements[-1]['fuse'] = fuse
    record('fuse-init-7.31')
    assert guest.ssh('id -u; id -g; whoami').splitlines() == ['1000', '1000', 'workspace']
    assert guest.ssh("set -e; command -v python3 git cc; python3 -c 'print(6*7)'; git --version; cc --version").splitlines()[3] == '42'
    record('ssh-workspace-user')
    assert guest.ssh('cat /sys/block/vda/ro') == '1'
    assert 'ro' in guest.ssh('findmnt -n -o OPTIONS /').split(',')
    record('immutable-root')
    listeners = guest.ssh("ss -ltnH | awk '{print $4}'").splitlines()
    assert all(address in ('127.0.0.53%lo:53', '127.0.0.54:53', '127.0.0.53:53') for address in listeners), listeners
    assert ':22' in guest.ssh('ss -l --vsock')
    record('vsock-only-ssh')
    assert guest.ssh('stat -c %a:%u:%g /workspaces') == '755:0:0'
    assert guest.ssh('findmnt -n -o FSTYPE /workspaces') == 'tmpfs'
    assert guest.ssh('test -x /workspaces && test ! -w /workspaces && echo traversable') == 'traversable'
    record('workspace-root-layout')
    token = uuid.uuid4().hex
    guest.ssh("printf '%s\\n' '" + token + "' > ~/persistence; sync -f ~/persistence")
    old_key = (state / 'guest_host_key.pub').read_text()
    guest.command('pause')
    paused = guest.wait('paused', 25)
    assert paused['fenced'] and not paused['attach_allowed'] and paused['generation'] == 1
    assert paused['operations'][-1] == 'pause-completed'
    guest.command('status')
    assert guest.wait('status')['phase'] == 'pausedCold'
    time.sleep(1)
    record('controlled-cold-pause')
    guest.command('resume')
    resumed = guest.wait('resumed', 25)
    assert resumed['operations'][-1] == 'resume-completed'
    assert resumed['mount_states'] == []
    assert guest.ssh('cat ~/persistence') == token
    memory = guest.ssh("awk '/MemTotal:|MemAvailable:/ {print}' /proc/meminfo")
    measurements[-1]['guest_memory'] = memory
    measurements[-1]['owner_rss_kib'] = int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(guest.p.pid)], text=True).strip())
    guest.stop()
    guest = Guest()
    assert guest.ssh('cat ~/persistence') == token
    record('data-disk-reboot-persistence')
    assert guest.ready['host_key'].split()[:2] == old_key.split()[:2]
    debug = subprocess.run(['/usr/bin/ssh', '-vv', '-F', guest.ready['ssh_config'], 'portablefs-workspace', 'true'], text=True, capture_output=True, timeout=30)
    fingerprint = subprocess.check_output(['/usr/bin/ssh-keygen', '-lf', str(state/'guest_host_key.pub')], text=True).split()[1]
    assert debug.returncode == 0 and 'Server host key: ssh-ed25519 ' + fingerprint in debug.stderr
    record('guest-host-key-persistence')
    guest.stop()
    record('clean-stop')
    guest = Guest()
    guest.command('pause'); guest.wait('paused', 25)
    guest.command('resume'); guest.wait('resumed', 25)
    guest.command('replay-resume')
    assert guest.wait('replay-refused', 25)['generation'] == 1
    # This is a real replay on the paired stream; the guest closes it and the
    # coordinator discards the now-unpaired VM. No dev input guard refused it.
    guest.wait('failure', 25)
    guest.wait('stopped', 25)
    assert guest.p.wait(timeout=10) == 1
    record('resume-single-use')
    assert sorted(passed) == sorted(required), (passed, required)
    (root / 'results.json').write_text(json.dumps({'required': required, 'passed': passed, 'measurements': measurements, 'state': str(state)}, indent=2) + '\n')
    print('native-workspace: PASS (exact inventory: %d)' % len(passed), flush=True)
finally:
    if guest:
        guest.cleanup()
    events.close()
