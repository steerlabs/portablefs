"""Real VZ execution, independent causal assertions, exact required inventory."""
import json
import pathlib
import queue
import subprocess
import sys
import threading
import time
import uuid

binary, image, evidence, inventory = sys.argv[1:]
root = pathlib.Path(evidence)
state = root / ('state-' + uuid.uuid4().hex)
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
    record('artifact-verification')
    assert guest.starting['power_registered'] is True
    record('power-before-start')
    assert guest.ready['mounts'] == 1
    record('exact-handshake')
    fuse = json.loads(guest.ssh('cat /run/portablefs-fuse-init.json'))
    assert fuse['negotiated_major'] == 7 and fuse['negotiated_minor'] >= 31
    measurements[-1]['fuse'] = fuse
    record('fuse-init-7.31')
    assert guest.ssh('id -u; id -g; whoami').splitlines() == ['1000', '1000', 'workspace']
    assert guest.ssh("python3 -c 'print(6*7)'; git --version; cc --version | head -1").splitlines()[0] == '42'
    record('ssh-workspace-user')
    assert guest.ssh("findmnt -n -o OPTIONS /; test ! -w /usr; test ! -w /etc").split(',')[0] == 'ro'
    record('immutable-root')
    assert guest.ssh("ss -ltnH '( sport = :22 )' | wc -l") == '0'
    assert ':22' in guest.ssh('ss -l --vsock')
    record('vsock-only-ssh')
    assert guest.ssh('test ! -r /workspaces && test ! -x /workspaces && test ! -w /workspaces && echo denied') == 'denied'
    record('unmounted-workspaces-inaccessible')
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
    assert resumed['mount_states'] == ['authorization-required']
    guest.command('resume')
    assert guest.wait('refused')['command'] == 'resume'
    assert guest.ssh('cat ~/persistence') == token
    record('resume-single-use')
    memory = guest.ssh("awk '/MemTotal:|MemAvailable:/ {print}' /proc/meminfo")
    measurements[-1]['guest_memory'] = memory
    measurements[-1]['owner_rss_kib'] = int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(guest.p.pid)], text=True).strip())
    guest.stop()
    guest = Guest()
    assert guest.ssh('cat ~/persistence') == token
    record('data-disk-reboot-persistence')
    assert (state / 'guest_host_key.pub').read_text() == old_key
    record('guest-host-key-persistence')
    guest.stop()
    record('clean-stop')
    assert sorted(passed) == sorted(required), (passed, required)
    (root / 'results.json').write_text(json.dumps({'required': required, 'passed': passed, 'measurements': measurements, 'state': str(state)}, indent=2) + '\n')
    print('native-workspace: PASS (exact inventory: %d)' % len(passed), flush=True)
finally:
    if guest:
        guest.cleanup()
    events.close()
