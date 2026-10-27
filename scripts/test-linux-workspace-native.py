"""Real VZ execution, independent causal assertions, exact required inventory."""
import json
import hashlib
import os
import datetime
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
import signal
from linux_workspace_native_managed import NativeAuthority
from linux_workspace_native_lifecycle import lifecycle_checks
from linux_workspace_native_product import product_checks
from linux_workspace_native_g0 import pause_checks

binary, image, evidence, inventory = sys.argv[1:]
root = pathlib.Path(evidence)
state = pathlib.Path(tempfile.mkdtemp(prefix=os.environ.get('PFS_NATIVE_FIXTURE_PREFIX', 'pfs-workspace-native-'), dir='/tmp'))
(root / 'state-directory.json').write_text(json.dumps({'state': str(state)}))
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
        self.history = []
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
            self.history.append(value)
            if value['event'] in (expected if isinstance(expected, tuple) else (expected,)):
                return value
            if value['event'] in ('failure', 'eof'):
                raise RuntimeError(value)

    def command(self, name, **fields):
        self.p.stdin.write(json.dumps({'command': name, **fields}) + '\n'); self.p.stdin.flush()

    def discard(self):
        self.command('discard')
        value = self.wait('stopped', 30)
        assert value['operations'][-1] == 'stop-completed', value
        assert self.p.wait(timeout=10) == 0
        self.stderr.close()

    def ssh(self, command):
        result = subprocess.run(['/usr/bin/ssh', '-F', self.ready['ssh_config'], 'portablefs-workspace', command],
                                text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, (command, result.returncode, result.stderr, result.stdout)
        return result.stdout.strip()

    def stop(self, interrupt=False):
        self.ssh('sync')
        if interrupt: self.p.send_signal(signal.SIGINT)
        else: self.command('stop')
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
authority = None
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
    g0_native=json.loads((root/'g0-native.json').read_text())
    assert g0_native['image_manifest_sha256']==hashlib.sha256((pathlib.Path(image)/'manifest.json').read_bytes()).hexdigest()
    for case in g0_native['cases']:
        assert case['pass'] and case['no_host_round_trip_after_resume'] and case['rpc_delta']==0
        record(case['case'])
    operations = guest.starting['operations']
    assert operations.index('power-registered') < operations.index('start-request')
    record('power-before-start')
    assert guest.ready['mounts'] == 0
    # Each negative case boots the paired image and exchanges a valid but
    # mismatched Hello with the real guest over its authenticated vsock stream.
    # No host-only model test can satisfy this case.
    for field in ('version', 'commit', 'digest'):
        mismatch_state = pathlib.Path(tempfile.mkdtemp(prefix=os.environ.get('PFS_NATIVE_FIXTURE_PREFIX', 'pfs-ws-mismatch-'), dir='/tmp'))
        try:
            process = subprocess.Popen([binary, image, str(mismatch_state), '--pairing-mismatch', field],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                process.wait(timeout=180)
                stdout = process.stdout.read(); stderr = process.stderr.read()
                mismatch = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            finally:
                if process.poll() is None:
                    process.terminate(); process.wait(timeout=30)
                process.stdin.close(); process.stdout.close(); process.stderr.close()
            (root / ('handshake-' + field + '.stdout')).write_text(mismatch.stdout)
            (root / ('handshake-' + field + '.stderr')).write_text(mismatch.stderr)
            frames = [json.loads(line) for line in mismatch.stdout.splitlines()]
            names = [frame['event'] for frame in frames]
            assert mismatch.returncode == 1, (field, mismatch.returncode, frames, mismatch.stderr)
            assert 'control-ready' in names and 'hello-refused' in names, (field, frames)
            refusal = next(frame for frame in frames if frame['event'] == 'hello-refused')
            assert 'peer closed' in refusal['reason'], (field, refusal)
            assert 'ready' not in names and names[-1] == 'stopped', (field, frames)
            assert frames[-1]['operations'][-1] == 'stop-completed', (field, frames)
        finally:
            shutil.rmtree(mismatch_state)
    record('exact-handshake')
    fuse = json.loads(guest.ssh('timeout 15 portablefs-workspaced probe-fuse'))
    assert fuse['kernel_major'] == 7 and fuse['kernel_minor'] >= 31
    assert fuse['negotiated_major'] == 7 and fuse['negotiated_minor'] >= 31 and fuse['initialized'] is True
    measurements[-1]['fuse'] = fuse
    record('fuse-init-7.31')
    assert guest.ssh('id -u; id -g; whoami').splitlines() == ['1000', '1000', 'workspace']
    assert guest.ssh("set -e; command -v python3 git cc; python3 -c 'print(6*7)'; git --version; cc --version").splitlines()[3] == '42'
    toolchain = guest.ssh('set -e; node --version; npm --version; python3 -m pip --version; '
                          'work=$(mktemp -d); trap \'rm -rf "$work"\' EXIT; '
                          'python3 -m venv "$work/venv"; "$work/venv/bin/python" -m pip --version; '
                          'portablefs version')
    node_version = next(p['version'] for p in json.loads((pathlib.Path(image) / 'packages.json').read_text()) if p['package'] == 'nodejs')
    assert toolchain.splitlines()[0].startswith('v' + node_version.split(':')[-1].split('.')[0] + '.'), toolchain
    assert toolchain.splitlines()[-1] == 'portablefs ' + json.loads((pathlib.Path(image) / 'release.json').read_text())['app_version'], toolchain
    record('guest-development-toolchain')
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
    for _ in range(2):
        guest.command('probe-unavailable-jobs')
        jobs = guest.wait('jobs-refused', 10)
        assert jobs['mounts'] == 0 and jobs['failure'] == 'handler-failed' and jobs['cleanup'] == 'complete', jobs
        assert len(jobs['request_ids']) == 3 and all(a < b for a, b in zip(jobs['request_ids'], jobs['request_ids'][1:])), jobs
    record('unprovisioned-jobs-retain-failure')
    guest.command('probe-identity')
    identity = guest.wait('identity', 10)
    guest.command('probe-identity')
    repeated = guest.wait('identity', 10)
    for field in ('mount', 'public_key', 'csr', 'guest_uuid', 'identity_incarnation', 'renewal_epoch'):
        assert repeated[field] == identity[field], field
    import base64
    csr = root / 'identity-probe.csr.der'
    csr.write_bytes(base64.b64decode(identity['csr']))
    checked = subprocess.run(['openssl', 'req', '-inform', 'DER', '-in', str(csr), '-verify', '-noout'], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    pub = subprocess.check_output(['openssl', 'req', '-inform', 'DER', '-in', str(csr), '-pubkey', '-noout'])
    public_der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub, capture_output=True, check=True).stdout
    assert public_der == base64.b64decode(identity['public_key'])
    record('guest-identity-signed-csr')
    owner = json.loads(guest.ssh('cat /run/portablefs-workspace/clock-owner.json'))
    assert owner['read_only'] and owner['second_open_busy'] and 'pl031' in owner['source']
    contention = json.loads((root/'rtc-contention.json').read_text())
    assert contention['readers'] == 8 and contention['samples'] == 8000
    assert contention['read_only'] and contention['second_open_busy'] and contention['maximum_ns'] <= 250_000_000
    assert contention['source'] == owner['source']
    measurements[-1]['rtc_contention'] = contention
    measurements[-1]['clock_owner'] = owner
    record('rtc-single-owner-duplicate-contention')
    first_resume=json.loads((root/'rtc-first-resume.json').read_text())
    assert first_resume['operation_prestarted'] and not first_resume['host_round_trip_after_resume']
    assert first_resume['read_age_ns']<=250_000_000
    record('g0-rtc-first-read-after-vz-resume')
    before = json.loads(guest.ssh('cat /run/portablefs-workspace/clock.json'))
    assert before['generation'] == 0 and before['sample_age_ns'] <= 250_000_000
    record('rtc-boot-correction')
    clock_arguments = ['--seconds', '1800', '--dry-run'] if os.environ.get('PFS_NATIVE_CLOCK_DRY_RUN') == '1' else ['--seconds', '65']
    subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('qualify-linux-workspace-clock.py')), image, guest.ready['ssh_config'], str(root/'clock-qualification'), *clock_arguments], check=True)
    record('rtc-awake-measurement')
    authority = NativeAuthority(root)
    managed = authority.mount(guest, outage=True)
    record('managed-standalone-provision')
    record('managed-prepare-outage-over-45s')
    authority.initial_io(guest)
    record('managed-write-read-fsync')
    record('managed-peer-coherence')
    managed = pause_checks(authority, guest, managed, record)
    token = uuid.uuid4().hex
    guest.ssh("printf '%s\\n' '" + token + "' > ~/persistence; sync -f ~/persistence")
    old_key = (state / 'guest_host_key.pub').read_text()
    guest.command('status')
    prior_generation = guest.wait('status')['generation']
    before = json.loads(guest.ssh('cat /run/portablefs-workspace/clock.json'))
    assert before['generation'] == prior_generation and before['sample_age_ns'] <= 250_000_000, before
    expected_generation = prior_generation + 1
    measurements[-1]['pre_pause_clock'] = before
    # One input batch makes Status in flight when Suspend is enqueued.
    guest.p.stdin.write(json.dumps({'command':'status'})+'\n'+json.dumps({'command':'pause'})+'\n'); guest.p.stdin.flush()
    paused = guest.wait('paused', 25)
    assert paused['fenced'] and not paused['attach_allowed'] and paused['generation'] == expected_generation
    operations = paused['operations']
    assert max(i for i, op in enumerate(operations) if op == 'pause-completed') < max(i for i, op in enumerate(operations) if op == 'sleep-fenced')
    guest.command('status')
    assert guest.wait('status')['phase'] == 'pausedCold'
    authority.write_while_paused()
    time.sleep(5)
    record('controlled-cold-pause')
    authority.network(True)
    guest.command('resume')
    resumed = guest.wait('resumed', 25)
    assert resumed['operations'][-1] == 'resume-completed'
    assert len(resumed['mount_states']) == 1
    retained = authority.outage(guest, 'recover')
    authority.ready(guest)
    assert authority.authority_sessions() == retained
    record('managed-recover-outage-over-45s')
    assert guest.ssh('cat /workspaces/native-managed/data') == 'peer-during-pause'
    record('managed-suspend-resume-data')
    deadline = time.monotonic() + 10
    while True:
        after = json.loads(guest.ssh('cat /run/portablefs-workspace/clock.json'))
        if after['generation'] == expected_generation:
            break
        assert time.monotonic() < deadline, after
        time.sleep(.1)
    assert after['generation'] == expected_generation and after['sample_age_ns'] <= 250_000_000
    wall_delta = (datetime.datetime.fromisoformat(after['wall_after'].replace('Z', '+00:00')) - datetime.datetime.fromisoformat(before['wall_after'].replace('Z', '+00:00'))).total_seconds()
    elapsed_delta = (after['elapsed_end_ns'] - before['elapsed_end_ns']) / 1e9
    assert wall_delta - elapsed_delta >= 3, 'resume did not exercise real guest wall correction'
    measurements[-1]['resume_clock'] = after
    record('rtc-cold-resume-generation')
    assert guest.ssh('cat ~/persistence') == token
    memory = guest.ssh("awk '/MemTotal:|MemAvailable:/ {print}' /proc/meminfo")
    measurements[-1]['guest_memory'] = memory
    measurements[-1]['owner_rss_kib'] = int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(guest.p.pid)], text=True).strip())
    authority.awake_recovery(guest)
    record('managed-awake-proof-loss-cold-recovery')
    managed = lifecycle_checks(authority, guest, managed, record)
    authority.unmount(guest, managed)
    record('managed-unmount-exact-cleanup')
    provisioned = authority.mount(guest, provision_only=True)
    guest.discard()
    guest = Guest()
    reprovisioned = authority.mount(guest)
    assert reprovisioned['mount'] != provisioned['mount'] and reprovisioned['public_key'] == provisioned['public_key']
    assert reprovisioned['identity_incarnation'] == provisioned['identity_incarnation']
    record('managed-provision-only-reboot-reissue')
    authority.kill_child(guest)
    record('managed-child-death-exact-cleanup')
    previous = authority.mount(guest)
    guest.discard()
    record('managed-channel-loss-vm-discard')
    guest = Guest()
    authority.reconciled(guest, previous)
    record('managed-reboot-durable-reconcile')
    authority.terminal_replacement(guest)
    record('managed-terminal-replacement')
    record('managed-terminal-final-evidence-retired')
    record('managed-old-handle-terminal')
    assert guest.ssh('cat ~/persistence') == token
    record('data-disk-reboot-persistence')
    guest.command('probe-identity')
    replacement = guest.wait('identity', 10)
    for field in ('public_key', 'guest_uuid', 'identity_incarnation', 'renewal_epoch'):
        assert replacement[field] == identity[field], field
    assert replacement['mount'] != identity['mount']
    record('guest-identity-reboot-persistence')
    assert guest.ready['host_key'].split()[:2] == old_key.split()[:2]
    debug = subprocess.run(['/usr/bin/ssh', '-vv', '-F', guest.ready['ssh_config'], 'portablefs-workspace', 'true'], text=True, capture_output=True, timeout=30)
    fingerprint = subprocess.check_output(['/usr/bin/ssh-keygen', '-lf', str(state/'guest_host_key.pub')], text=True).split()[1]
    assert debug.returncode == 0 and 'Server host key: ssh-ed25519 ' + fingerprint in debug.stderr
    record('guest-host-key-persistence')
    guest.stop(interrupt=True)
    guest = Guest()
    root_death_mount = authority.mount(guest)
    guest.command('pause'); guest.wait('paused', 25)
    guest.command('resume'); guest.wait('resumed', 25)
    authority.ready(guest)
    assert guest.ssh('cat /workspaces/native-managed/data') == 'peer-during-pause'
    guest.command('replay-resume')
    refusal = guest.wait('replay-refused', 25)
    assert refusal['generation'] == 1 and 'guest refused resume: resume token consumed' in refusal['reason'], refusal
    # This is a real replay on the paired stream; the guest closes it and the
    # coordinator discards the now-unpaired VM. No dev input guard refused it.
    guest.wait('failure', 25)
    stopped = guest.wait('stopped', 25)
    assert stopped['operations'][-1] == 'stop-completed', stopped
    assert guest.p.wait(timeout=10) == 1
    record('resume-single-use')
    record('managed-root-owner-death-vm-discard')
    guest = Guest()
    authority.reconciled(guest, root_death_mount)
    guest.p.stdin.close()
    stopped = guest.wait('stopped', 30)
    assert stopped['operations'][-1] == 'shutdown-completed'
    assert guest.p.wait(timeout=10) == 0
    record('clean-stop')
    product_checks(image, root / "product", record, authority=authority)
    assert sorted(passed) == sorted(required), (passed, required)
    (root / 'results.json').write_text(json.dumps({'required': required, 'passed': passed, 'measurements': measurements, 'state': str(state), 'image_manifest_sha256': hashlib.sha256((pathlib.Path(image)/'manifest.json').read_bytes()).hexdigest(), 'rtc_admission': 'pass', 'utc': 'inconclusive', 'g0': 'inconclusive', 'first_read_after_resume': True, 'concurrent_duplicate_readers': True}, indent=2) + '\n')
    print('native-workspace: PASS (exact inventory: %d)' % len(passed), flush=True)
finally:
    if guest:
        guest.cleanup()
    if authority:
        authority.close()
    events.close()
    if (state / "serial.log").exists():
        shutil.copyfile(state / "serial.log", root / "guest-final-serial.log")
    shutil.rmtree(state)
