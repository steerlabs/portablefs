"""Disposable direct-TLS XFS authority and independent ordinary Linux peer."""
import contextlib
import json
import selectors
import os
import pathlib
import re
import shlex
import subprocess
import time
import uuid


class NativeAuthority:
    volume = 'native-managed'
    target = '/workspaces/native-managed'

    def __init__(self, evidence):
        self.evidence = pathlib.Path(evidence)
        self.repo = pathlib.Path(__file__).resolve().parent.parent
        self.name = os.environ.get('PFS_NATIVE_FIXTURE_PREFIX', 'pfs-workspace-native-') + uuid.uuid4().hex[:10]
        self.helper = self.evidence / 'pfs-workspace-fixture'
        subprocess.run(['go', '-C', str(self.repo/'vcs'), 'build', '-o', str(self.helper),
                        './test/workspace/cmd/pfs-workspace-fixture'], check=True)
        image = os.environ.get('PORTABLEFS_CI_IMAGE', 'golang@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51')
        subprocess.run(['docker', 'run', '-d', '--name', self.name, '--privileged',
                        '-e', 'PFS_NATIVE_FIXTURE_CONTAINER=1', '-v', str(self.repo)+':/work:ro', '-w', '/work',
                        '-p', '0.0.0.0::17443', image, 'bash', '/work/scripts/linux-workspace-native-authority.sh'],
                       check=True, capture_output=True, text=True)
        try:
            deadline = time.monotonic() + 240
            while subprocess.run(['docker', 'exec', self.name, 'test', '-f', '/var/tmp/pfs-native/ready'],
                                 capture_output=True).returncode != 0:
                running = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Running}}', self.name], text=True).strip()
                assert running == 'true' and time.monotonic() < deadline, 'native authority/peer startup failed'
                time.sleep(.25)
            route = subprocess.check_output(['/sbin/route', '-n', 'get', 'default'], text=True)
            interface = re.search(r'interface:\s*(\S+)', route).group(1)
            address = subprocess.check_output(['/usr/sbin/ipconfig', 'getifaddr', interface], text=True).strip()
            published = subprocess.check_output(['docker', 'port', self.name, '17443/tcp'], text=True).splitlines()[0]
            self.endpoint = address + ':' + published.rsplit(':', 1)[1]
            (self.evidence/'native-authority.json').write_text(json.dumps({'container': self.name, 'endpoint': self.endpoint,
                'topology': 'guest VZ NAT -> Mac routed address -> Docker port NAT -> authority TLS; ordinary peer in authority container'}, indent=2))
        except BaseException:
            self.close()
            raise

    def fixture(self, *args):
        return subprocess.check_output([str(self.helper), *args], text=True).strip()

    def peer(self, script):
        return subprocess.check_output(['docker', 'exec', '--user', '200001:200001', self.name,
                                        'python3', '-c', script], text=True).strip()

    def authority_sessions(self):
        raw = subprocess.check_output(['docker', 'exec', self.name, 'python3', '-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:7444/metrics').read().decode())"], text=True)
        active = re.search(r'^portablefs_authority_active_sessions\{[^\n]*\} (\d+)$', raw, re.M)
        log = subprocess.check_output(['docker', 'exec', self.name, 'cat', '/var/tmp/pfs-native/authority.log'], text=True)
        attached = re.findall(r'session=([0-9a-f]+) opcode=attach outcome=success', log)
        assert active, raw
        return {'active': int(active.group(1)), 'attached': attached}

    def network(self, blocked):
        subprocess.run(['docker', 'exec', self.name, 'iptables', '-I' if blocked else '-D', 'INPUT',
                        '-i', 'eth0', '-p', 'tcp', '--dport', '17443', '-j', 'DROP'], check=True)

    def arm_prepare_outage(self):
        # Delayed egress gives the fixture observer time to block guest ingress
        # after real Activate commits and before the initial Subscribe. The
        # ordinary peer uses loopback and remains independently live.
        subprocess.run(['docker', 'exec', self.name, 'tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'netem', 'delay', '500ms'], check=True)
        script = """import pathlib,subprocess,time
p=pathlib.Path('/var/tmp/pfs-native/authority.log')
with p.open() as f:
    f.seek(0,2)
    pathlib.Path('/var/tmp/pfs-native/outage-armed').touch()
    limit=time.monotonic()+60
    while time.monotonic()<limit:
        line=f.readline()
        if 'opcode=activate outcome=success' in line:
            subprocess.run(['iptables','-I','INPUT','-i','eth0','-p','tcp','--dport','17443','-j','DROP'],check=True)
            subprocess.run(['tc','qdisc','del','dev','eth0','root'],check=True)
            pathlib.Path('/var/tmp/pfs-native/outage-blocked').touch()
            break
        time.sleep(.001)
    else:
        raise RuntimeError('no managed Activate observed')
"""
        subprocess.run(['docker', 'exec', '-d', self.name, 'python3', '-c', script], check=True)
        self.wait_fixture('outage-armed')

    def wait_fixture(self, name):
        deadline = time.monotonic()+65
        while subprocess.run(['docker', 'exec', self.name, 'test', '-f', '/var/tmp/pfs-native/'+name], capture_output=True).returncode:
            assert time.monotonic()<deadline, name
            time.sleep(.02)

    def outage(self, guest, phase):
        before = self.authority_sessions()
        assert before['active'] == 2, before
        started = time.monotonic()
        deadline = started+46
        samples = []
        while time.monotonic()<deadline:
            status = self.status(guest)
            mounts = [m for m in status.get('mounts', []) if m['mount']['volumeId'] == self.volume]
            assert len(mounts) == 1 and mounts[0]['state'] == 'recovering', status
            if phase == 'prepare':
                jobs = [j for j in status.get('jobs', []) if j['mount']['volumeId'] == self.volume and j['operation'] == 'mount']
                assert len(jobs) == 1 and jobs[0]['phase'] == 'running', status
            samples.append({'elapsed': time.monotonic()-started, 'state': mounts[0]['state']})
            time.sleep(.2)
        after = self.authority_sessions()
        assert before == after, (before, after)
        (self.evidence/('managed-'+phase+'-outage.json')).write_text(json.dumps({'before': before, 'after': after, 'seconds': time.monotonic()-started, 'samples': samples}, indent=2))
        self.network(False)
        return before

    def status(self, guest):
        guest.command('mount-status')
        event = guest.wait('mount-status', 30)
        return json.loads(self.fixture('decode-status', event['body']))

    def job(self, guest, operation, timeout=90, allow_fail=False):
        deadline = time.monotonic() + timeout
        seen = getattr(self, 'seen_jobs', {})
        key = (guest.p.pid, operation)
        while True:
            current = self.status(guest)
            # The host's autonomous observer may already have acknowledged this
            # result. Its exact retained-evidence event is still the observation.
            snapshots = [current] + [json.loads(self.fixture('decode-status', e['body']))
                for e in guest.history if e['event'] == 'retained-evidence']
            for status in snapshots:
                jobs = status.get('jobs', []) + [r['job'] for r in status.get('retired', []) if 'job' in r]
                selected = [j for j in jobs if j['mount']['volumeId'] == self.volume and j['operation'] == operation
                            and int(j['requestId']) > seen.get(key, 0)]
                for job in selected:
                    if job['phase'] in ('complete', 'failed'):
                        assert allow_fail or job['phase'] == 'complete', job
                        self.last_job = job
                        seen[key] = int(job['requestId']); self.seen_jobs = seen
                        return status
            assert time.monotonic() < deadline, (operation, current)
            time.sleep(.05)

    def ready(self, guest, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            status = self.status(guest)
            mounts = [m for m in status.get('mounts', []) if m['mount']['volumeId'] == self.volume]
            if mounts and mounts[0]['state'] == 'ready':
                return mounts[0]
            if mounts:
                assert mounts[0]['state'] not in ('terminal', 'authorization-required'), mounts[0]
            assert time.monotonic() < deadline, status
            time.sleep(.05)

    def mount(self, guest, short=False, outage=False, provision_only=False):
        guest.command('identity', body=self.fixture('identity-request', self.volume))
        identity = guest.wait('identity-result', 30)['body']
        public = json.loads(self.fixture('decode-identity', identity))
        material = subprocess.check_output(['docker', 'exec', '--user', '200001:200001', self.name,
            '/var/tmp/pfs-native/bin/pfs-workspace-fixture', 'provision-short' if short else 'provision',
            '/var/tmp/pfs-native/home/test-pki', self.endpoint, identity], text=True).strip()
        guest.command('provision', body=material)
        assert guest.wait('provision-accepted', 30)['code'] == 'accepted'
        self.job(guest, 'provision')
        if provision_only:
            return public
        if outage:
            self.arm_prepare_outage()
        guest.command('mount', body=public['mount'])
        assert guest.wait('mount-accepted', 30)['code'] == 'accepted'
        if outage:
            self.wait_fixture('outage-blocked')
            retained = self.outage(guest, 'prepare')
        self.job(guest, 'mount')
        mounted = self.ready(guest)
        if outage:
            assert self.authority_sessions() == retained
        public['incarnation'] = mounted['mount']['incarnation']
        assert mounted['renewal']['state'] == 'not-required', mounted
        return public

    def awake_recovery(self, guest):
        before = self.authority_sessions()
        initial = self.status(guest)
        generation = int(initial.get('generation', '0'))
        self.network(True)
        try:
            deadline = time.monotonic() + 90
            while True:
                phase = guest.wait('phase', max(.1, deadline-time.monotonic()))
                if int(phase['generation']) > generation and phase['phase'] == 'draining':
                    break
                assert time.monotonic() < deadline, phase
        finally:
            self.network(False)
        # Observe the VM owner's transaction without enqueueing a control
        # exchange into its confirmed-pause boundary.
        while True:
            completed = guest.wait('phase', 30)
            if int(completed['generation']) == generation+1 and completed['phase'] == 'running':
                break
        mounted = self.ready(guest)
        after = self.authority_sessions()
        assert before == after and before['active'] == 2, (before, after)
        assert mounted['state'] == 'ready'
        guest.command('status')
        host = guest.wait('status')
        assert host['phase'] == 'running' and int(host['generation']) == generation+1, host
        # No command or synthetic power notification initiated this recovery.
        (self.evidence/'managed-awake-recovery.json').write_text(json.dumps({
            'before': before, 'after': after, 'host': host, 'trigger': phase}, indent=2))

    def initial_io(self, guest):
        result = guest.ssh("python3 -c " + shlex.quote(
            "import os; p='/workspaces/native-managed/data'; f=open(p,'wb'); f.write(b'guest-one'); f.flush(); os.fsync(f.fileno()); f.close(); assert open(p,'rb').read()==b'guest-one'; print('durable')"))
        assert result == 'durable'
        result = self.peer("import os; p='/var/tmp/pfs-native/home/peer/data'; assert open(p,'rb').read()==b'guest-one'; f=open(p,'wb'); f.write(b'peer-two'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-complete')")
        assert result == 'peer-complete'
        assert guest.ssh('cat /workspaces/native-managed/data') == 'peer-two'

    def write_while_paused(self):
        assert self.peer("import os; p='/var/tmp/pfs-native/home/peer/data'; f=open(p,'wb'); f.write(b'peer-during-pause'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-durable-before-resume')") == 'peer-durable-before-resume'

    def unmount(self, guest, public):
        guest.command('umount', body=public['mount'])
        assert guest.wait('umount-accepted', 30)['code'] == 'accepted'
        self.job(guest, 'umount')
        self.protected(guest)

    def protected(self, guest):
        script = """import os,stat
p='/workspaces/native-managed'
s=os.stat(p)
assert stat.S_IMODE(s.st_mode)==0 and s.st_uid==0 and s.st_gid==0
try:
    open(p+'/forbidden','wb')
except PermissionError:
    print('protected')
else:
    raise AssertionError('wrote exposed backing')
"""
        assert guest.ssh('python3 -c '+shlex.quote(script)) == 'protected'

    def kill_child(self, guest):
        script = """import os,pathlib,signal
pids=[]
for p in pathlib.Path('/proc').glob('[0-9]*'):
    try:
        if p.stat().st_uid!=1000: continue
        args=(p/'cmdline').read_bytes().split(b'\\0')
        if args[:2]==[b'/usr/local/bin/portablefs',b'mount'] and b'native-managed' in args:
            pids.append(int(p.name))
    except FileNotFoundError:
        pass
assert len(pids)==1,pids
os.kill(pids[0],signal.SIGKILL)
print(pids[0])
"""
        pid = int(guest.ssh('python3 -c '+shlex.quote(script)))
        deadline = time.monotonic()+30
        while True:
            status = self.status(guest)
            mounts = [m for m in status.get('mounts', []) if m['mount']['volumeId']==self.volume]
            if mounts and mounts[0]['state']=='terminal' and mounts[0]['cleanup']=='complete':
                break
            assert time.monotonic()<deadline,status
            time.sleep(.05)
        self.protected(guest)
        (self.evidence/'managed-child-death.json').write_text(json.dumps({'pid':pid,'status':mounts[0]},indent=2))

    def reconciled(self, guest, old):
        self.status(guest)
        records = []
        for event in guest.history:
            if event['event'] == 'retained-evidence':
                status = json.loads(self.fixture('decode-status', event['body']))
                records.extend(r['mountStatus'] for r in status.get('retired', []) if 'mountStatus' in r)
        prior = [m for m in records if m['mount']['volumeId'] == self.volume and m['mount']['incarnation'] == old['incarnation']]
        assert prior and prior[0]['cleanup'] == 'complete', records
        assert prior[0]['outcome']['observation'] == 'unobserved' and prior[0]['outcome']['durability'] == 'unresolved', prior
        self.protected(guest)

    @contextlib.contextmanager
    def held_handle(self, guest, worker):
        # The accepted SSH session owns its process group. Retain that session
        # while the old descriptor crosses expiry/replacement; nohup cannot
        # transfer ownership out of the per-connection systemd service.
        with (self.evidence/'held-fd-worker.stderr').open('w') as stderr:
            process = subprocess.Popen(['/usr/bin/ssh', '-F', guest.ready['ssh_config'],
                'portablefs-workspace', 'python3 -u -c '+shlex.quote(worker)],
                text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr)
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    assert ready.select(10), 'held descriptor worker did not start'
                    assert process.stdout.readline().strip() == 'held-ready', process.poll()
                yield process
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                process.stdout.close()

    def terminal_replacement(self, guest):
        old = self.mount(guest, short=True)
        worker = """import errno,fcntl,os,time,json,pathlib
root=pathlib.Path.home()
stop=root/'pfs-native-held.stop'
stop.unlink(missing_ok=True)
fd=os.open('/workspaces/native-managed/data',os.O_RDONLY)
with open(root/'pfs-native-held.jsonl','w',buffering=1) as out:
    print('held-ready',flush=True)
    while not stop.exists():
        try:
            data=os.pread(fd,128,0); os.fsync(fd)
            value={'data':data.decode()}
        except OSError as e:
            value={'error':e.errno}
        out.write(json.dumps(value)+'\\n')
        time.sleep(.05)
close_error=0
try:
    os.close(fd)
except OSError as e:
    close_error=e.errno
try:
    fcntl.fcntl(fd,fcntl.F_GETFD)
except OSError as e:
    assert e.errno==errno.EBADF,e
else:
    raise AssertionError('old descriptor remains open')
print(json.dumps({'closed':True,'close_error':close_error}),flush=True)
"""
        with self.held_handle(guest, worker) as held:
            deadline = time.monotonic() + 75
            while True:
                status = self.status(guest)
                mounts = [m for m in status.get('mounts', []) if m['mount']['volumeId'] == self.volume]
                if mounts and mounts[0]['state'] == 'terminal' and mounts[0]['cleanup'] == 'complete':
                    break
                assert time.monotonic() < deadline, status
                time.sleep(.1)
            final = mounts[0]
            assert final['outcome']['observation'] == 'observed' and final['outcome']['release'] == 'abandoned', final
            fresh = self.mount(guest)
            retired = []
            for event in guest.history:
                if event['event'] == 'retained-evidence':
                    observed_status = json.loads(self.fixture('decode-status', event['body']))
                    retired += [r['mountStatus'] for r in observed_status.get('retired', []) if 'mountStatus' in r
                                and r['mountStatus']['mount'] == final['mount']]
            assert retired and retired[0]['outcome'] == final['outcome'] and retired[0].get('loss', []) == final.get('loss', []), retired
            (self.evidence/'managed-terminal-final-evidence.json').write_text(json.dumps({'final': final, 'retired': retired[0]}, indent=2))
            assert fresh['mount'] != old['mount'] and fresh['public_key'] == old['public_key']
            assert guest.ssh('cat /workspaces/native-managed/data') == 'peer-during-pause'
            time.sleep(.2)
            observed = guest.ssh('tail -n 1 ~/pfs-native-held.jsonl')
            assert json.loads(observed).get('error', 0) != 0, observed
            guest.ssh('touch ~/pfs-native-held.stop')
            assert held.wait(timeout=10) == 0
            closure = json.loads(held.stdout.readline())
            assert closure['closed'] and closure['close_error'] in (0, 5, 107), closure
            (self.evidence/'managed-held-fd.json').write_text(json.dumps({
                'old': old['incarnation'], 'fresh': fresh['incarnation'],
                'last_old_handle': json.loads(observed), 'closure': closure}, indent=2))
            self.unmount(guest, fresh)
        return old, fresh

    def close(self):
        if not getattr(self, 'name', None):
            return
        logs = subprocess.run(['docker', 'logs', self.name], capture_output=True, text=True)
        (self.evidence/'native-authority.log').write_text(logs.stdout+logs.stderr)
        subprocess.run(['docker', 'stop', '-t', '25', self.name], capture_output=True, timeout=40)
        for name in ('authority', 'peer'):
            captured = subprocess.run(['docker', 'cp', self.name+':/var/tmp/pfs-native/'+name+'.log',
                                      str(self.evidence/('native-'+name+'-rpc.log'))], capture_output=True, text=True)
            if captured.returncode:
                (self.evidence/('native-'+name+'-unavailable.log')).write_text(captured.stderr)
        subprocess.run(['docker', 'rm', self.name], check=True, capture_output=True)
        self.name = None
