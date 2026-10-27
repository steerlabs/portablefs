"""Application effects across real managed-mount lifecycle transitions."""
import contextlib
import json
import pathlib
import selectors
import shlex
import subprocess
import time
import uuid


class LifecycleChecks:
    def __init__(self, authority, guest, record):
        self.a, self.g, self.record = authority, guest, record
        self.results = {}

    def save(self, name, value):
        self.results[name] = value
        (self.a.evidence / 'managed-lifecycle.json').write_text(json.dumps(self.results, indent=2))
        self.record(name)

    def mount(self):
        mounts = [m for m in self.a.status(self.g).get('mounts', [])
                  if m['mount']['volumeId'] == self.a.volume]
        return mounts[0] if mounts else None

    @contextlib.contextmanager
    def holder(self, kind, threads=2):
        tag = 'pfs-native-lifecycle-' + uuid.uuid4().hex
        stop, result = '~/'+tag+'.stop', '~/'+tag+'.json'
        worker = r'''import json,os,pathlib,threading,time
home=pathlib.Path.home(); stop=home/STOP; result=home/RESULT
root=pathlib.Path(ROOT); errors=[]; error_details=[]; counts={}; ready=set(); lock=threading.Lock()
allocated=[]
if KIND=='killable': (home/(TAG+'.pid')).write_text(str(os.getpid()))
def run(i):
    n=0; fd=None; stage='open'
    try:
        flags=os.O_CREAT|os.O_WRONLY
        if KIND!='positioned': flags|=os.O_APPEND
        fd=os.open(root/(TAG+'-'+str(i)),flags,0o600)
        while not stop.exists():
            try:
                stage='write'; data=('%08d\n'%n).encode()
                written=os.pwrite(fd,data,n*len(data)) if KIND=='positioned' else os.write(fd,data)
                assert written==len(data)
                stage='fsync'; os.fsync(fd); n+=1
                if KIND=='killable':
                    marker=home/(TAG+'.ack-'+str(i)); temp=marker.with_name(marker.name+'.tmp')
                    temp.write_text(str(n));temp.replace(marker)
                if n==1:
                    with lock: ready.add(i)
            except OSError as e:
                with lock:
                    errors.append(e.errno)
                    error_details.append(dict(errno=e.errno,stage=stage,iteration=n,thread=i,boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME)))
                break
            time.sleep(.01)
    except BaseException as e:
        with lock: errors.append(repr(e))
    finally:
        try:
            if fd is not None: os.close(fd)
        except OSError as e:
            with lock:
                errors.append(e.errno)
                error_details.append(dict(errno=e.errno,stage='close',iteration=n,thread=i,boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME)))
        counts[str(i)]=n
if KIND=='probe':
    fd=os.open(root/TAG,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    print('held-ready',flush=True)
    while not stop.exists(): time.sleep(.005)
    counts['probe']=0
    try:
        assert os.write(fd,b'recovered-durable')==17
        os.fsync(fd);counts['probe']=1
    except OSError as e: errors.append(e.errno)
    finally:
        try: os.close(fd)
        except OSError as e: errors.append(e.errno)
elif KIND=='allocate':
    n=0
    while not stop.exists():
        try:
            body=(TAG+':'+str(n)).encode()
            with (root/(TAG+'-'+str(n))).open('xb') as f:
                f.write(body);f.flush()
                if n%2==0:
                    os.fsync(f.fileno());allocated.append(n)
                    if len(allocated)==1: print('held-ready',flush=True)
        except OSError as e: errors.append(e.errno)
        n+=1;time.sleep(.01)
    counts['allocate']=len(allocated)
elif KIND=='cwd':
    os.chdir(root); print('held-ready',flush=True)
    while not stop.exists(): time.sleep(.01)
    try: os.stat('.'); counts['cwd']=1
    except OSError as e: errors.append(e.errno)
else:
    workers=[threading.Thread(target=run,args=(i,)) for i in range(THREADS)]
    for w in workers: w.start()
    # A replacement's first CREATE can wait out the authority's retained
    # ten-second cache horizon. This setup bound is independent of the later
    # EBUSY and power-drain assertions, which start only after real fsync.
    deadline=time.monotonic()+20
    while True:
        with lock: active=len(ready); failures=list(errors)
        assert not failures,failures
        if active==THREADS: break
        assert time.monotonic()<deadline,('initial fsync did not complete',active,THREADS)
        time.sleep(.005)
    print('held-ready',flush=True)
    for w in workers: w.join()
value={'counts':counts,'errors':errors,'error_details':error_details,'tag':TAG}
if KIND=='allocate': value['allocated']=allocated
result.write_text(json.dumps(value))
'''
        variables = {'STOP': tag+'.stop', 'RESULT': tag+'.json', 'ROOT': self.a.target,
                     'TAG': tag, 'KIND': kind, 'THREADS': threads}
        # Assign constants rather than substitute into Python string literals.
        source = '\n'.join(k+'='+repr(v) for k, v in variables.items())+'\n'+worker
        stderr = (self.a.evidence / (tag+'.stderr')).open('w')
        p = subprocess.Popen(['/usr/bin/ssh', '-F', self.g.ready['ssh_config'],
            'portablefs-workspace', 'python3 -u -c '+shlex.quote(source)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(p.stdout, selectors.EVENT_READ)
                assert ready.select(22), 'application holder did not start'
                assert p.stdout.readline().strip() == 'held-ready', p.poll()
            yield p, stop, result
        finally:
            if p.poll() is None:
                with contextlib.suppress(Exception):
                    self.g.ssh('touch '+stop)
                try: p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.terminate(); p.wait(timeout=5)
            p.stdout.close(); stderr.close()

    def finish_holder(self, holder, allow_errors=False):
        p, stop, result = holder
        self.g.ssh('touch '+stop)
        assert p.wait(timeout=20) == 0
        value = json.loads(self.g.ssh('cat '+result))
        assert all(isinstance(e, int) for e in value['errors']), value
        assert allow_errors or not value['errors'], value
        assert value['counts'] and all(n > 0 or allow_errors and n == 0 for n in value['counts'].values()), value
        if 'allocated' in value:
            check = """import pathlib,json
r=pathlib.Path('/var/tmp/pfs-native/home/peer');v=json.loads(VALUE)
for n in v['allocated']:
    assert (r/(v['tag']+'-'+str(n))).read_bytes()==(v['tag']+':'+str(n)).encode(),n
print('all-allocated-acknowledgements-intact')
""".replace('VALUE', repr(json.dumps(value)))
            assert self.a.peer(check) == 'all-allocated-acknowledgements-intact'
        elif 'probe' in value['counts']:
            if value['counts']['probe']:
                assert self.a.peer("import pathlib;print((pathlib.Path('/var/tmp/pfs-native/home/peer')/"+repr(value['tag'])+").read_text())") == 'recovered-durable'
        elif 'cwd' not in value['counts']:
            # Every fsync-acknowledged record is checked through the independent
            # ordinary peer, including a failure tail beyond the ack watermark.
            check = """import pathlib,json
r=pathlib.Path('/var/tmp/pfs-native/home/peer'); v=json.loads(VALUE)
for i,n in v['counts'].items():
    data=(r/(v['tag']+'-'+i)).read_bytes()
    expected=b''.join(('%08d\\n'%j).encode() for j in range(n))
    assert data[:len(expected)]==expected,(i,n,len(data))
print('all-acknowledged-records-intact')
""".replace('VALUE', repr(json.dumps(value)))
            assert self.a.peer(check) == 'all-acknowledged-records-intact'
        self.g.ssh('rm -f '+stop+' '+result)
        return value

    def pause_resume(self, seconds=1):
        started = time.monotonic()
        self.g.command('pause')
        paused = self.g.wait('paused', 20)
        drain = time.monotonic()-started
        assert paused['fenced'] and drain < 15, (paused, drain)
        time.sleep(seconds)
        self.g.command('resume'); self.g.wait('resumed', 20)
        self.a.ready(self.g, timeout=15)
        return drain

    def network(self):
        for seconds in (8, 20, 90):
            before = self.a.authority_sessions()
            generation = int(self.a.status(self.g)['generation'])
            incarnation = self.mount()['mount']['incarnation']
            with self.holder('fsync') as holder, self.holder('probe') as probe_holder, self.holder('allocate') as allocate_holder:
                self.a.network(True)
                started = time.monotonic()
                try:
                    while time.monotonic()-started < seconds:
                        self.a.status(self.g)  # A real caller during awake recovery.
                        time.sleep(.2)
                finally:
                    self.a.network(False)
                # A still-ready snapshot can describe the old interval while
                # its last assigned RPC is settling after restoration. Require
                # the new recovery publication before testing fresh durable I/O.
                deadline = time.monotonic()+20
                while True:
                    status = self.a.status(self.g)
                    recovered = next(m for m in status['mounts'] if m['mount']['volumeId'] == self.a.volume)
                    if int(status['generation']) > generation and recovered['state'] == 'ready': break
                    assert recovered['state'] not in ('terminal', 'authorization-required'), recovered
                    assert time.monotonic() < deadline, status
                    time.sleep(.05)
                recovery = time.monotonic()-started-seconds
                assert recovered['mount']['incarnation'] == incarnation, recovered
                assert self.a.authority_sessions() == before, 'outage replaced the authority session'
                probe_result = self.finish_holder(probe_holder)
                probe = 'pfs-native-recovered-'+uuid.uuid4().hex
                payload = 'durable-after-outage-'+str(seconds)
                script = "import os,pathlib;p=pathlib.Path("+repr(self.a.target)+")/"+repr(probe)+";f=p.open('xb');f.write("+repr(payload.encode())+");f.flush();os.fsync(f.fileno());f.close();assert p.read_text()=="+repr(payload)
                self.g.ssh('python3 -c '+shlex.quote(script))
                assert self.a.peer("import pathlib;print((pathlib.Path('/var/tmp/pfs-native/home/peer')/"+repr(probe)+").read_text())") == payload
                allocation = self.finish_holder(allocate_holder, allow_errors=True)
                value = self.finish_holder(holder, allow_errors=True)
            self.save('managed-network-outage-'+str(seconds)+'s',
                      {'recovery_seconds': recovery, 'application': value,
                       'recovery_probe': probe_result, 'allocation': allocation, 'sessions': before})

    def busy(self, public):
        for kind in ('cwd', 'fsync'):
            with self.holder(kind) as holder:
                started = time.monotonic()
                self.g.command('umount', body=public['mount'])
                assert self.g.wait('umount-accepted', 10)['code'] == 'accepted'
                self.a.job(self.g, 'umount', timeout=5, allow_fail=True)
                job = self.a.last_job
                assert job['phase'] == 'failed' and job['failure'] == 'busy' and 'busy' in job['reason'].lower(), job
                assert time.monotonic()-started < 5 and self.mount()['state'] == 'ready'
                value = self.finish_holder(holder)
            self.a.unmount(self.g, public)
            public = self.a.mount(self.g)
            self.save('managed-busy-'+kind+'-unmount-retry', {'job': job, 'application': value})
        return public

    def umount_suspend(self, public):
        with self.holder('fsync') as holder:
            started = time.monotonic()
            self.g.p.stdin.write(json.dumps({'command':'umount','body':public['mount']})+'\n'+json.dumps({'command':'pause'})+'\n')
            self.g.p.stdin.flush()
            assert self.g.wait('umount-accepted', 10)['code'] == 'accepted'
            paused = self.g.wait('paused', 20)
            elapsed = time.monotonic()-started
            assert paused['fenced'] and elapsed < 15, paused
            self.g.command('resume'); self.g.wait('resumed', 20)
            self.a.ready(self.g, timeout=15)
            self.a.job(self.g, 'umount', timeout=5, allow_fail=True)
            job = self.a.last_job
            assert job['phase'] == 'failed' and job['failure'] in ('busy', 'stopped'), job
            value = self.finish_holder(holder)
        self.save('managed-umount-suspend-independent-budget',
                  {'drain_seconds': elapsed, 'job': job, 'application': value})

    def busy_killed_application(self, public):
        with self.holder('killable') as holder:
            self.g.command('umount', body=public['mount'])
            assert self.g.wait('umount-accepted', 10)['code'] == 'accepted'
            self.a.job(self.g, 'umount', timeout=5, allow_fail=True)
            job = self.a.last_job
            assert job['phase'] == 'failed' and job['failure'] == 'busy', job
            tag = pathlib.Path(holder[2]).stem
            kill = """import os,pathlib,signal
p=int((pathlib.Path.home()/(tag+'.pid')).read_text())
fd=os.pidfd_open(p)
assert pathlib.Path('/proc',str(p)).stat().st_uid==1000
assert tag.encode() in pathlib.Path('/proc',str(p),'cmdline').read_bytes()
signal.pidfd_send_signal(fd,signal.SIGKILL);os.close(fd)
"""
            started = time.monotonic()
            self.g.ssh('python3 -c '+shlex.quote('tag='+repr(tag)+'\n'+kill))
            assert holder[0].wait(timeout=5) != 0
            elapsed = time.monotonic()-started
            assert elapsed < 5 and self.mount()['state'] == 'ready'
            watermarks = json.loads(self.g.ssh('python3 -c '+shlex.quote(
                "import json,pathlib;h=pathlib.Path.home();print(json.dumps([int((h/("+repr(tag)+"+'.ack-'+str(i))).read_text()) for i in range(2)]))")))
            assert all(n > 0 for n in watermarks), watermarks
            verify = """import pathlib
r=pathlib.Path('/var/tmp/pfs-native/home/peer')
for i,n in enumerate(counts):
    body=(r/(tag+'-'+str(i))).read_bytes()
    expected=b''.join(('%08d\\n'%j).encode() for j in range(n))
    assert body[:len(expected)]==expected
print('acknowledged-prefix-intact')
"""
            assert self.a.peer('tag='+repr(tag)+'\ncounts='+repr(watermarks)+'\n'+verify) == 'acknowledged-prefix-intact'
            name = tag+'-survivor'
            fresh = "import os,pathlib;p=pathlib.Path("+repr(self.a.target)+")/"+repr(name)+";f=p.open('xb');f.write(b'after-application-kill');f.flush();os.fsync(f.fileno());f.close();assert p.read_bytes()==b'after-application-kill'"
            self.g.ssh('python3 -c '+shlex.quote(fresh))
            assert self.a.peer("import pathlib;print((pathlib.Path('/var/tmp/pfs-native/home/peer')/"+repr(name)+").read_text())") == 'after-application-kill'
            self.g.ssh('rm -f ~/'+tag+'.pid ~/'+tag+'.ack-* ~/'+tag+'.tmp')
        self.a.unmount(self.g, public)
        replacement = self.a.mount(self.g)
        self.save('managed-busy-unmount-application-sigkill',
                  {'job': job, 'application_exit_seconds': elapsed, 'acknowledged_watermarks': watermarks})
        return replacement

    def suspend(self):
        with self.holder('allocate') as namespace, self.holder('positioned', threads=4) as holder:
            drains = [self.pause_resume(seconds=.1) for _ in range(30)]
            value = self.finish_holder(holder)
            allocating = self.finish_holder(namespace, allow_errors=True)
        self.save('managed-suspend-application-transparency',
                  {'drain_seconds': drains, 'application': value, 'namespace': allocating})

    def listing(self):
        rows = json.loads(self.g.ssh('portablefs mounts --json'))['mounts']
        assert len([r for r in rows if r['mountPath'] == self.a.target]) == 1, rows
        plain = self.g.ssh('portablefs mounts')
        assert self.a.target in plain and 'no active mounts' not in plain, plain
        self.save('managed-guest-cli-inventory', {'json': rows, 'text': plain})

    def mount_race(self, public):
        self.a.unmount(self.g, public)
        public = self.a.mount(self.g, provision_only=True)
        observed = len(self.g.history)
        self.g.p.stdin.write(json.dumps({'command':'mount','body':public['mount']})+'\n'+json.dumps({'command':'pause'})+'\n')
        self.g.p.stdin.flush()
        paused = self.g.wait('paused', 20)
        assert paused['fenced']
        self.g.command('resume'); self.g.wait('resumed', 20)
        accepted = next((e for e in self.g.history[observed:] if e['event'] == 'mount-accepted'), None)
        if accepted is None: accepted = self.g.wait('mount-accepted', 10)
        assert accepted['code'] == 'accepted', accepted
        self.a.job(self.g, 'mount', timeout=15)
        mounted = self.a.ready(self.g, timeout=15)
        public['incarnation'] = mounted['mount']['incarnation']
        assert self.g.ssh("printf resumed-intent > /workspaces/native-managed/mount-race; sync /workspaces/native-managed/mount-race; cat /workspaces/native-managed/mount-race") == 'resumed-intent'
        assert self.a.peer("import pathlib;print(pathlib.Path('/var/tmp/pfs-native/home/peer/mount-race').read_text())") == 'resumed-intent'
        self.save('managed-mount-intent-across-suspend', {'mount': mounted})
        return public

    def unresponsive_child(self, public):
        with self.holder('probe') as holder:
            self.a.network(True)
            try:
                deadline = time.monotonic()+30
                while self.mount()['state'] != 'recovering':
                    assert time.monotonic()<deadline
                    time.sleep(.05)
                signal_child = """import os,pathlib,signal
pids=[]
for p in pathlib.Path('/proc').glob('[0-9]*'):
    try:
        args=(p/'cmdline').read_bytes().split(b'\\0')
        if p.stat().st_uid==1000 and args[:2]==[b'/usr/local/bin/portablefs',b'mount'] and b'native-managed' in args: pids.append(int(p.name))
    except FileNotFoundError: pass
assert len(pids)==1,pids
fd=os.pidfd_open(pids[0])
signal.pidfd_send_signal(fd,signal.SIGSTOP)
os.close(fd)
print(pids[0])
"""
                pid = int(self.g.ssh('python3 -c '+shlex.quote(signal_child)))
                started = time.monotonic()
                self.g.command('umount', body=public['mount'])
                assert self.g.wait('umount-accepted', 10)['code'] == 'accepted'
                self.a.job(self.g, 'umount', timeout=10)
                self.a.protected(self.g)
                elapsed = time.monotonic()-started
                assert elapsed < 10, elapsed
                value = self.finish_holder(holder, allow_errors=True)
                assert value['errors'], value
            finally:
                self.a.network(False)
        replacement = self.a.mount(self.g)
        assert replacement['incarnation'] != public['incarnation']
        self.save('managed-terminal-removal-unresponsive-child',
                  {'pid': pid, 'seconds': elapsed, 'application': value})
        return replacement

    def terminal_io(self, public):
        with self.holder('fsync', threads=4) as holder:
            started = time.monotonic()
            self.a.kill_child(self.g)
            elapsed = time.monotonic()-started
            assert elapsed < 10, elapsed
            mounted = self.mount()
            assert 'killed' in mounted['reason'] and mounted['cleanup'] == 'complete', mounted
            value = self.finish_holder(holder, allow_errors=True)
            assert value['errors'], value
        self.a.unmount(self.g, public)
        replacement = self.a.mount(self.g)
        assert replacement['incarnation'] != public['incarnation']
        self.save('managed-terminal-removal-wakes-inflight-io',
                  {'seconds': elapsed, 'terminal': mounted, 'application': value})
        return replacement

    def long_pause(self, public):
        with self.holder('cwd') as holder:
            self.g.command('pause'); assert self.g.wait('paused', 20)['fenced']
            time.sleep(150)
            started = time.monotonic()
            self.g.command('resume'); self.g.wait('resumed', 20)
            while True:
                mounted = self.mount()
                if mounted and mounted['state'] == 'terminal' and mounted.get('cleanup') == 'complete': break
                assert time.monotonic()-started < 15, mounted
                time.sleep(.05)
            assert 'session ended' in mounted['reason'], mounted
            # The original cwd is terminal. It must not prevent exact removal,
            # fresh provisioning, or an independent fresh-open application.
            self.a.protected(self.g)
            self.a.unmount(self.g, public)
            replacement = self.a.mount(self.g)
            assert replacement['incarnation'] != public['incarnation']
            self.g.ssh('touch '+holder[1])
            assert holder[0].wait(timeout=10) == 0
            old_cwd = json.loads(self.g.ssh('cat '+holder[2]))
            assert old_cwd['errors'] and all(e in (5, 107, 116) for e in old_cwd['errors']), old_cwd
            self.g.ssh('rm -f '+holder[1]+' '+holder[2])
            assert self.g.ssh('cat /workspaces/native-managed/data') == 'peer-during-pause'
        self.save('managed-long-pause-terminal-replacement', {'terminal': mounted, 'settle_seconds': time.monotonic()-started})
        self.save('managed-terminal-cause-and-cwd-removal', {'reason': mounted['reason']})
        return replacement

    def caught_signal(self, public):
        with self.holder('probe') as holder:
            started = time.monotonic()
            self.a.kill_child(self.g, 'SIGTERM')
            mounted = self.mount()
            assert time.monotonic()-started < 10 and mounted['cleanup'] == 'complete', mounted
            assert mounted['reason'] == 'workspace child received signal: terminated', mounted
            value = self.finish_holder(holder, allow_errors=True)
            assert value['errors'], value
        self.a.unmount(self.g, public)
        replacement = self.a.mount(self.g)
        self.save('managed-caught-signal-terminal-cause', {'terminal': mounted, 'application': value})
        return replacement


def lifecycle_checks(authority, guest, public, record):
    checks = LifecycleChecks(authority, guest, record)
    checks.listing()
    checks.network()
    public = checks.busy(public)
    public = checks.busy_killed_application(public)
    checks.umount_suspend(public)
    checks.suspend()
    public = checks.mount_race(public)
    public = checks.unresponsive_child(public)
    public = checks.terminal_io(public)
    public = checks.caught_signal(public)
    return checks.long_pause(public)
