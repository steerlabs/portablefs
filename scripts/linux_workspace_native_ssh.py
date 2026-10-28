"""Session ownership and detached-job lifetime through real SSH disconnects."""
import json
import pathlib
import shlex
import time
import uuid


WORKER = r'''
import json,os,pathlib,signal,sys,time
root=pathlib.Path(sys.argv[1]);name=sys.argv[2]
def put(suffix,value):
    path=root/(name+suffix);tmp=path.with_suffix(path.suffix+'.tmp')
    with tmp.open('w') as f: json.dump(value,f);f.flush();os.fsync(f.fileno())
    tmp.replace(path)
def stop(sig,frame):
    put('.stopped',{'pid':os.getpid(),'signal':sig})
    sys.exit(0)
signal.signal(signal.SIGTERM,stop)
if signal.getsignal(signal.SIGHUP)!=signal.SIG_IGN:
    signal.signal(signal.SIGHUP,stop)
put('.started',{'pid':os.getpid(),'start':pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19],
    'cgroup':pathlib.Path('/proc/self/cgroup').read_text()})
n=0
while True:
    n+=1;put('.progress',n);time.sleep(.1)
'''


class SSHJobs:
    def __init__(self, ssh, evidence, record):
        self.evidence = pathlib.Path(evidence)
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.record = record
        self.tag = 'pfs-ssh-jobs-' + uuid.uuid4().hex
        self.root = '/home/workspace/' + self.tag
        session = json.loads(ssh("python3 -c " + shlex.quote(
            "import json,os,pathlib;print(json.dumps({'cgroup':pathlib.Path('/proc/self/cgroup').read_text(),"
            "'session':os.environ.get('XDG_SESSION_ID'),'runtime':os.environ.get('XDG_RUNTIME_DIR')}))")))
        assert '/user.slice/user-1000.slice/session-' in session['cgroup'] and '.scope' in session['cgroup'], session
        assert session['session'] and session['runtime'] == '/run/user/1000', session
        self.record('ssh-logind-session')
        assert ssh('loginctl show-user workspace -p Linger --value') == 'yes'
        assert ssh('systemctl --user is-active default.target') == 'active'
        self.record('ssh-user-manager-linger')
        ssh('mkdir -m700 ' + shlex.quote(self.root) + '; cat > ' + shlex.quote(self.root + '/worker.py') +
            " <<'PFS_SSH_WORKER'\n" + WORKER + '\nPFS_SSH_WORKER')
        worker = 'python3 ' + shlex.quote(self.root + '/worker.py') + ' ' + shlex.quote(self.root)
        # Each command returns normally with every inherited stream closed.
        # The three jobs must outlive the actual connection service teardown.
        ssh('nohup ' + worker + ' nohup </dev/null >' + shlex.quote(self.root + '/nohup.log') + ' 2>&1 &')
        ssh('setsid ' + worker + ' setsid </dev/null >' + shlex.quote(self.root + '/setsid.log') + ' 2>&1 &')
        ssh('systemd-run --user --unit=' + self.tag + ' ' + worker + ' user-service')
        self.names = ['nohup', 'setsid', 'user-service']
        self.started = self.observe(ssh)
        for name, value in self.started.items():
            cgroup = value['started']['cgroup']
            expected = self.tag + '.service' if name == 'user-service' else 'session-'
            assert '/user.slice/user-1000.slice/' in cgroup and expected in cgroup, (name, value)
            assert 'portablefs-workspace-ssh@' not in cgroup, (name, value)
        for _ in range(3):
            time.sleep(1)
            current = self.observe(ssh)
            for name, value in current.items():
                assert value['started'] == self.started[name]['started'], (name, value)
                assert value['progress'] > self.started[name]['progress'], (name, value)
        self.record('ssh-background-disconnect')
        (self.evidence / 'disconnect.json').write_text(json.dumps({'session':session, 'started':self.started,
            'after_disconnects':current, 'root':self.root}, indent=2) + '\n')

    def observe(self, ssh):
        source = r'''
import json,pathlib,time
root=pathlib.Path(ROOT);names=NAMES;deadline=time.monotonic()+5
while not all((root/(n+'.progress')).exists() for n in names):
    assert time.monotonic()<deadline,'detached jobs did not start'
    time.sleep(.05)
out={}
for name in names:
    value=json.loads((root/(name+'.started')).read_text());pid=value['pid']
    current=pathlib.Path('/proc')/str(pid)
    stat=current.joinpath('stat').read_text().rsplit(')',1)[1].split()
    assert stat[0]!='Z' and stat[19]==value['start'],(name,value,stat)
    assert not (root/(name+'.stopped')).exists(),name
    out[name]={'started':value,'progress':json.loads((root/(name+'.progress')).read_text())}
print(json.dumps(out))
'''.replace('ROOT', repr(self.root)).replace('NAMES', repr(self.names))
        return json.loads(ssh('python3 -c ' + shlex.quote(source)))

    def check_shutdown(self, ssh):
        source = r'''
import json,pathlib,signal
root=pathlib.Path(ROOT);out={}
for name in NAMES:
    value=json.loads((root/(name+'.stopped')).read_text())
    assert value['signal'] in (signal.SIGTERM,signal.SIGHUP),(name,value)
    out[name]=value
print(json.dumps(out))
'''.replace('ROOT', repr(self.root)).replace('NAMES', repr(self.names))
        stopped = json.loads(ssh('python3 -c ' + shlex.quote(source)))
        for name, value in stopped.items():
            assert value['pid'] == self.started[name]['started']['pid'], (name, value)
        (self.evidence / 'shutdown.json').write_text(json.dumps(stopped, indent=2) + '\n')
        ssh('rm -r ' + shlex.quote(self.root))
        self.record('ssh-background-stop')
