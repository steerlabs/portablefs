"""Read-only searches and Git walks over a repository larger than metadata caches."""
import json
import pathlib
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from linux_workspace_native_hold import hold_between_cases


def read_checks(authority, guest, evidence, record, rounds=20, stress_work=None):
    evidence = pathlib.Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    hold_between_cases(restart_on_release=True)
    setup = r'''
import json,pathlib,shutil,subprocess
from concurrent.futures import ThreadPoolExecutor
root=pathlib.Path('/var/tmp/pfs-native/home/read-stress-source')
root.mkdir()
for directory in range(6300):
    parent=root/('g%02d'%(directory//100))/('d%03d'%(directory%100));parent.mkdir(parents=True,exist_ok=True)
    for number in range(5):
        (parent/('f%03d.go'%number)).write_text('package fixture\n'+('// TODO: retained search marker\n' if directory%2==0 and number==0 else '// ordinary source\n')+'var payload = "'+('x'*1024)+'"\n')
def git(*args):subprocess.run(['git','-C',str(root),*args],check=True,stdout=subprocess.DEVNULL)
git('init','-q');git('add','.');git('-c','user.name=Workspace Test','-c','user.email=workspace@example.invalid','commit','-qm','Read stress fixture')
# Populate through the independent peer after preparing Git's local objects.
# Parallel file imports keep fixture preparation out of the read-load result.
def copy(source,target):
    with open(source,'rb') as incoming,open(target,'wb') as outgoing:shutil.copyfileobj(incoming,outgoing,1024*1024)
    shutil.copystat(source,target,follow_symlinks=False)
    return target
with ThreadPoolExecutor(max_workers=8) as pool:
    pending=[]
    def submit(source,target):
        pending.append(pool.submit(copy,source,target))
        return target
    shutil.copytree(root,'/var/tmp/pfs-native/home/peer/read-stress',symlinks=True,copy_function=submit)
    for future in pending:future.result()
subprocess.run(['sync','-f','/var/tmp/pfs-native/home/peer/read-stress'],check=True)
print(json.dumps({'files':31500,'matches':3150,'directories':6363}))
'''
    expected = json.loads(authority.peer(setup))
    assert expected == {'files':31500, 'matches':3150, 'directories':6363}, expected
    target = authority.target + '/read-stress'
    ssh = ['/usr/bin/ssh', '-F', guest.ready['ssh_config'], 'portablefs-workspace']
    # The imported index names the source filesystem's stat identities. Refresh
    # it once through the managed mount, as an ordinary first status would, so
    # the read-only rounds exercise normal metadata walks without rehashing every
    # unchanged blob solely because the fixture crossed filesystems.
    hold_between_cases(restart_on_release=True)
    began = time.monotonic()
    prepared = subprocess.run([*ssh, 'cd ' + shlex.quote(target) + ' && git -c safe.directory=' +
        shlex.quote(target) + ' status --porcelain'], stdin=subprocess.DEVNULL, text=True,
        capture_output=True, timeout=1800)
    (evidence / 'index-refresh.json').write_text(json.dumps({'seconds':time.monotonic()-began,
        'returncode':prepared.returncode, 'stdout':prepared.stdout, 'stderr':prepared.stderr}, indent=2) + '\n')
    assert prepared.returncode == 0 and not prepared.stdout and not prepared.stderr, prepared
    commands = [('rg', 'rg -l TODO .'), ('git-status', 'GIT_OPTIONAL_LOCKS=0 git -c safe.directory=' +
        shlex.quote(target) + ' status --porcelain')]
    rows = []
    # The overnight campaign overlaps its requested Redis build with the
    # strict rounds, after fixture setup and the index refresh have finished.
    with ThreadPoolExecutor(max_workers=1) as pool:
        load = pool.submit(stress_work) if stress_work else None
        for iteration in range(rounds):
            for name, command in commands:
                hold_between_cases(restart_on_release=True)
                started = time.monotonic()
                result = subprocess.run([*ssh, 'cd ' + shlex.quote(target) + ' && ' + command],
                    stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=600)
                row = {'iteration':iteration, 'command':name, 'seconds':time.monotonic()-started,
                    'returncode':result.returncode, 'lines':len(result.stdout.splitlines()), 'stderr':result.stderr}
                rows.append(row)
                (evidence / 'read-stress.json').write_text(json.dumps({'fixture':expected, 'rounds':rounds, 'runs':rows}, indent=2) + '\n')
                assert result.returncode == 0 and not result.stderr, row
                assert row['lines'] == (expected['matches'] if name == 'rg' else 0), row
        if load: load.result()
    record('managed-large-repository-read-stress')
    # Namespace cleanup also crosses the real mount rather than backing storage.
    authority.peer("import shutil;shutil.rmtree('/var/tmp/pfs-native/home/peer/read-stress');shutil.rmtree('/var/tmp/pfs-native/home/read-stress-source')")
