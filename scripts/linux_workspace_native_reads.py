"""Read-only searches and Git walks over a repository larger than metadata caches."""
import json
import pathlib
import shlex
import subprocess
import time


def read_checks(authority, guest, evidence, record, rounds=20):
    evidence = pathlib.Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    setup = r'''
import json,pathlib,subprocess
root=pathlib.Path('/var/tmp/pfs-native/home/peer/read-stress')
root.mkdir()
for directory in range(6300):
    parent=root/('g%02d'%(directory//100))/('d%03d'%(directory%100));parent.mkdir(parents=True,exist_ok=True)
    for number in range(5):
        (parent/('f%03d.go'%number)).write_text('package fixture\n'+('// TODO: retained search marker\n' if directory%2==0 and number==0 else '// ordinary source\n')+'var payload = "'+('x'*1024)+'"\n')
def git(*args):subprocess.run(['git','-C',str(root),*args],check=True,stdout=subprocess.DEVNULL)
git('init','-q');git('add','.');git('-c','user.name=Workspace Test','-c','user.email=workspace@example.invalid','commit','-qm','Read stress fixture')
print(json.dumps({'files':31500,'matches':3150,'directories':6363}))
'''
    expected = json.loads(authority.peer(setup))
    assert expected == {'files':31500, 'matches':3150, 'directories':6363}, expected
    target = authority.target + '/read-stress'
    ssh = ['/usr/bin/ssh', '-F', guest.ready['ssh_config'], 'portablefs-workspace']
    commands = [('rg', 'rg -l TODO .'), ('git-status', 'GIT_OPTIONAL_LOCKS=0 git -c safe.directory=' +
        shlex.quote(target) + ' status --porcelain')]
    rows = []
    for iteration in range(rounds):
        for name, command in commands:
            started = time.monotonic()
            result = subprocess.run([*ssh, 'cd ' + shlex.quote(target) + ' && ' + command],
                stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=600)
            row = {'iteration':iteration, 'command':name, 'seconds':time.monotonic()-started,
                'returncode':result.returncode, 'lines':len(result.stdout.splitlines()), 'stderr':result.stderr}
            rows.append(row)
            (evidence / 'read-stress.json').write_text(json.dumps({'fixture':expected, 'rounds':rounds, 'runs':rows}, indent=2) + '\n')
            assert result.returncode == 0 and not result.stderr, row
            assert row['lines'] == (expected['matches'] if name == 'rg' else 0), row
    record('managed-large-repository-read-stress')
    # Namespace cleanup also crosses the real mount rather than backing storage.
    authority.peer("import shutil;shutil.rmtree('/var/tmp/pfs-native/home/peer/read-stress')")
