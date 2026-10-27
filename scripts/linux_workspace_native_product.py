"""Throwaway SMAppService tests; no installed app identities or SSH config."""
import base64
import contextlib
import fcntl
import json
import os
import pathlib
import plistlib
import select
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid


def execution_reference_busy(path):
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: return True
        return False
    finally: os.close(fd)


def execution_reference_worker(path):
    matches=[]
    rows=subprocess.check_output(['ps','-Ao','pid=,comm='],text=True).splitlines()
    for row in rows:
        if not row.endswith('/com.apple.Virtualization.VirtualMachine'): continue
        pid=int(row.split(None,1)[0])
        observed=subprocess.run(['lsof','-a','-p',str(pid),'-Fpcfn','--',str(path)],text=True,capture_output=True)
        if observed.returncode==0 and str(path) in observed.stdout: matches.append((pid,observed.stdout))
    assert len(matches)==1,{'matching_workers':matches,'reference':str(path)}
    return matches[0]


def product_checks(image, evidence, record, authority=None, api_only=False, outcome_case='crash'):
    assert outcome_case in ('crash','loss') and (outcome_case!='loss' or authority is not None)
    if outcome_case=='loss':
        observe=record
        # A separate disposable service isolates known loss from the crash's
        # unknown outcome. Common acceptance controls run again; count them once.
        record=lambda name:observe(name) if name.startswith('service-loss-') else None
    repo = pathlib.Path(__file__).resolve().parent.parent
    evidence = pathlib.Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix='pfs-wsp-', dir='/private/tmp'))
    home = root/'home'; home.mkdir(mode=0o700)
    app = root/'PortableFS Workspace Test.app'
    contents = app/'Contents'
    service = contents/'Library/LaunchAgents/PortableFSWorkspaceService.app'
    (service/'Contents/MacOS').mkdir(parents=True)
    (contents/'Helpers').mkdir()
    (contents/'MacOS').mkdir()
    identifier = 'dev.portablefs.workspace-tests.' + uuid.uuid4().hex
    label = identifier + '.workspace'
    assert identifier.startswith('dev.portablefs.workspace-tests.')
    env = dict(os.environ, HOME=str(home), PORTABLEFS_E2E_ACCOUNT_HOME=str(home),
               PFS_WORKSPACE_BUILD_COMMIT=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip())
    scratch = evidence/'product-build'
    common = ['swift','build','--package-path',str(repo/'swift/PortableFSKit'),'--scratch-path',str(scratch),'-Xswiftc','-DWORKSPACE_SERVICE_TESTING']
    with (evidence/'product-build.log').open('w') as log:
        for product in ['portablefs-workspace-service','portablefs-workspace-service-test-host']:
            subprocess.run([*common,'--product',product],env=env,check=True,stdout=log,stderr=subprocess.STDOUT)
    binary = pathlib.Path(subprocess.check_output([*common,'--show-bin-path'],env=env,text=True).strip())
    shutil.copy2(binary/'portablefs-workspace-service', service/'Contents/MacOS/portablefs-workspace-service')
    shutil.copy2(binary/'portablefs-workspace-service-test-host', contents/'MacOS/PortableFS')
    cli = contents/'Helpers/portablefs'
    subprocess.run(['go','-C',str(repo/'vcs'),'build','-tags','portablefs_e2e','-o',str(cli),'./cmd/portablefs'],check=True)
    version = json.loads((pathlib.Path(image)/'release.json').read_text())['app_version'] if pathlib.Path(image,'release.json').exists() else 'dev'
    info = {'CFBundleIdentifier':identifier,'CFBundleExecutable':'PortableFS','CFBundleName':'PortableFS Workspace Test '+identifier.rsplit('.',1)[-1][:8],
            'CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':version,'LSBackgroundOnly':True,
            'PFSWorkspaceTestHome':str(home),'PFSWorkspaceTestImage':str(pathlib.Path(image).resolve())}
    with (contents/'Info.plist').open('wb') as f: plistlib.dump(info,f)
    with (service/'Contents/Info.plist').open('wb') as f:
        plistlib.dump({'CFBundleIdentifier':identifier+'.WorkspaceService','CFBundleExecutable':'portablefs-workspace-service',
                      'CFBundleName':'PortableFS Workspace Test Service','CFBundlePackageType':'APPL','CFBundleVersion':'1',
                      'CFBundleShortVersionString':version,'LSBackgroundOnly':True,'LSMinimumSystemVersion':'26.0'},f)
    with (contents/'Library/LaunchAgents'/ (label+'.plist')).open('wb') as f:
        plistlib.dump({'Label':label,'BundleProgram':'Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/MacOS/portablefs-workspace-service',
                      'RunAtLoad':True,'KeepAlive':True,'StandardErrorPath':str(evidence/'service.stderr'),'StandardOutPath':str(evidence/'service.stdout')},f)
    signer = os.environ.get('PFS_WORKSPACE_TEST_SIGNER','-')
    for component in [cli,service,app]:
        command = ['codesign','--force','--options','runtime','--sign',signer]
        if component == service: command += ['--entitlements',str(repo/'swift/PortableFSApp/Config/PortableFSWorkspaceService.entitlements')]
        subprocess.run([*command,str(component)],check=True,capture_output=True)
    subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True)
    fixture = {'root':str(root),'app':str(app),'home':str(home),'identifier':identifier,'label':label,'image':str(image)}
    (evidence/'product-fixture.json').write_text(json.dumps(fixture,indent=2))
    lsregister='/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister'
    subprocess.run([lsregister,'-f',str(app)],check=True)
    host = contents/'MacOS/PortableFS' 
    registered = subprocess.run([str(host),'--workspace-service-register'],env=env,capture_output=True,text=True)
    if registered.returncode:
        (evidence/'product-registration.txt').write_text(registered.stdout+registered.stderr)
        raise RuntimeError('throwaway SMAppService registration requires consent or failed: '+registered.stderr.strip()+'; fixture '+str(evidence/'product-fixture.json'))
    endpoint = home/'.local/state/portablefs/workspace/control.sock'
    def command(*args, success=True):
        result = subprocess.run([str(cli),'workspace',*args],env=env,capture_output=True,text=True,timeout=40)
        if success: assert result.returncode == 0, (args,result.stdout,result.stderr)
        return result
    def status():
        result=command('status','--json',success=False)
        value=json.loads(result.stdout)
        expected=1 if value['state'] in ('refused','busy','cleanup-required') else 0
        assert result.returncode==expected and value['version']==1, (result.returncode,value,result.stderr)
        return value
    def until(predicate, limit=180):
        deadline=time.monotonic()+limit
        while time.monotonic()<deadline:
            try:
                value=status()
                if predicate(value): return value
            except (AssertionError,json.JSONDecodeError): pass
            time.sleep(.1)
        last=command('status','--json',success=False)
        raise AssertionError('product status deadline: '+last.stdout+' '+last.stderr)
    crashed=False
    try:
        deadline=time.monotonic()+30
        while not endpoint.exists():
            assert time.monotonic()<deadline, 'test service did not publish its socket; see service.stderr'
            time.sleep(.1)
        until(lambda s:s['state']=='stopped',30)
        subprocess.run([str(host),'--abandon-workspace-test-request'],env=env,check=True)
        assert status()['state']=='stopped'
        record('service-authenticated-status')
        # Same UID alone has no authority. Python is not a sealed app/CLI peer.
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(3);client.connect(str(endpoint))
            with contextlib.suppress(BrokenPipeError,ConnectionResetError): client.sendall(b'{"version":1,"operation":"start"}\n')
            try: reply=client.recv(4096)
            except ConnectionResetError: reply=b''
            assert not reply
        assert status()['state']=='stopped'
        record('service-unsigned-peer-refusal')
        # A new signed image at the same path is a different release execution.
        original=root/'original-cli';shutil.copy2(cli,original)
        subprocess.run(['codesign','--force','--options','runtime','--sign',signer,'--identifier',identifier+'.foreign',str(cli)],check=True,capture_output=True)
        subprocess.run(['codesign','--force','--options','runtime','--sign',signer,str(app)],check=True,capture_output=True)
        assert command('status','--json',success=False).returncode!=0
        shutil.copy2(original,cli)
        subprocess.run(['codesign','--force','--options','runtime','--sign',signer,str(app)],check=True,capture_output=True)
        until(lambda s:s['state']=='stopped',10)
        record('service-cross-release-refusal')
        for args in [('shell',),('pause',),('identity',),('exec','true'),('vm-list',),('start','--json')]: assert command(*args,success=False).returncode==2
        record('service-api-cli-five-verbs')
        if api_only: return
        command('start');command('start')
        until(lambda s:s['state']=='running')
        record('service-start-idempotent')
        # The registration-only host has exited. SSH still executes in the VM.
        config=home/'.local/state/portablefs/workspace/ssh_config'
        def ssh(script): return subprocess.check_output(['ssh','-F',str(config),'portablefs-workspace',script],env=env,text=True,timeout=30).strip()
        assert ssh('id -u')=='1000'
        ssh('printf service-persistence > /home/workspace/service-product-proof')
        record('service-app-exit-vm-alive')
        before=(home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()
        if authority is not None:
            descriptor=subprocess.check_output(['docker','exec','--user','200001:200001',authority.name,
                '/var/tmp/pfs-native/bin/pfs-workspace-fixture','document-connection','/var/tmp/pfs-native/home/test-pki',authority.endpoint,authority.volume],text=True)
            connection=root/'connection.pfsworkspace';connection.write_text(descriptor)
            def mount_volume():
                command('mount',str(connection),'--json')
                waiting=until(lambda s:s['volumes'] and s['volumes'][0]['state']=='authorization-required' and s['volumes'][0].get('authorizationRequest'))
                public=pathlib.Path(waiting['volumes'][0]['authorizationRequest']).read_bytes()
                response=subprocess.check_output(['docker','exec','--user','200001:200001',authority.name,
                    '/var/tmp/pfs-native/bin/pfs-workspace-fixture','document-authorize','/var/tmp/pfs-native/home/test-pki',base64.b64encode(public).decode()],text=True)
                authorized=root/'authorized.pfsworkspace';authorized.write_text(response)
                command('mount',str(authorized),'--json')
                return until(lambda s:s['volumes'] and s['volumes'][0]['state']=='ready')
            mount_volume()
            assert ssh("python3 -c \"import os; p='/workspaces/native-managed/product-proof'; f=open(p,'wb'); f.write(b'product-volume'); f.flush(); os.fsync(f.fileno()); f.close(); print(open(p).read())\"")=='product-volume'
            assert authority.peer("import os; p='/var/tmp/pfs-native/home/peer/product-proof'; assert open(p).read()=='product-volume'; f=open(p,'w'); f.write('peer-product'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-durable')")=='peer-durable'
            assert ssh('cat /workspaces/native-managed/product-proof')=='peer-product'
            record('service-document-standalone')
            holder=subprocess.Popen(['ssh','-F',str(config),'portablefs-workspace',
                'cd /workspaces/native-managed && echo holding && read -r release'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                assert holder.stdout.readline().strip()=='holding'
                command('umount',authority.volume,'--json')
                until(lambda s:s['volumes'] and s['volumes'][0]['state']=='busy')
                assert ssh('cat /workspaces/native-managed/product-proof')=='peer-product'
            finally:
                holder.stdin.write('release\n');holder.stdin.flush();holder.wait(timeout=15)
                holder.stdin.close();holder.stdout.close();holder.stderr.close()
            command('umount',authority.volume,'--json')
            settled=until(lambda s:not s['volumes'])
            (evidence/'used-clean-unmount.json').write_text(json.dumps(settled,indent=2))
            assert not settled['previousWriteOutcomeUnknown'] and not settled['someChangesWereNotSaved'],settled
            record('service-used-clean-unmount-outcome')
        command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
        if authority is not None:
            settled=status()
            (evidence/'used-clean-stop.json').write_text(json.dumps(settled,indent=2))
            assert not settled['previousWriteOutcomeUnknown'] and not settled['someChangesWereNotSaved'],settled
            record('service-used-clean-stop-outcome')
        record('service-stop-persists')
        # Registration and status cannot defeat the explicit stopped intent.
        subprocess.run([str(host),'--workspace-service-register'],env=env,check=True)
        assert status()['state']=='stopped'
        command('start');until(lambda s:s['state']=='running')
        assert ssh('cat /home/workspace/service-product-proof')=='service-persistence'
        assert (home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()==before
        record('service-ssh-identity-persistence')
        if authority is not None: mount_volume()
        if outcome_case=='loss':
            payload=b'accepted-before-expiry'
            script="""import errno,json,os
f=os.open('/workspaces/native-managed/loss-proof',os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
print('opened',flush=True)
input()
assert os.write(f,b'accepted-before-expiry')==22
print('accepted',flush=True)
input()
try: os.fsync(f); fsync_error=0
except OSError as e: fsync_error=e.errno
try: os.close(f); close_error=0
except OSError as e: close_error=e.errno
print(json.dumps({'fsync_errno':fsync_error,'close_errno':close_error}),flush=True)
"""
            writer=subprocess.Popen(['ssh','-F',str(config),'portablefs-workspace','python3 -u -c '+shlex.quote(script)],
                env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            def writer_line():
                assert select.select([writer.stdout],[],[],30)[0], 'loss writer did not progress'
                return writer.stdout.readline().strip()
            try:
                assert writer_line()=='opened'
                authority.network(True)
                try:
                    writer.stdin.write('\n');writer.stdin.flush()
                    assert writer_line()=='accepted'
                    # Both the guest and authority's original cache horizons
                    # expire while this accepted payload cannot reach storage.
                    time.sleep(20)
                finally: authority.network(False)
                until(lambda s:s['volumes'] and s['volumes'][0]['state']=='ready')
                writer.stdin.write('\n');writer.stdin.flush()
                result=json.loads(writer_line())
                assert result['fsync_errno']==5,result
                assert writer.wait(timeout=20)==0
                assert authority.peer("from pathlib import Path; assert Path('/var/tmp/pfs-native/home/peer/loss-proof').read_bytes()==b''; print('tail-not-applied')")=='tail-not-applied'
                assert authority.peer("import os; p='/var/tmp/pfs-native/home/peer/loss-proof'; f=open(p,'wb'); f.write(b'peer-after-loss'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-durable')")=='peer-durable'
                assert ssh('cat /workspaces/native-managed/loss-proof')=='peer-after-loss'
                record('service-loss-accepted-tail-peer')
            finally:
                if writer.poll() is None: writer.terminate();writer.wait(timeout=20)
                writer.stdin.close();writer.stdout.close();writer.stderr.close()
            command('umount',authority.volume,'--json');until(lambda s:not s['volumes'])
            command('stop','--json');settled=until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
            assert settled['someChangesWereNotSaved'],settled
            statuses=[]
            for raw in settled['retainedEvidence']:
                page=json.loads(authority.fixture('decode-status-evidence',raw))
                statuses += page.get('mounts',[]) + [r['mountStatus'] for r in page.get('retired',[]) if 'mountStatus' in r]
            losses=[loss for row in statuses for loss in row.get('loss',[]) if int(loss.get('acceptedBytes','0'))==len(payload)]
            assert losses and all(int(loss['acceptedEntries'])==1 for loss in losses), statuses
            (evidence/'known-loss-retained.json').write_text(json.dumps({'status':settled,'losses':losses,'old_descriptor':result},indent=2))
            record('service-loss-retained-after-clean-stop')
            return
        old_boot=ssh('cat /proc/sys/kernel/random/boot_id')
        if authority is not None:
            assert ssh('cat /workspaces/native-managed/product-proof')=='peer-product'
        reference=home/'.local/state/portablefs/workspace/owner.lock'
        worker,observed=execution_reference_worker(reference)
        assert execution_reference_busy(reference)
        suspended=False
        try:
            os.kill(worker,signal.SIGSTOP);suspended=True
            subprocess.run(['launchctl','kill','SIGKILL',f'gui/{os.getuid()}/{label}'],check=True)
            crashed=True
            refused=until(lambda s:s['state']=='cleanup-required')
            assert command('start',success=False).returncode!=0
            assert execution_reference_busy(reference)
            (evidence/'crash-worker-held.json').write_text(json.dumps({'worker':worker,'lsof':observed,'status':refused},indent=2))
            record('service-crash-live-worker-refusal')
        finally:
            if suspended: os.kill(worker,signal.SIGCONT)
        deadline=time.monotonic()+30
        while execution_reference_busy(reference):
            assert time.monotonic()<deadline, 'VM worker retained execution reference after owner death'
            time.sleep(.01)
        if authority is not None:
            assert authority.peer("import os; p='/var/tmp/pfs-native/home/peer/product-proof'; f=open(p,'wb'); f.write(b'peer-after-owner-crash'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-durable')")=='peer-durable'
        command('start');until(lambda s:s['state']=='running')
        assert ssh('cat /proc/sys/kernel/random/boot_id')!=old_boot
        assert ssh('cat /home/workspace/service-product-proof')=='service-persistence'
        assert (home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()==before
        record('service-crash-same-boot-recovery')
        record('service-crash-no-ram-adoption')
        if authority is not None:
            mount_volume()
            assert ssh('cat /workspaces/native-managed/product-proof')=='peer-after-owner-crash'
            assert status()['previousWriteOutcomeUnknown']
            command('umount',authority.volume,'--json');until(lambda s:not s['volumes'])
        command('stop','--json');settled=until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
        if authority is not None:
            assert settled['previousWriteOutcomeUnknown'],settled
            (evidence/'crash-reconciled-unknown.json').write_text(json.dumps(settled,indent=2))
            record('service-crash-reconcile-unknown-retained')
        crashed=False
    finally:
        # This identity was generated by this invocation. Never unregister any
        # installed or dev-host identity, and retain unconfirmed execution data.
        assert label.startswith('dev.portablefs.workspace-tests.')
        confirmed_absent=False
        if not crashed:
            try:
                command('stop','--force','--json');until(lambda s:s['state']=='stopped',30)
                confirmed_absent=True
            except Exception as error:
                (evidence/'cleanup-unconfirmed.txt').write_text(str(error)+'\n')
        subprocess.run([str(host),'--unregister-workspace-test'],env=env,check=True,capture_output=True,text=True)
        subprocess.run([lsregister,'-u',str(app)],check=True)
        if confirmed_absent: shutil.rmtree(root)
        else: (evidence/'unconfirmed-test-vm-state.txt').write_text(str(root)+'\nretained until exact execution-reference or host-boot absence proof\n')

if __name__=='__main__':
    import sys
    observed=[]
    product_checks(sys.argv[1],sys.argv[2],lambda name:(observed.append(name),print('PASS:',name,flush=True)),api_only='--api-only' in sys.argv[3:])
    pathlib.Path(sys.argv[2],'product-results.json').write_text(json.dumps({'passed':observed},indent=2))
