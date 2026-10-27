"""Throwaway SMAppService tests; no installed app identities or SSH config."""
import base64
import contextlib
import fcntl
import select
import shlex
import signal
import hashlib

import json
import os
import pathlib
import plistlib
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from linux_workspace_native_editors import editor_checks


def wait_for_hold():
    path = os.environ.get('PFS_TEST_HOLD_FILE')
    while path and pathlib.Path(path).exists():
        print('HOLD: waiting between native cases', flush=True)
        time.sleep(30)


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


def product_checks(image, evidence, record, authority=None, api_only=False, defer_ui=False, defer_case=None, outcome_case='crash'):
    assert outcome_case in ('crash','loss','removal') and (outcome_case!='loss' or authority is not None)
    # Removal changes registration history. Fresh identities keep its teardown
    # separate from the crash and loss controls inherited from the service gate.
    ux = {'service-app-api-client','service-managed-ssh-config','service-two-ssh-agents',
          'service-cursor-missing-extension','service-cursor-remote-save-peer',
          'service-vscode-missing-extension','service-vscode-remote-save-peer',
          'service-busy-removal-refusal','service-stop-busy-preserves-running',
          'service-unmounted-path-denial','service-removal-keep-data','service-removal-delete-data',
          'service-background-consent-denied','service-outcome-clean-1000-cycles'}
    if not api_only:
        observe=record
        if outcome_case=='loss': record=lambda name:observe(name) if name.startswith('service-loss-') else None
        elif outcome_case=='removal': record=lambda name:observe(name) if name in ux else None
        else: record=lambda name:observe(name) if name not in ux and not name.startswith('service-loss-') else None
    wait_for_hold()
    repo = pathlib.Path(__file__).resolve().parent.parent
    evidence = pathlib.Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix='pfs-wsp-', dir='/private/tmp'))
    home = root/'home'; home.mkdir(mode=0o700)
    # Faults operate only on this invocation's image, including after a crash.
    test_image = root/'image'
    subprocess.run(['/bin/cp', '-cR', str(pathlib.Path(image).resolve()), str(test_image)], check=True)

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
            'PFSWorkspaceTestHome':str(home),'PFSWorkspaceTestImage':str(test_image)}
    with (contents/'Info.plist').open('wb') as f: plistlib.dump(info,f)
    with (service/'Contents/Info.plist').open('wb') as f:
        plistlib.dump({'CFBundleIdentifier':identifier+'.WorkspaceService','CFBundleExecutable':'portablefs-workspace-service',
                      'CFBundleName':'PortableFS Workspace Test Service','CFBundlePackageType':'APPL','CFBundleVersion':'1',
                      'CFBundleShortVersionString':version,'LSBackgroundOnly':True,'LSMinimumSystemVersion':'26.0',
                      'PFSWorkspaceImageManifestSHA256':hashlib.sha256((test_image/'manifest.json').read_bytes()).hexdigest()},f)
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
    update_receipts=[]
    def prepare_update(refusal=None):
        guard=subprocess.Popen([str(cli),'lifecycle','hold-install-exclusive','--json'],env=env,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            assert select.select([guard.stdout],[],[],15)[0], 'installer admission readiness deadline'
            frame=guard.stdout.readline()
            if refusal is None:
                ready=json.loads(frame)
                assert ready['held'] and ready['purpose']=='service-update',ready
                assert all(ready[key]==0 for key in ['kernelMounts','mountRecords','mountIntents','durableAttaches','liveAttaches']),ready
            else:
                assert not frame and guard.wait(timeout=15)==1,frame
                assert 'workspace resources remain' in guard.stderr.read()
                ready=None
            result=subprocess.run([str(host),'--workspace-update-quiesce'],env=env,capture_output=True,text=True,timeout=210)
            if refusal is None: assert result.returncode==0,(result.stdout,result.stderr)
            else: assert result.returncode!=0 and refusal in result.stderr,result.stderr
            update_receipts.append({'guard':ready,'refusal':refusal,'exit':result.returncode,'stderr':result.stderr})
            (evidence/'update-boundaries.json').write_text(json.dumps(update_receipts,indent=2))
        finally:
            guard.stdin.close()
            try: guard.wait(timeout=15)
            except subprocess.TimeoutExpired: guard.terminate();guard.wait(timeout=15)
            guard.stdout.close();guard.stderr.close()
    if outcome_case=='removal':
        # The incoming installer can leave a lock-only directory without registering
        # any service. The actual shared API must handle that pristine boundary.
        account = home/'.local/state/portablefs'
        account.mkdir(parents=True, mode=0o700)
        pristine = account/'workspace'
        pristine.mkdir(mode=0o700)
        (pristine/'owner.lock').touch(mode=0o600)
        prepare_update()
    registered = subprocess.run([str(host),'--workspace-service-register'],env=env,capture_output=True,text=True)
    if registered.returncode:
        (evidence/'product-registration.txt').write_text(registered.stdout+registered.stderr)
        # Approval can fail before the main fixture finally block is entered.
        # Retire only this invocation's generated identity even on that cut.
        cleanup=subprocess.run([str(host),'--unregister-workspace-test'],env=env,capture_output=True,text=True)
        (evidence/'product-registration-cleanup.txt').write_text(cleanup.stdout+cleanup.stderr)
        if cleanup.returncode==0:subprocess.run([lsregister,'-u',str(app)],check=True)
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
    confirmed_absent=False
    finished=False
    def app_command(*args, success=True):
        result=subprocess.run([str(host),*args],env=env,capture_output=True,text=True,timeout=200)
        if success: assert result.returncode==0,(args,result.stdout,result.stderr)
        return result
    def snapshot(name):
        value=status()
        (evidence/('menu-'+name+'.json')).write_text(json.dumps(value,indent=2))
        return value
    try:
        deadline=time.monotonic()+30
        while not endpoint.exists():
            assert time.monotonic()<deadline, 'test service did not publish its socket; see service.stderr'
            time.sleep(.1)
        until(lambda s:s['state']=='stopped',30)
        snapshot('stopped')
        assert json.loads(app_command('--workspace-api','status').stdout)['state']=='stopped'
        record('service-app-api-client')
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
        if api_only:
            finished=True
            return
        if outcome_case=='removal':
            # The controlling agent uses computer use to toggle only this generated
            # Background Item. No global background-item reset or installed service
            # identifier participates. Files coordinate the two UI observations.
            if defer_ui:
                defer_case('service-background-consent-denied')
            else:
                (evidence/'consent-fixture.json').write_text(json.dumps({**fixture, 'displayName': info['CFBundleName']},indent=2))
                print('AWAITING: disable throwaway Background Item; write '+str(evidence/'consent-denied'),flush=True)
                deadline=time.monotonic()+300
                while not (evidence/'consent-denied').exists():
                    assert time.monotonic()<deadline,'denied-consent UI observation unavailable'
                    time.sleep(.2)
                denied=app_command('--workspace-service-register',success=False)
                assert denied.returncode==3 and 'Allow PortableFS in Background Items' in denied.stderr,denied
                (evidence/'denied-consent.txt').write_text(denied.stdout+denied.stderr)
                print('AWAITING: re-enable same throwaway Background Item; write '+str(evidence/'consent-restored'),flush=True)
                deadline=time.monotonic()+300
                while not (evidence/'consent-restored').exists():
                    assert time.monotonic()<deadline,'restored-consent UI observation unavailable'
                    time.sleep(.2)
                app_command('--workspace-service-register')
                until(lambda s:s['state']=='stopped',30)
                record('service-background-consent-denied')
        kernel = test_image/'kernel'
        with kernel.open('r+b') as image_file:
            original = image_file.read(1)
            image_file.seek(0); image_file.write(bytes([original[0] ^ 1]))
        refused = command('start', success=False)
        assert refused.returncode == 1 and 'Workspace image failed verification' in refused.stdout
        with kernel.open('r+b') as image_file: image_file.write(original)
        record('service-corrupted-image-refusal')
        manifest = test_image/'manifest.json'; original_manifest = manifest.read_bytes()
        manifest.write_bytes(original_manifest + b' ')
        refused = command('start', success=False)
        assert refused.returncode == 1 and 'Workspace image failed verification' in refused.stdout
        manifest.write_bytes(original_manifest)
        record('service-image-manifest-pin')

        command('start');command('start')
        until(lambda s:s['state']=='running')
        snapshot('running')
        record('service-start-idempotent')
        # The registration-only host has exited. SSH still executes in the VM.
        config=home/'.local/state/portablefs/workspace/ssh_config'
        def ssh(script): return subprocess.check_output(['ssh','-F',str(config),'portablefs-workspace',script],env=env,text=True,timeout=30).strip()
        managed=home/'.ssh/portablefs-workspace.conf'
        assert managed.read_bytes()==config.read_bytes()
        assert (home/'.ssh/config').read_text().startswith('# PortableFS Linux Workspace\nInclude ~/.ssh/portablefs-workspace.conf\n')
        effective=subprocess.check_output(['ssh','-G','-F',str(managed),'portablefs-workspace'],env=env,text=True)
        for option in ['user workspace\n','identitiesonly yes\n','forwardagent no\n','identityagent none\n','stricthostkeychecking true\n']:
            assert option in effective,(option,effective)
        assert subprocess.check_output(['ssh','-F',str(managed),'portablefs-workspace','id -u'],env=env,text=True).strip()=='1000'
        (evidence/'ssh-effective.txt').write_text(effective)
        record('service-managed-ssh-config')
        with ThreadPoolExecutor(max_workers=2) as agents:
            first=agents.submit(ssh,"printf agent-one > /home/workspace/agent-one; sleep 1; cat /home/workspace/agent-two")
            second=agents.submit(ssh,"printf agent-two > /home/workspace/agent-two; sleep 1; cat /home/workspace/agent-one")
            assert first.result()=='agent-two' and second.result()=='agent-one'
        assert ssh('id -u')=='1000'
        ssh('printf service-persistence > /home/workspace/service-product-proof')
        record('service-app-exit-vm-alive')
        before=(home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()
        def mount_volume():
            wait_for_hold()
            descriptor=subprocess.check_output(['docker','exec','--user','200001:200001',authority.name,
                '/var/tmp/pfs-native/bin/pfs-workspace-fixture','document-connection','/var/tmp/pfs-native/home/test-pki',authority.endpoint,authority.volume],text=True)
            connection=root/'connection.pfsworkspace';connection.write_text(descriptor)
            app_command('--workspace-api','mount',str(connection))
            waiting=until(lambda s:s['volumes'] and s['volumes'][0]['state']=='authorization-required' and s['volumes'][0].get('authorizationRequest'))
            snapshot('authorization')
            public=pathlib.Path(waiting['volumes'][0]['authorizationRequest']).read_bytes()
            response=subprocess.check_output(['docker','exec','--user','200001:200001',authority.name,
                '/var/tmp/pfs-native/bin/pfs-workspace-fixture','document-authorize','/var/tmp/pfs-native/home/test-pki',base64.b64encode(public).decode()],text=True)
            authorized=root/'authorized.pfsworkspace';authorized.write_text(response)
            app_command('--workspace-api','mount',str(authorized))
            until(lambda s:s['volumes'] and s['volumes'][0]['state']=='ready')
            snapshot('volume-ready')
            return status()
        # Exercise retained data before the volume workload, then repeat Keep
        # after a used volume has proved its clean final outcome.
        if authority is not None:
            authority.peer("import pathlib; (pathlib.Path('/var/tmp/pfs-native/home/peer')/'removal-peer-sentinel').write_text('remote-data')")
        update_lock = os.open(home/'.local/state/portablefs/mount-lifecycle.lock', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(update_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert command('start', success=False).returncode == 1
            assert status()['desiredRunning']
            command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
        finally:
            os.close(update_lock)
        record('service-stop-under-update-exclusion')

        record('service-stop-persists')
        # Registration and status cannot defeat the explicit stopped intent.
        subprocess.run([str(host),'--workspace-service-register'],env=env,check=True)
        assert status()['state']=='stopped'
        command('start');until(lambda s:s['state']=='running')
        assert ssh('cat /home/workspace/service-product-proof')=='service-persistence'
        assert (home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()==before
        record('service-ssh-identity-persistence')
        if outcome_case=='removal':
            command('stop','--json');until(lambda s:s['state']=='stopped')
            snapshot('before-removal')
            prepare_update();prepare_update()
            assert json.loads(app_command('--workspace-api','status').stdout)['state']=='stopped'
            assert (home/'.local/state/portablefs/workspace/data.ext4').exists()
            assert not managed.exists() and not (home/'.ssh/config').exists()
            record('service-removal-keep-data')
            app_command('--workspace-remove','delete');app_command('--workspace-remove','delete')
            assert not (home/'.local/state/portablefs/workspace').exists()
            if authority is not None:
                assert authority.peer("import pathlib; print((pathlib.Path('/var/tmp/pfs-native/home/peer')/'removal-peer-sentinel').read_text())")=='remote-data'
            record('service-removal-delete-data')
            app_command('--workspace-service-register');command('start');until(lambda s:s['state']=='running')
            ssh('printf service-persistence > /home/workspace/service-product-proof')
            before=(home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()
        if authority is not None:
            mount_volume()
            assert ssh('printf product-volume > /workspaces/native-managed/product-proof; sync; cat /workspaces/native-managed/product-proof')=='product-volume'
            record('service-document-standalone')
            with ThreadPoolExecutor(max_workers=2) as agents:
                first=agents.submit(ssh,"printf volume-agent-one > /workspaces/native-managed/agent-one; sync; sleep 1; cat /workspaces/native-managed/agent-two")
                second=agents.submit(ssh,"printf volume-agent-two > /workspaces/native-managed/agent-two; sync; sleep 1; cat /workspaces/native-managed/agent-one")
                assert first.result()=='volume-agent-two' and second.result()=='volume-agent-one'
            assert authority.peer("import pathlib; p=pathlib.Path('/var/tmp/pfs-native/home/peer'); print((p/'agent-one').read_text()+','+(p/'agent-two').read_text())")=='volume-agent-one,volume-agent-two'
            record('service-two-ssh-agents')
            if outcome_case=='removal': editor_checks(host,env,config,home,evidence/'editors',authority,ssh,record,defer_ui,defer_case)
            holder=subprocess.Popen(['ssh','-F',str(config),'portablefs-workspace',
                'cd /workspaces/native-managed && echo holding && read -r release'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                assert holder.stdout.readline().strip()=='holding'
                app_command('--workspace-api','umount',authority.volume)
                busy=until(lambda s:s['volumes'] and s['volumes'][0]['state']=='busy')
                assert busy['volumes'][0]['message']=='Volume is in use. Close its terminals and editor windows, then try again.'
                snapshot('busy')
                assert ssh('cat /workspaces/native-managed/product-proof')=='product-volume'
                refused=app_command('--workspace-remove','delete',success=False)
                assert refused.returncode!=0 and 'Volume is in use.' in refused.stderr
                assert (home/'.local/state/portablefs/workspace/data.ext4').exists()
                record('service-busy-removal-refusal')
                command('stop','--json');until(lambda s:s['state']=='running' and s['volumes'][0]['state']=='busy')
                assert status()['desiredRunning'] and ssh('cat /workspaces/native-managed/product-proof')=='product-volume'
                record('service-stop-busy-preserves-running')
            finally:
                holder.stdin.write('release\n');holder.stdin.flush();holder.wait(timeout=15)
                holder.stdin.close();holder.stdout.close();holder.stderr.close()
            app_command('--workspace-api','umount',authority.volume);until(lambda s:not s['volumes'])
            settled=snapshot('volume-removed')
            assert not settled['previousWriteOutcomeUnknown'] and not settled['someChangesWereNotSaved'],settled
            record('service-used-clean-unmount-outcome')
            denied=subprocess.run(['ssh','-F',str(config),'portablefs-workspace',
                'printf forbidden > /workspaces/native-managed/unmounted-proof'],env=env,capture_output=True,text=True,timeout=30)
            assert denied.returncode!=0 and ('Permission denied' in denied.stderr or 'does not exist' in denied.stderr),denied
            assert authority.peer("import pathlib; print((pathlib.Path('/var/tmp/pfs-native/home/peer')/'unmounted-proof').exists())")=='False'
            record('service-unmounted-path-denial')
        command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
        settled=snapshot('stopped-after-volume')
        assert not settled['previousWriteOutcomeUnknown'] and not settled['someChangesWereNotSaved'],settled
        record('service-used-clean-stop-outcome')
        if outcome_case=='removal':
            command('start');until(lambda s:s['state']=='running')
            peak=0
            for cycle in range(1000):
                mount_volume()
                assert ssh("python3 -c \"import os; f=os.open('/workspaces/native-managed/cycle-proof',os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600); os.write(f,b'cycle'); os.fsync(f); os.close(f)\"") == ''
                command('umount',authority.volume,'--json');settled=until(lambda s:not s['volumes'])
                saved=json.loads((home/'.local/state/portablefs/workspace/desired.json').read_text())
                assert not saved['retained'] and not settled['outcomes'] and not settled['retainedEvidence'], (cycle,saved)
                assert not settled['someChangesWereNotSaved'] and not settled['previousWriteOutcomeUnknown'], (cycle,settled)
                peak=max(peak,(home/'.local/state/portablefs/workspace/desired.json').stat().st_size)
                assert peak<16384,(cycle,peak)
                if (cycle+1)%100==0:
                    (evidence/'clean-cycles.json').write_text(json.dumps({'cycles':cycle+1,'peak_state_bytes':peak,'retirement_through':saved['retirementThrough']},indent=2))
            command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
            record('service-outcome-clean-1000-cycles')
            prepare_update();prepare_update()
            assert (home/'.local/state/portablefs/workspace/data.ext4').exists()
            app_command('--workspace-service-register')
            command('start');until(lambda s:s['state']=='running')
            assert ssh('cat /home/workspace/service-product-proof')=='service-persistence'
            assert (home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()==before
            command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
            finished=True
            return
        command('start');until(lambda s:s['state']=='running')
        if authority is not None: mount_volume()
        if outcome_case=='loss':
            for cycle in range(127):
                if cycle: mount_volume()
                command('umount',authority.volume,'--force','--json')
                settled=until(lambda s:not s['volumes'] and len(s['outcomes'])==cycle+1)
                assert settled['previousWriteOutcomeUnknown'],(cycle,settled)
                assert len(json.loads((home/'.local/state/portablefs/workspace/desired.json').read_text())['retained'])==cycle+1
            refused=command('mount',str(root/'connection.pfsworkspace'),'--json',success=False)
            assert refused.returncode==1 and 'Dismiss a previous write outcome' in refused.stdout,refused
            assert status()['state']=='running' and len(status()['outcomes'])==127
            record('service-loss-capacity-backpressure')
            # Every operation names one exact notice; no API acknowledges all.
            chosen=settled['outcomes'][63]['id']
            command('status','--dismiss',chosen,'--json')
            command('status','--dismiss',chosen,'--json')
            command('status','--dismiss','999999/09090909090909090909090909090909/unknown','--json')
            assert len(status()['outcomes'])==126
            mount_volume();command('umount',authority.volume,'--json');until(lambda s:not s['volumes'])
            for outcome in status()['outcomes']: command('status','--dismiss',outcome['id'],'--json')
            assert not status()['outcomes'] and not status()['previousWriteOutcomeUnknown']
            record('service-loss-double-and-unknown-dismiss')
            # Force a final independent notice and prove removal's unchanged
            # guard before Dismiss, then the actual public removal boundary.
            mount_volume();command('umount',authority.volume,'--force','--json');until(lambda s:not s['volumes'])
            command('stop','--json');settled=until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
            refused=app_command('--workspace-remove','keep',success=False)
            assert refused.returncode!=0 and 'Previous write outcome unknown' in refused.stderr
            for outcome in settled['outcomes']: app_command('--workspace-api','dismiss',outcome['id'])
            assert not status()['previousWriteOutcomeUnknown']
            app_command('--workspace-remove','keep')
            record('service-loss-force-umount-dismiss-removal')
            app_command('--workspace-service-register');command('start');until(lambda s:s['state']=='running')
            mount_volume()
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
                writer.stdin.close()
                if writer.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired): writer.wait(timeout=20)
                writer.stdout.close();writer.stderr.close()
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
            refused=app_command('--workspace-remove','delete',success=False)
            assert refused.returncode!=0 and 'Some changes were not saved' in refused.stderr
            prepare_update('Some changes were not saved')
            record('service-loss-retained-after-clean-stop')
            for outcome in settled['outcomes']: command('status','--dismiss',outcome['id'],'--json')
            settled=snapshot('known-loss-dismissed')
            assert not settled['outcomes'] and not settled['someChangesWereNotSaved'] and not settled['previousWriteOutcomeUnknown']
            prepare_update();confirmed_absent=True
            record('service-loss-dismiss-update')
            finished=True
            return
        old_boot=ssh('cat /proc/sys/kernel/random/boot_id')
        if authority is not None:
            assert ssh('cat /workspaces/native-managed/product-proof')=='product-volume'
        reference=home/'.local/state/portablefs/workspace/owner.lock'
        worker,observed=execution_reference_worker(reference)
        assert execution_reference_busy(reference)
        suspended=False
        try:
            os.kill(worker,signal.SIGSTOP);suspended=True
            # Signal delivery must settle before the owner-death control.
            deadline=time.monotonic()+5
            while True:
                stopped=subprocess.check_output(['ps','-p',str(worker),'-o','state='],text=True).strip()
                if stopped.startswith('T'): break
                assert time.monotonic()<deadline, 'VM worker did not acknowledge SIGSTOP'
                time.sleep(.01)
            (evidence/'worker-paused.json').write_text(json.dumps({'worker':worker,'state':stopped,'lsof':observed},indent=2))
            subprocess.run(['launchctl','kill','SIGKILL',f'gui/{os.getuid()}/{label}'],check=True)
            crashed=True
            refused=until(lambda s:s['state']=='cleanup-required')
            assert command('start',success=False).returncode!=0
            assert execution_reference_busy(reference)
            (evidence/'crash-worker-held.json').write_text(json.dumps({'worker':worker,'lsof':observed,'status':refused},indent=2))
            record('service-crash-live-worker-refusal')
        finally:
            if suspended:
                try: os.kill(worker,signal.SIGCONT)
                except ProcessLookupError: pass

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
        prepare_update('Previous write outcome unknown')
        refused=app_command('--workspace-remove','delete',success=False)
        assert refused.returncode!=0 and 'Previous write outcome unknown' in refused.stderr
        snapshot('cleanup')
        record('service-removal-unknown-refusal')
        for outcome in settled['outcomes']: command('status','--dismiss',outcome['id'],'--json')
        settled=snapshot('unknown-dismissed')
        assert not settled['outcomes'] and not settled['previousWriteOutcomeUnknown']
        # Recreate the real owner before update; a conservative stale presence
        # marker must not recreate an acknowledged outcome.
        subprocess.run(['launchctl','kill','SIGKILL',f'gui/{os.getuid()}/{label}'],check=True)
        until(lambda s:s['state']=='stopped' and not s['outcomes'])
        prepare_update();confirmed_absent=True
        record('service-crash-dismiss-update')
        record('service-outcome-dismiss-durable')
        crashed=False
        finished=True
    finally:
        # This identity was generated by this invocation. Never unregister any
        # installed or dev-host identity, and retain unconfirmed execution data.
        assert label.startswith('dev.portablefs.workspace-tests.')
        if not crashed and not confirmed_absent:
            try:
                command('stop','--force','--json')
                until(lambda s:s['state']=='stopped' and not s['desiredRunning'],30)
                confirmed_absent=True
            except Exception as error:
                (evidence/'cleanup-unconfirmed.txt').write_text(str(error)+'\n')
        subprocess.run([str(host),'--unregister-workspace-test'],env=env,check=True,capture_output=True,text=True)
        probe=subprocess.run(['launchctl','print',f'gui/{os.getuid()}/{label}'],capture_output=True,text=True)
        assert probe.returncode==113,('throwaway registration still present',probe.stdout,probe.stderr)
        reference=home/'.local/state/portablefs/workspace/owner.lock'
        if confirmed_absent and reference.exists(): assert not execution_reference_busy(reference)
        (evidence/'cleanup-confirmation.json').write_text(json.dumps({'identifier':identifier,'launchctl_exit':probe.returncode,'execution_absent':confirmed_absent,'finished':finished},indent=2))
        subprocess.run([lsregister,'-u',str(app)],check=True)
        if confirmed_absent and finished: shutil.rmtree(root)
        elif confirmed_absent: (evidence/'failed-test-state.txt').write_text(str(root)+'\nVM confirmed stopped; retained for failure diagnosis\n')
        else: (evidence/'unconfirmed-test-vm-state.txt').write_text(str(root)+'\nretained until exact execution-reference or host-boot absence proof\n')

if __name__=='__main__':
    import sys
    from linux_workspace_native_managed import NativeAuthority
    image,evidence,*options=sys.argv[1:]
    assert options in ([],['--api-only'],['--defer-ui']),options
    api_only=options==['--api-only'];defer_ui=options==['--defer-ui']
    evidence=pathlib.Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    observed=[];not_run=[];authority=None
    required=[name for name in pathlib.Path(__file__).with_name('linux-workspace-required-native-tests.txt').read_text().splitlines() if name.startswith('service-')]
    if api_only:required=['service-app-api-client','service-authenticated-status','service-unsigned-peer-refusal','service-cross-release-refusal','service-api-cli-five-verbs']
    try:
        if not api_only:authority=NativeAuthority(evidence)
        product_checks(image,evidence,lambda name:(observed.append(name),print('PASS:',name,flush=True)),
                       authority=authority,api_only=api_only,defer_ui=defer_ui,
                       defer_case=lambda name:(not_run.append(name),print('NOT RUN (UI deferred):',name,flush=True)))
        if not api_only:
            product_checks(image,evidence/'product-removal',lambda name:(observed.append(name),print('PASS:',name,flush=True)),authority=authority,outcome_case='removal',defer_ui=defer_ui,defer_case=lambda name:(not_run.append(name),print('NOT RUN (UI deferred):',name,flush=True)))
            product_checks(image,evidence/'product-loss',lambda name:(observed.append(name),print('PASS:',name,flush=True)),authority=authority,outcome_case='loss',defer_ui=True,defer_case=lambda name:None)
        assert sorted(observed+not_run)==sorted(required),(observed,not_run,required)
        (evidence/'product-results.json').write_text(json.dumps({'required':required,'passed':observed,'notRun':not_run,
            'scope':'api-only' if api_only else 'product','qualified':not not_run and not api_only},indent=2))
        if not_run:sys.exit(3)
    finally:
        if authority is not None:authority.close()
