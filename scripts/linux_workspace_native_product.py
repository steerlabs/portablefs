"""Throwaway SMAppService tests; no installed app identities or SSH config."""
import base64
import contextlib
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


def product_checks(image, evidence, record, authority=None, api_only=False, defer_ui=False, defer_case=None):
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
        if api_only: return
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
        if authority is not None:
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
            assert ssh('printf product-volume > /workspaces/native-managed/product-proof; sync; cat /workspaces/native-managed/product-proof')=='product-volume'
            record('service-document-standalone')
            with ThreadPoolExecutor(max_workers=2) as agents:
                first=agents.submit(ssh,"printf volume-agent-one > /workspaces/native-managed/agent-one; sync; sleep 1; cat /workspaces/native-managed/agent-two")
                second=agents.submit(ssh,"printf volume-agent-two > /workspaces/native-managed/agent-two; sync; sleep 1; cat /workspaces/native-managed/agent-one")
                assert first.result()=='volume-agent-two' and second.result()=='volume-agent-one'
            assert authority.peer("import pathlib; p=pathlib.Path('/var/tmp/pfs-native/home/peer'); print((p/'agent-one').read_text()+','+(p/'agent-two').read_text())")=='volume-agent-one,volume-agent-two'
            record('service-two-ssh-agents')
            editor_checks(host,env,config,home,evidence/'editors',authority,ssh,record,defer_ui,defer_case)
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
            denied=subprocess.run(['ssh','-F',str(config),'portablefs-workspace',
                'printf forbidden > /workspaces/native-managed/unmounted-proof'],env=env,capture_output=True,text=True,timeout=30)
            assert denied.returncode!=0 and ('Permission denied' in denied.stderr or 'does not exist' in denied.stderr),denied
            assert authority.peer("import pathlib; print((pathlib.Path('/var/tmp/pfs-native/home/peer')/'unmounted-proof').exists())")=='False'
            record('service-unmounted-path-denial')
        command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
        record('service-stop-persists')
        # Registration and status cannot defeat the explicit stopped intent.
        subprocess.run([str(host),'--workspace-service-register'],env=env,check=True)
        assert status()['state']=='stopped'
        command('start');until(lambda s:s['state']=='running')
        assert ssh('cat /home/workspace/service-product-proof')=='service-persistence'
        assert (home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()==before
        record('service-ssh-identity-persistence')
        command('stop','--json');until(lambda s:s['state']=='stopped')
        app_command('--workspace-remove','keep');app_command('--workspace-remove','keep')
        assert json.loads(app_command('--workspace-api','status').stdout)['state']=='stopped'
        assert (home/'.local/state/portablefs/workspace/data.ext4').exists()
        assert not managed.exists() and not (home/'.ssh/config').exists()
        record('service-removal-keep-data')
        app_command('--workspace-remove','delete');app_command('--workspace-remove','delete')
        assert not (home/'.local/state/portablefs/workspace').exists()
        if authority is not None:
            assert authority.peer("import pathlib; print((pathlib.Path('/var/tmp/pfs-native/home/peer')/'product-proof').read_text())")=='product-volume'
        record('service-removal-delete-data')
        app_command('--workspace-service-register');command('start');until(lambda s:s['state']=='running')
        subprocess.run(['launchctl','kill','SIGKILL',f'gui/{os.getuid()}/{label}'],check=True)
        crashed=True
        until(lambda s:s['state']=='cleanup-required')
        assert command('start',success=False).returncode!=0
        record('service-crash-no-ram-adoption')
        refused=app_command('--workspace-remove','delete',success=False)
        assert refused.returncode!=0 and (home/'.local/state/portablefs/workspace/data.ext4').exists()
        snapshot('cleanup')
        record('service-removal-unknown-refusal')
    finally:
        # This identity was generated by this invocation. Never unregister any
        # installed or dev-host identity, and retain unconfirmed execution data.
        assert label.startswith('dev.portablefs.workspace-tests.')
        if not crashed:
            try:
                command('stop','--force','--json')
                until(lambda s:s['state']=='stopped' and not s['desiredRunning'],30)
                confirmed_absent=True
            except Exception as error:
                (evidence/'cleanup-unconfirmed.txt').write_text(str(error)+'\n')
        subprocess.run([str(host),'--unregister-workspace-test'],env=env,check=True,capture_output=True,text=True)
        subprocess.run([lsregister,'-u',str(app)],check=True)
        if confirmed_absent: shutil.rmtree(root)
        else: (evidence/'unconfirmed-test-vm-state.txt').write_text(str(root)+'\nretained until host reboot proves absence\n')

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
        assert sorted(observed+not_run)==sorted(required),(observed,not_run,required)
        (evidence/'product-results.json').write_text(json.dumps({'required':required,'passed':observed,'notRun':not_run,
            'scope':'api-only' if api_only else 'product','qualified':not not_run and not api_only},indent=2))
        if not_run:sys.exit(3)
    finally:
        if authority is not None:authority.close()
