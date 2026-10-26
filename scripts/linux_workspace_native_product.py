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


def product_checks(image, evidence, record, authority=None, api_only=False):
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
    def status(): return json.loads(command('status','--json').stdout)
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
            command('mount',str(connection),'--json')
            waiting=until(lambda s:s['volumes'] and s['volumes'][0]['state']=='authorization-required' and s['volumes'][0].get('authorizationRequest'))
            public=pathlib.Path(waiting['volumes'][0]['authorizationRequest']).read_bytes()
            response=subprocess.check_output(['docker','exec','--user','200001:200001',authority.name,
                '/var/tmp/pfs-native/bin/pfs-workspace-fixture','document-authorize','/var/tmp/pfs-native/home/test-pki',base64.b64encode(public).decode()],text=True)
            authorized=root/'authorized.pfsworkspace';authorized.write_text(response)
            command('mount',str(authorized),'--json')
            until(lambda s:s['volumes'] and s['volumes'][0]['state']=='ready')
            assert ssh('printf product-volume > /workspaces/native-managed/product-proof; sync; cat /workspaces/native-managed/product-proof')=='product-volume'
            record('service-document-standalone')
            command('umount',authority.volume,'--json');until(lambda s:not s['volumes'])
        command('stop','--json');until(lambda s:s['state']=='stopped' and not s['desiredRunning'])
        record('service-stop-persists')
        # Registration and status cannot defeat the explicit stopped intent.
        subprocess.run([str(host),'--workspace-service-register'],env=env,check=True)
        assert status()['state']=='stopped'
        command('start');until(lambda s:s['state']=='running')
        assert ssh('cat /home/workspace/service-product-proof')=='service-persistence'
        assert (home/'.local/state/portablefs/workspace/client_ed25519.pub').read_bytes()==before
        record('service-ssh-identity-persistence')
        subprocess.run(['launchctl','kill','SIGKILL',f'gui/{os.getuid()}/{label}'],check=True)
        crashed=True
        until(lambda s:s['state']=='cleanup-required')
        assert command('start',success=False).returncode!=0
        record('service-crash-no-ram-adoption')
    finally:
        # This identity was generated by this invocation. Never unregister any
        # installed or dev-host identity, and retain unconfirmed execution data.
        assert label.startswith('dev.portablefs.workspace-tests.')
        if not crashed:
            with contextlib.suppress(Exception): command('stop','--force','--json');until(lambda s:s['state']=='stopped',30)
        subprocess.run([str(host),'--unregister-workspace-test'],env=env,check=True,capture_output=True,text=True)
        subprocess.run([lsregister,'-u',str(app)],check=True)
        if not crashed: shutil.rmtree(root)
        else: (evidence/'unconfirmed-test-vm-state.txt').write_text(str(root)+'\nretained until host reboot proves absence\n')

if __name__=='__main__':
    import sys
    observed=[]
    product_checks(sys.argv[1],sys.argv[2],lambda name:(observed.append(name),print('PASS:',name,flush=True)),api_only='--api-only' in sys.argv[3:])
    pathlib.Path(sys.argv[2],'product-results.json').write_text(json.dumps({'passed':observed},indent=2))
