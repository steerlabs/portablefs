"""Real editor Remote-SSH saves using isolated profiles and an ordinary peer."""
import json
import os
import pathlib
import shlex
import signal
import subprocess
import time


EDITOR_EXTENSION = r'''
const vscode = require('vscode');
exports.activate = async () => {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder || !folder.uri.path.startsWith('/workspaces/')) return;
  const name = NAME;
  const uri = file => vscode.Uri.joinPath(folder.uri, 'ux-' + name + '-' + file);
  const write = async (file, value) => vscode.workspace.fs.writeFile(uri(file), Buffer.from(value));
  try {
    if (vscode.env.remoteName !== 'ssh-remote' || folder.uri.scheme !== 'vscode-remote') throw Error('not Remote-SSH');
    await write('save.txt', name + ':initial');
    const document = await vscode.workspace.openTextDocument(uri('save.txt'));
    const editor = await vscode.window.showTextDocument(document);
    const seen = new Set();
    for (let i = 0; i < 40; ++i) {
      const value = name + ':' + i;
      const changed = await editor.edit(edit => edit.replace(new vscode.Range(0, 0, document.lineCount, 0), value));
      if (!changed || !await document.save()) throw Error('save failed');
      const deadline = Date.now() + 15000;
      for (;;) {
        const reply = Buffer.from(await vscode.workspace.fs.readFile(uri('ack.txt'))).toString();
        if (reply === value) break;
        if (Date.now() >= deadline) throw Error('peer did not observe saved document: ' + value);
        await new Promise(resolve => setTimeout(resolve, 30));
      }
      seen.add(Buffer.from(await vscode.workspace.fs.readFile(uri('peer.txt'))).toString());
    }
    if (seen.size < 2) throw Error('no concurrent peer writes observed');
    await write('result.json', JSON.stringify({status:'passed', saves:40, peerVersions:seen.size,
      remote:vscode.env.remoteName, folder:folder.uri.toString(), document:document.uri.toString()}));
  } catch (error) {
    await write('result.json', JSON.stringify({status:'failed', error:String(error)}));
  }
};
'''


def editor_checks(host, env, config, home, evidence, authority, ssh, record, defer_ui=False, defer_case=None):
    evidence = pathlib.Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    applications = {
        'cursor': pathlib.Path('/Applications/Cursor.app'),
        'vscode': pathlib.Path(os.environ['PFS_WORKSPACE_TEST_VSCODE_APP']),
    }
    for name, application in applications.items():
        assert application.is_dir(), f'UNAVAILABLE: real {name}: {application}'
        root = evidence/name
        user = root/'user-data'
        extensions = root/'extensions'
        test_home = root/'home'
        for directory in [user/'User', extensions, test_home]: directory.mkdir(parents=True, exist_ok=True)
        isolated = dict(env, HOME=str(test_home), VSCODE_PORTABLE='')
        settings = {'remote.SSH.configFile': str(config), 'remote.SSH.path':'/usr/bin/ssh',
                    'remote.SSH.useLocalServer':False, 'security.workspace.trust.enabled':False,
                    'telemetry.telemetryLevel':'off', 'workbench.startupEditor':'none',
                    'update.mode':'none', 'extensions.autoUpdate':False, 'extensions.autoCheckUpdates':False,
                    'window.restoreWindows':'none', 'chat.disableAIFeatures':True}
        (user/'User/settings.json').write_text(json.dumps(settings, indent=2))
        cli = application/'Contents/Resources/app/bin'/('cursor' if name == 'cursor' else 'code')
        profile = ['--user-data-dir', str(user), '--extensions-dir', str(extensions)]
        missing = subprocess.run([str(host), '--workspace-editor', name, authority.volume,
                                  str(application), str(user), str(extensions)], env=isolated,
                                 text=True, capture_output=True, timeout=60)
        assert missing.returncode != 0 and 'Remote-SSH extension is not installed' in missing.stderr, missing
        assert not any(extensions.iterdir()), 'production action installed an extension'
        (root/'missing-extension.txt').write_text(missing.stderr)
        record('service-' + name + '-missing-extension')
        if defer_ui:
            defer_case('service-' + name + '-remote-save-peer')
            continue
        extension_id = 'anysphere.remote-ssh' if name == 'cursor' else 'ms-vscode-remote.remote-ssh'
        with (root/'extension-install.log').open('w') as log:
            subprocess.run([str(cli), *profile, '--install-extension', extension_id], env=isolated,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
        test = extensions/('portablefs.workspace-ux-' + name + '-1.0.0')
        test.mkdir()
        (test/'package.json').write_text(json.dumps({'name':'workspace-ux-' + name, 'publisher':'portablefs',
            'version':'1.0.0', 'engines':{'vscode':'^1.90.0'}, 'main':'./extension.js',
            'activationEvents':['onStartupFinished'], 'extensionKind':['ui']}))
        (test/'extension.js').write_text(EDITOR_EXTENSION.replace('NAME', json.dumps(name)))
        target = authority.target + '/ux-' + name + '-'
        # Only this fixture's mount and this editor's files participate.
        peer_script = '''import json,os,pathlib,time
base=pathlib.Path('/var/tmp/pfs-native/home/peer')
prefix=PREFIX
def put(name,value):
    with (base/(prefix+name)).open('w') as f: f.write(value);f.flush();os.fsync(f.fileno())
put('ack.txt','waiting');put('peer.txt','peer:initial')
seen=set();iterations=0;deadline=time.monotonic()+300
while time.monotonic()<deadline:
    put('peer.txt','peer:'+str(iterations));iterations+=1
    try:
        value=(base/(prefix+'save.txt')).read_text()
        if value.startswith(NAME+':') and value != NAME+':initial':
            number=value.split(':',1)[1]
            assert number.isdecimal() and 0<=int(number)<40,value
            seen.add(int(number));put('ack.txt',value)
    except FileNotFoundError:pass
    if (base/(prefix+'result.json')).exists():break
    time.sleep(.015)
else:raise RuntimeError('editor save deadline')
result=json.loads((base/(prefix+'result.json')).read_text())
assert result['status']=='passed' and seen==set(range(40)),(result,seen)
print(json.dumps({'iterations':iterations,'observedSaves':len(seen),'editor':result}))
'''.replace('PREFIX', repr('ux-' + name + '-')).replace('NAME', repr(name))
        peer_log = (root/'peer.json').open('w')
        peer = subprocess.Popen(['docker','exec','--user','200001:200001',authority.name,'python3','-c',peer_script],
                                stdout=peer_log,stderr=subprocess.STDOUT,text=True)
        try:
            deadline = time.monotonic()+20
            while ssh('if test -e '+shlex.quote(target+'ack.txt')+'; then echo ready; fi') != 'ready':
                assert time.monotonic()<deadline
                time.sleep(.1)
            launched = subprocess.run([str(host), '--workspace-editor', name, authority.volume,
                str(application), str(user), str(extensions)], env=isolated,text=True,capture_output=True,timeout=90)
            assert launched.returncode == 0, launched.stderr
            assert peer.wait(timeout=320) == 0, f'{name}: see {root}/peer.json and isolated editor logs'
            result=json.loads(ssh('cat '+shlex.quote(target+'result.json')))
            assert result['status']=='passed' and result['saves']==40, result
            (root/'result.json').write_text(json.dumps(result,indent=2))
            processes=ssh("ps -eo user,args | grep -E '(cursor-server|vscode-server|code-.*server)' | grep -v grep")
            assert 'workspace' in processes, processes
            (root/'guest-editor-processes.txt').write_text(processes)
            record('service-' + name + '-remote-save-peer')
        finally:
            if peer.poll() is None: peer.terminate();peer.wait(timeout=10)
            peer_log.close()
            # Electron's CLI exits after spawning. Terminate only processes
            # whose argument vector contains this exact isolated profile path.
            listing=subprocess.check_output(['ps','-axo','pid=,args='],text=True)
            for line in listing.splitlines():
                if str(user) not in line: continue
                pid=int(line.strip().split(None,1)[0])
                if pid != os.getpid():
                    try: os.kill(pid,signal.SIGTERM)
                    except ProcessLookupError: pass
