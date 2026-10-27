#!/usr/bin/env python3
"""Own a disposable VZ guest, independent XFS peer, awake assertion and G3 run.

Build the exact image/dev owner and NTS adapter first. This test owner never
changes host time, sleeps macOS, or adopts an existing guest/container.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import pathlib
import queue
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from linux_workspace_native_managed import NativeAuthority
from linux_workspace_native_g0 import pause_checks

ROOT = pathlib.Path(__file__).resolve().parent


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.replace(path)


def driver(address, case):
    with socket.socket(socket.AF_UNIX) as client:
        client.connect(address)
        client.sendall((case+'\n').encode())
        with client.makefile('r') as stream:
            print(stream.readline(), end='')


class Guest:
    def __init__(self, binary, image, state, evidence):
        self.lines = queue.Queue()
        self._history = collections.deque(maxlen=512)
        self.stderr = (evidence/'owner.stderr').open('w')
        self.events = (evidence/'owner-events.jsonl').open('w')
        self.p = subprocess.Popen([binary, str(image), str(state)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1)
        threading.Thread(target=self.read, daemon=True).start()
        try:
            self.wait('starting')
            self.ready = self.wait('ready')
        except BaseException:
            self.command('stop')
            self.p.wait(timeout=60)
            raise

    @property
    def history(self):
        return list(self._history)

    def read(self):
        for line in self.p.stdout:
            if self.events.tell() < 8*1024*1024:
                self.events.write(line); self.events.flush()
            value = json.loads(line)
            if value['event'] == 'retained-evidence':
                self._history.append(value)
            else:
                self.lines.put(value)
        self.lines.put(dict(event='eof', returncode=self.p.wait()))

    def wait(self, expected, timeout=180):
        deadline = time.monotonic()+timeout
        while True:
            value = self.lines.get(timeout=max(.01, deadline-time.monotonic()))
            self._history.append(value)
            if value['event'] in (expected if isinstance(expected, tuple) else (expected,)):
                return value
            if value['event'] in ('failure','eof'):
                raise RuntimeError(value)

    def command(self, name, **fields):
        self.p.stdin.write(json.dumps(dict(command=name, **fields))+'\n'); self.p.stdin.flush()

    def ssh(self, command):
        return subprocess.check_output(['ssh','-F',self.ready['ssh_config'],
                                       'portablefs-workspace',command], text=True, timeout=30).strip()

    def stop(self):
        if self.p.poll() is None:
            self.command('stop')
            result = self.wait('stopped', 60)
            assert result['operations'][-1] == 'shutdown-completed', result
        assert self.p.wait(timeout=10) == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=pathlib.Path)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('reference', type=pathlib.Path)
    parser.add_argument('evidence', type=pathlib.Path)
    parser.add_argument('--soak', action='store_true')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    assert not (evidence/'status.json').exists(), 'use a new evidence directory'
    os.environ['PFS_NATIVE_CLOCK_SOAK'] = '1'
    os.environ['PFS_NATIVE_FIXTURE_PREFIX'] = 'pfs-g3-'
    os.environ['PFS_RTC_NTS_REFERENCE'] = str(args.reference.resolve())
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    state = pathlib.Path(tempfile.mkdtemp(prefix='pfs-g3-', dir='/tmp'))
    stop = evidence/'STOP'
    signal.signal(signal.SIGTERM, lambda *_: stop.touch())
    signal.signal(signal.SIGINT, lambda *_: stop.touch())
    caffeinate = subprocess.Popen(['caffeinate','-i','-w',str(os.getpid())])
    now = lambda: datetime.datetime.now(datetime.timezone.utc)
    status = dict(pid=os.getpid(), launched=now().isoformat(), state_directory=str(state),
                  image_manifest_sha256=hashlib.sha256((args.image/'manifest.json').read_bytes()).hexdigest(),
                  phase='preparing', caffeinate_pid=caffeinate.pid, errors=[])
    (evidence/'pid').write_text(str(os.getpid())+'\n')
    atomic(evidence/'status.json',status)
    guest = authority = process = None
    server = socket.socket(socket.AF_UNIX)
    address = str(state/'campaign.sock')
    server.bind(address); server.listen(1); server.settimeout(1)
    campaign_lock = threading.Lock()
    closing = threading.Event()
    managed = None
    peer = None
    try:
        # Validate real authenticated connectivity before spending time booting.
        subprocess.run([str(args.reference)], check=True, timeout=10)
        subprocess.run(['bash',str(ROOT/'test-linux-workspace-g0.sh'),str(args.image),str(evidence)],
                       check=True,timeout=180)
        subprocess.run(['bash',str(ROOT/'test-linux-workspace-rtc.sh'),str(args.image),str(evidence)],
                       check=True,timeout=90)
        atomic(evidence/'admission.json',dict(image_manifest_sha256=status['image_manifest_sha256'],
                   rtc_admission='pass',first_read_after_resume=True,concurrent_duplicate_readers=True,
                   basis='55 exact injected admission cases and separate exact-kernel RTC initramfs; product pause traces follow'))
        guest = Guest(str(args.binary), args.image, state, evidence)
        status['guest_pid'] = guest.p.pid
        authority = NativeAuthority(evidence)
        status['authority_container'] = authority.name
        managed = authority.mount(guest)
        authority.initial_io(guest)

        def campaigns():
            nonlocal managed
            while not closing.is_set():
                try: client, _ = server.accept()
                except socket.timeout: continue
                with client, campaign_lock, client.makefile('r') as stream:
                    try:
                        case = json.loads(stream.readline(65536))
                        assert case['image_manifest_sha256'] == status['image_manifest_sha256']
                        assert case['host_sleep'] is False
                        directory = evidence/'campaigns'/f"{case['block']:02d}-{case['fencing']}-{case['pause_seconds']}"
                        directory.mkdir(parents=True)
                        prior_evidence = authority.evidence
                        authority.evidence = directory
                        try:
                            managed = pause_checks(authority,guest,managed,lambda _: None,
                                                   durations=(case['pause_seconds'],),modes=(case['fencing'],))
                        finally:
                            authority.evidence = prior_evidence
                        # Separate read-only initramfs, exact product kernel: this
                        # preserves sole-opening ownership in the product guest.
                        subprocess.run(['bash',str(ROOT/'test-linux-workspace-rtc.sh'),str(args.image),str(directory)],
                                       check=True, timeout=90, stdout=subprocess.DEVNULL)
                        first = json.loads((directory/'rtc-nts-reference.json').read_text())
                        duplicate = json.loads((directory/'rtc-contention.json').read_text())
                        trace = json.loads((directory/'g0-vz-pauses.json').read_text())[0]
                        result = dict(case=case,image_manifest_sha256=status['image_manifest_sha256'],
                                      first_operation_prestarted=trace['first_operation_prestarted'],
                                      denied_before_host_round_trip='denial_observed_before_host_recovery_ns' in trace,
                                      closed_cold_fresh=trace['recovery_disposition']=='closed-cold-fresh',
                                      terminal_cleanup_complete=trace['recovery_disposition']=='terminal-cleanup-fresh-authorization',
                                      first_read=first,duplicate_readers=duplicate,
                                      first_read_fixture='separate test-only initramfs on exact product kernel',
                                      trace=trace)
                    except Exception as error:
                        result = dict(error=repr(error))
                    client.sendall((json.dumps(result)+'\n').encode())

        threading.Thread(target=campaigns,daemon=True).start()
        peer_code = """import json,os,time
p='/var/tmp/pfs-native/home/peer/soak-heartbeat'
while True:
 with open(p,'w') as f:
  f.write(str(time.monotonic_ns()));f.flush();os.fsync(f.fileno())
 print(json.dumps({'peer_completed_ns':time.monotonic_ns()}),flush=True)
 time.sleep(30)
"""
        peer_log = (evidence/'peer-heartbeats.jsonl').open('w')
        peer = subprocess.Popen(['docker','exec','--user','200001:200001',authority.name,'python3','-u','-c',peer_code],
                                stdout=peer_log,stderr=subprocess.STDOUT)
        deadline = time.monotonic()+15
        while not authority.peer("import pathlib; print(pathlib.Path('/var/tmp/pfs-native/home/peer/soak-heartbeat').exists())") == 'True':
            assert time.monotonic()<deadline, 'peer heartbeat did not start'
            time.sleep(.1)
        stamp = now()
        status.update(phase='running',start_time=stamp.isoformat(),
                      expected_end=(stamp+datetime.timedelta(hours=72) if args.soak else stamp+datetime.timedelta(minutes=30)).isoformat(),
                      peer_pid=peer.pid)
        (evidence/'start-time').write_text(status['start_time']+'\n')
        atomic(evidence/'status.json',status)
        command = [sys.executable,str(ROOT/'qualify-linux-workspace-clock.py'),str(args.image),guest.ready['ssh_config'],
                   str(evidence/'clock'),'--utc-reference-command',str(args.reference),
                   '--pause-command',shlex.join([sys.executable,str(pathlib.Path(__file__).resolve()),'--driver',address]),
                   '--admission-evidence',str(evidence/'admission.json'),
                   '--stop-file',str(stop)]
        command += ['--soak'] if args.soak else ['--seconds','1800','--dry-run']
        with (evidence/'harness.log').open('w') as log:
            process = subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            status['harness_pid']=process.pid
            while process.poll() is None:
                assert caffeinate.poll() is None, 'awake assertion exited'
                assert guest.p.poll() is None, 'guest owner exited'
                assert peer.poll() is None, 'independent peer exited'
                if campaign_lock.acquire(blocking=False):
                    try:
                        # A real guest admission/coherence operation, separate
                        # from the maintenance-page measurement and live peer.
                        outcome = guest.ssh('cat /workspaces/native-managed/soak-heartbeat')
                        status['last_guest_read']=dict(host_ns=time.monotonic_ns(),value=outcome)
                    finally: campaign_lock.release()
                progress = evidence/'clock/progress.json'
                if progress.exists():
                    status['progress']=json.loads(progress.read_text())
                status['updated']=now().isoformat()
                if stop.exists(): status['phase']='stopping'
                atomic(evidence/'status.json',status)
                closing.wait(10)
            assert process.returncode == 0, f'harness exited {process.returncode}'
        status['result']=json.loads((evidence/'clock/result.json').read_text())
        status['phase']='stopped' if stop.exists() else 'completed'
    except BaseException as error:
        status['errors'].append(repr(error));status['phase']='failed'
        raise
    finally:
        stop.touch()
        if process is not None and process.poll() is None:
            try: process.wait(timeout=850)
            except subprocess.TimeoutExpired:
                process.terminate();process.wait(timeout=30)
        closing.set()
        with campaign_lock:
            if peer is not None and peer.poll() is None:
                peer.terminate()
                try: peer.wait(timeout=5)
                except subprocess.TimeoutExpired: peer.kill();peer.wait(timeout=5)
            if authority is not None and guest is not None:
                try:
                    if managed: authority.unmount(guest,managed)
                except Exception as error: status['errors'].append('unmount: '+repr(error))
            if guest is not None:
                try: guest.stop()
                except Exception as error: status['errors'].append('guest stop: '+repr(error))
            if authority is not None:
                try: authority.close()
                except Exception as error: status['errors'].append('authority cleanup: '+repr(error))
        server.close()
        caffeinate.terminate();caffeinate.wait(timeout=5)
        status['finished']=now().isoformat()
        atomic(evidence/'status.json',status)
    if status['errors']:
        raise RuntimeError(status['errors'])


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--driver':
        driver(*sys.argv[2:])
    else:
        main()
