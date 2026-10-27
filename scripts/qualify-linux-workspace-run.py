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
import uuid
from g3_product_probe import ProductProbe
from g3_continuity import Continuity
from g3_pins import verify as verify_pins

from linux_workspace_native_managed import NativeAuthority
from linux_workspace_native_g0 import pause_checks

ROOT = pathlib.Path(__file__).resolve().parent


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.replace(path)


def write_status(evidence, status, body):
    notice=(f"Owned authority container: {status.get('authority_container','preparing')}.\n"
            "Other sessions must not pause pfs-g3* containers. Any unplanned authority pause invalidates the run.\n"
            "Coordinate quiet windows before container pauses; the run must restart at zero after disruption.\n\n")
    (evidence/'STATUS.md').write_text('# G3 clock run\n\n'+notice+body)


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
    parser.add_argument('--pins',type=pathlib.Path,required=True)
    args = parser.parse_args()
    hold=pathlib.Path('/Users/timjang/.local/state/portablefs-tests/linux-workspace/HOLD')
    if hold.exists(): parser.error('HOLD exists: no VM, container or soak may start')
    pins=verify_pins(json.loads(args.pins.read_text()),ROOT,args.image,args.binary,args.reference)
    def require_unheld():
        if hold.exists(): raise RuntimeError('HOLD exists: native work must wait for coordinator')
    run_id=str(uuid.uuid4())
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    assert not (evidence/'status.json').exists(), 'use a new evidence directory'
    atomic(evidence/'run-inputs.json',pins)
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
                  phase='preparing', caffeinate_pid=caffeinate.pid, errors=[],run_id=run_id)
    (evidence/'pid').write_text(str(os.getpid())+'\n')
    atomic(evidence/'status.json',status)
    write_status(evidence,status,'Preparing pinned run inputs.\n')
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
        preflight=json.loads(subprocess.check_output([str(args.reference)],text=True,timeout=10))
        sys.path.insert(0,str(ROOT))
        from g3_coverage import OPERATORS
        assert len({OPERATORS[r['server']] for r in preflight['references']})>=2, 'preflight lacks two operators'
        atomic(evidence/'adapter-preflight.json',preflight)
        require_unheld()
        subprocess.run(['bash',str(ROOT/'test-linux-workspace-g0.sh'),str(args.image),str(evidence)],
                       check=True,timeout=240)
        require_unheld()
        subprocess.run(['bash',str(ROOT/'test-linux-workspace-rtc.sh'),str(args.image),str(evidence)],
                       check=True,timeout=150)
        atomic(evidence/'admission.json',dict(image_manifest_sha256=status['image_manifest_sha256'],
                   rtc_admission='pass',first_read_after_resume=False,concurrent_duplicate_readers=False,
                   basis='55 exact injected admission cases and separate exact-kernel RTC initramfs; product pause traces follow'))
        require_unheld()
        guest = Guest(str(args.binary), args.image, state, evidence)
        status['guest_pid'] = guest.p.pid
        require_unheld()
        authority = NativeAuthority(evidence)
        status['authority_container'] = authority.name
        managed = authority.mount(guest)
        authority.initial_io(guest)
        initial_probe=ProductProbe(guest,args.reference.resolve())
        initial_probe.close()

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
                        assert case['run_id']==run_id
                        if hold.exists():
                            atomic(evidence/'coordinator-request.json',dict(reason='HOLD blocks VZ pause/load campaign; coordinator decision required',case=case))
                            stop.touch()
                            raise RuntimeError('HOLD appeared: coordinator required before pause/load campaign')
                        directory = evidence/'campaigns'/f"{case['block']:02d}-{case['fencing']}-{case['pause_seconds']}"
                        directory.mkdir(parents=True)
                        phase=json.loads((evidence/'clock/load-state.json').read_text())
                        assert phase['run_id']==run_id and phase['load']==case['load'], 'actual load phase differs from campaign'
                        if phase['load']=='load': os.getpgid(phase['pid'])
                        prior_evidence = authority.evidence
                        authority.evidence = directory
                        try:
                            probe=ProductProbe(guest,args.reference.resolve())
                            managed = pause_checks(authority,guest,managed,lambda _: None,
                                                   durations=(case['pause_seconds'],),modes=(case['fencing'],),
                                                   rtc_probe=probe,load=case['load'])
                        finally:
                            authority.evidence = prior_evidence
                        trace = json.loads((directory/'g0-vz-pauses.json').read_text())[0]
                        trace['load_evidence']=phase
                        first=trace['product_first_read']
                        duplicate=trace['product_duplicate_readers']
                        result = dict(case=case,image_manifest_sha256=status['image_manifest_sha256'],
                                      first_operation_prestarted=trace['first_operation_prestarted'],
                                      denied_before_host_round_trip='denial_observed_before_host_recovery_ns' in trace,
                                      closed_cold_fresh=trace['recovery_disposition']=='closed-cold-fresh',
                                      terminal_cleanup_complete=trace['recovery_disposition']=='terminal-cleanup-fresh-authorization',
                                      first_read=first,duplicate_readers=duplicate,
                                      first_read_fixture='prestarted reader of product service retained RTC description',
                                      trace=trace)
                    except Exception as error:
                        active=directory/'g0-vz-active.json' if 'directory' in locals() else None
                        trace=json.loads(active.read_text()) if active and active.exists() else {}
                        operation=trace.get('first_operation',{})
                        violation=case.get('fencing')!='normal' and (operation.get('success') is True or operation.get('operation_ns',0)>=1_000_000_000)
                        result = dict(error=repr(error),case=case,trace=trace,bound_violation=violation,admission_violation=violation)
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
        continuity=Continuity(authority,guest,evidence/'peer-heartbeats.jsonl')
        # Docker events preserve even a pause/unpause wholly between polls.
        event_log=(evidence/'authority-events.jsonl').open('w')
        event_process=subprocess.Popen(['docker','events','--since',str(int(time.time())),
                        '--filter','container='+authority.name,'--format','{{json .}}'],stdout=event_log,stderr=subprocess.STDOUT)
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
                   '--stop-file',str(stop),'--invalid-file',str(evidence/'INVALID.json'),'--run-id',run_id,'--hold-file',str(hold)]
        command += ['--soak'] if args.soak else ['--seconds','1800','--dry-run']
        with (evidence/'harness.log').open('w') as log:
            process = subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            status['harness_pid']=process.pid
            while process.poll() is None:
                assert caffeinate.poll() is None, 'awake assertion exited'
                assert guest.p.poll() is None, 'guest owner exited'
                assert peer.poll() is None, 'independent peer exited'
                campaign_active=not campaign_lock.acquire(blocking=False)
                try:
                    status['continuity']=continuity.check(campaign_active)
                    serial=state/'serial.log'
                    if serial.exists() and serial.stat().st_size>8*1024*1024:
                        with serial.open('r+b') as serial_log: serial_log.truncate(0)
                    if (evidence/'owner.stderr').stat().st_size>8*1024*1024:
                        with (evidence/'owner.stderr').open('r+b') as error_log: error_log.truncate(0)
                    if event_process.poll() is not None: raise RuntimeError('authority event stream lost')
                    for line in (evidence/'authority-events.jsonl').read_text().splitlines(keepends=True):
                        if not line.endswith('\n'): continue
                        event=json.loads(line)
                        if event.get('Action') in ('pause','unpause','die','kill','restart','stop','destroy'):
                            raise RuntimeError('unplanned authority disruption: '+event['Action'])
                except BaseException:
                    if not campaign_active: campaign_lock.release()
                    raise
                if not campaign_active:
                    try:
                        # A real guest admission/coherence operation, separate
                        # from the maintenance-page measurement and live peer.
                        outcome = guest.ssh('cat /workspaces/native-managed/soak-heartbeat')
                        status['last_guest_read']=dict(host_ns=time.monotonic_ns(),value=outcome)
                    finally: campaign_lock.release()
                progress = evidence/'clock/progress.json'
                if progress.exists():
                    status['progress']=json.loads(progress.read_text())
                    clock_run=json.loads((evidence/'clock/run.json').read_text())
                    status['start_time']=clock_run['start_time']
                    status['expected_end']=(datetime.datetime.fromisoformat(status['start_time'])+datetime.timedelta(seconds=clock_run['seconds'])).isoformat()
                status['updated']=now().isoformat()
                if stop.exists(): status['phase']='stopping'
                if (evidence/'coordinator-request.json').exists():
                    status['coordinator_request']=json.loads((evidence/'coordinator-request.json').read_text())
                atomic(evidence/'status.json',status)
                write_status(evidence,status,f"Phase: {status['phase']}; run: {run_id}.\nOwner PID: {os.getpid()}; caffeinate PID: {caffeinate.pid}.\nStart: {status['start_time']}; expected end: {status['expected_end']}.\nUpdated: {status['updated']}.\nSee status.json and clock/progress.json for evidence.\nCoordinator request: {status.get('coordinator_request','none')}.\n")
                closing.wait(5)
            assert process.returncode == 0, f'harness exited {process.returncode}'
        status['result']=json.loads((evidence/'clock/result.json').read_text())
        status['phase']='stopped' if stop.exists() else 'completed'
        if not args.soak and not stop.exists() and not status['result']['proof_qualified']:
            raise RuntimeError('30-minute proof did not qualify; preserve result and do not launch soak')
    except BaseException as error:
        status['errors'].append(repr(error))
        disrupted=process is not None and process.poll() is None
        status['phase']='invalid' if disrupted else 'failed' if status.get('result',{}).get('failures') else 'inconclusive'
        if disrupted:
            atomic(evidence/'INVALID.json',dict(run_id=run_id,error=repr(error),observed_ns=time.monotonic_ns(),at=now().isoformat()))
        atomic(evidence/'status.json',status)
        write_status(evidence,status,status['phase']+': '+repr(error)+'\nEvidence preserved; stopping owned resources.\n')
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
        if 'event_process' in locals() and event_process.poll() is None:
            event_process.terminate();event_process.wait(timeout=5)
        server.close()
        caffeinate.terminate();caffeinate.wait(timeout=5)
        status['finished']=now().isoformat()
        atomic(evidence/'status.json',status)
        write_status(evidence,status,f"Phase: {status['phase']}.\nRun: {run_id}; owner PID: {os.getpid()}.\nErrors: {status['errors']!r}.\nEvidence retained; runs are never spliced.\n")
    if status['errors']:
        raise RuntimeError(status['errors'])


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--driver':
        driver(*sys.argv[2:])
    else:
        main()
