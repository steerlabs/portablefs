"""Controlled VZ pauses with prestarted operations and an independent live peer.

These runs never sleep the host or edit a clock. Exact virtual-clock schedules
are separately owned by the injected Go inventory; actual pause durations and
publication observations are recorded here without rounding them to that model.
"""
import errno
import json
import selectors
import shlex
import subprocess
import time
import uuid


def pause_checks(authority, guest, managed, record):
    traces = []
    for fencing in ('normal', 'delayed', 'suppressed'):
        for duration in (5, 15, 45, 150, 600):
            case = f'g0-vz-{fencing}-{duration}s'
            token = 'g0-' + uuid.uuid4().hex
            worker = None
            blocked = False
            trace = dict(case=case, requested_pause_seconds=duration, fencing=fencing,
                         first_operation_prestarted=True, host_sleep=False)
            try:
                if fencing != 'normal':
                    code = '''import errno,json,os,sys,time
print('armed',flush=True)
assert sys.stdin.readline().strip()=='probe'
b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);start=time.monotonic_ns()
try:
 os.stat(PATH); result={'success':True}
except OSError as e:
 result={'success':False,'errno':e.errno}
result.update(boottime_ns=b,operation_ns=time.monotonic_ns()-start)
print(json.dumps(result),flush=True)
'''.replace('PATH', repr(authority.target+'/'+token))
                    worker = subprocess.Popen(['/usr/bin/ssh', '-F', guest.ready['ssh_config'],
                        'portablefs-workspace', 'python3 -u -c '+shlex.quote(code)],
                        text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    with selectors.DefaultSelector() as ready:
                        ready.register(worker.stdout, selectors.EVENT_READ)
                        assert ready.select(10), 'prestarted first operation not armed'
                        assert worker.stdout.readline().strip() == 'armed'
                    limit = time.monotonic()+10
                    while True:
                        guest.command('test-hold-host')
                        held = guest.wait(('test-host-held','refused'),10)
                        if held['event']=='test-host-held': break
                        assert time.monotonic()<limit, held
                        time.sleep(.02)
                    authority.network(True); blocked = True
                    # Let the old authority horizon age before the five-second
                    # case so the peer completes within the requested pause.
                    # No host observer can initiate cold recovery in this gap.
                    time.sleep(6.5)
                    trace['pre_pause_network_gap_seconds'] = 6.5
                    limit = time.monotonic()+10
                    while True:
                        guest.command('test-pause-unfenced')
                        paused = guest.wait(('test-paused-unfenced','refused'), 10)
                        if paused['event'] == 'test-paused-unfenced': break
                        assert time.monotonic()<limit, paused
                        time.sleep(.02)
                    # Queue the already-started request while the guest cannot
                    # execute. It needs no host recovery/status/SSH round trip
                    # after VZ resume to make its first filesystem operation.
                    worker.stdin.write('probe\n'); worker.stdin.flush()
                else:
                    guest.command('pause'); paused = guest.wait('paused',25)
                    assert paused['fenced'] and not paused['attach_allowed'], paused
                trace['pause_confirmed_host_ns'] = time.monotonic_ns()
                # The ordinary peer is outside the guest and remains live.
                # It waits for the actual authority obligation, then persists.
                peer = subprocess.Popen(['docker','exec','--user','200001:200001',authority.name,
                    'python3','-c',"import os; p="+repr('/var/tmp/pfs-native/home/peer/'+token)+
                    "; f=open(p,'wb'); f.write(b'peer-after-old-permission'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-complete',flush=True)"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                target = time.monotonic()+duration
                while time.monotonic()<target: time.sleep(min(.25,target-time.monotonic()))
                stdout, stderr = peer.communicate(timeout=20)
                assert peer.returncode==0 and stdout.strip()=='peer-complete', (stdout,stderr)
                trace['peer_complete_host_ns'] = time.monotonic_ns()
                trace['actual_paused_seconds'] = (trace['peer_complete_host_ns']-trace['pause_confirmed_host_ns'])/1e9
                if fencing == 'normal':
                    guest.command('resume'); guest.wait('resumed',25)
                else:
                    guest.command('test-resume-unfenced'); guest.wait('test-resumed-unfenced',10)
                    with selectors.DefaultSelector() as ready:
                        ready.register(worker.stdout, selectors.EVENT_READ)
                        assert ready.select(5), 'first expired operation waited for host recovery'
                        first = json.loads(worker.stdout.readline())
                    assert not first['success'] and first['errno'] in (errno.EIO,errno.ENOTCONN,errno.ESTALE), first
                    assert first['operation_ns']<1_000_000_000, first
                    trace['first_operation'] = first
                    trace['denial_observed_before_host_recovery_ns'] = time.monotonic_ns()
                    if fencing == 'delayed': time.sleep(.5)
                    authority.network(False); blocked = False
                    guest.command('test-recover-awake')
                    recovery = guest.wait('test-awake-recovery',10)
                    assert not recovery['attach_allowed'], recovery
                    trace['recovery'] = recovery
                authority.ready(guest)
                assert guest.ssh('cat '+shlex.quote(authority.target+'/'+token)) == 'peer-after-old-permission'
                trace['fresh_permission_observed_host_ns'] = time.monotonic_ns()
                traces.append(trace)
                (authority.evidence/'g0-vz-pauses.json').write_text(json.dumps(traces,indent=2)+'\n')
                record(case)
                authority.unmount(guest,managed)
                managed = authority.mount(guest)
            finally:
                if blocked: authority.network(False)
                if worker is not None:
                    if worker.poll() is None:
                        worker.terminate()
                        try: worker.wait(timeout=5)
                        except subprocess.TimeoutExpired: worker.kill();worker.wait(timeout=5)
                    worker.stdin.close();worker.stdout.close();worker.stderr.close()
    return managed
