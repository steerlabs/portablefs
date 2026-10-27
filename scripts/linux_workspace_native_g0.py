"""Controlled VZ pauses with prestarted operations and an independent live peer.

These runs never sleep the host or edit a clock. Exact virtual-clock schedules
are separately owned by the injected Go inventory; actual pause durations and
publication observations are recorded here without rounding them to that model.
"""
import json
import selectors
import shlex
import subprocess
import time
import uuid


def pause_checks(authority, guest, managed, record, durations=(5,15,45,150,600), modes=('normal','delayed','suppressed'), rtc_probe=None, load=None):
    traces = []
    for duration in durations:
        for fencing in modes:
            case = f'g0-vz-{fencing}-{duration}s'
            token = 'g0-' + uuid.uuid4().hex
            worker = None
            peer = None
            blocked = False
            trace = dict(case=case, requested_pause_seconds=duration, fencing=fencing,
                         first_operation_prestarted=True, host_sleep=False, request_token=token, request_path=authority.target+'/'+token)
            def checkpoint(stage):
                trace['stage'] = stage
                (authority.evidence/'g0-vz-active.json').write_text(json.dumps(trace,indent=2)+'\n')
            try:
                if rtc_probe: rtc_probe.prepare(duration)
                trace['load'] = load
                if rtc_probe: trace['boot_id'] = rtc_probe.armed['boot_id']
                code = '''import errno,json,os,sys,time
print('armed',flush=True)
assert sys.stdin.readline().strip()=='probe'
b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);start=time.monotonic_ns()
try:
 os.stat(PATH); result={'success':True}
except OSError as e:
 result={'success':False,'errno':e.errno,'errno_name':errno.errorcode[e.errno]}
result.update(boottime_ns=b,operation_ns=time.monotonic_ns()-start)
print(json.dumps(result),flush=True)
'''.replace('PATH', repr(authority.target+'/'+token))
                worker = subprocess.Popen(['/usr/bin/ssh', '-F', guest.ready['ssh_config'],
                    '-o','ServerAliveInterval=0','-o','TCPKeepAlive=no','portablefs-workspace', 'python3 -u -c '+shlex.quote(code)],
                    text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with selectors.DefaultSelector() as ready:
                    ready.register(worker.stdout, selectors.EVENT_READ)
                    assert ready.select(10), 'prestarted first operation not armed'
                    assert worker.stdout.readline().strip() == 'armed'
                trace['worker_armed_host_ns'] = time.monotonic_ns()
                # Arm the independent peer before pausing. Starting docker exec
                # inside a 100 ms pause would measure process-launch latency
                # instead of the guest/authority deadline boundary.
                peer = subprocess.Popen(['docker','exec','-i','--user','200001:200001',authority.name,
                    'python3','-u','-c',"import os,sys; print('peer-armed',flush=True); assert sys.stdin.readline().strip()=='publish'; p="+
                    repr('/var/tmp/pfs-native/home/peer/'+token)+
                    "; f=open(p,'wb'); f.write(b'peer-after-old-permission'); f.flush(); os.fsync(f.fileno()); f.close(); print('peer-complete',flush=True)"],
                    text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with selectors.DefaultSelector() as ready:
                    ready.register(peer.stdout, selectors.EVENT_READ)
                    assert ready.select(10), 'independent peer not armed'
                    assert peer.stdout.readline().strip() == 'peer-armed'
                trace['peer_armed_host_ns'] = time.monotonic_ns()
                trace['fence_requested_host_ns'] = time.monotonic_ns()
                if fencing != 'normal':
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
                    gap = max(6.5, 10.1-duration)
                    time.sleep(gap)
                    trace['pre_pause_network_gap_seconds'] = gap
                    limit = time.monotonic()+10
                    while True:
                        guest.command('test-pause-unfenced')
                        paused = guest.wait(('test-paused-unfenced','refused'), 10)
                        if paused['event'] == 'test-paused-unfenced': break
                        assert time.monotonic()<limit, paused
                        time.sleep(.02)
                else:
                    guest.command('pause'); paused = guest.wait('paused',25)
                    assert paused['fenced'] and not paused['attach_allowed'], paused
                # Queue every case's prestarted operation while VZ is paused.
                # Normal fencing may hold it outside the cold cohort until
                # fresh admission; unfenced cases must deny without recovery.
                worker.stdin.write('probe\n'); worker.stdin.flush()
                trace['pause_confirmed_host_ns'] = time.monotonic_ns()
                checkpoint('paused')
                if rtc_probe: rtc_probe.paused(duration)
                # The ordinary peer is outside the guest and remains live.
                # It waits for the actual authority obligation, then persists.
                trace['peer_started_host_ns'] = time.monotonic_ns()
                peer.stdin.write('publish\n'); peer.stdin.flush()
                target = time.monotonic()+duration
                while time.monotonic()<target: time.sleep(min(.25,target-time.monotonic()))
                # A normal cold fence may leave the old authority obligation
                # to expire after a short pause. Resume on schedule and join
                # that peer independently; do not turn a five-second case into
                # a ten-second pause by waiting for the receipt first.
                peer_before_resume = peer.poll() is not None
                if fencing != 'normal':
                    assert peer_before_resume, 'expired-permission peer did not complete while frozen'
                trace['resume_requested_host_ns'] = time.monotonic_ns()
                if rtc_probe: rtc_probe.resuming(trace['resume_requested_host_ns'])
                trace['actual_paused_seconds'] = (trace['resume_requested_host_ns']-trace['pause_confirmed_host_ns'])/1e9
                assert duration <= trace['actual_paused_seconds'] < duration+1, trace
                trace['peer_completed_before_resume'] = peer_before_resume
                if peer_before_resume: trace['peer_completion_upper_host_ns'] = trace['resume_requested_host_ns']
                if fencing == 'normal':
                    guest.command('resume'); guest.wait('resumed',25)
                else:
                    guest.command('test-resume-unfenced'); guest.wait('test-resumed-unfenced',10)
                    with selectors.DefaultSelector() as ready:
                        ready.register(worker.stdout, selectors.EVENT_READ)
                        assert ready.select(5), 'first expired operation waited for host recovery'
                        first = json.loads(worker.stdout.readline())
                    trace['first_operation'] = first
                    checkpoint('first-operation-observed')
                    assert not first['success'] and first['errno_name'] in ('EIO','ENOTCONN','ESTALE','EACCES'), first
                    assert first['operation_ns']<1_000_000_000, first
                    trace['first_operation'] = first
                    trace['denial_observed_before_host_recovery_ns'] = time.monotonic_ns()
                    checkpoint('denied-before-recovery')
                    if fencing == 'delayed': time.sleep(.5)
                    authority.network(False); blocked = False
                    guest.command('test-recover-awake')
                    recovery = guest.wait('test-awake-recovery',10)
                    assert not recovery['attach_allowed'], recovery
                    trace['recovery'] = recovery
                stdout, stderr = peer.communicate(timeout=20)
                assert peer.returncode==0 and stdout.strip()=='peer-complete', (stdout,stderr)
                trace['peer_receipt_observed_host_ns'] = time.monotonic_ns()
                if rtc_probe:
                    trace['product_first_read'], trace['product_duplicate_readers'] = rtc_probe.finish()
                    checkpoint('product-rtc-read')
                deadline=time.monotonic()+90
                while True:
                    snapshot=authority.status(guest)
                    rows=[m for m in snapshot.get('mounts',[]) if m['mount']['volumeId']==authority.volume]
                    if rows and rows[0]['state']=='ready':
                        trace['recovery_disposition']='closed-cold-fresh'; break
                    if rows and rows[0]['state'] in ('terminal','authorization-required') and rows[0]['cleanup']=='complete':
                        trace['terminal']=rows[0]
                        authority.protected(guest)
                        authority.unmount(guest,managed)
                        previous=managed
                        managed=authority.mount(guest)
                        assert managed['incarnation']!=previous['incarnation']
                        trace['recovery_disposition']='terminal-cleanup-fresh-authorization'; break
                    assert time.monotonic()<deadline, snapshot
                    time.sleep(.05)
                if fencing == 'normal':
                    with selectors.DefaultSelector() as ready:
                        ready.register(worker.stdout, selectors.EVENT_READ)
                        assert ready.select(5), 'fenced first operation stranded after recovery'
                        trace['first_operation'] = json.loads(worker.stdout.readline())
                assert worker.wait(timeout=5) == 0, worker.stderr.read()
                assert guest.ssh('cat '+shlex.quote(authority.target+'/'+token)) == 'peer-after-old-permission'
                trace['fresh_permission_observed_host_ns'] = time.monotonic_ns()
                checkpoint('fresh-permission')
                traces.append(trace)
                (authority.evidence/'g0-vz-pauses.json').write_text(json.dumps(traces,indent=2)+'\n')
                record(case)
                authority.unmount(guest,managed)
                managed = authority.mount(guest)
            finally:
                if rtc_probe: rtc_probe.close()
                if blocked: authority.network(False)
                if peer is not None and peer.poll() is None:
                    peer.terminate()
                    try: peer.wait(timeout=5)
                    except subprocess.TimeoutExpired: peer.kill();peer.wait(timeout=5)
                if worker is not None:
                    if worker.poll() is None:
                        worker.terminate()
                        try: worker.wait(timeout=5)
                        except subprocess.TimeoutExpired: worker.kill();worker.wait(timeout=5)
                    worker.stdin.close();worker.stdout.close();worker.stderr.close()
    return managed
