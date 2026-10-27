#!/usr/bin/env python3
"""Read-only UTC qualification for an exact, already-running disposable guest.

A full run is explicitly requested with --soak. It never starts automatically.
The NTS adapter command must return independently authenticated observations:
{"references":[{"server":"...","protocol":"NTS","authenticated":true,
"unix_ns":...,"uncertainty_ns":...}, ...]}. Each observation's sample lies
inside that command invocation. No host clock is changed. Missing evidence is
inconclusive, including missing NTS, resume or duplicate-reader coverage.
Optional query_began_ns/query_ended_ns in the named host monotonic clock constrain
the NTP sample inside the full invocation without charging earlier NTS-KE time.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import time
import threading
import re
import sys
import selectors
import uuid
from g3_continuity import verify_owner, verify_awake, host_pair, record_invalid
from g3_coverage import (OPERATORS, BoundViolation, ReferenceDisagreement, coverage_verdict, campaign_coverage, causal_generation)

SECOND = 1_000_000_000
FULL_SECONDS = 72 * 3600
BLOCK_SECONDS = 3 * 3600
INTERVAL = 30
REFERENCE_CLOCK = {'darwin':'darwin.CLOCK_UPTIME_RAW','linux':'linux.CLOCK_MONOTONIC'}.get(sys.platform)


def utc_ns(value):
    fraction = re.search(r'\.(\d+)(?:Z|[+-]\d\d:\d\d)$', value)
    extra = int((fraction.group(1)+'000000000')[6:9]) if fraction else 0
    value = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    delta = value - epoch
    return (delta.days * 86400 + delta.seconds) * SECOND + delta.microseconds * 1000 + extra


def reference_interval(references, began, ended, guest_began, guest_ended, reference_clock=None):
    """Charge server uncertainty and the complete bounded NTP/SSH transit window."""
    if any(type(value) is not int for value in (began,ended,guest_began,guest_ended)):
        raise ValueError('timestamp brackets must use integer nanoseconds')
    if began > ended or guest_began > guest_ended:
        raise ValueError('reversed reference or sample interval')
    if not isinstance(references, list) or len(references) < 2:
        raise ValueError('two independent NTS servers required')
    if reference_clock is not None and (REFERENCE_CLOCK is None or reference_clock != REFERENCE_CLOCK):
        raise ValueError('reference uses a different monotonic clock')
    servers, operators, intervals = set(), set(), []
    for ref in references:
        if ref['protocol'] != 'NTS' or ref['authenticated'] is not True:
            raise ValueError('unauthenticated UTC reference')
        if ref['server'] not in OPERATORS:
            raise ValueError('reference outside approved hostname policy')
        operator = OPERATORS[ref['server']]
        if ref.get('operator', operator) != operator:
            raise ValueError('reference operator identity mismatch')
        operators.add(operator)
        servers.add(ref['server'])
        uncertainty = ref['uncertainty_ns']
        if type(uncertainty) is not int or not 0 <= uncertainty <= SECOND:
            raise ValueError('reference uncertainty outside source allocation')
        instant = ref['unix_ns']
        if type(instant) is not int:
            raise ValueError('reference timestamp must be integer nanoseconds')
        first, last = began, ended
        if reference_clock is not None:
            qb, qe = ref['query_began_ns'], ref['query_ended_ns']
            if type(qb) is not int or type(qe) is not int or not began<=qb<=qe<=ended:
                raise ValueError('NTP query outside reference command interval')
            # Both clocks use the same kernel monotonic domain. Charge the
            # complete NTP/guest transit. KE precedes this fresh time sample;
            # process launch and exit cannot change its observed endpoints.
            first, last = qb, qe
        intervals.append((instant - uncertainty + guest_began - last,
                          instant + uncertainty + guest_ended - first))
    if len(operators) < 2:
        raise ValueError('two independent NTS operators required')
    low, high = max(v[0] for v in intervals), min(v[1] for v in intervals)
    if low > high:
        raise ReferenceDisagreement('authenticated UTC intervals disagree')
    return low, high


def evaluate(sample, reference=None):
    m = sample['measurement']
    age = sample['elapsed_ns'] - m['elapsed_end_ns']
    sample_age = m['sample_age_ns']
    if not 0 <= age < 60 * SECOND:
        raise ValueError('measurement freshness exhausted')
    if not 0 <= sample_age <= SECOND // 4:
        raise BoundViolation('RTC sample/set age exceeds 250 ms')
    rtc_low = utc_ns(m['rtc']) + age
    rtc_high = rtc_low + SECOND + sample_age  # upper endpoint is exclusive
    # Quantization is strictly less than one second; sample/set age is separate.
    conditional_low, conditional_high = rtc_low - SECOND, rtc_high + SECOND
    wall = sample['wall_ns']
    worst = max(abs(wall - conditional_low), abs(wall - conditional_high)) + SECOND // 4
    if worst > 3 * SECOND:
        raise BoundViolation('conditional UTC allocation exceeds three seconds')
    result = dict(measurement_age_ns=age, quantization_upper_exclusive_ns=SECOND,
                  sample_set_age_ns=sample_age, worst_conditional_utc_error_ns=worst,
                  source='inconclusive', drift='inconclusive')
    drift = abs(wall - (utc_ns(m['wall_after']) + age)) + sample_age
    result['awake_drift_bound_ns'] = drift
    result['drift'] = 'pass' if drift <= SECOND // 4 else 'fail'
    if drift > SECOND // 4:
        raise BoundViolation('awake wall/BOOTTIME drift exceeds 250 ms')
    if reference is not None:
        low, high = reference
        # Charge the measured guest wall/BOOTTIME projection discrepancy
        # within the existing source allocation, never as extra budget.
        offset = (rtc_low - high - drift, rtc_high - low + drift)
        result['source_offset_interval_ns'] = offset
        result['source'] = ('pass' if max(abs(v) for v in offset) <= SECOND else
                            'fail' if offset[0] > SECOND or offset[1] < -SECOND else 'inconclusive')
        result['reference_interval_ns'] = reference
        result['wall_offset_interval_ns'] = (wall - high, wall - low)
    return result


def measurement_coverage(records, seconds):
    # Catch-up bursts cannot replace an unobserved thirty-second interval.
    slots = [v['interval_slot'] for v in records if v.get('observation') != 'closing']
    return len(slots) == len(set(slots)) and set(range(int(seconds // INTERVAL))).issubset(slots)


# Bounded CPU, fsync, directory traversal and source indexing in one owned tree.
LOAD = r'''
import hashlib,os,pathlib,sys,tempfile,threading
stop=threading.Event()
def until_closed():
 sys.stdin.buffer.read(1);stop.set()
threading.Thread(target=until_closed,daemon=True).start()
with tempfile.TemporaryDirectory(prefix='pfs-clock-load-') as root:
 p=pathlib.Path(root); data=b'x'*1048576
 for n in range(256): (p/('source-%04d.py'%n)).write_text('def value(): return 42\n'*128)
 print('load-ready',flush=True)
 while not stop.is_set():
  for n in range(16):
   with (p/('io-%d'%n)).open('wb') as f: f.write(data);f.flush();os.fsync(f.fileno())
   hashlib.sha256(data).digest()
  for f in p.glob('source-*'): compile(f.read_text(),str(f),'exec')
'''
PROBE = "python3 -c " + shlex.quote("import json,time,pathlib,subprocess; m=json.load(open('/run/portablefs-workspace/clock.json')); print(json.dumps(dict(measurement=m,elapsed_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),wall_ns=time.time_ns(),boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),service_pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value','portablefs-workspaced'],text=True).strip())))")


def stop_load(load):
    # EOF names only this SSH command's owned workload and remains meaningful
    # when guest MONOTONIC stopped during a VZ pause in the load block.
    load.stdin.close()
    try:
        return load.wait(timeout=20) == 0
    except subprocess.TimeoutExpired:
        load.terminate()
        try:
            load.wait(timeout=5)
        except subprocess.TimeoutExpired:
            load.kill(); load.wait(timeout=5)
        return False


class PauseCampaign:
    """The exact candidate's test owner supplies VZ controls; never sleep macOS.

    The command receives one case JSON argument and returns causal evidence.
    It owns only its VM, runs prestarted operations and fresh duplicate reads,
    and collects NTS observations around the first register read after resume.
    Missing command/coverage never produces a qualification pass.
    """
    def __init__(self, command, image_hash, evidence, duration, dry_run, start_ns=None, run_id=None):
        self.command, self.image_hash, self.evidence = command, image_hash, evidence
        self.duration, self.dry_run = duration, dry_run
        self.started = (start_ns/SECOND if start_ns is not None else time.monotonic())
        self.run_id = run_id
        self.start_ns = start_ns
        self.stop = threading.Event()
        self.active = threading.Event()
        self.records, self.errors = [], []
        self.thread = threading.Thread(target=self.run, daemon=True)
        if command:
            self.thread.start()

    def run(self):
        blocks = 1 if self.dry_run else int(self.duration // (6*3600))
        for block in range(blocks):
            cases = [(mode,pause) for mode in ('normal','delayed','suppressed')
                     for pause in ((.1,) if self.dry_run else (.1,.5,2,5,15,45,150,600))]
            if block % 2: cases.reverse()
            for index,(mode,pause) in enumerate(cases):
                phase = 0 if self.dry_run or index < len(cases)//2 else 1
                when = 60 if self.dry_run else 900+block*6*3600+phase*3*3600
                if self.stop.wait(max(0,self.started+when-time.monotonic())):
                    return
                if self.stop.is_set(): return
                case = dict(block=block, fencing=mode, pause_seconds=pause,
                            image_manifest_sha256=self.image_hash, host_sleep=False,
                            load='load' if phase else 'idle', run_id=self.run_id, run_start_ns=self.start_ns)
                self.active.set()
                try:
                    result = None
                    raw = subprocess.check_output(shlex.split(self.command)+[json.dumps(case)], text=True,
                                                  timeout=pause+120)
                    result = json.loads(raw)
                    if not isinstance(result,dict): raise ValueError('pause driver returned a malformed result')
                    if result.get('bound_violation'):
                        raise BoundViolation(result.get('error','observed campaign admission violation'))
                    if result.get('image_manifest_sha256') != self.image_hash:
                        raise ValueError('pause driver used a different image')
                    if result.get('case') != case or result.get('first_operation_prestarted') is not True:
                        raise ValueError('pause driver did not bind the requested prestarted operation')
                    if mode != 'normal' and result.get('denied_before_host_round_trip') is not True:
                        raise ValueError('expired admission succeeded or waited for host recovery')
                    if not (result.get('closed_cold_fresh') is True or result.get('terminal_cleanup_complete') is True):
                        raise ValueError('pause did not prove cold recovery or exact terminal cleanup')
                    first = result['first_read']
                    if (first.get('vm') != 'product' or first.get('operation_prestarted') is not True
                            or first.get('host_round_trip_after_resume') is not False
                            or not causal_generation(first,result.get('trace') or {})):
                        raise ValueError('missing causal product RTC first read/generation')
                    interval = reference_interval(first['references'], first['reference_began_ns'],
                        first['reference_ended_ns'], first['sample_began_ns'], first['sample_ended_ns'],first.get('clock'))
                    rtc = utc_ns(first['rtc'])
                    offset = (rtc-interval[1],rtc+SECOND+first['sample_age_ns']-interval[0])
                    if not 0 <= first['sample_age_ns'] <= SECOND//4:
                        raise BoundViolation('first resumed sample exceeded age allocation')
                    result['first_read_source_offset_ns'] = offset
                    result['first_read_source'] = ('pass' if max(abs(v) for v in offset)<=SECOND else 'inconclusive')
                    if offset[0] > SECOND or offset[1] < -SECOND:
                        raise BoundViolation(f'first resumed RTC source exceeds one second: {offset}')
                    duplicate = result['duplicate_readers']
                    if duplicate.get('vm') != 'product' or not duplicate.get('read_only') or not duplicate.get('second_open_busy'):
                        raise ValueError('missing product duplicate descriptor ownership')
                    if not 0<=duplicate['maximum_ns']<=SECOND//4:
                        raise BoundViolation('duplicate RTC read exceeded age allocation')
                    if duplicate['readers']<8 or duplicate['samples']<8000:
                        raise ValueError('concurrent duplicate-reader coverage incomplete')
                    self.records.append(result)
                except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
                    self.errors.append(dict(case=case,error=str(error),bound_violation=isinstance(error,BoundViolation),evidence=result))
                    if result is not None: self.records.append(result)
                finally:
                    self.active.clear()
                    temporary=self.evidence/'pause-campaign.json.tmp'
                    temporary.write_text(json.dumps(dict(cases=self.records,errors=self.errors),indent=2)+'\n')
                    temporary.replace(self.evidence/'pause-campaign.json')

    def finish(self):
        self.stop.set()
        if self.command:
            self.thread.join(timeout=725)
            if self.thread.is_alive():
                self.errors.append(dict(error="pause driver failed to join; qualification incomplete"))

    def sample_token(self):
        return self.active.is_set(), len(self.records) + len(self.errors)

    def overlaps_sample(self, token):
        return token[0] or self.active.is_set() or token[1] != len(self.records) + len(self.errors)


def wall_pair():
    began = time.monotonic_ns()
    wall = time.time_ns()
    ended = time.monotonic_ns()
    return dict(began_ns=began, wall_ns=wall, ended_ns=ended)


def attach_planned_windows(records, campaign):
    # Only a completed causal product trace can excuse an unavailable sample.
    # The driver's process lifetime (or an unrelated SSH timeout) is no window.
    for case in campaign.records:
        trace = case.get('trace') or {}
        if not trace.get('fresh_permission_observed_host_ns') or not trace.get('peer_receipt_observed_host_ns'):
            continue
        window = dict(begin_ns=trace['fence_requested_host_ns'],
                      end_ns=trace['fresh_permission_observed_host_ns'],
                      run_id=case['case']['run_id'], verified=True,
                      case=[case['case'][k] for k in ('block','fencing','pause_seconds')])
        for row in records:
            if (row['sample_began_ns'] <= window['end_ns'] and row['sample_ended_ns'] >= window['begin_ns']
                    and ('sample' in row or row.get('error_type')=='TimeoutExpired')):
                row['planned_window'] = window
                row['intentional_pause_unavailability'] = True
            elif row['sample_began_ns'] > window['end_ns'] and row.get('sample') and trace.get('product_first_read'):
                first=trace['product_first_read']
                sample=row['sample']
                recovery_generation=trace.get('recovery',{}).get('generation')
                if (type(recovery_generation) is not int
                        or sample['measurement']['generation'] < recovery_generation):
                    row['error']='guest BOOTTIME projection crosses a pause/recovery generation'
                    row['rejected_projection']=row.pop('sample')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=pathlib.Path)
    p.add_argument('ssh_config')
    p.add_argument('evidence', type=pathlib.Path)
    p.add_argument('--seconds', type=float, default=65)
    p.add_argument('--soak', action='store_true')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--utc-reference-command')
    p.add_argument('--admission-evidence', type=pathlib.Path)
    p.add_argument('--pause-command')
    p.add_argument('--stop-file', type=pathlib.Path)
    p.add_argument('--invalid-file', type=pathlib.Path)
    p.add_argument('--run-id', default=None)
    p.add_argument('--hold-file',type=pathlib.Path)
    p.add_argument('--owner-pid',type=int)
    p.add_argument('--owner-status',type=pathlib.Path)
    a = p.parse_args()
    seconds = FULL_SECONDS if a.soak else a.seconds
    if a.soak and (not a.owner_pid or not a.owner_status):
        p.error('soak requires the continuous native owner and its status evidence')
    if seconds < 60 or seconds % INTERVAL or (a.soak and a.dry_run):
        p.error('duration must contain whole 30-second slots, at least 60s; soak excludes dry-run')
    block_seconds = 900 if a.dry_run else BLOCK_SECONDS
    a.evidence.mkdir(parents=True, exist_ok=False)
    image_hash = hashlib.sha256((a.image/'manifest.json').read_bytes()).hexdigest()
    ssh = ['ssh','-F',a.ssh_config,'portablefs-workspace']
    run_id = a.run_id or str(uuid.uuid4())
    host_awake_origin=host_pair()
    start_ns = time.monotonic_ns()
    start_pair=wall_pair()
    start_wall_ns=start_pair['wall_ns']+start_ns-(start_pair['began_ns']+start_pair['ended_ns'])//2
    start_time=datetime.datetime.fromtimestamp(start_wall_ns/SECOND,datetime.timezone.utc).isoformat()
    start = start_ns/SECOND
    deadline_ns = start_ns+int(seconds*SECOND)
    campaign = PauseCampaign(a.pause_command,image_hash,a.evidence,seconds,a.dry_run,start_ns,run_id)
    records, failures, run_disruptions = [], [], []
    load, block = None, -1
    next_ns = start_ns
    sample_file = (a.evidence/'samples.jsonl').open('x')
    atomic = lambda path,value: path.write_text(json.dumps(value,indent=2)+'\n')
    atomic(a.evidence/'run.json',dict(run_id=run_id,run_start_ns=start_ns,start_time=start_time,start_wall_pair=start_pair,seconds=seconds,reference_policy='astra-g3-2026-10-27',rate_envelope=None))
    try:
        while True:
            began = time.monotonic_ns()
            closing = began >= deadline_ns
            current = min(int((began-start_ns)//(block_seconds*SECOND)), int((seconds-1)//block_seconds))
            if a.hold_file and a.hold_file.exists():
                atomic(a.evidence.parent/'coordinator-request.json',dict(reason='HOLD stops native qualification; explicit coordinator release required'))
                if a.stop_file: a.stop_file.touch()
                break
            if current != block:
                if load is not None:
                    if not stop_load(load): failures.append('owned guest load failed')
                    load = None
                block = current
                if block % 2:
                    load = subprocess.Popen(ssh+['python3 -c '+shlex.quote(LOAD)],stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
                    with selectors.DefaultSelector() as ready:
                        ready.register(load.stdout,selectors.EVENT_READ)
                        if not ready.select(10) or load.stdout.readline().strip()!='load-ready':
                            failures.append('owned guest load failed to arm')
                atomic(a.evidence/'load-state.json',dict(run_id=run_id,run_start_ns=start_ns,block=block,
                       load='load' if block%2 else 'idle',pid=load.pid if load else None,
                       acknowledged_ns=time.monotonic_ns()))
            reference, reference_error = None,None
            ref_began = time.monotonic_ns()
            try:
                if a.utc_reference_command:
                    reference = json.loads(subprocess.check_output(shlex.split(a.utc_reference_command),text=True,timeout=9.8))
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                reference_error = str(error)
            ref_ended = time.monotonic_ns()
            pair = wall_pair()
            row = dict(index=len(records),run_id=run_id,run_start_ns=start_ns,block=block,
                       load='load' if block%2 else 'idle',
                       observation='closing' if closing else 'opening' if not records else 'ordinary',
                       interval_slot=None if closing else (ref_began-start_ns)//(INTERVAL*SECOND),
                       reference_began_ns=ref_began,reference_ended_ns=ref_ended,
                       independent_reference=reference,reference_error=reference_error,reference_valid=False,
                       host_wall_pair=pair,host_wall_ns=pair['wall_ns'],
                       sample_began_ns=time.monotonic_ns(),load_pid=load.pid if load else None,
                       load_alive=load.poll() is None if load else False)
            if load is not None and load.poll() is not None:
                failures.append('owned guest load exited during its load block')
            if reference:
                try:
                    reference_interval(reference['references'],ref_began,ref_ended,ref_ended,ref_ended,reference.get('clock'))
                    row['reference_valid']=True
                except (KeyError,TypeError,ValueError) as error:
                    row['reference_error']=str(error)
                    if isinstance(error,BoundViolation): row.update(bound_violation=True,error=str(error))
            try:
                row['sample']=json.loads(subprocess.check_output(ssh+[PROBE],text=True,timeout=10))
                row['sample_ended_ns']=time.monotonic_ns()
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                row.update(error=str(error),error_type=type(error).__name__,sample_ended_ns=time.monotonic_ns())
            if 'sample' in row:
                try:
                    interval=None
                    if row['reference_valid']:
                        ref=row['independent_reference']
                        interval=reference_interval(ref['references'],ref_began,ref_ended,row['sample_began_ns'],row['sample_ended_ns'],ref.get('clock'))
                    # Projection may be stale inside a causal pause. Preserve
                    # tentative checks; the final adjudication uses trace windows.
                    row['tentative_checks']=evaluate(row['sample'],interval)
                except (KeyError,TypeError,ValueError) as error:
                    row['tentative_check_error']=str(error)
            row['host_wall_pair_after']=wall_pair()
            try:
                row['host_awake_pair_ns']=verify_awake(host_awake_origin,host_pair())
            except RuntimeError as error:
                disruption=dict(run_id=run_id,error=str(error),observed_ns=time.monotonic_ns())
                run_disruptions.append(disruption);row['disruption']=disruption
                if a.invalid_file: record_invalid(a.invalid_file,disruption)
            if a.owner_pid:
                try:
                    row['owner_heartbeat_ns']=verify_owner(a.owner_status,a.owner_pid,run_id,time.monotonic_ns,os.getppid)
                except (OSError,ValueError,RuntimeError) as error:
                    disruption=dict(run_id=run_id,error=str(error),observed_ns=time.monotonic_ns())
                    run_disruptions.append(disruption);row['disruption']=disruption
                    if a.invalid_file: record_invalid(a.invalid_file,disruption)
            records.append(row)
            sample_file.write(json.dumps(row,sort_keys=True)+'\n');sample_file.flush()
            temporary=a.evidence/'progress.json.tmp'
            atomic(temporary,dict(pid=os.getpid(),run_id=run_id,run_start_ns=start_ns,seconds=(time.monotonic_ns()-start_ns)/SECOND,
                   samples=len(records),unique_slots=len({v['interval_slot'] for v in records if v['interval_slot'] is not None}),
                   reference_coverage=len({v['interval_slot'] for v in records if v['reference_valid'] and v['interval_slot'] is not None}),
                   source_coverage=sum(v.get('tentative_checks',{}).get('source')=='pass' for v in records),
                   failures=failures,pause_campaign_cases=len(campaign.records),pause_campaign_errors=campaign.errors,last_sample=row))
            temporary.replace(a.evidence/'progress.json')
            if failures or run_disruptions or closing or (a.stop_file and a.stop_file.exists()) or (a.invalid_file and a.invalid_file.exists()): break
            # Never synthesize catch-up observations for elapsed slots.
            next_ns=max(next_ns+INTERVAL*SECOND,start_ns+((time.monotonic_ns()-start_ns)//(INTERVAL*SECOND)+1)*INTERVAL*SECOND)
            time.sleep(max(0,(min(next_ns,deadline_ns)-time.monotonic_ns())/SECOND))
    finally:
        sample_file.close()
        campaign.finish()
        if load is not None and not stop_load(load): failures.append('owned guest load failed')
    try:
        verify_awake(host_awake_origin,host_pair())
        if a.owner_pid: verify_owner(a.owner_status,a.owner_pid,run_id,time.monotonic_ns,os.getppid)
    except (OSError,ValueError,RuntimeError) as error:
        disruption=dict(run_id=run_id,error=str(error),observed_ns=time.monotonic_ns())
        run_disruptions.append(disruption)
        if a.invalid_file: record_invalid(a.invalid_file,disruption)
    attach_planned_windows(records,campaign)
    disruptions=list(run_disruptions)
    if a.invalid_file and a.invalid_file.exists(): disruptions.append(json.loads(a.invalid_file.read_text()))
    verdict=coverage_verdict(records,start_ns,seconds,run_id,reference_interval,evaluate,disruptions=disruptions)
    verdict['failures'].extend(failures)
    verdict['failures'].extend(v['error'] for v in campaign.errors if v.get('bound_violation'))
    if verdict['failures']: verdict['utc']='fail'
    inventory=campaign_coverage(campaign.records,campaign.errors)
    full=seconds==FULL_SECONDS and not a.dry_run and bool(records and records[-1]['observation']=='closing')
    source_qualified=verdict['utc']=='pass'
    admission='inconclusive'
    if a.admission_evidence:
        evidence=json.loads(a.admission_evidence.read_text())
        if evidence.get('image_manifest_sha256')==image_hash: admission=evidence.get('rtc_admission','inconclusive')
    if any((v.get('evidence') or {}).get('admission_violation') for v in campaign.errors): admission='fail'
    utc=verdict['utc']
    if utc!='fail' and not(full and inventory['complete'] and inventory['first_read_after_resume'] and inventory['concurrent_duplicate_readers']): utc='inconclusive'
    checks=verdict.pop('checks')
    worst=dict(observations=len(checks),maximum_sample_set_age_ns=max((v['sample_set_age_ns'] for v in checks),default=None),
               maximum_awake_drift_ns=max((v['awake_drift_bound_ns'] for v in checks),default=None),
               maximum_conditional_utc_error_ns=max((v['worst_conditional_utc_error_ns'] for v in checks),default=None),
               maximum_source_offset_abs_ns=max((abs(n) for v in checks for n in v.get('source_offset_interval_ns',[])),default=None))
    proof_campaigns=sum(v.get('first_read_source')=='pass'
                        and v.get('first_read',{}).get('vm')=='product'
                        and v.get('duplicate_readers',{}).get('vm')=='product'
                        and v.get('duplicate_readers',{}).get('readers',0)>=8
                        and v.get('duplicate_readers',{}).get('samples',0)>=8000
                        and 0<=v.get('duplicate_readers',{}).get('maximum_ns',-1)<=SECOND//4
                        for v in campaign.records)
    proof_qualified=(not a.soak and a.dry_run and seconds==1800 and source_qualified
                     and admission=='pass' and proof_campaigns==3 and not campaign.errors)
    result=dict(format=9,run_id=run_id,image_manifest_sha256=image_hash,seconds=(time.monotonic_ns()-start_ns)/SECOND,
                coverage=verdict,proof_source_coverage_qualified=source_qualified,
                proof_qualified=proof_qualified,proof_campaigns_completed=proof_campaigns,proof_campaigns_required=3 if a.dry_run else None,worst_cases=worst,full_soak=full,
                samples=len(records),reference_coverage=verdict['direct_reference_slots'],source_coverage=verdict['source_passes'],
                source_measurements=verdict['ordinary_measurements'],failures=verdict['failures'],invalid=bool(disruptions or verdict['invalid']),
                utc=utc,rtc_admission=admission,g0='fail' if 'fail' in (utc,admission) else 'pass' if utc==admission=='pass' else 'inconclusive',
                pause_inventory=inventory,first_read_after_resume=inventory['first_read_after_resume'],
                concurrent_duplicate_readers=inventory['concurrent_duplicate_readers'],pause_campaign_errors=campaign.errors,
                measurement_coverage_complete=verdict['unique_slots']==verdict['required_slots'])
    atomic(a.evidence/'samples.json',records)
    atomic(a.evidence/'worst-cases.json',worst)
    atomic(a.evidence/'result.json',result)
    print(json.dumps(result,sort_keys=True),flush=True)
    return 1 if verdict['failures'] or result['invalid'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
