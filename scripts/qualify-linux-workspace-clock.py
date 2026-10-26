#!/usr/bin/env python3
"""Read-only UTC qualification for an exact, already-running disposable guest.

A full run is explicitly requested with --soak. It never starts automatically.
The NTS adapter command must return independently authenticated observations:
{"references":[{"server":"...","protocol":"NTS","authenticated":true,
"unix_ns":...,"uncertainty_ns":...}, ...]}. Each observation's sample lies
inside that command invocation. No host clock is changed. Missing evidence is
inconclusive, including missing NTS, resume or duplicate-reader coverage.
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

SECOND = 1_000_000_000
FULL_SECONDS = 72 * 3600
BLOCK_SECONDS = 3 * 3600
INTERVAL = 30


def utc_ns(value):
    fraction = re.search(r'\.(\d+)(?:Z|[+-]\d\d:\d\d)$', value)
    extra = int((fraction.group(1)+'000000000')[6:9]) if fraction else 0
    value = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    delta = value - epoch
    return (delta.days * 86400 + delta.seconds) * SECOND + delta.microseconds * 1000 + extra


def reference_interval(references, began, ended, guest_began, guest_ended):
    """Charge server uncertainty and the complete command/SSH transit window."""
    if not isinstance(references, list) or len(references) < 2:
        raise ValueError('two independent NTS servers required')
    servers, intervals = set(), []
    for ref in references:
        if ref['protocol'] != 'NTS' or ref['authenticated'] is not True:
            raise ValueError('unauthenticated UTC reference')
        if not ref['server'] or ref['server'] in servers:
            raise ValueError('references must use independent servers')
        servers.add(ref['server'])
        uncertainty = ref['uncertainty_ns']
        if type(uncertainty) is not int or not 0 <= uncertainty <= SECOND:
            raise ValueError('reference uncertainty outside source allocation')
        instant = ref['unix_ns']
        if type(instant) is not int:
            raise ValueError('reference timestamp must be integer nanoseconds')
        intervals.append((instant - uncertainty + max(0, guest_began - ended),
                          instant + uncertainty + guest_ended - began))
    low, high = max(v[0] for v in intervals), min(v[1] for v in intervals)
    if low > high:
        raise ValueError('independent UTC intervals disagree')
    return low, high


def evaluate(sample, reference=None):
    m = sample['measurement']
    age = sample['elapsed_ns'] - m['elapsed_end_ns']
    sample_age = m['sample_age_ns']
    if not 0 <= age < 60 * SECOND:
        raise ValueError('measurement freshness exhausted')
    if not 0 <= sample_age <= SECOND // 4:
        raise ValueError('RTC sample/set age exceeds 250 ms')
    rtc_low = utc_ns(m['rtc']) + age
    rtc_high = rtc_low + SECOND + sample_age  # upper endpoint is exclusive
    # Quantization is strictly less than one second; sample/set age is separate.
    conditional_low, conditional_high = rtc_low - SECOND, rtc_high + SECOND
    wall = sample['wall_ns']
    worst = max(abs(wall - conditional_low), abs(wall - conditional_high)) + SECOND // 4
    if worst > 3 * SECOND:
        raise ValueError('conditional UTC allocation exceeds three seconds')
    result = dict(measurement_age_ns=age, quantization_upper_exclusive_ns=SECOND,
                  sample_set_age_ns=sample_age, worst_conditional_utc_error_ns=worst,
                  source='inconclusive', drift='inconclusive')
    drift = abs(wall - (utc_ns(m['wall_after']) + age)) + sample_age
    result['awake_drift_bound_ns'] = drift
    result['drift'] = 'pass' if drift <= SECOND // 4 else 'fail'
    if drift > SECOND // 4:
        raise ValueError('awake wall/BOOTTIME drift exceeds 250 ms')
    if reference is not None:
        low, high = reference
        offset = (rtc_low - high, rtc_high - low)
        result['source_offset_interval_ns'] = offset
        result['source'] = ('pass' if max(abs(v) for v in offset) <= SECOND else
                            'fail' if offset[0] > SECOND or offset[1] < -SECOND else 'inconclusive')
        result['reference_interval_ns'] = reference
        result['wall_offset_interval_ns'] = (wall - high, wall - low)
    return result


# Bounded CPU, fsync, directory traversal and source indexing in one owned tree.
LOAD = r'''
import hashlib,os,pathlib,tempfile,time
end=time.monotonic()+float(__import__('sys').argv[1])
with tempfile.TemporaryDirectory(prefix='pfs-clock-load-') as root:
 p=pathlib.Path(root); data=b'x'*1048576
 for n in range(256): (p/('source-%04d.py'%n)).write_text('def value(): return 42\n'*128)
 while time.monotonic()<end:
  for n in range(16):
   with (p/('io-%d'%n)).open('wb') as f: f.write(data);f.flush();os.fsync(f.fileno())
   hashlib.sha256(data).digest()
  for f in p.glob('source-*'): compile(f.read_text(),str(f),'exec')
'''
PROBE = "python3 -c " + shlex.quote("import json,time; m=json.load(open('/run/portablefs-workspace/clock.json')); print(json.dumps(dict(measurement=m,elapsed_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),wall_ns=time.time_ns())))")


class PauseCampaign:
    """The exact candidate's test owner supplies VZ controls; never sleep macOS.

    The command receives one case JSON argument and returns causal evidence.
    It owns only its VM, runs prestarted operations and fresh duplicate reads,
    and collects NTS observations around the first register read after resume.
    Missing command/coverage never produces a qualification pass.
    """
    def __init__(self, command, image_hash, evidence, duration, dry_run):
        self.command, self.image_hash, self.evidence = command, image_hash, evidence
        self.duration, self.dry_run = duration, dry_run
        self.started = time.monotonic()
        self.stop = threading.Event()
        self.active = threading.Event()
        self.records, self.errors = [], []
        self.thread = threading.Thread(target=self.run, daemon=True)
        if command:
            self.thread.start()

    def run(self):
        blocks = 1 if self.dry_run else int(self.duration // (6*3600))
        for block in range(blocks):
            if self.stop.wait(max(0,self.started+(60 if self.dry_run else 900+block*6*3600)-time.monotonic())):
                return
            cases = [(mode,pause) for mode in ('normal','delayed','suppressed')
                     for pause in ((.1,) if self.dry_run else (.1,.5,2,5,15,45,150,600))]
            for mode,pause in cases:
                if self.stop.is_set(): return
                case = dict(block=block, fencing=mode, pause_seconds=pause,
                            image_manifest_sha256=self.image_hash, host_sleep=False)
                self.active.set()
                try:
                    raw = subprocess.check_output(shlex.split(self.command)+[json.dumps(case)], text=True,
                                                  timeout=pause+120)
                    result = json.loads(raw)
                    if result.get('image_manifest_sha256') != self.image_hash:
                        raise ValueError('pause driver used a different image')
                    if result.get('case') != case or result.get('first_operation_prestarted') is not True:
                        raise ValueError('pause driver did not bind the requested prestarted operation')
                    if mode != 'normal' and result.get('denied_before_host_round_trip') is not True:
                        raise ValueError('expired admission succeeded or waited for host recovery')
                    if not (result.get('closed_cold_fresh') is True or result.get('terminal_cleanup_complete') is True):
                        raise ValueError('pause did not prove cold recovery or exact terminal cleanup')
                    first = result['first_read']
                    interval = reference_interval(first['references'], first['reference_began_ns'],
                        first['reference_ended_ns'], first['sample_began_ns'], first['sample_ended_ns'])
                    rtc = utc_ns(first['rtc'])
                    offset = (rtc-interval[1],rtc+SECOND+first['sample_age_ns']-interval[0])
                    if not 0 <= first['sample_age_ns'] <= SECOND//4:
                        raise ValueError('first resumed sample exceeded age allocation')
                    result['first_read_source_offset_ns'] = offset
                    result['first_read_source'] = ('pass' if max(abs(v) for v in offset)<=SECOND else 'inconclusive')
                    duplicate = result['duplicate_readers']
                    if duplicate['readers']<8 or duplicate['samples']<8000 or not 0<=duplicate['maximum_ns']<=SECOND//4:
                        raise ValueError('concurrent duplicate-reader coverage incomplete')
                    self.records.append(result)
                except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
                    self.errors.append(dict(case=case,error=str(error)))
                finally:
                    self.active.clear()
                    (self.evidence/'pause-campaign.json').write_text(json.dumps(dict(cases=self.records,errors=self.errors),indent=2)+'\n')

    def finish(self):
        self.stop.set()
        if self.command:
            self.thread.join(timeout=725)
            if self.thread.is_alive():
                self.errors.append(dict(error="pause driver failed to join; qualification incomplete"))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=pathlib.Path)
    p.add_argument('ssh_config')
    p.add_argument('evidence', type=pathlib.Path)
    p.add_argument('--seconds', type=float, default=65)
    p.add_argument('--soak', action='store_true', help='explicitly run 72 hours')
    p.add_argument('--dry-run', action='store_true', help='exercise idle/load in 15-minute blocks')
    p.add_argument('--utc-reference-command')
    p.add_argument('--admission-evidence', type=pathlib.Path)
    p.add_argument('--pause-command', help='read-only-clock native VZ qualification driver; receives one JSON case argument')
    a = p.parse_args()
    seconds = FULL_SECONDS if a.soak else a.seconds
    if seconds < 60 or (a.soak and a.dry_run):
        p.error('measurement requires at least 60 seconds; soak and dry-run are exclusive')
    block_seconds = 900 if a.dry_run else BLOCK_SECONDS
    a.evidence.mkdir(parents=True, exist_ok=True)
    manifest = (a.image / 'manifest.json').read_bytes()
    image_hash = hashlib.sha256(manifest).hexdigest()
    ssh = ['ssh', '-F', a.ssh_config, 'portablefs-workspace']
    records, failures, drift_bounds = [], [], []
    start, next_sample, block, load = time.monotonic(), 0., -1, None
    deadline = start + seconds
    campaign = PauseCampaign(a.pause_command, image_hash, a.evidence, seconds, a.dry_run)
    sample_file = (a.evidence / 'samples.jsonl').open('w')
    try:
        while True:
            now = time.monotonic()
            current = int((now - start) // block_seconds)
            if current != block:
                if load is not None:
                    load.wait(timeout=15)
                    if load.returncode != 0:
                        failures.append('owned guest load failed')
                    load = None
                block = current
                if block % 2:
                    duration = max(0, min(deadline, start + (block + 1) * block_seconds) - now)
                    load = subprocess.Popen(ssh + ['python3 -c ' + shlex.quote(LOAD) + ' ' + str(duration)],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            reference, reference_error = None, None
            ref_began = time.monotonic_ns()
            try:
                if a.utc_reference_command:
                    reference = json.loads(subprocess.check_output(shlex.split(a.utc_reference_command), text=True, timeout=10))
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                reference_error = str(error)
            ref_ended = time.monotonic_ns()
            began = time.monotonic_ns()
            record = dict(index=len(records), block=block, load='load' if block % 2 else 'idle',
                          host_elapsed_ns=began-int(start*SECOND), independent_reference=reference, reference_error=reference_error, reference_valid=False)
            if reference:
                try:
                    reference_interval(reference['references'],ref_began,ref_ended,ref_ended,ref_ended)
                    record['reference_valid']=True
                except (KeyError,TypeError,ValueError) as error:
                    record['reference_error']=str(error)
            try:
                sample = json.loads(subprocess.check_output(ssh + [PROBE], text=True, timeout=10))
                ended = time.monotonic_ns()
                interval = None
                if reference:
                    try:
                        interval = reference_interval(reference['references'], ref_began, ref_ended, began, ended)
                    except (KeyError, TypeError, ValueError) as error:
                        reference_error = str(error)
                checks = evaluate(sample, interval)
                record.update(sample=sample, checks=checks, independent_reference=reference,
                              reference_error=reference_error, host_measurement_ns=ended-began,
                              full_reference_sampling_transit_ns=ended-ref_began)
                drift_bounds.append(checks['awake_drift_bound_ns'])
                if checks['source'] == 'fail':
                    failures.append('independent source error exceeds one second')
            except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
                record['error'] = str(error)
                if campaign.active.is_set():
                    record['intentional_pause_unavailability'] = True
                else:
                    failures.append(str(error))
            records.append(record)
            sample_file.write(json.dumps(record, sort_keys=True)+'\n'); sample_file.flush()
            if time.monotonic() >= deadline:
                break
            next_sample += INTERVAL
            time.sleep(max(0, min(start+next_sample, deadline)-time.monotonic()))
    finally:
        sample_file.close()
        campaign.finish()
        if load is not None:
            # Only our SSH process, whose bounded remote workload owns a temp tree.
            load.wait(timeout=20)
    (a.evidence / 'samples.json').write_text(json.dumps(records, indent=2)+'\n')
    coverage = sum(v.get('checks', {}).get('source') == 'pass' for v in records)
    available = len(records)-sum(v.get('intentional_pause_unavailability') is True for v in records)
    reference_coverage = sum(v.get('reference_valid') is True for v in records)
    full = time.monotonic()-start >= FULL_SECONDS and not a.dry_run
    utc = ('fail' if failures else 'pass' if full and available > 0 and coverage == available and reference_coverage == len(records) and
           drift_bounds and all(v <= SECOND//4 for v in drift_bounds) else 'inconclusive')
    admission, resume_covered, duplicates_covered = 'inconclusive', False, False
    if a.admission_evidence:
        evidence = json.loads(a.admission_evidence.read_text())
        if evidence.get('image_manifest_sha256') == image_hash:
            admission = evidence.get('rtc_admission', 'inconclusive')
            resume_covered = evidence.get('first_read_after_resume') is True
            duplicates_covered = evidence.get('concurrent_duplicate_readers') is True
    campaign_complete = (bool(a.pause_command) and not campaign.errors and full and
                         len(campaign.records)==12*3*8 and
                         all(v['first_read_source']=='pass' for v in campaign.records))
    if not campaign_complete:
        resume_covered = False
        duplicates_covered = False
    if not resume_covered or not duplicates_covered:
        utc = 'inconclusive' if utc != 'fail' else utc
    result = dict(format=8, image_manifest_sha256=image_hash, seconds=time.monotonic()-start,
                  dry_run=a.dry_run, full_soak=full, samples=len(records), source_coverage=coverage, source_measurements=available, reference_coverage=reference_coverage,
                  blocks=sorted({(v['block'], v['load']) for v in records}), failures=failures,
                  awake_discipline_passed=not failures, utc=utc, rtc_admission=admission,
                  g0='pass' if utc == admission == 'pass' else 'fail' if 'fail' in (utc,admission) else 'inconclusive',
                  first_read_after_resume=resume_covered, concurrent_duplicate_readers=duplicates_covered,
                  pause_campaign_cases=len(campaign.records), pause_campaign_errors=campaign.errors,
                  utc_accuracy_qualified=utc == 'pass',
                  unproven=[name for name,ok in [('72-hour coverage',full),('independent NTS UTC coverage',reference_coverage==len(records) and coverage==available),
                            ('first read after VZ resume',resume_covered),('concurrent duplicated readers',duplicates_covered),
                            ('six-hour VZ pause campaigns',campaign_complete),('awake drift bound',bool(drift_bounds) and all(v<=SECOND//4 for v in drift_bounds))] if not ok])
    (a.evidence / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True), flush=True)
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
