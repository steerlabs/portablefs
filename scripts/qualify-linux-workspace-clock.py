#!/usr/bin/env python3
"""Measure the pinned image's awake RTC/wall discipline; never qualify UTC by assumption.

The supplied SSH config must belong to the disposable native-test VM. This
harness neither samples RTC for admission nor corrects any clock. An optional
independent UTC reference command returns {unix_ns, error_ns}; its provenance
and multi-day coverage must be reviewed separately before a release verdict.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import shlex
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('image', type=pathlib.Path)
p.add_argument('ssh_config')
p.add_argument('evidence', type=pathlib.Path)
p.add_argument('--seconds', type=float, default=65)
p.add_argument('--utc-reference-command')
a = p.parse_args()
assert a.seconds >= 60, 'awake measurement must span at least one full maintenance interval'
a.evidence.mkdir(parents=True, exist_ok=True)
manifest = (a.image / 'manifest.json').read_bytes()
records = []
start = time.monotonic()
probe = "python3 -c " + shlex.quote("import json,time; m=json.load(open('/run/portablefs-workspace/clock.json')); print(json.dumps(dict(measurement=m,elapsed_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),wall_ns=time.time_ns())))")

def ns(value):
    return int(datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()*1e9)

while True:
    reference = None
    if a.utc_reference_command:
        reference = json.loads(subprocess.check_output(shlex.split(a.utc_reference_command), text=True, timeout=10))
        assert 0 <= reference['error_ns'] <= 1_000_000_000
    began = time.monotonic_ns()
    v = json.loads(subprocess.check_output(['ssh', '-F', a.ssh_config, 'portablefs-workspace', probe], text=True, timeout=10))
    ended = time.monotonic_ns()
    m = v['measurement']
    age = v['elapsed_ns'] - m['elapsed_end_ns']
    assert 0 <= age < 60_000_000_000, 'clock measurement freshness exceeded'
    assert m['sample_age_ns'] <= 250_000_000, 'sample/set allocation exceeded'
    rtc = ns(m['rtc']) + age
    # Includes the source allocation without claiming it has been established.
    lower = rtc - 1_000_000_000
    upper = rtc + 2_000_000_000 + m['sample_age_ns']
    worst = max(abs(v['wall_ns']-lower), abs(v['wall_ns']-upper)) + 250_000_000
    assert worst <= 3_000_000_000, 'wall outside qualified-source uncertainty budget'
    v.update(host_measurement_ns=ended-began, worst_conditional_utc_error_ns=worst)
    if reference:
        # This broad interval also charges the complete SSH transit interval.
        v['independent_reference'] = reference
        v['reference_observation_bound_ns'] = reference['error_ns'] + ended-began
    records.append(v)
    (a.evidence / 'samples.json').write_text(json.dumps(records, indent=2)+'\n')
    if time.monotonic()-start >= a.seconds:
        break
    time.sleep(min(5, a.seconds-(time.monotonic()-start)))
assert len({r['measurement']['elapsed_end_ns'] for r in records}) >= 2
(a.evidence / 'result.json').write_text(json.dumps(dict(
    format=8, image_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
    seconds=time.monotonic()-start, samples=len(records), awake_discipline_passed=True,
    utc_accuracy_qualified=False, independent_reference_supplied=bool(a.utc_reference_command),
    unproven=['multi-day independently credible UTC accuracy', 'RTC relation to host corrections',
              'worst-case long-awake drift under load', 'unfenced host-sleep ordering']), indent=2)+'\n')
