#!/usr/bin/env python3
"""Serial native VZ boot/workload/orderly-stop cycles; fail on kernel diagnostics."""
import argparse
import hashlib
import json
import pathlib
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from linux_workspace_native_pressure import MemoryPressureRecorder

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=pathlib.Path)
parser.add_argument('image', type=pathlib.Path)
parser.add_argument('evidence', type=pathlib.Path)
parser.add_argument('--cycles', type=int, default=50)
args = parser.parse_args()
assert args.cycles > 0
args.evidence.mkdir(parents=True, exist_ok=True)
assert not any(args.evidence.iterdir()), 'evidence directory must be empty'
workload = pathlib.Path(__file__).with_name('linux-workspace-kernel-workload.sh').read_text()
release = json.loads((args.image / 'release.json').read_text())
kernel = json.loads((args.image / 'image-inputs.json').read_text())['lock']['kernel_release']
# Include firmware failures and nonfatal warnings; no allowlist hides known errors.
diagnostic = re.compile(r'\b(?:warning|error|bug|oops|kernel panic|failed|failure|corrupt(?:ion|ed)?|call trace|unable to handle|hung task|soft lockup|hard lockup)\b', re.I)
ansi = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
kernel_line = re.compile(r'^\[\s*\d+\.\d+\]\s*(.*)')
results = {'release': release, 'kernel': kernel, 'requested_cycles': args.cycles,
           'workload_sha256': hashlib.sha256(workload.encode()).hexdigest(), 'cycles': []}


def save():
    (args.evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')


for number in range(1, args.cycles + 1):
    out = args.evidence / f'cycle-{number:03d}'
    out.mkdir()
    state = pathlib.Path(tempfile.mkdtemp(prefix='pfs-kernel-cycle-', dir='/tmp'))
    events = queue.Queue()
    started = time.monotonic()
    record = {'cycle': number, 'passed': False, 'kernel_diagnostics': []}
    process = None
    pressure = MemoryPressureRecorder(out / 'host-memory-pressure.jsonl', state / 'data.ext4')
    try:
        with (out / 'owner.stderr').open('w') as stderr, (out / 'events.jsonl').open('w') as transcript:
            process = subprocess.Popen([str(args.binary.resolve()), str(args.image.resolve()), str(state)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1)

            def read():
                for line in process.stdout:
                    transcript.write(line); transcript.flush()
                    events.put(json.loads(line))
                events.put({'event': 'eof', 'returncode': process.wait()})

            reader = threading.Thread(target=read)
            reader.start()

            def wait(expected, seconds):
                deadline = time.monotonic() + seconds
                while True:
                    event = events.get(timeout=max(.01, deadline - time.monotonic()))
                    if event['event'] == expected:
                        return event
                    assert event['event'] not in ('failure', 'eof'), event

            ready = wait('ready', 180)
            pressure.sample('ready')
            ssh = ['/usr/bin/ssh', '-F', ready['ssh_config'], 'portablefs-workspace']
            actual = subprocess.check_output([*ssh, 'uname -r'], text=True, timeout=30).strip()
            assert actual == kernel, (actual, kernel)
            with (out / 'workload.log').open('w') as log:
                run = subprocess.run([*ssh, 'bash -s'], input=workload, text=True,
                                     stdout=log, stderr=subprocess.STDOUT, timeout=180)
            assert run.returncode == 0, ('workload failed', run.returncode)
            record['workload_completed'] = True
            pressure.sample('stop-request')
            process.stdin.write('{"command":"stop"}\n'); process.stdin.flush()
            stopped = wait('stopped', 30)
            record['operations'] = stopped['operations']
            assert stopped['operations'][-1] == 'shutdown-completed', stopped
            assert 'stop-request' not in stopped['operations'], stopped
            assert process.wait(timeout=10) == 0
            reader.join(timeout=10)
            assert not reader.is_alive()
            record['passed'] = True
    except BaseException as error:
        record['failure'] = repr(error)
        raise
    finally:
        # Cleanup never turns a failed cycle into a success or retries it.
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        pressure.close()
        serial = state / 'serial.log'
        if serial.exists():
            shutil.copyfile(serial, out / 'serial.log')
            if not 0 < serial.stat().st_size < 8 * 1024 * 1024:
                record['passed'] = False
                record['failure'] = 'missing or truncated serial evidence'
            for line in ansi.sub('', serial.read_text(errors='replace')).splitlines():
                match = kernel_line.match(line)
                # systemd emits userspace service names inside timestamped lines.
                if match and not re.match(r'(?:systemd|systemd-[\w-]+)\[\d+\]:', match[1]) and diagnostic.search(match[1]):
                    record['kernel_diagnostics'].append(line)
            if record['kernel_diagnostics']:
                record['passed'] = False
        else:
            record['passed'] = False
            record['failure'] = 'missing serial evidence'
        record['seconds'] = round(time.monotonic() - started, 3)
        results['cycles'].append(record)
        save()
        shutil.rmtree(state)
    assert record['passed'], record
    print(f'PASS: cycle {number}/{args.cycles}, orderly shutdown, zero kernel diagnostics', flush=True)
print(f'PASS: {args.cycles} serial boot/workload/orderly-stop cycles', flush=True)
