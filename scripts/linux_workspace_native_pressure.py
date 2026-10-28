"""Bounded, read-only host/owned-VM memory evidence; never induces pressure."""
import datetime
import json
import pathlib
import re
import subprocess
import threading
import time


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or str(result.returncode))
    return result.stdout


def vm_statistics(text):
    page_size = int(re.search(r'page size of (\d+) bytes', text)[1])
    pages = {name: int(value) for name, value in re.findall(r'^([^:\n]+):\s+(\d+)\.', text, re.M)}
    return {'page_size': page_size,
            'compressor_stored_bytes': pages['Pages stored in compressor'] * page_size,
            'compressor_occupied_bytes': pages['Pages occupied by compressor'] * page_size,
            'compressions': pages['Compressions'], 'decompressions': pages['Decompressions'],
            'swapins': pages['Swapins'], 'swapouts': pages['Swapouts']}


def footprint_statistics(text):
    # footprint's Swapped column includes compressed memory. Keep the raw
    # output: this is not a claim to distinguish disk swap from compression.
    total = re.search(r'^\s*(\d+) B\s+(\d+) B\s+.*\bTOTAL\s*$', text, re.M)
    physical = re.search(r'^\s*phys_footprint:\s*(\d+) B', text, re.M)
    if total is None or physical is None:
        raise ValueError('missing footprint byte totals')
    return {'resident_dirty_bytes': int(total[1]), 'compressed_swapped_bytes': int(total[2]),
            'phys_footprint_bytes': int(physical[1])}


class MemoryPressureRecorder:
    def __init__(self, evidence, reference):
        self.path = pathlib.Path(evidence)
        self.reference = pathlib.Path(reference).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.finished = threading.Event()
        self.lock = threading.Lock()
        self.worker = None
        self.sample('harness-start')
        self.thread = threading.Thread(target=self.run, name='workspace-pressure', daemon=True)
        self.thread.start()

    def run(self):
        while not self.finished.wait(60):
            self.sample('interval')

    def sample(self, phase):
        with self.lock:
            started = time.monotonic()
            record = {'phase': phase, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'monotonic_seconds': started, 'reference': str(self.reference)}
            for name, args in (
                    ('vm_stat', ['/usr/bin/vm_stat']),
                    ('pressure', ['/usr/sbin/sysctl', 'kern.memorystatus_level', 'kern.memorystatus_vm_pressure_level']),
                    ('swap', ['/usr/sbin/sysctl', 'vm.swapusage'])):
                try:
                    record[name] = command(*args)
                    if name == 'vm_stat': record.update(vm_statistics(record[name]))
                except Exception as error:
                    record[name + '_error'] = str(error)
            try:
                # XPC workers belong to launchd. Bind the PID by an exact open
                # disk/lock path, never by process-name or process ancestry alone.
                if self.worker is None:
                    rows = command('/bin/ps', '-Ao', 'pid=,comm=').splitlines()
                    matches = []
                    for row in rows:
                        if not row.endswith('/com.apple.Virtualization.VirtualMachine'): continue
                        pid = int(row.split(None, 1)[0])
                        observed = subprocess.run(['/usr/sbin/lsof', '-a', '-p', str(pid), '-Fn', '--', str(self.reference)],
                                                  capture_output=True, text=True, timeout=10)
                        if 'n' + str(self.reference) in observed.stdout.splitlines(): matches.append(pid)
                    if len(matches) != 1: raise RuntimeError('owned VM worker matches: ' + str(matches))
                    self.worker = matches[0]
                # Revalidate the identity on every sample; PIDs can be reused
                # after a panic or an orderly stop.
                observed = command('/usr/sbin/lsof', '-a', '-p', str(self.worker), '-Fn', '--', str(self.reference))
                if 'n' + str(self.reference) not in observed.splitlines(): raise RuntimeError('VM reference closed')
                record['vm_pid'] = self.worker
                record['footprint'] = command('/usr/bin/footprint', '-p', str(self.worker), '--swapped', '-f', 'bytes')
                record['vm'] = footprint_statistics(record['footprint'])
            except Exception as error:
                record['vm_error'] = str(error)
                self.worker = None
            record['sample_seconds'] = time.monotonic() - started
            with self.path.open('a') as output:
                output.write(json.dumps(record, sort_keys=True) + '\n')

    def close(self):
        if self.finished.is_set(): return
        self.finished.set()
        self.thread.join(timeout=60)
        assert not self.thread.is_alive(), 'memory pressure sampler did not stop'
        self.sample('harness-end')
