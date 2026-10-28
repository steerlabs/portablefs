"""The stock native guest owner shared by full and focused qualification."""
import json
import queue
import shutil
import signal
import subprocess
import threading
import time
from linux_workspace_native_hold import hold_between_cases
from linux_workspace_native_pressure import MemoryPressureRecorder


def native_guest_class(binary, image, root, state, events, measurements):
    class Guest:
        def __init__(self):
            hold_between_cases(restart_on_release=True)
            self.lines = queue.Queue()
            self.history = []
            self.stderr = (root / ('owner-' + str(len(measurements)) + '.stderr')).open('w')
            self.p = subprocess.Popen([binary, image, str(state)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.stderr, text=True, bufsize=1)
            self.pressure = MemoryPressureRecorder(root / 'host-memory-pressure.jsonl', state / 'data.ext4')

            def read():
                for line in self.p.stdout:
                    assert events.tell() + len(line) <= 8*1024*1024, 'event log bound exceeded'
                    events.write(line); events.flush()
                    self.lines.put(json.loads(line))
                self.lines.put({'event': 'eof', 'returncode': self.p.wait()})

            threading.Thread(target=read, daemon=True).start()
            try:
                self.starting = self.wait('starting')
                self.ready = self.wait('ready')
                self.pressure.sample('start')
            except BaseException:
                self.cleanup()
                raise
            measurements.append({'boot_ns': self.ready['boot_ns'], 'pid': self.starting['pid']})

        def wait(self, expected, timeout=180):
            deadline = time.monotonic() + timeout
            while True:
                value = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
                self.history.append(value)
                if value['event'] in (expected if isinstance(expected, tuple) else (expected,)):
                    return value
                if value['event'] in ('failure', 'eof'):
                    raise RuntimeError(value)

        def command(self, name, **fields):
            self.p.stdin.write(json.dumps({'command': name, **fields}) + '\n'); self.p.stdin.flush()

        def discard(self):
            hold_between_cases()
            self.pressure.sample('end')
            self.command('discard')
            value = self.wait('stopped', 30)
            assert value['operations'][-1] == 'stop-completed', value
            assert self.p.wait(timeout=10) == 0
            self.stderr.close()
            self.finish()

        def ssh(self, command):
            result = subprocess.run(['/usr/bin/ssh', '-F', self.ready['ssh_config'], 'portablefs-workspace', command],
                                    text=True, capture_output=True, timeout=30)
            assert result.returncode == 0, (command, result.returncode, result.stderr, result.stdout)
            return result.stdout.strip()

        def stop(self, interrupt=False):
            hold_between_cases()
            self.pressure.sample('end')
            self.ssh('sync')
            if interrupt: self.p.send_signal(signal.SIGINT)
            else: self.command('stop')
            value = self.wait('stopped', 30)
            assert value['operations'][-1] == 'shutdown-completed'
            assert self.p.wait(timeout=10) == 0
            self.stderr.close()
            self.finish()

        def finish(self):
            self.pressure.close()
            if (state / 'serial.log').exists():
                shutil.copyfile(state / 'serial.log', root / ('guest-%d-serial.log' % self.p.pid))

        def cleanup(self):
            try:
                if self.p.poll() is None:
                    try: self.command('stop')
                    except (BrokenPipeError, ValueError): pass
                    try: self.p.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        self.p.terminate()
                        try: self.p.wait(timeout=30)
                        except subprocess.TimeoutExpired: self.p.kill(); self.p.wait(timeout=10)
            finally:
                self.finish()
                self.stderr.close()

    return Guest
