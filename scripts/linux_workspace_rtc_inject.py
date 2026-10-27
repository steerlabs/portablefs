#!/usr/bin/env python3
"""Root-only arm64 ptrace fixture for one owned managed daemon's RTC ioctl.

This runs inside a disposable native guest. It never signals SSH or changes a
clock. A skipped RTC_RD_TIME has no device sample and no output-buffer write.
"""
import argparse
import ctypes
import errno
import json
import os
import pathlib
import platform
import signal
import struct
import time


SEIZE, INTERRUPT, SYSCALL, DETACH = 0x4206, 0x4207, 24, 17
GET_INFO, GET_REGSET, SET_REGSET, GET_EVENT = 0x420e, 0x4204, 0x4205, 0x4201
PEEK_DATA = 2
TRACESYSGOOD, TRACECLONE = 1, 8
NT_PRSTATUS, NT_ARM_SYSTEM_CALL = 1, 0x404
WALL = 0x40000000
RTC_RD_TIME, SYS_IOCTL = 0x80247009, 29


class IOVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]


def boot_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def process_start(pid):
    return pathlib.Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]


class Trace:
    def __init__(self, options):
        self.o = options
        self.libc = ctypes.CDLL('libc.so.6', use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.tasks, self.stopped, self.inflight = set(), set(), {}
        self.pending_signals = {}
        self.events = []
        self.injected = 0
        self.real_samples = 0
        self.after_injected_boot_ns = 0

    def call(self, request, tid, addr=0, data=0):
        ctypes.set_errno(0)
        result = self.libc.ptrace(request, tid, addr, data)
        failure = ctypes.get_errno()
        if result == -1 and failure:
            raise OSError(failure, os.strerror(failure))
        return result

    def record(self, kind, **values):
        self.events.append(dict(event=kind, boot_ns=boot_ns(), **values))
        self.save(False)

    def save(self, passed, error=None):
        value = dict(pid=self.o.pid, start=self.o.start, descriptor=self.o.fd,
                     request=RTC_RD_TIME, injected=self.injected, events=self.events,
                     detached=not self.tasks, passed=passed)
        if error is not None:
            value['error'] = str(error)
        destination = pathlib.Path(self.o.output)
        temporary = destination.with_suffix('.tmp')
        temporary.write_text(json.dumps(value, indent=2) + '\n')
        temporary.replace(destination)

    def validate(self):
        assert process_start(self.o.pid) == self.o.start, 'target process identity changed'
        command = pathlib.Path('/proc', str(self.o.pid), 'cmdline').read_bytes().split(b'\0')
        assert command[0] == b'/usr/local/bin/portablefs', 'not the product client'
        assert ('--workspace-rtc-fd=' + str(self.o.fd)).encode() in command, 'not a managed RTC descriptor'
        assert pathlib.Path('/proc', str(self.o.pid)).stat().st_uid == 1000
        assert os.readlink('/proc/%d/fd/%d' % (self.o.pid, self.o.fd)) == '/dev/rtc0'

    def attach(self):
        self.validate()
        # Clone tracing closes the enumeration race once the first tasks are
        # seized. Auto-attached children report their own subsequent stop.
        for path in pathlib.Path('/proc', str(self.o.pid), 'task').iterdir():
            tid = int(path.name)
            try:
                self.call(SEIZE, tid, 0, TRACESYSGOOD | TRACECLONE)
            except OSError as error:
                if error.errno == errno.ESRCH:
                    continue
                status = path.joinpath('status').read_text()
                if 'TracerPid:\t%d\n' % os.getpid() not in status:
                    raise
            self.tasks.add(tid)
        for tid in list(self.tasks):
            try:
                self.call(INTERRUPT, tid)
            except OSError as error:
                if error.errno not in (errno.ESRCH, errno.EIO):
                    raise
                if error.errno == errno.ESRCH:
                    self.tasks.discard(tid)
        self.record('attached', tasks=sorted(self.tasks))

    def resume(self, tid, forwarded=0):
        self.call(SYSCALL, tid, 0, forwarded)
        self.stopped.discard(tid)

    def registers(self, tid):
        # Linux arm64 user_pt_regs: x0..x30, sp, pc, pstate.
        registers = (ctypes.c_uint64 * 34)()
        vector = IOVec(ctypes.addressof(registers), ctypes.sizeof(registers))
        self.call(GET_REGSET, tid, NT_PRSTATUS, ctypes.byref(vector))
        assert vector.length == ctypes.sizeof(registers), 'unexpected arm64 register layout'
        return registers, vector

    def skip(self, tid):
        number = ctypes.c_int(-1)
        vector = IOVec(ctypes.addressof(number), ctypes.sizeof(number))
        self.call(SET_REGSET, tid, NT_ARM_SYSTEM_CALL, ctypes.byref(vector))

    def sample(self, tid, address):
        data = bytearray()
        for offset in range(0, 32, 8):
            word = self.call(PEEK_DATA, tid, address + offset)
            data.extend((word & ((1 << 64) - 1)).to_bytes(8, 'little'))
        word = self.call(PEEK_DATA, tid, address + 28)
        data.extend((word & ((1 << 64) - 1)).to_bytes(8, 'little')[4:])
        fields = struct.unpack('<9i', data)
        return dict(zip(('second', 'minute', 'hour', 'day', 'month_zero_based',
                         'year_since_1900', 'weekday', 'yearday', 'isdst'), fields))

    def handle(self, tid, status):
        self.tasks.add(tid)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self.tasks.discard(tid)
            self.stopped.discard(tid)
            self.inflight.pop(tid, None)
            assert tid != self.o.pid, 'managed client exited while tracing'
            return False
        assert os.WIFSTOPPED(status), status
        self.stopped.add(tid)
        event, stopped_signal = status >> 16, os.WSTOPSIG(status)
        if event == 3:  # PTRACE_EVENT_CLONE
            child = ctypes.c_ulong()
            self.call(GET_EVENT, tid, 0, ctypes.byref(child))
            self.tasks.add(child.value)
        if stopped_signal != (signal.SIGTRAP | 0x80):
            # Seize/clone stops and debugger traps are not delivered as process
            # signals. Real signals retain their ordinary target disposition.
            forwarded = 0 if event else stopped_signal
            self.resume(tid, forwarded)
            return False
        raw = ctypes.create_string_buffer(88)
        size = self.call(GET_INFO, tid, ctypes.sizeof(raw), ctypes.byref(raw))
        assert size >= 24
        operation = raw.raw[0]
        if operation == 1:  # syscall entry
            number, *args = struct.unpack_from('<7Q', raw.raw, 24)
            if number == SYS_IOCTL and args[0] == self.o.fd and args[1] == RTC_RD_TIME:
                reserved = sum(value[1] for value in self.inflight.values())
                inject = self.injected + reserved < self.o.count and pathlib.Path(self.o.arm).exists()
                self.inflight[tid] = (args[2], inject, boot_ns())
                if inject:
                    self.validate()
                    self.skip(tid)
                    self.record('skip-ioctl', tid=tid, descriptor=args[0], request=args[1])
        elif operation == 2 and tid in self.inflight:  # syscall exit
            address, injected, entry_boot = self.inflight.pop(tid)
            result = struct.unpack_from('<q', raw.raw, 24)[0]
            if injected:
                assert result == -errno.ENOSYS, ('ioctl was not skipped', result)
                registers, vector = self.registers(tid)
                registers[0] = (-getattr(errno, self.o.errno)) & ((1 << 64) - 1)
                self.call(SET_REGSET, tid, NT_PRSTATUS, ctypes.byref(vector))
                actual, _ = self.registers(tid)
                assert actual[0] == registers[0], 'injected return did not install'
                self.injected += 1
                self.record('injected-return', tid=tid, errno=self.o.errno, skipped_return=result,
                            actual_return=ctypes.c_int64(actual[0]).value, wrote_buffer=False)
                if self.injected == 1 and self.o.delay_return:
                    self.record('return-held', seconds=self.o.delay_return)
                    time.sleep(self.o.delay_return)
                    self.record('return-released')
                self.after_injected_boot_ns = boot_ns()
            elif result == 0:
                self.real_samples += 1
                if self.real_samples == 1 or self.injected:
                    self.record('real-sample', tid=tid, result=result, sequence=self.real_samples,
                                entry_boot_ns=entry_boot, calendar=self.sample(tid, address))
                if self.injected == self.o.count and entry_boot > self.after_injected_boot_ns:
                    return True
            else:
                self.record('real-error', tid=tid, result=result)
        self.resume(tid)
        return False

    def run(self):
        deadline = time.monotonic() + self.o.timeout
        self.attach()
        while time.monotonic() < deadline:
            tid, status = os.waitpid(-1, os.WNOHANG | WALL)
            if tid:
                if self.handle(tid, status):
                    return
            else:
                time.sleep(.0001)
        raise TimeoutError('no real successful RTC sample after the finite injected burst')

    def detach(self):
        deadline = time.monotonic() + 10
        for tid in self.tasks - self.stopped:
            try:
                self.call(INTERRUPT, tid)
            except OSError as error:
                if error.errno not in (errno.ESRCH, errno.EIO):
                    raise
                if error.errno == errno.ESRCH:
                    self.tasks.discard(tid)
        while self.tasks - self.stopped and time.monotonic() < deadline:
            tid, status = os.waitpid(-1, os.WNOHANG | WALL)
            if not tid:
                time.sleep(.001)
            elif os.WIFSTOPPED(status):
                self.tasks.add(tid)
                self.stopped.add(tid)
                event, stopped_signal = status >> 16, os.WSTOPSIG(status)
                if event == 3:
                    child = ctypes.c_ulong()
                    self.call(GET_EVENT, tid, 0, ctypes.byref(child))
                    self.tasks.add(child.value)
                if not event and stopped_signal != (signal.SIGTRAP | 0x80):
                    self.pending_signals[tid] = stopped_signal
            else:
                self.tasks.discard(tid)
                self.stopped.discard(tid)
        assert not self.tasks - self.stopped, 'traced threads did not stop for detach'
        for tid in list(self.tasks):
            try:
                self.call(DETACH, tid, 0, self.pending_signals.pop(tid, 0))
            except OSError as error:
                if error.errno != errno.ESRCH:
                    raise
            self.tasks.discard(tid)
        self.record('detached')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--start', required=True)
    parser.add_argument('--fd', type=int, default=8)
    parser.add_argument('--errno', choices=['EINTR', 'EIO'], default='EINTR')
    parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--delay-return', type=float, default=0)
    parser.add_argument('--timeout', type=float, default=40)
    parser.add_argument('--arm', required=True)
    parser.add_argument('--output', required=True)
    options = parser.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.geteuid() == 0
    assert options.count > 0 and options.delay_return >= 0
    trace = Trace(options)
    try:
        try:
            trace.run()
        finally:
            trace.detach()
    except BaseException as error:
        trace.save(False, error)
        raise
    trace.save(True)


if __name__ == '__main__':
    main()
