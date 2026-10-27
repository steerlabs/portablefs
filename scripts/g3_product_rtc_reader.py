#!/usr/bin/env python3
"""Test-only reader in the product VM; no device reopen or clock setter.

pidfd_getfd duplicates the running service's sole read-only RTC description.
The accompanying sealed clock page supplies the exact generation at the read.
This helper is copied into the disposable guest, never into the product image.
"""
import ctypes
import errno
import fcntl
import json
import mmap
import os
import pathlib
import struct
import sys
import threading
import time
import datetime


def duplicate(pidfd, fd):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(438, pidfd, fd, 0)  # pidfd_getfd on Linux arm64/x86_64
    if result < 0:
        raise OSError(ctypes.get_errno(), 'duplicate product RTC/clock description')
    return result


def generation(page):
    for _ in range(10000):
        before = struct.unpack_from('<Q', page, 128)[0]
        value = struct.unpack_from('<Q', page, 136)[0]
        after = struct.unpack_from('<Q', page, 128)[0]
        if before == after and before % 2 == 0:
            return value
    raise RuntimeError('product generation seqlock remained busy')


def main():
    pid = int(sys.argv[1])
    pidfd = os.pidfd_open(pid)
    rtc = clock = None
    # Only this known service's descriptor links are inspected. Never open any
    # linked path or inspect service arguments, environment, keys or tokens.
    for entry in pathlib.Path('/proc', str(pid), 'fd').iterdir():
        target = os.readlink(entry)
        if target == '/dev/rtc0':
            rtc = duplicate(pidfd, int(entry.name))
        elif target.startswith('/memfd:portablefs-workspace-tls-clock'):
            clock = duplicate(pidfd, int(entry.name))
    assert rtc is not None and clock is not None, 'missing product retained descriptions'
    assert fcntl.fcntl(rtc, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    page = mmap.mmap(clock, mmap.PAGESIZE, access=mmap.ACCESS_READ)
    assert page[:13] == b'PFS-TLS-CLOCK'
    try:
        other = os.open('/dev/rtc0', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        assert error.errno == errno.EBUSY
    else:
        os.close(other)
        raise RuntimeError('product RTC unexpectedly admits a second opening')
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def read(fd):
        began = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        raw = bytearray(36)
        fcntl.ioctl(fd, 0x80247009, raw, True)  # RTC_RD_TIME, never RTC_SET_TIME
        ended = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        sec, minute, hour, day, month, year, *_ = struct.unpack('9i', raw)
        utc = datetime.datetime(year+1900, month+1, day, hour, minute, sec, tzinfo=datetime.timezone.utc)
        return utc.isoformat(), ended-began, began, ended
    print(json.dumps(dict(event='armed',vm='product',boot_id=boot,service_pid=pid,generation=generation(page))),flush=True)
    assert sys.stdin.readline().strip() == 'probe'
    g0 = generation(page)
    utc, age, began, ended = read(rtc)
    g1 = generation(page)
    print(json.dumps(dict(event='first-read',vm='product',boot_id=boot,service_pid=pid,
         generation=g0,generation_after=g1,rtc=utc,sample_age_ns=age,
         boottime_began_ns=began,boottime_ended_ns=ended,
         operation_prestarted=True,host_round_trip_after_resume=False)),flush=True)
    # Dup all eight before releasing the barrier. No readers reopen rtc0.
    barrier = threading.Barrier(8)
    samples, errors = [], []
    def reader(fd):
        try:
            barrier.wait()
            local = [read(fd)[1] for _ in range(1000)]
            samples.extend(local)
        except BaseException as error:
            errors.append(repr(error))
        finally:
            os.close(fd)
    readers = [threading.Thread(target=reader,args=(os.dup(rtc),)) for _ in range(8)]
    for thread in readers: thread.start()
    for thread in readers: thread.join()
    assert not errors and len(samples) == 8000, errors
    print(json.dumps(dict(event='contention',vm='product',boot_id=boot,service_pid=pid,
         readers=8,samples=len(samples),maximum_ns=max(samples),read_only=True,second_open_busy=True)),flush=True)


if __name__ == '__main__':
    main()
