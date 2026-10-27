"""Pure host units for proof selection; these execute no ptrace or VM operation."""
import ctypes
import errno
import importlib.util
import pathlib
import signal
import struct
import tempfile
import types
import unittest
from unittest import mock

path = pathlib.Path(__file__).with_name('linux_workspace_rtc_inject.py')
spec = importlib.util.spec_from_file_location('rtc_inject_fixture', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProofSelection(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        arm = pathlib.Path(self.directory.name) / 'arm'
        arm.touch()
        self.trace = object.__new__(module.Trace)
        self.trace.o = types.SimpleNamespace(pid=17, start='1', fd=8, count=1, arm=str(arm), errno='EINTR', delay_return=0)
        self.trace.tasks, self.trace.stopped, self.trace.inflight = set(), set(), {}
        self.trace.pending_signals = {}
        self.trace.events = []
        self.trace.injected, self.trace.real_samples, self.trace.after_injected_boot_ns = 0, 0, 0
        self.trace.record = lambda kind, **data: self.trace.events.append(dict(event=kind, **data))
        self.trace.validate = lambda: None
        self.skipped, self.resumed = [], []
        self.trace.skip = self.skipped.append
        self.trace.resume = lambda tid, forwarded=0: self.resumed.append((tid, forwarded))
        self.trace.sample = lambda tid, address: dict(second=17)
        self.registers = (ctypes.c_uint64 * 34)()
        self.vector = module.IOVec(ctypes.addressof(self.registers), ctypes.sizeof(self.registers))
        self.trace.registers = lambda tid: (self.registers, self.vector)
        self.info = bytes(88)
        self.calls = []
        def call(request, tid, addr=0, data=0):
            self.calls.append(request)
            if request == module.GET_INFO:
                ctypes.memmove(data, self.info, len(self.info))
                return len(self.info)
            if request == module.SET_REGSET:
                return 0
            self.fail(('unexpected operation', request))
        self.trace.call = call
        self.clock = 50
        module.boot_ns = lambda: self.clock

    def stop(self, number=signal.SIGTRAP | 0x80):
        return (number << 8) | 0x7f

    def entry(self, number=module.SYS_IOCTL, fd=8, request=module.RTC_RD_TIME):
        self.info = struct.pack('<B3xIQQ7Q', 1, 0xc00000b7, 0, 0, number, fd, request, 1234, 0, 0, 0)

    def exit(self, result):
        self.info = struct.pack('<B3xIQQqB', 2, 0xc00000b7, 0, 0, result, int(result < 0))

    def test_arm64_skip_initializes_its_preserved_return_register(self):
        calls=[]
        def call(request,tid,addr=0,data=0):
            self.assertEqual(request,module.SET_REGSET)
            vector=ctypes.cast(data,ctypes.POINTER(module.IOVec))[0]
            if addr==module.NT_ARM_SYSTEM_CALL:
                value=ctypes.cast(vector.base,ctypes.POINTER(ctypes.c_int))[0]
                self.assertEqual(value,-1)
            else:
                self.assertEqual(addr,module.NT_PRSTATUS)
                self.assertEqual(ctypes.c_int64(self.registers[0]).value,-errno.ENOSYS)
            calls.append(addr)
            return 0
        self.trace.call=call
        module.Trace.skip(self.trace,17)
        self.assertEqual(calls,[module.NT_ARM_SYSTEM_CALL,module.NT_PRSTATUS])

    def test_only_selected_ioctl_can_be_skipped(self):
        for number, fd, request in [(0,8,module.RTC_RD_TIME),(module.SYS_IOCTL,9,module.RTC_RD_TIME),
                                    (module.SYS_IOCTL,8,0)]:
            self.entry(number, fd, request)
            self.assertFalse(self.trace.handle(17, self.stop()))
        self.assertFalse(self.skipped)
        self.assertFalse(self.trace.inflight)
        self.entry()
        self.assertFalse(self.trace.handle(17, self.stop()))
        self.assertEqual(self.skipped, [17])

    def test_concurrent_entries_reserve_the_finite_burst(self):
        self.entry()
        self.trace.handle(17, self.stop())
        self.trace.handle(18, self.stop())
        self.assertEqual(self.skipped, [17])
        self.assertIs(self.trace.inflight[17][1], True)
        self.assertIs(self.trace.inflight[18][1], False)

    def test_injected_return_changes_only_registers(self):
        for failure in ['EINTR','EIO']:
            self.trace.o.errno = failure
            self.trace.injected = 0
            self.entry()
            self.trace.handle(17, self.stop())
            self.exit(-errno.ENOSYS)
            self.assertFalse(self.trace.handle(17, self.stop()))
            event = self.trace.events[-1]
            self.assertEqual(event['event'], 'injected-return')
            self.assertEqual(event['actual_return'], -getattr(errno,failure))
            self.assertIs(event['wrote_buffer'], False)
            self.assertEqual(self.trace.injected, 1)
            self.assertEqual(self.trace.after_injected_boot_ns, 50)
        self.assertNotIn(module.PEEK_DATA, self.calls)

    def test_inflight_pre_interruption_sample_cannot_complete_proof(self):
        self.trace.injected = 1
        self.trace.after_injected_boot_ns = 50
        self.trace.inflight[17] = (1234,False,49)
        self.exit(0)
        self.assertFalse(self.trace.handle(17, self.stop()))
        self.assertEqual(self.resumed[-1], (17,0))
        self.trace.inflight[17] = (1234,False,51)
        self.assertTrue(self.trace.handle(17, self.stop()))
        self.assertEqual(self.trace.events[-1]['entry_boot_ns'], 51)

    def test_preemption_signal_is_forwarded(self):
        self.assertFalse(self.trace.handle(17, self.stop(signal.SIGURG)))
        self.assertEqual(self.resumed, [(17,signal.SIGURG)])
        self.assertFalse(self.calls)

    def test_detach_forwards_a_pending_real_signal(self):
        self.trace.tasks = {17}
        calls = []
        self.trace.call = lambda request,tid,addr=0,data=0: calls.append((request,tid,addr,data)) or 0
        with mock.patch.object(module.os, 'waitpid', return_value=(17,self.stop(signal.SIGURG))):
            self.trace.detach()
        self.assertEqual(calls, [(module.INTERRUPT,17,0,0),(module.DETACH,17,0,signal.SIGURG)])
        self.assertFalse(self.trace.tasks)

    def test_detach_includes_a_concurrent_clone(self):
        self.trace.tasks = {17}
        calls = []
        def call(request,tid,addr=0,data=0):
            calls.append((request,tid,addr,data if request!=module.GET_EVENT else None))
            if request==module.GET_EVENT:
                ctypes.cast(data,ctypes.POINTER(ctypes.c_ulong))[0]=18
            return 0
        self.trace.call=call
        stops=[(17,self.stop(signal.SIGTRAP)|(3<<16)),(18,self.stop(signal.SIGTRAP)|(128<<16))]
        with mock.patch.object(module.os,'waitpid',side_effect=stops):
            self.trace.detach()
        self.assertFalse(self.trace.tasks)
        self.assertEqual(sorted(tid for request,tid,_,_ in calls if request==module.DETACH),[17,18])

    def test_sample_reads_only_the_calendar_buffer(self):
        raw=struct.pack('<9i',*range(9))
        addresses=[]
        def peek(request,tid,address):
            self.assertEqual(request,module.PEEK_DATA)
            offset=address-1000
            self.assertGreaterEqual(offset,0)
            self.assertLessEqual(offset+8,len(raw))
            addresses.append(address)
            return int.from_bytes(raw[offset:offset+8],'little')
        self.trace.call=peek
        # Invoke the actual parser rather than this fixture's per-test stub.
        sample=module.Trace.sample(self.trace,17,1000)
        self.assertEqual(list(sample.values()),list(range(9)))
        self.assertEqual(addresses,[1000,1008,1016,1024,1028])


if __name__ == '__main__':
    unittest.main()
