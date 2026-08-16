#!/usr/bin/env python3
"""Optional direct-XFS oracle for the private FALLOCATE contract.

Set PFS_XFS_TEST_DIR to a disposable directory on the pinned XFS volume.  The
test never runs against an inferred path and creates only a TemporaryDirectory
beneath that explicit root.
"""

from __future__ import annotations

import ctypes
import errno
import os
import resource
import signal
import subprocess
import sys
import tempfile
import unittest


KEEP = 0x01
PUNCH = 0x02
COLLAPSE = 0x08
ZERO = 0x10
INSERT = 0x20
UNSHARE = 0x40
BLOCK = 4096
TARGET_KERNEL_PREFIX = "6.12.100"

ORACLE_ROOT = os.environ.get("PFS_XFS_TEST_DIR")
ORACLE_ENABLED = bool(ORACLE_ROOT) and sys.platform.startswith("linux")
fallocate_fn = None
if ORACLE_ENABLED:
    libc = ctypes.CDLL(None, use_errno=True)
    fallocate_fn = libc.fallocate
    fallocate_fn.argtypes = (ctypes.c_int, ctypes.c_int,
                             ctypes.c_longlong, ctypes.c_longlong)
    fallocate_fn.restype = ctypes.c_int


def is_target_kernel_release(release: str) -> bool:
    return (
        release == TARGET_KERNEL_PREFIX
        or release.startswith(TARGET_KERNEL_PREFIX + "-")
        or release.startswith(TARGET_KERNEL_PREFIX + "+")
    )


class OracleAdmissionTests(unittest.TestCase):
    def test_only_exact_612100_release_family_qualifies(self) -> None:
        for release in (
            "6.12.100",
            "6.12.100-pfs-strict-kasan",
            "6.12.100+debug",
        ):
            self.assertTrue(is_target_kernel_release(release))
        for release in ("6.8.0", "6.12.99", "6.12.1000", "6.13.0"):
            self.assertFalse(is_target_kernel_release(release))


def fallocate(fd: int, mode: int, offset: int, length: int) -> None:
    assert fallocate_fn is not None
    if fallocate_fn(fd, mode, offset, length):
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


@unittest.skipUnless(
    ORACLE_ENABLED,
    "set PFS_XFS_TEST_DIR on Linux for direct XFS tests",
)
class DirectXfsFallocateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        release = os.uname().release
        if not is_target_kernel_release(release):
            raise RuntimeError(
                "direct-XFS oracle is qualifying only on Linux 6.12.100; "
                f"running kernel is {release}"
            )

    def setUp(self) -> None:
        assert ORACLE_ROOT is not None
        fs_type = subprocess.run(
            ["stat", "-f", "-c", "%T", ORACLE_ROOT],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        if fs_type != "xfs":
            self.fail(f"PFS_XFS_TEST_DIR is {fs_type}, not xfs")
        self.temp = tempfile.TemporaryDirectory(prefix="pfs-xfs-oracle-",
                                                dir=ORACLE_ROOT)
        self.path = os.path.join(self.temp.name, "range-file")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def reset(self, blocks: int = 4) -> int:
        fd = os.open(self.path, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)
        for index in range(blocks):
            os.write(fd, bytes((65 + index,)) * BLOCK)
        os.fsync(fd)
        return fd

    def test_allocate_keep_punch_zero_and_unshare_sizes(self) -> None:
        fd = self.reset(2)
        try:
            fallocate(fd, 0, 2 * BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 3 * BLOCK)
            fallocate(fd, KEEP, 4 * BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 3 * BLOCK)
            fallocate(fd, PUNCH | KEEP, 0, BLOCK)
            self.assertEqual(os.pread(fd, BLOCK, 0), b"\0" * BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 3 * BLOCK)
            fallocate(fd, ZERO | KEEP, BLOCK, BLOCK)
            self.assertEqual(os.pread(fd, BLOCK, BLOCK), b"\0" * BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 3 * BLOCK)
            fallocate(fd, UNSHARE, 4 * BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 5 * BLOCK)
            fallocate(fd, UNSHARE | KEEP, 6 * BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 5 * BLOCK)
        finally:
            os.close(fd)

    def test_collapse_and_insert_shift_exact_bytes(self) -> None:
        fd = self.reset(4)
        try:
            fallocate(fd, COLLAPSE, BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 3 * BLOCK)
            self.assertEqual(os.pread(fd, 3 * BLOCK, 0),
                             b"A" * BLOCK + b"C" * BLOCK + b"D" * BLOCK)
            fallocate(fd, INSERT, BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 4 * BLOCK)
            self.assertEqual(os.pread(fd, 4 * BLOCK, 0),
                             b"A" * BLOCK + b"\0" * BLOCK +
                             b"C" * BLOCK + b"D" * BLOCK)
        finally:
            os.close(fd)

    def test_collapse_end_at_eof_and_insert_at_eof_are_einval(self) -> None:
        fd = self.reset(2)
        try:
            cases = (
                (COLLAPSE, BLOCK, BLOCK),
                (INSERT, 2 * BLOCK, BLOCK),
            )
            for mode, offset, length in cases:
                with self.assertRaises(OSError) as caught:
                    fallocate(fd, mode, offset, length)
                self.assertEqual(caught.exception.errno, errno.EINVAL)
                self.assertEqual(os.fstat(fd).st_size, 2 * BLOCK)
        finally:
            os.close(fd)

    def test_growth_rlimit_signals_but_keep_does_not(self) -> None:
        fd = self.reset(2)
        old_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        old_handler = signal.getsignal(signal.SIGXFSZ)
        signals: list[int] = []
        signal.signal(signal.SIGXFSZ, lambda signum, _frame: signals.append(signum))
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (2 * BLOCK, old_limit[1]))
            with self.assertRaises(OSError) as caught:
                fallocate(fd, 0, 2 * BLOCK, BLOCK)
            self.assertEqual(caught.exception.errno, errno.EFBIG)
            self.assertEqual(signals, [signal.SIGXFSZ])
            fallocate(fd, KEEP, 3 * BLOCK, BLOCK)
            self.assertEqual(os.fstat(fd).st_size, 2 * BLOCK)
            self.assertEqual(signals, [signal.SIGXFSZ])
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, old_limit)
            signal.signal(signal.SIGXFSZ, old_handler)
            os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
