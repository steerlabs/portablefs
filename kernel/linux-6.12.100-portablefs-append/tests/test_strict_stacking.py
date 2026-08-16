#!/usr/bin/env python3
"""Optional live proof that strict FUSE cannot be stacked.

Set PFS_STRICT_STACK_TEST_DIR to an explicitly disposable directory on a
mounted strict PortableFS instance.  The test creates only temporary children
beneath that directory and /tmp.
"""

from __future__ import annotations

import ctypes
import errno
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


STRICT_ROOT = os.environ.get("PFS_STRICT_STACK_TEST_DIR")
LIVE_ENABLED = bool(STRICT_ROOT) and sys.platform.startswith("linux")
TARGET_KERNEL_PREFIX = "6.12.100"
MNT_DETACH = 2
MS_NOSUID = 2
MS_NODEV = 4
AT_FDCWD = -100
CAP_SYS_ADMIN = 21


def has_effective_capability(capability: int) -> bool:
    with open("/proc/self/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) & (1 << capability))
    return False


class FileHandle(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint),
        ("handle_type", ctypes.c_int),
        ("f_handle", ctypes.c_ubyte * 128),
    ]


def target_kernel(release: str) -> bool:
    return release == TARGET_KERNEL_PREFIX or release.startswith(
        (TARGET_KERNEL_PREFIX + "-", TARGET_KERNEL_PREFIX + "+")
    )


@unittest.skipUnless(
    LIVE_ENABLED,
    "set PFS_STRICT_STACK_TEST_DIR for the privileged live stacking test",
)
class StrictStackingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not has_effective_capability(CAP_SYS_ADMIN):
            raise RuntimeError(
                "live stacking qualification requires effective CAP_SYS_ADMIN"
            )
        if not target_kernel(os.uname().release):
            raise RuntimeError("live stacking qualification requires 6.12.100")
        assert STRICT_ROOT is not None
        cls.strict_root = pathlib.Path(STRICT_ROOT).resolve(strict=True)
        fs_type = subprocess.run(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", cls.strict_root],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        if not fs_type.startswith("fuse"):
            raise RuntimeError(
                f"PFS_STRICT_STACK_TEST_DIR is on {fs_type}, not FUSE"
            )
        if not pathlib.Path("/sys/module/overlay").exists():
            subprocess.run(["modprobe", "overlay"], check=True)
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.libc.mount.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_char_p,
        )
        cls.libc.mount.restype = ctypes.c_int
        cls.libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
        cls.libc.umount2.restype = ctypes.c_int
        cls.libc.name_to_handle_at.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(FileHandle),
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
        )
        cls.libc.name_to_handle_at.restype = ctypes.c_int

        # Prove that this namespace and capability set can mount overlayfs at
        # all.  A later EINVAL on the strict superblock is meaningful only when
        # an ordinary local lower succeeds through this exact libc path.
        with tempfile.TemporaryDirectory(prefix="pfs-overlay-control-") as root:
            root_path = pathlib.Path(root)
            lower_a = root_path / "lower-a"
            lower_b = root_path / "lower-b"
            target = root_path / "target"
            lower_a.mkdir()
            lower_b.mkdir()
            target.mkdir()
            result = cls.libc.mount(
                b"overlay",
                os.fsencode(target),
                b"overlay",
                0,
                os.fsencode(f"lowerdir={lower_a}:{lower_b}"),
            )
            if result:
                value = ctypes.get_errno()
                raise RuntimeError(
                    f"local overlay positive control: {os.strerror(value)}"
                )
            cls.libc.umount2(os.fsencode(target), MNT_DETACH)

    def assert_overlay_refused(self, target: pathlib.Path, options: str) -> None:
        result = self.libc.mount(
            b"overlay",
            os.fsencode(target),
            b"overlay",
            0,
            os.fsencode(options),
        )
        if result == 0:
            self.libc.umount2(os.fsencode(target), MNT_DETACH)
            self.fail("overlay unexpectedly stacked above strict FUSE")
        # overlayfs returns EINVAL specifically when the computed stack depth
        # exceeds FILESYSTEM_MAX_STACK_DEPTH.  The successful local positive
        # control above rules out missing privilege/module support.
        self.assertEqual(ctypes.get_errno(), errno.EINVAL)

    def assert_export_handle_refused(self, target: pathlib.Path) -> None:
        handle = FileHandle(handle_bytes=128)
        mount_id = ctypes.c_int()
        result = self.libc.name_to_handle_at(
            AT_FDCWD,
            os.fsencode(target),
            ctypes.byref(handle),
            ctypes.byref(mount_id),
            0,
        )
        self.assertEqual(result, -1)
        self.assertEqual(ctypes.get_errno(), errno.EOPNOTSUPP)

    def test_delayed_init_never_exposes_a_stackable_fuse_superblock(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pfs-init-delay-") as root:
            root_path = pathlib.Path(root)
            fuse_target = root_path / "fuse"
            local_lower = root_path / "local-lower"
            overlay_target = root_path / "overlay"
            fuse_target.mkdir()
            local_lower.mkdir()
            overlay_target.mkdir()
            fuse_fd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
            mounted = False
            try:
                options = (
                    f"fd={fuse_fd},rootmode=40000,user_id={os.getuid()},"
                    f"group_id={os.getgid()},default_permissions"
                )
                result = self.libc.mount(
                    b"pfs-init-delay",
                    os.fsencode(fuse_target),
                    b"fuse",
                    MS_NOSUID | MS_NODEV,
                    os.fsencode(options),
                )
                if result:
                    value = ctypes.get_errno()
                    self.fail(f"raw delayed-INIT FUSE mount: {os.strerror(value)}")
                mounted = True
                # Deliberately do not read or answer FUSE_INIT.
                self.assert_export_handle_refused(fuse_target)
                self.assert_overlay_refused(
                    overlay_target, f"lowerdir={fuse_target}:{local_lower}"
                )
            finally:
                if mounted:
                    self.libc.umount2(os.fsencode(fuse_target), MNT_DETACH)
                os.close(fuse_fd)

    def test_strict_mount_is_refused_as_overlay_lower(self) -> None:
        self.assert_export_handle_refused(self.strict_root)
        with tempfile.TemporaryDirectory(prefix="pfs-stack-local-") as root:
            local_lower = pathlib.Path(root, "local-lower")
            target = pathlib.Path(root, "merged")
            local_lower.mkdir()
            target.mkdir()
            self.assert_overlay_refused(
                target, f"lowerdir={self.strict_root}:{local_lower}"
            )

    def test_strict_mount_is_refused_as_overlay_upper(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="pfs-stack-shared-", dir=self.strict_root
        ) as shared, tempfile.TemporaryDirectory(
            prefix="pfs-stack-local-"
        ) as local:
            shared_root = pathlib.Path(shared)
            upper = shared_root / "upper"
            work = shared_root / "work"
            lower = pathlib.Path(local, "lower")
            target = pathlib.Path(local, "merged")
            for directory in (upper, work, lower, target):
                directory.mkdir()
            self.assert_overlay_refused(
                target,
                f"lowerdir={lower},upperdir={upper},workdir={work}",
            )

    def test_shared_file_is_refused_as_read_only_loop_backing(self) -> None:
        if not pathlib.Path("/sys/module/loop").exists():
            subprocess.run(["modprobe", "loop"], check=True)
        with tempfile.TemporaryDirectory(
            prefix="pfs-loop-shared-", dir=self.strict_root
        ) as shared, tempfile.TemporaryDirectory(
            prefix="pfs-loop-local-"
        ) as local:
            shared_file = pathlib.Path(shared, "backing")
            local_file = pathlib.Path(local, "backing")
            shared_file.write_bytes(b"S" * 4096)
            local_file.write_bytes(b"L" * 4096)

            before = subprocess.run(
                ["losetup", "--list", "--noheadings", "--output", "BACK-FILE"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout
            refused = subprocess.run(
                ["losetup", "--find", "--show", "--read-only", shared_file],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(refused.returncode, 0)
            after = subprocess.run(
                ["losetup", "--list", "--noheadings", "--output", "BACK-FILE"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout
            self.assertEqual(after, before)

            # LOCAL regular files retain normal loop functionality.
            accepted = subprocess.run(
                ["losetup", "--find", "--show", "--read-only", local_file],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            try:
                self.assertTrue(accepted.startswith("/dev/loop"))
            finally:
                subprocess.run(["losetup", "--detach", accepted], check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
