#!/usr/bin/env python3
"""Offline probe mechanics only; never a native FSKit qualification result."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load("writeback", "test-macos27-writeback.py")
small = load("small_writes", "diagnose-small-writes.py")


class WriteBackProbeTests(unittest.TestCase):
    def test_worker_records_native_geometry_dirty_acceptance_and_separate_barriers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "file"
            fixture.write_bytes(b"A" * native.SIZE)
            artifact = root / "events"
            with artifact.open("w") as output:
                process = subprocess.Popen([sys.executable, native.__file__, "--worker", str(fixture)],
                                           stdin=subprocess.PIPE, stdout=output, text=True)
                try:
                    ready = native.await_event(artifact, "ready")
                    self.assertEqual(ready["offsets"], [0, native.PAGE_SIZE])
                    self.assertGreater(ready["size"], 2 * 1024 * 1024)
                    for command in ("dirty", "fsync", "reopen-fsync"):
                        native.command(process, command)
                        result = native.await_event(artifact, command + "-finished")
                        self.assertTrue(result["success"], result)
                    native.command(process, "stop")
                    process.wait(timeout=5)
                    self.assertEqual(fixture.read_bytes(), b"B" * native.SIZE)
                    rows = native.events(artifact)
                    self.assertLess(next(r["monotonic_ns"] for r in rows if r["event"] == "dirty-finished"),
                                    next(r["monotonic_ns"] for r in rows if r["event"] == "fsync-started"))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    process.stdin.close()

    def test_missing_operator_evidence_is_open(self):
        artifact = io.StringIO()
        with patch("builtins.input", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "OPEN"):
                native.checkpoint(artifact, "held callback")
        self.assertEqual(json.loads(artifact.getvalue())["evidence"], "")

    def test_diagnostic_exact_loops_have_only_final_fsync_and_close(self):
        for name, count, size, flags in small.WORKLOADS:
            for drain in ("fsync", "close"):
                calls = []
                actual = {"length": 0, "sha256": "independent"}
                with patch.object(small.os, "open", return_value=10), \
                     patch.object(small.os, "fstat") as stat, \
                     patch.object(small.os, "write", side_effect=lambda fd, data: (calls.append(("write", len(data))) or len(data))), \
                     patch.object(small.os, "fsync", side_effect=lambda fd: calls.append(("fsync", 0))), \
                     patch.object(small.os, "close", side_effect=lambda fd: calls.append(("close", 0))), \
                     patch.object(small, "inspect_file", return_value=actual):
                    stat.return_value.st_size = 0
                    result = small.run_file(Path("fixture"), Path("independent"), name, count, size, flags, drain)
                self.assertEqual(calls[:count], [("write", size)] * count)
                self.assertEqual(calls[count:], [("fsync", 0), ("close", 0)] if drain == "fsync" else [("close", 0)])
                self.assertEqual(result["expected"]["length"], 1_000_000 if name == "append" else 64 * 1024 * 1024)
                self.assertEqual(result["writes_completed"], count)
                self.assertFalse(result["verified"])  # no retry or invented authority match
                self.assertEqual(result["authority"], actual)
                self.assertGreaterEqual(result["write_and_drain_ns"], result["loop_ns"])

    def test_diagnostic_short_write_is_preserved(self):
        with patch.object(small.os, "open", return_value=10), patch.object(small.os, "fstat") as stat, \
             patch.object(small.os, "write", return_value=99), patch.object(small.os, "fsync"), \
             patch.object(small.os, "close"), patch.object(small, "inspect_file", return_value={}):
            stat.return_value.st_size = 0
            result = small.run_file(Path("fixture"), Path("independent"), "append", 10_000, 100, 0, "fsync")
        self.assertEqual(result["writes_completed"], 0)
        self.assertEqual(result["failure"]["phase"], "write")
        self.assertFalse(result["verified"])


if __name__ == "__main__":
    unittest.main()
