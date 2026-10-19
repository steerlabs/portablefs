#!/usr/bin/env python3
"""Tests of the native evidence collector; no FSKit mount or fault injection."""
import errno
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("kernel_cache_observer", Path(__file__).with_name("test-macos27-kernel-cache.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class FlushedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushed = ""

    def flush(self):
        self.flushed = self.getvalue()


class ObserverTests(unittest.TestCase):
    def test_successful_reads_survive_later_fstat_failure(self):
        output = FlushedOutput()

        def metadata(_):
            # Both completed reads must already be visible outside the process.
            reads = [json.loads(line) for line in output.flushed.splitlines()]
            self.assertEqual([record["bytes"] for record in reads], [[65], [66]])
            raise OSError(errno.ESTALE, "revoked metadata")

        with patch.object(observer.sys, "stdout", output), patch.object(observer.os, "pread", side_effect=(b"A", b"B")), patch.object(observer.os, "fstat", side_effect=metadata):
            observer.observe(123, None, "metadata-fails", "fd")
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([record["operation"] for record in records], ["read", "read", "fstat", "complete"])
        self.assertEqual(records[2]["errno"], errno.ESTALE)
        self.assertEqual(records[0]["bytes"], [65])

    def test_first_page_is_flushed_before_second_page_failure(self):
        output = FlushedOutput()

        class FaultingMapping:
            def __getitem__(mapping, region):
                if region.start == 0:
                    return b"A"
                first = json.loads(output.flushed)
                self.assertEqual((first["page"], first["bytes"]), (1, [65]))
                raise OSError(errno.EIO, "second page failed")

        with patch.object(observer.sys, "stdout", output), patch.object(observer.os, "fstat", side_effect=OSError(errno.ESTALE, "revoked")):
            observer.observe(123, FaultingMapping(), "second-page-fails", "mapped")
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(records[0]["bytes"], [65])
        self.assertEqual((records[1]["page"], records[1]["errno"]), (2, errno.EIO))
        self.assertEqual(records[2]["operation"], "fstat")

    def procedure(self, case):
        actions = []
        with patch.object(observer, "checkpoint", side_effect=lambda label, _: actions.append(label)), patch.object(observer, "sample", side_effect=lambda _, label, __: actions.append("sample:" + label)), patch.object(observer, "command", side_effect=lambda _, label: actions.append("command:" + label)), patch.object(observer, "collect"):
            observer.loss_procedure(case, "fixture", [], io.StringIO())
        return actions

    def test_stall_mutation_and_samples_precede_resume(self):
        actions = self.procedure("extension-stall")
        self.assertIn("STOP the extension", actions[0])
        self.assertIn("EBUSY", actions[1])
        self.assertIn("exclusion end", actions[2])
        self.assertIn("WHILE THE EXTENSION IS STILL STOPPED", actions[3])
        self.assertEqual(actions[4], "sample:stopped-after-linux-mutation")
        self.assertIn("RESUME", actions[5])
        self.assertIn("actual revoke completion", actions[5])
        self.assertEqual(actions[6], "sample:resumed-after-withdrawal")

    def test_sleep_observers_arm_before_sleep_and_run_through_withdrawal(self):
        actions = self.procedure("sleep-wake")
        self.assertIn("DURING MAC SLEEP", actions[0])
        self.assertEqual(actions[1], "command:arm:sleep-wake-continuous")
        self.assertIn("Sleep the Mac now", actions[2])
        self.assertIn("actual fixture revoke completion", actions[3])
        self.assertEqual(actions[4:], ["command:disarm", "sample:wake-after-withdrawal"])

    def test_proof_expiry_requires_read_evidence_before_recovery(self):
        actions = self.procedure("proof-expiry")
        self.assertIn("counters BEFORE", actions[1])
        self.assertEqual(actions[2], "sample:proof-expired")
        self.assertIn("POST-EXPIRY fixture READ/miss", actions[3])
        self.assertIn("Restore renewal", actions[4])

    @unittest.skipIf(observer.os.geteuid() == 0, "permission denial requires an unprivileged user")
    def test_local_retained_permission_description(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = io.StringIO()
            observer.retained_permissions(Path(directory), evidence)
            records = [json.loads(line) for line in evidence.getvalue().splitlines()]
            self.assertEqual(records[1]["errno"], errno.EACCES)
            self.assertEqual(records[2]["permission_probe"], "chmod-600-reopen-succeeded")


if __name__ == "__main__":
    unittest.main()
