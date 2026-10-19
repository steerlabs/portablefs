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

def load_observer():
    spec = importlib.util.spec_from_file_location("kernel_cache_observer", Path(__file__).with_name("test-macos27-kernel-cache.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


observer = load_observer()


class FlushedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushed = ""

    def flush(self):
        self.flushed = self.getvalue()


class ObserverTests(unittest.TestCase):
    def test_native_page_geometry_and_mapping_extent(self):
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size), patch.object(observer.mmap, "PAGESIZE", page_size):
                runtime = load_observer()
                extent = 2 * page_size
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "fixture"
                    path.write_bytes(b"A" * page_size + b"B" * page_size)
                    for mode in ("fd", "mapped"):
                        with self.subTest(mode=mode):
                            output = io.StringIO()
                            with patch.object(runtime.sys, "stdout", output), patch.object(runtime.sys, "stdin", io.StringIO("geometry\nstop\n")), patch.object(runtime.selectors, "DefaultSelector"), patch.object(runtime.mmap, "mmap", wraps=runtime.mmap.mmap) as mapping:
                                runtime.reader(path, mode)
                            records = [json.loads(line) for line in output.getvalue().splitlines()]
                            ready = records[0]
                            self.assertTrue(all(record["page_size"] == page_size for record in records))
                            self.assertEqual(ready["offsets"], [0, page_size])
                            self.assertEqual(ready["fixture_size"], extent)
                            reads = [record for record in records if record.get("operation") == "read"]
                            offsets = [record["offset"] for record in reads]
                            self.assertEqual(offsets, [0, page_size])
                            self.assertEqual([offset // page_size for offset in offsets], [0, 1])
                            self.assertEqual([record["bytes"] for record in reads], [[65], [66]])
                            self.assertGreaterEqual(ready["fixture_size"], offsets[1] + page_size)
                            if mode == "mapped":
                                mapping.assert_called_once_with(unittest.mock.ANY, extent, access=runtime.mmap.ACCESS_READ)
                                self.assertEqual(ready["mapping_length"], extent)
                                self.assertGreaterEqual(ready["mapping_length"], offsets[1] + page_size)
                            else:
                                mapping.assert_not_called()
                                self.assertEqual(ready["mapping_length"], 0)

    def test_healthy_write_truncate_regrow_and_metadata_geometry(self):
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size), patch.object(observer.mmap, "PAGESIZE", page_size):
                runtime = load_observer()
                extent = 2 * page_size
                snapshots = {
                    "warm": b"A" * extent,
                    "local-alias-write-expect-66": b"B" * extent,
                    f"alias-truncate-expect-66-0-size{extent}": b"B" * page_size + b"\0" * page_size,
                    "rewarm-expect-65": b"A" * extent,
                }
                sampled = []
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "fixture"
                    alias = Path(directory) / "alias"
                    path.write_bytes(snapshots["warm"])
                    runtime.os.link(path, alias)
                    with alias.open("rb", buffering=0) as file, runtime.mmap.mmap(file.fileno(), extent, access=runtime.mmap.ACCESS_READ) as mapping:
                        def sample(_, label, evidence, expected):
                            sampled.append(label)
                            self.assertEqual(path.read_bytes(), snapshots[label])
                            self.assertEqual(len(mapping), extent)
                            for mode, retained_mapping in (("fd", None), ("mapped", mapping)):
                                output = io.StringIO()
                                with patch.object(runtime.sys, "stdout", output):
                                    runtime.observe(file.fileno(), retained_mapping, label, mode)
                                runtime.collect([(mode, None, io.StringIO(output.getvalue()))], label, evidence, expected)

                        with patch.object(runtime, "sample", side_effect=sample):
                            runtime.healthy_probes(path, alias, [], io.StringIO())
                    self.assertEqual(sampled, list(snapshots))

    def test_loss_instructions_cover_both_native_pages(self):
        for page_size in (4096, 16384):
            with patch.object(observer.mmap, "PAGESIZE", page_size):
                runtime = load_observer()
            for case in runtime.CASES:
                with self.subTest(page_size=page_size, case=case):
                    actions = self.procedure(case, runtime)
                    mutation = next(action for action in actions if "IN PLACE" in action)
                    self.assertIn(f"from offset 0 with {2 * page_size} bytes of 76", mutation)
                    self.assertIn(f"two {page_size}-byte Mac VM pages", mutation)
                    self.assertIn(f"offsets (0, {page_size})", mutation)
                    self.assertIn("fsync and preserve its inode", mutation)
                    if case == "proof-expiry":
                        trace = next(action for action in actions if "POST-EXPIRY fixture READ/miss" in action)
                        self.assertIn(f"[0, {page_size}) and [{page_size}, {2 * page_size})", trace)
                        self.assertIn("two requests are not required", trace)

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

    def procedure(self, case, runtime=observer):
        actions = []
        with patch.object(runtime, "checkpoint", side_effect=lambda label, _: actions.append(label)), patch.object(runtime, "sample", side_effect=lambda _, label, __: actions.append("sample:" + label)), patch.object(runtime, "command", side_effect=lambda _, label: actions.append("command:" + label)), patch.object(runtime, "collect"):
            runtime.loss_procedure(case, "fixture", [], io.StringIO())
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
