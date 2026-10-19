#!/usr/bin/env python3
"""Offline probe mechanics only; never a native FSKit qualification result."""
import errno
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


def rows(output):
    return [json.loads(line) for line in output.getvalue().splitlines()]


def mount_proof(index, adapter="V3"):
    return {"signed_app": "app hash/log", "signed_extension": "extension hash/log",
            "signed_daemon": "daemon hash/log", "signature_evidence": "codesign log",
            "session_id": f"session-{index}", "epoch_id": f"epoch-{index}", "mount_evidence": "mount log",
            "faults_restored": True, "adapter": adapter, "adapter_evidence": "V2 trace",
            "grant_evidence": "V3 grant trace", "requested_mode": "readWriteWithCache", "granted_mode": "writeBack"}


def permission_answers(directory):
    answers = [{"grant_evidence": "CREATE grant", "description_evidence": "live CREATE read/write rights",
                "requested_mode": "readWriteWithCache", "granted_mode": "writeBack", "retained_read_description": True}]
    for name, mode in (("existing-0200", "0200"), ("existing-readable", "0600")):
        for trial in ("O_WRONLY", "O_APPEND"):
            common = {"fixture": str(directory / name), "trial": trial, "no_retained_read_description": True}
            answers.append({**common, "mode": mode, "final_close_evidence": "FSKit final close",
                            "retirement_evidence": "all descriptions released"})
            answers.append({**common, "requested_mode": "readWriteWithCache", "granted_mode": "noCache",
                            "grant_evidence": "noCache grant", "open_trace": "only write OPEN",
                            "description_evidence": "write-only ownership", "read_open_observed": False})
    return answers


class FlushedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushed = []

    def flush(self):
        self.flushed.append(self.getvalue())


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
                    for command in ("dirty", "fsync"):
                        native.command(process, command)
                        result = native.await_event(artifact, command + "-finished")
                        self.assertTrue(result["success"], result)
                    native.command(process, "reopen-fsync")
                    self.assertTrue(native.await_event(artifact, "reopen-fsync-finished")["fsync_reached"])
                    self.assertTrue(native.await_event(artifact, "reopened-fsync-finished")["success"])
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

    def reopen_records(self, close_results, open_error=None, fsync_error=None):
        output = FlushedOutput()
        with patch.object(native.os, "close", side_effect=close_results), \
             patch.object(native.os, "open", side_effect=open_error, return_value=11) as opened, \
             patch.object(native.os, "fsync", side_effect=fsync_error) as synced:
            native.reopen_fsync(10, Path("fixture"), lambda event, **fields: native.record(output, event, **fields))
        result = rows(output)
        # Every started/result record must be observable before the next syscall.
        self.assertEqual(len(output.flushed), len(result))
        for count, snapshot in enumerate(output.flushed, 1):
            self.assertEqual(len(snapshot.splitlines()), count)
        return result, opened, synced

    def test_reopened_fsync_success_then_close_failure_is_failed(self):
        result, _, synced = self.reopen_records([None, OSError(errno.EIO, "final close")])
        self.assertEqual([row["event"] for row in result], [
            "reopen-fsync-started", "old-close-started", "old-close-finished", "reopen-started", "reopen-finished",
            "reopened-fsync-started", "reopened-fsync-finished", "final-close-started", "final-close-finished",
            "reopen-fsync-finished"])
        self.assertTrue(result[6]["success"])
        self.assertFalse(result[8]["success"])
        synced.assert_called_once_with(11)
        with self.assertRaisesRegex(RuntimeError, "FAILED"):
            native.require_reopen_error(result)

    def test_initial_close_failure_leaves_fsync_proof_open(self):
        result, opened, synced = self.reopen_records([OSError(errno.EINTR, "old close")])
        self.assertFalse(result[2]["success"])
        self.assertEqual(result[2]["errno"], errno.EINTR)
        self.assertFalse(result[-1]["fsync_reached"])
        opened.assert_not_called()
        synced.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "OPEN"):
            native.require_reopen_error(result)

    def test_reopen_refusal_is_access_refusal_and_fsync_proof_stays_open(self):
        result, _, synced = self.reopen_records([None], open_error=OSError(errno.EACCES, "fenced"))
        refused = next(row for row in result if row["event"] == "reopen-finished")
        self.assertTrue(refused["access_refusal"])
        self.assertEqual(refused["errno"], errno.EACCES)
        self.assertFalse(result[-1]["fsync_reached"])
        synced.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "access refusal.*OPEN"):
            native.require_reopen_error(result)

    def test_fsync_failure_then_close_failure_preserves_both_errors(self):
        result, _, _ = self.reopen_records([None, OSError(errno.EINTR, "final close")],
                                          fsync_error=OSError(errno.ENOSPC, "fsync"))
        failures = [(row["event"], row["errno"]) for row in result if row.get("success") is False]
        self.assertEqual(failures, [("reopened-fsync-finished", errno.ENOSPC), ("final-close-finished", errno.EINTR)])
        self.assertTrue(result[-1]["fsync_reached"])
        native.require_reopen_error(result)

    def test_stalled_cleanup_cannot_hide_fsync_success(self):
        result, _, _ = self.reopen_records([None, None])
        result = result[:-2]  # final close started, but no result or sequence completion
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "events"
            artifact.write_text("".join(json.dumps(row) + "\n" for row in result))
            output = io.StringIO()
            with patch.object(native, "await_event", side_effect=RuntimeError("stalled; OPEN")):
                with self.assertRaisesRegex(RuntimeError, "FAILED"):
                    native.collect_reopen_error(artifact, output, "faulted")
            self.assertEqual(rows(output)[-1]["results"], result)

    def test_mount_preparation_requires_fault_artifact_grant_and_new_identities(self):
        variants = [({}, True), ({"faults_restored": False}, True), ({"signed_extension": ""}, True),
                    ({"signature_evidence": ""}, True), ({"grant_evidence": ""}, True),
                    ({"granted_mode": "noCache"}, True), ({"session_id": "session-0"}, True),
                    ({"epoch_id": "epoch-0"}, True), ({}, False)]
        for changes, mounted in variants:
            with self.subTest(changes=changes, mounted=mounted):
                proof = {**mount_proof(1), **changes}
                identities = [mount_proof(0)] if changes or not mounted else [mount_proof(1)]
                with patch("builtins.input", return_value=json.dumps(proof)), \
                     patch.object(native.os.path, "ismount", return_value=mounted):
                    with self.assertRaisesRegex(RuntimeError, "OPEN"):
                        native.prepare_mount(Path("/mount"), io.StringIO(), "shapes", identities)
                self.assertEqual(len(identities), 1)

    def collect_sequence(self, restore_shapes):
        output = io.StringIO()
        sequence = []
        state = {"mounted": False, "index": 0}

        def answer(prompt):
            if prompt.startswith("Prepare fresh healthy"):
                state["index"] += 1
                adapter = "V2" if "signed V2 mount" in prompt else "V3"
                shapes = "for healthy shapes." in prompt
                state["mounted"] = restore_shapes or not shapes
                sequence.append(("prepare", "shapes" if shapes else adapter))
                return json.dumps(mount_proof(state["index"], adapter))
            if any(prompt.startswith(case + ":") for case in native.LIFECYCLE):
                state["mounted"] = False
                sequence.append(("lifecycle-loss", prompt.split(":")[0]))
            return "external evidence"

        def mkdir(path, *args, **kwargs):
            self.assertTrue(state["mounted"], "filesystem operation on fenced/unmounted mount")
            sequence.append(("mkdir", "shapes" if "shapes" in path.name else "hold"))

        def held(directory, output_dir, output, hold, barrier, fault):
            if fault:
                state["mounted"] = False
                sequence.append(("fenced-unmounted", barrier))

        with patch.object(native, "HOLD_CASES", ("after-durability-before-reply",)), \
             patch.object(native, "FAULTS", ("fencing",)), \
             patch.object(native, "LIFECYCLE", ("ordinary-unmount", "writer-loss")), \
             patch("builtins.input", side_effect=answer), \
             patch.object(native.os.path, "ismount", side_effect=lambda path: state["mounted"]), \
             patch.object(native.Path, "mkdir", new=mkdir), \
             patch.object(native, "hold_proof", side_effect=held), \
             patch.object(native, "healthy_shapes") as shapes:
            if restore_shapes:
                native.collect_proofs(Path("/mount"), Path("/output"), output)
                shapes.assert_called_once()
            else:
                with self.assertRaisesRegex(RuntimeError, "OPEN"):
                    native.collect_proofs(Path("/mount"), Path("/output"), output)
                shapes.assert_not_called()
        return sequence, rows(output)

    def test_fenced_final_case_requires_preparation_before_shapes_and_lifecycle(self):
        sequence, evidence = self.collect_sequence(True)
        shape = sequence.index(("mkdir", "shapes"))
        self.assertEqual(sequence[shape - 2:shape], [("fenced-unmounted", "fullfsync"), ("prepare", "shapes")])
        for index, (event, _) in enumerate(sequence):
            if event == "lifecycle-loss":
                self.assertEqual(sequence[index + 1][0], "prepare")
        preparations = [row for row in evidence if row["event"] == "mount-preparation"]
        self.assertEqual(len(preparations), 8)  # four held cuts, shapes, two lifecycle cases, V2
        self.assertTrue(all(row["actual_mount"] and row["fresh_identities"] for row in preparations))

    def test_bare_mountpoint_after_final_fencing_never_runs_shapes(self):
        sequence, evidence = self.collect_sequence(False)
        self.assertNotIn(("mkdir", "shapes"), sequence)
        self.assertFalse(evidence[-1]["actual_mount"])

    def test_writeonly_procedure_retires_each_fixture_and_keeps_create_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = io.StringIO()
            answers = permission_answers(directory)
            opened_trials = []
            real_open = native.os.open

            def tracked_open(path, flags, *args):
                if path.name.startswith("existing-"):
                    proof = [row["proof"] for row in rows(output) if row["event"] == "proof"][-1]
                    self.assertEqual(proof["fixture"], str(path))
                    self.assertTrue(proof["no_retained_read_description"])
                    self.assertEqual(proof["retirement_evidence"], "all descriptions released")
                    self.assertEqual(proof["trial"], "O_APPEND" if flags & native.os.O_APPEND else "O_WRONLY")
                    self.assertEqual(flags & native.os.O_ACCMODE, native.os.O_WRONLY)
                    opened_trials.append((path.name, proof["trial"]))
                return real_open(path, flags, *args)

            with patch("builtins.input", side_effect=[json.dumps(answer) for answer in answers]), \
                 patch.object(native.os, "open", side_effect=tracked_open):
                native.permission_shapes(directory, output)
            self.assertEqual(opened_trials, [(name, trial) for name in ("existing-0200", "existing-readable")
                                            for trial in ("O_WRONLY", "O_APPEND")])
            proofs = [row["proof"] for row in rows(output) if row["event"] == "proof"]
            self.assertEqual(proofs, answers)
            self.assertEqual(proofs[0]["granted_mode"], "writeBack")
            self.assertTrue(all(proofs[index]["granted_mode"] == "noCache" for index in (2, 4, 6, 8)))

    def test_missing_retirement_evidence_prevents_writeonly_open(self):
        for missing in ("final_close_evidence", "retirement_evidence", "no_retained_read_description"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                output = io.StringIO()
                answers = permission_answers(Path(temporary))[:2]
                del answers[1][missing]
                with patch("builtins.input", side_effect=[json.dumps(answer) for answer in answers]), \
                     patch.object(native.os, "open", wraps=native.os.open) as opened:
                    with self.assertRaisesRegex(RuntimeError, "OPEN"):
                        native.permission_shapes(Path(temporary), output)
                self.assertEqual(opened.call_count, 1)  # CREATE only; never reopen the existing file
                self.assertFalse(any(row["event"] == "write-only-open-started" for row in rows(output)))

    def test_writeonly_missing_or_unsafe_grant_evidence_stays_open(self):
        for trial_index in (2, 4, 6, 8):
            for field, value in (("requested_mode", ""), ("granted_mode", "writeBack"),
                                 ("read_open_observed", True), ("no_retained_read_description", False),
                                 ("open_trace", "")):
                with self.subTest(trial_index=trial_index, field=field), tempfile.TemporaryDirectory() as temporary:
                    output = io.StringIO()
                    answers = permission_answers(Path(temporary))[:trial_index + 1]
                    answers[-1][field] = value
                    with patch("builtins.input", side_effect=[json.dumps(answer) for answer in answers]):
                        with self.assertRaisesRegex(RuntimeError, "OPEN"):
                            native.permission_shapes(Path(temporary), output)
                    completed = [row for row in rows(output) if row["event"] == "write-only-trial-recorded"]
                    self.assertEqual(len(completed), trial_index // 2 - 1)

    def test_create_with_retained_rights_requires_writeback_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            proof = permission_answers(Path(temporary))[0]
            proof["granted_mode"] = "noCache"
            with patch("builtins.input", return_value=json.dumps(proof)):
                with self.assertRaisesRegex(RuntimeError, "OPEN"):
                    native.permission_shapes(Path(temporary), io.StringIO())

    def test_native_namespace_shapes_cross_directories_and_replace_dirty_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            replacements = []
            real_rename = native.os.rename

            def rename(source, target):
                self.assertNotEqual(source.parent, target.parent)
                if target.exists():
                    self.assertNotEqual(source.stat().st_ino, target.stat().st_ino)
                    self.assertEqual(source.read_bytes()[:native.PAGE_SIZE], b"N" * native.PAGE_SIZE)
                    self.assertEqual(target.read_bytes()[:native.PAGE_SIZE], b"X" * native.PAGE_SIZE)
                    replacements.append(str(target))
                real_rename(source, target)

            with patch.object(native, "permission_shapes"), patch.object(native, "checkpoint"), \
                 patch.object(native.os, "rename", side_effect=rename):
                native.healthy_shapes(Path(temporary), output)
            self.assertEqual(len(replacements), 1)
            self.assertIn("dirty-replacement-returned", [row["event"] for row in rows(output)])

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
