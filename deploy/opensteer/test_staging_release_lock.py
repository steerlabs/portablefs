#!/usr/bin/env python3
"""Unit and shared-golden-vector tests for staging-release-lock.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "staging_release_lock", SCRIPT_DIR / "staging-release-lock.py"
)
assert SPEC is not None and SPEC.loader is not None
lock = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lock
SPEC.loader.exec_module(lock)

NOW = 1_700_000_100
CLOUD_ID = "12345678-1234-1234-1234-123456789abc"
OTHER_CLOUD_ID = "abcdefab-abcd-abcd-abcd-abcdefabcdef"
COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def owner(
    *,
    kind: str = "cloud-build",
    owner_id: str = CLOUD_ID,
    source_commit: str = COMMIT,
    acquired_at: int = 1_700_000_000,
    hard_deadline: int = 1_700_012_600,
    heartbeat_at: int = 1_700_000_050,
) -> object:
    return lock.Owner(
        kind=kind,
        owner_id=owner_id,
        source_commit=source_commit,
        acquired_at=acquired_at,
        hard_deadline=hard_deadline,
        heartbeat_at=heartbeat_at,
    )


class FakeBackend:
    def __init__(self, current: object | None = None) -> None:
        self.current = current
        self.put_preconditions: list[int] = []
        self.deleted: list[int] = []
        self.next_generation = 1 if current is None else current.generation + 1

    def describe(self) -> object | None:
        return self.current

    def put(self, candidate: object, if_generation_match: int) -> object:
        self.put_preconditions.append(if_generation_match)
        actual = 0 if self.current is None else self.current.generation
        if actual != if_generation_match:
            raise lock.LockBusy("generation race")
        self.current = lock.LockObject(self.next_generation, candidate)
        self.next_generation += 1
        return self.current

    def heartbeat(self, generation: int, candidate: object) -> object:
        return self.put(candidate, generation)

    def delete(self, generation: int) -> None:
        self.deleted.append(generation)
        if self.current is None or self.current.generation != generation:
            raise lock.LockError("wrong generation")
        self.current = None


class OwnerSchemaTests(unittest.TestCase):
    def test_exact_schema_round_trips(self) -> None:
        expected = owner()
        self.assertEqual(lock.owner_from_metadata(expected.metadata(), now=NOW), expected)

    def test_extra_missing_non_string_and_unknown_schema_fail_closed(self) -> None:
        for mutate in (
            lambda value: value.update({"extra": "no"}),
            lambda value: value.pop("source-commit"),
            lambda value: value.update({"owner-id": 42}),
            lambda value: value.update({"schema-version": "2"}),
            lambda value: value.update({"owner-kind": "jenkins"}),
            lambda value: value.update({"acquired-at": "01700000000"}),
            lambda value: value.update({"heartbeat-at": "+1700000050"}),
        ):
            metadata = owner().metadata()
            mutate(metadata)
            with self.subTest(metadata=metadata), self.assertRaises(lock.LockError):
                lock.owner_from_metadata(metadata, now=NOW)

    def test_ids_commits_and_platform_bounds_are_strict(self) -> None:
        invalid = (
            owner(owner_id="not-a-build"),
            owner(source_commit="A" * 40),
            owner(hard_deadline=1_700_018_001),
            owner(heartbeat_at=1_699_999_999),
            owner(heartbeat_at=NOW + 301),
            owner(
                kind="github-actions",
                owner_id="0:1",
                hard_deadline=1_700_007_200,
            ),
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(lock.LockError):
                lock.require_owner(value, now=NOW)


class AcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = owner(
            owner_id=OTHER_CLOUD_ID,
            source_commit=OTHER_COMMIT,
            acquired_at=NOW,
            heartbeat_at=NOW,
            hard_deadline=NOW + 12_600,
        )

    def test_absent_create_uses_generation_zero(self) -> None:
        backend = FakeBackend()
        acquired = lock.acquire_once(backend, self.candidate, now=NOW)
        self.assertEqual(acquired.generation, 1)
        self.assertEqual(backend.put_preconditions, [0])

    def test_same_identity_is_idempotent_without_status_query(self) -> None:
        current = lock.LockObject(17, self.candidate)
        backend = FakeBackend(current)
        terminal = mock.Mock(side_effect=AssertionError("must not query"))
        self.assertIs(lock.acquire_once(backend, self.candidate, now=NOW, terminal=terminal), current)
        terminal.assert_not_called()
        self.assertEqual(backend.put_preconditions, [])

    def test_same_identity_cannot_reenter_after_hard_deadline(self) -> None:
        expired = owner(hard_deadline=NOW)
        backend = FakeBackend(lock.LockObject(17, expired))
        retry = owner(
            acquired_at=NOW,
            heartbeat_at=NOW,
            hard_deadline=NOW + 12_600,
        )
        terminal = mock.Mock(side_effect=AssertionError("must not query"))
        with self.assertRaises(lock.LockError):
            lock.acquire_once(backend, retry, now=NOW, terminal=terminal)
        terminal.assert_not_called()

    def test_active_owner_refuses_even_after_deadline(self) -> None:
        for now in (NOW, 1_700_012_601):
            current = lock.LockObject(17, owner())
            backend = FakeBackend(current)
            with self.subTest(now=now), self.assertRaises(lock.LockBusy):
                lock.acquire_once(backend, self.candidate, now=now, terminal=lambda _owner: False)
            self.assertEqual(backend.put_preconditions, [])

    def test_terminal_owner_allows_early_exact_generation_takeover(self) -> None:
        backend = FakeBackend(lock.LockObject(17, owner()))
        acquired = lock.acquire_once(
            backend, self.candidate, now=NOW, terminal=lambda _owner: True
        )
        self.assertEqual(backend.put_preconditions, [17])
        self.assertEqual(acquired.generation, 18)

    def test_unknown_status_fails_closed(self) -> None:
        backend = FakeBackend(lock.LockObject(17, owner()))

        def unknown(_owner: object) -> bool:
            raise lock.LockError("unknown")

        with self.assertRaises(lock.LockError):
            lock.acquire_once(backend, self.candidate, now=NOW, terminal=unknown)
        self.assertEqual(backend.put_preconditions, [])

    def test_generation_race_has_one_winner(self) -> None:
        backend = FakeBackend(lock.LockObject(17, owner()))
        first = lock.acquire_once(
            backend, self.candidate, now=NOW, terminal=lambda _owner: True
        )
        contender = owner(
            owner_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            source_commit="c" * 40,
            acquired_at=NOW,
            heartbeat_at=NOW,
            hard_deadline=NOW + 12_600,
        )
        with self.assertRaises(lock.LockBusy):
            backend.put(contender, 17)
        self.assertEqual(backend.current, first)

    def test_terminal_takeover_losing_cas_race_fails(self) -> None:
        class RaceBackend(FakeBackend):
            def put(self, candidate: object, if_generation_match: int) -> object:
                self.current = lock.LockObject(18, candidate)
                raise lock.LockBusy("generation race")

        backend = RaceBackend(lock.LockObject(17, owner()))
        with self.assertRaises(lock.LockBusy):
            lock.acquire_once(
                backend, self.candidate, now=NOW, terminal=lambda _owner: True
            )

    def test_successful_create_with_lost_response_is_safe_to_retry(self) -> None:
        class LostResponseBackend(FakeBackend):
            lost = True

            def put(self, candidate: object, if_generation_match: int) -> object:
                written = super().put(candidate, if_generation_match)
                if self.lost:
                    self.lost = False
                    raise lock.LockError("response lost")
                return written

        backend = LostResponseBackend()
        with self.assertRaises(lock.LockError):
            lock.acquire_once(backend, self.candidate, now=NOW)
        terminal = mock.Mock(side_effect=AssertionError("must not query"))
        recovered = lock.acquire_once(
            backend, self.candidate, now=NOW + 1, terminal=terminal
        )
        self.assertEqual(recovered.generation, 1)
        terminal.assert_not_called()


class FencingTests(unittest.TestCase):
    def test_assert_requires_exact_owner_generation_and_live_deadline(self) -> None:
        expected = owner()
        backend = FakeBackend(lock.LockObject(9, expected))
        self.assertEqual(lock.assert_owned(backend, expected, 9, now=NOW).generation, 9)
        for generation, identity, now in (
            (8, expected, NOW),
            (9, owner(source_commit=OTHER_COMMIT), NOW),
            (9, expected, expected.hard_deadline),
        ):
            with self.subTest(generation=generation, now=now), self.assertRaises(lock.LockError):
                lock.assert_owned(backend, identity, generation, now=now)

        backend.current = lock.LockObject(9, owner(heartbeat_at=NOW))
        with self.assertRaises(lock.LockError):
            lock.assert_owned(backend, expected, 9, now=NOW)

    def test_heartbeat_returns_a_new_generation_and_aba_safe_release(self) -> None:
        original = owner()
        backend = FakeBackend(lock.LockObject(9, original))
        renewed_owner = owner(heartbeat_at=NOW)
        renewed = backend.heartbeat(9, renewed_owner)
        self.assertEqual(renewed.generation, 10)
        with self.assertRaises(lock.LockError):
            backend.delete(9)
        backend.delete(10)
        self.assertIsNone(backend.current)

    def test_release_refuses_after_concurrent_generation_change(self) -> None:
        expected = owner()
        backend = FakeBackend(lock.LockObject(9, expected))
        backend.current = lock.LockObject(10, expected)
        with self.assertRaises(lock.LockError):
            backend.delete(9)
        self.assertEqual(backend.current.generation, 10)

    def test_heartbeat_loop_advances_state_and_acknowledges_stop(self) -> None:
        expected = owner()
        backend = FakeBackend(lock.LockObject(9, expected))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            stop = root / "stop"
            aborted = root / "abort"
            stopped = root / "stopped"
            lost = root / "lost"
            lock.write_state(state, backend.current)

            def request_stop(_seconds: int) -> None:
                stop.write_text("stop\n")

            with mock.patch.object(lock.time, "time", return_value=NOW), mock.patch.object(
                lock.time, "sleep", side_effect=request_stop
            ):
                lock.heartbeat_loop(
                    backend,
                    state,
                    stop,
                    aborted,
                    stopped,
                    lost,
                    interval_seconds=1,
                )
            renewed_owner, renewed_generation = lock.read_state(state)
            self.assertEqual(renewed_generation, 10)
            self.assertEqual(renewed_owner.heartbeat_at, NOW)
            self.assertTrue(stopped.exists())
            self.assertFalse(lost.exists())

    def test_heartbeat_loss_marks_lost_and_never_acknowledges_stop(self) -> None:
        expected = owner()
        backend = FakeBackend(lock.LockObject(10, expected))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            stop = root / "stop"
            aborted = root / "abort"
            stopped = root / "stopped"
            lost = root / "lost"
            lock.write_state(state, lock.LockObject(9, expected))
            with self.assertRaises(lock.LockError):
                lock.heartbeat_loop(
                    backend,
                    state,
                    stop,
                    aborted,
                    stopped,
                    lost,
                    interval_seconds=1,
                )
            self.assertTrue(lost.exists())
            self.assertFalse(stopped.exists())

    def test_abort_stops_heartbeat_without_release_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aborted = root / "abort"
            aborted.write_text("abort\n")
            stopped = root / "stopped"
            lock.heartbeat_loop(
                FakeBackend(),
                root / "absent-state",
                root / "stop",
                aborted,
                stopped,
                root / "lost",
                interval_seconds=1,
            )
            self.assertFalse(stopped.exists())


class PlatformStatusTests(unittest.TestCase):
    @mock.patch.object(lock.subprocess, "run")
    def test_cloud_build_status_matrix(self, run: mock.Mock) -> None:
        for status, terminal in (("PENDING", False), ("WORKING", False), ("SUCCESS", True)):
            run.return_value = subprocess.CompletedProcess([], 0, status + "\n", "")
            with self.subTest(status=status):
                self.assertEqual(lock.cloud_build_terminal(CLOUD_ID), terminal)
        run.return_value = subprocess.CompletedProcess([], 0, "MYSTERY\n", "")
        with self.assertRaises(lock.LockError):
            lock.cloud_build_terminal(CLOUD_ID)
        run.return_value = subprocess.CompletedProcess([], 1, "", "denied")
        with self.assertRaises(lock.LockError):
            lock.cloud_build_terminal(CLOUD_ID)

    @mock.patch.object(lock.urllib.request, "urlopen")
    def test_github_attempt_status_and_identity_are_authoritative(self, urlopen: mock.Mock) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(
            {"id": 1234, "run_attempt": 2, "status": "completed"}
        ).encode()
        urlopen.return_value = response
        self.assertTrue(lock.github_actions_terminal("1234:2"))
        self.assertIn("/1234/attempts/2", urlopen.call_args.args[0].full_url)

        response.read.return_value = json.dumps(
            {"id": 1234, "run_attempt": 2, "status": "in_progress"}
        ).encode()
        self.assertFalse(lock.github_actions_terminal("1234:2"))
        response.read.return_value = json.dumps(
            {"id": 1234, "run_attempt": 3, "status": "completed"}
        ).encode()
        with self.assertRaises(lock.LockError):
            lock.github_actions_terminal("1234:2")


class GcloudBackendTests(unittest.TestCase):
    @staticmethod
    def gcloud_object(expected: object, generation: str = "18") -> dict[str, object]:
        """Fixture matching real `gcloud storage ... --format=json` output."""

        return {
            "bucket": "opensteer-tfstate",
            "content_type": "application/json",
            "crc32c_hash": "AAAAAA==",
            "creation_time": "2026-08-23T00:00:00+0000",
            "custom_fields": expected.metadata(),
            "etag": "fixture-etag",
            "generation": generation,
            "md5_hash": "fixture-md5",
            "metageneration": 1,
            "name": "release-locks/opensteer-staging",
            "size": 1,
            "storage_class": "STANDARD",
            "storage_class_update_time": "2026-08-23T00:00:00+0000",
            "storage_url": lock.LOCK_URL,
            "update_time": "2026-08-23T00:00:00+0000",
        }

    def test_write_uses_exact_generation_and_observes_full_metadata(self) -> None:
        expected = owner()
        backend = lock.GcloudBackend()
        describe = json.dumps(self.gcloud_object(expected))
        with mock.patch.object(
            backend,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, describe, ""),
            ),
        ) as run:
            written = backend.put(expected, 17)
        self.assertEqual(written, lock.LockObject(18, expected))
        arguments = run.call_args_list[0].args[0]
        self.assertIn("--if-generation-match=17", arguments)
        self.assertIn("--content-type=application/json", arguments)
        metadata = next(
            value for value in arguments if value.startswith("--custom-metadata=")
        )
        for key, value in expected.metadata().items():
            self.assertIn(f"{key}={value}", metadata)

    def test_describe_accepts_real_gcloud_cli_schema(self) -> None:
        expected = owner()
        backend = lock.GcloudBackend()
        with mock.patch.object(
            backend,
            "_run",
            return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(self.gcloud_object(expected, "23")), ""
            ),
        ):
            self.assertEqual(backend.describe(), lock.LockObject(23, expected))

    def test_describe_rejects_rest_shape_unknown_fields_and_noncanonical_generation(
        self,
    ) -> None:
        expected = owner()
        invalid_documents = (
            {"generation": "18", "metadata": expected.metadata()},
            {
                **self.gcloud_object(expected),
                "custom_fields": {**expected.metadata(), "unknown": "field"},
            },
            self.gcloud_object(expected, "018"),
            {**self.gcloud_object(expected), "generation": 18},
        )
        backend = lock.GcloudBackend()
        for document in invalid_documents:
            with self.subTest(document=document), mock.patch.object(
                backend,
                "_run",
                return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(document), ""
                ),
            ), self.assertRaises(lock.LockError):
                backend.describe()

    def test_write_precondition_race_is_busy(self) -> None:
        backend = lock.GcloudBackend()
        with mock.patch.object(
            backend,
            "_run",
            return_value=subprocess.CompletedProcess(
                [], 1, "", "412 Precondition Failed"
            ),
        ), self.assertRaises(lock.LockBusy):
            backend.put(owner(), 17)

    def test_heartbeat_rewrites_and_returns_new_fencing_generation(self) -> None:
        backend = lock.GcloudBackend()
        expected = owner(heartbeat_at=NOW)
        with mock.patch.object(
            backend, "put", return_value=lock.LockObject(18, expected)
        ) as put:
            renewed = backend.heartbeat(17, expected)
        self.assertEqual(renewed.generation, 18)
        put.assert_called_once_with(expected, 17)

    def test_delete_has_exact_generation_precondition(self) -> None:
        backend = lock.GcloudBackend()
        with mock.patch.object(
            backend,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run:
            backend.delete(23)
        self.assertEqual(
            run.call_args.args[0],
            ["rm", lock.LOCK_URL, "--if-generation-match=23", "--quiet"],
        )

    @mock.patch.object(lock.urllib.request, "urlopen")
    def test_github_transport_failure_fails_closed(self, urlopen: mock.Mock) -> None:
        urlopen.side_effect = urllib.error.URLError("offline")
        with self.assertRaises(lock.LockError):
            lock.github_actions_terminal("1234:2")


class StateAndGoldenTests(unittest.TestCase):
    def test_successful_release_removes_state_only_after_exact_delete(self) -> None:
        expected = owner()
        backend = FakeBackend(lock.LockObject(9, expected))
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            lock.write_state(state, backend.current)
            with mock.patch.object(lock.time, "time", return_value=NOW), mock.patch.object(
                lock, "GcloudBackend", return_value=backend
            ):
                self.assertEqual(
                    lock.main(["release", "--state-file", str(state)]),
                    0,
                )
            self.assertEqual(backend.deleted, [9])
            self.assertFalse(state.exists())

    def test_failed_exact_release_preserves_state_for_fail_closed_recovery(self) -> None:
        class DeleteRaceBackend(FakeBackend):
            def delete(self, generation: int) -> None:
                self.deleted.append(generation)
                raise lock.LockError("concurrent generation change")

        expected = owner()
        backend = DeleteRaceBackend(lock.LockObject(9, expected))
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            lock.write_state(state, backend.current)
            with mock.patch.object(lock.time, "time", return_value=NOW), mock.patch.object(
                lock, "GcloudBackend", return_value=backend
            ):
                self.assertEqual(
                    lock.main(["release", "--state-file", str(state)]),
                    1,
                )
            self.assertEqual(backend.deleted, [9])
            self.assertTrue(state.exists())

    def test_state_round_trip_and_exact_schema(self) -> None:
        value = lock.LockObject(27, owner())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            lock.write_state(path, value)
            self.assertEqual(lock.read_state(path), (value.owner, value.generation))
            document = json.loads(path.read_text())
            document["extra"] = True
            path.write_text(json.dumps(document))
            with self.assertRaises(lock.LockError):
                lock.read_state(path)
            del document["extra"]
            document["generation"] = True
            path.write_text(json.dumps(document))
            with self.assertRaises(lock.LockError):
                lock.read_state(path)

    def test_shared_golden_vectors(self) -> None:
        document = json.loads(
            (SCRIPT_DIR / "staging-release-lock-vectors.json").read_text()
        )
        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(
            document["implementationSha256"],
            hashlib.sha256(
                (SCRIPT_DIR / "staging-release-lock.py").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(document["lockUrl"], lock.LOCK_URL)
        self.assertEqual(document["maxHoldSeconds"], lock.MAX_HOLD_SECONDS)
        self.assertEqual(document["metadataKeys"], sorted(lock.LOCK_METADATA_KEYS))
        current = lock.LockObject(17, owner())
        candidate = owner(
            owner_id=OTHER_CLOUD_ID,
            source_commit=OTHER_COMMIT,
            acquired_at=NOW,
            heartbeat_at=NOW,
            hard_deadline=NOW + 12_600,
        )
        for case in document["cases"]:
            backend = FakeBackend(current)

            def terminal(_owner: object) -> bool:
                if case["ownerStatus"] == "terminal":
                    return True
                if case["ownerStatus"] == "active":
                    return False
                raise lock.LockError("unknown")

            with self.subTest(name=case["name"]):
                if case["expected"] == "takeover":
                    acquired = lock.acquire_once(
                        backend, candidate, now=case["now"], terminal=terminal
                    )
                    self.assertEqual(acquired.generation, 18)
                else:
                    expected_error = (
                        lock.LockBusy if case["expected"] == "busy" else lock.LockError
                    )
                    with self.assertRaises(expected_error):
                        lock.acquire_once(
                            backend, candidate, now=case["now"], terminal=terminal
                        )


if __name__ == "__main__":
    unittest.main()
