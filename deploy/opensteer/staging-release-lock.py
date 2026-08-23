#!/usr/bin/env python3
"""Generation-fenced global release lock for the live OpenSteer staging system."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol


LOCK_URL = "gs://opensteer-tfstate/release-locks/opensteer-staging"
LOCK_ENVIRONMENT = "opensteer-staging"
LOCK_SCHEMA_VERSION = "1"
LOCK_METADATA_KEYS = {
    "acquired-at",
    "environment",
    "hard-deadline",
    "heartbeat-at",
    "owner-id",
    "owner-kind",
    "schema-version",
    "source-commit",
}
OWNER_ID_PATTERNS = {
    "cloud-build": re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"),
    "github-actions": re.compile(r"^[1-9][0-9]*:[1-9][0-9]*$"),
}
MAX_HOLD_SECONDS = {
    "cloud-build": 18_000,
    "github-actions": 7_200,
}
SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
CLOUD_BUILD_ACTIVE = {"PENDING", "QUEUED", "WORKING"}
CLOUD_BUILD_TERMINAL = {
    "SUCCESS",
    "FAILURE",
    "INTERNAL_ERROR",
    "TIMEOUT",
    "CANCELLED",
    "EXPIRED",
}
GITHUB_ACTIVE = {"queued", "in_progress", "pending", "waiting", "requested"}


class LockError(RuntimeError):
    pass


class LockBusy(LockError):
    pass


@dataclass(frozen=True)
class Owner:
    kind: str
    owner_id: str
    source_commit: str
    acquired_at: int
    hard_deadline: int
    heartbeat_at: int

    def metadata(self) -> dict[str, str]:
        return {
            "acquired-at": str(self.acquired_at),
            "environment": LOCK_ENVIRONMENT,
            "hard-deadline": str(self.hard_deadline),
            "heartbeat-at": str(self.heartbeat_at),
            "owner-id": self.owner_id,
            "owner-kind": self.kind,
            "schema-version": LOCK_SCHEMA_VERSION,
            "source-commit": self.source_commit,
        }


@dataclass(frozen=True)
class LockObject:
    generation: int
    owner: Owner


class Backend(Protocol):
    def describe(self) -> LockObject | None: ...

    def put(self, owner: Owner, if_generation_match: int) -> LockObject: ...

    def heartbeat(self, generation: int, owner: Owner) -> LockObject: ...

    def delete(self, generation: int) -> None: ...


def require_owner(owner: Owner, *, now: int | None = None) -> None:
    pattern = OWNER_ID_PATTERNS.get(owner.kind)
    if pattern is None:
        raise LockError(f"unknown release-lock owner kind: {owner.kind!r}")
    if pattern.fullmatch(owner.owner_id) is None:
        raise LockError(f"invalid {owner.kind} owner id")
    if SOURCE_COMMIT.fullmatch(owner.source_commit) is None:
        raise LockError("release-lock source commit must be one full lowercase commit")
    if owner.acquired_at <= 0:
        raise LockError("release-lock acquired-at must be a positive Unix timestamp")
    if owner.heartbeat_at < owner.acquired_at:
        raise LockError("release-lock heartbeat precedes acquisition")
    duration = owner.hard_deadline - owner.acquired_at
    if duration <= 0 or duration > MAX_HOLD_SECONDS[owner.kind]:
        raise LockError(
            f"release-lock hard deadline exceeds the {owner.kind} platform bound"
        )
    if now is not None and owner.heartbeat_at > now + 300:
        raise LockError("release-lock heartbeat is implausibly far in the future")


def owner_from_metadata(metadata: object, *, now: int | None = None) -> Owner:
    if not isinstance(metadata, dict) or set(metadata) != LOCK_METADATA_KEYS:
        actual = sorted(metadata) if isinstance(metadata, dict) else []
        raise LockError(
            "release-lock metadata schema differs: "
            f"expected={sorted(LOCK_METADATA_KEYS)} actual={actual}"
        )
    if any(not isinstance(value, str) for value in metadata.values()):
        raise LockError("release-lock metadata values must all be strings")
    if metadata["schema-version"] != LOCK_SCHEMA_VERSION:
        raise LockError("release-lock schema version is unknown")
    if metadata["environment"] != LOCK_ENVIRONMENT:
        raise LockError("release-lock environment is not staging")
    timestamp_values = {
        key: metadata[key]
        for key in ("acquired-at", "hard-deadline", "heartbeat-at")
    }
    if any(
        POSITIVE_DECIMAL.fullmatch(value) is None
        for value in timestamp_values.values()
    ):
        raise LockError("release-lock timestamps must be canonical positive Unix decimals")
    acquired_at = int(timestamp_values["acquired-at"])
    hard_deadline = int(timestamp_values["hard-deadline"])
    heartbeat_at = int(timestamp_values["heartbeat-at"])
    owner = Owner(
        kind=metadata["owner-kind"],
        owner_id=metadata["owner-id"],
        source_commit=metadata["source-commit"],
        acquired_at=acquired_at,
        hard_deadline=hard_deadline,
        heartbeat_at=heartbeat_at,
    )
    require_owner(owner, now=now)
    return owner


def same_identity(left: Owner, right: Owner) -> bool:
    return (
        left.kind,
        left.owner_id,
        left.source_commit,
    ) == (
        right.kind,
        right.owner_id,
        right.source_commit,
    )


def cloud_build_terminal(owner_id: str) -> bool:
    result = subprocess.run(
        [
            "gcloud",
            "builds",
            "describe",
            owner_id,
            "--project=opensteer-admin",
            "--format=value(status)",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise LockError("could not establish the Cloud Build lock owner's status")
    status = result.stdout.strip()
    if status in CLOUD_BUILD_TERMINAL:
        return True
    if status in CLOUD_BUILD_ACTIVE:
        return False
    raise LockError(f"Cloud Build lock owner returned unknown status {status!r}")


def github_actions_terminal(owner_id: str) -> bool:
    run_id, attempt = owner_id.split(":", 1)
    request = urllib.request.Request(
        "https://api.github.com/repos/steerlabs/portablefs/actions/runs/"
        f"{run_id}/attempts/{attempt}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "opensteer-staging-release-lock",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    token = os.environ.get("OPENSTEER_RELEASE_LOCK_GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.load(response)
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        raise LockError("could not establish the GitHub Actions lock owner's status") from error
    if (
        not isinstance(document, dict)
        or document.get("id") != int(run_id)
        or document.get("run_attempt") != int(attempt)
    ):
        raise LockError("GitHub returned a different release-lock owner")
    status = document.get("status")
    if status == "completed":
        return True
    if status in GITHUB_ACTIVE:
        return False
    raise LockError(f"GitHub Actions lock owner returned unknown status {status!r}")


def owner_is_terminal(owner: Owner) -> bool:
    if owner.kind == "cloud-build":
        return cloud_build_terminal(owner.owner_id)
    if owner.kind == "github-actions":
        return github_actions_terminal(owner.owner_id)
    raise LockError(f"unknown release-lock owner kind: {owner.kind!r}")


def acquire_once(
    backend: Backend,
    candidate: Owner,
    *,
    now: int,
    terminal: Callable[[Owner], bool] = owner_is_terminal,
) -> LockObject:
    require_owner(candidate, now=now)
    current = backend.describe()
    if current is None:
        return backend.put(candidate, 0)
    require_owner(current.owner, now=now)
    if same_identity(current.owner, candidate):
        if now >= current.owner.hard_deadline:
            raise LockError("release-lock owner cannot re-enter after its hard deadline")
        return current
    # A platform-terminal owner cannot issue another mutation, so it is safe to
    # replace immediately. Time is deliberately not a takeover oracle: an
    # active owner remains authoritative even after its declared deadline, and
    # an unavailable or unknown owner-status API fails closed.
    if not terminal(current.owner):
        raise LockBusy(
            f"staging release is held by {current.owner.kind}/{current.owner.owner_id}"
        )
    # Generation CAS is the fencing token: only one contender can replace this
    # exact terminal owner.
    return backend.put(candidate, current.generation)


def assert_owned(
    backend: Backend, expected: Owner, generation: int, *, now: int
) -> LockObject:
    require_owner(expected, now=now)
    current = backend.describe()
    if current is None:
        raise LockError("staging release lock disappeared while owned")
    if current.generation != generation or current.owner != expected:
        raise LockError("staging release lock fencing token or metadata changed")
    if now >= current.owner.hard_deadline:
        raise LockError("staging release lock reached its platform hard deadline")
    return current


class GcloudBackend:
    def __init__(self, url: str = LOCK_URL) -> None:
        self.url = url

    @staticmethod
    def _run(arguments: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["gcloud", "storage", *arguments],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )

    def describe(self) -> LockObject | None:
        result = self._run(["objects", "describe", self.url, "--format=json"])
        if result.returncode != 0:
            message = f"{result.stderr}\n{result.stdout}".lower()
            if "not found" in message or "no urls matched" in message or "404" in message:
                return None
            raise LockError("could not describe the staging release lock")
        try:
            document = json.loads(result.stdout)
            if not isinstance(document, dict):
                raise TypeError("object description is not a mapping")
            generation_value = document.get("generation")
            if (
                not isinstance(generation_value, str)
                or POSITIVE_DECIMAL.fullmatch(generation_value) is None
            ):
                raise ValueError("object generation is not a canonical decimal string")
            generation = int(generation_value)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise LockError("Cloud Storage returned invalid lock metadata") from error
        # `gcloud storage objects describe --format=json` is not the Cloud
        # Storage REST resource: its CLI schema uses snake_case and exposes
        # custom object metadata as `custom_fields`. Accept only that observed
        # transport shape so a renamed/empty field cannot silently erase the
        # strict owner schema.
        owner = owner_from_metadata(document.get("custom_fields"), now=int(time.time()))
        return LockObject(generation=generation, owner=owner)

    def put(self, owner: Owner, if_generation_match: int) -> LockObject:
        require_owner(owner)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="opensteer-release-lock-", delete=True
        ) as source:
            json.dump(owner.metadata(), source, sort_keys=True, separators=(",", ":"))
            source.write("\n")
            source.flush()
            metadata = ",".join(
                f"{key}={value}" for key, value in sorted(owner.metadata().items())
            )
            result = self._run(
                [
                    "cp",
                    source.name,
                    self.url,
                    f"--if-generation-match={if_generation_match}",
                    f"--custom-metadata={metadata}",
                    "--content-type=application/json",
                    "--quiet",
                ]
            )
        if result.returncode != 0:
            message = f"{result.stderr}\n{result.stdout}".lower()
            if "conditionnotmet" in message or "precondition" in message or "412" in message:
                raise LockBusy("another staging release contender won the generation race")
            raise LockError("could not write the staging release lock")
        current = self.describe()
        if current is None or current.owner != owner:
            raise LockError("staging release lock write was not observable as the exact owner")
        return current

    def heartbeat(self, generation: int, owner: Owner) -> LockObject:
        # Rewrite the object under an exact-generation precondition instead of
        # patching metadata in place. Every successful renewal therefore emits
        # a new generation/fencing token that the caller must persist.
        try:
            return self.put(owner, generation)
        except LockBusy as error:
            raise LockError("lost the staging release lock while renewing it") from error

    def delete(self, generation: int) -> None:
        result = self._run(
            ["rm", self.url, f"--if-generation-match={generation}", "--quiet"]
        )
        if result.returncode != 0:
            raise LockError("refused to release a staging lock no longer owned")


STATE_KEYS = {"generation", "owner", "schemaVersion", "url"}


def write_state(path: Path, lock: LockObject) -> None:
    document = {
        "generation": lock.generation,
        "owner": lock.owner.metadata(),
        "schemaVersion": 1,
        "url": LOCK_URL,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def read_state(path: Path) -> tuple[Owner, int]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LockError("release-lock state file is absent or invalid") from error
    if not isinstance(document, dict) or set(document) != STATE_KEYS:
        raise LockError("release-lock state file schema differs")
    if document.get("schemaVersion") != 1 or document.get("url") != LOCK_URL:
        raise LockError("release-lock state file names a different protocol or object")
    generation = document.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        raise LockError("release-lock state file has an invalid generation")
    owner = owner_from_metadata(document.get("owner"))
    return owner, generation


@contextlib.contextmanager
def state_guard(path: Path):
    """Serialize local state reads with heartbeat generation advancement."""

    path.parent.mkdir(parents=True, exist_ok=True)
    guard_path = path.with_name(f".{path.name}.guard")
    with guard_path.open("a+", encoding="utf-8") as guard:
        os.chmod(guard_path, 0o600)
        fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(guard.fileno(), fcntl.LOCK_UN)


def candidate_from_args(args: argparse.Namespace, now: int) -> Owner:
    hold_seconds = args.hold_seconds
    maximum = MAX_HOLD_SECONDS.get(args.owner_kind)
    if maximum is None or hold_seconds <= 0 or hold_seconds > maximum:
        raise LockError(
            f"hold-seconds must be within the fixed {args.owner_kind} platform bound"
        )
    return Owner(
        kind=args.owner_kind,
        owner_id=args.owner_id,
        source_commit=args.source_commit,
        acquired_at=now,
        hard_deadline=now + hold_seconds,
        heartbeat_at=now,
    )


def common_owner_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--owner-kind", choices=sorted(OWNER_ID_PATTERNS), required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--state-file", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    acquire = subparsers.add_parser("acquire-once")
    common_owner_arguments(acquire)
    acquire.add_argument("--hold-seconds", type=int, required=True)
    for name in ("assert-owned", "renew", "release"):
        command = subparsers.add_parser(name)
        command.add_argument("--state-file", type=Path, required=True)
    heartbeat = subparsers.add_parser("heartbeat-loop")
    heartbeat.add_argument("--state-file", type=Path, required=True)
    heartbeat.add_argument("--stop-file", type=Path, required=True)
    heartbeat.add_argument("--abort-file", type=Path, required=True)
    heartbeat.add_argument("--stopped-file", type=Path, required=True)
    heartbeat.add_argument("--lost-file", type=Path, required=True)
    heartbeat.add_argument("--interval-seconds", type=int, default=30)
    return parser


def heartbeat_loop(
    backend: Backend,
    state_file: Path,
    stop_file: Path,
    abort_file: Path,
    stopped_file: Path,
    lost_file: Path,
    *,
    interval_seconds: int,
) -> None:
    if interval_seconds <= 0 or interval_seconds > 60:
        raise LockError("heartbeat interval must be from 1 through 60 seconds")
    while True:
        if abort_file.exists():
            return
        if stop_file.exists():
            stopped_file.write_text("stopped\n", encoding="utf-8")
            return
        try:
            with state_guard(state_file):
                owner, generation = read_state(state_file)
                now = int(time.time())
                current = assert_owned(backend, owner, generation, now=now)
                renewed_owner = Owner(
                    kind=current.owner.kind,
                    owner_id=current.owner.owner_id,
                    source_commit=current.owner.source_commit,
                    acquired_at=current.owner.acquired_at,
                    hard_deadline=current.owner.hard_deadline,
                    heartbeat_at=now,
                )
                renewed = backend.heartbeat(generation, renewed_owner)
                if renewed.owner != renewed_owner:
                    raise LockError("staging release lock metadata changed during renewal")
                write_state(state_file, renewed)
        except (LockError, OSError, subprocess.SubprocessError) as error:
            lost_file.write_text("lost\n", encoding="utf-8")
            raise LockError("heartbeat lost the staging release lock") from error
        for _second in range(interval_seconds):
            if abort_file.exists():
                return
            if stop_file.exists():
                stopped_file.write_text("stopped\n", encoding="utf-8")
                return
            time.sleep(1)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    backend = GcloudBackend()
    now = int(time.time())
    try:
        if args.command == "heartbeat-loop":
            heartbeat_loop(
                backend,
                args.state_file,
                args.stop_file,
                args.abort_file,
                args.stopped_file,
                args.lost_file,
                interval_seconds=args.interval_seconds,
            )
            return 0
        with state_guard(args.state_file):
            if args.command == "acquire-once":
                candidate = candidate_from_args(args, now)
                lock = acquire_once(backend, candidate, now=now)
                write_state(args.state_file, lock)
                print(
                    f"Acquired global staging release lock generation {lock.generation} "
                    f"for {candidate.kind}/{candidate.owner_id}."
                )
                return 0

            owner, generation = read_state(args.state_file)
            current = assert_owned(backend, owner, generation, now=now)
            if args.command == "assert-owned":
                print(f"Global staging release lock generation {generation} is owned.")
                return 0
            if args.command == "renew":
                renewed_owner = Owner(
                    kind=current.owner.kind,
                    owner_id=current.owner.owner_id,
                    source_commit=current.owner.source_commit,
                    acquired_at=current.owner.acquired_at,
                    hard_deadline=current.owner.hard_deadline,
                    heartbeat_at=now,
                )
                renewed = backend.heartbeat(generation, renewed_owner)
                if renewed.owner != renewed_owner:
                    raise LockError("staging release lock metadata changed during renewal")
                write_state(args.state_file, renewed)
                print(
                    "Renewed global staging release lock generation "
                    f"{generation} -> {renewed.generation}."
                )
                return 0
            if args.command == "release":
                backend.delete(current.generation)
                args.state_file.unlink(missing_ok=True)
                print(f"Released global staging release lock generation {generation}.")
                return 0
        raise LockError(f"unknown command {args.command!r}")
    except LockBusy as error:
        print(f"staging-release-lock: {error}", file=sys.stderr)
        return 75
    except (LockError, OSError, subprocess.SubprocessError) as error:
        print(f"staging-release-lock: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
