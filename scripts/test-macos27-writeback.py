#!/usr/bin/env python3
"""Interactive r3l writeBack proof on an exact, separately deployed signed build.

Never deploy or run against the lab without separate authorization. This driver
performs local POSIX operations only. An operator supplies target-WRITE holds,
fault injection, independent authority/Linux observations and lifecycle actions.
Those facilities must keep renewals independent of the held WRITE. A whole-server
pause alone cannot prove the two required hold points. Missing evidence is OPEN,
never a pass. Output must be on local storage outside the mount.

Example (after separate review/deployment):
  python3 scripts/test-macos27-writeback.py --mount /Volumes/pfs --output /tmp/pfs-wb

Run the package-B kernel-cache observer separately for daemon death, extension
stall and sleep/wake; it records native page geometry and per-page residuals.
This collector does not claim device power-loss qualification.
"""
import argparse
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time

PAGE_SIZE = mmap.PAGESIZE
# Cross native pages and the existing 1 MiB callback chunk boundary.
SIZE = max(4 * PAGE_SIZE, 2 * 1024 * 1024 + PAGE_SIZE)
HOLD_CASES = ("before-apply", "after-durability-before-reply")
FAULTS = ("ENOSPC", "EDQUOT", "EIO", "short-write", "transport-loss", "fencing")
LIFECYCLE = ("pushInvalidate-proof-expiry", "ordinary-unmount", "writer-loss",
             "authorization-loss", "daemon-death", "extension-stall", "sleep-wake")


def record(output, event, **fields):
    output.write(json.dumps({"event": event, "time_ns": time.time_ns(),
                             "monotonic_ns": time.monotonic_ns(), **fields}) + "\n")
    output.flush()


def digest(path):
    with path.open("rb", buffering=0) as file:
        data = file.read()
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def check_write(fd, data, offset):
    count = os.pwrite(fd, data, offset)
    if count != len(data):
        raise OSError(f"short application pwrite: {count}/{len(data)}")


def worker(path):
    """Independent input, write and barrier threads preserve blocked evidence."""
    fd = os.open(path, os.O_RDWR)
    output_lock = threading.Lock()
    threads = []

    def emit(event, **fields):
        with output_lock:
            record(sys.stdout, event, **fields)

    def operation(command):
        emit(command + "-started")
        try:
            if command == "dirty":
                for offset in range(0, SIZE, PAGE_SIZE):
                    check_write(fd, b"B" * min(PAGE_SIZE, SIZE - offset), offset)
            elif command == "fsync":
                os.fsync(fd)
            elif command == "fullfsync":
                fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            elif command == "reopen-fsync":
                # V3 final close has no error channel. Check retained error
                # delivery after an application close and a fresh description.
                os.close(fd)
                reopened = os.open(path, os.O_RDWR)
                try:
                    os.fsync(reopened)
                finally:
                    os.close(reopened)
            else:
                raise ValueError(command)
            emit(command + "-finished", success=True)
        except (OSError, ValueError) as error:
            emit(command + "-finished", success=False, errno=getattr(error, "errno", None), error=str(error))

    emit("ready", page_size=PAGE_SIZE, size=SIZE, offsets=[0, PAGE_SIZE], inode=os.fstat(fd).st_ino)
    for line in sys.stdin:
        command = line.strip()
        if command == "stop":
            break
        thread = threading.Thread(target=operation, args=(command,), daemon=True)
        threads.append(thread)
        thread.start()
    # Parent records stalled children and preserves artifacts before termination.
    for thread in threads:
        thread.join()


def checkpoint(output, text):
    answer = input(text + "\nRecord exact commands, timestamps, modes, log/artifact paths and outcomes: ")
    record(output, "operator", checkpoint=text, evidence=answer)
    if not answer.strip():
        raise RuntimeError("required evidence missing; case remains OPEN")


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def await_event(path, name, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [row for row in events(path) if row["event"] == name]
        if found:
            return found[-1]
        time.sleep(0.02)
    raise RuntimeError(f"{name} stalled; inspect {path}; result remains OPEN")


def command(process, name):
    process.stdin.write(name + "\n")
    process.stdin.flush()


def hold_proof(directory, output_dir, output, hold, barrier, fault=None):
    label = f"{hold}-{barrier}-{fault or 'success'}"
    path = directory / label
    with path.open("xb", buffering=0) as file:
        assert file.write(b"A" * SIZE) == SIZE
        os.fsync(file.fileno())
    record(output, "persisted-fixture", label=label, **digest(path))
    checkpoint(output, f"{label}: verify fixture independently at authority; arm targeted WRITE hold {hold}. "
               "Keep KeepAlive/authorization live. Trace every covered callback/chunk and its durable result. "
               "Require requested readWriteWithCache and granted writeBack for this fixture on the exact signed artifact.")
    artifact = output_dir / (label + ".jsonl")
    with artifact.open("x") as stream, (output_dir / (label + ".stderr")).open("x") as errors:
        process = subprocess.Popen([sys.executable, __file__, "--worker", str(path)], stdin=subprocess.PIPE,
                                   stdout=stream, stderr=errors, text=True)
        try:
            await_event(artifact, "ready")
            command(process, "dirty")
            accepted = await_event(artifact, "dirty-finished")
            if not accepted["success"]:
                raise RuntimeError("fresh dirty acceptance failed; preserve failure, do not call this a buffered cut")
            checkpoint(output, f"{label}: prove fresh B bytes accepted by write(2), at least one covered WRITE held at {hold}, "
                       "and independent authority bytes/length at that hold. A clean already-durable cut is insufficient.")
            command(process, barrier)
            await_event(artifact, barrier + "-started")
            checkpoint(output, f"{label}: keep ALL covered callbacks held; prove {barrier} pending, record held request IDs, "
                       "accepted cut, native pending syscall and callback counts. Do not release yet.")
            if any(row["event"] == barrier + "-finished" for row in events(artifact)):
                raise RuntimeError("barrier completed while covered WRITE was held; native proof FAILED")
            checkpoint(output, f"{label}: now {'inject ' + fault if fault else 'release every held callback successfully'}; "
                       "record callback outcomes/durable replies and exact release timestamps. "
                       "Keep the fault active through close/reopen. Short WRITE must leave an incomplete accepted cut; "
                       "record whether the kernel retries it.")
            result = await_event(artifact, barrier + "-finished", timeout=30)
            if fault and result["success"]:
                raise RuntimeError("faulted/incomplete cut certified by barrier; native proof FAILED")
            if not fault and not result["success"]:
                raise RuntimeError("healthy barrier failed; preserve failure")
            if fault:
                command(process, "reopen-fsync")
                reopened = await_event(artifact, "reopen-fsync-finished")
                record(output, "reopen-error-delivery", label=label, result=reopened)
                if reopened["success"]:
                    raise RuntimeError("close/reopen fsync certified an incomplete faulted cut; native proof FAILED")
                checkpoint(output, f"{label}: adjudicate error retention after close/reopen/fsync; no successful barrier may "
                           "certify an incomplete accepted cut. Record final-close timing (no FSKit error return), "
                           "ordinary unmount outcome and actual revoke/fence. Preserve all native errors.")
            else:
                assert digest(path) == {"length": SIZE, "sha256": hashlib.sha256(b"B" * SIZE).hexdigest()}
                checkpoint(output, f"{label}: independently verify full authority length/hash after drain; check already-open "
                           "and new Linux readers' bytes/size/cache withdrawal. Record pre-barrier delivered-only visibility.")
        finally:
            record(output, "worker-state", label=label, exit=process.poll(), artifact=str(artifact))
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def healthy_shapes(directory, output):
    path = directory / "shapes"
    alias = directory / "alias"
    with path.open("xb", buffering=0) as file:
        assert file.write(b"A" * SIZE) == SIZE
        os.fsync(file.fileno())
    os.link(path, alias)
    fd = os.open(path, os.O_RDWR)
    try:
        check_write(fd, b"B" * SIZE, 0)  # overwrite pages and callback chunks
        check_write(fd, b"C" * PAGE_SIZE, SIZE)  # extend
        os.ftruncate(fd, PAGE_SIZE)
        os.ftruncate(fd, SIZE)
        os.fsync(fd)
        assert os.pread(fd, SIZE, 0) == b"B" * PAGE_SIZE + b"\0" * (SIZE - PAGE_SIZE)
        with mmap.mmap(fd, SIZE, access=mmap.ACCESS_READ) as mapping:
            assert mapping[PAGE_SIZE:PAGE_SIZE + 1] == b"\0"
        # Each namespace operation has an earlier dirty cut with no explicit
        # application barrier between that write and the namespace syscall.
        check_write(fd, b"L" * PAGE_SIZE, 0)
        os.link(path, directory / "dirty-link")
        record(output, "dirty-link-returned", file=str(path))
        check_write(fd, b"R" * PAGE_SIZE, 0)
        os.rename(alias, directory / "renamed")
        record(output, "dirty-rename-returned", file=str(path))
        check_write(fd, b"U" * PAGE_SIZE, 0)
        os.unlink(directory / "dirty-link")
        record(output, "dirty-unlink-returned", file=str(path))
        os.unlink(path)
        os.unlink(directory / "renamed")
        check_write(fd, b"D" * PAGE_SIZE, 0)
        os.fsync(fd)
        assert os.pread(fd, PAGE_SIZE, 0) == b"D" * PAGE_SIZE
    finally:
        os.close(fd)
    for name, flag in (("sync", getattr(os, "O_SYNC", None)), ("dsync", getattr(os, "O_DSYNC", None))):
        if flag is None:
            record(output, "unsupported", operation=name)
            continue
        fd = os.open(directory / name, os.O_CREAT | os.O_EXCL | os.O_RDWR | flag, 0o600)
        try:
            check_write(fd, b"S" * PAGE_SIZE, 0)
            os.fsync(fd)
        finally:
            os.close(fd)
    path = directory / "existing-0200"
    path.write_bytes(b"A" * SIZE)
    path.chmod(0o200)
    try:
        for flags in (os.O_WRONLY, os.O_WRONLY | os.O_APPEND):
            fd = os.open(path, flags)
            try:
                assert os.write(fd, b"W" * 100) == 100
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        path.chmod(0o600)
    checkpoint(output, "Review shape traces: overwrite/extend/truncate-regrow, native pages/chunks, O_SYNC/O_DSYNC, aliases, "
               "open-unlinked and read-only mappings. Correlate dirty-link/rename/unlink returns with their earlier WRITE "
               "durability and push completion BEFORE namespace dispatch, including replacement/aliases. "
               "Existing O_WRONLY/O_APPEND and 0200 must receive noCache when only "
               "write rights remain; verify no extra read OPEN. Repeat on an existing readable file. "
               "Record concurrent writes with a defined barrier cut, supported mappings and explicit unsupported mapping errors; "
               "do not infer any of these guarantees from the healthy local checks alone.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mount", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    if not args.mount or not args.output:
        parser.error("--mount and --output required")
    if platform.system() != "Darwin" or int(platform.mac_ver()[0].split(".")[0]) < 27 or os.geteuid() == 0:
        parser.error("requires unprivileged macOS 27 observer")
    if args.output.resolve().is_relative_to(args.mount.resolve()):
        parser.error("output must be outside the mount")
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / "operator.jsonl").open("x") as output:
        record(output, "geometry", page_size=PAGE_SIZE, offsets=[0, PAGE_SIZE], fixture_size=SIZE,
               os=platform.platform(), observer=sys.executable)
        checkpoint(output, "Record exact signed app/extension/daemon hashes, version, OS build, authority/session/epoch, "
                   "path/load, trace setup and independent authority hash command. Keep fresh identities per failure. "
                   "Start bounded grant/callback size/count/durability/final-close tracing; retain raw logs outside the mount.")
        for hold in HOLD_CASES:
            for barrier in ("fsync", "fullfsync"):
                for fault in (None, *FAULTS):
                    checkpoint(output, f"Prepare fresh healthy mount/session for {hold}/{barrier}/{fault or 'success'}; "
                               "record artifact identity again after any restart; restore faults before fixture persistence.")
                    directory = args.mount / f"writeback-{time.time_ns()}"
                    directory.mkdir()
                    hold_proof(directory, args.output, output, hold, barrier, fault)
        directory = args.mount / f"writeback-shapes-{time.time_ns()}"
        directory.mkdir()
        healthy_shapes(directory, output)
        for case in LIFECYCLE:
            checkpoint(output, f"{case}: fresh signed mount; accept dirty kernel pages, record real writeBack grant; "
                       "for healthy proof-only expiry/unmount require completed pushInvalidate, all reentrant durable WRITE replies, "
                       "pinned descriptions and no deadlock under grant renewal/final-close/reclaim/namespace overlap. "
                       "Inject a failed pushInvalidate separately: unchanged kernel state must fail/fence, never acknowledge withdrawal. "
                       "For ownership/authorization loss require revoke without pushing into any new session/epoch; old dirty callbacks fail. "
                       "Verify a previously successful barrier's data independently at authority and Linux old/new readers. "
                       "Use test-macos27-kernel-cache.py's native-page observer for daemon death/stall/sleep, retain stale wake/stall "
                       "windows honestly, prove exclusion expiry plus storage drain before Linux mutation; no automatic pass.")
        checkpoint(output, "Repeat relevant held barrier/error/error-retention cases on V2 using a separately reviewed deployed artifact. "
                   "Preserve unchanged acceptance runs and their deadlines/failures; no qualification inherited from build 5008. "
                   "Review every callback cut, native error and independent hash. Any missing proof leaves writeBack unqualified.")
    print("Evidence collected. Native writeBack qualification requires review; no automatic pass claimed.")


if __name__ == "__main__":
    main()
