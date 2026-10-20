#!/usr/bin/env python3
"""Interactive r3l kernel-cache write proof on an exact, separately deployed signed build.

macOS 27 grants writeThrough, never writeBack. The held-WRITE cases below were
written for writeBack and expect write(2) to return while a covered WRITE is
held; under writeThrough that write blocks, so those cases stay OPEN.

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
import errno
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
LIFECYCLE = ("pushInvalidate-proof-expiry", "ordinary-unmount", "pushInvalidate-failure", "writer-loss",
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


def recorded_call(emit, name, operation, **fields):
    emit(name + "-started", **fields)
    try:
        value = operation()
    except OSError as error:
        emit(name + "-finished", success=False, errno=error.errno, error=str(error),
             **fields, **({"access_refusal": True} if name == "reopen" else {}))
        return False, None
    emit(name + "-finished", success=True, **fields)
    return True, value


def reopen_fsync(fd, path, emit):
    """A cleanup error must never replace the decisive barrier outcome."""
    emit("reopen-fsync-started")
    closed, _ = recorded_call(emit, "old-close", lambda: os.close(fd))
    reached = False
    if closed:
        opened, reopened = recorded_call(emit, "reopen", lambda: os.open(path, os.O_WRONLY))
        if opened:
            reached = True
            recorded_call(emit, "reopened-fsync", lambda: os.fsync(reopened))
            recorded_call(emit, "final-close", lambda: os.close(reopened))
    emit("reopen-fsync-finished", fsync_reached=reached)


def require_reopen_error(rows):
    barriers = [row for row in rows if row["event"] == "reopened-fsync-finished"]
    if any(row["success"] for row in barriers):
        raise RuntimeError("close/reopen fsync certified an incomplete faulted cut; native proof FAILED")
    if not barriers:
        raise RuntimeError("reopened fsync not reached/completed; access refusal or close failure is not an error-retention proof; OPEN")


def worker(path):
    """Independent input, write and barrier threads preserve blocked evidence."""
    fd = os.open(path, os.O_WRONLY)
    output_lock = threading.Lock()
    threads = []

    def emit(event, **fields):
        with output_lock:
            record(sys.stdout, event, **fields)

    def operation(command):
        if command == "reopen-fsync":
            reopen_fsync(fd, path, emit)
            return
        emit(command + "-started")
        try:
            if command == "dirty":
                for offset in range(0, SIZE, PAGE_SIZE):
                    check_write(fd, b"B" * min(PAGE_SIZE, SIZE - offset), offset)
            elif command == "fsync":
                os.fsync(fd)
            elif command == "fullfsync":
                fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
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
    return answer


def proof_checkpoint(output, text, evidence_fields=(), **expected):
    answer = checkpoint(output, text + "\nSupply a JSON object with nonempty evidence fields "
                        f"{list(evidence_fields)} and exact values {json.dumps(expected)}.")
    try:
        proof = json.loads(answer)
    except ValueError as error:
        raise RuntimeError("structured proof missing; case remains OPEN") from error
    if (not isinstance(proof, dict)
            or any(not isinstance(proof.get(key), str) or not proof[key].strip() for key in evidence_fields)
            or any(type(proof.get(key)) is not type(value) or proof[key] != value for key, value in expected.items())):
        raise RuntimeError("required proof fields missing or inconsistent; case remains OPEN")
    record(output, "proof", checkpoint=text, proof=proof)
    return proof


def prepare_mount(mount, output, phase, identities, adapter="V3"):
    """Preparation is operator-owned; a writable bare mountpoint is never enough."""
    fields = ["signed_app", "signed_extension", "signed_daemon", "signature_evidence",
              "session_id", "epoch_id", "mount_evidence"]
    expected = {"faults_restored": True, "adapter": adapter}
    if adapter == "V3":
        fields.append("grant_evidence")
        expected.update(requested_mode="readWriteWithCache", granted_mode="writeThrough")
    else:
        fields.append("adapter_evidence")
    proof = proof_checkpoint(output, f"Prepare fresh healthy signed {adapter} mount for {phase}. Restore every fault; "
                             "establish NEW session AND epoch identities. Record exact signed artifact hashes and signature "
                             "verification, actual mounted filesystem identity and current grant/adapter traces before any "
                             "fixture/directory operation. Never reuse the fenced session or silently recreate the mount.",
                             evidence_fields=fields, **expected)
    mounted = os.path.ismount(mount)
    fresh = all(proof["session_id"] != old["session_id"] and proof["epoch_id"] != old["epoch_id"]
                for old in identities)
    record(output, "mount-preparation", phase=phase, mount=str(mount), actual_mount=mounted,
           fresh_identities=fresh, proof=proof)
    if not mounted or not fresh:
        raise RuntimeError("actual fresh healthy mount/session/epoch not established; case remains OPEN")
    identities.append(proof)


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


def collect_reopen_error(artifact, output, label):
    try:
        await_event(artifact, "reopen-fsync-finished")
    finally:
        # Even a stalled final close cannot hide an observed fsync success.
        reopened = events(artifact)
        record(output, "reopen-error-delivery", label=label, results=reopened)
        require_reopen_error(reopened)


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
               "Prove all seed CREATE/read descriptions retired before the worker O_WRONLY reopen, and trace its combined "
               "access-only OPEN. Require requested readWriteWithCache and granted writeThrough on the exact signed artifact.")
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
                collect_reopen_error(artifact, output, label)
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


def independent_shape_proof(output, path, expected):
    proof_checkpoint(output, f"{path}: obtain final length/hash through an independent authority read path. "
                     "Record read-path provenance and requested/granted modes/callback counts; mount reads alone are insufficient.",
                     evidence_fields=("authority_path_evidence", "grant_evidence", "callback_evidence"),
                     fixture=str(path), authority_length=len(expected), authority_sha256=hashlib.sha256(expected).hexdigest())


def buffered_writeonly_shapes(directory, output):
    path = directory / "partial-pages"
    expected = bytearray(b"A" * SIZE)
    with path.open("xb", buffering=0) as file:
        assert file.write(expected) == len(expected)
        os.fsync(file.fileno())
    checkpoint(output, f"{path}: persist fixture and prove all CREATE/read descriptions retired before the O_WRONLY "
               "reopen; trace a combined access-only OPEN and writeThrough grant. Arm a delayed pre-write attribute reply "
               "without blocking writes, then release it after the dirty extension and record its sequence.")
    fd = os.open(path, os.O_WRONLY)
    try:
        require_writeonly_reads_fail(fd)
        for offset, payload in ((17, b"partial"), (PAGE_SIZE + 13, b"neighbours")):
            check_write(fd, payload, offset)
            expected[offset:offset + len(payload)] = payload
        end = SIZE + PAGE_SIZE + 3
        check_write(fd, b"EOF", end)
        expected.extend(b"\0" * (end - len(expected)) + b"EOF")
        observed = os.fstat(fd).st_size
        record(output, "dirty-eof", fixture=str(path), expected=len(expected), observed=observed)
        assert observed == len(expected)
        checkpoint(output, "Release the delayed old attribute reply now. Record that it cannot regress dirty EOF. "
                   "No application fsync has occurred; identify the delivered-only authority size separately.")
        assert os.fstat(fd).st_size == len(expected)
        os.fsync(fd)
        assert path.read_bytes() == expected  # partial fills preserve every neighbour
        independent_shape_proof(output, path, expected)
        # Dirty pages exist before shrink/regrow, with no intervening barrier.
        check_write(fd, b"D" * SIZE, 0)
        os.ftruncate(fd, PAGE_SIZE + 19)
        os.ftruncate(fd, SIZE)
        expected = b"D" * (PAGE_SIZE + 19) + b"\0" * (SIZE - PAGE_SIZE - 19)
        os.fsync(fd)
        assert path.read_bytes() == expected
        independent_shape_proof(output, path, expected)
    finally:
        os.close(fd)

    path = directory / "multi-append"
    with path.open("xb", buffering=0) as file:
        assert file.write(b"seed") == 4
        os.fsync(file.fileno())
    checkpoint(output, f"{path}: persist and retire fixture descriptions, then trace two O_WRONLY|O_APPEND descriptors "
               "with authorized backing reads/writeThrough. No fsync or close may interleave with the append loops.")
    descriptors = [os.open(path, os.O_WRONLY | os.O_APPEND) for _ in range(2)]
    failures = []
    start = threading.Barrier(2)

    def append(index):
        try:
            start.wait(timeout=5)
            for sequence in range(128):
                payload = (f"{index}:{sequence:04d}:".encode() + b"A" * 93)
                if os.write(descriptors[index], payload) != 100:
                    raise OSError("short concurrent append")
        except Exception as error:
            failures.append(str(error))

    threads = [threading.Thread(target=append, args=(index,)) for index in range(2)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        if failures or any(thread.is_alive() for thread in threads):
            raise RuntimeError(f"append loops failed/stalled: {failures}; OPEN")
        record(output, "multi-append-loops-finished", fixture=str(path), dirty_length=os.fstat(descriptors[0]).st_size)
        for fd in descriptors:
            os.fsync(fd)
        actual = path.read_bytes()
        records = [actual[offset:offset + 100] for offset in range(4, len(actual), 100)]
        wanted = [(f"{index}:{sequence:04d}:".encode() + b"A" * 93) for index in range(2) for sequence in range(128)]
        assert actual[:4] == b"seed" and sorted(records) == sorted(wanted)
        independent_shape_proof(output, path, actual)
    finally:
        for fd in descriptors:
            os.close(fd)


def healthy_shapes(directory, output):
    path = directory / "shapes"
    other = directory / "other"
    other.mkdir()
    alias = other / "alias"
    replacement = other / "replacement"
    with path.open("xb", buffering=0) as file:
        assert file.write(b"A" * SIZE) == SIZE
        os.fsync(file.fileno())
    os.link(path, alias)
    with replacement.open("xb", buffering=0) as file:
        assert file.write(b"T" * SIZE) == SIZE
        os.fsync(file.fileno())
    replaced_fd = os.open(replacement, os.O_RDWR)
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
        os.link(path, other / "dirty-link")
        record(output, "dirty-link-returned", file=str(path), alias=str(other / "dirty-link"))
        check_write(fd, b"R" * PAGE_SIZE, 0)
        os.rename(alias, directory / "renamed")  # cross-directory alias
        record(output, "dirty-rename-returned", file=str(path), source=str(alias), target=str(directory / "renamed"))
        check_write(fd, b"N" * PAGE_SIZE, 0)
        check_write(replaced_fd, b"X" * PAGE_SIZE, 0)
        os.rename(directory / "renamed", replacement)  # both items dirty
        record(output, "dirty-replacement-returned", source=str(directory / "renamed"), target=str(replacement))
        assert os.pread(replaced_fd, PAGE_SIZE, 0) == b"X" * PAGE_SIZE
        check_write(fd, b"U" * PAGE_SIZE, 0)
        os.unlink(other / "dirty-link")
        record(output, "dirty-unlink-returned", file=str(path))
        os.unlink(path)
        os.unlink(replacement)
        check_write(fd, b"D" * PAGE_SIZE, 0)
        os.fsync(fd)
        assert os.pread(fd, PAGE_SIZE, 0) == b"D" * PAGE_SIZE
    finally:
        os.close(fd)
        os.close(replaced_fd)
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
    buffered_writeonly_shapes(directory, output)
    permission_shapes(directory, output)
    checkpoint(output, "Review shape traces: overwrite/extend/truncate-regrow, native pages/chunks, O_SYNC/O_DSYNC, aliases, "
               "open-unlinked and read-only mappings. Correlate dirty-link/rename/unlink returns with their earlier WRITE "
               "durability and push completion BEFORE namespace dispatch, including both dirty replacement identities "
               "and cross-directory aliases/rename. "
               "Record concurrent writes with a defined barrier cut, supported mappings and explicit unsupported mapping errors; "
               "do not infer any of these guarantees from the healthy local checks alone.")


PERMISSION_FIXTURES = (("existing-0200", 0o200, True), ("existing-0644", 0o644, False),
                       ("existing-0600", 0o600, False), ("existing-acl", 0o600, True))
PERMISSION_TRIALS = (("O_WRONLY", os.O_WRONLY), ("O_APPEND", os.O_WRONLY | os.O_APPEND),
                     ("O_TRUNC", os.O_WRONLY | os.O_TRUNC), ("O_CREAT", os.O_WRONLY | os.O_CREAT),
                     ("O_CREAT_TRUNC", os.O_WRONLY | os.O_CREAT | os.O_TRUNC))


def require_writeonly_reads_fail(fd):
    for operation in (lambda: os.read(fd, 1), lambda: os.pread(fd, 1, 0)):
        try:
            operation()
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        raise RuntimeError("application read through O_WRONLY succeeded; native proof FAILED")


def permission_shapes(directory, output):
    # CREATE grants read/write backing ownership even for a new 0200 file.
    # Keep the application descriptor O_WRONLY in both creation trials.
    for suffix, mode, effects in (("0600", 0o600, os.O_EXCL), ("0200", 0o200, os.O_EXCL),
                                  ("trunc-0600", 0o600, os.O_TRUNC), ("trunc-0200", 0o200, os.O_TRUNC)):
        path = directory / ("create-retained-rights-" + suffix)
        fd = os.open(path, os.O_CREAT | effects | os.O_WRONLY, mode)
        try:
            check_write(fd, b"C" * PAGE_SIZE, 0)
            require_writeonly_reads_fail(fd)
            proof_checkpoint(output, f"{path}: new O_CREAT|O_WRONLY flags={os.O_CREAT | effects | os.O_WRONLY} with legitimate CREATE read/write backing "
                             "description retained. Record application EBADF and V3 grant/ownership traces.",
                             evidence_fields=("grant_evidence", "description_evidence"),
                             requested_mode="readWriteWithCache", granted_mode="writeThrough", retained_read_description=True)
            os.fsync(fd)
        finally:
            os.close(fd)

    for name, mode, denied in PERMISSION_FIXTURES:
        path = directory / name
        with path.open("xb", buffering=0) as file:
            assert file.write(b"A" * SIZE) == SIZE
            os.fsync(file.fileno())
        path.chmod(mode)
        for trial, flags in PERMISSION_TRIALS:
            # Application close and chmod do not retire CREATE rights. ACL
            # fixtures require an actual storage ACL, not an inference from mode.
            proof_checkpoint(output, f"{path} mode {mode:04o} {trial}: BEFORE reopening, record real FSKit final close "
                             "and retirement of ALL prior descriptions, including CREATE/previous trials. Prove no retained "
                             "read description. For existing-acl install a same-principal storage ACL denying read but "
                             "allowing write; record its effective access check. Preserve the original create/truncate intent.",
                             evidence_fields=("final_close_evidence", "retirement_evidence", "permission_evidence"),
                             fixture=str(path), trial=trial, mode=f"{mode:04o}", no_retained_read_description=True,
                             read_denied=denied, write_allowed=True, storage_acl=name == "existing-acl")
            record(output, "write-only-open-started", fixture=str(path), trial=trial, flags=flags, mode=f"{mode:04o}")
            fd = os.open(path, flags, 0o600)
            try:
                require_writeonly_reads_fail(fd)
                if os.write(fd, b"W" * 100) != 100:
                    raise OSError("short write-only application write")
                os.fsync(fd)
            finally:
                os.close(fd)
            expected = dict(requested_mode="readWriteWithCache", granted_mode="noCache" if denied else "writeThrough",
                            successful_read_description=not denied,
                            authority_opens=([{"access": "readWrite", "result": "EACCES"},
                                              {"access": "write", "result": "success"}] if denied else
                                             [{"access": "readWrite", "result": "success"}]),
                            no_destructive_repeat=True, application_read_errno="EBADF")
            if denied:
                expected.update(cache_fill_read_observed=False)
            proof_checkpoint(output, f"{path} {trial}: record exact authority OPEN access/results for the SAME canonical "
                             "capability and requested/granted cache modes. A denied case may issue a FAILED read-capable "
                             "OPEN, but must retain no successful read-capable description and issue no cache-fill READ. "
                             "Readable cases require writeThrough. Verify CREATE/TRUNC happened exactly once on their original "
                             "paths, never in optional access acquisition or its retry.",
                             evidence_fields=("grant_evidence", "open_trace", "description_evidence", "canonical_item_evidence"),
                             fixture=str(path), trial=trial, **expected)
            record(output, "write-only-trial-recorded", fixture=str(path), trial=trial)


def collect_proofs(mount, output_dir, output):
    identities = []
    for hold in HOLD_CASES:
        for barrier in ("fsync", "fullfsync"):
            for fault in (None, *FAULTS):
                prepare_mount(mount, output, f"{hold}/{barrier}/{fault or 'success'}", identities)
                directory = mount / f"writeback-{time.time_ns()}"
                directory.mkdir()
                hold_proof(directory, output_dir, output, hold, barrier, fault)
    # The last case fences or unmounts. Do not touch shapes on its old session
    # or on the now-writable local directory underneath the mountpoint.
    prepare_mount(mount, output, "healthy shapes", identities)
    directory = mount / f"writeback-shapes-{time.time_ns()}"
    directory.mkdir()
    healthy_shapes(directory, output)
    for case in LIFECYCLE:
        prepare_mount(mount, output, case, identities)
        checkpoint(output, f"{case}: accept dirty kernel pages, record real writeThrough grant; "
                   "for healthy proof-only expiry/unmount require completed pushInvalidate, all reentrant durable WRITE replies, "
                   "pinned descriptions and no deadlock under grant renewal/final-close/reclaim/namespace overlap. "
                   "In the separate pushInvalidate-failure case inject a failed action: unchanged kernel state must "
                   "fail/fence, never acknowledge withdrawal. End that case before preparing another fresh mount. "
                   "For ownership/authorization loss require revoke without pushing into any new session/epoch; old dirty callbacks fail. "
                   "Verify a previously successful barrier's data independently at authority and Linux old/new readers. "
                   "Use test-macos27-kernel-cache.py's native-page observer for daemon death/stall/sleep, retain stale wake/stall "
                   "windows honestly, prove exclusion expiry plus storage drain before Linux mutation; no automatic pass.")
    prepare_mount(mount, output, "V2 comparison", identities, adapter="V2")
    checkpoint(output, "Repeat relevant held barrier/error/error-retention cases on V2 using this separately reviewed deployed artifact. "
               "Require the same fresh signed actual-mount/session/epoch preparation after each destructive case; "
               "record V2 adapter evidence rather than claiming a V3 grant. "
               "Preserve unchanged acceptance runs and their deadlines/failures; no qualification inherited from build 5008. "
               "Review every callback cut, native error and independent hash. Any missing proof leaves writeThrough unqualified.")


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
        collect_proofs(args.mount, args.output, output)
    print("Evidence collected. Native writeThrough qualification requires review; no automatic pass claimed.")


if __name__ == "__main__":
    main()
