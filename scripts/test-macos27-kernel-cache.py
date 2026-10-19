#!/usr/bin/env python3
"""Interactive native correctness battery for a deployed macOS 27 dev build.

Run locally, never against an undeployed lab build:
  python3 scripts/test-macos27-kernel-cache.py --mount /Volumes/pfs --output /tmp/pfs-cache-run

Use a disposable authority volume with a Linux reader/writer mount. The operator
owns deployment, fault injection, writer-exclusion evidence, and Linux writes;
this script does not deploy, contact another host, or force-unmount anything.
Keep the authority/daemon logs and exact signed build identity with the output.

For each loss case, record authority exclusion ending before attempting the
Linux write; an early write must fail EBUSY. Then Linux must overwrite BOTH
native VM pages of the named fixture with byte 76, using the observer's recorded
page size and extent, fsync it, and preserve its inode. Existing Mac
descriptors/mappings must not serve their old byte 65 after successful
withdrawal. A SIGBUS is an observed revoke result, not a script crash: mapped
readers run in separate subprocesses.

A proof-expiry-only case must keep the authority session authorized/usable while
withholding renewal replies past the actual proof horizon. Verify an invalidate
success, a noCache reopen and actual post-expiry READ/miss evidence, then let
renewal recover. For writer/authorization
loss and daemon death require revoke results. Extension stall and sleep/wake
explicitly examine residual races; record stale results without calling them a
qualification pass. Per-item results do not prove negative-name/attribute or
complete directory withdrawal. Do not infer withdrawal from callback-gate logs.
The stall procedure mutates and samples before resuming the extension. Sleep
observers write directly to files before sleep through withdrawal completion;
first scheduled wake reads require no human checkpoint. Healthy probes include
retained access across chmod and permission-checked reopen after final close.
"""
import argparse
import errno
import json
import mmap
import os
from pathlib import Path
import platform
import signal
import selectors
import subprocess
import sys
import time

CASES = ("proof-expiry", "writer-loss", "authorization-loss", "daemon-death",
         "extension-stall", "sleep-wake")
PAGE_SIZE = mmap.PAGESIZE
PAGE_OFFSETS = (0, PAGE_SIZE)
FIXTURE_SIZE = 2 * PAGE_SIZE


def emit(value):
    print(json.dumps({"time_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(), "page_size": PAGE_SIZE, **value}), flush=True)


def observe(fd, mapping, label, mode):
    # Flush each completed read before touching another page or asking metadata.
    # A later errno or mapped SIGBUS must never erase an earlier readable page.
    for page, offset in enumerate(PAGE_OFFSETS, start=1):
        record = {"sample": label, "mode": mode, "operation": "read", "page": page, "offset": offset}
        try:
            data = mapping[offset:offset + 1] if mapping is not None else os.pread(fd, 1, offset)
            emit({**record, "bytes": list(data)})
        except OSError as error:
            emit({**record, "errno": error.errno, "error": str(error)})
    try:
        metadata = os.fstat(fd)
        emit({"sample": label, "mode": mode, "operation": "fstat", "size": metadata.st_size, "inode": metadata.st_ino})
    except OSError as error:
        emit({"sample": label, "mode": mode, "operation": "fstat", "errno": error.errno, "error": str(error)})
    emit({"sample": label, "mode": mode, "operation": "complete"})


def reader(path, mode):
    fd = os.open(path, os.O_RDONLY)
    mapping = mmap.mmap(fd, FIXTURE_SIZE, access=mmap.ACCESS_READ) if mode == "mapped" else None
    emit({"ready": mode, "inode": os.fstat(fd).st_ino, "offsets": PAGE_OFFSETS,
          "fixture_size": FIXTURE_SIZE, "mapping_length": FIXTURE_SIZE if mapping is not None else 0})
    observing = None
    with selectors.DefaultSelector() as selector:
        selector.register(sys.stdin, selectors.EVENT_READ)
        while True:
            if observing is not None and not selector.select(timeout=0.01):
                # Output goes straight to the artifact, never a pipe that can
                # fill while the operator sleeps. First scheduled wake reads
                # need no human checkpoint; wall timestamps join kernel logs.
                observe(fd, mapping, observing, mode)
                continue
            line = sys.stdin.readline()
            if not line or line.strip() == "stop":
                break
            command = line.strip()
            if command.startswith("arm:"):
                observing = command.removeprefix("arm:")
                emit({"sample": command, "mode": mode, "operation": "armed"})
            elif command == "disarm":
                observing = None
                emit({"sample": command, "mode": mode, "operation": "disarmed"})
            else:
                observe(fd, mapping, command, mode)
    if mapping is not None:
        mapping.close()
    os.close(fd)


def checkpoint(label, evidence):
    print(label, flush=True)
    answer = input("Record actions, timestamps, commands/log paths and observed errors; Enter to continue: ")
    evidence.write(json.dumps({"time_ns": time.time_ns(), "checkpoint": label, "operator": answer}) + "\n")
    evidence.flush()


def collect(processes, label, evidence, expected=None, completion="complete"):
    for mode, process, output in processes:
        deadline = time.monotonic() + 10
        pages = {}
        while True:
            line = output.readline()
            if not line:
                if process.poll() is not None:
                    result = {"sample": label, "mode": mode, "exit": process.returncode}
                    evidence.write(json.dumps(result) + "\n")
                    evidence.flush()
                    if expected is not None:
                        raise RuntimeError(f"healthy {mode} reader exited")
                    break
                if time.monotonic() >= deadline:
                    evidence.write(json.dumps({"sample": label, "mode": mode, "stalled": True}) + "\n")
                    evidence.flush()
                    if expected is not None:
                        raise RuntimeError(f"healthy {mode} read stalled")
                    break
                time.sleep(0.01)
                continue
            result = json.loads(line)
            evidence.write(json.dumps({"requested_sample": label, "mode": mode, "result": result}) + "\n")
            evidence.flush()
            # Keep original labels on reads that finish after a stalled sample.
            if result.get("sample") != label:
                continue
            if result.get("operation") == "read":
                pages[result["page"]] = result
            if expected is not None and result.get("operation") == "fstat":
                if result.get("size") != FIXTURE_SIZE:
                    raise RuntimeError(f"{label}: {mode} metadata failed: {result}")
            if result.get("operation") == completion:
                if expected is not None:
                    for page, byte in enumerate(expected, start=1):
                        if pages.get(page, {}).get("bytes") != [byte]:
                            raise RuntimeError(f"{label}: {mode} page {page}: {pages.get(page)}, expected {[byte]}")
                break


def command(processes, label):
    for _, process, _ in processes:
        if process.poll() is None:
            process.stdin.write(label + "\n")
            process.stdin.flush()


def sample(processes, label, evidence, expected=None):
    # Start both observers before waiting: a blocked fd must not postpone the
    # mapped probe until the extension has resumed or withdrawn its pages.
    command(processes, label)
    collect(processes, label, evidence, expected)


def healthy_probes(path, alias, processes, evidence):
    sample(processes, "warm", evidence, [65, 65])
    with path.open("r+b", buffering=0) as file:
        file.write(b"B" * FIXTURE_SIZE)
        os.fsync(file.fileno())
    sample(processes, "local-alias-write-expect-66", evidence, [66, 66])
    with alias.open("r+b", buffering=0) as file:
        file.truncate(PAGE_SIZE)
        file.truncate(FIXTURE_SIZE)
        os.fsync(file.fileno())
    sample(processes, f"alias-truncate-expect-66-0-size{FIXTURE_SIZE}", evidence, [66, 0])
    with path.open("r+b", buffering=0) as file:
        file.write(b"A" * FIXTURE_SIZE)
        os.fsync(file.fileno())
    sample(processes, "rewarm-expect-65", evidence, [65, 65])


def loss_procedure(case, relative_path, processes, evidence):
    mutation = (f"Through Linux overwrite {relative_path} IN PLACE from offset 0 with {FIXTURE_SIZE} bytes of 76 "
                f"(two {PAGE_SIZE}-byte Mac VM pages, sampled at offsets {PAGE_OFFSETS}), "
                "fsync and preserve its inode; retain command output and timestamps")
    if case == "extension-stall":
        checkpoint("STOP the extension (SIGSTOP); record PID/status, last proof and exclusion deadline. Keep it stopped through the Linux mutation and Mac samples", evidence)
        checkpoint("While stopped and before exclusion ends, prove Linux write-intent OPEN is refused EBUSY; retain exact errno and authority timestamps. Then fence the Mac writer/stop its renewals at the authority, without resuming the extension; record the final promised exclusion", evidence)
        checkpoint("WAIT for the recorded authority exclusion end AND admitted-storage drain; record actual end evidence. Extension must remain stopped", evidence)
        checkpoint(mutation + " WHILE THE EXTENSION IS STILL STOPPED", evidence)
        sample(processes, "stopped-after-linux-mutation", evidence)
        checkpoint("Record stale byte 65 and partial successes as residuals. Now RESUME the extension; record resume timestamp and wait for actual revoke completion for this fixture, including errors", evidence)
        sample(processes, "resumed-after-withdrawal", evidence)
        return
    if case == "sleep-wake":
        checkpoint("Arrange a Linux operator/job to prove early EBUSY, wait for recorded exclusion end AND storage drain, then " + mutation + " DURING MAC SLEEP. Retain the sleep interval, exclusion end and mutation/fsync timestamps", evidence)
        command(processes, "arm:sleep-wake-continuous")
        collect(processes, "arm:sleep-wake-continuous", evidence, completion="armed")
        checkpoint("Observers are ARMED. Sleep the Mac now, let Linux complete the ordered mutation during sleep, then wake. Observers record first scheduled reads on wake before this prompt returns; record exact sleep/wake times and Linux evidence", evidence)
        checkpoint("Keep observers running until actual fixture revoke completion; record withdrawal timestamps/errors and any old byte 65 seen on wake as a residual", evidence)
        command(processes, "disarm")
        collect(processes, "disarm", evidence, completion="disarmed")
        sample(processes, "wake-after-withdrawal", evidence)
        return
    checkpoint(f"Inject {case}; record actual proof horizon/authorization deadline and setCacheState outcomes", evidence)
    if case == "proof-expiry":
        checkpoint("Keep session authorized/usable while withholding renewal past the recorded horizon. Require successful invalidate and noCache grant; record fixture READ/miss counters BEFORE the following post-expiry samples", evidence)
        sample(processes, "proof-expired", evidence)
        ranges = " and ".join(f"[{offset}, {offset + PAGE_SIZE})" for offset in PAGE_OFFSETS)
        checkpoint(f"Retain actual POST-EXPIRY fixture READ/miss trace and authority READ counter delta, with timestamps and ranges correlated to both Mac VM pages {ranges}. Read-ahead may cover both pages in one authority READ; two requests are not required. Unchanged byte 65, noCache and setCacheState success alone do not prove invalidation", evidence)
        checkpoint("Restore renewal and require readCache eligibility", evidence)
        sample(processes, "proof-recovered", evidence)
        checkpoint("Now end writer ownership, retaining its terminal revoke results", evidence)
    checkpoint("Prove early Linux write-intent OPEN refused EBUSY; then wait for recorded authority exclusion end AND admitted-storage drain", evidence)
    checkpoint(mutation, evidence)
    sample(processes, "after-linux-mutation", evidence)
    checkpoint("Require actual fixture revoke completion, including errors; a callback gate alone is insufficient", evidence)
    sample(processes, "after-withdrawal", evidence)


def retained_permissions(directory, evidence):
    if os.geteuid() == 0:
        raise RuntimeError("native permission qualification requires an unprivileged mount user")
    path = directory / "retained-permissions"
    created = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    retained = None
    try:
        assert os.pwrite(created, b"held", 0) == 4
        os.fsync(created)
        retained = os.open(path, os.O_RDONLY)
        os.chmod(path, 0)
        assert os.pread(retained, 4, 0) == b"held"
        assert os.pwrite(created, b"live", 0) == 4
        os.fsync(created)
        assert os.pread(retained, 4, 0) == b"live"
        evidence.write(json.dumps({"time_ns": time.time_ns(), "permission_probe": "chmod-000-retained-read-write-succeeded"}) + "\n")
        evidence.flush()
        os.close(retained)
        retained = None
        os.close(created)
        created = None
        try:
            reopened = os.open(path, os.O_RDONLY)
        except OSError as error:
            evidence.write(json.dumps({"time_ns": time.time_ns(), "permission_probe": "close-reopen", "errno": error.errno}) + "\n")
            evidence.flush()
            if error.errno != errno.EACCES:
                raise
        else:
            os.close(reopened)
            raise RuntimeError("fresh read open after chmod 000 and final close unexpectedly succeeded")
        os.chmod(path, 0o600)
        reopened = os.open(path, os.O_RDONLY)
        try:
            assert os.pread(reopened, 4, 0) == b"live"
        finally:
            os.close(reopened)
        evidence.write(json.dumps({"time_ns": time.time_ns(), "permission_probe": "chmod-600-reopen-succeeded"}) + "\n")
        evidence.flush()
    finally:
        if retained is not None:
            os.close(retained)
        if created is not None:
            os.close(created)
        os.chmod(path, 0o600)


def open_unlinked(directory):
    path = directory / "open-unlinked"
    alias = directory / "open-unlinked-alias"
    path.write_bytes(b"held")
    os.link(path, alias)
    fd = os.open(alias, os.O_RDWR)
    try:
        os.unlink(path)
        os.unlink(alias)
        assert os.pread(fd, 4, 0) == b"held"
        assert os.pwrite(fd, b"live", 0) == 4
        os.ftruncate(fd, 2)
        os.fsync(fd)
        assert os.pread(fd, 4, 0) == b"li"
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mount", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reader", choices=("fd", "mapped"), help=argparse.SUPPRESS)
    parser.add_argument("--path", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.reader:
        reader(args.path, args.reader)
        return
    if not args.mount or not args.output:
        parser.error("--mount and --output are required")
    if platform.system() != "Darwin" or int(platform.mac_ver()[0].split(".")[0]) < 27:
        parser.error("this native battery requires macOS 27")
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / "operator.jsonl").open("w") as evidence, (args.output / "kernel-cache.jsonl").open("w") as kernel_log:
        evidence.write(json.dumps({"time_ns": time.time_ns(), "page_size": PAGE_SIZE,
                                   "offsets": PAGE_OFFSETS, "fixture_size": FIXTURE_SIZE}) + "\n")
        evidence.flush()
        log = subprocess.Popen(["/usr/bin/log", "stream", "--style", "ndjson", "--level", "debug", "--predicate",
                                'subsystem == "dev.portablefs.fskit" AND (category == "KernelCache" OR category == "PortableFSVolume")'], stdout=kernel_log, stderr=kernel_log)
        try:
            for case in CASES:
                checkpoint(f"{case}: prepare a fresh healthy dev mount at {args.mount}; record signed build/OS/authority identity", evidence)
                directory = args.mount / ("kernel-cache-" + case)
                directory.mkdir()
                path = directory / "file"
                alias_dir = directory / "alias-dir"
                alias_dir.mkdir()
                alias = alias_dir / "alias"
                with path.open("wb", buffering=0) as file:
                    file.write(b"A" * FIXTURE_SIZE)
                    os.fsync(file.fileno())
                os.link(path, alias)
                open_unlinked(directory)
                retained_permissions(directory, evidence)
                processes = []
                outputs = []
                try:
                    for mode in ("fd", "mapped"):
                        artifact = args.output / f"{case}-{mode}.jsonl"
                        output = artifact.open("w")
                        errors = (args.output / f"{case}-{mode}.stderr").open("w")
                        outputs.extend((output, errors))
                        process = subprocess.Popen([sys.executable, __file__, "--reader", mode, "--path", str(alias)], stdin=subprocess.PIPE, stdout=output, stderr=errors, text=True)
                        observed = artifact.open("r")
                        outputs.append(observed)
                        processes.append((mode, process, observed))
                        deadline = time.monotonic() + 10
                        while not (ready := observed.readline()):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError(f"{mode} reader did not become ready; inspect {artifact}")
                            time.sleep(0.01)
                        evidence.write(ready)
                        evidence.flush()
                        if "ready" not in json.loads(ready):
                            raise RuntimeError(f"{mode} reader failed to initialize")
                    checkpoint("Require cache grant read_cache=true for the fixture and retain authority cold/warm READ counts; warm fd/mapped pages must actually use readCache", evidence)
                    healthy_probes(path, alias, processes, evidence)
                    loss_procedure(case, path.relative_to(args.mount), processes, evidence)
                    checkpoint("Inspect page-by-page fd/mapped artifacts, independent fstat outcomes, exits/SIGBUS and all withdrawal errors; record residual stale reads honestly", evidence)
                    checkpoint("Review healthy open-unlinked probe: require no revoke caused solely by unlink; compare its timestamps with cache actions", evidence)
                finally:
                    for _, process, _ in processes:
                        if process.poll() is None:
                            process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    for output in outputs:
                        output.close()
        finally:
            if log.poll() is None:
                log.send_signal(signal.SIGINT)
                try:
                    log.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    log.kill()
                    log.wait()
    print("Evidence collected; native qualification requires review of all artifacts and residuals. No automatic pass claimed.")


if __name__ == "__main__":
    main()
