#!/usr/bin/env python3
"""Interactive native correctness battery for a deployed macOS 27 dev build.

Run locally, never against an undeployed lab build:
  python3 scripts/test-macos27-kernel-cache.py --mount /Volumes/pfs --output /tmp/pfs-cache-run

Use a disposable authority volume with a Linux reader/writer mount. The operator
owns deployment, fault injection, writer-exclusion evidence, and Linux writes;
this script does not deploy, contact another host, or force-unmount anything.
Keep the authority/daemon logs and exact signed build identity with the output.

For each loss case, record authority exclusion ending before attempting the
Linux write; an early write must fail EBUSY. Then Linux must overwrite BOTH the
first and second 4096-byte pages of the named fixture with byte 76, fsync it,
and preserve its inode. Existing Mac descriptors/mappings must not serve their
old byte 65 after successful withdrawal. A SIGBUS is an observed revoke result,
not a script crash: mapped readers run in separate subprocesses.

A proof-expiry-only case must keep the authority session authorized/usable while
withholding renewal replies past the actual proof horizon. Verify an invalidate
success and a noCache reopen, then let renewal recover. For writer/authorization
loss and daemon death require revoke results. Extension stall and sleep/wake
explicitly examine residual races; record stale results without calling them a
qualification pass. Per-item results do not prove negative-name/attribute or
complete directory withdrawal. Do not infer withdrawal from callback-gate logs.
"""
import argparse
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


def emit(value):
    print(json.dumps({"time_ns": time.time_ns(), **value}), flush=True)


def reader(path, mode):
    fd = os.open(path, os.O_RDONLY)
    mapping = mmap.mmap(fd, 8192, access=mmap.ACCESS_READ) if mode == "mapped" else None
    emit({"ready": mode, "inode": os.fstat(fd).st_ino})
    for line in sys.stdin:
        if line.strip() == "stop":
            break
        try:
            # Two different pages expose partial invalidation. The mapping is
            # MAP_SHARED and read-only; no writable-mmap promise is implied.
            data = bytes(mapping[:1] + mapping[4096:4097]) if mapping is not None else os.pread(fd, 1, 0) + os.pread(fd, 1, 4096)
            emit({"sample": line.strip(), "mode": mode, "bytes": list(data), "size": os.fstat(fd).st_size})
        except OSError as error:
            emit({"sample": line.strip(), "mode": mode, "errno": error.errno, "error": str(error)})
    if mapping is not None:
        mapping.close()
    os.close(fd)


def checkpoint(label, evidence):
    print(label, flush=True)
    answer = input("Record action, authority exclusion evidence and observed errors; Enter to continue: ")
    evidence.write(json.dumps({"time_ns": time.time_ns(), "checkpoint": label, "operator": answer}) + "\n")
    evidence.flush()


def sample(processes, label, evidence, expected=None):
    for mode, process, output in processes:
        if process.poll() is not None:
            evidence.write(json.dumps({"sample": label, "mode": mode, "exit": process.returncode}) + "\n")
            if expected is not None:
                raise RuntimeError(f"healthy {mode} reader exited")
            continue
        process.stdin.write(label + "\n")
        process.stdin.flush()
        deadline = time.monotonic() + 10
        while True:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=max(0, deadline - time.monotonic())):
                    evidence.write(json.dumps({"sample": label, "mode": mode, "stalled": True}) + "\n")
                    if expected is not None:
                        raise RuntimeError(f"healthy {mode} read stalled")
                    break
            line = process.stdout.readline()
            output.write(line)
            output.flush()
            result = json.loads(line) if line else {"exit": process.poll()}
            evidence.write(json.dumps({"requested_sample": label, "mode": mode, "result": result}) + "\n")
            # A previously stalled read may finish after a later checkpoint.
            # Keep its original label rather than attributing it to a new read.
            if line and result.get("sample") != label:
                continue
            if expected is not None and result.get("bytes") != expected:
                raise RuntimeError(f"{label}: {mode} observed {result}, expected {expected}")
            break
    evidence.flush()


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
                    file.write(b"A" * 8192)
                    os.fsync(file.fileno())
                os.link(path, alias)
                open_unlinked(directory)
                processes = []
                outputs = []
                try:
                    for mode in ("fd", "mapped"):
                        output = (args.output / f"{case}-{mode}.jsonl").open("w")
                        outputs.append(output)
                        process = subprocess.Popen([sys.executable, __file__, "--reader", mode, "--path", str(alias)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=output, text=True)
                        processes.append((mode, process, output))
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stdout, selectors.EVENT_READ)
                            if not selector.select(timeout=10):
                                process.kill()
                                process.wait()
                                raise RuntimeError(f"{mode} reader did not become ready")
                        ready = process.stdout.readline()
                        output.write(ready)
                        output.flush()
                        if "ready" not in json.loads(ready):
                            raise RuntimeError(f"{mode} reader failed to initialize")
                    checkpoint("Require cache grant read_cache=true for the fixture and retain authority cold/warm READ counts; warm fd/mapped pages must actually use readCache", evidence)
                    sample(processes, "warm", evidence, [65, 65])
                    with path.open("r+b", buffering=0) as file:
                        file.write(b"B" * 8192)
                        os.fsync(file.fileno())
                    sample(processes, "local-alias-write-expect-66", evidence, [66, 66])
                    with alias.open("r+b", buffering=0) as file:
                        file.truncate(4096)
                        file.truncate(8192)
                        os.fsync(file.fileno())
                    sample(processes, "alias-truncate-expect-66-0-size8192", evidence, [66, 0])
                    with path.open("r+b", buffering=0) as file:
                        file.write(b"A" * 8192)
                        os.fsync(file.fileno())
                    sample(processes, "rewarm-expect-65", evidence, [65, 65])
                    checkpoint(f"Inject {case}. Record actual horizon/deadline and every setCacheState result/error from kernel-cache.jsonl", evidence)
                    sample(processes, "fault", evidence)
                    if case == "proof-expiry":
                        checkpoint("Keep session usable: require successful invalidate/noCache, read via both aliases, then restore renewal and require readCache eligibility", evidence)
                        sample(processes, "proof-recovered", evidence)
                        checkpoint("Now end writer ownership so Linux can eventually mutate after exclusion drains", evidence)
                    if case in ("extension-stall", "sleep-wake"):
                        checkpoint("Observe retained reads while stopped or immediately on wake, then resume the extension; classify stale access as a residual", evidence)
                        sample(processes, "residual-window", evidence)
                    checkpoint(f"Prove early Linux write refused EBUSY, then authority exclusion ended. Through Linux overwrite {path.relative_to(args.mount)} in place with 8192 bytes of 76 and fsync; retain command output", evidence)
                    sample(processes, "after-linux-mutation", evidence)
                    checkpoint("Inspect fd/mapped artifacts and syscall errors or SIGBUS. Require actual invalidate/revoke completion; record stale old bytes and all withdrawal failures. A callback gate alone is insufficient", evidence)
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
