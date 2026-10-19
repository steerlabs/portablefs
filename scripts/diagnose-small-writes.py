#!/usr/bin/env python3
"""r3l supplemental small-write diagnostic, for separately reviewed lab runs.

Leaves all fixed acceptance runners unchanged. Precreate EMPTY files named
append-1..N and chunks-1..N under --directory on the tested filesystem. Supply
--authority-directory exposing those same files through an independent authority
read path (the operator must establish that provenance). No file is created,
truncated or removed by this script. Output goes outside the tested filesystem.
Use a fresh set for each --drain fsync or --drain close run and each artifact.

Exactly 10,000 unbuffered 100-byte O_APPEND writes and 64 MiB in 4 KiB writes,
without fsync/close inside either loop. Record write-loop acceptance separately
from final fsync/close and complete write+drain time. Close-only can expose where
unsynced drain moves; if the independent hash is not yet correct, preserve that
failure rather than waiting/polling until it matches. This is not an acceptance
or native durability qualification gate. No deployment/remote access is done.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import time

WORKLOADS = (("append", 10_000, 100, os.O_APPEND), ("chunks", 16_384, 4096, 0))


def distribution(values):
    ordered = sorted(values)
    return {name: ordered[min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1)]
            for name, percentile in (("p50_ns", .5), ("p95_ns", .95), ("p99_ns", .99), ("max_ns", 1))}


def inspect_file(path):
    sha = hashlib.sha256()
    length = 0
    with path.open("rb", buffering=0) as file:
        while data := file.read(1024 * 1024):
            length += len(data)
            sha.update(data)
    return {"length": length, "sha256": sha.hexdigest()}


def run_file(path, authority_path, name, count, size, flags, drain):
    payload = bytes(range(100)) if name == "append" else bytes(range(256)) * 16
    assert len(payload) == size
    expected_hash = hashlib.sha256()
    for _ in range(count):
        expected_hash.update(payload)
    fd = os.open(path, os.O_WRONLY | flags)
    metadata = os.fstat(fd)
    if metadata.st_size != 0:
        os.close(fd)
        raise ValueError(f"precreated file must be empty: {path}")
    latencies = []
    failure = None
    write_count = 0
    fsync_ns = None
    start = time.perf_counter_ns()
    try:
        for _ in range(count):
            began = time.perf_counter_ns()
            written = os.write(fd, payload)
            latencies.append(time.perf_counter_ns() - began)
            if written != size:
                raise OSError(f"short write: {written}/{size}")
            write_count += 1
    except OSError as error:
        failure = {"phase": "write", "errno": error.errno, "error": str(error)}
    loop_end = time.perf_counter_ns()
    if drain == "fsync":
        began = time.perf_counter_ns()
        try:
            os.fsync(fd)
        except OSError as error:
            failure = failure or {"phase": "fsync", "errno": error.errno, "error": str(error)}
        fsync_ns = time.perf_counter_ns() - began
    close_start = time.perf_counter_ns()
    try:
        os.close(fd)
    except OSError as error:
        failure = failure or {"phase": "close", "errno": error.errno, "error": str(error)}
    end = time.perf_counter_ns()
    expected = {"length": count * size, "sha256": expected_hash.hexdigest()}
    # One immediate independent observation. No retries, scraping or sleeps
    # can silently move the measured close-only completion boundary.
    try:
        actual = inspect_file(authority_path)
    except OSError as error:
        actual = {"errno": error.errno, "error": str(error)}
    return {"workload": name, "file": str(path), "authority_file": str(authority_path),
            "writes_required": count, "writes_completed": write_count, "write_size": size,
            "drain": drain, "loop_ns": loop_end - start, "write_ns": sum(latencies),
            "fsync_ns": fsync_ns, "close_ns": end - close_start, "write_and_drain_ns": end - start,
            "latency": distribution(latencies) if latencies else {}, "failure": failure,
            "expected": expected, "authority": actual, "verified": actual == expected and failure is None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--authority-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact", required=True, help="exact signed artifact/revision and OS/path/load evidence reference")
    parser.add_argument("--drain", choices=("fsync", "close"), default="fsync")
    parser.add_argument("--repetitions", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    if args.directory.resolve() == args.authority_directory.resolve():
        parser.error("authority verification must use an independent read path")
    if any(args.output.resolve().is_relative_to(root.resolve())
           for root in (args.directory, args.authority_directory)):
        parser.error("output must be outside the measured directory")
    failed = False
    with args.output.open("x") as output:
        output.write(json.dumps({"event": "identity", "time_ns": time.time_ns(), "os": platform.platform(),
                                 "artifact": args.artifact, "directory": str(args.directory),
                                 "authority_directory": str(args.authority_directory), "drain": args.drain,
                                 "authority_provenance": "operator-supplied independent authority read path"}) + "\n")
        output.flush()
        for repetition in range(1, args.repetitions + 1):
            for name, count, size, flags in WORKLOADS:
                filename = f"{name}-{repetition}"
                result = run_file(args.directory / filename, args.authority_directory / filename,
                                  name, count, size, flags, args.drain)
                output.write(json.dumps({"repetition": repetition, **result}) + "\n")
                output.flush()
                failed |= not result["verified"]
                print(json.dumps({"repetition": repetition, **result}), flush=True)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
