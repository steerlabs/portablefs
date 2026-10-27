#!/usr/bin/env python3
"""Fixed Linux metadata acceptance lane. Run inside the measured Linux guest.

This runner never provisions or reconfigures a VM/container. Configuration names
two already mounted paths on the same dedicated READY volume, a clean native
checkout of the pinned corpus, its local bare source, a warm native npm cache,
an authority metrics URL, and exact `portablefs mount-loss ... --json` commands.
All evidence, including raw command stdout/stderr, stays outside both mounts.
See benchmarks/linux-metadata.md for preparation and evidence requirements.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import urllib.request


HERE = Path(__file__).resolve().parent
DEFAULT_HOLD = Path("/Users/timjang/.local/state/portablefs-tests/linux-workspace/HOLD")
PROCESS_VERSION = 1


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def percentile(values, q):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def require_no_hold(path):
    if path.exists():
        raise RuntimeError(f"compute HOLD remains present: {path}")


def checked(argv, cwd=None, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{argv!r}: exit {result.returncode}: {result.stderr.decode(errors='replace')}")
    return result.stdout


def path_set(data):
    return sorted(set(p.removeprefix(b"./") for p in data.split(b"\0") if p))


def tree_manifest(root):
    """Content, symlinks and executable bits; no timestamps or .git internals."""
    h, count, size, directory_count = hashlib.sha256(), 0, 0, 0
    for parent, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d != ".git")
        names = sorted(files + [d for d in directories if Path(parent, d).is_symlink()])
        directories[:] = [d for d in directories if not Path(parent, d).is_symlink()]
        for name in directories:
            relative = os.fsencode(str(Path(parent,name).relative_to(root)))
            h.update(relative+b"\0directory\0")
            directory_count+=1
        for name in names:
            path = Path(parent, name)
            relative = os.fsencode(str(path.relative_to(root)))
            st = path.lstat()
            if path.is_symlink():
                payload, kind = os.fsencode(os.readlink(path)), b"link"
                checksum = digest(payload)
                size += len(payload)
            else:
                kind = b"exec" if st.st_mode & 0o111 else b"file"
                checksum = file_hash(path)
                size += st.st_size
            h.update(relative + b"\0" + kind + b"\0" + checksum.encode() + b"\0")
            count += 1
    return {"sha256": h.hexdigest(), "files": count, "bytes": size, "directories":directory_count}


def parse_prometheus(data):
    counters = {}
    for line in data.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        match = re.fullmatch(r'(portablefs_[a-zA-Z0-9_:]+(?:\{[^\n]*\})?) ([^ ]+)(?: [^ ]+)?', line)
        if match:
            value = int(match[2]) if match[2].isdigit() else float(match[2])
            if not math.isfinite(value):
                raise ValueError("nonfinite metric")
            counters[match[1]] = value
    if not any(k.startswith("portablefs_authority_rpc_requests_total") for k in counters):
        raise ValueError("authority RPC counters absent")
    return counters


def counter_delta(before, after):
    result = {}
    for key in sorted(before.keys() | after.keys()):
        # Prometheus creates opcode/outcome labels lazily. A newly appearing
        # counter starts at zero; a disappearing series invalidates the sample.
        if key not in after:
            raise ValueError(f"counter disappeared: {key}")
        value = after[key] - before.get(key, 0)
        if value < 0:
            raise ValueError(f"counter decreased: {key}")
        result[key] = value
    return result


COUNTERS = ["notifications", "notificationNanos", "notificationFailures", "metadataHits", "metadataMisses", "pageHits", "pageMisses", "openHits", "openMisses",
            "missAbsent", "missAttributes", "missWithdrawn", "missOwnership", "missFinalPublication",
            "singleFlightWaits", "capacityEvictions", "invalidations", "rtcReads", "rtcNanos",
            "rtcFailures", "coldInstalls", "withdrawals", "withdrawalNanos"]


def snapshot(config, mount):
    start = time.monotonic_ns()
    daemon = json.loads(checked(mount["snapshot"]))
    metadata = daemon["metadata"]
    for key in COUNTERS + ["pid", "processStart", "fuseOperations", "payloadBytes", "payloadLimit",
                           "names", "pages", "backings", "pendingFills", "incarnation", "terminal"]:
        if key not in metadata:
            raise ValueError(f"missing daemon series: {key}")
    if not 0<=metadata["payloadBytes"]<=metadata["payloadLimit"] or metadata["payloadLimit"]!=128*1024*1024 or not 0<=metadata["names"]<=65536 or not 0<=metadata["backings"]<=8192:
        raise ValueError("daemon cache resource bounds violated")
    if len(metadata["fuseOperations"])!=106:
        raise ValueError("FUSE counter inventory differs")
    pid = int(metadata["pid"])
    status = Path(f"/proc/{pid}/status").read_text()
    memory = {m[1]: int(m[2]) * 1024 for m in re.finditer(r"^(VmRSS|VmHWM):\s+(\d+) kB$", status, re.M)}
    with urllib.request.urlopen(config["authority_metrics_url"], timeout=5) as response:
        metrics = response.read().decode()
    # Process-start is mandatory: an increasing counter after restart remains
    # incomparable. Capture the exact raw scrape and its own observation window.
    starts = re.findall(r"^portablefs_authority_process_start_unix_nanos(?:\{[^}]*\})? (\d+)$", metrics, re.M)
    if len(starts) != 1:
        raise ValueError("authority process-start witness missing")
    return {"start_ns": start, "end_ns": time.monotonic_ns(), "daemon": daemon,
            "authority_start": starts[0], "metrics": metrics, "memory": memory}


def observation_delta(before, after):
    b, a = before["daemon"]["metadata"], after["daemon"]["metadata"]
    if (b["pid"], b["processStart"], before["authority_start"]) != (a["pid"], a["processStart"], after["authority_start"]):
        raise ValueError("daemon or authority restarted")
    counters = counter_delta({k: b[k] for k in COUNTERS}, {k: a[k] for k in COUNTERS})
    if len(b["fuseOperations"]) != len(a["fuseOperations"]):
        raise ValueError("FUSE counter inventory changed")
    counters["fuseOperations"] = counter_delta(dict(enumerate(b["fuseOperations"])), dict(enumerate(a["fuseOperations"])))
    # Only counter series are differenced. Histograms/gauges and raw scrapes
    # remain inspectable, without treating a lifetime high-water as a delta.
    rpc_b = {k: v for k, v in parse_prometheus(before["metrics"]).items() if k.startswith("portablefs_authority_rpc_requests_total")}
    rpc_a = {k: v for k, v in parse_prometheus(after["metrics"]).items() if k.startswith("portablefs_authority_rpc_requests_total")}
    counters["rpc"] = counter_delta(rpc_b, rpc_a)
    if a["terminal"] or a["incarnation"] != b["incarnation"] or counters["coldInstalls"]:
        raise ValueError("terminal/cold recovery crossed measurement")
    return counters


def barrier_worker(body):
    request = json.loads(body)
    result = Path(request["result"])
    state = {"stage": "opening-root", "exit_status": None, "barrier": None}
    result.write_text(json.dumps(state))
    root_fd = None
    try:
        root_fd = os.open(request["root"], os.O_RDONLY | os.O_DIRECTORY)
        state["stage"] = "command"
        started = time.monotonic_ns()
        process = subprocess.Popen(request["argv"])
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        state.update(exit_status=process.returncode, pid=process.pid,
                     command_seconds=(time.monotonic_ns() - started) / 1e9,
                     command_maxrss_bytes=usage.ru_maxrss * 1024)
        state["stage"] = "barrier" if process.returncode == 0 else "command-failed"
        result.write_text(json.dumps(state))
        if process.returncode == 0:
            started = time.monotonic_ns()
            try:
                os.fsync(root_fd)
                state["barrier"] = {"exit_status": 0}
            except OSError as failure:
                state["barrier"] = {"exit_status": failure.errno, "error": str(failure)}
            state["barrier"]["elapsed_seconds"] = (time.monotonic_ns() - started) / 1e9
        state["stage"] = "complete"
    except OSError as failure:
        state["error"] = str(failure)
    finally:
        if root_fd is not None:
            os.close(root_fd)
        result.write_text(json.dumps(state))
    return 0 if state["stage"] == "complete" else 125


def run_process(argv, cwd, evidence, name, env, timeout, root=None):
    """No shell/pipeline; the deadline includes root open, command and barrier.

    A controller child keeps blocking FUSE barriers out of this runner. Its
    local evidence records command status before fsync, so a timed-out barrier
    cannot erase a successful command or turn the run into a timing success.
    """
    stdout, stderr = evidence / f"{name}.stdout", evidence / f"{name}.stderr"
    control = evidence / f"{name}.barrier.json"
    executed = argv
    if root:
        executed = [sys.executable, str(Path(__file__).resolve()), "--barrier-worker",
                    json.dumps({"argv": argv, "root": str(root), "result": str(control)})]
    expired = threading.Event()
    started = time.monotonic_ns()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(executed, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)

        def terminate():
            expired.set()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(timeout, terminate)
        timer.start()
        try:
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        finally:
            timer.cancel()
        finished = time.monotonic_ns()
    worker = json.loads(control.read_text()) if root and control.exists() else {}
    return {"argv": argv, "cwd": str(cwd), "pid": worker.get("pid", process.pid),
            "controller_pid": process.pid, "controller_exit_status": process.returncode,
            "exit_status": worker.get("exit_status") if worker.get("exit_status") is not None else process.returncode,
            "timed_out": expired.is_set(), "started_ns": started, "finished_ns": finished,
            "elapsed_seconds": (finished - started) / 1e9,
            "command_seconds": worker.get("command_seconds", (finished - started) / 1e9),
            "barrier": worker.get("barrier"), "barrier_worker": worker if root else None,
            "stdout": str(stdout), "stderr": str(stderr), "stdout_sha256": file_hash(stdout),
            "stderr_sha256": file_hash(stderr), "maxrss_bytes": usage.ru_maxrss * 1024,
            "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime}


def cold_content(root, paths):
    count = 0
    for relative in paths:
        path = root / os.fsdecode(relative)
        if not path.is_symlink() and path.is_file():
            fd = os.open(path, os.O_RDONLY)
            try:
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            finally:
                os.close(fd)
            count += 1
    return {"files_advised": count, "scope": "client clean file pages; authority cache warm"}


def summarize(samples, manifest):
    table = {}
    for workload, target in manifest["targets_p95_seconds"].items():
        table[workload] = {}
        for mount in ("ordinary", "workspace"):
            rows = [s for s in samples if s["workload"] == workload and s["mount"] == mount]
            valid = [s["process"]["elapsed_seconds"] for s in rows if s["valid"]]
            row = {"samples": len(rows), "valid": len(valid), "target_p95_seconds": target,
                   "passed": len(valid) == len(rows) and len(valid) >= manifest["minimum_repetitions"]}
            if valid:
                row.update(median_seconds=statistics.median(valid), p95_seconds=percentile(valid, 0.95))
                row["passed"] &= row["p95_seconds"] <= target
            table[workload][mount] = row
        ordinary, workspace = table[workload]["ordinary"], table[workload]["workspace"]
        if ordinary.get("median_seconds", 0) and workspace.get("median_seconds"):
            ratios = {"median": workspace["median_seconds"] / ordinary["median_seconds"],
                      "p95": workspace["p95_seconds"] / ordinary["p95_seconds"]}
            ratios["passed"] = all(ratios[k] <= limit for k, limit in manifest["ratio_targets"].items())
            table[workload]["workspace_to_ordinary"] = ratios
    return table


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=HERE / "benchmarks/linux-metadata.json")
    parser.add_argument("--hold-file", type=Path, default=DEFAULT_HOLD)
    parser.add_argument("--label", choices=("before", "after"), required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--prepare", action="store_true", help="prepare only this runner's dedicated data paths")
    args = parser.parse_args()
    require_no_hold(args.hold_file)
    if platform.system() != "Linux":
        parser.error("run inside the measured Linux guest")
    manifest = json.loads(args.manifest.read_text())
    config = json.loads(args.config.read_text())
    if args.repetitions < manifest["minimum_repetitions"]:
        parser.error("at least 20 alternating repetitions are required")
    if config.get("authority_state") != "READY" or config.get("shared_tree") is not True or not config.get("host_load_note"):
        parser.error("READY, shared-tree and host-load evidence are required")
    mounts = config["mounts"]
    if [m["name"] for m in mounts] != ["ordinary", "workspace"]:
        parser.error("exact ordinary/workspace mount roster required")
    roots = [Path(m["root"]).resolve(strict=True) for m in mounts]
    evidence = Path(config["evidence_directory"]).resolve()
    if any(evidence.is_relative_to(root) for root in roots):
        parser.error("evidence must be outside the mounts")
    evidence.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, **manifest["environment"])
    env["NPM_CONFIG_USERCONFIG"] = "/dev/null"
    for tool, expected in manifest["tools"].items():
        actual = checked([tool, "--version"], env=env).decode().splitlines()[0]
        if actual != expected:
            parser.error(f"{tool}: {actual!r}, expected pinned {expected!r}")
    reference = Path(config["native_reference"]).resolve(strict=True)
    revision = manifest["corpus"]["revision"]
    if checked(["git", "rev-parse", "HEAD"], reference, env).decode().strip() != revision:
        parser.error("native reference is not the pinned commit")
    if checked(manifest["commands"]["status_warm"], reference, env):
        parser.error("native reference has modifications or untracked files")
    if checked(["git", "--git-dir", config["bare_source"], "rev-parse", "HEAD"], env=env).decode().strip() != revision:
        parser.error("bare source HEAD is not the pinned commit")
    paths = path_set(checked(["git", "ls-files", "--cached", "-z"], reference, env))
    expected_todo = path_set(checked(manifest["commands"]["rg_warm"], reference, env))
    if len(paths)!=manifest["corpus"]["tracked_files"]:
        parser.error("tracked-file inventory differs from the fixed public corpus")
    frozen = {"manifest_sha256": file_hash(args.manifest), "revision": revision,
              "tracked_files": len(paths), "tree": tree_manifest(reference),
              "todo_paths_sha256": digest(b"\0".join(expected_todo)),
              "todo_paths": [os.fsdecode(p) for p in expected_todo], "tools": manifest["tools"],
              "npm_lock_sha256": file_hash(args.manifest.parent / manifest["npm_fixture"] / "package-lock.json")}
    if frozen["tree"]["bytes"]!=manifest["corpus"]["tracked_bytes"]:
        parser.error("tracked corpus byte inventory differs")
    (evidence / "reference.json").write_text(json.dumps(frozen, indent=2) + "\n")
    relative = config.get("corpus_relative", "perf-pr1-corpus")
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        parser.error("corpus_relative must remain within the dedicated mount")
    if args.prepare:
        destination = roots[0] / relative
        if destination.exists():
            parser.error("prepare refuses an existing corpus destination")
        require_no_hold(args.hold_file)
        prepared=run_process(["git","clone","--no-local",config["bare_source"],str(destination)],roots[0],evidence,"prepare",env,120,roots[0])
        (evidence/"preparation.json").write_text(json.dumps(prepared,indent=2)+"\n")
        if prepared["exit_status"]!=0 or prepared["controller_exit_status"]!=0 or prepared["timed_out"] or (prepared["barrier"] or {}).get("exit_status")!=0:
            raise RuntimeError("corpus preparation failed; see preparation.json")
        print(evidence)
        return 0
    for root in roots:
        if not os.path.ismount(root) or tree_manifest(root / relative) != frozen["tree"]:
            parser.error(f"mounted corpus differs from the pinned reference: {root}")
    fixture = args.manifest.parent / manifest["npm_fixture"]
    # Freeze the exact successful native install before any mounted timings.
    # A broad file-count range alone cannot detect an incomplete installation.
    npm_reference = evidence / "npm-reference"
    npm_reference.mkdir()
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(fixture / name, npm_reference / name)
    npm_argv = [a.format(npm_cache=config["npm_cache"]) for a in manifest["commands"]["npm_fresh"]]
    require_no_hold(args.hold_file)
    npm_oracle = run_process(npm_argv, npm_reference, evidence, "native-npm-reference", env, 120)
    (evidence / "native-npm-reference.json").write_text(json.dumps(npm_oracle, indent=2) + "\n")
    if npm_oracle["exit_status"] or npm_oracle["controller_exit_status"] or npm_oracle["timed_out"]:
        raise RuntimeError("native npm fixture failed; see native-npm-reference.json")
    if file_hash(npm_reference / "package-lock.json") != frozen["npm_lock_sha256"]:
        raise RuntimeError("pinned npm changed the fixture lockfile")
    frozen["npm_tree"] = tree_manifest(npm_reference)
    frozen["npm_module_files"] = sum(len(files) for _, _, files in os.walk(npm_reference / "node_modules"))
    if not manifest["npm_expected_files_min"] <= frozen["npm_module_files"] <= manifest["npm_expected_files_max"]:
        raise RuntimeError("native npm file count is outside the fixture range")
    (evidence / "reference.json").write_text(json.dumps(frozen, indent=2) + "\n")
    samples = []
    run_id = f"perf-pr1-{args.label}-{time.time_ns()}"
    report = {"completed": False, "schema": PROCESS_VERSION, "label": args.label, "run_id": run_id,
              "source_commit": config["source_commit"], "image_identity": config["image_identity"],
              "host_load_note": config["host_load_note"], "manifest": manifest, "reference": frozen,
              "kernel": platform.uname()._asdict(), "samples": samples,
              "fuse_count_scope": "completed stock kernel requests by opcode; separate reverse notification attempts/failures/time",
              "cold_content_scope": manifest["cold_content_scope"]}
    ping_file = (evidence / "rtt.stdout").open("wb")
    ping = subprocess.Popen(config["rtt_command"], stdout=ping_file, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        for repetition in range(args.repetitions):
            order = mounts if repetition % 2 == 0 else list(reversed(mounts))
            for mount in order:
                root = Path(mount["root"]).resolve()
                corpus = root / relative
                for workload in manifest["targets_p95_seconds"]:
                    require_no_hold(args.hold_file)
                    name = f"{repetition:02d}-{mount['name']}-{workload}"
                    cwd, barrier, validation = corpus, None, []
                    npm_relative = f"{run_id}/{repetition:02d}-{mount['name']}-npm"
                    destination = root / run_id / f"clone-{repetition:02d}-{mount['name']}"
                    substitutions = {"bare_source": config["bare_source"], "destination": str(destination), "npm_cache": config["npm_cache"]}
                    row = {"repetition": repetition, "mount": mount["name"], "workload": workload, "valid": False, "errors": []}
                    try:
                        if workload in ("status_warm", "rg_warm"):
                            checked(manifest["commands"][workload], corpus, env)
                        elif workload == "rg_cold":
                            row["cold_content"] = cold_content(corpus, paths)
                        elif workload == "clone":
                            cwd, barrier = root, root
                            (root/run_id).mkdir(parents=True,exist_ok=True)
                        elif workload == "npm_fresh":
                            # Unique shared path per repetition; never remove
                            # another run's node_modules or package cache.
                            cwd = root / npm_relative
                            cwd.mkdir(parents=True, exist_ok=False)
                            for source in ("package.json", "package-lock.json"):
                                shutil.copyfile(fixture / source, cwd / source)
                            barrier = root
                        elif workload == "npm_noop":
                            cwd, barrier = root / npm_relative, root
                        elif workload == "expand_warm":
                            cwd = root / run_id / "expand"
                            if not cwd.exists():
                                cwd.mkdir(parents=True)
                                for i in range(manifest["expansion_entries"]):
                                    (cwd / f"entry-{i:04d}").write_bytes(b"")
                            checked([sys.executable, "-c", "import os; print('\\n'.join(sorted(os.listdir('.'))))"], cwd, env)
                        if ping.poll() is not None:
                            raise RuntimeError("continuous RTT collector stopped")
                        before = snapshot(config, mount)
                        if workload == "expand_warm":
                            argv = [sys.executable, "-c", "import os; print('\\n'.join(sorted(os.listdir('.'))))"]
                        else:
                            argv = [a.format(**substitutions) for a in manifest["commands"][workload]]
                        process = run_process(argv, cwd, evidence, name, env, 120, barrier)
                        row["process"] = process
                        after = snapshot(config, mount)
                        row.update(before=before, after=after, counters=observation_delta(before, after))
                        if process["exit_status"] != 0 or process["timed_out"] or process["controller_exit_status"] != 0:
                            validation.append("command failed or timed out")
                        if barrier and (process["barrier"] or {}).get("exit_status") != 0:
                            validation.append("root barrier failed")
                        output = Path(process["stdout"]).read_bytes()
                        if workload == "status_warm":
                            if output:
                                validation.append("status is not clean")
                            rpc = row["counters"]["rpc"]
                            if row["counters"]["openMisses"] or any(v for k, v in rpc.items() if re.search(r'opcode="(?:readdir|read_dir)"', k)):
                                validation.append("unchanged warm directories issued OPEN/READDIR RPCs")
                        elif workload.startswith("rg_") and path_set(output) != expected_todo:
                            validation.append("TODO path set differs from exact pinned expectation")
                        elif workload == "clone" and process["exit_status"] == 0:
                            destination = Path(substitutions["destination"])
                            checked(["git", "fsck", "--full"], destination, env)
                            peer_root = next(Path(m["root"]) for m in mounts if m["name"] != mount["name"])
                            if tree_manifest(destination) != frozen["tree"] or tree_manifest(peer_root / destination.relative_to(root)) != frozen["tree"]:
                                validation.append("clone integrity/peer tree differs")
                        elif workload in ("npm_fresh", "npm_noop") and process["exit_status"] == 0:
                            actual_tree = tree_manifest(cwd)
                            row["npm_tree"] = actual_tree
                            row["npm_files"] = sum(len(files) for _, _, files in os.walk(cwd / "node_modules"))
                            if actual_tree != frozen["npm_tree"] or row["npm_files"] != frozen["npm_module_files"]:
                                validation.append("npm install differs from exact successful native tree")
                            if file_hash(cwd / "package-lock.json") != frozen["npm_lock_sha256"]:
                                validation.append("npm changed the pinned lockfile")
                            peer_root = next(Path(m["root"]) for m in mounts if m["name"] != mount["name"])
                            if actual_tree != tree_manifest(peer_root / cwd.relative_to(root)):
                                validation.append("npm peer tree differs")
                        elif workload == "expand_warm":
                            expected = b"\n".join(f"entry-{i:04d}".encode() for i in range(manifest["expansion_entries"])) + b"\n"
                            if output != expected:
                                validation.append("expansion inventory differs")
                        row["errors"].extend(validation)
                        row["valid"] = not row["errors"]
                    except Exception as failure:
                        row["errors"].append(f"{type(failure).__name__}: {failure}")
                    # Cleanup is outside the measured window, uses only this
                    # unique run's paths, and retains its own status/barrier.
                    cleanup_path=None
                    if workload=="clone":
                        cleanup_path=destination
                    elif workload=="npm_noop":
                        cleanup_path=cwd
                    if cleanup_path is not None and cleanup_path.is_relative_to(root/run_id) and cleanup_path.exists():
                        cleanup=run_process([sys.executable,"-c","import shutil,sys; shutil.rmtree(sys.argv[1])",str(cleanup_path)],root,evidence,name+"-cleanup",env,120,root)
                        row["cleanup"]=cleanup
                        if cleanup["exit_status"]!=0 or cleanup["timed_out"] or (cleanup["barrier"] or {}).get("exit_status")!=0:
                            row["errors"].append("owned workload cleanup/barrier failed")
                            row["valid"]=False
                    samples.append(row)
                    (evidence / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        ping.send_signal(signal.SIGINT)
        try:
            report["rtt_exit_status"] = ping.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ping.kill()
            report["rtt_exit_status"] = ping.wait(timeout=5)
            report["rtt_collector_error"] = "RTT collector did not stop after SIGINT"
        ping_file.close()
        (evidence / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    report["completed"] = True
    rtt_output = (evidence / "rtt.stdout").read_text()
    rtt = [float(v) for v in re.findall(r"time[=<]([\d.]+) ms", rtt_output)]
    packets = re.search(r"(\d+) packets transmitted, (\d+) received", rtt_output)
    report["rtt"] = {"samples": len(rtt), "stdout_sha256": file_hash(evidence / "rtt.stdout"),
                     "transmitted": int(packets[1]) if packets else None,
                     "received": int(packets[2]) if packets else None}
    if rtt:
        report["rtt"].update(p50_ms=percentile(rtt, .5), p99_ms=percentile(rtt, .99), max_ms=max(rtt))
    report["rtt"]["qualified"] = report["rtt_exit_status"] == 0 and packets is not None and int(packets[1]) == int(packets[2]) and len(rtt)>=20 and percentile(rtt, .5) <= manifest["rtt_targets_ms"]["p50"] and percentile(rtt, .99) <= manifest["rtt_targets_ms"]["p99"]
    report["table"] = summarize(samples, manifest)
    report["qualified"] = report["rtt"]["qualified"] and all(row[m]["passed"] for row in report["table"].values() for m in ("ordinary", "workspace", "workspace_to_ordinary") if m in row)
    (evidence / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"evidence": str(evidence), "qualified": report["qualified"], "table": report["table"]}, indent=2))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    if len(sys.argv)==3 and sys.argv[1]=="--barrier-worker":
        sys.exit(barrier_worker(sys.argv[2]))
    sys.exit(main())
