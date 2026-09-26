#!/usr/bin/env python3
"""Render the recorded v6/v7 baseline observations without changing their totals."""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROL_V7 = {"change_ack", "next_control_event", "renew_subscription", "subscribe", "delegation_release", "delegation_break_ack", "delegation_recall_ack", "delegation_mode_change_ack"}


def read_records(path):
    records = []
    for line in path.read_text().splitlines():
        if "PORTABLEFS_BASELINE {" in line:
            records.append(json.loads(line.split("PORTABLEFS_BASELINE ", 1)[1]))
        elif line.startswith('{"scenario":'):
            records.append(json.loads(line))
    assert len(records) == 10, (path, len(records))
    return records


def key(record):
    return record["scenario"], record["target"], record.get("workers", 0)


def kinds(record):
    return dict(record.get("authority_filesystem_breakdown", {}), **record.get("authority_control_breakdown", {}))


def label(record):
    return {"install": "Install (40,000 files, %d worker%s)" % (record.get("workers", 0), "" if record.get("workers") == 1 else "s"),
            "git-status-cold": "Git status cold (20,000 files)",
            "git-status-warm": "Git status warm (20,000 files)",
            "two-mount-write-list-read": "Two-mount write/list/read (2,000 files)"}[record["scenario"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run1", type=Path)
    parser.add_argument("run2", type=Path)
    args = parser.parse_args()
    assert args.run1.resolve() != args.run2.resolve(), "provide two distinct run logs"
    base = read_records(ROOT / "docs/coherence-v2/baseline.md")
    runs = [read_records(args.run1), read_records(args.run2)]
    indexed = [{key(r): r for r in records} for records in [base] + runs]
    for run in indexed:
        assert run.keys() == indexed[0].keys()
        for r in run.values():
            assert sum(kinds(r).values()) == r["authority_requests"]
            assert abs(r["authority_requests_per_operation"] - r["authority_requests"] / r["operations"]) < 1e-9
    durations = []
    for path in [args.run1, args.run2]:
        match = re.search(r"--- PASS: TestCoherenceBaseline \(([^)]+)\)", path.read_text())
        assert match, (path, "benchmark did not pass")
        durations.append(match.group(1))
    destination = ROOT / "vcs/bench/coherencebench/testdata/results"
    destination.mkdir(parents=True, exist_ok=True)
    for number, records in enumerate(runs, 1):
        (destination / f"v7-run{number}.jsonl").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))
    out = ["# Protocol 7 measurement results\n",
           "Product revision: `5f76079`; v6 reference: `67c52ef`. Two unprofiled runs use the unchanged `TestCoherenceBaseline` workload and meter. Raw observations are in `vcs/bench/coherencebench/testdata/results/v7-run{1,2}.jsonl`.\n",
           "## Method and environment\n",
           "Both runs use the method in [baseline.md](baseline.md): 40,000 1 KiB files and 2,000 directories with 1 and 8 workers (42,000 operations); cold then immediate warm ordinary `git status --porcelain=v1` on 20,000 committed 1 KiB files (20,000 operations); and 2,000 published and verified files across two mounts (4,000 operations). Git configuration, the 1.1-second pre-add wait, cold-cache definitions, and initial reader/writer handshake are unchanged. The install meter includes empty-root preflight; its wall time excludes preflight. Git disables automatic GC/maintenance and ignores system/global configuration. Direct-XFS cold status follows `sync` and `FADV_DONTNEED` on regular files while retaining inode/dentry caches; PortableFS cold recreates the Authority and mount without claiming eviction of backing XFS file pages.\n",
           "The measured name cache and item capacities are 65,536. Untimed Git setup retains the baseline's 4,096-name-cache workaround, followed by a complete Authority/mount recreation at 65,536; its item capacity remains 65,536. The separate shipping-capacity regression is recorded in [measure-findings.md](measure-findings.md).\n",
           "Measurements ran on 2026-09-16. The privileged Docker VM has 4 CPUs and 8 GiB RAM (8,309,018,624 reported bytes), kernel `6.8.0-100-generic`. The digest-pinned image is `golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36`. Storage is a 1 GiB loop-backed XFS image on `/var/tmp` tmpfs, with a 512 MiB/200,000-inode test-volume quota. Authority and mounts run in the fixture process over loopback TLS and real kernel FUSE. These timings do not measure physical-disk throughput.\n",
           "Unrelated containers run on the shared VM during these measurements. The wall times therefore are not isolated comparisons and should not be treated as speedup ratios. Authority counts are scoped to the fixture's in-process request handler, so other containers do not enter those counts. Every requested workload ran at full size; none was scaled down.\n",
           "Exact command, run twice (logs `/tmp/cv2-measure-run1.log` and `/tmp/cv2-measure-run2.log`):\n",
           "```sh\nPORTABLEFS_PERFORMANCE_TEST=1 \\\nPORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' \\\nbash scripts/xfs-fuse-integration.sh\n```\n",
           f"Both complete tests passed: run 1 in {durations[0]} and run 2 in {durations[1]}. The focused wrapper's exit 70 denotes missing unrelated required tests after the benchmark PASS. It is not a full-suite gate pass.\n",
           "Counts include every filesystem and control request, including requests entering long polls. The meter remains active through asynchronous FUSE RELEASE and Authority CLOSE completion. The separate drain column excludes that duration from workload wall time. No explicit directory durability barrier was added to the baseline method.\n",
           "## Wall time and requests\n",
           "| Workload | Target | v6 seconds | v6 requests | v6 requests/op | v7 run 1 seconds | v7 run 1 requests | v7 run 1 requests/op | v7 run 2 seconds | v7 run 2 requests | v7 run 2 requests/op |",
           "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for b in base:
        row = [label(b), b["target"]]
        for run in indexed:
            r = run[key(b)]
            row += [f'{r["wall_seconds"]:.6f}', f'{r["authority_requests"]:,}', f'{r["authority_requests_per_operation"]:.6f}']
        out.append("| " + " | ".join(row) + " |")
    out += ["\n## Close drain and filesystem counts\n",
            "The original v6 classifier labels new v7 control opcodes as filesystem requests. This table moves subscription, change-event/acknowledgment, and delegation-release/acknowledgment traffic to control; raw JSON retains the original fields. Total Authority counts are unchanged. `barrier` remains a filesystem operation.\n",
            "| Workload | Version/run | Filesystem requests | Filesystem requests/op | Close drain seconds |",
            "| --- | --- | ---: | ---: | ---: |"]
    for b in base:
        if b["target"] != "portablefs":
            continue
        for version, run in zip(["v6", "v7 run 1", "v7 run 2"], indexed):
            r = run[key(b)]
            fs = sum(n for k, n in r["authority_filesystem_breakdown"].items() if k not in CONTROL_V7)
            out.append(f'| {label(b)} | {version} | {fs:,} | {fs / r["operations"]:.6f} | {r["authority_drain_seconds"]:.6f} |')
    out += ["\n## Per-opcode requests\n", "Zero denotes an opcode absent from that run's recorded map.\n"]
    for b in base:
        if b["target"] != "portablefs":
            continue
        observed = [kinds(run[key(b)]) for run in indexed]
        out += ["### " + label(b) + "\n", "| Opcode | v6 | v7 run 1 | v7 run 2 |", "| --- | ---: | ---: | ---: |"]
        for opcode in sorted(set().union(*observed)):
            out.append("| `" + opcode + "` | " + " | ".join(f'{r.get(opcode, 0):,}' for r in observed) + " |")
        out.append("\n")
    out += ["## Reader/writer overlap\n", "| Target/run | Directory scans | ESTALE retries | Incomplete-read retries | Vanished-read retries | Files verified before writer finished |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for version, records in zip(["v6", "v7 run 1", "v7 run 2"], [base] + runs):
        for r in records:
            if r["scenario"] == "two-mount-write-list-read":
                out.append("| " + version + " " + r["target"] + " | " + " | ".join(str(r.get(k, 0)) for k in ["directory_scans", "transient_retries", "incomplete_read_retries", "vanished_read_retries", "files_observed_during_write"]) + " |")
    (ROOT / "docs/coherence-v2/results.md").write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
