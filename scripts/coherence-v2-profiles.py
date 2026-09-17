#!/usr/bin/env python3
"""Generate the coherence-v2 CPU and allocation profile report."""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


AUTHORITY_FOCUS = (
    r"authorityrpc\.\(\*Server\)|authorityrpc\.\(\*VolumeHandler\)|"
    r"internal/volumeserver\.|internal/xfsstore\."
)
DAEMON_FOCUS = (
    r"fusev3\.\(\*|authorityrpc\.\(\*Client\)|go-fuse/v2/fuse\.|"
    r"internal/writeback\."
)
DAEMON_IGNORE = r"countingHandler|integrationFixture"


@dataclass(frozen=True)
class ProfileInput:
    workload: str
    label: str
    kind: str
    profile: Path
    base: Path | None = None


@dataclass(frozen=True)
class HotSpot:
    name: str
    location: str
    self_percent: str
    cumulative_percent: str


def run(command: list[str], root: Path) -> str:
    completed = subprocess.run(
        command,
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout


def pprof_command(
    binary: Path,
    profile: ProfileInput,
    focus: str,
    relative: bool,
    nodecount: int,
    ignore: str | None,
) -> list[str]:
    command = [
        "go",
        "tool",
        "pprof",
        "-top",
        "-lines",
        f"-nodecount={nodecount}",
        "-nodefraction=0",
        f"-focus={focus}",
    ]
    if relative:
        command.append("-relative_percentages")
    if ignore:
        command.append(f"-ignore={ignore}")
    if profile.kind == "alloc_space":
        if profile.base is None:
            raise ValueError("allocation profile has no base")
        command.extend(
            [
                "-sample_index=alloc_space",
                f"-base={profile.base}",
            ]
        )
    command.extend([str(binary), str(profile.profile)])
    return command


def parse_hotspots(output: str) -> list[HotSpot]:
    rows: list[HotSpot] = []
    percent = re.compile(r"^-?\d+(?:\.\d+)?%$")
    location = re.compile(r"(?:^|/)[^ ]+:\d+$")
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        if not (percent.match(fields[1]) and percent.match(fields[2]) and percent.match(fields[4])):
            continue
        location_index = next(
            (index for index in range(len(fields) - 1, 4, -1) if location.search(fields[index])),
            None,
        )
        if location_index is None:
            continue
        name = " ".join(fields[5:location_index]) or fields[location_index]
        rows.append(
            HotSpot(
                name=name,
                location=trim_location(fields[location_index]),
                self_percent=fields[1],
                cumulative_percent=fields[4],
            )
        )
    return rows


def trim_location(location: str) -> str:
    markers = (
        "/work/vcs/",
        "github.com/steerlabs/portablefs/vcs/",
        "github.com/hanwen/go-fuse/v2/",
        "/gomodcache/",
    )
    for marker in markers:
        if marker in location:
            return location.split(marker, 1)[1]
    if "/src/" in location:
        return location.split("/src/", 1)[1]
    return location


def focused_fraction(output: str) -> float:
    return profile_total(output)


def profile_total(output: str) -> float:
    units = {
        "B": 1.0,
        "kB": 1024.0,
        "MB": 1024.0**2,
        "GB": 1024.0**3,
        "ns": 1e-9,
        "us": 1e-6,
        "ms": 1e-3,
        "s": 1.0,
    }
    for line in output.splitlines():
        match = re.search(r"of\s+(-?\d+(?:\.\d+)?)(B|kB|MB|GB|ns|us|ms|s)\s+total", line)
        if match:
            return float(match.group(1)) * units[match.group(2)]
    raise ValueError(f"could not read profile total from pprof output:\n{output}")


def accounted_total(output: str) -> float:
    units = {
        None: 1.0,
        "B": 1.0,
        "kB": 1024.0,
        "MB": 1024.0**2,
        "GB": 1024.0**3,
        "ns": 1e-9,
        "us": 1e-6,
        "ms": 1e-3,
        "s": 1.0,
    }
    for line in output.splitlines():
        match = re.search(r"accounting for\s+(-?\d+(?:\.\d+)?)(B|kB|MB|GB|ns|us|ms|s)?(?:,|\s)", line)
        if match:
            return float(match.group(1)) * units[match.group(2)]
    raise ValueError(f"could not read accounted profile value from pprof output:\n{output}")


def has_negative_lines(output: str) -> bool:
    percent = re.compile(r"^-?\d+(?:\.\d+)?%$")
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[0].startswith("-") and percent.match(fields[1]):
            return True
    return False


def filtered_proto_command(binary: Path, profile: ProfileInput, focus: str) -> list[str]:
    command = ["go", "tool", "pprof", "-proto", f"-focus={focus}"]
    if profile.kind == "alloc_space":
        if profile.base is None:
            raise ValueError("allocation profile has no base")
        command.extend(["-sample_index=alloc_space", f"-base={profile.base}"])
    command.extend([str(binary), str(profile.profile)])
    return command


def filter_intersection(binary: Path, profile: ProfileInput, repository: Path) -> float:
    with tempfile.NamedTemporaryFile(suffix=".pprof") as filtered:
        subprocess.run(
            filtered_proto_command(binary, profile, AUTHORITY_FOCUS),
            cwd=repository,
            check=True,
            stdout=filtered,
            stderr=subprocess.PIPE,
        )
        filtered.flush()
        command = [
            "go",
            "tool",
            "pprof",
            "-top",
            "-lines",
            "-nodecount=-1",
            "-nodefraction=0",
            f"-focus={DAEMON_FOCUS}",
            f"-ignore={DAEMON_IGNORE}",
            str(binary),
            filtered.name,
        ]
        return accounted_total(run(command, repository))


def reason(hotspot: HotSpot, side: str) -> str:
    text = f"{hotspot.name} {hotspot.location}".lower()
    if "syscall" in text or "unix." in text or "internal/poll" in text:
        if side == "Mount daemon":
            return "It enters the kernel for FUSE-device and loopback-RPC I/O on daemon stacks."
        return "It enters the kernel for loopback-RPC and descriptor-relative XFS I/O on Authority stacks."
    rules = [
        (("canonicalpresentfields",), "It builds the canonical present-field set used to validate each protocol message."),
        (("coherencecoordinator).poll",), "It materializes subscription changes returned by the Authority's control poll."),
        (("unsafe_new",), "It allocates values requested through protocol-buffer reflection."),
        (("newtimer", "newtimer"), "It allocates timers for request, polling, and repair deadlines."),
        (("acquireframepayload",), "It acquires the bounded byte buffer that receives an RPC frame."),
        (("operationresolutioncontext",), "It records descriptor-relative namespace and item resolution for one Authority operation."),
        (("handlecoherencepoll",), "It constructs the reply for a protocol-7 subscription poll."),
        (("signalsourcechangedlocked",), "It closes the old source-publication wake channel and allocates its replacement."),
        (("mutationcontext",), "It creates the lifecycle context that tracks one kernel mutation through reply publication."),
        (("reservecachecandidatelocked",), "It records a candidate name-cache entry while enforcing the mount's capacity."),
        (("registerreplypublication",), "It records the cache coordinates that must settle before the FUSE reply is published."),
        (("acquiresourcepublication",), "It allocates the coordinate map used to acquire source-publication ownership."),
        (("settlereplypublicationlocked",), "It removes publication coordinates after the kernel reply becomes safe to expose."),
        (("bindcachednamelocked",), "It allocates and installs the mount's positive name-cache binding."),
        (("publishentry",), "It constructs the FUSE entry and associates it with subscription state."),
        (("propagatecancel", "withdeadlinecause", "cancelctx).done", "context.withcancel", "parentcancelctx"), "It creates or links cancellation state for bounded RPC and FUSE operations."),
        (("client).readloop",), "It receives and decodes Authority replies for the mount client."),
        (("callmutationwithidentityretained",), "It sends a mutating RPC while retaining its request identity through reply publication."),
        (("transportislive",), "It checks the mount client's transport generation before admitting an RPC."),
        (("dispatchownedframe",), "It routes an owned reply frame to the waiting mount request."),
        (("cloneproof",), "It copies the session proof attached to a mount RPC."),
        (("coordinatesforsourcegate",), "It builds the publication-coordinate set guarded by a local mutation reply."),
        (("buffer).admit",), "It records a delegated mutation in the bounded writeback buffer."),
        (("newserver.func2",), "It allocates go-fuse request buffers used to receive kernel operations."),
        (("wiretypeforkind", "validatewiremessagedepth"), "It validates protobuf shape and wire types before decoding an RPC frame."),
        (("preparereplypayload",), "It serializes the FUSE reply after its cache-publication conditions are satisfied."),
        (("subscriptionregistry).stamp",), "It reads the current subscription coordinate attached to a cached entry."),
        (("coherencedirectorydependencies",), "It builds the directory and item dependency set for an Authority read."),
        (("mutationsequencer", "newmutationdependencies"), "It allocates dependency state used to order an Authority operation."),
        (("cloneoutcome",), "It copies a retained Authority outcome for replay-safe delivery."),
        (("volumehandler).success",), "It builds the successful Authority reply and attaches coherence metadata."),
        (("servesession",), "It allocates per-request server dispatch state for the authenticated RPC session."),
        (("coherencechanges",), "It constructs the committed change set emitted by an Authority mutation."),
        (("mutateoperation",), "It allocates the operation context used for Authority mutation admission and commit."),
        (("writeheapbitssmall",), "It updates garbage-collector metadata for small heap allocations on the focused path."),
        (("maps.probeseq.next",), "It probes Go hash tables used by request and coherence state."),
        (("time.now", "nanotime"), "It reads clocks for request deadlines and coherence horizons."),
        (("futex", "mutex"), "It executes synchronization and lock operations protecting concurrent request and coherence state."),
        (("runtime.pcvalue", "runtime.step", "textaddr", "readvarint", "funcinfo.entry"), "It performs Go runtime stack walking and program-counter metadata lookup."),
        (("chacha8rand",), "It advances the Go runtime's random state for hash-table seeding and scheduling."),
        (("aeshashbody",), "It hashes Go map keys used by request and coherence state."),
        (("sysrand",), "It obtains cryptographic randomness used by the TLS connection."),
        (("cmpbody",), "It compares byte strings used as protocol identities, names, or tokens."),
        (("mallocgc", "newobject", "makeslice", "growslice"), "It allocates objects or grows buffers retained by this side's request path."),
        (("scanobject", "gcdrain", "markroot", "greyobject"), "It is garbage-collector work induced by allocations in the focused request stacks."),
        (("memmove", "memclr"), "It copies or clears request, reply, or cache buffers in the focused stacks."),
        (("sha256", "hash"), "It computes protocol, identity, or payload hashes used by the focused path."),
        (("crypto/tls", "aes", "gcm", "chacha"), "It encrypts or authenticates loopback TLS records for Authority RPC traffic."),
        (("proto", "marshal", "unmarshal"), "It encodes or decodes protocol-buffer request and reply frames."),
        (("go-fuse", "readrequest", "writemsg"), "It receives or replies to kernel FUSE requests for the mounted workload."),
        (("lookup",), "It resolves a pathname component and publishes or consumes its cache state."),
        (("readdir", "read_dir"), "It enumerates directory entries and carries their continuation and attributes."),
        (("create", "mkdir"), "It admits and publishes file or directory creation for the install workload."),
        (("close", "release"), "It drains file handles and any associated delegation state after the workload closes them."),
        (("delegat",), "It grants, applies, recalls, or releases protocol-7 delegated state."),
        (("writeback", "flush"), "It applies buffered mutation state and advances its durability watermark."),
        (("read",), "It reads request frames, file data, or directory data used by the workload."),
        (("write",), "It writes request frames, replies, or workload data on the focused path."),
        (("xfsstore",), "It translates the Authority operation into descriptor-relative XFS storage work."),
        (("volumeserver",), "It performs Authority admission, ordering, or coherence bookkeeping."),
        (("authorityrpc",), "It dispatches or transports an Authority protocol request."),
        (("fusev3",), "It translates a kernel FUSE operation into PortableFS state and Authority RPC work."),
        (("runtime.",), "It is Go runtime work charged to samples whose stacks pass through this side."),
    ]
    for needles, explanation in rules:
        if any(needle in text for needle in needles):
            return explanation
    return f"It is sampled work on the focused {side} request stacks."


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def preserve_profiles(inputs: list[ProfileInput], binary: Path, repository: Path) -> list[tuple[str, int, str, str]]:
    destination = repository / "vcs/bench/coherencebench/testdata/profiles"
    destination.mkdir(parents=True, exist_ok=True)
    paths = sorted({item.profile for item in inputs} | {item.base for item in inputs if item.base is not None})
    records: list[tuple[str, int, str, str]] = []
    for path in paths:
        size = path.stat().st_size
        digest = sha256(path)
        if size < 2 * 1024 * 1024:
            target = destination / path.name
            shutil.copy2(path, target)
            location = str(target.relative_to(repository))
        else:
            location = str(path)
        records.append((path.name, size, digest, location))
    records.append((binary.name, binary.stat().st_size, sha256(binary), str(binary)))
    return records


def table(title: str, rows: list[HotSpot], side: str) -> str:
    lines = [
        f"### {title}",
        "",
        "| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |",
        "| ---: | --- | --- | ---: | ---: | --- |",
    ]
    for index, hotspot in enumerate(rows, 1):
        lines.append(
            f"| {index} | `{hotspot.name}` | `{hotspot.location}` | "
            f"{hotspot.self_percent} | {hotspot.cumulative_percent} | {reason(hotspot, side)} |"
        )
    return "\n".join(lines)


def profile_artifact(directory: Path, prefix: str, workload: str, suffix: str) -> Path:
    stem = {
        "install-1": "TestCoherenceBaseline-install-portablefs-workers-1-install",
        "git-status-cold": "TestCoherenceBaseline-git-portablefs-cold",
    }[workload]
    run = f"{prefix}." if prefix else ""
    current = directory / f"{run}{stem}.{suffix.replace('allocs.', 'allocs-')}.pprof"
    if current.is_file():
        return current
    return directory / f"{run}{workload}.{suffix}.pprof"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles", type=Path, default=Path("/tmp/cv2-measure-profiles"))
    parser.add_argument("--prefix", default="run1")
    parser.add_argument("--output", type=Path, default=Path("docs/coherence-v2/profiles.md"))
    parser.add_argument("--product-revision", default="5f76079")
    args = parser.parse_args()

    repository = Path(__file__).resolve().parent.parent
    profile_dir = args.profiles.absolute()
    binary = profile_dir / (f"{args.prefix}.fusev3.test" if args.prefix else "fusev3.test")
    inputs = [
        ProfileInput("Install, 1 worker", "install-1", "cpu", profile_artifact(profile_dir, args.prefix, "install-1", "cpu")),
        ProfileInput(
            "Install, 1 worker",
            "install-1",
            "alloc_space",
            profile_artifact(profile_dir, args.prefix, "install-1", "allocs.after"),
            profile_artifact(profile_dir, args.prefix, "install-1", "allocs.before"),
        ),
        ProfileInput("Cold Git status", "git-status-cold", "cpu", profile_artifact(profile_dir, args.prefix, "git-status-cold", "cpu")),
        ProfileInput(
            "Cold Git status",
            "git-status-cold",
            "alloc_space",
            profile_artifact(profile_dir, args.prefix, "git-status-cold", "allocs.after"),
            profile_artifact(profile_dir, args.prefix, "git-status-cold", "allocs.before"),
        ),
    ]
    missing = [str(path) for path in [binary] + [item.profile for item in inputs] + [item.base for item in inputs if item.base] if not path.is_file()]
    if missing:
        raise SystemExit("missing profile artifacts:\n" + "\n".join(missing))

    sections: list[str] = []
    fractions: list[tuple[str, str, float, float, float, float]] = []
    commands: list[str] = []
    cold_cpu_samples: dict[str, int] = {}
    for profile in inputs:
        full_command = pprof_command(binary, profile, ".", False, -1, None)
        full_output = run(full_command, repository)
        full_total = profile_total(full_output)
        if profile.kind == "alloc_space" and has_negative_lines(full_output):
            raise ValueError(f"allocation delta for {profile.label} contains negative line samples")
        side_results: dict[str, list[HotSpot]] = {}
        side_fractions: dict[str, float] = {}
        side_totals: dict[str, float] = {}
        for side, focus, ignore in (
            ("Mount daemon", DAEMON_FOCUS, DAEMON_IGNORE),
            ("Authority", AUTHORITY_FOCUS, None),
        ):
            relative_command = pprof_command(binary, profile, focus, True, 15, ignore)
            relative_output = run(relative_command, repository)
            side_results[side] = parse_hotspots(relative_output)
            side_totals[side] = focused_fraction(relative_output)
            side_fractions[side] = 100.0 * side_totals[side] / full_total
            commands.append(shlex.join(relative_command))
        overlap = 100.0 * filter_intersection(binary, profile, repository) / full_total
        unattributed = 100.0 - side_fractions["Mount daemon"] - side_fractions["Authority"] + overlap
        if unattributed < -0.01:
            raise ValueError(f"invalid inclusion-exclusion result for {profile.label} {profile.kind}")
        if profile.label == "git-status-cold" and profile.kind == "cpu":
            cold_cpu_samples = {side: round(total / 0.01) for side, total in side_totals.items()}
        fractions.append(
            (
                profile.workload,
                "CPU" if profile.kind == "cpu" else "Allocation space delta",
                side_fractions["Mount daemon"],
                side_fractions["Authority"],
                overlap,
                unattributed,
            )
        )
        metric = "CPU" if profile.kind == "cpu" else "Allocation space delta"
        for side in ("Mount daemon", "Authority"):
            sections.append(table(f"{profile.workload}: {side}, {metric}", side_results[side], side))

    artifacts = preserve_profiles(inputs, binary, repository)
    lines = [
        "# Coherence v2 profiles",
        "",
        f"Product revision: `{args.product_revision}`. This is the first workload CPU and allocation profile in the integration record; `integration.md` contains no earlier hot-spot ranking.",
        "",
        "## Method",
        "",
        "The fixture runs the Linux FUSE frontend, loopback TLS transport, and in-process Authority in one `go test` process. Each raw profile is therefore a combined-process observation. The tables attribute a sample to the mount daemon or Authority when its stack matches the filters below. Percentages in each hot-spot table use `-relative_percentages`, so their denominator is the focused side rather than the whole process. Runtime work descended from a matched stack is charged to that side; runtime-only and other stacks that match neither filter remain unattributed. These are stack-filter shares, not exclusive process measurements. Intersection was measured by filtering the Authority profile protobuf through the daemon filter, and the residual uses `100 - daemon - Authority + intersection`.",
        "",
        "The install profile covers the full 40,000-file, 2,000-directory, one-worker workload. The cold Git profile prepares and commits 20,000 files at the shipping 65,536-name capacity, recreates the complete Authority and mount at the shipping 65,536 name and item capacities, then runs the first clean `git status --porcelain=v1`. CPU capture remains active through asynchronous delegation application, release, and final Authority CLOSE drain. Allocation-space (`alloc_space`) results are sampled allocated bytes at Go's default 512 KiB memory-profile rate, not retained heap. They subtract a snapshot taken after two forced GCs immediately before the workload from another taken after two forced GCs following the CLOSE drain. The signed deltas contained no negative line samples, so no negative values were suppressed. Profiled wall times are not performance results.",
        "",
        f"CPU sampling uses 10 ms samples. The short cold-status window produced approximately {cold_cpu_samples.get('Mount daemon', 0)} daemon and {cold_cpu_samples.get('Authority', 0)} Authority samples; its ranks are correspondingly coarse, and equal percentages are sampling ties.",
        "",
        "Capture with the unified baseline harness:",
        "",
        "```sh",
        "PORTABLEFS_PERFORMANCE_TEST=1 \\",
        "PORTABLEFS_PROFILE_DIR=/tmp/cv2-measure-profiles \\",
        "PORTABLEFS_PROFILE_RUN=run1 \\",
        "PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$/(install-portablefs-workers-1|git-portablefs)$' \\",
        "bash scripts/xfs-fuse-integration.sh",
        "```",
        "",
        "The focused wrapper exits 70 when required full-suite inventory is omitted. Profile artifacts alone are not full-gate evidence.",
        "",
        f"Authority focus: `{AUTHORITY_FOCUS}`.",
        "",
        f"Mount-daemon focus: `{DAEMON_FOCUS}` with `-ignore={DAEMON_IGNORE}` so fixture-side Authority dispatch frames are not charged to the daemon.",
        "",
        "Tables rank source lines by self cost (`-lines -top`). Repeated functions at different source lines are intentional; cumulative percentages are reported for the same line-level nodes.",
        "",
        "Source paths under `internal/authorityrpc`, `internal/fusev3`, `internal/volumeserver`, `internal/writeback`, and `internal/xfsstore` are relative to `vcs/`; `third_party` paths are also relative to `vcs/`. Standard-library paths, including `runtime`, `internal/runtime`, `internal/sync`, `internal/chacha8rand`, `context`, and `time`, refer to the Go 1.26.6 source tree. Versioned module paths refer to the Go module cache.",
        "",
        "## Focused share of the combined process",
        "",
        "| Workload | Metric | Mount daemon | Authority | Filter intersection | Unattributed by filters |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for workload, metric, daemon, authority, overlap, unattributed in fractions:
        lines.append(f"| {workload} | {metric} | {daemon:.2f}% | {authority:.2f}% | {overlap:.2f}% | {unattributed:.2f}% |")
    lines.extend(["", "## Ranked hot spots", "", "\n\n".join(sections), "", "## Raw artifacts", ""])
    lines.extend(
        [
            "Raw profiles smaller than 2 MiB are retained in the repository. The exact test executable is larger and remains under `/tmp`; its digest identifies the binary used for symbolization.",
            "",
            "| Artifact | Bytes | SHA-256 | Preserved location |",
            "| --- | ---: | --- | --- |",
        ]
    )
    for name, size, digest, location in artifacts:
        lines.append(f"| `{name}` | {size} | `{digest}` | `{location}` |")
    lines.extend(["", "## Analysis commands", "", "Each table was generated with the corresponding command below:", "", "```sh"])
    lines.extend(commands)
    lines.extend(["```", ""])

    output = args.output if args.output.is_absolute() else repository / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
