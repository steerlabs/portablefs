# Linux metadata acceptance runner

Run `benchmark-linux-metadata.py` inside the measured Linux guest, with both
mounts already established against the same dedicated READY volume. The runner
does not start or configure infrastructure. Check the owner's host HOLD before
every preparation, test, image build or measurement. The runner also checks its
configured HOLD path before each workload; a missing guest path is not proof
that a host HOLD was lifted.

The checked-in manifest fixes the corpus revision, tools, commands, ignore
behavior, four rg threads, targets and minimum twenty repetitions. The original
31,509-file corpus revision was not supplied. The manifest records the public
substitute; `reference.json` freezes its actual tracked-file inventory, bytes,
content tree, exact TODO path set and hash, fixture lock hash, and the exact
successful native npm tree before timing. Native fixture installation keeps its
process status and raw outputs beside the measured evidence.
The corpus and fixture must be shared authority data, without local routes.

Use the exact tools in the manifest. Prepare a clean native reference checkout,
a native bare source with HEAD at the same revision, and a native warm offline
npm package cache. Create the cache using the pinned fixture, npm and Node
versions. Both mount roots need enough free quota for a checkout and one install
per repetition. Keep clone and installation mutations out of the input corpus.

Example configuration (all paths and identities are supplied by the owning
qualification run):

```json
{
  "source_commit": "exact candidate commit",
  "image_identity": "exact sealed guest manifest SHA-256",
  "authority_state": "READY",
  "shared_tree": true,
  "host_load_note": "Record concurrent host VZ/Docker, editor, build and release work here.",
  "mounts": [
    {"name": "ordinary", "root": "/mnt/ordinary", "snapshot": ["portablefs", "mount-loss", "/mnt/ordinary", "--mount-instance", "exact ordinary instance", "--json"]},
    {"name": "workspace", "root": "/mnt/workspace", "snapshot": ["portablefs", "mount-loss", "/mnt/workspace", "--mount-instance", "exact workspace instance", "--json"]}
  ],
  "corpus_relative": "perf-pr1-corpus",
  "native_reference": "/var/tmp/perf-reference",
  "bare_source": "/var/tmp/perf-source.git",
  "npm_cache": "/var/tmp/perf-npm-cache",
  "authority_metrics_url": "http://authority-admin/metrics",
  "rtt_command": ["ping", "-n", "-i", "0.2", "authority-data-address"],
  "evidence_directory": "/var/tmp/perf-evidence/unique-after-run"
}
```

Use `--prepare` once on a separate configuration/evidence directory to clone
the pinned input through the ordinary mount and complete its root barrier.
Preparation refuses an existing corpus destination. The measured invocation
checks both mounted trees against the pinned reference, alternates mount order
on successive repetitions, primes warm commands, and retains actual stdout,
stderr, exit status, output hashes, per-process rusage and barrier outcome.
Failures remain failures when later collection or validation also fails.

The live `mount-loss --json` metadata object supplies completed stock FUSE
operation counts by numeric opcode, daemon metadata/page/open decisions, miss
reasons, single-flight waits, capacity evictions, payload bytes, cached
descriptions, RTC calls/time/errors, withdrawal time and cold installations.
The existing go-fuse statistics hook includes fixed refusals and FORGET.
Reverse notifications have separate attempt, failure and transport-time counters. Authority
scrapes retain RPC counts, histograms and recovery metrics. A process-start
witness, missing series, decreasing counter or incarnation change invalidates
a delta. Gauges are snapshots, not differenced high-water measurements. The
before/after windows are separate observations, not an atomic cross-process cut.

Cold content means clean client file pages advised away with
POSIX_FADV_DONTNEED on exactly the tracked corpus files; the authority storage
cache remains warm. There is no global cache drop. Root-directory descriptors
open before clone/install and fsync after the subprocess; command and barrier
time are retained separately and the target covers both. Clone runs
`git fsck --full` and verifies content, links and executable bits through both
mounts. Fresh and no-op installs must match the complete native tree and
unchanged pinned lockfile through both mounts. No failed or partial TODO search is a
timing success.

Keep the complete JSON and raw outputs in the external evidence directory,
never in this repository. Before and after runs must use identical reference
hashes, tools, commands, lane topology and RTT qualification (p50 <=1 ms,
p99 <=3 ms). Include both tables and ratios in the PR. Disclose concurrent load
and repeat contaminated numbers. A timing pass does not qualify remote editor
watch delivery or replace the privileged, native VZ and power-loss gates.
