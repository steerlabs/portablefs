# Real-workload soak

Linux-only protocol 7 qualification probes. These tests require the real XFS
Authority and kernel FUSE; an ordinary `go test` skips them.

```sh
PORTABLEFS_SOAK_TEST=1 \
PORTABLEFS_PROFILE_DIR=/tmp/portablefs-soak \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoak' \
bash scripts/xfs-fuse-integration.sh
```

The script limits this container to two CPUs and 2 GiB, runs tests sequentially,
and installs Node/npm for the pinned lockfile fixture. The first npm installation
seeds a cache outside the mount; the measured mount installation is offline.
The synthetic package test additionally checks 20,000 files, 3,000 directories,
100 hard links and 100 symlinks. Git uses 200 commits and 5,000 tracked files.
Compiler output is compared to an independent build on direct XFS, with path
trimming and VCS stamping disabled in both builds.

Each case runs in a subprocess. A timeout captures the Go runtime dump, then
aborts only that case's new FUSE connections so remaining cases can run. Tests
retain daemon/Authority logs, live and failure goroutine dumps, request counters,
and JSON measurements in the profile directory. `SOAK_RESULT` reports a phase;
`SOAK_CASE.body_pass` describes the body before fixture teardown. Only the final
Go PASS establishes whole-case success. Counts include background CONTROL and
keepalive traffic, including during direct-XFS comparison phases.

Setting `PORTABLEFS_PROFILE_DIR` also captures CPU and blocking profiles for each
measured workload in its isolated child process. Each `.profile.json` manifest
names the exact content-addressed `.test` executable and its profiles; preserve
them together when comparing source revisions. `PORTABLEFS_PROFILE_RUN` optionally
prefixes the phase artifacts. `SOAK_RESULT.profiled` marks timings with profiling
overhead. Unset the profile directory for timing runs without instrumentation.
Use `go tool pprof -top <binary> <cpu-profile>` for CPU work and
`go tool pprof -top -base=<block-before-profile> <binary> <block-profile>` for
phase-specific blocking; the block profile is cumulative within each child.

For a focused reproduction, replace the `-run` expression with its test name.
The script intentionally still checks the full required inventory: a passing
focused selection can exit 70 for omitted tests. An actual failing test exits
nonzero before inventory qualification. The complete soak is distinct from
`verify-local.sh --full`.

Fault cases use reduced concurrent file operations to isolate epoch replacement,
CONTROL loss, buffer backpressure, and dirty unmount. Passing these probes does
not establish that an entire npm/Git/compiler run survives each fault. See
[the findings](../../../docs/coherence-v2/soak-findings.md) for observed failures,
reproductions, measurements, and qualification limits.
