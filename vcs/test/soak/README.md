# Real-workload soak

Linux-only real-workload probes against the protocol-8 stack. These tests
require the real XFS Authority and kernel FUSE; an ordinary `go test` skips
them. They are a workload harness, not a qualification gate, and no result is
recorded in the tree.

```sh
PORTABLEFS_SOAK_TEST=1 \
PORTABLEFS_PROFILE_DIR=/tmp/portablefs-soak \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoak' \
bash scripts/xfs-fuse-integration.sh
```

With `PORTABLEFS_SOAK_TEST=1` the script runs only `./test/soak`, not the
standard privileged suites. It limits the container to two CPUs and 2 GiB
(`GOMAXPROCS=2`, `GOMEMLIMIT=768MiB` for the tests), runs tests sequentially,
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
Go PASS establishes whole-case success. Counts include background CONTROL,
subscription renewal and KeepAlive traffic, including during direct-XFS
comparison phases.

Setting `PORTABLEFS_PROFILE_DIR` also captures CPU and blocking profiles for each
measured workload in its isolated child process. Each `.profile.json` manifest
names the exact content-addressed `.test` executable and its profiles; preserve
them together when comparing source revisions. `PORTABLEFS_PROFILE_RUN` optionally
prefixes the phase artifacts. `SOAK_RESULT.profiled` marks timings with profiling
overhead. Unset the profile directory for timing runs without instrumentation.
Use `go tool pprof -top <binary> <cpu-profile>` for CPU work and
`go tool pprof -top -base=<block-before-profile> <binary> <block-profile>` for
phase-specific blocking; the block profile is cumulative within each child.

The script then requires the exact soak inventory to pass: `TestSoakPackageTree`,
`TestSoakGit`, `TestSoakCompiler`, `TestSoakChaos`, `TestSoakFaults`,
`TestSoakNPM`, and `TestSoakGitLock`. For a focused reproduction, replace the
`-run` expression with one test name; a passing focused selection still exits 70
for the omitted inventory tests, while an actual failing test exits nonzero
before the inventory check. The soak is distinct from
`verify-local.sh --full`.

Fault cases use reduced concurrent file operations to isolate epoch replacement,
CONTROL loss, buffer backpressure, and dirty unmount. Passing these probes does
not establish that an entire npm/Git/compiler run survives each fault, and no
earlier protocol's soak observations carry over to protocol 8.
