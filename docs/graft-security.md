# Local-graft security verification

Machine-local graft paths are tenant-controlled input. Their host backing
directory is therefore a capability boundary: runtime code must never join a
graft path onto a host path and pass the result to an `os` or `syscall` path
operation. The routing language, the topology rules, and the errno contract are
described in
[xfs-authority-architecture.md](./xfs-authority-architecture.md#machine-local-routing).

## What the boundary is in v3

- Routes are declared volume-wide in `.portablefs/local-dirs` and replaced only
  through the authority's admin `ApplyRoutes` call, which canonicalizes the
  declaration and compare-and-swaps its revision. A mount or an existing
  session carrying a different revision fails closed
  (`vcs/internal/authorityrpc/routes_linux.go`,
  `vcs/internal/localroutes`).
- `--local-dir` is refused unconditionally on every platform. The refusal lives
  in the one gate every mount invocation passes
  (`validateDirectV3MountOpts`, `vcs/cmd/portablefs/internal/cli/mountcmd.go`)
  and is not conditioned on whether the volume publishes a declaration.
  `--no-local-dirs` refuses a declaring volume rather than ignoring its
  topology.
- macOS v3 refuses local-dir and graft options outright
  (`vcs/internal/portablefsd/v3attach.go`), so a volume that declares routes
  mounts from Linux. Grafts are Linux-only:
  `vcs/internal/fusev3/graft_linux.go`, `vcs/internal/localdirs`,
  `vcs/internal/localroutes`.
- Confinement is `vcs/internal/confinedfs`. Linux requires `openat2(2)` with
  `RESOLVE_IN_ROOT` and `RESOLVE_NO_MAGICLINKS` and fails closed when the
  primitive is unavailable or blocked: `probe_linux.go` maps `ENOSYS`,
  `EINVAL` and `EPERM` to `ErrUnsupportedPlatform` rather than continuing
  without confinement.
- Nothing under a graft reaches the authority. Grafted operations run on
  file-descriptor-backed handles against machine-local disk.

## Required verification

Run the capability, routing and graft suites on the development host, under the
race detector:

```bash
cd vcs
go test -race ./internal/confinedfs ./internal/localdirs ./internal/localroutes -count=1
go test ./internal/portablefsd -count=1
go test ./cmd/portablefs/internal/cli -count=1
```

The `portablefsd` suite carries the case-safety probe and the v3 attach
refusal; the `cli` suite carries the unconditional `--local-dir` gate and the
`--no-local-dirs` semantics.

### Case-exact backing, and what the probe does not cover

Graft activation probes the machine-local backing filesystem and refuses when
it folds names the shared namespace keeps distinct: `ErrBackingCaseUnsafe`, or
`ErrBackingProbeIncomplete` when the probe could not reach a verdict at all
(`vcs/internal/portablefsd/localcasesafety.go`). `TestBackingCaseProbe*` and
`TestOpenLocalBackingRefusesAFoldingBacking` run and assert on every host: they
compare the probe's verdict against ground truth measured independently with
plain `os` calls, so the same test proves the refusal on a case-insensitive
host and the acceptance on a case-sensitive one.

Two honest limits apply to that probe today:

- It sits on the retained daemon-side backing path. Because production macOS
  never reaches Attach and the qualification attach refuses grafts before any
  backing is opened, no macOS FSKit path reaches it.
- The Linux FUSE frontend has no equivalent probe. A graft backed by a
  case-insensitive filesystem mounted on Linux is still unguarded. That is an
  open gap, not a covered case.

## Real kernel confinement

Unit tests and cross-compilation do not exercise `openat2(2)`. The required
privileged Linux gate does, against real XFS and a real FUSE mount on the exact
stock kernel interface at FUSE protocol 7.31 or newer:

```bash
bash scripts/xfs-fuse-integration.sh
```

Its `REQUIRED_TESTS` list names the graft tests explicitly, including
`TestGraftedSubtreeReachesTheAuthorityZeroTimes`,
`TestRenamingAnAncestorOfAnActiveGraftIsEBUSY`,
`TestTheGraftBoundaryIsEXDEV` and
`TestARouteRootShadowsTheVolumeSubtreeOfTheSameName`. A required test that is
renamed, deleted or skipped fails the job rather than quietly shrinking
coverage. The suite also includes a live capability probe and an injected
`ENOSYS` case proving that unsupported or blocked `openat2` fails closed.

Two-machine routing isolation is proven separately and black box by the
`local_route_isolation` and `routes_revision_mismatch` cases in
[the cross-mount coherence matrix](./cross-mount-coherence-matrix.md).

Run the FSKit protocol and adapter suite on macOS:

```bash
bash scripts/test-swift-xcode.sh
```

The shared gate disables Xcode parallel testing because several tests share
process resources or exercise hard protocol deadlines. It separately
enumerates and then proves the exact executed test set from the native
`.xcresult`. This suite covers the qualification FSKit frontend, not graft
confinement — the macOS graft refusal is a Go-side property and is covered by
the `portablefsd` suite above.

`bash scripts/verify-local.sh` is the repository's single local merge gate and
runs the Go and Swift suites together.

## Source audit

Before release, search the graft implementations for newly introduced host-path
operations. Expected host paths are limited to creation and opening of the
trusted backing root in `internal/confinedfs`, and to daemon state-directory
management; tenant-relative operations must be methods on the confined
capability:

```bash
cd vcs
rg -n 'localBackingPath|BackingPath' internal cmd
rg -n 'os\.(Open|OpenFile|Lstat|Stat|Mkdir|MkdirAll|Remove|Rename|Link|Symlink|Readlink|Chmod|Chtimes|Truncate)' \
  internal/localdirs internal/localroutes internal/fusev3 internal/portablefsd \
  --glob '!**/*_test.go'
rg -n 'filepath\.Join\(.*mount|unix\.Truncate\(' \
  internal/fusev3 internal/portablefsd --glob '!**/*_test.go'
```

Review any match rather than blindly allowlisting it. A test may intentionally
use raw host paths to construct an attack fixture; production graft operations
may not. The last search must have no matches at all: mounted paths must never
be joined into a host pathname or passed to path-based `truncate(2)`.

## External certification gates

Unit tests, race tests, native Linux syscall tests, and cross-compilation do not
replace these release-environment checks:

- A Linux host with `/dev/fuse` and `fusermount3` must run the real kernel-mount
  integration suite. Docker Desktop does not expose `/dev/fuse` to its Linux VM
  by default, so it cannot certify this gate.
- A separately signed qualification PortableFS FSKit extension runs the live
  macOS kernel-mount matrix when exercising that lane. The Swift mock/adapter
  suite cannot certify extension activation, entitlements, signing, or kernel
  handoff, and neither result admits a production macOS mount while the required
  cache primitives are absent.

The Linux gate is a production release blocker. The signed macOS run is a gate
for the qualification artifact only; it is neither a production release blocker
nor a fallback, and passing it cannot admit current FSKit.
