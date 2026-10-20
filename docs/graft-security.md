# Local-graft security verification

Machine-local graft paths are tenant-controlled input. Their host backing
directory is therefore a capability boundary: runtime code must never join a
graft path onto a host path and pass the result to an `os` or `syscall` path
operation. The routing language, the topology rules, and the errno contract are
described in
[xfs-authority-architecture.md](./xfs-authority-architecture.md#machine-local-routing).

## What the boundary is

- Routes are declared volume-wide in `.portablefs/local-dirs` and replaced only
  through the authority's admin `ApplyRoutes` call, which canonicalizes the
  declaration and compare-and-swaps its revision. A mount or an existing
  session carrying a different revision fails closed
  (`vcs/internal/authorityrpc/routes_linux.go`,
  `vcs/internal/localroutes`).
- There is no per-mount route option. `portablefs mount` on Linux adopts the
  volume's declaration through the attach refusal and presents its revision;
  nothing on one machine can add a route its peers do not see.
- macOS serves no graft. The Mac attach always presents the empty rule set's
  revision, so the authority refuses it on a volume that declares routes, and
  such a volume mounts from Linux. Grafts are Linux-only:
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
go test ./cmd/portablefs/internal/cli -count=1
```

The `cli` suite carries route adoption, active-route state, `portablefs route`,
and `prune-local`.

### Case-exact backing is not probed

The Linux graft path does not probe its machine-local backing filesystem for
case folding. A graft backed by a case-insensitive filesystem mounted on Linux
can fold names the shared namespace keeps distinct, and nothing refuses it.
That is an open gap, not a covered case. The daemon-side probe that guarded the
retired macOS backing path was removed with that path; macOS serves no graft.

## Real kernel confinement

Unit tests and cross-compilation do not exercise `openat2(2)`. The required
privileged Linux gate does, against real XFS and a real FUSE mount on the exact
stock kernel interface at FUSE protocol 7.31 or newer:

```bash
bash scripts/xfs-fuse-integration.sh
```

Its required fusev3 inventory, `scripts/xfs-required-fuse-tests.txt`, names the
graft tests explicitly, including
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
`.xcresult`. This suite covers the FSKit frontend, not graft confinement:
macOS serves no graft, and its empty route revision is a property of the Go
CLI attach.

`bash scripts/verify-local.sh` is the repository's local gate and runs the Go
and Swift suites together; `--full` also runs the two privileged real-mount
suites.

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
- A signed PortableFS app on macOS 26 and 27 must run the native FSKit
  acceptance listed in [COMPATIBILITY.md](../COMPATIBILITY.md#qualification-status).
  The Swift mock/adapter suite cannot certify extension activation,
  entitlements, signing, or kernel handoff.

Both are release blockers for their platform. Neither has passed on protocol 8.
