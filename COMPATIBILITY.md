# Compatibility

This is the PortableFS launch contract for authority protocol 8.

Status: **unqualified**. PortableFS has not launched. The surfaces below are
the intended launch freeze, but they are not yet qualified: the gates listed
under [Qualification status](#qualification-status) have not passed on the
integrated protocol-8 tree. They freeze at launch, after those gates pass.
Until then a gate failure can still change a detail here; such a change is
made to this document and the code together, never silently.

Protocol 8 replaces every earlier protocol. Nothing earlier shipped, so there
is no older client, authority, Mac artifact, on-disk state, or release line to
serve, convert, or refuse by name. An unequal version is refused because it is
unequal.

If a surface is not listed here, treat it as internal and unstable.

## Two limits that apply to every deployment

**A shared XFS cell is one durability-error and latency domain.** Volumes
placed as XFS project directories on one filesystem share its superblock.
Handleless FSKit mutations, and the Linux root-directory barrier, persist through
`syncfs` on the authority's retained XFS-root description. Since Linux 5.8,
`syncfs` reports a superblock-wide writeback error sequence against the
calling description's cursor, and `sync_filesystem` waits for the whole
filesystem's dirty inodes. A writeback or log failure caused by another
project's inode can therefore surface at this volume's next barrier, which
fences this volume's store; another project's dirty data can lengthen this
volume's barrier latency. Project quotas, per-volume service identities, and
per-volume workers do not isolate either effect. The authority never filters,
relabels, or erases such an error, and never rotates its root description to
reset the cursor. A deployment that needs durability-error or latency
isolation must place each volume on its own filesystem; even then, volumes on
one device share device contention and media failure. See
[xfs-authority-deployment.md](./docs/xfs-authority-deployment.md#shared-cell-durability-domain).

**macOS terminal enforcement does not withdraw kernel cache state.** When a
Mac session ends, is fenced, or loses its daemon, PortableFS stops answering
from its own caches, stops publishing successful serving replies into FSKit,
and expires its proof-based cache eligibility. That does not synchronously
remove names, attributes, or pages the macOS kernel already retains for the
mount. FSKit documents no module-initiated namespace or inode-attribute
invalidation, so
processes on that Mac may observe retained kernel state until the mount is
unmounted. The authority's writer exclusion (below) keeps every other client
from writing while that Mac's daemon could still serve; it does not revoke
the old Mac's kernel state. PortableFS does not advertise Linux-style
immediate cache revocation on macOS, and it does not unmount automatically on
fence.

## Exact versions

Each row is an independent identity. The release SemVer, the product
generation, the authority major, and the local versions do not track one
another, and none is bumped to match another.

| Surface | Value | Rule |
| --- | --- | --- |
| Authority TLS ALPN | `portablefs-authority-v8` | Exact. Both connections; no other ALPN offered or accepted. |
| Authority protocol major | `8` | Exact, in both role Hellos. Unequal majors are refused at the handshake. |
| Authority protobuf package | `portablefs.authority.v1` | A namespace, not a version. |
| Product generation | v3 | Product naming (`portablefs-mount-v3`); not a wire version. |
| Linux kernel FUSE | protocol 7.31 or newer | Refused during FUSE INIT below 7.31. |
| Authority host kernel | Linux 5.17 final or newer | Refused at storage startup below 5.17 and for 5.17 release candidates; later release candidates are accepted. |
| `pfslocal` (daemon to FSKit extension) | 2.0 | Exact major and minor; paired within one signed release. |
| Daemon operational control | `2` | Exact; `X-PortableFS-Control-Protocol` header and `/v2/` paths; paired within one signed release. |
| Daemon lifecycle API | `1` | `/lifecycle/v1/...`; independent of the operational version and stable across releases. |
| Daemon identity record | schema `1` | Reports the serving release's actual control and `pfslocal` versions. |
| Mac release identity | daemon CodeDirectory hash, executable SHA-256, release version | Static release authentication; protocol numbers are not part of it. |
| Lifecycle registry witness | `attaches.json` in the daemon state directory | Present only while the daemon has registered attachments; absent means none. |
| Mount membership file | `mount.membership`, header `PFS-MEMBERSHIP-1` | Exact; one shared codec for authority and cell host. |
| Signed cell plan | version `3` | Exact version, token prefix, and signing domain. |
| Daemon attach registry, Manager snapshot | schema `3` | Exact; private. |
| Cell helper durable state | version `2` | Exact; private. |
| CLI mount state, active-route state, operation intent | schemas `1`, `1`, `3` | Exact; private. |

The exact current authority grammar is the descriptor manifest
`vcs/internal/authoritypb/testdata/protocol8-schema.json`, checked by the Go
suite against the generated code. The `pfslocal` grammar is
`pfslocal/pfslocal.proto` with the shared golden frames in
`pfslocal/testdata/` and the Swift test bundle.

## Frontend profiles

A session declares one profile before Attach. Attach and Activate echo it, the
canonical session fingerprint pins it, and replay or reconnection cannot change
it. A profile is a behavioral contract, not a capability bundle.

| Profile | Meaning |
| --- | --- |
| `FRONTEND_PROFILE_UNSPECIFIED` | Invalid for a mount. Valid only where the route-admin contract requires it. |
| `FRONTEND_PROFILE_LINUX` | Stock kernel FUSE with a volume subscription, ordered change stream, and file write delegations. |
| `FRONTEND_PROFILE_FSKIT_EXCLUSIVE` | The single macOS writer: positioned direct WRITE, durable mutation replies, coherent conservative metadata stamps, KeepAlive cache proofs, retained writer exclusion. No peer-actuation interface. |
| `FRONTEND_PROFILE_CACHELESS_READER` | Exactly read access, no cache permission, no subscription, no writer exclusion. Reads break delegated data for read. The files gateway uses it. |

There is one macOS profile on macOS 26 and 27. There is no cache-policy name,
selector, registry field, or CLI option. Platform eligibility is checked
against supported macOS releases before Attach.

## The authority wire

**Transport.** Mutually authenticated TLS 1.3. Each session owns exactly one
DATA and one CONTROL connection in a random authenticated connection set.
Attach is provisional; Activate succeeds only after both role bindings and
their generations are proven; AbortAttach releases one exact provisional
attempt. A provisional credential cannot execute filesystem operations.
Route-admin sessions are separate: they receive no root capability, mount
membership, or subscription. Plaintext is refused; there is no environment
escape.

**No negotiation.** Protocol 8 has no authority feature strings, required
feature tables, or optional-capability fallbacks. The major and the profile
fix the grammar and semantics. Unknown fields, unknown bodies, and unknown
enum values are invalid, so a changed grammar, a new operation, or a changed
semantic promise requires a new exact major and ALPN. Peers that implement
the same major may carry different release versions; the Mac CLI, daemon, and
extension remain one paired release.

**Canonical framing and exact replay.** Frames carry big-endian metadata and
bulk lengths; only READ and WRITE use out-of-line bulk. Canonical encoding
emits ascending tags and minimal varints and rejects unknown fields, duplicate
singular fields, multiple oneof members, maps, and fixed-width fields.
Collections are bounded before allocation. Within one authority epoch each
mutation carries a client-owned replay slot and sequence; exact replay
returns the retained outcome without re-execution, and reuse with a different
canonical body fences the session. Replay dies with the epoch. A reply lost
across authority death is uncertain and is never resubmitted automatically.
Surviving field and enum numbers are never renumbered and a shipped tag is
never reused within protocol 8.

**Object-relative requests.** Activate returns an opaque root token; Lookup
takes a parent token and one raw name component of 1 to 255 bytes, without
slash or NUL, never `.` or `..`. Stable identities coordinate caching and
never authorize access. An epoch change invalidates every capability and
server handle; there is no open-by-identity recovery.

**Conservative object versions.** An object version `v` is sampled at a
committed storage sequence `s` with `0 < v <= s`; a negative lookup carries
`s > 0`. Samples taken in increasing snapshot order have nondecreasing
versions for one identity; every logical change gets a strictly greater
version than earlier samples of that identity; equal versions of one identity
agree on logical attributes. Versions may advance without a logical change.
Neither side infers a changed identity, namespace effect, permission change,
or durable outcome from `v == s`. Allocated blocks and restore-mode ctime
remain observational, and restore hydration preserves logical mtime. Mutation
replies carry the complete post-state of every affected object.

**MKDIR.** A successful MKDIR returns `MkdirReply`: the owning `Item` and
`child_search_permitted`, a kernel effective-credential search check on the
new directory evaluated at the same committed cut as the Item and post-state.
`false` is an evaluated denial, not an absent observation; mkdir still
succeeds. Replay returns the original bit without resampling.

### Linux profile

- One volume subscription per mount: a 10-second authority horizon renewed
  every 3 seconds, anchored conservatively at request start. Subscribe returns
  an atomic version watermark and the delegated identity set. Ordered change
  batches travel on CONTROL; an acknowledgment of position N proves complete
  local withdrawal through N in that incarnation. Expiry fences the subscriber
  until it invalidates everything and subscribes cold.
- File write delegations: CREATE/OPEN can return a FULL or WRITETHROUGH grant.
  Generation-bound flushes are rejected before application under stale
  ownership. Recall, break-for-read, and mode change travel on CONTROL with a
  budget of at most 5 seconds.
- Ordered delegated flush is mandatory: a window of 4 dense ordinals per
  delegation generation on a dedicated lane. Linux client and authority DATA
  `max_in_flight` must be at least 9; smaller configurations are refused before
  activation. There is no serial or capacity-negotiated alternative.
- `CLOSE_BATCH` (1 to 128 handles) and individual `CLOSE` are both valid.
- Completion: file fsync and `O_SYNC`/`O_DSYNC` wait for durability of that
  file's accepted cut; the run barrier is FSYNCDIR on a root-directory handle
  opened before the run, which fails if mount loss advanced since its open.
  Stock FUSE `syncfs(2)` is not a completion surface.

### FSKit exclusive-writer profile

- WRITE is one positioned direct write without append, sync, delegation, flush
  sequence, or lock owner. Close uses `CLOSE_BATCH` only.
- Every successful FSKit mutation reply is durable on authority storage before
  it is sent or retained for replay (see [Durability](#durability)).
- A successful KeepAlive carries `session_valid_for_nanos`, the proof `R`: a
  positive whole-millisecond duration in nanoseconds, bounded by the remaining
  session lease, the remaining installed authorization, the advertised lease,
  and `MaxCacheProof` = 60,000,000,000 ns. With
  `epsilon(R) = 1,000,000,000 + ceil(R / 1000)`, a client may serve cached
  metadata only while `R > epsilon(R)` and `now < t0 + R - epsilon(R)`, where
  `t0` precedes queueing on a clock that advances across sleep. The margin
  assumes at most 1,000 ppm aggregate clock-rate error and one second of
  measurement uncertainty, and no clock-offset agreement. A wall clock may deny
  expired authorization; it never grants a cache horizon.
- Writer exclusion: an active FSKit session excludes Linux visible mutations
  and write-intent opens, and every other Mac activation, including a Mac
  whose access happens to be read-only. After the session is fenced, exclusion
  persists until every promised proof has expired **and** all its admitted
  storage applications have drained; an accepted exact absence proof discharges
  the time, not the drain. After an authority restart that finds prior FSKit
  membership, foreign writers are refused for 61.06 seconds
  (`MaxCacheProof + epsilon(MaxCacheProof)`) after safe takeover, and Mac
  activation requires operator reconciliation. The restart bound assumes the
  predecessor's renewal and storage work have irrevocably stopped.

### Cacheless reader profile

Lifecycle operations, LOOKUP, GETATTR, read-only OPEN, individual CLOSE, READ,
READDIR, and Reclaim. No mutation, cache-capable handle, subscription,
delegation, or `CLOSE_BATCH`. Every data-consuming operation breaks delegated
data for read before storage admission. It neither recalls a Linux writer nor
joins Mac writer exclusion, and its transport loss leaves no withdrawal duty.

## Durability

XFS is the durable truth. Linux delegated writes may sit in a bounded,
volatile daemon buffer until a durability barrier; the Linux completion rules
are above.

FSKit delivers no fsync, directory-sync, or `F_FULLFSYNC` callback, so each
mutation reply is the durability point. A mutation with a retained syncable
description (WRITE, CREATE, truncating OPEN, handle-backed SETATTR) full-fsyncs
that description. A handleless mutation (namespace changes, item-backed
metadata) uses `syncfs` on the authority's retained XFS-root description. The
barrier is selected from the operation, never by trying a reopen and falling
back. Every failed fsync, fdatasync, or syncfs fences the store before any
affected waiter can succeed; the first failure is retained and no later
barrier can certify durability. Cancellation after apply does not abandon the
barrier, and replay never repeats apply or sync.

## macOS

- macOS 26 and 27 mount through `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`. A mounted
  Mac is the volume's only writer; Linux peers can remain mounted and read,
  and their visible mutations return `EBUSY`. A clean Mac unmount lets Linux
  write again and lets another Mac mount.
- Current FSKit exposes no exact namespace or inode-attribute invalidation, no
  per-write append intent, and no advisory-lock callbacks. Cross-machine
  `fcntl`/`flock` exclusion and cross-client atomic append require Linux
  mounts with no Mac writer attached.
- The daemon answers metadata from versioned authority state its own session
  received, ordered by storage sequence, only within the current KeepAlive
  proof and authorization, and only after the complete effect of any
  in-flight callback on the same coordinate has settled. For directories this
  mount created, it can also answer an absent name locally from a bounded
  names-only completeness record (1,024 directories, 16,384 names, 1 MiB of
  name bytes per mount) that requires a positive search-permission
  observation; overflow or uncertainty discards the record. None of this is
  FSKit kernel caching, whose limit is stated at the top of this document.
- Buffered `write(2)` returns at kernel page-cache acceptance. Whether a native
  `fsync`, `F_FULLFSYNC`, or ordinary unmount delivers every dirty page as
  write callbacks and reports their errors is host behavior that is not yet
  qualified. A forced unmount can discard pages the kernel never delivered.
- `umount` makes one unforced attempt and returns the real `EBUSY` when
  something holds the mount. Only an explicit user `--force` ever forces an
  unmount: no daemon failure, terminal session, timeout, or proven daemon
  death does, because none proves that FSKit delivered every dirty page. The
  mount supervisor is not an authority-session health monitor; it waits for
  signals and kernel mount-table change notifications and re-reads the exact
  mount inventory on each. Daemon fencing and terminal publication do not
  withdraw existing FSKit kernel cache state.
- Detach reporting: the daemon answers a completed unmount with an empty 204
  or with one combined error, and the CLI separately classifies the exact
  kernel mount as absent, present, or unverified. A daemon error with the
  kernel mount absent is reported as "kernel mount is absent; daemon unmount
  completion is unconfirmed (absence-proof delivery or cleanup may be
  incomplete)", with state and intent preserved and a failing exit; a lost or
  timed-out reply is reported the same way. The CLI does not report
  proof-delivery and cleanup as separate authoritative outcomes, and a later
  204 or 404 is never an absence-accepted receipt. A Swift teardown
  acknowledgement neither authorizes the daemon's 204 nor removes a durable
  registry record. Only a valid empty 204 plus independently proven exact
  kernel absence permits durable CLI cleanup; presence, unverified kernel
  state, or a malformed success remains an error and preserves state and intent.
- Extended-attribute get, list, and remove are supported for portable
  `user.*` names; set is refused with `EOPNOTSUPP`, which prevents AppleDouble
  fallback files.
- FSKit file IDs are the pfslocal file ID plus one; the volume root is FSKit
  ID 2. Zero and overflow are refused.

### FSKit callback publication and teardown

Once the session is terminal, no FSKit callback that publishes data, metadata,
namespace or durability reports success. Resource loading, volume activation
and mounting are serving callbacks and obey the same rule. Session termination
and each serving callback's final synchronous reply share one publication gate:
a reply that wins the gate precedes termination; when termination wins, the
final gate rejects publication with the first terminal cause. Earlier definite
request refusals remain failures.

Volume deactivation and resource unloading acknowledge local teardown only.
They must perform their local cleanup even after terminal failure and report
success only after the cleanup they acknowledge has completed. An earlier
session-terminal cause does not make completed cleanup fail. A genuine error
in the teardown request or its local cleanup remains an error. Repeated
completed teardown is idempotent. Unmount's errorless completion acknowledges
the same local cleanup boundary.

A teardown acknowledgement does not certify durability, erase or replace the
first terminal cause, revive a session, prove kernel mount absence, prove
authority acceptance of absence, or certify daemon/CLI reconciliation. Mutation
and synchronize failures retain their existing error paths. Every successful
FSKit mutation reply still requires authority-storage durability before
publication.

This exception names `deactivate`, `unloadResource`, and errorless `unmount`
completion. Close, reclaim, release, cancellation, and other cleanup activity
retain their existing publication and resource-settlement rules.
`loadResource`, `activate`, `mount`, and `synchronize` remain gated. Closing the
session cannot retract state already published into the kernel's caches.

`synchronize` waits for the authority's SyncVolume barrier over its captured
applied cut, then Statfs; barrier and Statfs errors propagate. Its final gate
can still reject success after both requests succeed. This covers neither
mutations outside the captured cut nor kernel pages not yet delivered as
callbacks. Native `fsync`/`F_FULLFSYNC` waiting, dirty-page drain, and error
propagation remain qualification boundaries. A real sync failure or busy
reference can prevent ordinary unmount of a terminal writable mount; completed
local teardown does not promise its removal. Only explicit user force
authorizes force, whose completion still depends on the OS and never certifies
undelivered writes as durable.

## Filesystem semantics

The guarantees in [docs/consistency-model.md](./docs/consistency-model.md) are
part of this contract: fsync on the authoritative descriptor, `close` is not an
implicit fsync, session-exact replay inside an epoch, no silent continuation
across an epoch, atomic rename, and open-after-unlink. The authority
implements independent POSIX record and `flock` lock namespaces; Linux FUSE
forwards both, FSKit exposes neither.

Cross-mount namespace coherence covers forward pathname resolution and
directory enumeration. Reverse rendering of an already-held Linux dentry
(`getcwd`, `/proc/*/fd`, other `d_path` users) is outside it: stock Linux
performs no FUSE revalidation for those observations.

Explicit refusals carry equal weight: shared file-backed `mmap`, `setxattr`,
device nodes, FIFOs, sockets, setuid execution, multiple POSIX principals in
one volume, and cross-volume link and rename. Unsupported xattr writes are
`EOPNOTSUPP`.

## Mount transports

Linux mounts through stock kernel FUSE protocol 7.31 or newer, with no
PortableFS-private capability bit or opcode. A lower kernel protocol is
refused during FUSE INIT; because INIT is the first point at which the level
is known, the client proves no usable mount was installed and cleanly detaches
its authority session. A Linux mount needs `/dev/fuse` and a mounted fusectl
filesystem at `/sys/fs/fuse/connections` with the connection's abort file
writable by the mount owner.

macOS mounts through the FSKit profile above.

Windows has no declared transport, released client, or install path. The
`auto` selector refuses it at a stable primitive gate. The evidence and the
gates for a future transport are in
[docs/windows-mount.md](./docs/windows-mount.md).

## The routing declaration

`.portablefs/local-dirs` is the single source of a volume's machine-local
routing. Its rule syntax and its canonicalization, which determines the
revision hash every mount must agree on, are frozen. Routes change only
through the authority's admin `ApplyRoutes` compare-and-swap; a mount or live
session on a different revision fails closed.

## The CLI surface

`portablefs mount`, `reauthorize`, `umount` (alias `unmount`), `mounts`,
`mount-loss`, `route`, `prune-local`, `daemon`, `doctor`, `mount-check`, and
`version` are the user-facing commands, with `--json` on each and the
`PORTABLEFS_MOUNT_TOKEN` environment variable. Documented flags and JSON
fields keep their meaning; consumers must ignore unknown JSON fields.
`mount-check --probe-mount` is the one mutating option: it installs and removes
one throwaway FUSE mount and is opt-in for that reason. `lifecycle`,
`install-macos-app`, and `install-linux-release` are installer and app
coordination surfaces, not a user contract.

`portablefs version --json` advertises exactly these capability strings, each
a separate consumer contract unrelated to the authority major:

- `hosted-mount-reauthorization-v1`;
- `hosted-automatic-mount-reauthorization-v2`;
- `linux-mount-loss-observation-v1` (Linux builds only).

Automatic hosted mounts advertise `hosted-automatic-mount-reauthorization-v2`.
Their enrollment identity has the enrollment CA's remaining certificate
validity, while the Manager keeps a separate sliding lease that a fresh
successful refresh renews and replayed, rate-limited, or failed refreshes do
not. A lapsed active lease becomes `EXPIRED` with termination reason
`lease-expired` before ordinary terminal retention pruning. A renewal scope
names one machine incarnation and may hold one active enrollment per volume;
scoped issuance supersedes only the prior active enrollment for the same
product issuer, scope, and volume, and advancing the scope epoch revokes every
lower-epoch enrollment in the scope.

The installer reads `PORTABLEFS_VERSION`, `PORTABLEFS_GITHUB_REPO`,
`PORTABLEFS_INSTALL_DIR`, and, for a repository other than
`steerlabs/portablefs`, the five `PORTABLEFS_EXPECTED_*` identity values.

## External hosted contracts

These are consumed outside this repository, so they are preserved even where
an internal component could change:

- the Manager HTTP API and its JSON outputs, including `CreateAdmissible` and
  `RestoreAdmissible` alongside the status fields;
- the enrollment and reauthorization request and response schemas;
- the three CLI capability strings above. The OpenSteer Runner requires
  `hosted-automatic-mount-reauthorization-v2` before it reports a workspace
  mount ready;
- the `v1` literals in the external workspace integration: the Manager HTTP
  API prefix, the product-authorization format, and the mount capability
  envelope. None of them names the authority protocol major.

## Release identity

The tag-to-artifact chain is frozen: SemVer tag, stamped binary version, the
exact two-binary client archive membership, `checksums.txt`, the published
attestation bundles, and on macOS the signed bundle identity tuple (team ID,
bundle identifier, app group, FSKit type `pfs`, resource scheme
`dev.portablefs.oss`). A signed Mac app contains its CLI, Go daemon, and Swift
extension from one immutable commit, with exact executable and bundle matching.
See [docs/release-identity.md](./docs/release-identity.md).

A Mac release is identified by exactly its daemon's CodeDirectory hash,
executable SHA-256, and release version. Protocol numbers are not part of the
release identity and are not sealed into the bundle: after a release and its
running daemon are authenticated, the daemon reports its own live identity
(schema 1, control protocol, `pfslocal` major and minor). Before any socket
request, the CLI and the app authenticate the daemon peer identically: from
the connection's kernel audit token they require the same user, the exact
canonical daemon path inside the authenticated owning bundle, the running
image's kernel CodeDirectory hash equal to the release's, and valid,
hardened-runtime code (`CS_VALID` and `CS_RUNTIME`); any failure refuses the
connection. Incoming activation and every ordinary operation then require the
live schema, control protocol, and `pfslocal` version to equal the incoming
build's exact constants. Quiescence of an outgoing release instead accepts
that release's own reported numbers, and the incoming build's compiled
numbers are never imposed on it. Lifecycle v1 is the one cross-release surface
on that socket:

| Route | Purpose |
| --- | --- |
| `GET /lifecycle/v1/identity` | Identity schema 1, including the serving release's actual control and `pfslocal` versions. |
| `GET /lifecycle/v1/inventory` | Exactly `{"attachment_count": N}`, counting every active or persisted registered attachment once, terminal and revivable entries included. |
| `POST /lifecycle/v1/stop-if-idle` | Empty body. Closes attach admission and atomically requires the same inventory to be empty before stopping: `204` with no body on success, `409` busy with no state change. |

Any other status is a failure, never an empty-inventory or stopped proof. A
host authenticates the outgoing release and its running daemon as above
before it accepts that release's reported versions, and uses lifecycle v1
only to quiesce it. Ordinary mount and attach operations always require the
incoming paired release. An inventory snapshot is not removal authority:
process termination, kernel inventory, and the state singleton supply that
proof. The state singleton is one canonical flock inode that is never
unlinked or replaced to bypass a holder; a holder stuck in kernel exit blocks
startup until the kernel releases it.

The upgrade invariant has two cases. A running outgoing daemon is quiesced
only through its lifecycle v1 inventory and `stop-if-idle`; the incoming
release never decodes the outgoing daemon's private registry. With no
outgoing daemon running, and while the host holds the state singleton and the
lifecycle exclusion, only the actual absence of `attaches.json` in the
validated daemon state directory proves an empty registry. Any entry at that
name blocks replacement, whatever its size, type, or contents. The daemon keeps
that invariant by durably unlinking the file (with a parent-directory sync)
when its registry becomes empty and writing it atomically while it is not;
an empty registry is never written as a file.

## Private state

Repository-owned persistent state carries one exact format marker per owner
and fails closed on a malformed or unequal marker. No historical decoder or
migration exists; protocol-8 deployments are provisioned fresh. The markers
are in the version table above. These formats are internal: a later change
may introduce a new marker, and must then specify its own upgrade path.

## Changing a contract surface

After launch:

- **Authority wire.** Any grammar or semantic change is a new exact major and
  ALPN, refused by the old major at the handshake. Implementation changes and
  explicitly variable negotiated capacities can evolve within a major.
- **Paired local interfaces.** `pfslocal` and operational control change with
  the paired release under a new exact version.
- **Lifecycle v1.** Stays frozen across operational bumps. An incompatible
  lifecycle change needs a separately designed upgrade boundary.
- **Public non-wire surfaces** (CLI commands, flags, JSON meanings, documented
  environment names, routing syntax, capability strings, hosted contracts).
  Evolve additively, or deprecate in docs and release notes and remove only at
  a product-major boundary.
- **Release identity.** Not changed to match a version number.

PRs that touch a surface listed here must say so and explain the compatibility
story.

## Internal

No stability promise, including in patch releases: Go package paths and layout
under `vcs/`, Swift package internals under `swift/`, mount records,
environment knobs not documented in this file or under [docs/](./docs/), test
helpers, scripts, benchmark harnesses and their trace format, metric names not
listed in the deployment guide, and documentation wording. The hosted Manager
state, signed cell-plan schema, and helper state are internal formats with
exact markers; their external outputs are listed above.

## Qualification status

None of the following has passed on the integrated protocol-8 tree. Until each
has, this contract is a specification, and earlier protocol results are not
evidence for it.

- `bash scripts/verify-local.sh --full`: Darwin Foundation/cgo and static Linux
  builds, native and race Go suites, the exact native Swift inventory,
  release-trust and current-architecture checks, the privileged XFS/FUSE suite,
  and the Linux coherence matrix.
- Native macOS 26 and 27 acceptance: first usable proof before readiness,
  terminal enforcement, the 128-callback window, no product-owned mount-root
  descriptor, one unforced unmount with real `EBUSY` under normal system
  indexing, explicit force, exact final inventories, and buffered-I/O
  delivery. Isolated signed mounts must cover healthy and terminal sessions,
  busy references, and undelivered dirty pages, recording callback results,
  `/sbin/umount` status, exact kernel inventory, and PortableFS reconciliation.
  Check ordinary refusal and explicit force independently, eventual cleanup,
  and a fresh attach incarnation. Cleanup-only acknowledgements and errorless
  unmount completion do not qualify durability or mount removal; native
  fixtures and static framework inspection cannot prove these outcomes. See
  [FSKit verification](./docs/fskit-mount.md#verification).
- Native signed-app lifecycle: the CLI and the app accept the real shipping
  daemon and refuse a substituted image renamed onto its path, a two-release
  upgrade with different control and `pfslocal` numbers quiesces through
  lifecycle v1, and the absent-daemon path proceeds only on `attaches.json`
  absence.
- FSKit-handler power-cut recovery around acknowledged mutations
  ([power-loss-testing.md](./docs/power-loss-testing.md)).
- Shared-cell durability: a real two-project XFS writeback fault and dirty-
  neighbor barrier latency, with a separate-filesystem control.
- Writer exclusion and resource pressure: proof, fence, deadline, apply drain,
  readmission, second-Mac refusal, and bounded resources under tiny limits.
- Suspend/resume on macOS and Linux with the stated continuous clocks.
- The unchanged LAN workload: a 1,200-file initial Git add within its
  120-second deadline, subsequent commits, integrity checks, and detach. There
  is no numerical forecast; see [performance.md](./docs/performance.md).
- Fresh hosted cell provisioning with current membership, plan, and state
  formats, and external reauthorization.
