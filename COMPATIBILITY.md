# Compatibility

This is the PortableFS v3 stability contract. Authority protocol 6 is a
deliberate wire reset from the retired protocol-5/private-kernel candidate;
there is no mixed-version execution path.

## v2 is gone

v3 is a breaking reset, not a migration. The v2 product — the remote
append-only journal, its TypeScript journal control plane, the client write-back stack,
and the history, branch, fork, snapshot, and lease surfaces built on them — was
deleted from the tree, not deprecated. There are no tombstones, because there is
no service left to answer with one, and there is no conversion path, because
there is nothing left to convert with.

What survives from v2 is a small amount of local-machine machinery that was
never journal-specific: mount records, the daemon control socket, the installers,
and the macOS bundle identity. Persisted v2 attach and lease records are
recognised and refused with remount-or-discard guidance rather than silently
reinterpreted.

If you are running v2, v3 is a separate product. Its wire protocol refuses a v2
client at the handshake rather than negotiating down.

Everything below describes v3 and only v3. If a surface is not listed here,
treat it as internal and unstable.

## Frozen

Breaking changes are prohibited. Deployments and clients may pin against these.

### The authority wire

- **Transport is mutually authenticated TLS 1.3**, with ALPN
  `portablefs-authority-v6` and authority protocol major `6`. Plaintext is
  refused; there is no fallback mode and no environment escape.

  The names are worth reading carefully, because two version numbers are in play
  and they do not mean the same thing. `portablefs-authority-v6` and protocol
  major `6` name the *authority protocol* generation, not the product
  generation. Authority protocol 6 requires exactly one authenticated DATA
  transport and one authenticated CONTROL transport in the same random
  connection set. Attach returns only a provisional credential. The session
  becomes active exactly once, through Activate, after both role bindings and
  their generations are proven; AbortAttach names the exact attach attempt.
  A provisional session cannot execute filesystem or visibility operations.
  There is no single-connection or direct-active-attach compatibility path.

  Protocol 6 retains session-exact replay, canonical framed bulk data,
  object-relative authority operations, paired transport activation, and
  write-through mutation acknowledgement. Each mount declares one immutable
  frontend profile. `LINUX_LEASES` uses authority-issued N/A/D/E leases for
  name bindings, attributes, whole-file clean data, and directory enumeration.
  `FSKIT_SYNC_REPAIR` uses the ordered PREPARE/COMPLETE repair and source-
  publication surfaces that the macOS API can actually drive. A conflicting
  mutation closes every affected Linux lease audience and FSKit repair audience
  before XFS apply and does not reopen either early. The initiating syscall's
  response is the external completion/visibility boundary; the mutation
  linearizes after XFS apply and before that response, consistently with the
  guarantees declared by its frontend profile. Linux source A/D/E and daemon N
  state are purged before the reply; kernel entry validity is always zero, so
  rename cannot transplant an old leased dentry timeout. There is no private
  kernel publication message.

  Writes use ordinary `FUSE_WRITE` between Linux and the daemon. Operation
  identity, replay, and streaming are daemon-to-authority concerns; no kernel
  transaction, one-shot capability, private opcode, or completion ring is part
  of the contract. Append placement is the one
  decision the frontend forwards rather than makes: `WriteRequest.append` asks
  the authority to place the payload at the true EOF and `assigned_offset`
  reports where it landed. The intent is the description's
  `O_APPEND`, which stock `FUSE_WRITE.flags` reports. The per-call
  `RWF_APPEND`/`RWF_NOAPPEND` flags are not forwarded by stock Linux and are
  disclosed deviations: the former arrives as a positioned write at the offset the
  kernel derived, the latter keeps appending.

- **Both peers name what they require, and refuse on absence.** Every mount
  requires the common paired-transport, canonical-framing, replay,
  write-through, stable-identity, single-principal, and read-only-user-xattr
  assertions. A `LINUX_LEASES` session additionally requires
  `lease-coherence-v1` and `directory-enumeration-lease-v1` at `Hello`, then
  `lease-renewal-v1`, `lease-recall-v1`, `open-by-identity-v1`, direct I/O, and
  distributed Linux locks at `Activate`. Its successful cacheable responses
  carry `lease_grants`; CONTROL traffic uses `next_lease_event`,
  `acknowledge_lease_event`, `acknowledge_source_lease_discharge`, and
  `renew_leases` with their exact response counterparts. An
  `FSKIT_SYNC_REPAIR` session instead requires `fskit-sync-repair-v1`,
  `fskit-source-publication-v1`, and `fskit-fragmented-write-v1`; its CONTROL
  traffic uses the FSKit repair stream and never receives a Linux lease grant.
  Absence of any feature required by the selected profile refuses the session;
  features are not negotiated into a weaker profile.

  Protocol 6 freezes a 20-second maximum authority lease horizon and a
  five-second client withdrawal interval. A client anchors the wire
  `valid_for_nanos` duration at request start, ends local cache validity five
  seconds before that horizon, and authorizes no caching when the remaining
  duration cannot contain the withdrawal interval. Renewal, withdrawal, and
  terminalization are independent; a blocked renewal cannot extend cache
  validity or postpone the hard horizon.

  Attach declares one required session purpose. `MOUNT` is the only purpose
  that receives a root capability or joins durable mount membership; a Linux
  mount joins the lease coordinator and an FSKit mount joins the repair
  coordinator. `ROUTE_ADMIN` requires signed admin access and is restricted to
  route CAS and session plumbing; it receives no root, lease cursor, or repair
  cursor and never joins mount membership. A mount session cannot invoke
  `ApplyRoutes`, even when its credential also has admin scope. This separation
  makes the route clean-absence check exclude only a control connection, never
  a possible mount.

  Feature advertisement proves what the authority can execute; it does not
  manufacture a callback that a host filesystem API does not expose. In
  particular, `distributed-posix-locks` proves the authority's lock operations
  for frontends that forward them. Linux FUSE does. macOS FSKit exposes no
  advisory-lock callback, so a macOS process does not receive cross-machine
  `fcntl` or `flock` exclusion from that feature.

- **A wire-incompatible change gets a new exact protocol major and a new ALPN**,
  and requires a coordinated client and authority upgrade. PortableFS fails
  closed instead of carrying a second compatibility execution path.

- **Requests are object-relative.** Activate returns an opaque root token; lookup
  takes a parent token and one raw name component. The authority never accepts a
  host path or a client-supplied inode number, and every token is invalidated at
  an epoch change.

### Filesystem semantics

The guarantees in [docs/consistency-model.md](./docs/consistency-model.md) are
frozen: write-through acknowledgement, `fsync` on the authoritative descriptor,
`close` is not an implicit `fsync`, session-exact replay inside an epoch, no
silent continuation across an epoch, atomic rename, and open-after-unlink. The
authority implements independent POSIX record and `flock` lock namespaces, and
Linux FUSE forwards both. Current FSKit exposes neither lock callback nor the
N/A/E cache primitives, per-reply non-installing metadata control, nor exact
append intent. macOS therefore declares the separate `FSKIT_SYNC_REPAIR`
profile and its smaller guarantees instead of advertising Linux lease
semantics.

Cross-mount namespace coherence covers forward pathname resolution and
directory enumeration. Reverse rendering of an already-held Linux dentry
(`getcwd`, `/proc/*/fd`, and other `d_path` users) is outside that guarantee:
stock Linux performs no FUSE revalidation for those observations and exposes no
receipt that can make a remote rename linearizable there. This is an explicit
semantic boundary, not a weaker negotiated profile.

The explicit refusals are equally frozen, because programs depend on getting an
errno rather than incoherent data: shared file-backed `mmap`, `setxattr`, device
nodes, FIFOs, sockets, setuid execution, and cross-volume link and rename. The
XFS authority and Linux expose unsupported xattr writes as `EOPNOTSUPP`. The
macOS xattr mapping remains covered by its explicit FSKit profile tests and is
not evidence for Linux-equivalent cache coherence.

### Mount transports

Linux mounts through stock kernel FUSE protocol 7.31 or newer. PortableFS
requires only upstream FUSE requests and notification semantics; it advertises
no PortableFS-private capability bit and recognizes no private opcode. A kernel below 7.31 is
refused during FUSE INIT rather than served through a reduced semantic profile.
The authority session is established first because the kernel level is revealed
only by INIT; on refusal the client proves that no usable mount was installed
and cleanly detaches that session.

macOS 26 and 27 mount through the explicit protocol-6 `FSKIT_SYNC_REPAIR`
frontend profile. It is selected before Attach, pinned into the canonical
session fingerprint, and cannot change on replay or resume. The authority does
not issue N/A/D/E grants to it; it retains the FSKit PREPARE/COMPLETE,
source-publication, and fragmented-write bodies behind a strict profile
allowlist. Linux sessions cannot invoke those bodies, and FSKit sessions cannot
invoke lease control. This is a declared platform contract, not probing,
fallback to an older protocol major, or local-filesystem substitution.

Windows has no declared transport, released client binary, or install path yet.
The pure `auto` selector carries a stable primitive-gate refusal that any future
Windows build must reach before attach: the evaluated signed user-mode
filesystem runtimes do not expose both authority-forwarded byte-range locks and
synchronous cache control. PortableFS does not turn a locally coherent Windows
drive into a falsely multi-writer mount. The evidence and the gates for
declaring a future transport are in
[docs/windows-mount.md](./docs/windows-mount.md).

### Declared macOS cache policies

The frozen macOS 26 v1/v2 synchronous-repair policy spellings and
`fskit-native-revocation-v1` name the admitted implementations behind the
protocol-6 FSKit frontend profile. They do not select the Linux lease profile
or imply identical guarantees.

Ordinary macOS 27 uses the admitted
`macos26-synchronous-vfs-repair-v2` actuator under the FSKit profile. The
SDK-27 native adapter is selected only by an app built and signed with its exact
compile-time capability stamp
`sdk27-live-qualification-only` in the CLI and the compile-time
`portablefs_macos27_qualification` packaging tag. The historical spelling is
frozen even though protocol 6 admits the resulting stronger actuator; it is a
property of the signed artifact, not a runtime toggle or fallback. The stamp
does not alter the ordinary v2 policy or automatically admit a future macOS
release. An unsupported repair terminates the mount before COMPLETE.

The weaker boundary is architectural. macOS 26 `FSVolume.Operations`
callbacks cannot return every exact source snapshot or invalidate every peer
namespace/attribute cache shape. The writer lease prevents a second machine
from mutating underneath that missing primitive within the FSKit profile's
declared constraints; it is not a proof of Linux lease semantics.
macOS 27 `FSVolume.Handler` adds most source result attributes, but current
FSKit still has no documented exact namespace or inode-attribute invalidation
API for peer changes; its data-cache handler covers only retained item data. A
TTL change, polling loop, or hidden retry cannot manufacture those primitives.
See
[docs/macos-26-coherence-contract.md](./docs/macos-26-coherence-contract.md) and
[docs/macos-27-native-coherence.md](./docs/macos-27-native-coherence.md).

### The routing declaration

`.portablefs/local-dirs` is the single source of a volume's machine-local
routing. Its rule syntax and its canonicalization — which determines the revision
hash every mount must agree on — are frozen. Routes are replaced only through the
authority's admin `ApplyRoutes` compare-and-swap; a mount or a live session on a
different revision fails closed.

### The CLI surface

`portablefs mount`, `reauthorize`, `umount`, `mounts`, `route`, `prune-local`, `daemon`,
`doctor`, `mount-check`, and `version` are the user-facing commands, along with
`--json` on every one of them and the `PORTABLEFS_MOUNT_TOKEN` environment
variable. Documented flags keep their meaning; new flags and new JSON fields may
appear, and consumers must ignore unknown fields. `lifecycle`,
`install-macos-app`, and `install-linux-release` are installer and app
coordination surfaces, not a user contract. The shipping macOS mount command
selects synchronous VFS repair v2 on macOS 26 and 27 before Attach. Only the
separately stamped SDK-27 artifact selects native readiness; unsupported OS and
policy combinations still fail before Attach.

### Release identity

The tag-to-artifact identity chain — SemVer tag, stamped binary version, the
exact two-binary client archive membership, `checksums.txt`, the published
attestation bundles, and on macOS the signed bundle identity tuple (team ID,
bundle identifier, app group, FSKit type `pfs`, resource scheme
`dev.portablefs.oss`) — is frozen. Clients and installers verify against it. See
[docs/release-identity.md](./docs/release-identity.md).

## Evolvable

Additive evolution with versioning; consumers tolerate additions.

- New authority operations and new feature strings behind the existing
  handshake, where an authority that lacks them still serves the frozen set.
  `session-reauthorization-v1` is one such optional feature: it adds an exact,
  session-bound `Reauthorize` operation without making older protocol-6
  authorities invalid for standalone mounts. `mount-enrollment-reauthorization-v1` names
  the Manager-enrollment grant basis; an automatic mount requires it and fails
  its handshake against an older authority instead of changing renewal modes.
- New optional protobuf fields. Unknown fields are not part of the protocol —
  the canonical request encoding rejects them — so a field is added on both sides
  or not at all.
- `pfslocal` minor version bumps. The local protocol between `portablefsd` and
  the FSKit extension is major 1, currently minor 15, and grows additively.
- New environment variables, where leaving one unset preserves previous
  behaviour.
- New authority bounds and timeouts. Their defaults may change; a deployment that
  cares pins them explicitly.
- New telemetry series and events. A shipped name keeps its meaning or follows
  the deprecation process below.

## Internal

No stability promise, including in patch releases: Go package paths and layout
under `vcs/`, Swift package internals under `swift/`, the on-disk shapes of mount
records and the strict-membership file, environment knobs not documented under
[docs/](./docs/), test helpers, scripts, benchmark harnesses, and documentation
wording.

The per-user `portablefsd` HTTP control API is also a private paired-release
surface. The CLI and the menu app require an exact `/v1/identity` match for the
daemon version, executable digest, and control protocol before issuing any
operational request. This is deliberately stricter than the additive `pfslocal`
policy: an older live daemon is left untouched and the operation fails closed
until it is cleanly drained.

The hosted manager HTTP API, signed cell-plan schema, helper durable state, and
manager state file are likewise internal in this initial foundation. They fail
closed on unknown fields and carry explicit schema/version fields, but they are
not frozen public APIs yet. The authority protocol additions they use remain
additive under the rules above.

## Changing a frozen surface

Frozen does not mean immortal; changes are deliberate and staged.

1. Propose the change in an issue explaining why additive evolution cannot work.
2. Ship the replacement additively while the old surface keeps working, and mark
   the old surface deprecated in docs and release notes.
3. Keep the deprecated surface for at least one minor release line, with a typed
   warning or refusal where feasible.
4. Remove it only in the next major version.

A protocol-visible change is the exception that skips straight to a new exact
protocol major: PortableFS would rather refuse a mount at the handshake than
serve one under a contract neither side can name.

PRs that touch a frozen surface must say so explicitly and explain the
compatibility story. Reviewers should reject silent changes to anything in the
frozen list.
