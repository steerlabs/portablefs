# Compatibility

This is the PortableFS v3 stability contract.

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
  `portablefs-authority-v5` and authority protocol major `5`. Plaintext is
  refused; there is no fallback mode and no environment escape.

  The names are worth reading carefully, because two version numbers are in play
  and they do not mean the same thing. `portablefs-authority-v5` and protocol
  major `5` name the *authority protocol* generation, not the product
  generation. Authority protocol 5 requires exactly one authenticated DATA
  transport and one authenticated CONTROL transport in the same random
  connection set. Attach returns only a provisional credential. The session
  becomes active exactly once, through Activate, after both role bindings and
  their generations are proven; AbortAttach names the exact attach attempt.
  A provisional session cannot execute filesystem or visibility operations.
  There is no single-connection or direct-active-attach compatibility path.

  Protocol 5 retains protocol 4's exact-replay treatment
  of every capability acquisition. For mutations, the client sends only its
  owned replay slot and sequence; the authority derives the content identity
  with a per-epoch secret keyed fingerprint over the full canonical body. The
  secret and fingerprint never cross the wire, and replay state is discarded
  with that same epoch. Protocol 5 carries write-transaction DATA fragments in
  `WriteTransactionRequest.Data`, complete single-fragment writes in
  `OneShotWriteRequest.Data`, and read payloads in `ReadReply.Data` as the
  frame's one exact out-of-line bulk body. The protobuf
  metadata and bulk lengths are both in the frame header; a bulk body on any
  other message, or an inline copy of either bulk field, is a protocol error.
  This removes client-side mutation hashing and payload-sized protobuf copies
  without adding another data path.
  In particular, Lookup is not a side-effect-free read: its reply transfers an
  item capability that must be returned exactly once or explicitly reclaimed.
  Protocol 4 also permits a visibility `Next` request to atomically acknowledge
  its `after` cursor and long-poll for the successor. Repeating that request
  after a lost response is safe because the exact last accepted cursor remains
  idempotent. Protocol 5 replaces source self-phases with one exact
  source-publication gate: the initiating frontend closes and drains its stable
  item/name footprint before dispatch, the authority independently derives and
  validates that same footprint, and PREPARE/COMPLETE are delivered only to
  other cached participants. On Linux the local gate remains closed through
  the kernel's operation-specific VFS postprocessing and the physical ACK of a
  forced `FUSE_PFS_PUBLISH`; a daemon `write(/dev/fuse)` returning is not that
  boundary. Qualification frontends must supply an equally explicit framework
  publication verdict. A post-apply local publication failure ends the mount
  rather than reopening stale state. Protocol-4 single-transport
  direct activation and protocol-5 paired, provisional activation are
  wire-incompatible, so peers fail at TLS ALPN and `Hello` rather than mix
  lifecycles.

- **Both peers name what they require, and refuse on absence.** A session
  requires the `xfs-current-state`, `session-exact-epoch`, `direct-write`,
  `framed-bulk-data-v1`, `authority-keyed-replay-fingerprint-v1`,
  `visibility-ack-next-v1`, `mandatory-dual-transport-v1`,
  `transactional-shared-write-v1`, `one-shot-write-v1`, `strict-linux-mutation-suite-v1`,
  `terminal-applied-delivery-receipt-v1`,
  `strict-two-phase-visibility`, `classified-visibility-interruption`,
  `sequenced-visibility-retry-v1`, `lockless-namespace-repair-v1`,
  `source-publication-gate-v1`,
  `namespace-post-binding-identity`, and `exact-resource-acquisition` features at `Hello`, and `write-through`,
  `no-history`, `no-branches`,
  `direct-io-no-file-mmap`, `user-xattr-readonly`, `single-principal`,
  `distributed-posix-locks`, `stable-item-identity`, `readdir-plus-items`,
  `volume-syncfs-barrier`, `transactional-shared-write-v1`,
  `one-shot-write-v1`, and `exact-resource-acquisition` at `Activate`. A
  strict attach additionally requires
  `strict-two-phase-visibility`, `classified-visibility-interruption`,
  `sequenced-visibility-retry-v1`, `lockless-namespace-repair-v1`,
  `source-publication-gate-v1`, and
  `namespace-post-binding-identity` in its Activate reply. These strings are the contract's shape written down: an
  authority that stopped meeting one of them would be refused rather than
  silently tolerated.

  `one-shot-write-v1` is the additive protocol-5 write operation for a payload
  no larger than negotiated `max_write`. It is one source-gated replay-slot
  mutation and has no transaction ID or staging phase. Larger writes use the
  existing BEGIN/DATA/COMMIT transaction shape. The size boundary selects one
  shape deterministically; neither shape is a runtime fallback for the other.

  The sequenced visibility retry is an internal Linux liveness transaction,
  not an application errno or a timed retry. The authority names the exact
  peer COMPLETE that blocked a callback; after repairing it, the frontend
  resubmits with that sequence. The authority accepts the proof only for the
  same callback identity and its retained one-shot FIFO debt. This lets both
  namespace and inode operations wait behind a CONTROL ACK already in flight
  without allowing a stale, forged, or FSKit request to bypass visibility
  ordering. Strict Linux namespace repair is lockless dentry expiration; the
  retired parent-lock profile is refused rather than translated into an
  application-visible synthetic `EINTR`.

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
cache primitives required for a strict shared filesystem, so production macOS
mounts are refused before Attach rather than advertising a smaller guarantee.

The explicit refusals are equally frozen, because programs depend on getting an
errno rather than incoherent data: shared file-backed `mmap`, `setxattr`, device
nodes, FIFOs, sockets, setuid execution, and cross-volume link and rename. The
XFS authority and Linux expose unsupported xattr writes as `EOPNOTSUPP`. The
macOS xattr mapping remains covered by qualification tests, but it is not a
production surface while all macOS protocol-5 mounts are refused.

### Mount transports

Linux mounts through kernel FUSE. macOS 26 mounts through the shipping FSKit
extension under the named `macos26-synchronous-vfs-repair-v2` best-effort
policy. One active Mac owns the volume's compatibility writer lease; Linux
peers may read but their visible mutations return `EBUSY`, and a second Mac
writer is refused before activation. There is no protocol fallback, local
filesystem substitution, or runtime policy opt-in. macOS 27 remains a separate
qualification-only native-cache track.

Windows has no declared transport, released client binary, or install path yet.
The pure `auto` selector carries a stable primitive-gate refusal that any future
Windows build must reach before attach: the evaluated signed user-mode
filesystem runtimes do not expose both authority-forwarded byte-range locks and
synchronous cache control. PortableFS does not turn a locally coherent Windows
drive into a falsely multi-writer mount. The evidence and the gates for
declaring a future transport are in
[docs/windows-mount.md](./docs/windows-mount.md).

### Declared macOS cache policies

Three cache-policy names remain in the protocol so clients are classified
precisely: the frozen macOS 26 v1/v2 synchronous-repair policies and
`fskit-native-revocation-v1`. Shipping macOS 26 selects v2 explicitly; v1 is a
frozen compatibility spelling and both callback-serialized profiles acquire
the same exclusive writer lease at authority admission. The native policy is
qualification-only. An unknown policy still fails closed; no name is
reinterpreted as another policy.

The SDK-27 adapter remains a compile and test lane for protocol work. It
requires the exact build-time qualification stamp
`sdk27-live-qualification-only` in the CLI and the compile-time
`portablefs_macos27_qualification` packaging tag. These are properties of a
separately signed qualification artifact, not environment toggles. The stamp
does not change macOS 26's product policy or admit macOS 28. An unsupported
repair terminates a qualification mount before COMPLETE; passing a
qualification test does not promote the native policy to product support.

The best-effort boundary is architectural. macOS 26 `FSVolume.Operations`
callbacks cannot return every exact source snapshot or invalidate every peer
namespace/attribute cache shape. The writer lease prevents a second machine
from mutating underneath that missing primitive; repair failure still fences.
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
fails at its FSKit primitive gate before readiness or Attach. Qualification-only
readiness code remains internal and makes no production compatibility promise.

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
  session-bound `Reauthorize` operation without making older protocol-5
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
