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
  `portablefs-authority-v3` and authority protocol major `3`. Plaintext is
  refused; there is no fallback mode and no environment escape.

  The names are worth reading carefully, because two version numbers are in play
  and they do not mean the same thing. `portablefs-authority-v3` and protocol
  major `3` name the *authority protocol* generation, not the product
  generation. Authority protocol 3 makes every capability acquisition an exact
  replay operation. In particular, Lookup is not a side-effect-free read: its
  reply transfers an item capability that must be returned exactly once or
  explicitly reclaimed. A protocol-2 peer can leak the first capability when a
  successful reply is lost, so peers fail at `Hello` rather than mix lifecycles.

- **Both peers name what they require, and refuse on absence.** A session
  requires the `xfs-current-state`, `session-exact-epoch`, `direct-write`,
  `strict-two-phase-visibility`, `exact-parent-repair-interruption`,
  `classified-visibility-interruption`, `source-phase-queueability`,
  `namespace-post-binding-identity`, and `exact-resource-acquisition` features at `Hello`, and `write-through`,
  `no-history`, `no-branches`,
  `direct-io-no-file-mmap`, `user-xattr-readonly`, `single-principal`,
  `distributed-posix-locks`, `stable-item-identity`, `readdir-plus-items`, and
  `volume-syncfs-barrier`, and `exact-resource-acquisition` at `Attach`. A
  strict attach additionally requires
  `strict-two-phase-visibility`, `exact-parent-repair-interruption`,
  `classified-visibility-interruption`, `source-phase-queueability`, and
  `namespace-post-binding-identity` in its attach reply. These strings are the contract's shape written down: an
  authority that stopped meeting one of them would be refused rather than
  silently tolerated.

- **A wire-incompatible change gets a new exact protocol major and a new ALPN**,
  and requires a coordinated client and authority upgrade. PortableFS fails
  closed instead of carrying a second compatibility execution path.

- **Requests are object-relative.** Attach returns an opaque root token; lookup
  takes a parent token and one raw name component. The authority never accepts a
  host path or a client-supplied inode number, and every token is invalidated at
  an epoch change.

### Filesystem semantics

The guarantees in [docs/consistency-model.md](./docs/consistency-model.md) are
frozen: write-through acknowledgement, `fsync` on the authoritative descriptor,
`close` is not an implicit `fsync`, session-exact replay inside an epoch, no
silent continuation across an epoch, atomic rename, open-after-unlink, and
independent POSIX record and `flock` lock namespaces.

The explicit refusals are equally frozen, because programs depend on getting an
errno rather than incoherent data: shared file-backed `mmap`, `setxattr`, device
nodes, FIFOs, sockets, setuid execution, and cross-volume link and rename.
The XFS authority and Linux expose unsupported xattr writes as `EOPNOTSUPP`.
For a production v3 attach, pfslocal advertises the xattr family but separately
advertises xattr set as unsupported. macOS validates the item and name, refuses
set/create/replace/upsert before emitting a daemon mutation, and exposes
Darwin's distinct `EOPNOTSUPP` (102), not `ENOTSUP` (45): XNU interprets 45 as
permission to create an AppleDouble `._*` sidecar. PortableFS never substitutes
that second xattr store. Read, list, and removal remain ordinary daemon calls.

### Mount transports

Linux mounts through kernel FUSE; macOS mounts through the FSKit extension and
the `portablefsd` v3 data plane. One transport per platform, no fallback. A host
that cannot serve its platform's transport fails with guidance rather than
degrading to a weaker consistency model.

### Declared macOS cache policies

A macOS mount names its cache policy and the authority validates it. Three names
are declared: the frozen `macos26-synchronous-vfs-repair-v1`, the current
`macos26-synchronous-vfs-repair-v2` compatibility policy, and
`fskit-native-revocation-v1`, the macOS 27 native policy, which is
declared so that it can be refused explicitly rather than approximated. An
unknown policy fails closed with `ENOTSUP`. A policy name means exactly one set
of semantics forever; a changed contract gets a new name. See
[docs/macos-26-coherence-contract.md](./docs/macos-26-coherence-contract.md).

The frozen execution semantics are load-bearing:

- `macos26-synchronous-vfs-repair-v1` declares the authority's
  `CALLBACK_SERIALIZED` participant profile. While that participant owes
  PREPARE or deferred COMPLETE, its new or already-queued mutation is refused
  definite-preapply with a classified `EINTR` and retained as that replay
  outcome. The legacy FSKit boundary exposes that `EINTR` unchanged. An
  overlapping FSKit callback arriving after local PREPARE is refused `EBUSY`
  before any pfslocal request.
- `macos26-synchronous-vfs-repair-v2` declares the identity-aware
  `CALLBACK_SERIALIZED_PIPELINED` profile and translates classified authority
  interruption to `ECANCELED` at the FSKit edge. macOS 26 may re-enter a
  mutating callback after `EINTR`, `EBUSY`, or `EAGAIN` with a fresh replay
  identity, so v2 never exposes those restartable outcomes for a publication
  refusal. A peer repair, an unknown callback identity, another mutation from
  the exact callback that initiated the outstanding source phase, or a request
  whose `source_phase_queueable` proof is false is still interrupted
  definite-preapply. A distinct nonzero callback from that source may queue
  through its own PREPARE and deferred COMPLETE only when that exact ordered
  request carries `source_phase_queueable=true`. True means the Swift frontend
  committed the request while the callback had submitted no ordinary request
  of any kind, and will therefore exclude that ordered-only callback from its
  own-source PREPARE drain. A mixed callback carries false, is revoked and
  drained locally, and its ordered mutation is interrupted before prepare or
  apply at the authority. A pristine callback parks locally before dispatch.
  Source repair never re-enters FSKit and COMPLETE waits only for the initiating
  callback, so the explicitly proven ordered-only queue has no reverse
  dependency. After a peer's local COMPLETE, overlapping callbacks likewise
  park until the authority accepts that exact cursor; the ACK-only gap never
  reaches mutation order.
  Once any ordered mutation frame is dispatched, cancellation waits for its
  exact outcome; loss of that outcome terminates the mount with `EIO`.
- `fskit-native-revocation-v1` declares the `INDEPENDENT` participant profile.
  It never inherits callback-serialized interruption; until native cache repair
  is implemented, attach fails closed instead.

Changing either profile, errno boundary, pre-apply guarantee, or replay meaning
requires a new cache-policy name.

### The routing declaration

`.portablefs/local-dirs` is the single source of a volume's machine-local
routing. Its rule syntax and its canonicalization — which determines the revision
hash every mount must agree on — are frozen. Routes are replaced only through the
authority's admin `ApplyRoutes` compare-and-swap; a mount or a live session on a
different revision fails closed.

### The CLI surface

`portablefs mount`, `umount`, `mounts`, `route`, `prune-local`, `daemon`,
`doctor`, `mount-check`, and `version` are the user-facing commands, along with
`--json` on every one of them and the `PORTABLEFS_MOUNT_TOKEN` environment
variable. Documented flags keep their meaning; new flags and new JSON fields may
appear, and consumers must ignore unknown fields. `lifecycle`,
`internal-root-probe`, `install-macos-app`, and `install-linux-release` are
installer and app coordination surfaces, not a user contract.

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
  session-bound `Reauthorize` operation without making older v3 authorities
  invalid for standalone mounts.
- New optional protobuf fields. Unknown fields are not part of the protocol —
  the canonical request encoding rejects them — so a field is added on both sides
  or not at all.
- `pfslocal` minor version bumps. The local protocol between `portablefsd` and
  the FSKit extension is major 1, currently minor 14, and grows additively.
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
