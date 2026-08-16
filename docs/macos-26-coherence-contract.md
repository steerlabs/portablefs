# macOS FSKit coherence support boundary

Status: **no production protocol-5 macOS mount is admitted on any currently
documented FSKit version**

PortableFS is a strict shared filesystem. Returning from a mutation is not
enough: the source mount must publish the exact authoritative result to its
kernel cache, and every peer must make older namespace, attribute, and data
state unobservable before acknowledging COMPLETE. Current FSKit cannot close
both boundaries.

Production therefore fails before authority Attach. It does not select a short
TTL, reinterpret a cache-policy name, switch to a local filesystem, or continue
with weaker semantics.

## Production selection

The refusal is enforced independently at three layers:

1. The ordinary macOS CLI rejects macOS 26, macOS 27, and unknown later
   versions before starting portablefsd or requesting an authority Attach.
2. The shipping FSKit extension rejects `loadResource` before resolving or
   opening the local daemon socket.
3. A shipping portablefsd rejects every protocol-5 FSKit `EnsureAttach` before
   constructing or dialing an authority transport.

The duplication is intentional. A stale CLI, a directly invoked extension, or
a direct daemon control request cannot bypass the unsupported-platform fact.
There is no runtime opt-in.

The SDK-26 and SDK-27 adapters remain as compile, unit-test, and separately
signed qualification code. The SDK-27 live lane requires both the exact CLI
build stamp `sdk27-live-qualification-only` and the portablefsd compile tag
`portablefs_macos27_qualification`. The embedding build applies the tag to both
helpers. The stamp does not admit macOS 26, macOS 28, or the shipping
extension. A qualification artifact is not a supported product mount.

## The missing source boundary

After a successful authority mutation, the initiating FSKit callback must
return every post-state attribute snapshot that the framework may cache. The
snapshot must be authoritative and tied to the exact stable identity; a later
`getattr`, a guessed local value, or an assumed framework refresh is not the
same transaction.

The legacy macOS 26 `FSVolume.Operations` result surface is incomplete:

| mutation | attributes the strict callback must publish | macOS 26 result |
| --- | --- | --- |
| set attributes / truncate | item | item attributes available |
| write | item, including post-write size and times | no item attributes |
| create, mkdir, symlink | created item and parent | no item or parent attributes |
| hard link | linked item and parent | no item or parent attributes |
| remove | removed item and parent | no item or parent attributes |
| rename | moved item, source parent, destination parent, and overwritten item when present | none of these attributes |
| set/remove xattr | affected item | no affected-item attributes |

This is not only a response-schema gap. The legacy callback has no supported
place to consume the missing values. In particular, a cached parent `getattr`
may remain stale after a local namespace mutation because the callback neither
returns the parent snapshot nor invokes a documented parent-attribute
invalidation primitive.

macOS 27 `FSVolume.Handler` adds typed result attributes for create, symlink,
link, remove, rename, write, and setattr. That is a stronger source boundary,
but the xattr result still reports only free-space information, and source
results do not solve peer invalidation.

## The missing peer boundary

A peer PREPARE must close overlapping local admission. After authority apply,
the peer must revoke every affected kernel name, inode attribute, and data
entry before COMPLETE is acknowledged. An asynchronous notification or a
future TTL expiry cannot establish that cut because the kernel may answer from
cache without re-entering the extension.

No currently documented FSKit version exposes an exact module-initiated
namespace or inode-attribute invalidation API. The macOS 27 data-cache handler
can act on retained item data, but it does not invalidate names or attributes.
Apple DTS has also stated that inode/attribute invalidation currently does not
exist and that FSKit does not yet fully support shared/network filesystems:
[Apple Developer Forums thread 821376](https://developer.apple.com/forums/thread/821376).

Consequently, SDK 27 cannot acknowledge a general peer COMPLETE exactly even
when its source callback can return most post-state attributes.

## Why the existing mechanisms are not substitutes

The protocol-5 source-publication gate is necessary, but it cannot itself edit
FSKit's kernel caches. Holding it longer only prevents later ordered mutations;
reads on the initiating mount may still consume an old parent or item
attribute.

A nested synthetic VFS callback is not a root transaction. It can re-enter the
outer callback's own locks, cannot address a newly created item before the
outer reply installs it, and relies on undocumented cache side effects. The
same objection applies to rename-to-scratch, chmod-as-refresh, truncate-based
data eviction, lookup probes, and provenance-based callback swallowing. Those
paths remain qualification experiments, not production correctness primitives.

Force-unmount is a terminal fencing action. It limits how long a failed mount
can continue serving; it cannot turn a successful mutation callback or peer
COMPLETE into an exact cache publication.

Returning `ECANCELED`, shortening TTLs, mounting through another local path, or
retrying automatically would likewise change behavior without closing the
missing cache boundary. None is a supported fallback.

## Protocol implemented in qualification code

The retained adapters exercise the root protocol without claiming that FSKit
can complete its platform half:

- Every visible mutation derives one canonical source gate from stable
  identities before replay assignment or send. Item targets use ATTR or DATA,
  where DATA implies ATTR. Namespace targets use parent stable identity plus
  raw name and an exact bound-item ATTR/DATA scope.
- Setattr gates the item (DATA for a size change); write gates item DATA;
  create, mkdir, symlink, and unlink gate parent ATTR plus the name's bound ATTR;
  rename gates both parent ATTR coordinates and both names; hard link also
  gates the existing item; xattr mutations gate item ATTR.
- Item and handle identities must agree. An unknown post-binding remains a
  conservative scoped wildcard until the authority reply supplies its exact
  stable identity or proves that no binding remains. Per-call claim counts keep
  concurrent requests in one callback from resolving each other's wildcard.
- Source-first ordering holds the local gate while peers receive PREPARE,
  repair COMPLETE, and acknowledge it. The source receives no filesystem
  visibility event. Peer-first overlapping source admission fails definite
  pre-apply before replay identity assignment or authority send; disjoint work
  remains independent.
- Exact replay retains the same logical lease. An assigned uncertain result is
  terminal. A definite pre-apply interruption can return and release normally.
- The gate releases only after both the daemon request reservation retires and
  the exact FSKit callback sends `PublicationAck(PUBLISHED)`. Disconnect before
  that acknowledgement is terminal. `NOT_PUBLISHED` is terminal whenever any
  visible authority mutation in the logical operation committed.
- Peer PREPARE owns its cut through paired COMPLETE publication and authority
  acknowledgement. There is no mount-wide source gate, source PREPARE/COMPLETE,
  source ticket, boolean publication attestation, or compatibility path.

These invariants prevent daemon/authority ordering bugs and remain useful when
FSKit eventually supplies the missing platform primitives. They do not make a
current macOS mount production-safe.

## Why post-attribute wire expansion is deferred

A generic authoritative post-mutation attribute set would be the cleanest
authority response shape: stable-identity keyed, canonical, unique, bounded,
and retained exactly by replay. It would need to cover the actual callback
completion identities—parents, moved or linked items, and removed or replaced
items where the framework result publishes them.

That schema is deliberately not added yet. macOS 26 has no callback result that
can consume most of it, and no current FSKit version can invalidate the peer's
namespace and attribute caches. Adding snapshots without an exact consumer
would create a misleading half-contract rather than a working architecture.

## Boundary for future production support

A future macOS/FSKit combination can be considered only when all of these are
documented and available at the actual deployment target:

1. Every visible source callback can publish the complete authoritative
   post-state attribute set for all affected stable identities.
2. A module can synchronously invalidate an exact peer namespace coordinate,
   exact inode attributes, and exact retained data without a path guess or
   synthetic filesystem mutation.
3. The invalidation operation has a completion boundary strong enough to keep
   PREPARE closed until local repair finishes and COMPLETE is acknowledged.
4. Failure is observable and terminal; the framework cannot report completion
   while stale state remains servable.

The supported SDK surface must then pass a mounted two-machine matrix, not only
unit tests:

- Prime source item and parent attributes, run every namespace and data
  mutation, and immediately read them back without relying on an unrelated
  callback to refresh the cache.
- Prime peer positive and negative names, item attributes, sizes, bytes, hard
  links, and open-unlinked objects; mutate from the other machine; prove no
  pre-COMPLETE value is observable after acknowledgement.
- Exercise source-first and peer-first races, same-name and disjoint operations,
  rename-over and same-inode rename, callback cancellation, lost replies,
  daemon disconnect, and forced fencing.
- Count the documented result/invalidation calls so an incidental cache miss or
  TTL expiry cannot make the test pass.

Observed automatic refresh on one kernel build is not enough to replace a
documented primitive. Until the entire boundary exists and the matrix passes,
production macOS remains refused before Attach.

## Historical qualification evidence

Earlier macOS 26.5 experiments exercised authenticated synthetic namespace,
attribute, and data actuators, saturation, and daemon-death fencing. Those runs
were valuable for finding callback cycles and shaping the source-owned gate.
They did not prove a supported cache transaction, and they are not a production
compatibility claim. Performance measurements from those qualification mounts
must be labeled as such; they cannot be compared as supported multi-writer
product results.
