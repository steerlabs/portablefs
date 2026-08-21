# macOS 27 native FSKit coherence

Status: **optional build-stamped protocol-6 `FSKIT_SYNC_REPAIR` actuator with
native data revocation; ordinary macOS 27 uses synchronous VFS repair v2**

No currently documented FSKit release supplies the complete primitives needed
for Linux-equivalent lease semantics. macOS 27 nevertheless remains operational
through the explicit FSKit synchronous-repair profile: the ordinary app selects
the shipping v2 synchronous-VFS actuator, while a separately signed and
build-stamped artifact selects native data revocation. Both retain the declared
namespace, attribute, enumeration, append, and lock gaps. Unknown policies
still fail before Attach.

## Exact missing primitives

The Linux profile requires exact discharge of N/A/D/E leases before a
conflicting mutation returns. FSKit does not claim that profile. The table
retains the source/peer audit vocabulary because it describes the host cache
controls that keep the Mac contract weaker.

| FSKit generation | source callback boundary | peer repair boundary |
| --- | --- | --- |
| macOS 26 `FSVolume.Operations` | `setAttributes` can return item attributes, but create, symlink, link, remove, rename, and write cannot return their complete item/parent post-state | no supported namespace, inode-attribute, or data-cache invalidation API |
| macOS 27 `FSVolume.Handler` | typed results add child/parent, linked/parent, removed/parent, renamed/both-parents/overwritten, write-item, and setattr-item attributes; the xattr result still carries only free space | `DataCacheHandler` can act on retained item data, but there is still no supported namespace or inode-attribute invalidation API |

Keeping a source publication gate closed does not fix either absence: local
reads may still consume stale kernel attributes, and a peer COMPLETE cannot be
acknowledged until its kernel effects are exact. A synthetic nested VFS
operation is also not a contract. It is reentrant, can cycle on the callback's
own locks, cannot address a newly created item before the outer reply installs
it, and depends on undocumented cache side effects.

Apple DTS has now stated directly that inode/attribute invalidation “currently
doesn't exist” and that FSKit does not yet fully support shared/network file
systems: [Apple Developer Forums thread 821376](https://developer.apple.com/forums/thread/821376).

## Documented SDK 27 contract

Apple introduced the `FSVolume.Handler` family and `FSVolume.DataCacheHandler`
in macOS 27. Both remain beta as of August 2026.

`DataCacheHandler` negotiates data caching when a file opens. The kernel asks
for one of `none`, `readWithCache`, or `readWriteWithCache`; the module grants
`noCache`, `readCache`, `writeThrough`, or `writeBack` within Apple's allowed
mapping. A module can later call
`setCacheState(for:cacheMode:coherencyType:action:)` to synchronously push,
invalidate, update, or revoke cache state for one `FSItem`.

Apple states two constraints that shape this adapter:

- `setCacheState` must run without module-internal locks because the kernel may
  call back into the module while applying the transition.
- `revoke` applies when an item no longer exists or is no longer accessible.
  Apple's examples describe deletion or a server callback reporting absence.

References:

- [FSKit updates](https://developer.apple.com/documentation/updates/fskit)
- [`FSVolume.Handler`](https://developer.apple.com/documentation/fskit/fsvolume/handler)
- [`FSVolume.DataCacheHandler`](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler)
- [`setCacheState`](https://developer.apple.com/documentation/fskit/fsvolume/setcachestate%28for%3Acachemode%3Acoherencytype%3Aaction%3A%29)
- [`KernelCacheCoherencyAction.revoke`](https://developer.apple.com/documentation/fskit/fsvolume/kernelcachecoherencyaction/revoke)

## PortableFS data-cache policy

PortableFS may grant at most:

| kernel request | PortableFS grant |
| --- | --- |
| `none` | `noCache` |
| `readWithCache` | `readCache` |
| `readWriteWithCache` | `writeThrough` |

`writeBack` is forbidden. A successful PortableFS write already means the
authority accepted those bytes into XFS current state; no client-only dirty
tail can exist after that acknowledgement. `writeThrough` preserves that rule
while allowing the kernel to retain clean data.

For a peer data mutation, the authority's PREPARE phase first closes and drains
overlapping callback publication. COMPLETE may then use synchronous
`invalidate` on the exact retained `FSItem`. It must not use `pushInvalidate`:
pushing an old dirty page after the peer mutation could overwrite the newer XFS
state. This safety argument still needs the live data and memory-mapping matrix.

## Repairs that remain unproven

Apple's published `DataCacheHandler` contract describes data cache state for an
`FSItem`. It does not separately promise positive-name, negative-name, or
attribute-cache invalidation.

This was rechecked against the headers shipped in Xcode 27 beta build
`27A5237l`, macOS SDK 27.0 build `26A5406c`, not inferred from the web
documentation. The only module-to-kernel cache-state operation in `FSVolume`
is the item-scoped `setCacheState` method.
`FSItem.Attributes.invalidateAllProperties()` only marks fields inactive on an
attributes object that the module is populating; it does not invalidate
attributes already cached by the kernel. The SDK has no name-entry or kernel
attribute-cache notification operation.

| PortableFS repair | SDK 27 status |
| --- | --- |
| data for a retained item | Representable through `invalidate`, pending live proof |
| data for an open, unlinked item | Representable through the retained `FSItem`, pending live proof |
| remotely deleted item | `revoke` matches Apple's documented use, pending open-handle proof |
| positive binding after rename or replacement | No documented mapping |
| negative name becoming present | No `FSItem` exists; no documented mapping |
| attribute or size metadata without data invalidation | No documented mapping |
| attributes of an open, unlinked item | No documented mapping |

Calling `revoke` on a renamed item would exceed Apple's stated contract because
the item still exists and may have open descriptors. Calling it on the parent
directory in the hope that child name entries disappear is also an assumption.
The exact adapter must not do either unless the final SDK contract says so
and the installed-kernel matrix proves the required behavior.

Until every row has a supported representation, no shipping app selects the
native SDK-27 adapter. The separately signed development host may serve a test
mount only when paired with a CLI and portablefsd carrying the exact build-time
tag; an unsupported repair then fails the mount terminally before COMPLETE. It
never substitutes the macOS 26 repair mechanism under the native policy name.

## Adapter boundary

The SDK-27 implementation belongs in its own source target and build lane. It
reuses `VolumeCore`, the pfslocal transport, stable item objects, visibility
planner, exact cursor runner, and publication barrier. The checked-in
qualification adapter now implements `DataCacheHandler` open, close, and
upgrade negotiation, injects one synchronous data-cache invalidator without
holding adapter locks, and compiles as a separately signed FSKit extension with
Xcode/SDK 27.

That completes the documented data-cache boundary; it does not manufacture
the namespace or attribute invalidation primitives the SDK does not expose.
Those two missing repair families, plus their live kernel matrix if Apple adds
them, are the remaining production gates.

The checked-in `PortableFSKitMacOS27` package compiles the exact
`FSVolume.DataCacheHandler` constraint and
`setCacheState(for:cacheMode:coherencyType:action:)` call from the SDK 27
headers. Its `PfsFSKit27DataCacheInvalidator` resolves an event to the exact
retained `FSItem`, then requests `.none`/`.noCache` with `.invalidate`. This is
the least-permissive valid state and cannot leave stale client data cached. The
type has no namespace or attribute operation and is not linked by either
shipping app target.

The checked-in qualification adapter implements the reply-handler forms of the
three `DataCacheHandler` methods on the existing volume. It deliberately does
not use their Swift async alternatives: resuming a continuation would let an
inner reply return before the outer Handler result necessarily reached FSKit.
Open invokes FSKit's real cache-result reply inside the existing admitted
`openItem` callback, so the shared barrier publishes only after that reply
returns. Upgrade uses the same exact item-scoped admission/reply edge even
though it performs no authority operation. Close has no error channel; its
shared wrapper fully retires the strict mount after an authority-close failure
before issuing FSKit's real no-error reply.

The adapter deliberately keeps the existing reply-handler forms for ordinary
filesystem operations. They give PortableFS an observable framework-reply
return edge for its publication barrier. Moving those operations to the SDK-27
`Handler` result family would expose richer result objects, but would not add a
namespace or attribute invalidation API and is not required for the documented
data-cache contract.

Compile that lane with Xcode 27 explicitly:

```sh
DEVELOPER_DIR=/path/to/Xcode-beta.app/Contents/Developer \
  xcrun swift build \
  --package-path swift/PortableFSKitMacOS27
```

The adapter is a separate Swift 6.4 package with a macOS 27 deployment target.
The macOS 26 package does not discover or compile it during its normal build
and test lane.

The macOS 26 target must continue to compile without SDK-27 symbols. A compiler
condition that hides uncompiled native code is not a verification lane.

Inside qualification and unit-test composition, `VolumeCore` still requires an
adapter to declare its exact policy set before Resolve. The macOS 26 test set
retains both frozen experimental revisions; the SDK-27 qualification adapter
contains only `fskit-native-revocation-v1`. A mismatch closes the pfslocal
connection and returns `ENOTSUP`. Shipping composition never reaches Resolve.

The CLI has a second, independent gate. Its normal build selects the shipping
synchronous-VFS-repair v2 policy on both macOS 26 and macOS 27. The signed
development lane may stamp exactly `sdk27-live-qualification-only` into
`nativeFSKitPolicyQualification` with Go `-ldflags -X`; its packaging tag
selects the matching SDK-27 app/extension layout. This is a build identity, not
a runtime environment toggle. It selects native revocation only for that
artifact, does not alter macOS 26's policy, and leaves macOS 28 and later
refused until independently qualified. OS version detection alone never
authorizes the native policy.

Qualification mount readiness is also policy-specific. After `/sbin/mount`
returns, the CLI proves the exact `pfs` kernel identity, asks `portablefsd` to
attest that a live `portablefskit` connection completed `Hello` and
`Resolve(attachRef)` for this native-policy attach, then proves the unchanged
kernel identity again. The witness is registered only after the Resolve reply
is delivered and is removed synchronously when that connection closes or the
attach detaches. The daemon's own frontend preflight uses a different client
name and cannot satisfy it. The app-group socket and signed packaging identity
authorize the peer; `Hello.ClientVersion` is the Swift protocol-client revision,
not a daemon release identifier. The CLI independently proves the exact paired
daemon release before it creates the attach.

This path performs no I/O through the mounted directory. In particular it does
not request Network Volumes privacy access and does not install the macOS 26
repair-root descriptor. Native DataCacheHandler revocation has no such
descriptor/actuation channel.

## Live qualification

Run the signed extension against the same hosted XFS volume mounted by a Linux
writer. Each peer mutation must finish before the Mac observation begins.

The minimum matrix covers:

- clean and cached file data, EOF growth, shrink, sparse ranges, repeated
  invalidation, and mapped-file refusal;
- negative lookup followed by peer create, positive lookup followed by delete,
  rename within one parent, rename across parents, rename-over, and hard-link
  aliases;
- mode, ownership, timestamps, link count, size, and directory attributes;
- open-after-unlink reads and writes, deletion with a retained vnode, final
  close, reclaim, daemon loss, extension loss, and forced unmount; and
- two Mac mounts plus Linux, with source and peer mutations under concurrency.

Record both the application observation and the FSKit callback/cache-state
trace. A passing return from `setCacheState` proves only that the kernel accepted
that call; it does not by itself prove that a later lookup, getattr, or read
crossed the required visibility boundary.

Production selection stays disabled if any case is stale, hangs past the repair
budget, breaks open-descriptor semantics, or requires an undocumented side
effect. A later Apple API may close the missing namespace and attribute rows; if
it does not, `fskit-native-revocation-v1` remains a refused policy.
