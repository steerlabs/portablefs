# The FSKit mount (macOS)

Status: **supported protocol-6 FSKit profile with explicitly weaker cache,
append, and lock guarantees than Linux**

PortableFS ships the app, daemon, and FSKit extension for macOS 26 and 27. A
mount declares the immutable `FSKIT_SYNC_REPAIR` frontend profile before Attach;
it never claims or negotiates the Linux N/A/D/E lease profile.

## Platform contract

Protocol 6 permits cache only under authority N/A/D/E leases. Before a
conflicting mutation returns, every peer must prove it discharged the affected
name binding, attributes, clean data, and directory-enumeration state. Append
also requires the frontend to preserve `O_APPEND` intent so the authority can
place each write at true EOF, and the product requires distributed POSIX record
and `flock` operations.

Current public FSKit does not expose all of those primitives:

- no documented exact negative/positive namespace invalidation;
- no documented inode-attribute invalidation;
- no complete directory-enumeration invalidation contract;
- `FSVolume.OpenModes` carries read/write access but not append intent; and
- no advisory-lock callbacks.

`DataCacheHandler` on macOS 27 covers retained item data, but does not fill the
namespace, attribute, enumeration, append, or lock gaps. The FSKit profile
therefore retains ordered synchronous repair and states those edges as
best-effort instead of representing them as exact Linux coherence.

## Admission behavior

On Darwin, `portablefs mount` selects the FSKit profile exactly. Attach and
Activate echo that profile; replay or reconnect with a different profile is a
protocol error. The authority admits only the FSKit repair,
source-publication, fragmented-write, and shared filesystem operations for that
session. It does not issue lease grants or accept lease-control requests.

The frozen policy spellings `macos26-synchronous-vfs-repair-v1`,
`macos26-synchronous-vfs-repair-v2`, and `fskit-native-revocation-v1` remain
exact. They choose the host actuator inside the FSKit profile; none selects the
Linux lease profile.

## Qualification topology

Qualification builds keep the same three-piece local architecture:

```text
portablefs CLI -- owner-private control socket --> portablefsd
portablefsd    -- versioned pfslocal socket ----> FSKit extension
FSKit extension <-------------------------------> macOS kernel
```

The daemon owns authority credentials and session state; the extension owns
FSKit item identity and kernel callbacks. `pfslocal` frames are length-delimited
and versioned, and the extension validates daemon identity, mount identity, and
request shape before dispatch. Host, daemon, and extension must share the exact
signed app-group and bundle identity described in
[release-identity.md](./release-identity.md).

Ordinary macOS 27 selects the same shipping v2 synchronous-repair actuator as
macOS 26. The stronger SDK-27 native actuator remains build-stamped; runtime
flags cannot promote an older signed app into it or silently reinterpret an
unknown OS. The historical qualification spelling is retained as release
identity, not as a statement that protocol-6 mounting is disabled.

## Install and lifecycle

The notarized `PortableFS.app` remains the distribution unit. It contains the
CLI, per-user daemon service, and FSKit extension with one exact identity chain.
Users enable the extension in System Settings; installers cannot do that
silently. Replacement or re-registration of the host app can terminate the
live extension, so packaging and updater tests must continue to prove identity
and drain behavior.

The CLI and daemon private control API require exact release identity. A foreign
or stale daemon is left untouched and the command fails with clean-stop
guidance. There is no automatic replacement of an unknown socket owner.

The launchd-managed daemon appends to
`~/.local/state/portablefs/portablefsd.log`; per-mount logs are separate, under
`~/.local/state/portablefs/mounts/`. The per-mount wrapper and the attach's
renewal owner append there without sharing file offsets. Automatic mount-credential
renewal emits structured scheduled, succeeded, retrying, denied, cutoff, and
stopped events carrying sequence, deadline, retry, and bounded error metadata
only; capabilities, certificates, and tokens are never logged.

## Verification

- app, daemon, extension, entitlement, and bundle identity;
- daemon lifecycle and owner-private control sockets;
- `pfslocal` framing, version negotiation, item identity, and error mapping;
- callback implementations through unit and native Xcode tests;
- explicitly stamped live macOS 27 mounts and the macOS coherence matrix;
- profile mismatch refusal before Attach.

The native Swift suite is run with:

```bash
bash scripts/test-swift-xcode.sh
```

The live matrix accepts already-mounted paths and never changes their profile:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/a --mount-b /path/b
```

## Historical evidence

[macos-26-coherence-contract.md](./macos-26-coherence-contract.md) defines the
current best-effort profile and labels its protocol-5 measurements as dated
evidence.
[protocol5-hosted-qualification-2026-08-16.md](./protocol5-hosted-qualification-2026-08-16.md)
records the hosted protocol-5 qualification. That receipt remains dated
evidence, not a protocol-6 result.

[macos-27-native-coherence.md](./macos-27-native-coherence.md) tracks the SDK-27
API audit and the remaining gaps. New host primitives can strengthen the
profile without silently changing its current guarantees.
