# Architecture

Status: **root product contract**

This document states what PortableFS is and what it must never become. It is
deliberately short. The complete v3 design — the storage model, the coherence
protocol, the security boundaries, the failure model, and the proof gates — is
in [xfs-authority-architecture.md](./xfs-authority-architecture.md), which is
the core document. Anything more specific than the invariants below belongs
there or in one of the contracts it references.

## The product

A user mounts a volume on a machine and runs ordinary programs against ordinary
files. The same volume mounts on another machine at the same time, and both see
one live filesystem. That mounted tree is the product. It is not a cache of a
product stored elsewhere.

## Root invariants

1. **The live filesystem is the product.** Anything that makes the mounted view
   less like a local filesystem — eventual visibility, silent divergence,
   invented merge semantics — is a regression regardless of what it buys.

2. **One volume has exactly one authority.** A volume is one XFS project
   directory served by one `portablefs-authority` process on one Linux host.
   Two writers to one volume tree is a correctness bug, not a scaling
   configuration.

3. **XFS is the only durable filesystem truth.** PortableFS holds no second
   inode tree, no content index, no mutation log, no checkpoint format, no
   branch graph, and no write-back overlay. Authority state is disposable epoch
   state: sessions, open file descriptions, locks, replay slots, cancellation.
   The one durable exception is strict-mount membership, which records only
   which cached kernel mounts a previous epoch admitted.

4. **Data-plane acknowledgement means applied.** Linux direct-I/O `write(2)`
   completes after XFS application. The macOS 26 FSKit tier also forwards
   callbacks synchronously, while stating its weaker kernel-cache boundary.
   PortableFS owns no separate tail to replay or park.

5. **Coherence is synchronous or absent.** A cached frontend either holds state
   the authority repaired synchronously before the mutation returned, or it holds
   no cached state at all. There is no asynchronous invalidation stream that a
   reader can outrun.

6. **Shared writing uses declared filesystem semantics.** Atomic rename,
   authority-serialized exclusive create, distinct files, POSIX record locks,
   `flock`, and append intent work through the exact Linux frontend. An active
   macOS 26 mount owns one compatibility writer lease: Linux peers can read,
   but their visible mutations return `EBUSY` until the Mac unmounts. macOS 26
   does not provide distributed locks or authority atomic append. PortableFS
   does not merge file contents or invent conflict resolution to hide a
   platform gap.

7. **One transport per supported platform, with no fallback.** Linux mounts
   through kernel FUSE. macOS 26 mounts through one named FSKit best-effort
   policy. Unknown Mac policies and Windows remain primitive-gated. A host
   without a supported transport fails with guidance rather than substituting
   a different filesystem or protocol.

8. **Unsupported is explicit.** Shared file-backed `mmap`, `setxattr`, device
   nodes, FIFOs, sockets, and cross-volume rename are refused with a real errno.
   They are never emulated with divergent semantics. Linux and the authority
   expose unsupported xattr mutation as `EOPNOTSUPP`; no client invents a
   second xattr store. macOS advertises its operation-level limits and returns
   the matching errno.

9. **Lifecycle control stays out of filesystem I/O.** The optional hosted
   manager may store placement, quota entitlement, PKI, authorization receipts,
   desired state, and observed health. It never stores file bytes or metadata
   and is not consulted by ordinary reads, writes, locks, or visibility repair.
   Cells poll it outbound; network input never becomes a privileged path,
   command, unit file, or executable.

## What not to build

- A second durable store, index, or operation log beside XFS.
- Client write-back caching, or any acknowledgement path that returns before the
  authority applied the bytes.
- Asynchronous cache invalidation presented as a coherence guarantee.
- History, branches, forks, snapshots, or commits in the filesystem surface.
  That was the v2 product; the v3 reset removed it deliberately.
- Tenant command execution inside the storage plane.

## Where the details live

| Question | Document |
| --- | --- |
| How the authority, protocol, and coherence protocol actually work | [xfs-authority-architecture.md](./xfs-authority-architecture.md) |
| Exact visibility, durability, and retry rules | [consistency-model.md](./consistency-model.md) |
| What a process observes when something breaks | [failure-modes.md](./failure-modes.md) |
| Running a volume | [xfs-authority-deployment.md](./xfs-authority-deployment.md) |
| Hosted placement, credentials, reauthorization, and fencing | [hosted-control-plane.md](./hosted-control-plane.md) |
| Deploying a hosted XFS cell | [hosted-cell-deployment.md](./hosted-cell-deployment.md) |
| The macOS 26 best-effort boundary and future exact requirements | [macos-26-coherence-contract.md](./macos-26-coherence-contract.md) |
| The shipping macOS FSKit mount path | [fskit-mount.md](./fskit-mount.md) |
| Why Windows currently fails closed and what a native frontend must prove | [windows-mount.md](./windows-mount.md) |
| Machine-local routing and its confinement boundary | [graft-security.md](./graft-security.md) |
| What is actually verified, and how | [cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md) |
| Compatibility and what can be pinned | [../COMPATIBILITY.md](../COMPATIBILITY.md) |

## Verification contract

A change to this system is not complete until `bash scripts/verify-local.sh`
passes. A change to the authority, the frontends, or the coherence protocol is
not complete until `bash scripts/xfs-fuse-integration.sh` passes on real XFS with
a real FUSE mount booted from the exact patched Linux 6.12.100 series, and
`bash scripts/coherence-matrix-linux.sh` passes on that same kernel in the
strict protocol with its falsifiability controls intact. A stock-kernel run is
a refusal test, not substitute evidence.
