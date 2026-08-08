# Liveness and coherence follow-ups

Status as of 2026-08-05, branch `codex/xfs-authority` at `dba5b8f` ("v3: remove
the v2 architecture entirely"): this file was a running ledger from the
2026-07-30 incident and its validation campaign, written against the v2 journal
stack. Most of that ledger is gone with the code it described. What remains
below are the items whose subject matter survives the reset — an unexplained
observation, four macOS platform gaps, and one design question that must be
re-asked rather than carried forward as an answer. None of them is fixed, and
none of them has been re-verified against a live v3 mount, because no live-mount
campaign has been run on this tree.

## Open

### Transient ENODATA reading a peer's just-created file

Observed once, during a two-Mac stress run: `read peer done marker: no message
available on STREAM` immediately after the file had become visible to the
reading machine. An implicit retry succeeded. It was never reproduced and never
root-caused.

The observation predates the v3 reset, so it is not evidence about the current
data plane. It is kept because the failure shape — a name that resolves,
followed by a read that returns `ENODATA` rather than bytes or a definite error
— is exactly the kind of defect the coherence work is meant to make impossible,
and "we saw it once and never explained it" is not a closed item.

Next step is a repro, not a fix: run `scripts/two-mac-stress.sh` against v3
mounts with daemon tracing on and capture the failing sequence. Do not make code
changes on the strength of the original sighting.

### macOS FSKit platform gaps

Kernel-verified on macOS 26 during the v2 campaign. These are properties of
Apple's framework, not of PortableFS code, so the reset did not touch them. Each
still needs a Feedback radar filed, and each still needs re-confirmation against
the v3 FSKit extension before it is quoted as a v3 contract.

- **Negative dentries are cached permanently.** There is no revalidation against
  parent attributes and no invalidation API, so a lookup performed before a name
  exists blinds that machine to the name until a *local* mutation purges the
  directory's cache. Cross-machine "stat-poll until it appears" cannot work.
  Enumeration always consults the filesystem and is the supported discovery
  pattern. This is the same absence that makes the macOS 26 cache contract a
  release gate rather than a claim; see
  [macos-26-coherence-contract.md](./macos-26-coherence-contract.md).
- **No advisory-lock operations.** FSKit exposes no lock callbacks, so
  cross-machine `fcntl`/`flock` exclusion is impossible from a macOS mount. The
  v3 adapter conforms to the operations, open/close, read/write, xattr, and
  pathconf protocols and to nothing else, so this is unchanged. The supported
  cross-machine mutual-exclusion primitive on macOS remains `O_EXCL` create,
  which the authority serializes exactly once. Linux is not in this position:
  the Linux frontend refuses to mount unless the kernel forwards both POSIX
  record locks and `flock` (see [consistency-model.md](./consistency-model.md)),
  so the two platforms differ here by design and the difference must stay stated.
- **No append intent.** `FSVolume.OpenModes` carries only read and write access
  bits and writes arrive with kernel-resolved offsets, so cross-machine
  `O_APPEND` interleaving cannot be expressed on FSKit; FUSE mounts do get true
  authority-assigned append offsets. Use per-writer files, or write-tmp+rename.
  The boundary is stated in [fskit-mount.md](./fskit-mount.md).
- **Replacing the hosting app tears down live mounts.** Replacing or
  re-registering an app that hosts an FSKit extension makes `pkd` `SIGTERM` the
  running extension instance, killing every live mount mid-write. Installers and
  updaters must drain mounts first. This one has a concrete v3 consequence that
  is not yet designed: the release installer replaces PortableFS.app, so the
  install path and the mount lifecycle interact and neither currently accounts
  for the other.

These belong in user-facing consistency documentation as contracts once
re-confirmed, not only in a follow-up list.

### Path-scoped repair versus inode-shared objects — re-ask, do not assume

The v2 form of this question was: an operation scope that has already passed the
frontend gate cannot be re-blocked when the operation subsequently discovers a
hard-link alias inside that scope, because attribute reads were delegated per
path and not per inode. Narrowing lookup and enumerate scopes was therefore
unsound, and closing it properly needed a design that decoupled alias discovery
from the publication gate.

The delegation machinery that framed it is gone. The v3 macOS stack answers a
structurally similar question with two separate indexes rather than one scope:
`PfsMacOSNamespaceIndex` keys per name coordinate and keeps a reverse index so
every alias of a hard-linked item survives independently, while
`PfsMacOSLiveObjectIndex` tracks live objects, and unlink removes a coordinate
from the first without retiring the object in the second.

That is a different design, and the fact that it is a better-shaped design is
not evidence that the original defect is absent. The question has to be put to
the v3 daemon and the v3 FSKit adapter on their own terms:

- can a repair whose plan was computed from one coordinate miss an alias that
  becomes reachable while the plan is executing;
- can an alias discovered mid-operation force a repair the publication barrier
  has already admitted past;
- and does the answer differ between the Linux FUSE mount, which has no such
  barrier, and the macOS mount, which does.

Nothing in the offline Swift suite can settle those, because none of it mounts a
real FSKit volume. Treat this as open and unmeasured, not as inherited-and-fixed.

## Made moot by the v3 reset

The remaining items in the original ledger — the legacy WAL store's checkpoint
losing birthtime and flags, non-atomic multi-group setattr, the unreconcilable
mount intent for a nonexistent branch, unifying the pre-lock credit grant with
the WAL reservation, the recovery gaps from the 2026-07-31 managed-Postgres
outage, and the long "Fixed on fix/root-architecture" and
"Fixed on fix/root-liveness-metadata" sections — all described mechanisms that
were deleted at `dba5b8f`: the write-back engine and its credit ledger, the
journal and its segment reclaim, delegation and publication scopes, access
leases, branches, the authority manager, and the hosted control plane. None of
them describes code that exists, so their per-item detail is not carried
forward. Recovering it means reading the history at or before `dba5b8f`, not
this file.
