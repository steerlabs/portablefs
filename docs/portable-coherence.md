# PortableFS Portable Coherence Architecture

Status: DRAFT v3 after stock-FUSE and FSKit API audit. The writable Linux
profile supports exact append: placement is resolved by the authority at the true
EOF (§4.3), with the per-call flags stock FUSE does not forward disclosed as
deviations. Supersedes the private-kernel exact
profile defined in `docs/vnext-protocol.md` §2–§5 and the Linux exact-append
ABI. Authority protocol major for this architecture: **6 (portable)**. There is
exactly one architecture: no patched-kernel mode, no fallback profile, no
PortableFS-private kernel capability bits.

DRAFT here means protocol 6 is a **verification-candidate contract
(pre-launch)**, not a frozen one, and `COMPATIBILITY.md` states it with the same
words. The §12 L1–L6 program is what promotes it: until L6 closes, every surface
in `COMPATIBILITY.md` is reviewed as if frozen but is not yet a stability
promise.

Evidence was audited directly against pristine Linux 6.12.100 and established
lease-filesystem designs. The earlier review used **[SC §n]** and **[LS §n]**
labels for working notes; those research files are not present in this tree and
the labels below are provenance markers, not resolvable repository citations.
No portability or performance claim relies on their presence. Before this
document leaves draft status, each normative kernel claim must link a committed
source extract or upstream file:line reference.

v3 incorporates the adversarial reviews: commit-point reformalization (§1),
source-side discharge and the non-installing metadata lane (§2.2, §3.3),
whole-file data recall-to-none (§2.2), the directory-enumeration lease class
(§2.1, §5.4), authority-resolved exact append (§4.3), the honest
open-existing RPC shape (§5.2), the 7.31 semantic floor (§6), and the hidden
data-invalidation result as a second explicitly disclosed residual (§7.3b).
The FSKit audit defines a separate synchronous-repair profile and its weaker
host-cache, append, and lock boundaries (§8).

---

## 1. Correctness model

PortableFS presents one volume to many mounts as if it were a single local
filesystem. The formal bar is **linearizability of supported filesystem
operations**, with each operation's linearization point between its invocation
and response. Supported namespace observations are forward pathname resolution
and directory enumeration. Reverse rendering of an already-held dentry
(`getcwd`, `/proc/*/fd` links, and other `d_path` users) is outside this
coherence contract: stock Linux does not revalidate those observations, even
when `entry_valid` is zero, and FUSE exposes no receipt proving that a remote
rename has been incorporated into every retained dentry. This is a semantic
scope boundary, not a cache mode silently presented as coherent.

This is the target contract for supported operations. Append is inside it:
placement is resolved by the authority at the true EOF (§4.3). The two per-call
flags stock Linux does not forward are disclosed deviations of that section, not
silent reinterpretations of an offset.

1. A mutation linearizes at one point after its authoritative XFS apply and
   before its response, chosen consistently with observations by operations
   that overlap it. The response—the return of the mutating syscall—is the
   external completion and visibility boundary. The FUSE reply is not written
   until XFS apply and every conflicting peer discharge complete (§2.2).
2. Any operation whose relevant acquisition **begins after a mutation's
   response** observes post-mutation state — on every mount. "Relevant
   acquisition" is the operation's first read of kernel or daemon cache state
   that answers it, or the daemon's receipt of the request if nothing is
   cached.
3. An operation **concurrent** with a mutation (acquisition began before the
   mutation's response) may linearize on either side.

Why the response is a boundary rather than the exact linearization point: an
overlapping peer operation may already observe the new XFS state and complete
before the source syscall returns. The mutation must linearize before that
observation, while still remaining after XFS apply and before its own response.
Stock FUSE completes the source operation's VFS bookkeeping after the reply and
before returning to userspace. Remote leases are discharged before that reply.
The source daemon purges A/D/E state before writing it, and kernel name-entry
validity is always zero, so a rename cannot transplant an old leased timeout to
its new dentry. Stock VFS applies the namespace result before the syscall
returns. This proves forward pathname and enumeration publication on stock
FUSE; a generic userspace "reply written" callback alone is not a kernel
publication receipt, and the proof does not extend to reverse dentry rendering.

**Durability** is unchanged: write-through. Every acknowledged write,
namespace mutation, and attribute mutation has been applied to the authority's
XFS before its response. `fsync`/`fdatasync` remain the durability barrier
with group commit. No mount ever buffers a dirty mutation.

**Fail-closed rule.** Wherever this spec cannot prove freshness for a
post-response acquisition, the implementation must miss to the
daemon/authority or fence the mount — never serve a possibly stale answer.
The two bounded, explicitly accepted exceptions are §7.3a and §7.3b.

---

## 2. Lease model

Coherence is enforced by **authority-issued, TTL-bounded cache leases**
(NFSv4 delegations / AFS callbacks / SMB leases / closest: Ceph capabilities
[LS §2]). A lease is permission to *cache*, never permission to *mutate
locally*: all mutations remain write-through regardless of rights held.

### 2.1 Coordinate families and rights  [LS §3.2]

| Coordinate | Shared | Exclusive | Cache state covered |
|---|---|---|---|
| `N(parentStableID, rawName)` | N-R | N-X | one positive or negative name binding |
| `A(stableID)` | A-R | A-X | the complete attribute record (`PostState.Attr`) |
| `D(stableID, WHOLE)` | D-R | D-X | clean whole-file data and read-ahead |
| `E(dirStableID)` | E-R | — | a complete enumeration (membership) of one directory |

- Shared rights may be held by many mounts; an exclusive right by at most one
  mount, conflicting with all other rights in its family.
- `E-R` is the **directory-enumeration lease** (v1, shared only): it covers
  the *membership* of a directory — the fact that the holder's enumeration is
  complete. Any create/unlink/rename/link touching the directory recalls E-R
  (the authority already computes the parent-directory touched set for every
  namespace mutation, so recall wiring exists). Per-name N-R cannot substitute
  for E-R: no holder can enumerate leases for names it has never seen.
- Exclusive rights remain write-through. `D-X` is defined for sole-writer cache
  policy; append placement is resolved by the authority instead (§4.3). `N-X`/`A-X` are
  defined on the wire but never granted by v1 policy.
- Data leases are whole-file in v1; range leases are future-additive [LS §3.2].
- Xattr/ACL values have no cache class in v1.

### 2.2 Lease lifecycle

States per (coordinate, holder): `GRANTED → REVOKING → DISCHARGED`, with a
monotone **epoch** per (coordinate, holder) on every grant and revoke; a late
acknowledgment for an old epoch is rejected [LS §2.3, §3.3].

**Grant.** The authority MAY attach grants to successful read-side replies
(LOOKUP/RESOLVE → N-R + A-R; enumeration page → E-R; open-for-read → D-R).
Policy is conservative and server-side. A **changed mutation reply also carries
an A-R successor grant to its source** for every object its exact post-state
describes, except an object the mutation removed. That grant is issued after
every conflicting peer lease has discharged to none and after XFS apply, at a
fresh epoch, so it covers exactly the state the same reply carries and nothing
whose freshness this transaction did not just establish. It does not cancel the
source obligation below: the recalled epoch's payload is still purged before the
reply, and the fresh epoch is what the post-state is installed under. A peer
recall still holds the coordinate closed for the source, so a mutation racing a
peer's recall of the same coordinate installs no successor and its own follow-up
read is an ordinary miss.

The source's outstanding discharge receipt does not close a coordinate against
the source itself: the purge that receipt attests to happened before the reply
that let the next request be issued, so refusing the source there would make an
ordinary write-then-read on one mount return `EAGAIN`. Every earlier phase of
the transaction still blocks the source, because until peers discharge the
barrier is incomplete for everyone.

**A closed coordinate never refuses a read.** `read(2)` on a blocking
description has no retryable errno — `EAGAIN` reaches the caller verbatim and
permanently parks any runtime that then polls the descriptor — so a data read
that arrives during a recall waits and is then answered, never refused. The two
lanes wait for different lengths, and the difference is load-bearing:

- A **metadata** read waits for the whole barrier: reservation, recall, apply,
  and every discharge receipt. Nothing in a recall waits on a metadata reply, so
  holding one for the full transaction costs only latency, and it is then
  answered under fresh cache authority. That invariant is why **opening a file
  for reading is a data-lane admission, not a metadata one**: the frontend
  registers its page-cache publication and the recall's purge waits for that
  publication's reply, so an open on this lane would be something a recall waits
  on. Opening a *directory* stays here — an enumeration reply publishes no pages.
- A **data** read waits only until the mutation has **applied**, and is then
  admitted with the applied bytes and, unless it is the mount still discharging
  that recall, a fresh grant. What "the applied bytes" promises is exactly the
  bytes this read fetches, not that every folio of the inode agrees with them:
  until this mount's own COMPLETE purge runs, the page cache can still hold
  pre-apply folios beside them, and §3.3 records that mixed-state window. A read
  by the mount still discharging gets *no grant* — the coordinate is still under
  recall, so it still misses to the authority next time. It may not wait longer,
  because the FUSE_READ callback is holding the kernel folio that this same
  transaction's whole-file purge will need, and that purge runs strictly after
  apply. Waiting past apply would close the cycle and wedge the mount at its
  repair budget. The apply phase is bounded by the recall budget and the
  authority lease horizon; a coordinate still mid-apply beyond both belongs to a
  transaction that outlived every budget that should have fenced it, and the
  read fails hard rather than parking forever.

No other family gets a successor. N-R, D-R, and E-R recalled from the source are
discharged to none, and a later read reacquires state and cache authority
together.

**Revoke.** When a mutation's touched-coordinate set (the existing
`MutationDependencies`/`VisibilityTarget` rules; the cross-class recall table
of [LS §3.2] plus E-R for the parent directory) conflicts with outstanding
rights, the authority:

1. closes new grant admission for those coordinates;
2. marks each conflicting lease REVOKING and delivers the revoke on the
   per-participant CONTROL lane (today's PREPARE fan-out, reshaped);
3. waits for every peer's REVOKE acknowledgment, then sequences and applies the
   mutation to XFS;
4. sends COMPLETE with exact post-state to every affected peer and waits for
   every matching recall-to-none discharge;
5. if the source held affected leases, returns an exact source-discharge
   obligation while keeping those coordinates closed;
6. the source daemon performs the pre-reply and post-write discipline below,
   acknowledges that obligation, and only then may the authority reopen the
   coordinates. The syscall response remains the external visibility boundary
   (§1), even though the authority source barrier can finish just after it.

**Discharge (peer mounts).** A revoked v1 lease is discharged only by
**recall-to-none**: the holder purges *all* covered cache state (the full file
for D; the binding for N; attributes for A; the enumeration for E), follows the
§3.3 sequence, then acks. No covered state survives without a covering lease.

Range purge cannot be paired with a successor to a WHOLE lease: that successor
would again cover pages whose freshness was not re-established. Range leases
and a proof of gapless range continuity are a future protocol, not a v1 mode.

**Source-side discharge (the mutating mount).** The source is not sent its own
CONTROL recall, because waiting for that recall from inside the mutating FUSE
callback would create the parent-lock cycle found in review. Instead, the
authority captures its affected grants as a source obligation and leaves the
coordinates closed while the daemon performs this exact sequence:

- before returning the raw FUSE callback, invalidate source A and whole-file D
  state and purge daemon-held N/E state; these stock inode notifications do not
  acquire the VFS parent lock under the declared non-DAX, no-writeback profile;
- write the mutation reply. Stock VFS applies the reply's namespace and inode
  bookkeeping before returning the syscall. The response itself carries no
  successor cache validity unless the authority issued that exact successor;
- after the device write, acknowledge the exact source obligation. Kernel
  entry validity is always zero, including positive and negative LOOKUP replies,
  so no namespace notification or undocumented parent-lock receipt is needed;
- only that acknowledgment, or
  fencing followed by the original grants' authority expiry, reopens the
  coordinates.

A definite no-op restores the source's original grants and has no source
obligation. A changed operation with no affected source grant likewise needs no
receipt. This split removes the self-recall deadlock without dropping the
authority's obligation to remember source cache.

### 2.3 TTL, renewal, expiry

- Every grant carries a TTL **duration** (v1 default and protocol maximum 20 s).
  The client records a monotonic `requestStart` before sending the request. Its
  authority horizon is `requestStart + grantedTTL`; its cache-valid deadline is
  the horizon minus the frozen 5 s withdrawal budget, clamped at
  `requestStart`. Time spent in flight or processing therefore shortens both
  intervals, and a grant too short to leave a withdrawal interval authorizes
  no caching. The client never compares an authority absolute timestamp with
  its wall clock. Renewal uses a new request-start anchor; explicit RENEW
  exists. Renewal I/O, expiry scheduling, cache withdrawal, and the terminal
  watchdog are independent lanes: a stuck renewal cannot delay withdrawal.
- **Expiry is implicit discharge.** If a REVOKING holder does not discharge
  within the revoke budget, the authority fences it (existing machinery) and
  proceeds once its own grant-expiry deadline has elapsed. Post-response
  metadata and daemon validity end at the earlier cache-valid deadline. D-cache
  withdrawal starts then. If withdrawal is not proved before the authority
  horizon, an independent watchdog terminalizes and aborts the mount before
  the authority may proceed. Aborting stops new FUSE work; it is not proof that
  every already-resident clean page disappeared. Residual exposure: §7.3.

---

## 3. Stock-Linux client profile

The daemon mounts with **standard FUSE INIT negotiation only**. The portable
floor is **protocol 7.31** — the level of Linux 5.10, the oldest provider LTS
kernel PortableFS targets — which carries the full semantic surface the
product uses: entry/inode invalidation (7.12), flock (7.17), fallocate
(7.19), READDIRPLUS availability (7.21, unused), writeback negotiation (7.23,
declined), `copy_file_range` (7.28), `EXPLICIT_INVAL_DATA` (7.30) [SC §7].
Features above the floor (`HANDLE_KILLPRIV_V2` 7.33, `FUSE_SYNCFS` 7.34) are
used when advertised; when absent, the **stock kernel's own** degradation
semantics apply (e.g., the kernel's suid-strip SETATTR path) — PortableFS adds
no fallback of its own. There are no PortableFS capability bits; a stock
kernel ≥ 7.31 is the target. The relevant UAPI was source-audited across LTS
5.10/5.15/6.1/6.12 [SC §7]; current hosted CI exercises one Ubuntu stock
kernel, so the multi-LTS live matrix remains a qualification gate.

### 3.1 Cache-mode decisions

| Kernel cache class | Decision | Why |
|---|---|---|
| Dentries (`entry_valid`) | **Always zero** | N-R covers the daemon's binding cache, but stock rename can transplant an existing dentry timeout through `d_move`/`d_exchange`. Zero kernel validity removes the need for an undocumented post-reply parent-lock receipt for forward lookup. It does not make reverse `d_path` rendering coherent (§1). |
| Negative dentries | **Always zero** | Negative N-R still avoids an authority RPC; the kernel re-enters the daemon for validation. |
| Attributes (`attr_valid`) | **Granted** under A-R, ≤ conservative request-start deadline | INVAL_INODE sets inval_mask/attr_version [SC §6.3 rows 7–8]. |
| Directory cache (`FOPEN_CACHE_DIR`) | **Never** | Position-zero-only validation; unfixable midstream refill race [SC §5.1, §6.3]. |
| READDIRPLUS | **Not used** | Post-reply entry install has no version gate [SC §5.2, §6.3]. Plain READDIR only. |
| Symlink target cache | **Declined** | Shares data-cache races with no governing class [SC §4.6]. Daemon serves READLINK. |
| File data, **write-capable opens** | **FOPEN_DIRECT_IO** | No dirty/shared pages; no buffered split; avoids the unverifiable data-purge result for dirty state [SC §4.3, §6.2 item 5]. |
| File data, **read-only opens** | **FOPEN_KEEP_CACHE** under D-R | Clean pages; INVAL_INODE removes clean (even mapped) folios; enables page-cached reads and **exec/mmap-read**, which sandboxes require [SC §6.2 item 5]. Purge success is not observable on stock — bounded residual §7.3b; belt: an open without a D lease is granted without KEEP_CACHE, forcing the kernel's own unconditional cache drop for that inode at open [SC §4.1]. |
| Shared writable mmap | **Refused** (no `DIRECT_IO_ALLOW_MMAP`) | Not write-through [SC §4.4]. Read-only and MAP_PRIVATE mappings supported. |
| Writeback cache | **Off, permanently** | Write-through is the product [SC §4.3]. |

The INIT profile also refuses DAX. The source-side whole-file invalidation proof
depends on clean non-DAX folios and on write-capable opens remaining DIRECT_IO;
these are asserted protocol premises, not incidental kernel defaults.

### 3.2 Validity arithmetic

Every reply sets `entry_valid` to zero. Attribute-bearing replies set
`attr_valid` to
`min(policy, max(0, cacheValidDeadline − monotonicNow))`, and zero when
no covering A lease is held. Kernel attributes therefore expire no later than
the conservative local cache deadline (§2.3), while all names re-enter the
daemon. Data pages have no kernel timer; they are governed by the D-lease,
full-file revocation purge, and the §7.3b residual.

### 3.3 The revoke sequence (normative daemon discipline)  [SC §6.2]

Two lanes, one logical order per coordinate:

- **Installing lane (ordered):** all replies that install kernel cache state
  and all invalidation notifications, in one total order per coordinate —
  required because the kernel does not serialize notification dispatch with
  request replies [SC §6.3 row 1].
- **Non-installing metadata lane:** metadata replies with zero entry/attribute
  validity may be written without retaining cache authority. Buffered READ has
  no validity field: returning bytes fills a folio, so it is never described as
  a zero-validity reply.

On a revoke/COMPLETE affecting local coordinates, the daemon:

1. **Closes reply admission** for the affected coordinates on the installing
   lane. Every candidate is bound to the exact reply-local grant and its issued
   generation, rechecked immediately before the device write. It may never
   borrow a later global grant for the same coordinate. A recall advances a
   conservative issued-generation floor; a candidate older than that floor
   installs no metadata validity and cannot retain buffered data. This may drop
   a safe delayed grant on a disjoint coordinate, but never withdraws an
   already-installed disjoint lease. CONTROL event sequence numbers are exact
   phase tokens, not a per-holder delivery order: disjoint recalls may overtake.
2. **Orders every whole-file purge after the READs already admitted for that
   inode.** The purge takes a snapshot of the buffered reads in flight for the
   coordinate and waits for their physical replies before invalidating, so no
   folio filled with pre-mutation bytes survives it. It is a snapshot rather
   than a quiescence wait in both directions that matters: a read admitted after
   the cut was issued after the mutation applied, so its bytes are the new state
   and waiting for it would let a stream of readers starve the purge.

   A buffered READ is therefore **never refused, for any coherence reason** —
   not because this mount is mutating, not because a peer recall is in progress
   for the coordinate, and not because the recall caught the read in flight. It
   cannot be: the kernel holds the folio lock while it waits for the reply, so
   refusing is the only non-blocking answer available and the only errno for it
   is `EAGAIN`, which `read(2)` may not return on a blocking description — stock
   Linux hands it straight to the caller, where it is a spurious failure or, for
   a runtime that polls the descriptor, a permanent stall. The frontend
   therefore neither refuses nor waits inside the callback; the ordering lives
   at the authority (which releases a data read at apply) and at this purge
   (which waits for the replies already admitted). A read the recall caught
   mid-flight still delivers its bytes, and those bytes reach the caller
   strictly before the mutation's own reply, because this purge is upstream of
   the discharge that releases it. A READ reply likewise does not need a
   successor D grant of its own: it is covered by the D lease its handle was
   opened under, which is the obligation that will purge those pages. Metadata
   requests use the zero-validity lane.

   **Disclosed residual: the mixed-state window.** On a mount in the recall
   audience, between the transaction's apply and that mount's own COMPLETE
   purge, a page-cache miss is answered with post-apply bytes while the inode's
   other folios still hold pre-apply bytes. A single `read(2)` spanning that
   boundary can therefore return a mix that equals no serial state of the file
   — not the state before the mutation and not the state after it. This is the
   price of answering rather than refusing: the alternative is `EAGAIN` on a
   blocking descriptor, which is worse and not a legal answer at all. The window
   opens at apply and closes when this mount's whole-file invalidation completes,
   so it is bounded by one COMPLETE round trip plus one INVAL_INODE, and it
   closes for every reader at once rather than decaying per folio. It is
   distinct from §7.3b: there the invalidation silently fails to remove a folio,
   here the invalidation has simply not run yet. A reader that needs a serial
   view across a peer mutation must use its own synchronization, exactly as it
   must on any filesystem where a read may interleave with a concurrent write.

   The data publication is registered only once the callback holds this mount's
   bounded bulk lane slot. A purge waits for registered publications, and the
   source mutation that drives a purge is itself holding a bulk slot; registering
   before the slot is held would let a saturated lane close a wait cycle between
   the purge and the very reads it is waiting for.
3. **Purges daemon namespace state, then invalidates inodes**: every recalled N
   binding is removed from the daemon cache; kernel entry validity is already
   zero. Then INVAL_INODE expires attributes and purges the full file for every
   D recall [SC §6.2 items 3, 5].
4. **Errors**: entry/notification errors that stock reports
   (EINVAL/ENOMEM/ENOTDIR, unexpected ENOENT) fail the discharge and fence
   the mount. **The data-purge result is not reported by stock** —
   `fuse_reverse_inval_inode` discards the underlying `-EBUSY` [SC §6.3
   row "-EBUSY"] — so data purge is completion-of-the-notify only; the
   bounded consequence is §7.3b and the remedy is the §13 upstream patch.
   ENOENT is success-equivalent only after the namespace barrier.
5. **Acks** the discharge with its epoch; reopens installing-lane admission
   at the post-state cursor.

The daemon validates COMPLETE's exact post-state at the same recall cut, then
purges every recalled payload before acknowledging recall-to-none. It does not
retain that payload after giving up its covering lease. A later read reacquires
authority and state together; COMPLETE adds no follow-up RPC to the mutation
critical path itself. A **peer's** recall is never paired with a successor: the
peer discharges to none and reacquires later. Only the mutating source, whose own
reply carries the applied post-state, receives the A-R successor of §2.2, so no
recall-to-none is ever disguised as continuity.

### 3.4 Daemon-side caches

Lease-governed daemon caches in v1 are attributes, name bindings, and directory
enumeration pages under E-R (§5.4). Read-only file data is cached by the kernel
under D-R. Write-capable DIRECT_IO reads and symlink targets are fetched from
the authority; v1 does not add a second byte cache in the daemon. **Every daemon
cache hit checks the local monotonic deadline and per-coordinate recall
cursor**; a lapsed lease is a miss. Directory handles check E on every buffered
page hit, not only when fetching the next authority page. This makes a
partitioned daemon fail closed by itself.

---

## 4. Write path

### 4.1 Shape

Write-through over stock FUSE_WRITE. With FOPEN_DIRECT_IO, an eligible small
write is one kernel exchange [SC §4.3] — the "one-shot" transport shape with
zero kernel dependency — followed by one authority mutation RPC. The kernel
splits at `max_write` (1 MiB); the daemon pipelines chunks over the **unified
write stream** (outgoing vNext §3 reshaped to a pure daemon↔authority
protocol: windowed frames, receipts, no kernel replay/ring machinery).
Exactly-once is daemon-owned: each FUSE_WRITE maps to a daemon-generated
operation identity; the authority dedupes replays on it.

### 4.2 Ack and durability

The FUSE_WRITE reply is written only after the authority's ack — i.e., after
XFS application and conflicting-lease discharge (a write to a file with
remote D-R holders recalls them first). `fsync` remains the group-committed
durability barrier; the visibility/durability split is retained unchanged.

### 4.3 Append

Append is **supported and exact**, with placement resolved by the authority.

Stock FUSE cannot place an append itself on a shared volume: the kernel derives
its offset from `i_size`, which for a non-writeback FUSE inode is nothing more
than an advisory shadow of what this daemon last told it, and another machine may
have moved EOF since. Protocol 6 therefore forwards the *intent* and lets the
authority choose the offset inside the per-inode writer stripe that already
serializes every size-changing operation:

- `WriteRequest.append` carries the writing description's `O_APPEND` state, which
  stock `FUSE_WRITE.flags` reports. It asks the authority to place the payload at
  the object's true EOF, read under that stripe.
- `WriteReply.assigned_offset` reports where the bytes landed. The authority
  additionally proves exactness by requiring the object to end exactly at
  `assigned_offset + committed_size`, which nothing but a serialized append can
  satisfy.
- Every other write is placed exactly where the kernel asked. The kernel's offset
  is never reinterpreted, and never consulted for an append.

`i_size` remains advisory throughout. The kernel raises it from its own offset,
so after an append the authority placed further along, the kernel's value
understates the object — which is what a shared filesystem's cached size always
is, and never what the next append's placement depends on.

**Two disclosed deviations**, both because stock Linux carries the per-call
read/write flags nowhere the daemon can see them (`fuse_write_in` has no
`IOCB_APPEND`/`IOCB_NOAPPEND` bit, and the direct-I/O write path does not refresh
`i_size` from the daemon before an appending write either):

1. **`RWF_APPEND` on a description without `O_APPEND`** is resolved by the kernel
   against its own `i_size` and arrives as an ordinary positioned write. It is
   exact while that `i_size` is the object's EOF and lands at the stale offset
   otherwise. An earlier revision of this design tried to recover the intent from
   "the offset equals the `i_size` I published" and had the authority refuse a
   mismatch; that was withdrawn because the same offset is what every ordinary
   sequential write carries, so the rule refused honest concurrent writers, and
   because the trace it depended on does not exist in this profile.
2. **`RWF_NOAPPEND` on a description with `O_APPEND`** is placed at EOF like any
   other append. Inferring "positioned" from the kernel's offset would misplace
   real appends, whose offsets are equally advisory; the ordinary appends are the
   ones that must stay exact.

Appends cannot duplicate under retry: the replay-slot retention returns the
retained outcome, including its `assigned_offset`, rather than re-resolving EOF.

**`RLIMIT_FSIZE` exception.** The kernel checks the file-size rlimit against its
own `ki_pos`, which is `i_size`. When that shadow equals EOF — the ordinary case —
the check is exact. When a peer has moved EOF further along, an append the
authority places past the kernel's position may cross a limit the kernel checked
at a smaller size. This is a named, disclosed exception: the authority does not
replay private rlimit policy, and stock FUSE offers no mechanism that would let
it.

### 4.4 Truncate / fallocate / copy_range / setattr

Unchanged authority mutations through the sequencer, with recall sets per the
cross-class table [LS §3.2] plus E-R where membership changes. The daemon
validates exact post-state for reply construction and recall ordering, but v1
does not retain it as cache state after recall-to-none; kernel invalidations
follow §3.3.

**Three stock-kernel boundaries** on these operations. None is a PortableFS
policy: in each case the kernel decides before or after the daemon is consulted,
and the authority's XFS implements the operation the daemon never gets to
perform. Each is pinned by name in `TestStrictKernelSharedFallocateMutations`,
`TestStrictKernelSharedCopyFileRangeAndCrossClassBoundary`, and
`TestStrictKernelTmpfileFirstLinkAndExclusiveNonlinkable`.

1. **`fallocate` modes.** `fuse_file_fallocate` forwards only `KEEP_SIZE`,
   `PUNCH_HOLE`, and `ZERO_RANGE`, refusing every other mode with `EOPNOTSUPP`
   before a request exists. `COLLAPSE_RANGE`, `INSERT_RANGE`, and
   `UNSHARE_RANGE` therefore cannot be delivered on this profile, although the
   authority and its XFS support all three. The tests pin the refusal to zero
   authority requests so a PortableFS-side refusal could not hide behind the
   same errno.
2. **Cross-class `copy_file_range`.** A copy spanning a LOCAL route and the
   shared volume has no common backing store, so the daemon answers `EXDEV`.
   Stock `vfs_copy_file_range` retries `EXDEV`/`EOPNOTSUPP` through its own
   generic read/write path, so userspace observes an ordinary successful copy —
   the same bytes `cp(1)` would move. The contract is that the authority is
   never asked to copy into or out of a machine-local object, not that the
   syscall fails.
3. **`linkat(AT_EMPTY_PATH)` on `O_TMPFILE`.** `do_linkat` requires
   `CAP_DAC_READ_SEARCH` for a null name and returns `ENOENT` without consulting
   any filesystem. The data plane runs unprivileged by design, so the supported
   first link is the capability-free idiom `open(2)` documents:
   `/proc/self/fd/<n>` with `AT_SYMLINK_FOLLOW`. That path works, and an
   `O_TMPFILE` opened `O_EXCL` still refuses it, because the kernel never marks
   that inode `I_LINKABLE`.

---

## 5. Metadata and namespace path

### 5.1 LOOKUP / GETATTR

Every path validation enters the daemon because kernel entry validity is zero.
A daemon N-lease hit is one local FUSE exchange with no authority RPC; a miss is
one authority stabilized-read RPC returning exact post-state + N-R/A-R grants.
Attributes can still hit in the kernel under A-R. Negative lookups use the same
daemon N-R path.

### 5.2 Create and open (honest stock shapes)

- **FUSE_CREATE** (kernel sends it for O_CREAT) carries parent + name + flags
  and maps to one **RESOLVE_OPEN(parent, name)** authority RPC — the outgoing
  §4 RPC retained; the private kernel opcode is retired. Create-and-open ≡
  1 RPC.
- **Plain open of an existing file** is, on stock, LOOKUP (by parent/name)
  then OPEN (**by nodeid only** — stock FUSE_OPEN carries no parent/name, so
  it cannot map to RESOLVE_OPEN; reconstructing a name from an inode is
  unsound under hard links and rename races [round-1 review]). OPEN maps to
  an **open-by-identity** authority RPC on the stable ID (the authority
  already tracks opens by identity).
  - Warm (N/A leases held): LOOKUP answered locally → **1 RPC** total.
  - Cold: LOOKUP RPC + OPEN RPC = **2 RPCs** — one more than the retired
    kernel design's RESOLVE_OPEN collapse. This is a real, accepted
    regression of the portable profile (recorded in §10); the LOOKUP's
    N-R/A-R grant amortizes every subsequent open to 1 RPC.

### 5.3 Namespace mutations

create/unlink/link/rename/mkdir/rmdir/symlink: one authority mutation RPC;
recall of conflicting N/A/E leases before the ack; the mutating daemon
uses exact post-state to construct and validate the reply without a follow-up
RPC. It retains no recalled payload without a newly issued covering lease.

### 5.4 Readdir

Plain READDIR only. The daemon serves enumeration from its directory cache
**held under E-R** (§2.1); the cache is filled by authority enumeration pages
(paginated — a large directory is multiple pages on first fill; subsequent
enumerations under an unrevoked E-R are zero RPCs). E covers membership, not
each child's attributes: `ls -l` still resolves N/A for children that were not
already warm, instead of borrowing E as an attribute lease. Without E-R (cold
or post-recall), enumeration refetches. No kernel directory cache (§3.1).

**An ungranted enumeration reply is not a protocol violation.** §2.2 makes the
grant on a read-side reply a MAY, and a directory under sustained mutation is
precisely where the authority withholds it; independently, the frontend
declines to install a grant a newer recall's floor has overtaken, one whose
coordinate has a local recall between BEGIN and FINISH, and one past the
family's cache budget. All four outcomes mean the same thing and only that
thing: **this reply is uncached.** The frontend serves the page and refetches
next time; it does not fence, and the mount is not revoked. The genuine
violation that does stay fail-closed is a directory reply that carries no
stable identity, because no coordinate can name it and therefore no recall can
ever reach it.

**One enumeration pass returns every stable entry exactly once.** This is
unconditional and it outranks the caching rules above. POSIX's latitude covers
*membership* only — an entry created or removed while a pass is running may
appear or not — and it never licenses returning one name twice or dropping a
name that was present throughout. A pass therefore has exactly three permitted
outcomes: it is **served exactly**, it fails **loudly with `ESTALE`** so the
application re-`opendir`s, or the mount is **revoked**. Silently returning a
repositioned stream is not one of them, and is worse than the revocation it
would replace: a revoked mount stops, while a repositioned one keeps serving
wrong answers that look like right ones.

An uncovered page is **bounded to the kernel callback that fetched it** and is
retired when the next callback begins — entries, buffered EOF and all. What is
*not* retired is the position: the authority cookie following the last entry
actually delivered, and the verifier naming the snapshot that cookie counts in.
Both are resent on the refetch, so the resume is not asserted by this frontend,
it is **proven by the authority**: `ReadDirOpen` answers a resume whose verifier
no longer describes the directory with `ESTALE`, and refuses a non-zero cookie
carrying no verifier outright, rather than repositioning silently. That is what
makes the uncached path skip no name and repeat none, and it puts the mutation
check on the readdir verifier (§5.4,
`TestPagedReaddirRefusesToPageAcrossARemoteMutation`) rather than on the
presence of a cache lease.

The corollary is a state distinction the frontend has to keep, and getting it
wrong is how this shipped broken once: a stream that is *deliberately uncovered
with a proven position* is not the same as one holding *leftovers from a lease
that lapsed*. Both have no live grant. Only the second may be reset. Collapsing
them — clearing the uncovered mark at retirement while keeping the cookie — made
the lapsed-lease reset fire on a healthy uncovered stream and restart it from
the first entry, so a stable directory came back with its first callback's worth
of names delivered twice. Where such a reset does have to drop a position the
kernel has already read from, it marks the stream invalidated so the next
resume is answered with `ESTALE`, because re-reading from the beginning would
repeat every name already taken.

Note that `ESTALE` here is driven by the *directory's own* mutation, not by
cache pressure: a stable directory enumerated beside a churning sibling never
sees one, which is what keeps enumeration completing under a package install
rather than livelocking on retry.

### 5.5 LOCAL routes

Route-owned names remain LOCAL-class: served entirely by the daemon, no
authority coordinates, no leases. Classification lives in the daemon; the
retired kernel wire-shape validation is unnecessary here. Because LOCAL cache
has no authority TTL, a route revision cannot change while any mount might
still exist: active and merely fenced holders both make ApplyRoutes return
`EBUSY`. Only an authenticated clean-detach observation (or an explicitly
audited control-plane proof covering durable prior membership) permits the
change. A lease-expiry timeout is never treated as proof that LOCAL state died.
`ApplyRoutes` uses a distinct `ROUTE_ADMIN` session purpose that requires admin
scope but receives no root capability, lease cursor, or durable mount
membership. Its authenticated control connection therefore does not defeat the
clean-absence test, while a `MOUNT` session can never invoke the operation.

---

## 6. Authority protocol changes

**Retained unchanged:** transport pipeline (TLS batching, streamed hash,
frame pooling), dependency-key mutation sequencing, fsync group commit, exact
post-state record shapes, RESOLVE_OPEN RPC (now reached only via
FUSE_CREATE), enrollment/renewal, fencing.

**Reshaped for Linux:** coordinate registration + repair fan-out → the lease
service (grant tokens: coordinate, rights, epoch, TTL; recall on the CONTROL
lane; discharge gating with source-side obligations and peer recall-to-none).
Daemon coherence registries → the lease-governed cache with the §3.3 two-lane
admission discipline. New: the open-by-identity RPC (§5.2) and the E-R
enumeration lease. FSKit retains its profile-scoped repair coordinator and
source-publication boundary; §8 defines how both coordinators surround one XFS
apply without exposing either profile's control bodies to the other.

**Retired:** kernel patches 0001–0005; private opcodes 4096–4101; exact cache
stamps and stamped installers; publication acknowledgments (PFS_PUBLISH) and
the completion-ring design; `CAP_PFS_*`; the kernel-ABI halves of one-shot
and RESOLVE_OPEN (their transport/RPC-collapse value survives in §4.1/§5.2).

**Negotiation:** authority protocol 6 frontend↔authority; standard FUSE INIT
(floor 7.31) applies only to the Linux kernel↔daemon edge. A
`LINUX_LEASES` Hello requires `lease-coherence-v1` and
`directory-enumeration-lease-v1`; Activate requires `lease-renewal-v1`,
`lease-recall-v1`, and `open-by-identity-v1`. Linux cacheable responses carry
grants in `lease_grants`; CONTROL uses `next_lease_event`,
`acknowledge_lease_event`, `acknowledge_source_lease_discharge`, and
`renew_leases` with their exact response counterparts. An
`FSKIT_SYNC_REPAIR` Hello and Activate instead require the exact FSKit repair,
source-publication, and fragmented-write features and use only the FSKit repair
CONTROL stream. Missing features required by the selected immutable profile
refuse the session.

Attach also requires an exact session purpose: `MOUNT` for the data plane or
`ROUTE_ADMIN` for the restricted route-control client. Purpose is part of the
canonical attach fingerprint and cannot change on replay or resume.

---

## 7. Failure model

### 7.1 Daemon death
Kernel aborts the connection; nothing is served afterward. Fail-closed.
Authority reclaims leases at its grant-expiry deadline or on enrollment fencing.

### 7.2 Daemon partitioned
Daemon caches use request-start-anchored monotonic cache deadlines (§3.4);
kernel metadata validity is bounded by the same earlier deadline (§3.2). The
daemon starts purging D-covered kernel read caches then, without waiting for a
renewal RPC. If it cannot prove withdrawal before the authority horizon, the
independent watchdog terminalizes the mount. New work then fails; reads through
preexisting cached references are subject to §7.3b.

### 7.3 The two accepted residuals (explicit product tradeoffs)

**(a) Wedged daemon.** Kernel-held clean read pages have no kernel timer. A
daemon that is stopped-but-alive (e.g., SIGSTOP) cannot run its expiry purge;
after the authority fences the mount and a peer mutates, a process on the
fenced mount can read stale cached/mapped bytes until the daemon resumes or
dies. Trigger conjunction: wedged-not-dead daemon ∧ fenced mount ∧ peer
mutation ∧ read-only-open cached data. Never affects supported forward
metadata operations, writes, or durability; reverse dentry rendering remains
outside the contract independently of this failure (§1). This is a
userspace-daemon exposure that kernel-resident lease
clients do not share in the same form; deployment guidance (watchdog,
supervision policy) bounds it operationally. It is a product tradeoff, not a
claimed equivalence with kernel-client filesystems.

**(b) Unproved data-cache withdrawal.** Stock FUSE discards the result of inode
data invalidation, so a referenced clean folio can survive a completed purge
invisibly [SC §6.3 row "-EBUSY"]. A notification can also fail to complete
before the authority horizon.

**Scope: this is a normal-operation residual, not only a post-terminalization
one.** The paragraphs below describe the terminalization case because that is
where the exposure is unbounded, but the underlying mechanism -- an
invalidation that silently fails to remove a folio some reader has pinned -- is
live in ordinary healthy operation, on every recall of a file another mount is
reading. Two things bound it there and neither eliminates it: the purge waits
for the reads it admitted before its cut (§3.3 item 2), and a folio it does miss
is still covered by a lease, so the next mutation of that file recalls and
purges it again.

Admitting reads through the REVOKE→COMPLETE window makes this **more likely,
though not newly possible**. Before the read wait existed, a read that arrived
inside a recall was refused, and a refused read pins no folio; now it is served,
so there are more reads in flight at the moment invalidation runs and more
chances for one of them to hold the folio the purge wants. The mechanism is
unchanged and pre-existing; the exposure rate is not. Refusing those reads is
not an available alternative -- the only errno for it is `EAGAIN`, which
`read(2)` may not return on a blocking description -- so this is a deliberate
trade of a certain defect for a rarer one, and the §13 primitive is what closes
it.

**The exposure has a liveness face as well as a staleness one.** Stock's
whole-file invalidation is not a bounded operation: `INVAL_INODE` is a
synchronous write to `/dev/fuse` that returns only once the kernel has walked
the mapping, and it must take each folio's lock to do so. A workload that keeps
one inode's folios continuously locked -- several processes on the same mount
reading the same file in a tight loop -- can therefore hold that notification in
the kernel for a long time. The mount discharging the recall is blocked in that
write, so it does not answer COMPLETE, and the mutating mount's transaction
burns its whole `RecallBudget` waiting for a discharge that is starved rather
than lost. Observed shape: three processes re-opening and re-reading one file
while a peer rewrites it stalls the writer for the full budget and ends its
operation as uncertain. Pacing those readers reduces the rate but does not
remove it -- a 2 ms gap between reads still reached the stall within a few dozen
rewrites -- because what matters is whether the inode is ever quiet, not how
fast the readers go. Access that lets the inode fall idle between bursts, which
is what ordinary workloads do, does not reproduce it. The daemon cannot bound this from
userspace -- it cannot decline to serve the reads, and it cannot cancel a
notification already in the kernel -- so, like the silent `-EBUSY`, it is closed
by the §13 result-bearing invalidation primitive and not before.

In either case the watchdog terminalizes and
aborts the mount before the authority proceeds, but aborting the FUSE channel
does not invalidate resident folios. A read or private mapping through a
preexisting reference can therefore continue to observe old clean bytes after
a peer commits, potentially for that reference's lifetime. No new open, cache
miss, daemon answer, metadata answer, accepted write, or durability result is
authorized after terminalization. A later successful full purge or destruction
of the retained reference removes the exposure. The complete upstream remedy
is a bounded, result-bearing invalidation or cache-generation primitive that
both proves withdrawal and prevents later cache hits; merely reporting
`-EBUSY` closes the silent-failure case but not an indefinitely stuck
notification. Until such a primitive exists, this is an explicit exception to
post-fence data freshness, not a bounded or transient window.

### 7.4 Revoke non-response
Revoke budget → fence → authority proceeds at its grant-expiry deadline. A mutation may stall
up to ~TTL when a lease holder dies un-acking; healthy holders discharge in
~RTT. TTL sizing trades this stall against renewal traffic (20 s default).

### 7.5 Authority restart

v1 uses a grace period: the restarted authority allows reads but refuses
conflicting mutations for the frozen protocol-6 maximum grant lifetime (20 s),
not merely the newly configured TTL. Lowering the TTL therefore cannot let a
previous process's grant outlive recovery. Durable mount membership separately
keeps LOCAL route changes blocked until clean absence is proved; lease expiry
does not clear that topology obligation. Persisting exact leases to cut the
mutation stall is §13.

---

## 8. macOS FSKit

Protocol 6 admits macOS through a required, immutable
`FSKIT_SYNC_REPAIR` frontend profile. It does not issue N/A/D/E grants to that
profile. Instead, every mixed-platform mutation closes Linux lease admission
and sends FSKit PREPARE before applying once to XFS; the same exact post-state
then drives Linux COMPLETE and FSKit COMPLETE, and both audiences must finish
before the mutation returns. The existing FSKit source-publication ledger
remains the source-side boundary for Mac callbacks.

This is deliberately a weaker platform contract, not a hidden fallback.
macOS 26 synchronous VFS repair cannot prove every retained namespace,
attribute, or data reference was removed. macOS 27 native data-cache revocation
strengthens D repair but still does not expose exact N/A/E withdrawal, append
intent, or distributed lock callbacks. Those edges are best-effort and are not
described as Linux-equivalent linearizability. Profile-specific request
allowlists prevent a Mac session from using lease operations and prevent a
Linux session from using FSKit repair or fragmented-write operations.

## 9. Windows (forward-looking)

WinFsp documents per-open cache-mode flags and directory/metadata
invalidation sufficient for the same mapping — documentation-level only.
A §3-rigor contract document is a precondition for any Windows commitment
(§13).

---

## 10. Performance model (estimates and targets — to be measured in L6)

All numbers marked (m) are prior measurements of other configurations, (t)
are targets, (e) are estimates. Nothing here is a measured result of the
portable profile yet.

| Path | Portable profile | vs retired patched profile | vs Archil |
|---|---|---|---|
| Warm stat / lookup | 1 local FUSE exchange for name validation; attributes may remain a kernel hit | regression | slower than a kernel dentry hit |
| Cold stat | 1 FUSE + 1 RPC | equal | comparable |
| Small write (4 KiB) | 1 FUSE + 1 RPC ≈ 0.48 ms (e — RPC-dominated; 0.48 ms was measured (m) on the patched one-shot with the same RPC count) | equal shape | slower than 0.098 ms (m): Archil acks from write-back cache; write-through is the retained product choice |
| Sequential write | ≥ 350 MiB/s (t, via the pipelined stream) | equal design | parity target |
| Warm read (read-only opens) | 0 exchanges (page cache) | equal | equal |
| Read on a write-capable open | 1 authority RPC per FUSE read chunk (DIRECT_IO; no daemon byte cache in v1) | regression | slower; bounded by write-through design |
| Open existing, warm | 1 RPC | equal | comparable |
| **Open existing, cold** | **2 RPCs (LOOKUP + open-by-identity)** | **regression: was 1 (RESOLVE_OPEN)** | comparable |
| `ls -l` large dir, warm E-R and child N/A | 0 RPCs + N kernel↔daemon stats (~10 µs each, e) | slower than READDIRPLUS installs | acceptable; repeat listings are local while all leases remain live |
| `ls -l` large dir, cold | ⌈N/page⌉ enumeration RPCs + up to N N/A resolution RPCs | regression | workload-dependent |
| Hot shared dir, one writer | recall ping-pong: +1 RTT per conflicting mutation (e) | patched paid equivalent repair RTTs | similar cost, different mechanism |
| Mutation with dead lease holder | stall ≤ TTL (new) | patched fenced faster | Archil similar (ownership timeout) |

The honest regressions vs the patched design: cold open-existing (+1 RPC),
mixed-mode warm reads and large-dir listings (µs-scale). They are the price
of running on every stock provider kernel; the write-latency gap vs Archil is
a semantics choice, retained deliberately.

## 11. Retired complexity

Five kernel patches and their regeneration/verification toolchain; six
private opcodes; the stamp/publication/ring machinery; `CAP_PFS_*`
negotiation; the patched-kernel CI rebuild apparatus. Deployment requirement
drops from "our exact patched kernel" to "any Linux with FUSE ≥ 7.31
(practically: any provider LTS since 5.10)". The deleted surface was the
source of the E2B incident class; its removal is a feature.

## 12. Landing order (each step independently verifiable on stock kernels)

1. **L0 — Spec review** to GO (round 2 addresses this document).
2. **L1 — Daemon stock core.** Two-lane device writer + coordinate admission
   gate + invalidation engine + standard INIT (floor 7.31). Stock-kernel CI
   lane stands up here (runner on stock Debian kernel; LTS 5.10/5.15/6.1
   container/VM matrix) and replaces the patched lanes.
3. **L2 — Lease service.** Grant/recall/TTL/epoch with self-exemption and
   whole-file recall-to-none; metadata + E-R leases end-to-end; validity
   arithmetic; two-mount coherence matrix green on stock.
4. **L3 — Write path.** DIRECT_IO writes → single RPC; authority-resolved exact
   `O_APPEND` with the unforwarded per-call flags disclosed; fsync group commit;
   then the pipelined unified write stream.
5. **L4 — Metadata completion.** FUSE_CREATE→RESOLVE_OPEN, open-by-identity,
   negative entries, readdir under E-R, LOCAL routes, D-R read caching
   (daemon + read-only KEEP_CACHE with the §7.3b belt).
6. **L5 — FSKit profile.** Pin `FSKIT_SYNC_REPAIR` through Hello, Attach,
   Activate, replay, and resume; compose PREPARE/COMPLETE with Linux lease
   recall around one XFS apply; enforce profile-specific request allowlists;
   exercise macOS 26 synchronous repair and macOS 27 native data revocation.
7. **L6 — Retirement + full verification.** Remove the private ABI from the tree
   entirely. Its patch series is not retained in-tree: the directory
   `kernel/linux-6.12.100-portablefs-append/` was removed on branch
   `codex/legacy-cleanup` in the commit titled "kernel: delete the retired
   private-ABI patch series", and the sources are recoverable from git history at
   the last commit that contained that directory. Then: power-loss harness;
   multi-client stress/coherence fuzzing under kills; measure §10 on stock
   kernels; benchmark v3 vs Archil on stock.

## 13. Open questions and upstream program (honest list)

1. **Upstream patch: propagate data-invalidation failure** from
   `fuse_reverse_inval_inode` (removes §7.3b entirely; small, generally
   useful — the correct successor to private patching).
2. **Upstream conversation: forward `IOCB_APPEND`/`IOCB_NOAPPEND` in
   `fuse_write_in.flags`.** `O_APPEND` is exact today without it, because the
   description's state is already reported. The two bits are what would close the
   per-call `RWF_APPEND`/`RWF_NOAPPEND` deviations in §4.3 — and, with an
   authority-assigned offset in the reply, would let the kernel apply
   `RLIMIT_FSIZE` against the offset actually used.
3. Authority-restart lease persistence vs v1 grace (§7.5).
4. Range data leases (after all frontends prove exact range purge).
5. WinFsp contract verification to §3 rigor before Windows work.
6. TTL/grant-policy tuning under real workloads (recall ping-pong telemetry).
7. Whether E-R should extend to a full directory lease (entry attributes
   included) to close the `ls -l` gap further.
