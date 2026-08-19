# PortableFS Portable Coherence Architecture

Status: DRAFT for adversarial review. Supersedes the private-kernel exact
profile defined in `docs/vnext-protocol.md` §2–§5 and the Linux exact-append
ABI. Authority protocol major for this architecture: **6 (portable)**. There is
exactly one architecture: no patched-kernel mode, no fallback profile, no
PortableFS-private kernel capability bits.

Evidence base: the stock-kernel contract (`stock-fuse-contract.md`, pristine
Linux 6.12.100, 171 file:line citations — cited below as **[SC §n]**) and the
lease-coherence survey (`lease-coherence-survey.md` — cited as **[LS §n]**).
Where this spec grants a cache right or orders an invalidation, the grant or
ordering is only as strong as the cited stock-kernel evidence; a claim without
a citation is a defect.

---

## 1. Correctness model

PortableFS presents one volume to many mounts as if it were a single local
filesystem. The formal bar is **linearizability of filesystem operations with
the authority's COMPLETE acknowledgment as the commit point**:

1. Every mutation has exactly one commit point: the instant the authority
   acknowledges the mutating mount's COMPLETE. The mutating syscall does not
   return success before this point.
2. Any operation whose **relevant acquisition begins after** a mutation's
   commit point observes post-mutation state. "Relevant acquisition" means the
   operation's first read of the kernel or daemon cache state that answers it,
   or the daemon's receipt of the request if nothing is cached.
3. An operation **concurrent** with a mutation (its acquisition began before
   the commit point) may linearize on either side and may therefore complete
   with pre-mutation state.

Rule 3 is not a relaxation. It is the semantics of a local filesystem (a `stat`
racing a `chmod` may return either mode), it is what the retired exact-kernel
profile actually provided (its multi-field local-parity rule codified exactly
this), and it is the strongest contract stock kernels can support: stock FUSE
has no VFS-wide quiescence receipt for in-flight operations, so the literal
"nothing in flight may finish with old state" contract is unimplementable on
stock Linux [SC §6.1, §6.4]. This spec adopts contract (1) of [SC §6.4]:
**overlap-linearizable strict coherence**.

**Durability** is unchanged from the outgoing architecture: write-through.
Every acknowledged write, namespace mutation, and attribute mutation has been
applied to the authority's XFS before its commit point. `fsync`/`fdatasync`
remain the durability barrier with group commit. No mount ever buffers a dirty
mutation.

**Fail-closed rule.** Wherever this spec cannot prove freshness for a
post-commit-point acquisition, the implementation must refuse to serve from
cache (miss to the daemon/authority) or fence the mount. Serving a possibly
stale answer is never a permitted degradation.

---

## 2. Lease model

Coherence is enforced by **authority-issued, TTL-bounded cache leases**, in the
tradition of NFSv4 delegations, AFS callbacks, SMB leases, and (closest) Ceph
capabilities [LS §2]. A lease is permission to *cache*, never permission to
*mutate locally*: all mutations remain write-through regardless of rights held.

### 2.1 Coordinate families and rights  [LS §3.2]

| Coordinate | Shared | Exclusive | Cache state covered |
|---|---|---|---|
| `N(parentStableID, rawName)` | N-R | N-X | one positive or negative name binding |
| `A(stableID)` | A-R | A-X | the complete attribute record (`PostState.Attr`) |
| `D(stableID, WHOLE)` | D-R | D-X | clean whole-file data and read-ahead |

- Shared rights may be held by many mounts; an exclusive right is held by at
  most one mount and conflicts with all other mounts' rights in that family.
- Exclusive rights remain write-through. `D-X` exists for sole-writer bursts
  and is **required for the append regime** (§4.3). `N-X`/`A-X` are defined in
  the wire protocol but v1 policy never grants them (downgrade path reserved).
- Data leases are whole-file in v1. Range leases are a future additive class,
  admissible only after every frontend proves exact synchronous range purge
  [LS §3.2].
- Directory enumeration has **no lease class in v1**; readdir is served by the
  daemon (§5.4). Xattr/ACL values have no cache class in v1.

### 2.2 Lease lifecycle

States per (coordinate, holder): `GRANTED → REVOKING → RETURNED`, with a
monotone **epoch** per (coordinate, holder) stamped on every grant and every
revoke, so a late acknowledgment for an old epoch is rejected (SMB-style)
[LS §2.3, §3.3].

- **Grant.** The authority MAY attach lease grants to any successful read or
  mutation reply it sends a mount (LOOKUP/RESOLVE result → N-R + A-R; open for
  read → D-R; the mutating mount's own reply → refreshed A-R/N-R for the
  objects its exact post-state describes). Grant policy is conservative and
  server-side; a mount never demands a lease.
- **Revoke (recall).** When a mutation's touched-coordinate set (computed by
  the existing `MutationDependencies`/`VisibilityTarget` rules — the
  cross-class recall table of [LS §3.2] is normative) conflicts with
  outstanding rights, the authority: (1) closes new grant admission for those
  coordinates; (2) marks each conflicting lease REVOKING and delivers the
  revoke on the existing per-participant CONTROL lane (this is today's
  PREPARE fan-out, reshaped); (3) sequences the mutation through the
  dependency-key sequencer and applies it to XFS; (4) sends COMPLETE with the
  mutation's **exact post-state records** to every affected participant;
  (5) waits for every REVOKING holder to finish its local drain + OS
  invalidation (§3.3) and acknowledge with the matching epoch; only then
  (6) acknowledges the mutating mount — the commit point.
- **Return.** A lease is RETURNED only by an epoch-matching acknowledgment or
  by expiry (§2.3). Voluntary early return is allowed (cache pressure).

The commit point therefore retains exactly today's linearization structure:
what was "stamp every kernel cache and repair it exactly" becomes "revoke every
lease and prove local invalidation," with the same authority-side sequencing,
the same PREPARE/COMPLETE shape, and the same participant fencing.

### 2.3 TTL, renewal, expiry

- Every lease carries an authority-clock TTL (v1 default: 20 s metadata,
  20 s data; tunable). Renewal is piggybacked on any authority round trip and
  available as an explicit RENEW; a healthy busy mount never lets leases lapse.
- Clock skew is bounded by δ from the enrollment heartbeat protocol; every
  daemon-side comparison uses (remaining TTL − δ).
- **Expiry is implicit return.** If a REVOKING holder does not acknowledge
  within the revoke budget, the authority fences that participant (existing
  machinery) and proceeds once `TTL + δ` has elapsed since the lease's last
  renewal. Freshness for post-commit acquisitions on the fenced mount is
  guaranteed by construction: every kernel validity duration the daemon granted
  was ≤ remaining TTL − δ (§3.2), so all kernel-side metadata cache has
  self-expired, and all daemon-side cache is lease-clock-checked (§3.4).
  The one residual exposure is §7.3.

---

## 3. Stock-Linux client profile

The daemon mounts with **standard FUSE INIT negotiation only**. Minimum
required protocol: **7.12** (INVAL_INODE/INVAL_ENTRY; mainline since 2.6.31)
[SC §7]. Optional features (splice, NOTIFY_DELETE, AUTO_INVAL_DATA) are used
when advertised and never required. There are no PortableFS capability bits; a
stock kernel at or above the minimum mounts, full stop. Verified against
provider LTS kernels 5.10 / 5.15 / 6.1 / 6.12 [SC §7].

### 3.1 Cache-mode decisions (each cites its evidence)

| Kernel cache class | Decision | Why |
|---|---|---|
| Dentries (`entry_valid`) | **Granted** under N-R, duration ≤ remaining TTL − δ | Full INVAL_ENTRY unhashes and bumps d_seq; future walks cannot reacquire [SC §6.3 rows 4–6]. |
| Negative dentries | **Granted** under N-R (negative binding) | Same invalidation path; the daemon's negative registry reshapes into this. |
| Attributes (`attr_valid`) | **Granted** under A-R, duration ≤ remaining TTL − δ | INVAL_INODE sets inval_mask/attr_version; future stat/permission refetches [SC §6.3 rows 7–8]. |
| Directory cache (`FOPEN_CACHE_DIR`) | **Never** | Validity checked only at stream position zero; midstream/delayed refill race is unfixable by any duration [SC §6.3 row "FOPEN_CACHE_DIR", §5.1]. |
| READDIRPLUS | **Not used** | Entry install after the reply has no version gate; would bypass the admission gate [SC §6.3 row "READDIRPLUS", §5.2]. Plain READDIR only. |
| Symlink target cache (`CACHE_SYMLINKS`) | **Declined** | Page-cache symlink data shares the data-cache races without a lease class to govern it [SC §4.6, §6.3]. READLINK is served by the daemon (§3.4). |
| File data, **write-capable opens** | **FOPEN_DIRECT_IO** | Eliminates dirty/shared page state, the buffered partial-page write split, and the unverifiable `-EBUSY` invalidation discard [SC §4.3, §6.2 item 5, §6.3 row "-EBUSY"]. |
| File data, **read-only opens** | **FOPEN_KEEP_CACHE** under D-R | Clean pages only; INVAL_INODE with exact ranges removes clean (even mapped) folios; read-only mappings cannot go dirty, so the `-EBUSY` case does not arise [SC §6.2 item 5, mm/truncate citations]. Enables page-cached reads and **exec/mmap-read of binaries**, which sandboxes require. Residual: §7.3. |
| Shared writable mmap | **Refused** (no `DIRECT_IO_ALLOW_MMAP`; MAP_SHARED+PROT_WRITE fails) | Not write-through; page_mkwrite/writepages cannot be reconciled with the commit point [SC §4.4, §6.3 row "Shared mmap"]. Read-only and MAP_PRIVATE mappings are supported. |
| Writeback cache | **Off, permanently** | Write-through is the product [SC §4.3]. |

### 3.2 Validity arithmetic

For every reply that installs kernel-cached state, the daemon sets
`entry_valid`/`attr_valid` = `min(policy duration, remaining lease TTL − δ)`,
and 0 when it holds no covering lease. Kernel metadata caches therefore
provably self-expire before the authority can ever proceed past that lease
(§2.3). Data pages have no kernel timer; their governance is the D-lease plus
revocation invalidation, with the §7.3 residual.

### 3.3 The revoke sequence (normative daemon discipline)  [SC §6.2]

On receiving a revoke/COMPLETE affecting local coordinates, the daemon, on its
**single totally-ordered device writer** (one order for all replies and
notifications touching a coordinate — required because notification dispatch is
not serialized with request replies in the kernel [SC §6.3 row 1]):

1. **Close reply admission** for the affected coordinates: every candidate
   reply carries the coordinate cursor; the gate is rechecked immediately
   before the physical device write; a reply computed pre-revoke is discarded
   and recomputed from post-state [SC §6.2 item 1]. (This is the daemon
   reincarnation of the outgoing PENDING/FINALIZED admission machinery.)
2. **Drain lock owners first**: never write INVAL_ENTRY/DELETE while an
   in-flight LOOKUP/unlink/rename request whose requester holds the parent
   `i_rwsem` is unanswered — reply (or error) first, then invalidate;
   never write a data invalidation ahead of a READ reply whose locked folio
   depends on it [SC §2.6, §6.2 item 2, §6.3 row "deadlock"].
3. **Namespace before inode**: full INVAL_ENTRY (never EXPIRE_ONLY) for every
   affected (parent, name) — both rename parents, overwritten targets, every
   hard-link name whose binding changed — then INVAL_INODE per affected
   nodeid: attributes always, exact data ranges when contents/size changed
   [SC §6.2 items 3, 5; §6.3 row "under-invalidated"].
4. **Error handling**: any unexpected notification error
   (EINVAL/ENOMEM/ENOTDIR/EBUSY/ENOTEMPTY, unexpected ENOENT) fails the revoke
   and fences the mount rather than acknowledging a revocation it cannot
   prove. ENOENT is success-equivalent only after the namespace barrier
   [SC §6.2 item 6].
5. **Acknowledge** the revoke with its epoch, then reopen reply admission at
   the post-state cursor.

The daemon consumes the COMPLETE's **exact post-state records** directly into
its own cache (attributes, name bindings, sizes), so a revoke is
install-not-invalidate at the daemon layer — the surviving heart of the
outgoing §2 work — and follow-up authority RPCs stay at zero.

### 3.4 Daemon-side caches

The daemon maintains lease-governed caches for: attributes and name bindings
(source of kernel grants and of daemon-served LOOKUP/GETATTR when kernel
validity has expired mid-lease), directory enumerations (§5.4), symlink
targets, and clean file data for write-capable-open files (which the kernel
reads via DIRECT_IO). **Every daemon cache hit checks the lease clock**
(remaining TTL − δ > 0) and the coordinate cursor; a lapsed lease is a miss.
This is what makes a partitioned daemon fail closed by itself.

---

## 4. Write path

### 4.1 Shape

Writes are write-through over stock FUSE_WRITE. With FOPEN_DIRECT_IO, an
eligible small write is **one kernel/userspace exchange** [SC §4.3] — the
"one-shot" transport shape with zero kernel dependency — followed by exactly
one authority mutation RPC. The kernel splits streams at `max_write` (1 MiB);
the daemon pipelines chunks to the authority over the **unified write stream**
(the outgoing vNext §3 design reshaped to a pure daemon↔authority protocol:
windowed frames, receipts, no kernel replay or ring machinery). Exactly-once
is daemon-owned: each FUSE_WRITE maps to a daemon-generated operation identity;
authority replay dedupes on it; an interrupted FUSE request that the kernel
re-issues reuses the identity.

### 4.2 Ack and durability

The FUSE_WRITE reply is written only after the authority's COMPLETE ack — i.e.,
after XFS application and any conflicting-lease revocation (a write to a file
with remote D-R holders revokes them first, per §2.2). `fsync` remains the
group-committed durability barrier; the visibility/durability split of the
outgoing architecture is retained unchanged.

### 4.3 Append

Stock FUSE supplies a kernel-chosen offset and cannot carry authoritative
append semantics [LS exec §2]. Therefore: **O_APPEND opens require the file's
D-X (exclusive) lease.** The sole holder's daemon knows the authoritative EOF
from exact post-state and issues correctly-positioned authority appends;
concurrent cross-mount appenders serialize by lease handoff (correct, slower
under contention — stated in §10). An O_APPEND open that cannot obtain D-X
blocks until the recall completes or fails with the mount's configured policy
(default: wait within the operation budget). No dirty buffering ever.

### 4.4 Truncate / fallocate / copy_range / setattr

Unchanged authority mutations through the sequencer, with recall sets per the
cross-class table [LS §3.2]. The daemon's own caches update from exact
post-state; kernel invalidations per §3.3.

---

## 5. Metadata and namespace path

### 5.1 LOOKUP / GETATTR

Kernel cache hit under lease → zero exchanges. Kernel miss → daemon; daemon
lease-cache hit → ~µs reply with refreshed validity; daemon miss → one
authority stabilized-read RPC returning exact post-state + N-R/A-R grants.
Negative lookups identical via negative N-R.

### 5.2 CREATE and open

Stock FUSE_CREATE is atomic lookup+create+open; it maps to one
**RESOLVE_OPEN** authority RPC (the outgoing §4 RPC, retained; the private
kernel opcode is retired). Open-existing: LOOKUP (daemon/kernel-served under
lease, zero RPCs when warm) + OPEN → one RESOLVE_OPEN RPC. RPC counts equal
the outgoing design's: create ≡ 1, warm open ≡ 1, cold open ≡ 1.

### 5.3 Mutations

create/unlink/link/rename/mkdir/rmdir/symlink: one authority mutation RPC;
recall of conflicting N/A leases before commit; the mutating daemon installs
exact post-state locally (zero follow-up RPCs — the preserved outgoing-§2
property, now measured at the daemon boundary).

### 5.4 Readdir

Plain READDIR only. The daemon serves enumeration from its directory cache,
filled by authority enumeration pages that carry per-entry exact post-state;
the daemon simultaneously warms its attribute cache so the following stat
storm (e.g., `ls -l`) is served at daemon speed and, per entry once granted,
kernel speed. No kernel directory cache (§3.1). Cost stated honestly in §10.

### 5.5 LOCAL routes

The LOCAL/SHARED classification survives: route-owned names are LOCAL-class,
served entirely by the daemon with no authority coordinates and no leases.
(The kernel-side wire-shape validation of the outgoing design is retired with
the private ABI; classification lives in the daemon.)

---

## 6. Authority protocol changes

**Retained unchanged:** transport pipeline (TLS batching, streamed hash, frame
pooling), dependency-key mutation sequencing, fsync group commit, exact
post-state record shapes, RESOLVE_OPEN RPC, enrollment/renewal, fencing.

**Reshaped:** coordinate registration + repair fan-out → the lease service
(grant tokens: coordinate, rights, epoch, TTL; recall on the CONTROL lane;
COMPLETE gating on epoch-matched returns). The daemon coherence registries →
the lease-governed daemon cache with the §3.3 admission gate.

**Retired:** kernel patches 0001–0005; private opcodes 4096–4101; exact cache
stamps and stamped installers; publication acknowledgments (PFS_PUBLISH) and
the completion-ring design; `CAP_PFS_STRICT_COHERENCE` / `CAP_PFS_CACHED_DATA`
/ `CAP_PFS_WRITE_ONESHOT`; the kernel-ABI portions of one-shot (its transport
shape is native to stock FUSE; its RPC collapse lives in the write stream).

**Negotiation:** authority protocol 6 between daemon and authority; standard
FUSE INIT (min 7.12) between kernel and daemon. FSKit refusal of protocol 6
is replaced by FSKit *support* of protocol 6 (§8) — the refusal existed only
because 6 was previously defined as the exact-kernel profile.

---

## 7. Failure model

### 7.1 Daemon death
The kernel aborts the FUSE connection; nothing is served afterward. Fail-closed
by construction. Authority reclaims the mount's leases at `TTL + δ` or on
enrollment fencing, whichever first.

### 7.2 Daemon partitioned from authority
All daemon caches are lease-clock-checked (§3.4) → daemon-side hits stop at
expiry. All kernel metadata validity was granted ≤ remaining TTL − δ → kernel
hits stop by then too. The daemon's fail-closed timer additionally issues
kernel invalidations for D-covered read caches at lease expiry. Mount degrades
to errors, never staleness.

### 7.3 Wedged (alive but not scheduling) daemon — the accepted residual
Kernel-held **clean read pages** (§3.1, read-only opens) have no kernel timer;
a daemon that is wedged (e.g., SIGSTOP) cannot run its expiry invalidation, so
after the authority fences the mount and a peer mutates, a process on the
fenced mount could read stale cached/mapped bytes until the daemon resumes or
dies. This is the same exposure class every lease-based network filesystem
accepts (an NFS client with a stopped clock serves the same way). Bounding
options (watchdog process, oom-score/cgroup policy) are deployment guidance,
not protocol. This is the **single** accepted deviation from rule 2 of §1, it
requires the conjunction (wedged-not-dead daemon ∧ fenced mount ∧ peer
mutation ∧ read-only-open cached data), and it never affects metadata,
writes, or durability. Documented, not hidden.

### 7.4 Revoke non-response
Revoke budget → participant fenced → authority proceeds at `TTL + δ`. A
mutation may therefore stall up to ~TTL when a lease holder dies un-acking
(healthy holders ack in ~RTT). TTL sizing balances this stall against renewal
traffic; 20 s default, per-volume tunable.

### 7.5 Authority restart
v1: grace period — the restarted authority refuses conflicting mutations for
max-TTL + δ (lease table is volatile), mirroring NFSv4 grace. Persisting the
lease table to cut failover stalls is an explicit §13 item.

---

## 8. macOS FSKit

The daemon core (leases, admission gate, revoke sequence, caches) is shared.
The FSKit adapter maps grants to FSKit's cache controls and revocations to its
invalidation surface, replacing the current "refuse protocol 6" boundary with
protocol-6 support. FSKit's stricter kernel-resource model already routes all
data through the extension, so the Linux §7.3 residual does not arise there.
A dedicated FSKit mapping addendum (like the stock-Linux §3 table, with
FSKit-API citations) is a landing-step deliverable, not folklore.

## 9. Windows (forward-looking)

WinFsp exposes cache-mode flags per create/open and directory/metadata
invalidation calls sufficient for the same lease mapping (documentation-level;
to be contract-verified the way §3 was, before any Windows commitment).
Nothing in §1–§7 is Linux-specific.

---

## 10. Performance model (honest)

Baselines: benchmark v2 (patched kernel, one-shot) and Archil's published
shape from the same report.

| Path | Portable profile | vs patched profile | vs Archil |
|---|---|---|---|
| Warm stat / lookup | **0 exchanges** (kernel cache under lease) | equal | equal |
| Cold stat | 1 FUSE + 1 RPC | equal | comparable |
| Small write (4 KiB) | 1 FUSE + 1 RPC ≈ **0.48 ms** | equal to one-shot | slower (~0.1 ms) — Archil acks from write-back cache; write-through is the product, unchanged trade |
| Sequential write | pipelined stream target ≥ 350 MiB/s | equal (design carried over) | parity target |
| Warm read (read-only opens) | 0 exchanges (page cache) | equal | equal |
| Warm read (file also open for write) | daemon hit ~10–20 µs | slower than patched (~2 µs) | slower; bounded by design (§3.1) |
| `ls -l` large dir | 1 RPC + N kernel↔daemon stats (~10 µs each, daemon-warmed) | slower than READDIRPLUS-installed | slower; acceptable, revisit via future directory lease class |
| Hot shared dir, one writer | recall ping-pong: +1 RTT per conflicting mutation | patched paid equivalent repair round trips | different mechanism, similar cost |
| Mutation with dead lease holder | stall ≤ TTL (new) | patched fenced faster | Archil similar (ownership timeout) |

The two regressions vs the patched design (mixed-mode warm reads, big-dir
listings) are µs-scale against ms-scale network costs and are the price of
running on every stock kernel. The write-latency gap vs Archil is a semantics
choice (write-through vs write-back), explicitly retained.

## 11. Retired complexity

Five kernel patches (publication scopes, strict profile, namespace expiry,
exact post-state installer, resolve-open routing) and their regeneration/
verification toolchain; six private opcodes; the stamp/publication/ring
machinery; the CAP_PFS_* negotiation; the patched-kernel CI rebuild apparatus;
the kernel-ABI halves of one-shot and RESOLVE_OPEN. Deployment requirement
drops from "our exact patched kernel" to "any Linux ≥ 2.6.31-era FUSE
(practically: any provider LTS)". The deleted surface was the source of the
E2B incident class; its removal is a feature.

## 12. Landing order (each step independently verifiable on stock kernels)

1. **L0 — Spec review.** Adversarial review of this document to GO.
2. **L1 — Daemon stock core.** Ordered device writer + coordinate admission
   gate + invalidation engine + standard INIT (min 7.12). Stock-kernel CI lane
   stands up here (runner boots stock Debian kernel; container matrix for LTS
   5.10/5.15/6.1 where feasible) and replaces the patched-kernel lanes.
3. **L2 — Lease service.** Authority grant/recall/TTL/epoch reshaping of
   registration+repair; metadata leases end-to-end; validity arithmetic; the
   two-mount coherence matrix green on stock.
4. **L3 — Write path.** DIRECT_IO writes → single RPC; D-X append regime;
   fsync group commit verified; then the pipelined unified write stream.
5. **L4 — Metadata completion.** RESOLVE_OPEN wiring, negative entries,
   readdir/daemon directory cache, LOCAL routes, D-R read caching (daemon +
   read-only KEEP_CACHE).
6. **L5 — FSKit alignment** to the lease model with its mapping addendum.
7. **L6 — Retirement + full verification.** Delete the private ABI and kernel
   patch series; power-loss harness; multi-client stress/coherence fuzzing
   under kills; benchmark v3 vs Archil **on stock kernels**.

## 13. Open questions (honest list)

1. Authority-restart lease persistence vs v1 grace period (§7.5).
2. Upstreaming a FUSE data-cache validity/timeout mechanism to close §7.3
   properly — the long-term-correct replacement for private patches.
3. Range data leases (after all frontends prove exact range purge).
4. A directory-enumeration lease class to recover `ls -l` performance.
5. WinFsp contract verification to §3 rigor before Windows work begins.
6. TTL/grant-policy tuning under real workloads (lease ping-pong telemetry).
