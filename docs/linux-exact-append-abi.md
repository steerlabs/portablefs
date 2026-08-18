# PortableFS Linux 6.12.100 strict-coherence ABI

Superseded for vNext by [PortableFS vNext protocol and private kernel ABI](./vnext-protocol.md).
This document remains the protocol-5/FUSE-7.41 implementation record only.

Status: implementation candidate, not a production-qualified kernel.

This document freezes the private FUSE dialect implemented by the patch series
under `kernel/linux-6.12.100-portablefs-append/`.  Despite the historical file
name, the design is no longer append-only.  It covers transactional shared-file
writes, exact cache publication, range mutation, copy-file-range, namespace
publication, and shared/local graft classification as one indivisible profile.

The target is upstream and Debian Linux **6.12.100**, FUSE protocol **7.41**.
There is no compatibility mode, stock-write fallback, or best-effort coherence
path after the strict profile is accepted.

## The correctness boundary

A daemon `write(/dev/fuse)` returning is not a kernel publication boundary.
`fuse_request_end()` wakes the requester while the daemon writer is still in the
kernel, and generic VFS work can continue after the FUSE callback returns.  For
example, path lookup still has `d_lookup_done()`, rename still has dcache moves,
and a current-position write still has file-position, fsnotify, and accounting
work.

PortableFS therefore uses two separate acknowledgements:

1. the ordinary reply transfers the result to the kernel and retains the
   daemon's source/visibility gate;
2. a kernel-generated `FUSE_PFS_PUBLISH` is sent only after the operation's
   exact kernel/VFS publication point;
3. the daemon physically writes the PUBLISH ACK and only its reply completion
   releases the retained gate.

This is a causal acknowledgement, not a timeout or invalidation heuristic.

## Strict INIT profile

`FUSE_PFS_STRICT_COHERENCE = 1ULL << 63`,
`FUSE_PFS_CACHED_DATA = 1ULL << 62`, and
`FUSE_PFS_WRITE_ONESHOT = 1ULL << 61` together denote the complete profile.
They are one revision, not three independent features: selecting an incomplete
set fails INIT. That keeps a kernel and daemon from disagreeing about either the
SHARED open flags or the write shape after the mount is live. The kernel accepts
the profile only when all of the following are true:

- all three private capability bits are returned;
- the returned protocol version is exactly 7.41;
- the mount uses `default_permissions`;
- `FUSE_ATOMIC_O_TRUNC`, `FUSE_HANDLE_KILLPRIV_V2`, `FUSE_POSIX_LOCKS`, and
  `FUSE_FLOCK_LOCKS` are returned;
- transport is `/dev/fuse`, not virtio-fs;
- `FUSE_WRITEBACK_CACHE`, `FUSE_DIRECT_IO_ALLOW_MMAP`, inode DAX, export
  support, submounts, zero-message OPEN/OPENDIR, READDIRPLUS, passthrough, and
  RESEND are absent; and
- `FUSE_POSIX_ACL` is absent.  ACL caching happens outside the inner GETXATTR
  reply boundary and therefore requires a future dedicated post-cache
  publication hook before it can be admitted safely; and
- `FUSE_AUTO_INVAL_DATA` is absent and `FUSE_EXPLICIT_INVAL_DATA` is present.
  Retained pages are withdrawn by ordered DATA publication alone.  An mtime
  heuristic would drop a coherent cache on unrelated attribute refreshes and,
  because `fuse_cache_read_iter()` consults `fc->auto_inval_data`, would also put
  a GETATTR in front of every buffered read.

The negotiated `max_readahead` is installed verbatim rather than clamped to the
generic `VM_READAHEAD_PAGES` default: a SHARED page fill is one authority round
trip, so the window is what decides how many of them a sequential reader pays,
and the daemon sizes it against the same `max_read` bound it will honour.

Any mismatch fails INIT.  A daemon may not negotiate a subset and may not use a
lower minor version.  Under the accepted profile, unexpected daemon `ENOSYS` is
centrally terminal.  Operations intentionally handled locally or rejected are
decided before a request is sent.

The synthetic FUSE root is bootstrapped as SHARED.  The legacy go-fuse epoll
hack must be disabled by userspace; an unclassified synthetic reply correctly
fails the strict mount.

Before the asynchronous FUSE INIT reply, every new primary FUSE superblock is
provisionally assigned `SB_I_REPLY_PUBLISH`,
`s_stack_depth = FILESYSTEM_MAX_STACK_DEPTH`, and no export operations; it is
therefore never exposed as stackable during negotiation.  A successful
non-strict INIT clears the provisional bit, restores export operations, and
relaxes the depth to zero or its negotiated passthrough depth.  An accepted
strict superblock retains the bit, no export operations, and maximum depth.
Overlayfs, eCryptfs, and other VFS stackers must
therefore reject the strict mount as either a lower or upper layer: their own
required `+1` depth would exceed the VFS limit.  This is a coherence boundary,
because reverse repairs issued to the FUSE superblock cannot invalidate a
separate stacked filesystem's inode and dentry caches.  Bind mounts remain
valid because they reuse the same superblock and do not add a stacking layer.

The VFS `file_can_back_independent_cache()` predicate rejects a SHARED regular
file as the backing object for an independent kernel storage/cache stack.  The
pinned in-tree admission inventory is loop configure/change-fd, NVMe target
file namespaces, target-core FILEIO data and protection files, USB mass-storage
gadget LUNs, nandsim `cache_file`, userspace-supplied Coda container files,
swapon, MD external bitmap files, EROFS primary/extra file-backed devices, and
CacheFiles cache-object files.
The block, protocol, emulated-device, or stacked-filesystem
caches above those consumers are not reachable by FUSE reverse invalidations,
so even read-only binding would otherwise retain stale peer data.  Every listed
admission returns `EOPNOTSUPP`.  The predicate does not reject LOCAL files; the
superblock-wide stacking/export closure still applies to the entire strict
mount.  A source inventory test requires the common predicate at each site.
Userspace SMB servers and privileged processes that access the backing XFS
store directly remain outside the kernel trust boundary and are forbidden by
the deployment profile.

KSMBD is closed at the export boundary instead: it rejects every open on a
strict `SB_I_REPLY_PUBLISH` superblock before `dentry_open`, including
directories and LOCAL grafts.  Existing targets are rejected while their
looked-up path is still owned; absent targets are rejected inside KSMBD's
parent-path create helper before write access, lookup, create, or EA mutation.
Its directory and file leases are independent caches that FUSE reverse repairs
cannot break.

The same pre-exposure rule sets `s_export_op = NULL`.  Only a successful
non-strict INIT restores the ordinary or fid-only FUSE export operations;
strict and failed INIT retain no export surface.  This closes both resident
file-handle encoding and NFS/exportfs admission, whose client-side inode and
data caches likewise cannot be repaired by notifications to the FUSE
superblock.

## Immutable inode and handle class

Every attr-bearing reply for every inode type carries exactly one private attr
flag:

| Flag | Value | Meaning |
| --- | ---: | --- |
| `FUSE_ATTR_PFS_SHARED` | `1 << 2` | authority-backed shared object |
| `FUSE_ATTR_PFS_LOCAL` | `1 << 3` | machine-local graft object |

The first attr assigns the inode class under `fuse_inode.lock`.  Every later
attr, alias, and hard link must agree.  Missing, dual, or contradictory classes
are protocol errors.  Strict STATX is disabled because `fuse_statx` has no
frozen class field; classified GETATTR is used instead.

Every OPEN and OPENDIR returns exactly one matching handle flag:

| Flag | Value |
| --- | ---: |
| `FOPEN_PFS_SHARED` | `1 << 8` |
| `FOPEN_PFS_LOCAL` | `1 << 9` |

A SHARED regular handle has the exact open-flag set
`FOPEN_KEEP_CACHE | FOPEN_PFS_SHARED`.  DIRECT_IO, NONSEEKABLE, CACHE_DIR,
STREAM, NOFLUSH, PARALLEL_DIRECT_WRITES, and PASSTHROUGH are forbidden.
DIRECT_IO is refused rather than merely unused: it would route reads around the
page cache the DATA barrier is written against.  It was never what routed
writes -- `FOPEN_PFS_SHARED` alone selects the strict write transaction in
`fuse_file_write_iter()` and alone makes the kernel refuse every shared mapping,
so the retired pair differed from this one only in how reads were served.  There
is no compatibility mode in which both pairs are accepted.  LOCAL
grafts retain stock cached behavior and use `FOPEN_PFS_LOCAL`.  A SHARED
directory handle is exactly `FOPEN_PFS_SHARED`: in particular, CACHE_DIR and
KEEP_CACHE are forbidden, so every rewind/repeated getdents stream crosses the
daemon even if a peer repair names a dentry that is already absent locally.
LOCAL directory handles may retain the stock directory-cache flags.

SHARED reads are served from this kernel's page cache: `read`/`readv` route to
`fuse_cache_read_iter()`, splice/sendfile to `filemap_splice_read()`, and
`POSIX_FADV_WILLNEED` reaches ordinary address-space readahead.  A repeated read
of resident bytes therefore does not cross the daemon at all, which is the point.

What makes that coherent is `mapping->invalidate_lock`, not a lifetime.  Every
path that can insert a folio into a SHARED mapping holds it shared across the
FUSE READ it issues -- `filemap_create_folio()` for a read miss,
`page_cache_ra_unbounded()` for read-ahead and WILLNEED, `filemap_fault()` for a
`MAP_PRIVATE` fault -- or holds the folio locked across an asynchronous
read-ahead read started under it.  Every newer DATA sequence takes the same lock
exclusively and invalidates the whole mapping (see *Exact size and data
notification*).  A read therefore either completes and is invalidated, or begins
strictly after the authority applied.

`fuse_cache_read_iter()` additionally skips the past-EOF revalidating GETATTR for
a SHARED handle: `i_size` is installed by the ordered DATA publication, which
also bumps `fi->attr_version`, so a racing GETATTR reply cannot roll it back and
issuing one could not observe anything the barrier has not already installed.

Every `MAP_SHARED` mapping of a SHARED file is refused with `ENODEV`, writable or
not.  A writable shared mapping would produce dirty folios that never travelled
the write transaction, and a dirty folio is also the only thing
`invalidate_inode_pages2()` cannot withdraw, which would make every later DATA
repair on that inode terminal.  `MAP_PRIVATE` is permitted and coherent: its
folios come from the same cache, and the DATA invalidation unmaps its page-table
entries along with them.  `fuse_writepages()` and `fuse_write_begin()` fence the
connection under the strict profile, because reaching either would mean SHARED
file data left this kernel outside the write transaction.

Positive LOOKUP is classified from the returned child.  Negative LOOKUP has no
child attr and derives its marker requirement from the parent.  Consequently a
LOCAL route root below a SHARED parent is legal and unmarked when found, while a
missing name in a SHARED directory remains marked.

## Private identifiers

| Item | Value |
| --- | ---: |
| strict capability | bit 63 |
| cached-data capability | bit 62 |
| daemon reply PUBLISH marker | `fuse_out_header.unique` bit 62 |
| exact-size notification | code 10 |
| transactional write | opcode 4097 |
| generic PUBLISH | opcode 4098 |
| private fallocate | opcode 4099 |
| private copy-file-range | opcode 4100 |

Normal request IDs are positive, nonwrapping, even, and strictly below bit 62.
Publication IDs are positive, nonwrapping, odd, and at most `S64_MAX`.  The
strict profile rejects RESEND, so bits 62 and 63 never alias replay state.
Counter exhaustion fences the connection instead of wrapping or reusing an
identity, including FORGET and batched FORGET paths.

## Transactional SHARED write: opcode 4097

Every SHARED regular-file `write_iter`, positioned or effective append, uses one
transaction.  A stock `FUSE_WRITE` on such a handle is a kernel/protocol bug and
fences the mount.  LOCAL writes remain stock local operations.

### Request layout

`struct fuse_pfs_write_in` is exactly 80 bytes:

```c
struct fuse_pfs_write_in {
        uint64_t fh;
        uint64_t txid;
        uint64_t requested_size;
        uint64_t fragment_offset;
        uint64_t position;
        uint64_t rlimit_fsize;
        uint64_t file_max_size;
        uint64_t lock_owner;
        uint32_t size;
        uint32_t write_flags;
        uint32_t flags;
        uint32_t phase;
};
```

`rlimit_fsize` is the raw 64-bit Linux `rlim_cur`: zero is a real zero-byte
limit and `UINT64_MAX` is infinity.  `file_max_size` is nonzero and at most
`S64_MAX`.  The kernel captures one limit snapshot before selecting the write
shape and does not reread it during the operation.

Effective append means `position == 0`.  Positioned write means `position` is
the exact checked nonnegative `ki_pos`.  `flags` is constructed from zero and
contains only effective `O_APPEND`, `O_DSYNC`, and `O_SYNC`; it never copies
arbitrary `file->f_flags`.  `write_flags` contains only
`FUSE_WRITE_LOCKOWNER` and `FUSE_WRITE_KILL_SUIDGID`.  `lock_owner` is zero
unless LOCKOWNER is set. Every field is frozen in the one-shot request or at
BEGIN and repeated exactly across a fragmented transaction.

### Phases

| Phase | Value | Payload | `fragment_offset` | Effect |
| --- | ---: | --- | ---: | --- |
| BEGIN | 1 | none | 0 | bounded inert reservation |
| DATA | 2 | `size` bytes | staged prefix | idempotent inert staging |
| COMMIT | 3 | none | exact staged prefix | one authority mutation |
| ABORT | 4 | none | 0 | idempotent precommit cleanup |
| ONE_SHOT | 5 | `size` bytes | 0 | one authority mutation, no staging |

The initial `iov_iter` selects exactly one shape. A count at or below negotiated
`max_write` whose complete iterator also fits the negotiated request page
vector sends ONE_SHOT with the complete extracted payload, write geometry, and
`txid == 0`. A direct kernel-vector argument must likewise fit one segment. The
ONE_SHOT shape neither allocates nor consumes a transaction ID. A larger byte
count or page-vector shape consumes the next monotonic transaction ID and uses
BEGIN, one or more DATA fragments, and COMMIT. Selection is deterministic
before dispatch; the transaction is not a runtime fallback from a partial
ONE_SHOT.

BEGIN and DATA do not acquire the source visibility gate and cannot expose
partial data.  COMMIT acquires the source gate only after prior peer phases have
drained, performs one PREPARE/apply/COMPLETE authority mutation, and retains the
gate through generic PUBLISH.  This avoids holding the peer FIFO during large
payload upload.

The kernel fragments one Linux `write_iter` without splitting its authority
mutation.  DATA replay at an already staged offset must match byte-for-byte.
Gaps, mutable metadata, or a COMMIT prefix different from the staged prefix are
protocol errors.  ABORT always uses offset zero because the kernel cannot know
whether a lost DATA ACK advanced authority staging.  Unknown/already-aborted
ABORT is successful and idempotent.

COMMIT is forced and uninterruptible once a prefix is staged. ONE_SHOT is also
forced because it is already the mutation. A lost or malformed COMMIT or
ONE_SHOT reply is outcome-ambiguous and fences the mount. BEGIN/DATA
transport failure triggers best-effort ABORT; failure to confirm that cleanup
does not imply an XFS mutation because COMMIT was never sent, and bounded
session expiry owns the inert allocation.

### Write result layout

`struct fuse_pfs_write_out` is exactly 48 bytes:

```c
struct fuse_pfs_write_out {
        uint64_t txid;
        uint64_t committed_size;
        uint64_t assigned_offset;
        uint64_t post_size;
        uint64_t sequence;
        uint32_t flags;
        int32_t  error;
};
```

Control ACKs use the sole flag BEGUN, STAGED, or ABORTED and zero result fields.
A clean COMMIT or ONE_SHOT uses sole COMMITTED, a positive committed prefix,
assigned offset, exact post-size, nonzero nonwrapping sequence, and `error == 0`.
ONE_SHOT echoes `txid == 0`; transactional replies echo their positive ID.

For append, `post_size` must equal `assigned_offset + committed_size` exactly.
For positioned overwrite it may be larger, but never smaller than the written
end.  The kernel installs the exact size and invalidates all cached data before
PUBLISH.

`REJECTED` is sole flag bit 4, has a Linux errno in `[-4095,-1]`, and all result
fields zero.  It proves no apply and discarded staging.  Sole
`REJECTED_RLIMIT` bit 6 additionally proves a zero-progress finite RLIMIT
failure; only then does the kernel send exactly one `SIGXFSZ`.

`COMMITTED | POSTAPPLY_ERROR` carries the full committed tuple and a negative
post-apply fsync/fdatasync/killpriv error.  Data and exact kernel state are
published before the error is exposed.  Core write paths use the committed byte
count independently to install `ki_pos`/OFD position where applicable and emit
fsnotify/accounting once.  An explicit pwrite does not change OFD position.

Authority data descriptors are deliberately opened without sticky
`O_SYNC`/`O_DSYNC`. The frontend freezes effective per-write sync intent in
ONE_SHOT or BEGIN. A one-shot payload is applied directly from the retained
authority frame with one `pwrite` or `pwritev2(RWF_APPEND)` and no memfd or
sendfile. A transaction applies its staged prefix at COMMIT. Both shapes perform
exactly one fsync/fdatasync after data and killpriv work; a sticky descriptor
would amplify one syscall into multiple durability barriers.

XFS may change killpriv/timestamp attrs before returning zero bytes plus an
error.  That is represented as marked `COMMITTED | POSTAPPLY_ERROR` with
`committed_size == 0`, `assigned_offset == 0`, exact post-size and sequence, and
a negative errno.  The kernel reverts the entire advanced iterator and performs
the same full DATA+ATTR invalidation and PUBLISH, but it does not change
`ki_pos`/OFD position, set applied-byte state, emit a byte modify event, or
account write bytes.  A clean COMMITTED result must remain positive.

io_uring's internal regular-file short-write retry is suppressed for this
terminal result so one SQE is one transaction.  Splice/sendfile publish each
`write_iter` transaction before dispatching the next; the committed pipe prefix,
operation-local position, and modify event are installed first.  A later
preapply error returns the prior positive prefix.  Only failure to ACK an exact
already-applied transaction remains terminal.

## Generic post-VFS PUBLISH: opcode 4098

The daemon marks a publication-bearing ordinary reply by OR-ing bit 62 into the
original `fuse_out_header.unique`.  The kernel verifies the exact expected
result class, strips the marker only for request lookup, retains the original
request, and places a preallocated token into the requester thread's exact VFS
scope.  A marker with no live compatible scope is terminal.

After all operation-specific and generic VFS work, the kernel sends:

```c
struct fuse_pfs_publish_in {
        uint64_t request_unique;   /* original even ID, no marker */
        uint64_t publication_id;  /* new odd ID */
        uint64_t nodeid;
        uint32_t opcode;
        uint32_t flags;            /* zero */
};
```

The daemon returns the identical 32-byte tuple with sole
`FUSE_PFS_PUBLISH_ACK`.  PUBLISH is forced and credential-free.  Missing,
malformed, or lost ACK fences the connection.  Userspace must tolerate the
PUBLISH request arriving before its callback records completion of the original
reply write; it must order the two internally and must physically write the ACK
before releasing/retiring the source gate.

Tokens are embedded in and retain the original `fuse_req`, but never dereference
the caller's stack `fuse_args` after `fuse_simple_request` returns.  Every scope
exit flushes or cancels all tokens, and disconnect settles forced PUBLISH.  No
task-work fallback or global token list is used.

### Publication-point matrix

| Result | Marker rule | Kernel flush point |
| --- | --- | --- |
| positive LOOKUP | iff returned child is SHARED | after splice/instantiate, timeout, and `d_lookup_done` |
| negative LOOKUP | iff parent is SHARED | after negative dentry publication and `d_lookup_done` |
| dentry revalidate | same result rule | after ref-walk invalidation; never in RCU walk |
| GETATTR | SHARED required, LOCAL forbidden | after classified attr/cache install and kstat fill |
| SETATTR | SHARED success required | after notify_change, cache/size work, fsnotify, security post-hook |
| CREATE/MKNOD/MKDIR/SYMLINK/LINK | iff resulting inode is SHARED | after dentry/inode instantiation and VFS notification |
| atomic CREATE/open | SHARED CREATE marked | after open, security post-open, truncate, and outer open completion |
| TMPFILE | iff resulting inode is SHARED | after instantiate/open, may_open, linkability, security hook |
| UNLINK/RMDIR | iff actual target is SHARED | after d_delete/dcache and VFS notification |
| RENAME/RENAME2 | iff actual source is SHARED | after d_move/exchange, target cleanup, and VFS notification |
| O_TRUNC OPEN | SHARED required | after `handle_truncate` and post-open hooks |
| PFS_WRITE COMMIT | applied result required | after exact size/cache, position, fsnotify, and accounting edge |
| PFS_FALLOCATE | applied result required | after exact size/full cache+attr invalidation and fsnotify |
| PFS_COPY_FILE_RANGE | copied result required | after destination exact state, source attr handling, positions, and fsnotify |
| REMOVEXATTR | SHARED success required | after fsnotify/security post-remove |

Ordinary nontruncating OPEN/OPENDIR, reads, locks, FLUSH, FSYNC, and read-only
xattr operations do not publish dentry/data state and are unmarked.  Their
protocol support is nevertheless mandatory; daemon ENOSYS is fatal.

Nested scopes flush at their own true boundary.  They are not blindly deferred
to a parent: a positive LOOKUP must publish before a subsequent OPEN can acquire
the same source gate.  FUSE atomic-open ends and publishes a positive internal
LOOKUP before issuing OPEN; a negative internal LOOKUP stays private until the
atomic CREATE/no-create result and outer `d_lookup_done`.

## Exact DATA notification: code 10

```c
struct fuse_notify_pfs_size_out {
        uint64_t nodeid;
        uint64_t size;
        uint64_t sequence;
};
```

It is valid only for a SHARED regular inode.  `sequence` is the authority's one
global epoch-local visibility sequence, in `[1,S64_MAX]`, and never wraps.
Mounts die across authority epochs.

For every newer DATA sequence the kernel:

1. holds the per-inode publication mutex;
2. takes `mapping->invalidate_lock` exclusive;
3. installs exact `i_size` and invalidates complete mutation attrs/ACLs;
4. truncates and invalidates the entire page cache, even when EOF is unchanged;
5. publishes the new sequence only after all steps succeed.

This excludes concurrent filemap/MAP_PRIVATE faults from inserting a clean stale
page after the invalidation scan, and it is what partitions every SHARED read
into "completed and withdrawn" or "started after apply".  Ordering is by
sequence only: a same-length overwrite carries a strictly greater sequence and
reaches step 4 exactly like a grow or a shrink, so nothing short-circuits on an
unchanged `i_size`.  `invalidate_inode_pages2()` failure is terminal, and cannot
occur on a SHARED mapping because such a mapping is never dirty.  An older
sequence is ignored; equal sequence/equal size is idempotent; equal
sequence/different size is terminal.

`FUSE_NOTIFY_INVAL_INODE` with `off == 0 && len == 0` on a SHARED inode is the
strict whole-inode data withdrawal (`fuse_pfs_withdraw_data()`).  It takes the
same publication mutex and mapping lock and performs the same
`invalidate_inode_pages2()`, but installs no size and consumes no sequence: it
is the revocation primitive, and a dying mount that advanced the ordered
sequence would make a later real publication look like a replay.  `off < 0`
retains the stock attribute-only meaning used by ATTRIBUTES repair.

The strict reverse-notification surface is closed: only INVAL_INODE,
INVAL_ENTRY, DELETE, and PFS_SIZE are admitted.  The stock repairs have one
canonical wire shape and are checked before touching cache state:

- INVAL_INODE is exactly `off=-1,len=0` and may target only a resident SHARED
  inode.  Partial/ranged page invalidation is unsequenced and terminal.
- INVAL_ENTRY has `flags=0` (in particular, never `FUSE_EXPIRE_ONLY`) and its
  resident parent must be a SHARED directory.  A resident positive child must
  itself be SHARED; a LOCAL graft below that parent is never invalidated.
- DELETE likewise requires a resident SHARED directory parent and zero
  reserved padding.  Its resident positive target must be SHARED and match the
  exact nonzero child node ID before directory version, cache, dentry, or link
  state is changed.

Every inode/parent identity is nonzero; DELETE also requires a nonzero child.
PFS_SIZE validates its nonzero sequence and the universal signed-64-bit
size/sequence bounds before looking up the target.  Namespace names are one
nonempty opaque byte component followed by the wire terminator: embedded NUL,
slash, `.` and `..` are terminal, while arbitrary non-UTF-8 bytes remain valid.
An absent *nonzero* target remains the stock benign `-ENOENT`: it proves there
is no resident local state to repair.  A malformed identity,
length/name/reserved field, a LOCAL target, or the wrong inode type fences with
`-EPROTO`; ordinary repair errors such as a missing dentry or a busy mountpoint
retain their stock result.
STORE is terminal because it can inject unsequenced page-cache data and change
`i_size`; RETRIEVE, POLL, RESEND, and unknown/future codes are likewise
unmodeled and fence before their parser or handler runs.  LOCAL caching does not
weaken this mount-wide protocol admission rule.

No `inode_lock` is taken after source COMMIT.  The retained source gate plus the
per-inode publication mutex establishes authority order without the cycle in
which SETATTR holds `inode_lock` waiting for the source gate while COMMIT holds
the source gate waiting for `inode_lock`.

### Why source SETATTR/O_TRUNC needs no new sequence in its stock reply

All lower overlapping peer COMPLETE notifications are physically applied and
ACKed before the source receives the visibility FIFO.  Every later overlapping
peer PREPARE waits behind the retained source gate until generic PUBLISH and has
a higher sequence.  Therefore no legal lower notification can arrive after the
source kernel update.  The next legal DATA notification is higher and applies.
Transactional PFS_WRITE still carries its exact sequence because its private
COMMIT directly updates the sequence-tracked local state.

## Private FALLOCATE: opcode 4099

Input is 48 bytes:

```c
struct fuse_pfs_fallocate_in {
        uint64_t fh;
        uint64_t offset;
        uint64_t length;
        uint64_t rlimit_fsize;
        uint64_t file_max_size; /* exactly s_maxbytes */
        uint32_t mode;
        uint32_t write_flags;   /* zero or KILL_SUIDGID */
};
```

Accepted modes are exactly:

- allocate (`0`), with or without KEEP_SIZE;
- PUNCH_HOLE only with KEEP_SIZE;
- ZERO_RANGE, with or without KEEP_SIZE;
- COLLAPSE_RANGE only;
- INSERT_RANGE only;
- UNSHARE_RANGE, with or without KEEP_SIZE.

Every mode is one source-gated DATA+ATTR mutation and performs full data+attr
invalidation even when EOF is unchanged.  XFS `file_modified` semantics mean
all modes carry the canonical KILL_SUIDGID intent.

Let `S` be authoritative pre-EOF and `E = offset + length`:

| Mode | Clean success post-size |
| --- | ---: |
| allocate/ZERO/UNSHARE without KEEP | `max(S,E)` |
| allocate/ZERO/UNSHARE with KEEP | `S` |
| PUNCH_HOLE + KEEP | `S` |
| COLLAPSE | `S - length`, requiring aligned range and `E < S` |
| INSERT | `S + length`, requiring aligned range and `offset < S` |

The universal VFS check still requires nonnegative offset, positive length,
nonoverflowing `E`, and `E <= s_maxbytes`.  Unlike write, fallocate does not
apply `MAX_NON_LFS`/`O_LARGEFILE`; `file_max_size` is exactly `s_maxbytes`.
RLIMIT applies only to actual growth.

For COLLAPSE/INSERT, the authority must reproduce the pinned-XFS allocation
unit before deciding RLIMIT: query `FS_IOC_FSGETXATTR` for
`FS_XFLAG_REALTIME` and `XFS_IOC_FSGEOMETRY` for block size and realtime extent
size while holding its stable-inode writer lock.  The unit is block size for a
normal inode and `blocksize * rtextsize` for a realtime inode.  Both offset and
length must be multiples.  Geometry failure fences; guessing 4 KiB is forbidden.

Pinned XFS precedence is:

- COLLAPSE: alignment, then `E < S`;
- INSERT: alignment, then `S + length <= s_maxbytes`, then `offset < S`, then
  `inode_newsize_ok`/RLIMIT.

The common 32-byte range result has `result_size`, `post_size`, `sequence`,
`flags`, and signed `error`.  Clean APPLIED has result_size zero, exact mode
post-size, nonzero sequence, and a marked reply.  The kernel checks the
stale-EOF-independent COLLAPSE proof
`offset < post_size <= file_max_size - length`, derived from
`post_size = S - length`, `offset + length < S`, and `S <= s_maxbytes`; an
impossible clean EOF is a terminal protocol error.  Once the XFS syscall is
dispatched, **any errno** is conservatively `APPLIED | POSTAPPLY_ERROR` with an
exact observed post-size/sequence, full invalidation, and PUBLISH; XFS range
operations can partially mutate before returning an error.

FALLOCATE has no per-call sync bits.  The authority retains immutable logical
`O_SYNC`/`O_DSYNC` state from OPEN on the otherwise non-sticky destination fd
and performs one full sync or data sync after a clean operation and privilege
cleanup.  It does not sync a pre-dispatch rejection or failed XFS operation,
matching the pinned XFS clean-operation log-force boundary.

Pre-dispatch REJECTED is unmarked with all u64 fields zero.  Sole
REJECTED_RLIMIT is the one exception: for opcode 4099 only, `post_size` carries
the authoritative pre-size `S`, while result_size and sequence remain zero and
error is `-EFBIG`.  The kernel revalidates the mode-specific growth formula from
that proof before sending SIGXFSZ.  It never consults stale local EOF.

## Private COPY_FILE_RANGE: opcode 4100

Input is 72 bytes and names source handle/offset, destination node/handle/offset,
requested length, raw RLIMIT, destination file maximum, canonical killpriv
intent, and zero flags.

SHARED-to-SHARED uses one authority mutation, one destination DATA+ATTR
visibility sequence, and one PUBLISH.  Authority pins both handles and takes
canonical stable-inode locks; source DATA+ATTR participates in PREPARE to obtain
one source snapshot.  Same-inode overlap is evaluated only after clipping to
the authoritative source EOF.

SHARED-to-LOCAL and LOCAL-to-SHARED return EXDEV before mutation.  LOCAL-to-LOCAL
uses the daemon's direct local backend copy.  No SHARED endpoint may enter
`COPY_FILE_SPLICE`, including nfsd/ksmbd retry paths and cross-mount cases.

Output-limit precedence follows Linux: source EOF clips the count, then a
destination offset at finite RLIMIT returns `EFBIG`/SIGXFSZ even if the clipped
count is zero; file-max follows; overlap uses the clipped count.  A true EOF
NOOP is unmarked and all-zero, but the kernel rejects NOOP at or beyond either
frozen output ceiling as malformed instead of letting it suppress the required
limit result.  APPLIED carries a positive count, exact
destination post-size, and sequence.  If bytes were applied and PUBLISH succeeds,
the syscall returns the positive count even when authority reports POSTAPPLY;
returning the errno would permit a duplicate retry.

CFR likewise retains logical OPEN sync state: after a clean positive copy and
privilege cleanup it syncs the destination exactly once if either source or
destination was opened synchronously (full sync wins over data-only).  NOOP and
failed copies do not add a sync.  This reproduces pinned XFS without leaving a
sticky descriptor to multiply barriers elsewhere.

As with write, XFS may mutate destination/source attrs before CFR returns zero
bytes plus an errno.  Marked `APPLIED | POSTAPPLY_ERROR` therefore permits
`result_size == 0` with exact destination post-size/sequence and negative errno.
The kernel publishes full destination DATA+ATTR state, invalidates source attrs
when the source is distinct, advances no offsets, emits no byte accounting or
modify event, and returns the errno after PUBLISH.  Clean APPLIED remains
strictly positive.

## TMPFILE and deliberate local boundaries

TMPFILE remains stock FUSE opcode 51 with the standard `fuse_create_in` and the
kernel's exact `"/\0"` slash-name payload.  `CreateIn.Flags` preserves O_EXCL.
The returned attr and open handle are classified, a SHARED success is marked,
and generic PUBLISH spans instantiate/open, may_open, I_LINKABLE handling, and
the security post-hook.  Strict ENOSYS is terminal; there is no cached
no_tmpfile downgrade.

Current deliberate kernel-boundary decisions are:

- LSEEK: pre-dispatch EOPNOTSUPP;
- POLL/epoll on regular files: local `DEFAULT_POLLMASK`, no request;
- ACCESS: handled by required `default_permissions`;
- STATX and READDIRPLUS: invariant-unreachable in strict mode;
- SETXATTR and SHARED ioctl/fileattr mutation: pre-dispatch EOPNOTSUPP;
- SYNCFS: mandatory real opcode 50; ordinary durability errno propagates,
  ENOSYS/protocol/transport failure fences.

These are explicit profile boundaries, not daemon-ENOSYS fallbacks.  Expanding
product functionality requires a classified mutation protocol, not silently
re-enabling a stock bypass.

## Failure semantics

| Failure point | Kernel result |
| --- | --- |
| pre-shape local validation | ordinary Linux errno, no request |
| ONE_SHOT transport/body failure | outcome ambiguous, fence |
| definite ONE_SHOT REJECTED | exact errno, mount survives |
| BEGIN/DATA transport/body failure | best-effort ABORT; malformed protocol fences |
| definite COMMIT REJECTED | exact errno, mount survives |
| lost/malformed/transport COMMIT | outcome ambiguous, fence |
| applied private result with malformed tuple/marker | fence |
| local post-reply cache/inode/dentry failure | fence; never return retryable refusal |
| PUBLISH missing/malformed/lost | fence |
| exact-size invalidation failure | fence |
| unexpected daemon ENOSYS | centrally fence |
| RELEASE/RELEASEDIR response error | asynchronous fence |
| authority ordinary FSYNC/SYNCFS errno | propagate unless frontend revokes for fatal storage health |

## Lock/order proof

The daemon's coordinate admission/FIFO is the distributed serialization lock.
BEGIN/DATA are inert and hold no FIFO. COMMIT and ONE_SHOT obtain the FIFO after
older peer COMPLETEs, apply once, and retain it. Kernel postprocessing uses the
per-inode publication mutex and mapping invalidate lock, not `inode_lock`.
PUBLISH ACK then releases the FIFO.  A newer peer PREPARE cannot enter before
that ACK.

No synchronous PUBLISH is sent from a FUSE async completion callback; that
would deadlock the daemon writer's reply mutex.  Strict transactional write is
forced synchronous.  Stack scopes are entered by supported VFS/core entry
points; a direct/out-of-tree SHARED `->write_iter` without a compatible scope
fences before selecting a shape. Repeated `write_iter` callers use an explicit always-child
write scope for each write operation: its token is PUBLISHed before the next
iteration, then the still-live outer operation scope is restored.  Reusable
scope entry returns ownership and no caller may discard that result.

## Qualification requirements

The checked-in verifier must establish all of the following before release:

1. exact UAPI layout compilation;
2. clean patch application to both kernel.org and Debian 6.12.100 sources;
3. `W=1` compilation of every affected object for x86_64 and arm64;
4. deterministic protocol/state/error/concurrency model tests;
5. source-structure regression tests for exact hook boundaries;
6. direct XFS fallocate oracle tests on the production geometry;
7. KASAN/lockdep/fault-injection runs for marked-reply teardown, lookup/open,
   page-fault invalidation, daemon close, and publication ACK races;
8. live overlay/loop boundary tests, including a daemon-held delayed INIT; and
9. a live two-mount stress run against the matching userspace dialect covering
   append, positioned write, truncate, rename, tmpfile, fallocate, CFR, mmap
   faults, locks, fsync, and process/daemon failure.

The matching userspace handlers and deterministic cross-layer tests are now in
tree, but model and object builds are not substitutes for items 6–8. Until the
direct-XFS, KASAN/lockdep/fault, and patched-kernel two-mount runs pass, this
series must be reported as **unqualified**, not production-ready.
