# PortableFS vNext protocol and private kernel ABI

Status: implementation specification. This document replaces the protocol-5
write, mutation-reply, Linux atomic-open, and source-publication shapes. It is
not a compatibility proposal.

The words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY have their RFC 2119 meanings.

## 1. Version cut and common rules

PortableFS is not launched. vNext is therefore one coordinated version cut:

| Boundary | Required vNext value | Retired value or shape |
|---|---:|---|
| Authority TLS ALPN | `portablefs-authority-v6` | `portablefs-authority-v5` |
| Authority `protocol_major` | 6 | 5 |
| Linux FUSE version | exactly 7.42 | exactly 7.41 |
| pfslocal version | exactly 2.0 | 1.x |
| Linux private profile bits | `FUSE_PFS_STRICT_COHERENCE \| FUSE_PFS_CACHED_DATA \| FUSE_PFS_VNEXT` | `FUSE_PFS_WRITE_ONESHOT` |

`FUSE_PFS_STRICT_COHERENCE` remains bit 63 and
`FUSE_PFS_CACHED_DATA` remains bit 62. Bit 61 is named `FUSE_PFS_VNEXT` in
7.42. A daemon MUST offer all three bits and the kernel MUST return all three.
Either side MUST refuse any other version or bit set. This is an exact profile,
not capability negotiation.

The authority feature assertions retain every protocol-5 required feature
except `transactional-shared-write-v1`, `one-shot-write-v1`, and
`strict-linux-mutation-suite-v1`. Protocol 6 replaces those strings with:

* `unified-write-stream-v1` in Hello and Attach;
* `exact-post-state-v1` in Hello, Attach, and strict Attach;
* `atomic-resolve-open-v1` in Hello, Attach, and strict Attach;
* `source-publication-receipt-v2` in Hello and strict Attach; and
* `strict-linux-mutation-suite-v2` in Hello.

The lists remain required assertions. They do not offer an older shape. A
missing string refuses Hello or Activate with `EOPNOTSUPP`.

Protocol 6 keeps the authority frame header unchanged: an 8-byte big-endian
pair `{metadata_length:u32, bulk_length:u32}`, followed by deterministic
protobuf metadata and then the one legal out-of-line bulk body. A write-stream
frame is the sole new bulk carrier. The negotiated `max_frame_bytes` bounds the
whole frame and `max_write_bytes` bounds one stream segment. DATA and CONTROL
remain separate authenticated TLS connections. Filesystem traffic and write
stream frames use DATA. Visibility, liveness, terminal-delivery receipts, and
session fencing use CONTROL.

Protocol-6 `HelloReply` renames field 9 to
`max_write_stream_bytes` and adds the stream and CONTROL-lane limits:

```proto
message HelloReply {
  // fields 1..8 retain their protocol-5 meanings
  uint64 max_write_stream_bytes = 9;
  uint32 max_stream_frames_in_flight = 10;
  uint64 max_stream_bytes_in_flight = 11;
  uint32 max_streams_per_handle = 12;
  uint32 max_write_streams_in_flight = 13;
  uint64 max_write_staging_bytes = 14;
  uint32 max_terminal_receipts_in_flight = 15;
}
```

All seven values are nonzero. `max_write_stream_bytes` is at least Linux
`MAX_RW_COUNT` (`0x7ffff000`) for a production Linux authority,
`max_stream_frames_in_flight >= 2`, and `max_streams_per_handle >= 2`.
`max_stream_bytes_in_flight` counts received segment bytes not yet copied into
their authority stage and is at least twice `max_write_bytes`.
`max_write_staging_bytes >= max_write_stream_bytes` is the byte quota guaranteed
to this activated session. The authority reserves that quota from its
process-wide pool at Activate; it refuses Activate rather than advertise a
quota that later ordinary load can remove. START admission reserves its
`total_length` from that quota. `max_write_streams_in_flight` is a dedicated
write-stream lane and does not consume the ordinary DATA-operation lane.

The CONTROL connection has three disjoint logical lanes: visibility,
liveness/reauthorization, and terminal-delivery receipts. Each has its own
queue and permits. `max_terminal_receipts_in_flight` sizes the third lane; a
KeepAlive, Detach, Reauthorize, visibility long poll, or slow filesystem DATA
request cannot consume one of those permits. Saturation waits in the named
lane and is not a connection error.

Protocol 6 reserves the authority request oneof fields 46 and 55 and response
oneof fields 38 and 44, including their old names. `WriteTransactionRequest`,
`WriteTransactionReply`, `OneShotWriteRequest`, and `OneShotWriteReply` do not
exist in generated protocol-6 APIs. The Linux opcode `FUSE_PFS_PUBLISH` also no
longer exists. There is no fallback from a vNext operation to a stock FUSE
operation.

The protocol-6 implementation sets `responseEnvelopeReserve` to 2048 bytes.
The maximum four-object PostState, its two-byte field-45 tag, request ID, epoch,
errno, mutation state, and terminal-delivery token MUST fit that reserve;
`TestRetainedReplyEnvelopeFitsReserve` constructs and measures this maximum
shape. A `TerminalDeliveryReceiptReply` has no body and MUST have
`Response.post_state == nil`; the retired `post_attr` accessor is not used as a
proxy for that validation.

The private Linux opcodes are:

```c
enum fuse_opcode {
	FUSE_PFS_WRITE_STREAM    = 4097,
	FUSE_PFS_RESOLVE_OPEN    = 4098,
	FUSE_PFS_FALLOCATE       = 4099,
	FUSE_PFS_COPY_FILE_RANGE = 4100,
};
```

All integers in Linux UAPI structures use the native FUSE little-endian UAPI
representation. All reserved fields MUST be sent as zero and checked as zero.
Unknown flags, enum values, noncanonical protobuf, extra bulk bytes, and a
field present in a phase where this specification says zero are protocol
errors. A protocol error aborts the FUSE connection and fences the authority
session. It is never translated to an application `EINVAL`.

The unchanged semantic floor is:

* a successful mutation acknowledgment means the operation has been applied
  once and its result is visible under the strict coherence protocol;
* a successful `fsync`, `fdatasync`, or `syncfs` means the named durability
  barrier completed at XFS; and
* an applied or possibly applied operation is never retried under a new replay
  identity by the frontend.

In the failure tables, **client** means the application-facing filesystem
frontend: the patched kernel mount on Linux or the FSKit extension on macOS.
**Daemon** means portablefsd. **Authority** means the remote XFS authority
process. A Linux kernel crash normally also removes the machine-side client;
the tables still name the boundary because it determines which proof is
available.

## 2. Common exact post-state envelope

This envelope is defined first because the other three changes consume it.

### 2.1 Authority fields

Protocol 6 removes `Response.post_attr` field 5 and reserves its number and
name. It adds `Response.post_state` at field 45:

```proto
message Response {
  uint64 request_id = 1;
  bytes epoch = 2;
  int32 errno = 3;
  bool uncertain = 4;
  reserved 5;
  reserved "post_attr";
  MutationState mutation = 6;
  FailureClass failure = 7;
  RoutesMismatch routes_mismatch = 8;
  bytes terminal_delivery_token = 9;
  uint64 visibility_retry_sequence = 43;
  PostState post_state = 45;
  // existing and vNext oneof fields follow
}

message PostState {
  uint64 visibility_sequence = 1;
  repeated ObjectPostState objects = 2;
  uint64 snapshot_sequence = 3;
}

message ObjectPostState {
  bytes stable_identity = 1; // exactly 16 bytes
  uint64 object_version = 2;
  Attr attr = 3;
  uint32 roles = 4;
}
```

`roles` is a bit set:

```text
TARGET       = 0x0001  PARENT       = 0x0002
OLD_PARENT   = 0x0004  NEW_PARENT   = 0x0008
REMOVED      = 0x0010  OVERWRITTEN  = 0x0020
SOURCE       = 0x0040  DESTINATION  = 0x0080
CREATED      = 0x0100  EXCHANGED    = 0x0200
```

One identity occurs once in `objects`; its record ORs every applicable role.
Records are sorted by raw `stable_identity` bytes. `objects` contains one to
four records; more than four is a protocol error. Four covers the largest
legal set: moved inode, overwritten inode, old parent, and new parent.

`snapshot_sequence` is the positive visibility cursor at which all entry and
attribute facts in the envelope were sampled. For a mutation,
`visibility_sequence` is positive and equals `snapshot_sequence`. For a
nonmutating resolve-open result, `visibility_sequence` is zero and
`snapshot_sequence` is the cursor returned by the authority stabilization
step. Every `object_version` equals the last sequence in the current authority
epoch that changed that object and is no greater than `snapshot_sequence`.
Every object changed by the current mutation has `object_version ==
visibility_sequence`.

`Attr` in protocol 6 contains this complete set:

```proto
message Attr {
  enum Kind { KIND_UNSPECIFIED = 0; REGULAR = 1; DIRECTORY = 2; SYMLINK = 3; }
  Kind kind = 1;
  uint64 inode = 2;
  int64 size = 3;
  uint64 blocks = 4;       // 512-byte units, as stat(2)
  uint32 mode = 5;         // permission and type bits
  uint32 uid = 6;
  uint32 gid = 7;
  uint32 nlink = 8;
  int64 atime_ns = 9;
  int64 mtime_ns = 10;
  int64 ctime_ns = 11;
  int64 birth_time_ns = 12;
  uint32 rdev = 13;
  uint32 blksize = 14;
  uint32 flags = 15;       // persisted inode/BSD flags; zero when none
}
```

The authority snapshots all listed attributes from XFS after the syscall has
returned and before it releases the operation's visibility turn. The current
`inodeMutationLock` is a striped lock, not a per-inode lock. Every protocol-6
mutation, including SetAttr and namespace mutations, takes the writer locks for
the complete touched-identity set in increasing stripe index, holds them across
the XFS operation and snapshot, and releases them after the terminal replay
record is complete. A stripe collision is one lock, not a recursive lock.

The snapshot uses `statx` with every supported basic, birth-time, device, block
size, and attribute bit requested. It consumes `stx_rdev_major`,
`stx_rdev_minor`, and `stx_blksize`; `rdev` is Linux `new_encode_dev()` of that
device. Because XFS inode flags are not completely represented by `statx`, the
authority also issues `FS_IOC_GETFLAGS` on each retained descriptor while the
same stripe writer locks are held and places that result in `Attr.flags`.
Missing a required field or failing the ioctl is a post-apply storage error,
not permission to send zero. The authority does not derive timestamps, link
counts, block counts, flags, or parent attributes from the request. A
post-apply error has the same snapshot obligation as a clean success.

`PostState` is present exactly for `APPLIED` and `POSTAPPLY_ERROR` outcomes and
for every structured RESOLVE_OPEN outcome. In the latter case section 4 defines
the exact object set and permits zero `visibility_sequence`. A definite
pre-apply rejection, ordinary read, lock operation, close, `fsync`, and
`syncfs` has no `PostState`. Missing or extra state is a protocol error. A
replay returns byte-identical deterministic protobuf for the complete terminal
response, including `PostState`.

Protocol 6 also stamps every nonmutating reply from which a frontend can
install an entry or attributes:

```proto
message Item {
  bytes token = 1;
  Attr attr = 2;
  bytes stable_identity = 3;
  uint64 object_version = 4;
  uint64 snapshot_sequence = 5;
}
message LookupReply {
  Item item = 1;                 // absent on a negative result
  uint64 negative_snapshot_sequence = 2; // negative result only
}
message GetAttrReply {
  Attr attr = 1;
  uint64 object_version = 2;
  uint64 snapshot_sequence = 3;
}
message Dirent {
  bytes name = 1;
  Attr attr = 2;
  bytes next_cookie = 3;
  Item item = 4;
  uint64 object_version = 5;
  uint64 snapshot_sequence = 6;
}
```

`LookupReply.item`, every `GetAttrReply`, and every attribute-bearing Dirent
therefore carries both the sampled object's version and the stabilized cursor.
The nested Item values, when requested, MUST repeat the Dirent versions.
Lookup and GetAttr call the authority `Stabilize`-then-register loop before
sampling. READDIRPLUS performs one such transaction for the complete returned
page: it resolves the page, collects every `(parent,name)` namespace coordinate
and every returned item-attribute coordinate, stabilizes that whole set,
verifies that the directory verifier and page have not changed, and registers
all coordinates under one cursor. A conflict retries the whole page. Every
record in that page carries that cursor; per-record stabilization is forbidden.
READDIR without PLUS registers no cache coordinate.

A negative lookup carries `negative_snapshot_sequence`, no Item, and object
version zero. It is a structured body with `Response.errno == 0`; a positive
lookup has zero `negative_snapshot_sequence`. No entry or attr cache install in
the vNext profile lacks this stamp.

### 2.2 Required touched-object sets

The authority computes the set from what XFS may have changed, not from which
objects a frontend happened to cache.

| Mutation | Required objects |
|---|---|
| write, setattr, fallocate | target inode |
| copy-file-range | source inode and destination inode; one record if identical |
| create, mkdir, symlink | created inode and parent directory |
| hard link | linked inode after link-count change and new parent |
| unlink | removed inode after link removal and parent |
| rmdir | removed directory after removal and parent |
| rename, same parent | moved inode, parent, and overwritten inode when present |
| rename, distinct parents | moved inode, old parent, new parent, and overwritten inode when present |
| rename exchange | both exchanged inodes and both parents |
| resolve-open create | created inode and parent |
| resolve-open, any structured outcome | the supplied parent; also the target for OPENED/CREATED, including truncation |
| tmpfile | new inode and supplied parent |
| xattr removal or any future xattr mutation | target inode |

"Parent" means every namespace parent operand of the mutation. A handle-only
write, setattr, or fallocate has no parent operand: an open inode may be
unlinked or may have several hard-link parents, so the protocol MUST NOT invent
one. Such an operation returns the target inode only. Namespace mutations
always return the parent set shown above.

An unlinked inode is read through the retained authority description before it
is released. `nlink == 0` is valid. A rename-over record describes the
overwritten inode after its link was removed. Both parents are present even
when one parent's attributes happen to compare equal before and after the
operation. If old and new parent are the same identity, one record carries both
role bits.

### 2.3 Linux cache stamps and atomic installation

Every applied mutation and every RESOLVE_OPEN result ends with one post-state
trailer. Standard FUSE reply bytes, if any, precede it. The private kernel knows
the exact base size for each opcode; bytes after that size are the trailer.

```c
struct fuse_pfs_post_state_header {       /* size 32 */
	uint64_t visibility_sequence;       /* offset 0; zero only for nonmutation */
	uint64_t snapshot_sequence;         /* offset 8; always positive */
	uint64_t attr_valid_ns;             /* offset 16; 60000000000 or zero */
	uint32_t object_count;              /* offset 24; 1..4 canonical nodeids */
	uint32_t flags;                     /* offset 28; must be zero */
};

struct fuse_pfs_object_state {            /* size 144 */
	uint64_t nodeid;                    /* offset 0 */
	uint64_t object_version;            /* offset 8 */
	uint8_t  stable_identity[16];       /* offset 16 */
	struct fuse_attr attr;              /* offset 32, size 88 */
	uint32_t roles;                     /* offset 120 */
	uint32_t inode_flags;               /* offset 124; Attr.flags */
	int64_t  birth_time_ns;             /* offset 128 */
	uint32_t pfs_class;                 /* offset 136; SHARED=1, LOCAL=2 */
	uint32_t record_flags;              /* offset 140 */
};

#define FUSE_PFS_OBJECT_DROP_ATTR (1U << 0)

struct fuse_pfs_cache_stamp {             /* size 16 */
	uint64_t snapshot_sequence;         /* offset 0; positive */
	uint64_t object_version;            /* offset 8; zero only for negative */
};
```

`record_flags` is zero or `FUSE_PFS_OBJECT_DROP_ATTR`; all other bits are
errors. The fixed cache stamp follows the standard base result for positive and
negative LOOKUP and GETATTR. Positive LOOKUP and GETATTR carry the sampled
object version; negative LOOKUP carries zero. In READDIRPLUS, each record is:

```c
struct fuse_pfs_direntplus {              /* name follows at offset 168 */
	struct fuse_entry_out entry_out;     /* offset 0, size 128 */
	struct fuse_dirent dirent;           /* offset 128, size 24 */
	struct fuse_pfs_cache_stamp stamp;   /* offset 152, size 16 */
};
```

The name follows the structure and the complete record is padded to eight
bytes. READDIR without PLUS does not install entries or attrs and carries no
stamp. For CREATE, LINK, and RESOLVE_OPEN, the kernel ignores
`fuse_entry_out.attr`; the matching trailer record is the sole target attr.

Protocol 6 has one canonical live FUSE `nodeid` per stable identity; hard-link
aliases reuse it. The daemon emits that nodeid for each authority object. The
request target and parent, positive destination dentry, and newly allocated
entry MUST all resolve through that canonical identity index before reply.
There is no `nodeid == 0` record. The daemon compares the authority set and
roles with section 2.2 before writing the reply. A missing or duplicate live
mapping is a local protocol failure and withdraws the mount.

#### One cache-admission rule

The daemon maintains `last_peer_repair_sequence` for every cache coordinate:

* namespace: `(parent stable identity, raw name)`;
* attributes: `stable identity`; and
* data: `stable identity`.

It updates a coordinate only after the kernel repair for that coordinate has
completed and before sending the corresponding peer COMPLETE acknowledgment.
The sequence maps, peer-repair records, and cache-install reservations use the
existing single source/peer publication mutex.

Every entry or attr candidate carries `snapshot_sequence`. Admission is one
transaction under that mutex:

1. Compare the candidate with every coordinate it could install. If
   the coordinate is REPAIRING, or
   `snapshot_sequence <= last_peer_repair_sequence[coordinate]`, drop that
   coordinate immediately.
2. Reserve capacity for each surviving positive or negative namespace
   candidate and each surviving attr candidate. If either the positive-name,
   negative-name, or attr registry is full, do not register that candidate and
   give only that entry or attr zero lifetime. Capacity exhaustion is not a
   request error and never starts withdrawal.
3. Insert every surviving candidate into the per-coordinate in-flight registry
   with state PENDING and a mutable `revoked` bit. A READDIRPLUS page inserts
   all of its names and item attrs under the page's one cursor. The reservation
   remains until the FUSE reply writer reports physical completion or failure.

On peer-repair arrival, the daemon takes the same mutex, marks every affected
coordinate REPAIRING, and sets `revoked` on every overlapping PENDING
candidate. Before writing reply bytes, the reply writer takes the mutex and
changes each reservation from PENDING to FINALIZED. A revoked reservation is
encoded with zero lifetime and the applicable DROP flag. A peer repair that
finds an overlapping FINALIZED reservation waits outside the mutex for that
reply's physical `/dev/fuse` write to finish, then performs the kernel repair;
a failed write starts withdrawal. Candidate admission while the wait or repair
is active drops that coordinate. After the kernel repair completes, the daemon
takes the mutex, advances `last_peer_repair_sequence[coordinate]`, clears
REPAIRING, and only then sends peer COMPLETE. Physical reply completion or
failure removes the FINALIZED reservation. A reply writer MUST NOT emit
cacheable bytes for a PENDING reservation or change FINALIZED bytes. The kernel
sequence gate below remains mandatory and covers any installer/notification
overlap at the kernel boundary.

A candidate that is not newer, was revoked, or exceeded a registry capacity is
dropped, not treated as a protocol error:

* a namespace result receives zero entry lifetime and no positive or negative
  cached binding;
* an object trailer record sets `FUSE_PFS_OBJECT_DROP_ATTR` and receives zero
  attr lifetime; and
* a LOOKUP, GETATTR, or READDIRPLUS result receives zero lifetime for the
  affected entry/attr and the kernel does not update the cached attrs.

A mixed operation may drop one coordinate and install another. Structural
faults, an impossible future sequence, a wrong identity, or a missing required
record remain protocol errors. Sequence age and bounded-registry pressure are
never such faults. This reservation-and-revocation rule is the only daemon-side
late-reply gate; there is no install ordinal or connection-wide install gate.

The kernel processes an admitted trailer as one installation transaction:

1. Parse and validate the entire base reply and trailer without changing an
   inode or dentry. Check the operation's exact object/role set, identities,
   versions, kinds, inode numbers, class flags, filesystem flags, birth times,
   sizes, DROP decisions, and duplicates. `fuse_attr.flags` carries private
   FUSE attr bits; `inode_flags` carries the filesystem flag word.
2. Sort distinct `nodeid` values and take their `pfs_publish_mutex` locks in
   numeric order, including the parent inode for every entry candidate. Take a
   regular file's `mapping->invalidate_lock` exclusively only when the operation
   changes cached data or EOF.
3. Under each target `fi->lock`, compare an attr record's `object_version` with
   the target `fi->pfs_object_version`. Under the parent `fi->lock`, compare an
   entry candidate's `snapshot_sequence` with the parent's
   `fi->pfs_object_version`. Every namespace mutation changes the parent at the
   same visibility sequence, so the parent stamp is the kernel's conservative
   namespace-coordinate gate; a newer repair of another name may drop this
   entry but can never admit stale state. A marked record, or a record not
   strictly newer than its gate, makes no cache change. It is silently dropped
   even when it came from the current mutation. These comparisons cover a peer
   repair completed after daemon finalization but before the kernel lock was
   acquired.
4. Install every eligible `fuse_attr` field, `i_size`, inode class, cached ACL
   decision, and admitted lifetime. Still under `fi->lock`, set
   `fi->attr_version = atomic64_inc_return(&fc->attr_version)` and then set
   `fi->pfs_object_version`. For every record with PARENT, OLD_PARENT, or
   NEW_PARENT, call `inode_maybe_inc_iversion(dir, false)` as part of this
   transaction, even if that record's attrs were dropped. Perform the admitted
   dcache change and required page-cache action in the same locked section. Do
   not infer ctime, mtime, nlink, size, or parent state in VFS code.
5. Release all locks only after the dcache effect and every eligible attr are
   complete. A parse, identity, or cache-action failure installs no subset:
   abort the connection and run fail-closed withdrawal. Age-based DROPs are a
   successful transaction, not a partial-install failure.

`fi->attr_version` also fences an already in-flight stock GETATTR reply that
sampled the old counter. The stamped LOOKUP/GETATTR path applies the same
object-version comparison before `fuse_change_attributes()`. An old reply can
therefore neither overwrite exact state nor turn normal concurrency into mount
withdrawal.

"Atomic" means no operation publication receipt can be posted and no affected
cache can become newly usable between the dcache effect and all eligible attrs.
CPUs may observe unrelated inodes independently. No correctness rule relies on
physical DATA-reply order.

The mandated `default_permissions` remains enabled. Exact installed attrs let
the VFS perform its normal mode, uid, gid, type, mount, and immutable/append
checks without a mutation-triggered GETATTR. A cached ACL is retained only when
the complete permission inputs and ACL xattr version are unchanged; otherwise
`forget_all_cached_acls()` remains required.

### 2.4 Removed and retained invalidations

The implementation deletes these source-success calls that are present in the
current patch series:

* `fs/fuse/dir.c:fuse_unlink()`:
  `fuse_dir_changed(dir)` at patch 0002 line 1263;
* `fs/fuse/dir.c:fuse_rmdir()`:
  `fuse_dir_changed(dir)` at patch 0002 line 1281;
* `fs/fuse/file.c:fuse_pfs_copy_file_range()`:
  `fuse_invalidate_attr(inode_in)` at patch 0002 line 3056; and
* the source-write use of `fuse_pfs_update_size_locked()`: its
  `fuse_invalidate_attr(inode)`, whole-mapping `truncate_pagecache()`, and
  whole-mapping `invalidate_inode_pages2()` at patch 0002 lines 3455-3458.

Deleting the two `fuse_dir_changed(dir)` calls deletes only their
`fuse_invalidate_attr(dir)` half. Their readdir-cache effect is retained by the
mandatory `inode_maybe_inc_iversion(dir, false)` in section 2.3. The
`fi->attr_version` increment currently reached through
`fuse_pfs_update_size_locked()` is likewise moved into the common installer;
it is not deleted semantically.

Source rename/create/link paths MUST likewise remove any stock-FUSE local
timestamp, link-count, or parent-attribute inference reached after a successful
reply. `fuse_entry_unlinked()` may retain only its dcache/lookup-reference work;
it MUST NOT decrement the exact installed link count. `fuse_update_ctime()` is
not called for an object supplied in the trailer.

Protocol 6 replaces the unstamped stock attribute and namespace reverse
notifications with these exact forms:

```c
#define FUSE_NOTIFY_PFS_ATTR  12
#define FUSE_NOTIFY_PFS_ENTRY 13

struct fuse_notify_pfs_attr_out {         /* size 16 */
	uint64_t nodeid;                      /* offset 0; nonzero */
	uint64_t visibility_sequence;         /* offset 8; positive */
};

#define FUSE_PFS_ENTRY_EXPIRE 0
#define FUSE_PFS_ENTRY_DELETE (1U << 0)
struct fuse_notify_pfs_entry_out {        /* size 32; raw name follows */
	uint64_t parent;                      /* offset 0; nonzero */
	uint64_t child;                       /* offset 8; DELETE only */
	uint64_t visibility_sequence;         /* offset 16; positive */
	uint32_t namelen;                     /* offset 24; 1..NAME_MAX */
	uint32_t flags;                       /* offset 28; EXPIRE or DELETE */
};
```

The ENTRY message length is exactly 32 plus `namelen`; the raw name contains no
NUL or slash. EXPIRE requires `child == 0`; DELETE requires a nonzero canonical
child nodeid. Unknown flags, malformed names, zero sequences, or wrong live
identities are protocol errors.

PFS_ATTR takes the inode's `pfs_publish_mutex`, expires attrs and ACLs, then
under `fi->lock` increments `fi->attr_version` and sets
`fi->pfs_object_version = max(fi->pfs_object_version,
visibility_sequence)`. PFS_ENTRY takes the parent's `pfs_publish_mutex`,
performs the expire or delete repair, calls
`inode_maybe_inc_iversion(parent, false)`, and under the parent `fi->lock`
increments `fi->attr_version` and applies the same object-version stamp. That
parent stamp is checked against every later positive or negative entry's
`snapshot_sequence` as specified in section 2.3. The stamp is installed even
when the named dentry is absent. A notification returns success only after the
cache action and stamp are complete; only then may portablefsd advance its map
and send peer COMPLETE.

The existing `FUSE_NOTIFY_PFS_SIZE` remains code 10. After its page/size repair
succeeds it also sets the target `fi->pfs_object_version` to at least the
notification sequence under `fi->lock`; its existing `pfs_size_sequence`
ordering remains. A peer event that affects data and attrs sends the required
SIZE and ATTR repairs and waits for both. The stock
`FUSE_NOTIFY_INVAL_INODE`, `FUSE_NOTIFY_INVAL_ENTRY`, and
`FUSE_NOTIFY_DELETE` are not legal peer-repair shapes in the vNext profile
because they carry no visibility sequence.

These paths remain:

* the namespace dcache work formerly reached through
  `fuse_dir_changed(parent)` in reverse repair, including patch 0002 line 1442
  and patch 0003 lines 75 and 122, now performed by PFS_ENTRY with the stamp
  above;
* `fuse_invalidate_attr()` and whole-mapping
  `invalidate_inode_pages2()` in `fuse_pfs_withdraw_data()` at patch 0002 lines
  3518-3520;
* full peer DATA repair when the visibility event does not carry a changed byte
  range; and
* truncate, collapse, insert, hole-punch, and open-`O_TRUNC` page-cache removal
  required by the data operation itself.

Source installation, peer repair, and terminal withdrawal become separate
functions. Sharing the current full-invalidation helper between them is not
permitted because their proofs and damage ranges differ.

For a write issued by this mount with `FOPEN_KEEP_CACHE`, the smallest correct
data action is:

1. under `pfs_publish_mutex`, take `mapping->invalidate_lock` exclusively;
2. invalidate and unmap only folios intersecting
   `[assigned_offset, assigned_offset + committed_size)` with
   `invalidate_inode_pages2_range()`; partial-page intersection invalidates the
   whole folio;
3. install the complete returned attributes and new object version, including
   the `fi->attr_version` increment under `fi->lock`; and
4. release the locks before posting the publication receipt.

A zero-byte post-apply attribute change invalidates no data. A write cannot
shrink EOF. Growth needs no tail walk beyond the intersecting range. Existing
folios outside the written range remain valid because every peer mutation that
could change them is still repaired under the full peer DATA path. Strict
SHARED mappings remain clean, and the range invalidation must unmap private
PTEs. Any nonzero invalidation error fences and withdraws the mount.

### 2.5 Failure matrix

| Failure point | Required result |
|---|---|
| Client crashes before or during installation | It can publish no receipt. Its mount is absent or is fenced and withdrawn before peer progress treats it as repaired. |
| Authority fails before XFS apply | Definite no-change error; no `PostState`. |
| Authority fails after XFS may have changed an object but before a complete snapshot is retained | New authority epoch; every old session is fenced. No old-epoch replay and no successful source syscall. |
| DATA connection is lost before the response | Reconnect in the same epoch and replay the same mutation identity. The authority returns the retained byte-identical response or fences on mismatch. |
| CONTROL connection is lost while visibility or terminal delivery is pending | Do not install-and-ack as success. Resume the connection set within its lease or fence the session and withdraw the client. |
| Daemon rejects, truncates, reorders, or cannot map the object set | It writes no partial FUSE reply, aborts the connection, and begins withdrawal. |
| Daemon crashes after receiving state | No publication acknowledgment is possible. The client follows completion-ring withdrawal before any waiter is released. |
| Kernel detects a bad trailer before installation | No object is installed; abort and withdrawal. |
| Reply snapshot is not newer than a completed peer repair or installed object | Drop only that entry/attr cache candidate, use zero lifetime, and continue. This is normal concurrency. |
| Peer repair reaches a PENDING candidate | Mark it revoked; the reply writer encodes zero lifetime/DROP before writing any reply bytes. |
| Peer repair reaches a FINALIZED candidate | Hold the coordinate REPAIRING, wait for the physical reply write, perform and stamp kernel repair, and only then send COMPLETE. |
| Positive, negative, or attr admission registry is full | Return the result with only the affected cache lifetime zero; do not withdraw or wait under the source/peer mutex. |
| Page-cache action fails during installation | No publication receipt; abort and withdrawal. The applied authority result remains the only truth. |
| Kernel or machine dies after XFS apply | The mount is absent. Authority fencing/lease expiry removes it from visibility participation. |
| Response and installation complete but receipt is lost | The syscall cannot report success. Completion-ring recovery or withdrawal, described in section 5, is required. |

### 2.6 Coherence argument

The authority takes mutation post-state while the mutation order is still
closed, and stabilizes nonmutation samples at a named cursor. Peers cannot
acknowledge COMPLETE with older cached state, and the source does not release
its local gate until kernel installation finishes. Every possible entry/attr
install carries that cursor. A candidate at or behind the last repair of its
coordinate is uncacheable, and a candidate at or behind an installed object
version cannot change the inode. Thus delayed lookup, getattr, resolve-open,
readdir, mutation, and replay replies all obey the same ordering rule. Parent
timestamps and permission fields install with the namespace effect, while the
parent i_version invalidates readdir pages. For source writes, only pages
containing bytes changed by that source are removed; peer writes still remove
every possibly stale page. A successful acknowledgment therefore leaves no
servable source cache entry older than the acknowledged visibility sequence.

### 2.7 FSKit mapping

pfslocal 2.0 carries `PostState` and `ObjectPostState` with the same fields and
role values in every applied mutation reply. `Attr` contains the protocol-6
attribute set. `VolumeCore` validates the whole set before constructing an
FSKit result. It also carries `snapshot_sequence` and `object_version` on every
lookup, getattr, directory, and resolve-open result. `MacOSV3Coherence` records
the last completed peer-repair sequence per namespace and item coordinate under
its source/peer actor. Candidate results occupy PENDING reservations in that
actor until the real FSKit reply-handler call is finalized; an overlapping peer
repair revokes them first. A not-newer, revoked, or over-capacity result
receives no cacheable FSKit state. Any FSKit generation that supplies the exact
repair primitives MUST also retain the peer sequence in the item/namespace
cache stamp checked at install. These are the same two gates as Linux, not a
timer policy.

The checked-in macOS 27 adapter compiles only
`FSVolume.DataCacheHandler.setCacheState(..., action: .invalidate)`, which
supplies the retained-item data invalidation primitive. Claims that
`FSVolume.Handler` offers typed child/parent, linked/parent, removed/parent,
rename/both-parent/overwritten, write-item, or setattr-item result families are
unverified in this repository: there is no checked-in SDK artifact or compiling
probe target for them, and the current adapter deliberately does not adopt
them. If a checked-in macOS 27 probe later proves those types, the adapter MUST
populate them from this envelope at the actual reply-handler call. Until then,
they are requirements, not available primitives.

macOS 27 still has no supported namespace-cache or inode-attribute invalidation
primitive for peer COMPLETE. macOS 26 `FSVolume.Operations` also cannot return
the complete parent/object sets for create, symlink, link, remove, rename, and
write, and has no supported data, namespace, or inode-attribute invalidation
API. `FSItem.Attributes.invalidateAllProperties()` is not a kernel-cache
operation. Re-resolving a pathname is not an invalidation primitive.

The exact requirement is an FSKit API that can synchronously install every
typed source post-state and synchronously invalidate exact peer namespace,
attribute, and data cache entries. Until checked-in compiling probes establish
those operations, macOS 26 MUST refuse the exact vNext profile and macOS 27 is
only an unqualified candidate. No timer, zero cache lifetime, pathname
substitution, or compatibility-writer lease implements this ABI.

## 3. Unified pipelined write stream

### 3.1 Authority message layout

Request oneof field 56 is `write_stream`. Response oneof field 46 is
`write_stream`. Every physical stream frame has a unique nonzero
`Request.request_id`. The authority sends one response only: it uses the
request ID of the accepted START frame. DATA frame request IDs are one-way
transport identities and never receive responses.

```proto
message Request {
  // existing envelope
  oneof body {
    // existing protocol-6 bodies
    WriteStreamFrame write_stream = 56;
    ResolveOpenRequest resolve_open = 57;
  }
}

message Response {
  // existing envelope, including post_state = 45
  oneof body {
    // existing protocol-6 bodies
    WriteStreamReply write_stream = 46;
    ResolveOpenReply resolve_open = 47;
  }
}

message WriteStreamFrame {
  bytes handle = 1;             // exactly 16 bytes; present on every frame
  uint64 operation_sequence = 2;
  uint32 frame_flags = 3;
  uint64 total_length = 4;      // START only
  uint64 stream_offset = 5;
  uint64 position = 6;          // START only; zero for append
  uint64 rlimit_fsize = 7;      // START only; UINT64_MAX is infinity
  uint64 file_max_size = 8;     // START only; 1..INT64_MAX
  uint64 lock_owner = 9;        // START only
  uint32 segment_length = 10;
  uint32 write_flags = 11;      // START only; FUSE_WRITE_* closed set
  uint32 flags = 12;            // START only; effective O_APPEND/O_DSYNC/O_SYNC
  uint64 apply_length = 13;     // FINAL only
  bytes data = 14;              // exact out-of-line bulk body
}

message WriteStreamReply {
  enum Outcome {
    OUTCOME_UNSPECIFIED = 0;
    APPLIED = 1;
    POSTAPPLY_ERROR = 2;
    REJECTED = 3;
    DISCARDED = 4;
  }
  enum Rejection {
    REJECTION_NONE = 0;
    RLIMIT_FSIZE = 1;
  }
  bytes handle = 1;
  uint64 operation_sequence = 2;
  Outcome outcome = 3;
  Rejection rejection = 4;
  uint64 committed_length = 5;
  uint64 assigned_offset = 6;
  int32 error = 7;
}
```

`frame_flags` is a closed bit set:

```text
START   = 0x0001
FINAL   = 0x0002
DISCARD = 0x0004
```

`START|FINAL` is legal. `DISCARD` is legal only with FINAL. There is no phase
enum and no geometry-specific message.

The START `Request` alone carries `Mutation`, `source_publication_gate`, and any
`visibility_retry_after_sequence`. Every frame carries the same nonzero
`frontend_operation_id`, epoch, and session proof. DATA and a non-START FINAL
MUST omit the mutation and source-gate envelope fields. The sole terminal
`Response` carries `MutationState` for the START mutation identity. A frame
whose envelope disagrees with this grammar is rejected before staging.

START freezes handle, operation sequence, total requested length, position
mode, both size ceilings, lock owner, killpriv flags, and effective syscall
flags. `total_length` is in `1..0x7ffff000`. `O_APPEND` selects append and
requires `position == 0`; otherwise the operation is positioned at `position`.
Exactly the bits `O_APPEND`, `O_DSYNC`, and `O_SYNC` may occur in `flags`.
`O_SYNC` includes `O_DSYNC` semantically, but both raw bits are preserved.

Every frame may carry a segment. Its bulk length and metadata
`segment_length` are equal, and its bytes cover
`[stream_offset, stream_offset + segment_length)`. START's segment begins at
zero. Subsequent new segments begin at the current contiguous staged length.
Zero-length START is legal; zero-length non-FINAL DATA is not. FINAL may carry
the last segment.

An applying FINAL has no `DISCARD`, has `1 <= apply_length <= total_length`,
and ends with contiguous staged length exactly equal to `apply_length`. A
discarding FINAL has no data, has `apply_length == 0`, and ignores then destroys
any staged prefix. A clean full write uses `apply_length == total_length`. An
explicit short write uses a smaller prefix. No unfinalized prefix can reach
XFS.

The common case of a 1 MiB write whose payload fits `max_write_bytes` is one
physical frame with `START|FINAL`, offset zero, the full bytes, and equal total
and apply lengths. Alignment does not select that case; frame capacity does. An
unaligned 1 MiB write has the same one-frame shape if it fits. A multi-MiB
write uses START, zero or more DATA frames, and FINAL under the same state
machine.

### 3.2 Linux FUSE layout

The kernel-to-daemon layout is:

```c
#define FUSE_PFS_STREAM_START   (1U << 0)
#define FUSE_PFS_STREAM_FINAL   (1U << 1)
#define FUSE_PFS_STREAM_DISCARD (1U << 2)

struct fuse_pfs_write_stream_in {         /* size 96 */
	uint64_t fh;                        /* offset 0 */
	uint64_t operation_sequence;        /* offset 8 */
	uint64_t total_length;              /* offset 16, START only */
	uint64_t stream_offset;             /* offset 24 */
	uint64_t position;                  /* offset 32, START only */
	uint64_t rlimit_fsize;              /* offset 40, START only */
	uint64_t file_max_size;             /* offset 48, START only */
	uint64_t lock_owner;                /* offset 56, START only */
	uint64_t apply_length;              /* offset 64, FINAL only */
	uint32_t size;                      /* offset 72 */
	uint32_t write_flags;               /* offset 76, START only */
	uint32_t flags;                     /* offset 80, START only */
	uint32_t frame_flags;               /* offset 84 */
	uint64_t reserved;                  /* offset 88 */
};

#define FUSE_PFS_STREAM_OUT_ACCEPTED        (1U << 0)
#define FUSE_PFS_STREAM_OUT_APPLIED         (1U << 1)
#define FUSE_PFS_STREAM_OUT_POSTAPPLY_ERROR (1U << 2)
#define FUSE_PFS_STREAM_OUT_REJECTED        (1U << 3)
#define FUSE_PFS_STREAM_OUT_DISCARDED       (1U << 4)
#define FUSE_PFS_STREAM_OUT_RLIMIT          (1U << 5)

struct fuse_pfs_write_stream_out {        /* size 48 */
	uint64_t operation_sequence;        /* offset 0 */
	uint64_t committed_length;          /* offset 8 */
	uint64_t assigned_offset;           /* offset 16 */
	uint32_t flags;                     /* offset 24 */
	int32_t  error;                     /* offset 28 */
	uint32_t post_state_bytes;          /* offset 32 */
	uint32_t reserved0;                 /* offset 36 */
	uint64_t reserved1;                 /* offset 40 */
};

struct fuse_pfs_init_out {                /* appended to fuse_init_out; size 32 */
	uint32_t stream_window_frames;       /* offset 0; at least 2 */
	uint32_t max_streams_per_handle;     /* offset 4; at least 2 */
	uint64_t stream_window_bytes;        /* offset 8 */
	uint32_t max_write_streams_in_flight;/* offset 16; dedicated lane */
	uint32_t max_publication_tokens;     /* offset 20; section 5 */
	uint64_t max_kernel_retained_stream_bytes; /* offset 24 */
};
```

The private INIT extension is present exactly when the returned profile
contains `FUSE_PFS_VNEXT`. The stream fields are the minima of portablefsd's
transient reorder limits and the authority Hello limits.
`max_kernel_retained_stream_bytes` is a weighted kernel-memory budget and is at
least `max_write_stream_bytes`, so one maximum-sized write can always enter.
`max_publication_tokens` is nonzero and no greater than the configured ring
size. Missing, short, zero, or larger-than-advertised values abort INIT.

Payload bytes follow the input structure. A non-FINAL local response is exactly
the 48-byte output with `ACCEPTED`, the matching sequence, and every other
field zero. `ACCEPTED` means only that portablefsd has written the ordered frame
to authority DATA. portablefsd has no replay memfd. `ACCEPTED` does not mean XFS
application or visibility, and it does not release the kernel's immutable
replay bytes. A FINAL local response has one terminal outcome flag and, for an
applied outcome, the post-state trailer from section 2. `ACCEPTED` never appears
with a terminal flag.

For an applied terminal result,
`post_state_bytes == 32 + 144 * object_count`; it is zero for REJECTED and
DISCARDED. The terminal shapes are closed:

| Shape | Counts and offset | Error and state |
|---|---|---|
| APPLIED | `1 <= committed_length <= apply_length`; assigned offset is the positioned offset or authority append result | error 0; exact `PostState` |
| POSTAPPLY_ERROR | `0 <= committed_length <= apply_length`; assigned offset is zero when committed length is zero | negative errno; exact `PostState` |
| REJECTED | both counts/offset zero | negative errno; no state; RLIMIT flag only with `-EFBIG` |
| DISCARDED | both counts/offset zero | error 0; no state |

For all four structured authority outcomes, `Response.errno == 0` and
`Response.uncertain == false`; `WriteStreamReply.error` carries the operation
error. An ambiguous transport condition has no structured response and is
resolved by replay or fencing.

### 3.3 Per-open sequence and replay identity

Every authority file handle has `next_operation_sequence`, initially 1.
`OpenReply`, `CreateReply`, `TmpfileReply`, and `ResolveOpenReply` return that
initial value with the handle. The kernel stores an atomic next value in the
shared `fuse_file`; `dup` and inherited descriptors share it. That file also
owns a counting semaphore initialized to `max_streams_per_handle`.

Admission order is exact: reserve `total_length` from the connection's weighted
kernel-retention budget, take a dedicated write-lane permit, take the per-handle
semaphore, and prepare the first immutable payload segment. Only then, under the
per-handle submission lock, allocate the next sequence and commit START to the
FUSE request queue as one action. A zero-length write, pre-START user fault, or
interrupted admission consumes neither sequence nor permit. Any local failure
after allocation MUST queue `START|FINAL|DISCARD` for that sequence; if the
FUSE connection can no longer accept that frame, fail-closed connection
withdrawal and session fencing discharge the gap. The three reservations are
released only after a terminal outcome or withdrawal.

The protocol-6 field additions are exact:

```proto
message OpenReply { bytes handle = 1; uint64 next_operation_sequence = 2; }
message CreateReply { Item item = 1; bytes handle = 2; uint64 next_operation_sequence = 3; }
message TmpfileReply { Item item = 1; bytes handle = 2; uint64 next_operation_sequence = 3; }
```

Each value is exactly 1 on first delivery and replay. A later value is never
minted by reopening a replayed handle.

The authority replay identity is:

```text
(authority_epoch, session_id, handle, operation_sequence)
```

START also carries the ordinary `(Mutation.slot, Mutation.sequence)`. The
authority binds that mutation identity to the tuple at first acceptance. The
slot and one dedicated write-stream permit remain occupied until the stream
reaches a terminal outcome; no ordinary request permit is held. A changed START
field, mutation identity, source gate, final apply length, or byte sequence
under the same tuple is a replay mismatch and fences the session.

The canonical retained mutation body consists of the frozen START fields,
`apply_length`, and SHA-256 of bytes `[0, apply_length)`. Physical request IDs,
segment boundaries, and retry connection are excluded. Thus a replay may use
different legal segment boundaries but must name and apply the same bytes.

The kernel `pfs_write_ctx` retains an immutable kernel-owned copy of every
accepted byte until it consumes the terminal result. Pinning mutable user pages
alone is insufficient: bytes copied into the write context cannot change after
START. On same-epoch DATA reconnection portablefsd resumes the DATA role, then
sends this daemon-to-kernel notification through `/dev/fuse`:

```c
#define FUSE_NOTIFY_PFS_STREAM_REPLAY 11
struct fuse_notify_pfs_stream_replay_out { /* size 24 */
	uint64_t fh;                        /* offset 0 */
	uint64_t operation_sequence;        /* offset 8 */
	uint64_t connection_generation;     /* offset 16 */
};
```

From ingress of START until terminal retirement or withdrawal, portablefsd
retains stream metadata
`(fh, operation_sequence, connection_generation, accepted_prefix,
final_sent)` in its active-stream registry. `accepted_prefix` is the largest
contiguous prefix for which portablefsd sent local ACCEPTED; `final_sent` means
FINAL was written to authority DATA. Reorder slots retain only their bounded
copies until the DATA writer consumes them. There is no daemon replay memfd or
post-send byte retention.

After same-epoch DATA reconnection, portablefsd enumerates that registry and
sends one notification for every nonterminal stream that had accepted START.
The notification always requests replay from byte zero; nonzero-offset replay
is not an ABI feature. The kernel rejects an unknown context, mismatched
generation, or duplicate concurrent replay request. It requeues START and all
accepted bytes from offset zero, and FINAL when `final_sent` is true, from its
retained bytes with the original identities. The authority compares them with
its active staged prefix or runs hash-only replay against the terminal record
and never invokes XFS twice.

Replay requests and their continuation frames have priority over new START
admission on the same handle. The kernel blocks allocation of a new per-handle
and one maximum-frame byte credit for replay. That reserved pair is recycled
from each local ACCEPTED to the next replay frame until the replayed prefix and
any FINAL have entered the daemon reorder map. New traffic on other handles may
use only the remaining credits. A busy handle therefore cannot starve the
replay needed to clear its own operation-sequence window.

Operation sequences on one handle are contiguous. The authority may stage a
bounded window of later sequences, but it applies and emits their terminal
responses in sequence order. A discarded or rejected operation consumes its
sequence. A missing lower sequence blocks higher sequences until the lower
stream is replayed, discarded, times out to a definite rejection, or the
session is fenced. The accepted window is
`[next_sequence, next_sequence + max_streams_per_handle)`. A sequence outside
it is a protocol error.

Across handles, ready mutations enter the existing authority visibility FIFO.
Applied terminal responses are written in increasing visibility sequence.
That authority terminal-send order is the protocol meaning of “ack order equals
visibility order”: no applied terminal is sent before its peer visibility is
complete or ahead of a lower visibility sequence. portablefsd dispatches each
terminal result to its FUSE request immediately. Kernel post-processing,
publication work, DONE records, and independent syscall returns may then finish
in any order. No POSIX or coherence observable depends on return order once
both mutations are visible, so there is no mount-wide write-DONE queue.
Per-handle rejected and discarded replies preserve operation-sequence order but
have no visibility sequence.

### 3.4 Authority state machine and staging

The authority state machine is:

```text
ABSENT -> STAGING -> FINAL_READY -> ORDERED -> APPLYING -> TERMINAL
                    |                         |
                    +-> DISCARDED ------------+
STAGING --deadline--> REJECTED(ETIMEDOUT) ----+
any nonterminal state --session fence--> DESTROYED
```

START reserves one slot from the session's dedicated write lane and
`total_length` logical bytes from the session's guaranteed
`max_write_staging_bytes` before it accepts data. Activate already backed that
quota from the process-wide pool, so unrelated load cannot revoke it or close a
connection. If the session's guaranteed staging charge is temporarily
occupied, the authority holds START in the dedicated write-admission lane until
capacity is released; it neither accepts bytes nor rejects the operation.
`REJECTED/EAGAIN` is not a legal write-stream result. The kernel's dedicated
write permit mirrors this authority bound, so ordinary load cannot create an
unbounded set of such waits, and a blocking `write(2)` never receives EAGAIN as
load backpressure. The wait has no repair deadline and never triggers
withdrawal.
The authority creates a session-owned memfd. New segments are copied into that
inert stage and are never written through an XFS file description. Duplicate
bytes on replay are compared, not applied. A conflicting overlap, gap, or
overflow is a protocol error.

FINAL without DISCARD is accepted only after the required prefix is complete.
The authority seals the memfd against writes, growth, and shrink, computes the
canonical digest, resolves replay, and takes the stable-inode mutation writer
lock. Only then may it enter visibility PREPARE and call the XFS write path.
There is one XFS write operation for the finalized prefix. The stage remains
inert before this point.

The authority records exactly one terminal result. If XFS writes a positive
prefix smaller than `apply_length`, that positive prefix is the committed
length and the syscall result. If XFS or killpriv changes state and a later
step fails, the result is `POSTAPPLY_ERROR` with the exact committed length,
error, and post-state. If no XFS-visible change occurred, the result is a
definite `REJECTED`. `RLIMIT_FSIZE` is set only for the limit-specific `EFBIG`
that requires `SIGXFSZ`; filesystem or non-LFS ceiling `EFBIG` is ordinary
rejection.

The authority memfd and its byte budget may be released after the terminal
canonical digest and segment-independent replay record are retained. The
terminal record stays in the mutation replay slot until normal replay-slot advancement. No
terminal response is sent until strict peer visibility has completed and the
post-state snapshot has been retained.

An orderly cancellation sends FINAL|DISCARD. Existing `CancelRequest` may
target the START request ID only before FINAL is accepted; it has the same
effect as DISCARD. After FINAL acceptance cancellation returns `EALREADY`, and
the frontend must consume and publish the terminal result. Killing a waiting
task does not abandon an applied result.

### 3.5 Kernel submission and short writes

One `write(2)` owns one `pfs_write_ctx`. Before START it reserves the full
length from `max_kernel_retained_stream_bytes`. It copies user bytes into
kernel-owned pages by segment, queues asynchronous FUSE stream requests, and
keeps up to `stream_window_frames` requests outstanding. It does not call
`fuse_simple_request()` serially for each frame. A local `ACCEPTED` completion
opens one transport-window credit but does not release those pages; all replay
bytes and the weighted reservation remain through the terminal reply. FINAL is
queued only after every earlier offset has been queued.

The go-fuse request readers may deliver one stream's requests out of order, and
stock go-fuse runs handlers inline on a mount-wide pool of at most 16 readers.
No stream handler may wait on authority I/O, an offset gap, or a reorder budget
while occupying one of those readers.

Before queueing a frame, the kernel charges one connection frame credit and the
exact payload bytes against `stream_window_frames` and `stream_window_bytes`.
That charge remains until the local ACCEPTED or terminal response. The
maintained go-fuse fork dispatches each private stream opcode as follows:

1. The reader validates the fixed header and copies it and the payload into a
   daemon-owned immutable job charged to that already-reserved connection
   window. It enqueues the job and deferred FUSE reply handle without waiting,
   then immediately returns to the reader loop.
2. Off-reader stream workers insert jobs into a per-stream ordered-send map
   keyed by `stream_offset`. The combined ingress queue, ordered map, and active
   sender own at most the negotiated frame and byte window; moving a job between
   them does not charge it again.
3. A sender drains each contiguous prefix to authority DATA. After the socket
   write completes it sends local ACCEPTED through the deferred reply handle and
   releases the daemon copy. FINAL holds its charge until its terminal response.

Because every submitted job already owns a kernel window credit, enqueue cannot
legitimately exceed the daemon budget. A failed nonblocking enqueue, a gap
beyond the negotiated window, or a conflicting duplicate is an accounting or
protocol error and withdraws the connection; it never blocks a reader. This is
new vNext adapter behavior. Protocol-5 transaction DATA rejected out-of-order
fragments and supplies no implementation for it.

`stream_window_frames` is the minimum of:

* the daemon-advertised stream window;
* available FUSE background-request credits;
* the daemon's transient reorder frame and byte credits; and
* the authority's negotiated stream frame window.

It is at least 2 for an admitted vNext mount. Frames from different writes may
occupy the window concurrently. One stream consumes one dedicated authority
write permit and one replay slot, not one permit per segment. Continuation
frames consume only the reserved byte/frame window. START reserves the whole
authority staging charge, so an admitted stream cannot deadlock waiting for
capacity needed by its own FINAL. Ordinary DATA permits and every CONTROL lane
are untouched. Waiting for kernel memory, the write lane, the per-handle
semaphore, or connection frame/byte credits occurs in kernel admission before
request queueing; daemon reader goroutines never perform those waits. No such
wait has a repair deadline or converts load into mount withdrawal.

The kernel handles iterator and signal boundaries as follows:

| Point | Action |
|---|---|
| User copy fails before any START bytes are queued | Return the local error; no stream and no sequence. |
| User copy fails after a nonzero contiguous prefix | FINAL that prefix with `apply_length == prefix`; return the applied positive count. |
| Signal arrives before any byte is staged | FINAL|DISCARD, wait for DISCARDED, then return `EINTR`. |
| Signal arrives after a nonzero prefix but before FINAL | FINAL the prefix and return the applied positive count. |
| Signal arrives after FINAL acceptance | Continue waiting uninterruptibly for the terminal result or withdrawal. |
| Authority commits fewer bytes than finalized | Revert the iterator by `advanced - committed_length`; return the positive committed length. |
| Definite rejection | Revert every advanced byte and return the authority errno; raise `SIGXFSZ` only for `RLIMIT_FSIZE`. |
| Ambiguous transport failure after FINAL | Do not retry with a new identity. Resume the same stream or withdraw the mount. |

No error path returns a positive count unless those exact bytes were applied,
installed, and publication-acknowledged. An incomplete stream with no FINAL
never changes XFS.

Finalizing a copied prefix on signal or user fault is an intentional vNext
Linux ABI change. Stock regular-file write paths may stop at a different copy
boundary; this profile promises the table above instead. Qualification tests
must assert the vNext result rather than inherit stock-FUSE expectations.

### 3.6 Append, sync, and durability

The START `O_APPEND` bit is the effective per-syscall append decision after
`O_APPEND`, `RWF_APPEND`, and `RWF_NOAPPEND` resolution. The authority ignores
the caller's file position, takes the stable-inode writer lock, assigns current
EOF, checks `RLIMIT_FSIZE` and `file_max_size` against that EOF, and writes
there. `assigned_offset` is returned. Two handles appending concurrently are
ordered at that lock and cannot receive the same offset.

A positioned stream freezes its supplied position. It does not sample or
update a shared file position until the terminal result. The kernel advances
`ki_pos` by the committed count only after publication acknowledgment.

For ordinary writes, terminal acknowledgment requires apply and visibility but
not stable-media durability. For `O_DSYNC`, the authority performs the XFS
data-sync barrier, including metadata needed to retrieve the data, before the
terminal response. For `O_SYNC`, it performs a full file sync before the
response. A sync failure after data application is `POSTAPPLY_ERROR`; the exact
state is still installed and published before the error returns. A later
successful `fsync`, `fdatasync`, or `syncfs` keeps its existing replay-safe
durability-barrier meaning.

### 3.7 Failure matrix

| Failure | Before FINAL | After FINAL, before apply | During/after apply | After terminal retained |
|---|---|---|---|---|
| Application exits or is killed | Kernel finalizes a copied prefix or discards zero bytes; no orphaned sequence. | Kernel continues the request. | Kernel continues installation/publication. | Result is consumed even if no task remains. |
| Client frontend crashes | No client receipt; authority fencing destroys the inert stage. | The identity is not replayed by a new mount. | No success is reported; mount absence or withdrawal discharges client cache state. | Retained authority truth is not converted into old-client success. |
| portablefsd crashes | Authority session is fenced and stage is destroyed; kernel withdraws. | No new identity; authority stage is destroyed on fence. | Applied state may exist; kernel cannot return success and withdraws. | Kernel cannot return success without a ring ack; retained result remains authority truth. |
| Authority process crashes | New epoch; stage is inert and discarded. | New epoch; no old-session replay. | Old mounts are fenced; any XFS result is discovered only by a new session, never replayed as old success. | Old terminal record is unavailable, so the old mount withdraws. |
| DATA connection drops, authority lives | Daemon resumes DATA and asks the kernel to replay retained immutable bytes with the same identity. | Same. | Replay resolves to the retained terminal result; if outcome is not yet classifiable, the session remains fenced from new work. | Hash-only replay returns the byte-identical response without XFS. |
| CONTROL connection drops | Stop new apply, resume the connection set within the lease, or fence. Staged bytes remain inert. | Same. | No acknowledgment until visibility status is exact. | No syscall success until visibility and publication complete. |
| Guaranteed staging quota is occupied | START waits in the dedicated admission lane without authority acceptance; no EAGAIN or withdrawal. | Not applicable after START admission. | Not applicable. | Not applicable. |
| Stage deadline expires | Definite `ETIMEDOUT`, consumes the per-open sequence, destroys bytes. | Not applicable once FINAL is accepted. | Deadlines do not convert APPLYING to rejection. | Terminal replay rules apply. |
| Client sends changed replay bytes or metadata | Fence before XFS. | Fence before XFS. | Never select a different result. | Fence; do not return retained success to a changed body. |

### 3.8 Coherence argument

Before FINAL, there is no XFS mutation and hence nothing for another mount to
observe. FINAL creates one ordered mutation, not one mutation per segment. The
authority assigns append offset, applies the finalized prefix once, snapshots
the exact post-state, completes peer visibility, and emits terminal replies in
that order. The source kernel removes only its intersecting stale pages and
installs the exact attributes before posting publication. The syscall cannot
return until the daemon acknowledges that publication. Therefore frame count,
alignment, and concurrent transport scheduling do not change the operation's
single visibility point.

### 3.9 FSKit mapping

pfslocal 2.0 keeps one high-level `WriteRequest` per FSKit write callback. It
adds `handle`, `operation_sequence`, `total_length`, effective position/append,
sync flags, and the callback bytes. portablefsd maps that request to the same
authority START/DATA/FINAL state machine and returns the protocol-6 terminal
reply plus `PostState`. `VolumeCore` allocates the sequence in its actor-owned
open-handle record and retains the Data until terminal publication. The actor
takes the dedicated write permit, retained-Data byte budget, and per-handle
permit before allocating that sequence; a post-allocation local failure sends
DISCARD under the same rule as Linux.

macOS 26 `FSVolume.Operations.write` provides one Data value and a resolved
offset, so positioned writes map without a second filesystem callback. A macOS
27 Handler write callback may be used only after a checked-in compiling probe
establishes its exact signature and result type; the current macOS 27 adapter
implements DataCacheHandler only. FSKit does not expose effective per-write append
intent, `RWF_APPEND`/`RWF_NOAPPEND`, `O_SYNC`, or `O_DSYNC` to the extension.
The current offset cannot be reinterpreted as append intent. Exact append and
per-write sync require FSKit to expose those decisions on the open description
or write callback. Without that primitive, the frontend MUST refuse those
flags or the exact profile; it MUST NOT emulate append with a size lookup.

A typed macOS 27 write result capable of returning post attributes is an
unverified requirement, not a claimed primitive. macOS 26 cannot return
complete write post attrs. The peer invalidation limits in section 2.7 still
prevent either checked-in adapter from qualifying as the exact multiwriter
profile.

## 4. Atomic resolve-open

### 4.1 Authority message layout

`ResolveOpenRequest` is request oneof field 57 and `ResolveOpenReply` is
response oneof field 47.

```proto
message ResolveOpenRequest {
  bytes parent = 1;              // 16-byte parent capability
  bytes name = 2;                // 1..NAME_MAX, no slash or NUL
  OpenFlags open = 3;
  bool create = 4;               // O_CREAT
  bool exclusive = 5;            // O_EXCL; requires create
  uint32 create_mode = 6;        // permission bits only
  uint32 umask = 7;
  bool no_follow = 8;            // final symlink refusal requested by caller
}

message ResolveOpenReply {
  enum Outcome {
    OUTCOME_UNSPECIFIED = 0;
    OPENED = 1;
    CREATED = 2;
    NEGATIVE = 3;
    POSTAPPLY_ERROR = 4;
  }
  enum HandleKind {
    HANDLE_KIND_UNSPECIFIED = 0;
    FILE = 1;
    DIRECTORY = 2;
  }
  Outcome outcome = 1;
  Item item = 2;                 // OPENED or CREATED
  bytes handle = 3;              // OPENED or CREATED; exactly 16 bytes
  HandleKind handle_kind = 4;
  uint64 next_operation_sequence = 5; // exactly 1 for a new handle
  reserved 6 to 8;
  reserved "parent_attr", "parent_object_version", "negative_valid_ns";
  int32 error = 9;               // POSTAPPLY_ERROR only; negative errno
}
```

Every structured outcome carries `Response.post_state`. Its object set is the
section 2.2 resolve-open set: PARENT for every outcome, plus TARGET for OPENED
or CREATED. CREATED marks the target CREATED; truncating OPENED marks TARGET and
uses positive equal visibility/snapshot sequences. Nonmutating OPENED and
NEGATIVE use `visibility_sequence == 0` and the positive stabilized
`snapshot_sequence`. POSTAPPLY_ERROR contains the parent and every target XFS
may have changed; it carries an Item only when that item remains a valid
post-state description and carries no transferable handle. There is no raw
parent attr or version outside this one envelope.
The authority does not choose cache lifetime; portablefsd derives the local
zero-or-60-second lifetime at the admission point.

The semantic `OpenFlags` are the existing read, write, append, truncate, sync,
and data-sync booleans. Exactly one or both of read/write is true. `exclusive`
without `create` is rejected by the kernel before dispatch. `O_CLOEXEC`,
`O_NONBLOCK`, and `O_LARGEFILE` remain local descriptor flags and are not sent.
`O_DIRECT`, `O_PATH`, `O_TMPFILE`, unknown resolve flags, and unsupported file
types are refused without fallback. `O_TMPFILE` retains its dedicated exact
operation.

The final component is never followed inside this operation:

* `create && exclusive` plus any existing directory entry, including a
  symlink, returns `EEXIST`;
* any other existing final symlink returns `ELOOP`, whether or not
  `no_follow` is set; and
* a missing name without `create` returns the successful `NEGATIVE` outcome.

The VFS may continue ordinary symlink path walking only by starting a new path
resolution outside this operation. It cannot convert the same
`RESOLVE_OPEN` into LOOKUP followed by OPEN. This keeps the operation's
authority path beneath its supplied directory capability.

### 4.2 Linux FUSE layout

The request payload is the structure followed by the raw name and one NUL:

```c
#define FUSE_PFS_RO_CREATE    (1U << 0)
#define FUSE_PFS_RO_EXCLUSIVE (1U << 1)
#define FUSE_PFS_RO_NOFOLLOW  (1U << 2)

struct fuse_pfs_resolve_open_in {         /* size 32 */
	uint32_t flags;                     /* offset 0; Linux open flags */
	uint32_t mode;                      /* offset 4; permission bits */
	uint32_t umask;                     /* offset 8 */
	uint32_t resolve_flags;             /* offset 12 */
	uint64_t parent_object_version;     /* offset 16 */
	uint64_t reserved;                  /* offset 24 */
};

#define FUSE_PFS_RO_OPENED   (1U << 0)
#define FUSE_PFS_RO_CREATED  (1U << 1)
#define FUSE_PFS_RO_NEGATIVE (1U << 2)
#define FUSE_PFS_RO_DIRECTORY (1U << 3)
#define FUSE_PFS_RO_POSTAPPLY_ERROR (1U << 4)
#define FUSE_PFS_RO_ENTRY_DROPPED (1U << 5)

struct fuse_pfs_resolve_open_out {        /* size 184 */
	struct fuse_entry_out entry;        /* offset 0, size 128 */
	struct fuse_open_out open;          /* offset 128, size 16 */
	uint64_t reserved_at_144;           /* offset 144; zero */
	uint64_t next_operation_sequence;   /* offset 152 */
	uint32_t flags;                     /* offset 160 */
	int32_t  error;                     /* offset 164 */
	uint32_t post_state_bytes;          /* offset 168 */
	uint32_t reserved0;                 /* offset 172 */
	uint64_t reserved1;                 /* offset 176 */
};
```

For NEGATIVE, `entry.nodeid == 0`, the entire `open` structure is zero, and
`next_operation_sequence == 0`. portablefsd first performs the same authority
stabilize-and-register loop as LOOKUP, then calls the existing
`admitNegativeNameLocked` equivalent under its source/peer mutex. It sets entry
lifetime to 60 seconds only when that admission succeeds; while the coordinate
is held, not registered, over capacity, or not newer than its last peer repair,
it sets both lifetime fields to zero. The kernel returns that uncacheable
negative without retaining a dentry.

OPENED and CREATED carry a positive entry, handle, and next sequence 1. The
kernel ignores `entry.attr`; TARGET and PARENT trailer records are the sole attr
source. The header attr lifetime is 60 seconds when every relevant coordinate
passes section 2.3 admission and zero for a dropped candidate. CREATED and
truncating OPENED use positive mutation sequence rules. Nonmutating OPENED and
NEGATIVE use zero visibility and a positive stabilized snapshot sequence.

`FUSE_PFS_RO_ENTRY_DROPPED` says the namespace candidate failed the common
sequence gate. For OPENED/CREATED, `fuse_atomic_open()` attaches the returned
handle to an unhashed dentry, calls `d_drop()`, and gives the entry zero
lifetime; it MUST NOT publish the old `(parent,name)` binding. For NEGATIVE it
means only the zero-lifetime result. The flag is not an error.

POSTAPPLY_ERROR has a negative `error`, zero `open`, zero next sequence, and a
positive-sequence applied trailer. The kernel installs and publishes the exact
state, abandons any provisional handle, and then returns that error. Clean
OPENED, CREATED, and NEGATIVE have `error == 0`. Definite pre-apply failures
have no resolve-open body and use `Response.errno`. Structured resolve outcomes
have `Response.errno == 0` and `Response.uncertain == false`.

`fuse_atomic_open()` issues exactly one `FUSE_PFS_RESOLVE_OPEN`. It does not
issue FUSE LOOKUP, CREATE, OPEN, or SETATTR for the same final component. A
failure to support the opcode under the vNext profile aborts the connection;
`ENOSYS` is not a fallback signal.

On CREATED, `fuse_atomic_open()` sets `FMODE_CREATED` before returning to
`do_open`, including when CREATED came from exact replay. This is the required
VFS signal to skip a contradictory post-create access check; its absence is a
kernel ABI defect, not an authority permission failure.

For a truncating OPENED result, `fuse_atomic_open()` sets private
`FMODE_PFS_APPLIED` before returning to `do_open`. Patch 0001 changes
`fs/namei.c:do_open()` before `may_open()` and `handle_truncate()` to apply the
same consumed-operation rule as create:

```c
if (file->f_mode & (FMODE_CREATED | FMODE_PFS_APPLIED)) {
	open_flag &= ~O_TRUNC;
	acc_mode = 0;
}
```

This is not just errno suppression: clearing `O_TRUNC` prevents the VFS from
issuing a second SETATTR truncate, and clearing `acc_mode` prevents a second
access decision after the authority has applied the operation. The bit is set
only for a structured truncating OPENED result whose truncate reached the
authority's normative decision; nontruncating OPENED and pre-apply failures do
not set it.

### 4.3 Authority operation and permission split

The authority resolves and acts under one parent/name namespace writer lock.
It uses the parent capability rather than a reconstructed path and refuses
escape, magic links, and final symlinks. On Linux this requires an fd-relative
`openat2`/XFS operation with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
RESOLVE_NO_SYMLINKS`, or an equivalent single XFS-locked operation with the
same properties. A separate `stat` followed by `open` is not equivalent.

For an outcome that makes no XFS change, the authority uses the existing
lookup stabilization loop: stabilize `(parent identity,name)` and the parent
and target attr coordinates, take the namespace lock, resolve and snapshot,
verify that no newer overlapping cursor appeared, register the positive or
negative resolution in the session audience, and retry on conflict. The
successful cursor becomes `PostState.snapshot_sequence`. A mutating outcome
uses its source publication gate and visibility sequence instead. A response
is not written until registration or mutation visibility is complete.

The operation is:

1. Resolve the raw final name under the locked parent.
2. On miss without create, snapshot the parent, register the negative
   resolution, and return NEGATIVE.
3. On miss with create, check create permission, apply `create_mode & ~umask`,
   create and open once, snapshot child and parent, and return CREATED.
4. On hit with `create && exclusive`, return `EEXIST` before opening or
   truncating.
5. On another hit, refuse a symlink, check target access/type, open it, and if
   requested perform truncate under the same item writer lock. Snapshot the
   entry and any changed target before returning OPENED.

If handle acquisition succeeds but a later pre-apply check fails, the
authority closes the provisional handle. If truncate reaches XFS and a later
step fails, the reply is an applied post-error with exact target state and the
provisional handle is either returned as part of the retained outcome or
closed exactly once according to that outcome. Resource ownership continues to
use the existing exact resource-disposition protocol.

The mount is single-principal. Attach binds the authenticated principal's uid,
gid, and supplementary groups. The FUSE request credential MUST name that same
principal. The permission split under mandatory `default_permissions` is:

| Check | Kernel | Authority |
|---|---|---|
| Execute/search on already walked ancestors | Normative VFS check against installed attrs | Session root/capability confinement |
| Execute/search on final parent | Normative VFS check before dispatch | Rechecked under the parent/name lock |
| Parent write permission when the name is absent and create is needed | Not checked unconditionally; doing so would wrongly reject `O_CREAT` on an existing file | Normative conditional check |
| Existing target read/write permission for nontruncating OPENED | Recheck admitted attrs; if they were dropped as stale, run the normal VFS check against the already-newer installed attrs and close the provisional handle on denial | Normative check before open |
| Existing target type, append-only, immutable, mount-read-only | Validate admitted attrs; for an applied result, do not replace the retained outcome with a later local errno | Normative check before open/truncate |
| `O_TRUNC` write permission and regular-file requirement | Pre-dispatch consistency where an inode is already available; post-reply validation cannot veto an applied truncate | Normative check before XFS truncate |
| Create mode, umask, ownership, setgid-directory inheritance | Validate returned result | Normative computation and XFS operation |

An admitted nonmutation attr must make the kernel and authority checks agree;
otherwise the mount configuration is wrong and withdrawal follows. If a later
peer attr made a nontruncating OPENED record stale, an ordinary local denial is
legal: the kernel closes the replay-safe provisional handle and linearizes the
side-effect-free open after that later change. CREATED uses `FMODE_CREATED`.
Truncating OPENED uses the `FMODE_PFS_APPLIED` `do_open()` rule in section 4.2,
so the VFS neither rechecks nor repeats an already-applied truncate; the
authority's check is normative. Parent write permission stays authority-side
because the kernel cannot know before the atomic request whether the final name
exists.

### 4.4 Replay and O_EXCL

Every RESOLVE_OPEN that can return a handle carries a mutation envelope even
when it opens an existing object without changing XFS. Handle and item
capabilities are replayed authority resources. The canonical body includes
parent capability, raw name, all semantic flags, mode, and umask.

For `O_CREAT|O_EXCL`, the first accepted replay identity owns the create
decision. If it creates the object and its response is lost, an exact replay
returns the same item, handle result, attributes, and CREATED outcome. It does
not re-resolve the now-existing name to `EEXIST`. A different mutation identity
observes the name and returns `EEXIST`. Changed flags or mode under the same
identity are a replay mismatch.

Replay does not grant the retained namespace entry a new cache position. The
retained CREATED record carries its original positive `snapshot_sequence`.
At cache admission, portablefsd compares that sequence with
`last_peer_repair_sequence[(parent,name)]` under the common gate. If it is not
newer, portablefsd performs a fresh noncreating stabilize-and-register
resolution; it MUST NOT execute create or truncate again. The original handle
and CREATED result remain the syscall result. If the fresh binding is still the
created item, its current attrs and snapshot replace the stale cache payload.
If the binding is absent or names another item, the kernel receives
`FUSE_PFS_RO_ENTRY_DROPPED`, attaches the original handle to an unhashed dentry,
and caches no retained binding. The authority also samples the original handled
item at the fresh cursor so any eligible disconnected-inode attrs are current.
Thus POSIX may return a descriptor for an object whose name was concurrently
removed, but no old pathname binding is installed. The original or refreshed
entry and every attr then occupy the section 2.3 PENDING reservations until the
reply is finalized; this replay path has no point-in-time-only exception.

NEGATIVE carries no handle. It is registered like LOOKUP and gets a 60-second
lifetime only after daemon admission. A held, over-capacity, or not-newer
coordinate returns the same linearized ENOENT with zero lifetime. A later
create/link/rename sends peer namespace repair before acknowledgment; a repair
that won before reply admission makes the negative uncacheable.

### 4.5 Failure matrix

| Failure point | Required result |
|---|---|
| Kernel fails before request queueing | No authority operation and no replay identity consumption. |
| Client crashes or task cancels while request is definitely pre-apply | Authority closes provisional resources and records a definite no-change result; session fencing removes an abandoned client. |
| Client crashes after possible apply | It publishes no success. The mount is absent or withdrawn, and the retained authority outcome remains visible to new sessions. |
| DATA connection drops before create/open dispatch | Same-identity replay; no new LOOKUP or CREATE. |
| Connection drops after create/open/truncate | Same-identity replay returns the retained resource and exact state. No second create or truncate. |
| CONTROL connection drops during visibility/publication | Resume within the lease or fence and withdraw. No source acknowledgment is inferred from the DATA reply. |
| portablefsd dies after authority apply but before FUSE reply | Kernel withdraws; authority fences the session and releases or retains provisional resources according to exact resource rules. The caller receives no success. |
| Authority dies before apply | New epoch, no old replay, mount withdrawal. |
| Authority dies after XFS may have applied | Old session is fenced. A new mount observes current XFS state by a new resolution; the old call never reports success. |
| Kernel cannot install the positive or negative entry | No publication receipt; mount withdrawal. An applied create remains visible authority state. |
| O_EXCL response is lost | Exact replay returns CREATED; a new identity returns EEXIST. |
| Replayed CREATED is older than peer repair of `(parent,name)` | Fresh noncreating stabilization runs; create is not repeated. Return the original handle on an unhashed dentry unless the same binding is still current. |
| Parent or target post-state is malformed | No partial dentry/attr/handle installation; abort and withdrawal. |

### 4.6 Coherence argument

The source closes the `(parent identity, name)` publication coordinate before
dispatch. The authority resolves and changes that coordinate once under its
namespace lock. The kernel installs the resulting positive or negative entry,
parent state, target state, and handle before source publication. A peer
mutation that later changes the name must repair the installed entry before it
can acknowledge. A later repair that completed before reply admission forces a
zero-lifetime drop through the common snapshot gate. There is no interval in
which LOOKUP said absent but a separate CREATE races another creator, and an
O_EXCL replay neither repeats create nor republishes its old name over a newer
binding.

### 4.7 FSKit mapping

pfslocal 2.0 defines `ResolveOpenRequest` and `ResolveOpenReply` with the same
semantic fields, outcomes, entry, common PostState, handle, snapshot sequence,
and admitted negative lifetime. It replaces separate frontend
LOOKUP-plus-CREATE/OPEN use for any framework callback that can express atomic
final-component open.

macOS 26 `FSVolume.Operations` exposes lookup, create, and open as separate
callbacks. The checked-in macOS 27 adapter proves DataCacheHandler only; no
compiling Handler probe establishes a callback that owns final-name resolution
plus open-or-create. Calling pfslocal RESOLVE_OPEN from a create callback and
later satisfying a separate open callback does not give FSKit an atomic
framework result or exact handle ownership boundary.

The exact requirement is an FSKit primitive whose input is parent item, raw
final name, create/exclusive/truncate/no-follow flags, mode, and context, and
whose one reply can install a positive or negative entry, complete child and
parent attrs, and the open handle. macOS 26 lacks that primitive; macOS 27 is
unverified until a checked-in SDK artifact and compiling probe establish it.
Both checked-in adapters MUST refuse the exact vNext profile rather than
compose lookup, create, and open callbacks.

## 5. Completion-ring publication

### 5.1 Purpose and lifecycle

The current second blocking `FUSE_PFS_PUBLISH` request is removed. The original
state-bearing FUSE reply is still retained by the kernel's post-VFS reply
publication scope. After VFS post-processing has installed the full result,
the kernel posts a fixed receipt to a shared ring and signals portablefsd.
portablefsd copies receipts in order but processes them concurrently, posts one
completion record for each finished receipt, and signals the kernel. The
originating syscall does not return a normal or applied-error result before its
own completion record is observed. It does not wait for lower-numbered,
unrelated receipts.

The connection owns a semaphore of exactly `max_publication_tokens` permits.
One permit represents one possible publication token and therefore one receipt,
not one task or scope. Before entering a VFS operation that can add tokens, the
kernel reserves the path's exact maximum token count, before any affected inode
or parent `i_rwsem` is taken. Token-add consumes one of that scope's reserved
permits without sleeping; scope merge moves tokens and their permits and never
coalesces them. Atomic open may therefore leave lookup and open/create tokens in
one scope while still consuming two permits.

Each created token retains its permit until its matching DONE is consumed or
the connection reaches CACHE_WITHDRAWN or UNSERVABLE. A reservation that never
becomes a token is released when that path can no longer add it; a token
canceled before receipt posting releases it at cancellation. After a receipt
is posted, cancellation cannot release the permit. Every transition owns an
exactly-once release bit, and merge does not change its owner. This is a hard
bound on all uncompleted receipts; `max_background`, task count, scope count,
and `fc->num_waiting` are not bounds and are not used for ring sizing.

There is one ring per FUSE connection. It is set up exactly once after the
kernel has queued FUSE_INIT and before the daemon writes the INIT reply. The
daemon creates two non-semaphore `eventfd` objects with `EFD_CLOEXEC |
EFD_NONBLOCK` and calls:

```c
#define FUSE_DEV_IOC_PFS_RING_SETUP \
	_IOWR(229, 3, struct fuse_pfs_ring_setup)

struct fuse_pfs_ring_setup {              /* size 96 */
	uint32_t abi_version;                /* in: exactly 1 */
	uint32_t entry_count;                /* in: power of two */
	int32_t  receipt_eventfd;            /* in: kernel signals daemon */
	int32_t  completion_eventfd;         /* in: daemon signals kernel */
	uint64_t mmap_offset;                /* out */
	uint64_t mmap_length;                /* out */
	uint8_t  mount_instance_id[32];      /* in: Attach field 11 */
	uint8_t  session_id[16];             /* in: activated session */
	uint64_t session_generation;         /* in: activated generation */
	uint64_t connection_generation;      /* out: nonzero */
};
```

`entry_count` is in `[64, 65536]` and is at least the accepted FUSE
`max_publication_tokens`. Protocol 6 adds required
`AttachRequest.mount_instance_id = 11`, exactly 32 random bytes; the authority,
daemon, kernel, and supervisor retain the same value. The kernel allocates the
shared pages. The daemon maps
exactly `mmap_length` bytes from the same `/dev/fuse` file at `mmap_offset` with
`MAP_SHARED`, read/write. Repeated setup, setup after INIT reply, bad eventfds,
identity disagreement, or an INIT selecting vNext without a ready ring aborts
the connection. There is no request fallback.

### 5.2 Shared layout and memory ordering

The first 64 bytes are the header. Receipt entries begin at offset 64.
Completion entries begin at `64 + entry_count * 64`. The logical shared length
is `64 + entry_count * 80`; `mmap_length` is that value rounded up to PAGE_SIZE,
and padding is zero.

```c
struct fuse_pfs_ring_header {             /* size 64, cache-line aligned */
	uint32_t abi_version;                /* offset 0; exactly 1 */
	uint32_t entry_count;                /* offset 4 */
	uint32_t receipt_entry_size;         /* offset 8; exactly 64 */
	uint32_t completion_entry_size;      /* offset 12; exactly 16 */
	uint64_t receipt_tail;               /* offset 16; kernel release-store */
	uint64_t receipt_head;               /* offset 24; daemon release-store */
	uint64_t completion_tail;            /* offset 32; daemon release-store */
	uint64_t completion_head;            /* offset 40; kernel release-store */
	uint64_t reserved_at_48;             /* offset 48; always zero */
	uint64_t connection_generation;      /* offset 56; kernel-owned */
};

struct fuse_pfs_publication_receipt {     /* size 64 */
	uint64_t receipt_sequence;          /* offset 0 */
	uint64_t request_unique;            /* offset 8 */
	uint64_t visibility_sequence;       /* offset 16; zero for negative/read */
	uint64_t nodeid;                    /* offset 24; primary request node */
	int64_t  result;                    /* offset 32; final syscall/FUSE result */
	uint32_t opcode;                    /* offset 40 */
	uint32_t flags;                     /* offset 44 */
	uint64_t applied_bytes;             /* offset 48 */
	uint64_t reserved;                  /* offset 56 */
};

#define FUSE_PFS_COMPLETION_DONE (1U << 0)
struct fuse_pfs_publication_completion {  /* size 16 */
	uint64_t receipt_sequence;          /* offset 0 */
	uint32_t flags;                     /* offset 8; exactly DONE */
	uint32_t reserved;                  /* offset 12; zero */
};
```

Receipt flags are:

```text
PUBLISHED       = 0x0001
NOT_PUBLISHED   = 0x0002
POSTAPPLY_ERROR = 0x0004
NEGATIVE_ENTRY  = 0x0008
RESOURCE_REPLY  = 0x0010
```

Exactly one of PUBLISHED and NOT_PUBLISHED is set. NOT_PUBLISHED is legal only
when the authority definitely made no visible mutation. An applied or
post-apply-error response can produce only PUBLISHED.

The kernel stores private immutable copies of ABI version, entry count, both
entry sizes, logical length, and connection generation at setup. It never uses
the daemon-writable header copies for bounds or identity. It also stores the
last accepted daemon head and tail values privately.

The kernel serializes receipt producers with a per-connection spinlock. It
validates that acquire-loaded `receipt_head` did not decrease and is no greater
than its private `receipt_tail`. It then requires `receipt_tail - receipt_head <
entry_count`, writes the entry at `tail & (entry_count - 1)`, and release-stores
the incremented tail. A token owns a permit before it can reach this point and
`entry_count >= max_publication_tokens`; therefore a valid not-yet-posted token
always has a receipt slot. Observing a full receipt ring for such a token proves
counter corruption, a duplicate post, or broken permit accounting and is a
protocol failure, not a load-shedding path. Receipt posting never sleeps while
holding a VFS lock. `receipt_eventfd` is a wake hint for new receipts.

The daemon acquire-loads `receipt_tail`, copies entries in sequence order, and
release-stores `receipt_head` after each copy. A head that decreases or exceeds
tail is a protocol failure. It signals `completion_eventfd` after advancing the
head so blocked kernel receipt producers recheck space. Copying releases the
receipt slot but does not acknowledge the syscall. Each copy is dispatched to
a bounded publication worker; overlapping source coordinates remain ordered by
the existing local source/peer gates, while unrelated receipts run concurrently.

After one worker completes all semantic work, the daemon serializes only the
short completion append. It validates acquire-loaded `completion_head`, waits
while `completion_tail - completion_head == entry_count`, writes the exact
receipt sequence at `completion_tail & (entry_count - 1)`, and release-stores
the incremented completion tail. The kernel drains completion records in their
completion order, matches each to one private outstanding waiter, rejects an
unknown or duplicate sequence, marks that waiter done, and release-stores
`completion_head`. It then signals `receipt_eventfd` to wake a completion
producer. A syscall wakes from its own done bit; completion sequences need not
be contiguous.

Receipt sequences start at 1 and never wrap. There is no contiguous
acknowledgment counter: the DONE record is the sole normal completion proof for
one receipt. Counter overflow or bad bounds is a protocol failure. Eventfd
counts may coalesce and are never treated as records. Both sides require
`reserved_at_48 == 0` and never write it after setup.

### 5.3 Receipt processing and ordering

At scope finish, the kernel posts one receipt for every token in the merged
scope before waiting. It then waits uninterruptibly until every token has either
consumed its own DONE or observed CACHE_WITHDRAWN/UNSERVABLE. Fatal signals and
task exit do not cancel this wait and do not release permits. Tokens may finish
out of order; each DONE atomically marks its token complete and releases that
token's permit exactly once. A fail-closed transition marks every remaining
token failed and releases each remaining permit exactly once only after the
withdrawal proof is established.

For each receipt, its assigned worker MUST complete these steps in order:

1. Match `(connection_generation, request_unique, opcode)` to the retained
   source-publication record.
2. Confirm that the original FUSE reply write completed. A receipt may race the
   userspace response-writer completion callback, so the daemon waits for that
   callback exactly as the current PUBLISH handler does.
3. Apply the semantic verdict. For PUBLISHED, mark the callback publication
   ready and release its exact local source gate. For a legal NOT_PUBLISHED,
   retire the no-change callback without publishing cached state.
4. Commit any provisional item/handle ownership attached to the reply.
5. If the response carries an authority terminal-delivery token, send its
   receipt and observe the CONTROL reply.
6. Append that receipt's DONE completion and signal `completion_eventfd`.

The original syscall waits through step 6 for every token in its scope. Thus
"publication observable" still means VFS effects, fsnotify/accounting, dcache
and attr installation, page-cache action, source-gate release, resource
disposition, and any required terminal-delivery receipt are complete. A fast
ring cannot acknowledge merely because it saw a kernel entry.

Ring copying runs on a dedicated daemon goroutine with no DATA-operation
permit. Publication workers have their own bounded pool. Terminal-delivery step
5 uses the dedicated terminal CONTROL lane and its
`max_terminal_receipts_in_flight` permits, never the liveness or visibility
lane. Receipt copying, completion appends, and source-gate release use no
ordinary or write-stream permit. Saturated writes, lookups, KeepAlive calls, or
an unrelated slow terminal receipt cannot prevent another ready receipt from
posting DONE.

### 5.4 Daemon death and withdrawal fence

Closing the daemon's `/dev/fuse` owner aborts the connection, but stock FUSE
disconnect alone is insufficient because reads can still hit retained pages.
vNext adds connection/superblock withdrawal states:

```text
ACTIVE -> QUIESCING -> CACHE_WITHDRAWN -> DEAD
                  \-> UNSERVABLE ------> DEAD
```

On daemon death, malformed ring state, explicit supervisor revocation, or
authority fencing, the kernel first enters QUIESCING. It rejects new requests
and blocks new page-cache fills and
new dentry/attribute cache hits for SHARED objects. It then takes each tracked
SHARED inode's publication and invalidate locks, removes all data pages and
private mappings, expires attrs and namespace entries, and marks the
superblock incapable of satisfying cached operations. Only after all tracked
state is withdrawn does it enter CACHE_WITHDRAWN and wake publication waiters
with `ENOTCONN`.

If page or dentry withdrawal cannot complete, including
`invalidate_inode_pages2()` returning `-EBUSY` for a pinned folio, the kernel
MUST make the superblock permanently UNSERVABLE instead of waiting for an
unreachable forced unmount. It release-stores the state before exposing proof,
rejects every subsequent lookup, permission check, getattr, open, read, write,
and cache hit with `EIO`, blocks new fills and mappings, unmaps every existing
SHARED PTE with TLB shootdown, and makes later faults return `VM_FAULT_SIGBUS`.
The exact profile rejects `FOLL_LONGTERM` pins on SHARED mappings from mount
activation onward and rejects every new GUP pin once QUIESCING begins. A
resident or transiently pinned folio may remain allocated, but no VFS or mmap
path may serve it. Once these checks and unmaps complete, UNSERVABLE is
irreversible and publication waiters wake with `ENOTCONN`.

The kernel exposes the following raw 80-byte record as mode 0400 at
`/sys/fs/fuse/connections/<id>/pfs_unservable` only in UNSERVABLE:

```c
#define FUSE_PFS_SUPERBLOCK_UNSERVABLE 1
struct fuse_pfs_unservable_proof {         /* size 80 */
	uint32_t abi_version;                /* offset 0; exactly 1 */
	uint32_t state;                      /* offset 4; UNSERVABLE */
	uint8_t  mount_instance_id[32];      /* offset 8 */
	uint8_t  session_id[16];             /* offset 40 */
	uint64_t session_generation;         /* offset 56 */
	uint64_t connection_generation;      /* offset 64 */
	uint64_t fence_generation;           /* offset 72; nonzero */
};
```

`fence_generation` increments before the state store. The official supervisor
reads this kernel record and sends its exact bytes in the existing
`MountAbsenceProof.observation` with component
`linux-fuse-pfs-unservable-v1` over the authenticated session. The authority
accepts it only for the enrolled mount instance, session ID and generation,
and a `fence_generation` greater than any proof already accepted for that mount.
It first marks the participant fenced, or verifies that it already is, then
retires it. This authenticated unservable proof substitutes for mount absence
when retiring the participant; it does not claim that the superblock is
unmounted. A malformed, stale, or mismatched record does nothing.

The daemon MUST NOT fabricate completion records during shutdown. The kernel
pins ring pages and eventfd contexts until DEAD, so
descriptor reuse cannot acknowledge an old generation. A remount gets new
pages and a new connection generation. A daemon death therefore yields either
an observed DONE completion, complete cache withdrawal, authenticated
UNSERVABLE state, or a waiter that remains blocked; it never releases a syscall
while unacknowledged cached state is servable.

### 5.5 Failure matrix

| Failure point | Required result |
|---|---|
| Client/kernel crashes before posting | The mount is absent; authority lease/fence removes the participant. |
| FSKit client extension crashes before PublicationAck | No semantic acknowledgment. The supervisor must prove mount absence before the authority retires the participant. |
| Daemon crashes before consuming | No completion. Kernel withdraws all cache or enters authenticated UNSERVABLE before waking the syscall. |
| Daemon crashes after copying but before source-gate release | Same; copied ring state is not an acknowledgment. |
| Daemon crashes after source-gate release but before completion append | Same-epoch daemon recovery is not supported for the same FUSE connection. Withdrawal is required; duplicate authority terminal receipt is idempotent. |
| Daemon appends completion but dies before eventfd signal | Kernel's abort path drains `completion_tail`; an already stored valid DONE completes, otherwise withdrawal. |
| eventfd signal is lost/coalesced | Eventfd is a wake hint. Kernel and daemon always recheck shared counters. |
| Task is killed while a scope awaits DONE | The wait remains uninterruptible; each token consumes DONE or a fail-closed result and releases its permit exactly once. |
| Atomic-open child scope merges into its parent | Every token and permit moves individually; no receipt is coalesced and the parent waits for all of them. |
| Receipt ring appears full to a permitted token | This is impossible under valid token accounting; counter corruption, duplicate post, or a permit bug aborts and withdraws. Ordinary load does not take this path. |
| Completion ring fills | The daemon completion appender waits outside every DATA and CONTROL permit; kernel draining continues. Load has no withdrawal deadline and no PUBLISH fallback exists. |
| Authority CONTROL connection fails during terminal receipt | Do not ack the ring. Resume within the lease or fence and withdraw. |
| Authority DATA connection fails after the original result | The retained result may be replayed only with its original identity. DONE still waits for exact daemon-side publication processing. |
| Original FUSE reply write status is not yet known | Hold the receipt until it becomes definite. Do not infer it from ring arrival. |
| Malformed or duplicate receipt/completion mapping | Abort, fence, and withdraw. Eventfd coalescing does not create a duplicate record. |
| Cache withdrawal returns EBUSY | Enter irreversible UNSERVABLE, zap mappings, expose the bound proof, then wake waiters. Forced unmount is not required for the proof. |
| Authority crashes while publication is pending | Old session fences. The daemon does not ack; kernel withdrawal completes the local side. |

### 5.6 Coherence argument

The post-VFS scope is the only receipt producer, so a receipt cannot precede
kernel installation and notification work. The daemon releases the exact
source gate only after matching that receipt to the physically written reply,
and DONE follows terminal delivery for that same receipt. A syscall waits for
its own DONE, not an unrelated lower sequence. If DONE cannot arrive, cached
service is withdrawn or the whole superblock becomes provably unservable before
the syscall is released. The two-ring transport changes neither the publication
edge nor its fail-closed condition.

### 5.7 FSKit mapping

The shared-memory ring is Linux-only because FSKit does not expose `/dev/fuse`
request scopes. pfslocal 2.0 retains one-way `PublicationAck`, with
`operation_id` and the exact PUBLISHED/NOT_PUBLISHED verdict. The Swift
`publishAfterReply` wrapper MUST invoke the real FSKit reply handler first,
then send `PublicationAck`, and MUST keep the callback pending until
portablefsd confirms the local send/terminal shutdown rule. A Swift
continuation completed before the real reply-handler call is not a publication
edge.

macOS 26 provides the checked-in reply-handler callback. macOS 27 may use an
equivalent Handler callback only after the required compiling probe establishes
it; DataCacheHandler alone is not that publication edge. Neither checked-in
adapter exposes a primitive that can prove global kernel cache withdrawal if
the extension dies while a publication is pending.
The exact requirement is either synchronous framework invalidation of all
retained state followed by an observed unmount, or an OS-provided mount-death
fence that makes cached vnodes unservable. Until that proof exists, extension
death uses the existing mount-absence supervisor path and cannot be claimed as
an exact profile acknowledgment.

## 6. Implementation order and component map

The landing order below is normative. A step may use temporary development-only
shims from an earlier protocol, but it MUST satisfy every obligation named for
that step before the next step lands, and no intermediate commit may advertise
protocol 6:

1. **Exact post-state replies (section 2).** This defines the common mutation
   result and version rule consumed by resolve-open and write. This step includes
   daemon candidate reservation/revocation, positive and negative registry
   capacity, whole-page READDIRPLUS registration, stamped ATTR/ENTRY/SIZE peer
   repairs, both kernel version gates, parent `i_version`, and locked
   `fi->attr_version` updates. It can first be exercised by existing
   one-operation mutations while the old write transport remains on an
   intermediate development branch.
2. **Atomic resolve-open (section 4).** It uses the post-state installer and
   removes the namespace race without depending on the write-stream or ring
   throughput work. Patch 0001's `FMODE_PFS_APPLIED` `do_open()` change lands in
   this step; a second SETATTR truncate is a step-2 failure.
3. **Completion-ring publication (section 5).** It changes how every installed
   result crosses the publication boundary. The per-token semaphore, all
   pre-lock reservation sites, uninterruptible multi-token DONE wait, and
   exactly-once permit release land with the ring. Landing it after the one
   installer exists avoids implementing ring receipts for two result shapes.
4. **Unified write stream (section 3).** This is the largest transport and
   kernel-I/O change. Off-reader go-fuse dispatch, non-EAGAIN staging admission,
   kernel-owned replay bytes, daemon replay metadata, and replay priority are
   part of this step. Landing it last lets it use the final post-state and ring
   paths from its first implementation. The protocol-6 version cut is enabled
   only when all four are present and the retired messages/opcode and
   compatibility-writer lease have been deleted.

Expected implementation touch points follow. Names denote current files or the
replacement file in the same component; generated files are included in the
change that edits their source schema.

| Component | Files or areas |
|---|---|
| Authority schema/framing | `proto/authority/v1/authority.proto`, generated `vcs/internal/authoritypb`, `vcs/internal/authorityrpc/protocol.go`, `frame.go`, `wire_validate.go`, client/server transport dispatch; set `responseEnvelopeReserve = 2048`, retain the four-object PostState cap in validation, and extend `TestRetainedReplyEnvelopeFitsReserve` with the maximum two-byte-tag envelope |
| Authority writes and replay | `vcs/internal/authorityrpc/write_transaction_linux.go` replaced by write-stream state, one-shot handlers removed, source-publication gate derivation, replay fingerprinting, dedicated write and terminal-receipt lanes, guaranteed staging quota, staging sweeper, `vcs/internal/volumeserver` replay/visibility order |
| XFS state extraction | `vcs/internal/xfsstore` mutation interfaces and implementations, canonical striped writer-lock sets for every mutation including SetAttr, post-operation `statx`, `FS_IOC_GETFLAGS`, rdev/blksize extraction, parent snapshots, sync error classification |
| Linux daemon adapter | `vcs/internal/fusev3/fuse_linux.go`, `raw_linux.go`, `write_transaction_linux.go` replacement, mutation handlers, source publication, identity/node registry, range mutation replies, and mount teardown; add PENDING/FINALIZED cache-install reservations under the source/peer mutex, peer revocation before COMPLETE, positive/negative/attr capacity drops, page-atomic READDIRPLUS registration, and retained stream replay metadata |
| Maintained go-fuse fork | FUSE 7.42 constants and UAPI structs, deferred private-opcode reply handles, nonblocking reader-to-stream-worker dispatch, combined ingress/reorder window accounting, replay notification, and variable private-opcode replies; no reader goroutine may wait on an authority write or offset gap. The current fork has no `/dev/fuse` mmap API, does not export `mountFd`, and computes `outPayloadSize` only for six stock opcodes, so all three surfaces must be added explicitly along with completion-ring setup exposure |
| Kernel patch 0001: generic VFS | `kernel/linux-6.12.100-portablefs-append/0001-fs-add-post-VFS-reply-publication-scopes.patch` and `fs/namei.c`; make token permits part of `fs_reply_publish_token`, preserve them through scope merge, post and wait for every token uninterruptibly, and release exactly once. Reserve two possible tokens in `open_last_lookups()` before the final-parent lock; reserve one in `filename_create()` before the parent lock, `do_unlinkat()`/rmdir before the parent lock, and `do_renameat2()` before either parent lock and before `lock_rename()` (the one rename token covers both parent roles). Reserve one before inode/file locks in `vfs_write()`, `vfs_iter_write()`, splice, copy-file-range, and io_uring write entry points, and before the applicable locks in setattr, fallocate, xattr, link, symlink, mkdir/mknod, and tmpfile sites. Add the `FMODE_PFS_APPLIED` clearing of `O_TRUNC` and `acc_mode` in `do_open()` before `may_open()`/`handle_truncate()` |
| Kernel patches 0002/0003: FUSE profile | `0002-fuse-add-PortableFS-strict-coherence-profile.patch`, `0003-fuse-expire-strict-namespace-entries-without-parent-.patch`, and `README.md`; add the protocol-6 installer, ATTR/ENTRY/SIZE sequence stamps, parent and target gates, publication-token semaphore and ring, write-stream contexts/replay scheduling, withdrawal states, ABI layout/state-machine tests, and live qualification |
| pfslocal | `pfslocal/pfslocal.proto`, generated Go/Swift, framing golden files, protocol-major gates, mutation replies, write request, resolve-open messages, PublicationAck tests |
| macOS shared adapter | `swift/PortableFSKit/Sources/PortableFSKit/FSKitMapping.swift`, `OperationsAdapter.swift`, `VolumeCore.swift`, `MacOSV3Coherence.swift`, `MacOSV3FSKitComposition.swift`, transport and publication tests |
| macOS 27 adapter | `swift/PortableFSKitMacOS27/Sources/PortableFSKitMacOS27/NativeDataCache.swift`; checked-in SDK artifacts and compiling Handler probes must precede any Handler result adapter or qualification claim |
| Compatibility-writer lease removal | `vcs/internal/volumeserver/visibility.go`, `vcs/internal/authorityrpc/volume_handler_linux.go`, `vcs/cmd/portablefs/internal/cli/mountcmd.go`, related policy tests and docs; protocol 6 deletes the macOS 26 compatibility-writer lease rather than leaving a hidden serialization path |
| Terminal-delivery validation | `vcs/internal/authorityrpc/client.go` and tests: replace the retired `GetPostAttr() == nil` assertion with the exact requirement that terminal-receipt responses have `GetPostState() == nil` and no body |
| Contract and release gates | `COMPATIBILITY.md`, architecture/coherence docs, `docs/linux-exact-append-abi.md` supersession marker, `scripts/verify-local.sh`, kernel/source stale-architecture scans, protocol golden tests, packaging policy checks |

Implementation tests MUST cover every legal terminal shape, same-identity
replay with changed segment geometry, changed-body replay fencing, admission
before sequence allocation, concurrent append handles, user-fault short writes,
the deliberate signal-short-write ABI, post-apply sync errors, all touched
object sets, not-newer attr/entry drops, parent i_version and fi attr_version
bumps, admission/peer-repair/reply-write races, READDIRPLUS whole-page
registration, positive and negative capacity drops, stale O_EXCL replay,
multi-token merged scopes, exact-once permit release, uninterruptible DONE
waits, ring wrap/out-of-order DONE, shared-counter corruption, eventfd
coalescing, daemon death at each publication step, reader-pool progress while an
authority stream is stalled, blocking-write staging pressure without EAGAIN,
reconnect replay priority on a saturated handle, and
CACHE_WITHDRAWN/UNSERVABLE with private mapped and pinned pages.
Performance results do not replace these state-machine and crash-point tests.
