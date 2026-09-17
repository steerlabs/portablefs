# Authority protocol 7 wire contract

Workstream A defines the encoding and handshake for the coherence v2 design in
[design.md](design.md). This is an integration contract for streams C and F;
adding these messages does not implement subscription or delegation execution.

Protocol major is exactly `7`; the only TLS ALPN is
`portablefs-authority-v7`. Both peers use mutually authenticated TLS 1.3 and
refuse protocol 6, including a peer that offers only `portablefs-authority-v6`.
A peer that reaches Hello must still name major 7. There is no downgrade.
The protobuf package `portablefs.authority.v1` and Go package `authoritypb`
keep their existing names; neither names the negotiated protocol major.

## Required features

Feature names are exact, case-sensitive strings. Extra advertisements do not
relax a requirement. The following table is the complete required set, grouped
by the common requirements and the additions for each frontend. Activation
requirements travel in `ActivateReply.features`, despite the historical Go
identifier `requiredAttachFeatures`.

| Boundary and audience | Required strings |
|---|---|
| Hello, every profile | `xfs-current-state`, `session-exact-epoch`, `framed-bulk-data-v1`, `authority-keyed-replay-fingerprint-v1`, `mandatory-dual-transport-v1`, `exact-resource-acquisition` |
| Hello, Linux additions | `direct-write`, `volume-subscription-v1`, `ordered-change-stream-v1`, `file-write-delegation-v1` |
| Hello, cacheless reader additions | `cacheless-peer-reader-v1` |
| Hello, FSKit additions | `fskit-sync-repair-v1`, `fskit-source-publication-v1`, `fskit-fragmented-write-v1` |
| Activate, every profile | `no-history`, `no-branches`, `user-xattr-readonly`, `single-principal`, `stable-item-identity`, `volume-syncfs-barrier`, `exact-resource-acquisition` |
| Activate, Linux additions | `direct-io-no-file-mmap`, `distributed-posix-locks`, `delegation-control-v1`, `session-durable-sequence-v1`, `root-directory-barrier-v1`, `bounded-control-replay-v1` |
| Activate, cacheless reader additions | `cacheless-peer-reader-v1` |
| Activate, FSKit additions | `write-through`, `fskit-sync-repair-v1`, `fskit-source-publication-v1`, `fskit-fragmented-write-v1`, `peer-complete-fifo-feedback` |

`volume-subscription-v1` includes cold subscription, pagination, renewal,
incarnation fencing, and the 10-second horizon. `ordered-change-stream-v1`
includes the CONTROL delivery cursor, bounded batches, and cumulative proven
withdrawal acks. `file-write-delegation-v1` includes CREATE/OPEN piggyback,
cache-capable handle accounting, full and writethrough modes, and generation
checks on every delegated flush. `delegation-control-v1` requires recall,
break, mode changes, their acks, and batch release. `session-durable-sequence-v1` and `root-directory-barrier-v1` require session
application/durability tickets and the root FSYNCDIR barrier. Optional
`batched-close-v1` advertises the bounded DATA close operation below.

Linux no longer requires or advertises `lease-coherence-v1`,
`directory-enumeration-lease-v1`, `lease-renewal-v1`, `lease-recall-v1`,
`open-by-identity-v1`, or `write-through`. `volume-syncfs-barrier` continues to
name the existing authority RPC; it does not assert that Linux delivers
FUSE_SYNCFS. `direct-io-no-file-mmap` keeps its existing scope: direct-IO
handles do not promise mmap; cacheable read handles retain private/read-only
mapping support. No shared writable mapping is admitted.

The frozen enum spelling `FRONTEND_PROFILE_LINUX_LEASES = 1` remains the Linux
frontend identifier. Major 7 determines its subscription/delegation contract;
it is not a switch to a v6 execution path. FSKit retains its explicit repair
profile and the design's compatibility writer exclusion for every Mac mount.
`FRONTEND_PROFILE_CACHELESS_READER = 3` is an authenticated peer reader. Attach
requires exactly read access. The profile admits lifecycle operations, LOOKUP,
GETATTR, read-only OPEN/CLOSE, READ, READDIR and RECLAIM. It admits no mutation,
cache-capable handle, subscription, delegation or FSKit repair operation. Each
data-consuming operation uses BreakForRead before storage admission and binding
revalidation. It neither recalls the Linux writer nor joins the Mac writer
exclusion; no writer waits for a cacheless reader's acknowledgment. The files
gateway uses this profile. Its transport loss leaves no cache withdrawal duty.

Optional session and enrollment reauthorization feature names are unchanged.

## Framing, envelopes, and counter domains

The existing frame header carries big-endian 32-bit metadata and bulk lengths.
Only the existing READ/WRITE/FSKit carriers use out-of-line bulk; none of the
new control messages does. Unknown fields, duplicate singular fields, multiple
oneof alternatives, incorrect wire types, and allocation amplification remain
invalid. The canonical replay representation emits fields by ascending tag,
repeated values in their declared order, and explicit optional/message presence.
It rejects unknown fields, maps, and fixed-width fields. No new message uses a
map or fixed-width field. The write-data digest substitution is unchanged.
Changing delegation id or generation changes a mutation's replay fingerprint.

Repeated collections have at most 4,096 elements, except `CloseBatchRequest`
and replies, whose limit is 128. Every collection must also fit the
negotiated frame byte bound; senders split batches/pages earlier when needed.
Identities are exactly 16 bytes and nonzero. Delegation ids and snapshot ids
are opaque 16-byte nonzero values. Raw names contain 1–255 bytes, no NUL or
slash, and cannot be `.` or `..`. Unspecified enum values are invalid in live
operations. These semantic checks belong to the coordinator/handler; the
frame decoder enforces the structural protobuf grammar.

The ordinary `Request` envelope retains `request_id`, `epoch`, `session`, and
`mutation`. CONTROL requests below require the active session proof and epoch,
but no mutation replay slot. DATA mutations and Barrier use the existing
session-exact mutation replay header. A response echoes the request id and
epoch; nonzero `errno` means the operation did not provide the successful
contract below. Existing uncertainty and failure classification still apply.

### Directory-page capability reuse and reclaim

`ReadDirRequest.want_items` remains tag 5. The additive
`held_identities` field (tag 6) is a sorted, unique list of nonzero 16-byte
stable identities that the session already retains for the page beginning at
the request cookie. It is a page-local optimization hint, never authority.
It is legal only with `want_items`, contains at most 4,096 identities, and
irrelevant identities have no effect. A cold page or an unknown cached page
sends an empty list.

Every resolvable `Dirent` carries `stable_identity` at tag 7 together with its
attributes, object version, and snapshot sequence. When `want_items` is true,
the Authority returns a fresh `Item` unless that exact stable identity appears
in `held_identities`; for a held identity it omits `Item`. The client may use
the identity only to find its already-retained capability. It must fail closed
if that binding is absent or mismatched. The Authority still resolves and
revalidates every entry under the page's storage cut and never turns the hint
into access authority.

`ReclaimRequest.item` remains the legacy singular tag 1. The additive `items`
field at tag 2 carries 1–4,096 distinct item capabilities. Exactly one form is
nonempty. The complete shape and every session capability are validated before
retirement begins, and one mutation replay slot owns the whole ordered batch.
The client batches lazily at its cleanup watermark or timer and never combines
tokens from different Authority epochs. A negotiated frame bound may require a
smaller batch.

| Counter | Scope and meaning |
|---|---|
| `volume_version`, subscription `watermark` | Authority volume version within an epoch. Comparable with served reply versions, never with a client or replay-slot sequence. Delegation changes may share the current storage version; stream position orders every entry, including equal-version entries. |
| `incarnation` | Nonzero session subscription generation, incremented for each cold subscribe; pagination and renewal preserve it. A stale incarnation cannot acknowledge or renew the current subscription. |
| `ControlEvent.sequence` | Contiguous per-incarnation delivery cursor starting at 1; covers both batches and delegation events. Receipt alone advances the next poll. |
| `ChangeEntry.position` | Contiguous per-incarnation change cursor starting at 1, across all batches. Only ChangeAck advances the withdrawn prefix. Delegation control events do not consume change positions. |
| Application sequence | Authority-issued per-session, epoch-scoped ticket for an applied data/attribute mutation; starts at 1 and advances monotonically. A ticket describes storage application, never local acceptance or a replay slot. Replayed outcomes return the original ticket. |
| `durable_sequence` | Largest contiguous application-ticket prefix whose effects are durable. Zero means no proven prefix. It must never skip an undurable ticket or exceed the applied prefix. |
| Local accepted sequence | Client buffer order; never sent as an authority application ticket. The client maps accepted entries, including coalesced entries, to the tickets returned by their flushes. |

Counters must not wrap or reuse values within their scope; retire that scope
before exhaustion.

`Response.applied_sequence` (tag 56) carries the ticket for successful changed
WRITE, SETATTR, and FALLOCATE results. Other operations leave it zero. The
handler retains this ticket with the replay outcome. A rejected flush gets no
ticket; a partially applied result must describe its actual applied effects
and cannot retire a rejected suffix as durable.

`Response.volume_version` (67) names the version at which any cache-installing
reply was served, including a negative LOOKUP and empty READDIR. The new
`ReadReply.volume_version` (2) must equal the envelope value. Existing
object/snapshot version fields keep their meanings. The client also drains
in-flight cache-installing replies before acknowledging a withdrawal and
tracks the local publication generation: a version comparison alone cannot
reject an equal-version reply that predates delegation withdrawal.

## Subscription and delivery messages

| Message; request/response oneof tag | Fields and meaning |
|---|---|
| `SubscribeRequest`; request 65 | `snapshot_id` (1): empty starts a cold subscription after the client has invalidated all state. Nonempty resumes pagination only. `after_identity` (2): empty on the initial request, otherwise exactly the preceding reply's `next_after_identity`. |
| `SubscribeReply`; response 57 | `watermark` (1): atomic snapshot volume version. `delegated_identities` (2): sorted unique identities excluded by a reservation or live delegation at that snapshot, in bytewise order across pages. `incarnation` (3): new nonzero incarnation. `horizon_nanos` (4): conservative validity duration, at most 10,000,000,000 ns, anchored at the initial request's monotonic start. `snapshot_id` (5): token binding every page to this snapshot/session/incarnation. `next_after_identity` (6): final identity on a nonfinal page; empty marks completion. |
| `RenewSubscriptionRequest`; request 66 | `incarnation` (1): exact current subscription. |
| `RenewSubscriptionReply`; response 58 | `incarnation` (1): exact echo. `horizon_nanos` (2): conservative duration, at most 10 seconds, anchored at renewal request start. |
| `NextControlEventRequest`; request 67 | `incarnation` (1): exact subscription. `after_sequence` (2): last received CONTROL event sequence, initially zero. `completed_event_through` (3): contiguous prefix whose ACK retries are surrendered. Long-polls for the delivered cursor's successor. |
| `ControlEvent`; response 59 | `incarnation` (1), `sequence` (2), and exactly one of `change_batch` (3), `delegation_recall` (4), `delegation_break` (5), `delegation_mode_change` (6). The outer request id matches the poll; events are never unsolicited response frames. |
| `ChangeBatch`; ControlEvent 3 | `incarnation` (1): equals the event envelope. `entries` (2): nonempty ordered list of `ChangeEntry`, contiguous with the preceding batch. |
| `ChangeAck`; request 68 | `position` (1): greatest fully withdrawn change prefix; zero acknowledges nothing. `incarnation` (2): exact current subscription. |
| `ChangeAckReply`; response 60 | Empty success receipt. |

The snapshot includes reserved, granted, and recalling identities so a subscriber
arriving during reserve/withdraw/grant cannot cache through the transition.
The authority registers the subscriber and freezes the delegated set atomically
at `watermark`, then retains subsequent events. Pagination reads that frozen
set, not a changing delegation table. Every page repeats the same watermark,
incarnation, horizon duration, and snapshot token. It neither starts another
subscription nor extends the horizon. Pages are sequential; repeating a page
request returns the same page. A nonfinal page must contain at least one entry.
Discard the partial snapshot on failure or expiry and subscribe cold again.
Do not cache until the final page arrives; the first cacheable read must be at
or after the watermark. The client may start polling/renewing after the first
page so a large snapshot cannot prevent liveness, but must stage later changes
until it has installed the whole snapshot, then apply them in order.

Renew every 3 seconds, independently of polls and acks. The authority horizon
is its last accepted renewal plus 10 seconds; the client anchors the returned
duration at request start, so transit delay only shortens local permission.
The client must stop serving and finish invalidating caches by its conservative
horizon. A late response cannot revive expired permission. The authority fences
all ordinary requests at expiry; only cold subscription and required transport/
session recovery plumbing may establish a usable incarnation again. Renewal
cannot revive an expired incarnation.

Only one poll may be outstanding per incarnation. Retrying the same poll cursor returns
the same event until a subsequent cursor proves receipt. Receipt is independent of
ChangeAck and delegation acknowledgments. Retain adapter ACK replay records until
`completed_event_through` explicitly surrenders retries. This receipt is distinct from
delivery and is not a cut acknowledgment: failed handlers may surrender replay while
coordinator deadlines still govern their unfinished cuts. The client advances the
receipt only across a contiguous prefix of finished handlers. Completed records at or
below the receipt are deleted; current grant tracking is deleted at recall or release. A
poll can deliver a recall while an earlier ChangeBatch is still being withdrawn; this
separation prevents an ack/flush dependency from stopping delivery of the event that can
resolve it. C and F must reserve independent CONTROL execution capacity for renewal and
acknowledgments while the poll is parked.

Release operations share one serialized acknowledgment lane, held across reconnect and
exact retry. A new release carries sequence H+1 and completion H, where H is the last
accepted sequence. The Authority retains only the latest exact request fingerprint and
result, including definite errors. An exact retry repeats both coordinates. A malformed final response ends the client session. An uncertain final response fences
the subscription incarnation: no further release, renewal, or poll may use that incarnation.
The client withdraws its caches before a cold subscription creates a new release replay
domain; it cannot acknowledge or surrender the uncertain result in the old domain. Invalid local request shapes consume no sequence. Linux attach requires
`bounded-control-replay-v1` so clients cannot silently omit these coordinates.

Application tickets retain monotonic applied/durable counters and only the
volume-version suffix above the session's durable prefix. Volume sync retires covered
records for every session, including idle sessions. Exact delegation ACK validation uses
the active cut's floor and tickets issued while that cut is pending, independent of
retired durability history.

## Change entries and withdrawal

`ChangeEntry` fields are `position` (1), `volume_version` (2), `kind` (3),
`identity` (4), `parent_identity` (5), raw `name` (6), and optional message
`byte_range` (7). `ByteRange` contains unsigned `offset` (1) and positive
`length` (2); it describes `[offset, offset + length)` without overflow. Its
absence means the entire file. Offset zero has its ordinary meaning and does
not erase message presence.

| `ChangeKind` numeric value | Required coordinates and effect |
|---|---|
| `NAMESPACE_CHANGED = 1` | `parent_identity` and `name` identify an added, removed, or replaced binding. `identity` is empty; use separate identity entries for affected objects. Withdraw both positive and negative binding state. |
| `ATTRIBUTES_CHANGED = 2` | `identity`; withdraw cached attributes. |
| `DATA_CHANGED = 3` | `identity`, optional `byte_range`; withdraw cached data for the range or whole file. Size changes also emit attributes changes. |
| `DELEGATION_GRANTED = 4` | `identity`; withdraw all peer caching permission before the grant activates, including data and attributes. This is a reservation notice, not permission for its recipient to write. |
| `DELEGATION_RELEASED = 5` | `identity`; remove that identity from the delegated exclusion set. This permits fresh cache fills; it never restores old cached bytes. |
| `DIRECTORY_CHANGED = 6` | `identity` of a directory; withdraw its listing cache. |

Enum names carry the `CHANGE_KIND_` prefix in the generated API. All unused
coordinates must be empty, and `byte_range` is legal only for DATA_CHANGED.
Namespace operations emit all affected bindings/directories and object changes;
a rename may therefore produce several entries at the same volume version.

ChangeAck(N, I) means **every change through position N in incarnation I has finished
local withdrawal**. Inode notification has returned for affected kernel data and
attributes, and pending cache-installing replies on those coordinates have drained or
been discarded. Authority-backed shared names always have zero kernel entry validity.
Their withdrawal closes the coordinate, revokes or drains old replies, and purges daemon
positive/negative bindings and stamps; no entry notification is required. The next
forward lookup must re-enter FUSE. Retained kernel dentry objects used by reverse
`d_path` remain outside the contract; machine-local graft names are separate. A client
can process disjoint entries concurrently, but cannot acknowledge past a hole. An
identical or older ack is an idempotent no-op within that incarnation; a
future/undelivered position is invalid. An old incarnation is refused, never translated
to a current cursor. Transient notify failure gets a bounded retry, not a premature ack.

An operation/grant awaiting withdrawal from a subscriber waits for that
subscriber's ack through the relevant position or its horizon. Change entries
have no PREPARE/COMPLETE handshake. A committed namespace operation completes
externally after its required deliveries/withdrawals. A delegation reservation
becomes a grant only after peers' DELEGATION_GRANTED withdrawals finish. The
initiating session handles its own publication boundary locally. Its source
commits advance the coordinator cursor internally and produce no CONTROL event
or ChangeAck. Delegation grant/release bookkeeping is likewise implicit for the
exact owning subscription incarnation; a cold incarnation still receives a
delayed old-generation release retained by its snapshot. An intervening peer
change prevents implicit acknowledgement across that outstanding withdrawal.
Its committed changes are omitted from its wire change stream: a reverse
notification can otherwise wait on the initiating syscall's VFS locks and
block acknowledgments needed by a concurrent peer mutation. Skipped internal
positions do not create holes in the session's wire change positions.

## Delegations and flushes

`Delegation` contains opaque `id` (1), nonzero `generation` (2), and `mode` (3).
`DelegationRef` contains the same `id` (1) and `generation` (2), without a mode.
The authority binds the id to the authenticated holder session, epoch, and
identity. An id never replaces a handle or item capability. Mode values are
`DELEGATION_MODE_FULL = 1` and `DELEGATION_MODE_WRITETHROUGH = 2`; zero is invalid.
Subscription expiry retires its delegations as well as cache permission; a cold
resubscription never revives an old reference. A mode transition preserves generation; retiring/reassigning ownership must
invalidate the old reference even if the same session later reacquires it.

| Existing message | Additions and semantics |
|---|---|
| `CreateRequest` | `write_intent` (6) requests a delegation; it requires `flags.write`. `cache_capable` (7) requests kernel caching for the returned handle. |
| `CreateReply` | `delegation` (3), absent if no grant; `cache_capable` (4) is the admitted capability for this handle. `item` and `handle` retain tags 1 and 2. |
| `OpenRequest` | `write_intent` (3), `cache_capable` (4), with the same meanings. `item` (1) and `flags` (2) are unchanged. |
| `OpenReply` | `delegation` (2), `cache_capable` (3); `handle` remains 1. Identity comes from the opened item. |
| `WriteRequest` | `delegation` (13), a DelegationRef required on each buffered flush. Optional `flush_sequence` (14) orders pipelined chunks as specified below. Payload stays out of line. |
| `SetAttrRequest` | `delegation` (11), required when flushing buffered attributes or truncate. Optional size/mode/time presence remains unchanged. |
| `FallocateRequest` | `delegation` (8), required when operating under a delegation. Reserved tags stay reserved. |
| `WriteReply` | `durable_sequence` (8), the session's contiguous durable application prefix. The common response carries this operation's applied ticket. |
| `FsyncReply`; response 66 | New body with `durable_sequence` (1). Success still promises durability of the requested file's flushed cut. |
| `SyncFSReply`; response 35 | `durable_sequence` (1), after the existing volume durability operation. It does not stand in for the root FSYNCDIR barrier. |

CREATE reserves ownership before publishing the new binding; CREATE/OPEN return
a grant only after withdrawal. FULL permits daemon buffering. WRITETHROUGH
requires immediate authority application and peer invalidation for each write
while another session retains a pre-existing cache-capable handle. A peer that
opens an already delegated identity gets `cache_capable = false`. Requests
express a preference; only the reply authorizes kernel caching. A write-intent
handle is direct-IO. A separate holder read handle can be cache-capable if the
holder invalidates affected local kernel ranges on every accepted write.

SETATTR mode, uid, gid, timestamps, and size require an item capability or an
open handle owned by the session. A handle alone authorizes the operation even
if the item capability has been reclaimed; when both are present they must name
the same identity. Neither a stable identity nor a DelegationRef substitutes for
these capabilities. Omitting both returns EINVAL before storage application.

An absent DelegationRef is an ordinary synchronous operation, including a
first write that needs authority ownership arbitration. It never authorizes
local buffering. Reacquisition through OPEN with write_intent supplies the new
Delegation to an existing writer; F may close that auxiliary server handle
once it has a grant usable with its original valid handle. The schema does not
pretend an ordinary WriteReply grants a delegation. Reject an invalid or stale
reference before applying any part of its flush. The sender advances its loss
sequence if already accepted data cannot be applied.

Flush requests on disjoint files can pipeline freely within the existing
transport bounds. Requests for one file preserve accepted program order;
independent replay slots do not provide ordering. F must wait for a preceding
same-file request's application acknowledgment before dispatching the next,
unless its dispatcher supplies an equivalent proven ordering. Each flush may
coalesce several accepted entries; all share its resulting application ticket.
Partial writes require accounting for the unapplied suffix. Namespace operations
that name a dirty identity wait for that identity's flush before dispatch.

A successful file fsync or O_SYNC/O_DSYNC write proves durability of that
operation's effects, even when the common durable prefix is held back by an
unrelated file. The buffer can mark those exact entries durable from that
operation-specific proof; it can retire arbitrary entries only through the
reported contiguous prefix. A failed operation makes no new durability claim.
Never advance the prefix merely to the maximum completed fsync ticket.

## Delegation control and release

All events below travel inside ControlEvent, and their acknowledgments travel
as independent CONTROL requests. `budget_nanos` is positive and at most
5,000,000,000 ns. The authority starts its deadline when it issues the event;
the client starts a local budget at receipt, but a late client ack cannot undo
an authority timeout. The generation check remains decisive after a timeout.

| Message | Fields |
|---|---|
| `DelegationRecall` | `delegation` (1), `identity` (2), `budget_nanos` (3). Withdraw this exact grant. |
| `DelegationBreak` | `delegation` (1), `identity` (2), `budget_nanos` (3). Flush an accepted cut for a waiting peer read; retain ownership. |
| `DelegationModeChange` | `delegation` (1), `identity` (2), target `mode` (3), `budget_nanos` (4). |
| `DelegationRecallAck`; request 69 | `incarnation` (1), `event_sequence` (2), `delegation` (3), `applied_sequence` (4). |
| `DelegationBreakAck`; request 70 | Same field names/numbers as `DelegationRecallAck`. |
| `DelegationModeChangeAck`; request 71 | Same field names/numbers as `DelegationRecallAck`. |
| `DelegationRecallAckReply`; response 61 | Empty success receipt. |
| `DelegationBreakAckReply`; response 62 | Empty success receipt. |
| `DelegationModeChangeAckReply`; response 63 | Empty success receipt. |
| `DelegationRelease` | `delegation` (1), `applied_sequence` (2), naming the last flushed identity cut. |
| `DelegationReleaseRequest`; request 73 | `incarnation` (1), nonempty `delegations` (2), sorted by id, each id exactly once, at most 4,096 entries. `release_sequence` (3): contiguous logical operation starting at 1. `completed_release_through` (4): prior result received and no longer retried. |
| `DelegationReleaseReply`; response 65 | Empty all-or-error success receipt; validate the whole batch before releasing any grant. |

Recall is the two-phase ownership transition: authority withdrawal request,
then holder stop-admission/drain/flush acknowledgment before reassignment.
The holder first closes the retiring generation, drains in-flight admissions
and cache-installing replies, flushes the identity cut, then acknowledges with
the greatest application ticket covering that cut (zero if it never changed).
The ack does not assert durability. Arriving writes wait for a new grant;
they cannot enter the retiring generation. A missed deadline drops ownership
and advances the affected holder's loss sequence. There is no second COMPLETE
event for the retired grant.

Break is a flush request/ack exchange without ownership withdrawal. Capture
the identity's accepted cut on receipt, flush it in order, and ack with its
application ticket before the authority answers the waiting peer. Later
admissions may proceed; they cannot overtake the captured flush. A timeout
uses the same fencing/loss handling as a failed recall before the peer proceeds.

For a downgrade to WRITETHROUGH, stop buffered admission, drain and flush the
old mode's cut, install the target mode, then ack. Subsequent writes execute
synchronously. For an upgrade to FULL, install the new mode and ack the latest
applied identity cut. The authority cannot depend on a mode transition before
its ack. Neither mode exchange retires ownership or needs a COMPLETE phase.
Serialize control transitions per identity so recall, break, and mode change
cannot contradict one another. Disjoint identities can progress concurrently.

An ack must match incarnation, event sequence, event type, and grant reference.
It certifies all accepted entries in the event's identity cut were applied;
a ticket from some unrelated mutation is not a substitute. An exact repeated
ack is idempotent; a conflicting ack for an already completed event is invalid.
These acks do not acknowledge ChangeBatch positions. Conversely, ChangeAck
does not discharge a recall, break, or mode change.

Release follows last-handle close and a completed flush of that identity. It
stops admission under every listed reference, but does not discard applied
entries awaiting durability. Exact repeated batches in the same incarnation
are idempotent; changed generations are refused. Retain per-incarnation release
completion records so a retry after removing the live grant remains distinguishable
from a stale-generation request. After release the authority
emits DELEGATION_RELEASED. Unmount/planned restart must still wait for durability.

A release whose exact applied ticket covers the final storage application also
completes any pending recall, break, or mode-change cut for that reference. All
storage pins must have drained. The authority suppresses an undelivered event
for the released reference; an already delivered event is completed by the
release. A later exact acknowledgment of that completed cut is idempotent.

## Root directory barrier

`BarrierRequest` (request body 72) has `cut_sequence` (1).
`BarrierReply` (response body 64) has `applied_sequence` (1) and
`durable_sequence` (2). Both report session application-ticket prefixes;
success requires `applied_sequence >= durable_sequence >= cut_sequence`.
Zero is a valid empty cut and does not bypass the client's loss check.

At OPENDIR of the mount root, record the mount's loss sequence locally on that
handle. At FSYNCDIR, capture all locally accepted entries, flush and obtain
application acknowledgments for that cut, and convert it to the largest
corresponding authority ticket. Send Barrier on DATA with that ticket. The
authority makes the ticket prefix durable; it must reject a cut greater than
its applied prefix rather than park waiting for unsent client data. A reply
may cover later work, but need not wait for entries accepted after the client
cut. The durability operation also covers namespace mutations acknowledged before
this barrier, including when the data cut is zero; implementations can retain
the existing ordered volume syncfs operation for this. A replay returns the
same or an already sufficient retained result.

The client reports EIO if loss advanced since the root handle opened, even if
the authority barrier succeeded. Loss sequence stays local and monotonic
across cold resubscriptions and authority epoch changes. Old server handles
become permanently stale at epoch change. Neither a new subscription nor a
new epoch silently retires non-durable entries. FUSE_SYNCFS is never the
completion trigger; successful syncfs(2) on stock FUSE proves no daemon barrier.

## Refusals

Use the existing response `errno` and `failure` envelope. Malformed coordinates,
unknown enum values, inconsistent flags, an undelivered ack position, an
unissued application ticket, or a conflicting retry receive EINVAL with no
state change. Wrong/expired incarnations and stale delegation references
receive EIO with `FAILURE_CLASS_COHERENCE`; the client invalidates or reports
loss for the affected state, without interpreting it as storage death. A
stale-generation flush fails whole before apply. Ordinary storage errors keep
their existing errno and partial-application reporting. Handler enforcement of
these semantic refusals belongs to C/F; structural frame refusals already
occur before dispatch.

## Integration boundaries and decisions

C owns subscription snapshots, horizons, event retention, withdrawal waits,
delegation arbitration, and exact idempotency validation. F maps those objects
to these generated messages, implements polls and independent ack/renew lanes,
maintains accepted-to-application-ticket accounting, retains replay tickets,
and supplies the served volume versions. Generation checks must precede any
storage mutation. No commit lock may span an ack, recall, horizon, or durability
wait. The authority's existing mutation sequencer orders conflicting work.

The historical v6 lease schema stays for inspection of stored wire history.
`Lease*`, `NextLeaseEventRequest`, `AcknowledgeLeaseEventRequest`, `RenewLeasesRequest`,
SourceLeaseDischarge, AcknowledgeSourceLeaseDischarge, `lease_grants`,
`source_lease_discharge`, and Activate's `lease_cursor` are not sent or honoured
by the completed v7 implementation. F owns deletion of their executable
handler/client paths. Workstream A does not certify those paths as converted.

Decisions made here: paginated atomic subscribe snapshots avoid exceeding the
existing allocation bounds; one response per CONTROL long-poll preserves the
transport's request-id model; separate delivery and withdrawal cursors prevent
head-of-line blocking; authority application tickets avoid assuming that local
accepted sequences or replay-slot sequences are global storage order. The
additional transport-role allowlist entries and their exhaustive tests are
necessary wire plumbing outside PLAN's enumerated A files; no filesystem
handler or client state machine changes accompany them.

## Workstream A verification receipt (2026-09-16)

The following commands passed on this macOS arm64 worktree:

```sh
bash scripts/generate-authority-proto.sh
CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...
CGO_ENABLED=0 GOOS=linux go -C vcs build ./...
go -C vcs vet ./...
go -C vcs test ./internal/authorityrpc/...
go -C vcs test -race ./internal/authorityrpc/...
bash scripts/verify-local.sh
go -C vcs test ./internal/authorityrpc -run '^$' -bench '^BenchmarkChangeBatchEncoding$' -benchtime=100ms -benchmem
```

Generation used protoc 35.1 and protoc-gen-go 1.36.11; repeating generation
produced identical Go bytes. A descriptor comparison with base commit
`3fdc83866cdec3742818295d946d1af945ec90a8` preserved all 445 existing field
definitions, message reservations, and existing top-level enum values.
The default gate passed both builds/vets, vulnerability checking, native Go
and race suites, the go-fuse seam, all 344 enumerated Swift tests, release
policy checks, and architecture scans. Encoding tests cover every new body,
nested fields, frozen tags, unknown/duplicate rejection, collection bounds,
optional range presence, and delegation replay fingerprints. TLS and Hello
tests refuse literal protocol 6; feature tests assert exact sets.

The 256-entry benchmark measured CONTROL frame encoding at 117,926 ns/op,
9,476 B/op, and 1 allocation/op; canonical encoding measured 357,163 ns/op,
163,920 B/op, and 3,340 allocations/op. These are short local observations
on an Apple M5 Max while other verification ran, not a filesystem throughput
claim. CONTROL uses the frame path; canonical response encoding is a separate
measurement of the existing canonical writer.

`bash scripts/verify-local.sh --full` failed in the privileged XFS/FUSE suite:
`TestMutationPostStateEliminatesFollowupMetadataRPCs` observed three GETATTR
RPCs after mknod where its assertion expected zero. An untouched detached
worktree at the base commit above also failed this same test when run with:

```sh
PORTABLEFS_GO_TEST_FLAGS='-run ^TestMutationPostStateEliminatesFollowupMetadataRPCs$' bash scripts/xfs-fuse-integration.sh
```

That baseline run failed earlier at fallocate (one unexpected GETATTR), with
an additional unmount-cleanup failure. This establishes a failing baseline,
not proof that every full-suite failure is unrelated to the wire change.
No frontend behavior or test expectation was altered to obtain a pass.
The full gate remains unpassed and cannot serve as merge evidence.

The separately invoked `bash scripts/coherence-matrix-linux.sh` passed with
22 live cases passing, zero failures, and the declared
`remote_chown_visible` skip (23 total, zero unexpected results). Both
falsifiability controls reached their declared expectations. This exercises
the current frontend paths; it does not prove the new C/F state machines.

## Integration ordering clarifications

A new OPEN/CREATE grant remains reserved until the operation's synchronous
withdrawal completes. Pending peer reads may sample storage under a reservation;
grant activation drains those samples before the DATA reply. CONTROL may then
overtake DATA, so the client still handles that ordering. A synchronous mutation
under an already installed grant returns its application receipt before its
visibility wait, allowing the holder to acknowledge a peer cut independently.

Private synchronous generations exclude their source from grant/release reverse
notifications; its exact publication gate and post-state repair those coordinates.
Promotion to a visible grant restores the ordinary release notification. Normal
client-visible grants remain broadcast to purge the holder's earlier cached pages.

A new Authority process must also account for the preceding epoch's cache
horizon. Durable membership distinguishes Linux v7, cacheless readers, and
compatibility mounts. If any prior Linux v7 mount is recorded, the replacement
waits a full SubscriptionTTL from coordinator creation before granting a writer
delegation or applying a mutation. Cold Subscribe, ordinary reads, and barriers
remain available during that interval. A canceled wait takes no storage or
identity turn. This bound does not establish kernel mount absence: old durable
records still block topology changes and archive proof. Prior compatibility or
untyped legacy membership continues to require explicit fencing evidence.


## Batched descriptor close

Linux Activate optionally advertises `batched-close-v1`; absent advertisement
selects individual CLOSE requests. The required feature set is unchanged. DATA carries
`Request.close_batch` (tag 74) and `Response.close_batch` (tag 68); FSKit and
CACHELESS_READER retain ordinary CLOSE. A request contains 1–128 distinct
16-byte handle capabilities with each handle's lock owner and flock-unlock
flag. The entire shape is validated before any close. The frame grammar bounds
both request and reply lists to 128 before protobuf allocation.

One mutation replay slot owns the complete ordered request and ordered results.
Top-level success carries one result per input, including individual failures;
all entries are attempted. Exact replay returns those outcomes without closing
again. A changed order or handle is a replay mismatch. Callers retry only the
identical whole request in its existing replay domain.

A result carries errno, failure class, and `retired`. Once a session capability
is validated, descriptor close is attempted even if explicit flock cleanup
fails. The store consumes its capability before reporting a final close error;
the Authority removes session accounting and sets `retired` even on that error.
An already-stale session handle is also retired. Other pre-close refusal does
not claim retirement. Clients remove retired handles while preserving the error
for diagnostics. Unknown transport outcomes or malformed replies revoke the mounted session;
terminal session cleanup owns its remaining descriptors. Malformed result count, errno, or failure classification is refused.

Final-handle cleanup first applies each buffered cut and releases the grants in
one CONTROL batch. It does not wait for durability. Applied records cease to
participate in the read overlay after release, but their bytes and loss
obligations remain retained until a durable prefix or fencing loss. No per-file
acquire, transition, or operation lock spans the release or close RPC; a local
release flight orders same-identity admissions through completion.


## Optional ordered delegated flush

Linux peers may negotiate `ordered-delegated-flush-v1`. It is an optional Hello
feature: the client offers it only with four dedicated flush permits and replay
slots plus at least one ordinary slot; the Authority echoes it only when its
ordinary half can reserve those same five slots. DATA and CONTROL must agree,
including replacement transports. Activate must also advertise it. The frozen
required feature sets and protocol major are unchanged. Without negotiation,
clients use the existing serial delegated flush.

With negotiation, all delegated WRITE, SETATTR and FALLOCATE requests share the
four flush permits on both endpoints. Each nonzero WRITE `flush_sequence` is a
dense ordinal starting at one for the exact delegation ID and generation. At
most four successors may be registered. The replay runtime resolves duplicates
before registering an ordinal. A successor waits before acquiring storage or
mutation dependencies; its predecessor releases it only after recording its
exact replay outcome. Definite recorded errors consume their ordinal. An
unrecorded refusal retires the authenticated owner's exact grant and wakes
successors; it cannot leave an unfillable gap. Subscription loss, recall expiry,
and runtime transport cancellation also terminate waiting ordinals. Ordinal zero
retains the existing serial behavior; metadata flushes separate WRITE waves.

The daemon admits each predecessor to its transport lane before launching the
next chunk. It joins the wave before changing local ownership. Transport retries
retain the same mutation identity, ordinal and immutable scatter spans; an
unprovable wave result loses the delegation, while definite capacity errors keep
the grant and report the errno. A partial acceptance record remains retained and
is excluded from the applied acceptance cut until its final chunk succeeds.
Scatter spans use the existing single bulk carrier and canonical frame bytes;
there is no new bulk encoding or payload-copy requirement.

`Response.session_terminal` (69) is an additive terminal-session witness. It is
true only with envelope ESTALE when this exact Authority session expired or was
fenced. The client starts local session enforcement before delivering that
response, even if the transport remains connected. Ordinary stale item/handle
ESTALE omits the field and remains nonterminal. Epoch mismatch retains the
existing exact-epoch comparison; this field does not change its recovery path.
