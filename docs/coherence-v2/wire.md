# Authority wire contract

This is the normative encoding and handshake of authority protocol 8. The
schema source is `proto/authority/v1/authority.proto`, generated into the Go
package `authoritypb`; the descriptor manifest
`vcs/internal/authoritypb/testdata/protocol8-schema.json` pins the exact current
grammar and the Go suite checks the generated code against it. Compatibility
rules are in [COMPATIBILITY.md](../../COMPATIBILITY.md); the Linux coherence
algorithm is in [portable-coherence.md](../portable-coherence.md).

Protocol major is exactly `8`; the only TLS ALPN is `portablefs-authority-v8`.
Both peers use mutually authenticated TLS 1.3. The server rejects an unequal
major at transport ingress, before handler dispatch, and the client rejects an
unequal HelloReply. There is no downgrade and no plaintext mode. The protobuf
package `portablefs.authority.v1` and Go package `authoritypb` keep their names;
neither names the protocol major.

There are no feature strings. The major and the frontend profile fix the
grammar and semantics. Unknown fields, unknown bodies, unknown enum values,
duplicate singular fields, and multiple oneof members are invalid, so any
grammar or semantic change is a new exact major and ALPN.

## Handshake and sessions

A session owns exactly one DATA and one CONTROL TLS connection, joined by a
32-byte random `connection_set_id`. Each connection sends Hello with
`protocol_major`, its `role`, the set identity, and the session's
`frontend_profile`; HelloReply echoes role, set, and profile and states
`max_frame_bytes`, `max_read_bytes`, `max_write_bytes`, and `max_in_flight` for
that connection.

Execution capacity is partitioned by role and profile. For the Linux profile
both roles must advertise `max_in_flight >= 9`: DATA reserves
`blocking = max / 2` and a dedicated ordered-flush lane of 4, leaving
`ordinary = max - blocking - 4`; CONTROL keeps `ordinary = max - max / 2` and
`blocking = max / 2` with no flush lane, so at 9 it retains five ordinary slots
for delegation acknowledgments, change acknowledgments, and liveness. FSKit and
cacheless sessions split ordinary and blocking halves with no flush lane and
need at least 2. A smaller advertisement is refused at Hello, before the
connection can register. Replay slots and retained-byte budgets must cover the
same partition.

`AttachRequest` names the volume, the signed access token, the replay slot
count, the 32-byte `routes_revision`, a 32-byte random `attach_attempt_id`, the
`purpose`, and the profile. Attach is provisional: `AttachReply` carries the
session identity, generation, resume secret, a provisional deadline, and the two
binding generations. A provisional credential cannot execute filesystem
operations. `ActivateRequest` names the attempt and both binding generations;
activation succeeds only after both role bindings are proven and returns the
opaque root Item, the session lease in milliseconds, the admitted routes
revision, the installed authorization deadline, the session state, purpose, and
profile. `AbortAttach` releases one exact provisional attempt and is invalid
after activation. `Resume` rebinds a role connection to an existing session.

`SESSION_PURPOSE_MOUNT` sessions enter durable mount membership.
`SESSION_PURPOSE_ROUTE_ADMIN` sessions are capability-authenticated control
sessions for `ApplyRoutes`; they receive no root capability, subscription, or
membership, and only they may use `FRONTEND_PROFILE_UNSPECIFIED`.

`Reauthorize` replaces the signed access decision of the exact live session; it
is bound to the session ID, the TLS peer SPKI, and a monotonic sequence. An
identical retry is idempotent; a gap, changed token, or broader access fences
the session. `KeepAlive` renews the session lease. `Detach` carries a
`MountAbsenceProof`: the authenticated supervisor's description of its own
observation that its exact kernel mount is gone. The authority checks that the
observation belongs to this mount and postdates any obligation it discharges;
it cannot re-derive a remote kernel's mount table. A frontend that cannot
establish absence sends nothing and lets its session die fenced.

## Frontend profiles

| Profile | Admitted operations and obligations |
|---|---|
| `FRONTEND_PROFILE_LINUX` (1) | All filesystem operations, both CLOSE and CLOSE_BATCH, file locks, FSYNC/FLUSH/SYNCFS, Barrier and WaitVisibility on DATA; Subscribe, RenewSubscription, NextControlEvent, ChangeAck, delegation acknowledgments, DelegationRelease on CONTROL. |
| `FRONTEND_PROFILE_FSKIT_EXCLUSIVE` (2) | Lookup, GetAttr, ReadDir, Open, Read, positioned direct Write, Create, Mkdir, Symlink, Readlink, Link, Unlink, Rename, SetAttr, xattr get/list/remove, StatFS, CLOSE_BATCH, Reclaim, KeepAlive with a cache proof. No individual CLOSE, subscription, delegation, or lock operation. Holds writer exclusion. |
| `FRONTEND_PROFILE_CACHELESS_READER` (3) | Lifecycle operations, Lookup, GetAttr, read-only Open, individual CLOSE, Read, ReadDir, Reclaim. Exactly read access; no mutation, cache-capable handle, subscription, delegation, or CLOSE_BATCH. |

The profile is pinned into the canonical session fingerprint and cannot change
on replay or resume. A Linux session cannot invoke FSKit-only behavior and an
FSKit session cannot invoke subscription or delegation control. Each
data-consuming cacheless operation breaks delegated data for read before
storage admission and binding revalidation. A cacheless reader neither recalls
the Linux writer nor joins Mac writer exclusion, no writer waits for its
acknowledgment, and its transport loss leaves no withdrawal duty. The files
gateway uses it.

## Framing, envelopes, and counter domains

The frame header carries big-endian 32-bit metadata and bulk lengths. Only READ
and WRITE use out-of-line bulk; no control message does. Unknown fields,
duplicate singular fields, multiple oneof alternatives, incorrect wire types,
and allocation amplification are invalid. The canonical replay representation
emits fields by ascending tag with minimal varints, repeated values in their
declared order, and explicit optional/message presence. It rejects unknown
fields, maps, and fixed-width fields; no message uses either. The keyed replay
fingerprint substitutes a digest for WRITE payload bytes. Changing delegation
id or generation changes a mutation's replay fingerprint. Outgoing frames are
validated against this grammar before any byte is written.

Repeated collections have at most 4,096 elements, except `CloseBatchRequest`
and replies, whose limit is 128. Every collection must also fit the
negotiated frame byte bound; senders split batches/pages earlier when needed.
Identities are exactly 16 bytes and nonzero. Delegation ids and snapshot ids
are opaque 16-byte nonzero values. Raw names contain 1–255 bytes, no NUL or
slash, and cannot be `.` or `..`. Unspecified enum values are invalid in live
operations. These semantic checks belong to the coordinator/handler; the
frame decoder enforces the structural protobuf grammar.

The `Request` envelope carries `request_id`, `epoch`, `session`, and
`mutation`. CONTROL requests below require the active session proof and epoch,
but no mutation replay slot. DATA mutations and Barrier use the session-exact
mutation replay header: a client-owned slot and sequence. A response echoes the
request id and epoch; nonzero `errno` means the operation did not provide the
successful contract. `uncertain` means the operation may have reached XFS and is
never retried automatically; `failure` separates STORAGE, INTERNAL, COHERENCE,
ROUTES, and RESTORE where one errno has two meanings.

### Directory-page capability reuse and reclaim

`ReadDirRequest.want_items` is tag 5. The
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

`ReclaimRequest.items` (tag 2) carries 1–4,096 distinct item capabilities;
there is no singular form. The complete shape and every session capability are validated before
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

## Object versions, post-state, and MKDIR

Every Item, GetAttr reply, Dirent, and mutation post-state object carries an
object version `v` sampled at a committed storage sequence `s`, with
`0 < v <= s`; a negative Lookup carries `negative_snapshot_sequence > 0`. Both
are in the authority's committed storage-sequence domain, scoped to one epoch
and stable identity. Samples in increasing snapshot order have nondecreasing
versions; every logical change gets a newer commit sequence and a version
strictly greater than earlier samples of that identity; equal versions of one
identity agree on logical attributes. Versions may advance without a logical
change: the authority keeps a bounded version map and raises a floor when it
fills, so unchanged identities can report a higher version. Neither side infers
a changed identity, namespace effect, permission change, or durable outcome
from numerical equality with the snapshot. `Attr.blocks` and restore-mode ctime
remain observational; restore hydration preserves logical mtime. Exact replay
returns the original stamps.

A successful mutation carries `Response.post_state`: the complete versioned
attributes of every affected object with its roles, the snapshot sequence, and
the visibility sequence. Clients apply it instead of issuing follow-up reads.

A successful MKDIR returns `Response.mkdir` (tag 73), a `MkdirReply` with the
owning `item` and `child_search_permitted`. The bit is the kernel's
effective-credential search check on the new directory's identity, evaluated
at the same committed cut as the Item and post-state, while the new directory
is still unexposed. `false` is an evaluated denial and canonical omission, not
an absent observation; the mkdir itself succeeded. Replay returns the original
bit without resampling. A successful MKDIR never uses `LookupReply`; Lookup and
Symlink do.

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
is at most its last accepted renewal plus 10 seconds. An outstanding relevant
change caps renewal at its issue time plus 10 seconds, without shortening any
horizon already issued. The earliest unacknowledged relevant change supplies
that cap; source-owned and unrelated targeted changes do not. Writers wait for
the actual issued horizon, a complete withdrawal ack, or a cold reset, never
an independent timeout that could precede promised permission. The client
anchors the returned duration at request start, so transit delay only shortens
local permission.
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
resolve it. Both ends reserve independent CONTROL execution capacity for renewal and
acknowledgments while the poll is parked.

Release operations share one serialized acknowledgment lane, held across reconnect and
exact retry. A new release carries sequence H+1 and completion H, where H is the last
accepted sequence. The Authority retains only the latest exact request fingerprint and
result, including definite errors. An exact retry repeats both coordinates. A malformed final response ends the client session. An uncertain final response fences
the subscription incarnation: no further release, renewal, or poll may use that incarnation.
The client withdraws its caches before a cold subscription creates a new release replay
domain; it cannot acknowledge or surrender the uncertain result in the old domain. Invalid local request shapes consume no sequence. The Linux profile requires
these coordinates; omitting them is invalid.

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
have no separate completion handshake. A committed namespace operation completes
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

| Message | Coherence fields and semantics |
|---|---|
| `CreateRequest` | `write_intent` (6) requests a delegation; it requires `flags.write`. `cache_capable` (7) requests kernel caching for the returned handle. |
| `CreateReply` | `delegation` (3), absent if no grant; `cache_capable` (4) is the admitted capability for this handle. `item` and `handle` retain tags 1 and 2. |
| `OpenRequest` | `write_intent` (3), `cache_capable` (4), with the same meanings. `item` (1) and `flags` (2) are unchanged. |
| `OpenReply` | `delegation` (2), `cache_capable` (3); `handle` remains 1. Identity comes from the opened item. |
| `WriteRequest` | `delegation` (13), a DelegationRef required on each buffered flush. Optional `flush_sequence` (14) orders pipelined chunks as specified below. Payload stays out of line. |
| `SetAttrRequest` | `delegation` (11), required when flushing buffered attributes or truncate. Optional size/mode/time presence remains unchanged. |
| `FallocateRequest` | `delegation` (8), required when operating under a delegation. |
| `WriteReply` | `durable_sequence` (8), the session's contiguous durable application prefix. The common response carries this operation's applied ticket. |
| `FsyncReply`; response 66 | `durable_sequence` (1). Success promises durability of the requested file's flushed cut. |
| `SyncFSReply`; response 35 | `durable_sequence` (1), after the volume durability operation. It does not stand in for the root FSYNCDIR barrier. |

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
Delegation to an existing writer; the client may close that auxiliary server handle
once it has a grant usable with its original valid handle. The schema does not
pretend an ordinary WriteReply grants a delegation. Reject an invalid or stale
reference before applying any part of its flush. The sender advances its loss
sequence if already accepted data cannot be applied.

Flush requests on disjoint files can pipeline freely within the
transport bounds. Requests for one file preserve accepted program order;
independent replay slots do not provide ordering. The client must wait for a preceding
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

## Ordered delegated flush

Ordered flush is part of the Linux profile, not an option. All delegated WRITE,
SETATTR, and FALLOCATE requests share four dedicated flush permits on both
endpoints. Each delegated WRITE carries a nonzero `flush_sequence`, a dense
ordinal starting at one for the exact delegation ID and generation; at most four
successors may be registered. The replay runtime resolves duplicates before
registering an ordinal. A successor waits before acquiring storage or mutation
dependencies, and its predecessor releases it only after recording its exact
replay outcome. Definite recorded errors consume their ordinal. An unrecorded
refusal retires the authenticated owner's exact grant and wakes successors; it
cannot leave an unfillable gap. Subscription loss, recall expiry, and transport
cancellation also terminate waiting ordinals. Metadata flushes separate WRITE
waves.

The client admits each predecessor to its transport lane before launching the
next chunk and joins the wave before changing local ownership. Transport
retries keep the same mutation identity, ordinal, and immutable scatter spans;
an unprovable wave result loses the delegation, while definite capacity errors
keep the grant and report the errno. A partial acceptance record stays retained
and outside the applied acceptance cut until its final chunk succeeds. Scatter
spans use the single bulk carrier and canonical frame bytes.

While a Mac activation holds exclusive profile admission, exact-generation
recall flushes still drain, so activation cannot deadlock behind the recall it
issued.

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
and advances the affected holder's loss sequence. There is no second completion
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
its ack. Neither mode exchange retires ownership or needs a completion phase.
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
this barrier, including when the data cut is zero; the authority uses its
ordered volume syncfs operation, with the shared-cell error and latency scope
stated in COMPATIBILITY.md. A replay returns the
same or an already sufficient retained result.

The client reports EIO if loss advanced since the root handle opened, even if
the authority barrier succeeded. Loss sequence stays local and monotonic
across cold resubscriptions and authority epoch changes. Old server handles
become permanently stale at epoch change. Neither a new subscription nor a
new epoch silently retires non-durable entries. FUSE_SYNCFS is never the
completion trigger; successful syncfs(2) on stock FUSE proves no daemon barrier.

## Batched descriptor close

`Request.close_batch` (tag 74) and `Response.close_batch` (tag 68) travel on
DATA for Linux and FSKit sessions; Linux may also use individual CLOSE, and
FSKit uses only the batch. Cacheless readers use individual CLOSE only. A
request contains 1–128 distinct 16-byte handle capabilities, each with its lock
owner and flock-unlock flag. The whole shape is validated before any close, and
the frame grammar bounds both lists to 128 before allocation.

One mutation replay slot owns the complete ordered request and ordered results.
Top-level success carries one result per input, including individual failures;
every entry is attempted. Exact replay returns those outcomes without closing
again; a changed order or handle is a replay mismatch.

A result carries errno, failure class, and `retired`. Once a session capability
is validated, descriptor close is attempted even if explicit flock cleanup
fails. The store consumes its capability before reporting a final close error;
the authority removes session accounting and sets `retired` even then. An
already-stale session handle is also retired. Other pre-close refusal does not
claim retirement. Clients remove retired handles while preserving the error for
diagnostics. Unknown transport outcomes or malformed replies revoke the mounted
session; terminal session cleanup owns its remaining descriptors.

Linux final-handle cleanup first applies each buffered cut and releases the
grants in one CONTROL batch; it does not wait for durability. Applied records
leave the read overlay after release, but their bytes and loss obligations stay
retained until a durable prefix or fencing loss. No per-file lock spans the
release or close RPC.

## FSKit exclusive-writer profile

**Writes.** FSKit sessions use the ordinary `Request.write` body (tag 55) for
one positioned write of an out-of-line payload no larger than the negotiated
maximum, with the ordinary replay fingerprint, short-write, and post-apply
carriers. `append`, `sync`, `data_sync`, `delegation`, `flush_sequence`,
`lock_owner`, and the lock-owner write flag must be unset; the authority
refuses them with EINVAL before admission. FSKit sessions receive no
application ticket or durable sequence.

**Durability.** Every successful FSKit mutation reply certifies authority-storage
durability before the reply is sent or retained for replay. Every mutation that
applied or may have applied waits for its selected storage barrier, even if its
eventual reply fails. A mutation with a retained syncable description (WRITE,
CREATE, truncating OPEN, handle-backed SETATTR) full-fsyncs that description.
A handleless mutation (namespace operations, item-backed metadata) uses syncfs
on the volume's retained root description. The barrier is chosen from the
operation; there is no post-apply reopen and no alternate barrier after an
acquisition failure, and failure to retain a required handle after apply is
terminal. Any persistence syscall failure is an uncertain EIO with
`FAILURE_CLASS_STORAGE` and fences the epoch before waiters are released; the
first failure survives an apparently successful later syscall. Linux withdrawal
may precede durability; a successful reply may not. Cancellation after apply
does not abandon the barrier.

**Frontend publication and teardown.** No FSKit callback publishing data,
metadata, namespace, or durability reports success after the session is
terminal. Resource loading, volume activation, mounting, and synchronize remain
serving callbacks. Their final synchronous reply and session termination share
one publication gate: a reply that wins precedes termination; termination that
wins rejects publication with the first terminal cause. Earlier definite
request refusals remain failures.

Volume deactivation and resource unloading acknowledge completed local cleanup
only, even after terminal failure. Genuine request or local cleanup errors
remain errors; repeated completed teardown is idempotent, and overlapping
callers wait for the cleanup they acknowledge. Unmount's void completion has
no error or errno and acknowledges the same local boundary. None certifies
durability, replaces the first terminal cause, revives the session, proves
kernel absence or authority acceptance of absence, or certifies daemon/CLI
reconciliation. This exception does not change close, reclaim, release,
cancellation, or other publication and resource-settlement rules.

Mutation durability above is unchanged. Synchronize waits for the authority
barrier over its captured applied cut and then Statfs, propagates their errors,
and still passes the final serving gate. It cannot cover undelivered kernel
pages or mutations outside the cut; native fsync/F_FULLFSYNC waiting, dirty-page
drain, and error propagation remain qualification boundaries. Closing a session
cannot retract kernel cache already published. Local teardown success neither
authorizes a daemon control 204 nor removes a durable registry record: the CLI
independently checks exact kernel absence and daemon completion under
[the detach reporting contract](../fskit-mount.md#unmount-and-detach). No new
wire outcome or typed teardown receipt follows from these local callbacks.

**Stamps.** FSKit read and mutation replies carry the conservative versions
above. The authority samples existence, attributes, `v`, and `s` under one
storage read dependency set; every attribute sample honours the hydration lock.

**Cache proof.** A successful KeepAlive reply carries
`Response.session_valid_for_nanos` (tag 72): the remaining duration, sampled
after renewal under the session lock, of `min(lease remaining, authorization
remaining, advertised lease, MaxCacheProof)`, rounded down to a whole
millisecond and encoded in nanoseconds, with `MaxCacheProof` =
60,000,000,000 ns. A terminal session receives no positive value, and no other
reply or profile carries the field. Both peers refuse a zero,
fractional-millisecond, or over-cap value and the field beside an errno,
failure class, body, uncertain outcome, or terminal flag; the client also
requires the exact request ID and epoch and a proof no larger than the
advertised lease. Any such reply is a protocol defect that ends the session.

With `R` in nanoseconds, `epsilon(R) = 1,000,000,000 + ceil(R / 1000)`. The
client anchors `R` at `t0`, taken before the KeepAlive is queued on a clock that
advances across sleep, requires `R > epsilon(R)`, and serves cached metadata
only before `t0 + R - epsilon(R)`. The margin assumes at most 1,000 ppm
aggregate relative clock-rate error and one second of measurement uncertainty;
it assumes no clock-offset agreement.

**Exclusion.** The authority registers each proof before its reply can escape
and keeps the session's writer exclusion until the latest granted proof has
expired, even if the session is fenced earlier. An ordinary request that renews
a longer session lease grants no cache permission. Exclusion ends after both
the retained deadline and the drain of every admitted storage application of
the old session; an accepted absence proof removes only the deadline. Activation
refuses an occupied Mac writer before waiting for exclusive profile admission
and rechecks under it before publishing; an ordinary FSKit mutation is admitted
only while the writer registry names its session as the current unfenced
writer.

## Ordering across the profiles

A new OPEN/CREATE grant stays reserved until the operation's synchronous
withdrawal completes. Pending peer reads may sample storage under a
reservation; grant activation drains those samples before the DATA reply.
CONTROL may then overtake DATA, so the client handles that ordering. A
synchronous mutation under an installed grant returns its application receipt
before its visibility wait, so the holder can acknowledge a peer cut
independently. Private synchronous generations exclude their source from
grant/release reverse notifications; its exact publication gate and post-state
cover those coordinates. Client-visible grants remain broadcast to purge the
holder's earlier cached pages.

`Response.visible_sequence` (70) is the largest contiguous session application
prefix whose peer withdrawals have completed; `WaitVisibility` (request 75,
response 71) waits for withdrawal through one already-issued ticket without a
storage or durability operation. `Response.session_terminal` (69) is true only
with envelope ESTALE when this exact session expired or was fenced; the client
starts local session enforcement before delivering that response. Ordinary
stale item/handle ESTALE omits it. A volume-terminal exact outcome carries
`terminal_delivery_token` (9); the frontend returns it in
`TerminalDeliveryReceipt` on CONTROL after its kernel publication boundary, and
the authority keeps the fenced epoch's transports alive until then.

## Restart fencing

A new authority process accounts for the preceding epoch's cache horizons from
durable membership (`mount.membership`, profiles `linux`, `fskit-exclusive`,
`cacheless`). If any prior Linux mount is recorded, the replacement waits a full
subscription horizon from coordinator creation before granting a writer
delegation or applying a mutation; cold Subscribe, ordinary reads, and barriers
remain available, and a canceled wait takes no storage or identity turn. If
prior FSKit membership is recorded, foreign visible mutations and write-intent
opens are refused for `MaxCacheProof + epsilon(MaxCacheProof)` (61.06 s),
measured on a clock that includes suspend, from safe takeover: exclusive root
and membership ownership, irreversibly closed predecessor renewal, and no
predecessor storage apply still able to run. Mac activation against that
membership requires operator reconciliation. Neither bound establishes kernel
mount absence: old durable records still block topology changes and archive
proof until exact absence or operator reconciliation.

## Refusals

Refusals use the response `errno` and `failure` envelope. Malformed coordinates,
unknown enum values, inconsistent flags, an undelivered ack position, an
unissued application ticket, or a conflicting retry receive EINVAL with no
state change. Wrong/expired incarnations and stale delegation references
receive EIO with `FAILURE_CLASS_COHERENCE`; the client invalidates or reports
loss for the affected state, without interpreting it as storage death. A
stale-generation flush fails whole before apply. Ordinary storage errors keep
their errno and partial-application reporting. The handler enforces
these semantic refusals; structural frame refusals occur before dispatch.
