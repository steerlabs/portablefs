// Package fsproto is the custom filesystem protocol between a FUSE client (on the
// agent's machine) and the VCS (the authority/cache node). The VCS serves its
// billy.Filesystem over this protocol; the FUSE client translates kernel ops into
// requests. Unlike the in-kernel NFSv3 client, a FUSE client controls its own
// caching, so a thin client gets live, read-after-write coherence across machines
// (every read reaches the single authority) rather than NFSv3 close-to-open.
//
// Wire format: a gob stream per direction on a persistent TCP connection — the
// client encodes Requests and decodes Responses; the server does the reverse.
// gob sends each type descriptor once per stream, so steady-state framing is just
// the field bytes.
package fsproto

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/coherence"
	"github.com/trendup-ai/portablefs/vcs/internal/modebits"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// Op identifies a filesystem operation.
type Op uint8

const (
	OpGetattr Op = iota + 1
	OpReaddir
	OpRead
	OpWrite
	OpCreate
	OpMkdir
	OpRemove
	OpRename
	OpSymlink
	OpReadlink
	OpTruncate
	OpFsync
	OpSubscribe         // open a server-push stream of cache invalidations
	OpSetattr           // chmod / set mtime
	OpCheckout          // acquire an exclusive write delegation on a subtree
	OpCheckin           // release a delegation
	OpFlushBatch        // apply a write-back session's batched mutations (exactly-once via a watermark)
	OpLock              // advisory byte-range lock (POSIX fcntl/flock): getlk / setlk / setlkw
	OpOrphan            // detach Path from the tree but PARK its inode (open-after-unlink): returns the parked ino
	OpReap              // drop a parked orphan (OrphanIno) on the last close
	OpRenewOrphanLeases // renew leases for parked orphan inos still held open by this mount
	OpMarkOpen          // register/deregister that this mount holds Ino open (Stage 2 authority open-state)
	OpRenewOpenInodes   // renew leases for the open (still-named) inos this mount holds open

	// ---- protocol version 3 (exact mount sessions). Values are APPENDED so
	// every earlier op keeps its wire value; an old server answers any of
	// these with EINVAL via its dispatch default, and a new client never
	// sends them to a server whose negotiated version is below
	// ProtoVersionExactSessions (see protoversion.go).
	OpSessionOpen   // establish (or idempotently re-establish) a mount session identity
	OpSessionResume // authenticate + durably renew an existing session (reconnect / periodic lease renewal)
	OpSessionAttach // authenticate an existing session onto THIS connection (no durable renewal)
	OpSessionExpire // voluntarily fence THIS session generation (clean unmount); its lease-owned state is released
	OpReclaimDone   // the resumed session finished re-asserting its coordination state (ends its reclaim-grace share early)

	// ---- open-registration batching (FeatOpenRegistration). Appended so every
	// earlier op keeps its wire value; a client only sends it to an authority
	// that advertises the feature bit, so an old server never sees it.
	OpUnmarkOpenInodes // clear this mount's open holds for a batch of inos (deferred/batched last-close unmarks)

	// ---- extended attributes (FeatXattrs). Appended so every earlier op
	// keeps its wire value; a client only sends them to an authority that
	// advertises the feature bit (an old server's dispatch default would
	// answer EINVAL, and the client maps a missing bit to EOPNOTSUPP without
	// a round-trip). Reads (get/list) are pure reads; set/remove are
	// journaled mutations that ride the exact-once path on session
	// authorities exactly like OpCreate/OpWrite.
	OpGetxattr    // read one attribute value (Path/HandleIno + XattrName)
	OpSetxattr    // set one attribute (XattrName + Data; optional XattrFlags)
	OpListxattr   // list attribute names (Path/HandleIno)
	OpRemovexattr // remove one attribute (ENODATA when absent)

	// ---- hard links (FeatHardLinks). Appended so every earlier op keeps
	// its wire value. Path is the existing source name and NewPath is the
	// new directory entry. Clients send it only after capability
	// negotiation; older authorities therefore never see the unknown op.
	OpLink
)

// Feature bits advertised in the OpProtocolVersion probe response. Zero from
// any server that predates them (gob omits the absent field).
const (
	// FeatExactSessions: the authority durably supports session establish/
	// resume/attach and exact-once mutation envelopes.
	FeatExactSessions uint64 = 1 << 0
	// FeatReclaimGrace: after restart/promotion the authority runs an
	// authenticated reclaim-grace window for durable prior sessions. Never
	// advertised by a managed (journaled) authority: its recovery is exact,
	// so there is no re-assert phase to grant.
	FeatReclaimGrace uint64 = 1 << 1
	// FeatJournaledCoordination: the authority's session store journals
	// through a fenced remote journal generation. Coordination state (exact
	// sessions, outcomes, locks, checkouts) recovers from cold replay with
	// no reclaim grace and no wall-time outcome pruning, and the probe
	// advertises ProtoVersionJournaledSessions.
	FeatJournaledCoordination uint64 = 1 << 2
	// FeatParentVersion: the authority stamps every lookup miss with the
	// parent directory's coherence version (Response.ParentVersion) and bumps
	// that version on every name mutation in the directory, so a client may
	// default the version-gated negative dentry cache ON. Advertised iff the
	// backing fs implements ParentVersioned — an explicit capability, not a
	// wire sniff, so a client never has to interpret ParentVersion==0
	// ambiguously ("old authority" vs "no version available right now").
	FeatParentVersion uint64 = 1 << 3
	// FeatOpenRegistration: the authority supports the reduced-op open
	// registration surface — Request.RegisterOpen on OpCreate (create and
	// register the creating owner's open hold in one round-trip) and
	// OpUnmarkOpenInodes (batched last-close unmarks). Advertised by BOTH
	// generations: legacy holds ride the in-memory lease-renewed open table;
	// managed holds are durable journaled open-pin coordination rows (the
	// fused create ensures its pin row before the reply, and the batched
	// unmark journals N releases as one exact row).
	FeatOpenRegistration uint64 = 1 << 4
	// FeatXattrs: the authority serves native extended attributes
	// (OpGetxattr/OpSetxattr/OpListxattr/OpRemovexattr) as journaled LIVE
	// volume state. Advertised by BOTH server generations whenever the
	// backing fs implements the xattr surface (workfs does on legacy AND
	// managed); a client never sends xattr ops without it and reports
	// EOPNOTSUPP locally instead, so kernels fall back to today's behavior
	// (e.g. AppleDouble sidecars) against old authorities.
	FeatXattrs uint64 = 1 << 5
	// FeatHardLinks: the authority can atomically add a second name for an
	// existing non-directory inode and maintains stable inode identity and
	// nlink through unlink, rename-over, replay, and HistoryCut materialization.
	FeatHardLinks uint64 = 1 << 6
	// FeatAtomicAppend: Request.Append is honored by the authority and EOF is
	// selected at the write record's ordered apply position. Clients never
	// send the flag to an older authority that would silently ignore it.
	FeatAtomicAppend uint64 = 1 << 7
	// FeatAtomicXattrFlags: Request.XattrFlags is honored at the xattr
	// record's ordered apply position. It is separate from FeatXattrs so a
	// new client never sends conditional flags to an older xattr authority
	// whose gob decoder would silently ignore the additive field.
	FeatAtomicXattrFlags uint64 = 1 << 8
)

// Lock modes carried in Request.LkMode (OpLock).
const (
	LkGetlk  uint8 = 0 // report a conflicting lock (F_GETLK)
	LkSetlk  uint8 = 1 // acquire/release without blocking (F_SETLK)
	LkSetlkw uint8 = 2 // acquire, blocking until grantable (F_SETLKW)
)

// Notifier is the source of cache invalidations (the writable working tree). A
// read-only filesystem has none, so it may be nil.
type Notifier interface {
	Subscribe() (<-chan []coherence.Invalidation, func())
}

// Delegations coordinates exclusive write access to subtrees (checkout/checkin).
// May be nil (read-only / no coordination).
type Delegations interface {
	Checkout(path, owner string) (granted bool, heldBy string)
	Checkin(path, owner string) bool
	// HeldBy reports the owner of the checkout covering path (the path itself or any
	// ancestor), and the path it is held at. Empty owner = not checked out.
	HeldBy(path string) (owner, at string)
	// ReleaseOwner drops every checkout held by owner (crash cleanup when a mount's
	// liveness stream drops), so a dead mount's exclusive holds don't block others.
	ReleaseOwner(owner string)
	// AwaitFree blocks until no delegation overlaps path (so a contender can acquire), or ctx is
	// cancelled (returns false). Used after recalling a holder, to wait out its flush + checkin.
	AwaitFree(ctx context.Context, path string) bool
	// ForceCheckout revokes overlapping delegations held by others and grants path to owner —
	// the escalation when a recalled holder does not relinquish within the bound. The revoked
	// owners are fenced (see IsFenced) until they re-establish a checkout.
	ForceCheckout(path, owner string) (revoked []string)
	// IsFenced reports whether owner was force-revoked from a subtree covering path and has not
	// re-acquired it — so its in-flight write-back flush must be rejected (ESTALE) rather than
	// applied over the subtree after the new holder hands it back.
	IsFenced(owner, path string) bool
}

// Recaller broadcasts a handoff recall for a contended subtree to subscribers (the writable
// authority FS). May be nil (no recall — contention then falls back to EBUSY).
type Recaller interface {
	PublishRecall(path string)
}

// maxReadBytes bounds a single OpRead's wire-supplied size, so a hostile or
// corrupt request cannot drive an unbounded server-side allocation. Generous vs
// the client's 1 MiB read size.
const maxReadBytes = 64 << 20 // 64 MiB

// Wire bounds for exact-session requests, enforced BEFORE any WAL reservation
// or durable state change. A request that exceeds them is definitively
// malformed (EINVAL / ENAMETOOLONG); nothing about it is recorded. The session
// bounds mirror workfs's durable control-state bounds, so admission and
// replicated state enforce one finite shape.
const (
	// MaxPathBytes bounds any wire path (Path/NewPath/Target). PATH_MAX-sized.
	MaxPathBytes = 4096
	// MaxWriteBytes bounds one exact OpWrite payload (FUSE writes are <=1MiB;
	// generous headroom for large direct writes without unbounded intents).
	MaxWriteBytes = 64 << 20
	// MaxBatchRecords bounds one OpFlushBatch's record count.
	MaxBatchRecords = 4096
	// MaxSessionIDBytes / MaxTokenBytes / MaxOwnerBytes mirror workfs's
	// durable session-identity bounds.
	MaxSessionIDBytes = 128
	MaxTokenBytes     = 256
	MaxOwnerBytes     = 256
	// MaxSessionSlots bounds a session's concurrent exact-mutation slots.
	MaxSessionSlots = 4096
)

// streamWriteTimeout bounds a single invalidation push to a subscribed client, so a
// client that stopped reading cannot block (and leak) the server's stream goroutine
// indefinitely. Generous: invalidations are tiny and a healthy client drains at once.
const streamWriteTimeout = 30 * time.Second

// Liveness of the (mostly-idle) invalidation stream: the server emits a heartbeat
// every streamHeartbeat; the client arms a read deadline of streamReadTimeout and, if
// it elapses with neither an invalidation nor a heartbeat, treats the stream as dead
// (a silent half-open partition) and reconnects + flushes. Without this an idle
// half-open stream would deliver no invalidations yet never be detected, so a client
// could serve stale reads indefinitely.
const (
	streamHeartbeat   = 10 * time.Second
	streamReadTimeout = 35 * time.Second
)

// recallTimeout bounds how long a contended OpCheckout waits for the recalled holder to flush +
// check in before force-revoking it (presumed dead). Generous enough for a holder to flush a large
// write-back buffer, but < opTimeout so the contending mount's RPC always returns within its bound.
const recallTimeout = 30 * time.Second

// opTimeout bounds a single request/response round-trip, so a partitioned VCS fails
// the FUSE op (EIO) within a bounded time instead of hanging the mount in D-state for
// the OS TCP timeout (minutes). Generous for large reads over slow cross-region links.
const opTimeout = 60 * time.Second

// connKeepAlive enables TCP keepalive on every data-plane connection so a silently
// dead/half-open link is detected at the transport layer too.
const connKeepAlive = 15 * time.Second

// serverIdleTimeout bounds how long a post-handshake connection may sit between
// requests. A peer that connects, authenticates, then sends nothing (or
// dribbles a slow-loris request) cannot pin a goroutine and gob buffers
// indefinitely. Far larger than opTimeout so a quiet-but-healthy mount is never
// killed mid-op; on timeout the client simply redials on its next request
// (sessions are lease-owned and survive a socket close).
const serverIdleTimeout = 30 * time.Minute

// maxServerConns caps concurrent data-plane connections one authority serves so
// a connection flood cannot exhaust goroutines/file descriptors. Generous for
// real fan-out (many mounts, a few connections each).
const maxServerConns = 4096

// dialTimeout bounds one TCP/TLS connect attempt. Generous for a cross-region
// link, but far below the OS default (minutes): a blackholed authority must
// consume one bounded attempt on the redial backoff schedule, not pin the op
// for the kernel's connect timeout.
const dialTimeout = 10 * time.Second

// errno values (subset of syscall) carried in Response.Status; 0 is success.
const (
	OK           int32 = 0
	EPERM        int32 = 1
	ENOENT       int32 = 2
	EIO          int32 = 5
	EEXIST       int32 = 17
	ENOTDIR      int32 = 20
	EISDIR       int32 = 21
	EINVAL       int32 = 22
	ENAMETOOLONG int32 = 36 // a path component exceeded NAME_MAX (255)
	EBUSY        int32 = 16
	EAGAIN       int32 = 11  // OpLock: F_SETLK could not be granted (contended); also handoff grace elapsed
	ESTALE       int32 = 116 // flush from a SUPERSEDED session generation: don't apply AND don't ack-compact
	ENOTEMPTY    int32 = 39
	ENOSPC       int32 = 28  // local WAL backlog exceeded its retention quota (definite, durable outcome); also the per-inode xattr total bound
	EDQUOT       int32 = 122 // database-owned journal data quota exhausted (definite, durable outcome)
	E2BIG        int32 = 7   // one xattr value exceeds wal.MaxXattrValueBytes
	ERANGE       int32 = 34  // one xattr name exceeds wal.MaxXattrNameBytes
	ENODATA      int32 = 61  // xattr not present (Linux ENODATA == ENOATTR; Darwin frontends translate)
	EOPNOTSUPP   int32 = 95  // op not supported by this authority (client-side capability gate)
)

// Attr is a file's metadata.
type Attr struct {
	Kind    string // "file" | "directory" | "symlink"
	Size    int64
	Mode    uint32 // POSIX mode bits: 0o777 plus setuid/setgid/sticky
	MtimeMs int64
	CtimeMs int64
	AtimeMs int64
	Uid     uint32 // POSIX owner
	Gid     uint32 // POSIX group
	Nlink   uint32 // POSIX hard-link count; 0 from an older/read-only authority ⇒ client defaults to 1
	Ino     uint64 // stable authority-assigned inode identity; 0 ⇒ client falls back to a path hash
}

// Dirent is one entry in a directory listing.
type Dirent struct {
	Name string
	Attr Attr
	// Version is the child's per-inode coherence version at readdir time PLUS ONE, so a mount can fill
	// its attr cache from the listing (readdir-plus) under the SAME monotonic check as a single Getattr
	// — a stale or delayed readdir can't overwrite a newer invalidation. The +1 bias makes a real
	// version 0 (a clean, never-mutated inode) distinguishable on the wire from the gob-omitted 0 a
	// pre-readdir-plus authority sends; the mount subtracts 1 and treats wire-0 as "no version info"
	// (don't cache from readdir — fall back to per-entry Getattr).
	Version uint64
}

// Request is one operation from the client.
type Request struct {
	Op           Op
	Path         string
	NewPath      string // OpRename target
	OrphanTarget bool   // OpRename: park the existing NewPath destination as an orphan before replacing it (rename-over-an-open-file)
	Offset       int64  // OpRead/OpWrite
	Size         int64  // OpRead length, OpTruncate size
	Mode         uint32 // OpCreate/OpMkdir/OpWrite-create/OpSetattr
	Target       string // OpSymlink target
	Data         []byte // OpWrite payload
	// Append marks an O_APPEND write. Offset must be zero and is ignored;
	// the authority resolves EOF atomically in sequencer order.
	Append  bool
	MtimeMs int64  // OpSetattr
	SetMode bool   // OpSetattr: apply Mode
	SetTime bool   // OpSetattr: apply MtimeMs
	UID     uint32 // OpSetattr: owner
	GID     uint32 // OpSetattr: group
	SetUID  bool   // OpSetattr: apply UID (else leave unchanged)
	SetGID  bool   // OpSetattr: apply GID (else leave unchanged)
	Owner   string // OpCheckout/OpCheckin/mutations: delegation owner

	// OpFlushBatch: a write-back session's buffered mutations. Records carry the mount's
	// LOCAL WAL Seqs; the authority dedups on these (drops Seq < watermark) for
	// exactly-once apply across resend, WAL replay, and checkpoint compaction. Epoch is the
	// session GENERATION (monotonic per session instance): a higher epoch than the stored
	// watermark resets dedup, so a re-acquired or restarted session (whose local Seq space
	// restarts at 0) is not dropped against a stale watermark from a prior generation.
	SessionID string
	Epoch     uint64
	Records   []wal.Record

	// OpLock: an advisory byte-range lock (POSIX fcntl/flock). Owner (above) is the mount; LkID is
	// the kernel's per-open lock owner; together they identify the lock owner across clients.
	LkID     uint64
	LkStart  uint64
	LkEnd    uint64
	LkWrite  bool  // exclusive (F_WRLCK)
	LkUnlock bool  // release (F_UNLCK)
	LkMode   uint8 // LkGetlk / LkSetlk / LkSetlkw

	// OrphanIno addresses a parked (unlinked-but-open) inode by its stable ino instead of a path:
	// OpRead/OpWrite/OpTruncate operate on the orphan when it is non-zero, and OpReap drops it. Zero
	// for ordinary path-addressed ops. (OpOrphan itself uses Path and RETURNS the ino in the response.)
	OrphanIno uint64
	// HandleIno addresses an OPEN file handle by stable ino while still carrying Path as the mount's
	// current name for coherence invalidation. Unlike OrphanIno, the target may still be named.
	HandleIno uint64
	// OpRenewOrphanLeases: batch of parked orphan inos the mount still holds open.
	OrphanInos []uint64
	// OpMarkOpen: the live inode this mount is (de)registering as open. OpenState true=open/false=close.
	OpenIno   uint64
	OpenState bool
	// OpRenewOpenInodes: batch of OPEN (still-named) inos this mount holds open, to renew their leases.
	// OpUnmarkOpenInodes: batch of inos whose deferred last-close unmark is being flushed.
	OpenInos []uint64
	// RegisterOpen on OpCreate asks the authority to register the creating
	// owner's open hold on the new inode in the same round-trip (the kernel
	// CREATE is create+open, so the separate MarkOpen RPC is pure overhead).
	// The hold is recorded before the reply, so the same open-vs-unlink
	// guarantee holds: once the create returns, a peer unlink parks. Only
	// sent to authorities advertising FeatOpenRegistration (gob-additive:
	// an old server would decode and silently ignore it, which would leave
	// the open unregistered — hence the capability gate, never a sniff).
	RegisterOpen bool

	// ---- protocol version 3 fields (gob omits zero values, so v1/v2 peers
	// are unaffected; an old server decodes and silently drops them) ----

	// Mount-session identity (OpSessionOpen/Resume/Attach/Expire, and
	// OpSubscribe so the stream binds to the session's lease instead of the
	// socket). SessionID doubles as the write-back session id on OpFlushBatch
	// (a v1 field); the mount session uses its own distinct id space.
	SessionGen   uint64 // nonzero session generation (client-chosen on open; exact on resume/attach)
	SessionToken string // client-minted opaque credential (hashed durably server-side)
	SessionSlots uint32 // OpSessionOpen: requested concurrent exact-mutation slots

	// Env carries the exact-once mutation identity for every session-protocol
	// write-through mutation. The server verifies it against the connection's
	// authenticated session, stamps the canonical request hash itself, and
	// embeds it in the SAME WAL record as the mutation.
	Env *wal.Envelope

	// ---- journaled-coordination (managed) fields (gob-additive) ----

	// CheckoutPath/CheckoutEpoch name the durable checkout grant a managed
	// flush rides (OpFlushBatch) or releases (OpCheckin). The epoch is the
	// server-controlled monotonic grant identity OpCheckout returned.
	CheckoutPath  string
	CheckoutEpoch string

	// Excl is the O_EXCL / POSIX-exclusive intent on OpCreate: the
	// requireAbsent decision happens at the mutation's ordered apply
	// position, so an existing name is a deterministic EEXIST (never a
	// lookup-then-create race). Zero (the default) keeps idempotent create.
	Excl bool

	// XattrName names the extended attribute of an OpGetxattr/OpSetxattr/
	// OpRemovexattr request (raw case-sensitive bytes, 1..wal.MaxXattrNameBytes,
	// NUL-free UTF-8). The set VALUE rides Data. Gob-additive: an old server
	// never sees these ops (FeatXattrs gate), so the field never dangles.
	XattrName string
	// XattrFlags carries wal.XattrCreate or wal.XattrReplace for
	// OpSetxattr. The precondition is decided atomically at ordered apply.
	XattrFlags uint8
}

// Response is the server's reply. Status != OK means the op failed (Status is an
// errno) and the other fields are unset.
type Response struct {
	Status    int32
	Attr      *Attr
	Entries   []Dirent
	Data      []byte
	Target    string
	Count     int32    // OpWrite bytes written
	Paths     []string // (legacy; the versioned stream uses Invs)
	Owner     string   // OpCheckout: the owner currently holding it (on EBUSY)
	Keepalive bool     // OpSubscribe: a liveness heartbeat — not an invalidation

	// Coherence: a read response carries the path's Version; every read response AND every
	// stream message carry the authority Gen (so a client detects a restart/promotion and
	// refreshes). An OpSubscribe stream message carries a batch of invalidations in Invs.
	Version uint64
	Gen     uint64
	Invs    []coherence.Invalidation
	// ParentVersion is carried on ENOENT lookup/getattr-style responses as the parent directory's
	// coherence version PLUS ONE. Zero means "unavailable" (old authority or unversioned fs), so a
	// new client must not cache the negative. The +1 keeps a real parent version 0 representable.
	ParentVersion uint64

	AppliedThrough uint64 // OpFlushBatch: highest local Seq now durable on the authority

	// OpLock (getlk): a conflicting lock, if any. Status is OK (granted / no conflict) or EAGAIN.
	LkConflict bool
	LkStart    uint64
	LkEnd      uint64
	LkWrite    bool

	// OpOrphan: the stable ino the authority parked the unlinked inode under. The client addresses
	// subsequent reads/writes/truncates/reap of the open-but-unlinked file by this ino (Request.OrphanIno).
	OrphanIno uint64

	// OpProtocolVersion: the server's protocol version (see protoversion.go). Zero from
	// any server that predates negotiation; gob decoders that predate the field drop it.
	ProtoVersion uint32

	// ---- protocol version 3 fields (gob-additive; old decoders drop them) ----

	// OpProtocolVersion: the authority's feature bits (exact sessions,
	// reclaim grace). Zero from an older server or one without a session
	// store — the client then keeps plain v1/v2 behavior.
	Features uint64

	// Session ops: the granted lease duration (ms) and — on open/resume/attach
	// — the authoritative slot count. ReclaimMs is the remaining reclaim-grace
	// window (0 = none): during it the resumed session should re-assert its
	// locks/checkouts, and conflicting acquisitions from other sessions are
	// held off. LeaseMs also rides the OpProtocolVersion probe response.
	LeaseMs      int64
	SessionSlots uint32
	ReclaimMs    int64

	// Exact mutation outcomes. Ino is the mutated inode's stable identity.
	// Duplicate reports that this response was served from the stored slot
	// outcome (Attr is then absent — the client re-stats if it needs one).
	Ino       uint64
	Duplicate bool

	// ---- journaled-coordination (managed) fields (gob-additive) ----

	// Offset is the essential integer stored with a duplicate exact outcome
	// (managed checkout replays recover their granted epoch from it; managed
	// flush replays recover their definite AppliedThrough).
	Offset int64
	// CheckoutEpoch is the durable grant epoch a managed OpCheckout returns;
	// the client presents it on OpCheckin and on managed flushes.
	CheckoutEpoch string

	// XattrNames is an OpListxattr reply's sorted attribute-name list
	// (gob-additive; the value of an OpGetxattr rides Data).
	XattrNames []string
}

// toErrno maps a Go filesystem error to a wire errno.
func toErrno(err error) int32 {
	switch {
	case err == nil:
		return OK
	case errors.Is(err, os.ErrNotExist):
		return ENOENT
	case errors.Is(err, os.ErrExist):
		return EEXIST
	case errors.Is(err, os.ErrPermission):
		return EPERM
	case errors.Is(err, syscall.ENAMETOOLONG):
		return ENAMETOOLONG
	case errors.Is(err, syscall.ENODATA):
		return ENODATA
	case errors.Is(err, syscall.ENOSPC):
		return ENOSPC
	case errors.Is(err, syscall.E2BIG):
		return E2BIG
	case errors.Is(err, syscall.ERANGE):
		return ERANGE
	case errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP):
		return EOPNOTSUPP
	}
	switch msg := err.Error(); {
	case strings.Contains(msg, "not empty"):
		return ENOTEMPTY
	case strings.Contains(msg, "not a directory"):
		return ENOTDIR
	case strings.Contains(msg, "is a directory"):
		return EISDIR
	case strings.Contains(msg, "invalid argument"):
		return EINVAL
	default:
		return EIO
	}
}

// attrOf builds an Attr from an os.FileInfo, including POSIX ownership when the
// filesystem exposes it via Sys() (the in-memory working/volume FS does).
func attrOf(fi os.FileInfo) Attr {
	kind := "file"
	switch {
	case fi.IsDir():
		kind = "directory"
	case fi.Mode()&os.ModeSymlink != 0:
		kind = "symlink"
	}
	mtimeMs := fi.ModTime().UnixMilli()
	a := Attr{Kind: kind, Size: fi.Size(), Mode: modebits.ToUnix(fi.Mode()), MtimeMs: mtimeMs, CtimeMs: mtimeMs, AtimeMs: mtimeMs}
	if c, ok := fi.Sys().(interface{ ChangeTime() time.Time }); ok {
		if ct := c.ChangeTime(); !ct.IsZero() {
			a.CtimeMs = ct.UnixMilli()
		}
	}
	if at, ok := fi.Sys().(interface{ AccessTime() time.Time }); ok {
		if av := at.AccessTime(); !av.IsZero() {
			a.AtimeMs = av.UnixMilli()
		}
	}
	if o, ok := fi.Sys().(interface{ OwnerIDs() (uint32, uint32) }); ok {
		a.Uid, a.Gid = o.OwnerIDs()
	}
	if l, ok := fi.Sys().(interface{ LinkCount() uint32 }); ok {
		a.Nlink = l.LinkCount() // accurate count keeps a live inode from reading as "unlinked"
	}
	if i, ok := fi.Sys().(interface{ Ino() uint64 }); ok {
		a.Ino = i.Ino() // stable identity → st_ino survives rename and never aliases a recreated path
	}
	return a
}
