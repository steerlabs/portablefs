package fsproto

import (
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-git/go-billy/v5"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/locks"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/modebits"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// lockDebug enables verbose advisory-lock tracing (acquire/release/conflict/owner-release) to
// stderr; set VCS_LOCK_DEBUG=1 on the authority. Diagnostic only — off in production.
var lockDebug = os.Getenv("VCS_LOCK_DEBUG") != ""

func lockf(format string, a ...any) {
	if lockDebug {
		log.Printf("LOCK "+format, a...)
	}
}

var (
	fsprotoOps     = metrics.Default.Counter("vcs_fsproto_ops")
	fsprotoConns   = metrics.Default.Gauge("vcs_fsproto_conns")
	fsprotoLatency = metrics.Default.Histogram("vcs_fsproto_op_latency")
)

// opNames labels each sequential protocol op for the per-op counters below. The
// benchmark harness (vcs/bench) uses these to attribute where a workload's
// round-trips go; keep names stable once published.
var opNames = map[Op]string{
	OpGetattr:           "getattr",
	OpReaddir:           "readdir",
	OpRead:              "read",
	OpWrite:             "write",
	OpCreate:            "create",
	OpMkdir:             "mkdir",
	OpRemove:            "remove",
	OpRename:            "rename",
	OpSymlink:           "symlink",
	OpReadlink:          "readlink",
	OpTruncate:          "truncate",
	OpFsync:             "fsync",
	OpSubscribe:         "subscribe",
	OpSetattr:           "setattr",
	OpCheckout:          "checkout",
	OpCheckin:           "checkin",
	OpFlushBatch:        "flush_batch",
	OpLock:              "lock",
	OpOrphan:            "orphan",
	OpReap:              "reap",
	OpRenewOrphanLeases: "renew_orphan_leases",
	OpMarkOpen:          "mark_open",
	OpRenewOpenInodes:   "renew_open_inodes",
	OpUnmarkOpenInodes:  "unmark_open_inodes",
	OpGetxattr:          "getxattr",
	OpSetxattr:          "setxattr",
	OpListxattr:         "listxattr",
	OpRemovexattr:       "removexattr",
	OpLink:              "link",
	OpProtocolVersion:   "protocol_version",
	OpSessionOpen:       "session_open",
	OpSessionResume:     "session_resume",
	OpSessionAttach:     "session_attach",
	OpSessionExpire:     "session_expire",
	OpReclaimDone:       "reclaim_done",
}

// opCounters gives every op its own counter (vcs_fsproto_op_<name>) so a metrics
// snapshot shows the op MIX, not just the total. Unknown ops share one counter.
var opCounters = func() map[Op]*metrics.Counter {
	m := make(map[Op]*metrics.Counter, len(opNames))
	for op, name := range opNames {
		m[op] = metrics.Default.Counter("vcs_fsproto_op_" + name)
	}
	return m
}()

var opCounterOther = metrics.Default.Counter("vcs_fsproto_op_other")

func countOp(op Op) {
	if c, ok := opCounters[op]; ok {
		c.Inc()
		return
	}
	opCounterOther.Inc()
}

// Server serves a billy.Filesystem over the protocol. All the VCS's behaviour
// (lazy block reads, WAL, checkpoint, single authority) lives behind that
// interface, so the server is a pure translation layer. The optional Notifier
// supplies cache invalidations to push to subscribed clients.
type Server struct {
	fs       billy.Filesystem
	notifier Notifier
	deleg    Delegations
	recaller Recaller // broadcasts handoff recalls to subscribers (nil ⇒ no recall, contention falls back to EBUSY)
	token    string   // data-plane auth token (VCS_AUTH_TOKEN); "" = no handshake
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	locks    *locks.Manager // advisory byte-range lock table (OpLock): single point ⇒ cross-client correct
	// exact is the exact-mount-session machinery (protocol version 3),
	// non-nil iff fs is a workfs-style SessionStore. Envelope-less v1
	// mutations stay admitted unless VCS_REQUIRE_EXACT_SESSIONS=1.
	exact *exactState
	// beforeFlushBatch is a test seam used to stall OpFlushBatch for fsync/barrier tests.
	// Nil in production.
	beforeFlushBatch func()
	// dropReply is a test seam simulating a LOST RESPONSE: the request is
	// fully applied, but when dropReply returns true the connection is
	// dropped instead of replying — exactly the failure the exact-once replay
	// machinery exists for. Nil in production.
	dropReply func(req *Request, resp *Response) bool
	// flushShard serializes a session's watermark-read + ApplyBatch so they form one atomic
	// critical section per SessionID — otherwise two concurrent flushBatch calls for the same
	// session (e.g. a client retry on a new conn after a timeout while the first is mid-apply)
	// can both read the same `through` and double-apply (an exactly-once violation). Sharded by
	// SessionID hash to bound memory (same id ⇒ same shard ⇒ serialized; cross-session sharing
	// is harmless extra serialization).
	flushShard [64]sync.Mutex
}

// SetBeforeFlushBatch installs a test hook that runs immediately before an OpFlushBatch is applied.
func (s *Server) SetBeforeFlushBatch(fn func()) { s.beforeFlushBatch = fn }

// SetDropReply installs a test hook that, when it returns true for an applied
// request, drops the connection WITHOUT sending the response (a lost reply).
func (s *Server) SetDropReply(fn func(req *Request, resp *Response) bool) { s.dropReply = fn }

// SetRequireExactSessions toggles the fail-closed posture at runtime (the
// VCS_REQUIRE_EXACT_SESSIONS=1 startup default): envelope-less v1 mutations
// are then refused with EPERM, and write-back flushes must ride an attached,
// still-current mount session. No-op on a server without a session store.
func (s *Server) SetRequireExactSessions(require bool) {
	if s.exact != nil {
		s.exact.mu.Lock()
		s.exact.requireExact = require
		s.exact.mu.Unlock()
	}
}

func (s *Server) sessionLock(id string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return &s.flushShard[h.Sum32()%uint32(len(s.flushShard))]
}

// NewServer returns a Server backed by fs. notifier and deleg may be nil
// (read-only fs / no write coordination). When fs implements SessionStore
// (workfs.FS), exact mount sessions are served behind the protocol version
// negotiation; VCS_REQUIRE_EXACT_SESSIONS=1 additionally refuses envelope-less
// v1 mutations (fail-closed; default stays permissive for compatibility).
func NewServer(fs billy.Filesystem, notifier Notifier, deleg Delegations) *Server {
	s := &Server{
		fs:       fs,
		notifier: notifier,
		deleg:    deleg,
		token:    secure.AuthToken(),
		conns:    map[net.Conn]struct{}{},
		locks:    locks.New(),
	}
	if store, ok := fs.(SessionStore); ok {
		s.exact = newExactState(store, os.Getenv("VCS_REQUIRE_EXACT_SESSIONS") == "1")
	}
	if s.exact != nil && s.exact.managed {
		// Managed construction selects PFC2 ONLY: the legacy volatile lock
		// manager and delegation manager are never even built, so no
		// dispatch path can route coordination through both worlds. Every
		// managed session, lock, checkout, pin, flush, reap, and barrier
		// decision goes through the journaled coordination interface.
		if _, ok := fs.(CoordinationStore); !ok {
			panic("fsproto: managed session store lacks the coordination surface")
		}
		s.locks = nil
		s.deleg = nil
	}
	// The writable authority FS broadcasts handoff recalls over the same subscriber fan-out it uses
	// for invalidations; wire it up when present so contention triggers a recall, not a bare EBUSY.
	if r, ok := notifier.(Recaller); ok {
		s.recaller = r
	}
	return s
}

// Serve accepts connections until ctx is cancelled or ln is closed.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.exact != nil {
		// Lease-owned cleanup: elapsed session leases are durably fenced and
		// their locks/delegations released — never on a socket flap.
		s.exact.sweeperOnce.Do(func() {
			go s.leaseSweeper(s.exact.sweeperStop)
		})
		defer close(s.exact.sweeperStop)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if len(s.conns) >= maxServerConns {
			// Connection flood: refuse rather than exhaust goroutines/FDs. A
			// legitimate peer redials on the backoff schedule.
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	fsprotoConns.Add(1)
	defer func() {
		fsprotoConns.Add(-1)
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	// TCP keepalive detects a silently dead/half-open peer at the transport layer.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(connKeepAlive)
	}
	// Authenticate the peer before serving any filesystem op (no-op when unset).
	if err := secure.ServerHandshake(conn, s.token); err != nil {
		return
	}
	dec := gob.NewDecoder(conn)
	enc := gob.NewEncoder(conn)
	cs := &connSession{}
	for {
		// Idle bound between requests: a peer that authenticates then stalls
		// (sends nothing / a slow-loris request) cannot pin this goroutine and
		// its gob buffers forever. Reset each iteration; generous vs opTimeout.
		_ = conn.SetReadDeadline(time.Now().Add(serverIdleTimeout))
		var req Request
		if err := dec.Decode(&req); err != nil {
			return // peer closed, idle-timed-out, or stream error
		}
		if req.Op == OpSubscribe {
			// The invalidation stream manages its own read/write deadlines and
			// heartbeats; clear the idle bound before handing off.
			_ = conn.SetReadDeadline(time.Time{})
			s.stream(conn, enc, cs, req.Owner)
			return // the connection becomes a one-way invalidation stream
		}
		start := time.Now()
		resp := s.dispatchConn(cs, &req)
		fsprotoOps.Inc()
		countOp(req.Op)
		fsprotoLatency.Time(start)
		if resp == nil {
			// UNKNOWN outcome (possibly durably prepared): NEVER invent a
			// definite errno. Drop the connection; the client parks + replays
			// the identical exact identity against a surviving authority.
			return
		}
		if s.dropReply != nil && s.dropReply(&req, resp) {
			return // test seam: response lost in flight (see SetDropReply)
		}
		// A peer that stopped reading must not block the server in Encode on a
		// full send buffer; bound the write, then clear it for the next read.
		_ = conn.SetWriteDeadline(time.Now().Add(opTimeout))
		if err := enc.Encode(resp); err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
}

// stream turns the connection into a server-push channel of invalidations until
// the client disconnects (or the server shuts the conn).
func (s *Server) stream(conn net.Conn, enc *gob.Encoder, cs *connSession, owner string) {
	// LEGACY liveness-release: for a session-LESS subscriber the stream is
	// the mount's only liveness signal, so its checkouts/locks release when
	// it drops (else a crashed mount blocks others forever). A
	// session-attached mount explicitly does NOT release on a socket flap:
	// its coordination state is owned by the session lease, and cleanup
	// happens only on durable lease expiry or voluntary session expire.
	if owner != "" && !(s.exact != nil && cs.attached()) {
		defer func() {
			trace(evRelease, 0, tag(owner), 0, 0, 0)
			if s.deleg != nil {
				s.deleg.ReleaseOwner(owner)
			}
			if s.locks != nil {
				lockf("RELEASE-OWNER mount=%q (stream disconnect)", owner)
				s.locks.ReleaseOwner(owner) // free this mount's advisory locks on disconnect
			}
		}()
	}
	if s.notifier == nil {
		// No invalidation source (read-only fs): just hold until the client leaves.
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	var gen uint64
	if v, ok := s.fs.(Versioned); ok {
		gen = v.Generation()
	}
	// Register as a subscriber BEFORE announcing the generation, so no mutation can slip through
	// the gap between the handshake and registration (it would otherwise be silently missed).
	sub, cancel := s.notifier.Subscribe()
	defer cancel()
	// Announce the generation so the client refreshes (drops all cached versions) before applying
	// any versioned invalidation from this — possibly freshly restarted/promoted — authority.
	_ = conn.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	if err := enc.Encode(&Response{Keepalive: true, Gen: gen}); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, conn); close(done) }() // detect client close
	hb := time.NewTicker(streamHeartbeat)
	defer hb.Stop()
	for {
		var resp Response
		select {
		case <-done:
			return
		case batch, ok := <-sub:
			if !ok {
				return
			}
			// Source suppression: drop the invalidations this subscriber itself originated
			// (its own write-back echoes); a FlushAll always passes. Build a NEW slice — the
			// batch is shared across subscribers and must not be mutated.
			var out []coherence.Invalidation
			for _, inv := range batch {
				if owner != "" && inv.Owner == owner && !inv.FlushAll {
					continue
				}
				out = append(out, inv)
			}
			if len(out) == 0 {
				continue
			}
			resp = Response{Invs: out, Gen: gen}
		case <-hb.C:
			// Idle heartbeat: lets the client detect a silently dead/half-open stream
			// (it arms a read deadline) and exercises the write path so a wedged client
			// is caught even when no invalidations are flowing.
			resp = Response{Keepalive: true, Gen: gen}
		}
		// Bound the write: a client that stopped reading (full TCP send buffer) would
		// otherwise block this goroutine — and pin the subscription — forever. On a
		// timeout we drop the stream rather than leak the connection.
		_ = conn.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
		if err := enc.Encode(&resp); err != nil {
			return
		}
	}
}

// mutatingOps are the ops that change the tree; they are subject to checkout
// enforcement. Reads/stat/readlink/subscribe/checkout/checkin are not.
func mutatingOp(op Op) bool {
	switch op {
	case OpWrite, OpCreate, OpMkdir, OpRemove, OpRename, OpSymlink, OpLink, OpTruncate, OpSetattr, OpOrphan,
		OpSetxattr, OpRemovexattr:
		// OpOrphan detaches a named path (checkout-gated like OpRemove). OpReap is NOT here: it targets
		// a parked inode by ino, which has no path to gate on — its ownership is the orphan's lease.
		// OpSetxattr/OpRemovexattr are attr-level mutations (checkout-gated like OpSetattr);
		// OpGetxattr/OpListxattr are pure reads.
		return true
	}
	return false
}

// enforceCheckout refuses a mutating op whose target is under a checkout held by a
// DIFFERENT owner (checkout is no longer advisory). Un-checked-out paths are
// unrestricted, so ordinary write-through is unaffected until a checkout exists.
// Rename is checked on BOTH source and destination. The requester identity is
// req.Owner (a mount stamps its owner id on mutations while it holds a checkout).
func (s *Server) enforceCheckout(req *Request) *Response {
	if s.deleg == nil {
		return nil
	}
	if r := s.pathOwnerOK(req.Path, req.Owner); r != nil {
		return r
	}
	if req.Op == OpRename || req.Op == OpLink {
		if r := s.pathOwnerOK(req.NewPath, req.Owner); r != nil {
			return r
		}
	}
	return nil
}

func (s *Server) pathOwnerOK(path, owner string) *Response {
	if holder, _ := s.deleg.HeldBy(path); holder != "" && holder != owner {
		return &Response{Status: EBUSY, Owner: holder}
	}
	return nil
}

// reservedPrefix marks internal authority metadata kept IN the tree (so it inherits the
// manifest/WAL/checkpoint/replication durability) yet hidden from clients. Currently the
// per-session flush watermarks (.portablefs-<sessionID>), which live at the volume root.
const reservedPrefix = ".portablefs-"

// isReserved reports whether p resolves to internal authority metadata. It CANONICALIZES p the
// same way the workfs does before resolving an inode (path.Clean + trim) — otherwise a client
// could slip past this guard with traversal ("x/../.portablefs-<id>") yet still hit the reserved file,
// reading/writing/deleting a flush watermark and breaking exactly-once.
func isReserved(p string) bool {
	return strings.HasPrefix(strings.Trim(path.Clean("/"+p), "/"), reservedPrefix)
}

func watermarkPath(session string) string { return reservedPrefix + session }

// BatchApplier is the authority FS's atomic batch-apply entry point (workfs.FS): apply an
// ordered batch as one group commit + a single invalidation.
type BatchApplier interface {
	ApplyBatch([]wal.Record, string) error
}

// VersionedWriter lets OpWrite get back the coherence version THIS write produced (workfs.FS),
// instead of re-sampling the path's current version afterward — which under a concurrent
// same-path write could return the OTHER writer's version. A read-only fs need not implement it.
type VersionedWriter interface {
	WriteAt(name string, off int64, data []byte, perm os.FileMode) (n int, version uint64, err error)
}

// AtomicAppendStore resolves EOF and commits the write under the authority's
// mutation lock. It is deliberately separate from VersionedWriter: an older
// or read-only store must not advertise an append capability it cannot honor.
type AtomicAppendStore interface {
	AppendAtHandleExistingAs(name string, ino uint64, data []byte, owner string) (n int, offset int64, version uint64, err error)
	AppendOrphanAs(ino uint64, data []byte, owner string) (n int, offset int64, version uint64, err error)
}

// OwnedMutator lets the server tag a write-through mutation's published invalidation with the
// originating mount owner (workfs.FS), so the authority's subscribe stream source-suppresses
// the echo back to that mount BY IDENTITY — race-free self-suppression, the same mechanism a
// write-back flush uses (ApplyBatch owner). It supersedes relying on the client recording the
// version before the echo lands. A read-only or test fs need not implement it; the server then
// falls back to the plain (owner-less) billy mutators, which the version predicate suppresses.
type OwnedMutator interface {
	MutateAs(r wal.Record, owner string) error
	CreateAs(name string, perm os.FileMode, owner string) error
	TruncateAs(name string, size int64, owner string) error
	TruncateHandleAs(name string, ino uint64, size int64, owner string) error
	WriteAtAs(name string, off int64, data []byte, perm os.FileMode, owner string) (n int, version uint64, err error)
	// WriteAtExistingAs is WriteAtAs that does NOT create an absent path (returns ErrNotExist), so a
	// write racing an unlink cannot resurrect the just-orphaned name. The RPC OpWrite path uses it.
	WriteAtExistingAs(name string, off int64, data []byte, owner string) (n int, version uint64, err error)
	WriteAtHandleExistingAs(name string, ino uint64, off int64, data []byte, owner string) (n int, version uint64, err error)
	ChownAs(name string, uid, gid int, owner string) error
	ChownHandleAs(name string, ino uint64, uid, gid int, owner string) error
}

// Versioned is the authority FS's coherence-versioning view (workfs.FS): the process
// generation nonce and a path's current coherence version. A read-only fs need not
// implement it (reads then carry Gen=0/Version=0, which clients treat as "always refetch").
type Versioned interface {
	Generation() uint64
	Version(string) (uint64, bool)
}

// ParentVersioned reports the parent directory version for a lookup miss at path. It lets clients
// safely cache ENOENT only when a later name mutation in that directory can be version-ordered.
type ParentVersioned interface {
	ParentVersion(string) (uint64, bool)
}

// HandleVersioned returns a version by stable ino when a write-through handle op carries one.
type HandleVersioned interface {
	VersionByHandle(path string, ino uint64) (uint64, bool)
}

// HandleStore is the authority FS's named-or-orphan stable-handle view. Path is retained as a
// fallback/current name, but ino wins when non-zero.
type HandleStore interface {
	ReadHandleAt(name string, ino uint64, p []byte, off int64) (int, error)
	// HandleInfo distinguishes VERIFIED absence (os.ErrNotExist → ENOENT)
	// from a lazy-base hydration/integrity/transport failure (any other
	// error → its errno, EIO by default). The distinction is load-bearing: a
	// mount that receives ENOENT drops the handle permanently, while an EIO
	// retry of the same inode succeeds once the authority's base recovers.
	HandleInfo(name string, ino uint64) (os.FileInfo, error)
}

// owned returns the fs's owner-aware mutator view (workfs.FS) for race-free self-suppression,
// or false for a read-only/test fs (the caller then uses the plain billy mutators).
func (s *Server) owned() (OwnedMutator, bool) {
	o, ok := s.fs.(OwnedMutator)
	return o, ok
}

// OrphanStore is the authority FS's open-after-unlink view (workfs.FS): park an unlinked-but-open
// inode (Orphan), serve reads/writes/truncates against it by its stable ino, and free it on the last
// close (Reap). A read-only or test fs need not implement it; the server then rejects orphan ops.
type OrphanStore interface {
	Orphan(name, owner string) (uint64, error)
	Reap(ino uint64, owner string) error
	ReadOrphanAt(ino uint64, p []byte, off int64) (int, error)
	WriteOrphanAt(ino uint64, off int64, data []byte, owner string) (int, uint64, error)
	TruncateOrphanAt(ino uint64, size int64, owner string) error
	OrphanInfo(ino uint64) (os.FileInfo, bool)
	RenewOrphanLeases([]uint64) int
	RenameWithOrphanTarget(oldName, newName string, orphanTarget bool, owner string) (uint64, error)
	// Stage 2 authority open-state: a mount registers/renews/clears its hold on a LIVE inode so the
	// authority can park (orphan) instead of remove an inode a peer mount still holds open.
	// MarkOpenInode returns false if the inode no longer exists (the open raced a peer unlink).
	MarkOpenInode(ino uint64, owner string) bool
	UnmarkOpenInode(ino uint64, owner string)
	RenewOpenInodes(inos []uint64, owner string)
}

// orphans returns the fs's open-after-unlink view (workfs.FS), or false for a fs that does not
// support it (the caller then returns EPERM for orphan ops).
func (s *Server) orphans() (OrphanStore, bool) {
	o, ok := s.fs.(OrphanStore)
	return o, ok
}

// XattrStore is the authority FS's extended-attribute READ surface
// (workfs.FS): resolve by stable ino when non-zero (named or parked orphan),
// else by path. Mutations ride the ordinary journaled mutation paths
// (OwnedMutator.MutateAs / the exact-once MutateEnv), never a separate
// surface. Implementing this is what makes the server advertise FeatXattrs —
// an explicit capability, never a wire sniff.
type XattrStore interface {
	GetxattrHandle(path string, ino uint64, name string) ([]byte, error)
	ListxattrHandle(path string, ino uint64) ([]string, error)
}

// AtomicXattrFlagStore explicitly marks an xattr implementation that consumes
// wal.XattrCreate/wal.XattrReplace. The separate capability is load-bearing
// for rolling upgrades: older XattrStore implementations decode the additive
// wire field as zero and would otherwise turn a conditional set into an
// unconditional overwrite.
type AtomicXattrFlagStore interface {
	SupportsAtomicXattrFlags() bool
}

// xattrs returns the fs's xattr read view, or false (callers then answer
// EOPNOTSUPP, matching the un-advertised feature bit).
func (s *Server) xattrs() (XattrStore, bool) {
	x, ok := s.fs.(XattrStore)
	return x, ok
}

func (s *Server) supportsAtomicXattrFlags() bool {
	if _, ok := s.xattrs(); !ok {
		return false
	}
	x, ok := s.fs.(AtomicXattrFlagStore)
	return ok && x.SupportsAtomicXattrFlags()
}

// HardLinkStore is the authority's atomic hard-link surface. The operation is
// capability-advertised rather than inferred from generic billy interfaces:
// older/read-only authorities make clients fail locally with EOPNOTSUPP.
type HardLinkStore interface {
	LinkAs(oldPath, newPath, owner string) error
}

func (s *Server) hardLinks() (HardLinkStore, bool) {
	h, ok := s.fs.(HardLinkStore)
	return h, ok
}

// validateXattrRequest is the wire-bounds gate shared by the legacy and exact
// xattr paths: everything here fails BEFORE any WAL reservation. Returns OK
// or the definitive errno (ERANGE oversized name, E2BIG oversized value,
// EINVAL malformed name).
func validateXattrRequest(req *Request) int32 {
	if len(req.XattrName) == 0 || strings.IndexByte(req.XattrName, 0) >= 0 || !utf8.ValidString(req.XattrName) {
		return EINVAL
	}
	if len(req.XattrName) > wal.MaxXattrNameBytes {
		return ERANGE
	}
	if req.Op == OpSetxattr && len(req.Data) > wal.MaxXattrValueBytes {
		return E2BIG
	}
	if req.XattrFlags&^wal.XattrFlagMask != 0 || req.XattrFlags == wal.XattrFlagMask ||
		(req.Op != OpSetxattr && req.XattrFlags != 0) {
		return EINVAL
	}
	return OK
}

// registerCreateOpen fuses Stage-2 open registration into a successful
// OpCreate reply (Request.RegisterOpen, FeatOpenRegistration). The kernel
// CREATE is create+open, so the mount previously paid a second MarkOpen
// round-trip before the create could return; here the hold is recorded before
// the reply leaves the server, which preserves the exact guarantee of the
// two-RPC flow: once create returns to the application, a concurrent peer
// unlink sees the hold and parks instead of destroying. If the just-created
// inode is already gone (a peer unlink won inside this window), the reply
// degrades to ENOENT exactly as the separate MarkOpen would have — the mount
// fails the open rather than holding a dead inode. Runs on fresh executions
// AND duplicate exact replays. On the legacy generation the hold is
// in-memory liveness (idempotent, lease-renewed), never part of the durable
// outcome; a managed generation routes to the journaled fusion instead
// (registerCreateOpenManaged) — its pins are durable coordination rows and
// must never touch the legacy in-memory table.
func (s *Server) registerCreateOpen(cs *connSession, req *Request, resp *Response) *Response {
	if resp == nil || !req.RegisterOpen || req.Op != OpCreate || resp.Status != OK {
		return resp
	}
	if s.exact != nil && s.exact.managed {
		return s.registerCreateOpenManaged(cs, req, resp)
	}
	os, ok := s.orphans()
	if !ok {
		return resp // no open-state store: the feature was never advertised
	}
	ino := resp.Ino
	if ino == 0 && resp.Attr != nil {
		ino = resp.Attr.Ino
	}
	if ino == 0 {
		// A duplicate exact replay of an idempotent create-over-existing
		// carries no ino in its stored outcome; resolve the name's CURRENT
		// binding — the same inode the two-RPC client would have re-stat'ed
		// and then marked.
		if fi, err := s.fs.Lstat(req.Path); err == nil {
			a := attrOf(fi)
			ino = a.Ino
		}
	}
	if ino == 0 || !os.MarkOpenInode(ino, req.Owner) {
		return &Response{Status: ENOENT, Gen: s.gen()}
	}
	if resp.Ino == 0 {
		// Report the inode the hold was recorded on, so the client refcounts
		// (and eventually unmarks) exactly the ino this registration pinned.
		resp.Ino = ino
	}
	return resp
}

// gen returns the authority's coherence generation nonce (0 for a non-versioned fs).
func (s *Server) gen() uint64 {
	if v, ok := s.fs.(Versioned); ok {
		return v.Generation()
	}
	return 0
}

// versionStamp returns the authority generation and a path's current coherence version.
// For a READ, sample it BEFORE the underlying fs op: it is then a lower bound on the bytes'
// true version, which is safe (a client only needs cachedVersion <= the bytes' version; a
// later real change is strictly greater and still evicts). For a WRITE, sample it AFTER:
// it is then the version the write itself produced (which the writer records to suppress
// its own echo).
func (s *Server) versionStamp(p string) (gen, version uint64) {
	return s.versionStampFor(p, 0)
}

func (s *Server) versionStampFor(p string, ino uint64) (gen, version uint64) {
	if v, ok := s.fs.(Versioned); ok {
		gen = v.Generation()
		if ino != 0 {
			if hv, ok := s.fs.(HandleVersioned); ok {
				version, _ = hv.VersionByHandle(p, ino)
				return
			}
		}
		version, _ = v.Version(p)
	}
	return
}

func parentOf(p string) string {
	d := path.Dir(strings.Trim(path.Clean("/"+p), "/"))
	if d == "." || d == "/" {
		return ""
	}
	return d
}

func (s *Server) parentVersion(p string) (gen, parentVersion uint64, ok bool) {
	v, vok := s.fs.(Versioned)
	if !vok {
		return 0, 0, false
	}
	gen = v.Generation()
	if pv, pok := s.fs.(ParentVersioned); pok {
		parentVersion, ok = pv.ParentVersion(p)
		return gen, parentVersion, ok
	}
	parentVersion, ok = v.Version(parentOf(p))
	return gen, parentVersion, ok
}

// missResponse builds a lookup-miss reply from a parent version the CALLER sampled BEFORE the
// underlying Lstat (see C1 at OpGetattr). Passing the pre-sampled (pgen, pv, pvok) in — rather than
// re-sampling here after the Lstat — is what makes a cached negative safe.
func (s *Server) missResponse(status int32, pgen, pv uint64, pvok bool) *Response {
	resp := &Response{Status: status, Gen: s.gen()}
	if status != ENOENT {
		return resp
	}
	// ENOENT is cacheable only when it is ordered by the parent directory's coherence version.
	// workfs serializes lookup/mutation under its tree lock and bumps a directory's version when a
	// child is created/removed/renamed. Because the caller sampled that parent version BEFORE the
	// Lstat, the negative is stamped for a directory state no later than the miss: any create that
	// could shadow this name either (a) preceded the sample and would already have made the Lstat
	// hit, or (b) follows the sample with a strictly greater parent version, whose invalidation
	// advances the client past the stored negative. The wire carries pv+1 so a real version 0 is
	// distinguishable from gob's omitted zero / an old authority. A client stores the negative under
	// pv and serves it only while cachedParentVersion >= currently-observed parentVersion; a racing
	// create's invalidation strictly advances the parent and evicts it. If that invalidation has not
	// arrived yet, the miss is still ordered before the create for that client, so returning ENOENT
	// for that syscall is a valid concurrent outcome — never a negative that survives the bump.
	if pvok {
		resp.Gen = pgen
		resp.ParentVersion = pv + 1
	}
	return resp
}

// flushBatch applies a write-back session's buffered mutations EXACTLY ONCE.
// Dedupe is on the mount's LOCAL Seq via a durable per-session watermark,
// advanced in the SAME atomic batch as the mutations, so a resend never
// double-applies — across ack loss, authority WAL replay, OR checkpoint
// compaction.
//
// On an exact-session authority the watermark is a REPLICATED CONTROL record
// (ctlKindWatermark, read via SessionStore.FlushWatermark) with a one-time
// migration off the legacy hidden .portablefs-<id> file; on a plain billy fs
// the hidden-file watermark is kept.
//
// Flush exactness is the watermark's, not an envelope's; sessions compose with
// it as AUTHENTICATION: under VCS_REQUIRE_EXACT_SESSIONS=1 the flush must
// arrive on a connection whose authenticated mount session is still CURRENT —
// a fenced/expired mount's straggler flush is rejected ESTALE (it keeps its
// records; no compaction, no loss).
func (s *Server) flushBatch(cs *connSession, req *Request) *Response {
	if traceOn {
		var fseq, lseq uint64
		if n := len(req.Records); n > 0 {
			fseq, lseq = req.Records[0].Seq, req.Records[n-1].Seq
		}
		trace(evFlushRecv, tag(req.SessionID), tag(req.Owner), req.Epoch, fseq, lseq)
	}
	ba, ok := s.fs.(BatchApplier)
	if !ok {
		return &Response{Status: EPERM} // read-only fs: cannot apply a write-back batch
	}
	if req.SessionID == "" || len(req.SessionID) > MaxSessionIDBytes ||
		strings.ContainsAny(req.SessionID, "/\\") || isReserved(req.SessionID) {
		return &Response{Status: EINVAL} // a malformed id could escape the reserved namespace
	}
	if len(req.Records) > MaxBatchRecords {
		return &Response{Status: EINVAL} // bound one flush intent
	}
	if s.exact != nil && s.exact.exactRequired() {
		if !cs.attached() {
			return &Response{Status: ESTALE}
		}
		if info, ok := s.exact.store.CurrentSession(cs.id); !ok || info.Expired || info.Generation != cs.gen {
			return &Response{Status: ESTALE}
		}
	}
	for i := range req.Records {
		if isReserved(req.Records[i].Path) || isReserved(req.Records[i].NewPath) {
			return &Response{Status: EINVAL} // a client batch may not touch reserved metadata
		}
		if req.Records[i].Env != nil || req.Records[i].Op.IsControl() || req.Records[i].Op.IsBatch() {
			return &Response{Status: EINVAL} // a client batch may not smuggle control/exact/batch records
		}
		if req.Records[i].Op == wal.OpSetxattr || req.Records[i].Op == wal.OpRemovexattr {
			// Xattr mutations are write-through only (sessions never buffer
			// them); a flush batch may not smuggle them past the write-through
			// admission gates. Mirrors the managed store's batch validation.
			return &Response{Status: EINVAL}
		}
		if r := s.pathOwnerOK(req.Records[i].Path, req.Owner); r != nil {
			trace(evFlushOwner, tag(req.SessionID), tag(req.Owner), req.Epoch, tag(req.Records[i].Path), uint64(r.Status))
			return r
		}
		if s.deleg.IsFenced(req.Owner, req.Records[i].Path) {
			// This owner was force-revoked from a subtree covering the record and has not
			// re-acquired it: a straggler flush from its presumed-dead session. Reject so it
			// cannot apply over the subtree the new holder already handed back.
			trace(evFlushOwner, tag(req.SessionID), tag(req.Owner), req.Epoch, tag(req.Records[i].Path), uint64(ESTALE))
			return &Response{Status: ESTALE}
		}
		if req.Records[i].Op == wal.OpRename || req.Records[i].Op == wal.OpLink {
			if r := s.pathOwnerOK(req.Records[i].NewPath, req.Owner); r != nil {
				return r
			}
			if s.deleg.IsFenced(req.Owner, req.Records[i].NewPath) {
				return &Response{Status: ESTALE}
			}
		}
	}

	// Atomic per session: watermark read + dedup + ApplyBatch + watermark advance are ONE
	// critical section, so two concurrent flushes of the same SessionID can't both read the same
	// `through` and double-apply.
	lk := s.sessionLock(req.SessionID)
	lk.Lock()
	defer lk.Unlock()

	// Read the durable watermark: replicated control state on an exact
	// authority (with a one-time migration off the legacy hidden file), the
	// legacy hidden file otherwise.
	var (
		wmEpoch, through uint64
		exists           bool
		legacyFile       bool
	)
	wmPath := watermarkPath(req.SessionID)
	if s.exact != nil {
		wmEpoch, through, exists = s.exact.store.FlushWatermark(req.SessionID)
		if !exists {
			e, t, ex, err := s.readWatermark(wmPath)
			if err != nil {
				return &Response{Status: EIO}
			}
			wmEpoch, through, exists, legacyFile = e, t, ex, ex
		}
	} else {
		var err error
		wmEpoch, through, exists, err = s.readWatermark(wmPath)
		if err != nil {
			return &Response{Status: EIO}
		}
	}
	if exists && req.Epoch < wmEpoch {
		// A flush from a SUPERSEDED (older) session generation — a newer generation of this
		// SessionID already advanced the watermark. We must NOT apply these records, AND we must
		// NOT return an AppliedThrough: the newer generation's `through` is in a DIFFERENT local
		// Seq space, so the stale sender would compact (drop) un-applied records against it —
		// silent data loss. Return ESTALE so the sender keeps its records (no compaction) instead.
		trace(evFlushStale, tag(req.SessionID), tag(req.Owner), req.Epoch, wmEpoch, through)
		return &Response{Status: ESTALE}
	}
	if !exists || req.Epoch > wmEpoch {
		through = 0 // new generation: the mount's local Seq space restarts at 0; reset dedup
	}

	// Drop already-applied records; the first survivor must be contiguous with the
	// watermark (== through), and survivors contiguous among themselves.
	first := -1
	for i := range req.Records {
		if req.Records[i].Seq >= through {
			first = i
			break
		}
	}
	if first == -1 { // whole batch already durable (pure resend): no-op
		trace(evFlushResend, tag(req.SessionID), tag(req.Owner), req.Epoch, through, 0)
		return &Response{AppliedThrough: prevSeq(through)}
	}
	if req.Records[first].Seq != through {
		trace(evFlushGap, tag(req.SessionID), tag(req.Owner), req.Epoch, req.Records[first].Seq, through)
		return &Response{Status: EINVAL} // gap below this batch: mount must resend from `through`
	}
	survivors := req.Records[first:]
	for i := 1; i < len(survivors); i++ {
		if survivors[i].Seq != survivors[i-1].Seq+1 {
			return &Response{Status: EINVAL} // non-contiguous batch
		}
	}
	newThrough := survivors[len(survivors)-1].Seq + 1

	// Atomic batch: the user mutations + the watermark advance. One group
	// commit, one invalidation — the watermark moves iff the mutations land.
	var batch []wal.Record
	if s.exact != nil {
		wmRec, err := workfs.FlushWatermarkRecord(req.SessionID, req.Epoch, newThrough)
		if err != nil {
			return &Response{Status: EIO}
		}
		batch = make([]wal.Record, 0, len(survivors)+2)
		batch = append(batch, survivors...)
		batch = append(batch, wmRec)
		if legacyFile {
			// One-time migration: retire the legacy hidden-file watermark in
			// the SAME atomic intent that records the control watermark.
			batch = append(batch, wal.Record{Op: wal.OpRemove, Path: wmPath})
		}
	} else {
		batch = make([]wal.Record, 0, len(survivors)+2)
		batch = append(batch, survivors...)
		if !exists {
			batch = append(batch, wal.Record{Op: wal.OpCreate, Path: wmPath, Mode: 0o600})
		}
		var wm [16]byte
		binary.BigEndian.PutUint64(wm[0:8], req.Epoch) // generation
		binary.BigEndian.PutUint64(wm[8:16], newThrough)
		batch = append(batch, wal.Record{Op: wal.OpWrite, Path: wmPath, Offset: 0, Data: append([]byte(nil), wm[:]...)})
	}

	if err := ba.ApplyBatch(batch, req.Owner); err != nil {
		return &Response{Status: toErrno(err)} // surface e.g. ENAMETOOLONG from a batch-introduced name
	}
	trace(evFlushOK, tag(req.SessionID), tag(req.Owner), req.Epoch, through, newThrough)
	return &Response{AppliedThrough: newThrough - 1}
}

func prevSeq(through uint64) uint64 {
	if through == 0 {
		return 0
	}
	return through - 1
}

// readWatermark reads a session's durable flush watermark (the next-expected local Seq).
// (0,false,nil) = no watermark yet. A present-but-unreadable watermark returns an error
// (never silently treated as 0, which would re-apply already-durable records).
func (s *Server) readWatermark(wmPath string) (epoch, through uint64, exists bool, err error) {
	f, oerr := s.fs.Open(wmPath)
	if oerr != nil {
		if errors.Is(oerr, os.ErrNotExist) {
			return 0, 0, false, nil
		}
		return 0, 0, false, oerr
	}
	defer f.Close()
	var buf [16]byte
	n, rerr := f.ReadAt(buf[:], 0)
	if rerr != nil && rerr != io.EOF {
		return 0, 0, true, rerr
	}
	if n < 16 {
		return 0, 0, true, io.ErrUnexpectedEOF // exists but malformed → surface, don't guess
	}
	return binary.BigEndian.Uint64(buf[0:8]), binary.BigEndian.Uint64(buf[8:16]), true, nil
}

// dispatch runs one request exactly as a fresh stateless legacy connection
// would — the same admission gates as the wire path, minus gob framing.
// In-package tests drive the server through it; live traffic arrives via
// handle → dispatchConn with real per-connection state.
func (s *Server) dispatch(req *Request) *Response {
	return s.dispatchConn(&connSession{}, req)
}

// dispatchConn routes connection-stateful (session) ops, applies the
// exact-session write gate and reclaim-grace gate, then falls through to the
// stateless v1 dispatch for everything else.
func (s *Server) dispatchConn(cs *connSession, req *Request) *Response {
	switch req.Op {
	case OpProtocolVersion:
		// Version probe (see protoversion.go). Request.Size carries the
		// client's version; the response advertises ours plus the
		// exact-session feature bits and lease, so a skewed client detects
		// capability differences up front and negotiates down gracefully.
		return s.probeResponse()
	case OpSessionOpen:
		return s.sessionOpen(cs, req)
	case OpSessionResume:
		return s.sessionResume(cs, req)
	case OpSessionAttach:
		return s.sessionAttach(cs, req)
	case OpSessionExpire:
		return s.sessionExpire(cs, req)
	case OpReclaimDone:
		if s.exact == nil {
			return &Response{Status: EPERM}
		}
		if s.exact.managed {
			// Managed (journaled) recovery is exact: there is no reclaim /
			// re-assert phase, so the op itself is absent from that protocol.
			return &Response{Status: EPERM}
		}
		s.exact.markReclaimDone(cs)
		return &Response{Gen: s.gen()}
	}
	if s.exact != nil && s.exact.managed {
		// Managed (journaled) routing: NO state-changing operation may reach
		// the legacy in-memory lock manager, delegation manager, open-inode
		// map, orphan lease clock, flush watermark files, or checkpoint
		// path. Every coordination decision journals in the same ordered
		// PFJ3 authority; reads answer from the reconstructed durable state.
		switch req.Op {
		case OpLock:
			if req.LkMode == LkGetlk && req.Env == nil {
				return s.managedGetlk(cs, req) // pure read (durable reducer)
			}
			if req.Env == nil {
				return &Response{Status: EPERM} // journaled exact identity required
			}
			return s.exactCoordinate(cs, req)
		case OpCheckout, OpCheckin, OpMarkOpen:
			if req.Env == nil {
				return &Response{Status: EPERM}
			}
			return s.exactCoordinate(cs, req)
		case OpFlushBatch:
			if s.beforeFlushBatch != nil {
				s.beforeFlushBatch()
			}
			// Serialize per write-back session: the ledger's strict
			// monotonicity would otherwise reject an interleaved retry.
			lk := s.sessionLock(req.SessionID)
			lk.Lock()
			defer lk.Unlock()
			return s.flushBatchManaged(cs, req)
		case OpRenewOrphanLeases, OpRenewOpenInodes:
			// Typed no-ops on managed generations: liveness is owned by the
			// journaled session lease (DB-time facts); wall-clock renewals
			// neither extend nor authorize anything.
			return &Response{Gen: s.gen()}
		case OpUnmarkOpenInodes:
			// Batched last-close unmarks (FeatOpenRegistration): N durable
			// pin releases journal as ONE row under ONE exact identity
			// (replay-exact). Envelope-less requests stay refused — managed
			// pins are journaled coordination state, never liveness.
			if req.Env == nil {
				return &Response{Status: EPERM}
			}
			return s.exactCoordinate(cs, req)
		case OpFsync:
			// The volume sync barrier: every row reserved before this call
			// must be durable, applied, and its invalidations published. A
			// pure barrier — never HistoryCut, snapshot, checkpoint, object
			// storage, peer-cache acknowledgement, or global drain. With an
			// exact identity the barrier is an APPENDED ordered control-only
			// row (replayable exactly); without one (reads-compatible
			// clients) it is the equivalent applied-cursor wait.
			if req.Env != nil {
				return s.coordinateBarrier(cs, req)
			}
			if store := s.coordStore(); store != nil {
				if err := store.SyncBarrier(); err != nil {
					return nil // UNKNOWN/sealed: drop the conn, never a false success
				}
				return &Response{Gen: s.gen()}
			}
			return &Response{Status: EPERM}
		}
	}
	if req.Env != nil {
		// Exact-once mutation path. OpReap counts as a mutation here (it
		// destroys a parked inode) even though v1 never checkout-gated it.
		// The reserved-namespace, reclaim-grace, and checkout gates for this
		// path live INSIDE exactMutate: their rejections must be durably
		// recorded against the identity (under the slot lock, after duplicate
		// detection), or a gate reply would leave "was my identity consumed?"
		// ambiguous and desynchronize the client's slot sequence.
		if s.exact == nil {
			return &Response{Status: EPERM} // exact mutations need a session store
		}
		if !mutatingOp(req.Op) && req.Op != OpReap {
			return &Response{Status: EINVAL} // envelope on a non-mutating op
		}
		return s.registerCreateOpen(cs, req, s.exactMutate(cs, req))
	}
	// Restart/promotion reclaim grace (envelope-less ops): hold off NEW
	// coordination state and mutations until durable prior sessions have
	// re-asserted (or the bounded window elapses). Token-proven prior owners
	// pass; reads always flow.
	if s.reclaimBlocked(cs, req) {
		return &Response{Status: EAGAIN}
	}
	if (mutatingOp(req.Op) || req.Op == OpReap) && s.exactRequired(req) {
		// Fail-closed posture (VCS_REQUIRE_EXACT_SESSIONS=1): refuse legacy
		// envelope-less mutations. The default admits them (compatibility).
		return &Response{Status: EPERM}
	}
	return s.dispatchLegacy(cs, req)
}

// dispatchLegacy serves the stateless v1 op surface.
func (s *Server) dispatchLegacy(cs *connSession, req *Request) *Response {
	// Reserved internal metadata (flush watermarks) lives in-tree for durability but is
	// invisible to clients: a direct client op on a reserved path behaves as if absent.
	// OpFlushBatch is the authority's own internal apply path and is exempt.
	if req.Op != OpFlushBatch && (isReserved(req.Path) || isReserved(req.NewPath)) {
		return &Response{Status: ENOENT}
	}
	if mutatingOp(req.Op) {
		if resp := s.enforceCheckout(req); resp != nil {
			return resp
		}
	}
	switch req.Op {
	case OpFlushBatch:
		if s.beforeFlushBatch != nil {
			s.beforeFlushBatch()
		}
		return s.flushBatch(cs, req)

	case OpLock:
		if s.locks == nil {
			// Managed generations never construct the legacy lock manager;
			// their locks are journaled and dispatch earlier (defense in
			// depth — the managed routing intercepts OpLock before here).
			return &Response{Status: EPERM}
		}
		owner := locks.Owner{Mount: req.Owner, LkID: req.LkID}
		switch req.LkMode {
		case LkGetlk:
			if h, c := s.locks.Getlk(req.Path, owner, req.LkStart, req.LkEnd, req.LkWrite); c {
				return &Response{LkConflict: true, LkStart: h.Start, LkEnd: h.End, LkWrite: h.Write}
			}
			return &Response{} // no conflict
		case LkSetlk:
			ok := s.locks.Setlk(req.Path, owner, req.LkStart, req.LkEnd, req.LkWrite, req.LkUnlock)
			lockf("SETLK path=%q owner=%+v [%d,%d] write=%v unlock=%v -> ok=%v", req.Path, owner, req.LkStart, req.LkEnd, req.LkWrite, req.LkUnlock, ok)
			if ok {
				return &Response{}
			}
			return &Response{Status: EAGAIN}
		case LkSetlkw:
			// Bound each blocking attempt so a dead connection's waiter can't leak; the client
			// re-issues on EAGAIN, so the app still blocks indefinitely (and wakes promptly on
			// release via the lock table's per-path signal).
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			ok := s.locks.Setlkw(ctx, req.Path, owner, req.LkStart, req.LkEnd, req.LkWrite)
			lockf("SETLKW path=%q owner=%+v [%d,%d] write=%v -> ok=%v", req.Path, owner, req.LkStart, req.LkEnd, req.LkWrite, ok)
			if ok {
				return &Response{}
			}
			return &Response{Status: EAGAIN}
		default:
			return &Response{Status: EINVAL}
		}

	case OpGetattr:
		if req.OrphanIno != 0 { // fstat on an unlinked-but-open fd: stat the parked inode by ino
			os, ok := s.orphans()
			if !ok {
				return &Response{Status: EPERM}
			}
			fi, ok := os.OrphanInfo(req.OrphanIno)
			if !ok {
				return &Response{Status: ENOENT}
			}
			a := attrOf(fi)
			return &Response{Attr: &a, Gen: s.gen()}
		}
		if req.HandleIno != 0 {
			hs, ok := s.fs.(HandleStore)
			if !ok {
				return &Response{Status: EPERM}
			}
			fi, err := hs.HandleInfo(req.Path, req.HandleIno)
			if err != nil {
				// toErrno keeps verified absence ENOENT while a lazy-base
				// hydration/transport failure maps to EIO — the client
				// retries the SAME handle instead of discarding it.
				return &Response{Status: toErrno(err)}
			}
			a := attrOf(fi)
			gen, ver := s.versionStampFor(req.Path, req.HandleIno)
			return &Response{Attr: &a, Version: ver, Gen: gen}
		}
		// C1: sample the parent-directory version BEFORE the Lstat, not inside missResponse
		// AFTER it. The serialization argument for a cacheable negative only holds sample-before:
		// a create that lands between this sample and the Lstat makes the Lstat HIT (no negative
		// is produced); a create that lands after the Lstat carries a parent version strictly
		// greater than pv, so its invalidation advances the client's parent version past the
		// stored negative and evicts it. Sampling AFTER the Lstat admitted the fatal interleave —
		// a create bumping the parent in the miss→sample window stamped the negative at the SAME
		// version the create's own invalidation carried, so cachedParentVersion == observed
		// parentVersion served the stale negative forever (no further invalidation ever comes).
		gen, ver := s.versionStamp(req.Path)
		pgen, pv, pvok := s.parentVersion(req.Path)
		fi, err := s.fs.Lstat(req.Path)
		if err != nil {
			return s.missResponse(toErrno(err), pgen, pv, pvok)
		}
		a := attrOf(fi)
		return &Response{Attr: &a, Version: ver, Gen: gen}

	case OpReaddir:
		gen, ver := s.versionStamp(req.Path)
		fis, err := s.fs.ReadDir(req.Path)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		ents := make([]Dirent, 0, len(fis))
		for _, fi := range fis {
			// Hide internal metadata (flush watermarks) — but match the FULL path, not the
			// basename: watermarks are flat root-level files (".portablefs-<session>"), so a user file
			// legitimately named ".portablefs-*" inside a SUBDIRECTORY must still be listed.
			if isReserved(path.Join(req.Path, fi.Name())) {
				continue
			}
			d := Dirent{Name: fi.Name(), Attr: attrOf(fi)}
			if vfi, ok := fi.Sys().(interface{ Version() uint64 }); ok {
				d.Version = vfi.Version() + 1 // +1 so a real version 0 (clean inode) is distinguishable on the wire from a gob-omitted 0 (an authority without readdir-plus); the mount subtracts 1
			}
			ents = append(ents, d)
		}
		return &Response{Entries: ents, Version: ver, Gen: gen}

	case OpRead:
		if req.Size < 0 || req.Size > maxReadBytes {
			return &Response{Status: EINVAL} // bound a wire-supplied size; never allocate unbounded
		}
		if req.OrphanIno != 0 { // open-after-unlink: read the parked inode by ino (its name is gone)
			os, ok := s.orphans()
			if !ok {
				return &Response{Status: EPERM}
			}
			buf := make([]byte, req.Size)
			n, err := os.ReadOrphanAt(req.OrphanIno, buf, req.Offset)
			if err != nil && err != io.EOF {
				return &Response{Status: toErrno(err)}
			}
			return &Response{Data: buf[:n], Gen: s.gen()}
		}
		if req.HandleIno != 0 {
			hs, ok := s.fs.(HandleStore)
			if !ok {
				return &Response{Status: EPERM}
			}
			gen, ver := s.versionStampFor(req.Path, req.HandleIno)
			buf := make([]byte, req.Size)
			n, err := hs.ReadHandleAt(req.Path, req.HandleIno, buf, req.Offset)
			if err != nil && err != io.EOF {
				return &Response{Status: toErrno(err)}
			}
			return &Response{Data: buf[:n], Version: ver, Gen: gen}
		}
		gen, ver := s.versionStamp(req.Path)
		f, err := s.fs.Open(req.Path)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		defer f.Close()
		buf := make([]byte, req.Size)
		n, err := f.ReadAt(buf, req.Offset)
		if err != nil && err != io.EOF {
			return &Response{Status: toErrno(err)}
		}
		return &Response{Data: buf[:n], Version: ver, Gen: gen}

	case OpWrite:
		if len(req.Data) > MaxWriteBytes {
			// Bound the legacy write payload like the exact path, so one
			// request cannot drive a multi-GiB server-side allocation.
			return &Response{Status: EINVAL}
		}
		if req.Append {
			if req.Offset != 0 {
				return &Response{Status: EINVAL}
			}
			as, ok := s.fs.(AtomicAppendStore)
			if !ok {
				return &Response{Status: EOPNOTSUPP}
			}
			if req.OrphanIno != 0 {
				n, off, ver, err := as.AppendOrphanAs(req.OrphanIno, req.Data, req.Owner)
				if err != nil {
					return &Response{Status: toErrno(err)}
				}
				return &Response{Count: int32(n), Offset: off, Version: ver, Gen: s.gen()}
			}
			n, off, ver, err := as.AppendAtHandleExistingAs(req.Path, req.HandleIno, req.Data, req.Owner)
			if err != nil {
				return &Response{Status: toErrno(err)}
			}
			return &Response{Count: int32(n), Offset: off, Version: ver, Gen: s.gen()}
		}
		if req.OrphanIno != 0 { // open-after-unlink: write the parked inode by ino
			os, ok := s.orphans()
			if !ok {
				return &Response{Status: EPERM}
			}
			n, _, err := os.WriteOrphanAt(req.OrphanIno, req.Offset, req.Data, req.Owner)
			if err != nil {
				return &Response{Status: toErrno(err)}
			}
			return &Response{Count: int32(n), Gen: s.gen()}
		}
		// Use the versioned write path so we return the version THIS write produced (captured
		// atomically under the FS lock), never a concurrent writer's re-sampled version. The
		// owner-aware variant ALSO tags the echo with req.Owner so the originating mount source-
		// suppresses it at its subscribe stream — race-free, instead of racing to record the
		// version before the echo lands.
		if o, ok := s.owned(); ok {
			// Non-creating: a write to an absent (just-unlinked/orphaned) path returns ENOENT rather
			// than resurrecting the name. The mount always Creates before its first Write, so only a
			// write racing an unlink lands here on an absent path.
			n, ver, werr := o.WriteAtHandleExistingAs(req.Path, req.HandleIno, req.Offset, req.Data, req.Owner)
			if werr != nil {
				return &Response{Status: toErrno(werr)}
			}
			return &Response{Count: int32(n), Version: ver, Gen: s.gen()}
		}
		if vw, ok := s.fs.(VersionedWriter); ok {
			n, ver, werr := vw.WriteAt(req.Path, req.Offset, req.Data, modebits.FromUnix(req.Mode))
			if werr != nil {
				return &Response{Status: toErrno(werr)}
			}
			return &Response{Count: int32(n), Version: ver, Gen: s.gen()}
		}
		f, err := s.fs.OpenFile(req.Path, os.O_RDWR|os.O_CREATE, modebits.FromUnix(req.Mode))
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		defer f.Close()
		if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
			return &Response{Status: toErrno(err)}
		}
		n, err := f.Write(req.Data)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		gen, ver := s.versionStamp(req.Path)
		return &Response{Count: int32(n), Version: ver, Gen: gen}

	case OpCreate:
		if o, ok := s.owned(); ok {
			if err := o.CreateAs(req.Path, modebits.FromUnix(req.Mode), req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
			return s.registerCreateOpen(cs, req, s.statResponse(req.Path))
		}
		f, err := s.fs.OpenFile(req.Path, os.O_CREATE|os.O_RDWR, modebits.FromUnix(req.Mode))
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		_ = f.Close()
		return s.registerCreateOpen(cs, req, s.statResponse(req.Path))

	case OpMkdir:
		if o, ok := s.owned(); ok {
			if err := o.MutateAs(wal.Record{Op: wal.OpMkdir, Path: req.Path, Mode: modebits.CleanUnix(req.Mode)}, req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
			return s.statResponse(req.Path)
		}
		if err := s.fs.MkdirAll(req.Path, modebits.FromUnix(req.Mode)); err != nil {
			return &Response{Status: toErrno(err)}
		}
		return s.statResponse(req.Path)

	case OpRemove:
		if o, ok := s.owned(); ok {
			// Stage 2: the OpRemove APPLY parks the inode as an orphan instead of removing when any
			// mount holds it open (cross-mount delete-on-last-close); the holder learns the parked ino
			// via the Orphaned invalidation. Same apply path covers a write-back OpRemove via flush.
			if err := o.MutateAs(wal.Record{Op: wal.OpRemove, Path: req.Path}, req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
		} else if err := s.fs.Remove(req.Path); err != nil {
			return &Response{Status: toErrno(err)}
		}
		gen, ver := s.versionStamp(req.Path) // for the originator's self-echo suppression
		return &Response{Version: ver, Gen: gen}

	case OpOrphan:
		// Detach req.Path but PARK its inode (open-after-unlink). The vanished name is published as an
		// invalidation (owner-suppressed for the originator), and the parked ino is returned so the
		// client addresses subsequent reads/writes/reap by it.
		os, ok := s.orphans()
		if !ok {
			return &Response{Status: EPERM}
		}
		ino, err := os.Orphan(req.Path, req.Owner)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		gen, ver := s.versionStamp(req.Path)
		return &Response{OrphanIno: ino, Version: ver, Gen: gen}

	case OpReap:
		os, ok := s.orphans()
		if !ok {
			return &Response{Status: EPERM}
		}
		if err := os.Reap(req.OrphanIno, req.Owner); err != nil {
			return &Response{Status: toErrno(err)}
		}
		return &Response{Gen: s.gen()}

	case OpRenewOrphanLeases:
		os, ok := s.orphans()
		if !ok {
			return &Response{Status: EPERM}
		}
		os.RenewOrphanLeases(req.OrphanInos)
		return &Response{Gen: s.gen()}

	case OpMarkOpen:
		os, ok := s.orphans()
		if !ok {
			return &Response{Status: EPERM}
		}
		if req.OpenState {
			if !os.MarkOpenInode(req.OpenIno, req.Owner) {
				// The inode is gone — the open lost the race to a peer unlink. Tell the mount so it
				// fails the open with ENOENT rather than holding a handle to a destroyed inode.
				return &Response{Status: ENOENT, Gen: s.gen()}
			}
		} else {
			os.UnmarkOpenInode(req.OpenIno, req.Owner)
		}
		return &Response{Gen: s.gen()}

	case OpRenewOpenInodes:
		os, ok := s.orphans()
		if !ok {
			return &Response{Status: EPERM}
		}
		os.RenewOpenInodes(req.OpenInos, req.Owner)
		return &Response{Gen: s.gen()}

	case OpUnmarkOpenInodes:
		// Batched last-close unmarks (FeatOpenRegistration). Each entry has
		// exactly UnmarkOpenInode's semantics; the batch only removes the
		// per-inode round-trips. A close carries no open-vs-unlink guarantee,
		// so deferring/batching unmarks never weakens the contract — until
		// the unmark applies, the authority errs toward parking, and a
		// spuriously parked inode is reclaimed by orphan lease GC.
		os, ok := s.orphans()
		if !ok {
			return &Response{Status: EPERM}
		}
		for _, ino := range req.OpenInos {
			os.UnmarkOpenInode(ino, req.Owner)
		}
		return &Response{Gen: s.gen()}

	case OpRename:
		var orphanIno uint64
		if req.OrphanTarget { // rename-over-an-open-file: park the replaced destination by ino
			os, ok := s.orphans()
			if !ok {
				return &Response{Status: EPERM}
			}
			ino, err := os.RenameWithOrphanTarget(req.Path, req.NewPath, true, req.Owner)
			if err != nil {
				return &Response{Status: toErrno(err)}
			}
			orphanIno = ino
		} else if o, ok := s.owned(); ok {
			if err := o.MutateAs(wal.Record{Op: wal.OpRename, Path: req.Path, NewPath: req.NewPath}, req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
		} else if err := s.fs.Rename(req.Path, req.NewPath); err != nil {
			return &Response{Status: toErrno(err)}
		}
		gen, ver := s.versionStamp(req.NewPath) // new path's version; originator suppresses its echo
		return &Response{OrphanIno: orphanIno, Version: ver, Gen: gen}

	case OpSymlink:
		if o, ok := s.owned(); ok {
			if err := o.MutateAs(wal.Record{Op: wal.OpSymlink, Path: req.Path, Target: req.Target}, req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
			return s.statResponse(req.Path)
		}
		if err := s.fs.Symlink(req.Target, req.Path); err != nil {
			return &Response{Status: toErrno(err)}
		}
		return s.statResponse(req.Path)

	case OpLink:
		h, ok := s.hardLinks()
		if !ok {
			return &Response{Status: EOPNOTSUPP}
		}
		if err := h.LinkAs(req.Path, req.NewPath, req.Owner); err != nil {
			return &Response{Status: toErrno(err)}
		}
		return s.statResponse(req.NewPath)

	case OpReadlink:
		gen, ver := s.versionStamp(req.Path)
		t, err := s.fs.Readlink(req.Path)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		return &Response{Target: t, Version: ver, Gen: gen}

	case OpGetxattr:
		xs, ok := s.xattrs()
		if !ok {
			return &Response{Status: EOPNOTSUPP}
		}
		if st := validateXattrRequest(req); st != OK {
			return &Response{Status: st}
		}
		// Sample the version BEFORE the read (lower bound on the bytes'
		// true version), exactly like OpRead.
		gen, ver := s.versionStampFor(req.Path, req.HandleIno)
		value, err := xs.GetxattrHandle(req.Path, req.HandleIno, req.XattrName)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		return &Response{Data: value, Version: ver, Gen: gen}

	case OpListxattr:
		xs, ok := s.xattrs()
		if !ok {
			return &Response{Status: EOPNOTSUPP}
		}
		gen, ver := s.versionStampFor(req.Path, req.HandleIno)
		names, err := xs.ListxattrHandle(req.Path, req.HandleIno)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		return &Response{XattrNames: names, Version: ver, Gen: gen}

	case OpSetxattr, OpRemovexattr:
		if _, ok := s.xattrs(); !ok {
			return &Response{Status: EOPNOTSUPP}
		}
		if st := validateXattrRequest(req); st != OK {
			return &Response{Status: st}
		}
		if req.Op == OpSetxattr && req.XattrFlags != 0 && !s.supportsAtomicXattrFlags() {
			return &Response{Status: EOPNOTSUPP}
		}
		o, ok := s.owned()
		if !ok {
			return &Response{Status: EOPNOTSUPP} // read-only/test fs: no journaled xattr apply
		}
		rec := wal.Record{
			Op: wal.OpSetxattr, Path: req.Path, Ino: req.HandleIno,
			XattrName: req.XattrName, XattrFlags: req.XattrFlags, Data: req.Data,
		}
		if req.Op == OpRemovexattr {
			if req.XattrFlags != 0 {
				return &Response{Status: EINVAL}
			}
			rec = wal.Record{Op: wal.OpRemovexattr, Path: req.Path, Ino: req.HandleIno, XattrName: req.XattrName}
		}
		if err := o.MutateAs(rec, req.Owner); err != nil {
			return &Response{Status: toErrno(err)}
		}
		gen, ver := s.versionStampFor(req.Path, req.HandleIno)
		return &Response{Version: ver, Gen: gen}

	case OpTruncate:
		if req.OrphanIno != 0 { // open-after-unlink: ftruncate the parked inode by ino
			os, ok := s.orphans()
			if !ok {
				return &Response{Status: EPERM}
			}
			if err := os.TruncateOrphanAt(req.OrphanIno, req.Size, req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
			return &Response{Gen: s.gen()}
		}
		if o, ok := s.owned(); ok {
			if err := o.TruncateHandleAs(req.Path, req.HandleIno, req.Size, req.Owner); err != nil {
				return &Response{Status: toErrno(err)}
			}
			gen, ver := s.versionStampFor(req.Path, req.HandleIno)
			return &Response{Version: ver, Gen: gen}
		}
		f, err := s.fs.OpenFile(req.Path, os.O_RDWR, 0)
		if err != nil {
			return &Response{Status: toErrno(err)}
		}
		defer f.Close()
		if err := f.Truncate(req.Size); err != nil {
			return &Response{Status: toErrno(err)}
		}
		gen, ver := s.versionStamp(req.Path) // for the originator's self-echo suppression
		return &Response{Version: ver, Gen: gen}

	case OpSetattr:
		ch, ok := s.fs.(billy.Change)
		if !ok {
			return &Response{Status: EPERM} // read-only fs
		}
		o, owned := s.owned() // owner-aware path source-suppresses each attr echo at the originator
		if req.SetMode {
			if owned {
				if err := o.MutateAs(wal.Record{Op: wal.OpChmod, Path: req.Path, Ino: req.HandleIno, Mode: modebits.CleanUnix(req.Mode)}, req.Owner); err != nil {
					return &Response{Status: toErrno(err)}
				}
			} else if err := ch.Chmod(req.Path, modebits.FromUnix(req.Mode)); err != nil {
				return &Response{Status: toErrno(err)}
			}
		}
		if req.SetTime {
			if owned {
				if err := o.MutateAs(wal.Record{Op: wal.OpChtimes, Path: req.Path, Ino: req.HandleIno, MtimeMs: req.MtimeMs}, req.Owner); err != nil {
					return &Response{Status: toErrno(err)}
				}
			} else {
				t := time.UnixMilli(req.MtimeMs)
				if err := ch.Chtimes(req.Path, t, t); err != nil {
					return &Response{Status: toErrno(err)}
				}
			}
		}
		if req.SetUID || req.SetGID {
			uid, gid := -1, -1 // -1 = leave unchanged (POSIX)
			if req.SetUID {
				uid = int(req.UID)
			}
			if req.SetGID {
				gid = int(req.GID)
			}
			if owned {
				if err := o.ChownHandleAs(req.Path, req.HandleIno, uid, gid, req.Owner); err != nil {
					return &Response{Status: toErrno(err)}
				}
			} else if err := ch.Chown(req.Path, uid, gid); err != nil {
				return &Response{Status: toErrno(err)}
			}
		}
		return s.statResponseFor(req.Path, req.HandleIno)

	case OpCheckout:
		if s.deleg == nil {
			return &Response{Status: EPERM}
		}
		if granted, _ := s.deleg.Checkout(req.Path, req.Owner); granted {
			trace(evCheckoutOK, tag(req.Path), tag(req.Owner), 0, 0, 0)
			return &Response{}
		}
		// Contended by another owner. The delegation handoff: RECALL the CURRENT holder (broadcast over
		// the subscriber stream — the holder flushes its buffered writes + checks in), wait for it to
		// relinquish, then grant. We LOOP: if a different contender wins the freed checkout first, we
		// recall THAT new holder in turn rather than force-revoking it — a fresh legitimate holder is
		// never force-revoked, only one that won't relinquish within the deadline (presumed dead) is.
		// The whole loop is bounded by recallTimeout (< opTimeout), so this RPC always returns.
		trace(evCheckoutBusy, tag(req.Path), tag(req.Owner), 0, 0, 0)
		if s.recaller != nil {
			deadline := time.Now().Add(recallTimeout)
			for time.Now().Before(deadline) {
				holder, at := s.deleg.HeldBy(req.Path)
				if holder == "" {
					// Momentarily free — try to grab it. If another contender beat us, re-observe.
					if granted, _ := s.deleg.Checkout(req.Path, req.Owner); granted {
						trace(evCheckoutOK, tag(req.Path), tag(req.Owner), 0, 0, 0)
						return &Response{}
					}
					continue
				}
				lockf("RECALL path=%q contender=%q (held by %q at %q)", req.Path, req.Owner, holder, at)
				s.recaller.PublishRecall(req.Path)
				ctx, cancel := context.WithTimeout(context.Background(), time.Until(deadline))
				freed := s.deleg.AwaitFree(ctx, req.Path)
				cancel()
				if !freed {
					break // current holder never relinquished within the deadline → force-revoke below
				}
				if granted, _ := s.deleg.Checkout(req.Path, req.Owner); granted {
					trace(evCheckoutOK, tag(req.Path), tag(req.Owner), 0, 0, 0)
					return &Response{}
				}
				// A fresh contender grabbed it between AwaitFree and our Checkout: loop to recall it.
			}
		}
		// No recaller, or the holder stayed unresponsive past the deadline (presumed dead): revoke it
		// and grant. ForceCheckout fences the revoked owner so its in-flight flush cannot apply later.
		s.deleg.ForceCheckout(req.Path, req.Owner)
		trace(evCheckoutOK, tag(req.Path), tag(req.Owner), 0, 0, 0)
		return &Response{}

	case OpCheckin:
		if s.deleg == nil {
			return &Response{Status: EPERM}
		}
		if !s.deleg.Checkin(req.Path, req.Owner) {
			trace(evCheckinNo, tag(req.Path), tag(req.Owner), 0, 0, 0)
			return &Response{Status: ENOENT} // not held by this owner
		}
		trace(evCheckinOK, tag(req.Path), tag(req.Owner), 0, 0, 0)
		return &Response{}

	case OpFsync:
		return &Response{} // durability is the VCS checkpoint's job

	default:
		return &Response{Status: EINVAL}
	}
}

func (s *Server) statResponse(path string) *Response {
	return s.statResponseFor(path, 0)
}

func (s *Server) statResponseFor(path string, ino uint64) *Response {
	if ino != 0 {
		hs, ok := s.fs.(HandleStore)
		if !ok {
			return &Response{Status: EPERM}
		}
		fi, err := hs.HandleInfo(path, ino)
		if err != nil {
			return &Response{Status: toErrno(err)} // ENOENT only for verified absence
		}
		a := attrOf(fi)
		gen, ver := s.versionStampFor(path, ino)
		return &Response{Attr: &a, Version: ver, Gen: gen}
	}
	fi, err := s.fs.Lstat(path)
	if err != nil {
		return &Response{Status: toErrno(err)}
	}
	a := attrOf(fi)
	// Carry the version this mutation produced so the ORIGINATING mount can record it and suppress
	// its own invalidation echo (a write-through create/mkdir/symlink/setattr otherwise NOTIFY-
	// invalidates its OWN just-created path — and if that path is an in-use CWD directory, the
	// mount's getcwd() fails ENOENT → SQLITE_CANTOPEN). Mirrors how OpWrite returns its version.
	gen, ver := s.versionStamp(path)
	return &Response{Attr: &a, Version: ver, Gen: gen}
}
