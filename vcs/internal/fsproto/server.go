package fsproto

import (
	"context"
	"encoding/gob"
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

	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
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
	OpGetattr:                  "getattr",
	OpReaddir:                  "readdir",
	OpRead:                     "read",
	OpWrite:                    "write",
	OpCreate:                   "create",
	OpMkdir:                    "mkdir",
	OpRemove:                   "remove",
	OpRename:                   "rename",
	OpSymlink:                  "symlink",
	OpReadlink:                 "readlink",
	OpTruncate:                 "truncate",
	OpFsync:                    "fsync",
	OpSubscribe:                "subscribe",
	OpSetattr:                  "setattr",
	OpCheckout:                 "checkout",
	OpCheckin:                  "checkin",
	OpFlushBatch:               "flush_batch",
	OpLock:                     "lock",
	OpOrphan:                   "orphan",
	OpReap:                     "reap",
	OpRenewOrphanLeases:        "renew_orphan_leases",
	OpMarkOpen:                 "mark_open",
	OpRenewOpenInodes:          "renew_open_inodes",
	OpUnmarkOpenInodes:         "unmark_open_inodes",
	OpGetxattr:                 "getxattr",
	OpSetxattr:                 "setxattr",
	OpListxattr:                "listxattr",
	OpRemovexattr:              "removexattr",
	OpLink:                     "link",
	OpDelegationAcquire:        "delegation_acquire",
	OpWritebackState:           "writeback_state",
	OpWritebackRebind:          "writeback_rebind",
	OpWritebackDiscard:         "writeback_discard",
	OpInvalidationAck:          "invalidation_ack",
	OpDelegationPrepareRelease: "delegation_prepare_release",
	OpProtocolVersion:          "protocol_version",
	OpSessionOpen:              "session_open",
	OpSessionResume:            "session_resume",
	OpSessionAttach:            "session_attach",
	OpSessionExpire:            "session_expire",
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
// (lazy block reads, journal, single authority) lives behind that interface,
// so the server is a pure translation layer. The optional Notifier supplies
// cache invalidations to push to subscribed clients.
type Server struct {
	fs       billy.Filesystem
	notifier Notifier
	recaller Recaller // broadcasts checkout-contention recall HINTS to subscribers (nil ⇒ no hint)
	token    string   // data-plane auth token (VCS_AUTH_TOKEN); "" = no handshake
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	// exact is the exact-mount-session machinery, non-nil iff fs is a
	// workfs-style (managed) SessionStore. Every mutation requires an exact
	// envelope; a server without a session store serves reads only.
	exact *exactState
	// hookMu guards the mutable test seams below. Production leaves every
	// hook nil, but tests deliberately replace them while requests are live
	// to model transport failures and handoff races.
	hookMu sync.RWMutex
	// beforeFlushBatch is a test seam used to stall OpFlushBatch for fsync/barrier tests.
	// Nil in production.
	beforeFlushBatch func()
	// beforeDelegationPrepare is a test seam used to stall the open-path pin
	// phase while proving frontend closes remain live. Nil in production.
	beforeDelegationPrepare func()
	// dropReply is a test seam simulating a LOST RESPONSE: the request is
	// fully applied, but when dropReply returns true the connection is
	// dropped instead of replying — exactly the failure the exact-once replay
	// machinery exists for. Nil in production.
	dropReply func(req *Request, resp *Response) bool
	// flushShard serializes a write-back session's flush ledger read + apply
	// so they form one atomic critical section per SessionID. Sharded by
	// SessionID hash to bound memory (same id ⇒ same shard ⇒ serialized;
	// cross-session sharing is harmless extra serialization).
	flushShard [64]sync.Mutex
	// delegations tracks the volatile adaptive-policy inputs (recent access,
	// contention recalls). Grant ownership itself is durable PFC2 state.
	delegations delegationPolicy

	// Live invalidation subscribers and their acknowledged stream positions.
	// An authority barrier (fsync/synchronize/unmount) waits until every
	// live subscriber's observed position covers the barrier's mutations;
	// ackWake broadcasts progress (position acked, batch suppressed, or
	// subscriber dropped) to waiting barriers.
	subMu       sync.Mutex
	subscribers map[*subscriberState]struct{}
	ackWake     chan struct{}
}

// subscriberState is one live invalidation stream's delivery/ack cursor.
// Fields are guarded by Server.subMu.
type subscriberState struct {
	conn      net.Conn
	sent      uint64 // last position offered to the connection
	acked     uint64 // last position the client cumulatively acknowledged
	bootstrap uint64 // position covered by the fresh-subscribe cache reset
	ready     bool   // bootstrap was acknowledged after client cache application
}

// observedLocked is the position this subscriber claims to have incorporated.
// A fresh subscriber proves nothing until it acknowledges the bootstrap cache
// reset. There is deliberately no send-time or owner-suppression shortcut:
// only a valid client application ack advances coherence.
func (ss *subscriberState) observedLocked() uint64 {
	if !ss.ready {
		return 0
	}
	return ss.acked
}

// SetBeforeFlushBatch installs a test hook that runs immediately before an OpFlushBatch is applied.
func (s *Server) SetBeforeFlushBatch(fn func()) {
	s.hookMu.Lock()
	s.beforeFlushBatch = fn
	s.hookMu.Unlock()
}

func (s *Server) SetBeforeDelegationPrepare(fn func()) {
	s.hookMu.Lock()
	s.beforeDelegationPrepare = fn
	s.hookMu.Unlock()
}

// SetDropReply installs a test hook that, when it returns true for an applied
// request, drops the connection WITHOUT sending the response (a lost reply).
func (s *Server) SetDropReply(fn func(req *Request, resp *Response) bool) {
	s.hookMu.Lock()
	s.dropReply = fn
	s.hookMu.Unlock()
}

func (s *Server) currentDropReply() func(req *Request, resp *Response) bool {
	s.hookMu.RLock()
	defer s.hookMu.RUnlock()
	return s.dropReply
}

func (s *Server) currentBeforeFlushBatch() func() {
	s.hookMu.RLock()
	defer s.hookMu.RUnlock()
	return s.beforeFlushBatch
}

func (s *Server) currentBeforeDelegationPrepare() func() {
	s.hookMu.RLock()
	defer s.hookMu.RUnlock()
	return s.beforeDelegationPrepare
}

func (s *Server) sessionLock(id string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return &s.flushShard[h.Sum32()%uint32(len(s.flushShard))]
}

// NewServer returns a Server backed by fs. notifier may be nil (read-only
// fs). When fs implements SessionStore (workfs.FS), exact mount sessions and
// journaled coordination are served; the store must be MANAGED and must
// implement the coordination surface. A server without a session store
// serves reads only — every mutation requires an exact envelope.
func NewServer(fs billy.Filesystem, notifier Notifier) *Server {
	s := &Server{
		fs:          fs,
		notifier:    notifier,
		token:       secure.AuthToken(),
		conns:       map[net.Conn]struct{}{},
		subscribers: map[*subscriberState]struct{}{},
		ackWake:     make(chan struct{}),
	}
	if store, ok := fs.(SessionStore); ok {
		s.exact = newExactState(store)
		if _, ok := fs.(CoordinationStore); !ok {
			panic("fsproto: managed session store lacks the coordination surface")
		}
	}
	// The writable authority FS broadcasts recall hints over the same subscriber fan-out it uses
	// for invalidations; wire it up when present so contention nudges the holder to hand off.
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
	dec := newRequestDecoder(conn)
	enc := gob.NewEncoder(conn)
	cs := &connSession{}
	for {
		// Idle bound between requests: a peer that authenticates then stalls
		// (sends nothing / a slow-loris request) cannot pin this goroutine and
		// its request buffers forever. Reset each iteration; generous vs opTimeout.
		_ = conn.SetReadDeadline(time.Now().Add(serverIdleTimeout))
		var req Request
		if err := dec.Decode(&req); err != nil {
			return // peer closed, idle-timed-out, oversize, or stream error
		}
		if req.Op == OpSubscribe {
			fsprotoOps.Inc()
			countOp(req.Op)
			// Owner is coordination identity, not a client-selected stream
			// decoration. When supplied, it must match the session already
			// authenticated onto this connection. Unattached read-only/test
			// subscribers have no authenticated owner to bind, and no
			// owner-based coherence shortcut exists for them.
			if cs.attached() && req.Owner != "" && req.Owner != cs.owner {
				return
			}
			// The invalidation stream manages its own read/write deadlines and
			// heartbeats; clear the idle bound before handing off.
			_ = conn.SetReadDeadline(time.Time{})
			s.stream(conn, enc, dec)
			return // the connection becomes an invalidation stream (acks flow back)
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
		if dropReply := s.currentDropReply(); dropReply != nil && dropReply(&req, resp) {
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

// stream turns the connection into a server-push channel of invalidations
// (with client→server position acknowledgments flowing back) until the
// client disconnects (or the server shuts the conn). Dropping the stream
// releases NOTHING: coordination state is owned by the journaled session
// lease, and cleanup happens only on durable lease expiry or voluntary
// session expire — but the DROPPED subscriber leaves the barrier-ack set, so
// a dead peer never blocks barriers (its next attach resubscribes fresh and
// cannot serve stale).
func (s *Server) stream(conn net.Conn, enc *gob.Encoder, dec *requestDecoder) {
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
	// The bootstrap starts at the CURRENT published position, but does not
	// count as observed until the client confirms that it flushed every
	// cache. Register first so no mutation can slip between the position
	// snapshot and subscriber membership.
	ss := &subscriberState{conn: conn}
	s.subMu.Lock()
	start := s.notifier.InvalidationPosition()
	ss.sent = start
	ss.bootstrap = start
	s.subscribers[ss] = struct{}{}
	s.subMu.Unlock()
	defer func() {
		s.subMu.Lock()
		delete(s.subscribers, ss)
		s.wakeBarriersLocked()
		s.subMu.Unlock()
	}()
	// Announce the generation so the client refreshes (drops all cached versions) before applying
	// any versioned invalidation from this — possibly freshly restarted/promoted — authority.
	_ = conn.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	if err := enc.Encode(&Response{Keepalive: true, Gen: gen, InvPos: start, InvBootstrap: true}); err != nil {
		return
	}
	// Read position acknowledgments until the client closes the conn.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var ack Request
			if err := dec.Decode(&ack); err != nil {
				return
			}
			if ack.Op != OpInvalidationAck {
				return // protocol violation: only acks ride the stream
			}
			s.subMu.Lock()
			if ack.AckPos > ss.sent {
				// An ack for bytes the server never offered is impossible.
				// Drop the subscriber rather than allowing a forged future
				// cursor to satisfy this or every later barrier.
				delete(s.subscribers, ss)
				s.wakeBarriersLocked()
				s.subMu.Unlock()
				_ = conn.Close()
				return
			}
			if !ss.ready && ack.AckPos >= ss.bootstrap {
				ss.ready = true
			}
			if ack.AckPos > ss.acked {
				ss.acked = ack.AckPos
			}
			s.wakeBarriersLocked()
			s.subMu.Unlock()
		}
	}()
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
			s.subMu.Lock()
			if batch.Pos > ss.sent {
				ss.sent = batch.Pos
			}
			s.subMu.Unlock()
			// Own echoes are intentionally delivered too. The version gates
			// make them cheap to apply, and a real post-application ack is the
			// only trustworthy barrier accounting event.
			resp = Response{Invs: batch.Invs, Gen: gen, InvPos: batch.Pos}
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

// barrierAckWait bounds how long an authority barrier waits for every live
// subscriber to acknowledge the barrier's invalidation position. A live-but-
// slow subscriber that misses it fails the barrier (EIO) rather than letting
// it silently succeed; a DEAD subscriber is dropped by the stream machinery
// (write timeout / read error) and stops counting. A var so tests compress
// it; production never changes it.
var barrierAckWait = 20 * time.Second

// wakeBarriersLocked broadcasts subscriber-ack progress. Caller holds subMu.
func (s *Server) wakeBarriersLocked() {
	close(s.ackWake)
	s.ackWake = make(chan struct{})
}

// awaitSubscriberAcks blocks until every LIVE subscriber's observed
// invalidation position covers target, a subscriber set change makes that
// true, or the barrier-ack deadline expires (EIO). This is the cross-machine
// half of every fsync/synchronize/unmount barrier: on success, every
// currently-connected peer has processed the invalidations for the barrier's
// mutations, so its subsequent reads cannot be stale.
func (s *Server) awaitSubscriberAcks(target uint64) int32 {
	if s.notifier == nil || target == 0 {
		return OK
	}
	deadline := time.Now().Add(barrierAckWait)
	for {
		s.subMu.Lock()
		pending := false
		for ss := range s.subscribers {
			if ss.observedLocked() < target {
				pending = true
				break
			}
		}
		wake := s.ackWake
		s.subMu.Unlock()
		if !pending {
			return OK
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			// One failed barrier is the typed verdict for this cohort. Evict
			// every laggard so a read-but-never-ack peer cannot wedge all
			// future fsyncs. Closing the stream makes conforming clients flush
			// and bootstrap afresh before rejoining the ack set.
			var laggards []net.Conn
			s.subMu.Lock()
			for ss := range s.subscribers {
				if ss.observedLocked() < target {
					delete(s.subscribers, ss)
					laggards = append(laggards, ss.conn)
				}
			}
			s.wakeBarriersLocked()
			s.subMu.Unlock()
			for _, conn := range laggards {
				_ = conn.Close()
			}
			return EIO
		}
		if remain > time.Second {
			remain = time.Second
		}
		select {
		case <-wake:
		case <-time.After(remain):
		}
	}
}

// mutatingOps are the ops that change the tree; they require an exact
// envelope. Reads/stat/readlink/subscribe are not.
func mutatingOp(op Op) bool {
	switch op {
	case OpWrite, OpCreate, OpMkdir, OpRemove, OpRename, OpSymlink, OpLink, OpTruncate, OpSetattr, OpOrphan,
		OpSetxattr, OpRemovexattr:
		// OpOrphan detaches a named path. OpReap is NOT here: it targets
		// a parked inode by ino, which has no path to gate on.
		// OpSetxattr/OpRemovexattr are attr-level mutations;
		// OpGetxattr/OpListxattr are pure reads.
		return true
	}
	return false
}

// reservedPrefix marks internal authority metadata kept IN the tree (a
// historical reservation for the legacy hidden flush-watermark files) and
// still hidden from clients so no volume ever aliases it.
const reservedPrefix = ".portablefs-"

// isReserved reports whether p resolves to internal authority metadata. It CANONICALIZES p the
// same way the workfs does before resolving an inode (path.Clean + trim) — otherwise a client
// could slip past this guard with traversal ("x/../.portablefs-<id>") yet still hit the reserved file,
// reading/writing/deleting a flush watermark and breaking exactly-once.
func isReserved(p string) bool {
	return strings.HasPrefix(strings.Trim(path.Clean("/"+p), "/"), reservedPrefix)
}

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

// OrphanStore is the authority FS's open-after-unlink READ view (workfs.FS):
// serve reads against a parked (unlinked-but-open) inode by its stable ino.
// Orphan/reap/pin MUTATIONS ride the exact envelope and journaled
// coordination paths, never this surface. A read-only or test fs need not
// implement it; the server then rejects orphan reads.
type OrphanStore interface {
	ReadOrphanAt(ino uint64, p []byte, off int64) (int, error)
	OrphanInfo(ino uint64) (os.FileInfo, bool)
}

// orphans returns the fs's open-after-unlink view (workfs.FS), or false for a fs that does not
// support it (the caller then returns EPERM for orphan ops).
func (s *Server) orphans() (OrphanStore, bool) {
	o, ok := s.fs.(OrphanStore)
	return o, ok
}

// XattrStore is the authority FS's extended-attribute READ surface
// (workfs.FS): resolve by stable ino when non-zero (named or parked orphan),
// else by path. Mutations ride the exact-once MutateEnv path, never a
// separate surface.
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

// InodeMetadataStore lets a filesystem DECLINE the durable per-inode metadata
// PortableFS otherwise assumes: BSD file flags and birth time, both fields of
// the same PFT2 inode record revision (FeatureFlagPersistence).
//
// Unlike the other capability interfaces this one defaults to TRUE when it is
// not implemented, because the record revision is part of the v2 baseline tree
// format — every authority backed by it stores both fields. The interface
// exists so a store that is NOT backed by it (and the tests that model an
// authority predating the revision, whose clients must keep refusing chflags
// honestly) can say so instead of advertising a durability it does not have.
type InodeMetadataStore interface {
	PersistsInodeMetadata() bool
}

func (s *Server) persistsInodeMetadata() bool {
	m, ok := s.fs.(InodeMetadataStore)
	return !ok || m.PersistsInodeMetadata()
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

// registerCreateOpen fuses open registration into a successful OpCreate
// reply (Request.RegisterOpen). The kernel CREATE is create+open, so the
// hold is recorded — as a durable journaled open-pin coordination row —
// before the reply leaves the server: once create returns to the
// application, a concurrent peer unlink sees the pin and parks instead of
// destroying. If the just-created inode is already gone (a peer unlink won
// inside this window), the reply degrades to ENOENT exactly as a separate
// MarkOpen would have. Runs on fresh executions AND duplicate exact replays.
func (s *Server) registerCreateOpen(cs *connSession, req *Request, resp *Response) *Response {
	if resp == nil || !req.RegisterOpen || req.Op != OpCreate || resp.Status != OK {
		return resp
	}
	return s.registerCreateOpenManaged(cs, req, resp)
}

// gen returns the authority's coherence generation nonce (0 for a non-versioned fs).
func (s *Server) gen() uint64 {
	if v, ok := s.fs.(Versioned); ok {
		return v.Generation()
	}
	return 0
}

// notifierPosition reads the highest published invalidation position (0
// without a notifier).
func (s *Server) notifierPosition() uint64 {
	if s.notifier == nil {
		return 0
	}
	return s.notifier.InvalidationPosition()
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

// dispatch runs one request exactly as a fresh stateless legacy connection
// would — the same admission gates as the wire path, minus request framing.
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
		// client's version; anything but exactly ProtocolVersion is refused.
		return s.probeResponse(req.Size)
	case OpSessionOpen:
		return s.sessionOpen(cs, req)
	case OpSessionResume:
		return s.sessionResume(cs, req)
	case OpSessionAttach:
		return s.sessionAttach(cs, req)
	case OpSessionExpire:
		return s.sessionExpire(cs, req)
	}
	if s.exact != nil {
		// Journaled coordination routing: every coordination decision
		// journals in the same ordered PFJ3 authority; reads answer from the
		// reconstructed durable state.
		switch req.Op {
		case OpLock:
			if req.LkMode == LkGetlk && req.Env == nil {
				return s.managedGetlk(cs, req) // pure read (durable reducer)
			}
			if req.Env == nil {
				return &Response{Status: EPERM} // journaled exact identity required
			}
			return s.exactCoordinate(cs, req)
		case OpDelegationAcquire, OpWritebackRebind, OpWritebackDiscard:
			if req.Env == nil {
				return &Response{Status: EPERM}
			}
			return s.exactCoordinate(cs, req)
		case OpDelegationPrepareRelease:
			// Idempotent two-phase handoff: pins are durable while the exact
			// delegation remains held; only the later Checkin releases it.
			if before := s.currentBeforeDelegationPrepare(); before != nil {
				before()
			}
			return s.prepareDelegationRelease(cs, req)
		case OpWritebackState:
			return s.writebackStateRead(req)
		case OpCheckout, OpCheckin, OpMarkOpen:
			if req.Env == nil {
				return &Response{Status: EPERM}
			}
			return s.exactCoordinate(cs, req)
		case OpFlushBatch:
			if before := s.currentBeforeFlushBatch(); before != nil {
				before()
			}
			// Serialize per write-back session: the ledger's strict
			// monotonicity would otherwise reject an interleaved retry.
			lk := s.sessionLock(req.SessionID)
			lk.Lock()
			defer lk.Unlock()
			return s.flushBatchManaged(cs, req)
		case OpRenewOrphanLeases, OpRenewOpenInodes:
			// Typed no-ops: liveness is owned by the journaled session lease
			// (DB-time facts); wall-clock renewals neither extend nor
			// authorize anything.
			return &Response{Gen: s.gen()}
		case OpUnmarkOpenInodes:
			// Batched last-close unmarks: N durable pin releases journal as
			// ONE row under ONE exact identity (replay-exact).
			// Envelope-less requests are refused — pins are journaled
			// coordination state, never liveness.
			if req.Env == nil {
				return &Response{Status: EPERM}
			}
			return s.exactCoordinate(cs, req)
		case OpFsync:
			// The volume sync barrier: every row reserved before this call
			// must be durable, applied, and its invalidations published —
			// AND every live subscriber must have acknowledged processing
			// those invalidations, so a completed barrier is immediately
			// visible to every connected peer's subsequent reads. A pure
			// barrier otherwise — never HistoryCut, snapshot, checkpoint,
			// object storage, or global drain. With an exact identity the
			// barrier is an APPENDED ordered control-only row (replayable
			// exactly); without one (reads-only clients) it is the
			// equivalent applied-cursor wait.
			if req.Env != nil {
				return s.coordinateBarrier(cs, req)
			}
			if store := s.coordStore(); store != nil {
				if err := store.SyncBarrier(); err != nil {
					return nil // UNKNOWN/sealed: drop the conn, never a false success
				}
				if st := s.awaitSubscriberAcks(s.notifierPosition()); st != OK {
					return &Response{Status: st, Gen: s.gen()}
				}
				return &Response{Gen: s.gen()}
			}
			return &Response{Status: EPERM}
		}
	}
	if req.Env != nil {
		// Exact-once mutation path. OpReap carries an envelope for identity
		// accounting even though its rejection is deterministic. The
		// reserved-namespace gate for this path lives INSIDE exactMutate:
		// its rejections must be durably recorded against the identity
		// (under the slot lock, after duplicate detection), or a gate reply
		// would leave "was my identity consumed?" ambiguous and
		// desynchronize the client's slot sequence.
		if s.exact == nil {
			return &Response{Status: EPERM} // exact mutations need a session store
		}
		if !mutatingOp(req.Op) && req.Op != OpReap {
			return &Response{Status: EINVAL} // envelope on a non-mutating op
		}
		return s.registerCreateOpen(cs, req, s.exactMutate(cs, req))
	}
	if mutatingOp(req.Op) || req.Op == OpReap {
		// Envelope-less mutations do not exist in the v8 baseline: every
		// mutation carries an exact-once identity. An old client that
		// ignored the probe's version refusal fails closed here.
		return &Response{Status: EPERM}
	}
	if s.exact != nil {
		switch req.Op {
		case OpGetattr, OpReaddir, OpRead, OpReadlink, OpGetxattr, OpListxattr:
			if req.OrphanIno == 0 {
				// A peer read overlapping a delegation waits for recall; it
				// is never answered from stale pre-delegation state. The
				// holder's own reads pass (base reads under the grant).
				if st := s.delegationGate(cs, true, req.Path); st != OK {
					return &Response{Status: st}
				}
			}
		}
	}
	return s.dispatchRead(req)
}

// dispatchRead serves the stateless read surface (shared by the managed
// authority and reads-only test servers).
func (s *Server) dispatchRead(req *Request) *Response {
	// Reserved internal metadata stays invisible to clients: a direct client
	// op on a reserved path behaves as if absent.
	if isReserved(req.Path) || isReserved(req.NewPath) {
		return &Response{Status: ENOENT}
	}
	switch req.Op {
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
			// Hide reserved metadata — but match the FULL path, not the
			// basename: the reservation is flat root-level names, so a user file
			// legitimately named ".portablefs-*" inside a SUBDIRECTORY must still be listed.
			if isReserved(path.Join(req.Path, fi.Name())) {
				continue
			}
			d := Dirent{Name: fi.Name(), Attr: attrOf(fi)}
			if vfi, ok := fi.Sys().(interface{ Version() uint64 }); ok {
				d.Version = vfi.Version() + 1 // +1 so a real version 0 (clean inode) is distinguishable on the wire from a gob-omitted 0; the mount subtracts 1
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

	case OpFsync:
		// Reads-only test servers have no journal; the managed barrier
		// dispatched earlier.
		return &Response{}

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
