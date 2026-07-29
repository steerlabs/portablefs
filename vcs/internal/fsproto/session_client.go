package fsproto

// Exact mount sessions, client side.
//
// The client mints a stable random session identity (id + token) once per
// mount instance, establishes it durably on the authority, and stamps every
// write-through mutation with an exact-once identity: (session, generation,
// slot, slot sequence). Slots bound concurrency; each slot carries at most one
// in-flight identity, and its sequence advances ONLY on a definite reply.
//
// A request whose outcome is UNKNOWN (connection died after the request may
// have durably prepared) is PARKED: a background replayer resends the
// IDENTICAL identity — never a fresh one — until the authority answers
// definitively (executed exactly once, or the stored duplicate outcome, or a
// fence). The slot stays unavailable meanwhile, so the identity can never be
// reused for different bytes.
//
// A fenced/expired session never re-establishes a fresh generation by itself:
// every subsequent mutation fails ESTALE until the operator remounts. That is
// deliberate — an automatic new generation would let a zombie mount overwrite
// state a successor already took over.
//
// Sessions are mandatory: the client requires the authority to negotiate
// exactly ProtocolVersion (v7) and refuses anything else with a clear
// version-mismatch error. There is no legacy downgrade.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// DefaultExactSlots bounds a mount's concurrent in-flight exact mutations.
const DefaultExactSlots = 64

// exactForegroundAttempts is how many transport attempts a FUSE-blocking
// mutation makes before parking its identity with the background replayer and
// surfacing ErrMutationUnknown (the identity is never reused).
const exactForegroundAttempts = 3

// parkRetryMin/Max bound the background replayer's backoff.
const (
	parkRetryMin = 250 * time.Millisecond
	parkRetryMax = 5 * time.Second
)

// ErrMutationUnknown is returned when a mutation's outcome could not be
// determined within the foreground budget. The identity is parked and will be
// replayed until definite; it is NEVER reused for a different request.
var ErrMutationUnknown = errors.New("fsproto: mutation outcome unknown; identity parked for replay")

// ErrSessionFenced is returned once the mount session has been fenced or
// superseded: no further mutations are possible from this mount instance.
var ErrSessionFenced = errors.New("fsproto: mount session fenced (stale generation); remount required")

// exactSession is the client's mount-session state.
type exactSession struct {
	id    string
	token string
	gen   uint64
	owner string
	slots uint32
	// features is the immutable bitmap returned by the protocol probe that
	// preceded this session's establishment.
	features uint64

	mu       sync.Mutex
	fenced   bool
	seq      []uint64 // per-slot last COMMITTED sequence
	avail    chan uint32
	leaseMs  int64
	stopOnce sync.Once
	stop     chan struct{}
}

func newExactSession(owner string, slots uint32) (*exactSession, error) {
	if slots == 0 {
		slots = DefaultExactSlots
	}
	if slots > MaxSessionSlots {
		slots = MaxSessionSlots
	}
	id, err := randToken(12)
	if err != nil {
		return nil, err
	}
	token, err := randToken(24)
	if err != nil {
		return nil, err
	}
	es := &exactSession{
		id:    "pfs-" + id,
		token: "pfstok_" + token,
		gen:   1,
		owner: owner,
		slots: slots,
		seq:   make([]uint64, slots),
		avail: make(chan uint32, slots),
		stop:  make(chan struct{}),
	}
	for i := uint32(0); i < slots; i++ {
		es.avail <- i
	}
	return es, nil
}

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fsproto: mint exact-session credential: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (es *exactSession) isFenced() bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.fenced
}

// fence permanently disables the session client-side (server fenced it, its
// lease expired, or its generation was superseded). Idempotent.
func (es *exactSession) fence() {
	es.mu.Lock()
	es.fenced = true
	es.mu.Unlock()
	es.stopOnce.Do(func() { close(es.stop) })
}

// acquire reserves a slot and returns its next (uncommitted) sequence. It
// blocks while every slot is in flight or parked; deadline bounds the wait.
func (es *exactSession) acquire(deadline time.Duration) (slot uint32, seq uint64, err error) {
	if es.isFenced() {
		return 0, 0, ErrSessionFenced
	}
	t := time.NewTimer(deadline)
	defer t.Stop()
	select {
	case slot = <-es.avail:
	case <-es.stop:
		return 0, 0, ErrSessionFenced
	case <-t.C:
		return 0, 0, errors.New("fsproto: no exact-mutation slot available (all identities in flight or parked)")
	}
	es.mu.Lock()
	seq = es.seq[slot] + 1
	es.mu.Unlock()
	return slot, seq, nil
}

// commit records a definite outcome for (slot, seq) and frees the slot.
func (es *exactSession) commit(slot uint32, seq uint64) {
	es.mu.Lock()
	es.seq[slot] = seq
	fenced := es.fenced
	es.mu.Unlock()
	if !fenced {
		es.avail <- slot
	}
}

// abort frees a slot WITHOUT advancing its sequence — legal only when the
// request was provably never sent (no bytes hit a connection).
func (es *exactSession) abort(slot uint32) {
	if !es.isFenced() {
		es.avail <- slot
	}
}

func (es *exactSession) envelope(slot uint32, seq uint64) *wal.Envelope {
	return &wal.Envelope{SessionID: es.id, Generation: es.gen, Slot: slot, SlotSeq: seq}
}

// ---- client wiring ----

// exactState returns the client's session (nil if not established).
func (c *Client) exactState() *exactSession {
	c.exactMu.RLock()
	defer c.exactMu.RUnlock()
	return c.exact
}

// SetExactSlots bounds this mount's concurrent in-flight exact mutations.
// Call before the first mutation (0 = DefaultExactSlots).
func (c *Client) SetExactSlots(n uint32) { c.exactSlots = n }

// ExactSessionActive reports whether an exact session is live (established and
// not fenced).
func (c *Client) ExactSessionActive() bool {
	es := c.exactState()
	return es != nil && !es.isFenced()
}

// SessionFenced reports whether the mount session was fenced (stale
// generation / lease lost). A fenced mount must not flush old dirty bytes and
// never mints a fresh generation; remount to recover.
func (c *Client) SessionFenced() bool {
	es := c.exactState()
	return es != nil && es.isFenced()
}

func (c *Client) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// EnsureExactSession establishes the mount session, negotiating the protocol
// version first: the authority must speak exactly ProtocolVersion (v7).
// Returns (true, nil) when the session is live and an error otherwise —
// including ErrProtocolVersionMismatch against an older authority. There is
// no legacy downgrade.
//
// It never holds exactMu across network I/O (pool users take exactMu.RLock
// while holding a pooled conn; holding the write lock while waiting for a
// conn would invert that order and deadlock). establishMu serializes the
// one-time establish instead.
func (c *Client) EnsureExactSession() (bool, error) {
	if es := c.exactState(); es != nil {
		return !es.isFenced(), nil
	}
	c.establishMu.Lock()
	defer c.establishMu.Unlock()
	if es := c.exactState(); es != nil {
		return !es.isFenced(), nil
	}
	probe, err := c.doRaw(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)}, true)
	if err != nil {
		return false, err
	}
	if probe.Status != OK || probe.ProtoVersion != ProtocolVersion {
		return false, &ErrProtocolVersionMismatch{ServerVersion: probe.ProtoVersion}
	}
	es, err := newExactSession(c.owner, c.exactSlots)
	if err != nil {
		return false, err
	}
	es.features = probe.Features
	// The exact (id, gen, owner, slots, token) tuple is idempotent, so a lost
	// establish reply is safely replayed with the identical tuple.
	var resp *Response
	for attempt := 0; attempt < exactForegroundAttempts; attempt++ {
		resp, err = c.doRaw(&Request{
			Op: OpSessionOpen, SessionID: es.id, SessionGen: es.gen,
			SessionToken: es.token, SessionSlots: es.slots, Owner: es.owner,
		}, true)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	switch resp.Status {
	case OK:
	case ESTALE:
		// A 96-bit random id colliding with a live tombstone is not a chance
		// event; treat as fenced (never bump the generation automatically).
		es.fence()
		c.exactMu.Lock()
		c.exact = es
		c.exactMu.Unlock()
		return false, ErrSessionFenced
	default:
		return false, statusError("session open", resp.Status)
	}
	if resp.SessionSlots != 0 && resp.SessionSlots < es.slots {
		// Authority narrowed the slot budget; honor it. No identity has been
		// handed out yet (establish precedes first acquire), so rebuild the
		// free list with only in-budget slot ids.
		for len(es.avail) > 0 {
			<-es.avail
		}
		es.slots = resp.SessionSlots
		es.seq = es.seq[:es.slots]
		for i := uint32(0); i < es.slots; i++ {
			es.avail <- i
		}
	}
	es.leaseMs = resp.LeaseMs
	c.exactMu.Lock()
	c.exact = es
	c.exactMu.Unlock()
	go c.renewLoop(es)
	return true, nil
}

// Features returns the optional capability bitmap negotiated before the
// current exact session was established. Zero means either no live session
// or an authority that advertises no optional features.
func (c *Client) Features() uint64 {
	es := c.exactState()
	if es == nil {
		return 0
	}
	return es.features
}

// renewLoop periodically resumes (durably renews) the session lease. On a
// definite ESTALE the session is fenced — the lease was lost or a newer
// generation took over; this mount must not mutate again.
func (c *Client) renewLoop(es *exactSession) {
	interval := time.Duration(es.leaseMs) * time.Millisecond / 3
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	for {
		select {
		case <-es.stop:
			return
		case <-c.closed:
			return
		case <-time.After(interval):
		}
		resp, err := c.doRaw(&Request{
			Op: OpSessionResume, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
		}, true)
		if err != nil {
			continue // transport trouble: keep trying; the lease has slack
		}
		if resp.Status == ESTALE {
			es.fence()
			return
		}
	}
}

// doRaw runs one session-management request (probe/open/resume) on a pooled
// connection WITHOUT session attach. These are all lost-response safe by
// construction, so retry re-sends the identical request once after a
// transport error.
func (c *Client) doRaw(req *Request, retry bool) (*Response, error) {
	cn := <-c.conns
	defer func() { c.conns <- cn }()
	resp, err := cn.roundtrip(req)
	if err != nil && retry {
		resp, err = cn.roundtrip(req)
	}
	return resp, err
}

// doAttached runs one session-scoped request on a pooled connection that has
// this session authenticated onto it (attaching first if the conn re-dialed).
// ReclaimDone/SessionExpire prove identity by the ATTACHED connection, so a
// bare roundtrip on a fresh conn would be silently ignored server-side.
func (c *Client) doAttached(req *Request, retry bool) (*Response, error) {
	cn := <-c.conns
	defer func() { c.conns <- cn }()
	if err := c.prepareConn(cn); err != nil {
		return nil, err
	}
	resp, err := cn.roundtrip(req)
	if err != nil && retry {
		if err = c.prepareConn(cn); err == nil {
			resp, err = cn.roundtrip(req)
		}
	}
	return resp, err
}

// prepareConn dials (if needed) and attaches the client's exact session onto
// the transport, so subsequent mutations on it pass the server's envelope==
// connection-session check. A definite ESTALE on attach fences the session.
func (c *Client) prepareConn(cn *conn) error {
	if err := cn.ensure(); err != nil {
		return err
	}
	es := c.exactState()
	if es == nil || es.isFenced() || cn.attached == es.id {
		return nil
	}
	resp, err := cn.roundtrip(&Request{
		Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	})
	if err != nil {
		return err
	}
	if resp.Status != OK {
		if resp.Status == ESTALE {
			es.fence()
		}
		return statusError("session attach", resp.Status)
	}
	cn.attached = es.id
	return nil
}

// ExpireSession voluntarily fences this session (clean unmount): the authority
// releases its lease-owned locks/delegations immediately and durably.
func (c *Client) ExpireSession() {
	es := c.exactState()
	if es == nil || es.isFenced() {
		return
	}
	_, _ = c.doAttached(&Request{Op: OpSessionExpire, SessionID: es.id, SessionGen: es.gen}, false)
	es.fence()
}

// doExact executes one mutation under an exact-once identity. Every definite
// server reply (any status) commits the identity; transport failures replay
// the IDENTICAL identity. After the foreground budget the identity is parked
// with the background replayer and the caller gets ErrMutationUnknown.
//
// A definite EAGAIN means the authority's reclaim-grace gate held the mutation
// off (post-failover, prior sessions still re-asserting). The identity WAS
// consumed (the rejection is durably recorded), so the retry below uses a
// FRESH identity — and keeps the failover invisible to the caller for as long
// as one op is allowed to block.
func (c *Client) doExact(req *Request) (*Response, error) {
	deadline := time.Now().Add(opTimeout)
	backoff := 50 * time.Millisecond
	for {
		resp, err := c.doExactOnce(req)
		if err != nil || resp.Status != EAGAIN {
			return resp, err
		}
		c.kickResume()
		if c.SessionFenced() || !time.Now().Before(deadline) {
			return resp, nil
		}
		select {
		case <-c.closed:
			return resp, nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > time.Second {
			backoff = time.Second
		}
	}
}

// kickResume performs one debounced session resume (durable renewal). Safe
// under concurrency: the authority serializes lifecycle transitions per
// session, and a definite ESTALE fences the client session exactly like the
// renew loop.
func (c *Client) kickResume() {
	es := c.exactState()
	if es == nil || es.isFenced() {
		return
	}
	if !c.resumeKick.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.resumeKick.Store(false)
		resp, err := c.doRaw(&Request{
			Op: OpSessionResume, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
		}, true)
		if err == nil && resp.Status == ESTALE {
			es.fence()
		}
	}()
}

func (c *Client) doExactOnce(req *Request) (*Response, error) {
	es := c.exactState()
	if es == nil {
		live, err := c.EnsureExactSession()
		if err != nil {
			return nil, err
		}
		if !live {
			return &Response{Status: ESTALE}, nil
		}
		es = c.exactState()
	}
	if es.isFenced() {
		return &Response{Status: ESTALE}, nil
	}
	slot, seq, err := es.acquire(opTimeout)
	if err != nil {
		return nil, err
	}
	req.Env = es.envelope(slot, seq)
	if req.Owner == "" {
		req.Owner = c.owner
	}
	sent := false
	for attempt := 0; attempt < exactForegroundAttempts; attempt++ {
		resp, wasSent, rerr := c.roundtripExact(req)
		if rerr == nil {
			// Every definite reply is a durable outcome (grants, ENOENT,
			// EEXIST, EAGAIN alike): the identity is consumed and the
			// sequence advances. There is no unrecorded definite flow — an
			// outcome the authority could not durably record is replied as
			// NOTHING (transport drop) and replayed.
			c.finishExact(es, slot, seq, resp)
			return resp, nil
		}
		sent = sent || wasSent
		if !sent {
			// Nothing ever hit a connection: the identity is provably unused
			// (dialing or the pre-send session attach failed).
			es.abort(slot)
			if es.isFenced() {
				// The attach's definite ESTALE fenced the session before the
				// mutation could be sent: it never executed and never will
				// from this generation. That is a definite outcome.
				return &Response{Status: ESTALE}, nil
			}
			return nil, rerr
		}
	}
	// UNKNOWN: park the identity; the replayer resends it until definite.
	c.parkExact(es, slot, seq, req)
	return nil, ErrMutationUnknown
}

// finishExact commits a definite outcome and maintains session health state.
func (c *Client) finishExact(es *exactSession, slot uint32, seq uint64, resp *Response) {
	es.commit(slot, seq)
	if resp.Status == ESTALE {
		// The authority no longer recognizes this generation (fenced,
		// expired, superseded, or slot-state violation): stop mutating
		// permanently. The mount surfaces a hard error; remount recovers.
		es.fence()
	}
}

// parkExact hands an UNKNOWN-outcome identity to the background replayer.
func (c *Client) parkExact(es *exactSession, slot uint32, seq uint64, req *Request) {
	go func() {
		backoff := parkRetryMin
		for {
			if es.isFenced() || c.isClosed() {
				return // slot retired with the session
			}
			resp, _, err := c.roundtripExact(req)
			if err == nil {
				c.finishExact(es, slot, seq, resp)
				if resp.Status == OK {
					// The caller already returned ErrMutationUnknown; keep the
					// client's own cache coherent for the write that DID land.
					c.selfWrote(req.Path, resp, req.Op == OpWrite || req.Op == OpTruncate || req.Op == OpSetattr)
				}
				return
			}
			select {
			case <-es.stop:
				return
			case <-c.closed:
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > parkRetryMax {
				backoff = parkRetryMax
			}
		}
	}()
}

// roundtripExact performs one attempt of an exact mutation on a pooled
// connection. wasSent reports whether any request bytes may have reached the
// authority (false only when dialing or the pre-send attach itself failed).
func (c *Client) roundtripExact(req *Request) (resp *Response, wasSent bool, err error) {
	cn := <-c.conns
	defer func() { c.conns <- cn }()
	if err := c.prepareConn(cn); err != nil {
		return nil, false, err
	}
	resp, err = cn.roundtrip(req)
	if err != nil {
		return nil, true, err
	}
	return resp, true, nil
}

// exactOp reports whether op is a write-through tree mutation that must carry
// an exact-once identity on a session-negotiated authority. Mirrors the
// server's admission surface (mutatingOp + OpReap).
func exactOp(op Op) bool {
	switch op {
	case OpWrite, OpCreate, OpMkdir, OpRemove, OpRename, OpSymlink, OpLink, OpTruncate, OpSetattr, OpOrphan, OpReap,
		OpSetxattr, OpRemovexattr:
		return true
	default:
		return false
	}
}

func statusError(op string, status int32) error {
	return fmt.Errorf("fsproto: %s failed with status %d", op, status)
}
