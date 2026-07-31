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
// exactly ProtocolVersion (v8) and refuses anything else. PFRQ2 peers return
// a typed version mismatch; older request-wire peers fail closed at framing.
// There is no legacy downgrade.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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

// exactGateRetryDelay paces re-issuing an exact mutation after the
// authority's delegation gate returned a definite EAGAIN mid-recall. The
// recall it timed out on is already in flight, so the next attempt usually
// succeeds; the delay only prevents a tight identity-consuming loop.
const exactGateRetryDelay = 250 * time.Millisecond

// exactGateRetryBudget bounds how long DoContext keeps re-issuing after
// definite gate EAGAINs before surfacing the last one. Each server-side gate
// attempt already waits a full recall timeout, so a budget of a few recall
// timeouts covers every converging recall while a scope stuck behind a dead
// holder's recovery delegation still surfaces instead of blocking until
// lease expiry. Variable (not const) so tests can compress it.
var exactGateRetryBudget = 90 * time.Second

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

func (c *Client) takeConn() (*conn, error) {
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case cn := <-c.conns:
		if c.isClosed() {
			c.conns <- cn
			return nil, net.ErrClosed
		}
		return cn, nil
	}
}

func (c *Client) takeConnContext(ctx context.Context) (*conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	case cn := <-c.conns:
		if err := ctx.Err(); err != nil {
			c.conns <- cn
			return nil, err
		}
		if c.isClosed() {
			c.conns <- cn
			return nil, net.ErrClosed
		}
		return cn, nil
	}
}

// EnsureExactSession establishes the mount session, negotiating the protocol
// version first: the authority must speak exactly ProtocolVersion (v8).
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
	cn, err := c.takeConn()
	if err != nil {
		return nil, err
	}
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
	resp, sent, err := c.roundtripAttached(req)
	if err != nil && retry && sent {
		resp, _, err = c.roundtripAttached(req)
	}
	return resp, err
}

// roundtripAttached performs one session-attached request attempt. sent is
// false only when the request itself provably never reached a transport
// (taking/dialing/attaching failed first). Once cn.roundtrip is entered an
// error is conservatively ambiguous: request bytes may have reached the
// authority even if encoding or reading the reply failed.
func (c *Client) roundtripAttached(req *Request) (resp *Response, sent bool, err error) {
	return c.roundtripAttachedWithGate(req, false)
}

// roundtripAttachedContext is the cancellable form used by the write-back
// flusher. Cancellation interrupts the checked-out transport and then JOINS
// the roundtrip before returning. That join is the important ordering
// property: a timed-out digest batch can never remain live in a detached
// goroutine while the flusher submits a later batch for the same stream.
// The caller may safely replay the identical digest-addressed batch after an
// ambiguous error.
func (c *Client) roundtripAttachedContext(ctx context.Context, req *Request) (resp *Response, sent bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	cn, err := c.takeConnContext(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { c.conns <- cn }()

	stopInterrupt := make(chan struct{})
	interruptDone := make(chan struct{})
	go func() {
		defer close(interruptDone)
		select {
		case <-ctx.Done():
			cn.interrupt()
		case <-stopInterrupt:
		}
	}()
	defer func() {
		close(stopInterrupt)
		<-interruptDone
	}()

	if err := c.prepareConnContext(ctx, cn); err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	resp, sent, err = cn.roundtripSentWithGateContext(ctx, req, false)
	if err != nil && ctx.Err() != nil {
		return nil, sent, ctx.Err()
	}
	return resp, sent, err
}

func (c *Client) roundtripAttachedWithGate(req *Request, resolved bool) (resp *Response, sent bool, err error) {
	cn, err := c.takeConn()
	if err != nil {
		return nil, false, err
	}
	defer func() { c.conns <- cn }()
	if err := c.prepareConnWithGate(cn, resolved); err != nil {
		return nil, false, err
	}
	return cn.roundtripSentWithGate(req, resolved)
}

// doAttachedResolved runs an idempotent, session-scoped operation whose
// successful execution has durable side effects but no exact slot recording
// its response. A pre-send failure is definite and returns immediately. Once
// any attempt may have reached the authority, the identical request is replayed
// until its reply is known, the session is fenced, or the client closes.
//
// This is intentionally the envelope-less counterpart of
// doCoordinateResolved. Callers must retain any local serialization barrier
// that makes the operation idempotent for this method's whole lifetime.
func (c *Client) doAttachedResolved(req *Request) (*Response, error) {
	es := c.exactState()
	if es == nil || es.isFenced() {
		return &Response{Status: ESTALE}, nil
	}
	sent := false
	backoff := parkRetryMin
	var lastErr error
	for {
		resp, wasSent, err := c.roundtripAttachedWithGate(req, true)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sent = sent || wasSent
		if !sent {
			// The operation never crossed the attached transport, so it has no
			// durable side effect to discover.
			if es.isFenced() {
				return &Response{Status: ESTALE}, nil
			}
			return nil, err
		}
		select {
		case <-es.stop:
			// Terminalization releases the generation's pins, making the
			// unresolved prepare harmless and its session outcome definite.
			return &Response{Status: ESTALE}, nil
		case <-c.closed:
			return nil, lastErr
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > parkRetryMax {
			backoff = parkRetryMax
		}
	}
}

// prepareConn dials (if needed) and attaches the client's exact session onto
// the transport, so subsequent mutations on it pass the server's envelope==
// connection-session check. A definite ESTALE on attach fences the session.
func (c *Client) prepareConn(cn *conn) error {
	return c.prepareConnWithGate(cn, false)
}

func (c *Client) prepareConnContext(ctx context.Context, cn *conn) error {
	return c.prepareConnContextWithGate(ctx, cn, false)
}

func (c *Client) prepareConnContextWithGate(ctx context.Context, cn *conn, resolved bool) error {
	if err := cn.ensureWithGateContext(ctx, resolved); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	es := c.exactState()
	if es == nil || es.isFenced() || cn.attached == es.id {
		return nil
	}
	resp, _, err := cn.roundtripSentWithGateContext(ctx, &Request{
		Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	}, resolved)
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

func (c *Client) prepareConnWithGate(cn *conn, resolved bool) error {
	if err := cn.ensureWithGate(resolved); err != nil {
		return err
	}
	es := c.exactState()
	if es == nil || es.isFenced() || cn.attached == es.id {
		return nil
	}
	resp, _, err := cn.roundtripSentWithGate(&Request{
		Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	}, resolved)
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

// doExact executes exactly one mutation identity. Every definite server reply
// (including EAGAIN) commits that identity and returns immediately; transport
// failures replay only the IDENTICAL identity. Managed exact admission has no
// client-visible reclaim-grace status distinct from delegation contention, so
// blanket fresh-identity EAGAIN retry would turn one bounded recall timeout
// into a full opTimeout stall and could repeat a real lock/contention result.
//
// ctx carries only the park-transfer hook (WithParkTransfer): an exact
// identity is never abandoned on cancellation, but if it parks, the exclusion
// the caller issued it under must travel with it.
func (c *Client) doExact(ctx context.Context, req *Request) (*Response, error) {
	return c.doExactOnce(ctx, req)
}

func (c *Client) doExactOnce(ctx context.Context, req *Request) (*Response, error) {
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
	// UNKNOWN: park the identity; the replayer resends it until definite. The
	// park takes ownership of the caller's exclusion release, so the caller
	// may return ErrMutationUnknown without handing that exclusion to anyone.
	c.parkExact(ctx, es, slot, seq, req)
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
//
// INVARIANT: a possibly-sent exact identity reaches a definite outcome BEFORE
// the exclusion state it was issued under is released to anyone else. The
// identity may execute minutes from now, so parking it also parks the
// caller's delegation-transition claim / exact exclusion: parkExact captures
// that release from ctx (WithParkTransfer) synchronously, before the parking
// caller returns, and drops it on exactly one of three definite ends —
//
//  1. an authority reply for the identity (executed, or its stored outcome),
//  2. a session fence (es.stop: the generation can never execute again),
//  3. client teardown (Close/Abort, both of which fence first and then JOIN
//     this goroutine, so no transferred claim outlives the client).
//
// Every exit path runs the release exactly once via defer; with no hook
// installed the release is a no-op and behavior is unchanged.
func (c *Client) parkExact(ctx context.Context, es *exactSession, slot uint32, seq uint64, req *Request) {
	release := beginParkTransfer(ctx)
	if !c.registerPark() {
		// Torn down already: this identity can never be re-sent from this
		// generation, so its outcome is definite by teardown. Release inline —
		// a goroutine started here would not be joined by the close that is
		// already past its wait.
		release()
		return
	}
	go func() {
		defer c.parkWG.Done()
		// Ordered after Done's registration and therefore run BEFORE it: the
		// exclusion is handed back before teardown's join returns.
		defer release()
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
					// This runs INSIDE the still-transferred exclusion (the
					// deferred release follows), so the local overlay reflects
					// the landed write before the scope can be handed to a new
					// claim holder. The self-write recorder must therefore
					// never re-enter that exclusion.
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
	return c.roundtripExactWithGate(req, false)
}

func (c *Client) roundtripExactResolved(req *Request) (resp *Response, wasSent bool, err error) {
	return c.roundtripExactWithGate(req, true)
}

func (c *Client) roundtripExactWithGate(req *Request, resolved bool) (resp *Response, wasSent bool, err error) {
	cn, err := c.takeConn()
	if err != nil {
		return nil, false, err
	}
	defer func() { c.conns <- cn }()
	if err := c.prepareConnWithGate(cn, resolved); err != nil {
		return nil, false, err
	}
	return cn.roundtripSentWithGate(req, resolved)
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
