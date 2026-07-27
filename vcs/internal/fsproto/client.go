package fsproto

import (
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// splitAddrs parses a comma-separated authority address list, trimming blanks.
func splitAddrs(addr string) []string {
	var out []string
	for _, a := range strings.Split(addr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// Client is a pooled connection to a Server. Each pooled connection carries its
// own gob streams and serves one request at a time, so concurrent FUSE ops run on
// separate connections up to the pool size. Connections lazily re-dial, so a
// mount rides through a VCS restart or failover. Multiple authority addresses may be
// given (comma-separated): a connection tries each in order, so when the primary
// dies the mount follows over to a promoted standby without an external VIP. A
// non-nil tls config encrypts every connection.
type Client struct {
	addrs      []string
	tls        *tls.Config
	conns      chan *conn
	owner      string             // this mount's checkout-owner id, sent on Subscribe for liveness-release
	ops        *metrics.Counter   // authority round-trips (the RTT metric; write-back keeps it low)
	opLat      *metrics.Histogram // authority round-trip latency
	authMu     sync.RWMutex
	authToken  string
	authSource func() string

	// redial paces reconnection attempts across the WHOLE pool (shared
	// full-jitter backoff): concurrent ops failing against a dead authority
	// deepen one attempt counter, and any successful dial resets it. Without
	// this, every FUSE op performs its own instant redial and a dead manager
	// gets hammered in proportion to op traffic.
	redial *Backoff

	// Credential re-resolve coordination for explicit token rejections
	// (see reconnect.go). refreshGen counts completed re-resolves; a dial
	// captures it before fetching its token so a rejection can tell "my
	// token predates the last re-resolve" (just retry) from "the installed
	// token itself was rejected" (re-resolve). refreshMu single-flights the
	// resolver; refreshWait/refreshBackoff pace a failing resolver.
	refreshGen      atomic.Uint64
	refreshMu       sync.Mutex
	refreshWait     time.Time
	refreshBackoff  *Backoff
	onTokenRejected func() bool
	// onSelfWrite, if set, is called after every successful write-through MUTATION with the path,
	// the version the authority assigned, and whether the mutation was in-place. This lets the
	// mount update/evict its own caches for owner-suppressed invalidation echoes. nil => no-op.
	onSelfWrite func(path string, gen, version uint64, inPlace bool)

	// Exact mount-session state. exact is nil until EnsureExactSession
	// establishes it; serverLegacy is sticky once the authority proves to be
	// below the session protocol version (a mid-mount authority upgrade
	// requires a remount to adopt exact sessions — documented rolling-upgrade
	// behavior). sessionsDisabled reflects VCS_CLIENT_DISABLE_EXACT_SESSIONS=1
	// (debugging escape hatch: pure v1 behavior).
	exactMu          sync.RWMutex
	serverManaged    bool       // authority negotiated journaled coordination (managed generation)
	establishMu      sync.Mutex // serializes the one-time session establish
	exact            *exactSession
	serverLegacy     bool
	serverFeatures   uint64 // probe-advertised capability bits (valid once featuresKnown)
	featuresKnown    bool   // one successful OpProtocolVersion probe happened
	sessionsDisabled bool
	exactSlots       uint32
	onReclaim        func(window time.Duration)
	closed           chan struct{}
	closeOnce        sync.Once
	// resumeKick debounces the EAGAIN-triggered immediate session resume.
	resumeKick atomic.Bool

	// health tracks authority transport reachability (the fail-fast breaker,
	// see failfast.go); shared by every pooled, subscribe, and probe conn.
	health *connHealth
	// transport, when set, is the in-process dialer the pool was built with;
	// the reachability prober needs it to build a probe conn (net.Pipe etc.).
	transport func() (net.Conn, error)
}

// SetOnSelfWrite registers the self-write recorder (the mount's version cache). Call once at startup.
func (c *Client) SetOnSelfWrite(fn func(path string, gen, version uint64, inPlace bool)) {
	c.onSelfWrite = fn
}

// selfWrote records a successful mutation's version for self-echo suppression, if a recorder is set.
func (c *Client) selfWrote(path string, r *Response, inPlace bool) {
	if c.onSelfWrite != nil && r != nil && r.Gen != 0 {
		c.onSelfWrite(path, r.Gen, r.Version, inPlace)
	}
}

// SetMetrics makes the client count authority round-trips + their latency into reg. The op count
// is the key write-back efficiency signal (fewer round-trips per op = the local-latency win).
func (c *Client) SetMetrics(reg *metrics.Registry) {
	c.ops = reg.Counter("authority_ops_total")
	c.opLat = reg.Histogram("authority_op_seconds")
}

// SetOwner sets the mount's checkout-owner id (sent on the Subscribe stream so the
// authority releases this mount's checkouts when the stream drops). Set once at startup
// before Subscribe.
func (c *Client) SetOwner(owner string) { c.owner = owner }

// SetAuthToken sets the static token used for future connection handshakes. Existing live connections
// keep their handshake-time auth; reconnects pick up this value.
//
// Precedence (m3): an installed CredentialSource WINS and is NOT cleared here. A source-configured
// volume renews credentials dynamically through the source, so pinning it to a static token forever —
// which the old `c.authSource = nil` did on any RenewCredential — was a bug (it silently disabled the
// rotating source). SetAuthToken now only updates the static FALLBACK used when no source is installed;
// tokenForHandshake still prefers the source. Configure exactly one of source/token at startup.
func (c *Client) SetAuthToken(tok string) {
	c.authMu.Lock()
	c.authToken = tok
	c.authMu.Unlock()
}

// SetAuthTokenSource installs a callback used for future connection handshakes. It lets a mount or
// daemon renew credentials in place without rebuilding the client or dropping warm caches.
func (c *Client) SetAuthTokenSource(fn func() string) {
	c.authMu.Lock()
	c.authSource = fn
	c.authMu.Unlock()
}

func (c *Client) tokenForHandshake() string {
	c.authMu.RLock()
	source := c.authSource
	tok := c.authToken
	c.authMu.RUnlock()
	if source != nil {
		return source()
	}
	if tok != "" {
		return tok
	}
	return secure.AuthToken()
}

type conn struct {
	addrs []string
	tls   *tls.Config
	auth  func() string
	// transport, when set, replaces TCP dialing entirely (deterministic
	// in-process transports such as net.Pipe). The auth handshake still runs.
	transport func() (net.Conn, error)
	// client is the owning pool's client, when there is one: dial success
	// resets its shared redial backoff, and an explicit token rejection is
	// routed through its single-flight credential re-resolve.
	client *Client
	nc     net.Conn
	enc    *gob.Encoder
	dec    *gob.Decoder
	// attached is the mount-session id authenticated onto THIS transport
	// (exact sessions ride the connection; a re-dial must re-attach).
	attached string
	// health is the shared reachability breaker (nil-safe). gateExempt marks
	// the recovery conns (subscribe stream, prober) that must dial even while
	// fail-fast is engaged. dialTimeout overrides the default dial bound for
	// short probe dials (zero = the package default).
	health      *connHealth
	gateExempt  bool
	dialTimeout time.Duration
}

// ensure lazily (re)dials. An ordinary dial failure surfaces to the caller
// (whose retry policy owns the pacing); an explicit token rejection instead
// triggers ONE coalesced credential re-resolve and, when a fresh token was
// installed, ONE more dial pass — so a mount whose manager restarted recovers
// inside the op that first noticed, without a timer tick in the loop.
func (cn *conn) ensure() error {
	if cn.nc != nil {
		return nil
	}
	if err := cn.health.gate(cn.gateExempt); err != nil {
		return err
	}
	for pass := 0; ; pass++ {
		var gen uint64
		if cn.client != nil {
			// Captured BEFORE dialOnce fetches the token: a re-resolve that
			// completes in between advances the generation, which
			// refreshRejectedToken reads as "fresh credential already
			// installed, just retry".
			gen = cn.client.refreshGen.Load()
		}
		err := cn.dialOnce()
		if err == nil {
			cn.health.recordSuccess()
			if cn.client != nil {
				cn.client.noteDialSuccess()
			}
			return nil
		}
		// A definite token rejection is an ANSWER from a reachable peer, not
		// unreachability (see failfast.go): it must not feed the failure
		// streak, or an expired-but-renewable credential would masquerade as
		// a dead authority and trip fail-fast on a working mount.
		if !errors.Is(err, ErrSessionTokenRejected) {
			cn.health.recordFailure()
		}
		if !errors.Is(err, ErrSessionTokenRejected) || cn.client == nil || pass >= 1 {
			return err
		}
		if !cn.client.refreshRejectedToken(gen) {
			return err
		}
	}
}

// dialOnce makes one dial pass: the in-process transport, or each authority
// address in order — the first that connects AND completes the auth handshake
// wins, so a dead/fenced primary (listener closed) is skipped and the mount
// lands on a promoted standby. An explicit token rejection ends the pass
// immediately: every address shares the same credential, so offering a dead
// token to the rest of the list only adds to the reconnect storm.
func (cn *conn) dialOnce() error {
	token := secure.AuthToken()
	if cn.auth != nil {
		token = cn.auth()
	}
	if cn.transport != nil {
		nc, err := cn.transport()
		if err != nil {
			return err
		}
		if err := clientHandshake(nc, token); err != nil {
			_ = nc.Close()
			return err
		}
		cn.nc, cn.enc, cn.dec = nc, gob.NewEncoder(nc), gob.NewDecoder(nc)
		return nil
	}
	// Timeout bounds the TCP (and TLS) connect so a blackholed authority
	// costs one bounded attempt on the backoff schedule, not an OS-default
	// connect timeout of minutes serializing every retry.
	to := dialTimeout
	if cn.dialTimeout != 0 {
		to = cn.dialTimeout
	}
	dialer := &net.Dialer{KeepAlive: connKeepAlive, Timeout: to}
	var lastErr error
	for _, addr := range cn.addrs {
		var (
			nc  net.Conn
			err error
		)
		if cn.tls != nil {
			nc, err = tls.DialWithDialer(dialer, "tcp", addr, cn.tls)
		} else {
			nc, err = dialer.Dial("tcp", addr)
		}
		if err != nil {
			lastErr = err
			continue
		}
		// Authenticate to the server before using the connection (no-op when
		// unset). The typed classification is the point: rejection means the
		// CREDENTIAL is dead, not the network.
		if err := clientHandshake(nc, token); err != nil {
			_ = nc.Close()
			if errors.Is(err, ErrSessionTokenRejected) {
				return fmt.Errorf("fsproto: dial %s: %w", addr, err)
			}
			lastErr = err
			continue
		}
		cn.nc, cn.enc, cn.dec = nc, gob.NewEncoder(nc), gob.NewDecoder(nc)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("fsproto: no authority addresses configured")
	}
	return lastErr
}

func (cn *conn) reset() {
	if cn.nc != nil {
		_ = cn.nc.Close()
		cn.nc, cn.enc, cn.dec = nil, nil, nil
	}
	cn.attached = ""
}

func (cn *conn) roundtrip(req *Request) (*Response, error) {
	// Gate before dialing/sending: while fail-fast is engaged, a non-exempt op
	// fails immediately with ErrAuthorityUnreachable instead of burning a full
	// opTimeout socket deadline against a confirmed-dead peer.
	if err := cn.health.gate(cn.gateExempt); err != nil {
		return nil, err
	}
	if err := cn.ensure(); err != nil {
		return nil, err
	}
	// Bound the round-trip so a partitioned VCS surfaces as EIO (idempotent ops then
	// retry) instead of hanging the FUSE op until the OS TCP timeout. The conn is
	// reset on any error, so the deadline never leaks onto a reused connection.
	_ = cn.nc.SetDeadline(time.Now().Add(opTimeout))
	if err := cn.enc.Encode(req); err != nil {
		cn.health.recordFailure()
		cn.reset()
		return nil, err
	}
	var resp Response
	if err := cn.dec.Decode(&resp); err != nil {
		cn.health.recordFailure()
		cn.reset()
		return nil, err
	}
	_ = cn.nc.SetDeadline(time.Time{})
	cn.health.recordSuccess()
	return &resp, nil
}

// Dial opens a plaintext pool of connections to addr (which may be a comma-separated
// list of authority addresses for failover).
func Dial(addr string, pool int) (*Client, error) {
	return DialTLS(addr, pool, nil)
}

// DialTLS opens a pool of connections to addr, encrypted with tlsCfg if non-nil. addr
// may be a comma-separated list "host1:port,host2:port"; each pooled connection tries
// the addresses in order, so the mount follows a primary→standby failover.
func DialTLS(addr string, pool int, tlsCfg *tls.Config) (*Client, error) {
	return DialTLSAuth(addr, pool, tlsCfg, nil)
}

// DialTLSAuth is DialTLS with a token source installed before the initial connection pool is opened.
func DialTLSAuth(addr string, pool int, tlsCfg *tls.Config, auth func() string) (*Client, error) {
	return dialPool(addr, pool, tlsCfg, auth, nil)
}

// DialWithTransport opens a client whose connections use the given transport
// dialer instead of TCP. It exists for deterministic in-process transports
// (net.Pipe) in environments where loopback listeners are unavailable; live
// socket paths use Dial/DialTLS.
func DialWithTransport(pool int, transport func() (net.Conn, error)) (*Client, error) {
	return dialPool("in-process", pool, nil, nil, transport)
}

func dialPool(addr string, pool int, tlsCfg *tls.Config, auth func() string, transport func() (net.Conn, error)) (*Client, error) {
	if pool < 1 {
		pool = 1
	}
	addrs := splitAddrs(addr)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("fsproto: no authority address given")
	}
	c := &Client{
		addrs: addrs, tls: tlsCfg, conns: make(chan *conn, pool),
		closed:           make(chan struct{}),
		sessionsDisabled: os.Getenv("VCS_CLIENT_DISABLE_EXACT_SESSIONS") == "1",
		redial:           NewBackoff(DefaultReconnectBase, DefaultReconnectCap),
		refreshBackoff:   NewBackoff(DefaultReconnectBase, DefaultReconnectCap),
		transport:        transport,
	}
	c.health = newConnHealth()
	c.health.onEngage = func() { go c.runReachabilityProbe() }
	if auth != nil {
		c.authSource = auth
	}
	for i := 0; i < pool; i++ {
		cn := &conn{addrs: addrs, tls: tlsCfg, auth: c.tokenForHandshake, transport: transport, client: c, health: c.health}
		if err := cn.ensure(); err != nil {
			c.Close()
			return nil, err
		}
		c.conns <- cn
	}
	return c, nil
}

// Do sends a request on a pooled connection.
//
// Against a session-negotiated authority, tree mutations route through the
// exact-once machinery (doExact): each carries a (session, generation, slot,
// slot-sequence) identity, so a retry after a lost reply returns the STORED
// outcome instead of re-executing. Against a legacy authority (or with
// VCS_CLIENT_DISABLE_EXACT_SESSIONS=1) the pre-session behavior is preserved
// unchanged: idempotent ops retry once across a re-dial, mutations surface
// transport errors to the caller.
func (c *Client) Do(req *Request) (*Response, error) {
	if os.Getenv("PFS_WIRE_TRACE") != "" {
		start := time.Now()
		defer func() {
			log.Printf("WIRETRACE op=%s path=%q ms=%d", opNames[req.Op], req.Path, time.Since(start).Milliseconds())
		}()
	}
	if req.Owner == "" {
		// Stamp the originating mount identity so the authority's subscribe stream source-
		// suppresses this mutation's echo back to us (race-free self-suppression). Ops that set
		// Owner explicitly (checkout/checkin/flush/lock) keep theirs; reads carry it harmlessly
		// (the authority ignores Owner on non-mutating ops).
		req.Owner = c.owner
	}
	if c.ops != nil {
		c.ops.Inc()
		defer c.opLat.Time(time.Now()) // time.Now() captured at defer registration = op start
	}
	if c.sessionsEnabled() && !c.serverIsLegacy() {
		if exactOp(req.Op) {
			return c.doExact(req)
		}
		if req.Op == OpFlushBatch {
			// FlushBatch keeps its own durable watermark exactness, but on a
			// session authority it should arrive on a connection whose
			// authenticated mount session owns the flush (required under
			// VCS_REQUIRE_EXACT_SESSIONS=1). Establish once; pooled conns
			// then attach lazily in prepareConn. A fenced mount must never
			// flush old dirty write-back bytes over its successor's state.
			if c.SessionFenced() {
				return &Response{Status: ESTALE}, nil
			}
			if _, err := c.EnsureExactSession(); err != nil {
				return nil, err
			}
		}
	}
	cn := <-c.conns
	defer func() { c.conns <- cn }()
	var lastErr error
	for attempt := 0; attempt < opDialAttempts; attempt++ {
		if attempt >= 2 {
			// The first redial is immediate — a stale pooled socket after an
			// authority restart recovers in one hop, exactly the old single
			// silent retry. From there the SHARED full-jitter backoff paces
			// every further attempt so op traffic against a dead authority
			// decays instead of hammering.
			select {
			case <-c.closed:
				return nil, lastErr
			case <-time.After(c.redial.Next()):
			}
		}
		err := c.prepareConn(cn)
		if err != nil {
			lastErr = err
			if errors.Is(err, ErrAuthorityUnreachable) {
				// Fail-fast engaged: the authority is confirmed unreachable and
				// the reachability prober (not this op's retry loop) owns
				// recovery. Retrying here only burns the backoff budget
				// re-consulting the gate; surface EIO immediately.
				return nil, err
			}
			if errors.Is(err, ErrSessionTokenRejected) {
				// ensure() already coalesced one credential re-resolve and
				// retried the dial; a rejection that still escapes cannot be
				// fixed by redialing with the same credential — fail the op
				// now, and let the next op (or the invalidation resubscribe
				// loop) drive the paced re-resolve.
				return nil, err
			}
			if cn.nc != nil {
				// Connected but refused at the protocol level (a session
				// attach refusal): a redial cannot change the answer.
				return nil, err
			}
			continue
		}
		resp, err := cn.roundtrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if errors.Is(err, ErrAuthorityUnreachable) {
			// Fail-fast engaged mid-op: stop retrying (see the prepareConn
			// branch above); the prober owns recovery.
			return nil, err
		}
		if !isIdempotent(req.Op) {
			// The request may have executed; only ops whose re-apply is a
			// no-op are retried (see isIdempotent). Dial failures above are
			// different: nothing was ever sent, so every op retries those.
			return nil, err
		}
	}
	return nil, lastErr
}

// opDialAttempts bounds one op's transport attempts (dial + send). Sized so an
// op arriving during a manager/authority restart rides through a multi-second
// gap (cumulative full-jitter waits of a few seconds), while a genuinely dead
// authority still fails the op well inside opTimeout instead of pinning the
// FUSE caller to the full bound.
const opDialAttempts = 6

// isIdempotent reports whether an op is safe to transparently retry after a
// reconnect (a VCS restart/failover). Reads are; so are volatile coordination
// ops (checkout/checkin/lock/lease renewals — all naturally idempotent per
// owner), and writes whose re-apply is a no-op: the same bytes at the same
// offset, create/mkdir (O_CREATE), truncate to the same size, chmod to the
// same mode, setxattr of the same value. Rename/remove/symlink/removexattr
// are not retried (a second apply would spuriously fail), so they surface
// the error to the caller. (Against a session-negotiated authority mutations
// ride doExact instead, which replays identities rather than blindly
// retrying.)
func isIdempotent(op Op) bool {
	switch op {
	case OpGetattr, OpReaddir, OpRead, OpReadlink,
		OpWrite, OpCreate, OpMkdir, OpTruncate, OpSetattr, OpRenewOrphanLeases,
		OpMarkOpen, OpRenewOpenInodes, OpUnmarkOpenInodes,
		OpCheckout, OpCheckin, OpLock,
		OpGetxattr, OpListxattr, OpSetxattr:
		return true
	default:
		return false
	}
}

// Subscribe opens a dedicated connection that streams cache invalidations (a
// batch of changed paths; nil means flush everything). The channel closes if the
// connection drops; the caller re-subscribes and flushes.
//
// The stream conn is session-attached when an exact session is live, which
// switches the authority's cleanup model for this mount from "release
// checkouts/locks on stream drop" (legacy liveness) to session-lease expiry —
// a socket flap then releases nothing.
func (c *Client) Subscribe() (<-chan []coherence.Invalidation, error) {
	// gateExempt: the subscribe stream is a recovery path — its 500ms reconnect
	// loop doubles as an on-demand reachability probe, so it must dial even
	// while fail-fast is engaged (clearing the breaker on the first success).
	cn := &conn{addrs: c.addrs, tls: c.tls, auth: c.tokenForHandshake, client: c, health: c.health, gateExempt: true}
	if err := cn.ensure(); err != nil {
		return nil, err
	}
	if es := c.exactState(); es != nil && !es.isFenced() {
		resp, err := cn.roundtrip(&Request{
			Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
		})
		if err != nil {
			cn.reset()
			return nil, err
		}
		if resp.Status != OK {
			// A subscription stream that could not authenticate its session
			// MUST NOT serve: its liveness/ownership semantics would be
			// wrong. Abort; the caller resubscribes (or the fence stands).
			if resp.Status == ESTALE {
				es.fence()
			}
			cn.reset()
			return nil, statusError("subscribe session attach", resp.Status)
		}
		cn.attached = es.id
	}
	if err := cn.enc.Encode(&Request{Op: OpSubscribe, Owner: c.owner}); err != nil {
		cn.reset()
		return nil, err
	}
	ch := make(chan []coherence.Invalidation, 1024)
	go func() {
		defer close(ch)
		defer cn.reset()
		for {
			// Arm a read deadline: the server heartbeats every streamHeartbeat, so a
			// gap longer than streamReadTimeout means the stream is dead/half-open.
			// Closing ch makes watchInvalidations reconnect and flush — the only thing
			// that rescues a client whose invalidation stream silently died.
			_ = cn.nc.SetReadDeadline(time.Now().Add(streamReadTimeout))
			var resp Response
			if err := cn.dec.Decode(&resp); err != nil {
				return
			}
			if resp.Keepalive {
				// Liveness only — but convey the generation so the mount can detect an
				// authority restart/promotion (a new Gen) even on an otherwise idle stream.
				ch <- []coherence.Invalidation{{Gen: resp.Gen}}
				continue
			}
			if len(resp.Invs) > 0 {
				ch <- resp.Invs
			}
		}
	}()
	return ch, nil
}

// Checkout acquires an exclusive write delegation on path for owner. On conflict
// it returns granted=false and the owner currently holding it.
func (c *Client) Checkout(path, owner string) (granted bool, heldBy string, err error) {
	r, err := c.Do(&Request{Op: OpCheckout, Path: path, Owner: owner})
	if err != nil {
		return false, "", err
	}
	if r.Status == EBUSY {
		return false, r.Owner, nil
	}
	if r.Status != OK {
		return false, "", fmt.Errorf("checkout: status %d", r.Status)
	}
	return true, "", nil
}

// Checkin releases owner's delegation on path.
func (c *Client) Checkin(path, owner string) error {
	r, err := c.Do(&Request{Op: OpCheckin, Path: path, Owner: owner})
	if err != nil {
		return err
	}
	if r.Status != OK {
		return fmt.Errorf("checkin: status %d", r.Status)
	}
	return nil
}

// FlushBatch ships a write-back session's buffered mutations (carrying the mount's local
// WAL Seqs) to the authority for exactly-once apply. owner is the mount's checkout owner
// id. It returns the highest local Seq now durable on the authority (the mount advances
// its flush cursor to that), and the protocol status.
func (c *Client) FlushBatch(sessionID string, epoch uint64, owner string, records []wal.Record) (appliedThrough uint64, status int32, err error) {
	r, err := c.Do(&Request{Op: OpFlushBatch, SessionID: sessionID, Epoch: epoch, Owner: owner, Records: records})
	if err != nil {
		return 0, EIO, err
	}
	return r.AppliedThrough, r.Status, nil
}

// ReadV reads up to n bytes at off and returns the path's coherence version and the
// authority generation alongside the bytes, so the mount can do generation-aware,
// monotonic cache fills (install a read result only if it is not older than what it holds).
func (c *Client) ReadV(path string, off, n int64) (data []byte, version, gen uint64, status int32, err error) {
	return c.ReadVHandle(path, 0, off, n)
}

// ReadVHandle is ReadV addressed by an open file handle's stable ino when handleIno is non-zero.
func (c *Client) ReadVHandle(path string, handleIno uint64, off, n int64) (data []byte, version, gen uint64, status int32, err error) {
	r, err := c.Do(&Request{Op: OpRead, Path: path, HandleIno: handleIno, Offset: off, Size: n})
	if err != nil {
		return nil, 0, 0, EIO, err
	}
	return r.Data, r.Version, r.Gen, r.Status, nil
}

// GetattrV stats a path and returns its coherence version and the authority generation. On ENOENT,
// parentVersion is the parent directory version PLUS ONE; zero means the authority did not provide
// safe negative-cache metadata.
func (c *Client) GetattrV(path string) (a Attr, version, gen, parentVersion uint64, status int32, err error) {
	r, err := c.Do(&Request{Op: OpGetattr, Path: path})
	if err != nil {
		return Attr{}, 0, 0, 0, EIO, err
	}
	if r.Attr != nil {
		a = *r.Attr
	}
	return a, r.Version, r.Gen, r.ParentVersion, r.Status, nil
}

// WriteV writes data at off and returns the coherence version the write produced (and the
// authority generation), so the writer can record its own version and skip its own echo.
func (c *Client) WriteV(path string, off int64, data []byte, mode uint32) (count int, version, gen uint64, status int32, err error) {
	return c.WriteVHandle(path, 0, off, data, mode)
}

// WriteVHandle is WriteV addressed by an open file handle's stable ino when handleIno is non-zero.
func (c *Client) WriteVHandle(path string, handleIno uint64, off int64, data []byte, mode uint32) (count int, version, gen uint64, status int32, err error) {
	r, err := c.Do(&Request{Op: OpWrite, Path: path, HandleIno: handleIno, Offset: off, Data: data, Mode: mode})
	if err != nil {
		return 0, 0, 0, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return int(r.Count), r.Version, r.Gen, r.Status, nil
}

// AppendVHandle appends data atomically at authority EOF. It is one mutation
// RPC: no getattr/size read precedes it. Callers must gate on
// SupportsAtomicAppend.
func (c *Client) AppendVHandle(path string, handleIno uint64, data []byte, mode uint32) (count int, offset int64, version, gen uint64, status int32, err error) {
	r, err := c.Do(&Request{
		Op: OpWrite, Path: path, HandleIno: handleIno,
		Append: true, Data: data, Mode: mode,
	})
	if err != nil {
		return 0, 0, 0, 0, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return int(r.Count), r.Offset, r.Version, r.Gen, r.Status, nil
}

// LockResult is the outcome of an OpLock. For getlk, Conflict + the conflicting lock's range/type
// describe what WOULD block. For setlk/setlkw, Status is OK (granted) or EAGAIN (contended).
type LockResult struct {
	Status   int32
	Conflict bool
	CStart   uint64
	CEnd     uint64
	CWrite   bool
}

// Lock performs an advisory byte-range lock op (getlk/setlk/setlkw) against the single authority,
// so flock/fcntl are coordinated across machines. lkID is the kernel's per-open lock owner.
func (c *Client) Lock(path string, mode uint8, lkID, start, end uint64, write, unlock bool) (LockResult, error) {
	r, err := c.Do(&Request{
		Op: OpLock, Path: path, Owner: c.owner, LkMode: mode, LkID: lkID,
		LkStart: start, LkEnd: end, LkWrite: write, LkUnlock: unlock,
	})
	if err != nil {
		return LockResult{Status: EIO}, err
	}
	return LockResult{Status: r.Status, Conflict: r.LkConflict, CStart: r.LkStart, CEnd: r.LkEnd, CWrite: r.LkWrite}, nil
}

// ---- open-after-unlink (orphan) addressing ----

// Orphan detaches name from the tree but PARKS its inode so an open handle keeps addressing it by the
// returned ino after the name is gone. Issued instead of Remove when the mount still holds it open.
func (c *Client) Orphan(name string) (ino uint64, status int32, err error) {
	r, err := c.Do(&Request{Op: OpOrphan, Path: name, Owner: c.owner})
	if err != nil {
		return 0, EIO, err
	}
	return r.OrphanIno, r.Status, nil
}

// Reap frees a parked orphan on the last close of its final handle.
func (c *Client) Reap(ino uint64) (status int32, err error) {
	r, err := c.Do(&Request{Op: OpReap, OrphanIno: ino, Owner: c.owner})
	if err != nil {
		return EIO, err
	}
	return r.Status, nil
}

// RenewOrphanLeases extends the authority-side leases for parked orphans this mount still holds open.
func (c *Client) RenewOrphanLeases(inos []uint64) (status int32, err error) {
	if len(inos) == 0 {
		return OK, nil
	}
	r, err := c.Do(&Request{Op: OpRenewOrphanLeases, OrphanInos: append([]uint64(nil), inos...)})
	if err != nil {
		return EIO, err
	}
	return r.Status, nil
}

// MarkOpen registers that THIS mount holds ino open (Stage 2 authority open-state), so a cross-mount
// unlink of that inode PARKS it instead of removing it. Called eagerly on the first open of an inode.
func (c *Client) MarkOpen(ino uint64) (int32, error) {
	st, _, err := c.MarkOpenGen(ino)
	return st, err
}

// MarkOpenGen is MarkOpen returning the authority generation the registration
// landed under, so the client can stamp (and later re-validate) the hold.
// Against a managed authority the pin transition is a journaled coordination
// decision and rides an exact identity (doCoordinate); the legacy liveness
// mark stays envelope-less.
func (c *Client) MarkOpenGen(ino uint64) (int32, uint64, error) {
	req := &Request{Op: OpMarkOpen, OpenIno: ino, OpenState: true, Owner: c.owner}
	var r *Response
	var err error
	if c.serverManagedActive() {
		r, err = c.doCoordinate(req)
	} else {
		r, err = c.Do(req)
	}
	if err != nil {
		return EIO, 0, err
	}
	return r.Status, r.Gen, nil
}

// UnmarkOpen clears this mount's open hold on ino (its last local close).
func (c *Client) UnmarkOpen(ino uint64) (int32, error) {
	req := &Request{Op: OpMarkOpen, OpenIno: ino, OpenState: false, Owner: c.owner}
	var r *Response
	var err error
	if c.serverManagedActive() {
		r, err = c.doCoordinate(req)
	} else {
		r, err = c.Do(req)
	}
	if err != nil {
		return EIO, err
	}
	return r.Status, nil
}

// RenewOpenInodes refreshes the open leases for the inos this mount still holds open (periodic
// liveness, so a brief disconnect cannot drop the authority's view of what we hold open).
func (c *Client) RenewOpenInodes(inos []uint64) (int32, error) {
	st, _, err := c.RenewOpenInodesGen(inos)
	return st, err
}

// RenewOpenInodesGen is RenewOpenInodes returning the authority generation the
// renewal landed on, so the caller can re-validate generation-stamped
// registration state (a renewal against a restarted authority re-creates the
// holds there, making them valid under the NEW generation).
func (c *Client) RenewOpenInodesGen(inos []uint64) (int32, uint64, error) {
	if len(inos) == 0 {
		return OK, 0, nil
	}
	r, err := c.Do(&Request{Op: OpRenewOpenInodes, OpenInos: append([]uint64(nil), inos...), Owner: c.owner})
	if err != nil {
		return EIO, 0, err
	}
	return r.Status, r.Gen, nil
}

// UnmarkOpenBatch clears this mount's open holds on a batch of inos in one
// round-trip (OpUnmarkOpenInodes, FeatOpenRegistration). Callers gate on
// SupportsOpenRegistration; against an older authority use UnmarkOpen per ino.
// Against a managed authority the batch journals as one exact row and this
// call does not return until the identity RESOLVES (see
// unmarkOpenBatchManaged for why backgrounding it would be unsafe).
func (c *Client) UnmarkOpenBatch(inos []uint64) (int32, error) {
	if len(inos) == 0 {
		return OK, nil
	}
	req := &Request{Op: OpUnmarkOpenInodes, OpenInos: append([]uint64(nil), inos...), Owner: c.owner}
	if c.serverManagedActive() {
		return c.unmarkOpenBatchManaged(req)
	}
	r, err := c.Do(req)
	if err != nil {
		return EIO, err
	}
	return r.Status, nil
}

// GetattrOrphan stats a parked orphan by ino (fstat on an unlinked-but-open fd).
func (c *Client) GetattrOrphan(ino uint64) (*Attr, int32, error) {
	r, err := c.Do(&Request{Op: OpGetattr, OrphanIno: ino})
	if err != nil {
		return nil, EIO, err
	}
	return r.Attr, r.Status, nil
}

// ReadOrphan reads a parked orphan by ino (open-after-unlink).
func (c *Client) ReadOrphan(ino uint64, off, size int64) (data []byte, status int32, err error) {
	r, err := c.Do(&Request{Op: OpRead, OrphanIno: ino, Offset: off, Size: size})
	if err != nil {
		return nil, EIO, err
	}
	return r.Data, r.Status, nil
}

// WriteOrphan writes to a parked orphan by ino (open-after-unlink).
func (c *Client) WriteOrphan(ino uint64, off int64, data []byte) (count int, status int32, err error) {
	r, err := c.Do(&Request{Op: OpWrite, OrphanIno: ino, Offset: off, Data: data, Owner: c.owner})
	if err != nil {
		return 0, EIO, err
	}
	return int(r.Count), r.Status, nil
}

// AppendOrphan atomically appends to a parked open inode.
func (c *Client) AppendOrphan(ino uint64, data []byte) (count int, offset int64, status int32, err error) {
	r, err := c.Do(&Request{
		Op: OpWrite, OrphanIno: ino, Append: true,
		Data: data, Owner: c.owner,
	})
	if err != nil {
		return 0, 0, EIO, err
	}
	return int(r.Count), r.Offset, r.Status, nil
}

// TruncateOrphan truncates a parked orphan by ino (ftruncate on an unlinked-but-open fd).
func (c *Client) TruncateOrphan(ino uint64, size int64) (status int32, err error) {
	r, err := c.Do(&Request{Op: OpTruncate, OrphanIno: ino, Size: size, Owner: c.owner})
	if err != nil {
		return EIO, err
	}
	return r.Status, nil
}

// Close voluntarily expires the mount session (best-effort, bounded — the
// authority then releases this mount's locks/delegations immediately instead
// of waiting out the lease), stops the session goroutines, and closes all
// pooled connections.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.expireSessionOnClose()
		close(c.closed)
	})
	for {
		select {
		case cn := <-c.conns:
			cn.reset()
		default:
			return nil
		}
	}
}

// closeExpireTimeout bounds the clean-unmount session expire: a dead
// authority must not stall teardown (the lease sweeper will fence us anyway).
const closeExpireTimeout = 2 * time.Second

func (c *Client) expireSessionOnClose() {
	es := c.exactState()
	if es == nil || es.isFenced() {
		return
	}
	defer es.fence()
	select {
	case cn := <-c.conns:
		defer func() { c.conns <- cn }()
		if cn.nc == nil {
			return // not connected: never dial during teardown
		}
		if cn.attached != es.id {
			resp, err := cn.boundedRoundtrip(&Request{
				Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
			}, closeExpireTimeout)
			if err != nil || resp.Status != OK {
				return
			}
			cn.attached = es.id
		}
		_, _ = cn.boundedRoundtrip(&Request{
			Op: OpSessionExpire, SessionID: es.id, SessionGen: es.gen,
		}, closeExpireTimeout)
	default:
		// No idle pooled conn: skip the courtesy expire rather than block.
	}
}

// boundedRoundtrip is roundtrip with a caller-chosen deadline and NO redial:
// teardown paths must not hang on a dead authority.
func (cn *conn) boundedRoundtrip(req *Request, d time.Duration) (*Response, error) {
	if cn.nc == nil {
		return nil, fmt.Errorf("fsproto: connection not established")
	}
	_ = cn.nc.SetDeadline(time.Now().Add(d))
	if err := cn.enc.Encode(req); err != nil {
		cn.reset()
		return nil, err
	}
	var resp Response
	if err := cn.dec.Decode(&resp); err != nil {
		cn.reset()
		return nil, err
	}
	_ = cn.nc.SetDeadline(time.Time{})
	return &resp, nil
}

// ---- typed helpers for the FUSE layer ----

// Getattr returns a path's attributes (or an errno).
func (c *Client) Getattr(path string) (*Attr, int32, error) {
	return c.GetattrHandle(path, 0)
}

// GetattrHandle stats by an open file handle's stable ino when handleIno is non-zero.
func (c *Client) GetattrHandle(path string, handleIno uint64) (*Attr, int32, error) {
	r, err := c.Do(&Request{Op: OpGetattr, Path: path, HandleIno: handleIno})
	if err != nil {
		return nil, EIO, err
	}
	return r.Attr, r.Status, nil
}

// Stat reports a path's kind and mode in primitives (no *Attr), so the session package can
// determine a rename source's type without importing fsproto (which would cycle).
func (c *Client) Stat(path string) (kind string, mode uint32, status int32, err error) {
	a, st, err := c.Getattr(path)
	if err != nil || a == nil {
		return "", 0, st, err
	}
	return a.Kind, a.Mode, st, nil
}

// Readdir lists a directory.
// Readdir returns the directory's entries plus the authority generation the listing was taken at, so
// the mount can fill its attr cache from each Dirent's per-child Version under the same monotonic gate
// as a single Getattr (readdir-plus).
func (c *Client) Readdir(path string) ([]Dirent, uint64, int32, error) {
	ents, gen, _, st, err := c.ReaddirV(path)
	return ents, gen, st, err
}

// ReaddirV also returns the directory entry-list coherence version. A versioned
// frontend can cache the listing until the parent directory version advances.
func (c *Client) ReaddirV(path string) ([]Dirent, uint64, uint64, int32, error) {
	r, err := c.Do(&Request{Op: OpReaddir, Path: path})
	if err != nil {
		return nil, 0, 0, EIO, err
	}
	return r.Entries, r.Gen, r.Version, r.Status, nil
}

// Read reads up to size bytes at off.
func (c *Client) Read(path string, off, size int64) ([]byte, int32, error) {
	r, err := c.Do(&Request{Op: OpRead, Path: path, Offset: off, Size: size})
	if err != nil {
		return nil, EIO, err
	}
	return r.Data, r.Status, nil
}

// Write writes data at off and returns the byte count.
func (c *Client) Write(path string, off int64, data []byte, mode uint32) (int32, int32, error) {
	r, err := c.Do(&Request{Op: OpWrite, Path: path, Offset: off, Data: data, Mode: mode})
	if err != nil {
		return 0, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return r.Count, r.Status, nil
}

// ensureAttr backfills a nil Attr on a SUCCESSFUL response: a duplicate exact
// replay carries only the essential stored outcome (status/count/version/ino),
// but callers of the Attr-returning helpers dereference the result. Re-stat by
// the stable ino when we have one (rename-proof), else by path; if the inode
// raced away entirely, synthesize the minimal identity — the mount refreshes
// on its next lookup.
func (c *Client) ensureAttr(path, kind string, r *Response) *Attr {
	if r.Attr != nil || r.Status != OK {
		return r.Attr
	}
	if a, st, err := c.GetattrHandle(path, r.Ino); err == nil && st == OK && a != nil {
		return a
	}
	if r.Ino != 0 {
		if a, st, err := c.Getattr(path); err == nil && st == OK && a != nil {
			return a
		}
	}
	return &Attr{Kind: kind, Ino: r.Ino, Nlink: 1}
}

// Create makes (or truncates) a file and returns its attributes.
func (c *Client) Create(path string, mode uint32) (*Attr, int32, error) {
	a, _, st, err := c.create(path, mode, false, false)
	return a, st, err
}

// CreateExcl is Create with wire-level O_EXCL: a journal-native (managed)
// authority decides exclusivity atomically inside its ordered journal — two
// mounts on two machines cannot both win — and replays a durable EEXIST on a
// lost-response retry. Legacy servers ignore the flag, so callers there keep
// their lookup-then-create pre-check.
func (c *Client) CreateExcl(path string, mode uint32) (*Attr, int32, error) {
	a, _, st, err := c.create(path, mode, false, true)
	return a, st, err
}

// CreateRegisterOpen creates path AND registers this mount's open hold on the
// resulting inode in the same round-trip (Request.RegisterOpen,
// FeatOpenRegistration): the kernel CREATE is create+open, so the hold must be
// recorded before the create returns anyway — fusing it removes the separate
// MarkOpen round-trip without moving the open-vs-unlink race decision point.
// ENOENT means the just-created inode was already unlinked by a peer inside
// the registration window: the caller fails the open, exactly like a MarkOpen
// ENOENT. gen is the authority generation the registration is valid under.
// Callers gate on SupportsOpenRegistration.
func (c *Client) CreateRegisterOpen(path string, mode uint32) (*Attr, uint64, int32, error) {
	return c.create(path, mode, true, false)
}

// CreateExclRegisterOpen fuses wire-level O_EXCL (see CreateExcl) with open
// registration (see CreateRegisterOpen) in one round-trip.
func (c *Client) CreateExclRegisterOpen(path string, mode uint32) (*Attr, uint64, int32, error) {
	return c.create(path, mode, true, true)
}

func (c *Client) create(path string, mode uint32, registerOpen, excl bool) (*Attr, uint64, int32, error) {
	r, err := c.Do(&Request{Op: OpCreate, Path: path, Mode: mode, RegisterOpen: registerOpen, Excl: excl})
	if err != nil {
		return nil, 0, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, false)
	}
	return c.ensureAttr(path, "file", r), r.Gen, r.Status, nil
}

// Mkdir makes a directory and returns its attributes.
func (c *Client) Mkdir(path string, mode uint32) (*Attr, int32, error) {
	r, err := c.Do(&Request{Op: OpMkdir, Path: path, Mode: mode})
	if err != nil {
		return nil, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, false)
	}
	return c.ensureAttr(path, "directory", r), r.Status, nil
}

// Remove deletes a file or empty directory.
func (c *Client) Remove(path string) (int32, error) {
	r, err := c.Do(&Request{Op: OpRemove, Path: path})
	if err != nil {
		return EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, false)
	}
	return r.Status, nil
}

// Rename moves oldPath to newPath.
func (c *Client) Rename(oldPath, newPath string) (int32, error) {
	st, _, err := c.RenameWithOrphanTarget(oldPath, newPath, false)
	return st, err
}

// RenameWithOrphanTarget renames oldPath->newPath; when orphanTarget is set and newPath is currently
// open at this mount, the authority parks the replaced destination by ino and returns it (so the
// mount keeps serving the open fds by ino — rename-over-an-open-file). orphanTarget=false is plain rename.
func (c *Client) RenameWithOrphanTarget(oldPath, newPath string, orphanTarget bool) (int32, uint64, error) {
	r, err := c.Do(&Request{Op: OpRename, Path: oldPath, NewPath: newPath, OrphanTarget: orphanTarget})
	if err != nil {
		return EIO, 0, err
	}
	if r.Status == OK {
		// The server stamps the rename's namespace version on the new path, but workfs publishes the
		// same version for both old and new names. Update both locally because our stream echo is
		// owner-suppressed.
		c.selfWrote(oldPath, r, false)
		c.selfWrote(newPath, r, false)
	}
	return r.Status, r.OrphanIno, nil
}

// Symlink creates link -> target and returns the link's attributes.
func (c *Client) Symlink(target, link string) (*Attr, int32, error) {
	r, err := c.Do(&Request{Op: OpSymlink, Path: link, Target: target})
	if err != nil {
		return nil, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(link, r, false)
	}
	return c.ensureAttr(link, "symlink", r), r.Status, nil
}

// Link adds newPath as another name for oldPath's non-directory inode. The
// returned attributes describe the shared inode after nlink increments.
func (c *Client) Link(oldPath, newPath string) (*Attr, int32, error) {
	if !c.SupportsHardLinks() {
		return nil, EOPNOTSUPP, nil
	}
	r, err := c.Do(&Request{Op: OpLink, Path: oldPath, NewPath: newPath})
	if err != nil {
		return nil, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(oldPath, r, false)
		c.selfWrote(newPath, r, false)
	}
	return c.ensureAttr(newPath, "file", r), r.Status, nil
}

// Readlink returns a symlink's target.
func (c *Client) Readlink(path string) (string, int32, error) {
	r, err := c.Do(&Request{Op: OpReadlink, Path: path})
	if err != nil {
		return "", EIO, err
	}
	return r.Target, r.Status, nil
}

// Setattr applies a chmod and/or mtime change.
func (c *Client) Setattr(path string, mode uint32, setMode bool, mtimeMs int64, setTime bool, uid, gid uint32, setUID, setGID bool) (int32, error) {
	return c.SetattrHandle(path, 0, mode, setMode, mtimeMs, setTime, uid, gid, setUID, setGID)
}

// SetattrHandle applies metadata by an open file handle's stable ino when handleIno is non-zero.
//
// Under exact sessions each identity maps 1:1 to a single WAL record, so a
// kernel SETATTR carrying several attribute groups (mode + times + owner) is
// split into one exact mutation per group; a v1 server keeps receiving the
// combined request unchanged.
func (c *Client) SetattrHandle(path string, handleIno uint64, mode uint32, setMode bool, mtimeMs int64, setTime bool, uid, gid uint32, setUID, setGID bool) (int32, error) {
	groups := make([]*Request, 0, 3)
	if setMode {
		groups = append(groups, &Request{Op: OpSetattr, Path: path, HandleIno: handleIno, Mode: mode, SetMode: true})
	}
	if setTime {
		groups = append(groups, &Request{Op: OpSetattr, Path: path, HandleIno: handleIno, MtimeMs: mtimeMs, SetTime: true})
	}
	if setUID || setGID {
		groups = append(groups, &Request{Op: OpSetattr, Path: path, HandleIno: handleIno, UID: uid, GID: gid, SetUID: setUID, SetGID: setGID})
	}
	if len(groups) != 1 && c.sessionsEnabled() && !c.serverIsLegacy() {
		for _, g := range groups {
			r, err := c.Do(g)
			if err != nil {
				return EIO, err
			}
			if r.Status != OK {
				return r.Status, nil
			}
			c.selfWrote(path, r, true)
		}
		return OK, nil
	}
	r, err := c.Do(&Request{
		Op: OpSetattr, Path: path, HandleIno: handleIno,
		Mode: mode, SetMode: setMode,
		MtimeMs: mtimeMs, SetTime: setTime,
		UID: uid, GID: gid, SetUID: setUID, SetGID: setGID,
	})
	if err != nil {
		return EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return r.Status, nil
}

// ---- extended attributes (FeatXattrs; callers gate on SupportsXattrs) ----

// Getxattr reads one extended attribute. handleIno addresses an open handle's
// stable ino when non-zero (named or parked orphan). ENODATA = not present.
func (c *Client) Getxattr(path string, handleIno uint64, name string) ([]byte, int32, error) {
	r, err := c.Do(&Request{Op: OpGetxattr, Path: path, HandleIno: handleIno, XattrName: name})
	if err != nil {
		return nil, EIO, err
	}
	return r.Data, r.Status, nil
}

// Listxattr lists the extended-attribute names of path (sorted).
func (c *Client) Listxattr(path string, handleIno uint64) ([]string, int32, error) {
	r, err := c.Do(&Request{Op: OpListxattr, Path: path, HandleIno: handleIno})
	if err != nil {
		return nil, EIO, err
	}
	return r.XattrNames, r.Status, nil
}

// Setxattr creates-or-overwrites one extended attribute (last writer wins).
// Bounds: ERANGE oversized name, E2BIG oversized value, ENOSPC per-inode total.
func (c *Client) Setxattr(path string, handleIno uint64, name string, value []byte) (int32, error) {
	return c.SetxattrFlags(path, handleIno, name, value, 0)
}

// SetxattrFlags applies wal.XattrCreate/wal.XattrReplace atomically at the
// authority's ordered mutation position.
func (c *Client) SetxattrFlags(path string, handleIno uint64, name string, value []byte, flags uint8) (int32, error) {
	if flags != 0 && !c.SupportsAtomicXattrFlags() {
		return EOPNOTSUPP, nil
	}
	r, err := c.Do(&Request{
		Op: OpSetxattr, Path: path, HandleIno: handleIno,
		XattrName: name, XattrFlags: flags, Data: value,
	})
	if err != nil {
		return EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true) // attr-level in-place change, like chmod
	}
	return r.Status, nil
}

// Removexattr removes one extended attribute; a missing name is ENODATA.
func (c *Client) Removexattr(path string, handleIno uint64, name string) (int32, error) {
	r, err := c.Do(&Request{Op: OpRemovexattr, Path: path, HandleIno: handleIno, XattrName: name})
	if err != nil {
		return EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return r.Status, nil
}

// Truncate resizes a file.
func (c *Client) Truncate(path string, size int64) (int32, error) {
	return c.TruncateHandle(path, 0, size)
}

// TruncateHandle truncates by an open file handle's stable ino when handleIno is non-zero.
func (c *Client) TruncateHandle(path string, handleIno uint64, size int64) (int32, error) {
	r, err := c.Do(&Request{Op: OpTruncate, Path: path, HandleIno: handleIno, Size: size})
	if err != nil {
		return EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return r.Status, nil
}

func (a Attr) String() string {
	return fmt.Sprintf("%s size=%d mode=%o", a.Kind, a.Size, a.Mode)
}
