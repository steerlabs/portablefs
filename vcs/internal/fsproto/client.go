package fsproto

import (
	"context"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
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
// own framed request encoder and gob response decoder and serves one request at
// a time, so concurrent FUSE ops run on separate connections up to the pool
// size. Connections lazily re-dial, so a mount rides through a VCS restart or
// failover. Multiple authority addresses may be given (comma-separated): a
// connection tries each in order, so when the primary dies the mount follows
// over to a promoted standby without an external VIP. A non-nil tls config
// encrypts every connection.
type Client struct {
	addrs      []string
	tls        *tls.Config
	conns      chan *conn
	poolSize   int
	pool       []*conn
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

	// onSelfWrite, if set, is called after every successful write-through MUTATION with the path,
	// the version the authority assigned, and whether the mutation was in-place. This lets the
	// mount update/evict its own caches for owner-suppressed invalidation echoes. nil => no-op.
	onSelfWrite func(path string, gen, version uint64, inPlace bool)

	// Exact mount-session state. exact is nil until EnsureExactSession
	// establishes it (negotiating the mandatory v8 protocol first).
	exactMu     sync.RWMutex
	establishMu sync.Mutex // serializes the one-time session establish
	exact       *exactSession
	exactSlots  uint32
	closed      chan struct{}
	closeOnce   sync.Once
	poolOnce    sync.Once

	// lifecycleMu serializes the terminal close transition with transport
	// adoption. A dial that returns after Close/Abort cannot install its
	// socket or authenticate/send on it. It also protects the set of
	// non-pooled transports (subscriptions and reachability probes), whose
	// owners are joined before teardown returns.
	lifecycleMu     sync.Mutex
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	dedicated       map[*conn]struct{}
	dedicatedWG     sync.WaitGroup

	// health tracks authority transport reachability (the fail-fast breaker,
	// see failfast.go); shared by every pooled, subscribe, and probe conn.
	health *connHealth
	// transport, when set, is the in-process dialer the pool was built with;
	// the reachability prober needs it to build a probe conn (net.Pipe etc.).
	transport transportDialer
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
	// in-process transports such as net.Pipe). It receives the owning
	// client's lifecycle context, and the auth handshake still runs.
	transport transportDialer
	// client is the owning pool's client, when there is one: dial success
	// resets its shared redial backoff.
	client  *Client
	stateMu sync.Mutex
	nc      net.Conn
	enc     *requestEncoder
	dec     *gob.Decoder
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
// (whose retry policy owns the pacing). An explicit token rejection is a
// terminal credential result and is returned without another resolution path.
func (cn *conn) ensure() error {
	return cn.ensureWithGate(false)
}

// ensureWithGate lets one explicit resolution loop perform its own
// backoff-paced real attempt while ordinary operations remain fail-fast
// gated. The caller still owns one pooled connection and every dial is
// bounded and health-accounted; a successful attempt is the probe that
// clears the shared reachability state.
func (cn *conn) ensureWithGate(resolved bool) error {
	return cn.ensureWithGateContext(context.Background(), resolved)
}

func (cn *conn) ensureWithGateContext(ctx context.Context, resolved bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cn.connected() {
		return nil
	}
	if cn.client != nil && cn.client.isClosed() {
		return net.ErrClosed
	}
	if err := cn.health.gate(cn.gateExempt || resolved); err != nil {
		return err
	}
	err := cn.dialOnceContext(ctx)
	if err == nil {
		cn.health.recordSuccess()
		if cn.client != nil && cn.client.redial != nil {
			cn.client.redial.Reset()
		}
		return nil
	}
	// A definite token rejection is an ANSWER from a reachable peer, not
	// unreachability (see failfast.go), so it does not trip the transport
	// breaker. It still returns immediately and fails closed.
	if !errors.Is(err, ErrSessionTokenRejected) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		cn.health.recordFailure()
	}
	return err
}

// dialOnce makes one dial pass: the in-process transport, or each authority
// address in order — the first that connects AND completes the auth handshake
// wins, so a dead/fenced primary (listener closed) is skipped and the mount
// lands on a promoted standby. An explicit token rejection ends the pass
// immediately: every address shares the same credential, so offering a dead
// token to the rest of the list only adds to the reconnect storm.
func (cn *conn) dialOnce() error {
	return cn.dialOnceContext(context.Background())
}

func (cn *conn) dialOnceContext(ctx context.Context) error {
	token := secure.AuthToken()
	if cn.auth != nil {
		token = cn.auth()
	}
	dialCtx, cancelDial := context.WithCancel(ctx)
	defer cancelDial()
	stopLifecycle := func() bool { return true }
	if cn.client != nil && cn.client.lifecycleCtx != nil {
		stopLifecycle = context.AfterFunc(cn.client.lifecycleCtx, cancelDial)
	}
	defer stopLifecycle()
	if cn.transport != nil {
		nc, err := cn.transport(dialCtx)
		if err != nil {
			if dialCtx.Err() != nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				return net.ErrClosed
			}
			return err
		}
		if err := dialCtx.Err(); err != nil {
			_ = nc.Close()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return net.ErrClosed
		}
		if err := cn.adoptTransport(nc); err != nil {
			return err
		}
		if err := dialCtx.Err(); err != nil {
			cn.reset()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return net.ErrClosed
		}
		if err := clientHandshake(nc, token); err != nil {
			cn.reset()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return err
		}
		if err := dialCtx.Err(); err != nil {
			cn.reset()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return net.ErrClosed
		}
		if err := cn.finishTransport(nc); err != nil {
			cn.reset()
			return err
		}
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
		if err := dialCtx.Err(); err != nil {
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return net.ErrClosed
		}
		var (
			nc  net.Conn
			err error
		)
		if cn.tls != nil {
			tlsDialer := &tls.Dialer{NetDialer: dialer, Config: cn.tls}
			nc, err = tlsDialer.DialContext(dialCtx, "tcp", addr)
		} else {
			nc, err = dialer.DialContext(dialCtx, "tcp", addr)
		}
		if err != nil {
			if dialCtx.Err() != nil {
				if callerErr := ctx.Err(); callerErr != nil {
					return callerErr
				}
				return net.ErrClosed
			}
			lastErr = err
			continue
		}
		if err := cn.adoptTransport(nc); err != nil {
			return err
		}
		if err := dialCtx.Err(); err != nil {
			cn.reset()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return net.ErrClosed
		}
		// Authenticate to the server before using the connection (no-op when
		// unset). The typed classification is the point: rejection means the
		// CREDENTIAL is dead, not the network.
		if err := clientHandshake(nc, token); err != nil {
			cn.reset()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			if errors.Is(err, ErrSessionTokenRejected) {
				return fmt.Errorf("fsproto: dial %s: %w", addr, err)
			}
			lastErr = err
			continue
		}
		if err := dialCtx.Err(); err != nil {
			cn.reset()
			if callerErr := ctx.Err(); callerErr != nil {
				return callerErr
			}
			return net.ErrClosed
		}
		if err := cn.finishTransport(nc); err != nil {
			cn.reset()
			return err
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("fsproto: no authority addresses configured")
	}
	return lastErr
}

func (cn *conn) reset() {
	cn.stateMu.Lock()
	nc := cn.nc
	cn.nc, cn.enc, cn.dec = nil, nil, nil
	cn.stateMu.Unlock()
	if nc != nil {
		_ = nc.Close()
	}
	cn.attached = ""
}

// adoptTransport publishes a freshly dialed socket before authentication so
// Close/Abort can interrupt a blocked handshake. The client lifecycle gate
// rejects and closes sockets returned by a dial after terminal closure.
func (cn *conn) adoptTransport(nc net.Conn) error {
	if cn.client != nil {
		cn.client.lifecycleMu.Lock()
		defer cn.client.lifecycleMu.Unlock()
		if cn.client.isClosed() {
			_ = nc.Close()
			return net.ErrClosed
		}
	}
	cn.stateMu.Lock()
	cn.nc, cn.enc, cn.dec = nc, nil, nil
	cn.stateMu.Unlock()
	return nil
}

// finishTransport makes an authenticated socket request-capable. It shares
// the close gate with adoption, so a handshake that races terminal closure
// cannot publish encoders and proceed to an authority request.
func (cn *conn) finishTransport(nc net.Conn) error {
	if cn.client != nil {
		cn.client.lifecycleMu.Lock()
		defer cn.client.lifecycleMu.Unlock()
		if cn.client.isClosed() {
			return net.ErrClosed
		}
	}
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()
	if cn.nc != nc {
		return net.ErrClosed
	}
	cn.enc, cn.dec = newRequestEncoder(nc), gob.NewDecoder(nc)
	return nil
}

func (cn *conn) connected() bool {
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()
	return cn.nc != nil && cn.enc != nil && cn.dec != nil
}

func (cn *conn) transportState() (net.Conn, *requestEncoder, *gob.Decoder) {
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()
	return cn.nc, cn.enc, cn.dec
}

// interrupt closes the current socket without rewriting conn state. A
// checked-out roundtrip immediately wakes and owns reset; an idle connection
// is reset by the pool closer after it is received.
func (cn *conn) interrupt() {
	cn.stateMu.Lock()
	nc := cn.nc
	cn.stateMu.Unlock()
	if nc != nil {
		_ = nc.Close()
	}
}

func (cn *conn) roundtrip(req *Request) (*Response, error) {
	resp, _, err := cn.roundtripSent(req)
	return resp, err
}

// roundtripSent is roundtrip plus the ambiguity boundary needed by
// resolved-side-effect operations. Request shape and allocation bounds are
// checked before any transport work; a preflight rejection is therefore
// provably unsent. Once encoding starts, an error is conservatively ambiguous
// because it may follow a partial transport write.
func (cn *conn) roundtripSent(req *Request) (*Response, bool, error) {
	return cn.roundtripSentWithGate(req, false)
}

func (cn *conn) roundtripSentWithGate(req *Request, resolved bool) (*Response, bool, error) {
	return cn.roundtripSentWithGateContext(context.Background(), req, resolved)
}

func (cn *conn) roundtripSentWithGateContext(ctx context.Context, req *Request, resolved bool) (*Response, bool, error) {
	prepared, err := prepareRequest(req)
	if err != nil {
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	// Gate before dialing/sending: while fail-fast is engaged, a non-exempt op
	// fails immediately with ErrAuthorityUnreachable instead of burning a full
	// opTimeout socket deadline against a confirmed-dead peer.
	if err := cn.health.gate(cn.gateExempt || resolved); err != nil {
		return nil, false, err
	}
	if err := cn.ensureWithGateContext(ctx, resolved); err != nil {
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if cn.client != nil && cn.client.isClosed() {
		cn.reset()
		return nil, false, net.ErrClosed
	}
	nc, enc, dec := cn.transportState()
	if nc == nil || enc == nil || dec == nil {
		return nil, false, errors.New("fsproto: connection transport disappeared")
	}
	// Bound the round-trip so a partitioned VCS surfaces as EIO (idempotent ops then
	// retry) instead of hanging the FUSE op until the OS TCP timeout. The conn is
	// reset on any error, so the deadline never leaks onto a reused connection.
	deadline := time.Now().Add(opTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	_ = nc.SetDeadline(deadline)
	if err := enc.encodePrepared(req, prepared); err != nil {
		if ctx.Err() == nil {
			cn.health.recordFailure()
		}
		cn.reset()
		return nil, true, err
	}
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		if ctx.Err() == nil {
			cn.health.recordFailure()
		}
		cn.reset()
		return nil, true, err
	}
	_ = nc.SetDeadline(time.Time{})
	cn.health.recordSuccess()
	return &resp, true, nil
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
	return dialPool("in-process", pool, nil, nil, adaptLegacyTransport(transport))
}

// transportDialer is the one internal transport boundary. Every dial observes
// the client's terminal lifecycle cancellation before it can hand a socket to
// authentication or request framing.
type transportDialer func(context.Context) (net.Conn, error)

// adaptLegacyTransport preserves DialWithTransport's context-less API while
// making client teardown independent of a callback that has not returned yet.
// The unbuffered handoff is intentional: if cancellation wins, a callback
// that eventually returns cannot strand its socket in an abandoned result
// channel; the adapter closes that late socket instead.
func adaptLegacyTransport(transport func() (net.Conn, error)) transportDialer {
	if transport == nil {
		return nil
	}
	return func(ctx context.Context) (net.Conn, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		if ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		type result struct {
			conn net.Conn
			err  error
		}
		resultCh := make(chan result)
		go func() {
			conn, err := transport()
			select {
			case resultCh <- result{conn: conn, err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
		select {
		case got := <-resultCh:
			if ctx.Err() != nil {
				if got.conn != nil {
					_ = got.conn.Close()
				}
				return nil, net.ErrClosed
			}
			return got.conn, got.err
		case <-ctx.Done():
			return nil, net.ErrClosed
		}
	}
}

func dialPool(addr string, pool int, tlsCfg *tls.Config, auth func() string, transport transportDialer) (*Client, error) {
	if pool < 1 {
		pool = 1
	}
	addrs := splitAddrs(addr)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("fsproto: no authority address given")
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	c := &Client{
		addrs: addrs, tls: tlsCfg, conns: make(chan *conn, pool),
		closed:          make(chan struct{}),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		dedicated:       make(map[*conn]struct{}),
		redial:          NewBackoff(DefaultReconnectBase, DefaultReconnectCap),
		transport:       transport,
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
		c.poolSize++
		c.pool = append(c.pool, cn)
	}
	return c, nil
}

// Do sends a request on a pooled connection.
//
// Tree mutations route through the exact-once machinery (doExact): each
// carries a (session, generation, slot, slot-sequence) identity, so a retry
// after a lost reply returns the STORED outcome instead of re-executing.
// Idempotent reads retry once across a re-dial.
func (c *Client) Do(req *Request) (*Response, error) {
	return c.DoContext(context.Background(), req)
}

type authorityWaitContextKey struct{}

// WithAuthorityWait arranges for every DoContext issued with ctx to bracket
// its complete authority attempt with wait/resume. The hook is intentionally
// per-call rather than client-global: concurrent frontend operations have
// independent publication participants. DoContext resumes after the final
// reply (or joined cancellation) and before typed helpers publish self-write
// metadata from that reply.
func WithAuthorityWait(ctx context.Context, wait func() (resume func())) context.Context {
	if wait == nil {
		return ctx
	}
	return context.WithValue(ctx, authorityWaitContextKey{}, wait)
}

func beginAuthorityWait(ctx context.Context) func() {
	wait, _ := ctx.Value(authorityWaitContextKey{}).(func() func())
	if wait == nil {
		return func() {}
	}
	resume := wait()
	if resume == nil {
		return func() {}
	}
	return resume
}

// DoContext is Do with caller lifetime propagation. Cancellation interrupts
// and joins the checked-out transport before it can be returned to the pool,
// so an abandoned frontend read cannot remain live and later install a stale
// authority sample. Exact mutations retain their existing exact-once
// resolution semantics; their identities cannot be abandoned after send.
func (c *Client) DoContext(ctx context.Context, req *Request) (*Response, error) {
	resumeAuthority := beginAuthorityWait(ctx)
	defer resumeAuthority()
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
	if exactOp(req.Op) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Once an exact identity can be sent, caller cancellation cannot
		// release the surrounding namespace/delegation exclusion while that
		// identity may still execute. Resolve through the existing exact-once
		// path; the authority-wait hook remains suspended until it returns.
		return c.doExact(req)
	}
	if req.Op == OpFlushBatch {
		// FlushBatch keeps its own durable ledger exactness, but it must
		// arrive on a connection whose authenticated mount session owns the
		// flush. Establish once; pooled conns then attach lazily in
		// prepareConn. A fenced mount must never flush old dirty write-back
		// bytes over its successor's state.
		if c.SessionFenced() {
			return &Response{Status: ESTALE}, nil
		}
		if _, err := c.EnsureExactSession(); err != nil {
			return nil, err
		}
	}
	cn, err := c.takeConnContext(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { c.conns <- cn }()
	if ctx.Done() != nil {
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
	}
	var lastErr error
	for attempt := 0; attempt < opDialAttempts; attempt++ {
		if attempt >= 2 {
			// The first redial is immediate — a stale pooled socket after an
			// authority restart recovers in one hop, exactly the old single
			// silent retry. From there the SHARED full-jitter backoff paces
			// every further attempt so op traffic against a dead authority
			// decays instead of hammering.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.closed:
				return nil, lastErr
			case <-time.After(c.redial.Next()):
			}
		}
		err := c.prepareConnContext(ctx, cn)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			if errors.Is(err, ErrAuthorityUnreachable) {
				// Fail-fast engaged: the authority is confirmed unreachable and
				// the reachability prober (not this op's retry loop) owns
				// recovery. Retrying here only burns the backoff budget
				// re-consulting the gate; surface EIO immediately.
				return nil, err
			}
			if errors.Is(err, ErrSessionTokenRejected) {
				// A rejection cannot be fixed by redialing with the same
				// credential. Fail closed without another resolution path.
				return nil, err
			}
			if cn.connected() {
				// Connected but refused at the protocol level (a session
				// attach refusal): a redial cannot change the answer.
				return nil, err
			}
			continue
		}
		resp, _, err := cn.roundtripSentWithGateContext(ctx, req, false)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
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

// AckFunc acknowledges that the subscriber has processed every invalidation
// batch up to pos. The authority's barriers wait on these acknowledgments,
// so the consumer must call it only AFTER applying the batch to its caches.
type AckFunc func(pos uint64)

// Subscribe opens a dedicated connection that streams cache invalidations (a
// batch of changed paths; nil means flush everything). The channel closes if
// the connection drops; the caller re-subscribes and flushes. The returned
// AckFunc reports processed stream positions back to the authority — the
// cross-machine half of fsync (a barrier completes only after every live
// subscriber acknowledged its position).
//
// The stream conn is session-attached when an exact session is live, which
// switches the authority's cleanup model for this mount from "release
// checkouts/locks on stream drop" (legacy liveness) to session-lease expiry —
// a socket flap then releases nothing.
func (c *Client) Subscribe() (<-chan coherence.Batch, AckFunc, error) {
	// gateExempt: the subscribe stream is a recovery path — its 500ms reconnect
	// loop doubles as an on-demand reachability probe, so it must dial even
	// while fail-fast is engaged (clearing the breaker on the first success).
	cn := &conn{
		addrs:      c.addrs,
		tls:        c.tls,
		auth:       c.tokenForHandshake,
		transport:  c.transport,
		client:     c,
		health:     c.health,
		gateExempt: true,
	}
	if !c.registerDedicated(cn) {
		return nil, nil, net.ErrClosed
	}
	handedOff := false
	defer func() {
		if !handedOff {
			cn.reset()
			c.unregisterDedicated(cn)
		}
	}()
	if err := cn.ensure(); err != nil {
		return nil, nil, err
	}
	if c.isClosed() {
		return nil, nil, net.ErrClosed
	}
	if es := c.exactState(); es != nil && !es.isFenced() {
		resp, err := cn.roundtrip(&Request{
			Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
		})
		if err != nil {
			return nil, nil, err
		}
		if resp.Status != OK {
			// A subscription stream that could not authenticate its session
			// MUST NOT serve: its liveness/ownership semantics would be
			// wrong. Abort; the caller resubscribes (or the fence stands).
			if resp.Status == ESTALE {
				es.fence()
			}
			return nil, nil, statusError("subscribe session attach", resp.Status)
		}
		cn.attached = es.id
	}
	if c.isClosed() {
		return nil, nil, net.ErrClosed
	}
	if err := cn.enc.Encode(&Request{Op: OpSubscribe, Owner: c.owner}); err != nil {
		return nil, nil, err
	}
	// Acks are the only writes after the subscribe request; serialize them
	// (the reader goroutine only decodes, so writes race nothing else).
	var ackMu sync.Mutex
	ack := func(pos uint64) {
		ackMu.Lock()
		defer ackMu.Unlock()
		if cn.nc == nil || cn.enc == nil {
			return
		}
		_ = cn.nc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
		// A failed ack write is resolved by the stream teardown: the server
		// drops the subscriber from the barrier set when the conn dies.
		_ = cn.enc.Encode(&Request{Op: OpInvalidationAck, AckPos: pos})
		_ = cn.nc.SetWriteDeadline(time.Time{})
	}
	ch := make(chan coherence.Batch, 1024)
	handedOff = true
	go func() {
		defer close(ch)
		defer func() {
			ackMu.Lock()
			cn.reset()
			ackMu.Unlock()
			c.unregisterDedicated(cn)
		}()
		deliver := func(batch coherence.Batch) bool {
			select {
			case ch <- batch:
				return true
			case <-c.closed:
				return false
			}
		}
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
				if !deliver(coherence.Batch{
					Pos: resp.InvPos, Bootstrap: resp.InvBootstrap,
					Invs: []coherence.Invalidation{{Gen: resp.Gen}},
				}) {
					return
				}
				continue
			}
			if len(resp.Invs) > 0 {
				if !deliver(coherence.Batch{Pos: resp.InvPos, Invs: resp.Invs}) {
					return
				}
			}
		}
	}()
	return ch, ack, nil
}

// ReadV reads up to n bytes at off and returns the path's coherence version and the
// authority generation alongside the bytes, so the mount can do generation-aware,
// monotonic cache fills (install a read result only if it is not older than what it holds).
func (c *Client) ReadV(path string, off, n int64) (data []byte, version, gen uint64, status int32, err error) {
	return c.ReadVHandle(path, 0, off, n)
}

// ReadVHandle is ReadV addressed by an open file handle's stable ino when handleIno is non-zero.
func (c *Client) ReadVHandle(path string, handleIno uint64, off, n int64) (data []byte, version, gen uint64, status int32, err error) {
	return c.ReadVHandleContext(context.Background(), path, handleIno, off, n)
}

// ReadVHandleContext is ReadVHandle with caller lifetime propagation.
func (c *Client) ReadVHandleContext(ctx context.Context, path string, handleIno uint64, off, n int64) (data []byte, version, gen uint64, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpRead, Path: path, HandleIno: handleIno, Offset: off, Size: n})
	if err != nil {
		return nil, 0, 0, EIO, err
	}
	return r.Data, r.Version, r.Gen, r.Status, nil
}

// GetattrV stats a path and returns its coherence version and the authority generation. On ENOENT,
// parentVersion is the parent directory version PLUS ONE; zero means the authority did not provide
// safe negative-cache metadata.
func (c *Client) GetattrV(path string) (a Attr, version, gen, parentVersion uint64, status int32, err error) {
	return c.GetattrVContext(context.Background(), path)
}

// GetattrVContext is the cancellable form used by frontend authority reads.
func (c *Client) GetattrVContext(ctx context.Context, path string) (a Attr, version, gen, parentVersion uint64, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpGetattr, Path: path})
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
	return c.WriteVHandleContext(context.Background(), path, handleIno, off, data, mode)
}

func (c *Client) WriteVHandleContext(ctx context.Context, path string, handleIno uint64, off int64, data []byte, mode uint32) (count int, version, gen uint64, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpWrite, Path: path, HandleIno: handleIno, Offset: off, Data: data, Mode: mode})
	if err != nil {
		return 0, 0, 0, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, true)
	}
	return int(r.Count), r.Version, r.Gen, r.Status, nil
}

// AppendVHandle appends data atomically at authority EOF. It is one mutation
// RPC: no getattr/size read precedes it.
func (c *Client) AppendVHandle(path string, handleIno uint64, data []byte, mode uint32) (count int, offset int64, version, gen uint64, status int32, err error) {
	return c.AppendVHandleContext(context.Background(), path, handleIno, data, mode)
}

func (c *Client) AppendVHandleContext(ctx context.Context, path string, handleIno uint64, data []byte, mode uint32) (count int, offset int64, version, gen uint64, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{
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
	return c.LockContext(context.Background(), path, mode, lkID, start, end, write, unlock)
}

func (c *Client) LockContext(ctx context.Context, path string, mode uint8, lkID, start, end uint64, write, unlock bool) (LockResult, error) {
	r, err := c.DoContext(ctx, &Request{
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
	return c.OrphanContext(context.Background(), name)
}

func (c *Client) OrphanContext(ctx context.Context, name string) (ino uint64, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpOrphan, Path: name, Owner: c.owner})
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
// The pin transition is a journaled coordination decision riding an exact
// identity (doCoordinate).
func (c *Client) MarkOpenGen(ino uint64) (int32, uint64, error) {
	r, err := c.doCoordinate(&Request{Op: OpMarkOpen, OpenIno: ino, OpenState: true, Owner: c.owner})
	if err != nil {
		return EIO, 0, err
	}
	return r.Status, r.Gen, nil
}

// UnmarkOpen clears this mount's open hold on ino (its last local close).
func (c *Client) UnmarkOpen(ino uint64) (int32, error) {
	r, err := c.doCoordinate(&Request{Op: OpMarkOpen, OpenIno: ino, OpenState: false, Owner: c.owner})
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
// round-trip (OpUnmarkOpenInodes). The batch journals as one exact row and
// this call does not return until the identity RESOLVES (see
// unmarkOpenBatchManaged for why backgrounding it would be unsafe).
func (c *Client) UnmarkOpenBatch(inos []uint64) (int32, error) {
	if len(inos) == 0 {
		return OK, nil
	}
	return c.unmarkOpenBatchManaged(&Request{Op: OpUnmarkOpenInodes, OpenInos: append([]uint64(nil), inos...), Owner: c.owner})
}

// GetattrOrphan stats a parked orphan by ino (fstat on an unlinked-but-open fd).
func (c *Client) GetattrOrphan(ino uint64) (*Attr, int32, error) {
	return c.GetattrOrphanContext(context.Background(), ino)
}

func (c *Client) GetattrOrphanContext(ctx context.Context, ino uint64) (*Attr, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpGetattr, OrphanIno: ino})
	if err != nil {
		return nil, EIO, err
	}
	return r.Attr, r.Status, nil
}

// ReadOrphan reads a parked orphan by ino (open-after-unlink).
func (c *Client) ReadOrphan(ino uint64, off, size int64) (data []byte, status int32, err error) {
	return c.ReadOrphanContext(context.Background(), ino, off, size)
}

func (c *Client) ReadOrphanContext(ctx context.Context, ino uint64, off, size int64) (data []byte, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpRead, OrphanIno: ino, Offset: off, Size: size})
	if err != nil {
		return nil, EIO, err
	}
	return r.Data, r.Status, nil
}

// WriteOrphan writes to a parked orphan by ino (open-after-unlink).
func (c *Client) WriteOrphan(ino uint64, off int64, data []byte) (count int, status int32, err error) {
	return c.WriteOrphanContext(context.Background(), ino, off, data)
}

func (c *Client) WriteOrphanContext(ctx context.Context, ino uint64, off int64, data []byte) (count int, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpWrite, OrphanIno: ino, Offset: off, Data: data, Owner: c.owner})
	if err != nil {
		return 0, EIO, err
	}
	return int(r.Count), r.Status, nil
}

// AppendOrphan atomically appends to a parked open inode.
func (c *Client) AppendOrphan(ino uint64, data []byte) (count int, offset int64, status int32, err error) {
	return c.AppendOrphanContext(context.Background(), ino, data)
}

func (c *Client) AppendOrphanContext(ctx context.Context, ino uint64, data []byte) (count int, offset int64, status int32, err error) {
	r, err := c.DoContext(ctx, &Request{
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
	return c.TruncateOrphanContext(context.Background(), ino, size)
}

func (c *Client) TruncateOrphanContext(ctx context.Context, ino uint64, size int64) (status int32, err error) {
	r, err := c.DoContext(ctx, &Request{Op: OpTruncate, OrphanIno: ino, Size: size, Owner: c.owner})
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
		c.closeTransportGate()
	})
	c.closeDedicated()
	c.closePool()
	return nil
}

// Abort closes this client's transports and local session machinery without
// sending SessionExpire. It is the crash-equivalent teardown used only after
// a forced journal-first unmount: authority lease expiry, not a clean control
// RPC, must preserve delegation recovery ownership. Active pooled operations
// return their connection before Abort completes, so callers may then safely
// quiesce engine workers and close the WAL.
func (c *Client) Abort() error {
	c.closeOnce.Do(func() {
		if es := c.exactState(); es != nil {
			es.fence()
		}
		c.closeTransportGate()
	})
	c.closeDedicated()
	c.closePool()
	return nil
}

// registerDedicated joins a dedicated transport to the client's close
// lifecycle. The closed check and WaitGroup Add share lifecycleMu with the
// close transition, so no Add can race a close-side Wait.
func (c *Client) registerDedicated(cn *conn) bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.isClosed() {
		return false
	}
	c.dedicated[cn] = struct{}{}
	c.dedicatedWG.Add(1)
	return true
}

func (c *Client) unregisterDedicated(cn *conn) {
	c.lifecycleMu.Lock()
	if _, ok := c.dedicated[cn]; ok {
		delete(c.dedicated, cn)
		c.dedicatedWG.Done()
	}
	c.lifecycleMu.Unlock()
}

// closeTransportGate is the single terminal transport transition. It cancels
// connect attempts, closes the public signal, and interrupts every socket
// while transport adoption is excluded by lifecycleMu.
func (c *Client) closeTransportGate() {
	c.lifecycleMu.Lock()
	if c.lifecycleCancel != nil {
		c.lifecycleCancel()
	}
	close(c.closed)
	for _, cn := range c.pool {
		cn.interrupt()
	}
	for cn := range c.dedicated {
		cn.interrupt()
	}
	c.lifecycleMu.Unlock()
}

func (c *Client) closeDedicated() {
	c.dedicatedWG.Wait()
}

func (c *Client) closePool() {
	c.poolOnce.Do(func() {
		for _, cn := range c.pool {
			cn.interrupt()
		}
		for i := 0; i < c.poolSize; i++ {
			cn := <-c.conns
			cn.reset()
		}
	})
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
		if !cn.connected() {
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
	nc, enc, dec := cn.transportState()
	if nc == nil || enc == nil || dec == nil {
		return nil, fmt.Errorf("fsproto: connection not established")
	}
	_ = nc.SetDeadline(time.Now().Add(d))
	if err := enc.Encode(req); err != nil {
		cn.reset()
		return nil, err
	}
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		cn.reset()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return &resp, nil
}

// ---- typed helpers for the FUSE layer ----

// Getattr returns a path's attributes (or an errno).
func (c *Client) Getattr(path string) (*Attr, int32, error) {
	return c.GetattrHandle(path, 0)
}

// GetattrHandle stats by an open file handle's stable ino when handleIno is non-zero.
func (c *Client) GetattrHandle(path string, handleIno uint64) (*Attr, int32, error) {
	return c.GetattrHandleContext(context.Background(), path, handleIno)
}

// GetattrHandleContext is GetattrHandle with caller lifetime propagation.
func (c *Client) GetattrHandleContext(ctx context.Context, path string, handleIno uint64) (*Attr, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpGetattr, Path: path, HandleIno: handleIno})
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
	return c.ReaddirVContext(context.Background(), path)
}

// ReaddirVContext is ReaddirV with caller lifetime propagation.
func (c *Client) ReaddirVContext(ctx context.Context, path string) ([]Dirent, uint64, uint64, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpReaddir, Path: path})
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
	return c.ensureAttrContext(context.Background(), path, kind, r)
}

func (c *Client) ensureAttrContext(ctx context.Context, path, kind string, r *Response) *Attr {
	if r.Attr != nil || r.Status != OK {
		return r.Attr
	}
	if a, st, err := c.GetattrHandleContext(ctx, path, r.Ino); err == nil && st == OK && a != nil {
		return a
	}
	if r.Ino != 0 {
		if a, _, _, _, st, err := c.GetattrVContext(ctx, path); err == nil && st == OK {
			return &a
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
// baseline): the kernel CREATE is create+open, so the hold must be
// recorded before the create returns anyway — fusing it removes the separate
// MarkOpen round-trip without moving the open-vs-unlink race decision point.
// ENOENT means the just-created inode was already unlinked by a peer inside
// the registration window: the caller fails the open, exactly like a MarkOpen
// ENOENT. gen is the authority generation the registration is valid under.
func (c *Client) CreateRegisterOpen(path string, mode uint32) (*Attr, uint64, int32, error) {
	return c.CreateRegisterOpenContext(context.Background(), path, mode)
}

func (c *Client) CreateRegisterOpenContext(ctx context.Context, path string, mode uint32) (*Attr, uint64, int32, error) {
	return c.createContext(ctx, path, mode, true, false)
}

// CreateExclRegisterOpen fuses wire-level O_EXCL (see CreateExcl) with open
// registration (see CreateRegisterOpen) in one round-trip.
func (c *Client) CreateExclRegisterOpen(path string, mode uint32) (*Attr, uint64, int32, error) {
	return c.CreateExclRegisterOpenContext(context.Background(), path, mode)
}

func (c *Client) CreateExclRegisterOpenContext(ctx context.Context, path string, mode uint32) (*Attr, uint64, int32, error) {
	return c.createContext(ctx, path, mode, true, true)
}

func (c *Client) create(path string, mode uint32, registerOpen, excl bool) (*Attr, uint64, int32, error) {
	return c.createContext(context.Background(), path, mode, registerOpen, excl)
}

func (c *Client) createContext(ctx context.Context, path string, mode uint32, registerOpen, excl bool) (*Attr, uint64, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpCreate, Path: path, Mode: mode, RegisterOpen: registerOpen, Excl: excl})
	if err != nil {
		return nil, 0, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, false)
	}
	return c.ensureAttrContext(ctx, path, "file", r), r.Gen, r.Status, nil
}

// Mkdir makes a directory and returns its attributes.
func (c *Client) Mkdir(path string, mode uint32) (*Attr, int32, error) {
	return c.MkdirContext(context.Background(), path, mode)
}

func (c *Client) MkdirContext(ctx context.Context, path string, mode uint32) (*Attr, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpMkdir, Path: path, Mode: mode})
	if err != nil {
		return nil, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(path, r, false)
	}
	return c.ensureAttrContext(ctx, path, "directory", r), r.Status, nil
}

// Remove deletes a file or empty directory.
func (c *Client) Remove(path string) (int32, error) {
	return c.RemoveContext(context.Background(), path)
}

func (c *Client) RemoveContext(ctx context.Context, path string) (int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpRemove, Path: path})
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
	return c.RenameWithOrphanTargetContext(context.Background(), oldPath, newPath, orphanTarget)
}

func (c *Client) RenameWithOrphanTargetContext(ctx context.Context, oldPath, newPath string, orphanTarget bool) (int32, uint64, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpRename, Path: oldPath, NewPath: newPath, OrphanTarget: orphanTarget})
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
	return c.SymlinkContext(context.Background(), target, link)
}

func (c *Client) SymlinkContext(ctx context.Context, target, link string) (*Attr, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpSymlink, Path: link, Target: target})
	if err != nil {
		return nil, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(link, r, false)
	}
	return c.ensureAttrContext(ctx, link, "symlink", r), r.Status, nil
}

// Link adds newPath as another name for oldPath's non-directory inode. The
// returned attributes describe the shared inode after nlink increments.
func (c *Client) Link(oldPath, newPath string) (*Attr, int32, error) {
	return c.LinkContext(context.Background(), oldPath, newPath)
}

func (c *Client) LinkContext(ctx context.Context, oldPath, newPath string) (*Attr, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpLink, Path: oldPath, NewPath: newPath})
	if err != nil {
		return nil, EIO, err
	}
	if r.Status == OK {
		c.selfWrote(oldPath, r, false)
		c.selfWrote(newPath, r, false)
	}
	return c.ensureAttrContext(ctx, newPath, "file", r), r.Status, nil
}

// Readlink returns a symlink's target.
func (c *Client) Readlink(path string) (string, int32, error) {
	return c.ReadlinkContext(context.Background(), path)
}

// ReadlinkContext is Readlink with caller lifetime propagation.
func (c *Client) ReadlinkContext(ctx context.Context, path string) (string, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpReadlink, Path: path})
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
	return c.SetattrTimesHandle(
		path, handleIno, mode, setMode,
		mtimeMs, setTime, 0, false,
		uid, gid, setUID, setGID,
	)
}

// SetattrTimesHandle is SetattrHandle with independent mtime and atime
// intent. The authority preserves an omitted timestamp at its ordered apply
// position rather than resolving it client-side.
func (c *Client) SetattrTimesHandle(
	path string,
	handleIno uint64,
	mode uint32,
	setMode bool,
	mtimeMs int64,
	setTime bool,
	atimeMs int64,
	setATime bool,
	uid, gid uint32,
	setUID, setGID bool,
) (int32, error) {
	return c.SetattrTimesHandleContext(
		context.Background(),
		path, handleIno, mode, setMode,
		mtimeMs, setTime, atimeMs, setATime,
		uid, gid, setUID, setGID,
	)
}

func (c *Client) SetattrTimesHandleContext(
	ctx context.Context,
	path string,
	handleIno uint64,
	mode uint32,
	setMode bool,
	mtimeMs int64,
	setTime bool,
	atimeMs int64,
	setATime bool,
	uid, gid uint32,
	setUID, setGID bool,
) (int32, error) {
	groups := make([]*Request, 0, 3)
	if setMode {
		groups = append(groups, &Request{Op: OpSetattr, Path: path, HandleIno: handleIno, Mode: mode, SetMode: true})
	}
	if setTime || setATime {
		groups = append(groups, &Request{
			Op: OpSetattr, Path: path, HandleIno: handleIno,
			MtimeMs: mtimeMs, SetTime: setTime,
			AtimeMs: atimeMs, SetATime: setATime,
		})
	}
	if setUID || setGID {
		groups = append(groups, &Request{Op: OpSetattr, Path: path, HandleIno: handleIno, UID: uid, GID: gid, SetUID: setUID, SetGID: setGID})
	}
	if len(groups) != 1 {
		for _, g := range groups {
			r, err := c.DoContext(ctx, g)
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
	r, err := c.DoContext(ctx, &Request{
		Op: OpSetattr, Path: path, HandleIno: handleIno,
		Mode: mode, SetMode: setMode,
		MtimeMs: mtimeMs, SetTime: setTime,
		AtimeMs: atimeMs, SetATime: setATime,
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

// ---- extended attributes ----

// Getxattr reads one extended attribute. handleIno addresses an open handle's
// stable ino when non-zero (named or parked orphan). ENODATA = not present.
func (c *Client) Getxattr(path string, handleIno uint64, name string) ([]byte, int32, error) {
	return c.GetxattrContext(context.Background(), path, handleIno, name)
}

// GetxattrContext is Getxattr with caller lifetime propagation.
func (c *Client) GetxattrContext(ctx context.Context, path string, handleIno uint64, name string) ([]byte, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpGetxattr, Path: path, HandleIno: handleIno, XattrName: name})
	if err != nil {
		return nil, EIO, err
	}
	return r.Data, r.Status, nil
}

// Listxattr lists the extended-attribute names of path (sorted).
func (c *Client) Listxattr(path string, handleIno uint64) ([]string, int32, error) {
	return c.ListxattrContext(context.Background(), path, handleIno)
}

// ListxattrContext is Listxattr with caller lifetime propagation.
func (c *Client) ListxattrContext(ctx context.Context, path string, handleIno uint64) ([]string, int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpListxattr, Path: path, HandleIno: handleIno})
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
	return c.SetxattrFlagsContext(context.Background(), path, handleIno, name, value, flags)
}

func (c *Client) SetxattrFlagsContext(ctx context.Context, path string, handleIno uint64, name string, value []byte, flags uint8) (int32, error) {
	r, err := c.DoContext(ctx, &Request{
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
	return c.RemovexattrContext(context.Background(), path, handleIno, name)
}

func (c *Client) RemovexattrContext(ctx context.Context, path string, handleIno uint64, name string) (int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpRemovexattr, Path: path, HandleIno: handleIno, XattrName: name})
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
	return c.TruncateHandleContext(context.Background(), path, handleIno, size)
}

func (c *Client) TruncateHandleContext(ctx context.Context, path string, handleIno uint64, size int64) (int32, error) {
	r, err := c.DoContext(ctx, &Request{Op: OpTruncate, Path: path, HandleIno: handleIno, Size: size})
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
