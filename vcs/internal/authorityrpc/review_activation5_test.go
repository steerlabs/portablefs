package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type o5ActivateHandler struct {
	clientTestHandler
	activates, resumes, detaches, aborts atomic.Int32
	hold                                 atomic.Bool
	entered, release                     chan struct{}
	enteredOnce, releaseOnce             sync.Once
}

func newO5Handler() *o5ActivateHandler {
	return &o5ActivateHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, entered: make(chan struct{}), release: make(chan struct{})}
}
func (h *o5ActivateHandler) Release() { h.releaseOnce.Do(func() { close(h.release) }) }
func (h *o5ActivateHandler) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	switch {
	case q.GetActivate() != nil:
		out := h.clientTestHandler.Handle(ctx, q)
		if h.activates.Add(1) == 1 && h.hold.Load() {
			h.enteredOnce.Do(func() { close(h.entered) })
			<-h.release
		}
		return out
	case q.GetDetach() != nil:
		h.detaches.Add(1)
		return &authoritypb.Response{RequestId: q.GetRequestId(), Epoch: h.Epoch()}
	case q.GetAbortAttach() != nil:
		h.aborts.Add(1)
	case q.GetResume() != nil:
		h.resumes.Add(1)
	}
	return h.clientTestHandler.Handle(ctx, q)
}

type o5Proxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []net.Conn
	refuse atomic.Bool
}

func newO5Proxy(t *testing.T, target string) *o5Proxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &o5Proxy{ln: ln, target: target}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if p.refuse.Load() {
				c.Close()
				continue
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, s)
			p.mu.Unlock()
			pipe := func(dst, src net.Conn) { io.Copy(dst, src); dst.Close(); src.Close() }
			go pipe(s, c)
			go pipe(c, s)
		}
	}()
	t.Cleanup(func() { ln.Close(); p.KillAll() })
	return p
}
func (p *o5Proxy) Addr() string { return p.ln.Addr().String() }
func (p *o5Proxy) KillAll() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// Realistic loss of a committed Activate reply: the reply is written after the
// client abandoned that connection (cancellation or dial timeout), not held
// forever. Reconciliation must learn ACTIVE and Detach exactly once.
func TestO5ReleasedActivateAfterCancellationDetaches(t *testing.T) {
	for _, mode := range []string{"signal-cancel", "dial-timeout"} {
		t.Run(mode, func(t *testing.T) {
			h := newO5Handler()
			h.hold.Store(true)
			addr, tls, stop := startTestServer(t, h, 9, time.Minute)
			defer stop()
			defer h.Release()
			cfg := coherentTestClientConfig(addr, tls, "volume", 9, 9)
			cfg.DialTimeout = 30 * time.Second
			cfg.CancelDrainTimeout = 2 * time.Second
			if mode == "dial-timeout" {
				cfg.DialTimeout = 400 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			started := time.Now()
			go func() {
				c, err := DialClient(ctx, cfg)
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			<-h.entered
			if mode == "signal-cancel" {
				cancel()
				time.AfterFunc(150*time.Millisecond, h.Release)
			} else {
				time.AfterFunc(600*time.Millisecond, h.Release)
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("DialClient did not return")
			}
			t.Logf("%s: err=%v after %v; resumes=%d activates=%d detaches=%d aborts=%d uncertain=%v", mode, err, time.Since(started).Round(time.Millisecond), h.resumes.Load(), h.activates.Load(), h.detaches.Load(), h.aborts.Load(), errors.Is(err, ErrTransportUncertain))
			if err == nil || h.detaches.Load() != 1 || h.aborts.Load() != 0 || errors.Is(err, ErrTransportUncertain) {
				t.Errorf("committed activation not released exactly")
			}
		})
	}
}

// Ordinary attach regression: a committed Activate reply lost to a transport
// drop with no caller cancellation must still publish a usable client, with no
// Detach/Abort, and the recovered pair must outlive the recovery deadline.
func TestO5LostActivateReplyWithoutCancelPublishesUsableClient(t *testing.T) {
	h := newO5Handler()
	h.hold.Store(true)
	addr, tls, stop := startTestServer(t, h, 9, time.Minute)
	defer stop()
	defer h.Release()
	p := newO5Proxy(t, addr)
	cfg := coherentTestClientConfig(p.Addr(), tls, "volume", 9, 9)
	cfg.DialTimeout = 5 * time.Second
	cfg.CancelDrainTimeout = 300 * time.Millisecond
	done := make(chan struct{})
	var client *Client
	var err error
	go func() { client, err = DialClient(context.Background(), cfg); close(done) }()
	<-h.entered
	p.KillAll()
	time.AfterFunc(20*time.Millisecond, h.Release)
	<-done
	t.Logf("lost reply, no cancel: err=%v resumes=%d activates=%d detaches=%d aborts=%d", err, h.resumes.Load(), h.activates.Load(), h.detaches.Load(), h.aborts.Load())
	if err != nil {
		t.Fatalf("ordinary attach regressed: %v", err)
	}
	defer client.Close()
	if h.detaches.Load() != 0 || h.aborts.Load() != 0 || h.activates.Load() < 2 {
		t.Errorf("unexpected cleanup on a published client")
	}
	time.Sleep(3 * cfg.CancelDrainTimeout) // past the reconciliation deadline
	resp, cerr := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	t.Logf("KeepAlive on recovered pair after reconciliation deadline: errno=%d err=%v", resp.GetErrno(), cerr)
	if cerr != nil {
		t.Errorf("recovered transport inherited the reconciliation deadline: %v", cerr)
	}
}

// The authority disappears after Activate was sent: DialClient returns bounded
// explicit uncertainty; caller cancellation does not shorten reconciliation.
func TestO5AuthorityGoneAfterActivateBoundedUncertainty(t *testing.T) {
	for _, cancelToo := range []bool{false, true} {
		h := newO5Handler()
		h.hold.Store(true)
		addr, tls, stop := startTestServer(t, h, 9, time.Minute)
		p := newO5Proxy(t, addr)
		cfg := coherentTestClientConfig(p.Addr(), tls, "volume", 9, 9)
		cfg.DialTimeout = 5 * time.Second
		cfg.CancelDrainTimeout = 600 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			c, err := DialClient(ctx, cfg)
			if c != nil {
				c.Close()
			}
			done <- err
		}()
		<-h.entered
		p.refuse.Store(true)
		p.KillAll()
		lost := time.Now()
		if cancelToo {
			cancel()
		}
		var err error
		select {
		case err = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("DialClient unbounded")
		}
		took := time.Since(lost)
		t.Logf("authority gone (cancel=%v): err=%v uncertain=%v took=%v detaches=%d aborts=%d", cancelToo, err, errors.Is(err, ErrTransportUncertain), took.Round(time.Millisecond), h.detaches.Load(), h.aborts.Load())
		if !errors.Is(err, ErrTransportUncertain) || h.aborts.Load() != 0 || took > 3*time.Second {
			t.Errorf("unbounded or unclassified reconciliation failure")
		}
		cancel()
		h.Release()
		stop()
	}
}

// Random caller cancellation across the whole handshake. Invariants per
// attempt: success => no Detach/Abort; Activate reached and failure => exactly
// one Detach or explicit uncertainty; Activate reached => no Abort.
func TestO5RandomCancellationDialStress(t *testing.T) {
	base := o5Sockets(t)
	goroutines := runtime.NumGoroutine()
	type result struct {
		ok, committed, uncertain bool
		detaches, aborts         int32
	}
	var mu sync.Mutex
	var results []result
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				h := newO5Handler()
				addr, tls, stop := startTestServer(t, h, 9, time.Minute)
				cfg := coherentTestClientConfig(addr, tls, "volume", 9, 9)
				cfg.CancelDrainTimeout = time.Second
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(time.Duration(rand.Intn(25000))*time.Microsecond, cancel)
				c, err := DialClient(ctx, cfg)
				r := result{ok: err == nil, uncertain: errors.Is(err, ErrTransportUncertain)}
				if c != nil {
					c.Close()
				}
				time.Sleep(20 * time.Millisecond)
				r.committed = h.activates.Load() > 0
				r.detaches, r.aborts = h.detaches.Load(), h.aborts.Load()
				cancel()
				stop()
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	var ok, committedFail, detached, uncertain, bad int
	for _, r := range results {
		switch {
		case r.ok:
			ok++
			if r.detaches != 0 || r.aborts != 0 {
				bad++
			}
		case r.committed:
			committedFail++
			if r.aborts != 0 || (r.detaches != 1 && !r.uncertain) {
				bad++
			}
			if r.detaches == 1 {
				detached++
			}
			if r.uncertain {
				uncertain++
			}
		}
	}
	time.Sleep(1500 * time.Millisecond)
	buf := make([]byte, 4<<20)
	nst := runtime.Stack(buf, true)
	counts := map[string]int{}
	for _, g := range bytes.Split(buf[:nst], []byte("\n\n")) {
		lines := bytes.Split(g, []byte("\n"))
		if len(lines) > 1 {
			counts[string(bytes.TrimSpace(lines[1]))]++
		}
	}
	for k, v := range counts {
		if v > 1 {
			t.Logf("goroutines %3d at %s", v, k)
		}
	}
	t.Logf("cancel stress: attempts=%d ok=%d committedThenFailed=%d (detached=%d uncertain=%d) violations=%d goroutineDelta=%d", len(results), ok, committedFail, detached, uncertain, bad, runtime.NumGoroutine()-goroutines)
	if bad != 0 {
		t.Errorf("%d attempts violated committed-activation ownership", bad)
	}
	// Only sockets opened during this test can leak from it. Earlier tests may
	// still be closing their own connections, so a process-wide descriptor
	// count can move in either direction without saying anything here.
	for socket := range o5Sockets(t) {
		if _, ok := base[socket]; !ok {
			t.Errorf("socket %s opened by the stress attempts is still open", socket)
		}
	}
}

func o5Sockets(t *testing.T) map[string]struct{} {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	sockets := map[string]struct{}{}
	for _, ent := range ents {
		target, err := os.Readlink("/proc/self/fd/" + ent.Name())
		if err == nil && strings.HasPrefix(target, "socket:") {
			sockets[target] = struct{}{}
		}
	}
	return sockets
}
