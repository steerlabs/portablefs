//go:build linux

package fusev3_test

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

// TestFilesGatewayCloseDoesNotStallAMutatingMount covers the gateway leaving
// cleanly and coming back.
//
// The gateway is a sidecar. In a deployment it restarts whenever its pod does,
// which means both departures are ordinary events, not faults: a graceful stop
// closes the session, and a SIGKILL just stops answering. Neither may cost the
// mounts sharing the volume their writes. The cacheless reader is never in a
// subscription-withdrawal or compatibility-repair audience, even while its
// authenticated session remains live after an abrupt departure.
func TestFilesGatewayCloseDoesNotStallAMutatingMount(t *testing.T) {
	peer := fusev3.NewGatewayPeerFixture(t, 1)
	const name = "served"
	payload := []byte("gateway departure fixture")
	if err := os.WriteFile(peer.Join(0, name), payload, 0o600); err != nil {
		t.Fatalf("seed the volume through the mount: %v", err)
	}

	ctx := context.Background()
	servedKey := mustEncodePath(t, name)

	// Each gateway session reaches the authority through its own proxy, because
	// a proxy stands in for one sidecar process and the point of the second one
	// is that it is a different process from the first.
	dial := func(what string, proxy *transportProxy) *readonlyfs.Client {
		t.Helper()
		dialContext, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		gateway, err := readonlyfs.Dial(dialContext, readonlyfs.Config{
			Address:              proxy.address(),
			AuthorityCAPEM:       peer.AuthorityCAPEM(),
			AuthorityServerName:  peer.ServerName(),
			Capability:           peer.Capability(),
			ClientCertificatePEM: peer.ClientCertificatePEM(),
			ClientPrivateKeyPEM:  peer.ClientPrivateKeyPEM(),
			VolumeID:             peer.VolumeID(),
		})
		if err != nil {
			t.Fatalf("dial %s: %v (%s)", what, err, peer.Diagnostics())
		}
		return gateway
	}

	// A gateway departure must not make a writer wait for a reader horizon.
	// Keep the bound well below the fixture's repair budget to catch accidental
	// compatibility-writer or subscription membership.
	writeBound := 2 * time.Second
	requireWrite := func(what string, content []byte) time.Duration {
		t.Helper()
		start := time.Now()
		if err := os.WriteFile(peer.Join(0, name), content, 0o600); err != nil {
			t.Fatalf("%s: %v (%s)", what, err, peer.Diagnostics())
		}
		elapsed := time.Since(start)
		if elapsed > writeBound {
			t.Fatalf("%s took %s, past the %s a departed reader may cost a writer; the fixture repair budget is %s (%s)",
				what, elapsed, writeBound, peer.RepairBudget(), peer.Diagnostics())
		}
		return elapsed
	}

	// The close is taken mid-stream so the departure lands between mutations
	// rather than on an idle volume.
	polite := dial("the gateway that closes politely", newTransportProxy(t, peer.AuthorityAddress()))
	requireGatewayContent(t, ctx, polite, servedKey, payload, "the polite gateway's read")
	politeClosed := make(chan error, 1)
	go func() { politeClosed <- polite.Close() }()
	for round := range 4 {
		requireWrite("write racing a polite gateway close", []byte{byte('a' + round)})
	}
	if err := <-politeClosed; err != nil {
		t.Fatalf("polite close: %v", err)
	}
	after := requireWrite("the first write after a polite close", []byte("after polite close"))
	t.Logf("write after a polite close: %s", after)
	if fenced := peer.FencedSessions(); fenced != 0 {
		t.Fatalf("%d session(s) were fenced by a polite close; a clean detach fences nobody", fenced)
	}
	if cause := peer.MountFatal(0); cause != nil {
		t.Fatalf("the mount was revoked across a polite close: %v", cause)
	}

	// Abrupt process death cannot add a withdrawal obligation: this session
	// never had cache permission or a compatibility-writer commitment.
	proxy := newTransportProxy(t, peer.AuthorityAddress())
	abrupt := dial("the gateway that disappears", proxy)
	defer abrupt.Close()
	requireGatewayContent(t, ctx, abrupt, servedKey, []byte("after polite close"), "before abrupt departure")
	proxy.close()
	requireWrite("write immediately after abrupt gateway death", []byte("after abrupt departure"))
	if cause := peer.MountFatal(0); cause != nil {
		t.Fatalf("gateway death revoked writer: %v", cause)
	}

	// The sidecar comes back. It caches nothing, so the guarantee is that a
	// reattached session is a new participant reading current state, never one
	// resuming the cut its predecessor held.
	final := []byte("state written while no gateway was attached")
	requireWrite("the write a reattaching gateway must observe", final)
	revived := dial("the gateway that reattaches", newTransportProxy(t, peer.AuthorityAddress()))
	defer func() { _ = revived.Close() }()
	requireGatewayContent(t, ctx, revived, servedKey, final, "the reattached gateway's read")
	requireWrite("a write beside the reattached gateway", []byte("beside the reattached gateway"))
	if cause := peer.MountFatal(0); cause != nil {
		t.Fatalf("the mount was revoked across the gateway's return: %v", cause)
	}
}

// transportProxy forwards TCP to the authority and can sever every connection
// it has forwarded. It is the test's stand-in for the sidecar's process
// lifetime: severing is what the authority and the client both observe when the
// pod holding the gateway is killed.
type transportProxy struct {
	t        *testing.T
	listener net.Listener

	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func newTransportProxy(t *testing.T, upstream string) *transportProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the gateway transport proxy: %v", err)
	}
	proxy := &transportProxy{t: t, listener: listener}
	t.Cleanup(proxy.close)
	go proxy.serve(upstream)
	return proxy
}

func (p *transportProxy) address() string { return p.listener.Addr().String() }

func (p *transportProxy) serve(upstream string) {
	for {
		downstream, err := p.listener.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			_ = downstream.Close()
			continue
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = downstream.Close()
			_ = up.Close()
			return
		}
		p.conns = append(p.conns, downstream, up)
		p.mu.Unlock()
		go func() { _, _ = io.Copy(up, downstream) }()
		go func() { _, _ = io.Copy(downstream, up) }()
	}
}

// severAll drops every forwarded connection without warning. Both ends see a
// reset socket, which is what a killed process leaves behind.
func (p *transportProxy) severAll() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (p *transportProxy) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = p.listener.Close()
	p.severAll()
}
