package portablefsd

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func testCallback(operation uint64) v3CallbackID {
	return v3CallbackID{origin: 1, operation: operation}
}

func TestP4ConnectionQualifiedPublicationAndDisposition(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	a := &attach{ref: "qualified", v3Data: d, v3Coherence: d.bridge, conns: make(map[interface{ Close() error }]struct{})}
	var connections []*frontendConn
	var peers []net.Conn
	for range 2 {
		server, peer := net.Pipe()
		peers = append(peers, peer)
		c := &frontendConn{conn: server}
		if !c.setAttach(a) {
			t.Fatal("bind failed")
		}
		connections = append(connections, c)
	}
	defer func() {
		for _, c := range connections {
			c.close()
		}
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	c1, c2 := connections[0], connections[1]
	if c1.origin == c2.origin || c1.origin == 0 || c2.origin == 0 {
		t.Fatal("reused connection origin")
	}
	const operation = uint64(7)
	counts := [2]atomic.Int32{}
	for i, c := range connections {
		initialize, ok := c.reserveLogicalOperation(operation, true)
		if !initialize || !ok {
			t.Fatal("reserve failed")
		}
		d.bridge.reserveFrontendPublication(c.callback(operation))
		if _, err := c.beginLogicalOperation(context.Background(), a, operation, true, &pfslocal.GetAttrRequest{}); err != nil {
			t.Fatal(err)
		}
		if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(c.callback(operation), &countingV3ResponseConsumption{count: &counts[i]}); err != nil {
			t.Fatal(err)
		}
	}
	// Multiple requests of the same callback join only that connection's lease.
	g1, _ := v3ItemSourceGate(testV3PublicationItem(1, 0x41), false)
	g2, _ := v3ItemSourceGate(testV3PublicationItem(2, 0x42), false)
	l1, err := d.bridge.sourcePublication.acquireSource(context.Background(), c1.callback(operation), g1)
	if err != nil {
		t.Fatal(err)
	}
	l1b, err := d.bridge.sourcePublication.acquireSource(context.Background(), c1.callback(operation), g1)
	if err != nil || l1b != l1 {
		t.Fatal("continuation lost its lease")
	}
	l2, err := d.bridge.sourcePublication.acquireSource(context.Background(), c2.callback(operation), g2)
	if err != nil || l2 == l1 {
		t.Fatal("connections shared a source lease")
	}
	l1.finishRequest()
	l1b.finishRequest()
	l2.finishRequest()
	// Identical request IDs name independent final resource dispositions.
	for _, c := range connections {
		if !c.registerProvisionalResource(11, &v3ProvisionalResources{d: d}) {
			t.Fatal("resource registration failed")
		}
	}
	if !c1.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{TargetRequestID: 11}) {
		t.Fatal("first disposition failed")
	}
	c2.resourceMu.Lock()
	secondPending := c2.provisional[11] != nil
	c2.resourceMu.Unlock()
	if !secondPending {
		t.Fatal("first disposition settled another connection")
	}
	// Closing an unexposed, unapplied callback retires only its receipt and holds.
	c1.finishLogicalRequest(operation)
	c1.close()
	if counts[0].Load() != 1 || counts[1].Load() != 0 || d.terminalError() != nil {
		t.Fatalf("close crossed origins: %d/%d terminal=%v", counts[0].Load(), counts[1].Load(), d.terminalError())
	}
	if known, _ := d.bridge.acknowledgePublication(c1.callback(operation), pfslocal.PublicationSemanticCommitPublished); known {
		t.Fatal("late ack resurrected closed origin")
	}
	if d.bridge.sourcePublication.operationLease(c2.callback(operation)) != l2 || l2.released {
		t.Fatal("late ack retired other source lease")
	}
	if known, err := d.bridge.acknowledgePublication(c2.callback(operation), pfslocal.PublicationSemanticCommitPublished); !known || err != nil {
		t.Fatal(err)
	}
	if !c2.acknowledgePublication(operation) {
		t.Fatal("second callback ack failed")
	}
	if counts[1].Load() != 0 {
		t.Fatal("ack consumed before handler retirement")
	}
	c2.finishLogicalRequest(operation)
	if counts[1].Load() != 1 {
		t.Fatal("second receipt not consumed exactly once")
	}
	if !c2.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{TargetRequestID: 11}) {
		t.Fatal("second disposition failed")
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c3 := &frontendConn{conn: server}
	defer c3.close()
	if !c3.setAttach(a) || c3.origin == c1.origin || c3.origin == c2.origin {
		t.Fatal("successor reused origin")
	}
	if init, ok := c3.reserveLogicalOperation(operation, true); !init || !ok {
		t.Fatal("successor could not use its own wire counter")
	}
	// No handler was launched for this deliberately transport-only reservation.
	c3.publicationMu.Lock()
	close(c3.operations[operation].ready)
	c3.operations[operation].activeRequests = 0
	c3.publicationMu.Unlock()
}

func TestP4OriginsFailClosedAtExhaustion(t *testing.T) {
	var counter atomic.Uint64
	counter.Store(math.MaxUint64 - 1)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			id := allocateFrontendOrigin(&counter)
			if id != 0 {
				if id != math.MaxUint64 {
					t.Errorf("wrapped origin %d", id)
				}
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 || allocateFrontendOrigin(&counter) != 0 {
		t.Fatal("origin exhaustion reused an identity")
	}
}

func TestP4SourceClaimsSettlePerConcurrentCall(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	id := v3CallbackID{origin: 77, operation: 8}
	c.reserve(id)
	gate, _ := v3NamespaceSourceGate(testV3PublicationItem(1, 0x51), []byte("child"), true)
	first, err := c.acquireSource(context.Background(), id, gate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.acquireSource(context.Background(), id, gate)
	if err != nil || first != second {
		t.Fatal(err)
	}
	if err := first.resolveNoBindings(gate); err != nil {
		t.Fatal(err)
	}
	first.finishRequest()
	c.mu.Lock()
	claims, active := first.unresolvedAttributes, first.active
	c.mu.Unlock()
	if claims != 1 || active != 1 {
		t.Fatalf("first response settled concurrent claim: claims=%d active=%d", claims, active)
	}
	target := testV3PublicationIdentity(0x52)
	if err := second.attachBinding(gate, v3PublicationNamespace{parent: testV3PublicationIdentity(0x51), name: "child"}, target); err != nil {
		t.Fatal(err)
	}
	second.finishRequest()
	c.cacheRead(func(conflict v3CacheConflict) {
		if got := conflict(v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: target}); got != v3CacheHit {
			t.Fatalf("settled callback blocked cache until ack: %v", got)
		}
	})
	if _, err := c.acknowledge(id, pfslocal.PublicationSemanticCommitPublished); err != nil {
		t.Fatal(err)
	}
	c.retire(id)
	if !first.released {
		t.Fatal("final publication retained source holds")
	}
}

func TestP4RenewalBudgetExceedsCadence(t *testing.T) {
	client := newFakeV3DataClient()
	clock := newFakeV3Clock()
	d := testV3DataPlaneWithClock(t, client, clock)
	entered, release := make(chan struct{}), make(chan struct{})
	client.mu.Lock()
	client.keepAlive = func(ctx context.Context) (time.Duration, error) {
		client.mu.Lock()
		client.keepAlive = nil
		client.mu.Unlock()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 50*time.Second {
			t.Error("cadence shortened renewal deadline")
		}
		close(entered)
		select {
		case <-release:
			return time.Minute, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	client.mu.Unlock()
	// Saturated DATA cannot consume this CONTROL budget.
	for range cap(d.ops) {
		d.ops <- struct{}{}
	}
	done := make(chan bool, 1)
	go func() { done <- d.scheduledRenewal() }()
	<-entered
	timer := time.NewTimer(5100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("renewal ended at cadence")
	case <-timer.C:
	}
	d.mu.Lock()
	eligible := d.cacheAdmissionLocked() == v3CacheHit
	d.mu.Unlock()
	if !eligible {
		t.Fatal("valid original horizon lost while renewal waited")
	}
	clock.advance(5100 * time.Millisecond)
	close(release)
	if !<-done || d.terminalError() != nil {
		t.Fatal("valid delayed renewal terminalized mount")
	}
	for range cap(d.ops) {
		<-d.ops
	}
}

func TestP4RenewalOutcomeClassification(t *testing.T) {
	for _, test := range []struct {
		name        string
		hook        func(*fakeV3DataClient, *fakeV3Clock, *v3DataPlane) func(context.Context) (time.Duration, error)
		keepServing bool
	}{
		{"settled-timeout", func(_ *fakeV3DataClient, _ *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) { return 0, context.DeadlineExceeded }
		}, true},
		{"transport-poison", func(c *fakeV3DataClient, _ *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) {
				c.poisoned.Store(true)
				return 0, context.DeadlineExceeded
			}
		}, false},
		{"transport-loss", func(c *fakeV3DataClient, _ *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) { _ = c.Close(); return 0, io.ErrClosedPipe }
		}, false},
		{"refusal", func(_ *fakeV3DataClient, _ *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) { return 0, errors.New("refused") }
		}, false},
		{"expired-answer", func(_ *fakeV3DataClient, clock *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) { clock.advance(time.Minute); return time.Minute, nil }
		}, false},
		{"fractional-proof", func(_ *fakeV3DataClient, _ *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) { return time.Second + 1, nil }
		}, false},
		{"clock-fault", func(_ *fakeV3DataClient, clock *fakeV3Clock, _ *v3DataPlane) func(context.Context) (time.Duration, error) {
			return func(context.Context) (time.Duration, error) {
				clock.fail(errors.New("clock unavailable"))
				return time.Minute, nil
			}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newFakeV3DataClient()
			clock := newFakeV3Clock()
			d := testV3DataPlaneWithClock(t, c, clock)
			c.mu.Lock()
			c.keepAlive = test.hook(c, clock, d)
			c.mu.Unlock()
			if got := d.scheduledRenewal(); got != test.keepServing {
				t.Fatalf("continue=%t terminal=%v", got, d.terminalError())
			}
			if (d.terminalError() == nil) != test.keepServing {
				t.Fatalf("terminal=%v", d.terminalError())
			}
		})
	}
}

func TestP4ExpiredHorizonUsesOriginalDataDuringRenewal(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	file := f.lookup(f.root, "file")
	entered, release := make(chan struct{}), make(chan struct{})
	f.client.mu.Lock()
	f.client.keepAlive = func(context.Context) (time.Duration, error) { close(entered); <-release; return time.Minute, nil }
	f.client.mu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- f.d.scheduledRenewal() }()
	<-entered
	f.clock.advance(61 * time.Second)
	f.requireAuthority("expired H with CONTROL delayed", func() { f.getattr(file.Item) })
	if f.d.terminalError() != nil {
		t.Fatal("horizon expiry invented terminal session")
	}
	close(release)
	if <-done || f.d.terminalError() == nil {
		t.Fatal("expired delayed proof restored serving")
	}
}

func TestP4MkdirRetainsEvaluatedWitness(t *testing.T) {
	for _, permitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "permitted"}[permitted], func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.hold = func(req *authoritypb.Request, res *authoritypb.Response) {
				if req.GetMkdir() != nil {
					res.GetMkdir().ChildSearchPermitted = permitted
				}
			}
			body, errno := f.dispatch(&pfslocal.MkdirRequest{Dir: f.root, Name: []byte("dir"), Mode: 0})
			if errno != 0 {
				t.Fatal(errno)
			}
			record := f.record(body.(*pfslocal.MkdirReply).Attr.Item)
			f.d.mu.Lock()
			w := record.mkdirWitness
			f.d.mu.Unlock()
			if w == nil || w.identity != record.item.StableIdentity || w.snapshot == 0 || w.searchPermitted != permitted {
				t.Fatalf("witness=%+v", w)
			}
		})
	}
}

func TestP4ReadinessRequiresEveryWitness(t *testing.T) {
	c := newFakeV3DataClient()
	clock := newFakeV3Clock()
	d := testV3DataPlaneWithClock(t, c, clock)
	a := &attach{ref: "ready", v3Data: d, v3Coherence: d.bridge, v3Config: &v3AttachConfig{}, state: pfslocal.AttachStateAttached}
	frontend := &frontendConn{origin: 77, helloClientName: shippingFSKitFrontendClientName}
	if !a.registerFrontendWitness(frontend) {
		t.Fatal("shipping witness refused")
	}
	if a.requireFrontendWitnesses(true) == nil {
		t.Fatal("unqualified event owner supplied readiness")
	}
	d.bridge.mu.Lock()
	d.bridge.frontendOrigin = 77
	d.bridge.mu.Unlock()
	if err := a.requireFrontendWitnesses(true); err != nil {
		t.Fatal(err)
	}
	if a.requireFrontendWitnesses(false) == nil {
		t.Fatal("missing kernel identity supplied readiness")
	}
	clock.advance(time.Minute)
	if a.requireFrontendWitnesses(true) == nil {
		t.Fatal("expired proof supplied readiness")
	}
	if err := d.renewHorizon(context.Background()); err != nil {
		t.Fatal(err)
	}
	frontend.connectionClosed.Store(true)
	if a.requireFrontendWitnesses(true) == nil || a.registerFrontendWitness(frontend) {
		t.Fatal("closed witness supplied readiness")
	}
	frontend.connectionClosed.Store(false)
	a.removeFrontendWitness(frontend)
	probe := &frontendConn{origin: 78, helloClientName: "portablefsd-control-preflight"}
	if a.registerFrontendWitness(probe) || a.requireFrontendWitnesses(true) == nil {
		t.Fatal("CLI probe supplied readiness")
	}
}

func TestP4LifecycleRoutesAreIndependentAndStrict(t *testing.T) {
	dir := shortDaemonSocketDir(t)
	s := NewServer(Config{ControlSocket: filepath.Join(dir, "ctl.sock"), Version: "arbitrary-serving-release"})
	s.registry = newRegistry(privateTestDir(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeControl(ctx) }()
	defer func() { cancel(); <-done }()
	waitUnix(t, s.cfg.ControlSocket)
	client := rawHTTPUDSClient(s.cfg.ControlSocket)
	request := func(method, path, body string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, b
	}
	status, body := request("GET", daemonctl.LifecycleIdentityPath, "")
	identity, err := daemonctl.DecodeIdentity(body)
	if status != 200 || err != nil || identity.DaemonVersion != s.cfg.Version || identity.PFSLocalMajor != pfslocal.ProtocolMajor {
		t.Fatalf("identity status=%d error=%v", status, err)
	}
	for _, path := range []string{daemonctl.LifecycleIdentityPath, daemonctl.LifecycleInventoryPath} {
		if status, _ := request("HEAD", path, ""); status != 405 {
			t.Fatalf("HEAD %s=%d", path, status)
		}
	}
	if status, _ := request("GET", "/v2/identity", ""); status != 426 {
		t.Fatalf("operational version equality lost: %d", status)
	}
	if status, _ := request("GET", "/v1/attaches", ""); status != 404 {
		t.Fatalf("retired endpoint served: %d", status)
	}
	for _, body := range []string{" ", "{}", "null", strings.Repeat("x", daemonctl.MaxLifecycleBodyBytes+1)} {
		if status, _ := request("POST", daemonctl.LifecycleStopIfIdlePath, body); status != 400 {
			t.Fatalf("malformed stop=%d", status)
		}
	}
	a := &attach{ref: "persisted-terminal"}
	s.registry.mu.Lock()
	s.registry.byRef[a.ref] = a
	s.registry.mu.Unlock()
	status, body = request("GET", daemonctl.LifecycleInventoryPath, "")
	inventory, err := daemonctl.DecodeLifecycleInventory(body)
	if status != 200 || err != nil || inventory.AttachmentCount != 1 {
		t.Fatalf("inventory=%s err=%v", body, err)
	}
	if status, _ := request("POST", daemonctl.LifecycleStopIfIdlePath, ""); status != 409 || s.registry.quiescing {
		t.Fatalf("busy stop changed admission: %d", status)
	}
	s.registry.mu.Lock()
	delete(s.registry.byRef, a.ref)
	s.registry.mu.Unlock()
	if status, body := request("POST", daemonctl.LifecycleStopIfIdlePath, ""); status != 204 || len(body) != 0 || !s.registry.quiescing {
		t.Fatalf("idle stop=%d %q", status, body)
	}
}

func TestP4StopIfIdleSerializesWithRealAttach(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	for range 2 {
		r := newRegistry(privateTestDir(t))
		req := v3TestEnsureRequest(address, pki, "/Volumes/AdmissionRace")
		start := make(chan struct{})
		attached := make(chan error, 1)
		stopped := make(chan bool, 1)
		go func() { <-start; _, _, err := r.ensure(context.Background(), req); attached <- err }()
		go func() {
			<-start
			idle, _, err := r.quiesceIfIdle()
			if err != nil {
				t.Error(err)
			}
			stopped <- idle
		}()
		close(start)
		attachErr, idle := <-attached, <-stopped
		if idle {
			if attachErr == nil || len(r.list()) != 0 || !r.quiescing {
				t.Fatal("stop admitted racing attach")
			}
		} else {
			if attachErr != nil || len(r.list()) != 1 || r.quiescing {
				t.Fatalf("winning attach was harmed: %v", attachErr)
			}
			a := r.list()[0]
			if a.v3Backend().terminalError() != nil {
				t.Fatal("busy refusal harmed service")
			}
			a.fenceV3(errors.New("test cleanup"))
		}
	}
}

func TestP4UnmountBusyPreservesBindingAndNeverForces(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	a := &attach{ref: "busy", v3Data: d, v3Coherence: d.bridge}
	r := newRegistry(privateTestDir(t))
	attempts := 0
	err := r.detachV3(a, false, fskitKernelOps{present: func(string, string) (bool, error) { return true, nil }, unmountExact: func(_, _ string, force bool) error {
		attempts++
		if force {
			t.Error("automatic force")
		}
		return syscall.EBUSY
	}})
	if !errors.Is(err, syscall.EBUSY) || attempts != 1 || d.terminalError() != nil || d.bridge.readyForOperations() != nil {
		t.Fatalf("busy changed live binding: %v", err)
	}
}

func TestP4RenewalCadenceAndProofBounds(t *testing.T) {
	for _, test := range []struct{ lease, want time.Duration }{{time.Minute, 5 * time.Second}, {9 * time.Second, 3 * time.Second}, {time.Millisecond, 0}, {0, 0}} {
		if got := v3KeepAliveInterval(test.lease); got != test.want {
			t.Fatalf("cadence %s=%s", test.lease, got)
		}
	}
	c := newFakeV3DataClient()
	c.keepAlive = func(context.Context) (time.Duration, error) { return 0, errors.New("initial refusal") }
	if _, err := newV3DataPlane(context.Background(), v3DataPlaneConfig{Client: c, VolumeID: "v", VolumeName: "v", ItemGeneration: 1}); err == nil {
		t.Fatal("startup without proof succeeded")
	}
	_ = c.Close()
}

func TestP4WireConnectionsMayReuseRequestAndOperationNumbers(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := newAttach(testFSKitAttachRef, "wire", ensureAttachRequest{VolumeID: "v", MountPath: "/Volumes/Wire"}, privateTestDir(t))
	a.v3Data = d
	a.v3Coherence = d.bridge
	a.v3Config = &v3AttachConfig{}
	s := NewServer(Config{FrontendSocket: filepath.Join(shortDaemonSocketDir(t), "p.sock"), Version: "test"})
	s.registry = newRegistry(privateTestDir(t))
	s.registry.byRef[a.ref] = a
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeFrontend(ctx) }()
	defer func() { cancel(); <-done }()
	waitUnix(t, s.cfg.FrontendSocket)
	var consumed atomic.Int32
	client.mu.Lock()
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	client.mu.Unlock()
	var connections []net.Conn
	for range 2 {
		conn, err := net.Dial("unix", s.cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		defer conn.Close()
		for _, env := range []*pfslocal.Envelope{{RequestID: 1, Body: &pfslocal.Hello{ProtocolMajor: pfslocal.ProtocolMajor, ProtocolMinor: pfslocal.ProtocolMinor, ClientName: shippingFSKitFrontendClientName}}, {RequestID: 2, Body: &pfslocal.ResolveRequest{AttachRef: a.ref}}} {
			if err := pfslocal.WriteFrame(conn, env); err != nil {
				t.Fatal(err)
			}
			readPFSReply(t, conn, env.RequestID)
		}
	}
	for _, conn := range connections {
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{RequestID: 3, OperationID: 7, Body: &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, conn := range connections {
		reply := readPFSReply(t, conn, 3)
		if _, ok := reply.Body.(*pfslocal.LookupReply); !ok {
			t.Fatalf("reply=%T", reply.Body)
		}
	}
	operationCount := func() int {
		d.bridge.sourcePublication.mu.Lock()
		defer d.bridge.sourcePublication.mu.Unlock()
		return len(d.bridge.sourcePublication.operations)
	}
	if operationCount() != 2 || consumed.Load() != 0 {
		t.Fatal("wire identities merged")
	}
	settle := func(conn net.Conn) {
		t.Helper()
		for _, body := range []any{&pfslocal.ResourceReplyDisposition{TargetRequestID: 3, AcceptedItemCount: 1}, &pfslocal.PublicationAck{OperationID: 7, SemanticCommit: pfslocal.PublicationSemanticCommitPublished}} {
			if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{Body: body}); err != nil {
				t.Fatal(err)
			}
		}
	}
	settle(connections[0])
	waitV3PublicationCondition(t, func() bool { return consumed.Load() == 1 && operationCount() == 1 })
	_ = connections[0].Close()
	if operationCount() != 1 || d.terminalError() != nil {
		t.Fatal("first close settled another wire connection")
	}
	settle(connections[1])
	waitV3PublicationCondition(t, func() bool { return consumed.Load() == 2 && operationCount() == 0 })
}

func TestP4ItemHandlesUseFullUInt64AndNeverWrap(t *testing.T) {
	c := newFakeV3DataClient()
	d := testV3DataPlane(t, c)
	d.mu.Lock()
	d.nextItemID = math.MaxUint64
	d.mu.Unlock()
	var issued byte = 0x60
	c.mutation = func(_ context.Context, id authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetReclaim() != nil {
			return c.reclaim(id, request), nil
		}
		issued++
		item := c.issueItem(uint64(issued), authoritypb.Attr_REGULAR, issued)
		response := exactTestMutationReply(id)
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}
		return response, nil
	}
	reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("last")})
	if errno != 0 || reply.(*pfslocal.LookupReply).Attr.Item.ItemID != math.MaxUint64 {
		t.Fatalf("last item=%v errno=%d", reply, errno)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("exhausted")}); errno != darwinEIO || d.terminalError() == nil {
		t.Fatal("exhausted handles wrapped")
	}
}

func TestP4PeriodicRenewalHasOneOwnerAndNoTickBacklog(t *testing.T) {
	c := newFakeV3DataClient()
	c.lease = 6 * time.Second
	clock := newFakeV3Clock()
	d := testV3DataPlaneWithClock(t, c, clock)
	started := make(chan int32, 2)
	release := make(chan struct{})
	var calls, inflight atomic.Int32
	c.mu.Lock()
	c.keepAlive = func(ctx context.Context) (time.Duration, error) {
		if inflight.Add(1) != 1 {
			t.Error("overlapping renewal requests")
		}
		defer inflight.Add(-1)
		n := calls.Add(1)
		started <- n
		if n == 1 {
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		return 6 * time.Second, nil
	}
	c.mu.Unlock()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("renewal owner did not start")
	}
	time.Sleep(2200 * time.Millisecond)
	close(release)
	waitV3PublicationCondition(t, func() bool { return inflight.Load() == 0 })
	select {
	case <-started:
		t.Fatal("ticker backlog triggered an immediate renewal")
	case <-time.After(time.Second):
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("normal cadence did not resume")
	}
	if d.terminalError() != nil {
		t.Fatal(d.terminalError())
	}
}

func TestP4RenewalIsCappedByInstalledAuthorization(t *testing.T) {
	c := newFakeV3DataClient()
	c.authorization = time.Now().Add(10 * time.Second)
	c.proof = 8 * time.Second
	d := testV3DataPlaneWithClock(t, c, newFakeV3Clock())
	c.mu.Lock()
	authorization := c.authorization
	c.keepAlive = func(ctx context.Context) (time.Duration, error) {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(authorization) {
			t.Error("renewal escaped installed authorization deadline")
		}
		return time.Second * 8, nil
	}
	c.mu.Unlock()
	if !d.scheduledRenewal() {
		t.Fatal("valid authorization-capped renewal failed")
	}
	d.mu.Lock()
	d.authorizationDeadline = time.Now().Add(-time.Second)
	d.mu.Unlock()
	if d.scheduledRenewal() || d.terminalError() == nil {
		t.Fatal("expired authorization continued serving")
	}
}

func TestP4EventOwnerLossAndAbortedDetachAreTerminal(t *testing.T) {
	for _, planned := range []bool{false, true} {
		t.Run(map[bool]string{false: "unexpected", true: "aborted-detach"}[planned], func(t *testing.T) {
			c := newFakeV3DataClient()
			d := testV3DataPlane(t, c)
			a := &attach{ref: "event", v3Data: d, v3Coherence: d.bridge}
			server, peer := net.Pipe()
			defer peer.Close()
			frontend := &frontendConn{origin: 81, conn: server, attach: a}
			d.bridge.mu.Lock()
			d.bridge.frontendOrigin = 81
			d.bridge.mu.Unlock()
			if planned {
				if err := d.bridge.beginDetach(); err != nil {
					t.Fatal(err)
				}
			}
			frontend.close()
			if planned {
				d.bridge.abortDetach(syscall.EBUSY)
			}
			if d.terminalError() == nil {
				t.Fatal("lost event owner remained usable")
			}
			if err := d.bridge.bind(); err == nil {
				t.Fatal("replacement event owner admitted")
			}
		})
	}
}

func TestP4RegistryHasOneStrictCurrentSchema(t *testing.T) {
	dir := privateTestDir(t)
	writeFSKitDetachFixture(t, dir)
	path := attachRegistryPath(dir)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"version": 3`, `"version": 99`, 1) },
		func(s string) string { return strings.Replace(s, `"version": 3`, `"Version": 3`, 1) },
		func(s string) string { return strings.Replace(s, `"version": 3`, `"version": 3, "version": 3`, 1) },
		func(s string) string {
			return strings.Replace(s, `"routesRevision":`, `"unexpected": null, "routesRevision":`, 1)
		},
		func(s string) string { return strings.Replace(s, `"identityEpoch": 1`, `"identityEpoch": null`, 1) },
		func(s string) string { return s + ` {}` },
	} {
		changed := []byte(mutate(string(original)))
		if err := os.WriteFile(path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPersistedAttachInventory(dir); err == nil {
			t.Fatal("malformed registry accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(changed) {
			t.Fatal("inventory rewrote invalid input")
		}
	}
	if err := writePersistedAttaches(dir, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "null") {
		t.Fatalf("empty current inventory=%s err=%v", data, err)
	}
	if entries, err := ReadPersistedAttachInventory(dir); err != nil || len(entries) != 0 {
		t.Fatal(err)
	}
}

func TestP4LookupMetricsCountOnlyExposedReplies(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	f.getattr(f.root)
	f.lookup(f.root, "file")
	before := f.d.cacheMetrics()
	a := &attach{ref: "metrics", v3Data: f.d, v3Coherence: f.d.bridge}
	server, peer := net.Pipe()
	_ = peer.Close()
	c := &frontendConn{origin: 1, conn: server, attach: a}
	defer c.close()
	const operation = uint64(99001)
	publicationTestOperation(t, c, a, operation)
	ctx, cancel := withOperationDeadline(context.Background())
	defer cancel()
	c.serveV3Attempt(ctx, a, f.d, 1, operation, true, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")}, false)
	after := f.d.cacheMetrics()
	if after.Lookup["hit"] != before.Lookup["hit"] || after.Lookup["terminal"] != before.Lookup["terminal"]+1 || after.LookupPolarity["positive"] != before.LookupPolarity["positive"] || after.LookupPolarity["error"] != before.LookupPolarity["error"]+1 {
		t.Fatalf("unexposed lookup metrics before=%+v after=%+v", before, after)
	}
}

func TestP4InventoryWaitsForDurableRemovalVerdict(t *testing.T) {
	dir := privateTestDir(t)
	writeFSKitDetachFixture(t, dir)
	r := newRegistry(dir)
	bad := filepath.Join(dir, "not-directory")
	if err := os.WriteFile(bad, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r.stateDir = bad
	r.persistMu.Lock()
	removed := make(chan error, 1)
	go func() {
		_, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{present: func(string, string) (bool, error) { return false, nil }})
		removed <- err
	}()
	waitV3PublicationCondition(t, func() bool { return r.get(testFSKitAttachRef) == nil })
	inventory := make(chan daemonctl.LifecycleInventory, 1)
	go func() {
		value, err := r.lifecycleInventory()
		if err != nil {
			t.Error(err)
		}
		inventory <- value
	}()
	select {
	case <-inventory:
		r.persistMu.Unlock()
		t.Fatal("inventory observed uncommitted removal")
	case <-time.After(10 * time.Millisecond):
	}
	r.persistMu.Unlock()
	if err := <-removed; err == nil {
		t.Fatal("removal unexpectedly persisted")
	}
	if value := <-inventory; value.AttachmentCount != 1 {
		t.Fatalf("inventory lost persisted terminal record: %+v", value)
	}
}
