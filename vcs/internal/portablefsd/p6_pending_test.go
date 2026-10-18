package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func p6Wait(t *testing.T, d *v3DataPlane, predicate func(v3PendingMetrics) bool) v3PendingMetrics {
	t.Helper()
	waitV3PublicationCondition(t, func() bool { return predicate(d.pending.metrics()) })
	return d.pending.metrics()
}

// p6Collect uses the actual dispatch, adoption, source, and disposition paths;
// the caller owns the resulting provisional reply and its callback verdict.
func p6Collect(t *testing.T, d *v3DataPlane, ctx context.Context, operation uint64, body any) (any, *v3ProvisionalResources, int32) {
	t.Helper()
	ctx = context.WithValue(ctx, v3CallbackContextKey{}, uint64(1))
	if operation != 0 {
		d.bridge.reserveFrontendPublication(testCallback(operation))
	}
	c := &v3ReplyResourceCollector{d: d}
	reply, errno := d.dispatchFrontend(context.WithValue(ctx, v3ReplyResourceContextKey{}, c), operation, body)
	resources, err := d.prepareReplyResources(c)
	if err != nil {
		t.Fatal(err)
	}
	return reply, resources, errno
}

func p6Settle(t *testing.T, d *v3DataPlane, resources *v3ProvisionalResources, accept bool) *v3ResourceCleanup {
	t.Helper()
	items := uint32(0)
	if accept {
		items = uint32(len(resources.items))
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, accept && len(resources.handles) != 0, items)
	if err != nil {
		t.Fatal(err)
	}
	consumeV3ProvisionalResponses(resources)
	return cleanup
}

func p6Ack(t *testing.T, d *v3DataPlane, operation uint64) {
	t.Helper()
	if !acknowledgeBridgePublished(t, d.bridge, operation) {
		t.Fatal("callback acknowledgement refused")
	}
	d.bridge.releaseFrontendPublication(testCallback(operation))
	if err := d.bridge.finishFrontendPublication(testCallback(operation)); err != nil {
		t.Fatal(err)
	}
}

func p6CreateReply(client *fakeV3DataClient, identity authorityrpc.MutationIdentity) *authoritypb.Response {
	item := client.issueItem(3, authoritypb.Attr_REGULAR, 0x62)
	item.Attr.Mode = 0 // CREATE's real grant survives restrictive final mode.
	response := exactTestMutationReply(identity)
	response.PostState = testV3RootBinding(item, v3PostStateRoleCreated)
	response.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: item, Handle: client.issueHandle()}}
	return response
}

func TestP6CombinedPressurePreservesSuccessfulCreate(t *testing.T) {
	client := newFakeV3DataClient()
	client.maxWrite = v3CloseTokenWireBytes // B=1, so CREATE spans two batches.
	client.limit = 1
	d := testV3DataPlane(t, client)
	d.pending = newV3PendingBudget(3)
	root := d.resolveReply().Root
	file := lookupTestAttr(t, d, root, "file")
	_, open, errno := p6Collect(t, d, t.Context(), 0, &pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeRead})
	if errno != 0 {
		t.Fatal(errno)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	client.mu.Lock()
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		switch request.GetBody().(type) {
		case *authoritypb.Request_Reclaim:
			<-release
			return client.reclaim(identity, request), nil
		case *authoritypb.Request_CloseBatch:
			return client.closeBatch(identity, request), nil
		case *authoritypb.Request_Lookup:
			response := exactTestMutationReply(identity)
			response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: client.issueItem(2, authoritypb.Attr_REGULAR, 0x40)}}
			return response, nil
		case *authoritypb.Request_Create:
			return p6CreateReply(client, identity), nil
		}
		return nil, errors.New("unexpected authority request")
	}
	client.mu.Unlock()
	saturateV3Releases(t, d, client)
	type result struct {
		reply     any
		resources *v3ProvisionalResources
		errno     int32
	}
	lookupDone, createDone := make(chan result, 1), make(chan result, 1)
	go func() {
		r, p, e := p6Collect(t, d, t.Context(), 101, &pfslocal.LookupRequest{Dir: root, Name: []byte("file")})
		lookupDone <- result{r, p, e}
	}()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Pending == 2 })
	waitV3PublicationCondition(t, func() bool { return len(d.ops) == cap(d.ops) })
	go func() {
		r, p, e := p6Collect(t, d, t.Context(), 102, &pfslocal.CreateRequest{Dir: root, Name: []byte("new"), Mode: 0, Exclusive: true})
		createDone <- result{r, p, e}
	}()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Pending == 3 })
	waitCtx, cancel := context.WithCancel(t.Context())
	cancelled := make(chan result, 1)
	go func() {
		r, p, e := p6Collect(t, d, waitCtx, 0, &pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeWrite})
		cancelled <- result{r, p, e}
	}()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Waiters == 1 })
	before := len(client.mutationRequests())
	cancel()
	refusal := <-cancelled
	if refusal.errno != darwinEINTR || len(client.mutationRequests()) != before {
		t.Fatalf("cancelled admission allocated: errno=%d", refusal.errno)
	}
	p6Settle(t, d, refusal.resources, false)
	cleanup := p6Settle(t, d, open, false)
	cleanupDone := make(chan error, 1)
	go func() { cleanupDone <- cleanup.finish() }()
	// Source claims and authority dispatch for CREATE have not begun while its
	// predecessor occupies the sole operation slot. CONTROL bypasses both.
	if lease := d.bridge.sourcePublication.operationLease(testCallback(102)); lease != nil {
		t.Fatal("queued CREATE acquired a source hold")
	}
	if err := d.renewHorizon(t.Context()); err != nil {
		t.Fatalf("CONTROL blocked by resource pressure: %v", err)
	}
	if m := d.pending.metrics(); m.Pending != 3 || m.Peak != 3 || client.liveTokens() > 1+2+2*3 {
		t.Fatalf("combined pressure escaped bound: metrics=%+v live=%d", m, client.liveTokens())
	}
	unblock()
	if err := <-cleanupDone; err != nil {
		t.Fatal(err)
	}
	looked, created := <-lookupDone, <-createDone
	if looked.errno != 0 || created.errno != 0 {
		t.Fatalf("successful allocation became an error: lookup=%d create=%d terminal=%v", looked.errno, created.errno, d.terminalError())
	}
	createReply, ok := created.reply.(*pfslocal.CreateReply)
	if !ok || createReply.Handle == 0 {
		t.Fatalf("create reply=%#v", created.reply)
	}
	p6Settle(t, d, looked.resources, true)
	p6Settle(t, d, created.resources, true)
	p6Ack(t, d, 101)
	p6Ack(t, d, 102)
	waitV3ReleasesIdle(t, d)
	// No OPEN follows CREATE. Both actual tokens remain charged until their
	// explicit close/reclaim, even though the pending reservation is retired.
	if live := client.liveTokens(); live != 4 {
		t.Fatalf("create grant lost or leaked: live=%d", live)
	}
	for _, body := range []any{&pfslocal.CloseRequest{Handle: createReply.Handle}, &pfslocal.ReclaimRequest{Item: createReply.Attr.Item}, &pfslocal.ReclaimRequest{Item: file.Item}} {
		if _, errno := dispatchV3Test(d, t.Context(), 0, body); errno != 0 {
			t.Fatal(errno)
		}
	}
	waitV3ReleasesIdle(t, d)
	m := d.pending.metrics()
	if m.Pending != 0 || m.Waiters != 0 || m.Reserved != m.Retired || m.CleanupWaitNS == 0 || client.liveTokens() != 1 || d.terminalError() != nil {
		t.Fatalf("ownership failed to retire once: metrics=%+v live=%d terminal=%v", m, client.liveTokens(), d.terminalError())
	}
}

func p6Frontend(t *testing.T, d *v3DataPlane, recorders ...*lantrace.Recorder) func(string) net.Conn {
	t.Helper()
	a := newAttach(testFSKitAttachRef, "p6", ensureAttachRequest{VolumeID: "v", MountPath: "/Volumes/P6"}, privateTestDir(t))
	a.v3Data, a.v3Coherence, a.v3Config = d, d.bridge, &v3AttachConfig{}
	s := NewServer(Config{FrontendSocket: filepath.Join(shortDaemonSocketDir(t), "p.sock"), Version: "test"})
	if len(recorders) != 0 {
		s.cfg.Trace = recorders[0]
	}
	s.registry = newRegistry(privateTestDir(t))
	s.registry.byRef[a.ref] = a
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ServeFrontend(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		waitV3PublicationCondition(t, func() bool { return s.frontendConnections.Load() == 0 })
	})
	waitUnix(t, s.cfg.FrontendSocket)
	return func(role string) net.Conn {
		conn, err := net.Dial("unix", s.cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		for _, env := range []*pfslocal.Envelope{
			{RequestID: 1, Body: &pfslocal.Hello{ProtocolMajor: pfslocal.ProtocolMajor, ProtocolMinor: pfslocal.ProtocolMinor, ClientName: role}},
			{RequestID: 2, Body: &pfslocal.ResolveRequest{AttachRef: a.ref}},
		} {
			p6Send(t, conn, env)
			readPFSReply(t, conn, env.RequestID)
		}
		return conn
	}
}

func p6Send(t *testing.T, conn net.Conn, env *pfslocal.Envelope) {
	t.Helper()
	if err := pfslocal.WriteFrame(conn, env); err != nil {
		t.Fatal(err)
	}
}

func TestP6WireSaturationKeepsReaderAckAndControlLive(t *testing.T) {
	p6WireSaturation(t, nil)
}

func p6WireSaturation(t *testing.T, recorder *lantrace.Recorder) {
	t.Helper()
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.pending = newV3PendingBudget(1)
	dial := p6Frontend(t, d, recorder)
	first, second := dial("p6.data.one"), dial("p6.data.two")
	lookup := &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")}
	p6Send(t, first, &pfslocal.Envelope{RequestID: 3, OperationID: 7, Body: lookup})
	if _, ok := readPFSReply(t, first, 3).Body.(*pfslocal.LookupReply); !ok {
		t.Fatal("lookup failed")
	}
	// Identical wire IDs on another connection and a later request on the same
	// reader both wait without owning a source hold, replay slot, or DATA lane.
	p6Send(t, second, &pfslocal.Envelope{RequestID: 3, OperationID: 7, Body: lookup})
	p6Send(t, first, &pfslocal.Envelope{RequestID: 4, OperationID: 8, Body: lookup})
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Waiters == 2 })
	_ = second.Close()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Waiters == 1 })
	p6Send(t, first, &pfslocal.Envelope{Body: &pfslocal.PublicationAck{OperationID: 7, SemanticCommit: pfslocal.PublicationSemanticCommitPublished}})
	p6Send(t, first, &pfslocal.Envelope{RequestID: 5, Body: &pfslocal.StatfsRequest{}})
	if _, ok := readPFSReply(t, first, 5).Body.(*pfslocal.StatfsReply); !ok {
		t.Fatal("serial reader blocked behind admission")
	}
	if len(d.ops) != 0 || len(client.mutationRequests()) != 1 {
		t.Fatal("budget waiter consumed a DATA or replay slot")
	}
	if err := d.renewHorizon(t.Context()); err != nil {
		t.Fatal(err)
	}
	p6Send(t, first, &pfslocal.Envelope{Body: &pfslocal.ResourceReplyDisposition{TargetRequestID: 3, AcceptedItemCount: 1}})
	reply := readPFSReply(t, first, 4)
	if _, ok := reply.Body.(*pfslocal.LookupReply); !ok {
		t.Fatalf("lookup reply=%T", reply.Body)
	}
	p6Send(t, first, &pfslocal.Envelope{Body: &pfslocal.ResourceReplyDisposition{TargetRequestID: 4, AcceptedItemCount: 1}})
	p6Send(t, first, &pfslocal.Envelope{Body: &pfslocal.PublicationAck{OperationID: 8, SemanticCommit: pfslocal.PublicationSemanticCommitPublished}})
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Pending == 0 && m.Waiters == 0 })
	if m := d.pending.metrics(); m.Reserved != 2 || m.Retired != 2 || m.Peak != 1 || d.terminalError() != nil {
		t.Fatalf("connection-qualified ownership: %+v terminal=%v", m, d.terminalError())
	}
	// The reader must actually retire both PublicationAcks before close;
	// otherwise an unread ack can turn a test cleanup into mount termination.
	waitV3PublicationCondition(t, func() bool {
		d.bridge.sourcePublication.mu.Lock()
		defer d.bridge.sourcePublication.mu.Unlock()
		return len(d.bridge.sourcePublication.operations) == 0
	})
	// Leave an OPEN without its disposition so close must run the existing
	// asynchronous cleanup owner and return its pending reservation.
	p6Send(t, first, &pfslocal.Envelope{RequestID: 6, Body: &pfslocal.OpenRequest{Item: reply.Body.(*pfslocal.LookupReply).Attr.Item, Mode: pfslocal.OpenModeRead}})
	if _, ok := readPFSReply(t, first, 6).Body.(*pfslocal.OpenReply); !ok {
		t.Fatal("OPEN failed")
	}
	_ = first.Close()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Pending == 0 && m.Retired == 3 })
	waitV3ReleasesIdle(t, d)
	if d.terminalError() != nil {
		t.Fatal(d.terminalError())
	}
	// A live reservation also exercises terminal transfer's trace sample.
	reservation, err := d.pending.reserve(context.WithValue(t.Context(), v3RequestTraceContextKey{}, v3RequestTrace{recorder: recorder}))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.fail(errors.New("test terminal transition")); err == nil {
		t.Fatal("terminal transition did not record its cause")
	}
	reservation.retire()
	if m := d.pending.metrics(); m.Pending != 0 || m.Teardown != 1 || m.Reserved != m.Retired {
		t.Fatalf("terminal transfer: %+v", m)
	}
}

func TestP6ZeroAllocationRefusalsReturnReservation(t *testing.T) {
	for _, kind := range []string{"invalid", "authority", "negative", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			d.pending = newV3PendingBudget(1)
			request := &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")}
			ctx := t.Context()
			want := int32(darwinEINVAL)
			switch kind {
			case "invalid":
				request.Name = []byte("invalid/name")
			case "authority", "negative":
				client.mutation = func(_ context.Context, id authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
					r := exactTestMutationReply(id)
					if kind == "authority" {
						r.Errno = errnos.ENOMEM
					} else {
						r.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: 1}}
					}
					return r, nil
				}
				want = darwinENOMEM
				if kind == "negative" {
					want = darwinENOENT
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = darwinEINTR
			}
			_, resources, errno := p6Collect(t, d, ctx, 0, request)
			if errno != want {
				t.Fatalf("errno=%d want=%d", errno, want)
			}
			p6Settle(t, d, resources, false)
			m := d.pending.metrics()
			if m.Pending != 0 || m.Reserved != m.Retired || client.liveTokens() != 1 || d.terminalError() != nil {
				t.Fatalf("refusal retained resources: %+v", m)
			}
		})
	}
}

func TestP6KernelPeerPIDIsCapturedFromAcceptedSocket(t *testing.T) {
	const key = "P6_TEST_PEER_SOCKET"
	if path := os.Getenv(key); path != "" {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var b [1]byte
		_, _ = conn.Read(b[:])
		return
	}
	path := filepath.Join(shortDaemonSocketDir(t), "pid-child.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestP6KernelPeerPIDIsCapturedFromAcceptedSocket$")
	cmd.Env = append(os.Environ(), key+"="+path, "GORACE=atexit_sleep_ms=0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	pid, err := frontendPeerPID(server)
	if err != nil || pid != cmd.Process.Pid || pid == os.Getpid() {
		t.Fatalf("peer pid=%d child=%d daemon=%d err=%v", pid, cmd.Process.Pid, os.Getpid(), err)
	}
	var stream bytes.Buffer
	recorder := p6Recorder(t, &stream, lantrace.LayerDaemon, lantrace.RecorderConfig{})
	c := &frontendConn{srv: NewServer(Config{Trace: recorder}), conn: server, frontendPID: pid,
		helloClientName: "P6.peer:Exact-1", origin: 77, attach: &attach{ref: "resolve-ref"}}
	c.requestTrace(9, 8, &pfslocal.LookupRequest{}).local(lantrace.PhaseEnqueue, 0)
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	report := p6TraceReport(t, stream.Bytes())
	if report.Rejected != 0 || report.ProducerLost != 0 || report.InconsistentStreams != 0 {
		t.Fatalf("serialized identity rejected: %+v", report)
	}
	events := p6TraceEvents(t, stream.Bytes())
	if len(events) != 1 || events[0].FrontendPID != uint32(pid) || events[0].AttachRef != "resolve-ref" || events[0].ConnRole != "P6.peer:Exact-1" || events[0].Conn != "77" || events[0].RequestID != 9 || events[0].LocalOp != lantrace.LocalLookup {
		t.Fatalf("serialized peer identity=%+v", events)
	}
}

func TestP6DuplicateLinkKeepsReservationUntilReleaseAcceptance(t *testing.T) {
	client := newFakeV3DataClient()
	client.maxWrite = v3CloseTokenWireBytes
	d := testV3DataPlane(t, client)
	d.pending = newV3PendingBudget(1)
	root := d.resolveReply().Root
	file := lookupTestAttr(t, d, root, "file")
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	issued := make(chan struct{})
	client.mu.Lock()
	client.mutation = func(_ context.Context, id authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		switch request.GetBody().(type) {
		case *authoritypb.Request_Reclaim:
			<-release
			return client.reclaim(id, request), nil
		case *authoritypb.Request_Link:
			item := client.issueItem(2, authoritypb.Attr_REGULAR, 0x40)
			item.Attr.Nlink = 2
			response := exactTestMutationReply(id)
			response.PostState = testV3RootBinding(item, v3PostStateRoleTarget)
			response.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: item}}
			close(issued)
			return response, nil
		}
		return nil, errors.New("unexpected request")
	}
	client.mu.Unlock()
	saturateV3Releases(t, d, client)
	done := make(chan *v3ProvisionalResources, 1)
	go func() {
		_, resources, errno := p6Collect(t, d, t.Context(), 201, &pfslocal.HardLinkRequest{Item: file.Item, Dir: root, Name: []byte("alias")})
		if errno != 0 {
			t.Errorf("link errno=%d", errno)
		}
		done <- resources
	}()
	<-issued
	waitCtx, cancel := context.WithCancel(t.Context())
	waiterDone := make(chan struct{})
	go func() {
		_, resources, _ := p6Collect(t, d, waitCtx, 0, &pfslocal.LookupRequest{Dir: root, Name: []byte("file")})
		p6Settle(t, d, resources, false)
		close(waiterDone)
	}()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Waiters == 1 })
	select {
	case <-done:
		t.Fatal("LINK released its reservation before duplicate cleanup acceptance")
	default:
	}
	if client.liveTokens() != 5 {
		t.Fatalf("unexpected token ownership: %d", client.liveTokens())
	}
	cancel()
	<-waiterDone
	unblock()
	resources := <-done
	if len(resources.items)+len(resources.handles) != 0 {
		t.Fatal("LINK invented a frontend resource disposition")
	}
	p6Settle(t, d, resources, true)
	p6Ack(t, d, 201)
	waitV3ReleasesIdle(t, d)
	if m := d.pending.metrics(); m.Pending != 0 || m.Reserved != m.Retired || client.liveTokens() != 2 || d.terminalError() != nil {
		t.Fatalf("LINK duplicate ownership: %+v live=%d terminal=%v", m, client.liveTokens(), d.terminalError())
	}
}

func TestP6LostOpenReplyRetainsReservationThroughCleanup(t *testing.T) {
	client := newFakeV3DataClient()
	client.maxWrite = v3CloseTokenWireBytes
	d := testV3DataPlane(t, client)
	d.pending = newV3PendingBudget(1)
	release := blockV3Reclaims(client)
	var once sync.Once
	unblock := func() { once.Do(release) }
	defer unblock()
	saturateV3Releases(t, d, client)
	conn := p6Frontend(t, d)("p6.lost-open")
	p6Send(t, conn, &pfslocal.Envelope{RequestID: 3, Body: &pfslocal.OpenRequest{Item: d.resolveReply().Root, Mode: pfslocal.OpenModeRead}})
	waitV3PublicationCondition(t, func() bool { d.mu.Lock(); defer d.mu.Unlock(); return len(d.handles) == 1 })
	// Discard the socket's unread successful reply. It cannot release its
	// reservation merely by launching an asynchronous cleanup.
	_ = conn.Close()
	waitV3PublicationCondition(t, func() bool { d.mu.Lock(); defer d.mu.Unlock(); return len(d.handles) == 0 })
	if m := d.pending.metrics(); m.Pending != 1 || m.Retired != 0 {
		t.Fatalf("lost reply retired before release acceptance: %+v", m)
	}
	unblock()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Pending == 0 })
	waitV3ReleasesIdle(t, d)
	if m := d.pending.metrics(); m.Reserved != m.Retired || client.liveTokens() != 1 || d.terminalError() != nil {
		t.Fatalf("lost OPEN: %+v live=%d terminal=%v", m, client.liveTokens(), d.terminalError())
	}
}

func TestP6LostCreateTransfersBothTokensToTerminalSession(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.pending = newV3PendingBudget(1)
	client.mutation = func(_ context.Context, id authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCreate() == nil {
			return nil, errors.New("unexpected request")
		}
		return p6CreateReply(client, id), nil
	}
	conn := p6Frontend(t, d)("p6.lost-create")
	p6Send(t, conn, &pfslocal.Envelope{RequestID: 3, OperationID: 7, Body: &pfslocal.CreateRequest{Dir: d.resolveReply().Root, Name: []byte("new"), Exclusive: true}})
	waitV3PublicationCondition(t, func() bool { d.mu.Lock(); defer d.mu.Unlock(); return len(d.handles) == 1 })
	_ = conn.Close()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Teardown == 1 && m.Pending == 0 })
	if m := d.pending.metrics(); m.Reserved != 1 || m.Retired != 1 || d.terminalError() == nil || client.liveTokens() != 3 {
		t.Fatalf("lost CREATE did not transfer its two authority tokens: %+v live=%d terminal=%v", m, client.liveTokens(), d.terminalError())
	}
}

func TestP6ExactDetachOwnsSaturatedReservations(t *testing.T) {
	pki := newV3TestPKI(t)
	h := newV3TestAuthority()
	h.releaseStarted, h.releaseFinish = make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(h.releaseFinish) }) }
	defer unblock()
	address := startV3TestAuthority(t, h, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/P6Detach"))
	d := a.v3Backend()
	if err := d.bridge.bind(); err != nil {
		t.Fatal(err)
	}
	d.pending = newV3PendingBudget(1)
	d.releases.limit = 1
	if err := d.releases.submit([][]byte{bytes.Repeat([]byte{0x81}, 16)}, nil); err != nil {
		t.Fatal(err)
	}
	<-h.releaseStarted
	if err := d.releases.submit([][]byte{bytes.Repeat([]byte{0x82}, 16)}, nil); err != nil {
		t.Fatal(err)
	}
	_, resources, errno := p6Collect(t, d, t.Context(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")})
	if errno != 0 {
		t.Fatal(errno)
	}
	cleanup := p6Settle(t, d, resources, false)
	cleaned := make(chan error, 1)
	go func() { cleaned <- cleanup.finish() }()
	waiter := make(chan int32, 1)
	go func() {
		_, p, e := p6Collect(t, d, t.Context(), 0, &pfslocal.OpenRequest{Item: d.resolveReply().Root, Mode: pfslocal.OpenModeRead})
		p6Settle(t, d, p, false)
		waiter <- e
	}()
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Waiters == 1 })
	detached := make(chan error, 1)
	go func() {
		_, err := r.unmountFSKitWith(a.ref, false, fskitKernelOps{present: func(string, string) (bool, error) { return false, nil }})
		detached <- err
	}()
	select {
	case err := <-detached:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exact absence waited on saturated DATA or pending-resource cleanup")
	}
	if err := <-cleaned; err != nil {
		t.Fatal(err)
	}
	if errno := <-waiter; errno == 0 {
		t.Fatal("teardown admitted a resource waiter")
	}
	if m := d.pending.metrics(); m.Pending != 0 || m.Waiters != 0 || m.Reserved != m.Retired || m.Teardown != 1 || h.recordedDetach().GetMountAbsence() == nil || r.get(a.ref) != nil {
		t.Fatalf("exact detach failed ownership/proof: %+v", m)
	}
	unblock()
	waitV3ReleasesIdle(t, d)
}

func TestP6CachedLookupReservesItsLocalDisposition(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "file", 0x70)
	if m := f.d.pending.metrics(); m.Limit != 1024 {
		t.Fatalf("production budget=%+v", m)
	}
	f.getattr(f.root)
	file := f.lookup(f.root, "file")
	f.d.pending = newV3PendingBudget(1)
	before := f.authorityCalls()
	_, resources, errno := p6Collect(t, f.d, t.Context(), 301, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("file")})
	if errno != 0 || f.authorityCalls() != before || f.d.pending.metrics().Pending != 1 {
		t.Fatalf("cached lookup was uncharged or remote: errno=%d metrics=%+v", errno, f.d.pending.metrics())
	}
	if cleanup := p6Settle(t, f.d, resources, false); cleanup.required() {
		t.Fatal("discarding a cached reference reclaimed an accepted item")
	}
	p6Ack(t, f.d, 301)
	record := f.record(file.Item)
	if m := f.d.pending.metrics(); m.Pending != 0 || m.Reserved != 1 || m.Retired != 1 || record == nil || record.provisional != 0 || !record.accepted {
		t.Fatalf("cached disposition ownership: metrics=%+v item=%+v", m, record)
	}
}

func TestP6EveryDispositionOwnershipBranch(t *testing.T) {
	for _, branch := range []string{"accepted", "abandoned", "closed-registration", "invalid-disposition", "terminal"} {
		t.Run(branch, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			d.pending = newV3PendingBudget(1)
			_, resources, errno := p6Collect(t, d, t.Context(), 0, &pfslocal.OpenRequest{Item: d.resolveReply().Root, Mode: pfslocal.OpenModeRead})
			if errno != 0 {
				t.Fatal(errno)
			}
			var cleanup *v3ResourceCleanup
			switch branch {
			case "accepted":
				cleanup = p6Settle(t, d, resources, true)
				if client.liveTokens() != 2 {
					t.Fatal("acceptance lost its real handle")
				}
				if _, errno := dispatchV3Test(d, t.Context(), 0, &pfslocal.CloseRequest{Handle: resources.handles[0].id}); errno != 0 {
					t.Fatal(errno)
				}
			case "abandoned":
				cleanup = p6Settle(t, d, resources, false)
			case "closed-registration":
				c := &frontendConn{resourceClosed: true}
				var registered bool
				var err error
				cleanup, registered, err = c.registerProvisionalResourceOrAbandon(3, resources)
				if registered || err != nil {
					t.Fatalf("closed registration=%t %v", registered, err)
				}
			case "invalid-disposition":
				if _, err := d.applyReplyResourceDisposition(resources, false, 1); err == nil {
					t.Fatal("invalid item acceptance succeeded")
				}
				if d.pending.metrics().Pending != 1 {
					t.Fatal("invalid disposition stole its reservation")
				}
				cleanup = p6Settle(t, d, resources, false)
			case "terminal":
				_ = d.stopServing(errors.New("terminal before disposition"))
				cleanup = p6Settle(t, d, resources, false)
			}
			// Racing callers cannot submit the same cleanup twice.
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() {
					if err := cleanup.finish(); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			consumeV3ProvisionalResponses(resources)
			if _, err := d.applyReplyResourceDisposition(resources, false, 0); err == nil {
				t.Fatal("duplicate disposition settled twice")
			}
			waitV3ReleasesIdle(t, d)
			m := d.pending.metrics()
			wantLive := 1
			if branch == "terminal" {
				wantLive = 2
			}
			if m.Pending != 0 || m.Reserved != 1 || m.Retired != 1 || client.liveTokens() != wantLive {
				t.Fatalf("branch=%s metrics=%+v live=%d", branch, m, client.liveTokens())
			}
		})
	}
}

func TestP6SocketCloseWithdrawsBeforeCancellingBudgetWaiter(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.pending = newV3PendingBudget(1)
	reservation, err := d.pending.reserve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.retire()
	a := newAttach(testFSKitAttachRef, "close-order", ensureAttachRequest{VolumeID: "v"}, privateTestDir(t))
	a.v3Data, a.v3Coherence = d, d.bridge
	s := NewServer(Config{})
	s.registry = newRegistry(privateTestDir(t))
	s.registry.byRef[a.ref] = a
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{srv: s, conn: server}
	done := make(chan struct{})
	go func() { c.serve(t.Context()); close(done) }()
	for _, env := range []*pfslocal.Envelope{
		{RequestID: 1, Body: &pfslocal.Hello{ProtocolMajor: pfslocal.ProtocolMajor, ProtocolMinor: pfslocal.ProtocolMinor, ClientName: "p6.close-order"}},
		{RequestID: 2, Body: &pfslocal.ResolveRequest{AttachRef: a.ref}},
	} {
		p6Send(t, peer, env)
		readPFSReply(t, peer, env.RequestID)
	}
	p6Send(t, peer, &pfslocal.Envelope{RequestID: 3, OperationID: 7, Body: &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")}})
	p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Waiters == 1 })
	func() {
		// Pause the actual close before publication withdrawal. Cancellation
		// must not wake the handler into publishing on this dead socket yet.
		a.mu.Lock()
		defer a.mu.Unlock()
		_ = peer.Close()
		waitV3PublicationCondition(t, func() bool { return c.connectionClosed.Load() })
		if err := c.connCtx.Err(); err != nil {
			t.Fatalf("socket close cancelled before publication withdrawal: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("socket close failed to join its cancelled waiter")
	}
	if m := d.pending.metrics(); m.Waiters != 0 || m.Pending != 1 || len(client.mutationRequests()) != 0 || d.terminalError() != nil {
		t.Fatalf("closing unallocated waiter changed mount ownership: %+v terminal=%v", m, d.terminalError())
	}
}
