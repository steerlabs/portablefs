package portablefsd

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// blockV3Reclaims holds every Reclaim batch until the returned release is
// called, then lets the fake authority apply them.
func blockV3Reclaims(client *fakeV3DataClient) func() {
	release := make(chan struct{})
	client.mu.Lock()
	defer client.mu.Unlock()
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		switch request.GetBody().(type) {
		case *authoritypb.Request_Reclaim:
			<-release
			return client.reclaim(identity, request), nil
		case *authoritypb.Request_CloseBatch:
			return client.closeBatch(identity, request), nil
		}
		return exactTestMutationReply(identity), nil
	}
	return func() { close(release) }
}

// abandonV3TestItem interns a distinct live capability under a reply the
// frontend then abandons, and starts that reply's cleanup the way the
// handler does.
func abandonV3TestItem(t *testing.T, d *v3DataPlane, client *fakeV3DataClient, index int) {
	t.Helper()
	item := client.issueItem(uint64(index)+100, authoritypb.Attr_REGULAR, 0)
	binary.BigEndian.PutUint64(item.StableIdentity, uint64(index)+1)
	collector := &v3ReplyResourceCollector{d: d}
	collectTestItem(t, d, collector, item)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil || len(cleanup.items) != 1 {
		t.Fatalf("abandon cleanup=%+v err=%v", cleanup, err)
	}
	go func() {
		if err := cleanup.finish(); err != nil {
			t.Errorf("abandoned cleanup: %v", err)
		}
	}()
}

func provisionalTestOpen(t *testing.T, d *v3DataPlane, client *fakeV3DataClient) *v3ProvisionalResources {
	t.Helper()
	handle, err := d.installHandle(client.issueHandle(), d.resolveReply().Root, false)
	if err != nil {
		t.Fatal(err)
	}
	collector := &v3ReplyResourceCollector{d: d}
	collectV3ReplyHandle(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), handle)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func waitV3CleanupDebt(t *testing.T, d *v3DataPlane, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for d.outstandingCleanup() != want {
		if time.Now().After(deadline) {
			t.Fatalf("cleanup debt = %d, want %d", d.outstandingCleanup(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// Abandoned resources still waiting for release capacity behind a slow
// reclaim share the provisional-reply bound. At the bound registration is
// refused, which the handler turns into stopping the mount (a terminal capacity
// guard, not backpressure); the accounting itself returns to zero once the
// release owner accepts them.
func TestV3AbandonedCleanupDebtBoundsProvisionalRegistration(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	release := blockV3Reclaims(client)
	// With one batch in flight and the forming batch full, every abandonment
	// is pre-enqueue debt.
	saturateV3Releases(t, d, client)
	for index := range maxProvisionalResourcesPerConnection {
		abandonV3TestItem(t, d, client, index)
	}
	waitV3CleanupDebt(t, d, maxProvisionalResourcesPerConnection)
	c := &frontendConn{}
	open := provisionalTestOpen(t, d, client)
	if c.registerProvisionalResource(1, open) {
		t.Fatal("a provisional reply registered past the cleanup-debt bound")
	}
	// The handler's existing path then withdraws the reply locally, which is
	// itself one more abandoned resource rather than unbounded growth.
	cleanup, registered, err := c.registerProvisionalResourceOrAbandon(1, open)
	if registered || err != nil || cleanup == nil || len(cleanup.handles) != 1 {
		t.Fatalf("registration at the bound = (%+v, %t, %v), want a synchronous local abandonment", cleanup, registered, err)
	}
	go func() { _ = cleanup.finish() }()
	release()
	waitV3CleanupDebt(t, d, 0)
	waitV3ReleasesIdle(t, d)
	if live := client.liveTokens(); live != 1 {
		t.Fatalf("live capabilities after drain = %d, want only the root", live)
	}
	if !c.registerProvisionalResource(2, provisionalTestOpen(t, d, client)) {
		t.Fatal("registration did not resume after the cleanup debt drained")
	}
}

// A connection that closes with provisional replies orphans them; their
// cleanup is debt like any other abandonment until the release owner accepts
// it.
func TestV3OrphanedProvisionalCleanupIsCountedUntilFinished(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "orphan-debt-test", v3Data: d, v3Coherence: d.bridge}
	collector := &v3ReplyResourceCollector{d: d}
	if _, errno := d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0,
		&pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")}); errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	if !c.registerProvisionalResource(9, resources) {
		t.Fatal("provisional lookup was not registered")
	}
	release := blockV3Reclaims(client)
	saturateV3Releases(t, d, client)
	c.close()
	waitV3CleanupDebt(t, d, 1)
	release()
	waitV3CleanupDebt(t, d, 0)
	waitV3ReleasesIdle(t, d)
	if live := client.liveTokens(); live != 1 || d.terminalError() != nil {
		t.Fatalf("orphan cleanup left live=%d terminal=%v", live, d.terminalError())
	}
}

// A terminal data plane sends no cleanup, but finishing still settles the
// debt the abandonment created.
func TestV3TerminalCleanupSettlesItsDebt(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	collector := &v3ReplyResourceCollector{d: d}
	collectTestItem(t, d, collector, client.issueItem(3, authoritypb.Attr_REGULAR, 0x43))
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil || d.outstandingCleanup() != 1 {
		t.Fatalf("abandon err=%v debt=%d", err, d.outstandingCleanup())
	}
	_ = d.stopServing(errFrontendPublicationUnprovable)
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	if debt := d.outstandingCleanup(); debt != 0 || len(client.reclaimBatches()) != 0 {
		t.Fatalf("terminal cleanup debt=%d reclaims=%d, want settled without a round trip", debt, len(client.reclaimBatches()))
	}
}
