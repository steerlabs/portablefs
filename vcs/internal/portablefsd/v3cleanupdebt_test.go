package portablefsd

import (
	"context"
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
		case *authoritypb.Request_Open:
			response := exactTestMutationReply(identity)
			response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: client.issueHandle()}}
			return response, nil
		}
		return exactTestMutationReply(identity), nil
	}
	return func() { close(release) }
}

func provisionalTestOpen(t *testing.T, d *v3DataPlane, client *fakeV3DataClient) *v3ProvisionalResources {
	t.Helper()
	collector := &v3ReplyResourceCollector{d: d}
	if _, errno := d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0,
		&pfslocal.OpenRequest{Item: d.resolveReply().Root, Mode: pfslocal.OpenModeRead}); errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func waitV3Pending(t *testing.T, d *v3DataPlane, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for d.pending.metrics().Pending != want {
		if time.Now().After(deadline) {
			t.Fatalf("pending reservations = %d, want %d", d.pending.metrics().Pending, want)
		}
		time.Sleep(time.Millisecond)
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
	c := &frontendConn{origin: 1, conn: server, attach: a}
	if !c.registerProvisionalResource(9, resources) {
		t.Fatal("provisional lookup was not registered")
	}
	release := blockV3Reclaims(client)
	saturateV3Releases(t, d, client)
	c.close()
	waitV3Pending(t, d, 1)
	release()
	waitV3Pending(t, d, 0)
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
	reservation, err := d.pending.reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	collector := &v3ReplyResourceCollector{d: d, reservation: reservation}
	collectTestItem(t, d, collector, client.issueItem(3, authoritypb.Attr_REGULAR, 0x43))
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil || d.pending.metrics().Pending != 1 {
		t.Fatalf("abandon err=%v debt=%d", err, d.pending.metrics().Pending)
	}
	_ = d.stopServing(errFrontendPublicationUnprovable)
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	if debt := d.pending.metrics().Pending; debt != 0 || len(client.reclaimBatches()) != 0 {
		t.Fatalf("terminal pending reservations=%d reclaims=%d, want settled without a round trip", debt, len(client.reclaimBatches()))
	}
}
