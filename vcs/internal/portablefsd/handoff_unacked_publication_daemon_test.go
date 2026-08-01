package portablefsd

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestColdScopeRemoveSequenceSurvivesAnUnacknowledgedPublication drives the
// EXACT live shape of the round-4 cold-scope wedge through the production
// daemon, over the production frontend socket:
//
//	mkdir d; touch d/f; rm d/f; rmdir d
//
// in a brand-new directory. On the live FSKit mount the rmdir burned its whole
// 50s operation budget, answered EIO, and left the subtree permanently dead
// with `kernel coherence barrier failed closed: frontend disconnected before
// acknowledging an exposed kernel publication` — while the frontend was alive
// the whole time.
//
// The daemon-side condition that produced it is reproduced here directly: the
// `rm d/f` reply's PublicationAck is WITHHELD, exactly as it is withheld while
// the FSKit callback that issued it has not yet returned. That operation stays
// a member of the active publication set, and — because its path epoch can no
// longer match after the namespace mutations around it — it blocks EVERY
// handoff on the mount, not merely one that overlaps it.
//
// Two properties are asserted, and both failed at 46a5e8d:
//
//  1. the rmdir reaches a DEFINITE answer well inside the operation budget,
//     instead of waiting on an event the daemon cannot bound;
//  2. the SUBTREE SURVIVES. The old code's handoff goroutine ran under the
//     engine's lifetime context, so when the syscall's own deadline fired the
//     goroutine kept frontendHandoffs["cold"] registered forever: every later
//     request in that subtree blocked in beginFrontendPathsAtEpochContext for
//     the life of the mount. A create in the same directory after the failed
//     rmdir therefore never returned.
func TestColdScopeRemoveSequenceSurvivesAnUnacknowledgedPublication(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _ := startDaemonNoAttach(t, authority)
	ref := ensureAttachWithPolicyOptions(
		t, hc, authority, "vol-cold-scope", "main",
		"/Volumes/ColdScope", "writeback",
		map[string]any{"flushIntervalMs": int64(20)},
	)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "cold-scope-wedge-test"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root

	dir := c.call(&pfslocal.MkdirRequest{
		Dir: root, Name: []byte("cold"), Mode: 0o755,
	}).(*pfslocal.MkdirReply)
	created := c.call(&pfslocal.CreateRequest{
		Dir: dir.Attr.Item, Name: []byte("f"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: created.Handle})

	// `rm d/f`, WITHOUT the acknowledgement. This is the live state exactly:
	// the handler has returned and the reply is exposed, but the framework
	// callback that owns the publication has not completed, so nothing has
	// acknowledged it yet.
	withheld := c.callWithoutPublicationAck(t, &pfslocal.RemoveRequest{
		Dir: dir.Attr.Item, Name: []byte("f"),
	})

	// `rmdir d`. It needs an exact view of the scope, which releases the
	// delegation, whose handoff waits on the publication set.
	started := time.Now()
	_, _ = c.callMaybe(&pfslocal.RemoveRequest{
		Dir: root, Name: []byte("cold"), Directory: true,
	})
	rmdirTook := time.Since(started)
	if rmdirTook >= 40*time.Second {
		t.Fatalf(
			"rmdir over an unacknowledged publication took %s: the handoff waited "+
				"without a verdict and the syscall burned its operation budget",
			rmdirTook,
		)
	}

	// THE SUBTREE MUST STILL BE ALIVE. Whether the rmdir succeeded or reached a
	// definite refusal, no handoff registration may outlive it: a later request
	// in the same subtree must reach an ANSWER, not a wait for a handoff that no
	// longer exists.
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		_, _ = c.callMaybe(&pfslocal.LookupRequest{
			Dir: root, Name: []byte("cold"),
		})
	}()
	select {
	case <-answered:
	case <-time.After(15 * time.Second):
		t.Fatal(
			"the subtree never recovered: a failed handoff left its scope " +
				"registered, so every later request in it waits for a handoff " +
				"that no longer exists",
		)
	}

	// The mount must not have been frozen attach-wide. A frontend that is
	// merely slow to acknowledge is not a disconnected frontend.
	var status attachStatus
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &status)
	if strings.Contains(status.LastError, "coherence barrier failed closed") ||
		strings.Contains(status.LastError, "disconnected") {
		t.Fatalf(
			"attach reported a terminal coherence failure for a CONNECTED frontend: %q",
			status.LastError,
		)
	}

	// The acknowledgement arriving LATE must restore full service. This is the
	// live case: the frontend was never gone, it was only behind.
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		Body: &pfslocal.PublicationAck{OperationID: withheld},
	}); err != nil {
		t.Fatal(err)
	}
	recovered := make(chan struct{})
	go func() {
		defer close(recovered)
		next := c.call(&pfslocal.MkdirRequest{
			Dir: root, Name: []byte("warm"), Mode: 0o755,
		}).(*pfslocal.MkdirReply)
		file := c.call(&pfslocal.CreateRequest{
			Dir: next.Attr.Item, Name: []byte("g"), Mode: 0o644, Exclusive: true,
		}).(*pfslocal.CreateReply)
		c.call(&pfslocal.CloseRequest{Handle: file.Handle})
		c.call(&pfslocal.RemoveRequest{Dir: next.Attr.Item, Name: []byte("g")})
		c.call(&pfslocal.RemoveRequest{
			Dir: root, Name: []byte("warm"), Directory: true,
		})
	}()
	select {
	case <-recovered:
	case <-time.After(30 * time.Second):
		t.Fatal("a full cold cycle did not complete after the late acknowledgement")
	}
}

// callWithoutPublicationAck issues one publishing request and deliberately does
// not acknowledge its exposed reply. It returns the operation ID that remains
// outstanding.
func (c *pfsTestClient) callWithoutPublicationAck(t *testing.T, body any) uint64 {
	t.Helper()
	body = currentTestProtocol(body)
	c.next++
	id := c.next
	operationID := testOperationID(body, id)
	if operationID == 0 {
		t.Fatalf("%T does not publish, so it has no acknowledgement to withhold", body)
	}
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID: id, OperationID: operationID, Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	env := readPFSReply(t, c.conn, id)
	if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
		t.Fatalf("unexpected error reply: %+v", er)
	}
	if !env.PublicationAckRequired {
		t.Fatalf("%T reply did not require a publication acknowledgement", body)
	}
	return operationID
}
