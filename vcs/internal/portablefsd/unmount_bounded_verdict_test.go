package portablefsd

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestUnmountAnswersWithinItsOwnBudgetDuringAnActiveDrain is the round-4
// scenario-A reproduction.
//
// LIVE SHAPE: `portablefs umount` issued during an ACTIVE, HEALTHY drain came
// back rc=1 after 60 seconds with a transport-shaped error — the CLI's own HTTP
// client timeout — and no verdict at all. The recorded-verdict refusal path,
// by contrast, answers a definite HTTP 409 naming the scope and the next action
// in under a second whenever a verdict already exists.
//
// The defect was that the unmount REQUEST and the unmount TRANSACTION were the
// same wait. The transaction legitimately takes as long as the authority drain
// barrier needs (clientcore's volumeBarrierTimeout is 60s for ONE attempt); the
// request must answer inside the CLI's timeout regardless.
//
// The contract asserted here: the request answers within its own budget, and a
// RETRY joins the same transaction rather than queueing a second one behind it
// — otherwise the bound is a rename of the same wait.
func TestUnmountAnswersWithinItsOwnBudgetDuringAnActiveDrain(t *testing.T) {
	restore := unmountTransactionBudget
	unmountTransactionBudget = 3 * time.Second
	t.Cleanup(func() { unmountTransactionBudget = restore })

	// A slow uplink is what makes the drain barrier take real time; without it
	// the transaction completes before any bound could be observed.
	authority := serveThrottledAuthority(t, 128<<10)
	cfg, hc, _ := startDaemonNoAttach(t, authority)
	ref := ensureAttachWithPolicyOptions(
		t, hc, authority, "vol-umount-bound", "main",
		"/Volumes/UmountBound", "writeback",
		map[string]any{"flushIntervalMs": int64(3600000), "diskCacheMb": int64(256)},
	)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "umount-bound-test"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
	dir := c.call(&pfslocal.MkdirRequest{
		Dir: root, Name: []byte("bulk"), Mode: 0o755,
	}).(*pfslocal.MkdirReply)
	payload := make([]byte, 256<<10)
	for i := 0; i < 12; i++ {
		created := c.call(&pfslocal.CreateRequest{
			Dir: dir.Attr.Item, Name: []byte(fmt.Sprintf("b%d", i)),
			Mode: 0o644, Exclusive: true,
		}).(*pfslocal.CreateReply)
		c.call(&pfslocal.WriteRequest{Handle: created.Handle, Data: payload})
		c.call(&pfslocal.CloseRequest{Handle: created.Handle})
	}

	// The request must ANSWER — either the completed unmount or the definite
	// in-progress verdict — inside its own budget, with margin for the HTTP
	// round trip itself.
	answered := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		req, err := http.NewRequest(
			http.MethodPost, "http://portablefsd/v1/attaches/"+ref+"/unmount", nil,
		)
		if err == nil {
			if resp, derr := hc.Do(req); derr == nil {
				_ = resp.Body.Close()
			}
		}
		answered <- time.Since(started)
	}()
	select {
	case took := <-answered:
		if took > 20*time.Second {
			t.Fatalf(
				"unmount request took %s: it blocked on the whole drain "+
					"transaction instead of answering within its own budget",
				took,
			)
		}
	case <-time.After(30 * time.Second):
		t.Fatal(
			"unmount request never answered: it blocked on the whole drain " +
				"transaction, so `portablefs umount` reports its own HTTP " +
				"timeout — a transport error — instead of a verdict",
		)
	}
}
