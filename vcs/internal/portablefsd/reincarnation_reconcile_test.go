package portablefsd

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// startDaemonServer is startDaemon with the *Server retained. These tests
// assert on the DAEMON REGISTRY's own attribute copy (itemRecord.attr), which
// is not observable through the frontend protocol: the frontend reply for a
// name is composed from a fresh authority answer, so a stale registry record
// stays invisible until something else consumes it (a kernel refresh size
// decision, an item-kind decision). Reaching the attach directly is the only
// way to state the invariant these findings are about.
func startDaemonServer(t *testing.T) (Config, *http.Client, *Server, context.CancelFunc) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfsd-reincarnation-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := Config{
		FrontendSocket: filepath.Join(dir, "run", "frontend.sock"),
		ControlSocket:  filepath.Join(dir, "run", "control.sock"),
		StateDir:       filepath.Join(dir, "state"),
		Version:        "portablefsd-test",
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer(cfg)
	runDone := make(chan error, 1)
	go func() { runDone <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("daemon Run: %v", err)
			}
		case <-time.After(35 * time.Second):
			t.Error("daemon did not complete its bounded cooperative shutdown")
		}
	})
	waitUnix(t, cfg.ControlSocket)
	waitUnix(t, cfg.FrontendSocket)
	return cfg, httpUDSClient(cfg.ControlSocket), srv, cancel
}

// registryAttr reads the daemon registry's retained attribute for a path.
func registryAttr(t *testing.T, a *attach, p string) fsproto.Attr {
	t.Helper()
	a.mu.RLock()
	defer a.mu.RUnlock()
	rec := a.paths[p]
	if rec == nil {
		t.Fatalf("no registry record for %q", p)
	}
	return rec.attr
}

// peerReplace performs the peer half of a rename-over: create a replacement
// file with distinct content and atomically move it onto name.
func peerReplace(t *testing.T, cli *fsproto.Client, tmp, name string, data []byte) {
	t.Helper()
	if _, st, err := cli.Create(tmp, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("peer create %s st=%d err=%v", tmp, st, err)
	}
	if _, st, err := cli.Write(tmp, 0, data, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("peer write %s st=%d err=%v", tmp, st, err)
	}
	if st, _, err := cli.RenameWithOrphanTarget(tmp, name, false); err != nil || st != fsproto.OK {
		t.Fatalf("peer rename %s -> %s st=%d err=%v", tmp, name, st, err)
	}
}

// TestEnumerateReconcilesReincarnatedAliasBeforeReply is the ENUMERATE mirror of
// TestRemoteRenameOverReincarnatesItem.
//
// Both are publishing operations by the same classification
// (frontendRequestPublishes) and both expose their replies through the same
// replyWithPublication, so a pathname reincarnation discovered by enumerate owes
// the displaced inode's retained aliases exactly the reconciliation a lookup
// owes them. Only lookup paid it.
//
// The alias deliberately lives in a DIFFERENT directory from the replaced name.
// An alias listed in the same page would be refreshed incidentally by the very
// readdir that carried the replacement, which would hide the missing ordering
// rather than test it.
func TestEnumerateReconcilesReincarnatedAliasBeforeReply(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, srv, cancel := startDaemonServer(t)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-enumerate-reincarnation", "main",
		"/Volumes/EnumerateReincarnation")
	a := srv.registry.get(ref)
	if a == nil {
		t.Fatal("attach missing after ensure")
	}

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "enumerate-reincarnation"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root

	names := c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("names"), Mode: 0o755}).(*pfslocal.MkdirReply)
	links := c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("links"), Mode: 0o755}).(*pfslocal.MkdirReply)
	f := c.call(&pfslocal.CreateRequest{
		Dir: names.Attr.Item, Name: []byte("a"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: f.Handle, Data: []byte("old\n")})
	c.call(&pfslocal.CloseRequest{Handle: f.Handle})
	b := c.call(&pfslocal.HardLinkRequest{
		Item: f.Attr.Item, Dir: links.Attr.Item, Name: []byte("b"),
	}).(*pfslocal.HardLinkReply)
	if b.Attr.Item != f.Attr.Item || b.Attr.Nlink != 2 {
		t.Fatalf("hard-link identity split before replace: a=%+v b=%+v", f.Attr, b.Attr)
	}
	if got := registryAttr(t, a, "links/b").Nlink; got != 2 {
		t.Fatalf("registry alias nlink before replace = %d, want 2", got)
	}

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	peerReplace(t, remote.Client(), "names/a.lock", "names/a", []byte("new\n"))

	// Drive the replacement's discovery through ENUMERATE only. Nothing in this
	// loop resolves "links/b", so the ONLY thing that can restate the retained
	// alias is the reconciliation the enumerate publisher owes.
	deadline := time.Now().Add(10 * time.Second)
	for {
		rep := c.call(&pfslocal.EnumerateRequest{
			Dir: names.Attr.Item, WantAttrs: true, MaxEntries: 64,
		}).(*pfslocal.EnumerateReply)
		replaced := false
		for _, e := range rep.Entries {
			if string(e.Name) == "a" && e.Attr.Item != f.Attr.Item {
				replaced = true
			}
		}
		if replaced {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("enumerate never observed the replacement of names/a")
		}
		time.Sleep(25 * time.Millisecond)
	}

	if got := registryAttr(t, a, "links/b").Nlink; got != 1 {
		t.Fatalf("enumerate published the replacement while the retained alias "+
			"still claimed the pre-replacement link count: links/b nlink=%d, want 1", got)
	}
}

// TestReincarnationDebtIsNotSettleableByAnotherPublisher pins ownership.
//
// The debt a reincarnation records belongs to the publisher whose registration
// created it. A second, unrelated publisher must not be able to discharge it:
// if it can, the owner's own settle finds nothing left to do and publishes a
// post-reincarnation identity beside an unrefreshed alias, which is precisely
// the impossible pair the ordering exists to prevent.
func TestReincarnationDebtIsNotSettleableByAnotherPublisher(t *testing.T) {
	a := newAttach("att_reincarnation_owner", "key", ensureAttachRequest{
		VolumeID: "vol-reincarnation-owner", Branch: "main",
		MountPath: "/Volumes/ReincarnationOwner", AuthorityURL: "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
	a.identityEpoch = 11

	a.registerLocked("a", fsproto.Attr{Ino: 41, Kind: "file", Nlink: 2})
	a.registerLocked("b", fsproto.Attr{Ino: 41, Kind: "file", Nlink: 2})
	a.registerLocked("x", fsproto.Attr{Ino: 71, Kind: "file", Nlink: 2})
	a.registerLocked("y", fsproto.Attr{Ino: 71, Kind: "file", Nlink: 2})

	// Publisher A discovers a reincarnation of "a": its retained alias "b" owes
	// a refresh, and A owns that debt.
	_, ticketA := a.registerOwned("a", fsproto.Attr{Ino: 99, Kind: "file", Nlink: 1})
	if ticketA == nil {
		t.Fatal("reincarnating registration minted no reconciliation ticket")
	}
	if !ticketA.owes("b") {
		t.Fatalf("ticket A does not own the debt for its own retained alias: %+v", ticketA)
	}

	// Publisher B discovers an unrelated reincarnation of "x". Settling B's own
	// ticket must not touch A's.
	_, ticketB := a.registerOwned("x", fsproto.Attr{Ino: 171, Kind: "file", Nlink: 1})
	if ticketB == nil || !ticketB.owes("y") {
		t.Fatalf("ticket B did not own its own retained alias: %+v", ticketB)
	}
	if ticketB.owes("b") {
		t.Fatalf("ticket B claims publisher A's debt: %+v", ticketB)
	}
	// This attach has no authority attached, so B's authority-backed alias
	// cannot be restated. That must FAIL the publisher rather than discard the
	// obligation: an unreconcilable alias is exactly the state that must never
	// be published past, and the old take-all could not even express it because
	// the drain had already destroyed what it took.
	if eno, _ := ticketB.settle(context.Background(), nil); eno != darwinEIO {
		t.Fatalf("settling an unreconcilable ticket errno=%d, want EIO", eno)
	}
	if !a.debtOutstanding("y") {
		t.Fatal("a failed settle discarded the debt it could not discharge")
	}
	if !a.debtOutstanding("b") {
		t.Fatal("publisher B's settle discharged publisher A's debt")
	}

	// A publisher that created no debt at all gets an inert ticket and pays
	// nothing — it must not be able to drain what it never recorded.
	_, inert := a.registerOwned("unrelated", fsproto.Attr{Ino: 200, Kind: "file", Nlink: 1})
	if inert != nil {
		t.Fatalf("a registration that created no debt minted ticket %+v, want inert", inert)
	}
	if eno, _ := inert.settle(context.Background(), nil); eno != 0 {
		t.Fatalf("settling an inert ticket errno=%d", eno)
	}
	if !a.debtOutstanding("b") || !a.debtOutstanding("y") {
		t.Fatal("an inert ticket discharged another publisher's debt")
	}

	// A third publisher whose retained alias is no longer in the registry at all
	// needs no authority to settle: there is no stale snapshot left to
	// contradict the replacement. It discharges only its OWN obligation.
	a.registerLocked("p", fsproto.Attr{Ino: 81, Kind: "file", Nlink: 2})
	a.registerLocked("q", fsproto.Attr{Ino: 81, Kind: "file", Nlink: 2})
	_, ticketC := a.registerOwned("p", fsproto.Attr{Ino: 181, Kind: "file", Nlink: 1})
	if ticketC == nil || !ticketC.owes("q") {
		t.Fatalf("ticket C did not own its own retained alias: %+v", ticketC)
	}
	a.mu.Lock()
	a.removePathLocked("q")
	a.mu.Unlock()
	if eno, _ := ticketC.settle(context.Background(), nil); eno != 0 {
		t.Fatalf("settling ticket C errno=%d", eno)
	}
	if a.debtOutstanding("q") {
		t.Fatal("ticket C's own settle left its debt outstanding")
	}
	if !a.debtOutstanding("b") || !a.debtOutstanding("y") {
		t.Fatal("ticket C's settle reached debt it did not own")
	}
	if !ticketA.owes("b") {
		t.Fatalf("publisher A's obligation was taken from its ticket: %+v", ticketA)
	}
}

// TestReincarnationReconcileDoesNotOverwriteNewerAttributes wedges a
// reconciliation getattr between the authority reply and the daemon-registry
// install, and publishes a strictly newer mutation for the same name into that
// window.
//
// The registry is the mount's SECOND authoritative attribute store. clientcore
// already refuses to let an install travel backwards there
// (VersionCache.PublishOKToken, which postattrs.go routes every mutation's
// post-op attributes through); the registry had no such gate, so the parked
// reply won and the newer state was lost.
func TestReincarnationReconcileDoesNotOverwriteNewerAttributes(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, srv, cancel := startDaemonServer(t)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-reconcile-monotonic", "main",
		"/Volumes/ReconcileMonotonic")
	a := srv.registry.get(ref)
	if a == nil {
		t.Fatal("attach missing after ensure")
	}

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "reconcile-monotonic"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
	names := c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("names"), Mode: 0o755}).(*pfslocal.MkdirReply)
	links := c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("links"), Mode: 0o755}).(*pfslocal.MkdirReply)
	f := c.call(&pfslocal.CreateRequest{
		Dir: names.Attr.Item, Name: []byte("a"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: f.Handle, Data: []byte("old\n")})
	c.call(&pfslocal.CloseRequest{Handle: f.Handle})
	b := c.call(&pfslocal.HardLinkRequest{
		Item: f.Attr.Item, Dir: links.Attr.Item, Name: []byte("b"),
	}).(*pfslocal.HardLinkReply)

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	peerReplace(t, remote.Client(), "names/a.lock", "names/a", []byte("new\n"))

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	a.testLookupAfterVolume = func(p string) {
		if p != "links/b" {
			return
		}
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	defer func() { a.testLookupAfterVolume = nil }()

	lookupDone := make(chan struct{})
	go func() {
		defer close(lookupDone)
		lc := dialPFS(t, cfg.FrontendSocket)
		defer lc.close()
		lc.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "reconcile-monotonic-lookup"})
		lc.call(&pfslocal.ResolveRequest{AttachRef: ref})
		deadline := time.Now().Add(10 * time.Second)
		for {
			got := lc.call(&pfslocal.LookupRequest{
				Dir: names.Attr.Item, Name: []byte("a"),
			}).(*pfslocal.LookupReply)
			if got.Attr.Item != f.Attr.Item {
				return
			}
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("reconciliation getattr for the retained alias never ran")
	}

	// The reconciliation now holds a pre-mutation observation of links/b.
	// Publish a strictly newer one for the same name from another connection.
	//
	// THE MUTATION RUNS CONCURRENTLY, AND THAT IS THE CONTRACT, NOT A DETAIL.
	//
	// links/b has outstanding reconciliation debt, so this setattr is a
	// publisher of an INDEBTED ALIAS and publication admission applies to it:
	// its registry write lands immediately, and its REPLY then joins the
	// reconciliation already in flight rather than being exposed beside it (see
	// reincarnation.go, admitPublicationLocked). Calling it synchronously here
	// would park it behind a reconciliation this test holds open by hand, which
	// is an artefact of the wedge and not a production shape — the real
	// reconciliation is bounded by one authority round trip.
	//
	// What the test is actually about is unchanged and is asserted below: the
	// mutation's strictly newer state reaches the registry, and the parked
	// reconciliation's older observation must not overwrite it when it resumes.
	mode := uint32(0o600)
	mutationDone := make(chan struct{})
	go func() {
		defer close(mutationDone)
		mc := dialPFS(t, cfg.FrontendSocket)
		defer mc.close()
		mc.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "reconcile-monotonic-mutator"})
		mc.call(&pfslocal.ResolveRequest{AttachRef: ref})
		mc.call(&pfslocal.SetAttrRequest{Item: b.Attr.Item, Mode: &mode})
	}()

	// The mutation's registry write happens under a.mu, before its own
	// publication admission joins anything, so it is observable while the
	// reconciliation is still parked.
	mutationDeadline := time.Now().Add(15 * time.Second)
	for registryAttr(t, a, "links/b").Mode&0o777 != 0o600 {
		if time.Now().After(mutationDeadline) {
			t.Fatalf("mutation did not reach the registry: mode=%o",
				registryAttr(t, a, "links/b").Mode&0o777)
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(release)
	select {
	case <-mutationDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the mutation never completed after the reconciliation was released")
	}
	select {
	case <-lookupDone:
	case <-time.After(15 * time.Second):
		t.Fatal("parked lookup never completed")
	}

	if got := registryAttr(t, a, "links/b").Mode & 0o777; got != 0o600 {
		t.Fatalf("alias reconciliation installed a stale observation over a newer "+
			"one: registry mode=%o, want 0600", got)
	}
}
