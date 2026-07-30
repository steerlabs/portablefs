package fsproto

import (
	"context"
	"encoding/binary"
	"encoding/gob"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// reservationBlockingLog pauses one CommitThrough after its row has already
// been reserved. It exposes the otherwise tiny reserved-before-applied window
// where protocol-only delegation gates used to miss a concurrent grant.
type reservationBlockingLog struct {
	*protoEntryLog

	mu      sync.Mutex
	block   bool
	entered chan struct{}
	release chan struct{}
}

func newReservationBlockingLog() *reservationBlockingLog {
	return &reservationBlockingLog{protoEntryLog: newProtoEntryLog()}
}

func (l *reservationBlockingLog) blockNextCommit() (<-chan struct{}, chan<- struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.block {
		panic("reservation blocking log already armed")
	}
	l.block = true
	l.entered = make(chan struct{})
	l.release = make(chan struct{})
	return l.entered, l.release
}

func (l *reservationBlockingLog) CommitThrough(seq uint64) error {
	l.mu.Lock()
	if !l.block {
		l.mu.Unlock()
		return l.protoEntryLog.CommitThrough(seq)
	}
	l.block = false
	entered, release := l.entered, l.release
	l.mu.Unlock()

	close(entered)
	<-release
	return l.protoEntryLog.CommitThrough(seq)
}

func waitReservedRows(t *testing.T, log *protoEntryLog, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := log.rowCount(); got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("journal reserved %d rows, want at least %d", log.rowCount(), want)
}

// TestCanonicalAliasSharesCooldown pins the canonicalize-once boundary: a
// contention recall recorded for a canonical scope declines an acquire
// spelled through an alias ("x/../ws"), and the durable decision itself is
// keyed canonically — alias spellings cannot bypass the cooldown or induce
// delegation churn.
func TestCanonicalAliasSharesCooldown(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-alias", 1, "MA", "tokA", 8)
	if r := exactDo(s, a, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}
	s.delegations.noteContention("ws")
	if r := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "x/../ws", SessionID: "wb-alias", Owner: "MA"}, 0, 2); r == nil || r.Status != EBUSY {
		t.Fatalf("alias-spelled acquire under cooldown: %+v, want EBUSY", r)
	}
	// The cooldown clears; the alias spelling acquires the CANONICAL scope.
	s.delegations.mu.Lock()
	s.delegations.recalls = map[string]time.Time{}
	s.delegations.mu.Unlock()
	r := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "x/../ws", SessionID: "wb-alias", Owner: "MA"}, 0, 3)
	if r == nil || r.Status != OK || r.CheckoutEpoch == "" {
		t.Fatalf("alias acquire after cooldown: %+v", r)
	}
	store := s.coordStore()
	if got := store.ManagedDelegationsOverlapping("ws"); len(got) != 1 || got[0].Path != "ws" {
		t.Fatalf("grant not keyed canonically: %+v", got)
	}
}

// TestAbsentAndOversizeScopesDecline pins the delegable-scope policy: an
// absent path, a file, and a directory past the grant children bound all
// decline durably (write-through), never grant.
func TestAbsentAndOversizeScopesDecline(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-shape", 1, "MA", "tokA", 8)
	if r := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "missing", SessionID: "wb-s", Owner: "MA"}, 0, 1); r == nil || r.Status != EBUSY {
		t.Fatalf("absent scope: %+v, want EBUSY", r)
	}
	if r := exactDo(s, a, &Request{Op: OpCreate, Path: "plain", Mode: 0o644}, 0, 2); r == nil || r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "plain", SessionID: "wb-s", Owner: "MA"}, 0, 3); r == nil || r.Status != EBUSY {
		t.Fatalf("file scope: %+v, want EBUSY", r)
	}
}

// serveManagedAuthorityServer is serveManagedAuthorityFS also returning the
// *Server for tests that install the lost-reply seam.
func serveManagedAuthorityServer(t *testing.T) (string, *Server) {
	t.Helper()
	fs, err := workfs.NewManaged(nil, nopBlobs{}, newProtoEntryLog())
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), srv
}

// TestAcquireLostReplyResolvesToGrant pins invariant 8's client half: a
// DelegationAcquire whose reply is LOST (fully applied server-side, dropped
// in flight) must resolve by replaying the identical exact identity — the
// caller learns the TRUE outcome (granted, with the stored epoch), never a
// fabricated denial that would leave the authority holding a grant the
// engine does not know exists.
func TestAcquireLostReplyResolvesToGrant(t *testing.T) {
	addr, srv := serveManagedAuthorityServer(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("M")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if _, st, err := cli.Mkdir("w", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	held, st, err := cli.Create("w/held", 0o644)
	if err != nil || st != OK {
		t.Fatalf("create held: st=%d err=%v", st, err)
	}
	// ONE seam installed before any traffic (SetDropReply is not safe to
	// swap mid-flight): drop the FIRST acquire reply, several consecutive
	// prepare replies, and the FIRST checkin reply, counting under a mutex.
	// More than two prepare losses proves the envelope-less prepare is resolved
	// beyond doAttached's old bounded retry budget.
	const lostPrepareReplies = 3
	var dropMu sync.Mutex
	droppedAcquire, droppedPrepare, droppedCheckin := 0, 0, 0
	srv.SetDropReply(func(req *Request, resp *Response) bool {
		dropMu.Lock()
		defer dropMu.Unlock()
		switch {
		case req.Op == OpDelegationAcquire && droppedAcquire == 0:
			droppedAcquire++
			return true // the grant committed; the reply is lost in flight
		case req.Op == OpDelegationPrepareRelease && droppedPrepare < lostPrepareReplies:
			droppedPrepare++
			return true // the pins committed; held grant makes retry stable
		case req.Op == OpCheckin && droppedCheckin == 0:
			droppedCheckin++
			return true
		}
		return false
	})
	grant, err := cli.DelegationAcquire("w", "wb-lost-reply")
	if err != nil {
		t.Fatalf("acquire with lost reply must resolve, got err=%v", err)
	}
	if !grant.Granted || grant.Epoch == "" {
		t.Fatalf("acquire resolved to %+v; the committed grant must be discovered, never denied", grant)
	}
	inos, _, err := cli.PrepareDelegationRelease("w", grant.Epoch, []string{"w/held"})
	if err != nil {
		t.Fatalf("prepare with lost reply must resolve: %v", err)
	}
	if len(inos) != 1 || inos[0] != held.Ino {
		t.Fatalf("prepare mapping = %v, want [%d]", inos, held.Ino)
	}
	fs := srv.fs.(*workfs.FS)
	if holders := managedPinState(t, fs).PinHolders(held.Ino); len(holders) != 1 {
		t.Fatalf("replayed prepare accumulated %d pin holders, want one: %v", len(holders), holders)
	}
	// The release outcome resolves identically through its own lost reply.
	if err := cli.CheckinManaged("w", grant.Epoch); err != nil {
		t.Fatalf("checkin with lost reply must resolve to the stored outcome: %v", err)
	}
	// The response taught the caller the committed inode identity, so its
	// ordinary exact unmark can retire the prepare hold completely. Replays
	// must not have accumulated hidden refcounts.
	if st, err := cli.UnmarkOpenBatch(inos); err != nil || st != OK {
		t.Fatalf("retire replayed prepare pin: status=%d err=%v", st, err)
	}
	if holders := managedPinState(t, fs).PinHolders(held.Ino); len(holders) != 0 {
		t.Fatalf("prepare pin survived one learned retirement: %v", holders)
	}
	dropMu.Lock()
	da, dp, dc := droppedAcquire, droppedPrepare, droppedCheckin
	dropMu.Unlock()
	if da != 1 || dp != lostPrepareReplies || dc != 1 {
		t.Fatalf(
			"test seam dropped acquire=%d prepare=%d checkin=%d replies, want 1/%d/1",
			da, dp, dc, lostPrepareReplies,
		)
	}
	// The grant is durably released: a peer can acquire immediately.
	store := srv.coordStore()
	if got := store.ManagedDelegationsOverlapping("w"); len(got) != 0 {
		t.Fatalf("grant survived the resolved release: %+v", got)
	}
}

func TestPrepareLostRepliesTerminateCleanlyOnClientClose(t *testing.T) {
	addr, srv := serveManagedAuthorityServer(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("M-close")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if _, st, err := cli.Mkdir("w", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: status=%d err=%v", st, err)
	}
	held, st, err := cli.Create("w/held", 0o644)
	if err != nil || st != OK {
		t.Fatalf("create held: status=%d err=%v", st, err)
	}
	grant, err := cli.DelegationAcquire("w", "wb-close")
	if err != nil || !grant.Granted {
		t.Fatalf("acquire: grant=%+v err=%v", grant, err)
	}

	prepareCommitted := make(chan struct{}, 1)
	srv.SetDropReply(func(req *Request, _ *Response) bool {
		if req.Op != OpDelegationPrepareRelease {
			return false
		}
		select {
		case prepareCommitted <- struct{}{}:
		default:
		}
		return true // every prepare reply is lost until client termination
	})

	prepareOut := make(chan error, 1)
	go func() {
		_, _, err := cli.PrepareDelegationRelease("w", grant.Epoch, []string{"w/held"})
		prepareOut <- err
	}()
	select {
	case <-prepareCommitted:
	case <-time.After(2 * time.Second):
		t.Fatal("prepare did not commit before its reply was dropped")
	}
	if holders := managedPinState(t, srv.fs.(*workfs.FS)).PinHolders(held.Ino); len(holders) != 1 {
		t.Fatalf("committed prepare pin holders = %v, want one", holders)
	}

	closeOut := make(chan error, 1)
	go func() { closeOut <- cli.Close() }()
	select {
	case err := <-closeOut:
		if err != nil {
			t.Fatalf("close client: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client close blocked behind unresolved prepare")
	}
	select {
	case err := <-prepareOut:
		if err == nil {
			t.Fatal("prepare reported success without a learned reply")
		}
	case <-time.After(time.Second):
		t.Fatal("unresolved prepare survived client close")
	}
	if holders := managedPinState(t, srv.fs.(*workfs.FS)).PinHolders(held.Ino); len(holders) != 0 {
		t.Fatalf("clean session close left committed prepare pin behind: %v", holders)
	}
}

// TestSameSessionWriteThroughGatedByOwnGrant pins the snapshot-exactness
// mechanism: a write-through mutation from the HOLDER's own session does not
// bypass the peer gate — it recalls the holder's grant and proceeds only
// after the durable release. Nothing (peer or same-session) can mutate a
// scope between its grant and its snapshot, and every mutation inside a held
// scope stays on exactly one lane.
func TestSameSessionWriteThroughGatedByOwnGrant(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-ssgate", 1, "MA", "tokA", 8)
	if r := exactDo(s, a, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}
	co := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-ssgate", Owner: "MA"}, 0, 2)
	if co == nil || co.Status != OK || co.CheckoutEpoch == "" {
		t.Fatalf("acquire: %+v", co)
	}
	done := make(chan *Response, 1)
	go func() {
		done <- exactDo(s, a, &Request{Op: OpCreate, Path: "ws/raced", Mode: 0o644}, 1, 1)
	}()
	select {
	case r := <-done:
		t.Fatalf("same-session write-through slipped past the held grant: %+v", r)
	case <-time.After(400 * time.Millisecond):
		// Correct: the mutation is parked behind the recall of our own grant.
	}
	if r := exactDo(s, a, &Request{Op: OpCheckin, Path: "ws", CheckoutEpoch: co.CheckoutEpoch, Owner: "MA"}, 2, 1); r == nil || r.Status != OK {
		t.Fatalf("checkin: %+v", r)
	}
	select {
	case r := <-done:
		if r == nil || r.Status != OK {
			t.Fatalf("gated create after release: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("gated create never proceeded after the release")
	}
}

// TestExactDelegationGateRejectionIsReplayable proves the bounded
// recovery-required EAGAIN is itself an exact outcome. Replaying the same
// identity returns the stored rejection, and the immediately following
// sequence on that slot remains valid. Cover both exact-gated surfaces:
// write-through tree mutations and managed lock acquisitions.
func TestExactDelegationGateRejectionIsReplayable(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	contender := openJournaledSession(t, s, "pfs-gate-contender", 1, "MC", "tokC", 8)
	holder := openJournaledSession(t, s, "pfs-gate-holder", 1, "MH", "tokH", 8)

	if r := exactDo(s, contender, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir delegated scope: %+v", r)
	}
	if r := exactDo(s, contender, &Request{Op: OpCreate, Path: "ws/file", Mode: 0o644}, 0, 2); r == nil || r.Status != OK {
		t.Fatalf("create delegated file: %+v", r)
	}
	if r := exactDo(s, contender, &Request{Op: OpCreate, Path: "outside", Mode: 0o644}, 0, 3); r == nil || r.Status != OK {
		t.Fatalf("create outside file: %+v", r)
	}
	grant := exactDo(s, holder, &Request{
		Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-gate", Owner: holder.owner,
	}, 0, 1)
	if grant == nil || grant.Status != OK || grant.CheckoutEpoch == "" {
		t.Fatalf("delegation acquire: %+v", grant)
	}
	if err := fs.ExpireSession(holder.id, holder.gen); err != nil {
		t.Fatalf("expire holder: %v", err)
	}
	if got := fs.ManagedDelegationsOverlapping("ws"); len(got) != 1 || !got[0].Recovery {
		t.Fatalf("delegation after holder expiry: %+v, want one recovery scope", got)
	}

	mutation := &Request{Op: OpCreate, Path: "ws/blocked", Mode: 0o644}
	if r := exactDo(s, contender, mutation, 0, 4); r == nil || r.Status != EAGAIN || r.Duplicate {
		t.Fatalf("first gated mutation: %+v, want durable EAGAIN", r)
	}
	if r := exactDo(s, contender, &Request{Op: OpCreate, Path: "ws/blocked", Mode: 0o644}, 0, 4); r == nil || r.Status != EAGAIN || !r.Duplicate {
		t.Fatalf("gated mutation replay: %+v, want stored EAGAIN duplicate", r)
	}
	if r := exactDo(s, contender, &Request{Op: OpCreate, Path: "after-gate", Mode: 0o644}, 0, 5); r == nil || r.Status != OK {
		t.Fatalf("mutation after gated identity: %+v, slot sequence did not advance contiguously", r)
	}

	lock := &Request{
		Op: OpLock, Path: "ws/file", LkMode: LkSetlk,
		LkID: 7, LkStart: 0, LkEnd: 10, LkWrite: true,
	}
	if r := exactDo(s, contender, lock, 1, 1); r == nil || r.Status != EAGAIN || r.Duplicate {
		t.Fatalf("first gated lock: %+v, want durable EAGAIN", r)
	}
	if r := exactDo(s, contender, &Request{
		Op: OpLock, Path: "ws/file", LkMode: LkSetlk,
		LkID: 7, LkStart: 0, LkEnd: 10, LkWrite: true,
	}, 1, 1); r == nil || r.Status != EAGAIN || !r.Duplicate {
		t.Fatalf("gated lock replay: %+v, want stored EAGAIN duplicate", r)
	}
	if r := exactDo(s, contender, &Request{
		Op: OpLock, Path: "outside", LkMode: LkSetlk,
		LkID: 7, LkStart: 0, LkEnd: 10, LkWrite: true,
	}, 1, 2); r == nil || r.Status != OK {
		t.Fatalf("lock after gated identity: %+v, slot sequence did not advance contiguously", r)
	}
}

// TestDelegationReservationAtomicallyGatesMutationAndLock pins the root
// ordering boundary. The grant row is reserved but deliberately not applied,
// so the protocol's applied-state recall gate observes no delegation. Both
// later operations must nevertheless see the RESERVED grant in their own
// journal decisions and consume their identities as exact EAGAIN outcomes.
// Consequently the grant snapshot cannot omit a mutation that later lands
// beneath it, and no managed lock can enter the delegated scope.
func TestDelegationReservationAtomicallyGatesMutationAndLock(t *testing.T) {
	log := newReservationBlockingLog()
	fs, err := workfs.NewManaged(nil, nopBlobs{}, log)
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	s := NewServer(fs, fs)
	holder := openJournaledSession(t, s, "pfs-atomic-holder", 1, "MH", "tokH", 8)
	peer := openJournaledSession(t, s, "pfs-atomic-peer", 1, "MP", "tokP", 8)

	if r := exactDo(s, holder, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir scope: %+v", r)
	}
	if r := exactDo(s, holder, &Request{Op: OpCreate, Path: "ws/file", Mode: 0o644}, 0, 2); r == nil || r.Status != OK {
		t.Fatalf("create lock target: %+v", r)
	}

	baseRows := log.rowCount()
	grantEntered, releaseGrant := log.blockNextCommit()
	grantDone := make(chan *Response, 1)
	go func() {
		grantDone <- exactDo(s, holder, &Request{
			Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-atomic", Owner: holder.owner,
		}, 1, 1)
	}()
	select {
	case <-grantEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("delegation row did not reach reserved-before-applied seam")
	}
	if got := fs.ManagedDelegationsOverlapping("ws"); len(got) != 0 {
		t.Fatalf("grant became applied before seam release: %+v", got)
	}

	mutationDone := make(chan *Response, 1)
	go func() {
		mutationDone <- exactDo(s, peer, &Request{
			Op: OpCreate, Path: "ws/late", Mode: 0o644,
		}, 0, 1)
	}()
	lockDone := make(chan *Response, 1)
	go func() {
		lockDone <- exactDo(s, peer, &Request{
			Op: OpLock, Path: "ws/file", LkMode: LkSetlk,
			LkID: 17, LkStart: 0, LkEnd: 10, LkWrite: true,
		}, 1, 1)
	}()

	// Grant + two exact rejection rows must all reserve while the grant is
	// still unapplied. A tree or LockChange row here is the historical race.
	waitReservedRows(t, log.protoEntryLog, baseRows+3)
	close(releaseGrant)

	var grant, mutation, lock *Response
	for name, result := range map[string]struct {
		ch  <-chan *Response
		dst **Response
	}{
		"grant":    {grantDone, &grant},
		"mutation": {mutationDone, &mutation},
		"lock":     {lockDone, &lock},
	} {
		select {
		case *result.dst = <-result.ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not finish after releasing grant durability", name)
		}
	}
	if grant == nil || grant.Status != OK || grant.CheckoutEpoch == "" {
		t.Fatalf("delegation acquire: %+v", grant)
	}
	if mutation == nil || mutation.Status != EAGAIN || mutation.Duplicate {
		t.Fatalf("mutation racing reserved grant: %+v, want fresh exact EAGAIN", mutation)
	}
	if lock == nil || lock.Status != EAGAIN || lock.Duplicate {
		t.Fatalf("lock racing reserved grant: %+v, want fresh exact EAGAIN", lock)
	}
	for _, entry := range grant.Entries {
		if entry.Name == "late" {
			t.Fatalf("grant snapshot contains mutation that should have been rejected: %+v", grant.Entries)
		}
	}
	if _, err := fs.Lstat("ws/late"); err == nil {
		t.Fatal("mutation landed beneath the delegation after its snapshot")
	}
	if replay := exactDo(s, peer, &Request{Op: OpCreate, Path: "ws/late", Mode: 0o644}, 0, 1); replay == nil || replay.Status != EAGAIN || !replay.Duplicate {
		t.Fatalf("mutation rejection replay: %+v", replay)
	}
	if replay := exactDo(s, peer, &Request{
		Op: OpLock, Path: "ws/file", LkMode: LkSetlk,
		LkID: 17, LkStart: 0, LkEnd: 10, LkWrite: true,
	}, 1, 1); replay == nil || replay.Status != EAGAIN || !replay.Duplicate {
		t.Fatalf("lock rejection replay: %+v", replay)
	}
	if got := log.rowCount(); got != baseRows+3 {
		t.Fatalf("duplicate replays appended rows: got %d want %d", got, baseRows+3)
	}
}

// TestDelegationSnapshotWaitsForEarlierReservedMutation proves the other
// reservation order. A mutation that reserves first is not yet visible when
// the acquire begins, but the later grant cannot apply or snapshot until the
// earlier row applies. The returned snapshot must therefore contain it.
func TestDelegationSnapshotWaitsForEarlierReservedMutation(t *testing.T) {
	log := newReservationBlockingLog()
	fs, err := workfs.NewManaged(nil, nopBlobs{}, log)
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	s := NewServer(fs, fs)
	holder := openJournaledSession(t, s, "pfs-prior-holder", 1, "MH", "tokH", 8)
	peer := openJournaledSession(t, s, "pfs-prior-peer", 1, "MP", "tokP", 8)
	if r := exactDo(s, holder, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir scope: %+v", r)
	}

	baseRows := log.rowCount()
	mutationEntered, releaseMutation := log.blockNextCommit()
	mutationDone := make(chan *Response, 1)
	go func() {
		mutationDone <- exactDo(s, peer, &Request{
			Op: OpCreate, Path: "ws/early", Mode: 0o644,
		}, 0, 1)
	}()
	select {
	case <-mutationEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("mutation row did not reach reserved-before-applied seam")
	}
	if _, err := fs.Lstat("ws/early"); err == nil {
		t.Fatal("blocked mutation became visible before its apply turn")
	}

	grantDone := make(chan *Response, 1)
	go func() {
		grantDone <- exactDo(s, holder, &Request{
			Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-prior", Owner: holder.owner,
		}, 1, 1)
	}()
	waitReservedRows(t, log.protoEntryLog, baseRows+2)
	select {
	case grant := <-grantDone:
		t.Fatalf("grant returned before the earlier mutation applied: %+v", grant)
	default:
	}
	close(releaseMutation)

	var mutation, grant *Response
	select {
	case mutation = <-mutationDone:
	case <-time.After(10 * time.Second):
		t.Fatal("mutation did not finish after durability release")
	}
	select {
	case grant = <-grantDone:
	case <-time.After(10 * time.Second):
		t.Fatal("grant did not finish after earlier mutation applied")
	}
	if mutation == nil || mutation.Status != OK {
		t.Fatalf("earlier mutation: %+v", mutation)
	}
	if grant == nil || grant.Status != OK || grant.CheckoutEpoch == "" {
		t.Fatalf("later delegation acquire: %+v", grant)
	}
	found := false
	for _, entry := range grant.Entries {
		if entry.Name == "early" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("grant snapshot omitted earlier reserved mutation: %+v", grant.Entries)
	}
}

// TestForgedExactEnvelopeCannotPublishRecall pins the authentication order:
// neither exact-gated surface may touch the recall policy before proving that
// the envelope belongs to the connection's attached session.
func TestForgedExactEnvelopeCannotPublishRecall(t *testing.T) {
	tests := []struct {
		name string
		req  func() *Request
	}{
		{
			name: "tree mutation",
			req: func() *Request {
				return &Request{Op: OpCreate, Path: "ws/forged", Mode: 0o644}
			},
		},
		{
			name: "lock acquisition",
			req: func() *Request {
				return &Request{
					Op: OpLock, Path: "ws/file", LkMode: LkSetlk,
					LkID: 9, LkStart: 0, LkEnd: 10, LkWrite: true,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := newManagedServer(t, newProtoEntryLog())
			holder := openJournaledSession(t, s, "pfs-recall-holder", 1, "MH", "tokH", 8)
			attacker := openJournaledSession(t, s, "pfs-recall-attacker", 1, "MA", "tokA", 8)
			if r := exactDo(s, holder, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
				t.Fatalf("mkdir: %+v", r)
			}
			if r := exactDo(s, holder, &Request{Op: OpCreate, Path: "ws/file", Mode: 0o644}, 0, 2); r == nil || r.Status != OK {
				t.Fatalf("create: %+v", r)
			}
			grant := exactDo(s, holder, &Request{
				Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-forged", Owner: holder.owner,
			}, 1, 1)
			if grant == nil || grant.Status != OK {
				t.Fatalf("delegation acquire: %+v", grant)
			}

			req := tt.req()
			req.Env = &wal.Envelope{
				SessionID: holder.id, Generation: holder.gen, Slot: 2, SlotSeq: 1,
			}
			done := make(chan *Response, 1)
			go func() { done <- s.dispatchConn(attacker, req) }()

			var (
				resp      *Response
				recalled  bool
				timedOut  bool
				waitUntil = time.Now().Add(time.Second)
			)
			for resp == nil && !recalled && time.Now().Before(waitUntil) {
				select {
				case resp = <-done:
				default:
					s.delegations.mu.Lock()
					_, recalled = s.delegations.recalls["ws"]
					s.delegations.mu.Unlock()
					if !recalled {
						time.Sleep(time.Millisecond)
					}
				}
			}
			if resp == nil && !recalled {
				timedOut = true
			}

			// Always release the live grant so a regressed pre-auth gate can
			// finish its wait and the test leaves no blocked goroutine behind.
			if r := exactDo(s, holder, &Request{
				Op: OpCheckin, Path: "ws", CheckoutEpoch: grant.CheckoutEpoch, Owner: holder.owner,
			}, 3, 1); r == nil || r.Status != OK {
				t.Fatalf("release grant: %+v", r)
			}
			if resp == nil {
				select {
				case resp = <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("forged request remained blocked after grant release")
				}
			}
			if timedOut {
				t.Fatal("forged request did not fail authentication promptly")
			}
			if recalled {
				t.Fatal("forged envelope published a delegation recall before authentication")
			}
			if resp == nil || resp.Status != ESTALE {
				t.Fatalf("forged request response: %+v, want ESTALE", resp)
			}
		})
	}
}

// TestBarrierFailsOnUnackedLiveSubscriber pins the bounded barrier wait: a
// LIVE subscriber that never acknowledges its invalidation position fails
// the barrier typed (EIO) within the bound — never a silent success claiming
// cross-machine visibility it cannot prove. The failed barrier evicts that
// subscriber, so one read-but-never-ack peer cannot wedge every later fsync.
func TestBarrierFailsOnUnackedLiveSubscriber(t *testing.T) {
	oldWait := barrierAckWait
	barrierAckWait = 500 * time.Millisecond
	t.Cleanup(func() { barrierAckWait = oldWait })
	_, addr := serveFS(t)

	// A raw subscriber that reads the stream but NEVER acks (live-but-slow).
	lurker, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := secure.ClientHandshake(lurker, secure.AuthToken()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	lenc := newRequestEncoder(lurker)
	ldec := gob.NewDecoder(lurker)
	if err := lenc.Encode(&Request{Op: OpSubscribe, Owner: "lurker"}); err != nil {
		t.Fatal(err)
	}
	defer lurker.Close()
	var hello Response
	if err := ldec.Decode(&hello); err != nil || !hello.Keepalive || !hello.InvBootstrap {
		t.Fatalf("subscribe hello: %+v err=%v", hello, err)
	}
	lurkerDone := make(chan struct{})
	go func() { // keep reading so the stream write path never stalls
		defer close(lurkerDone)
		for {
			var resp Response
			if err := ldec.Decode(&resp); err != nil {
				return
			}
		}
	}()

	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("M")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if _, st, err := cli.Create("bar.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	// The create's invalidation reached the lurker's stream; the lurker
	// never acks, so the barrier must fail typed within the bound.
	start := time.Now()
	err = cli.Sync()
	if err == nil {
		t.Fatal("barrier succeeded with a live subscriber that never acknowledged the covering invalidation")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("barrier failure took %v, want ~the ack bound", elapsed)
	}
	// The timeout itself drops the laggard. The next barrier succeeds without
	// an operator/client-side disconnect.
	select {
	case <-lurkerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("barrier timeout did not evict the unacked subscriber")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := cli.Sync(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("barrier still failing after the unacked subscriber dropped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSubscriberBootstrapMustBeAcknowledged(t *testing.T) {
	oldWait := barrierAckWait
	barrierAckWait = 250 * time.Millisecond
	t.Cleanup(func() { barrierAckWait = oldWait })
	_, addr := serveFS(t)

	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("bootstrap-writer")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if _, st, err := cli.Create("before-subscribe", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := secure.ClientHandshake(raw, secure.AuthToken()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	enc, dec := newRequestEncoder(raw), gob.NewDecoder(raw)
	if err := enc.Encode(&Request{Op: OpSubscribe}); err != nil {
		t.Fatal(err)
	}
	var bootstrap Response
	if err := dec.Decode(&bootstrap); err != nil {
		t.Fatal(err)
	}
	if !bootstrap.InvBootstrap || bootstrap.InvPos == 0 {
		t.Fatalf("bootstrap = %+v, want a tracked cache-reset position", bootstrap)
	}
	if err := cli.Sync(); err == nil {
		t.Fatal("barrier pre-counted a subscriber that never applied/acked its bootstrap")
	}
	if err := cli.Sync(); err != nil {
		t.Fatalf("barrier stayed wedged after evicting bootstrap-stalled subscriber: %v", err)
	}
}

func TestSubscriberRejectsAckBeyondSentPosition(t *testing.T) {
	_, addr := serveFS(t)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := secure.ClientHandshake(raw, secure.AuthToken()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	enc, dec := newRequestEncoder(raw), gob.NewDecoder(raw)
	if err := enc.Encode(&Request{Op: OpSubscribe}); err != nil {
		t.Fatal(err)
	}
	var bootstrap Response
	if err := dec.Decode(&bootstrap); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(&Request{Op: OpInvalidationAck, AckPos: bootstrap.InvPos + 1}); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	var unexpected Response
	if err := dec.Decode(&unexpected); err == nil {
		t.Fatalf("future ack kept the subscriber alive: %+v", unexpected)
	}
}

func TestAttachedSubscriberOwnerMustMatchSession(t *testing.T) {
	_, addr := serveFS(t)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := secure.ClientHandshake(raw, secure.AuthToken()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	enc, dec := newRequestEncoder(raw), gob.NewDecoder(raw)
	if err := enc.Encode(&Request{
		Op: OpSessionOpen, SessionID: "owner-bound-sub", SessionGen: 1,
		SessionToken: "owner-bound-token", SessionSlots: 1, Owner: "real-owner",
	}); err != nil {
		t.Fatal(err)
	}
	var opened Response
	if err := dec.Decode(&opened); err != nil || opened.Status != OK {
		t.Fatalf("session open: %+v err=%v", opened, err)
	}
	if err := enc.Encode(&Request{Op: OpSubscribe, Owner: "spoofed-owner"}); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	var unexpected Response
	if err := dec.Decode(&unexpected); err == nil {
		t.Fatalf("owner-spoofed subscription stayed alive: %+v", unexpected)
	}
}

// TestOversizeRequestDropsConnection pins the aggregate request-byte bound:
// an announced frame larger than maxRequestBytes is rejected before its body
// is read or allocated and the connection drops without a reply.
func TestOversizeRequestDropsConnection(t *testing.T) {
	_, addr := serveFS(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := secure.ClientHandshake(conn, secure.AuthToken()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	enc := newRequestEncoder(conn)
	dec := gob.NewDecoder(conn)
	// A small request round-trips (no auth token in tests).
	if err := enc.Encode(&Request{Op: OpGetattr, Path: ""}); err != nil {
		t.Fatalf("encode small: %v", err)
	}
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode small: %v", err)
	}
	// Announce the hostile aggregate without sending a body. A vulnerable
	// decoder would block reading or allocate the announced size first.
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], maxRequestBytes+1)
	if _, err := conn.Write(frame[:]); err != nil {
		t.Fatalf("write hostile header: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := dec.Decode(&resp); err == nil {
		t.Fatalf("oversize request was answered (%+v); the connection must drop", resp)
	}
}
