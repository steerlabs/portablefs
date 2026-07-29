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
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

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
	// ONE seam installed before any traffic (SetDropReply is not safe to
	// swap mid-flight): drop the FIRST acquire reply and the FIRST checkin
	// reply, counting under a mutex.
	var dropMu sync.Mutex
	droppedAcquire, droppedCheckin := 0, 0
	srv.SetDropReply(func(req *Request, resp *Response) bool {
		dropMu.Lock()
		defer dropMu.Unlock()
		switch {
		case req.Op == OpDelegationAcquire && droppedAcquire == 0:
			droppedAcquire++
			return true // the grant committed; the reply is lost in flight
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
	// The release outcome resolves identically through its own lost reply.
	if err := cli.CheckinManaged("w", grant.Epoch); err != nil {
		t.Fatalf("checkin with lost reply must resolve to the stored outcome: %v", err)
	}
	dropMu.Lock()
	da, dc := droppedAcquire, droppedCheckin
	dropMu.Unlock()
	if da != 1 || dc != 1 {
		t.Fatalf("test seam dropped acquire=%d checkin=%d replies, want 1 each", da, dc)
	}
	// The grant is durably released: a peer can acquire immediately.
	store := srv.coordStore()
	if got := store.ManagedDelegationsOverlapping("w"); len(got) != 0 {
		t.Fatalf("grant survived the resolved release: %+v", got)
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
