//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

// applicationClock is fake authority time. Background coherence waiters started
// by a mutation read it while the test advances it, so access is serialized.
type applicationClock struct {
	mu     sync.Mutex
	now    time.Time
	timers chan time.Duration
}

func newApplicationClock() *applicationClock {
	return &applicationClock{now: time.Now(), timers: make(chan time.Duration, 64)}
}

func (c *applicationClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *applicationClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *applicationClock) NewTimer(d time.Duration) volumeserver.CoherenceTimer {
	c.timers <- d
	return topologyFrozenTimer{make(chan time.Time)}
}

// This context pauses the existing pre-lock check in cut, after single-reader
// selection. It is used only for the peer, never for the applying mutation.
type applicationCutContext struct {
	context.Context
	once             sync.Once
	entered, proceed chan struct{}
}

func (c *applicationCutContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.proceed })
	return c.Context.Err()
}

type applicationOpenStore struct {
	resourceAdmissionFaultStore
	mu                       sync.Mutex
	exists                   bool
	size                     int64
	handles                  map[xfsstore.Capability]xfsstore.Capability
	truncates, closes        atomic.Uint32
	applied                  atomic.Bool
	preError, postError      error
	openEntered, openProceed chan struct{}
	readEntered, readProceed chan struct{}
	afterApply               func()
}

func (s *applicationOpenStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item[0] == 0x22 || item[0] == 0x24 {
		if s.applied.Load() && s.postError != nil {
			return xfsstore.Attr{}, s.postError
		}
		s.mu.Lock()
		size := s.size
		s.mu.Unlock()
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(item[0]), Size: size, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
	}
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: uint64(item[0]), Mode: 0700, Nlink: 2, DeviceMinor: 1}, nil
}
func (s *applicationOpenStore) Lookup(_ xfsstore.Capability, _ string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.mu.Lock()
	exists := s.exists
	s.mu.Unlock()
	if !exists {
		return xfsstore.Capability{}, xfsstore.Attr{}, syscall.ENOENT
	}
	item := xfsstore.Capability{0x22}
	a, err := s.Getattr(item)
	return item, a, err
}
func (s *applicationOpenStore) Create(_ xfsstore.Capability, _ string, _ fs.FileMode, exclusive bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.create.Add(1)
	s.mu.Lock()
	if s.exists && exclusive {
		s.mu.Unlock()
		return xfsstore.Capability{}, xfsstore.Attr{}, syscall.EEXIST
	}
	s.exists = true
	s.mu.Unlock()
	item := xfsstore.Capability{0x22}
	a, err := s.Getattr(item)
	return item, a, err
}
func (s *applicationOpenStore) OpenFile(item xfsstore.Capability, flags xfsstore.OpenFlags) (xfsstore.Capability, error) {
	n := s.open.Add(1)
	if s.preError != nil {
		return xfsstore.Capability{}, s.preError
	}
	handle := xfsstore.Capability{byte(0x80 + n)}
	s.mu.Lock()
	s.handles[handle] = item
	if flags.Truncate {
		s.size = 0
		s.truncates.Add(1)
		s.applied.Store(true)
	}
	s.mu.Unlock()
	if s.openEntered != nil {
		close(s.openEntered)
		<-s.openProceed
	}
	if s.afterApply != nil {
		s.afterApply()
	}
	return handle, nil
}
func (s *applicationOpenStore) IdentityOpen(handle xfsstore.Capability) ([16]byte, error) {
	s.mu.Lock()
	item, ok := s.handles[handle]
	s.mu.Unlock()
	if !ok {
		return [16]byte{}, syscall.EBADF
	}
	return [16]byte{item[0]}, nil
}
func (s *applicationOpenStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	i, err := s.IdentityOpen(handle)
	if err != nil {
		return xfsstore.Attr{}, err
	}
	return s.Getattr(xfsstore.Capability{i[0]})
}
func (s *applicationOpenStore) CloseOpen(handle xfsstore.Capability) error {
	s.mu.Lock()
	delete(s.handles, handle)
	s.mu.Unlock()
	s.closes.Add(1)
	return nil
}
func (s *applicationOpenStore) ReadAt(xfsstore.Capability, []byte, int64) (int, error) {
	if s.readEntered != nil {
		close(s.readEntered)
		<-s.readProceed
	}
	return 0, io.EOF
}

func applicationHarness(t *testing.T, store *applicationOpenStore) (*VolumeHandler, context.Context, volumeserver.SessionCredential, xfsstore.Capability, *applicationClock) {
	t.Helper()
	store.handles = make(map[xfsstore.Capability]xfsstore.Capability)
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 16, 16)
	clock := newApplicationClock()
	// Replace the otherwise unused fixture coordinator before any filesystem
	// work, then cold-subscribe the source into the frozen-clock coordinator.
	h.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: clock})
	if r := h.handleCoherenceSubscribe(0, cred.ID, &authoritypb.SubscribeRequest{}); r.GetErrno() != 0 {
		t.Fatal(r)
	}
	if err := h.trackItem(cred.ID, xfsstore.Capability{0x22}, false); err != nil {
		t.Fatal(err)
	}
	return h, ctx, cred, root, clock
}
func applicationRequest(cred volumeserver.SessionCredential, root xfsstore.Capability, kind string, truncate bool) *authoritypb.Request {
	r := coherenceReadRequest(cred)
	r.Mutation = &authoritypb.Mutation{Sequence: 1}
	flags := &authoritypb.OpenFlags{Read: true, Write: true, Truncate: truncate}
	if kind == "open" {
		item := xfsstore.Capability{0x22}
		r.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: item[:], Flags: flags, WriteIntent: true}}
	} else {
		r.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: root[:], Name: []byte("file"), Mode: 0600, Flags: flags, WriteIntent: true}}
	}
	return r
}
func applicationGrant(r *authoritypb.Response) *authoritypb.Delegation {
	if r.GetOpen() != nil {
		return r.GetOpen().GetDelegation()
	}
	return r.GetCreate().GetDelegation()
}
func applicationPeer(t *testing.T, h *VolumeHandler, store *applicationOpenStore, root xfsstore.Capability) (volumeserver.SubscriptionToken, xfsstore.Capability) {
	t.Helper()
	id := volumeserver.SessionID{0xee}
	if err := h.startSessionResources(id, root, 2, routesRevisionOf("")); err != nil {
		t.Fatal(err)
	}
	token, err := h.coherenceToken(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Coherence.AdmitCache(token, volumeserver.CacheAdmission{Data: [][16]byte{{0x22}}}); err != nil {
		t.Fatal(err)
	}
	handle := xfsstore.Capability{0x55}
	store.mu.Lock()
	store.handles[handle] = xfsstore.Capability{0x22}
	store.mu.Unlock()
	if err := h.trackOpen(id, handle, false); err != nil {
		t.Fatal(err)
	}
	return token, handle
}
func applicationEvents(t *testing.T, h *VolumeHandler, token volumeserver.SubscriptionToken) []volumeserver.StreamEvent {
	t.Helper()
	type result struct {
		events []volumeserver.StreamEvent
		err    error
	}
	ch := make(chan result, 1)
	state := h.initCoherenceControlState()
	state.mu.Lock()
	after := state.sessions[token.Session].coordinatorCursor
	state.mu.Unlock()
	go func() {
		events, err := h.Coherence.Poll(t.Context(), token, after, nil, 128)
		ch <- result{events, err}
	}()
	r := admissionReceive(t, ch)
	if r.err != nil || len(r.events) == 0 {
		t.Fatalf("events=%v err=%v", r.events, r.err)
	}
	return r.events
}
func applicationControlEvent(t *testing.T, h *VolumeHandler, token volumeserver.SubscriptionToken, kind volumeserver.StreamEventKind) volumeserver.StreamEvent {
	t.Helper()
	ch := make(chan volumeserver.StreamEvent, 1)
	go func() {
		var after uint64
		for {
			events, err := h.Coherence.Poll(t.Context(), token, after, nil, 128)
			if err != nil {
				return
			}
			for _, e := range events {
				if e.Kind == kind {
					ch <- e
					return
				}
				after = e.Position
			}
		}
	}()
	return admissionReceive(t, ch)
}

func applicationBalanced(t *testing.T, h *VolumeHandler, id volumeserver.SessionID) {
	t.Helper()
	h.resourcesMu.Lock()
	r := h.resources[id]
	items, opens := r.reservedItems, r.reservedOpens
	h.resourcesMu.Unlock()
	if items != 0 || opens != 0 || h.Coherence.Stats().DelegationCapacityReservations != 0 {
		t.Fatal("allocation retained a capacity reservation")
	}
}

func TestCoherencePublicOpenCreateApplicationPrecedesWithdrawal(t *testing.T) {
	for _, kind := range []string{"open", "create"} {
		for _, size := range []int64{0, 7} {
			name := kind + "/empty"
			if size != 0 {
				name = kind + "/nonempty"
			}
			t.Run(name, func(t *testing.T) {
				store := &applicationOpenStore{exists: true, size: size, openEntered: make(chan struct{}), openProceed: make(chan struct{}), readEntered: make(chan struct{}), readProceed: make(chan struct{})}
				h, ctx, cred, root, _ := applicationHarness(t, store)
				token, _ := h.coherenceToken(cred.ID)
				grant, err := h.Coherence.DataMutated(ctx, token, [16]byte{0x22})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.Coherence.DataMutated(ctx, token, [16]byte{0x24}); err != nil {
					t.Fatal(err)
				}
				peer, handle := applicationPeer(t, h, store, root)
				req := applicationRequest(cred, root, kind, true)
				done := make(chan *authoritypb.Response, 1)
				go func() { done <- h.Handle(ctx, req) }()
				admissionReceive(t, store.openEntered)
				read := make(chan *authoritypb.Response, 1)
				go func() {
					read <- h.coherenceReadData(t.Context(), 90, peer.Session, &authoritypb.ReadRequest{Handle: handle[:], Length: 1})
				}()
				cut := applicationControlEvent(t, h, token, volumeserver.StreamBreakForRead)
				if cut.Request == 0 || cut.AppliedSequence != 0 {
					t.Fatal("clean held grant did not receive an empty-floor break")
				}
				close(store.openProceed)
				reply := admissionReceive(t, done)
				if reply.GetErrno() != 0 || reply.GetAppliedSequence() != 1 || reply.GetAppliedSequence() == reply.GetVolumeVersion() || reply.GetVisibleSequence() != 0 || !proto.Equal(applicationGrant(reply), coherenceDelegationProto(grant)) {
					t.Fatalf("application receipt=%v", reply)
				}
				if _, durable := h.latestCoherenceDurability(cred.ID); durable != 0 {
					t.Fatal("application receipt manufactured durability")
				}
				replay := h.Handle(ctx, req)
				if !proto.Equal(reply, replay) || store.truncates.Load() != 1 || store.open.Load() != 1 {
					t.Fatal("replay changed the allocation, grant, ticket or apply count")
				}
				// A later session ticket on another identity must not satisfy this
				// pending cut, even though it exceeds the truncation's ticket.
				store.openEntered, store.openProceed = nil, nil
				if err := h.trackItem(cred.ID, xfsstore.Capability{0x24}, false); err != nil {
					t.Fatal(err)
				}
				other := applicationRequest(cred, root, "open", true)
				other.RequestId++
				other.Mutation.Slot = 1
				other.GetOpen().Item[0] = 0x24
				otherReply := h.Handle(ctx, other)
				if otherReply.GetErrno() != 0 || otherReply.GetAppliedSequence() != 2 {
					t.Fatal(otherReply)
				}
				if err := h.Coherence.AckDelegation(token, grant.Identity, grant.ID, grant.Generation, cut.Request, 2); !errors.Is(err, volumeserver.ErrDelegationAck) {
					t.Fatalf("foreign application accepted: %v", err)
				}
				if err := h.Coherence.AckDelegation(token, grant.Identity, grant.ID, grant.Generation, cut.Request, reply.GetAppliedSequence()); err != nil {
					t.Fatal(err)
				}
				admissionReceive(t, store.readEntered)
				if h.coherenceDurability.latestVisible(cred.ID) != 0 {
					t.Fatal("visibility crossed the read publication drain")
				}
				visible := make(chan *authoritypb.Response, 1)
				go func() {
					visible <- h.handleCoherenceVisibility(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: 2}}}, cred)
				}()
				close(store.readProceed)
				if r := admissionReceive(t, read); r.GetErrno() != 0 || len(r.GetRead().GetData()) != 0 {
					t.Fatal(r)
				}
				events := applicationEvents(t, h, peer)
				if err := h.Coherence.Ack(peer, events[len(events)-1].Position); err != nil {
					t.Fatal(err)
				}
				if r := admissionReceive(t, visible); r.GetErrno() != 0 || r.GetVisibleSequence() != 2 {
					t.Fatal(r)
				}
				if h.Coherence.LossSequence(cred.ID) != 0 {
					t.Fatal("healthy receipt produced delegation loss")
				}

				// DATA can be delivered after CONTROL has retired this grant.
				// Exact replay retains the original receipt without reinstalling
				// its generation or allowing it to flush a successor.
				recalled := make(chan error, 1)
				go func() { recalled <- h.Coherence.Recall(t.Context(), grant.Identity) }()
				recall := applicationControlEvent(t, h, token, volumeserver.StreamRecall)
				if err := h.Coherence.AckDelegation(token, grant.Identity, grant.ID, grant.Generation, recall.Request, reply.GetAppliedSequence()); err != nil {
					t.Fatal(err)
				}
				if err := admissionReceive(t, recalled); err != nil {
					t.Fatal(err)
				}
				if delayed := h.Handle(ctx, req); !proto.Equal(delayed, reply) {
					t.Fatal("retirement changed delayed DATA replay")
				}
				if _, ok := h.Coherence.LookupDelegation(grant.Identity); ok {
					t.Fatal("delayed DATA resurrected a retired grant")
				}
				reservation, err := h.Coherence.Reserve(t.Context(), token, grant.Identity)
				if err != nil {
					t.Fatal(err)
				}
				peerEvents, err := h.Coherence.Poll(t.Context(), peer, events[len(events)-1].Position, nil, 128)
				if err != nil || len(peerEvents) == 0 {
					t.Fatalf("successor withdrawal=%v %v", peerEvents, err)
				}
				if err := h.Coherence.Ack(peer, peerEvents[len(peerEvents)-1].Position); err != nil {
					t.Fatal(err)
				}
				successor, err := reservation.Grant(t.Context())
				if err != nil || successor.Generation == grant.Generation {
					t.Fatalf("successor=%v %v", successor, err)
				}
				if _, err := h.Coherence.BeginFlush(token, grant.Identity, grant.ID, grant.Generation); !errors.Is(err, volumeserver.ErrDelegationStale) {
					t.Fatalf("old generation flushed successor: %v", err)
				}
				if current, ok := h.Coherence.LookupDelegation(grant.Identity); !ok || current.Generation != successor.Generation {
					t.Fatal("stale flush changed successor")
				}
				applicationBalanced(t, h, cred.ID)
			})
		}
	}
}

func TestCoherencePrivateOpenCreateJoinsReadWithdrawal(t *testing.T) {
	for _, kind := range []string{"open", "create"} {
		t.Run(kind, func(t *testing.T) {
			store := &applicationOpenStore{exists: true, size: 7, openEntered: make(chan struct{}), openProceed: make(chan struct{}), readEntered: make(chan struct{}), readProceed: make(chan struct{})}
			h, ctx, cred, root, clock := applicationHarness(t, store)
			req := applicationRequest(cred, root, kind, true)
			done := make(chan *authoritypb.Response, 1)
			go func() { done <- h.Handle(ctx, req) }()
			admissionReceive(t, store.openEntered)
			selected, ok := h.Coherence.LookupDelegation([16]byte{0x22})
			if !ok || selected.State != volumeserver.DelegationActive {
				t.Fatal("no active private generation at storage apply")
			}
			peer, handle := applicationPeer(t, h, store, root)
			gap := &applicationCutContext{Context: t.Context(), entered: make(chan struct{}), proceed: make(chan struct{})}
			read := make(chan *authoritypb.Response, 1)
			go func() {
				read <- h.coherenceReadData(gap, 90, peer.Session, &authoritypb.ReadRequest{Handle: handle[:], Length: 1})
			}()
			admissionReceive(t, gap.entered)
			close(store.openProceed)
			admissionReceive(t, clock.timers) // WaitTargeted, after promotion and End(ticket).
			reserved, ok := h.Coherence.LookupDelegation([16]byte{0x22})
			if !ok || reserved.Generation != selected.Generation || reserved.State != volumeserver.DelegationReserved {
				t.Fatal("private grant did not remain reserved during withdrawal")
			}
			close(gap.proceed)
			admissionReceive(t, store.readEntered)
			stats := h.Coherence.Stats()
			if stats.BreakCompleted != 0 || stats.BreakLost != 0 || stats.DelegationsRecalling != 0 || h.coherenceDurability.latestVisible(cred.ID) != 0 {
				t.Fatal("reserved read needed holder CONTROL or became visible early")
			}
			select {
			case r := <-done:
				t.Fatalf("allocating DATA passed read withdrawal: %v", r)
			default:
			}
			close(store.readProceed)
			if r := admissionReceive(t, read); r.GetErrno() != 0 {
				t.Fatal(r)
			}
			events := applicationEvents(t, h, peer)
			for _, e := range events {
				if e.Kind == volumeserver.StreamBreakForRead || e.Kind == volumeserver.StreamRecall {
					t.Fatal("CONTROL issued against reserved generation")
				}
			}
			if err := h.Coherence.Ack(peer, events[len(events)-1].Position); err != nil {
				t.Fatal(err)
			}
			reply := admissionReceive(t, done)
			if reply.GetErrno() != 0 || reply.GetAppliedSequence() != 1 || reply.GetVisibleSequence() != 1 || applicationGrant(reply).GetGeneration() != selected.Generation {
				t.Fatal(reply)
			}
			if h.Coherence.LossSequence(cred.ID) != 0 {
				t.Fatal("private dependency join lost data")
			}
			applicationBalanced(t, h, cred.ID)
		})
	}
}

func TestCoherenceOpenCreateApplicationBoundaries(t *testing.T) {
	for _, kind := range []string{"open", "create"} {
		for _, boundary := range []string{"nontruncating", "pre-apply refusal", "post-apply failure", "cancel after apply", "cold source after apply", "new name", "new name truncate", "exclusive existing"} {
			if kind == "open" && (boundary == "new name" || boundary == "new name truncate" || boundary == "exclusive existing") {
				continue
			}
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				store := &applicationOpenStore{exists: boundary != "new name" && boundary != "new name truncate", size: 7}
				h, ctx, cred, root, _ := applicationHarness(t, store)
				if !store.exists {
					store.size = 0
				}
				req := applicationRequest(cred, root, kind, boundary != "nontruncating" && boundary != "new name")
				wantErr, wantApplied := int32(0), uint64(1)
				wantUncertain := false
				switch boundary {
				case "nontruncating", "new name", "new name truncate":
					wantApplied = 0
				case "exclusive existing":
					req.GetCreate().Exclusive = true
					wantErr = int32(syscall.EEXIST)
					wantApplied = 0
				case "pre-apply refusal":
					store.preError = syscall.EACCES
					wantErr = int32(syscall.EACCES)
					wantApplied = 0
				case "post-apply failure":
					store.postError = syscall.EIO
					wantErr = int32(syscall.EIO)
					wantUncertain = true
					wantApplied = 0
				case "cancel after apply":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					defer cancel()
					store.afterApply = cancel
				case "cold source after apply":
					store.afterApply = func() {
						if _, err := h.Coherence.Subscribe(cred.ID); err != nil {
							t.Error(err)
						}
					}
					wantErr = int32(syscall.EIO)
					wantUncertain = true
					wantApplied = 0
				}
				reply := h.Handle(ctx, req)
				if reply.GetErrno() != wantErr || reply.GetUncertain() != wantUncertain || reply.GetAppliedSequence() != wantApplied {
					t.Fatalf("boundary receipt=%v, want errno=%d uncertain=%v ticket=%d", reply, wantErr, wantUncertain, wantApplied)
				}
				if wantErr == 0 && applicationGrant(reply) == nil {
					t.Fatal("successful allocation lost its grant")
				}
				if wantErr != 0 && applicationGrant(reply) != nil {
					t.Fatal("failed allocation invented a successful grant")
				}
				if boundary == "post-apply failure" && (reply.GetVolumeVersion() <= 1 || store.closes.Load() != 1) {
					t.Fatal("post-apply failure lost its commit or handle cleanup")
				}
				if boundary == "cold source after apply" && store.closes.Load() != 1 {
					t.Fatal("cold replacement leaked the real allocated handle")
				}
				if boundary == "pre-apply refusal" || boundary == "exclusive existing" {
					if store.truncates.Load() != 0 || reply.GetVolumeVersion() != 1 {
						t.Fatal("definite refusal applied data")
					}
				}
				h.resourcesMu.Lock()
				retainedOpens := len(h.resources[cred.ID].opens)
				h.resourcesMu.Unlock()
				wantOpens := 0
				if wantErr == 0 {
					wantOpens = 1
				}
				if retainedOpens != wantOpens {
					t.Fatalf("retained open capabilities=%d, want %d", retainedOpens, wantOpens)
				}
				if boundary != "cold source after apply" {
					replay := h.Handle(context.WithoutCancel(ctx), req)
					if !proto.Equal(reply, replay) {
						t.Fatalf("boundary replay changed: %v / %v", reply, replay)
					}
				}
				applicationBalanced(t, h, cred.ID)
			})
		}
	}
}

// The FUSE receipt oracle lives in P3. This authority counterpart exercises
// both allocating handlers against the provisioned real XFS project.
func TestCoherenceTruncatingOpenCreateApplicationOnXFS(t *testing.T) {
	for _, kind := range []string{"open", "create"} {
		t.Run(kind, func(t *testing.T) {
			f := newTopologyHandlerFixture(t)
			proof, _, file := f.subscribedFile(t)
			written := f.flush(t, proof, file)
			id := topologySession(proof)
			f.h.resourcesMu.Lock()
			root := f.h.resources[id].root
			f.h.resourcesMu.Unlock()
			var cred volumeserver.SessionCredential
			copy(cred.ID[:], proof.GetId())
			cred.Generation = proof.GetGeneration()
			copy(cred.Epoch[:], f.epoch)
			req := applicationRequest(cred, root, kind, true)
			req.Epoch, req.Session, req.Mutation.Sequence = f.epoch, proof, 2
			if kind == "open" {
				req.GetOpen().Item = file.GetItem().GetToken()
			} else {
				req.GetCreate().Name = []byte("dirty")
			}
			reply := f.require(t, f.ctx, req)
			if reply.GetAppliedSequence() != written.GetAppliedSequence()+1 || !proto.Equal(applicationGrant(reply), file.GetDelegation()) {
				t.Fatalf("real XFS allocation omitted the exact grant application: %v", reply)
			}
			var handle xfsstore.Capability
			if kind == "open" {
				copy(handle[:], reply.GetOpen().GetHandle())
			} else {
				copy(handle[:], reply.GetCreate().GetHandle())
			}
			attr, err := f.h.Store.GetattrOpen(handle)
			if err != nil || attr.Size != 0 {
				t.Fatalf("truncate attr=%+v err=%v", attr, err)
			}
			if replay := f.require(t, f.ctx, req); !proto.Equal(reply, replay) {
				t.Fatal("real XFS replay changed the allocating receipt")
			}
			applicationBalanced(t, f.h, id)
		})
	}
}
