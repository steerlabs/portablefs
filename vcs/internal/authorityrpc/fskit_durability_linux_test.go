//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

type durabilityTestTarget struct{ sync func() error }

func (s durabilityTestTarget) Sync() error  { return s.sync() }
func (s durabilityTestTarget) Close() error { return nil }

type fskitDurabilityTestStore struct {
	writeTestStore
	acquireErr error
	syncErr    error
	syncs      atomic.Int32
	fenced     atomic.Bool
	fenceCause atomic.Pointer[xfsstore.DurabilityError]
	barrier    func()
	locked     atomic.Bool
}

func (s *fskitDurabilityTestStore) Fence(err error) {
	var cause *xfsstore.DurabilityError
	if errors.As(err, &cause) {
		s.fenceCause.Store(cause)
	}
	s.fenced.Store(true)
}
func (s *fskitDurabilityTestStore) LockMutation([][16]byte) func() {
	s.locked.Store(true)
	return func() { s.locked.Store(false) }
}
func (s *fskitDurabilityTestStore) PinSyncHandle(xfsstore.Capability) (xfsstore.SyncTarget, error) {
	if s.acquireErr != nil {
		return nil, s.acquireErr
	}
	return durabilityTestTarget{sync: s.doSync}, nil
}

func (s *fskitDurabilityTestStore) SyncFS() error { return s.doSync() }
func (s *fskitDurabilityTestStore) doSync() error {
	if s.locked.Load() {
		panic("durability sync under mutation lock")
	}
	s.syncs.Add(1)
	if s.barrier != nil {
		s.barrier()
	}
	return s.syncErr
}

func newDirectFskitHarness(t *testing.T) (*VolumeHandler, volumeserver.SessionCredential, *fskitDurabilityTestStore, *writeTestTarget) {
	h, cred, _, _ := newFskitWriteHarness(t)
	store := &fskitDurabilityTestStore{}
	target := &writeTestTarget{coordinate: xfsstore.ObjectCoordinate{Stable: [16]byte{0x41}, Ino: 0x41, DeviceMinor: 1}, committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x41, Size: 4, Mode: 0600, Nlink: 1, DeviceMinor: 1}}
	target.sync = store.doSync
	store.targets = []*writeTestTarget{target}
	h.Store = store
	h.Routes = &RoutesController{Mounts: h.Lifecycle, Locks: h.Runtime.Locks(), loaded: true}
	metrics, err := authoritymetrics.New("fskit-durable")
	if err != nil {
		t.Fatal(err)
	}
	h.Metrics = metrics
	return h, cred, store, target
}
func directFskitRequest() *authoritypb.Request {
	req := stockWriteTestRequest(1, 0, 1, xfsstore.Capability{0x41}, []byte("data"), 0, writeKillSUIDGID)
	req.GetWrite().WriteFlags = writeKillSUIDGID
	return req
}

func TestFskitDirectWriteDurabilityAndExactReplay(t *testing.T) {
	for _, test := range []struct {
		name                string
		committed           uint64
		applyErr, errorSync error
		terminal            bool
	}{
		{name: "success", committed: 4}, {name: "short", committed: 2},
		{name: "zero postapply", applyErr: fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.EACCES)},
		{name: "postapply", committed: 4, applyErr: fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.EACCES)},
		{name: "EIO", committed: 4, errorSync: syscall.EIO, terminal: true},
		{name: "ENOSPC", committed: 4, errorSync: syscall.ENOSPC, terminal: true},
		{name: "EDQUOT", committed: 4, errorSync: syscall.EDQUOT, terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, cred, store, target := newDirectFskitHarness(t)
			var observations []MutationObservation
			h.OnMutation = func(o MutationObservation) { observations = append(observations, o) }
			target.committed = test.committed
			target.err = test.applyErr
			store.syncErr = test.errorSync
			req := directFskitRequest()
			ctx := context.WithValue(t.Context(), coherenceOperationKey{}, &coherenceOperation{})
			response := h.handleWrite(ctx, req, cred, req.GetWrite())
			if response.GetErrno() != 0 || response.GetWrite() == nil || response.GetWrite().GetCommittedSize() != test.committed || response.GetWrite().GetAssignedOffset() != 0 || response.GetPostState() == nil {
				t.Fatalf("WRITE=%v", response)
			}
			if response.GetAppliedSequence() != 0 || response.GetWrite().GetDurableSequence() != 0 {
				t.Fatalf("FSKit fabricated Linux tickets: %v", response)
			}
			if test.applyErr == nil && !test.terminal && response.GetWrite().GetError() != 0 {
				t.Fatalf("successful WRITE carried post-apply failure: %v", response)
			}
			if test.terminal {
				if response.GetWrite().GetError() != -int32(syscall.EIO) || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || !store.fenced.Load() {
					t.Fatalf("sync failure=%v fenced=%v", response, store.fenced.Load())
				}
				if !terminalReceiptCarriesExactAppliedState(response) {
					t.Fatal("exact terminal write cannot be receipted")
				}
			}
			req.RequestId++
			replayed := h.handleWrite(ctx, req, cred, req.GetWrite())
			response.RequestId = replayed.RequestId
			if !proto.Equal(response, replayed) {
				t.Fatalf("replay changed outcome: %v / %v", response, replayed)
			}
			if calls, _ := target.directSnapshot(); calls != 1 || store.syncs.Load() != 1 {
				t.Fatalf("apply/sync=%d/%d", calls, store.syncs.Load())
			}
			if len(observations) != 2 || observations[0].Disposition != "executed" || observations[1].Disposition != "replayed" || observations[0].Sequence != observations[1].Sequence || observations[0].Session != cred.ID {
				t.Fatalf("mutation trace lost exact replay identity: %v", observations)
			}
			if observations[0].StorageWait <= 0 || observations[0].ApplyDuration <= 0 || observations[0].DurabilityKind != "handle" || observations[0].DurabilityWait <= 0 || observations[1].DurabilityWait != 0 {
				t.Fatalf("trace lost direct durability timing or charged replay: %v", observations)
			}

		})
	}
}

func TestFskitDirectWriteRefusalsBeforeApply(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*authoritypb.Request)
	}{
		{"append", func(r *authoritypb.Request) { r.GetWrite().Append = true }},
		{"sync", func(r *authoritypb.Request) { r.GetWrite().Sync = true }},
		{"data sync", func(r *authoritypb.Request) { r.GetWrite().DataSync = true }},
		{"delegation", func(r *authoritypb.Request) { r.GetWrite().Delegation = &authoritypb.DelegationRef{} }},
		{"flush sequence", func(r *authoritypb.Request) { r.GetWrite().FlushSequence = 1 }},
		{"lock flag", func(r *authoritypb.Request) { r.GetWrite().WriteFlags |= writeLockOwner }},
		{"lock owner", func(r *authoritypb.Request) { r.GetWrite().LockOwner = 1 }},
		{"bad size", func(r *authoritypb.Request) { r.GetWrite().Size = 1 }},
		{"bad flags", func(r *authoritypb.Request) { r.GetWrite().WriteFlags = 0x80000000 }},
		{"cross session handle", func(r *authoritypb.Request) { r.GetWrite().Handle = bytes.Repeat([]byte{9}, 16) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, cred, store, target := newDirectFskitHarness(t)
			req := directFskitRequest()
			if test.name == "cross session handle" {
				other, err := h.Runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{2}, volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				if err := h.startSessionResourcesForProfile(other.ID, xfsstore.Capability{0x70}, 2, [32]byte{}, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { h.closeSessionResources(other.ID) })
				var foreign xfsstore.Capability
				copy(foreign[:], bytes.Repeat([]byte{9}, 16))
				if err := h.trackOpen(other.ID, foreign, false); err != nil {
					t.Fatal(err)
				}
				if _, err := h.open(other.ID, foreign[:]); err != nil {
					t.Fatal(err)
				}
			}
			test.change(req)
			req.Epoch = cred.Epoch[:]
			req.Session = &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}
			ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1})
			result := h.Handle(ctx, req)
			if result.GetErrno() == 0 || result.GetUncertain() || result.GetMutation() == nil {
				t.Fatalf("refusal=%v", result)
			}
			if calls, _ := target.directSnapshot(); calls != 0 || store.syncs.Load() != 0 {
				t.Fatal("refusal applied or synced")
			}
		})
	}
}

func TestFskitUnadmittedWriteENOMEMShape(t *testing.T) {
	h, cred, store, target := newDirectFskitHarness(t)
	h.MaxRetainedReplyBytes = 1
	req := directFskitRequest()
	result := h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if result.GetErrno() != 0 || result.GetUncertain() || result.GetSessionTerminal() || result.GetMutation() != nil || result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED || result.GetWrite().GetError() != -int32(syscall.ENOMEM) || result.GetWrite().GetPostAttr() != nil || result.GetPostState() != nil || result.GetWrite().GetCommittedSize() != 0 {
		t.Fatalf("unadmitted WRITE=%v", result)
	}
	if calls, _ := target.directSnapshot(); calls != 0 || store.syncs.Load() != 0 {
		t.Fatal("unadmitted WRITE acquired resources")
	}
	h.MaxRetainedReplyBytes = 1 << 20
	if result := h.handleWrite(t.Context(), req, cred, req.GetWrite()); result.GetWrite().GetCommittedSize() != 4 {
		t.Fatalf("same identity retry=%v", result)
	}
}

func TestFskitReplayWaitsForDurabilityDespiteCancellation(t *testing.T) {
	h, cred, store, target := newDirectFskitHarness(t)
	entered, release := make(chan struct{}), make(chan struct{})
	store.barrier = func() { close(entered); <-release }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := directFskitRequest()
	first := make(chan *authoritypb.Response, 1)
	go func() { first <- h.handleWrite(ctx, req, cred, req.GetWrite()) }()
	<-entered
	cancel()
	replay := proto.Clone(req).(*authoritypb.Request)
	replay.RequestId++
	second := make(chan *authoritypb.Response, 1)
	go func() { second <- h.handleWrite(t.Context(), replay, cred, replay.GetWrite()) }()
	select {
	case r := <-first:
		t.Fatalf("canceled apply skipped durability: %v", r)
	case r := <-second:
		t.Fatalf("replay skipped durability: %v", r)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	for _, ch := range []chan *authoritypb.Response{first, second} {
		r := <-ch
		if r.GetWrite().GetCommittedSize() != 4 || r.GetWrite().GetPostAttr() == nil {
			t.Fatalf("durable completion=%v", r)
		}
	}
	if calls, _ := target.directSnapshot(); calls != 1 || store.syncs.Load() != 1 {
		t.Fatalf("apply/sync=%d/%d", calls, store.syncs.Load())
	}
}

func TestFskitNonWriteDurabilityFailureIsUncertainStorage(t *testing.T) {
	for _, failure := range []error{syscall.EIO, syscall.ENOSPC, syscall.EDQUOT} {
		t.Run(failure.Error(), func(t *testing.T) {
			h, cred, store, _ := newDirectFskitHarness(t)
			store.syncErr = failure
			item := xfsstore.Capability{0x70}
			identity := [16]byte{0x70}
			req := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item[:], Mode: proto.Uint32(0600)}}}
			stampMutation(t, req, 0, 1)
			result := h.mutateVisibleSequence(t.Context(), req, cred, func() ([]volumeserver.MutationTarget, error) {
				return []volumeserver.MutationTarget{inodeTarget(volumeserver.MutationAttributes, mutationCoordinate{identity: identity, ino: 0x70, device: 1}, 0)}, nil
			}, func(sequence uint64, changed *mutationChanges) (*authoritypb.Response, []volumeserver.MutationTarget) {
				r := h.success(0)
				r.PostState = h.mutationPostState(changed, sequence, postStateSnapshot{identity: identity, attr: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x70, Mode: 0600}, roles: postStateRoleTarget, changed: true})
				return r, []volumeserver.MutationTarget{}
			}, nil)
			if result.GetErrno() != int32(syscall.EIO) || !result.GetUncertain() || result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || !store.fenced.Load() {
				t.Fatalf("sync failure=%v", result)
			}
			if typed := store.fenceCause.Load(); typed == nil || !errors.Is(typed.Cause, failure) {
				t.Fatalf("fence lost durability cause: %v", typed)
			}
		})
	}
}

type fragmentedDurabilityFailureStore struct {
	*fskitWriteTestStore
	fences atomic.Int32
}

func (s *fragmentedDurabilityFailureStore) Fence(error) { s.fences.Add(1) }
func (s *fragmentedDurabilityFailureStore) PinSyncHandle(xfsstore.Capability) (xfsstore.SyncTarget, error) {
	panic("fragmented COMMIT reacquired its handle")
}

type partialSetAttrStore struct {
	*fskitDurabilityTestStore
	applies  int
	post     xfsstore.Attr
	applyErr error
}

func (s *partialSetAttrStore) SetAttr(_, _ xfsstore.Capability, _ xfsstore.SetAttrSpec) (xfsstore.Attr, error) {
	s.applies++
	return s.post, s.applyErr
}
func (s *partialSetAttrStore) Getattr(xfsstore.Capability) (xfsstore.Attr, error) { return s.post, nil }

func TestSetAttrPartialApplyRetainsPostStateAndDurabilityOnReplay(t *testing.T) {
	h, cred, store, _ := newDirectFskitHarness(t)
	partial := &partialSetAttrStore{fskitDurabilityTestStore: store, applyErr: errors.Join(xfsstore.ErrOutcomeUncertain, syscall.ENOSPC), post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x70, Mode: 0600, Size: 2, DeviceMinor: 1}}
	h.Store = partial
	item := xfsstore.Capability{0x70}
	req := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}, Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item[:], Mode: proto.Uint32(0600), Size: proto.Int64(2)}}}
	stampMutation(t, req, 0, 1)
	ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1})
	reply := h.Handle(ctx, req)
	if !reply.GetUncertain() || reply.GetPostState() == nil || reply.GetMutation() == nil || partial.applies != 1 || store.syncs.Load() != 1 {
		t.Fatalf("partial SETATTR = %v; apply/sync=%d/%d", reply, partial.applies, store.syncs.Load())
	}
	req.RequestId++
	replay := h.Handle(ctx, req)
	reply.RequestId = replay.RequestId
	if !proto.Equal(reply, replay) || partial.applies != 1 || store.syncs.Load() != 1 {
		t.Fatalf("partial SETATTR replay changed outcome or repeated work: %v", replay)
	}
}

// Descriptor acquisition is distinct from the persistence syscall. A failure
// before apply is definite; after CREATE or O_TRUNC it is a terminal defect.
type fskitAcquisitionStore struct {
	*fskitDurabilityTestStore
	parentErr error
	openErr   error
	applies   int
}

func (s *fskitAcquisitionStore) Create(xfsstore.Capability, string, os.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.applies++
	return xfsstore.Capability{0x42}, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x42, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *fskitAcquisitionStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.applies++
	if s.openErr != nil {
		return xfsstore.Capability{}, s.openErr
	}
	return xfsstore.Capability{0x42}, nil
}
func (s *fskitAcquisitionStore) SetAttr(xfsstore.Capability, xfsstore.Capability, xfsstore.SetAttrSpec) (xfsstore.Attr, error) {
	s.applies++
	return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x41, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *fskitAcquisitionStore) Getattr(cap xfsstore.Capability) (xfsstore.Attr, error) {
	if cap == (xfsstore.Capability{0x70}) && s.applies >= 2 && s.parentErr != nil {
		return xfsstore.Attr{}, s.parentErr
	}
	return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(cap[0]), Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *fskitAcquisitionStore) GetattrOpen(cap xfsstore.Capability) (xfsstore.Attr, error) {
	return s.Getattr(cap)
}

func TestFskitDescriptorAcquisitionNeverSelectsAnotherBarrier(t *testing.T) {
	for _, kind := range []string{"create pin", "truncate pin", "setattr pin"} {
		for _, cause := range []error{xfsstore.ErrStaleOpen} {
			t.Run(kind+"/"+cause.Error(), func(t *testing.T) {
				h, cred, base, _ := newDirectFskitHarness(t)
				store := &fskitAcquisitionStore{fskitDurabilityTestStore: base}
				base.acquireErr = cause
				h.Store = store
				parent, item, handle := xfsstore.Capability{0x70}, xfsstore.Capability{0x42}, xfsstore.Capability{0x41}
				if err := h.trackItem(cred.ID, item, false); err != nil {
					t.Fatal(err)
				}
				req := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}}
				switch kind {
				case "create pin":
					req.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent[:], Name: []byte("new"), Mode: 0600, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}
				case "truncate pin":
					req.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: item[:], Flags: &authoritypb.OpenFlags{Write: true, Truncate: true}}}
				case "setattr pin":
					req.Body = &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Handle: handle[:], Mode: proto.Uint32(0600)}}
				}
				stampMutation(t, req, 0, 1)
				reply := h.Handle(context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1}), req)
				if reply.GetErrno() == 0 || base.syncs.Load() != 0 {
					t.Fatalf("alternate durability success: %v syncs=%d", reply, base.syncs.Load())
				}
				if kind == "setattr pin" {
					if reply.GetUncertain() || base.fenced.Load() || store.applies != 0 {
						t.Fatalf("pre-apply refusal=%v applied=%d", reply, store.applies)
					}
				} else if !reply.GetUncertain() || reply.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || !base.fenced.Load() {
					t.Fatalf("post-apply acquisition was not terminal: %v", reply)
				}
				before := store.applies
				req.RequestId++
				replay := h.Handle(context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1}), req)
				reply.RequestId = replay.RequestId
				if !proto.Equal(reply, replay) || store.applies != before || base.syncs.Load() != 0 {
					t.Fatalf("acquisition replay changed outcome: %v / %v", reply, replay)
				}
			})
		}
	}
}

func TestFskitExistingCreateDoesNotAcquireDurabilityPin(t *testing.T) {
	h, cred, base, _ := newDirectFskitHarness(t)
	base.acquireErr = xfsstore.ErrStaleOpen
	base.lookupItem = xfsstore.Capability{0x42}
	store := &fskitAcquisitionStore{fskitDurabilityTestStore: base}
	h.Store = store
	parent := xfsstore.Capability{0x70}
	req := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent[:], Name: []byte("existing"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}
	stampMutation(t, req, 0, 1)
	reply := h.Handle(context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1}), req)
	if reply.GetErrno() != 0 || reply.GetUncertain() || base.fenced.Load() || base.syncs.Load() != 0 {
		t.Fatalf("nonmutating CREATE acquired durability: %v", reply)
	}
}

func TestFskitExistingCreateRawEIOIsUncertain(t *testing.T) {
	h, cred, base, _ := newDirectFskitHarness(t)
	base.lookupItem = xfsstore.Capability{0x42}
	store := &fskitAcquisitionStore{fskitDurabilityTestStore: base, openErr: syscall.EIO}
	h.Store = store
	parent := xfsstore.Capability{0x70}
	request := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent[:], Name: []byte("existing"), Mode: 0600, Flags: &authoritypb.OpenFlags{Write: true, Truncate: true}}}}
	stampMutation(t, request, 0, 1)
	ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1})
	response := h.Handle(ctx, request)
	if response.GetErrno() != int32(syscall.EIO) || !response.GetUncertain() || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || !base.fenced.Load() {
		t.Fatalf("raw reopen EIO was treated as definite: %v", response)
	}
	before := store.applies
	request.RequestId++
	replay := h.Handle(ctx, request)
	response.RequestId = replay.RequestId
	if !proto.Equal(response, replay) || store.applies != before {
		t.Fatalf("reopen EIO was reapplied: %v", replay)
	}
}

func TestFskitDirectWriteDoesNotReacquireHandle(t *testing.T) {
	h, cred, store, _ := newDirectFskitHarness(t)
	store.acquireErr = xfsstore.ErrStaleOpen
	req := directFskitRequest()
	reply := h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if reply.GetErrno() != 0 || reply.GetWrite().GetError() != 0 || reply.GetWrite().GetCommittedSize() != 4 || store.syncs.Load() != 1 || store.fenced.Load() {
		t.Fatalf("write reacquired its handle: %v", reply)
	}
}

func TestFskitCreatePreApplyRefusalsDoNotFence(t *testing.T) {
	for _, test := range []struct {
		name                  string
		flags                 *authoritypb.OpenFlags
		parentErr             error
		writeIntent, existing bool
	}{
		{"nil flags", nil, nil, false, false}, {"empty flags", &authoritypb.OpenFlags{}, nil, false, false},
		{"read truncate", &authoritypb.OpenFlags{Read: true, Truncate: true}, nil, false, false},
		{"read append", &authoritypb.OpenFlags{Read: true, Append: true}, nil, false, false},
		{"no-op parent getattr", &authoritypb.OpenFlags{Read: true, Write: true}, syscall.EACCES, false, true},
		{"new write intent", &authoritypb.OpenFlags{Read: true, Write: true}, nil, true, false},
		{"existing write intent", &authoritypb.OpenFlags{Read: true, Write: true, Truncate: true}, nil, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, cred, base, _ := newDirectFskitHarness(t)
			store := &fskitAcquisitionStore{fskitDurabilityTestStore: base, parentErr: test.parentErr}
			h.Store = store
			if test.existing {
				base.lookupItem = xfsstore.Capability{0x42}
			}
			parent := xfsstore.Capability{0x70}
			req := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent[:], Name: []byte("existing"), Mode: 0600, Flags: test.flags, WriteIntent: test.writeIntent}}}
			stampMutation(t, req, 0, 1)
			ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1})
			reply := h.Handle(ctx, req)
			want := int32(syscall.EINVAL)
			if test.parentErr != nil {
				want = int32(syscall.EACCES)
			} else if store.applies != 0 {
				t.Fatalf("malformed CREATE reached storage %d times", store.applies)
			}
			if reply.GetErrno() != want || reply.GetUncertain() || reply.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE || base.fenced.Load() || base.syncs.Load() != 0 {
				t.Fatalf("pre-apply CREATE=%v applies=%d syncs=%d", reply, store.applies, base.syncs.Load())
			}
			req.RequestId++
			replay := h.Handle(ctx, req)
			reply.RequestId = replay.RequestId
			if !proto.Equal(reply, replay) || base.fenced.Load() || base.syncs.Load() != 0 {
				t.Fatalf("CREATE refusal replay=%v", replay)
			}
		})
	}
}
