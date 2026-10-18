//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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
	req.FskitFrontendOperationId = 1
	identity := [16]byte{0x41}
	req.FskitSourcePublication = &authoritypb.FskitSourcePublication{Targets: []*authoritypb.FskitSourcePublicationTarget{{Coordinate: &authoritypb.FskitSourcePublicationTarget_Item{Item: &authoritypb.FskitSourcePublicationItem{Identity: identity[:], Attributes: true, Data: true}}}}}
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
			target.committed = test.committed
			target.err = test.applyErr
			store.syncErr = test.errorSync
			req := directFskitRequest()
			response := h.handleWrite(t.Context(), req, cred, req.GetWrite())
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
			replayed := h.handleWrite(t.Context(), req, cred, req.GetWrite())
			response.RequestId = replayed.RequestId
			if !proto.Equal(response, replayed) {
				t.Fatalf("replay changed outcome: %v / %v", response, replayed)
			}
			if calls, _ := target.directSnapshot(); calls != 1 || store.syncs.Load() != 1 {
				t.Fatalf("apply/sync=%d/%d", calls, store.syncs.Load())
			}
			h.writeAdmissionMu.Lock()
			count, reservedBytes := h.totalWrites, h.totalWriteBytes
			h.writeAdmissionMu.Unlock()
			if count != 0 || reservedBytes != 0 {
				t.Fatalf("admission leaked %d/%d", count, reservedBytes)
			}
			var metrics bytes.Buffer
			if err := h.Metrics.Registry().WritePrometheus(&metrics); err != nil {
				t.Fatal(err)
			}
			kind := "handle"
			if !strings.Contains(metrics.String(), fmt.Sprintf(`portablefs_authority_fskit_durability_syncs_total{volume="fskit-durable",target="%s"} 1`, kind)) {
				t.Fatalf("missing durability metric: %s", kind)
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
		{"wrong source gate", func(r *authoritypb.Request) { r.FskitSourcePublication.Targets[0].GetItem().Data = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, cred, store, target := newDirectFskitHarness(t)
			req := directFskitRequest()
			if test.name == "cross session handle" {
				other, err := h.Runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{2}, volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				if err := h.startSessionResourcesForProfile(other.ID, xfsstore.Capability{0x70}, 2, [32]byte{}, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR); err != nil {
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
			if h.totalWrites != 0 || h.totalWriteBytes != 0 {
				t.Fatal("refusal leaked admission")
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
	if calls, _ := target.directSnapshot(); calls != 0 || store.syncs.Load() != 0 || h.totalWrites != 0 {
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
			req.FskitFrontendOperationId = 1
			req.FskitSourcePublication = &authoritypb.FskitSourcePublication{Targets: []*authoritypb.FskitSourcePublicationTarget{{Coordinate: &authoritypb.FskitSourcePublicationTarget_Item{Item: &authoritypb.FskitSourcePublicationItem{Identity: identity[:], Attributes: true}}}}}
			result := h.mutateVisibleSequence(t.Context(), req, cred, func() ([]volumeserver.VisibilityTarget, error) {
				return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, visibilityCoordinate{identity: identity, ino: 0x70, device: 1}, 0)}, nil
			}, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
				r := h.success(0)
				r.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: identity, attr: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x70, Mode: 0600}, roles: postStateRoleTarget, changed: true})
				return r, []volumeserver.VisibilityTarget{}
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

func TestFskitWriteAdmissionRetainsOnlyAppliedExecution(t *testing.T) {
	h, cred, store, _ := newDirectFskitHarness(t)
	h.MaxWritesPerSession = 1
	h.MaxWrites = 1
	secondTarget := &writeTestTarget{sync: store.doSync, coordinate: xfsstore.ObjectCoordinate{Stable: [16]byte{0x42}, Ino: 0x42, DeviceMinor: 1}, committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x42, Size: 4, Mode: 0600, Nlink: 1}}
	store.targets = append(store.targets, secondTarget)
	entered, release := make(chan struct{}), make(chan struct{})
	store.barrier = func() {
		if store.syncs.Load() == 1 {
			close(entered)
			<-release
		}
	}
	firstReq := directFskitRequest()
	secondReq := proto.Clone(firstReq).(*authoritypb.Request)
	secondReq.RequestId = 2
	secondReq.Mutation.Slot = 1
	secondReq.FskitFrontendOperationId = 2
	secondHandle := xfsstore.Capability{0x42}
	if err := h.trackOpen(cred.ID, secondHandle, false); err != nil {
		t.Fatal(err)
	}
	secondReq.GetWrite().Handle = secondHandle[:]
	secondReq.FskitSourcePublication.Targets[0].GetItem().Identity = secondHandle[:]
	first, second := make(chan *authoritypb.Response, 1), make(chan *authoritypb.Response, 1)
	go func() { first <- h.handleWrite(t.Context(), firstReq, cred, firstReq.GetWrite()) }()
	<-entered
	h.writeAdmissionMu.Lock()
	count, reserved := h.totalWrites, h.totalWriteBytes
	h.writeAdmissionMu.Unlock()
	if count != 1 || reserved != 4 {
		t.Fatalf("applied execution admission=%d/%d", count, reserved)
	}
	go func() { second <- h.handleWrite(t.Context(), secondReq, cred, secondReq.GetWrite()) }()
	waitWriteAdmissionQueue(t, h, 1)
	if calls, _ := secondTarget.directSnapshot(); calls != 0 {
		t.Fatal("WRITE bypassed FIFO admission")
	}
	close(release)
	for _, result := range []chan *authoritypb.Response{first, second} {
		if r := <-result; r.GetWrite().GetCommittedSize() != 4 {
			t.Fatalf("WRITE=%v", r)
		}
	}
	if h.totalWrites != 0 || h.totalWriteBytes != 0 {
		t.Fatal("durable writes leaked admission")
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
func TestFragmentedCommitRetainsDurabilityFailureAndExactReceipt(t *testing.T) {
	for _, failure := range []error{syscall.EIO, syscall.ENOSPC} {
		t.Run(failure.Error(), func(t *testing.T) {
			h, cred, store, _ := newFskitWriteHarness(t)
			wrapped := &fragmentedDurabilityFailureStore{fskitWriteTestStore: store}
			h.Store = wrapped
			target := &fskitWriteTestTarget{sync: func() error { store.durableHandles.Add(1); return failure }}
			store.targets = append(store.targets, target)
			payload := []byte("fragmented")
			for index, phase := range []authoritypb.FskitWritePhase{authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA} {
				req := fskitWritePhaseRequest(uint64(index+1), 1, phase, payload, 0)
				if response := h.handleFskitWrite(t.Context(), req, cred, req.GetFskitWrite()); response.GetErrno() != 0 {
					t.Fatalf("staging=%v", response)
				}
			}
			req := fskitWritePhaseRequest(3, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT, payload, uint64(len(payload)))
			reply := h.commitFskitWrite(t.Context(), req, cred, req.GetFskitWrite())
			if reply.GetFskitWrite().GetCommittedSize() != uint64(len(payload)) || reply.GetFskitWrite().GetError() != -int32(syscall.EIO) || reply.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || wrapped.fences.Load() == 0 || !terminalReceiptCarriesExactAppliedState(reply) {
				t.Fatalf("fragmented durability failure=%v", reply)
			}
			req.RequestId++
			replayed := h.commitFskitWrite(t.Context(), req, cred, req.GetFskitWrite())
			reply.RequestId = replayed.RequestId
			if !proto.Equal(reply, replayed) || store.durableHandles.Load() != 1 || len(target.snapshot()) != 1 {
				t.Fatalf("fragmented replay repeated apply/sync: %v", replayed)
			}
		})
	}
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
	stampResolvedFskitPublication(t, h, cred.ID, req)
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

func TestMalformedSourcePublicationPrecedesWriteAdmission(t *testing.T) {
	for _, malformed := range []string{"absent", "invalid"} {
		t.Run(malformed, func(t *testing.T) {
			h, cred, store, _ := newDirectFskitHarness(t)
			req := directFskitRequest()
			if malformed == "absent" {
				req.FskitSourcePublication = nil
			} else {
				req.FskitSourcePublication.Targets[0].GetItem().Identity = []byte{1}
			}
			called := false
			ctx := context.WithValue(t.Context(), coherenceOperationKey{}, &coherenceOperation{beforeAdmission: func() error { called = true; return nil }})
			reply := h.mutateFskitCoherence(ctx, req, cred, nil, func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
				t.Fatal("malformed request applied")
				return nil, nil
			}, nil)
			if reply.GetErrno() != int32(syscall.EINVAL) || called || store.syncs.Load() != 0 {
				t.Fatalf("malformed source gate = %v; admission=%v", reply, called)
			}
		})
	}
}

// Descriptor acquisition is distinct from the persistence syscall. A failure
// before apply is definite; after CREATE or O_TRUNC it is a terminal defect.
type fskitAcquisitionStore struct {
	*fskitDurabilityTestStore
	parentErr error
	applies   int
}

func (s *fskitAcquisitionStore) Create(xfsstore.Capability, string, os.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.applies++
	return xfsstore.Capability{0x42}, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x42, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *fskitAcquisitionStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.applies++
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
				stampResolvedFskitPublication(t, h, cred.ID, req)
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
	stampResolvedFskitPublication(t, h, cred.ID, req)
	reply := h.Handle(context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1}), req)
	if reply.GetErrno() != 0 || reply.GetUncertain() || base.fenced.Load() || base.syncs.Load() != 0 {
		t.Fatalf("nonmutating CREATE acquired durability: %v", reply)
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
		name      string
		flags     *authoritypb.OpenFlags
		parentErr error
	}{
		{"nil flags", nil, nil}, {"empty flags", &authoritypb.OpenFlags{}, nil},
		{"read truncate", &authoritypb.OpenFlags{Read: true, Truncate: true}, nil},
		{"read append", &authoritypb.OpenFlags{Read: true, Append: true}, nil},
		{"no-op parent getattr", &authoritypb.OpenFlags{Read: true, Write: true}, syscall.EACCES},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, cred, base, _ := newDirectFskitHarness(t)
			store := &fskitAcquisitionStore{fskitDurabilityTestStore: base, parentErr: test.parentErr}
			h.Store = store
			if test.parentErr != nil {
				base.lookupItem = xfsstore.Capability{0x42}
			}
			parent := xfsstore.Capability{0x70}
			req := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent[:], Name: []byte("existing"), Mode: 0600, Flags: test.flags}}}
			stampMutation(t, req, 0, 1)
			stampResolvedFskitPublication(t, h, cred.ID, req)
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

func TestFragmentedCommitLogicalSyncFailureRetainsExactAppliedReply(t *testing.T) {
	for _, cause := range []error{syscall.ENOSPC, syscall.EDQUOT, syscall.EIO} {
		for _, dataOnly := range []bool{false, true} {
			t.Run(cause.Error()+map[bool]string{false: "/sync", true: "/datasync"}[dataOnly], func(t *testing.T) {
				h, cred, store, _ := newFskitWriteHarness(t)
				h.Store = &fragmentedDurabilityFailureStore{fskitWriteTestStore: store}
				h.OnStorageFailure = func(error) {}
				failure := &xfsstore.DurabilityError{Cause: cause}
				target := &fskitWriteTestTarget{commitErr: errors.Join(xfsstore.ErrWritePostApply, failure), sync: func() error { return failure }}
				store.targets = append(store.targets, target)
				payload := []byte("fragmented")
				for index, phase := range []authoritypb.FskitWritePhase{authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA} {
					req := fskitWritePhaseRequest(uint64(index+1), 1, phase, payload, 0)
					req.GetFskitWrite().Flags = uint32(syscall.O_SYNC)
					if dataOnly {
						req.GetFskitWrite().Flags = uint32(syscall.O_DSYNC)
					}
					if response := h.handleFskitWrite(t.Context(), req, cred, req.GetFskitWrite()); response.GetErrno() != 0 {
						t.Fatalf("staging=%v", response)
					}
				}
				req := fskitWritePhaseRequest(3, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT, payload, uint64(len(payload)))
				req.GetFskitWrite().Flags = uint32(syscall.O_SYNC)
				if dataOnly {
					req.GetFskitWrite().Flags = uint32(syscall.O_DSYNC)
				}
				reply := h.commitFskitWrite(t.Context(), req, cred, req.GetFskitWrite())
				got := reply.GetFskitWrite()
				if reply.GetErrno() != 0 || reply.GetUncertain() || got.GetCommittedSize() != uint64(len(payload)) || got.GetAssignedOffset() != 0 || got.GetPostSize() != uint64(len(payload)) || got.GetError() != -int32(syscall.EIO) || got.GetFlags() != fskitWriteReplyCommitted|fskitWriteReplyPostApply || reply.GetPostState() == nil || !terminalReceiptCarriesExactAppliedState(reply) {
					t.Fatalf("logical sync COMMIT=%v", reply)
				}
				h.terminalFailureMu.Lock()
				draining, receipts := h.terminalDraining, len(h.terminalReceiptFrames)
				h.terminalFailureMu.Unlock()
				if !draining || receipts == 0 {
					t.Fatalf("no terminal delivery drain: %v/%d", draining, receipts)
				}
				req.RequestId++
				replay := h.commitFskitWrite(t.Context(), req, cred, req.GetFskitWrite())
				reply.RequestId = replay.RequestId
				if !proto.Equal(reply, replay) || len(target.snapshot()) != 1 {
					t.Fatalf("exact COMMIT replay=%v", replay)
				}
			})
		}
	}
}
