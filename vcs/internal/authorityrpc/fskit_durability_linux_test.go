//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
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
	pins       []string
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
func (s *fskitDurabilityTestStore) pin(kind string, cap xfsstore.Capability) (xfsstore.SyncTarget, error) {
	if s.locked.Load() {
		panic("durability acquired under mutation lock")
	}
	s.pins = append(s.pins, fmt.Sprintf("%s:%d", kind, cap[0]))
	if s.acquireErr != nil {
		return nil, s.acquireErr
	}
	return durabilityTestTarget{sync: s.doSync}, nil
}
func (s *fskitDurabilityTestStore) PinSyncHandle(cap xfsstore.Capability) (xfsstore.SyncTarget, error) {
	return s.pin("handle", cap)
}
func (s *fskitDurabilityTestStore) PinSyncObject(cap xfsstore.Capability) (xfsstore.SyncTarget, error) {
	return s.pin("object", cap)
}
func (s *fskitDurabilityTestStore) SyncMutationFS() error {
	s.pins = append(s.pins, "syncfs")
	return s.doSync()
}
func (s *fskitDurabilityTestStore) doSync() error {
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

func TestFskitDurabilityTargetSelection(t *testing.T) {
	item, handle, parent, other := []byte{1}, []byte{2}, []byte{3}, []byte{4}
	for _, test := range []struct {
		name  string
		req   *authoritypb.Request
		reply *authoritypb.Response
		want  []fskitDurabilityTarget
	}{
		{"write", &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: handle}}}, nil, []fskitDurabilityTarget{{true, handle}}},
		{"fragmented commit", &authoritypb.Request{Body: &authoritypb.Request_FskitWrite{FskitWrite: &authoritypb.FskitWriteRequest{Handle: handle}}}, nil, []fskitDurabilityTarget{{true, handle}}},
		{"setattr object", &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item}}}, nil, []fskitDurabilityTarget{{false, item}}},
		{"setattr handle", &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item, Handle: handle}}}, nil, []fskitDurabilityTarget{{true, handle}}},
		{"remove xattr object", &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{Item: item}}}, nil, []fskitDurabilityTarget{{false, item}}},
		{"remove xattr handle", &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{Item: item, Handle: handle}}}, nil, []fskitDurabilityTarget{{true, handle}}},
		{"truncate open", &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: item}}}, &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle}}}, []fskitDurabilityTarget{{true, handle}}},
		{"create", &authoritypb.Request{Body: &authoritypb.Request_Create{}}, &authoritypb.Response{Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Handle: handle}}}, []fskitDurabilityTarget{{true, handle}}},
		{"mkdir", &authoritypb.Request{Body: &authoritypb.Request_Mkdir{}}, &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: &authoritypb.Item{Token: item}}}}, []fskitDurabilityTarget{{false, item}}},
		{"symlink", &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: parent}}}, nil, []fskitDurabilityTarget{{false, parent}}},
		{"link excludes source", &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: item, NewParent: parent}}}, nil, []fskitDurabilityTarget{{false, parent}}},
		{"unlink", &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: parent}}}, nil, []fskitDurabilityTarget{{false, parent}}},
		{"rename", &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: parent, NewParent: other}}}, nil, []fskitDurabilityTarget{{false, other}, {false, parent}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := fskitDurabilityTargets(test.req, test.reply); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("targets=%+v want %+v", got, test.want)
			}
		})
	}
}

func TestFskitDirectWriteDurabilityAndExactReplay(t *testing.T) {
	for _, test := range []struct {
		name                              string
		committed                         uint64
		applyErr, errorSync, errorAcquire error
		terminal                          bool
	}{
		{name: "success", committed: 4}, {name: "short", committed: 2},
		{name: "zero postapply", applyErr: fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.EACCES)},
		{name: "postapply", committed: 4, applyErr: fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.EACCES)},
		{name: "EIO", committed: 4, errorSync: syscall.EIO, terminal: true},
		{name: "ENOSPC", committed: 4, errorSync: syscall.ENOSPC, terminal: true},
		{name: "EDQUOT", committed: 4, errorSync: syscall.EDQUOT, terminal: true},
		{name: "unreadable", committed: 4, errorAcquire: syscall.EACCES},
		{name: "permission", committed: 4, errorAcquire: syscall.EPERM},
		{name: "reclaimed", committed: 4, errorAcquire: xfsstore.ErrStaleOpen},
		{name: "EMFILE", committed: 4, errorAcquire: syscall.EMFILE},
		{name: "ENFILE", committed: 4, errorAcquire: syscall.ENFILE},
		{name: "syncfs EIO", committed: 4, errorAcquire: syscall.EACCES, errorSync: syscall.EIO, terminal: true},
		{name: "syncfs ENOSPC", committed: 4, errorAcquire: syscall.EACCES, errorSync: syscall.ENOSPC, terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, cred, store, target := newDirectFskitHarness(t)
			target.committed = test.committed
			target.err = test.applyErr
			store.acquireErr = test.errorAcquire
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
			if test.errorAcquire != nil {
				kind = "syncfs"
			}
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
			})
			if result.GetErrno() != int32(syscall.EIO) || !result.GetUncertain() || result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || !store.fenced.Load() {
				t.Fatalf("sync failure=%v", result)
			}
			if typed := store.fenceCause.Load(); typed == nil || !errors.Is(typed.Cause, failure) {
				t.Fatalf("fence lost durability cause: %v", typed)
			}
		})
	}
}

func TestFskitDurabilityDeduplicatesRenameParentsByIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		old, new xfsstore.Capability
		want     []string
	}{
		{"same token", xfsstore.Capability{3}, xfsstore.Capability{3}, []string{"object:3"}},
		{"aliases", xfsstore.Capability{3, 1}, xfsstore.Capability{3, 2}, []string{"object:3"}},
		{"distinct", xfsstore.Capability{3}, xfsstore.Capability{4}, []string{"object:4", "object:3"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, _, store, _ := newDirectFskitHarness(t)
			req := &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: test.old[:], NewParent: test.new[:]}}}
			if err := h.syncFskitMutation(req, nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(store.pins, test.want) {
				t.Fatalf("sync targets=%v want %v", store.pins, test.want)
			}
		})
	}
}

func TestFskitWriteAdmissionRetainsOnlyAppliedExecution(t *testing.T) {
	h, cred, store, _ := newDirectFskitHarness(t)
	h.MaxWritesPerSession = 1
	h.MaxWrites = 1
	secondTarget := &writeTestTarget{coordinate: xfsstore.ObjectCoordinate{Stable: [16]byte{0x42}, Ino: 0x42, DeviceMinor: 1}, committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x42, Size: 4, Mode: 0600, Nlink: 1}}
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
	failure error
	fences  atomic.Int32
}

func (s *fragmentedDurabilityFailureStore) Fence(error) { s.fences.Add(1) }
func (s *fragmentedDurabilityFailureStore) PinSyncHandle(xfsstore.Capability) (xfsstore.SyncTarget, error) {
	return durabilityTestTarget{sync: func() error { s.durableHandles.Add(1); return s.failure }}, nil
}

func TestFragmentedCommitRetainsDurabilityFailureAndExactReceipt(t *testing.T) {
	for _, failure := range []error{syscall.EIO, syscall.ENOSPC} {
		t.Run(failure.Error(), func(t *testing.T) {
			h, cred, store, _ := newFskitWriteHarness(t)
			wrapped := &fragmentedDurabilityFailureStore{fskitWriteTestStore: store, failure: failure}
			h.Store = wrapped
			target := &fskitWriteTestTarget{}
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
			})
			if reply.GetErrno() != int32(syscall.EINVAL) || called || store.syncs.Load() != 0 {
				t.Fatalf("malformed source gate = %v; admission=%v", reply, called)
			}
		})
	}
}
