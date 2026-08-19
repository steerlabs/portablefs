//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

type fskitWriteTestStore struct {
	resourceAdmissionFaultStore
	mu      sync.Mutex
	targets []*fskitWriteTestTarget
}

func (s *fskitWriteTestStore) PinWriteTarget(handle xfsstore.Capability) (xfsstore.WriteTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 || handle == (xfsstore.Capability{}) {
		return nil, syscall.ESTALE
	}
	target := s.targets[0]
	s.targets = s.targets[1:]
	return target, nil
}

func (*fskitWriteTestStore) CloseOpen(xfsstore.Capability) error { return nil }

type fskitWriteTestTarget struct {
	mu       sync.Mutex
	payloads [][]byte
}

func (*fskitWriteTestTarget) Coordinate() xfsstore.ObjectCoordinate {
	return xfsstore.ObjectCoordinate{Stable: [16]byte{0x41}, Ino: 0x41, DeviceMinor: 1}
}

func (t *fskitWriteTestTarget) CommitWrite(reader io.ReaderAt, spec xfsstore.WriteCommit, _ []byte) (uint64, uint64, xfsstore.Attr, error) {
	payload := make([]byte, spec.RequestedSize)
	if _, err := io.ReadFull(io.NewSectionReader(reader, 0, int64(spec.RequestedSize)), payload); err != nil {
		return 0, 0, xfsstore.Attr{}, err
	}
	t.mu.Lock()
	t.payloads = append(t.payloads, bytes.Clone(payload))
	t.mu.Unlock()
	assigned := spec.Position
	return uint64(len(payload)), assigned, xfsstore.Attr{
		Kind: xfsstore.KindRegular, Ino: 0x41, Mode: 0o600, Nlink: 1, Size: int64(assigned) + int64(len(payload)), DeviceMinor: 1,
	}, nil
}

func (*fskitWriteTestTarget) CommitWriteData([]byte, xfsstore.WriteCommit) (uint64, uint64, xfsstore.Attr, error) {
	return 0, 0, xfsstore.Attr{}, syscall.EOPNOTSUPP
}

func (*fskitWriteTestTarget) Close() error { return nil }

func (t *fskitWriteTestTarget) snapshot() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.payloads...)
}

func newFskitWriteHarness(t *testing.T) (*VolumeHandler, volumeserver.SessionCredential, *fskitWriteTestStore, <-chan struct{}) {
	return newFskitWriteHarnessWithAccess(t, volumeserver.AccessRead|volumeserver.AccessWrite)
}

func newFskitWriteHarnessWithAccess(t *testing.T, access volumeserver.Access) (*VolumeHandler, volumeserver.SessionCredential, *fskitWriteTestStore, <-chan struct{}) {
	t.Helper()
	runtime, err := volumeserver.New("fskit-write", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{1}, volumeserver.Authorization{
		Access: access, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := runtime.SessionTerminal(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: runtime,
		MaxCachedNameCapacity: 64, MaxRepairBudget: time.Second, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Register(credential.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairLocklessExpiration,
	}); err != nil {
		t.Fatal(err)
	}
	store := &fskitWriteTestStore{}
	h := testVolumeHandler()
	h.Runtime, h.Store, h.Visibility = runtime, store, visibility
	h.Authorizer = allowAuthorizer{access: access}
	h.Routes = &RoutesController{}
	if err := h.startSessionResourcesForProfile(
		credential.ID, xfsstore.Capability{0x70}, 2, [32]byte{}, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR,
	); err != nil {
		t.Fatal(err)
	}
	handle := xfsstore.Capability{0x41}
	if err := h.trackOpen(credential.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.closeSessionResources(credential.ID) })
	return h, credential, store, terminal
}

func TestFskitWriteReadOnlyBeginIsRefusedBeforeStagingAdmission(t *testing.T) {
	h, credential, store, _ := newFskitWriteHarnessWithAccess(t, volumeserver.AccessRead)
	payload := []byte("must-not-be-staged")
	store.targets = append(store.targets, &fskitWriteTestTarget{})
	request := fskitWritePhaseRequest(1, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, payload, 0)
	request.Epoch = credential.Epoch[:]
	request.Session = &authoritypb.SessionProof{
		Id: credential.ID[:], Generation: credential.Generation, ResumeSecret: credential.Secret[:],
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
	if response := h.Handle(ctx, request); response.GetErrno() != int32(syscall.EPERM) {
		t.Fatalf("read-only BEGIN = %+v, want EPERM", response)
	}
	resources, err := h.fskitWriteResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	resources.fskitWriteMu.Lock()
	stagedTransactions := len(resources.fskitWrites)
	reservedBytes := resources.fskitWriteReservedBytes
	resources.fskitWriteMu.Unlock()
	if stagedTransactions != 0 || reservedBytes != 0 {
		t.Fatalf("read-only BEGIN touched staging: transactions=%d reserved=%d", stagedTransactions, reservedBytes)
	}
}

func fskitWritePhaseRequest(requestID, transactionID uint64, phase authoritypb.FskitWritePhase, payload []byte, fragmentOffset uint64) *authoritypb.Request {
	handle := xfsstore.Capability{0x41}
	request := &authoritypb.Request{
		RequestId: requestID,
		Body: &authoritypb.Request_FskitWrite{FskitWrite: &authoritypb.FskitWriteRequest{
			TransactionId: transactionID, Handle: handle[:], RequestedSize: uint64(len(payload)),
			RlimitFsize: 1 << 20, FileMaxSize: 1 << 20, Phase: phase,
		}},
	}
	switch phase {
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA:
		request.GetFskitWrite().FragmentOffset = fragmentOffset
		request.GetFskitWrite().Size = uint32(len(payload))
		request.GetFskitWrite().Data = bytes.Clone(payload)
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT:
		request.GetFskitWrite().FragmentOffset = fragmentOffset
		identity := [16]byte{0x41}
		request.FskitFrontendOperationId = transactionID
		request.FskitSourcePublication = &authoritypb.FskitSourcePublication{Targets: []*authoritypb.FskitSourcePublicationTarget{{
			Coordinate: &authoritypb.FskitSourcePublicationTarget_Item{Item: &authoritypb.FskitSourcePublicationItem{
				Identity: identity[:], Attributes: true, Data: true,
			}},
		}}}
		request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: transactionID}
	}
	return request
}

func TestFskitWriteBeginDataCommitReplayAndAbort(t *testing.T) {
	h, credential, store, _ := newFskitWriteHarness(t)
	payload := []byte("fragmented-fskit-write")
	target := &fskitWriteTestTarget{}
	store.targets = append(store.targets, target)

	begin := fskitWritePhaseRequest(1, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, payload, 0)
	if response := h.handleFskitWrite(context.Background(), begin, credential, begin.GetFskitWrite()); response.GetErrno() != 0 ||
		response.GetFskitWrite().GetFlags() != fskitWriteReplyBegun {
		t.Fatalf("BEGIN = %+v", response)
	}
	data := fskitWritePhaseRequest(2, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, payload, 0)
	if response := h.handleFskitWrite(context.Background(), data, credential, data.GetFskitWrite()); response.GetErrno() != 0 ||
		response.GetFskitWrite().GetFlags() != fskitWriteReplyStaged {
		t.Fatalf("DATA = %+v", response)
	}
	commit := fskitWritePhaseRequest(3, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT, payload, uint64(len(payload)))
	response := h.commitFskitWrite(context.Background(), commit, credential, commit.GetFskitWrite())
	if response.GetErrno() != 0 || response.GetFskitWrite().GetFlags()&fskitWriteReplyCommitted == 0 ||
		response.GetFskitWrite().GetCommittedSize() != uint64(len(payload)) || response.GetPostState() == nil {
		t.Fatalf("COMMIT = %+v", response)
	}
	if got := target.snapshot(); len(got) != 1 || !bytes.Equal(got[0], payload) {
		t.Fatalf("committed payloads = %q", got)
	}

	replay := proto.Clone(commit).(*authoritypb.Request)
	replay.RequestId = 4
	replayed := h.commitFskitWrite(context.Background(), replay, credential, replay.GetFskitWrite())
	if !proto.Equal(response.GetFskitWrite(), replayed.GetFskitWrite()) || !proto.Equal(response.GetPostState(), replayed.GetPostState()) {
		t.Fatalf("replay = %+v, want exact retained result %+v", replayed, response)
	}
	if got := target.snapshot(); len(got) != 1 {
		t.Fatalf("replay applied %d writes, want 1", len(got))
	}

	abortTarget := &fskitWriteTestTarget{}
	store.mu.Lock()
	store.targets = append(store.targets, abortTarget)
	store.mu.Unlock()
	beginAbort := fskitWritePhaseRequest(5, 2, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, payload, 0)
	if response := h.handleFskitWrite(context.Background(), beginAbort, credential, beginAbort.GetFskitWrite()); response.GetErrno() != 0 {
		t.Fatalf("second BEGIN = %+v", response)
	}
	abort := fskitWritePhaseRequest(6, 2, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT, payload, 0)
	if response := h.handleFskitWrite(context.Background(), abort, credential, abort.GetFskitWrite()); response.GetErrno() != 0 ||
		response.GetFskitWrite().GetFlags() != fskitWriteReplyAborted {
		t.Fatalf("ABORT = %+v", response)
	}
	if got := abortTarget.snapshot(); len(got) != 0 {
		t.Fatalf("aborted write applied %d times", len(got))
	}
}

func TestFskitWriteMetadataMismatchFencesSession(t *testing.T) {
	h, credential, store, terminal := newFskitWriteHarness(t)
	payload := []byte("payload")
	store.targets = append(store.targets, &fskitWriteTestTarget{})
	begin := fskitWritePhaseRequest(1, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, payload, 0)
	if response := h.handleFskitWrite(context.Background(), begin, credential, begin.GetFskitWrite()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	mismatch := fskitWritePhaseRequest(2, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, payload, 0)
	mismatch.GetFskitWrite().Position = 1
	if response := h.handleFskitWrite(context.Background(), mismatch, credential, mismatch.GetFskitWrite()); response.GetErrno() == 0 {
		t.Fatalf("mismatched DATA unexpectedly succeeded: %+v", response)
	}
	select {
	case <-terminal:
	case <-time.After(time.Second):
		t.Fatal("metadata mismatch did not fence the FSKit session")
	}
}

func TestFskitWriteReplayIncludesSourceGateAndFrontendOperation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*authoritypb.Request)
	}{
		{
			name: "frontend operation",
			mutate: func(request *authoritypb.Request) {
				request.FskitFrontendOperationId++
			},
		},
		{
			name: "source publication",
			mutate: func(request *authoritypb.Request) {
				request.GetFskitSourcePublication().GetTargets()[0].GetItem().Identity[0]++
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, credential, store, terminal := newFskitWriteHarness(t)
			payload := []byte("replay-envelope")
			store.targets = append(store.targets, &fskitWriteTestTarget{})
			begin := fskitWritePhaseRequest(1, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN, payload, 0)
			if response := h.handleFskitWrite(context.Background(), begin, credential, begin.GetFskitWrite()); response.GetErrno() != 0 {
				t.Fatalf("BEGIN = %+v", response)
			}
			data := fskitWritePhaseRequest(2, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, payload, 0)
			if response := h.handleFskitWrite(context.Background(), data, credential, data.GetFskitWrite()); response.GetErrno() != 0 {
				t.Fatalf("DATA = %+v", response)
			}
			commit := fskitWritePhaseRequest(3, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT, payload, uint64(len(payload)))
			if response := h.commitFskitWrite(context.Background(), commit, credential, commit.GetFskitWrite()); response.GetErrno() != 0 {
				t.Fatalf("COMMIT = %+v", response)
			}
			altered := proto.Clone(commit).(*authoritypb.Request)
			altered.RequestId = 4
			test.mutate(altered)
			if response := h.commitFskitWrite(context.Background(), altered, credential, altered.GetFskitWrite()); response.GetErrno() == 0 {
				t.Fatalf("altered exact replay unexpectedly succeeded: %+v", response)
			}
			select {
			case <-terminal:
			case <-time.After(time.Second):
				t.Fatal("altered exact replay did not fence the FSKit session")
			}
		})
	}
}

func TestFskitWriteDataDigestFingerprintMatchesDirectPayload(t *testing.T) {
	h, _, _, _ := newFskitWriteHarness(t)
	payload := bytes.Repeat([]byte{0x6d}, 128<<10)
	request := fskitWritePhaseRequest(1, 1, authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, payload, 0)
	direct, err := fskitWriteFingerprint(h, request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	streamed, err := canonicalFingerprintWithWriteDataDigest(h.Runtime, request, digest)
	if err != nil {
		t.Fatal(err)
	}
	if direct != streamed {
		t.Fatalf("FSKit DATA direct fingerprint = %x, streamed = %x", direct, streamed)
	}
}
