//go:build linux

package authorityrpc

import (
	"bytes"
	"math"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func oneShotWriteTestRequest(requestID uint64, slot uint32, sequence uint64, handle xfsstore.Capability, data []byte, position uint64, flags uint32) *authoritypb.Request {
	return &authoritypb.Request{
		RequestId: requestID, FrontendOperationId: 29,
		Mutation:              &authoritypb.Mutation{Slot: slot, Sequence: sequence},
		SourcePublicationGate: itemGate([16]byte{handle[0]}),
		Body: &authoritypb.Request_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteRequest{
			Handle: handle[:], Position: position, RlimitFsize: math.MaxUint64,
			FileMaxSize: math.MaxInt64, Size: uint32(len(data)), Flags: flags,
			Data: append([]byte(nil), data...),
		}},
	}
}

func prepareOneShotTarget(t *testing.T, h *VolumeHandler, credential volumeserver.SessionCredential, store *writeTransactionTestStore, target *writeTransactionTestTarget) xfsstore.Capability {
	t.Helper()
	handle := xfsstore.Capability{0x41}
	if err := h.trackOpen(credential.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.nextTargets = append(store.nextTargets, target)
	store.mu.Unlock()
	return handle
}

func TestOneShotWriteAppliesRetainedPayloadDirectlyAndReplaysOnce(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(uint64) (writeTransactionStage, error) {
		t.Fatal("one-shot write attempted to allocate staging")
		return nil, syscall.EIO
	}
	h.WriteStaging.mu.Unlock()
	target := &writeTransactionTestTarget{}
	target.setCommitResult(4, 2, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 6, Mode: 0o600, Nlink: 1}, nil)
	handle := prepareOneShotTarget(t, h, credential, store, target)
	request := oneShotWriteTestRequest(1, 0, 1, handle, []byte("data"), 2, 0)

	response := h.handleOneShotWrite(t.Context(), request, credential, request.GetOneShotWrite())
	reply := response.GetOneShotWrite()
	if response.GetErrno() != 0 || reply.GetFlags() != writeTransactionReplyCommitted ||
		reply.GetCommittedSize() != 4 || reply.GetAssignedOffset() != 2 || reply.GetPostSize() != 6 ||
		reply.GetVisibilitySequence() != 1 {
		t.Fatalf("one-shot reply = %+v", response)
	}
	if mutation := response.GetMutation(); mutation.GetSlot() != 0 || mutation.GetAcceptedSequence() != 1 {
		t.Fatalf("one-shot mutation state = %+v", mutation)
	}
	if calls, data := target.commitSnapshot(); calls != 1 || len(data) != 1 || !bytes.Equal(data[0], []byte("data")) {
		t.Fatalf("one-shot storage = %d calls, payloads %q", calls, data)
	}
	if direct, specs := target.directSnapshot(); direct != 1 || len(specs) != 1 ||
		specs[0].Mode != xfsstore.WritePositioned || specs[0].Position != 2 || specs[0].RequestedSize != 4 {
		t.Fatalf("one-shot direct apply = %d calls, specs %+v", direct, specs)
	}

	replay := proto.Clone(request).(*authoritypb.Request)
	replay.RequestId = 2
	replayed := h.handleOneShotWrite(t.Context(), replay, credential, replay.GetOneShotWrite())
	if replayed.GetErrno() != 0 || replayed.GetRequestId() != 2 || replayed.GetOneShotWrite().GetCommittedSize() != 4 {
		t.Fatalf("one-shot replay = %+v", replayed)
	}
	if direct, _ := target.directSnapshot(); direct != 1 {
		t.Fatalf("one-shot replay applied storage %d times, want 1", direct)
	}
	resources, err := h.writeTransactionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resources.writeReservedBytes != 0 || resources.writeTransactionCount != 0 || h.totalWriteStagingBytes != 0 || h.totalWriteTransactions != 0 {
		t.Fatalf("one-shot retained transaction accounting: session bytes %d/count %d, global bytes %d/count %d",
			resources.writeReservedBytes, resources.writeTransactionCount, h.totalWriteStagingBytes, h.totalWriteTransactions)
	}
}

func TestOneShotWriteAppendGeometryAndRLimitOutcome(t *testing.T) {
	t.Run("append", func(t *testing.T) {
		h, credential, store := newWriteTransactionHarness(t, nil)
		target := &writeTransactionTestTarget{}
		target.setCommitResult(3, 11, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 14, Mode: 0o600, Nlink: 1}, nil)
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := oneShotWriteTestRequest(1, 0, 1, handle, []byte("app"), 0, syscall.O_APPEND|syscall.O_SYNC)
		response := h.handleOneShotWrite(t.Context(), request, credential, request.GetOneShotWrite())
		if reply := response.GetOneShotWrite(); response.GetErrno() != 0 || reply.GetAssignedOffset() != 11 || reply.GetPostSize() != 14 {
			t.Fatalf("append one-shot = %+v", response)
		}
		if direct, specs := target.directSnapshot(); direct != 1 || specs[0].Mode != xfsstore.WriteAppend || !specs[0].Sync {
			t.Fatalf("append direct apply = %d calls, specs %+v", direct, specs)
		}
	})

	t.Run("rlimit", func(t *testing.T) {
		h, credential, store := newWriteTransactionHarness(t, nil)
		target := &writeTransactionTestTarget{}
		target.setCommitResult(0, 0, xfsstore.Attr{}, &xfsstore.WriteLimitError{RLimit: true})
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := oneShotWriteTestRequest(1, 0, 1, handle, []byte("x"), 0, syscall.O_APPEND)
		response := h.handleOneShotWrite(t.Context(), request, credential, request.GetOneShotWrite())
		reply := response.GetOneShotWrite()
		if response.GetErrno() != 0 || response.GetUncertain() || reply.GetFlags() != writeTransactionReplyRLimit || reply.GetError() != -int32(syscall.EFBIG) {
			t.Fatalf("one-shot RLIMIT rejection = %+v", response)
		}
	})
}

func TestOneShotWriteUsesTransactionFIFOAdmissionWithoutStaging(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	h.MaxWriteTransactionsPerSession = 2
	h.MaxWriteTransactionBytes = 1
	h.MaxWriteStagingBytesPerSession = 1
	started := make(chan struct{})
	release := make(chan struct{})
	firstTarget := &writeTransactionTestTarget{directStarted: started, directRelease: release}
	firstTarget.setCommitResult(1, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 1, Mode: 0o600, Nlink: 1}, nil)
	secondTarget := &writeTransactionTestTarget{}
	secondTarget.setCommitResult(1, 1, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 2, Mode: 0o600, Nlink: 1}, nil)
	handle := prepareOneShotTarget(t, h, credential, store, firstTarget)
	store.mu.Lock()
	store.nextTargets = append(store.nextTargets, secondTarget)
	store.mu.Unlock()

	first := oneShotWriteTestRequest(1, 0, 1, handle, []byte("a"), 0, 0)
	firstResult := make(chan *authoritypb.Response, 1)
	go func() { firstResult <- h.handleOneShotWrite(t.Context(), first, credential, first.GetOneShotWrite()) }()
	waitWriteTransactionTestSignal(t, started, "first one-shot direct apply")
	second := oneShotWriteTestRequest(2, 1, 1, handle, []byte("b"), 1, 0)
	secondResult := make(chan *authoritypb.Response, 1)
	go func() {
		secondResult <- h.handleOneShotWrite(t.Context(), second, credential, second.GetOneShotWrite())
	}()
	waitWriteTransactionCapacityQueue(t, h, 1)
	select {
	case response := <-secondResult:
		t.Fatalf("second one-shot bypassed FIFO capacity: %+v", response)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for name, result := range map[string]<-chan *authoritypb.Response{"first": firstResult, "second": secondResult} {
		select {
		case response := <-result:
			if response.GetErrno() != 0 || response.GetOneShotWrite().GetFlags() != writeTransactionReplyCommitted {
				t.Fatalf("%s one-shot = %+v", name, response)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s one-shot", name)
		}
	}
}

func TestOneShotWriteFingerprintHashesPayloadAndMetadata(t *testing.T) {
	runtime, err := volumeserver.New("one-shot-fingerprint", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := xfsstore.Capability{0x41}
	request := oneShotWriteTestRequest(1, 0, 1, handle, []byte("data"), 2, 0)
	first, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	request.GetOneShotWrite().Data = []byte("date")
	changedPayload, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	if first == changedPayload {
		t.Fatal("one-shot fingerprint omitted payload")
	}
	request.GetOneShotWrite().Position++
	changedGeometry, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	if changedPayload == changedGeometry {
		t.Fatal("one-shot fingerprint omitted write geometry")
	}
}
