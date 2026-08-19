//go:build linux

package authorityrpc

import (
	"bytes"
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

func stockWriteTestRequest(requestID uint64, slot uint32, sequence uint64, handle xfsstore.Capability, data []byte, position uint64, _ uint32) *authoritypb.Request {
	return &authoritypb.Request{
		RequestId: requestID,
		Mutation:  &authoritypb.Mutation{Slot: slot, Sequence: sequence},
		Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
			Handle: handle[:], Position: position, Size: uint32(len(data)), Data: append([]byte(nil), data...),
		}},
	}
}

type writeTestStore struct {
	resourceAdmissionFaultStore
	mu      sync.Mutex
	targets []*writeTestTarget
}

func (s *writeTestStore) PinWriteTarget(xfsstore.Capability) (xfsstore.WriteTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 {
		return nil, syscall.ESTALE
	}
	target := s.targets[0]
	s.targets = s.targets[1:]
	return target, nil
}

func (*writeTestStore) CloseOpen(xfsstore.Capability) error { return nil }

type writeTestTarget struct {
	mu        sync.Mutex
	committed uint64
	assigned  uint64
	post      xfsstore.Attr
	err       error
	payloads  [][]byte
	specs     []xfsstore.WriteCommit
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (t *writeTestTarget) Coordinate() xfsstore.ObjectCoordinate {
	return xfsstore.ObjectCoordinate{Stable: [16]byte{0x41}, Ino: 7, DeviceMinor: 1}
}
func (t *writeTestTarget) CommitWrite(io.ReaderAt, xfsstore.WriteCommit, []byte) (uint64, uint64, xfsstore.Attr, error) {
	return 0, 0, xfsstore.Attr{}, syscall.EOPNOTSUPP
}
func (t *writeTestTarget) CommitWriteData(data []byte, spec xfsstore.WriteCommit) (uint64, uint64, xfsstore.Attr, error) {
	if t.started != nil {
		t.once.Do(func() { close(t.started) })
	}
	if t.release != nil {
		<-t.release
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.payloads = append(t.payloads, bytes.Clone(data))
	t.specs = append(t.specs, spec)
	return t.committed, t.assigned, t.post, t.err
}
func (t *writeTestTarget) Close() error { return nil }
func (t *writeTestTarget) setCommitResult(committed, assigned uint64, post xfsstore.Attr, err error) {
	t.committed, t.assigned, t.post, t.err = committed, assigned, post, err
}
func (t *writeTestTarget) commitSnapshot() (int, [][]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.payloads), append([][]byte(nil), t.payloads...)
}
func (t *writeTestTarget) directSnapshot() (int, []xfsstore.WriteCommit) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.specs), append([]xfsstore.WriteCommit(nil), t.specs...)
}

func newWriteHarness(t *testing.T) (*VolumeHandler, volumeserver.SessionCredential, *writeTestStore) {
	t.Helper()
	runtime, err := volumeserver.New("write", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 2, MaxLockRecords: 8})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(4, volumeserver.PeerIdentity{1}, volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	store := &writeTestStore{}
	h := testVolumeHandler()
	h.Store, h.Runtime = store, runtime
	if err := h.startSessionResources(credential.ID, xfsstore.Capability{1}, 4, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.closeSessionResources(credential.ID) })
	return h, credential, store
}

func prepareOneShotTarget(t *testing.T, h *VolumeHandler, credential volumeserver.SessionCredential, store *writeTestStore, target *writeTestTarget) xfsstore.Capability {
	t.Helper()
	handle := xfsstore.Capability{0x41}
	if err := h.trackOpen(credential.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.targets = append(store.targets, target)
	store.mu.Unlock()
	return handle
}

func waitWriteTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitWriteAdmissionQueue(t *testing.T, h *VolumeHandler, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.writeAdmissionMu.Lock()
		seen := 0
		for waiter := h.writeAdmissionHead; waiter != nil; waiter = waiter.next {
			seen++
		}
		h.writeAdmissionMu.Unlock()
		if seen == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d queued writes", count)
}

func TestWriteAppliesRetainedPayloadDirectlyAndReplaysOnce(t *testing.T) {
	h, credential, store := newWriteHarness(t)
	target := &writeTestTarget{}
	target.setCommitResult(4, 2, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 6, Mode: 0o600, Nlink: 1}, nil)
	handle := prepareOneShotTarget(t, h, credential, store, target)
	request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 2, 0)

	response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
	reply := response.GetWrite()
	if response.GetErrno() != 0 || reply.GetCommittedSize() != 4 || reply.GetPostAttr().GetSize() != 6 || reply.GetError() != 0 {
		t.Fatalf("write reply = %+v", response)
	}
	if mutation := response.GetMutation(); mutation.GetSlot() != 0 || mutation.GetAcceptedSequence() != 1 {
		t.Fatalf("write mutation state = %+v", mutation)
	}
	if calls, data := target.commitSnapshot(); calls != 1 || len(data) != 1 || !bytes.Equal(data[0], []byte("data")) {
		t.Fatalf("write storage = %d calls, payloads %q", calls, data)
	}
	if direct, specs := target.directSnapshot(); direct != 1 || len(specs) != 1 ||
		specs[0].Mode != xfsstore.WritePositioned || specs[0].Position != 2 || specs[0].RequestedSize != 4 {
		t.Fatalf("write direct apply = %d calls, specs %+v", direct, specs)
	}

	replay := proto.Clone(request).(*authoritypb.Request)
	replay.RequestId = 2
	replayed := h.handleWrite(t.Context(), replay, credential, replay.GetWrite())
	if replayed.GetErrno() != 0 || replayed.GetRequestId() != 2 || replayed.GetWrite().GetCommittedSize() != 4 {
		t.Fatalf("write replay = %+v", replayed)
	}
	if direct, _ := target.directSnapshot(); direct != 1 {
		t.Fatalf("write replay applied storage %d times, want 1", direct)
	}
	resources, err := h.sessionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resources.writeReservedBytes != 0 || resources.writeCount != 0 || h.totalWriteBytes != 0 || h.totalWrites != 0 {
		t.Fatalf("write retained accounting accounting: session bytes %d/count %d, global bytes %d/count %d",
			resources.writeReservedBytes, resources.writeCount, h.totalWriteBytes, h.totalWrites)
	}
}

func TestWriteUsesStockPositionAndStructuredError(t *testing.T) {
	t.Run("positioned", func(t *testing.T) {
		h, credential, store := newWriteHarness(t)
		target := &writeTestTarget{}
		target.setCommitResult(3, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 3, Mode: 0o600, Nlink: 1}, nil)
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := stockWriteTestRequest(1, 0, 1, handle, []byte("pos"), 0, 0)
		response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
		if reply := response.GetWrite(); response.GetErrno() != 0 || reply.GetCommittedSize() != 3 || reply.GetPostAttr().GetSize() != 3 {
			t.Fatalf("positioned one-shot = %+v", response)
		}
		if direct, specs := target.directSnapshot(); direct != 1 || specs[0].Mode != xfsstore.WritePositioned || specs[0].Sync {
			t.Fatalf("positioned direct apply = %d calls, specs %+v", direct, specs)
		}
	})

	t.Run("rlimit", func(t *testing.T) {
		h, credential, store := newWriteHarness(t)
		target := &writeTestTarget{}
		target.setCommitResult(0, 0, xfsstore.Attr{}, &xfsstore.WriteLimitError{RLimit: true})
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := stockWriteTestRequest(1, 0, 1, handle, []byte("x"), 0, 0)
		response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
		reply := response.GetWrite()
		if response.GetErrno() != 0 || response.GetUncertain() || reply.GetPostAttr() != nil || reply.GetError() != -int32(syscall.EFBIG) {
			t.Fatalf("write structured rejection = %+v", response)
		}
	})
}

func TestWriteUsesTransactionFIFOAdmissionWithoutStaging(t *testing.T) {
	h, credential, store := newWriteHarness(t)
	h.MaxWritesPerSession = 2
	h.MaxWriteBytesPerSession = 1
	started := make(chan struct{})
	release := make(chan struct{})
	firstTarget := &writeTestTarget{started: started, release: release}
	firstTarget.setCommitResult(1, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 1, Mode: 0o600, Nlink: 1}, nil)
	secondTarget := &writeTestTarget{}
	secondTarget.setCommitResult(1, 1, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 2, Mode: 0o600, Nlink: 1}, nil)
	handle := prepareOneShotTarget(t, h, credential, store, firstTarget)
	store.mu.Lock()
	store.targets = append(store.targets, secondTarget)
	store.mu.Unlock()

	first := stockWriteTestRequest(1, 0, 1, handle, []byte("a"), 0, 0)
	firstResult := make(chan *authoritypb.Response, 1)
	go func() { firstResult <- h.handleWrite(t.Context(), first, credential, first.GetWrite()) }()
	waitWriteTestSignal(t, started, "first write direct apply")
	second := stockWriteTestRequest(2, 1, 1, handle, []byte("b"), 1, 0)
	secondResult := make(chan *authoritypb.Response, 1)
	go func() {
		secondResult <- h.handleWrite(t.Context(), second, credential, second.GetWrite())
	}()
	waitWriteAdmissionQueue(t, h, 1)
	select {
	case response := <-secondResult:
		t.Fatalf("second one-shot bypassed FIFO capacity: %+v", response)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for name, result := range map[string]<-chan *authoritypb.Response{"first": firstResult, "second": secondResult} {
		select {
		case response := <-result:
			if response.GetErrno() != 0 || response.GetWrite().GetPostAttr() == nil {
				t.Fatalf("%s one-shot = %+v", name, response)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s one-shot", name)
		}
	}
}

func TestWriteFingerprintHashesPayloadAndMetadata(t *testing.T) {
	runtime, err := volumeserver.New("one-shot-fingerprint", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := xfsstore.Capability{0x41}
	request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 2, 0)
	first, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	request.GetWrite().Data = []byte("date")
	changedPayload, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	if first == changedPayload {
		t.Fatal("write fingerprint omitted payload")
	}
	request.GetWrite().Position++
	changedGeometry, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	if changedPayload == changedGeometry {
		t.Fatal("write fingerprint omitted write geometry")
	}
}

func TestWriteResolvesAppendPlacementAtTheAuthority(t *testing.T) {
	t.Run("append", func(t *testing.T) {
		h, credential, store := newWriteHarness(t)
		target := &writeTestTarget{}
		target.setCommitResult(4, 6, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 10, Mode: 0o600, Nlink: 1}, nil)
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
		request.GetWrite().Append = true

		response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
		reply := response.GetWrite()
		if response.GetErrno() != 0 || reply.GetCommittedSize() != 4 || reply.GetAssignedOffset() != 6 || reply.GetError() != 0 {
			t.Fatalf("append reply = %+v", response)
		}
		if direct, specs := target.directSnapshot(); direct != 1 ||
			specs[0].Mode != xfsstore.WriteAppend || specs[0].Position != 0 || specs[0].RequirePositionAtEOF {
			t.Fatalf("append direct apply = %d calls, specs %+v", direct, specs)
		}
		// A retried append must return the retained outcome, never place the
		// payload a second time at a new EOF.
		replay := proto.Clone(request).(*authoritypb.Request)
		replay.RequestId = 2
		replayed := h.handleWrite(t.Context(), replay, credential, replay.GetWrite())
		if replayed.GetWrite().GetCommittedSize() != 4 || replayed.GetWrite().GetAssignedOffset() != 6 {
			t.Fatalf("append replay = %+v", replayed)
		}
		if direct, _ := target.directSnapshot(); direct != 1 {
			t.Fatalf("append replay applied storage %d times, want 1", direct)
		}
	})

	t.Run("append that did not land at the object end is uncertain", func(t *testing.T) {
		h, credential, store := newWriteHarness(t)
		target := &writeTestTarget{}
		target.setCommitResult(4, 6, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 11, Mode: 0o600, Nlink: 1}, nil)
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
		request.GetWrite().Append = true
		response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
		if response.GetErrno() == 0 || response.GetWrite() != nil {
			t.Fatalf("append past the object end = %+v, want a fenced envelope", response)
		}
	})

	t.Run("offset matching the client size requires EOF", func(t *testing.T) {
		h, credential, store := newWriteHarness(t)
		target := &writeTestTarget{}
		target.setCommitResult(4, 6, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 10, Mode: 0o600, Nlink: 1}, nil)
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 6, 0)
		request.GetWrite().OffsetMatchesClientSize = true
		response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
		if response.GetErrno() != 0 || response.GetWrite().GetCommittedSize() != 4 {
			t.Fatalf("flagged write reply = %+v", response)
		}
		if direct, specs := target.directSnapshot(); direct != 1 ||
			specs[0].Mode != xfsstore.WritePositioned || !specs[0].RequirePositionAtEOF {
			t.Fatalf("flagged write direct apply = %d calls, specs %+v", direct, specs)
		}
	})

	t.Run("the store refusal is returned as a structured errno", func(t *testing.T) {
		h, credential, store := newWriteHarness(t)
		target := &writeTestTarget{}
		target.setCommitResult(0, 6, xfsstore.Attr{}, xfsstore.ErrPositionNotAtEOF)
		handle := prepareOneShotTarget(t, h, credential, store, target)
		request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 6, 0)
		request.GetWrite().OffsetMatchesClientSize = true
		response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
		if response.GetErrno() != 0 || response.GetWrite().GetError() != -int32(syscall.EIO) {
			t.Fatalf("stale-size refusal = %+v, want a structured EIO", response)
		}
	})

	t.Run("durability intent reaches the store", func(t *testing.T) {
		for _, tc := range []struct{ sync, dataSync bool }{{sync: true}, {dataSync: true}} {
			h, credential, store := newWriteHarness(t)
			target := &writeTestTarget{}
			target.setCommitResult(4, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0o600, Nlink: 1}, nil)
			handle := prepareOneShotTarget(t, h, credential, store, target)
			request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
			request.GetWrite().Sync, request.GetWrite().DataSync = tc.sync, tc.dataSync
			if response := h.handleWrite(t.Context(), request, credential, request.GetWrite()); response.GetErrno() != 0 {
				t.Fatalf("durable write = %+v", response)
			}
			if _, specs := target.directSnapshot(); specs[0].Sync != tc.sync || specs[0].DataSync != tc.dataSync {
				t.Fatalf("durability intent %+v reached the store as %+v", tc, specs[0])
			}
		}
	})

	t.Run("contradictory placement statements are refused", func(t *testing.T) {
		for _, mutate := range []func(*authoritypb.WriteRequest){
			func(body *authoritypb.WriteRequest) { body.Append, body.Position = true, 6 },
			func(body *authoritypb.WriteRequest) { body.Append, body.OffsetMatchesClientSize = true, true },
			func(body *authoritypb.WriteRequest) { body.Sync, body.DataSync = true, true },
		} {
			h, credential, store := newWriteHarness(t)
			target := &writeTestTarget{}
			handle := prepareOneShotTarget(t, h, credential, store, target)
			request := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
			mutate(request.GetWrite())
			response := h.handleWrite(t.Context(), request, credential, request.GetWrite())
			if response.GetWrite().GetError() != -int32(syscall.EINVAL) {
				t.Fatalf("contradictory write request = %+v, want EINVAL", response)
			}
			if direct, _ := target.directSnapshot(); direct != 0 {
				t.Fatalf("contradictory write request reached storage %d times", direct)
			}
		}
	})
}
