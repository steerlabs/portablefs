//go:build linux

package authorityrpc

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type writeTransactionTestTarget struct {
	mu             sync.Mutex
	closed         int
	commitCalls    int
	committedData  [][]byte
	commitSize     uint64
	commitSizeSet  bool
	commitAssigned uint64
	commitPost     xfsstore.Attr
	commitErr      error
}

func (*writeTransactionTestTarget) Coordinate() xfsstore.ObjectCoordinate {
	return xfsstore.ObjectCoordinate{Stable: [16]byte{0x41}, Ino: 7, DeviceMinor: 1}
}

func (t *writeTransactionTestTarget) CommitWrite(staged io.ReaderAt, spec xfsstore.WriteCommit, _ []byte) (uint64, uint64, xfsstore.Attr, error) {
	data := make([]byte, spec.RequestedSize)
	if _, err := staged.ReadAt(data, 0); err != nil {
		return 0, 0, xfsstore.Attr{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.commitCalls++
	t.committedData = append(t.committedData, data)
	committed := uint64(len(data))
	if t.commitSizeSet {
		committed = t.commitSize
	}
	return committed, t.commitAssigned, t.commitPost, t.commitErr
}

func (t *writeTransactionTestTarget) Close() error {
	t.mu.Lock()
	t.closed++
	t.mu.Unlock()
	return nil
}

func (t *writeTransactionTestTarget) closeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *writeTransactionTestTarget) setCommitResult(committed, assigned uint64, post xfsstore.Attr, err error) {
	t.mu.Lock()
	t.commitSize, t.commitSizeSet = committed, true
	t.commitAssigned, t.commitPost, t.commitErr = assigned, post, err
	t.mu.Unlock()
}

func (t *writeTransactionTestTarget) commitSnapshot() (int, [][]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	data := make([][]byte, len(t.committedData))
	for i := range t.committedData {
		data[i] = append([]byte(nil), t.committedData[i]...)
	}
	return t.commitCalls, data
}

type writeTransactionTestStore struct {
	*resourceAdmissionFaultStore
	mu         sync.Mutex
	pinErr     error
	targets    []*writeTransactionTestTarget
	fenceCalls int
}

type writeTransactionTestStage struct {
	mu           sync.Mutex
	data         []byte
	writeStarted chan struct{}
	writeRelease <-chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
	closed       chan struct{}
	writeCalls   int
	writeErr     error
}

func newWriteTransactionTestStage(size uint64, writeStarted chan struct{}, writeRelease <-chan struct{}) *writeTransactionTestStage {
	return &writeTransactionTestStage{
		data: make([]byte, size), writeStarted: writeStarted, writeRelease: writeRelease, closed: make(chan struct{}),
	}
}

func (s *writeTransactionTestStage) ReadAt(dst []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, syscall.EINVAL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(dst, s.data[offset:])
	if n != len(dst) {
		return n, io.EOF
	}
	return n, nil
}

func (s *writeTransactionTestStage) WriteAt(src []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, syscall.EINVAL
	}
	if s.writeStarted != nil {
		s.startOnce.Do(func() { close(s.writeStarted) })
	}
	if s.writeRelease != nil {
		<-s.writeRelease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	if offset > int64(len(s.data)) || len(src) > len(s.data)-int(offset) {
		return 0, io.ErrShortWrite
	}
	s.writeCalls++
	return copy(s.data[offset:], src), nil
}

func (s *writeTransactionTestStage) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *writeTransactionTestStage) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeCalls
}

func (s *writeTransactionTestStage) setWriteError(err error) {
	s.mu.Lock()
	s.writeErr = err
	s.mu.Unlock()
}

func waitWriteTransactionTestSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func requireWriteTransactionTestBlocked(t *testing.T, result <-chan *authoritypb.Response, what string) {
	t.Helper()
	select {
	case response := <-result:
		t.Fatalf("%s completed before its transaction was released: %+v", what, response)
	case <-time.After(50 * time.Millisecond):
	}
}

func (s *writeTransactionTestStore) PinWriteTarget(xfsstore.Capability) (xfsstore.WriteTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pinErr != nil {
		return nil, s.pinErr
	}
	target := &writeTransactionTestTarget{}
	s.targets = append(s.targets, target)
	return target, nil
}

func (s *writeTransactionTestStore) setPinError(err error) {
	s.mu.Lock()
	s.pinErr = err
	s.mu.Unlock()
}

func (s *writeTransactionTestStore) Fence(error) {
	s.mu.Lock()
	s.fenceCalls++
	s.mu.Unlock()
}

func (s *writeTransactionTestStore) fenceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fenceCalls
}

func newWriteTransactionHarness(t *testing.T, pinErr error) (*VolumeHandler, volumeserver.SessionCredential, *writeTransactionTestStore) {
	t.Helper()
	runtime, err := volumeserver.New("write-transaction-test", volumeserver.Config{
		SessionLease: time.Hour, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp("/dev/shm", "portablefs-write-stage-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	staging, err := OpenWriteTransactionStaging(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = staging.Close() })
	store := &writeTransactionTestStore{resourceAdmissionFaultStore: &resourceAdmissionFaultStore{}, pinErr: pinErr}
	h := testVolumeHandler()
	h.Runtime = runtime
	h.Store = store
	h.WriteStaging = staging
	h.MaxWrite = 8
	h.MaxWriteTransactionBytes = 32
	h.MaxWriteStagingBytesPerSession = 64
	h.MaxWriteStagingBytes = 128
	h.MaxWriteTransactionsPerSession = 2
	h.MaxWriteTransactions = 4
	credential, err := runtime.AttachActiveForTest(4, volumeserver.PeerIdentity{0x31}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.startSessionResources(credential.ID, xfsstore.Capability{0x11}, 4, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		resources, err := h.sessionResources(credential.ID)
		if err != nil {
			return
		}
		for _, cleanup := range closeWriteTransactions(h, resources) {
			cleanup.finish()
		}
	})
	return h, credential, store
}

func writeTransactionTestRequest(requestID, transactionID uint64, phase authoritypb.WriteTransactionPhase, offset uint64, data []byte) *authoritypb.Request {
	handle := xfsstore.Capability{0x21}
	return &authoritypb.Request{
		RequestId: requestID,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: transactionID, Handle: append([]byte(nil), handle[:]...), RequestedSize: 4,
			FragmentOffset: offset, Position: 0, RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
			Size: uint32(len(data)), Phase: phase, Data: append([]byte(nil), data...),
		}},
	}
}

func writeTransactionTestCommitRequest(requestID, transactionID, offset uint64, identity [16]byte) *authoritypb.Request {
	request := writeTransactionTestRequest(requestID, transactionID, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT, offset, nil)
	request.FrontendOperationId = 17
	request.SourcePublicationGate = &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{{
		Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
			Identity: identity[:], Attributes: true, Data: true,
		}},
	}}}
	request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
	return request
}

func beginAndStageWriteTransaction(t *testing.T, h *VolumeHandler, credential volumeserver.SessionCredential, data []byte) {
	t.Helper()
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	stage := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, data)
	if response := h.stageWriteTransaction(stage, credential, stage.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("DATA = %+v", response)
	}
}

func TestWriteTransactionInitializingDoesNotBlockOtherTransactionDataAndExactRetryAllocatesOnce(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	first := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(first, credential, first.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("first BEGIN = %+v", response)
	}

	allocationStarted := make(chan struct{})
	allocationRelease := make(chan struct{})
	var allocationMu sync.Mutex
	allocationCalls := 0
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(size uint64) (writeTransactionStage, error) {
		allocationMu.Lock()
		allocationCalls++
		allocationMu.Unlock()
		select {
		case <-allocationStarted:
		default:
			close(allocationStarted)
		}
		<-allocationRelease
		return newWriteTransactionTestStage(size, nil, nil), nil
	}
	h.WriteStaging.mu.Unlock()

	second := writeTransactionTestRequest(2, 2, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	secondResult := make(chan *authoritypb.Response, 1)
	go func() { secondResult <- h.beginWriteTransaction(second, credential, second.GetWriteTransaction()) }()
	waitWriteTransactionTestSignal(t, allocationStarted, "second transaction allocation")

	retryEntered := make(chan struct{})
	retryResult := make(chan *authoritypb.Response, 1)
	retry := writeTransactionTestRequest(3, 2, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	go func() {
		close(retryEntered)
		retryResult <- h.beginWriteTransaction(retry, credential, retry.GetWriteTransaction())
	}()
	waitWriteTransactionTestSignal(t, retryEntered, "exact BEGIN retry dispatch")

	// Transaction 2 is blocked inside its private allocator, but transaction 1
	// must still stage data. Under the old session-wide critical section this
	// call deadlocked behind allocationRelease.
	data := writeTransactionTestRequest(4, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	if response := h.stageWriteTransaction(data, credential, data.GetWriteTransaction()); response.GetErrno() != 0 ||
		response.GetWriteTransaction().GetFlags() != writeTransactionReplyStaged {
		t.Fatalf("other-transaction DATA during allocation = %+v", response)
	}
	requireWriteTransactionTestBlocked(t, retryResult, "exact BEGIN retry")
	allocationMu.Lock()
	if allocationCalls != 1 {
		t.Fatalf("INITIALIZING allocation calls = %d, want 1", allocationCalls)
	}
	allocationMu.Unlock()

	close(allocationRelease)
	for name, result := range map[string]<-chan *authoritypb.Response{"initial BEGIN": secondResult, "exact BEGIN retry": retryResult} {
		select {
		case response := <-result:
			if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyBegun {
				t.Fatalf("%s = %+v", name, response)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	store.mu.Lock()
	targetCount := len(store.targets)
	store.mu.Unlock()
	if targetCount != 2 {
		t.Fatalf("target pins = %d, want one per transaction and no retry pin", targetCount)
	}
}

func TestWriteTransactionDataOverlapsAcrossTransactionsAndSerializesWithinOne(t *testing.T) {
	h, credential, _ := newWriteTransactionHarness(t, nil)
	firstWriteStarted := make(chan struct{})
	firstWriteRelease := make(chan struct{})
	firstStage := newWriteTransactionTestStage(4, firstWriteStarted, firstWriteRelease)
	secondStage := newWriteTransactionTestStage(4, nil, nil)
	stages := []writeTransactionStage{firstStage, secondStage}
	var stageMu sync.Mutex
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(uint64) (writeTransactionStage, error) {
		stageMu.Lock()
		defer stageMu.Unlock()
		if len(stages) == 0 {
			return nil, syscall.ENOSPC
		}
		stage := stages[0]
		stages = stages[1:]
		return stage, nil
	}
	h.WriteStaging.mu.Unlock()
	for id := uint64(1); id <= 2; id++ {
		begin := writeTransactionTestRequest(id, id, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
		if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
			t.Fatalf("BEGIN %d = %+v", id, response)
		}
	}

	firstData := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	firstResult := make(chan *authoritypb.Response, 1)
	go func() { firstResult <- h.stageWriteTransaction(firstData, credential, firstData.GetWriteTransaction()) }()
	waitWriteTransactionTestSignal(t, firstWriteStarted, "first transaction WriteAt")

	replay := writeTransactionTestRequest(4, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	replayResult := make(chan *authoritypb.Response, 1)
	go func() { replayResult <- h.stageWriteTransaction(replay, credential, replay.GetWriteTransaction()) }()
	requireWriteTransactionTestBlocked(t, replayResult, "same-transaction DATA replay")

	secondData := writeTransactionTestRequest(5, 2, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("b"))
	secondResult := make(chan *authoritypb.Response, 1)
	go func() {
		secondResult <- h.stageWriteTransaction(secondData, credential, secondData.GetWriteTransaction())
	}()
	select {
	case response := <-secondResult:
		if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyStaged {
			t.Fatalf("independent DATA = %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("independent DATA blocked behind another transaction's WriteAt")
	}

	close(firstWriteRelease)
	for name, result := range map[string]<-chan *authoritypb.Response{"first DATA": firstResult, "same-transaction replay": replayResult} {
		select {
		case response := <-result:
			if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyStaged {
				t.Fatalf("%s = %+v", name, response)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	if firstStage.calls() != 1 || secondStage.calls() != 1 {
		t.Fatalf("stage WriteAt calls = first %d, second %d; want 1 each", firstStage.calls(), secondStage.calls())
	}
}

func TestWriteTransactionSessionCleanupWaitsForActiveDataBeforeCloseAndCapacityRelease(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	writeStarted := make(chan struct{})
	writeRelease := make(chan struct{})
	stage := newWriteTransactionTestStage(4, writeStarted, writeRelease)
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(uint64) (writeTransactionStage, error) { return stage, nil }
	h.WriteStaging.mu.Unlock()
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	data := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	dataResult := make(chan *authoritypb.Response, 1)
	go func() { dataResult <- h.stageWriteTransaction(data, credential, data.GetWriteTransaction()) }()
	waitWriteTransactionTestSignal(t, writeStarted, "active DATA WriteAt")

	cleanupDone := make(chan struct{})
	go func() {
		h.closeSessionResources(credential.ID)
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
		t.Fatal("session cleanup returned while DATA still owned the stage")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-stage.closed:
		t.Fatal("session cleanup closed the stage during WriteAt")
	default:
	}
	if h.totalWriteStagingBytes != 4 || h.totalWriteTransactions != 1 {
		t.Fatalf("capacity released before active DATA drained: bytes=%d transactions=%d", h.totalWriteStagingBytes, h.totalWriteTransactions)
	}

	close(writeRelease)
	select {
	case response := <-dataResult:
		if response.GetErrno() != 0 {
			t.Fatalf("DATA while cleanup waited = %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DATA release")
	}
	waitWriteTransactionTestSignal(t, cleanupDone, "session cleanup completion")
	waitWriteTransactionTestSignal(t, stage.closed, "stage Close")
	if h.totalWriteStagingBytes != 0 || h.totalWriteTransactions != 0 {
		t.Fatalf("post-cleanup capacity = bytes %d, transactions %d", h.totalWriteStagingBytes, h.totalWriteTransactions)
	}
	if len(store.targets) != 1 || store.targets[0].closeCount() != 1 {
		t.Fatalf("target cleanup = %d targets, %d closes", len(store.targets), store.targets[0].closeCount())
	}
}

func TestWriteTransactionAbortWaitsForActiveDataBeforeCloseAndCapacityRelease(t *testing.T) {
	h, credential, _ := newWriteTransactionHarness(t, nil)
	writeStarted := make(chan struct{})
	writeRelease := make(chan struct{})
	stage := newWriteTransactionTestStage(4, writeStarted, writeRelease)
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(uint64) (writeTransactionStage, error) { return stage, nil }
	h.WriteStaging.mu.Unlock()
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	data := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	dataResult := make(chan *authoritypb.Response, 1)
	go func() { dataResult <- h.stageWriteTransaction(data, credential, data.GetWriteTransaction()) }()
	waitWriteTransactionTestSignal(t, writeStarted, "active DATA before ABORT")

	abort := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT, 0, nil)
	abortResult := make(chan *authoritypb.Response, 1)
	go func() { abortResult <- h.abortWriteTransaction(abort, credential, abort.GetWriteTransaction()) }()
	requireWriteTransactionTestBlocked(t, abortResult, "same-transaction ABORT")
	select {
	case <-stage.closed:
		t.Fatal("ABORT closed the stage during WriteAt")
	default:
	}
	if h.totalWriteStagingBytes != 4 || h.totalWriteTransactions != 1 {
		t.Fatalf("ABORT released capacity during WriteAt: bytes=%d transactions=%d", h.totalWriteStagingBytes, h.totalWriteTransactions)
	}

	close(writeRelease)
	select {
	case response := <-dataResult:
		if response.GetErrno() != 0 {
			t.Fatalf("DATA before ABORT = %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DATA before ABORT")
	}
	select {
	case response := <-abortResult:
		if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyAborted {
			t.Fatalf("ABORT after DATA = %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ABORT")
	}
	waitWriteTransactionTestSignal(t, stage.closed, "stage Close after ABORT")
	if h.totalWriteStagingBytes != 0 || h.totalWriteTransactions != 0 {
		t.Fatalf("post-ABORT capacity = bytes %d, transactions %d", h.totalWriteStagingBytes, h.totalWriteTransactions)
	}
}

func TestWriteTransactionSweeperNeverClosesActiveData(t *testing.T) {
	h, credential, _ := newWriteTransactionHarness(t, nil)
	writeStarted := make(chan struct{})
	writeRelease := make(chan struct{})
	stage := newWriteTransactionTestStage(4, writeStarted, writeRelease)
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(uint64) (writeTransactionStage, error) { return stage, nil }
	h.WriteStaging.mu.Unlock()
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	transactionResources, err := h.writeTransactionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	transaction := acquireWriteTransaction(transactionResources, 1)
	transaction.mu.Lock()
	transaction.progressDeadline = time.Now().Add(-time.Second)
	transaction.mu.Unlock()
	transaction.refs.Done()

	data := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	dataResult := make(chan *authoritypb.Response, 1)
	go func() { dataResult <- h.stageWriteTransaction(data, credential, data.GetWriteTransaction()) }()
	waitWriteTransactionTestSignal(t, writeStarted, "active DATA WriteAt")
	sweepDone := make(chan struct{})
	go func() {
		h.SweepWriteTransactions(time.Now())
		close(sweepDone)
	}()
	select {
	case <-sweepDone:
		t.Fatal("sweeper completed before active DATA published its progress")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-stage.closed:
		t.Fatal("sweeper closed a stage during active DATA")
	default:
	}
	if acquire := acquireWriteTransaction(transactionResources, 1); acquire == nil {
		t.Fatal("sweeper removed an actively progressing transaction")
	} else {
		acquire.refs.Done()
	}

	close(writeRelease)
	select {
	case response := <-dataResult:
		if response.GetErrno() != 0 {
			t.Fatalf("DATA after sweep = %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DATA after sweep")
	}
	waitWriteTransactionTestSignal(t, sweepDone, "sweeper after DATA progress")
	abort := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT, 0, nil)
	if response := h.abortWriteTransaction(abort, credential, abort.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("ABORT after sweep = %+v", response)
	}
	waitWriteTransactionTestSignal(t, stage.closed, "stage cleanup after ABORT")
}

func TestWriteTransactionDataFailureRetainsExactBeginOutcomeUntilAbort(t *testing.T) {
	h, credential, _ := newWriteTransactionHarness(t, nil)
	writeStarted := make(chan struct{})
	writeRelease := make(chan struct{})
	stage := newWriteTransactionTestStage(4, writeStarted, writeRelease)
	stage.setWriteError(syscall.ENOSPC)
	h.WriteStaging.mu.Lock()
	h.WriteStaging.newFileForTest = func(uint64) (writeTransactionStage, error) { return stage, nil }
	h.WriteStaging.mu.Unlock()
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	data := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("a"))
	dataResult := make(chan *authoritypb.Response, 1)
	go func() { dataResult <- h.stageWriteTransaction(data, credential, data.GetWriteTransaction()) }()
	waitWriteTransactionTestSignal(t, writeStarted, "failing DATA WriteAt")
	// Acquire an exact BEGIN retry while DATA still owns transaction.mu. The
	// failure removes the registry entry before waking this retry, so this also
	// proves that an already-pinned retry observes the exact terminal tombstone.
	retry := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	retryResult := make(chan *authoritypb.Response, 1)
	go func() { retryResult <- h.beginWriteTransaction(retry, credential, retry.GetWriteTransaction()) }()
	requireWriteTransactionTestBlocked(t, retryResult, "exact BEGIN behind failing DATA")
	close(writeRelease)
	for name, result := range map[string]<-chan *authoritypb.Response{"failed DATA": dataResult, "exact BEGIN after DATA failure": retryResult} {
		select {
		case response := <-result:
			if response.GetErrno() != int32(syscall.ENOSPC) {
				t.Fatalf("%s = %+v", name, response)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	waitWriteTransactionTestSignal(t, stage.closed, "failed DATA stage cleanup")
	if _, err := h.Runtime.Access(credential); err != nil {
		t.Fatalf("exact retry after DATA failure fenced session: %v", err)
	}
	abort := writeTransactionTestRequest(4, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT, 0, nil)
	if response := h.abortWriteTransaction(abort, credential, abort.GetWriteTransaction()); response.GetErrno() != 0 ||
		response.GetWriteTransaction().GetFlags() != writeTransactionReplyAborted {
		t.Fatalf("ABORT after DATA failure = %+v", response)
	}
}

func TestWriteTransactionRejectedBeginReplaysExactFailureAndConsumesIdentity(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, syscall.EBADF)
	first := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	response := h.beginWriteTransaction(first, credential, first.GetWriteTransaction())
	if response.GetErrno() != int32(syscall.EBADF) {
		t.Fatalf("first rejected BEGIN errno = %d, want EBADF", response.GetErrno())
	}
	replay := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	response = h.beginWriteTransaction(replay, credential, replay.GetWriteTransaction())
	if response.GetErrno() != int32(syscall.EBADF) {
		t.Fatalf("exact rejected BEGIN replay errno = %d, want retained EBADF", response.GetErrno())
	}
	resources, err := h.sessionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resources.writeHighWater != 1 || resources.writeTransactionCount != 0 || h.totalWriteTransactions != 0 {
		t.Fatalf("rejected BEGIN accounting = highwater %d, session %d, global %d", resources.writeHighWater, resources.writeTransactionCount, h.totalWriteTransactions)
	}

	store.setPinError(nil)
	next := writeTransactionTestRequest(3, 2, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	response = h.beginWriteTransaction(next, credential, next.GetWriteTransaction())
	if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyBegun {
		t.Fatalf("next BEGIN after retained refusal = %+v", response)
	}
}

func TestWriteTransactionAbortOfRejectedBeginRetainsExactBeginIdentity(t *testing.T) {
	h, credential, _ := newWriteTransactionHarness(t, syscall.EBADF)
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != int32(syscall.EBADF) {
		t.Fatalf("rejected BEGIN = %+v", response)
	}
	abort := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT, 0, nil)
	if response := h.abortWriteTransaction(abort, credential, abort.GetWriteTransaction()); response.GetErrno() != 0 ||
		response.GetWriteTransaction().GetFlags() != writeTransactionReplyAborted {
		t.Fatalf("ABORT after rejected BEGIN = %+v", response)
	}
	replay := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	response := h.beginWriteTransaction(replay, credential, replay.GetWriteTransaction())
	if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyAborted {
		t.Fatalf("delayed exact BEGIN after ABORT = %+v", response)
	}
	if _, err := h.Runtime.Access(credential); err != nil {
		t.Fatalf("exact delayed BEGIN fenced session: %v", err)
	}
}

func TestWriteTransactionDataReplayAndZeroOffsetAbortReleaseCapacity(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	data := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("abc"))
	if response := h.stageWriteTransaction(data, credential, data.GetWriteTransaction()); response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyStaged {
		t.Fatalf("DATA = %+v", response)
	}
	replay := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("abc"))
	if response := h.stageWriteTransaction(replay, credential, replay.GetWriteTransaction()); response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyStaged {
		t.Fatalf("exact DATA replay = %+v", response)
	}

	abort := writeTransactionTestRequest(4, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT, 0, nil)
	if response := h.abortWriteTransaction(abort, credential, abort.GetWriteTransaction()); response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyAborted {
		t.Fatalf("zero-offset ABORT after staged DATA = %+v", response)
	}
	if len(store.targets) != 1 || store.targets[0].closeCount() != 1 {
		t.Fatalf("pinned target close count = %d targets, %d closes", len(store.targets), store.targets[0].closeCount())
	}
	resources, err := h.sessionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resources.writeReservedBytes != 0 || resources.writeTransactionCount != 0 || h.totalWriteStagingBytes != 0 || h.totalWriteTransactions != 0 {
		t.Fatalf("post-ABORT accounting = session bytes %d/count %d, global bytes %d/count %d",
			resources.writeReservedBytes, resources.writeTransactionCount, h.totalWriteStagingBytes, h.totalWriteTransactions)
	}
	if response := h.abortWriteTransaction(abort, credential, abort.GetWriteTransaction()); response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyAborted {
		t.Fatalf("exact ABORT replay = %+v", response)
	}
}

func TestWriteTransactionAlteredDataReplayFencesAndNeverRestages(t *testing.T) {
	h, credential, _ := newWriteTransactionHarness(t, nil)
	begin := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	if response := h.beginWriteTransaction(begin, credential, begin.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("BEGIN = %+v", response)
	}
	data := writeTransactionTestRequest(2, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("abc"))
	if response := h.stageWriteTransaction(data, credential, data.GetWriteTransaction()); response.GetErrno() != 0 {
		t.Fatalf("DATA = %+v", response)
	}
	changed := writeTransactionTestRequest(3, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, 0, []byte("abd"))
	response := h.stageWriteTransaction(changed, credential, changed.GetWriteTransaction())
	if response.GetErrno() != int32(syscall.EINVAL) {
		t.Fatalf("altered DATA replay errno = %d, want EINVAL", response.GetErrno())
	}
	resources, err := h.sessionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	transaction := acquireWriteTransaction(resources, 1)
	if transaction == nil {
		t.Fatal("transaction disappeared after altered replay")
	}
	transaction.mu.Lock()
	staged := transaction.staged
	transaction.mu.Unlock()
	transaction.refs.Done()
	if staged != 3 {
		t.Fatalf("altered replay changed staged prefix to %d, want 3", staged)
	}
}

func TestWriteTransactionRawRLimitMetadataAcceptsZeroAndInfinity(t *testing.T) {
	for _, limit := range []uint64{0, 1, math.MaxUint64} {
		request := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
		request.GetWriteTransaction().RlimitFsize = limit
		if _, err := writeTransactionMetadataFromRequest(request.GetWriteTransaction()); err != nil {
			t.Fatalf("raw rlimit %d rejected: %v", limit, err)
		}
	}
	positioned := writeTransactionTestRequest(1, 1, authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil)
	positioned.GetWriteTransaction().Position = 1
	positioned.GetWriteTransaction().RlimitFsize = 1
	if _, err := writeTransactionMetadataFromRequest(positioned.GetWriteTransaction()); err != nil {
		t.Fatalf("position at finite rlimit is a COMMIT-time limit, got %v", err)
	}
}

func TestWriteTransactionCommitAppliesStagedPrefixOnceAndReplaysRetainedResult(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	beginAndStageWriteTransaction(t, h, credential, []byte("abc"))
	if len(store.targets) != 1 {
		t.Fatalf("pinned targets = %d, want 1", len(store.targets))
	}
	target := store.targets[0]
	target.setCommitResult(3, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 12, Mode: 0o600, Nlink: 1}, nil)

	first := writeTransactionTestCommitRequest(3, 1, 3, target.Coordinate().Stable)
	response := h.commitWriteTransaction(t.Context(), first, credential, first.GetWriteTransaction())
	if response.GetErrno() != 0 {
		calls, committed := target.commitSnapshot()
		t.Fatalf("COMMIT = %+v; storage = %d calls, data %q", response, calls, committed)
	}
	reply := response.GetWriteTransaction()
	if reply.GetFlags() != writeTransactionReplyCommitted || reply.GetCommittedSize() != 3 ||
		reply.GetAssignedOffset() != 0 || reply.GetPostSize() != 12 || reply.GetVisibilitySequence() != 1 {
		t.Fatalf("COMMIT reply = %+v", reply)
	}
	if mutation := response.GetMutation(); mutation.GetSlot() != 0 || mutation.GetAcceptedSequence() != 1 {
		t.Fatalf("COMMIT mutation state = %+v", mutation)
	}
	if calls, committed := target.commitSnapshot(); calls != 1 || len(committed) != 1 || string(committed[0]) != "abc" {
		t.Fatalf("storage COMMIT = %d calls, data %q", calls, committed)
	}
	if target.closeCount() != 1 {
		t.Fatalf("target close count after COMMIT = %d, want 1", target.closeCount())
	}
	resources, err := h.sessionResources(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resources.writeReservedBytes != 0 || resources.writeTransactionCount != 0 || h.totalWriteStagingBytes != 0 || h.totalWriteTransactions != 0 {
		t.Fatalf("post-COMMIT accounting = session bytes %d/count %d, global bytes %d/count %d",
			resources.writeReservedBytes, resources.writeTransactionCount, h.totalWriteStagingBytes, h.totalWriteTransactions)
	}

	replay := writeTransactionTestCommitRequest(4, 1, 3, target.Coordinate().Stable)
	replayed := h.commitWriteTransaction(t.Context(), replay, credential, replay.GetWriteTransaction())
	if replayed.GetErrno() != 0 || replayed.GetRequestId() != 4 || replayed.GetWriteTransaction().GetCommittedSize() != 3 {
		t.Fatalf("exact COMMIT replay = %+v", replayed)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("exact replay applied storage %d times, want 1", calls)
	}
}

func TestWriteTransactionCommitRetainsStructuredRLimitRefusalWithoutReapply(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	beginAndStageWriteTransaction(t, h, credential, []byte("abc"))
	target := store.targets[0]
	target.setCommitResult(0, 0, xfsstore.Attr{}, &xfsstore.WriteLimitError{RLimit: true})

	first := writeTransactionTestCommitRequest(3, 1, 3, target.Coordinate().Stable)
	response := h.commitWriteTransaction(t.Context(), first, credential, first.GetWriteTransaction())
	reply := response.GetWriteTransaction()
	if response.GetErrno() != 0 || reply.GetFlags() != writeTransactionReplyRLimit || reply.GetError() != -int32(syscall.EFBIG) {
		t.Fatalf("RLIMIT COMMIT = %+v", response)
	}
	if response.GetPostAttr() != nil || reply.GetCommittedSize() != 0 || reply.GetVisibilitySequence() != 0 {
		t.Fatalf("RLIMIT refusal carried applied result = %+v", response)
	}
	replay := writeTransactionTestCommitRequest(4, 1, 3, target.Coordinate().Stable)
	replayed := h.commitWriteTransaction(t.Context(), replay, credential, replay.GetWriteTransaction())
	if replayed.GetErrno() != 0 || replayed.GetWriteTransaction().GetFlags() != writeTransactionReplyRLimit || replayed.GetWriteTransaction().GetError() != -int32(syscall.EFBIG) {
		t.Fatalf("RLIMIT COMMIT replay = %+v", replayed)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("RLIMIT replay applied storage %d times, want 1", calls)
	}
}

func TestWriteTransactionCommitRetainsAppliedPrefixWithPostApplyError(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	beginAndStageWriteTransaction(t, h, credential, []byte("abc"))
	target := store.targets[0]
	target.setCommitResult(3, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 3, Mode: 0o600, Nlink: 1},
		fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.ENOSPC))

	first := writeTransactionTestCommitRequest(3, 1, 3, target.Coordinate().Stable)
	response := h.commitWriteTransaction(t.Context(), first, credential, first.GetWriteTransaction())
	reply := response.GetWriteTransaction()
	if response.GetErrno() != 0 || response.GetUncertain() ||
		reply.GetFlags() != writeTransactionReplyCommitted|writeTransactionReplyPostApply ||
		reply.GetCommittedSize() != 3 || reply.GetPostSize() != 3 || reply.GetError() != -int32(syscall.ENOSPC) {
		t.Fatalf("post-apply COMMIT = %+v", response)
	}
	replay := writeTransactionTestCommitRequest(4, 1, 3, target.Coordinate().Stable)
	replayed := h.commitWriteTransaction(t.Context(), replay, credential, replay.GetWriteTransaction())
	if replayed.GetErrno() != 0 || replayed.GetWriteTransaction().GetFlags() != writeTransactionReplyCommitted|writeTransactionReplyPostApply ||
		replayed.GetWriteTransaction().GetError() != -int32(syscall.ENOSPC) {
		t.Fatalf("post-apply COMMIT replay = %+v", replayed)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("post-apply replay applied storage %d times, want 1", calls)
	}
}

func TestWriteTransactionCommitPublishesZeroByteMetadataOnlyPostApply(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	beginAndStageWriteTransaction(t, h, credential, []byte("abc"))
	target := store.targets[0]
	target.setCommitResult(0, 99, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 11, Mode: 0o640, Nlink: 1},
		fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.ENOSPC))

	first := writeTransactionTestCommitRequest(3, 1, 3, target.Coordinate().Stable)
	response := h.commitWriteTransaction(t.Context(), first, credential, first.GetWriteTransaction())
	reply := response.GetWriteTransaction()
	if response.GetErrno() != 0 || response.GetUncertain() || response.GetPostAttr().GetSize() != 11 ||
		reply.GetFlags() != writeTransactionReplyCommitted|writeTransactionReplyPostApply ||
		reply.GetCommittedSize() != 0 || reply.GetAssignedOffset() != 0 || reply.GetPostSize() != 11 ||
		reply.GetVisibilitySequence() != 1 || reply.GetError() != -int32(syscall.ENOSPC) {
		t.Fatalf("zero-byte metadata-only COMMIT = %+v", response)
	}
	replay := writeTransactionTestCommitRequest(4, 1, 3, target.Coordinate().Stable)
	replayed := h.commitWriteTransaction(t.Context(), replay, credential, replay.GetWriteTransaction())
	if replayed.GetWriteTransaction().GetFlags() != writeTransactionReplyCommitted|writeTransactionReplyPostApply ||
		replayed.GetWriteTransaction().GetCommittedSize() != 0 || replayed.GetWriteTransaction().GetAssignedOffset() != 0 {
		t.Fatalf("zero-byte metadata-only replay = %+v", replayed)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("zero-byte metadata-only replay applied storage %d times, want 1", calls)
	}
}

func TestWriteTransactionCommitMalformedAppliedResultIsUncertainAndNeverReapplies(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	beginAndStageWriteTransaction(t, h, credential, []byte("abc"))
	target := store.targets[0]
	// A storage implementation claiming more committed bytes than were staged
	// is a post-apply contract defect. The authority must never serialize that
	// impossible result as a successful COMMIT.
	target.setCommitResult(4, 0, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0o600, Nlink: 1}, nil)
	first := writeTransactionTestCommitRequest(3, 1, 3, target.Coordinate().Stable)
	response := h.commitWriteTransaction(t.Context(), first, credential, first.GetWriteTransaction())
	if response.GetErrno() != int32(syscall.EIO) || !response.GetUncertain() || response.GetWriteTransaction() != nil {
		t.Fatalf("malformed applied COMMIT = %+v", response)
	}
	replay := writeTransactionTestCommitRequest(4, 1, 3, target.Coordinate().Stable)
	replayed := h.commitWriteTransaction(t.Context(), replay, credential, replay.GetWriteTransaction())
	if replayed.GetErrno() != int32(syscall.EIO) || !replayed.GetUncertain() {
		t.Fatalf("malformed applied COMMIT replay = %+v", replayed)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("malformed-result replay applied storage %d times, want 1", calls)
	}
}

func TestWriteTransactionDefiniteFatalStoreRefusalFencesVolumeAndReplays(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	beginAndStageWriteTransaction(t, h, credential, []byte("abc"))
	target := store.targets[0]
	target.setCommitResult(0, 0, xfsstore.Attr{}, syscall.EIO)
	first := writeTransactionTestCommitRequest(3, 1, 3, target.Coordinate().Stable)
	response := h.commitWriteTransaction(t.Context(), first, credential, first.GetWriteTransaction())
	if response.GetErrno() != 0 || response.GetWriteTransaction().GetFlags() != writeTransactionReplyRejected ||
		response.GetWriteTransaction().GetError() != -int32(syscall.EIO) {
		t.Fatalf("fatal pre-apply COMMIT = %+v", response)
	}
	if store.fenceCount() != 1 {
		t.Fatalf("fatal pre-apply store fence count = %d, want 1", store.fenceCount())
	}
	replay := writeTransactionTestCommitRequest(4, 1, 3, target.Coordinate().Stable)
	replayed := h.commitWriteTransaction(t.Context(), replay, credential, replay.GetWriteTransaction())
	if replayed.GetWriteTransaction().GetFlags() != writeTransactionReplyRejected || replayed.GetWriteTransaction().GetError() != -int32(syscall.EIO) {
		t.Fatalf("fatal pre-apply COMMIT replay = %+v", replayed)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("fatal refusal replay applied storage %d times, want 1", calls)
	}
	if store.fenceCount() != 1 {
		t.Fatalf("fatal refusal replay fenced store %d times, want 1", store.fenceCount())
	}
}

func TestWriteTransactionSessionCleanupRacesOnlyAfterAdmittedHandlerDrain(t *testing.T) {
	h, credential, store := newWriteTransactionHarness(t, nil)
	const workers = 32
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 100; attempt++ {
				resources, err := h.writeTransactionResources(credential.ID)
				if err != nil {
					return
				}
				resources.writeMu.Lock()
				_ = resources.writeTransactions
				resources.writeMu.Unlock()
			}
		}()
	}
	h.closeSessionResources(credential.ID)
	wait.Wait()
	if _, err := h.sessionResources(credential.ID); !errors.Is(err, volumeserver.ErrSessionExpired) {
		t.Fatalf("session resources after cleanup = %v, want expired", err)
	}
	if len(store.targets) != 0 {
		t.Fatalf("cleanup race unexpectedly pinned %d targets", len(store.targets))
	}
}
