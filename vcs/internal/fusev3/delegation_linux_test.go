//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

type delegationFakeRPC struct {
	mu           sync.Mutex
	sequence     uint64
	mutations    []*authoritypb.Request
	controls     []*authoritypb.Request
	barriers     int
	maxWrite     uint32
	block        <-chan struct{}
	fail         error
	omitPostAttr bool
}

func (f *delegationFakeRPC) IOLimits() (uint32, uint32) {
	if f.maxWrite == 0 {
		return writeback.MaxPayload, writeback.MaxPayload
	}
	return f.maxWrite, f.maxWrite
}

type delegationPipelineRPC struct {
	delegationFakeRPC
	started chan byte
	release chan struct{}
}

type delegationOrderedControlRPC struct {
	delegationFakeRPC
	firstStarted chan struct{}
	releaseFirst chan struct{}
	once         sync.Once
}

type delegationEpochSyncRPC struct {
	delegationFakeRPC
	writeStarted chan struct{}
	releaseWrite chan struct{}
	once         sync.Once
}

type delegationBlockedBarrierRPC struct {
	delegationFakeRPC
	barrierStarted chan struct{}
	releaseBarrier chan struct{}
	once           sync.Once
}

type delegationLimitedRPC struct {
	delegationFakeRPC
	muCalls    sync.Mutex
	writeCalls int
}

func (f *delegationLimitedRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetWrite() != nil {
		f.muCalls.Lock()
		f.writeCalls++
		call := f.writeCalls
		f.muCalls.Unlock()
		if call == 2 {
			return nil, errors.New("transient second chunk refusal")
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func (f *delegationBlockedBarrierRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		f.once.Do(func() { close(f.barrierStarted) })
		select {
		case <-f.releaseBarrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func (f *delegationEpochSyncRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetWrite() != nil {
		f.once.Do(func() { close(f.writeStarted) })
		select {
		case <-f.releaseWrite:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func (f *delegationOrderedControlRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if ack := request.GetDelegationModeChangeAck(); ack != nil && ack.GetEventSequence() == 10 {
		f.once.Do(func() { close(f.firstStarted) })
		select {
		case <-f.releaseFirst:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, request)
}

func (f *delegationPipelineRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	write := request.GetWrite()
	if write == nil || len(write.GetHandle()) == 0 {
		return nil, errors.New("pipeline fake expected write")
	}
	select {
	case f.started <- write.GetHandle()[0]:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	f.mu.Lock()
	f.sequence++
	sequence := f.sequence
	f.mutations = append(f.mutations, proto.Clone(request).(*authoritypb.Request))
	f.mu.Unlock()
	return &authoritypb.Response{AppliedSequence: sequence, VolumeVersion: sequence, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
		CommittedSize: uint64(len(write.GetData())), AssignedOffset: write.GetPosition(),
		PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: int64(write.GetPosition()) + int64(len(write.GetData()))},
	}}}, nil
}

func (f *delegationFakeRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail != nil {
		return nil, f.fail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if barrier := request.GetBarrier(); barrier != nil {
		f.barriers++
		return &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{
			AppliedSequence: barrier.GetCutSequence(), DurableSequence: barrier.GetCutSequence(),
		}}}, nil
	}
	f.sequence++
	f.mutations = append(f.mutations, proto.Clone(request).(*authoritypb.Request))
	response := &authoritypb.Response{AppliedSequence: f.sequence, VolumeVersion: f.sequence}
	if write := request.GetWrite(); write != nil {
		response.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
			CommittedSize: uint64(len(write.GetData())), AssignedOffset: write.GetPosition(),
			PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: int64(write.GetPosition()) + int64(len(write.GetData()))},
		}}
	}
	if set := request.GetSetAttr(); set != nil && !f.omitPostAttr {
		response.PostState = &authoritypb.PostState{Objects: []*authoritypb.ObjectPostState{{StableIdentity: delegationTestIdentity(set.GetHandle()[0]), ObjectVersion: f.sequence, Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: set.GetSize(), Mode: set.GetMode()}}}}
	}
	if f.omitPostAttr && response.GetWrite() != nil {
		response.GetWrite().PostAttr = nil
	}
	return response, nil
}

func (f *delegationFakeRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail != nil {
		return nil, f.fail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.controls = append(f.controls, proto.Clone(request).(*authoritypb.Request))
	response := &authoritypb.Response{}
	switch {
	case request.GetFsync() != nil:
		response.Body = &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{DurableSequence: f.sequence}}
	case request.GetDelegationRecallAck() != nil:
		response.Body = &authoritypb.Response_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAckReply{}}
	case request.GetDelegationBreakAck() != nil:
		response.Body = &authoritypb.Response_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAckReply{}}
	case request.GetDelegationModeChangeAck() != nil:
		response.Body = &authoritypb.Response_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAckReply{}}
	case request.GetDelegationRelease() != nil:
		response.Body = &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}
	default:
		return nil, errors.New("unexpected idempotent request")
	}
	return response, nil
}

func delegationTestIdentity(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 16)
}

func delegationTestGrant(seed byte, mode authoritypb.DelegationMode) *authoritypb.Delegation {
	return &authoritypb.Delegation{Id: bytes.Repeat([]byte{seed}, 16), Generation: 1, Mode: mode}
}

func newDelegationTestManager(t *testing.T, fake delegationRPC) *delegationManager {
	t.Helper()
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	return m
}

func installDelegationForTest(t *testing.T, m *delegationManager, seed byte, mode authoritypb.DelegationMode) []byte {
	t.Helper()
	id := delegationTestIdentity(seed)
	if err := m.Install(id, []byte{seed, 1}, []byte{seed, 2}, delegationTestGrant(seed+32, mode)); err != nil {
		t.Fatal(err)
	}
	return id
}

func fakeControlCount(fake *delegationFakeRPC, matches func(*authoritypb.Request) bool) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	count := 0
	for _, request := range fake.controls {
		if matches(request) {
			count++
		}
	}
	return count
}

func TestDelegationWritebackChunksAndOrdersOneFile(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 1, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	data := bytes.Repeat([]byte{0xa5}, 2*writeback.MaxPayload+17)
	cut, err := m.Write(context.Background(), id, 19, data, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.mutations) != 0 {
		t.Fatal("FULL write reached Authority before flush")
	}
	if _, err := m.FlushIdentity(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if cut.Sequence == 0 || len(fake.mutations) != 3 {
		t.Fatalf("cut=%+v mutation count=%d, want three chunks", cut, len(fake.mutations))
	}
	for i, request := range fake.mutations {
		write := request.GetWrite()
		wantOffset := uint64(19 + i*writeback.MaxPayload)
		wantSize := writeback.MaxPayload
		if i == 2 {
			wantSize = 17
		}
		if write == nil || write.GetPosition() != wantOffset || len(write.GetData()) != wantSize || write.GetDelegation() == nil {
			t.Fatalf("chunk %d = %+v", i, write)
		}
	}
}

func TestDelegationWritebackHonorsNegotiatedLimitAndResumesToken(t *testing.T) {
	const limit = 64 << 10
	fake := &delegationLimitedRPC{delegationFakeRPC: delegationFakeRPC{maxWrite: limit}}
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	id := installDelegationForTest(t, m, 28, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	data := bytes.Repeat([]byte{0x5a}, 2*limit+19)
	if _, err := m.Write(context.Background(), id, 0, data, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FlushIdentity(context.Background(), id); err == nil {
		t.Fatal("first flush unexpectedly survived injected transient failure")
	}
	if _, err := m.FlushIdentity(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.mutations) != 3 {
		t.Fatalf("successful chunk mutations=%d, want 3", len(fake.mutations))
	}
	for i, request := range fake.mutations {
		write := request.GetWrite()
		wantOffset := uint64(i * limit)
		wantSize := limit
		if i == 2 {
			wantSize = 19
		}
		if write.GetPosition() != wantOffset || len(write.GetData()) != wantSize {
			t.Fatalf("chunk %d=(offset %d, size %d), want (%d, %d)", i, write.GetPosition(), len(write.GetData()), wantOffset, wantSize)
		}
	}
}

func TestDelegationWritebackPipelinesDisjointFiles(t *testing.T) {
	fake := &delegationPipelineRPC{started: make(chan byte, 2), release: make(chan struct{})}
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	idA := installDelegationForTest(t, m, 13, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	idB := installDelegationForTest(t, m, 14, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), idA, 0, []byte("a"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(context.Background(), idB, 0, []byte("b"), false); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { _, err := m.FlushIdentity(context.Background(), idA); done <- err }()
	go func() { _, err := m.FlushIdentity(context.Background(), idB); done <- err }()
	seen := make(map[byte]bool)
	for range 2 {
		select {
		case handle := <-fake.started:
			seen[handle] = true
		case <-time.After(time.Second):
			t.Fatal("disjoint identity flushes did not overlap")
		}
	}
	close(fake.release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("started handles=%v, want two disjoint files", seen)
	}
}

func TestDelegationWritethroughFlushesBeforeReturn(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 2, authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH)
	if _, err := m.Write(context.Background(), id, 0, []byte("now"), false); err != nil {
		t.Fatal(err)
	}
	if len(fake.mutations) != 1 || fake.mutations[0].GetWrite() == nil {
		t.Fatalf("mutations = %+v", fake.mutations)
	}
}

func TestDelegationReadAndAttributeOverlay(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 3, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 2, []byte("XY"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Truncate(context.Background(), id, 5); err != nil {
		t.Fatal(err)
	}
	got, err := m.Read(context.Background(), id, 0, 8, func(_ context.Context, offset int64, length int) ([]byte, error) {
		base := []byte("abcdefghi")
		return cloneBytes(base[offset : offset+int64(length)]), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abXYe" {
		t.Fatalf("overlay read = %q", got)
	}
	attrs, err := m.OverlayAttributes(id, writeback.Attributes{Size: 9, HasSize: true})
	if err != nil || !attrs.HasSize || attrs.Size != 5 {
		t.Fatalf("overlay attrs = %+v, err=%v", attrs, err)
	}
}

func TestDelegationMetadataFlushUsesRetainedOpenHandle(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 3, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.SetAttr(t.Context(), id, writeback.Attributes{HasMode: true, Mode: 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FlushIdentity(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, request := range fake.mutations {
		if set := request.GetSetAttr(); set != nil {
			if len(set.GetItem()) != 0 || len(set.GetHandle()) == 0 || set.Mode == nil || set.GetMode() != 0 {
				t.Fatalf("metadata flush must use the retained handle: %v", set)
			}
			return
		}
	}
	t.Fatal("no metadata flush")
}

func TestDelegationAdmissionChecksOwnershipBeforePublication(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := delegationTestIdentity(18)
	prepared := false
	ctx := context.WithValue(t.Context(), delegationPrepareContextKey{}, func() error { prepared = true; return nil })
	if _, err := m.Write(ctx, id, 0, []byte("pending"), false); !errors.Is(err, errDelegationNotOwned) || prepared {
		t.Fatalf("unowned admission = %v, prepared=%v", err, prepared)
	}
	installDelegationForTest(t, m, 18, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(ctx, id, 0, []byte("accepted"), false); err != nil || !prepared {
		t.Fatalf("owned admission=%v prepared=%v", err, prepared)
	}
}

func TestDelegationControlWaitsForGrantReplyAndRejectsResurrection(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := delegationTestIdentity(19)
	grant := delegationTestGrant(51, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(t.Context(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 1,
		Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
			Delegation: cloneDelegationRef(&authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}), Identity: id, BudgetNanos: uint64(time.Second),
		}}})
	if err := m.Install(id, []byte{19, 1}, []byte{19, 2}, grant); err != nil {
		t.Fatal(err)
	}
	m.controlWG.Wait()
	if fakeControlCount(fake, func(r *authoritypb.Request) bool { return r.GetDelegationRecallAck() != nil }) != 1 {
		t.Fatal("overtaking recall was not acknowledged")
	}
	if err := m.Install(id, []byte{19, 1}, []byte{19, 3}, grant); !errors.Is(err, errDelegationRetired) {
		t.Fatalf("retired grant reinstallation=%v", err)
	}
}

func TestDelegationSuccessorEmptyCutDoesNotReusePriorTicket(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 20, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseBatch(t.Context(), [][]byte{id}); err != nil {
		t.Fatal(err)
	}
	grant := delegationTestGrant(53, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	grant.Generation = 2
	if err := m.Install(id, []byte{20, 1}, []byte{20, 3}, grant); err != nil {
		t.Fatal(err)
	}
	m.HandleControlEvent(t.Context(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 1, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{
		Delegation: &authoritypb.DelegationRef{Id: grant.Id, Generation: 2}, Identity: id, BudgetNanos: uint64(time.Second),
	}}})
	m.controlWG.Wait()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, r := range fake.controls {
		if ack := r.GetDelegationBreakAck(); ack != nil {
			if ack.GetAppliedSequence() != 0 {
				t.Fatalf("empty successor cut=%d", ack.GetAppliedSequence())
			}
			return
		}
	}
	t.Fatal("no break acknowledgment")
}

func TestDelegationBreakFlushesCutAndRetainsOwnership(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 4, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	grant := delegationTestGrant(36, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 1, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{
		Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: grant.GetGeneration()}, Identity: id, BudgetNanos: uint64(time.Second),
	}}})
	m.controlWG.Wait()
	if len(fake.mutations) != 1 || fakeControlCount(fake, func(request *authoritypb.Request) bool { return request.GetDelegationBreakAck() != nil }) != 1 {
		t.Fatalf("mutations=%d break acks=%d", len(fake.mutations), fakeControlCount(fake, func(request *authoritypb.Request) bool { return request.GetDelegationBreakAck() != nil }))
	}
	if _, err := m.Write(context.Background(), id, 3, []byte("new"), false); err != nil {
		t.Fatalf("write after break: %v", err)
	}
}

func TestDelegationRecallFlushesThenWithdraws(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 5, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("dirty"), false); err != nil {
		t.Fatal(err)
	}
	grant := delegationTestGrant(37, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 2, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
		Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id, BudgetNanos: uint64(time.Second),
	}}})
	m.controlWG.Wait()
	if fakeControlCount(fake, func(request *authoritypb.Request) bool { return request.GetDelegationRecallAck() != nil }) != 1 {
		t.Fatal("recall acknowledgment was not sent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.Write(ctx, id, 0, []byte("refused"), false); err == nil {
		t.Fatal("write after recall succeeded")
	}
}

func TestDelegationRecallStopsServingRetainedOverlay(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 30, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	grant := delegationTestGrant(62, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{
		Incarnation: 7, Sequence: 21, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
			Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id, BudgetNanos: uint64(time.Second),
		}},
	})
	m.controlWG.Wait()
	got, err := m.Read(context.Background(), id, 0, 3, func(context.Context, int64, int) ([]byte, error) {
		return []byte("new"), nil
	})
	if err != nil || string(got) != "new" {
		t.Fatalf("read after recall=(%q, %v), want peer Authority bytes", got, err)
	}
	if size, err := m.Size(id, 99); err != nil || size != 99 {
		t.Fatalf("size after recall=(%d, %v), want base size", size, err)
	}
	attrs, err := m.OverlayAttributes(id, writeback.Attributes{HasSize: true, Size: 99})
	if err != nil || attrs.Size != 99 {
		t.Fatalf("attributes after recall=(%+v, %v), want base", attrs, err)
	}
}

func TestDelegationReacquireCannotRevivePriorOverlay(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 31, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	oldGrant := delegationTestGrant(63, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{
		Incarnation: 7, Sequence: 22, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
			Delegation: &authoritypb.DelegationRef{Id: oldGrant.GetId(), Generation: 1}, Identity: id, BudgetNanos: uint64(time.Second),
		}},
	})
	m.controlWG.Wait()
	newGrant := &authoritypb.Delegation{
		Id: bytes.Repeat([]byte{0x7f}, 16), Generation: 2, Mode: authoritypb.DelegationMode_DELEGATION_MODE_FULL,
	}
	if err := m.Install(id, []byte{31, 1}, []byte{31, 3}, newGrant); err != nil {
		t.Fatal(err)
	}
	got, err := m.Read(context.Background(), id, 0, 3, func(context.Context, int64, int) ([]byte, error) {
		return []byte("new"), nil
	})
	if err != nil || string(got) != "new" {
		t.Fatalf("read after reacquire=(%q, %v), want peer Authority bytes", got, err)
	}
}

func TestDelegationRecallBudgetMissDropsAndAdvancesLoss(t *testing.T) {
	blocked := make(chan struct{})
	fake := &delegationFakeRPC{block: blocked}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 6, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("lost"), false); err != nil {
		t.Fatal(err)
	}
	grant := delegationTestGrant(38, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 3, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
		Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id, BudgetNanos: uint64(10 * time.Millisecond),
	}}})
	m.controlWG.Wait()
	if got := m.IdentityLoss(id); got == 0 || m.LossSequence() == 0 {
		t.Fatalf("identity loss=%d mount loss=%d", got, m.LossSequence())
	}
}

func TestDelegationModeChangeDowngradeAndUpgrade(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 7, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	grant := delegationTestGrant(39, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	modeEvent := func(sequence uint64, mode authoritypb.DelegationMode) *authoritypb.ControlEvent {
		return &authoritypb.ControlEvent{Incarnation: 7, Sequence: sequence, Event: &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{
			Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id, Mode: mode, BudgetNanos: uint64(time.Second),
		}}}
	}
	m.HandleControlEvent(context.Background(), modeEvent(4, authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH))
	m.controlWG.Wait()
	if _, err := m.Write(context.Background(), id, 0, []byte("through"), false); err != nil {
		t.Fatal(err)
	}
	if len(fake.mutations) != 1 {
		t.Fatal("downgraded write was not synchronous")
	}
	m.HandleControlEvent(context.Background(), modeEvent(5, authoritypb.DelegationMode_DELEGATION_MODE_FULL))
	m.controlWG.Wait()
	if _, err := m.Write(context.Background(), id, 7, []byte("buffered"), false); err != nil {
		t.Fatal(err)
	}
	if len(fake.mutations) != 1 {
		t.Fatal("upgraded write was not buffered")
	}
}

func TestDelegationControlEventsPreservePerIdentityDeliveryOrder(t *testing.T) {
	fake := &delegationOrderedControlRPC{firstStarted: make(chan struct{}), releaseFirst: make(chan struct{})}
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	id := installDelegationForTest(t, m, 24, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	grant := delegationTestGrant(56, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{
		Incarnation: 7, Sequence: 10, Event: &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{
			Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id,
			Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, BudgetNanos: uint64(time.Second),
		}},
	})
	select {
	case <-fake.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first mode transition did not reach its acknowledgment")
	}
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{
		Incarnation: 7, Sequence: 11, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
			Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id, BudgetNanos: uint64(time.Second),
		}},
	})
	time.Sleep(20 * time.Millisecond)
	if got := fakeControlCount(&fake.delegationFakeRPC, func(request *authoritypb.Request) bool { return request.GetDelegationRecallAck() != nil }); got != 0 {
		t.Fatalf("recall overtook blocked mode transition: ack count=%d", got)
	}
	close(fake.releaseFirst)
	m.controlWG.Wait()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var order []uint64
	for _, request := range fake.controls {
		if ack := request.GetDelegationModeChangeAck(); ack != nil {
			order = append(order, ack.GetEventSequence())
		}
		if ack := request.GetDelegationRecallAck(); ack != nil {
			order = append(order, ack.GetEventSequence())
		}
	}
	if len(order) != 2 || order[0] != 10 || order[1] != 11 {
		t.Fatalf("control acknowledgment order=%v, want [10 11]", order)
	}
	if m.Owns(id) {
		t.Fatal("ordered recall retained delegation ownership")
	}
}

func TestDelegationSynchronousFlushesBeforeOperation(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 8, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	called := false
	response, err := m.Synchronous(context.Background(), id, func(ref *authoritypb.DelegationRef) (*authoritypb.Response, error) {
		called = true
		if len(fake.mutations) != 1 || ref == nil {
			t.Fatalf("callback observed mutations=%d ref=%v", len(fake.mutations), ref)
		}
		return &authoritypb.Response{AppliedSequence: 2}, nil
	})
	if err != nil || response.GetAppliedSequence() != 2 || !called {
		t.Fatalf("response=%v called=%t err=%v", response, called, err)
	}
}

func TestDelegationSynchronousRetiresOverlayBeforeExternalMutation(t *testing.T) {
	fake := &delegationBlockedBarrierRPC{barrierStarted: make(chan struct{}), releaseBarrier: make(chan struct{})}
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	id := installDelegationForTest(t, m, 27, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := m.Synchronous(context.Background(), id, func(*authoritypb.DelegationRef) (*authoritypb.Response, error) {
			close(called)
			return &authoritypb.Response{AppliedSequence: 2}, nil
		})
		done <- err
	}()
	select {
	case <-fake.barrierStarted:
	case <-time.After(time.Second):
		t.Fatal("prior write did not enter durability barrier")
	}
	select {
	case <-called:
		t.Fatal("external mutation ran before prior overlay retired")
	default:
	}
	close(fake.releaseBarrier)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := m.Read(context.Background(), id, 0, 3, func(context.Context, int64, int) ([]byte, error) {
		return []byte("new"), nil
	})
	if err != nil || string(got) != "new" {
		t.Fatalf("post-mutation overlay read=(%q, %v), want Authority bytes", got, err)
	}
}

func TestDelegationDurabilityPumpReleasesCapacity(t *testing.T) {
	fake := &delegationFakeRPC{}
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{MaxEntries: 1, FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	id := installDelegationForTest(t, m, 12, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("one"), false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := m.Write(ctx, id, 3, []byte("two"), false); err != nil {
		t.Fatalf("second write remained blocked at retained-entry cap: %v", err)
	}
	fake.mu.Lock()
	barriers := fake.barriers
	fake.mu.Unlock()
	if barriers == 0 {
		t.Fatal("capacity was released without a durability barrier")
	}
	m.mu.Lock()
	m.durabilityMu.Lock()
	durable := m.durableHigh
	m.durabilityMu.Unlock()
	m.tokenMu.Lock()
	var retiredTokens int
	for _, progress := range m.tokens {
		if progress.complete && progress.sequence <= durable {
			retiredTokens++
		}
	}
	m.tokenMu.Unlock()
	m.mu.Unlock()
	if retiredTokens != 0 {
		t.Fatalf("durable completed tokens retained=%d, want 0", retiredTokens)
	}
}

func TestDelegationColdLookupsDoNotAllocateState(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := delegationTestIdentity(29)
	if m.Owns(id) {
		t.Fatal("unknown identity reported delegation ownership")
	}
	if attr, ok := m.BaseAttr(id); ok || attr != nil {
		t.Fatalf("unknown identity base attr=(%v, %t)", attr, ok)
	}
	if err := m.SetBaseAttr(id, &authoritypb.Attr{Size: 1}, 1); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	states := len(m.byID)
	m.mu.Unlock()
	if states != 0 {
		t.Fatalf("cold delegation lookups allocated %d states", states)
	}
}

func TestDelegationEpochChangeDoesNotStarveSyncDurability(t *testing.T) {
	fake := &delegationEpochSyncRPC{writeStarted: make(chan struct{}), releaseWrite: make(chan struct{})}
	m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	id := installDelegationForTest(t, m, 25, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	written := make(chan error, 1)
	go func() {
		_, err := m.Write(context.Background(), id, 0, []byte("sync"), true)
		written <- err
	}()
	select {
	case <-fake.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("synchronous write did not reach the Authority")
	}
	epochDone := make(chan struct{})
	go func() {
		m.EpochChanged("test epoch")
		close(epochDone)
	}()
	// Let the epoch writer queue behind WriteSync's read lock before the write
	// reply kicks the independent durability pump.
	time.Sleep(20 * time.Millisecond)
	close(fake.releaseWrite)
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("synchronous write starved its durability pump behind epoch change")
	}
	select {
	case <-epochDone:
	case <-time.After(time.Second):
		t.Fatal("epoch change did not finish after synchronous durability")
	}
}

func TestDelegationReleaseBatchSortsAndFlushes(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	idHigh := installDelegationForTest(t, m, 20, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	idLow := installDelegationForTest(t, m, 10, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), idHigh, 0, []byte("high"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(context.Background(), idLow, 0, []byte("low"), false); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseBatch(context.Background(), [][]byte{idHigh, idLow}); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	var request *authoritypb.DelegationReleaseRequest
	for _, control := range fake.controls {
		if control.GetDelegationRelease() != nil {
			request = proto.Clone(control.GetDelegationRelease()).(*authoritypb.DelegationReleaseRequest)
		}
	}
	fake.mu.Unlock()
	if request == nil || len(request.GetDelegations()) != 2 {
		t.Fatalf("release = %+v", request)
	}
	if bytes.Compare(request.GetDelegations()[0].GetDelegation().GetId(), request.GetDelegations()[1].GetDelegation().GetId()) >= 0 {
		t.Fatal("release batch is not sorted by delegation id")
	}
	if len(fake.mutations) != 2 {
		t.Fatalf("flush mutations=%d, want 2", len(fake.mutations))
	}
}

func TestDelegationQueueCloseBatchesFinalHandles(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	idHigh := installDelegationForTest(t, m, 22, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	idLow := installDelegationForTest(t, m, 21, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), idHigh, 0, []byte("high"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(context.Background(), idLow, 0, []byte("low"), false); err != nil {
		t.Fatal(err)
	}
	if err := m.QueueClose(idHigh, []byte{22, 2}, 17, true); err != nil {
		t.Fatal(err)
	}
	if err := m.QueueClose(idLow, []byte{21, 2}, 19, false); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		fake.mu.Lock()
		var release *authoritypb.DelegationReleaseRequest
		closes := make([]*authoritypb.CloseRequest, 0, 2)
		for _, request := range fake.controls {
			if request.GetDelegationRelease() != nil {
				release = request.GetDelegationRelease()
			}
		}
		for _, request := range fake.mutations {
			if request.GetClose() != nil {
				closes = append(closes, request.GetClose())
			}
		}
		fake.mu.Unlock()
		if release != nil && len(release.GetDelegations()) == 2 && len(closes) == 2 {
			if bytes.Compare(release.GetDelegations()[0].GetDelegation().GetId(), release.GetDelegations()[1].GetDelegation().GetId()) >= 0 {
				t.Fatal("queued release batch is not sorted by delegation id")
			}
			if closes[0].GetLockOwner() != 17 || !closes[0].GetFlockUnlock() || closes[1].GetLockOwner() != 19 || closes[1].GetFlockUnlock() {
				t.Fatalf("close requests = %+v", closes)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("release=%+v closes=%+v", release, closes)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDelegationQueuedCloseIsFencedByEpochChange(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 23, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if err := m.QueueClose(id, []byte{23, 2}, 0, false); err != nil {
		t.Fatal(err)
	}
	m.EpochChanged("test epoch")
	time.Sleep(30 * time.Millisecond)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, request := range fake.mutations {
		if request.GetClose() != nil {
			t.Fatal("old-epoch close reached the replacement session")
		}
	}
	for _, request := range fake.controls {
		if request.GetDelegationRelease() != nil {
			t.Fatal("old-epoch delegation release reached the replacement session")
		}
	}
}

func TestDelegationEpochChangeWithoutDirtyDataPreservesLoss(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	installDelegationForTest(t, m, 11, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	before := m.LossSequence()
	m.EpochChanged("clean epoch")
	if got := m.LossSequence(); got != before {
		t.Fatalf("clean epoch loss=%d, want %d", got, before)
	}
}

func TestDelegationSubscriptionFenceDropsOldBufferAndAllowsColdGrant(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 32, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	n := &node{mount: &Mount{delegations: m}, item: &authoritypb.Item{StableIdentity: cloneBytes(id)}}
	existing := &fileHandle{node: n, lossObserved: m.IdentityLoss(id)}
	if _, err := m.Write(context.Background(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	before := m.LossSequence()
	m.FenceSubscription("cold resubscribe")
	if got := m.LossSequence(); got <= before {
		t.Fatalf("subscription fence loss=%d, want greater than %d", got, before)
	}
	if m.Owns(id) {
		t.Fatal("subscription fence retained old delegation")
	}
	if _, err := m.Write(context.Background(), id, 0, []byte("fenced"), false); err == nil {
		t.Fatal("write admitted while subscription was fenced")
	}
	newGrant := &authoritypb.Delegation{Id: bytes.Repeat([]byte{0x6d}, 16), Generation: 2, Mode: authoritypb.DelegationMode_DELEGATION_MODE_FULL}
	if err := m.Install(id, []byte{32, 1}, []byte{32, 3}, newGrant); err == nil {
		t.Fatal("grant installed before cold subscription incarnation")
	}
	m.SetIncarnation(8)
	if existing.observeLoss() != syscall.EIO {
		t.Fatal("existing handle missed loss retained across cold reset")
	}
	if existing.observeLoss() != 0 {
		t.Fatal("existing handle reported the same retained loss twice")
	}
	newHandle := &fileHandle{node: n, lossObserved: m.IdentityLoss(id)}
	if newHandle.observeLoss() != 0 {
		t.Fatal("new handle did not start at retained identity loss")
	}
	if err := m.Install(id, []byte{32, 1}, []byte{32, 3}, newGrant); err != nil {
		t.Fatal(err)
	}
	got, err := m.Read(context.Background(), id, 0, 3, func(context.Context, int64, int) ([]byte, error) {
		return []byte("new"), nil
	})
	if err != nil || string(got) != "new" {
		t.Fatalf("read after cold grant=(%q, %v), want new Authority bytes", got, err)
	}
}

func TestDelegationBarrierReportsPriorLoss(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 9, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	observed := m.LossSequence()
	if _, err := m.Write(context.Background(), id, 0, []byte("lost"), false); err != nil {
		t.Fatal(err)
	}
	m.EpochChanged("test epoch")
	if err := m.Barrier(context.Background(), observed); !errors.Is(err, writeback.ErrLost) {
		t.Fatalf("barrier err=%v, want ErrLost", err)
	}
}

func TestDelegationBarrierRunsWithWithdrawnIdentity(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 26, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	grant := delegationTestGrant(58, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	m.HandleControlEvent(context.Background(), &authoritypb.ControlEvent{
		Incarnation: 7, Sequence: 20, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
			Delegation: &authoritypb.DelegationRef{Id: grant.GetId(), Generation: 1}, Identity: id, BudgetNanos: uint64(time.Second),
		}},
	})
	m.controlWG.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Barrier(ctx, m.LossSequence()); err != nil {
		t.Fatalf("barrier after recall: %v", err)
	}
}

func BenchmarkDelegationOwns(b *testing.B) {
	for _, hot := range []bool{false, true} {
		name := "cold"
		if hot {
			name = "delegated"
		}
		b.Run(name, func(b *testing.B) {
			fake := &delegationFakeRPC{}
			m, err := newDelegationManager(fake, time.Second, 7, writeback.Options{FlushInterval: -1})
			if err != nil {
				b.Fatal(err)
			}
			defer m.Stop()
			id := delegationTestIdentity(33)
			if hot {
				if err := m.Install(id, []byte{33, 1}, []byte{33, 2}, delegationTestGrant(65, authoritypb.DelegationMode_DELEGATION_MODE_FULL)); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = m.Owns(id)
			}
		})
	}
}

func TestDelegationFlushKeepsWritableCapabilityUntilApplication(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 21, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	writer, reader := []byte{21, 2}, []byte{1, 1}
	if err := m.AddHandle(id, []byte{21, 1}, reader, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: writer}}); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	for _, request := range fake.mutations {
		if write := request.GetWrite(); write != nil && !bytes.Equal(write.Handle, writer) {
			t.Errorf("flush used non-writable handle %x", write.Handle)
		}
	}
	fake.mu.Unlock()
	if m.TracksHandle(id, writer) || !m.TracksHandle(id, reader) {
		t.Fatal("closed writable handle remains registered or reader disappeared")
	}
	if m.LossSequence() != 0 {
		t.Fatal("closing writer reported loss")
	}
}

func TestDelegationReaderOpenRemainsValidWhenLastWriterReleaseWins(t *testing.T) {
	for _, state := range []string{"unseen", "live", "retired"} {
		t.Run(state, func(t *testing.T) {
			m := newDelegationTestManager(t, &delegationFakeRPC{})
			id := delegationTestIdentity(22)
			if state != "unseen" {
				id = installDelegationForTest(t, m, 22, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			}
			if state == "retired" {
				if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: []byte{22, 2}}}); err != nil {
					t.Fatal(err)
				}
			}
			reader := []byte{22, 3}
			err := m.AddHandle(id, []byte{22, 1}, reader, false)
			if state == "retired" {
				if !errors.Is(err, errDelegationRetired) {
					t.Fatalf("retired generation registration = %v, want retirement sentinel", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got := m.TracksHandle(id, reader); got != (state == "live") {
				t.Fatalf("reader tracking=%t for %s", got, state)
			}
			// The frontend preserves an Authority OPEN even if its local grant
			// retired before registration; it closes as an ordinary handle.
			n := &node{mount: &Mount{delegations: m}, item: &authoritypb.Item{StableIdentity: id, Token: []byte{22, 1}}}
			if err := n.registerDelegatedHandle(&fileHandle{node: n, token: reader}, nil); err != nil {
				t.Fatalf("successful read OPEN failed registration: %v", err)
			}
		})
	}
}

func TestDelegatedWriteRejectsMissingPostAttributes(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{omitPostAttr: true})
	id := installDelegationForTest(t, m, 61, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(context.Background(), id, 0, []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FlushIdentity(context.Background(), id); !errors.Is(err, writeback.ErrLost) {
		t.Fatalf("missing post attributes = %v, want loss", err)
	}
}

func TestDelegatedAttributeOverlayUsesCurrentBaseAfterDurability(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 62, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	old := &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Mode: 0o6755, MtimeNs: 11, CtimeNs: 12}
	if err := m.SetBaseAttr(id, old, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(context.Background(), id, 0, []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	sampled, ok := m.BaseAttr(id)
	if !ok {
		t.Fatal("missing sampled base")
	}
	seq, err := m.FlushIdentity(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	applied := &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: 1, Mode: 0o755, MtimeNs: 21, CtimeNs: 22}
	if err := m.SetBaseAttr(id, applied, 2); err != nil {
		t.Fatal(err)
	}
	m.DurableSequence(seq)
	mount := &Mount{delegations: m}
	got, err := mount.overlayProtoAttr(id, sampled, 1)
	if err != nil || got.GetMtimeNs() != 21 || got.GetCtimeNs() != 22 || got.GetMode() != 0o755 {
		t.Fatalf("retired overlay exposed sampled base: %v, %v", got, err)
	}
}

func TestDelegatedBaseVersionsOrderRepliesAndInvalidations(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 63, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	mount := &Mount{delegations: m}
	attr := func(links uint32) *authoritypb.Attr {
		return &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Nlink: links}
	}
	if err := m.SetBaseAttr(id, attr(2), 10); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                   string
		incoming, invalidation uint64
		links, want            uint32
	}{
		{"newer namespace metadata", 11, 0, 1, 1},
		{"older delayed lookup", 10, 0, 2, 1},
		{"older withdrawal preserves new base", 10, 9, 2, 1},
		{"exact committed version survives withdrawal", 11, 11, 1, 1},
		{"newer withdrawal forces refetch", 12, 12, 3, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.invalidation != 0 {
				m.InvalidateBaseAttr(id, tc.invalidation)
			}
			if tc.invalidation == 12 {
				if _, ok := m.BaseAttr(id); ok {
					t.Fatal("withdrawn base still available")
				}
				if err := m.SetBaseAttr(id, attr(2), 10); err != nil {
					t.Fatal(err)
				}
				if _, ok := m.BaseAttr(id); ok {
					t.Fatal("old reply resurrected withdrawn base")
				}
			}
			got, err := mount.overlayProtoAttr(id, attr(tc.links), tc.incoming)
			if err != nil || got.GetNlink() != tc.want {
				t.Fatalf("base order: %v, %v; want links=%d", got, err, tc.want)
			}
		})
	}
}

func TestDelegatedMetadataRejectsMissingPostAttributes(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{omitPostAttr: true})
	id := installDelegationForTest(t, m, 64, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Truncate(context.Background(), id, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FlushIdentity(context.Background(), id); !errors.Is(err, writeback.ErrLost) {
		t.Fatalf("missing metadata post attributes = %v, want loss", err)
	}
}

func TestDelegationTruncationAlwaysFlushesThroughWritableHandle(t *testing.T) {
	for _, kind := range []writeback.Kind{writeback.Truncate, writeback.SetAttr} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			fake := &delegationFakeRPC{}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 65, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			writer := []byte{65, 2}
			for i := byte(3); i < 35; i++ {
				if err := m.AddHandle(id, []byte{65, 1}, []byte{65, i}, false); err != nil {
					t.Fatal(err)
				}
			}
			for size := int64(1); size <= 32; size++ {
				var err error
				if kind == writeback.Truncate {
					_, err = m.Truncate(t.Context(), id, size)
				} else {
					_, err = m.SetAttr(t.Context(), id, writeback.Attributes{Size: size, HasSize: true})
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := m.FlushIdentity(t.Context(), id); err != nil {
					t.Fatal(err)
				}
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			for _, request := range fake.mutations {
				if set := request.GetSetAttr(); set != nil && !bytes.Equal(set.GetHandle(), writer) {
					t.Fatalf("truncate used read-only handle: %v", set)
				}
			}
		})
	}
}

func TestDelegationCloseBatchAppliesAllFilesBeforeWaitingForDurability(t *testing.T) {
	fake := &delegationBlockedBarrierRPC{barrierStarted: make(chan struct{}), releaseBarrier: make(chan struct{})}
	m := newDelegationTestManager(t, fake)
	var closes []delegationClose
	for i := byte(1); i <= 16; i++ {
		id := installDelegationForTest(t, m, i, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
		if _, err := m.Write(t.Context(), id, 0, []byte("batch"), false); err != nil {
			t.Fatal(err)
		}
		closes = append(closes, delegationClose{identity: id, handle: []byte{i, 2}})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.CloseHandles(ctx, closes) }()
	deadline := time.Now().Add(time.Second)
	for {
		fake.mu.Lock()
		writes := 0
		for _, request := range fake.mutations {
			if request.GetWrite() != nil {
				writes++
			}
		}
		releases := len(fake.controls)
		fake.mu.Unlock()
		if releases != 0 {
			t.Fatal("released ownership before durability")
		}
		if writes == len(closes) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d writes applied while durability was blocked", writes, len(closes))
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("close returned before durability: %v", err)
	default:
	}
	close(fake.releaseBarrier)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("close batch did not complete")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.controls) != 1 || len(fake.controls[0].GetDelegationRelease().GetDelegations()) != len(closes) {
		t.Fatalf("release was not one complete batch: %v", fake.controls)
	}
}

func TestDeferredCloseBacklogBlocksNewHandleAdmissionUntilCleanup(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	fake := &delegationFakeRPC{block: release}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 17, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	handles := make([][]byte, 0, deferredCloseAdmissionLimit)
	for i := 0; i < deferredCloseAdmissionLimit; i++ {
		handle := []byte{17, 2}
		if i != 0 {
			handle = []byte{17, 3, byte(i)}
			if err := m.AddHandle(id, []byte{17, 1}, handle, false); err != nil {
				t.Fatal(err)
			}
		}
		handles = append(handles, handle)
	}
	for _, handle := range handles {
		if err := m.QueueClose(id, handle, 0, false); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := m.waitCloseCapacity(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("new handle bypassed deferred-close backpressure: %v", err)
	}
	once.Do(func() { close(release) })
	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := m.waitCloseCapacity(ctx); err != nil {
		t.Fatalf("cleanup did not resume handle admission: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		m.closeMu.Lock()
		pending := m.closePending
		m.closeMu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending closes did not retire: %d", pending)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDeferredCloseShutdownJoinsRacingEnqueues(t *testing.T) {
	for range 20 {
		m := newDelegationTestManager(t, &delegationFakeRPC{})
		start := make(chan struct{})
		var producers sync.WaitGroup
		for worker := range 8 {
			producers.Add(1)
			go func() {
				defer producers.Done()
				<-start
				for i := range 100 {
					err := m.QueueClose(delegationTestIdentity(17), []byte{17, byte(worker), byte(i)}, 0, false)
					if err != nil && !errors.Is(err, writeback.ErrClosed) {
						t.Errorf("queue: %v", err)
					}
				}
			}()
		}
		close(start)
		m.Stop()
		producers.Wait()
		m.closeMu.Lock()
		pending := m.closePending
		m.closeMu.Unlock()
		if pending != 0 || len(m.closeQueue) != 0 {
			t.Fatalf("shutdown stranded closes: pending=%d queued=%d", pending, len(m.closeQueue))
		}
	}
}

type delegationRefusalRPC struct {
	delegationFakeRPC
	refusal *authoritypb.Response
}

func (f *delegationRefusalRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetWrite() != nil || request.GetSetAttr() != nil {
		f.mu.Lock()
		response := f.refusal
		f.mu.Unlock()
		if response != nil {
			return response, nil
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func TestDelegationCapacityRefusalPreservesGrantAndErrno(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSPC, syscall.EDQUOT, syscall.EFBIG} {
		for _, operation := range []string{"write", "setattr", "sync-write"} {
			t.Run(fmt.Sprintf("%s/%s", errno, operation), func(t *testing.T) {
				fake := &delegationRefusalRPC{refusal: &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Error: -int32(errno)}}}}
				if operation == "setattr" {
					fake.refusal = &authoritypb.Response{Errno: int32(errno)}
				}
				m := newDelegationTestManager(t, fake)
				id := installDelegationForTest(t, m, 87, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
				n := &node{mount: &Mount{delegations: m}, item: &authoritypb.Item{StableIdentity: cloneBytes(id)}}
				syncHandle, closeHandle := &fileHandle{node: n}, &fileHandle{node: n}
				writeHandle := &fileHandle{node: n}
				before := m.LossSequence()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				var err error
				switch operation {
				case "setattr":
					_, err = m.Truncate(ctx, id, 5)
				case "sync-write":
					_, err = m.Write(ctx, id, 0, []byte("quota"), true)
				default:
					_, err = m.Write(ctx, id, 0, []byte("quota"), false)
				}
				if operation != "sync-write" {
					if err != nil {
						t.Fatal(err)
					}
					_, err = m.FlushIdentity(ctx, id)
				}
				if !errors.Is(err, errno) {
					t.Fatalf("flush refusal = %v, want %v", err, errno)
				}
				if !m.Owns(id) {
					t.Fatal("capacity refusal retired delegation")
				}
				if m.LossSequence() <= before {
					t.Fatal("discarded write did not advance loss")
				}
				if got := writeHandle.observeLoss(); got != errno {
					t.Fatalf("next write observation = %v, want %v", got, errno)
				}
				if got := writeHandle.observeLoss(); got != 0 {
					t.Fatalf("repeated observation = %v", got)
				}
				if got := n.Fsync(ctx, syncHandle, 0); got != errno {
					t.Fatalf("fsync = %v, want %v", got, errno)
				}
				if got := n.Flush(ctx, closeHandle, 0); got != errno {
					t.Fatalf("close flush = %v, want %v", got, errno)
				}
				if err := m.Barrier(ctx, before); !errors.Is(err, errno) {
					t.Fatalf("root barrier = %v, want %v", err, errno)
				}
				fake.mu.Lock()
				fake.refusal = nil
				fake.mu.Unlock()
				if _, err := m.Write(ctx, id, 0, []byte("retry"), false); err != nil {
					t.Fatal(err)
				}
				if _, err := m.FlushIdentity(ctx, id); err != nil {
					t.Fatalf("retained grant cannot flush successor generation: %v", err)
				}
			})
		}
	}
}

func TestDelegationCapacityRefusalRequiresUnappliedReply(t *testing.T) {
	for _, test := range []struct {
		name     string
		response *authoritypb.Response
	}{
		{"coherence", &authoritypb.Response{Errno: int32(syscall.ENOSPC), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}},
		{"applied", &authoritypb.Response{Errno: int32(syscall.ENOSPC), AppliedSequence: 1}},
		{"partial", &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Error: -int32(syscall.ENOSPC), CommittedSize: 1}}}},
		{"post attributes", &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Error: -int32(syscall.ENOSPC), PostAttr: &authoritypb.Attr{}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := definiteDelegationCapacityRefusal(test.response, true); got != 0 {
				t.Fatalf("uncertain reply classified as definite capacity refusal: %v", got)
			}
		})
	}
}

func TestUncertainCapacityRefusalLosesDelegation(t *testing.T) {
	fake := &delegationRefusalRPC{refusal: &authoritypb.Response{Errno: int32(syscall.ENOSPC), Uncertain: true}}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 88, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("uncertain"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FlushIdentity(t.Context(), id); !errors.Is(err, writeback.ErrLost) {
		t.Fatalf("uncertain flush = %v", err)
	}
	if m.Owns(id) || m.IdentityLoss(id) == 0 {
		t.Fatal("uncertain quota reply preserved grant or failed to record loss")
	}
}
