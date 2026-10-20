//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

type orderedFlushFake struct {
	delegationFakeRPC
	permits      chan struct{}
	entered      chan uint64
	release      <-chan struct{}
	active, peak atomic.Int32
	muOrder      sync.Mutex
	assigned     []uint64
	fail         map[uint64]error
	errno        map[uint64]syscall.Errno
}

func (f *orderedFlushFake) CallMutation(ctx context.Context, r *authoritypb.Request) (*authoritypb.Response, error) {
	if r.GetBarrier() != nil {
		return nil, errors.New("durability held for pipeline test")
	}
	return f.delegationFakeRPC.CallMutation(ctx, r)
}
func (f *orderedFlushFake) CallMutationSegments(ctx context.Context, r *authoritypb.Request, pieces [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	select {
	case f.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-f.permits }()
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for old := f.peak.Load(); n > old; old = f.peak.Load() {
		if f.peak.CompareAndSwap(old, n) {
			break
		}
	}
	w := r.GetWrite()
	// The client takes the ordinal inside replay assignment, before dispatch.
	// The record shares the assignment's critical section: the manager
	// launches a successor as soon as its predecessor's assignment returns, so
	// a record taken afterwards could land out of admission order.
	f.muOrder.Lock()
	if err := assigned(authorityrpc.MutationIdentity{}); err != nil {
		f.muOrder.Unlock()
		return nil, err
	}
	ordinal := w.GetFlushSequence()
	f.assigned = append(f.assigned, ordinal)
	f.muOrder.Unlock()
	f.entered <- ordinal
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := f.fail[ordinal]; err != nil {
		return nil, err
	}
	if errno := f.errno[ordinal]; errno != 0 {
		return &authoritypb.Response{Errno: int32(errno)}, nil
	}
	size := 0
	for _, piece := range pieces {
		size += len(piece)
	}
	if size != int(w.Size) || len(w.Data) != 0 {
		return nil, errors.New("scatter size/carrier mismatch")
	}
	return &authoritypb.Response{AppliedSequence: ordinal, VolumeVersion: ordinal + 100, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{CommittedSize: uint64(size), AssignedOffset: w.Position, PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: int64(w.Position) + int64(size)}}}}, nil
}
func pipelineFake(release <-chan struct{}) *orderedFlushFake {
	return &orderedFlushFake{delegationFakeRPC: delegationFakeRPC{maxWrite: 8}, permits: make(chan struct{}, 4), entered: make(chan uint64, 32), release: release}
}
func TestDelegationPipelineAdmitsFourChunksBeforeJoining(t *testing.T) {
	release := make(chan struct{})
	f := pipelineFake(release)
	m := newDelegationTestManager(t, f)
	id := installDelegationForTest(t, m, 101, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("abcdefghijklmnopqrstuvwxyz0123456789ABCD"), false); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() { _, err := m.FlushIdentity(ctx, id); done <- err }()
	for range 4 {
		select {
		case <-f.entered:
		case <-ctx.Done():
			close(release)
			t.Fatal("four chunks never entered together")
		}
	}
	select {
	case seq := <-f.entered:
		close(release)
		t.Fatalf("fifth chunk %d entered before first wave completed", seq)
	default:
	}
	if f.peak.Load() != 4 {
		close(release)
		t.Fatalf("peak=%d", f.peak.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.muOrder.Lock()
	defer f.muOrder.Unlock()
	if len(f.assigned) != 5 {
		t.Fatalf("chunks=%v", f.assigned)
	}
	for i, seq := range f.assigned {
		if seq != uint64(i+1) {
			t.Fatalf("predecessor admission was reordered: %v", f.assigned)
		}
	}
}
func TestDelegationPipelineReducesFailuresOnceAfterJoining(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "capacity", true: "uncertainty dominates capacity"}[uncertain], func(t *testing.T) {
			release := make(chan struct{})
			close(release)
			f := pipelineFake(release)
			f.errno = map[uint64]syscall.Errno{1: syscall.ENOSPC, 3: syscall.EDQUOT}
			if uncertain {
				f.fail = map[uint64]error{4: authorityrpc.ErrTransportUncertain}
			}
			m := newDelegationTestManager(t, f)
			id := installDelegationForTest(t, m, 102, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), id, 0, []byte("abcdefghijklmnopqrstuvwxyz012345"), false); err != nil {
				t.Fatal(err)
			}
			_, err := m.FlushIdentity(t.Context(), id)
			if uncertain && !errors.Is(err, writeback.ErrLost) || !uncertain && !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("wave error=%v", err)
			}
			parsed, _ := delegationIdentity(id)
			if m.LossSequence() != 1 || m.buf.Stats().Entries != 0 || f.active.Load() != 0 {
				t.Fatalf("wave did not join/drop exactly once: loss=%d stats=%+v active=%d", m.LossSequence(), m.buf.Stats(), f.active.Load())
			}
			if delegationStateOwned(m.state(parsed)) == uncertain {
				t.Fatal("wave failure chose wrong grant disposition")
			}
			if !uncertain {
				if _, err := m.Write(t.Context(), id, 0, []byte("next"), false); err != nil {
					t.Fatal(err)
				}
				if _, err := m.FlushIdentity(t.Context(), id); err != nil {
					t.Fatal(err)
				}
				f.muOrder.Lock()
				defer f.muOrder.Unlock()
				if f.assigned[len(f.assigned)-1] != 5 {
					t.Fatal("preserved grant reset dense ordinal after capacity refusal")
				}
			}
		})
	}
}

// activationBlockedRPC holds every request that is not a delegated flush, the
// way the authority holds Linux ordinary mutations while a Mac activation owns
// exclusive profile admission. Delegated flush writes and metadata travel the
// transport's dedicated flush lane and recall acknowledgements its CONTROL
// lane, so they are admitted.
type activationBlockedRPC struct {
	delegationFakeRPC
	ordinaryEntered chan struct{}
	releaseOrdinary chan struct{}
	once            sync.Once
}

func delegatedFlushRequestForTest(request *authoritypb.Request) bool {
	return request.GetWrite().GetDelegation() != nil || request.GetSetAttr().GetDelegation() != nil || request.GetFallocate().GetDelegation() != nil
}

func (f *activationBlockedRPC) CallMutationSegments(ctx context.Context, request *authoritypb.Request, segments [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	return waveWrite(ctx, &f.waveOrder, f.CallMutation, request, segments, assigned)
}

func (f *activationBlockedRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if !delegatedFlushRequestForTest(request) {
		f.once.Do(func() { close(f.ordinaryEntered) })
		select {
		case <-f.releaseOrdinary:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

// A recall issued while ordinary mutations are held behind an exclusive
// activation must still make progress: its exact-generation flush of buffered
// writes and metadata, and its acknowledgement, use only the flush and CONTROL
// lanes. Every write carries the recalled grant and a dense ordinal.
func TestDelegationRecallFlushProgressesWhileOrdinaryMutationsAreHeld(t *testing.T) {
	fake := &activationBlockedRPC{delegationFakeRPC: delegationFakeRPC{maxWrite: 8}, ordinaryEntered: make(chan struct{}), releaseOrdinary: make(chan struct{})}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 6, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("twenty buffered bytes"[:20]), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetAttr(t.Context(), id, writeback.Attributes{HasMode: true, Mode: 0o640}); err != nil {
		t.Fatal(err)
	}
	held := make(chan error, 1)
	go func() {
		_, err := fake.CallMutation(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Name: []byte("held")}}})
		held <- err
	}()
	<-fake.ordinaryEntered
	defer close(fake.releaseOrdinary)

	grant := delegationTestGrant(6+32, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	recalled := &authoritypb.DelegationRef{Id: grant.GetId(), Generation: grant.GetGeneration()}
	done := make(chan struct{})
	go func() {
		m.HandleControlEvent(t.Context(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 3, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
			Delegation: recalled, Identity: id, BudgetNanos: uint64(5 * time.Second),
		}}})
		m.controlWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recall waited behind the held ordinary mutation")
	}
	select {
	case err := <-held:
		t.Fatalf("the held ordinary mutation finished first (%v); the test did not hold it", err)
	default:
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var acks []*authoritypb.DelegationRecallAck
	for _, request := range fake.controls {
		if ack := request.GetDelegationRecallAck(); ack != nil {
			acks = append(acks, ack)
		}
	}
	if len(acks) != 1 || !proto.Equal(acks[0].GetDelegation(), recalled) || acks[0].GetAppliedSequence() != fake.sequence {
		t.Fatalf("recall acknowledgements = %v, want one for the exact grant at applied sequence %d", acks, fake.sequence)
	}
	var ordinals []uint64
	var metadata int
	for _, request := range fake.mutations {
		switch {
		case request.GetWrite() != nil:
			if !proto.Equal(request.GetWrite().GetDelegation(), recalled) {
				t.Fatalf("recall flush write carried %v, want the recalled grant", request.GetWrite().GetDelegation())
			}
			ordinals = append(ordinals, request.GetWrite().GetFlushSequence())
		case request.GetSetAttr() != nil:
			if !proto.Equal(request.GetSetAttr().GetDelegation(), recalled) {
				t.Fatalf("recall flush metadata carried %v, want the recalled grant", request.GetSetAttr().GetDelegation())
			}
			metadata++
		}
	}
	if fmt.Sprint(ordinals) != "[1 2 3]" || metadata != 1 {
		t.Fatalf("recall flushed write ordinals %v and %d metadata records, want [1 2 3] and 1", ordinals, metadata)
	}
}

// The wave shape is fixed by protocol: the ordered window of four and the
// negotiated write bound, with no capability probe that could select another
// mode, and a wave wider than the window is refused before any dispatch.
func TestDelegationWaveShapeIsTheOrderedWindow(t *testing.T) {
	for _, maxWrite := range []uint32{8, 0} {
		fake := &delegationFakeRPC{maxWrite: maxWrite}
		m := newDelegationTestManager(t, fake)
		width, payload := m.FlushBatchSize()
		_, negotiated := fake.IOLimits()
		if width != volumeserver.OrderedFlushWindow || payload != int(negotiated) {
			t.Fatalf("wave shape = (%d, %d), want (%d, %d)", width, payload, volumeserver.OrderedFlushWindow, negotiated)
		}
	}
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	entries := make([]writeback.Entry, volumeserver.OrderedFlushWindow+1)
	if _, err := m.FlushBatch(t.Context(), writeback.Identity{1}, entries); !errors.Is(err, writeback.ErrInvalid) {
		t.Fatalf("over-wide wave error = %v, want ErrInvalid", err)
	}
}

// canceledWaveRPC applies every wave write except call number waitOn, which
// waits before replay assignment until its caller gives up, as a saturated
// flush lane would hold it. Call number durableOn carries a durable prefix
// through its own reply. Barriers are refused, so durability arrives only
// where a case delivers it.
type canceledWaveRPC struct {
	delegationFakeRPC
	callMu    sync.Mutex
	calls     int
	waitOn    int
	durableOn int
	waiting   chan struct{}
}

func (f *canceledWaveRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		return nil, errors.New("durability is delivered by the test case")
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func (f *canceledWaveRPC) CallMutationSegments(ctx context.Context, request *authoritypb.Request, segments [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	f.callMu.Lock()
	f.calls++
	call := f.calls
	f.callMu.Unlock()
	if call == f.waitOn {
		close(f.waiting)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	response, err := waveWrite(ctx, &f.waveOrder, f.CallMutation, request, segments, assigned)
	if err == nil && call == f.durableOn {
		response.GetWrite().DurableSequence = response.GetAppliedSequence()
	}
	return response, err
}

// A wave whose last member was never sent is retained with its tokens. Its
// applied members' receipts must outlive any durability of those members, or
// the retry applies a durable write twice and, when the resent member's
// ticket follows a cached one, loses the delegation and every later accepted
// write with it.
func TestRetainedWaveKeepsAppliedReceiptsThroughDurability(t *testing.T) {
	const limit = 8
	for _, tc := range []struct {
		name      string
		waitOn    int
		durableOn int
		durable   uint64
		tail      bool
	}{
		{name: "fully durable applied prefix", waitOn: 3, durable: 2},
		{name: "partially durable multi-entry prefix", waitOn: 3, durable: 1},
		{name: "durable prefix of one", waitOn: 2, durable: 1},
		{name: "later accepted write", waitOn: 3, durable: 1, tail: true},
		{name: "durable prefix carried by a member reply", waitOn: 3, durableOn: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &canceledWaveRPC{delegationFakeRPC: delegationFakeRPC{maxWrite: limit}, waitOn: tc.waitOn, durableOn: tc.durableOn, waiting: make(chan struct{})}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 29, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), id, 0, bytes.Repeat([]byte{'x'}, 3*limit), false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			go func() { <-fake.waiting; cancel() }()
			if _, err := m.FlushIdentity(ctx, id); !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted wave error = %v, want the caller's cancellation", err)
			}
			want := []uint64{0, limit, 2 * limit}
			if tc.tail {
				if _, err := m.Write(t.Context(), id, 3*limit, []byte("tail"), false); err != nil {
					t.Fatal(err)
				}
				want = append(want, 3*limit)
			}
			if tc.durable != 0 {
				m.DurableSequence(tc.durable)
			}
			m.tokenMu.Lock()
			receipts := len(m.tokens)
			m.tokenMu.Unlock()
			if receipts != tc.waitOn-1 {
				t.Fatalf("retained wave receipts = %d, want %d", receipts, tc.waitOn-1)
			}
			if _, err := m.FlushIdentity(t.Context(), id); err != nil {
				t.Fatalf("retry of the retained wave failed: %v", err)
			}
			m.tokenMu.Lock()
			receipts = len(m.tokens)
			m.tokenMu.Unlock()
			if receipts != 0 {
				t.Fatalf("successful wave retained %d receipts", receipts)
			}
			if !m.Owns(id) || m.LossSequence() != 0 {
				t.Fatalf("retry lost the delegation: owns=%v loss=%d", m.Owns(id), m.LossSequence())
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			var offsets, ordinals []uint64
			for _, request := range fake.mutations {
				if write := request.GetWrite(); write != nil {
					offsets = append(offsets, write.GetPosition())
					ordinals = append(ordinals, write.GetFlushSequence())
				}
			}
			if fmt.Sprint(offsets) != fmt.Sprint(want) {
				t.Fatalf("applied write offsets = %v, want each exactly once: %v", offsets, want)
			}
			for i, ordinal := range ordinals {
				if ordinal != uint64(i+1) {
					t.Fatalf("ordinals = %v, want dense from 1", ordinals)
				}
			}
		})
	}
}
