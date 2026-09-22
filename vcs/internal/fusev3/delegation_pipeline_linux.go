//go:build linux

package fusev3

import (
	"context"
	"errors"
	"math"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type orderedDelegationRPC interface {
	SupportsOrderedFlush() bool
	CallMutationSegments(context.Context, *authoritypb.Request, [][]byte, authorityrpc.MutationAssigned) (*authoritypb.Response, error)
}

func (m *delegationManager) FlushBatchSize() (int, int) {
	if rpc, ok := m.rpc.(orderedDelegationRPC); ok && rpc.SupportsOrderedFlush() {
		return volumeserver.OrderedFlushWindow, m.maxWrite
	}
	return 0, 0
}

// FlushBatch admits each predecessor to the dedicated transport lane before
// launching its successor. Server arrival may reorder them; the dense ordinal
// and exact replay outcome gate application. Every started RPC is joined before
// one wave-wide capacity/loss decision changes local ownership.
func (m *delegationManager) FlushBatch(ctx context.Context, id writeback.Identity, entries []writeback.Entry) ([]uint64, error) {
	if len(entries) == 0 || len(entries) > volumeserver.OrderedFlushWindow {
		return nil, writeback.ErrInvalid
	}
	if len(entries) == 1 && entries[0].Kind != writeback.Write {
		seq, err := m.Flush(ctx, id, entries[0])
		return []uint64{seq}, err
	}
	rpc, ok := m.rpc.(orderedDelegationRPC)
	if !ok || !rpc.SupportsOrderedFlush() {
		return nil, writeback.ErrInvalid
	}
	s := m.retainState(id, true)
	defer m.releaseState(s)
	s.admission.RLock()
	binding, ok := s.bindings[entries[0].Generation]
	current := ok && sameDelegation(s.ref, binding.ref)
	handle := firstDelegatedHandle(s.writers)
	s.admission.RUnlock()
	if !current {
		return nil, writeback.ErrLost
	}
	if len(handle) == 0 {
		return nil, errors.New("fusev3: ordered flush lost its generation binding")
	}
	type callResult struct {
		response *authoritypb.Response
		err      error
		size     int
		cached   uint64
	}
	results := make([]callResult, len(entries))
	requests := make([]*authoritypb.Request, len(entries))
	spans := make([][][]byte, len(entries))
	missing := 0
	for i, e := range entries {
		if e.Kind != writeback.Write || e.Generation != entries[0].Generation {
			return nil, writeback.ErrInvalid
		}
		pieces := e.Segments
		if pieces == nil {
			pieces = [][]byte{e.Data}
		} else if len(e.Data) != 0 {
			return nil, writeback.ErrInvalid
		}
		size := 0
		for _, piece := range pieces {
			size += len(piece)
			if size > m.maxWrite {
				return nil, writeback.ErrInvalid
			}
		}
		if size == 0 {
			return nil, writeback.ErrInvalid
		}
		spans[i], results[i].size = pieces, size
		m.tokenMu.Lock()
		progress := m.tokens[e.Token]
		m.tokenMu.Unlock()
		if progress.complete {
			results[i].cached = progress.sequence
			continue
		}
		missing++
		requests[i] = &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
			Handle: handle, Position: uint64(e.Offset), Size: uint32(size), WriteFlags: e.WriteOptions.Flags, LockOwner: e.WriteOptions.LockOwner, Delegation: cloneDelegationRef(binding.ref),
		}}}
	}
	s.admission.Lock()
	if !sameDelegation(s.ref, binding.ref) {
		s.admission.Unlock()
		return nil, writeback.ErrLost
	}
	s.meta.Lock()
	if uint64(missing) > math.MaxUint64-s.flushOrdinal {
		s.meta.Unlock()
		report := m.loseDelegationLocked(s, "delegated flush ordinal exhausted")
		s.admission.Unlock()
		m.reportDrop(report)
		return nil, writeback.ErrLost
	}
	for _, request := range requests {
		if request != nil {
			s.flushOrdinal++
			request.GetWrite().FlushSequence = s.flushOrdinal
		}
	}
	s.meta.Unlock()
	s.admission.Unlock()
	var joined sync.WaitGroup
	for i, request := range requests {
		if request == nil {
			continue
		}
		assigned, done := make(chan struct{}), make(chan struct{})
		joined.Add(1)
		go func(i int, request *authoritypb.Request) {
			defer joined.Done()
			defer close(done)
			results[i].response, results[i].err = rpc.CallMutationSegments(ctx, request, spans[i], func(authorityrpc.MutationIdentity) error { close(assigned); return nil })
		}(i, request)
		admitted := true
		select {
		case <-assigned:
		case <-done:
			select {
			case <-assigned:
			default:
				admitted = false
			}
		}
		if !admitted {
			if results[i].err == nil {
				results[i].err = errors.New("fusev3: ordered transport omitted replay assignment")
			}
			break
		}
	}
	joined.Wait()
	s.admission.Lock()
	if !sameDelegation(s.ref, binding.ref) {
		s.admission.Unlock()
		return nil, writeback.ErrLost
	}
	completion := delegationFlushResult{buffer: m.buf}
	defer m.finishFlushResult(s, &completion)
	sequences := make([]uint64, len(entries))
	var capacity syscall.Errno
	lost := false
	for i, result := range results {
		e := entries[i]
		if result.cached != 0 {
			sequences[i] = result.cached
			continue
		}
		response := result.response
		if result.err != nil || response == nil {
			lost = true
			continue
		}
		if errno := definiteDelegationCapacityRefusal(response, true); errno != 0 {
			if capacity == 0 {
				capacity = errno
			}
			continue
		}
		reply := response.GetWrite()
		if successfulDelegationResponse(response) != nil || reply == nil || response.GetVolumeVersion() == 0 || reply.GetPostAttr() == nil || reply.GetPostAttr().GetKind() != authoritypb.Attr_REGULAR || reply.GetPostAttr().GetSize() < e.Offset+int64(result.size) || reply.GetCommittedSize() != uint64(result.size) || reply.GetAssignedOffset() != uint64(e.Offset) || reply.GetError() != 0 || response.GetAppliedSequence() == 0 {
			lost = true
			continue
		}
		seq := response.GetAppliedSequence()
		sequences[i] = seq
		m.tokenMu.Lock()
		m.tokens[e.Token] = delegationFlushProgress{owner: s, sequence: seq, complete: true}
		s.trackFlushTokenLocked(e.Token)
		m.tokenMu.Unlock()
		s.meta.Lock()
		s.applied = max(s.applied, seq)
		s.appliedCut = max(s.appliedCut, e.AppliedThrough)
		s.meta.Unlock()
		m.durabilityMu.Lock()
		m.appliedHigh = max(m.appliedHigh, seq)
		m.durabilityMu.Unlock()
		m.updateBaseFromResponse(s, response)
		completion.durable = max(completion.durable, reply.GetDurableSequence())
	}
	var previous uint64
	for _, seq := range sequences {
		if seq != 0 {
			if seq < previous {
				lost = true
			}
			previous = seq
		}
	}
	if lost {
		completion.dropped = m.loseDelegationLocked(s, "ordered delegated wave outcome unprovable")
		return nil, writeback.ErrLost
	}
	if capacity != 0 {
		completion.dropped = m.refuseBufferedMutationLocked(s, capacity)
		return nil, capacity
	}
	select {
	case m.durableKick <- struct{}{}:
	default:
	}
	return sequences, nil
}
