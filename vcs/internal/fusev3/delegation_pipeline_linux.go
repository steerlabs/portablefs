//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// errFlushOrdinalExhausted is returned from the replay-assignment callback when
// the exact grant has no ordinal left. The wave then loses the delegation.
var errFlushOrdinalExhausted = errors.New("fusev3: delegated flush ordinal exhausted")

// FlushBatchSize is fixed: every Linux session carries the ordered flush lane,
// so a wave is always up to OrderedFlushWindow writes of at most one
// negotiated write each.
func (m *delegationManager) FlushBatchSize() (int, int) {
	return volumeserver.OrderedFlushWindow, m.maxWrite
}

// FlushBatch admits each predecessor to the dedicated transport lane before
// launching its successor. Server arrival may reorder them; the dense ordinal
// and exact replay outcome gate application. Every started RPC is joined before
// one wave-wide capacity/loss decision changes local ownership.
//
// An ordinal is consumed only when the transport assigns the write its replay
// identity, immediately before dispatch. A write that never reached that point
// (its caller's context ended while it waited for the lane) therefore leaves
// the grant's dense sequence without a hole and provably never applied, so the
// wave is retained for retry instead of discarding the delegation's data.
func (m *delegationManager) FlushBatch(ctx context.Context, id writeback.Identity, entries []writeback.Entry) ([]uint64, error) {
	if len(entries) == 0 || len(entries) > volumeserver.OrderedFlushWindow {
		return nil, writeback.ErrInvalid
	}
	if len(entries) == 1 && entries[0].Kind != writeback.Write {
		seq, err := m.flushMetadata(ctx, id, entries[0])
		if err == nil {
			m.retireFlushReceipts(id, nil)
		}
		return []uint64{seq}, err
	}
	s := m.retainState(id, true)
	defer m.releaseState(s)
	s.admission.RLock()
	binding, ok := s.bindings[entries[0].Generation]
	sessionCtx := s.sessionCtx
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
		// sent is set once the transport assigned a replay identity and the
		// write took its ordinal; only then can it have been applied.
		sent bool
	}
	results := make([]callResult, len(entries))
	requests := make([]*authoritypb.Request, len(entries))
	spans := make([][][]byte, len(entries))
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
		requests[i] = &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
			Handle: handle, Position: uint64(e.Offset), Size: uint32(size), WriteFlags: e.WriteOptions.Flags, LockOwner: e.WriteOptions.LockOwner, Delegation: cloneDelegationRef(binding.ref),
		}}}
	}
	// Validation and the exact-generation check precede receipt retirement.
	m.retireFlushReceipts(id, entries)
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
			results[i].response, results[i].err = m.rpc.CallMutationSegments(authorityrpc.RetainMutationForSession(ctx, sessionCtx), request, spans[i], func(authorityrpc.MutationIdentity) error {
				if err := m.assignFlushOrdinal(s, binding.ref, request.GetWrite()); err != nil {
					return err
				}
				close(assigned)
				return nil
			})
		}(i, request)
		select {
		case <-assigned:
		case <-done:
			select {
			case <-assigned:
			default:
			}
		}
		select {
		case <-assigned:
			results[i].sent = true
			continue
		default:
		}
		if results[i].err == nil {
			results[i].err = errors.New("fusev3: ordered transport omitted replay assignment")
		}
		break
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
	var unsent error
	lost := false
	lostReason := "ordered delegated wave outcome unprovable"
	for i, result := range results {
		e := entries[i]
		if result.cached != 0 {
			sequences[i] = result.cached
			continue
		}
		if !result.sent {
			switch {
			case errors.Is(result.err, errFlushOrdinalExhausted):
				lost, lostReason = true, "delegated flush ordinal exhausted"
			case result.err == nil || ctx.Err() != nil && (errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded)):
				// Never launched, or its context ended before the lane
				// admitted it: no ordinal, no dispatch, no application.
				if unsent == nil {
					unsent = result.err
				}
			default:
				lost = true
			}
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
		// A capacity failure can follow an exact prefix or only metadata
		// changes. Neither makes placement uncertain. Account its ticket and
		// preserve the errno without marking the unwritten suffix applied.
		if !response.GetUncertain() && !response.GetSessionTerminal() && len(response.GetTerminalDeliveryToken()) == 0 && response.GetFailure() == 0 && response.GetErrno() == 0 && response.GetVolumeVersion() != 0 &&
			reply != nil && reply.GetCommittedSize() <= uint64(result.size) &&
			(reply.GetCommittedSize() == 0 && reply.GetAssignedOffset() == 0 ||
				reply.GetCommittedSize() != 0 && reply.GetAssignedOffset() == uint64(e.Offset) && reply.GetPostAttr().GetSize() >= e.Offset+int64(reply.GetCommittedSize())) &&
			reply.GetPostAttr().GetKind() == authoritypb.Attr_REGULAR &&
			response.GetAppliedSequence() != 0 && response.GetPostState() != nil &&
			(reply.GetError() == -int32(syscall.ENOSPC) || reply.GetError() == -int32(syscall.EDQUOT) || reply.GetError() == -int32(syscall.EFBIG)) {
			if capacity == 0 {
				capacity = syscall.Errno(-reply.GetError())
			}
			sequences[i] = response.GetAppliedSequence()
			s.meta.Lock()
			s.applied = max(s.applied, response.GetAppliedSequence())
			s.meta.Unlock()
			m.durabilityMu.Lock()
			m.appliedHigh = max(m.appliedHigh, response.GetAppliedSequence())
			m.durabilityMu.Unlock()
			completion.durable = max(completion.durable, reply.GetDurableSequence())
			m.updateBaseFromResponse(s, response)
			continue
		}
		if successfulDelegationResponse(response) != nil || reply == nil || response.GetVolumeVersion() == 0 || reply.GetPostAttr() == nil || reply.GetPostAttr().GetKind() != authoritypb.Attr_REGULAR || reply.GetPostAttr().GetSize() < e.Offset+int64(result.size) || reply.GetCommittedSize() != uint64(result.size) || reply.GetAssignedOffset() != uint64(e.Offset) || reply.GetError() != 0 || response.GetAppliedSequence() == 0 {
			lost = true
			lostReason = fmt.Sprintf("ordered delegated write outcome unprovable: requested=%d offset=%d committed=%d assigned=%d error=%d errno=%d uncertain=%t failure=%s applied=%d", result.size, e.Offset, reply.GetCommittedSize(), reply.GetAssignedOffset(), reply.GetError(), response.GetErrno(), response.GetUncertain(), response.GetFailure(), response.GetAppliedSequence())
			continue
		}
		seq := response.GetAppliedSequence()
		sequences[i] = seq
		m.tokenMu.Lock()
		m.tokens[e.Token] = delegationFlushProgress{sequence: seq, complete: true}
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
		completion.dropped = m.loseDelegationLocked(s, lostReason)
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
	if unsent != nil {
		// The applied prefix keeps its completed tokens; the retained wave
		// resends only the writes that never left this client.
		return nil, unsent
	}
	// A successful wave cannot be retried, even if cancellation wins just
	// after this return: writeback commits its result before checking context.
	m.retireFlushReceipts(id, nil)
	return sequences, nil
}

// retireFlushReceipts releases the applied-token receipts of every earlier
// wave of this identity. Writeback retains one immutable pending wave per
// identity and forms the next one, with fresh tokens, only after that wave
// completed or was dropped; so once a wave reaches the flusher, no token
// outside it can be retried and its receipt has no remaining owner. The
// current wave's receipts stay, however much of it is already durable. An
// empty entry list retires a successfully completed wave immediately.
func (m *delegationManager) retireFlushReceipts(id writeback.Identity, entries []writeback.Entry) {
	s := m.retainState(id, false)
	if s == nil {
		return
	}
	defer m.releaseState(s)
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	for token := range s.flushTokens {
		current := false
		for _, entry := range entries {
			current = current || entry.Token == token
		}
		if !current {
			delete(m.tokens, token)
			delete(s.flushTokens, token)
		}
	}
	if len(s.flushTokens) == 0 {
		s.flushTokens = nil
	}
}

// assignFlushOrdinal gives one wave write the next dense ordinal of its exact
// grant. It runs inside the transport's replay assignment, before dispatch;
// the grant check and the increment share the admission and metadata locks
// that install a successor grant and reset its sequence, so a write of a
// replaced grant can never consume a successor's ordinal.
func (m *delegationManager) assignFlushOrdinal(s *delegationState, ref *authoritypb.DelegationRef, write *authoritypb.WriteRequest) error {
	s.admission.RLock()
	defer s.admission.RUnlock()
	if !sameDelegation(s.ref, ref) {
		return writeback.ErrLost
	}
	s.meta.Lock()
	defer s.meta.Unlock()
	if s.flushOrdinal == math.MaxUint64 {
		return errFlushOrdinalExhausted
	}
	s.flushOrdinal++
	write.FlushSequence = s.flushOrdinal
	return nil
}
