//go:build linux

package authorityrpc

import (
	"context"
	"sort"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type coherenceSessionApplications struct {
	applied, visible, durable uint64
	lastVersion               uint64
	applications              []uint64 // volume versions above the durable ticket prefix
	visibleOutOfOrder         map[uint64]struct{}
	visibilityChanged         chan struct{}
	forgotten                 bool
}

// coherenceDurability maps the session application-ticket domain exposed
// on protocol 7 to the volume commit domain covered by syncfs. The volume
// handler's commit-publication lock orders recordApplied with volume-version
// assignment; this mutex protects only the per-session indexes and is never
// held across storage I/O.
type coherenceDurability struct {
	mu       sync.RWMutex
	sessions map[volumeserver.SessionID]*coherenceSessionApplications
}

// recordApplied issues the next application ticket for session. The caller
// holds the handler's commit-publication lock and supplies the volume version
// assigned to this exact storage mutation.
func (s *coherenceDurability) recordApplied(session volumeserver.SessionID, identity [16]byte, volumeVersion uint64) uint64 {
	if volumeVersion == 0 || identity == ([16]byte{}) {
		panic("authorityrpc: invalid coherence application coordinate")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[volumeserver.SessionID]*coherenceSessionApplications)
	}
	state := s.sessions[session]
	if state == nil {
		state = &coherenceSessionApplications{visibilityChanged: make(chan struct{})}
		s.sessions[session] = state
	}
	if state.applied == ^uint64(0) {
		panic("authorityrpc: coherence application ticket exhausted")
	}
	if state.lastVersion >= volumeVersion {
		panic("authorityrpc: coherence application volume version did not advance")
	}
	state.applied++
	state.lastVersion = volumeVersion
	state.applications = append(state.applications, volumeVersion)
	return state.applied
}

func (s *coherenceDurability) markVisible(session volumeserver.SessionID, sequence uint64) {
	if sequence == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.sessions[session]
	if state == nil || state.forgotten || sequence > state.applied || sequence <= state.visible {
		return
	}
	if state.visibleOutOfOrder == nil {
		state.visibleOutOfOrder = make(map[uint64]struct{})
	}
	state.visibleOutOfOrder[sequence] = struct{}{}
	for {
		next := state.visible + 1
		if _, ok := state.visibleOutOfOrder[next]; !ok {
			break
		}
		delete(state.visibleOutOfOrder, next)
		state.visible = next
	}
	close(state.visibilityChanged)
	state.visibilityChanged = make(chan struct{})
}

func (s *coherenceDurability) latestVisible(session volumeserver.SessionID) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if state := s.sessions[session]; state != nil && !state.forgotten {
		return state.visible
	}
	return 0
}

func (s *coherenceDurability) waitVisible(ctx context.Context, session volumeserver.SessionID, sequence uint64) (applied, visible uint64, err error) {
	for {
		s.mu.RLock()
		state := s.sessions[session]
		if state == nil || state.forgotten {
			s.mu.RUnlock()
			return 0, 0, volumeserver.ErrSubscription
		}
		applied, visible = state.applied, state.visible
		if sequence > applied {
			s.mu.RUnlock()
			return applied, visible, syscall.EINVAL
		}
		if visible >= sequence {
			s.mu.RUnlock()
			return applied, visible, nil
		}
		changed := state.visibilityChanged
		s.mu.RUnlock()
		select {
		case <-ctx.Done():
			return applied, visible, ctx.Err()
		case <-changed:
		}
	}
}

// latest converts one proven durable volume cut to the session's largest
// contiguous durable application prefix. Application tickets for a session
// are appended in volume-commit order, so the conversion is a binary search.
func (s *coherenceDurability) latest(session volumeserver.SessionID, durableVolumeVersion uint64) (applied, durable uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.sessions[session]
	if state == nil {
		return 0, 0
	}
	applied = state.applied
	durable = state.durable + uint64(sort.Search(len(state.applications), func(index int) bool {
		return state.applications[index] > durableVolumeVersion
	}))
	return applied, durable
}

// retire drops proof records covered by the durable volume cut for every
// session, including idle readers whose last writes another session synced.
func (s *coherenceDurability) retire(volumeCut uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.sessions {
		n := sort.Search(len(state.applications), func(i int) bool { return state.applications[i] > volumeCut })
		if n == 0 {
			continue
		}
		state.durable += uint64(n)
		tail := state.applications[n:]
		if len(tail) == 0 {
			state.applications = nil
		} else if len(tail)*2 < cap(state.applications) {
			state.applications = append([]uint64(nil), tail...)
		} else {
			state.applications = tail
		}
	}
}

func (s *coherenceDurability) forget(session volumeserver.SessionID) {
	s.mu.Lock()
	if state := s.sessions[session]; state != nil && !state.forgotten {
		state.forgotten = true
		close(state.visibilityChanged)
	}
	delete(s.sessions, session)
	s.mu.Unlock()
}

func (h *VolumeHandler) forgetCoherenceApplications(session volumeserver.SessionID) {
	h.coherenceDurability.forget(session)
}

func (h *VolumeHandler) latestCoherenceDurability(session volumeserver.SessionID) (applied, durable uint64) {
	if h.Coherence == nil {
		return 0, 0
	}
	return h.coherenceDurability.latest(session, h.Coherence.LatestDurable())
}

// coherenceSyncVolume establishes a volume-wide durability cut. The cut is
// captured under the same lock that orders storage commits and OnCommit, but
// the lock is released before syncfs: every captured mutation has finished its
// storage apply before the syscall starts, while unrelated commits remain free
// to proceed. Mutations racing after the capture may also become durable, but
// are deliberately excluded from the published proof.
func (h *VolumeHandler) coherenceSyncVolume(session volumeserver.SessionID) (applied, durable uint64, err error) {
	if h.Store == nil || h.Coherence == nil {
		return 0, 0, errInternal
	}
	cut := h.coherenceVersionNow()
	if err := h.Store.SyncFS(); err != nil {
		return 0, 0, err
	}
	h.Coherence.DurableSequence(cut)
	h.coherenceDurability.retire(cut)
	applied, durable = h.latestCoherenceDurability(session)
	return applied, durable, nil
}

func (h *VolumeHandler) coherenceBarrier(session volumeserver.SessionID, requested uint64) (applied, durable uint64, err error) {
	applied, _ = h.latestCoherenceDurability(session)
	if requested > applied {
		return applied, 0, syscall.EINVAL
	}
	applied, durable, err = h.coherenceSyncVolume(session)
	if err != nil {
		return 0, 0, err
	}
	if durable < requested {
		// The requested ticket was issued before the captured volume cut. Falling
		// short means commit publication and durability capture were not ordered
		// by the same lock, which is an authority implementation failure.
		return 0, 0, errInternal
	}
	return applied, durable, nil
}

func (h *VolumeHandler) handleCoherenceBarrier(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential) *authoritypb.Response {
	return h.mutate(ctx, req, cred, func() *authoritypb.Response {
		body := req.GetBarrier()
		if body == nil {
			return h.errorResponse(0, syscall.EINVAL, false)
		}
		applied, durable, err := h.coherenceBarrier(cred.ID, body.GetCutSequence())
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		response := h.success(0)
		response.Body = &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{
			AppliedSequence: applied,
			DurableSequence: durable,
		}}
		return response
	})
}

func (h *VolumeHandler) handleCoherenceVisibility(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential) *authoritypb.Response {
	body := req.GetWaitVisibility()
	if body == nil || body.GetCutSequence() == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	applied, visible, err := h.coherenceDurability.waitVisible(ctx, cred.ID, body.GetCutSequence())
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	response := h.success(req.GetRequestId())
	response.VisibleSequence = visible
	response.Body = &authoritypb.Response_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityReply{
		AppliedSequence: applied,
		VisibleSequence: visible,
	}}
	return response
}
