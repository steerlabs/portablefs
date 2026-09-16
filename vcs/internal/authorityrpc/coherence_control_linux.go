//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

const coherenceControlBatchLimit = 4096

var coherenceDelegationIDPrefix = [8]byte{'p', 'f', 's', 'd', 'l', 'g', '7', 0}

type coherenceApplicationValidator interface {
	ValidateCoherenceApplication(volumeserver.SessionID, [16]byte, uint64) bool
}

type coherenceSnapshotState struct {
	id            [16]byte
	watermark     uint64
	horizonNanos  uint64
	delegated     [][16]byte
	expectedAfter string
	pages         map[string]*authoritypb.SubscribeReply
	complete      bool
}

type coherenceChangePosition struct {
	wire, coordinator uint64
}

type coherenceControlEventKind uint8

const (
	coherenceControlRecall coherenceControlEventKind = iota + 1
	coherenceControlBreak
	coherenceControlModeChange
)

type coherenceControlObligation struct {
	kind               coherenceControlEventKind
	identity           [16]byte
	id, generation     uint64
	coordinatorRequest uint64
	completed          bool
	appliedSequence    uint64
}

type coherenceTrackedDelegation struct {
	identity   [16]byte
	generation uint64
	retired    bool
}

type coherenceControlSession struct {
	token             volumeserver.SubscriptionToken
	snapshot          *coherenceSnapshotState
	coordinatorCursor uint64
	queued            []volumeserver.StreamEvent
	controlDelivered  uint64
	changeDelivered   uint64
	changeAcked       uint64
	changePositions   []coherenceChangePosition
	replayCursor      uint64
	replay            *authoritypb.ControlEvent
	pollActive        bool
	obligations       map[uint64]*coherenceControlObligation
	delegations       map[uint64]*coherenceTrackedDelegation
	releaseReplays    map[[32]byte]struct{}
}

type coherenceControlState struct {
	mu          sync.Mutex
	subscribeMu sync.Mutex
	now         func() time.Time
	random      io.Reader
	sessions    map[volumeserver.SessionID]*coherenceControlSession
}

func (h *VolumeHandler) initCoherenceControlState() *coherenceControlState {
	h.coherenceControlOnce.Do(func() {
		h.coherenceControl = &coherenceControlState{
			now: time.Now, random: rand.Reader,
			sessions: make(map[volumeserver.SessionID]*coherenceControlSession),
		}
	})
	return h.coherenceControl
}

func coherenceDelegationID(id uint64) []byte {
	if id == 0 {
		return nil
	}
	raw := make([]byte, 16)
	copy(raw, coherenceDelegationIDPrefix[:])
	binary.BigEndian.PutUint64(raw[8:], id)
	return raw
}

func parseCoherenceDelegationID(raw []byte) (uint64, error) {
	if len(raw) != 16 || !bytes.Equal(raw[:8], coherenceDelegationIDPrefix[:]) {
		return 0, syscall.EINVAL
	}
	id := binary.BigEndian.Uint64(raw[8:])
	if id == 0 {
		return 0, syscall.EINVAL
	}
	return id, nil
}

func coherenceDelegationRefProto(grant volumeserver.Delegation) *authoritypb.DelegationRef {
	return &authoritypb.DelegationRef{Id: coherenceDelegationID(grant.ID), Generation: grant.Generation}
}

func coherenceDelegationModeProto(mode volumeserver.DelegationMode) authoritypb.DelegationMode {
	switch mode {
	case volumeserver.DelegationFull:
		return authoritypb.DelegationMode_DELEGATION_MODE_FULL
	case volumeserver.DelegationWritethrough:
		return authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH
	default:
		return authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED
	}
}

func (h *VolumeHandler) rememberCoherenceDelegation(grant volumeserver.Delegation) error {
	if grant.ID == 0 || grant.Generation == 0 || grant.Identity == ([16]byte{}) || grant.Holder == (volumeserver.SessionID{}) {
		return syscall.EINVAL
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	defer state.mu.Unlock()
	session := state.sessions[grant.Holder]
	if session == nil || session.token.Session != grant.Holder {
		return volumeserver.ErrSubscription
	}
	if old := session.delegations[grant.ID]; old != nil && (old.identity != grant.Identity || old.generation != grant.Generation) {
		return errInternal
	}
	session.delegations[grant.ID] = &coherenceTrackedDelegation{identity: grant.Identity, generation: grant.Generation}
	return nil
}

func (h *VolumeHandler) coherenceToken(id volumeserver.SessionID) (volumeserver.SubscriptionToken, error) {
	if h.Coherence == nil {
		return volumeserver.SubscriptionToken{}, errInternal
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	session := state.sessions[id]
	state.mu.Unlock()
	if session == nil {
		return volumeserver.SubscriptionToken{}, volumeserver.ErrSubscription
	}
	return session.token, nil
}

func (h *VolumeHandler) coherenceError(requestID uint64, err error) *authoritypb.Response {
	response := h.success(requestID)
	switch {
	case errors.Is(err, volumeserver.ErrSubscription), errors.Is(err, volumeserver.ErrSessionFenced),
		errors.Is(err, volumeserver.ErrDelegationStale):
		response.Errno = errnos.EIO
		response.Failure = authoritypb.FailureClass_FAILURE_CLASS_COHERENCE
	case errors.Is(err, volumeserver.ErrSubscriptionPosition), errors.Is(err, volumeserver.ErrCoherenceIdentity),
		errors.Is(err, volumeserver.ErrDelegationAck), errors.Is(err, volumeserver.ErrDelegationBusy):
		response.Errno = errnos.EINVAL
	default:
		return h.errorResponse(requestID, err, false)
	}
	return response
}

func (h *VolumeHandler) handleCoherenceControl(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential) (*authoritypb.Response, bool) {
	if req == nil {
		return nil, false
	}
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Subscribe:
		return h.handleCoherenceSubscribe(req.GetRequestId(), cred.ID, body.Subscribe), true
	case *authoritypb.Request_RenewSubscription:
		return h.handleCoherenceRenew(req.GetRequestId(), cred.ID, body.RenewSubscription), true
	case *authoritypb.Request_NextControlEvent:
		return h.handleCoherencePoll(ctx, req.GetRequestId(), cred.ID, body.NextControlEvent), true
	case *authoritypb.Request_ChangeAck:
		return h.handleCoherenceChangeAck(req.GetRequestId(), cred.ID, body.ChangeAck), true
	case *authoritypb.Request_DelegationRecallAck:
		return h.handleCoherenceDelegationAck(req.GetRequestId(), cred.ID, coherenceControlRecall,
			body.DelegationRecallAck.GetIncarnation(), body.DelegationRecallAck.GetEventSequence(),
			body.DelegationRecallAck.GetDelegation(), body.DelegationRecallAck.GetAppliedSequence()), true
	case *authoritypb.Request_DelegationBreakAck:
		return h.handleCoherenceDelegationAck(req.GetRequestId(), cred.ID, coherenceControlBreak,
			body.DelegationBreakAck.GetIncarnation(), body.DelegationBreakAck.GetEventSequence(),
			body.DelegationBreakAck.GetDelegation(), body.DelegationBreakAck.GetAppliedSequence()), true
	case *authoritypb.Request_DelegationModeChangeAck:
		return h.handleCoherenceDelegationAck(req.GetRequestId(), cred.ID, coherenceControlModeChange,
			body.DelegationModeChangeAck.GetIncarnation(), body.DelegationModeChangeAck.GetEventSequence(),
			body.DelegationModeChangeAck.GetDelegation(), body.DelegationModeChangeAck.GetAppliedSequence()), true
	case *authoritypb.Request_DelegationRelease:
		return h.handleCoherenceDelegationRelease(req.GetRequestId(), cred.ID, body.DelegationRelease), true
	default:
		return nil, false
	}
}

func (h *VolumeHandler) handleCoherenceSubscribe(requestID uint64, id volumeserver.SessionID, request *authoritypb.SubscribeRequest) *authoritypb.Response {
	if h.Coherence == nil || request == nil {
		return h.coherenceError(requestID, errInternal)
	}
	state := h.initCoherenceControlState()
	if len(request.GetSnapshotId()) == 0 {
		if len(request.GetAfterIdentity()) != 0 {
			return h.coherenceError(requestID, syscall.EINVAL)
		}
		started := state.now()
		state.subscribeMu.Lock()
		defer state.subscribeMu.Unlock()
		h.coherenceCommitMu.Lock()
		snapshot, err := h.Coherence.Subscribe(id)
		h.coherenceCommitMu.Unlock()
		if err != nil {
			return h.coherenceError(requestID, err)
		}
		sort.Slice(snapshot.Delegated, func(i, j int) bool {
			return bytes.Compare(snapshot.Delegated[i][:], snapshot.Delegated[j][:]) < 0
		})
		var snapshotID [16]byte
		for snapshotID == ([16]byte{}) {
			if _, err := io.ReadFull(state.random, snapshotID[:]); err != nil {
				return h.coherenceError(requestID, errInternal)
			}
		}
		duration := snapshot.Horizon.Sub(started)
		if duration < 0 {
			duration = 0
		}
		if duration > volumeserver.SubscriptionTTL {
			duration = volumeserver.SubscriptionTTL
		}
		session := &coherenceControlSession{
			token: snapshot.Token, coordinatorCursor: snapshot.Position,
			obligations:    make(map[uint64]*coherenceControlObligation),
			delegations:    make(map[uint64]*coherenceTrackedDelegation),
			releaseReplays: make(map[[32]byte]struct{}),
			snapshot: &coherenceSnapshotState{
				id: snapshotID, watermark: snapshot.Watermark, horizonNanos: uint64(duration),
				delegated: snapshot.Delegated, pages: make(map[string]*authoritypb.SubscribeReply),
			},
		}
		state.mu.Lock()
		state.sessions[id] = session
		reply, pageErr := h.coherenceSubscribePageLocked(session, nil)
		state.mu.Unlock()
		if pageErr != nil {
			return h.coherenceError(requestID, pageErr)
		}
		response := h.success(requestID)
		response.Body = &authoritypb.Response_Subscribe{Subscribe: reply}
		return response
	}
	if len(request.GetSnapshotId()) != 16 {
		return h.coherenceError(requestID, syscall.EINVAL)
	}
	state.mu.Lock()
	session := state.sessions[id]
	if session == nil || session.snapshot == nil || !bytes.Equal(request.GetSnapshotId(), session.snapshot.id[:]) {
		state.mu.Unlock()
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	token := session.token
	state.mu.Unlock()
	if err := h.Coherence.CheckSession(token); err != nil {
		return h.coherenceError(requestID, err)
	}
	state.mu.Lock()
	if state.sessions[id] != session {
		state.mu.Unlock()
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	reply, err := h.coherenceSubscribePageLocked(session, request.GetAfterIdentity())
	state.mu.Unlock()
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	response := h.success(requestID)
	response.Body = &authoritypb.Response_Subscribe{Subscribe: reply}
	return response
}

func (h *VolumeHandler) coherenceSubscribePageLocked(session *coherenceControlSession, after []byte) (*authoritypb.SubscribeReply, error) {
	snapshot := session.snapshot
	key := string(after)
	if page := snapshot.pages[key]; page != nil {
		return proto.Clone(page).(*authoritypb.SubscribeReply), nil
	}
	if snapshot.complete || key != snapshot.expectedAfter {
		return nil, syscall.EINVAL
	}
	start := 0
	if len(after) != 0 {
		if len(after) != 16 {
			return nil, syscall.EINVAL
		}
		start = sort.Search(len(snapshot.delegated), func(i int) bool {
			return bytes.Compare(snapshot.delegated[i][:], after) > 0
		})
		if start == 0 || snapshot.delegated[start-1] != requestIdentity(after) {
			return nil, syscall.EINVAL
		}
	}
	reply := &authoritypb.SubscribeReply{
		Watermark: snapshot.watermark, Incarnation: session.token.Incarnation,
		HorizonNanos: snapshot.horizonNanos, SnapshotId: append([]byte(nil), snapshot.id[:]...),
	}
	maxBytes := h.coherenceReplyLimit()
	if maxBytes == 0 {
		return nil, syscall.EOVERFLOW
	}
	if proto.Size(reply) > maxBytes {
		return nil, syscall.EOVERFLOW
	}
	end := start
	for end < len(snapshot.delegated) && end-start < coherenceControlBatchLimit {
		reply.DelegatedIdentities = append(reply.DelegatedIdentities, append([]byte(nil), snapshot.delegated[end][:]...))
		candidateEnd := end + 1
		if candidateEnd < len(snapshot.delegated) {
			reply.NextAfterIdentity = append(reply.NextAfterIdentity[:0], snapshot.delegated[candidateEnd-1][:]...)
		} else {
			reply.NextAfterIdentity = nil
		}
		if proto.Size(reply) > maxBytes {
			reply.DelegatedIdentities = reply.DelegatedIdentities[:len(reply.DelegatedIdentities)-1]
			reply.NextAfterIdentity = nil
			break
		}
		end = candidateEnd
	}
	if end == start && start < len(snapshot.delegated) {
		return nil, syscall.EOVERFLOW
	}
	if end < len(snapshot.delegated) {
		reply.NextAfterIdentity = append([]byte(nil), snapshot.delegated[end-1][:]...)
		snapshot.expectedAfter = string(reply.NextAfterIdentity)
	} else {
		snapshot.complete = true
	}
	snapshot.pages[key] = proto.Clone(reply).(*authoritypb.SubscribeReply)
	return reply, nil
}

func (h *VolumeHandler) coherenceReplyLimit() int {
	if h.MaxFrame <= responseEnvelopeReserve {
		return 0
	}
	return int(h.MaxFrame - responseEnvelopeReserve)
}

func requestIdentity(raw []byte) [16]byte {
	var identity [16]byte
	copy(identity[:], raw)
	return identity
}

func (h *VolumeHandler) handleCoherenceRenew(requestID uint64, id volumeserver.SessionID, request *authoritypb.RenewSubscriptionRequest) *authoritypb.Response {
	if request == nil || request.GetIncarnation() == 0 {
		return h.coherenceError(requestID, syscall.EINVAL)
	}
	started := h.initCoherenceControlState().now()
	token, err := h.coherenceToken(id)
	if err != nil || token.Incarnation != request.GetIncarnation() {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	horizon, err := h.Coherence.Renew(token)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	duration := horizon.Sub(started)
	if duration < 0 {
		duration = 0
	}
	if duration > volumeserver.SubscriptionTTL {
		duration = volumeserver.SubscriptionTTL
	}
	response := h.success(requestID)
	response.Body = &authoritypb.Response_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionReply{
		Incarnation: token.Incarnation, HorizonNanos: uint64(duration),
	}}
	return response
}

func (h *VolumeHandler) handleCoherencePoll(ctx context.Context, requestID uint64, id volumeserver.SessionID, request *authoritypb.NextControlEventRequest) *authoritypb.Response {
	if request == nil || request.GetIncarnation() == 0 {
		return h.coherenceError(requestID, syscall.EINVAL)
	}
	token, err := h.coherenceToken(id)
	if err != nil || token.Incarnation != request.GetIncarnation() {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	if err := h.Coherence.CheckSession(token); err != nil {
		return h.coherenceError(requestID, err)
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	session := state.sessions[id]
	if session == nil || session.token != token {
		state.mu.Unlock()
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	after := request.GetAfterSequence()
	if session.pollActive {
		state.mu.Unlock()
		return h.coherenceError(requestID, volumeserver.ErrSubscriptionPosition)
	}
	if session.replay != nil && after == session.replayCursor {
		event := proto.Clone(session.replay).(*authoritypb.ControlEvent)
		state.mu.Unlock()
		return coherenceControlEventResponse(h, requestID, event)
	}
	if after != session.controlDelivered {
		state.mu.Unlock()
		return h.coherenceError(requestID, volumeserver.ErrSubscriptionPosition)
	}
	session.replay = nil
	session.pollActive = true
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		session.pollActive = false
		state.mu.Unlock()
	}()

	for {
		state.mu.Lock()
		if state.sessions[id] != session {
			state.mu.Unlock()
			return h.coherenceError(requestID, volumeserver.ErrSubscription)
		}
		if event, ok, eventErr := h.nextCoherenceControlEventLocked(session); ok || eventErr != nil {
			state.mu.Unlock()
			if eventErr != nil {
				return h.coherenceError(requestID, eventErr)
			}
			return coherenceControlEventResponse(h, requestID, event)
		}
		cursor := session.coordinatorCursor
		state.mu.Unlock()

		events, pollErr := h.Coherence.Poll(ctx, token, cursor, nil, coherenceControlBatchLimit)
		if pollErr != nil {
			return h.coherenceError(requestID, pollErr)
		}
		state.mu.Lock()
		if state.sessions[id] != session {
			state.mu.Unlock()
			return h.coherenceError(requestID, volumeserver.ErrSubscription)
		}
		if len(events) != 0 {
			session.coordinatorCursor = events[len(events)-1].Position
			session.queued = append(session.queued, events...)
		}
		state.mu.Unlock()
	}
}

func coherenceControlEventResponse(h *VolumeHandler, requestID uint64, event *authoritypb.ControlEvent) *authoritypb.Response {
	response := h.success(requestID)
	response.Body = &authoritypb.Response_ControlEvent{ControlEvent: event}
	return response
}

func (h *VolumeHandler) nextCoherenceControlEventLocked(session *coherenceControlSession) (*authoritypb.ControlEvent, bool, error) {
	for len(session.queued) != 0 {
		first := session.queued[0]
		session.queued = session.queued[1:]
		switch first.Kind {
		case volumeserver.StreamAdvance, volumeserver.StreamLoss:
			continue
		case volumeserver.StreamChange:
			entries := make([]*authoritypb.ChangeEntry, 0, min(len(session.queued)+1, coherenceControlBatchLimit))
			nextSequence := session.controlDelivered + 1
			if nextSequence == 0 {
				panic("authorityrpc: coherence control sequence exhausted")
			}
			event := &authoritypb.ControlEvent{
				Incarnation: session.token.Incarnation, Sequence: nextSequence,
				Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{
					Incarnation: session.token.Incarnation, Entries: entries,
				}},
			}
			for {
				position := session.changeDelivered + 1
				if position == 0 {
					panic("authorityrpc: coherence change position exhausted")
				}
				entry, err := coherenceChangeEntryProto(first.Change, position)
				if err != nil {
					return nil, false, err
				}
				entries = append(entries, entry)
				event.GetChangeBatch().Entries = entries
				if proto.Size(event) > h.coherenceReplyLimit() {
					entries = entries[:len(entries)-1]
					event.GetChangeBatch().Entries = entries
					session.queued = append([]volumeserver.StreamEvent{first}, session.queued...)
					if len(entries) == 0 {
						return nil, false, syscall.EOVERFLOW
					}
					break
				}
				session.changeDelivered = position
				session.changePositions = append(session.changePositions, coherenceChangePosition{wire: position, coordinator: first.Position})
				if len(entries) == coherenceControlBatchLimit || len(session.queued) == 0 {
					break
				}
				// Internal cursor advances have no wire change coordinate. Skip
				// them before selecting the next change, including at batch end.
				for len(session.queued) != 0 && (session.queued[0].Kind == volumeserver.StreamAdvance || session.queued[0].Kind == volumeserver.StreamLoss) {
					session.queued = session.queued[1:]
				}
				if len(session.queued) == 0 {
					break
				}
				first = session.queued[0]
				if first.Kind != volumeserver.StreamChange {
					break
				}
				session.queued = session.queued[1:]
			}
			return finishCoherenceControlEventLocked(session, event), true, nil
		case volumeserver.StreamRecall, volumeserver.StreamBreakForRead, volumeserver.StreamDelegationMode:
			if tracked := session.delegations[first.Delegation.ID]; tracked != nil &&
				(tracked.retired || tracked.generation > first.Delegation.Generation) {
				// A last-handle release can complete the terminal cut before
				// its queued control event reaches the wire.
				continue
			}
			if first.Delegation.ID == 0 || first.Delegation.Generation == 0 || first.Delegation.Identity == ([16]byte{}) ||
				first.Request == 0 || first.Deadline.IsZero() {
				return nil, false, errInternal
			}
			budget := first.Deadline.Sub(h.initCoherenceControlState().now())
			if budget <= 0 {
				continue
			}
			if budget > volumeserver.DelegationRecallBudget {
				budget = volumeserver.DelegationRecallBudget
			}
			ref := coherenceDelegationRefProto(first.Delegation)
			event := &authoritypb.ControlEvent{Incarnation: session.token.Incarnation}
			kind := coherenceControlRecall
			switch first.Kind {
			case volumeserver.StreamRecall:
				event.Event = &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{
					Delegation: ref, Identity: append([]byte(nil), first.Delegation.Identity[:]...), BudgetNanos: uint64(budget),
				}}
			case volumeserver.StreamBreakForRead:
				kind = coherenceControlBreak
				event.Event = &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{
					Delegation: ref, Identity: append([]byte(nil), first.Delegation.Identity[:]...), BudgetNanos: uint64(budget),
				}}
			case volumeserver.StreamDelegationMode:
				kind = coherenceControlModeChange
				mode := coherenceDelegationModeProto(first.Delegation.Mode)
				if mode == authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED {
					return nil, false, errInternal
				}
				event.Event = &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{
					Delegation: ref, Identity: append([]byte(nil), first.Delegation.Identity[:]...), Mode: mode, BudgetNanos: uint64(budget),
				}}
			}
			event = finishCoherenceControlEventLocked(session, event)
			session.obligations[event.Sequence] = &coherenceControlObligation{
				kind: kind, identity: first.Delegation.Identity, id: first.Delegation.ID,
				generation: first.Delegation.Generation, coordinatorRequest: first.Request,
			}
			session.delegations[first.Delegation.ID] = &coherenceTrackedDelegation{
				identity: first.Delegation.Identity, generation: first.Delegation.Generation,
			}
			return event, true, nil
		default:
			return nil, false, errInternal
		}
	}
	return nil, false, nil
}

func finishCoherenceControlEventLocked(session *coherenceControlSession, event *authoritypb.ControlEvent) *authoritypb.ControlEvent {
	session.controlDelivered++
	if session.controlDelivered == 0 {
		panic("authorityrpc: coherence control sequence exhausted")
	}
	event.Sequence = session.controlDelivered
	session.replayCursor = session.controlDelivered - 1
	session.replay = proto.Clone(event).(*authoritypb.ControlEvent)
	return event
}

func coherenceChangeEntryProto(change volumeserver.ChangeEntry, position uint64) (*authoritypb.ChangeEntry, error) {
	entry := &authoritypb.ChangeEntry{Position: position, VolumeVersion: change.VolumeVersion}
	switch change.Kind {
	case volumeserver.NamespaceChanged:
		if change.ParentIdentity == ([16]byte{}) || len(change.Name) == 0 || change.Identity != ([16]byte{}) || change.HasRange {
			return nil, errInternal
		}
		entry.Kind = authoritypb.ChangeKind_CHANGE_KIND_NAMESPACE_CHANGED
		entry.ParentIdentity = append([]byte(nil), change.ParentIdentity[:]...)
		entry.Name = []byte(change.Name)
	case volumeserver.AttributesChanged, volumeserver.DelegationGranted, volumeserver.DelegationReleased, volumeserver.DirectoryChanged:
		if change.Identity == ([16]byte{}) || change.ParentIdentity != ([16]byte{}) || change.Name != "" || change.HasRange {
			return nil, errInternal
		}
		switch change.Kind {
		case volumeserver.AttributesChanged:
			entry.Kind = authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED
		case volumeserver.DelegationGranted:
			entry.Kind = authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_GRANTED
		case volumeserver.DelegationReleased:
			entry.Kind = authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_RELEASED
		case volumeserver.DirectoryChanged:
			entry.Kind = authoritypb.ChangeKind_CHANGE_KIND_DIRECTORY_CHANGED
		}
		entry.Identity = append([]byte(nil), change.Identity[:]...)
	case volumeserver.DataChanged:
		if change.Identity == ([16]byte{}) || change.ParentIdentity != ([16]byte{}) || change.Name != "" {
			return nil, errInternal
		}
		entry.Kind = authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED
		entry.Identity = append([]byte(nil), change.Identity[:]...)
		if change.HasRange {
			if change.Length == 0 || change.Offset > ^uint64(0)-change.Length {
				return nil, errInternal
			}
			entry.ByteRange = &authoritypb.ByteRange{Offset: change.Offset, Length: change.Length}
		}
	default:
		return nil, errInternal
	}
	return entry, nil
}

func (h *VolumeHandler) handleCoherenceChangeAck(requestID uint64, id volumeserver.SessionID, request *authoritypb.ChangeAck) *authoritypb.Response {
	if request == nil || request.GetIncarnation() == 0 {
		return h.coherenceError(requestID, syscall.EINVAL)
	}
	token, err := h.coherenceToken(id)
	if err != nil || token.Incarnation != request.GetIncarnation() {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	if err := h.Coherence.CheckSession(token); err != nil {
		return h.coherenceError(requestID, err)
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	defer state.mu.Unlock()
	session := state.sessions[id]
	if session == nil || session.token != token {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	position := request.GetPosition()
	if position > session.changeDelivered {
		return h.coherenceError(requestID, volumeserver.ErrSubscriptionPosition)
	}
	if position <= session.changeAcked {
		return coherenceChangeAckResponse(h, requestID)
	}
	index := sort.Search(len(session.changePositions), func(i int) bool { return session.changePositions[i].wire >= position })
	if index == len(session.changePositions) || session.changePositions[index].wire != position {
		return h.coherenceError(requestID, volumeserver.ErrSubscriptionPosition)
	}
	if err := h.Coherence.Ack(token, session.changePositions[index].coordinator); err != nil {
		return h.coherenceError(requestID, err)
	}
	session.changeAcked = position
	session.changePositions = session.changePositions[index+1:]
	return coherenceChangeAckResponse(h, requestID)
}

func coherenceChangeAckResponse(h *VolumeHandler, requestID uint64) *authoritypb.Response {
	response := h.success(requestID)
	response.Body = &authoritypb.Response_ChangeAck{ChangeAck: &authoritypb.ChangeAckReply{}}
	return response
}

func (h *VolumeHandler) handleCoherenceDelegationAck(
	requestID uint64,
	id volumeserver.SessionID,
	kind coherenceControlEventKind,
	incarnation, eventSequence uint64,
	ref *authoritypb.DelegationRef,
	applied uint64,
) *authoritypb.Response {
	if incarnation == 0 || eventSequence == 0 || ref == nil || ref.GetGeneration() == 0 {
		return h.coherenceError(requestID, syscall.EINVAL)
	}
	token, err := h.coherenceToken(id)
	if err != nil || token.Incarnation != incarnation {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	if err := h.Coherence.CheckSession(token); err != nil {
		return h.coherenceError(requestID, err)
	}
	delegationID, err := parseCoherenceDelegationID(ref.GetId())
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	defer state.mu.Unlock()
	session := state.sessions[id]
	if session == nil || session.token != token {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	obligation := session.obligations[eventSequence]
	if obligation == nil || obligation.kind != kind {
		return h.coherenceError(requestID, volumeserver.ErrDelegationAck)
	}
	if obligation.id != delegationID || obligation.generation != ref.GetGeneration() {
		return h.coherenceError(requestID, volumeserver.ErrDelegationStale)
	}
	if obligation.completed {
		if obligation.appliedSequence != applied {
			return h.coherenceError(requestID, volumeserver.ErrDelegationAck)
		}
		return coherenceDelegationAckResponse(h, requestID, kind)
	}
	if h.CoherenceApplications == nil || !h.CoherenceApplications.ValidateCoherenceApplication(id, obligation.identity, applied) {
		return h.coherenceError(requestID, volumeserver.ErrDelegationAck)
	}
	if err := h.Coherence.AckDelegation(token, obligation.identity, obligation.id, obligation.generation, obligation.coordinatorRequest, applied); err != nil {
		return h.coherenceError(requestID, err)
	}
	obligation.completed = true
	obligation.appliedSequence = applied
	return coherenceDelegationAckResponse(h, requestID, kind)
}

func coherenceDelegationAckResponse(h *VolumeHandler, requestID uint64, kind coherenceControlEventKind) *authoritypb.Response {
	response := h.success(requestID)
	switch kind {
	case coherenceControlRecall:
		response.Body = &authoritypb.Response_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAckReply{}}
	case coherenceControlBreak:
		response.Body = &authoritypb.Response_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAckReply{}}
	case coherenceControlModeChange:
		response.Body = &authoritypb.Response_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAckReply{}}
	}
	return response
}

func (h *VolumeHandler) handleCoherenceDelegationRelease(requestID uint64, id volumeserver.SessionID, request *authoritypb.DelegationReleaseRequest) *authoritypb.Response {
	if request == nil || request.GetIncarnation() == 0 || len(request.GetDelegations()) == 0 || len(request.GetDelegations()) > coherenceControlBatchLimit {
		return h.coherenceError(requestID, syscall.EINVAL)
	}
	token, err := h.coherenceToken(id)
	if err != nil || token.Incarnation != request.GetIncarnation() {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	if err := h.Coherence.CheckSession(token); err != nil {
		return h.coherenceError(requestID, err)
	}
	digest, err := coherenceReleaseFingerprint(request)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	defer state.mu.Unlock()
	session := state.sessions[id]
	if session == nil || session.token != token {
		return h.coherenceError(requestID, volumeserver.ErrSubscription)
	}
	if _, replay := session.releaseReplays[digest]; replay {
		return coherenceDelegationReleaseResponse(h, requestID)
	}
	grants := make([]volumeserver.Delegation, len(request.GetDelegations()))
	applied := make([]uint64, len(request.GetDelegations()))
	for i, release := range request.GetDelegations() {
		ref := release.GetDelegation()
		delegationID, parseErr := parseCoherenceDelegationID(ref.GetId())
		if parseErr != nil || ref.GetGeneration() == 0 {
			return h.coherenceError(requestID, syscall.EINVAL)
		}
		tracked := session.delegations[delegationID]
		if tracked == nil || tracked.generation != ref.GetGeneration() {
			return h.coherenceError(requestID, volumeserver.ErrDelegationStale)
		}
		if tracked.retired {
			return h.coherenceError(requestID, volumeserver.ErrDelegationAck)
		}
		if h.CoherenceApplications == nil || !h.CoherenceApplications.ValidateCoherenceApplication(id, tracked.identity, release.GetAppliedSequence()) {
			return h.coherenceError(requestID, volumeserver.ErrDelegationAck)
		}
		grants[i] = volumeserver.Delegation{ID: delegationID, Identity: tracked.identity, Holder: id, Generation: tracked.generation}
		applied[i] = release.GetAppliedSequence()
	}
	if _, err := h.Coherence.ReleaseAppliedBatch(token, grants, applied); err != nil {
		return h.coherenceError(requestID, err)
	}
	for i, grant := range grants {
		session.delegations[grant.ID].retired = true
		for _, obligation := range session.obligations {
			if !obligation.completed && obligation.id == grant.ID && obligation.generation == grant.Generation {
				obligation.completed = true
				obligation.appliedSequence = applied[i]
			}
		}
	}
	session.releaseReplays[digest] = struct{}{}
	return coherenceDelegationReleaseResponse(h, requestID)
}

func coherenceReleaseFingerprint(request *authoritypb.DelegationReleaseRequest) ([32]byte, error) {
	var zero [32]byte
	hash := sha256.New()
	var previous []byte
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], request.GetIncarnation())
	_, _ = hash.Write(scratch[:])
	for _, release := range request.GetDelegations() {
		if release == nil || release.GetDelegation() == nil || len(release.GetDelegation().GetId()) != 16 ||
			previous != nil && bytes.Compare(previous, release.GetDelegation().GetId()) >= 0 {
			return zero, syscall.EINVAL
		}
		previous = release.GetDelegation().GetId()
		_, _ = hash.Write(previous)
		binary.BigEndian.PutUint64(scratch[:], release.GetDelegation().GetGeneration())
		_, _ = hash.Write(scratch[:])
		binary.BigEndian.PutUint64(scratch[:], release.GetAppliedSequence())
		_, _ = hash.Write(scratch[:])
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func coherenceDelegationReleaseResponse(h *VolumeHandler, requestID uint64) *authoritypb.Response {
	response := h.success(requestID)
	response.Body = &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}
	return response
}

func (h *VolumeHandler) expireCoherenceSession(id volumeserver.SessionID) {
	if h.Coherence != nil {
		h.Coherence.ExpireSession(id)
	}
}

func (h *VolumeHandler) forgetCoherenceSession(id volumeserver.SessionID) error {
	if h.Coherence == nil {
		return nil
	}
	if err := h.Coherence.ForgetSession(id); err != nil {
		return err
	}
	state := h.initCoherenceControlState()
	state.mu.Lock()
	delete(state.sessions, id)
	state.mu.Unlock()
	h.forgetCoherenceApplications(id)
	return nil
}
