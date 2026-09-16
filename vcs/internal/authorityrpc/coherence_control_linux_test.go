//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

type coherenceValidatorFunc func(volumeserver.SessionID, [16]byte, uint64) bool

func TestCoherenceChangesSkipInternalEventsWithoutCursorHoles(t *testing.T) {
	for _, internal := range []volumeserver.StreamEventKind{volumeserver.StreamAdvance, volumeserver.StreamLoss} {
		for _, trailing := range []bool{false, true} {
			handler, _ := newCoherenceControlTestHandler(t, 1<<20)
			change := func(position uint64) volumeserver.StreamEvent {
				return volumeserver.StreamEvent{Position: position, Kind: volumeserver.StreamChange,
					Change: volumeserver.ChangeEntry{VolumeVersion: 1, Kind: volumeserver.AttributesChanged, Identity: [16]byte{1}}}
			}
			session := &coherenceControlSession{token: volumeserver.SubscriptionToken{Session: volumeserver.SessionID{1}, Incarnation: 1},
				queued: []volumeserver.StreamEvent{change(1), {Position: 2, Kind: internal}, {Position: 3, Kind: internal}}}
			want := 1
			if !trailing {
				session.queued = append(session.queued, change(4))
				want++
			}
			event, ok, err := handler.nextCoherenceControlEventLocked(session)
			if err != nil || !ok || len(event.GetChangeBatch().GetEntries()) != want {
				t.Fatalf("internal=%d trailing=%t: event=%v ok=%t err=%v", internal, trailing, event, ok, err)
			}
			for index, entry := range event.GetChangeBatch().GetEntries() {
				if entry.GetPosition() != uint64(index+1) {
					t.Fatalf("change position %d = %d", index, entry.GetPosition())
				}
			}
			if len(session.queued) != 0 || session.changeDelivered != uint64(want) {
				t.Fatalf("queue/cursor = %v/%d", session.queued, session.changeDelivered)
			}
		}
	}
}

func (f coherenceValidatorFunc) ValidateCoherenceApplication(session volumeserver.SessionID, identity [16]byte, sequence uint64) bool {
	return f(session, identity, sequence)
}

func newCoherenceControlTestHandler(t *testing.T, maxFrame uint32) (*VolumeHandler, *volumeserver.CoherenceCoordinator) {
	t.Helper()
	coordinator := volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{MaxLogEntries: 256})
	handler := &VolumeHandler{Coherence: coordinator, MaxFrame: maxFrame}
	handler.CoherenceApplications = coherenceValidatorFunc(func(volumeserver.SessionID, [16]byte, uint64) bool { return true })
	state := handler.initCoherenceControlState()
	state.random = bytes.NewReader(bytes.Repeat([]byte{0x7a}, 1024))
	return handler, coordinator
}

func subscribeCoherenceControlTest(t *testing.T, handler *VolumeHandler, id volumeserver.SessionID) (*authoritypb.SubscribeReply, volumeserver.SubscriptionToken) {
	t.Helper()
	response, handled := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 1,
		Body:      &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{}},
	}, volumeserver.SessionCredential{ID: id})
	if !handled || response.GetErrno() != 0 || response.GetSubscribe() == nil {
		t.Fatalf("Subscribe response = %+v, handled=%t", response, handled)
	}
	token, err := handler.coherenceToken(id)
	if err != nil {
		t.Fatal(err)
	}
	return response.GetSubscribe(), token
}

func pollCoherenceControlTest(t *testing.T, handler *VolumeHandler, id volumeserver.SessionID, incarnation, after uint64) *authoritypb.Response {
	t.Helper()
	response, handled := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 2,
		Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{
			Incarnation: incarnation, AfterSequence: after,
		}},
	}, volumeserver.SessionCredential{ID: id})
	if !handled {
		t.Fatal("NextControlEvent was not handled")
	}
	return response
}

func ackChangeCoherenceControlTest(t *testing.T, handler *VolumeHandler, id volumeserver.SessionID, incarnation, position uint64) *authoritypb.Response {
	t.Helper()
	response, handled := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 3,
		Body: &authoritypb.Request_ChangeAck{ChangeAck: &authoritypb.ChangeAck{
			Incarnation: incarnation, Position: position,
		}},
	}, volumeserver.SessionCredential{ID: id})
	if !handled {
		t.Fatal("ChangeAck was not handled")
	}
	return response
}

func TestCoherenceSubscribePaginationIsFrozenSequentialAndReplaySafe(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, responseEnvelopeReserve+100)
	holder := volumeserver.SessionID{1}
	_, holderToken := subscribeCoherenceControlTest(t, handler, holder)
	for value := byte(8); value >= 1; value-- {
		identity := [16]byte{value}
		if _, err := coordinator.ReserveNew(holderToken, identity); err != nil {
			t.Fatal(err)
		}
	}

	subscriber := volumeserver.SessionID{2}
	first, _ := subscribeCoherenceControlTest(t, handler, subscriber)
	if len(first.GetDelegatedIdentities()) == 0 || len(first.GetNextAfterIdentity()) != 16 {
		t.Fatalf("first page = %+v, want a nonfinal bounded page", first)
	}
	if proto.Size(first) > int(handler.maxReplyBytes()) {
		t.Fatalf("first page size = %d, limit = %d", proto.Size(first), handler.maxReplyBytes())
	}
	if first.GetIncarnation() == 0 || len(first.GetSnapshotId()) != 16 || first.GetHorizonNanos() == 0 || first.GetHorizonNanos() > uint64(volumeserver.SubscriptionTTL) {
		t.Fatalf("invalid subscription envelope: %+v", first)
	}
	for i := 1; i < len(first.GetDelegatedIdentities()); i++ {
		if bytes.Compare(first.GetDelegatedIdentities()[i-1], first.GetDelegatedIdentities()[i]) >= 0 {
			t.Fatal("delegated identities are not sorted")
		}
	}
	request := &authoritypb.SubscribeRequest{SnapshotId: first.GetSnapshotId(), AfterIdentity: first.GetNextAfterIdentity()}
	pageRequest := &authoritypb.Request{RequestId: 4, Body: &authoritypb.Request_Subscribe{Subscribe: request}}
	second, handled := handler.handleCoherenceControl(t.Context(), pageRequest, volumeserver.SessionCredential{ID: subscriber})
	if !handled || second.GetErrno() != 0 || second.GetSubscribe() == nil {
		t.Fatalf("second page = %+v", second)
	}
	if proto.Size(second.GetSubscribe()) > int(handler.maxReplyBytes()) {
		t.Fatalf("second page size = %d, limit = %d", proto.Size(second.GetSubscribe()), handler.maxReplyBytes())
	}
	replayed, _ := handler.handleCoherenceControl(t.Context(), pageRequest, volumeserver.SessionCredential{ID: subscriber})
	if !proto.Equal(second.GetSubscribe(), replayed.GetSubscribe()) {
		t.Fatalf("page replay changed: first=%+v replay=%+v", second, replayed)
	}
	if second.GetSubscribe().GetWatermark() != first.GetWatermark() || second.GetSubscribe().GetIncarnation() != first.GetIncarnation() ||
		second.GetSubscribe().GetHorizonNanos() != first.GetHorizonNanos() || !bytes.Equal(second.GetSubscribe().GetSnapshotId(), first.GetSnapshotId()) {
		t.Fatal("pagination changed the frozen subscription envelope")
	}
	bad, _ := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 5, Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{
			SnapshotId: first.GetSnapshotId(), AfterIdentity: bytes.Repeat([]byte{0xff}, 16),
		}},
	}, volumeserver.SessionCredential{ID: subscriber})
	if bad.GetErrno() != errnos.EINVAL {
		t.Fatalf("out-of-order page errno=%d, want EINVAL", bad.GetErrno())
	}
}

func TestCoherenceRenewAndChangeStreamUseIndependentCursors(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, _ := subscribeCoherenceControlTest(t, handler, id)
	renew, handled := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 6,
		Body:      &authoritypb.Request_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionRequest{Incarnation: subscribe.GetIncarnation()}},
	}, volumeserver.SessionCredential{ID: id})
	if !handled || renew.GetErrno() != 0 || renew.GetRenewSubscription().GetIncarnation() != subscribe.GetIncarnation() ||
		renew.GetRenewSubscription().GetHorizonNanos() == 0 || renew.GetRenewSubscription().GetHorizonNanos() > uint64(volumeserver.SubscriptionTTL) {
		t.Fatalf("RenewSubscription response = %+v", renew)
	}

	coordinator.OnCommit([]volumeserver.ChangeEntry{
		{VolumeVersion: 7, Kind: volumeserver.AttributesChanged, Identity: [16]byte{1}},
		{VolumeVersion: 7, Kind: volumeserver.DataChanged, Identity: [16]byte{1}, HasRange: true, Offset: 4, Length: 8},
	})
	response := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0)
	event := response.GetControlEvent()
	if response.GetErrno() != 0 || event.GetSequence() != 1 || event.GetChangeBatch() == nil || len(event.GetChangeBatch().GetEntries()) != 2 {
		t.Fatalf("ControlEvent = %+v", response)
	}
	for index, entry := range event.GetChangeBatch().GetEntries() {
		if entry.GetPosition() != uint64(index+1) {
			t.Fatalf("change position %d = %d", index, entry.GetPosition())
		}
	}
	if event.GetChangeBatch().GetEntries()[1].GetByteRange().GetOffset() != 4 || event.GetChangeBatch().GetEntries()[1].GetByteRange().GetLength() != 8 {
		t.Fatal("data range was not preserved")
	}
	replay := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0)
	if !proto.Equal(event, replay.GetControlEvent()) {
		t.Fatalf("poll replay changed: first=%+v replay=%+v", event, replay.GetControlEvent())
	}
	if future := ackChangeCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 3); future.GetErrno() != errnos.EINVAL {
		t.Fatalf("future ChangeAck errno=%d, want EINVAL", future.GetErrno())
	}
	if ack := ackChangeCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 2); ack.GetErrno() != 0 || ack.GetChangeAck() == nil {
		t.Fatalf("ChangeAck response = %+v", ack)
	}
	if ack := ackChangeCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 1); ack.GetErrno() != 0 {
		t.Fatalf("older ChangeAck response = %+v", ack)
	}
}

func TestCoherenceChangeBatchesRespectReplyFrameLimit(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, responseEnvelopeReserve+150)
	id := volumeserver.SessionID{1}
	subscribe, _ := subscribeCoherenceControlTest(t, handler, id)
	changes := make([]volumeserver.ChangeEntry, 5)
	for i := range changes {
		changes[i] = volumeserver.ChangeEntry{
			VolumeVersion: 1, Kind: volumeserver.NamespaceChanged,
			ParentIdentity: [16]byte{1}, Name: string(bytes.Repeat([]byte{byte('a' + i)}, 64)),
		}
	}
	coordinator.OnCommit(changes)

	after := uint64(0)
	positions := make([]uint64, 0, len(changes))
	for len(positions) < len(changes) {
		response := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), after)
		if response.GetErrno() != 0 || response.GetControlEvent().GetChangeBatch() == nil {
			t.Fatalf("bounded poll = %+v", response)
		}
		if proto.Size(response.GetControlEvent()) > handler.coherenceReplyLimit() {
			t.Fatalf("control event size = %d, limit = %d", proto.Size(response.GetControlEvent()), handler.coherenceReplyLimit())
		}
		after = response.GetControlEvent().GetSequence()
		for _, entry := range response.GetControlEvent().GetChangeBatch().GetEntries() {
			positions = append(positions, entry.GetPosition())
		}
	}
	for i, position := range positions {
		if position != uint64(i+1) {
			t.Fatalf("position[%d] = %d", i, position)
		}
	}
}

func TestCoherencePollRejectsConcurrentOutstandingPoll(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, _ := subscribeCoherenceControlTest(t, handler, id)
	firstDone := make(chan *authoritypb.Response, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() {
		response, _ := handler.handleCoherenceControl(ctx, &authoritypb.Request{
			RequestId: 7, Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{
				Incarnation: subscribe.GetIncarnation(),
			}},
		}, volumeserver.SessionCredential{ID: id})
		firstDone <- response
	}()
	deadline := time.Now().Add(time.Second)
	for {
		state := handler.initCoherenceControlState()
		state.mu.Lock()
		active := state.sessions[id].pollActive
		state.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first poll did not park")
		}
	}
	second := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0)
	if second.GetErrno() != errnos.EINVAL {
		t.Fatalf("concurrent poll errno=%d, want EINVAL", second.GetErrno())
	}
	coordinator.OnCommit([]volumeserver.ChangeEntry{{VolumeVersion: 1, Kind: volumeserver.AttributesChanged, Identity: [16]byte{1}}})
	select {
	case response := <-firstDone:
		if response.GetErrno() != 0 || response.GetControlEvent() == nil {
			t.Fatalf("parked poll response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("parked poll did not wake")
	}
}

func TestCoherencePollRejectsReplayWhileNextPollIsOutstanding(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, _ := subscribeCoherenceControlTest(t, handler, id)
	coordinator.OnCommit([]volumeserver.ChangeEntry{{VolumeVersion: 1, Kind: volumeserver.AttributesChanged, Identity: [16]byte{1}}})
	first := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0)
	if first.GetErrno() != 0 || first.GetControlEvent().GetSequence() != 1 {
		t.Fatalf("first poll = %+v", first)
	}

	nextDone := make(chan *authoritypb.Response, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() {
		response, _ := handler.handleCoherenceControl(ctx, &authoritypb.Request{
			RequestId: 20, Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{
				Incarnation: subscribe.GetIncarnation(), AfterSequence: 1,
			}},
		}, volumeserver.SessionCredential{ID: id})
		nextDone <- response
	}()
	deadline := time.Now().Add(time.Second)
	for {
		state := handler.initCoherenceControlState()
		state.mu.Lock()
		active := state.sessions[id].pollActive
		state.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("next poll did not park")
		}
	}
	if replay := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0); replay.GetErrno() != errnos.EINVAL {
		t.Fatalf("concurrent replay errno=%d, want EINVAL", replay.GetErrno())
	}
	coordinator.OnCommit([]volumeserver.ChangeEntry{{VolumeVersion: 2, Kind: volumeserver.AttributesChanged, Identity: [16]byte{2}}})
	select {
	case response := <-nextDone:
		if response.GetErrno() != 0 || response.GetControlEvent().GetSequence() != 2 {
			t.Fatalf("next poll = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("next poll did not wake")
	}
}

func TestCoherenceDelegationBreakRecallAcksValidateTicketIdentityAndReplay(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, token := subscribeCoherenceControlTest(t, handler, id)
	identity := [16]byte{9}
	reservation, err := coordinator.ReserveNew(token, identity)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := reservation.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.rememberCoherenceDelegation(grant); err != nil {
		t.Fatal(err)
	}
	flush, err := coordinator.BeginFlush(token, identity, grant.ID, grant.Generation)
	if err != nil {
		t.Fatal(err)
	}
	flush.End(3)
	handler.CoherenceApplications = coherenceValidatorFunc(func(gotSession volumeserver.SessionID, gotIdentity [16]byte, sequence uint64) bool {
		return gotSession == id && gotIdentity == identity && (sequence == 0 || sequence == 3)
	})

	// The holder first receives the reservation's broadcast change.
	change := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0).GetControlEvent()
	if change.GetChangeBatch() == nil {
		t.Fatalf("first event = %+v, want change batch", change)
	}
	if response := ackChangeCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 1); response.GetErrno() != 0 {
		t.Fatal(response)
	}

	breakDone := make(chan error, 1)
	go func() { breakDone <- coordinator.BreakForRead(t.Context(), identity) }()
	breakEvent := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), change.GetSequence()).GetControlEvent()
	if breakEvent.GetDelegationBreak() == nil || breakEvent.GetSequence() != 2 {
		t.Fatalf("break event = %+v", breakEvent)
	}
	wrongTicket, _ := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 8, Body: &authoritypb.Request_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAck{
			Incarnation: subscribe.GetIncarnation(), EventSequence: breakEvent.GetSequence(),
			Delegation: breakEvent.GetDelegationBreak().GetDelegation(), AppliedSequence: 2,
		}},
	}, volumeserver.SessionCredential{ID: id})
	if wrongTicket.GetErrno() != errnos.EINVAL {
		t.Fatalf("foreign ticket errno=%d, want EINVAL", wrongTicket.GetErrno())
	}
	ackBreak := &authoritypb.Request{RequestId: 9, Body: &authoritypb.Request_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAck{
		Incarnation: subscribe.GetIncarnation(), EventSequence: breakEvent.GetSequence(),
		Delegation: breakEvent.GetDelegationBreak().GetDelegation(), AppliedSequence: 3,
	}}}
	for attempt := 0; attempt < 2; attempt++ {
		response, _ := handler.handleCoherenceControl(t.Context(), ackBreak, volumeserver.SessionCredential{ID: id})
		if response.GetErrno() != 0 || response.GetDelegationBreakAck() == nil {
			t.Fatalf("break ack attempt %d = %+v", attempt, response)
		}
	}
	if err := <-breakDone; err != nil {
		t.Fatal(err)
	}

	recallDone := make(chan error, 1)
	go func() { recallDone <- coordinator.Recall(t.Context(), identity) }()
	recallEvent := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), breakEvent.GetSequence()).GetControlEvent()
	if recallEvent.GetDelegationRecall() == nil || recallEvent.GetSequence() != 3 {
		t.Fatalf("recall event = %+v", recallEvent)
	}
	ackRecall := &authoritypb.Request{RequestId: 10, Body: &authoritypb.Request_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAck{
		Incarnation: subscribe.GetIncarnation(), EventSequence: recallEvent.GetSequence(),
		Delegation: recallEvent.GetDelegationRecall().GetDelegation(), AppliedSequence: 3,
	}}}
	response, _ := handler.handleCoherenceControl(t.Context(), ackRecall, volumeserver.SessionCredential{ID: id})
	if response.GetErrno() != 0 || response.GetDelegationRecallAck() == nil {
		t.Fatalf("recall ack = %+v", response)
	}
	if err := <-recallDone; err != nil {
		t.Fatal(err)
	}
}

func TestCoherenceDelegationModeAckControlsTransition(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	holder := volumeserver.SessionID{1}
	peer := volumeserver.SessionID{2}
	holderSubscribe, holderToken := subscribeCoherenceControlTest(t, handler, holder)
	_, peerToken := subscribeCoherenceControlTest(t, handler, peer)
	identity := [16]byte{7}
	if cacheable, err := coordinator.OpenCacheCapable(peerToken, identity); !cacheable || err != nil {
		t.Fatalf("OpenCacheCapable = %t, %v", cacheable, err)
	}
	reservation, err := coordinator.Reserve(t.Context(), holderToken, identity)
	if err != nil {
		t.Fatal(err)
	}
	peerEvents, err := coordinator.Poll(t.Context(), peerToken, 0, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ack(peerToken, peerEvents[len(peerEvents)-1].Position); err != nil {
		t.Fatal(err)
	}
	grant, err := reservation.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if grant.Mode != volumeserver.DelegationWritethrough {
		t.Fatalf("grant mode = %v", grant.Mode)
	}
	if err := handler.rememberCoherenceDelegation(grant); err != nil {
		t.Fatal(err)
	}
	grantEvent := pollCoherenceControlTest(t, handler, holder, holderSubscribe.GetIncarnation(), 0).GetControlEvent()
	if grantEvent.GetChangeBatch() == nil {
		t.Fatalf("grant event = %+v", grantEvent)
	}
	if err := coordinator.CloseCacheCapable(peerToken, identity); err != nil {
		t.Fatal(err)
	}
	modeEvent := pollCoherenceControlTest(t, handler, holder, holderSubscribe.GetIncarnation(), grantEvent.GetSequence()).GetControlEvent()
	if modeEvent.GetDelegationModeChange().GetMode() != authoritypb.DelegationMode_DELEGATION_MODE_FULL {
		t.Fatalf("mode event = %+v", modeEvent)
	}
	if current, _ := coordinator.LookupDelegation(identity); current.Mode != volumeserver.DelegationWritethrough {
		t.Fatal("coordinator installed mode before ack")
	}
	response, _ := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 11, Body: &authoritypb.Request_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAck{
			Incarnation: holderSubscribe.GetIncarnation(), EventSequence: modeEvent.GetSequence(),
			Delegation: modeEvent.GetDelegationModeChange().GetDelegation(),
		}},
	}, volumeserver.SessionCredential{ID: holder})
	if response.GetErrno() != 0 || response.GetDelegationModeChangeAck() == nil {
		t.Fatalf("mode ack = %+v", response)
	}
	if current, _ := coordinator.LookupDelegation(identity); current.Mode != volumeserver.DelegationFull {
		t.Fatal("coordinator did not install acknowledged mode")
	}
}

func TestCoherenceDelegationReleaseIsAtomicReplaySafeAndGenerationChecked(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, token := subscribeCoherenceControlTest(t, handler, id)
	grants := make([]volumeserver.Delegation, 0, 2)
	for value := byte(1); value <= 2; value++ {
		reservation, err := coordinator.ReserveNew(token, [16]byte{value})
		if err != nil {
			t.Fatal(err)
		}
		grant, err := reservation.Grant(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := handler.rememberCoherenceDelegation(grant); err != nil {
			t.Fatal(err)
		}
		grants = append(grants, grant)
	}
	releases := make([]*authoritypb.DelegationRelease, len(grants))
	for i, grant := range grants {
		releases[i] = &authoritypb.DelegationRelease{Delegation: coherenceDelegationRefProto(grant)}
	}
	flush, err := coordinator.BeginFlush(token, grants[0].Identity, grants[0].ID, grants[0].Generation)
	if err != nil {
		t.Fatal(err)
	}
	flush.End(5)
	request := &authoritypb.Request{RequestId: 12, Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{
		Incarnation: subscribe.GetIncarnation(), Delegations: releases,
	}}}
	for _, stale := range []uint64{0, 3} {
		request.GetDelegationRelease().Delegations[0].AppliedSequence = stale
		response, _ := handler.handleCoherenceControl(t.Context(), request, volumeserver.SessionCredential{ID: id})
		if response.GetErrno() != errnos.EINVAL {
			t.Fatalf("release with stale applied ticket %d = %+v", stale, response)
		}
		for _, grant := range grants {
			if _, exists := coordinator.LookupDelegation(grant.Identity); !exists {
				t.Fatal("stale applied ticket partially released batch")
			}
		}
	}
	request.GetDelegationRelease().Delegations[0].AppliedSequence = 5
	for attempt := 0; attempt < 2; attempt++ {
		response, _ := handler.handleCoherenceControl(t.Context(), request, volumeserver.SessionCredential{ID: id})
		if response.GetErrno() != 0 || response.GetDelegationRelease() == nil {
			t.Fatalf("release attempt %d = %+v", attempt, response)
		}
	}
	for _, grant := range grants {
		if _, exists := coordinator.LookupDelegation(grant.Identity); exists {
			t.Fatal("released delegation remains live")
		}
	}
	conflict := proto.Clone(request).(*authoritypb.Request)
	conflict.GetDelegationRelease().Delegations[0].AppliedSequence = 1
	response, _ := handler.handleCoherenceControl(t.Context(), conflict, volumeserver.SessionCredential{ID: id})
	if response.GetErrno() != errnos.EINVAL {
		t.Fatalf("conflicting replay errno=%d, want EINVAL", response.GetErrno())
	}
	stale := proto.Clone(request).(*authoritypb.Request)
	stale.GetDelegationRelease().Delegations[0].Delegation.Generation++
	response, _ = handler.handleCoherenceControl(t.Context(), stale, volumeserver.SessionCredential{ID: id})
	if response.GetErrno() != errnos.EIO || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
		t.Fatalf("stale generation response = %+v", response)
	}
}

func TestCoherenceStaleIncarnationIsNonterminalCoherenceEIO(t *testing.T) {
	handler, _ := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, _ := subscribeCoherenceControlTest(t, handler, id)
	var terminal atomic.Int32
	handler.OnCoherenceFailure = func(error) { terminal.Add(1) }
	response, _ := handler.handleCoherenceControl(t.Context(), &authoritypb.Request{
		RequestId: 13, Body: &authoritypb.Request_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionRequest{
			Incarnation: subscribe.GetIncarnation() + 1,
		}},
	}, volumeserver.SessionCredential{ID: id})
	if response.GetErrno() != errnos.EIO || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
		t.Fatalf("stale incarnation response = %+v", response)
	}
	if terminal.Load() != 0 {
		t.Fatal("recoverable subscription fence triggered terminal coherence callback")
	}
}

func TestCoherenceDelegationIDEncodingRejectsForeignDomain(t *testing.T) {
	raw := coherenceDelegationID(42)
	if id, err := parseCoherenceDelegationID(raw); err != nil || id != 42 {
		t.Fatalf("round trip = %d, %v", id, err)
	}
	raw[0] ^= 0xff
	if _, err := parseCoherenceDelegationID(raw); err == nil {
		t.Fatal("foreign delegation domain was accepted")
	}
}

func TestCoherenceReleaseCompletesRacingBreak(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(fmt.Sprintf("delivered=%v", delivered), func(t *testing.T) {
			handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
			id := volumeserver.SessionID{1}
			subscribe, token := subscribeCoherenceControlTest(t, handler, id)
			identity := [16]byte{93}
			reservation, err := coordinator.ReserveNew(token, identity)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := reservation.Grant(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := handler.rememberCoherenceDelegation(grant); err != nil {
				t.Fatal(err)
			}
			change := pollCoherenceControlTest(t, handler, id, subscribe.Incarnation, 0).GetControlEvent()
			if response := ackChangeCoherenceControlTest(t, handler, id, subscribe.Incarnation, 1); response.Errno != 0 {
				t.Fatal(response)
			}
			done := make(chan error, 1)
			go func() { done <- coordinator.BreakForRead(t.Context(), identity) }()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			state := handler.initCoherenceControlState()
			state.mu.Lock()
			cursor := state.sessions[id].coordinatorCursor
			state.mu.Unlock()
			for found := false; !found; {
				events, err := coordinator.Poll(ctx, token, cursor, nil, 128)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					cursor = event.Position
					if event.Kind == volumeserver.StreamBreakForRead {
						found = true
					}
				}
			}
			var event *authoritypb.ControlEvent
			if delivered {
				event = pollCoherenceControlTest(t, handler, id, subscribe.Incarnation, change.Sequence).GetControlEvent()
				if event.GetDelegationBreak() == nil {
					t.Fatal(event)
				}
			}
			request := &authoritypb.DelegationReleaseRequest{Incarnation: subscribe.Incarnation, Delegations: []*authoritypb.DelegationRelease{{Delegation: coherenceDelegationRefProto(grant)}}}
			for attempt := 0; attempt < 2; attempt++ {
				if response := handler.handleCoherenceDelegationRelease(20, id, request); response.Errno != 0 {
					t.Fatal(response)
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("release did not complete peer break")
			}
			if delivered {
				response := handler.handleCoherenceDelegationAck(21, id, coherenceControlBreak, subscribe.Incarnation, event.Sequence, coherenceDelegationRefProto(grant), 0)
				if response.Errno != 0 {
					t.Fatal(response)
				}
			} else {
				response := pollCoherenceControlTest(t, handler, id, subscribe.Incarnation, change.Sequence)
				if response.Errno != 0 || response.GetControlEvent().GetChangeBatch() == nil {
					t.Fatalf("released reference emitted control obligation: %v", response)
				}
			}
			if coordinator.LossSequence(id) != 0 {
				t.Fatal("release recorded loss")
			}
		})
	}
}

func TestCoherenceSourceOnlyCommitsRetireInternalPositions(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribe, token := subscribeCoherenceControlTest(t, handler, id)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan *authoritypb.Response, 1)
	go func() {
		done <- handler.handleCoherencePoll(ctx, 1, id, &authoritypb.NextControlEventRequest{Incarnation: subscribe.Incarnation})
	}()
	for sequence := uint64(2); sequence < 1026; sequence++ {
		position := coordinator.OnCommitFrom([]volumeserver.ChangeEntry{{Kind: volumeserver.AttributesChanged, Identity: [16]byte{2}, VolumeVersion: sequence}}, id)
		for {
			state := handler.initCoherenceControlState()
			state.mu.Lock()
			cursor := state.sessions[id].coordinatorCursor
			state.mu.Unlock()
			if cursor >= position {
				break
			}
			select {
			case response := <-done:
				t.Fatalf("source-only poll ended: %v", response)
			case <-ctx.Done():
				t.Fatal("source-only cursor did not advance")
			case <-time.After(time.Millisecond):
			}
		}
	}
	if err := coordinator.CheckSession(token); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
}
