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

func newCoherenceControlTestHandler(t *testing.T, maxFrame uint32) (*VolumeHandler, *volumeserver.CoherenceCoordinator) {
	t.Helper()
	coordinator := volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{MaxLogEntries: 256})
	handler := &VolumeHandler{Coherence: coordinator, MaxFrame: maxFrame}
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
	after := uint64(0)
	positions := make([]uint64, 0, 2*len(changes))
	for round := 0; round < 2; round++ {
		coordinator.OnCommit(changes)
		for len(positions) < (round+1)*len(changes) {
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
		if ack := ackChangeCoherenceControlTest(t, handler, id, subscribe.Incarnation, uint64(len(positions))); ack.Errno != 0 {
			t.Fatal(ack)
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

	// A peer change precedes the private break and requires an explicit receipt.
	publishPeerControlChange(coordinator)
	change := pollCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), 0).GetControlEvent()
	if change.GetChangeBatch() == nil {
		t.Fatalf("first event = %+v, want change batch", change)
	}
	if response := ackChangeCoherenceControlTest(t, handler, id, subscribe.GetIncarnation(), change.GetChangeBatch().Entries[0].Position); response.GetErrno() != 0 {
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
	publishPeerControlChange(coordinator)
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
		Incarnation: subscribe.GetIncarnation(), Delegations: releases, ReleaseSequence: 1,
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
		request.GetDelegationRelease().CompletedReleaseThrough = request.GetDelegationRelease().ReleaseSequence
		request.GetDelegationRelease().ReleaseSequence++
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
	stale.GetDelegationRelease().CompletedReleaseThrough = stale.GetDelegationRelease().ReleaseSequence
	stale.GetDelegationRelease().ReleaseSequence++
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
			publishPeerControlChange(coordinator)
			change := pollCoherenceControlTest(t, handler, id, subscribe.Incarnation, 0).GetControlEvent()
			if response := ackChangeCoherenceControlTest(t, handler, id, subscribe.Incarnation, change.GetChangeBatch().Entries[0].Position); response.Errno != 0 {
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
			request := &authoritypb.DelegationReleaseRequest{Incarnation: subscribe.Incarnation, ReleaseSequence: 1, Delegations: []*authoritypb.DelegationRelease{{Delegation: coherenceDelegationRefProto(grant)}}}
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
				publishPeerControlChange(coordinator)
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
		if err := coordinator.WaitWithdrawn(ctx, position, volumeserver.SessionID{}); err != nil {
			t.Fatalf("source-only position did not retire internally: %v", err)
		}
		select {
		case response := <-done:
			t.Fatalf("source-only poll ended: %v", response)
		default:
		}

	}
	if err := coordinator.CheckSession(token); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	state := handler.initCoherenceControlState()
	state.mu.Lock()
	cursor := state.sessions[id].coordinatorCursor
	state.mu.Unlock()
	if cursor < 1024 {
		t.Fatalf("cancelled poll lost implicit cursor: %d", cursor)
	}
	// A replacement long poll resumes from the internally acknowledged cursor.
	retry, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer stop()
	response := handler.handleCoherencePoll(retry, 2, id, &authoritypb.NextControlEventRequest{Incarnation: subscribe.Incarnation})
	if response.GetErrno() == int32(errnos.EINVAL) {
		t.Fatalf("retry rejected retained cursor: %v", response)
	}
}

func TestCoherenceLongLivedControlReplayRetiresOnlyExplicitReceipts(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribed, token := subscribeCoherenceControlTest(t, handler, id)
	var cursor, completed uint64
	poll := func() *authoritypb.ControlEvent {
		t.Helper()
		response := handler.handleCoherencePoll(t.Context(), 1, id, &authoritypb.NextControlEventRequest{Incarnation: subscribed.Incarnation, AfterSequence: cursor, CompletedEventThrough: completed})
		if response.Errno != 0 {
			t.Fatal(response)
		}
		event := response.GetControlEvent()
		cursor = event.Sequence
		return event
	}
	ackChange := func(event *authoritypb.ControlEvent) {
		t.Helper()
		entries := event.GetChangeBatch().GetEntries()
		if len(entries) == 0 {
			t.Fatal(event)
		}
		if response := ackChangeCoherenceControlTest(t, handler, id, subscribed.Incarnation, entries[len(entries)-1].Position); response.Errno != 0 {
			t.Fatal(response)
		}
		completed = event.Sequence
	}
	for sequence := uint64(1); sequence <= 10000; sequence++ {
		if sequence%1000 == 0 {
			if _, err := coordinator.Renew(token); err != nil {
				t.Fatal(err)
			}
		}
		reservation, err := coordinator.ReserveNew(token, [16]byte{1})
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
		publishPeerControlChange(coordinator)
		ackChange(poll())
		done := make(chan error, 1)
		go func() { done <- coordinator.BreakForRead(t.Context(), grant.Identity) }()
		event := poll()
		for range 2 {
			response := handler.handleCoherenceDelegationAck(2, id, coherenceControlBreak, subscribed.Incarnation, event.Sequence, coherenceDelegationRefProto(grant), 0)
			if response.Errno != 0 {
				t.Fatal(response)
			}
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		release := &authoritypb.DelegationReleaseRequest{Incarnation: subscribed.Incarnation, ReleaseSequence: sequence, CompletedReleaseThrough: sequence - 1, Delegations: []*authoritypb.DelegationRelease{{Delegation: coherenceDelegationRefProto(grant)}}}
		if sequence == 1 {
			gap := proto.Clone(release).(*authoritypb.DelegationReleaseRequest)
			gap.ReleaseSequence = 2
			if response := handler.handleCoherenceDelegationRelease(3, id, gap); response.Errno == 0 {
				t.Fatal("release sequence gap accepted")
			}
		}
		for range 2 {
			if response := handler.handleCoherenceDelegationRelease(3, id, release); response.Errno != 0 {
				t.Fatal(response)
			}
		}
		// Delivery can overtake an ACK retry; it must not discard that result.
		publishPeerControlChange(coordinator)
		released := poll()
		if response := handler.handleCoherenceDelegationAck(4, id, coherenceControlBreak, subscribed.Incarnation, event.Sequence, coherenceDelegationRefProto(grant), 0); response.Errno != 0 {
			t.Fatal("poll delivery retired ACK replay", response)
		}
		ackChange(released)
		state := handler.initCoherenceControlState().sessions[id]
		if len(state.obligations) > 1 || len(state.delegations) != 0 || state.releaseReplay == nil || state.releaseReplay.sequence != sequence {
			t.Fatalf("retained history: obligations=%d grants=%d replay=%v", len(state.obligations), len(state.delegations), state.releaseReplay)
		}
	}
}

func TestCoherenceCompletedEventReceiptCannotAcknowledgeFailedHandler(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribed, token := subscribeCoherenceControlTest(t, handler, id)
	reservation, err := coordinator.ReserveNew(token, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := reservation.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	publishPeerControlChange(coordinator)
	initial := pollCoherenceControlTest(t, handler, id, subscribed.Incarnation, 0).GetControlEvent()
	entries := initial.GetChangeBatch().GetEntries()
	if response := ackChangeCoherenceControlTest(t, handler, id, subscribed.Incarnation, entries[len(entries)-1].Position); response.Errno != 0 {
		t.Fatal(response)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- coordinator.BreakForRead(ctx, grant.Identity) }()
	event := pollCoherenceControlTest(t, handler, id, subscribed.Incarnation, initial.Sequence).GetControlEvent()
	if event.GetDelegationBreak() == nil {
		t.Fatal(event)
	}
	coordinator.OnCommit([]volumeserver.ChangeEntry{{Kind: volumeserver.AttributesChanged, Identity: [16]byte{2}, VolumeVersion: 1}})
	response := handler.handleCoherencePoll(ctx, 4, id, &authoritypb.NextControlEventRequest{Incarnation: subscribed.Incarnation, AfterSequence: event.Sequence, CompletedEventThrough: event.Sequence})
	if response.Errno != 0 {
		t.Fatal(response)
	}
	if len(handler.initCoherenceControlState().sessions[id].obligations) != 0 {
		t.Fatal("surrendered replay retained")
	}
	select {
	case err := <-done:
		t.Fatalf("receipt completed unacknowledged cut: %v", err)
	default:
	}
	if response := handler.handleCoherenceDelegationAck(5, id, coherenceControlBreak, subscribed.Incarnation, event.Sequence, coherenceDelegationRefProto(grant), 0); response.Errno == 0 {
		t.Fatal("surrendered ACK replay accepted")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if coordinator.LossSequence(id) == 0 {
		t.Fatal("failed handler did not advance loss at recall deadline")
	}
	if _, live := coordinator.LookupDelegation(grant.Identity); live {
		t.Fatal("failed handler retained grant")
	}
}

func TestCoherencePollReusesBoundedStorageWithoutAliasingReplies(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribed, _ := subscribeCoherenceControlTest(t, handler, id)
	var first *authoritypb.ControlEvent
	var saved *authoritypb.ControlEvent
	var backing *volumeserver.StreamEvent
	var after uint64
	for round := 0; round < 3; round++ {
		changes := make([]volumeserver.ChangeEntry, 64)
		for i := range changes {
			changes[i] = volumeserver.ChangeEntry{VolumeVersion: uint64(round + 1), Kind: volumeserver.NamespaceChanged, ParentIdentity: [16]byte{1}, Name: fmt.Sprintf("round-%d-name-%d", round, i)}
		}
		coordinator.OnCommit(changes)
		response := pollCoherenceControlTest(t, handler, id, subscribed.Incarnation, after)
		event := response.GetControlEvent()
		if response.Errno != 0 || len(event.GetChangeBatch().GetEntries()) != len(changes) {
			t.Fatalf("round %d: %v", round, response)
		}
		for i, entry := range event.GetChangeBatch().GetEntries() {
			if string(entry.Name) != changes[i].Name || entry.Position != uint64(round*64+i+1) {
				t.Fatalf("round %d entry %d: %v", round, i, entry)
			}
		}
		state := handler.initCoherenceControlState()
		state.mu.Lock()
		buffer := state.sessions[id].pollBuffer
		if len(buffer) != 64 || cap(buffer) > coherenceControlBatchLimit {
			t.Errorf("buffer len=%d cap=%d", len(buffer), cap(buffer))
		}
		if round == 0 {
			backing = &buffer[0]
		} else if backing != &buffer[0] {
			t.Error("poll failed to reuse its bounded buffer")
		}
		state.mu.Unlock()
		if round == 0 {
			first = event
			saved = proto.Clone(event).(*authoritypb.ControlEvent)
		} else if !proto.Equal(first, saved) {
			t.Fatal("buffer reuse changed an earlier wire response")
		}
		replay := pollCoherenceControlTest(t, handler, id, subscribed.Incarnation, after)
		if !proto.Equal(event, replay.GetControlEvent()) {
			t.Fatal("buffer reuse changed current replay")
		}
		after = event.Sequence
		if ack := ackChangeCoherenceControlTest(t, handler, id, subscribed.Incarnation, uint64((round+1)*64)); ack.Errno != 0 {
			t.Fatal(ack)
		}
	}
}

func TestCoherencePollDoesNotClearAliasedFrameLeftover(t *testing.T) {
	handler, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribed, token := subscribeCoherenceControlTest(t, handler, id)
	identity := [16]byte{0x71}
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
	publishPeerControlChange(coordinator)
	breakDone := make(chan error, 1)
	go func() { breakDone <- coordinator.BreakForRead(t.Context(), identity) }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for found := false; !found; {
		events, pollErr := coordinator.Poll(ctx, token, 0, nil, 16)
		if pollErr != nil {
			t.Fatal(pollErr)
		}
		for _, event := range events {
			found = found || event.Kind == volumeserver.StreamBreakForRead
		}
	}

	first := pollCoherenceControlTest(t, handler, id, subscribed.Incarnation, 0).GetControlEvent()
	if first.GetChangeBatch() == nil {
		t.Fatalf("first event = %+v, want change batch", first)
	}
	state := handler.initCoherenceControlState()
	state.mu.Lock()
	session := state.sessions[id]
	aliased := false
	if len(session.queued) == 1 {
		for i := range session.pollBuffer {
			aliased = aliased || &session.queued[0] == &session.pollBuffer[i]
		}
	}
	if !aliased || session.queued[0].Kind != volumeserver.StreamBreakForRead {
		state.mu.Unlock()
		t.Fatalf("split queue does not alias retained poll buffer: queued=%+v buffer=%+v", session.queued, session.pollBuffer)
	}
	state.mu.Unlock()

	second := pollCoherenceControlTest(t, handler, id, subscribed.Incarnation, first.Sequence).GetControlEvent()
	if second.GetDelegationBreak() == nil || second.GetSequence() != first.GetSequence()+1 {
		t.Fatalf("aliased leftover = %+v, want contiguous break", second)
	}
	response := handler.handleCoherenceDelegationAck(99, id, coherenceControlBreak, subscribed.Incarnation, second.Sequence, coherenceDelegationRefProto(grant), 0)
	if response.GetErrno() != 0 {
		t.Fatal(response)
	}
	select {
	case err := <-breakDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("break did not complete after preserved leftover acknowledgment")
	}
}

func TestCoherencePollBufferReuseRequiresDrainedQueue(t *testing.T) {
	session := &coherenceControlSession{
		queued:     []volumeserver.StreamEvent{{Kind: volumeserver.StreamChange}},
		pollBuffer: []volumeserver.StreamEvent{{Kind: volumeserver.StreamChange}},
	}
	defer func() {
		if recover() == nil {
			t.Fatal("poll buffer reuse accepted an undrained aliased queue")
		}
	}()
	reuseCoherencePollBufferLocked(session)
}

func TestCoherenceControlAutoAckRequiresDrainedQueue(t *testing.T) {
	for _, state := range []string{"queued", "unacknowledged", "drained"} {
		t.Run(state, func(t *testing.T) {
			h, coordinator := newCoherenceControlTestHandler(t, 1<<20)
			_, token := subscribeCoherenceControlTest(t, h, volumeserver.SessionID{1})
			position := coordinator.OnCommit([]volumeserver.ChangeEntry{{VolumeVersion: 1, Kind: volumeserver.AttributesChanged, Identity: [16]byte{1}}})
			events, err := coordinator.Poll(t.Context(), token, 0, nil, 16)
			if err != nil {
				t.Fatal(err)
			}
			session := &coherenceControlSession{token: token, coordinatorCursor: position}
			switch state {
			case "queued":
				session.queued = events
			case "unacknowledged":
				session.changeDelivered = 1
			case "drained":
				session.changeDelivered, session.changeAcked = 1, 1
			}
			if err := h.retireCoherenceAdvancesLocked(session); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
			defer cancel()
			err = coordinator.WaitWithdrawn(ctx, position, volumeserver.SessionID{})
			if state == "drained" {
				if err != nil {
					t.Fatalf("drained position not retired: %v", err)
				}
			} else if err == nil {
				t.Fatalf("%s change acknowledged without wire withdrawal", state)
			}
		})
	}
}

func TestCoherencePeerAckRetiresTrailingSourceAdvance(t *testing.T) {
	h, coordinator := newCoherenceControlTestHandler(t, 1<<20)
	id := volumeserver.SessionID{1}
	subscribed, _ := subscribeCoherenceControlTest(t, h, id)
	coordinator.OnCommit([]volumeserver.ChangeEntry{{Kind: volumeserver.AttributesChanged, Identity: [16]byte{3}, VolumeVersion: 2}})
	last := coordinator.OnCommitFrom([]volumeserver.ChangeEntry{{Kind: volumeserver.AttributesChanged, Identity: [16]byte{4}, VolumeVersion: 3}}, id)
	event := pollCoherenceControlTest(t, h, id, subscribed.Incarnation, 0).GetControlEvent()
	entries := event.GetChangeBatch().GetEntries()
	if len(entries) != 1 {
		t.Fatalf("wire entries=%v, want exact peer change", entries)
	}
	before, cancelBefore := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancelBefore()
	if err := coordinator.WaitWithdrawn(before, last, volumeserver.SessionID{}); err == nil {
		t.Fatal("source advance acknowledged an unwithdrawn peer change")
	}
	if response := ackChangeCoherenceControlTest(t, h, id, subscribed.Incarnation, entries[0].Position); response.GetErrno() != 0 {
		t.Fatal(response)
	}
	after, cancelAfter := context.WithTimeout(t.Context(), time.Second)
	defer cancelAfter()
	if err := coordinator.WaitWithdrawn(after, last, volumeserver.SessionID{}); err != nil {
		t.Fatalf("peer ACK did not retire trailing source advance: %v", err)
	}
}

// Real peer facts keep replay tests independent of holder-local bookkeeping.
func publishPeerControlChange(c *volumeserver.CoherenceCoordinator) {
	c.OnCommit([]volumeserver.ChangeEntry{{Kind: volumeserver.AttributesChanged, Identity: [16]byte{0xf0}, VolumeVersion: 1}})
}
