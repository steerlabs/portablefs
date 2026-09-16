package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type coherenceV2ClientHandler struct {
	clientTestHandler
	pollStarted chan struct{}
	pollRelease chan struct{}
	pollOnce    sync.Once
	paginate    bool
	pageDelay   time.Duration
}

func (h *coherenceV2ClientHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch()}
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Subscribe:
		identity := bytes.Repeat([]byte{0x21}, 16)
		if len(body.Subscribe.GetSnapshotId()) != 0 {
			if h.pageDelay != 0 {
				time.Sleep(h.pageDelay)
			}
			identity = bytes.Repeat([]byte{0x22}, 16)
		}
		reply := &authoritypb.SubscribeReply{
			Watermark:           41,
			DelegatedIdentities: [][]byte{identity},
			Incarnation:         7,
			HorizonNanos:        uint64(10 * time.Second),
			SnapshotId:          bytes.Repeat([]byte{0x31}, 16),
		}
		if h.paginate && len(body.Subscribe.GetSnapshotId()) == 0 {
			reply.NextAfterIdentity = bytes.Clone(identity)
		}
		response.Body = &authoritypb.Response_Subscribe{Subscribe: reply}
	case *authoritypb.Request_RenewSubscription:
		response.Body = &authoritypb.Response_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionReply{
			Incarnation: body.RenewSubscription.GetIncarnation(), HorizonNanos: uint64(10 * time.Second),
		}}
	case *authoritypb.Request_NextControlEvent:
		h.pollOnce.Do(func() { close(h.pollStarted) })
		select {
		case <-h.pollRelease:
		case <-ctx.Done():
			response.Errno = int32(syscall.EINTR)
			return response
		}
		response.Body = &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{
			Incarnation: body.NextControlEvent.GetIncarnation(),
			Sequence:    body.NextControlEvent.GetAfterSequence() + 1,
			Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{
				Incarnation: body.NextControlEvent.GetIncarnation(),
				Entries: []*authoritypb.ChangeEntry{{
					Position: 1, VolumeVersion: 41,
					Kind:     authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED,
					Identity: bytes.Repeat([]byte{0x41}, 16),
				}},
			}},
		}}
	case *authoritypb.Request_ChangeAck:
		response.Body = &authoritypb.Response_ChangeAck{ChangeAck: &authoritypb.ChangeAckReply{}}
	case *authoritypb.Request_DelegationRecallAck:
		response.Body = &authoritypb.Response_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAckReply{}}
	case *authoritypb.Request_DelegationBreakAck:
		response.Body = &authoritypb.Response_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAckReply{}}
	case *authoritypb.Request_DelegationModeChangeAck:
		response.Body = &authoritypb.Response_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAckReply{}}
	case *authoritypb.Request_DelegationRelease:
		response.Body = &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}
	case *authoritypb.Request_Barrier:
		response.Mutation = &authoritypb.MutationState{
			Slot: request.GetMutation().GetSlot(), AcceptedSequence: request.GetMutation().GetSequence(),
		}
		response.Body = &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{
			AppliedSequence: body.Barrier.GetCutSequence(), DurableSequence: body.Barrier.GetCutSequence(),
		}}
	default:
		return h.clientTestHandler.Handle(ctx, request)
	}
	return response
}

func TestSubscribePaginationKeepsInitialHorizonAnchor(t *testing.T) {
	handler := &coherenceV2ClientHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x19}, 16), maxInFlight: 6},
		pollStarted:       make(chan struct{}),
		pollRelease:       make(chan struct{}),
		paginate:          true,
		pageDelay:         25 * time.Millisecond,
	}
	client := dialCoherenceV2TestClient(t, handler)
	first, firstDeadline, err := client.Subscribe(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, secondDeadline, err := client.Subscribe(context.Background(), first.GetSnapshotId(), first.GetNextAfterIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if second.GetNextAfterIdentity() != nil {
		t.Fatal("second page did not complete the frozen snapshot")
	}
	if !secondDeadline.Equal(firstDeadline) {
		t.Fatalf("pagination extended initial horizon: first=%v second=%v", firstDeadline, secondDeadline)
	}
}

func dialCoherenceV2TestClient(t *testing.T, handler *coherenceV2ClientHandler) *Client {
	t.Helper()
	address, clientTLS, stop := startTestServer(t, handler, 6, time.Minute)
	t.Cleanup(stop)
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 6, 6))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSubscriptionRenewalAndAckProgressWhileControlPollIsParked(t *testing.T) {
	handler := &coherenceV2ClientHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x11}, 16), maxInFlight: 6},
		pollStarted:       make(chan struct{}),
		pollRelease:       make(chan struct{}),
	}
	client := dialCoherenceV2TestClient(t, handler)

	if client.laneFor(&authoritypb.Request{Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{}}}) != &client.controlPoll ||
		client.laneFor(&authoritypb.Request{Body: &authoritypb.Request_ChangeAck{ChangeAck: &authoritypb.ChangeAck{}}}) != &client.controlAck ||
		client.laneFor(&authoritypb.Request{Body: &authoritypb.Request_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionRequest{}}}) != &client.liveness {
		t.Fatal("protocol-7 poll, acknowledgment, and renewal did not receive independent admission lanes")
	}

	pollResult := make(chan error, 1)
	go func() {
		event, err := client.NextControlEvent(context.Background(), 7, 0)
		if err == nil && (event.GetSequence() != 1 || event.GetChangeBatch() == nil) {
			err = errors.New("control poll returned the wrong event")
		}
		pollResult <- err
	}()
	select {
	case <-handler.pollStarted:
	case <-time.After(time.Second):
		t.Fatal("control poll did not park at the authority")
	}

	renewStarted := time.Now()
	horizon, err := client.RenewSubscription(context.Background(), 7)
	if err != nil {
		t.Fatalf("RenewSubscription while poll parked: %v", err)
	}
	if horizon.Before(renewStarted.Add(9*time.Second)) || horizon.After(time.Now().Add(11*time.Second)) {
		t.Fatalf("renewed conservative horizon = %v", horizon)
	}
	if err := client.AcknowledgeChanges(context.Background(), 7, 1); err != nil {
		t.Fatalf("AcknowledgeChanges while poll parked: %v", err)
	}

	close(handler.pollRelease)
	if err := <-pollResult; err != nil {
		t.Fatal(err)
	}
}

func TestCoherenceV2ClientMethodsValidateAndCloneWireResults(t *testing.T) {
	handler := &coherenceV2ClientHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x12}, 16), maxInFlight: 6},
		pollStarted:       make(chan struct{}),
		pollRelease:       make(chan struct{}),
	}
	client := dialCoherenceV2TestClient(t, handler)

	started := time.Now()
	reply, horizon, err := client.Subscribe(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.GetIncarnation() != 7 || reply.GetWatermark() != 41 ||
		horizon.Before(started.Add(9*time.Second)) || horizon.After(time.Now().Add(11*time.Second)) {
		t.Fatalf("Subscribe reply=%+v horizon=%v", reply, horizon)
	}

	delegation := &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{0x51}, 16), Generation: 3}
	for name, acknowledge := range map[string]func() error{
		"recall": func() error {
			return client.AcknowledgeDelegationRecall(context.Background(), 7, 1, delegation, 9)
		},
		"break": func() error {
			return client.AcknowledgeDelegationBreak(context.Background(), 7, 2, delegation, 9)
		},
		"mode change": func() error {
			return client.AcknowledgeDelegationModeChange(context.Background(), 7, 3, delegation, 9)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := acknowledge(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := client.ReleaseDelegations(context.Background(), 7, []*authoritypb.DelegationRelease{{
		Delegation: delegation, AppliedSequence: 9,
	}}); err != nil {
		t.Fatal(err)
	}
	barrier, err := client.Barrier(context.Background(), 9)
	if err != nil || barrier.GetAppliedSequence() != 9 || barrier.GetDurableSequence() != 9 {
		t.Fatalf("Barrier = %+v, %v", barrier, err)
	}

	if _, _, err := client.Subscribe(context.Background(), bytes.Repeat([]byte{1}, 16), nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("half pagination cursor error = %v, want EINVAL", err)
	}
	if err := client.ReleaseDelegations(context.Background(), 7, []*authoritypb.DelegationRelease{
		{Delegation: &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{2}, 16), Generation: 1}},
		{Delegation: &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{1}, 16), Generation: 1}},
	}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("unsorted release error = %v, want EINVAL", err)
	}
}

func TestValidateControlEventRejectsMalformedProtocol7Bodies(t *testing.T) {
	identity := bytes.Repeat([]byte{0x61}, 16)
	ref := &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{0x62}, 16), Generation: 1}
	tests := []struct {
		name  string
		event *authoritypb.ControlEvent
	}{
		{name: "wrong successor", event: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 8,
			Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Delegation: ref, Identity: identity, BudgetNanos: 1}}}},
		{name: "empty batch", event: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 7,
			Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Incarnation: 2}}}},
		{
			name: "noncontiguous positions",
			event: &authoritypb.ControlEvent{
				Incarnation: 2,
				Sequence:    7,
				Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{
					Incarnation: 2,
					Entries: []*authoritypb.ChangeEntry{
						{Position: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity},
						{Position: 3, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity},
					},
				}},
			},
		},
		{name: "invalid mode target", event: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 7,
			Event: &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{
				Delegation: ref, Identity: identity, BudgetNanos: 1,
			}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateControlEvent(test.event, 2, 7); err == nil {
				t.Fatal("malformed event was accepted")
			}
		})
	}
}

func TestAuthorityEpochChangeWaitsForResponseConsumptionWithoutForcedRevocation(t *testing.T) {
	client := &Client{
		cfg:              ClientConfig{CancelDrainTimeout: 10 * time.Millisecond},
		fatalDone:        make(chan struct{}),
		fatalPendingDone: make(chan struct{}),
	}
	var forced bool
	receipt, err := client.beginResponseConsumption(func(error) { forced = true })
	if err != nil {
		t.Fatal(err)
	}
	client.signalSessionEnd(ErrAuthorityChanged)
	timer := time.NewTimer(30 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-client.SessionEndPending():
		t.Fatal("epoch terminal edge passed an unconsumed response")
	case <-timer.C:
	}
	if forced {
		t.Fatal("epoch change forced the mount revocation callback")
	}
	receipt.Consume()
	select {
	case <-client.SessionEndPending():
	case <-time.After(time.Second):
		t.Fatal("epoch terminal edge did not publish after response consumption")
	}
}
