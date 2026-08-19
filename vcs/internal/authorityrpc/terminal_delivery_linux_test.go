//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type terminalDeliveryStore struct {
	resourceAdmissionFaultStore
	fences atomic.Uint32
}

func (s *terminalDeliveryStore) Fence(error) { s.fences.Add(1) }

func terminalFallocateResponse(size, sequence uint64) *authoritypb.Response {
	return &authoritypb.Response{
		PostState: &authoritypb.PostState{VisibilitySequence: 2, SnapshotSequence: 2, Objects: []*authoritypb.ObjectPostState{{
			StableIdentity: []byte("0123456789abcdef"), ObjectVersion: 2,
			Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: int64(size)}, Roles: postStateRoleTarget,
		}}},
		Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
			PostSize: size, VisibilitySequence: sequence, Flags: rangeReplyApplied | rangeReplyPostApply, Error: -int32(syscall.EPERM),
		}},
	}
}

func TestStorageFatalTeardownWaitsForExactFrontendReceipt(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	called := make(chan error, 1)
	h.OnStorageFailure = func(err error) { called <- err }
	ordinary := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	if !h.beginTerminalRequest(ordinary) {
		t.Fatal("pre-fence handler was not admitted")
	}

	cause := errors.Join(xfsstore.ErrWritePostApply, xfsstore.ErrWritePrivilege, syscall.EPERM)
	response := terminalFallocateResponse(9, 4)
	h.deferStorageFailure(response, cause)
	if store.fences.Load() != 1 {
		t.Fatalf("store fence count = %d, want 1 before reply delivery", store.fences.Load())
	}
	if h.beginTerminalRequest(ordinary) {
		t.Fatal("post-fence filesystem request was admitted")
	}
	// Lease CONTROL must remain live while the already-applied operation
	// finishes its peer COMPLETE barrier.
	control := &authoritypb.Request{Body: &authoritypb.Request_AcknowledgeLeaseEvent{AcknowledgeLeaseEvent: &authoritypb.AcknowledgeLeaseEventRequest{}}}
	if !h.beginTerminalRequest(control) {
		t.Fatal("terminal lease control was refused")
	}
	h.endTerminalRequest()

	// Registration is deliberately at the immutable outer response boundary,
	// after retained-body reconstruction and visibility completion.
	h.prepareResponseWrite(ordinary, response, true)
	if len(response.GetTerminalDeliveryToken()) != 16 {
		t.Fatalf("terminal token length = %d, want 16", len(response.GetTerminalDeliveryToken()))
	}
	h.endTerminalRequest()
	h.ResponseWritten(response, nil)
	select {
	case err := <-called:
		t.Fatalf("terminal callback ran before frontend receipt: %v", err)
	default:
	}

	receiptRequest := &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceipt{Token: response.GetTerminalDeliveryToken()}}}
	if !h.beginTerminalRequest(receiptRequest) {
		t.Fatal("terminal receipt was refused")
	}
	receipt := h.terminalDeliveryReceipt(7, receiptRequest.GetTerminalDeliveryReceipt())
	if receipt.GetErrno() != 0 || receipt.GetTerminalDeliveryReceipt() == nil {
		t.Fatalf("terminal receipt response = %+v", receipt)
	}
	h.prepareResponseWrite(receiptRequest, receipt, true)
	h.endTerminalRequest()
	select {
	case err := <-called:
		t.Fatalf("terminal callback ran before receipt ACK write: %v", err)
	default:
	}
	h.ResponseWritten(receipt, nil)
	select {
	case err := <-called:
		if !errors.Is(err, xfsstore.ErrWritePrivilege) {
			t.Fatalf("terminal cause = %v", err)
		}
	default:
		t.Fatal("terminal callback did not run after exact frontend receipt")
	}
}

func TestTerminalDeliveryTokensCannotBeStolenByEqualBodies(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	called := make(chan error, 1)
	h.OnStorageFailure = func(err error) { called <- err }
	firstToken := bytes.Repeat([]byte{0x41}, 16)
	secondToken := bytes.Repeat([]byte{0x42}, 16)
	// Force the second token draw to collide with the first. The third draw is
	// the only legal identity for the second physical delivery obligation.
	h.terminalTokenReader = bytes.NewReader(append(append(append([]byte(nil), firstToken...), firstToken...), secondToken...))
	cause := errors.Join(xfsstore.ErrWritePostApply, xfsstore.ErrWritePrivilege, syscall.EPERM)
	if !h.beginTerminalRequest(&authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}) {
		t.Fatal("pre-fence handler was not admitted")
	}
	a := terminalFallocateResponse(9, 4)
	b := terminalFallocateResponse(9, 4)
	// Equal terminal result bodies belong to two independent physical response
	// instances; pointer identity must give each its own receipt obligation.
	h.deferStorageFailure(a, cause)
	h.deferStorageFailure(b, cause)
	h.prepareResponseWrite(&authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}, a, true)
	h.prepareResponseWrite(&authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}, b, true)
	if string(a.GetTerminalDeliveryToken()) == string(b.GetTerminalDeliveryToken()) {
		t.Fatal("equal terminal bodies received the same delivery token")
	}
	if !bytes.Equal(a.GetTerminalDeliveryToken(), firstToken) || !bytes.Equal(b.GetTerminalDeliveryToken(), secondToken) {
		t.Fatalf("collision retry tokens = %x %x, want %x %x", a.GetTerminalDeliveryToken(), b.GetTerminalDeliveryToken(), firstToken, secondToken)
	}
	h.endTerminalRequest()
	// An equal unregistered body and repeated physical observer call cannot
	// consume either opaque obligation.
	h.ResponseWritten(terminalFallocateResponse(9, 4), nil)
	h.ResponseWritten(a, nil)
	h.ResponseWritten(a, nil)
	select {
	case err := <-called:
		t.Fatalf("equal body or repeated write notification triggered teardown: %v", err)
	default:
	}
	for _, response := range []*authoritypb.Response{a, b} {
		receipt := &authoritypb.TerminalDeliveryReceipt{Token: response.GetTerminalDeliveryToken()}
		if !h.beginTerminalRequest(&authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{TerminalDeliveryReceipt: receipt}}) {
			t.Fatal("receipt request was not admitted")
		}
		got := h.terminalDeliveryReceipt(8, receipt)
		if got.GetErrno() != 0 {
			t.Fatalf("receipt = %+v", got)
		}
		receiptRequest := &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{TerminalDeliveryReceipt: receipt}}
		h.prepareResponseWrite(receiptRequest, got, true)
		h.endTerminalRequest()
		h.ResponseWritten(got, nil)
	}
	// b was intentionally never observed above; its physical DATA frame must
	// also settle before the final receipt ACK can release teardown.
	h.ResponseWritten(b, nil)
	select {
	case <-called:
	default:
		t.Fatal("teardown did not wait for both opaque receipts")
	}
}

func TestRetainedMutationTransfersTerminalReceiptAcrossReplayReconstruction(t *testing.T) {
	h, credential, store, handle, _ := newRangeMutationHarness(t)
	called := make(chan error, 1)
	h.OnStorageFailure = func(err error) { called <- err }
	store.fallocatePost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x21, Size: 12, Mode: 0o600, Nlink: 1}
	store.fallocateErr = errors.Join(xfsstore.ErrWritePostApply, xfsstore.ErrWritePrivilege, syscall.EPERM)
	firstRequest := fallocateMutationRequest(1, handle)
	replayRequest := fallocateMutationRequest(2, handle)
	// Both exact identities reached handler admission before the first one
	// discovered the terminal post-apply security failure. The replay slot
	// serializes them and storage must execute only once.
	if !h.beginTerminalRequest(firstRequest) || !h.beginTerminalRequest(replayRequest) {
		t.Fatal("pre-fence retained mutation handlers were not admitted")
	}
	first := h.handleFallocate(t.Context(), firstRequest, credential, firstRequest.GetFallocate())
	replay := h.handleFallocate(t.Context(), replayRequest, credential, replayRequest.GetFallocate())
	if first == replay {
		t.Fatal("retained mutation replay reused an inner protobuf pointer")
	}
	if store.fallocateCalls.Load() != 1 {
		t.Fatalf("retained mutation applied %d times, want 1", store.fallocateCalls.Load())
	}
	for index, response := range []*authoritypb.Response{first, replay} {
		h.prepareResponseWrite([]*authoritypb.Request{firstRequest, replayRequest}[index], response, true)
		if len(response.GetTerminalDeliveryToken()) != 16 {
			t.Fatalf("reconstructed response %d token length = %d, want 16", index, len(response.GetTerminalDeliveryToken()))
		}
	}
	if string(first.GetTerminalDeliveryToken()) == string(replay.GetTerminalDeliveryToken()) {
		t.Fatal("exact replay deliveries shared one receipt token")
	}
	if len(h.terminalReceiptFrames) != 2 {
		t.Fatalf("terminal response instances = %d, want only two reconstructed responses", len(h.terminalReceiptFrames))
	}
	h.endTerminalRequest()
	h.endTerminalRequest()
	h.ResponseWritten(first, nil)
	h.ResponseWritten(replay, nil)
	select {
	case err := <-called:
		t.Fatalf("terminal callback ran before replay receipts: %v", err)
	default:
	}
	for index, response := range []*authoritypb.Response{first, replay} {
		receiptRequest := &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{
			TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceipt{Token: response.GetTerminalDeliveryToken()},
		}}
		if !h.beginTerminalRequest(receiptRequest) {
			t.Fatalf("replay receipt %d was not admitted", index)
		}
		ack := h.terminalDeliveryReceipt(uint64(index+1), receiptRequest.GetTerminalDeliveryReceipt())
		h.prepareResponseWrite(receiptRequest, ack, true)
		h.endTerminalRequest()
		h.ResponseWritten(ack, nil)
	}
	select {
	case err := <-called:
		if !errors.Is(err, xfsstore.ErrWritePrivilege) {
			t.Fatalf("terminal cause = %v", err)
		}
	default:
		t.Fatal("terminal callback did not wait for both reconstructed receipts")
	}
}

func TestFailedTerminalFrameNeedsNoImpossibleReceipt(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	called := make(chan error, 1)
	h.OnStorageFailure = func(err error) { called <- err }
	request := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	if !h.beginTerminalRequest(request) {
		t.Fatal("pre-fence handler was not admitted")
	}
	response := terminalFallocateResponse(3, 1)
	h.deferStorageFailure(response, errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM))
	h.prepareResponseWrite(request, response, true)
	h.endTerminalRequest()
	h.ResponseWritten(response, syscall.EPIPE)
	select {
	case <-called:
	default:
		t.Fatal("failed terminal frame did not tear down after its write attempt")
	}
}

func TestAbandonedLifecycleResponseRetiresTransportFrame(t *testing.T) {
	h := testVolumeHandler()
	h.Store = &terminalDeliveryStore{}
	request := &authoritypb.Request{Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{}}}
	response := &authoritypb.Response{Body: &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{}}}
	if !h.beginTerminalRequest(request) {
		t.Fatal("lifecycle handler was not admitted")
	}
	h.retainTerminalHandlerResponse(response)
	cleanup := finishHandlerResponse(h, request, response)
	if len(h.terminalFrames) != 1 {
		t.Fatalf("transport frames after handler transfer = %d, want 1", len(h.terminalFrames))
	}
	// Model a transport-registry validation failure after Handle returned but
	// before writeObservedResponse took ownership of a socket write.
	cleanup()
	if len(h.terminalFrames) != 0 || len(h.terminalAdmittedFrames) != 0 || len(h.terminalReceiptFrames) != 0 {
		t.Fatalf("abandoned lifecycle frame leaked: frames=%d admitted=%d receipts=%d",
			len(h.terminalFrames), len(h.terminalAdmittedFrames), len(h.terminalReceiptFrames))
	}
	// The cleanup is intentionally safe after either abandonment or a real
	// observed write, because every server path defers it unconditionally.
	cleanup()
}

func TestTerminalDrainCapturesAlreadyQueuedAdmittedDataResponse(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	called := make(chan error, 1)
	h.OnStorageFailure = func(err error) { called <- err }
	dataRequest := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}

	// The handler has returned and transferred this response to the serialized
	// writer, but another response currently owns that writer.
	queued := &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{}}}
	if !h.beginTerminalRequest(dataRequest) {
		t.Fatal("queued DATA handler was not admitted")
	}
	h.retainTerminalHandlerResponse(queued)
	h.FinishHandlerResponse(dataRequest, queued)
	if len(queued.GetTerminalDeliveryToken()) != 0 {
		t.Fatal("response received a terminal token before terminal draining began")
	}

	// A later in-flight operation discovers the terminal cause. The queued
	// response is still an exact client consumption obligation even though its
	// body was constructed before the fence.
	terminal := terminalFallocateResponse(5, 2)
	if !h.beginTerminalRequest(dataRequest) {
		t.Fatal("terminal DATA handler was not admitted")
	}
	h.deferStorageFailure(terminal, errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM))
	h.retainTerminalHandlerResponse(terminal)
	h.FinishHandlerResponse(dataRequest, terminal)
	if len(terminal.GetTerminalDeliveryToken()) != 16 {
		t.Fatalf("terminal response token length = %d, want 16", len(terminal.GetTerminalDeliveryToken()))
	}

	// When the queued response finally reaches the writer it remains a physical
	// frame obligation, but it receives no cross-process receipt: this response
	// did not carry the terminal applied-state result. A strict frontend's local
	// pre-registered consumption still keeps its SessionDone behind publication.
	h.PrepareResponseWrite(dataRequest, queued)
	if len(queued.GetTerminalDeliveryToken()) != 0 {
		t.Fatalf("queued nonterminal response token length = %d, want 0", len(queued.GetTerminalDeliveryToken()))
	}
	h.ResponseWritten(queued, nil)
	h.ResponseWritten(terminal, nil)
	select {
	case err := <-called:
		t.Fatalf("terminal callback ran before queued response consumption: %v", err)
	default:
	}

	for index, response := range []*authoritypb.Response{terminal} {
		receiptRequest := &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{
			TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceipt{Token: response.GetTerminalDeliveryToken()},
		}}
		if !h.beginTerminalRequest(receiptRequest) {
			t.Fatalf("receipt %d was not admitted", index)
		}
		ack := h.terminalDeliveryReceipt(uint64(index+1), receiptRequest.GetTerminalDeliveryReceipt())
		h.prepareResponseWrite(receiptRequest, ack, true)
		h.endTerminalRequest()
		h.ResponseWritten(ack, nil)
	}
	select {
	case <-called:
	default:
		t.Fatal("terminal callback did not wait for the exact terminal receipt")
	}
}

func TestTerminalQuiesceEdgeClosesOnceAndLeavesControlAdmissible(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	h.OnStorageFailure = func(error) {}
	quiesce := h.TerminalQuiescing()
	select {
	case <-quiesce:
		t.Fatal("quiesce closed before a terminal cause")
	default:
	}
	ordinary := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	if !h.beginTerminalRequest(ordinary) {
		t.Fatal("ordinary request was not admitted before fence")
	}
	h.deferStorageFailure(nil, errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM))
	select {
	case <-quiesce:
	default:
		t.Fatal("terminal cause did not close quiesce edge")
	}
	if h.beginTerminalRequest(ordinary) {
		t.Fatal("ordinary request was admitted after quiesce")
	}
	control := &authoritypb.Request{Body: &authoritypb.Request_AcknowledgeLeaseEvent{AcknowledgeLeaseEvent: &authoritypb.AcknowledgeLeaseEventRequest{}}}
	if !h.beginTerminalRequest(control) {
		t.Fatal("lease control was refused during quiesce")
	}
	h.endTerminalRequest()
	h.endTerminalRequest()
}

func TestTerminalQuiesceRefusesNewParkableControlWithoutWaiting(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	h.OnStorageFailure = func(error) {}
	ordinary := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	if !h.beginTerminalRequest(ordinary) {
		t.Fatal("ordinary request was not admitted before fence")
	}
	h.deferStorageFailure(nil, errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM))
	next := &authoritypb.Request{RequestId: 9, Body: &authoritypb.Request_NextLeaseEvent{NextLeaseEvent: &authoritypb.NextLeaseEventRequest{}}}
	response := h.Handle(t.Context(), next)
	if response.GetErrno() != int32(syscall.EIO) || !response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE {
		t.Fatalf("post-quiesce NextLeaseEvent = %+v, want immediate fenced response", response)
	}
	h.endTerminalRequest()
}

func TestTerminalDeliveryTimeoutForcesEpochStop(t *testing.T) {
	store := &terminalDeliveryStore{}
	h := testVolumeHandler()
	h.Store = store
	h.TerminalDeliveryTimeout = 10 * time.Millisecond
	called := make(chan error, 1)
	h.OnStorageFailure = func(err error) { called <- err }
	request := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	if !h.beginTerminalRequest(request) {
		t.Fatal("pre-fence request was not admitted")
	}
	h.deferStorageFailure(nil, errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM))
	response := terminalFallocateResponse(7, 3)
	h.prepareResponseWrite(request, response, true)
	// Deliberately leave both the active handler and terminal token outstanding.
	select {
	case err := <-called:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("forced terminal cause = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal delivery timeout did not force epoch stop")
	}
	// The timeout cannot forge completion of a still-running handler. Its real
	// unwind must remain safe and must not fire the terminal callback twice.
	h.endTerminalRequest()
	select {
	case err := <-called:
		t.Fatalf("terminal callback ran twice after late handler unwind: %v", err)
	default:
	}
}

func TestTerminalDeliveryTimeoutDoesNotInventTheOtherFailureClass(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*VolumeHandler)
		trigger   func(*VolumeHandler)
		want      string
	}{
		{
			name: "storage only",
			configure: func(h *VolumeHandler) {
				h.Store = &terminalDeliveryStore{}
			},
			trigger: func(h *VolumeHandler) {
				h.deferStorageFailure(nil, errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM))
			},
			want: "storage",
		},
		{
			name:      "coherence only",
			configure: func(h *VolumeHandler) {},
			trigger: func(h *VolumeHandler) {
				h.deferCoherenceFailure(nil, errors.Join(volumeserver.ErrVisibilityPoisoned, syscall.EIO))
			},
			want: "coherence",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := testVolumeHandler()
			h.TerminalDeliveryTimeout = 10 * time.Millisecond
			test.configure(h)
			storage, coherence := make(chan error, 1), make(chan error, 1)
			h.OnStorageFailure = func(err error) { storage <- err }
			h.OnCoherenceFailure = func(err error) { coherence <- err }
			// Keep one pre-terminal handler admitted so the callback cannot run at
			// the ordinary clean-drain edge. The bounded timeout must be the event
			// that transfers the cause, which is precisely where the absent class
			// used to acquire a spurious DeadlineExceeded error.
			request := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
			if !h.beginTerminalRequest(request) {
				t.Fatal("pre-terminal handler was not admitted")
			}
			test.trigger(h)

			var wanted, unwanted <-chan error
			if test.want == "storage" {
				wanted, unwanted = storage, coherence
			} else {
				wanted, unwanted = coherence, storage
			}
			select {
			case err := <-wanted:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("%s timeout cause = %v", test.want, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("%s terminal callback did not run", test.want)
			}
			select {
			case err := <-unwanted:
				t.Fatalf("terminal timeout invented the other failure class: %v", err)
			case <-time.After(25 * time.Millisecond):
			}
			h.endTerminalRequest()
		})
	}
}
