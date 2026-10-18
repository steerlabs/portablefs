package authorityrpc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type mutationSettlementTestHandler struct {
	fskitProofTestHandler
	mutations atomic.Int32
	mutation  func(context.Context)
	resume    func()
}

func (h *mutationSettlementTestHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if request.GetMkdir() != nil {
		if h.mutations.Add(1) == 1 && h.mutation != nil {
			h.mutation(ctx)
		}
		// A definite pre-application refusal records no replay outcome.
		return &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch(), Errno: int32(syscall.EACCES)}
	}
	if request.GetResume() != nil && h.resume != nil {
		h.resume()
	}
	return h.fskitProofTestHandler.Handle(ctx, request)
}

func settlementTestMkdir() *authoritypb.Request {
	return &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
		Parent: make([]byte, 16), Name: []byte("x"), Mode: 0o755,
	}}}
}

// This is the R2-S1 review probe, tightened to require local cancellation with
// no dispatch, rather than also accepting a transmitted, definite refusal.
func TestCanceledUndispatchedMutationKeepsSessionUsable(t *testing.T) {
	handler := &mutationSettlementTestHandler{fskitProofTestHandler: newFskitProofTestHandler()}
	handler.set(uint64(time.Second), nil, 0)
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, control := client.data.conn, client.control.conn
	requestID := client.data.nextID.Load()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request := settlementTestMkdir()
	var identity MutationIdentity
	assignments := 0
	response, consumption, err := client.CallMutationWithIdentityRetained(ctx, request, func(assigned MutationIdentity) error {
		assignments++
		identity = assigned
		cancel()
		return nil
	}, func(error) { t.Error("unsent mutation required forced publication withdrawal") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("undispatched mutation = (%v, %v, %v)", response, consumption, err)
	}
	if response != nil || consumption != nil || assignments != 1 || handler.mutations.Load() != 0 {
		t.Fatalf("unsent outcome: response=%v consumption=%v assignments=%d calls=%d", response, consumption, assignments, handler.mutations.Load())
	}
	if request.GetRequestId() != 0 || request.GetSession() != nil || len(request.GetEpoch()) != 0 || client.data.nextID.Load() != requestID {
		t.Fatal("unsent mutation assigned a physical envelope")
	}
	if !client.LocalAdmissionOpen() || client.SessionEndCause() != nil {
		t.Fatalf("unsent cancellation ended the session: %v", client.SessionEndCause())
	}
	client.fatalMu.Lock()
	retained := len(client.responseConsumptions)
	client.fatalMu.Unlock()
	if retained != 0 || len(client.ordinary.permits) != 0 {
		t.Fatalf("unsent cancellation retained ownership: receipts=%d permits=%d", retained, len(client.ordinary.permits))
	}
	// Retain ordinary round-robin selection and revisit the canceled slot.
	// Definite refusals leave every slot unadvanced, just like the local refusal.
	for i := range len(client.ordinary.slots) {
		var next MutationIdentity
		response, err = client.CallMutationWithIdentity(t.Context(), settlementTestMkdir(), func(assigned MutationIdentity) error {
			next = assigned
			return nil
		})
		if err != nil || response.GetErrno() != int32(syscall.EACCES) || handler.mutations.Load() != int32(i+1) {
			t.Fatalf("next mutation = (%v, %v), calls=%d", response, err, handler.mutations.Load())
		}
		if i == len(client.ordinary.slots)-1 && next != identity {
			t.Fatalf("canceled slot advanced: identity=%+v want %+v", next, identity)
		}
	}
	if _, err := client.KeepAlive(t.Context()); err != nil {
		t.Fatalf("renewal after cancellation: %v", err)
	}
	for transport, original := range map[*clientTransport]net.Conn{client.data: data, client.control: control} {
		transport.pendingMu.Lock()
		unchanged := transport.conn == original && len(transport.pending) == 0
		transport.pendingMu.Unlock()
		if !unchanged {
			t.Fatal("settled cancellation replaced a transport or retained a waiter")
		}
	}
}

func TestSubmittedMutationCancellationDrainsExactOutcome(t *testing.T) {
	started := make(chan struct{})
	handler := &mutationSettlementTestHandler{
		fskitProofTestHandler: newFskitProofTestHandler(),
		mutation: func(ctx context.Context) {
			close(started)
			<-ctx.Done()
		},
	}
	handler.set(uint64(time.Second), nil, 0)
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan callResult, 1)
	go func() {
		response, err := client.CallMutation(ctx, settlementTestMkdir())
		done <- callResult{response: response, err: err}
	}()
	<-started
	cancel()
	result := <-done
	if result.err != nil || result.response.GetErrno() != int32(syscall.EACCES) || handler.mutations.Load() != 1 {
		t.Fatalf("settled mutation = (%v, %v), calls=%d", result.response, result.err, handler.mutations.Load())
	}
	if !client.LocalAdmissionOpen() || client.SessionEndCause() != nil {
		t.Fatalf("exact cancellation outcome ended the session: %v", client.SessionEndCause())
	}
	if _, err := client.KeepAlive(t.Context()); err != nil {
		t.Fatalf("renewal after exact outcome: %v", err)
	}
}

func TestSubmittedMutationCancellationEndsSession(t *testing.T) {
	for _, replay := range []bool{false, true} {
		name := "awaiting-reply"
		if replay {
			name = "awaiting-replay"
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			handler := &mutationSettlementTestHandler{
				fskitProofTestHandler: newFskitProofTestHandler(),
				mutation: func(context.Context) {
					close(started)
					<-release
				},
			}
			var resumes atomic.Int32
			if replay {
				handler.resume = func() {
					resumes.Add(1)
					// The first send is still unsettled when a same-epoch
					// reconnect begins. Cancel before any replay is submitted.
					cancel()
				}
			}
			client, err := dialFskitProofTestClient(t, handler, func(cfg *ClientConfig) {
				cfg.CancelDrainTimeout = 10 * time.Millisecond
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(releaseHandler)
			done := make(chan error, 1)
			var assignments atomic.Int32
			go func() {
				_, err := client.CallMutationWithIdentity(ctx, settlementTestMkdir(), func(MutationIdentity) error {
					assignments.Add(1)
					return nil
				})
				done <- err
			}()
			<-started
			if replay {
				client.data.pendingMu.Lock()
				conn := client.data.conn
				client.data.pendingMu.Unlock()
				client.failConnection(client.data, conn, ErrTransportUncertain)
				releaseHandler()
			} else {
				cancel()
			}
			if err := <-done; !errors.Is(err, ErrTransportUncertain) {
				t.Fatalf("unsettled cancellation = %v", err)
			}
			if client.LocalAdmissionOpen() || !errors.Is(client.SessionEndCause(), ErrTransportUncertain) {
				t.Fatalf("unsettled mutation kept admission: open=%t cause=%v", client.LocalAdmissionOpen(), client.SessionEndCause())
			}
			if handler.mutations.Load() != 1 || assignments.Load() != 1 || replay && resumes.Load() != 1 {
				t.Fatalf("calls=%d assignments=%d resumes=%d", handler.mutations.Load(), assignments.Load(), resumes.Load())
			}
		})
	}
}
