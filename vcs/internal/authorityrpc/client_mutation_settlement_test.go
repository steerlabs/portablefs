package authorityrpc

import (
	"context"
	"errors"
	"fmt"
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
	writes    atomic.Int32
	mutation  func(context.Context)
	resume    func()
}

func (h *mutationSettlementTestHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if request.GetWrite() != nil {
		h.writes.Add(1)
		return &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch(), Errno: int32(syscall.EACCES)}
	}
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

func TestNonLinuxFinalizedFlushSequenceIsRefused(t *testing.T) {
	for _, segmented := range []bool{false, true} {
		for _, assignment := range []string{"preset", "assigned", "cleared"} {
			t.Run(fmt.Sprintf("segmented=%t/%s", segmented, assignment), func(t *testing.T) {
				handler := &mutationSettlementTestHandler{fskitProofTestHandler: newFskitProofTestHandler()}
				handler.set(uint64(time.Second), nil, 0)
				client, err := dialFskitProofTestClient(t, handler, nil)
				if err != nil {
					t.Fatal(err)
				}
				write := &authoritypb.WriteRequest{Handle: make([]byte, 16), Size: 1}
				if assignment != "assigned" {
					write.FlushSequence = 1
				}
				request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: write}}
				assignments := 0
				assigned := func(MutationIdentity) error {
					assignments++
					if assignment == "assigned" {
						write.FlushSequence = 1
					} else if assignment == "cleared" {
						write.FlushSequence = 0
					}
					return nil
				}
				var response *authoritypb.Response
				if segmented {
					response, err = client.CallMutationSegments(t.Context(), request, [][]byte{[]byte("x")}, assigned)
				} else {
					write.Data = []byte("x")
					response, err = client.CallMutationWithIdentity(t.Context(), request, assigned)
				}
				if assignment == "cleared" {
					if err != nil || response.GetErrno() != int32(syscall.EACCES) || handler.writes.Load() != 1 {
						t.Fatalf("cleared flush sequence = (%v, %v), calls=%d", response, err, handler.writes.Load())
					}
				} else {
					if err != syscall.EOPNOTSUPP || response != nil || handler.writes.Load() != 0 {
						t.Fatalf("non-Linux flush = (%v, %v), calls=%d", response, err, handler.writes.Load())
					}
					if request.GetRequestId() != 0 || request.GetSession() != nil || len(request.GetEpoch()) != 0 {
						t.Fatal("refused flush assigned a physical envelope")
					}
				}
				if assignments != 1 || client.ordinary.slots[0].sequence != 0 {
					t.Fatal("finalized refusal changed assignment or advanced the replay slot")
				}
				client.fatalMu.Lock()
				retained := len(client.responseConsumptions)
				client.fatalMu.Unlock()
				if retained != 0 || len(client.ordinary.permits) != 0 || !client.LocalAdmissionOpen() || client.SessionEndCause() != nil {
					t.Fatalf("flush retained ownership or ended the session: receipts=%d cause=%v", retained, client.SessionEndCause())
				}
				if _, err := client.KeepAlive(t.Context()); err != nil {
					t.Fatalf("renewal after flush validation: %v", err)
				}
			})
		}
	}
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
