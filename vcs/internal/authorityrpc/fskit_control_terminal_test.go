package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestTransportLossAdmissionPolicy(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{
		authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
		authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX,
		authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER,
	} {
		for _, role := range []authoritypb.TransportRole{
			authoritypb.TransportRole_TRANSPORT_ROLE_DATA,
			authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL,
		} {
			for _, pendingCount := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/%s/pending=%d", profile, role, pendingCount), func(t *testing.T) {
					local, peer := net.Pipe()
					defer peer.Close()
					client := newTerminalDrainTestClient(nil, nil, time.Second)
					client.cfg.FrontendProfile = profile
					defer client.Close()
					transport := client.transportForRole(role)
					transport.conn = local
					results := make(chan callResult)
					for i := range pendingCount {
						transport.pending[uint64(i+1)] = results
					}
					failed := make(chan struct{})
					go func() {
						client.failConnection(transport, local, ErrTransportUncertain)
						close(failed)
					}()
					terminal := profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE &&
						role == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL
					for range pendingCount {
						result := <-results
						if !errors.Is(result.err, ErrTransportUncertain) {
							t.Errorf("pending result = %v", result.err)
						}
						if client.LocalAdmissionOpen() == terminal || (client.SessionEndCause() != nil) != terminal {
							t.Errorf("waiter notified before terminal admission: open=%t cause=%v", client.LocalAdmissionOpen(), client.SessionEndCause())
						}
					}
					<-failed
					if client.LocalAdmissionOpen() == terminal || (client.SessionError() != nil) != terminal {
						t.Fatalf("transport loss: open=%t session=%v, terminal=%t", client.LocalAdmissionOpen(), client.SessionError(), terminal)
					}
				})
			}
		}
	}
}

func TestFSKitControlCancelDrainIsTerminal(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			handler := newFskitProofTestHandler()
			handler.set(uint64(time.Second), func(*authoritypb.Response) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
			}, 0)
			client, err := dialFskitProofTestClient(t, handler, func(cfg *ClientConfig) {
				cfg.CancelDrainTimeout = 30 * time.Millisecond
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { close(release) })
			data := client.data.conn
			controlGeneration := client.control.binding.Load()
			ctx, cancel := context.WithCancel(t.Context())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := client.KeepAlive(ctx)
				done <- err
			}()
			<-started
			if !deadline {
				cancel()
			}
			if err := <-done; !errors.Is(err, ErrTransportUncertain) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unsettled CONTROL cancellation = %v, want terminal transport error", err)
			}
			if client.LocalAdmissionOpen() || !errors.Is(client.SessionError(), ErrTransportUncertain) {
				t.Fatalf("CONTROL cancel-drain failure remained usable: admission=%t session=%v", client.LocalAdmissionOpen(), client.SessionError())
			}
			if _, err := client.KeepAlive(t.Context()); !errors.Is(err, ErrTransportUncertain) {
				t.Fatalf("post-terminal KeepAlive = %v", err)
			}
			if calls.Load() != 1 || client.control.binding.Load() != controlGeneration || client.transportIsLive(client.control) {
				t.Fatal("terminal CONTROL loss retried or rebound the request")
			}
			client.data.pendingMu.Lock()
			sameData := client.data.conn == data
			client.data.pendingMu.Unlock()
			if !sameData {
				t.Fatal("CONTROL failure replaced the original DATA transport")
			}
		})
	}
}

func TestFSKitSettledCancellationKeepsSessionUsable(t *testing.T) {
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler := newFskitProofTestHandler()
	handler.set(uint64(time.Second), func(*authoritypb.Response) {
		close(started)
		<-ctx.Done()
	}, 0)
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	control := client.control.conn
	done := make(chan error, 1)
	go func() {
		proof, err := client.KeepAlive(ctx)
		if err == nil && proof != time.Second {
			err = fmt.Errorf("settled proof = %s, want one second", proof)
		}
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("settled cancellation lost its exact proof: %v", err)
	}
	if !client.LocalAdmissionOpen() || client.SessionEndCause() != nil {
		t.Fatalf("settled cancellation ended session: %v", client.SessionEndCause())
	}
	handler.set(uint64(time.Second), nil, 0)
	if _, err := client.KeepAlive(t.Context()); err != nil {
		t.Fatalf("CONTROL after settled cancellation = %v", err)
	}
	client.control.pendingMu.Lock()
	sameControl := client.control.conn == control
	client.control.pendingMu.Unlock()
	if !sameControl {
		t.Fatal("settled cancellation replaced CONTROL")
	}
}

func TestFSKitControlLossPreservesTerminalDrain(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	client := newTerminalDrainTestClient(nil, local, time.Second)
	client.cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE
	client.cfg.RequireLocalSessionEnforcement = true
	defer client.Close()
	// Both authority replies and local publications use this same receipt owner.
	retained, err := client.beginResponseConsumption(func(error) { t.Error("retained reply was prematurely revoked") })
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Consume()
	publication, err := client.BeginLocalPublication(func(error) { t.Error("local reply was prematurely revoked") })
	if err != nil {
		t.Fatal(err)
	}
	defer publication.Consume()
	waiter := make(chan callResult, 1)
	client.control.pending[1] = waiter
	client.failConnection(client.control, local, ErrTransportUncertain)
	if result := <-waiter; !errors.Is(result.err, ErrTransportUncertain) || client.LocalAdmissionOpen() || !errors.Is(client.SessionEndCause(), ErrTransportUncertain) {
		t.Fatalf("pending CONTROL loss = %v, admission=%t cause=%v", result.err, client.LocalAdmissionOpen(), client.SessionEndCause())
	}
	for _, receipt := range []ResponseConsumption{retained, publication} {
		select {
		case <-client.SessionEndPending():
			t.Fatal("terminal edge overtook a retained reply")
		default:
		}
		receipt.Consume()
	}
	select {
	case <-client.SessionEndPending():
	default:
		t.Fatal("consuming both replies did not release the teardown owner")
	}
	select {
	case <-client.SessionDone():
		t.Fatal("public terminal edge overtook local enforcement")
	default:
	}
	if err := client.SessionError(); err != nil {
		t.Fatalf("public session error overtook local enforcement: %v", err)
	}
	client.FinishLocalSessionEnforcement()
	select {
	case <-client.SessionDone():
	default:
		t.Fatal("finished local enforcement did not publish session end")
	}
	if !errors.Is(client.SessionError(), ErrTransportUncertain) {
		t.Fatalf("terminal cause changed during drain: %v", client.SessionError())
	}
}
