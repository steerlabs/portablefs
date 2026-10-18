package authorityrpc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestR4ReviewInterruptedMutationPreservesRecordedCause(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, cause := range []error{ErrAuthorityChanged, ErrSessionEnded, fmt.Errorf("%w: frame defect", ErrTransportBinding), ErrRoutesMismatch, ErrReplayDesynchronized, fmt.Errorf("%w: original transport failure", ErrTransportUncertain)} {
			t.Run(fmt.Sprintf("%s/%v", profile, cause), func(t *testing.T) {
				local, peer := net.Pipe()
				defer peer.Close()
				c := newTerminalDrainTestClient(local, nil, time.Second)
				c.cfg.FrontendProfile = profile
				defer c.Close()
				done := make(chan error, 1)
				go func() {
					_, err := c.CallMutation(t.Context(), settlementTestMkdir())
					done <- err
				}()
				if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := readFrame(peer, testMaxFrame, nil, 0, new(authoritypb.Request)); err != nil {
					t.Fatal(err)
				}
				c.signalSessionEnd(cause)
				c.failConnection(c.data, local, ErrTransportUncertain)
				select {
				case err := <-done:
					if err != cause || c.SessionEndCause() != cause {
						t.Fatalf("interrupted mutation = %v, recorded cause = %v, want exact %v", err, c.SessionEndCause(), cause)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("mutation did not drain")
				}
			})
		}
	}
}

func TestR4ReviewAssignedTerminalCausePrecedesCancellation(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		t.Run(profile.String(), func(t *testing.T) {
			c := newTerminalDrainTestClient(nil, nil, time.Second)
			c.cfg.FrontendProfile = profile
			defer c.Close()
			cause := fmt.Errorf("%w: recorded CONTROL failure", ErrTransportUncertain)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := settlementTestMkdir()
			response, err := c.CallMutationWithIdentity(ctx, request, func(MutationIdentity) error {
				c.signalSessionEnd(cause)
				cancel()
				return nil
			})
			if response != nil || err != cause || request.GetRequestId() != 0 || c.SessionEndCause() != cause {
				t.Fatalf("terminal at assignment = (%v, %v), id=%d cause=%v, want exact %v", response, err, request.GetRequestId(), c.SessionEndCause(), cause)
			}
		})
	}
}

// The two explicit cleanup entries retain permission to send exact evidence.
// Their canceled/invalid variants below exercise failure reporting without a
// wire transition; TestTerminalDetachPreservesExactAbsenceDelivery and the
// terminal-delivery tests cover their successful post-terminal dispatch.
func TestTerminalPublicEntryCauseMatrix(t *testing.T) {
	read := func() *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	}
	force := func(error) {}
	canceled := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		return ctx
	}
	entries := []struct {
		name     string
		call     func(context.Context, *Client) error
		allowNil bool
	}{
		{name: "Call", call: func(ctx context.Context, c *Client) error { _, err := c.Call(ctx, read()); return err }},
		{name: "Call-invalid", call: func(ctx context.Context, c *Client) error { _, err := c.Call(ctx, nil); return err }},
		{name: "CallRead", call: func(ctx context.Context, c *Client) error { _, err := c.CallRead(ctx, read()); return err }},
		{name: "CallIdempotent", call: func(ctx context.Context, c *Client) error { _, err := c.CallIdempotent(ctx, read()); return err }},
		{name: "CallReadRetained", call: func(ctx context.Context, c *Client) error {
			_, r, err := c.CallReadRetained(ctx, read(), force)
			if r != nil {
				r.Consume()
				t.Error("terminal read returned a receipt")
			}
			return err
		}},
		{name: "CallIdempotentRetained", call: func(ctx context.Context, c *Client) error {
			_, r, err := c.CallIdempotentRetained(ctx, read(), force)
			if r != nil {
				r.Consume()
				t.Error("terminal idempotent call returned a receipt")
			}
			return err
		}},
		{name: "CallMutation", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutation(ctx, settlementTestMkdir())
			return err
		}},
		{name: "CallMutationWithIdentity", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutationWithIdentity(ctx, settlementTestMkdir(), func(MutationIdentity) error { t.Error("terminal assignment"); return nil })
			return err
		}},
		{name: "CallMutationWithIdentityRetained", call: func(ctx context.Context, c *Client) error {
			_, r, err := c.CallMutationWithIdentityRetained(ctx, settlementTestMkdir(), nil, force)
			if r != nil {
				r.Consume()
				t.Error("terminal mutation returned a receipt")
			}
			return err
		}},
		{name: "CallMutationSegments-invalid", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutationSegments(ctx, nil, nil, nil)
			return err
		}},
		{name: "KeepAlive", call: func(ctx context.Context, c *Client) error { _, err := c.KeepAlive(ctx); return err }},
		{name: "Reauthorize-invalid", call: func(ctx context.Context, c *Client) error { _, err := c.Reauthorize(ctx, nil, 0); return err }},
		{name: "ReauthorizeWithCertificate-invalid", call: func(ctx context.Context, c *Client) error {
			_, err := c.ReauthorizeWithCertificate(ctx, nil, 0, nil, time.Now())
			return err
		}},
		{name: "ApplyRoutes", call: func(ctx context.Context, c *Client) error { _, err := c.ApplyRoutes(ctx, nil, [32]byte{}); return err }},
		{name: "BeginLocalPublication", call: func(_ context.Context, c *Client) error { _, err := c.BeginLocalPublication(nil); return err }},
		{name: "Reconnect", call: func(ctx context.Context, c *Client) error { return c.Reconnect(ctx) }},
		{name: "RecoverEpoch", call: func(ctx context.Context, c *Client) error { _, err := c.RecoverEpoch(ctx); return err }},
		{name: "RecoverEpoch-invalid-context", call: func(_ context.Context, c *Client) error { _, err := c.RecoverEpoch(nil); return err }},
		{name: "Subscribe-invalid", call: func(ctx context.Context, c *Client) error { _, _, err := c.Subscribe(ctx, []byte{1}, nil); return err }},
		{name: "RenewSubscription-reset", call: func(ctx context.Context, c *Client) error { _, err := c.RenewSubscription(ctx, 1); return err }},
		{name: "NextControlEvent-reset", call: func(ctx context.Context, c *Client) error { _, err := c.NextControlEvent(ctx, 1, 0, 0); return err }},
		{name: "AcknowledgeChanges-invalid", call: func(ctx context.Context, c *Client) error { return c.AcknowledgeChanges(ctx, 0, 0) }},
		{name: "AcknowledgeDelegationRecall-invalid", call: func(ctx context.Context, c *Client) error { return c.AcknowledgeDelegationRecall(ctx, 0, 0, nil, 0) }},
		{name: "AcknowledgeDelegationBreak-invalid", call: func(ctx context.Context, c *Client) error { return c.AcknowledgeDelegationBreak(ctx, 0, 0, nil, 0) }},
		{name: "AcknowledgeDelegationModeChange-invalid", call: func(ctx context.Context, c *Client) error {
			return c.AcknowledgeDelegationModeChange(ctx, 0, 0, nil, 0)
		}},
		{name: "ReleaseDelegations-invalid", call: func(ctx context.Context, c *Client) error { return c.ReleaseDelegations(ctx, 0, nil) }},
		{name: "Barrier", call: func(ctx context.Context, c *Client) error { _, err := c.Barrier(ctx, 0); return err }},
		{name: "WaitVisibility-invalid", call: func(ctx context.Context, c *Client) error { _, err := c.WaitVisibility(ctx, 0); return err }},
		{name: "CloseBatch", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{}}})
			return err
		}},
		{name: "Reclaim", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{}}})
			return err
		}},
		{name: "Detach-raw", call: func(ctx context.Context, c *Client) error {
			_, err := c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}}})
			return err
		}},
		{name: "TerminalDeliveryReceipt-raw", call: func(ctx context.Context, c *Client) error {
			_, err := c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceipt{}}})
			return err
		}},
		{name: "DetachAfterUnmount-invalid", call: func(ctx context.Context, c *Client) error { return c.DetachAfterUnmount(ctx, nil) }},
		{name: "DetachAfterUnmount-canceled", call: func(ctx context.Context, c *Client) error {
			proof := &authoritypb.MountAbsenceProof{Observation: []byte("attempt"), Component: "test", ObservedUnixNanos: 1}
			return c.DetachAfterUnmount(canceled(ctx), proof)
		}},
		{name: "DetachRouteAdmin-wrong-purpose", call: func(ctx context.Context, c *Client) error { return c.DetachRouteAdmin(ctx) }},
		{name: "DetachRouteAdmin-canceled", call: func(ctx context.Context, c *Client) error {
			c.cfg.Purpose = authoritypb.SessionPurpose_SESSION_PURPOSE_ROUTE_ADMIN
			return c.DetachRouteAdmin(canceled(ctx))
		}},
		{name: "TerminalDeliveryReceipt-invalid", call: func(ctx context.Context, c *Client) error {
			_, err := c.dispatchTerminalDeliveryReceipt(ctx, nil)
			return err
		}},
		{name: "TerminalDeliveryReceipt-canceled", call: func(ctx context.Context, c *Client) error {
			_, err := c.dispatchTerminalDeliveryReceipt(canceled(ctx), []byte("0123456789abcdef"))
			return err
		}},
		{name: "ReleaseBeforeMount-observer-failure", call: func(ctx context.Context, c *Client) error { return c.ReleaseBeforeMount(ctx) }},
		{name: "Close-socket-failure", call: func(_ context.Context, c *Client) error { return c.Close() }, allowNil: true},
		{name: "metadata-and-status", allowNil: true, call: func(_ context.Context, c *Client) error {
			c.Root()
			c.Epoch()
			c.RoutesRevision()
			c.IOLimits()
			c.DataPlaneOperationLimit()
			c.SessionID()
			c.SessionLease()
			c.AuthorizationSessionID()
			c.InitialAuthorizationDeadline()
			c.AuthorizationDeadline()
			c.LocalAdmissionOpen()
			c.SessionError()
			c.SessionEndCause()
			c.SessionDone()
			c.SessionEndPending()
			c.FinishLocalSessionEnforcement()
			return nil
		}},
	}
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, phase := range []string{"poisoned-draining", "terminal-published", "closed"} {
			for _, cause := range []error{ErrAuthorityChanged, ErrRoutesMismatch, ErrReplayDesynchronized, fmt.Errorf("%w: recorded failure", ErrTransportUncertain)} {
				for _, canceledContext := range []bool{false, true} {
					for _, entry := range entries {
						t.Run(fmt.Sprintf("%s/%s/%v/canceled=%t/%s", profile, phase, cause, canceledContext, entry.name), func(t *testing.T) {
							data, control := new(terminalCauseTestConn), new(terminalCauseTestConn)
							c := newTerminalDrainTestClient(data, control, time.Hour)
							c.cfg.FrontendProfile = profile
							c.cfg.Purpose = authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT
							c.cfg.ObservePreKernelMountAbsence = func(context.Context) (*authoritypb.MountAbsenceProof, error) { return nil, syscall.EIO }
							c.releaseInvalidIncarnation.Store(1)
							defer c.Close()
							if phase == "poisoned-draining" {
								r, err := c.BeginLocalPublication(force)
								if err != nil {
									t.Fatal(err)
								}
								defer r.Consume()
							}
							c.signalSessionEnd(cause)
							if phase == "closed" {
								_ = c.Close()
							}
							ctx := t.Context()
							if canceledContext {
								ctx = canceled(ctx)
							}
							err := entry.call(ctx, c)
							if err != cause && !(entry.allowNil && err == nil) {
								t.Fatalf("got %v, want exact %v", err, cause)
							}
							if c.SessionEndCause() != cause || c.LocalAdmissionOpen() {
								t.Fatal("entry changed recorded cause/admission")
							}
							if data.writes.Load() != 0 || control.writes.Load() != 0 || c.data.nextID.Load() != 0 || c.control.nextID.Load() != 0 || c.ordinary.nextSlot.Load() != 0 {
								t.Fatal("terminal entry dispatched or assigned an envelope/slot")
							}
						})
					}
				}
			}
		}
	}
}

type terminalCauseTestConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *terminalCauseTestConn) Write([]byte) (int, error)      { c.writes.Add(1); return 0, syscall.EIO }
func (*terminalCauseTestConn) Close() error                     { return syscall.EIO }
func (*terminalCauseTestConn) SetDeadline(time.Time) error      { return nil }
func (*terminalCauseTestConn) SetWriteDeadline(time.Time) error { return nil }

// Deliver parsed responses directly to the registered waiter. This isolates
// post-admission error translation from framing (whose poisoning regressions
// run separately) while still submitting a real framed request over DATA or
// CONTROL. A sibling terminal edge precedes each delivered response.
func TestAdmittedReplyErrorsUseRecordedCause(t *testing.T) {
	entries := []struct {
		name      string
		linuxOnly bool
		call      func(context.Context, *Client) error
		reply     func() *authoritypb.Response
	}{
		{name: "frame-proof-placement", call: func(ctx context.Context, c *Client) error {
			_, err := c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}})
			return err
		}, reply: func() *authoritypb.Response { return &authoritypb.Response{SessionValidForNanos: 1} }},
		{name: "keepalive-estale", call: func(ctx context.Context, c *Client) error { _, err := c.KeepAlive(ctx); return err }, reply: func() *authoritypb.Response { return &authoritypb.Response{Errno: int32(syscall.ESTALE)} }},
		{name: "keepalive-malformed", call: func(ctx context.Context, c *Client) error { _, err := c.KeepAlive(ctx); return err }, reply: func() *authoritypb.Response { return &authoritypb.Response{Errno: int32(syscall.EIO)} }},
		{name: "reauthorize-errno", call: func(ctx context.Context, c *Client) error {
			_, err := c.Reauthorize(ctx, []byte("token"), 1)
			return err
		}, reply: func() *authoritypb.Response { return &authoritypb.Response{Errno: int32(syscall.EINVAL)} }},
		{name: "reauthorize-missing", call: func(ctx context.Context, c *Client) error {
			_, err := c.Reauthorize(ctx, []byte("token"), 1)
			return err
		}, reply: func() *authoritypb.Response { return &authoritypb.Response{} }},
		{name: "reauthorize-expired", call: func(ctx context.Context, c *Client) error {
			_, err := c.Reauthorize(ctx, []byte("token"), 1)
			return err
		}, reply: func() *authoritypb.Response {
			return &authoritypb.Response{Body: &authoritypb.Response_Reauthorize{Reauthorize: &authoritypb.ReauthorizeReply{Sequence: 1}}}
		}},
		{name: "apply-routes-errno", call: func(ctx context.Context, c *Client) error { _, err := c.ApplyRoutes(ctx, nil, [32]byte{}); return err }},
		{name: "apply-routes-missing", call: func(ctx context.Context, c *Client) error { _, err := c.ApplyRoutes(ctx, nil, [32]byte{}); return err }, reply: func() *authoritypb.Response { return &authoritypb.Response{} }},
		{name: "mutation-replay-mismatch", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutation(ctx, settlementTestMkdir())
			return err
		}, reply: func() *authoritypb.Response {
			return &authoritypb.Response{Errno: int32(syscall.EACCES), Mutation: &authoritypb.MutationState{AcceptedSequence: 2}}
		}},
		{name: "mutation-malformed-token", call: func(ctx context.Context, c *Client) error {
			_, err := c.CallMutation(ctx, settlementTestMkdir())
			return err
		}, reply: func() *authoritypb.Response {
			return &authoritypb.Response{Errno: int32(syscall.EACCES), TerminalDeliveryToken: []byte{1}}
		}},
		{name: "Subscribe", linuxOnly: true, call: func(ctx context.Context, c *Client) error { _, _, err := c.Subscribe(ctx, nil, nil); return err }},
		{name: "RenewSubscription", linuxOnly: true, call: func(ctx context.Context, c *Client) error { _, err := c.RenewSubscription(ctx, 1); return err }},
		{name: "NextControlEvent", linuxOnly: true, call: func(ctx context.Context, c *Client) error { _, err := c.NextControlEvent(ctx, 1, 0, 0); return err }},
		{name: "AcknowledgeChanges", linuxOnly: true, call: func(ctx context.Context, c *Client) error { return c.AcknowledgeChanges(ctx, 1, 0) }},
		{name: "AcknowledgeDelegationRecall", linuxOnly: true, call: func(ctx context.Context, c *Client) error {
			return c.AcknowledgeDelegationRecall(ctx, 1, 1, &authoritypb.DelegationRef{Id: []byte("0123456789abcdef"), Generation: 1}, 0)
		}},
		{name: "AcknowledgeDelegationBreak", linuxOnly: true, call: func(ctx context.Context, c *Client) error {
			return c.AcknowledgeDelegationBreak(ctx, 1, 1, &authoritypb.DelegationRef{Id: []byte("0123456789abcdef"), Generation: 1}, 0)
		}},
		{name: "AcknowledgeDelegationModeChange", linuxOnly: true, call: func(ctx context.Context, c *Client) error {
			return c.AcknowledgeDelegationModeChange(ctx, 1, 1, &authoritypb.DelegationRef{Id: []byte("0123456789abcdef"), Generation: 1}, 0)
		}},
		{name: "ReleaseDelegations", linuxOnly: true, call: func(ctx context.Context, c *Client) error {
			return c.ReleaseDelegations(ctx, 1, []*authoritypb.DelegationRelease{{Delegation: &authoritypb.DelegationRef{Id: []byte("0123456789abcdef"), Generation: 1}}})
		}},
		{name: "Barrier", linuxOnly: true, call: func(ctx context.Context, c *Client) error { _, err := c.Barrier(ctx, 1); return err }},
		{name: "WaitVisibility", linuxOnly: true, call: func(ctx context.Context, c *Client) error { _, err := c.WaitVisibility(ctx, 1); return err }},
		{name: "DetachAfterUnmount-errno", call: func(ctx context.Context, c *Client) error {
			return c.DetachAfterUnmount(ctx, &authoritypb.MountAbsenceProof{Observation: []byte("attempt"), Component: "test", ObservedUnixNanos: 1})
		}},
		{name: "DetachRouteAdmin-errno", call: func(ctx context.Context, c *Client) error {
			c.cfg.Purpose = authoritypb.SessionPurpose_SESSION_PURPOSE_ROUTE_ADMIN
			return c.DetachRouteAdmin(ctx)
		}},
	}
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, first := range []error{nil, ErrRoutesMismatch, fmt.Errorf("%w: first verdict", ErrTransportUncertain)} {
			for _, entry := range entries {
				if entry.linuxOnly && profile != authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX {
					continue
				}
				t.Run(fmt.Sprintf("%s/%v/%s", profile, first, entry.name), func(t *testing.T) {
					data, dataPeer := net.Pipe()
					control, controlPeer := net.Pipe()
					defer dataPeer.Close()
					defer controlPeer.Close()
					c := newTerminalDrainTestClient(data, control, time.Hour)
					c.controlAck.permits = make(chan struct{}, 1)
					c.controlPoll.permits = make(chan struct{}, 1)
					c.changeAck.permits = make(chan struct{}, 1)
					c.cfg.FrontendProfile = profile
					defer c.Close()
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					defer cancel()
					done := make(chan error, 1)
					go func() { done <- entry.call(ctx, c) }()
					// Exactly one lane has a request. Read both concurrently and
					// let context cancellation close the unused reader at cleanup.
					type sentRequest struct {
						request   *authoritypb.Request
						transport *clientTransport
					}
					sent := make(chan sentRequest, 2)
					var readers sync.WaitGroup
					for _, lane := range []struct {
						peer      net.Conn
						transport *clientTransport
					}{{dataPeer, c.data}, {controlPeer, c.control}} {
						readers.Go(func() {
							request := new(authoritypb.Request)
							if err := readFrame(lane.peer, testMaxFrame, nil, 0, request); err == nil {
								sent <- sentRequest{request, lane.transport}
							}
						})
					}
					defer readers.Wait()
					defer dataPeer.Close()
					defer controlPeer.Close()
					var dispatched sentRequest
					select {
					case dispatched = <-sent:
					case <-ctx.Done():
						t.Fatal("request did not dispatch")
					}
					if first != nil {
						c.signalSessionEnd(first)
					}
					dispatched.transport.pendingMu.Lock()
					waiter := dispatched.transport.pending[dispatched.request.GetRequestId()]
					delete(dispatched.transport.pending, dispatched.request.GetRequestId())
					dispatched.transport.pendingMu.Unlock()
					response := &authoritypb.Response{Errno: int32(syscall.EACCES)}
					if entry.reply != nil {
						response = entry.reply()
					}
					waiter <- callResult{response: response}
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("expected an error")
						}
						cause := c.SessionEndCause()
						if first != nil && cause != first {
							t.Fatalf("cause = %v, want %v", cause, first)
						}
						if cause != nil && err != cause {
							t.Fatalf("returned %v, recorded %v", err, cause)
						}
					case <-ctx.Done():
						t.Fatal("reply did not settle")
					}
				})
			}
		}
	}
}

type terminalCauseRecoveryHandler struct {
	clientTestHandler
	profile authoritypb.FrontendProfile
	resume  func()
	refuse  bool
}

func (h *terminalCauseRecoveryHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, request)
	if active := response.GetActivate(); active != nil {
		active.FrontendProfile = h.profile
	}
	if request.GetResume() != nil {
		h.resume()
		if h.refuse {
			response.Errno = int32(syscall.ESTALE)
			response.Body = nil
		}
	}
	return response
}

func TestRecoveryCompletionPreservesRecordedCause(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, refuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/refuse=%t", profile, refuse), func(t *testing.T) {
				var c *Client
				cause := fmt.Errorf("%w: sibling terminal edge during Resume", ErrTransportUncertain)
				h := &terminalCauseRecoveryHandler{
					clientTestHandler: clientTestHandler{epoch: []byte("0123456789abcdef"), maxInFlight: 9},
					profile:           profile, refuse: refuse,
				}
				var resumes atomic.Int32
				h.resume = func() { resumes.Add(1); c.signalSessionEnd(cause) }
				address, tls, stop := startTestServer(t, h, 9, time.Minute)
				defer stop()
				cfg := coherentTestClientConfig(address, tls, "volume", 9, 9)
				cfg.FrontendProfile = profile
				var err error
				c, err = DialClient(t.Context(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.data.pendingMu.Lock()
				conn := c.data.conn
				c.data.pendingMu.Unlock()
				binding := c.data.binding.Load()
				c.failConnection(c.data, conn, ErrTransportUncertain)
				if err := c.Reconnect(t.Context()); err != cause || c.SessionEndCause() != cause {
					t.Fatalf("reconnect = %v, recorded = %v, want %v", err, c.SessionEndCause(), cause)
				}
				if resumes.Load() != 1 || c.transportIsLive(c.data) || c.data.binding.Load() != binding {
					t.Fatal("terminal recovery retried or published a new binding")
				}
			})
		}
	}
}
