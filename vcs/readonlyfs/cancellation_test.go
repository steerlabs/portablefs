package readonlyfs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// Context-aware allocation ledger: a settled resource reply can coincide with
// cancellation, while subsequent foreground calls are refused before dispatch.
// Closing the session is the terminal transfer of all outstanding resources.
type cancellationRPC struct {
	*capabilityLedger
	after          func(*authoritypb.Request)
	before         func(context.Context, *authoritypb.Request) error
	uncertain      func(*authoritypb.Request) bool
	uncertainError error
	ended          bool
}

func (r *cancellationRPC) CallMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.before != nil {
		if err := r.before(ctx, request); err != nil {
			return nil, err
		}
	}
	if err := assigned(authorityrpc.MutationIdentity{}); err != nil {
		return nil, err
	}
	response, err := r.capabilityLedger.CallMutation(ctx, request)
	if r.after != nil {
		r.after(request)
	}
	if r.uncertain != nil && r.uncertain(request) {
		if r.uncertainError != nil {
			return nil, r.uncertainError
		}
		return nil, authorityrpc.ErrTransportUncertain
	}
	return response, err
}

func (r *cancellationRPC) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = true
	clear(r.outstanding)
	clear(r.handles)
	return nil
}

func (r *cancellationRPC) assertNoResources(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.outstanding) != 0 || len(r.handles) != 0 || len(r.violations) != 0 {
		t.Fatalf("items=%v handles=%v violations=%v", r.outstanding, r.handles, r.violations)
	}
}

func TestGatewayCancellationReturnsKnownItemsAndInternalDescriptions(t *testing.T) {
	for _, stage := range []string{"first lookup", "next lookup", "open", "directory open", "directory EOF"} {
		t.Run(stage, func(t *testing.T) {
			rpc := &cancellationRPC{capabilityLedger: newCapabilityLedger()}
			rpc.kinds["file"] = authoritypb.Attr_REGULAR
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			lookups := 0
			rpc.after = func(request *authoritypb.Request) {
				if request.GetLookup() != nil {
					lookups++
				}
				if stage == "first lookup" && lookups == 1 || stage == "next lookup" && lookups == 2 || (stage == "open" || stage == "directory open") && request.GetOpen() != nil || stage == "directory EOF" && request.GetReadDir() != nil {
					cancel()
				}
			}
			client := newClient(rpc, time.Second)
			t.Cleanup(func() { _ = client.Close() })
			var err error
			if stage == "directory open" || stage == "directory EOF" {
				_, err = client.List(ctx, pathKey(t, "dir"), 1, nil)
			} else {
				var file *File
				file, err = client.OpenFile(ctx, pathKey(t, "a", "file"))
				if file != nil {
					err = file.Close(ctx)
				}
			}
			wantCanceled := stage == "first lookup" || stage == "next lookup" || stage == "directory open"
			if wantCanceled && !errors.Is(err, context.Canceled) || !wantCanceled && err != nil {
				t.Fatalf("operation = %v, want cancellation=%v", err, wantCanceled)
			}
			if client.Err() != nil {
				t.Fatalf("settled cleanup ended session: %v", client.Err())
			}
			rpc.assertNoResources(t)
		})
	}
}

func TestGatewayDescriptionCloseRetainsOwnerUntilSettled(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, outcome := range []string{"canceled caller", "pre-dispatch deadline", "uncertain after apply"} {
			t.Run(map[bool]string{false: "file", true: "directory"}[directory]+"/"+outcome, func(t *testing.T) {
				rpc := &cancellationRPC{capabilityLedger: newCapabilityLedger()}
				rpc.kinds["file"] = authoritypb.Attr_REGULAR
				client := newClient(rpc, time.Second)
				t.Cleanup(func() { _ = client.Close() })
				var closeDescription func(context.Context) error
				if directory {
					cursor, err := client.openDirectory(t.Context(), pathKey(t, "dir"))
					if err != nil {
						t.Fatal(err)
					}
					closeDescription = cursor.Close
				} else {
					file, err := client.OpenFile(t.Context(), pathKey(t, "file"))
					if err != nil {
						t.Fatal(err)
					}
					closeDescription = file.Close
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if outcome == "pre-dispatch deadline" {
					rpc.before = func(ctx context.Context, request *authoritypb.Request) error {
						if request.GetClose() == nil {
							return nil
						}
						if _, ok := ctx.Deadline(); !ok {
							t.Error("cleanup has no session deadline")
						}
						<-ctx.Done()
						return ctx.Err()
					}
				}
				if outcome == "uncertain after apply" {
					rpc.uncertain = func(request *authoritypb.Request) bool { return request.GetClose() != nil }
				}
				err := closeDescription(ctx)
				switch outcome {
				case "pre-dispatch deadline":
					if !errors.Is(err, context.DeadlineExceeded) || client.Err() != nil {
						t.Fatalf("close=%v session=%v", err, client.Err())
					}
					rpc.mu.Lock()
					open := len(rpc.handles)
					rpc.mu.Unlock()
					if open != 1 {
						t.Fatalf("retryable description count=%d", open)
					}
					rpc.before = nil
				case "uncertain after apply":
					if !errors.Is(err, authorityrpc.ErrTransportUncertain) || client.Err() == nil || !rpc.ended {
						t.Fatalf("close=%v session=%v ended=%v", err, client.Err(), rpc.ended)
					}
					if err := closeDescription(t.Context()); err == nil {
						t.Fatal("unsettled close reported success on retry")
					}
					rpc.assertNoResources(t)
					return
				default:
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := closeDescription(t.Context()); err != nil {
					t.Fatalf("retry: %v", err)
				}
				rpc.assertNoResources(t)
			})
		}
	}
}

func TestGatewayAbandonedCleanupFailureEndsSession(t *testing.T) {
	for _, operation := range []string{"reclaim", "open", "EOF close", "canceled after assignment"} {
		t.Run(operation, func(t *testing.T) {
			rpc := &cancellationRPC{capabilityLedger: newCapabilityLedger()}
			rpc.kinds["file"] = authoritypb.Attr_REGULAR
			rpc.before = func(_ context.Context, request *authoritypb.Request) error {
				if operation == "reclaim" && request.GetReclaim() != nil || operation == "EOF close" && request.GetClose() != nil {
					return context.DeadlineExceeded
				}
				return nil
			}
			rpc.uncertain = func(request *authoritypb.Request) bool {
				return (operation == "open" || operation == "canceled after assignment") && request.GetOpen() != nil
			}
			if operation == "canceled after assignment" {
				rpc.uncertainError = context.Canceled
			}
			client := newClient(rpc, time.Second)
			t.Cleanup(func() { _ = client.Close() })
			var err error
			if operation == "EOF close" {
				_, err = client.List(t.Context(), "", 1, nil)
			} else {
				_, err = client.OpenFile(t.Context(), pathKey(t, "file"))
			}
			if err == nil || client.Err() == nil || !rpc.ended {
				t.Fatalf("operation=%v session=%v ended=%v", err, client.Err(), rpc.ended)
			}
			rpc.assertNoResources(t)
		})
	}
}
