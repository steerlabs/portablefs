package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestAuthorityProtocolV3RequiresExactResourceAcquisition(t *testing.T) {
	if ProtocolMajor != 3 || ProtocolALPN != "portablefs-authority-v3" {
		t.Fatalf("authority protocol=(major %d, ALPN %q), want (3, portablefs-authority-v3)", ProtocolMajor, ProtocolALPN)
	}
	required := []string{"exact-resource-acquisition"}
	if !hasFeatures(requiredHelloFeatures, required) {
		t.Fatalf("Hello features %v omit exact-resource-acquisition", requiredHelloFeatures)
	}
	if !hasFeatures(requiredAttachFeatures, required) {
		t.Fatalf("Attach features %v omit exact-resource-acquisition", requiredAttachFeatures)
	}
	postBinding := []string{"namespace-post-binding-identity"}
	if !hasFeatures(requiredHelloFeatures, postBinding) {
		t.Fatalf("Hello features %v omit namespace-post-binding-identity", requiredHelloFeatures)
	}
	if !hasFeatures(requiredStrictAttachFeatures, postBinding) {
		t.Fatalf("strict Attach features %v omit namespace-post-binding-identity", requiredStrictAttachFeatures)
	}
}

// A blocking lock wait parks for as long as the conflicting holder chooses.
// Classifying it as a topology request would hold the coordinator's read
// guard across that unbounded park, so one waiter plus one queued ApplyRoutes
// writer would stall every guarded request on the volume. The wait never
// reaches XFS — the lock table is authority-epoch runtime state — so it is
// admitted through the ordinary session-routes check instead. Non-blocking
// lock calls complete immediately and keep the guard.
func TestRequestUsesTopologyReleasesBlockingLockWaits(t *testing.T) {
	setLock := func(wait, unlock bool) *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{
			Lock: &authoritypb.LockSpec{Write: true, Range: &authoritypb.LockRange{}}, Wait: wait, Unlock: unlock,
		}}}
	}
	if requestUsesTopology(setLock(true, false)) {
		t.Fatal("a blocking lock wait must not hold the topology read guard")
	}
	if !requestUsesTopology(setLock(false, false)) {
		t.Fatal("a non-blocking lock call completes immediately and keeps the guard")
	}
	if !requestUsesTopology(setLock(true, true)) {
		t.Fatal("an unlock never blocks and keeps the guard")
	}
	if !requestUsesTopology(&authoritypb.Request{Body: &authoritypb.Request_GetLock{GetLock: &authoritypb.GetLockRequest{}}}) {
		t.Fatal("a lock query completes immediately and keeps the guard")
	}
}

func TestSourcePhaseQueueabilityRequiresOperationIdentityAndVisibleMutation(t *testing.T) {
	tests := []struct {
		name      string
		request   *authoritypb.Request
		wantValid bool
	}{
		{
			name: "absent proof remains compatible",
			request: &authoritypb.Request{
				Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}},
			},
			wantValid: true,
		},
		{
			name: "ordered visible mutation with operation identity",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{}},
			},
			wantValid: true,
		},
		{
			name: "missing operation identity",
			request: &authoritypb.Request{
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{}},
			},
		},
		{
			name: "ordinary request",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}},
			},
		},
		{
			name: "hello control request",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{}},
			},
		},
		{
			name: "attach control request",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{}},
			},
		},
		{
			name: "visibility control request",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{}},
			},
		},
		{
			name: "non-visible mutation",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body:                 &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{}},
			},
		},
		{
			name: "open truncate does not carry the FSKit ordered-only proof",
			request: &authoritypb.Request{
				FrontendOperationId:  7,
				SourcePhaseQueueable: true,
				Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
					Flags: &authoritypb.OpenFlags{Write: true, Truncate: true},
				}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validSourcePhaseQueueability(test.request); got != test.wantValid {
				t.Fatalf("validSourcePhaseQueueability() = %v, want %v", got, test.wantValid)
			}
		})
	}
}
