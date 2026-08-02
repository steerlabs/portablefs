package cli

import (
	"strings"
	"testing"
)

// A ROUTER REFUSAL THAT IS NOT ABOUT THE CREDENTIAL MUST NOT READ LIKE ONE.
//
// The router used to spell capacity, lease transitions and its own backend
// outages with the same ack byte it used for a dead credential, so `portablefs
// mounts` printed "degraded (credential rejected; run `portablefs login` and
// remount)" for all four. Live, that told an operator to re-authenticate a
// lease with four and a half minutes of validity left, over a condition
// re-authenticating cannot touch.
func TestMountsRendersARouterRefusalAsItsOwnCondition(t *testing.T) {
	const reason = "the manager's data-plane router REFUSED this mount's tunnel, " +
		"and not because of the credential: the access lease is at its concurrent " +
		"data-plane tunnel limit"
	refused := mountStatusWord(mountStatusInput{
		health:           "live",
		mountPath:        "/Volumes/X",
		attachState:      "degraded",
		attachCredential: attachCredentialRouterRefused,
		attachLastError:  reason,
	})
	if !strings.Contains(refused, "tunnel limit") {
		t.Fatalf("the word must carry the condition the router actually "+
			"reported, got %q", refused)
	}
	if strings.Contains(refused, "portablefs login") {
		t.Fatalf("a refusal that is not about the credential must never "+
			"prescribe re-authentication: %q", refused)
	}
	if strings.Contains(refused, "credential rejected") {
		t.Fatalf("a router refusal must not borrow the credential verdict's "+
			"word: %q", refused)
	}
	if !strings.Contains(refused, "retrying") {
		t.Fatalf("a retryable condition must say it is retryable, or the "+
			"operator will intervene where waiting is the answer: %q", refused)
	}

	// With no daemon sentence to carry, the word still refuses to blame the
	// credential. It may MENTION login — to deny it, which is the whole point —
	// but it must never prescribe it.
	bare := mountStatusWord(mountStatusInput{
		health:           "live",
		attachState:      "degraded",
		attachCredential: attachCredentialRouterRefused,
	})
	if !strings.Contains(bare, "NOT a credential failure") ||
		!strings.Contains(bare, "`portablefs login` will not change it") {
		t.Fatalf("the fallback word must deny the credential claim explicitly: %q", bare)
	}
	if strings.Contains(bare, "run `portablefs login`") {
		t.Fatalf("the fallback word must not prescribe re-authentication: %q", bare)
	}

	// And it is distinct from BOTH pre-existing credential words.
	rejected := mountStatusWord(mountStatusInput{
		health: "live", attachState: "degraded", attachCredential: attachCredentialRejected,
	})
	unproven := mountStatusWord(mountStatusInput{
		health: "live", attachState: "degraded", attachCredential: attachCredentialPendingVerification,
	})
	if refused == rejected || refused == unproven || bare == rejected || bare == unproven {
		t.Fatal("three distinct facts must read as three distinct words")
	}
}
