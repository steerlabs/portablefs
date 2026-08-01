package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSessionTokenSourceCarriesTheLeaseExpiry pins the plumbing that makes the
// UNPROVEN credential state boundable at all.
//
// The deadline was always here. leaseState.ExpiresAtMs is persisted per mount,
// the lease keeper pushes it into this very struct on every renewal, and the
// keeper itself already bounds its unresolved replays by it (the house rule:
// the lease's OWN expiry, never a retry budget invented locally). And then
// get() returned the token alone and threw the number away, so the data plane
// — the one layer that has to decide whether an untested credential is still
// worth testing — never learned it.
func TestSessionTokenSourceCarriesTheLeaseExpiry(t *testing.T) {
	src := &sessionTokenSource{}
	expiresAtMs := time.Now().Add(30 * time.Minute).UnixMilli()
	src.setToken("lease-token", expiresAtMs)

	tok, gotExpiry := src.get()
	if tok != "lease-token" {
		t.Fatalf("token = %q", tok)
	}
	if gotExpiry != expiresAtMs {
		t.Fatalf("the lease's own expiry never reached the credential source "+
			"(got %d, want %d): without it an untested credential has no "+
			"boundary and stays pending for the life of the mount",
			gotExpiry, expiresAtMs)
	}

	// A renewal moves the deadline out; the source must serve the LIVE one, not
	// a copy stamped when the credential was first installed.
	renewed := time.Now().Add(2 * time.Hour).UnixMilli()
	src.setToken("renewed-token", renewed)
	if _, got := src.get(); got != renewed {
		t.Fatalf("renewed expiry = %d, want %d: a renewal that pushes the "+
			"deadline out must be honoured immediately", got, renewed)
	}
}

// TestEnvTokenStatesNoDeadline is the compatibility posture at the CLI edge. A
// direct --addr mount authenticated by VCS_AUTH_TOKEN has no lease and nothing
// ever stated when it stops being valid. Zero means "no deadline was stated",
// and reading it as one would harden a perfectly good static credential into a
// dead one the moment it went unproven.
func TestEnvTokenStatesNoDeadline(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "static-env-token")
	src := &sessionTokenSource{}
	tok, expiresAtMs := src.get()
	if tok != "static-env-token" {
		t.Fatalf("token = %q", tok)
	}
	if expiresAtMs != 0 {
		t.Fatalf("a static environment token stated a deadline (%d): it is not a "+
			"lease, nothing about it expires, and nothing about it may harden",
			expiresAtMs)
	}
}

// TestCredentialControlPayloadCarriesTheLeaseExpiry pins the DAEMON wire
// contract: the credential the CLI pushes to portablefsd travels with the
// deadline its lease stated for it, under the field name the daemon reads.
//
// Without it, the FSKit path re-acquires the same unbounded pending state the
// in-process FUSE path just escaped: the daemon holds the credential, the
// daemon runs the handshake, and the daemon is the one that has to decide when
// an untested credential has run out of time.
func TestCredentialControlPayloadCarriesTheLeaseExpiry(t *testing.T) {
	dir := shortSocketDir(t)
	socketPath := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	bodies := make(chan map[string]any, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attaches/att_x/credential", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bodies <- body
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	ctl := newFsdControl(socketPath)
	expiresAtMs := time.Now().Add(45 * time.Minute).UnixMilli()
	if err := ctl.setCredential("att_x", "lease-token", expiresAtMs); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	got, ok := body["authTokenExpiresAtMs"].(float64)
	if !ok || int64(got) != expiresAtMs {
		t.Fatalf("credential control payload = %v: the lease's own expiry never "+
			"reached the daemon, so an untested credential there has no boundary "+
			"and stays pending for the life of the attach", body)
	}

	// A caller with no lease behind it states nothing, and the daemon must be
	// able to tell "no deadline" apart from a real one.
	if err := ctl.setCredential("att_x", "static-token", 0); err != nil {
		t.Fatal(err)
	}
	body = <-bodies
	if v, present := body["authTokenExpiresAtMs"]; present && v.(float64) != 0 {
		t.Fatalf("a credential with no stated deadline sent %v", v)
	}
}

// TestMountsJSONCarriesTheDaemonsCredentialVerdict pins the machine-readable
// half of the surface.
//
// `portablefs mounts --json` is what agents and the extension read. The daemon
// now names WHICH credential fault is behind a degraded attach, and the CLI's
// presentation types must carry that through — a decode that drops it leaves
// an agent looking at attachState=degraded with no way to tell a proven-dead
// credential from an untested one, which is the same flattening the printed
// line used to do.
func TestMountsJSONCarriesTheDaemonsCredentialVerdict(t *testing.T) {
	const daemonStatus = `{
	  "attachRef": "att_x",
	  "mountPath": "/Volumes/X",
	  "volumeId": "vol",
	  "branch": "main",
	  "state": "degraded",
	  "credential": "pending-verification",
	  "lastError": "access credential is UNPROVEN: the authority has neither accepted nor refused it"
	}`
	var status cliAttachStatus
	if err := json.Unmarshal([]byte(daemonStatus), &status); err != nil {
		t.Fatal(err)
	}
	if status.Credential != attachCredentialPendingVerification {
		t.Fatalf("cliAttachStatus dropped the daemon's credential verdict (got %q): "+
			"a degraded attach whose credential is merely UNTESTED is then "+
			"indistinguishable in --json from one whose credential is proven dead",
			status.Credential)
	}
}

// TestMountsRendersTheUnprovenCredentialDistinctlyFromTheExpiredOne pins the
// operator-facing words.
//
// Three credential-shaped states now reach this command and they must read
// differently, because the action each one calls for is different:
//
//	credential-expired          the CLI lease keeper's own persisted verdict
//	                            (a control-plane renewal refusal) -> log in again
//	degraded, rejected          the data plane's ack-1 refusal    -> log in again
//	degraded, pending-verify    NOBODY has answered               -> look at the
//	                            router/authority, not at your login
//
// The last one used to print as bare "degraded", which reads as a write-back
// problem and says nothing about a credential at all.
func TestMountsRendersTheUnprovenCredentialDistinctlyFromTheExpiredOne(t *testing.T) {
	unproven := mountStatusWord(mountStatusInput{
		health:           "live",
		mountPath:        "/Volumes/X",
		attachState:      "degraded",
		attachCredential: attachCredentialPendingVerification,
	})
	if !strings.Contains(unproven, "pending-verification") {
		t.Fatalf("an untested credential renders as %q: an operator cannot tell it "+
			"from a stalled write-back engine", unproven)
	}
	if strings.Contains(unproven, "portablefs login") {
		t.Fatalf("an UNPROVEN credential must not send the operator to "+
			"re-authenticate: nothing has found fault with the credential, so "+
			"logging in again cannot fix it: %q", unproven)
	}
	if strings.Contains(unproven, "credential-expired") {
		t.Fatalf("an unproven credential must not borrow the expired word: %q", unproven)
	}

	rejected := mountStatusWord(mountStatusInput{
		health:           "live",
		mountPath:        "/Volumes/X",
		attachState:      "degraded",
		attachCredential: attachCredentialRejected,
	})
	if !strings.Contains(rejected, "rejected") || !strings.Contains(rejected, "portablefs login") {
		t.Fatalf("a proven-dead credential must name the one remedy that works: %q", rejected)
	}
	if rejected == unproven {
		t.Fatal("the two credential faults render identically: they call for " +
			"opposite investigations")
	}

	// The pre-existing paths are untouched: a degraded attach with no credential
	// fault still reads exactly as it did, and the CLI lease keeper's own
	// persisted verdict keeps its own separate word.
	if got := (mountStatusWord(mountStatusInput{health: "live", attachState: "degraded"})); got != "degraded" {
		t.Fatalf("a degraded attach with no credential fault = %q, want %q", got, "degraded")
	}
	if got := (mountStatusWord(mountStatusInput{health: "live"})); got != "live" {
		t.Fatalf("a healthy mount = %q, want live", got)
	}
	keeper := mountStatusWord(mountStatusInput{
		health:            mountStatusCredentialExpired,
		statusChangedAtMs: 1700000000000,
	})
	if !strings.HasPrefix(keeper, "credential-expired") || !strings.Contains(keeper, "portablefs login") {
		t.Fatalf("the CLI lease keeper's persisted verdict must keep its own word "+
			"and remedy: %q", keeper)
	}
}
