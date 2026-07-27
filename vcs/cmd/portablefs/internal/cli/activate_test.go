package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// activationStatus builds a journalActivationResponse from wire JSON, so the
// rendering tests double as wire-shape checks for the additive fields.
func activationStatus(t *testing.T, raw string) *journalActivationResponse {
	t.Helper()
	var st journalActivationResponse
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return &st
}

// TestActivationProgressRendering pins the progress line for every server
// generation: the old nested conversion/cut shape renders exactly as before,
// and the additive cutState/attemptCount/lastError fields render when present.
func TestActivationProgressRendering(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"bare state", `{"state":"converting"}`, "converting"},
		{"old nested shape unchanged",
			`{"state":"converting","conversion":{"state":"final_cut"},"cut":{"state":"materializing"}}`,
			"final_cut, cut materializing"},
		{"new fields render",
			`{"state":"converting","conversion":{"state":"final_cut"},"cutState":"materializing","attemptCount":3}`,
			"final_cut, cut materializing, attempt 3"},
		{"last error shown",
			`{"state":"converting","cutState":"materializing","attemptCount":2,"lastError":"upload throttled"}`,
			"converting, cut materializing, attempt 2, last error: upload throttled"},
		{"top-level cut state wins over nested",
			`{"state":"converting","cutState":"finalizing","cut":{"state":"materializing"}}`,
			"converting, cut finalizing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := activationProgress(activationStatus(t, tc.raw)); got != tc.want {
				t.Fatalf("activationProgress = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestActivationFailedTerminalStates pins what counts as terminal: overall
// state "failed" (as today) and the additive cutState "failed", with the
// server's error preferred from the top-level lastError.
func TestActivationFailedTerminalStates(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantFailed bool
		wantDetail string
	}{
		{"active is not failed", `{"state":"active"}`, false, ""},
		{"converting is not failed", `{"state":"converting","cutState":"materializing"}`, false, ""},
		{"overall failed without detail", `{"state":"failed"}`, true, ""},
		{"overall failed keeps nested conversion error",
			`{"state":"failed","conversion":{"lastError":"boom"}}`, true, `: "boom"`},
		{"overall failed keeps nested cut error",
			`{"state":"failed","cut":{"lastError":"cut boom"}}`, true, `: "cut boom"`},
		{"terminal cut state with top-level error",
			`{"state":"converting","cutState":"failed","lastError":"cut worker crashed"}`, true, ": cut worker crashed"},
		{"top-level error preferred over nested",
			`{"state":"failed","lastError":"top","cut":{"lastError":"nested"}}`, true, ": top"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail, failed := activationFailed(activationStatus(t, tc.raw))
			if failed != tc.wantFailed || detail != tc.wantDetail {
				t.Fatalf("activationFailed = (%q, %v), want (%q, %v)", detail, failed, tc.wantDetail, tc.wantFailed)
			}
		})
	}
}

// activateTestServer serves POST /v1/volumes/:id/activate-journal from a
// response function and counts the polls.
func activateTestServer(t *testing.T, respond func(call int32) string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/activate-journal") {
			_, _ = w.Write([]byte(respond(calls.Add(1))))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestActivateStopsImmediatelyOnTerminalCutFailure: a cutState of "failed"
// is terminal — the command must fail after ONE poll with the server's
// error, not keep waiting toward the 15-minute ceiling.
func TestActivateStopsImmediatelyOnTerminalCutFailure(t *testing.T) {
	srv, calls := activateTestServer(t, func(int32) string {
		return `{"state":"converting","cutState":"failed","lastError":"cut worker crashed: disk full"}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"activate", "vol1", "--api-url", srv.URL, "--api-token", "tok"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "activation failed: cut worker crashed: disk full") || !strings.Contains(msg, "re-run to retry") {
		t.Fatalf("must fail with the server's error and the retry hint: %q", msg)
	}
	if calls.Load() != 1 {
		t.Fatalf("terminal failure must stop polling immediately, got %d polls", calls.Load())
	}
}

// TestActivateTimeoutKeepsLastAttemptAndError: the ceiling message must carry
// the last seen state, attempt count, and error, plus the resume hint.
func TestActivateTimeoutKeepsLastAttemptAndError(t *testing.T) {
	srv, calls := activateTestServer(t, func(int32) string {
		return `{"state":"converting","conversion":{"state":"conversion_cut"},"cutState":"materializing","attemptCount":7,"lastError":"transient s3 throttle"}`
	})
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"activate", "vol1", "--timeout", "0s", "--api-url", srv.URL, "--api-token", "tok"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	for _, want := range []string{
		"did not converge within 0s",
		"conversion_cut, cut materializing, attempt 7, last error: transient s3 throttle",
		"re-run to keep waiting",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("timeout message missing %q: %q", want, msg)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("a 0s ceiling must stop after the first poll, got %d", calls.Load())
	}
}

// TestActivateOldServerShapeUnchanged: servers without the additive fields
// keep today's progress rendering and converge normally.
func TestActivateOldServerShapeUnchanged(t *testing.T) {
	srv, _ := activateTestServer(t, func(call int32) string {
		if call == 1 {
			return `{"state":"converting","conversion":{"state":"final_cut","attempt":1},"cut":{"state":"materializing"}}`
		}
		return `{"state":"active","branchMode":"managed_journal"}`
	})
	e, stdout, stderr := testEnv(t)
	if rc := e.run([]string{"activate", "vol1", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "activating journal (final_cut, cut materializing) ...") {
		t.Fatalf("old-shape progress must render unchanged: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "journal active: vol1@main (branch mode managed_journal)") {
		t.Fatalf("must report convergence: %q", stdout.String())
	}
}
