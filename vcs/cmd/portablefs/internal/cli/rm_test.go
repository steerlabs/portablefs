package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func rmFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := newFakeServer(t)
	f.on("DELETE", "/v1/volumes/vol_1", func(map[string]any) (int, string) {
		return 200, `{"volumeId":"vol_1","retiredAt":"2026-07-23T07:00:00.000Z"}`
	})
	return f
}

// TestRmRefusesWithoutYesOnNonTTY pins the non-interactive safety gate: a
// pipe or /dev/null stdin can never confirm a retirement, so rm must refuse
// with the --yes remediation BEFORE any request is sent.
func TestRmRefusesWithoutYesOnNonTTY(t *testing.T) {
	f := rmFakeServer(t)
	e, _, stderr := testEnv(t)
	e.stdinIsTTY = func() bool { return false }
	if rc := e.run(f.commonArgs("rm", "vol_1")); rc != 2 {
		t.Fatalf("rc = %d, want 2 (usage error)", rc)
	}
	if !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("the refusal must hand over the --yes remediation: %q", stderr.String())
	}
	if len(f.recorded()) != 0 {
		t.Fatalf("no request may be sent without confirmation: %+v", f.recorded())
	}
}

// TestRmInteractiveConfirmation pins the TTY flow: rm prints the
// consequences (mounts detach as leases expire; cannot be undone), requires
// the volume id to be typed back, and only then issues the DELETE.
func TestRmInteractiveConfirmation(t *testing.T) {
	f := rmFakeServer(t)
	e, stdout, stderr := testEnv(t)
	e.stdinIsTTY = func() bool { return true }
	e.stdin = strings.NewReader("vol_1\n")
	if rc := e.run(f.commonArgs("rm", "vol_1")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %q", rc, stderr.String())
	}
	prompt := stdout.String()
	for _, want := range []string{"vol_1", "leases expire", "cannot be undone", "type the volume id"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the confirmation prompt must state %q: %q", want, prompt)
		}
	}
	reqs := f.recorded()
	if len(reqs) != 1 || reqs[0].Method != "DELETE" || reqs[0].Path != "/v1/volumes/vol_1" {
		t.Fatalf("expected exactly one DELETE /v1/volumes/vol_1, got %+v", reqs)
	}
	// Retirement is a resource mutation: hosted control planes key their
	// exact-once operation ledger on the caller-retained Idempotency-Key.
	if reqs[0].IdempotencyKey == "" || len(reqs[0].IdempotencyKey) > 128 {
		t.Fatalf("DELETE must carry a bounded Idempotency-Key, got %q", reqs[0].IdempotencyKey)
	}
	// The receipt: volume id, retirement instant, and the mounts note.
	for _, want := range []string{"retired volume vol_1", "2026-07-23T07:00:00.000Z", "detach shortly"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the receipt must state %q: %q", want, prompt)
		}
	}
}

// TestRmInteractiveMismatchAborts: typing anything but the exact volume id
// aborts without a request.
func TestRmInteractiveMismatchAborts(t *testing.T) {
	f := rmFakeServer(t)
	e, _, stderr := testEnv(t)
	e.stdinIsTTY = func() bool { return true }
	e.stdin = strings.NewReader("vol_2\n")
	if rc := e.run(f.commonArgs("rm", "vol_1")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "nothing was retired") {
		t.Fatalf("the abort must say nothing happened: %q", stderr.String())
	}
	if len(f.recorded()) != 0 {
		t.Fatalf("a mismatched confirmation must never send a request: %+v", f.recorded())
	}
}

// TestRmInteractiveEOFAborts: a terminal that closes stdin mid-prompt (^D)
// aborts exactly like a mismatch.
func TestRmInteractiveEOFAborts(t *testing.T) {
	f := rmFakeServer(t)
	e, _, _ := testEnv(t)
	e.stdinIsTTY = func() bool { return true }
	e.stdin = strings.NewReader("")
	if rc := e.run(f.commonArgs("rm", "vol_1")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if len(f.recorded()) != 0 {
		t.Fatalf("EOF must never confirm a retirement: %+v", f.recorded())
	}
}

// TestRmYesSkipsConfirmation: --yes retires without a prompt, even on a
// non-interactive stdin (the scripted/agent path).
func TestRmYesSkipsConfirmation(t *testing.T) {
	f := rmFakeServer(t)
	e, stdout, stderr := testEnv(t)
	e.stdinIsTTY = func() bool { return false }
	if rc := e.run(f.commonArgs("rm", "vol_1", "--yes")); rc != 0 {
		t.Fatalf("rc = %d, stderr: %q", rc, stderr.String())
	}
	if strings.Contains(stdout.String(), "type the volume id") {
		t.Fatalf("--yes must not prompt: %q", stdout.String())
	}
	reqs := f.recorded()
	if len(reqs) != 1 || reqs[0].Method != "DELETE" || reqs[0].Path != "/v1/volumes/vol_1" {
		t.Fatalf("expected exactly one DELETE /v1/volumes/vol_1, got %+v", reqs)
	}
	if !strings.Contains(stdout.String(), "retired volume vol_1") {
		t.Fatalf("receipt output: %q", stdout.String())
	}
}

// TestRmJSONReceipt: --json emits the machine-readable receipt.
func TestRmJSONReceipt(t *testing.T) {
	f := rmFakeServer(t)
	e, stdout, _ := testEnv(t)
	if rc := e.run(f.commonArgs("rm", "vol_1", "--yes", "--json")); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	var receipt struct {
		VolumeID  string `json:"volumeId"`
		RetiredAt string `json:"retiredAt"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatalf("rm --json must emit valid JSON: %v (%q)", err, stdout.String())
	}
	if receipt.VolumeID != "vol_1" || receipt.RetiredAt != "2026-07-23T07:00:00.000Z" {
		t.Fatalf("receipt = %+v", receipt)
	}
}

// TestRm404IsActionable: the server's non-enumerating 404 (unknown, foreign,
// or already retired) is translated to plain language with a next step.
func TestRm404IsActionable(t *testing.T) {
	f := newFakeServer(t) // no DELETE route: the default envelope is the guard's 404
	e, _, stderr := testEnv(t)
	if rc := e.run(f.commonArgs("rm", "vol_gone", "--yes")); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	for _, want := range []string{"not found", "already be retired", "portablefs ls"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the 404 must be actionable (%q missing): %q", want, msg)
		}
	}
}

// TestRmUsageAndHelp: exactly one volume id; rm is documented in the root
// help's VOLUMES section and has detailed help.
func TestRmUsageAndHelp(t *testing.T) {
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"rm"}); rc != 2 {
		t.Fatalf("rc = %d, want 2 for a missing volume id", rc)
	}
	if !strings.Contains(stderr.String(), "exactly one volume id") {
		t.Fatalf("usage error: %q", stderr.String())
	}
	if !strings.Contains(rootHelp(), "rm <volumeId>") {
		t.Fatal("root help must list rm in the VOLUMES section")
	}
	text, ok := commandHelp("rm")
	if !ok {
		t.Fatal("`portablefs help rm` must exist")
	}
	for _, want := range []string{"--yes", "cannot be undone", "leases expire"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rm help must mention %q: %q", want, text)
		}
	}
}
