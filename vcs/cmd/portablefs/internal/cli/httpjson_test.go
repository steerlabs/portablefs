package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestFriendlyErrorTextTranslatesTypedCodes pins the plain-language mapping
// for every typed code users can hit: each entry must carry a next step and
// must never echo the raw code or the envelope's internal jargon.
func TestFriendlyErrorTextTranslatesTypedCodes(t *testing.T) {
	cases := []struct {
		code string
		want []string // fragments the translation must carry
	}{
		{"LIVE_AUTHORITY_ROUTE_REQUIRED", []string{"live authority", "mount"}},
		{"HISTORY_CUT_REQUIRED", []string{"snapshots", "readable"}},
		{"HISTORY_CUT_NOT_READY", []string{"live state", "still being written", "retry", "portablefs snapshots"}},
		{"HISTORY_CUT_FAILED", []string{"failed", "portablefs snapshot"}},
		{"HISTORY_FORK_UNSUPPORTED", []string{"cannot fork", "--from-snapshot"}},
		{"ACCESS_LEASE_UNAUTHORIZED", []string{"portablefs login", "remount"}},
		{"ACCESS_LEASE_INTERNAL", []string{"internal error", "try again", "docker compose logs authority-manager"}},
		{"VOLUME_COMMIT_PFT2_NO_MANIFEST", []string{"content-addressed", "upgrade"}},
	}
	for _, tc := range cases {
		got := friendlyErrorText(tc.code)
		if got == "" {
			t.Fatalf("friendlyErrorText(%q) must translate, got empty", tc.code)
		}
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Fatalf("friendlyErrorText(%q) missing %q: %q", tc.code, want, got)
			}
		}
		if strings.Contains(got, tc.code) {
			t.Fatalf("friendlyErrorText(%q) must not echo the raw code: %q", tc.code, got)
		}
	}
}

// TestFriendlyErrorTextUnknownCodesKeepUpstreamMessage: unknown codes must
// not translate — httpError.Error() keeps the server's message so real
// information is never dropped.
func TestFriendlyErrorTextUnknownCodesKeepUpstreamMessage(t *testing.T) {
	if got := friendlyErrorText("VOLUME_SOMETHING_NEW"); got != "" {
		t.Fatalf("unknown codes must pass through, got %q", got)
	}
	he := &httpError{Status: 409, Code: "VOLUME_SOMETHING_NEW", Message: "A new refusal."}
	if msg := he.Error(); !strings.Contains(msg, "A new refusal.") || !strings.Contains(msg, "VOLUME_SOMETHING_NEW") {
		t.Fatalf("unknown-code errors must keep the upstream message and code: %q", msg)
	}
}

// TestFriendlyErrorTextCarriesThroughHTTPError: a typed envelope parsed off
// the wire must surface the translation via Error(), never the raw text.
func TestFriendlyErrorTextCarriesThroughHTTPError(t *testing.T) {
	he := parseErrorBody(500, []byte(`{"error":{"code":"ACCESS_LEASE_INTERNAL","message":"Production lease creation requires the fenced authority runtime binding (sequence + runtime id)."}}`))
	msg := he.Error()
	if !strings.Contains(msg, "internal error while preparing this mount") {
		t.Fatalf("typed 500 must translate: %q", msg)
	}
	for _, jargon := range []string{"ACCESS_LEASE_INTERNAL", "fenced", "runtime binding"} {
		if strings.Contains(msg, jargon) {
			t.Fatalf("raw envelope text must not leak: %q", msg)
		}
	}
}

// ---- version handshake ----

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in   string
		want semver
		ok   bool
	}{
		{"v1.2.3", semver{1, 2, 3}, true},
		{"1.2.3", semver{1, 2, 3}, true},
		{"v0.4.12-rc.1", semver{0, 4, 12}, true},
		{"v10.20.30+build.5", semver{10, 20, 30}, true},
		{" v1.2.3 ", semver{1, 2, 3}, true},
		{"dev", semver{}, false},
		{"test", semver{}, false},
		{"", semver{}, false},
		{"1.2", semver{}, false},
		{"v1.2.3.4", semver{}, false},
		{"latest", semver{}, false},
	}
	for _, tc := range cases {
		got, ok := parseSemver(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("parseSemver(%q) = (%+v, %v), want (%+v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSemverLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.2.3", "1.2.4", true},
		{"1.2.3", "1.3.0", true},
		{"1.2.3", "2.0.0", true},
		{"1.2.3", "1.2.3", false},
		{"2.0.0", "1.9.9", false},
		{"1.10.0", "1.9.0", false},
		{"0.9.9", "1.0.0", true},
	}
	for _, tc := range cases {
		a, _ := parseSemver(tc.a)
		b, _ := parseSemver(tc.b)
		if got := a.less(b); got != tc.want {
			t.Fatalf("%s < %s = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// minVersionServer answers GET /v1/volumes (and everything else 404) with
// the min-CLI-version handshake header on every response.
func minVersionServer(t *testing.T, minVersion string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if minVersion != "" {
			w.Header().Set(minCLIVersionHeader, minVersion)
		}
		if r.Method == "GET" && r.URL.Path == "/v1/volumes" {
			_, _ = w.Write([]byte(`{"volumes":[]}`))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestVersionHandshakeFailsFastBelowMinimum: a release binary below the
// server's minimum must fail the command immediately — even on an otherwise
// successful response — with the copy-paste upgrade command for that origin.
func TestVersionHandshakeFailsFastBelowMinimum(t *testing.T) {
	srv := minVersionServer(t, "2.0.0")
	e, _, stderr := testEnv(t)
	e.version = "v1.4.0"
	if rc := e.run([]string{"ls", "--api-url", srv.URL, "--api-token", "tok"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	msg := stderr.String()
	for _, want := range []string{
		"this CLI is v1.4.0",
		"requires at least 2.0.0",
		"upgrade with: curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("skew failure missing %q: %q", want, msg)
		}
	}
}

// TestVersionHandshakeDevBuildWarnsOnceAndProceeds: a non-semver build
// ("portablefs dev") cannot be ordered against a release version, so it
// warns exactly once per client — not once per poll — and keeps working.
func TestVersionHandshakeDevBuildWarnsOnceAndProceeds(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(minCLIVersionHeader, "2.0.0")
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/activate-journal") {
			if polls.Add(1) < 3 {
				_, _ = w.Write([]byte(`{"state":"converting"}`))
				return
			}
			_, _ = w.Write([]byte(`{"state":"active","branchMode":"managed_journal"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	e, _, stderr := testEnv(t)
	e.version = "dev"
	if rc := e.run([]string{"activate", "vol1", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatalf("dev build must proceed, rc = %d, stderr: %s", rc, stderr.String())
	}
	if polls.Load() != 3 {
		t.Fatalf("expected 3 polls, got %d", polls.Load())
	}
	msg := stderr.String()
	if got := strings.Count(msg, "portablefs: warning:"); got != 1 {
		t.Fatalf("dev skew must warn exactly once, got %d: %q", got, msg)
	}
	if !strings.Contains(msg, "requires CLI 2.0.0 or newer") || !strings.Contains(msg, "curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh") {
		t.Fatalf("dev warning must name the minimum and the upgrade command: %q", msg)
	}
}

// TestVersionHandshakeMeetingMinimumPasses: equal or newer release versions
// pass silently.
func TestVersionHandshakeMeetingMinimumPasses(t *testing.T) {
	srv := minVersionServer(t, "2.0.0")
	e, _, stderr := testEnv(t)
	e.version = "v2.0.0"
	if rc := e.run([]string{"ls", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("meeting the minimum must be silent: %q", stderr.String())
	}
}

// TestVersionHandshakeUnparseableHeaderIgnored: a header the CLI cannot
// order against ("latest") must never break the command — a server-side bug
// must not take out every stale-looking client.
func TestVersionHandshakeUnparseableHeaderIgnored(t *testing.T) {
	srv := minVersionServer(t, "latest")
	e, _, stderr := testEnv(t)
	e.version = "v0.0.1"
	if rc := e.run([]string{"ls", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
}

// TestVersionHandshakeAbsentHeaderNoOp: servers that do not send the header
// (every server today) behave exactly as before.
func TestVersionHandshakeAbsentHeaderNoOp(t *testing.T) {
	srv := minVersionServer(t, "")
	e, _, stderr := testEnv(t)
	e.version = "v0.0.1"
	if rc := e.run([]string{"ls", "--api-url", srv.URL, "--api-token", "tok"}); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("absent header must be silent: %q", stderr.String())
	}
}
