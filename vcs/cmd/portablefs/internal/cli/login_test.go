package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDeviceFlowPendingThenSuccess drives the full device login: code issue,
// pending polls (202 and 200+status:pending), then the minted apiKey with a
// server-suggested managerUrl, all persisted to the profile.
func TestDeviceFlowPendingThenSuccess(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device/code":
			_, _ = w.Write([]byte(`{"deviceCode":"dc_1","userCode":"WXYZ-1234","verificationUri":"https://example.com/activate","expiresInSeconds":600,"intervalSeconds":1}`))
		case "/v1/auth/device/token":
			switch polls.Add(1) {
			case 1:
				w.WriteHeader(202)
			case 2:
				_, _ = w.Write([]byte(`{"status":"pending"}`))
			default:
				_, _ = w.Write([]byte(`{"apiKey":"key_9","managerUrl":"https://mgr.example.com"}`))
			}
		case "/v1/volumes": // credential verification after login
			_, _ = w.Write([]byte(`{"volumes":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	e, stdout, _ := testEnv(t)
	if rc := e.run([]string{"login", srv.URL}); rc != 0 {
		t.Fatalf("device login rc = %d", rc)
	}
	if !strings.Contains(stdout.String(), "https://example.com/activate") || !strings.Contains(stdout.String(), "WXYZ-1234") {
		t.Fatalf("must print the verification URI and user code: %q", stdout.String())
	}
	if polls.Load() != 3 {
		t.Fatalf("expected 3 polls (202, pending, success), got %d", polls.Load())
	}
	cfg, err := loadConfig(e.configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["default"]
	if p.APIToken != "key_9" {
		t.Fatalf("apiKey must be stored as apiToken: %+v", p)
	}
	if p.ManagerUrl != "https://mgr.example.com" {
		t.Fatalf("server-provided managerUrl must be stored: %+v", p)
	}
}

// TestDeviceFlowOpensBrowserWithPrefilledCode proves the golden path: the CLI
// opens the approval link with the user code prefilled, so the browser lands
// on a one-click approve screen and the key arrives on the existing poll.
func TestDeviceFlowOpensBrowserWithPrefilledCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device/code":
			_, _ = w.Write([]byte(`{"deviceCode":"dc_1","userCode":"UCQLI456","verificationUri":"https://cloud.example.com/device","expiresInSeconds":600,"intervalSeconds":1}`))
		case "/v1/auth/device/token":
			_, _ = w.Write([]byte(`{"apiKey":"key_1","managerUrl":""}`))
		case "/v1/volumes":
			_, _ = w.Write([]byte(`{"volumes":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	e, stdout, _ := testEnv(t)
	var openedURL string
	e.openURLFn = func(url string) error {
		openedURL = url
		return nil
	}
	if rc := e.run([]string{"login", srv.URL}); rc != 0 {
		t.Fatalf("device login rc = %d", rc)
	}
	if openedURL != "https://cloud.example.com/device?code=UCQLI456" {
		t.Fatalf("must open the prefilled approval URL, opened %q", openedURL)
	}
	if !strings.Contains(stdout.String(), "Opened https://cloud.example.com/device?code=UCQLI456") ||
		!strings.Contains(stdout.String(), "UCQLI456") {
		t.Fatalf("must report the opened link and the code: %q", stdout.String())
	}
}

// TestDeviceFlowNoBrowserPrintsLinkOnly covers SSH/headless usage: --no-browser
// never launches anything and prints both the one-click link and the manual
// code entry fallback.
func TestDeviceFlowNoBrowserPrintsLinkOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device/code":
			_, _ = w.Write([]byte(`{"deviceCode":"dc_1","userCode":"UCQLI456","verificationUri":"https://cloud.example.com/device","expiresInSeconds":600,"intervalSeconds":1}`))
		case "/v1/auth/device/token":
			_, _ = w.Write([]byte(`{"apiKey":"key_1","managerUrl":""}`))
		case "/v1/volumes":
			_, _ = w.Write([]byte(`{"volumes":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	e, stdout, _ := testEnv(t)
	e.openURLFn = func(string) error {
		t.Fatal("--no-browser must never attempt to open a browser")
		return nil
	}
	if rc := e.run([]string{"login", srv.URL, "--no-browser"}); rc != 0 {
		t.Fatalf("device login rc = %d", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "Visit https://cloud.example.com/device?code=UCQLI456") ||
		!strings.Contains(out, "or enter code UCQLI456 at https://cloud.example.com/device") {
		t.Fatalf("must print the prefilled link and the manual fallback: %q", out)
	}
}

func TestApprovalURL(t *testing.T) {
	for _, tc := range []struct {
		uri, code, want string
	}{
		{"https://x.example/device", "ABCD2345", "https://x.example/device?code=ABCD2345"},
		{"https://x.example/device?utm=1", "ABCD2345", "https://x.example/device?code=ABCD2345&utm=1"},
		{"://bad url", "ABCD2345", "://bad url"},
	} {
		if got := approvalURL(tc.uri, tc.code); got != tc.want {
			t.Fatalf("approvalURL(%q, %q) = %q, want %q", tc.uri, tc.code, got, tc.want)
		}
	}
}

func TestDeviceFlow404MeansUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":"VOLUME_NOT_FOUND","message":"Route not found."}}`))
	}))
	defer srv.Close()

	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"login", srv.URL}); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "this server does not support device login; pass --token") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestDeviceFlowDeniedStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device/code":
			_, _ = w.Write([]byte(`{"deviceCode":"dc_1","userCode":"WXYZ","verificationUri":"https://example.com/activate","expiresInSeconds":600,"intervalSeconds":1}`))
		case "/v1/auth/device/token":
			w.WriteHeader(410)
			_, _ = w.Write([]byte(`{"error":"code expired"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"login", srv.URL}); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(stderr.String(), "denied or expired") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
