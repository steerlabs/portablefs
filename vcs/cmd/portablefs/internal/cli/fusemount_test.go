package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// newTestAuthority serves an in-memory fsproto authority over loopback, the
// same harness the fsproto package's own tests use. No kernel mounts are
// involved anywhere in this file.
func newTestAuthority(t *testing.T) string {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	wfs, err := workfs.New(nil, noBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() { _ = fsproto.NewServer(wfs, wfs, delegation.New()).Serve(ctx, ln) }()
	return ln.Addr().String()
}

type noBlobs struct{}

func (noBlobs) Blob(context.Context, string) ([]byte, error) { return nil, nil }

func TestFillAttrDefaultsAndIdentity(t *testing.T) {
	var out fuse.Attr
	fillAttr("dir/file.txt", &fsproto.Attr{Kind: "file", Size: 7, Mode: 0o640, MtimeMs: 1500, Ino: 42}, &out)
	if out.Ino != 42 {
		t.Fatalf("authority ino must win: %d", out.Ino)
	}
	if out.Nlink != 1 {
		t.Fatalf("zero nlink must default to 1 (never report unlinked-while-open): %d", out.Nlink)
	}
	if out.Size != 7 || out.Mode&0o777 != 0o640 {
		t.Fatalf("size/mode wrong: %+v", out)
	}
	if out.Mtime != 1 || out.Mtimensec != 500*1e6 {
		t.Fatalf("mtime split wrong: %d.%d", out.Mtime, out.Mtimensec)
	}
	if out.Ctime != out.Mtime || out.Atime != out.Mtime {
		t.Fatal("zero ctime/atime must fall back to mtime")
	}

	var noIno fuse.Attr
	fillAttr("dir/file.txt", &fsproto.Attr{Kind: "file"}, &noIno)
	if noIno.Ino == 0 {
		t.Fatal("pre-identity authority must fall back to the path-hash ino")
	}
}

func TestSessionTokenSourceStaticAndRefresh(t *testing.T) {
	static := &sessionTokenSource{token: "tok_static"}
	if got := static.get(); got != "tok_static" {
		t.Fatalf("static token: %q", got)
	}

	refreshed := 0
	src := &sessionTokenSource{
		token:       "tok_old",
		expiresAtMs: time.Now().UnixMilli() - 1, // already expired
		refresh: func() (*mountSession, error) {
			refreshed++
			return &mountSession{Token: "tok_new", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}, nil
		},
	}
	if got := src.get(); got != "tok_new" || refreshed != 1 {
		t.Fatalf("expired token must refresh: %q (refreshed %d)", got, refreshed)
	}
	if got := src.get(); got != "tok_new" || refreshed != 1 {
		t.Fatalf("fresh token must not re-refresh: %q (refreshed %d)", got, refreshed)
	}
}

// TestSessionTokenSourceRefreshFeedbackNoDeadlock pins a wedge fix: the real
// refresh closure feeds the fresh lease back through keeper.adopt → setToken
// while the refresh is still in flight. get() used to hold the token mutex
// across the refresh call, so that echo self-deadlocked and the mount hung on
// the next reconnect handshake. get() must complete and serve the new token.
func TestSessionTokenSourceRefreshFeedbackNoDeadlock(t *testing.T) {
	src := &sessionTokenSource{token: "tok_old", expiresAtMs: time.Now().UnixMilli() - 1}
	src.refresh = func() (*mountSession, error) {
		src.setToken("tok_adopted", time.Now().Add(time.Hour).UnixMilli())
		return &mountSession{Token: "tok_new", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}, nil
	}
	done := make(chan string, 1)
	go func() { done <- src.get() }()
	select {
	case got := <-done:
		if got != "tok_new" {
			t.Fatalf("get() after feedback refresh = %q, want tok_new", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("get() deadlocked while the refresh fed tokens back through setToken")
	}
}

// TestSessionTokenSourceRefreshNow pins the reactive path used on router
// token rejection: refreshNow re-resolves immediately regardless of expiry
// and installs the fresh credential; without a refresh function (--addr
// static-token mounts) it reports false and changes nothing.
func TestSessionTokenSourceRefreshNow(t *testing.T) {
	static := &sessionTokenSource{token: "tok_static"}
	if static.refreshNow() {
		t.Fatal("static mounts have nothing to re-resolve")
	}
	if got := static.get(); got != "tok_static" {
		t.Fatalf("static token must survive a refreshNow no-op: %q", got)
	}

	refreshed := 0
	src := &sessionTokenSource{
		token: "tok_current",
		// Far from expiry: rejection is PROOF the token is dead (epoch-keyed
		// HMAC), so refreshNow must not consult the clock.
		expiresAtMs: time.Now().Add(time.Hour).UnixMilli(),
		refresh: func() (*mountSession, error) {
			refreshed++
			return &mountSession{Token: "tok_fresh", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}, nil
		},
	}
	if !src.refreshNow() {
		t.Fatal("refreshNow with a working resolver must succeed")
	}
	if refreshed != 1 || src.get() != "tok_fresh" {
		t.Fatalf("refreshNow must install the re-resolved token: refreshed=%d token=%q", refreshed, src.get())
	}

	failing := &sessionTokenSource{
		token:   "tok_kept",
		refresh: func() (*mountSession, error) { return nil, errors.New("manager down") },
	}
	if failing.refreshNow() {
		t.Fatal("a failed re-resolve must report false")
	}
	if got := failing.get(); got != "tok_kept" {
		t.Fatalf("a failed re-resolve must not clobber the token: %q", got)
	}
}

// shortSocketDir returns a tempdir short enough for sockaddr_un (macOS caps
// Unix socket paths at 104 bytes; t.TempDir() under /var/folders exceeds it).
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestEnsurePortablefsdAdoptsHealthyDaemon proves the fskit path adopts an
// already-listening control socket instead of spawning a second daemon: a
// fake control server answering /healthz is "the daemon", and ensure returns
// a client bound to it without ever exec-ing a binary.
func TestEnsurePortablefsdAdoptsHealthyDaemon(t *testing.T) {
	dir := shortSocketDir(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()

	cfg := fskitConfig{
		fsType:       "portablefs",
		frontendSock: filepath.Join(dir, "pfs.sock"),
		controlSock:  controlSock,
		// No daemon binary anywhere: adoption must succeed without one.
		daemonPath: filepath.Join(dir, "missing-portablefsd"),
	}
	ctl, err := ensurePortablefsd(cfg, dir)
	if err != nil {
		t.Fatalf("adopting a healthy daemon must not require the binary: %v", err)
	}
	if !ctl.healthy() {
		t.Fatal("adopted control client is not healthy")
	}
}

// TestFsdControlAttachRoundTrip drives the exact control-protocol bytes the
// fskit mount path sends: ensureAttach posts the attach request and reads the
// attachRef, setCredential and deleteAttach address the ref path, and daemon
// error envelopes surface as bounded messages.
func TestFsdControlAttachRoundTrip(t *testing.T) {
	dir := shortSocketDir(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var gotAttach fskitEnsureAttachRequest
	var credentialToken string
	var deleted string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attaches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotAttach); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if gotAttach.VolumeID == "vol-refuse" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"authority unreachable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"attachRef":"att_test1","volumeName":"vol@main"}`))
	})
	mux.HandleFunc("/v1/attaches/att_test1/credential", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AuthToken string `json:"authToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		credentialToken = body.AuthToken
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/attaches/att_test1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = "att_test1"
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()

	ctl := newFsdControl(controlSock)
	ref, err := ctl.ensureAttach(fskitEnsureAttachRequest{
		VolumeID:     "vol-1",
		Branch:       "main",
		AuthorityURL: "127.0.0.1:9",
		AuthToken:    "tok-initial",
		MountPath:    "/tmp/m",
		Options:      fskitOptionsFromPerf(perfOptionsFromEnv(false, func(string) string { return "" }), []string{"node_modules"}, true),
	})
	if err != nil {
		t.Fatalf("ensureAttach: %v", err)
	}
	if ref != "att_test1" {
		t.Fatalf("attachRef = %q", ref)
	}
	if gotAttach.Options.WritePolicy != "writethrough" || len(gotAttach.Options.LocalDirs) != 1 {
		t.Fatalf("attach options did not travel: %+v", gotAttach.Options)
	}
	if err := ctl.setCredential(ref, "tok-rotated"); err != nil {
		t.Fatalf("setCredential: %v", err)
	}
	if credentialToken != "tok-rotated" {
		t.Fatalf("rotated credential did not reach the daemon: %q", credentialToken)
	}
	if err := ctl.deleteAttach(ref); err != nil {
		t.Fatalf("deleteAttach: %v", err)
	}
	if deleted != "att_test1" {
		t.Fatal("delete did not address the attach ref")
	}

	// A typed daemon refusal surfaces its envelope, bounded.
	if _, err := ctl.ensureAttach(fskitEnsureAttachRequest{VolumeID: "vol-refuse"}); err == nil ||
		!strings.Contains(err.Error(), "authority unreachable") {
		t.Fatalf("daemon refusal must surface the envelope, got: %v", err)
	}
}

// TestFastModeAttachOptions pins the --fast translation: write-back policy
// with the bounded flush interval, exactly what the FUSE path's perfOptions
// mean, expressed as portablefsd attach options.
func TestFastModeAttachOptions(t *testing.T) {
	perf := perfOptionsFromEnv(true, func(string) string { return "" })
	opts := fskitOptionsFromPerf(perf, nil, true)
	if opts.WritePolicy != "writeback" {
		t.Fatalf("fast write policy = %q", opts.WritePolicy)
	}
	if opts.FlushIntervalMs != 250 {
		t.Fatalf("fast flush interval = %dms, want 250", opts.FlushIntervalMs)
	}
	if opts.FsyncPolicy != "authority" {
		t.Fatalf("fast fsync policy = %q, want authority (fsync stays a real durability barrier)", opts.FsyncPolicy)
	}
	slow := fskitOptionsFromPerf(perfOptionsFromEnv(false, func(string) string { return "" }), nil, true)
	if slow.WritePolicy != "writethrough" || slow.FlushIntervalMs != 0 {
		t.Fatalf("default must be write-through: %+v", slow)
	}
}
