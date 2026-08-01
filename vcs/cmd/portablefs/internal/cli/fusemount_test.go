package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// newTestAuthority serves an in-memory fsproto authority over loopback, the
// same harness the fsproto package's own tests use. No kernel mounts are
// involved anywhere in this file.
func newTestAuthority(t *testing.T) string {
	t.Helper()
	wfs := newManagedTestFS(t, noBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() { _ = fsproto.NewServer(wfs, wfs).Serve(ctx, ln) }()
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

func TestSessionTokenSourceOnlyAdvancesExplicitly(t *testing.T) {
	src := &sessionTokenSource{
		token:       "tok_old",
		expiresAtMs: time.Now().UnixMilli() - 1,
	}
	if got, _ := src.get(); got != "tok_old" {
		t.Fatalf("expired token must not trigger hidden resolution: %q", got)
	}
	src.setToken("tok_renewed", time.Now().Add(time.Hour).UnixMilli())
	if got, _ := src.get(); got != "tok_renewed" {
		t.Fatalf("explicit lease renewal token = %q", got)
	}
}

// shortSocketDir returns a tempdir short enough for sockaddr_un (macOS caps
// Unix socket paths at 104 bytes; t.TempDir() under /var/folders exceeds it).
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func fakePortablefsdBinary(t *testing.T, dir, version string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, "portablefsd")
	script := "#!/bin/sh\nprintf '%s\\n' '" + version + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	sum, err := daemonctl.FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, sum
}

func leaveCLIStaleUnixSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsurePortablefsdDelegatesStaleSocketsAndReportsEarlyExit(t *testing.T) {
	dir := shortSocketDir(t)
	daemonPath, _ := fakePortablefsdBinary(t, dir, "test-version")
	frontendSock := filepath.Join(dir, "pfs.sock")
	controlSock := filepath.Join(dir, "control.sock")
	stateRoot := filepath.Join(dir, "state-root")
	leaveCLIStaleUnixSocket(t, frontendSock)
	leaveCLIStaleUnixSocket(t, controlSock)

	started := time.Now()
	_, err := ensurePortablefsd(fskitConfig{
		fsType:            defaultFskitType,
		frontendSock:      frontendSock,
		controlSock:       controlSock,
		daemonPathForTest: daemonPath,
	}, stateRoot, "test-version")
	if err == nil || !strings.Contains(err.Error(), "exited without becoming healthy") {
		t.Fatalf("early daemon-exit verdict = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("early daemon exit took %v instead of returning immediately", elapsed)
	}
	for _, path := range []string{frontendSock, controlSock} {
		if info, statErr := os.Lstat(path); statErr != nil || info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("CLI mutated daemon-owned stale socket %s: mode=%v err=%v", path, info, statErr)
		}
	}
}

func TestEnsurePortablefsdHungControlCannotMaskSpawnedChildExit(t *testing.T) {
	dir := shortSocketDir(t)
	daemonPath, _ := fakePortablefsdBinary(t, dir, "test-version")
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				<-stop
				_ = conn.Close()
			}()
		}
	}()

	started := time.Now()
	_, err = ensurePortablefsd(fskitConfig{
		fsType:            defaultFskitType,
		frontendSock:      filepath.Join(dir, "pfs.sock"),
		controlSock:       controlSock,
		daemonPathForTest: daemonPath,
	}, filepath.Join(dir, "state-root"), "test-version")
	if err == nil || !strings.Contains(err.Error(), "exited without becoming healthy") {
		t.Fatalf("hung-control early-exit verdict = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("hung control socket masked the child exit for %v", elapsed)
	}
}

func TestFsdControlIdentityHonorsLifecycleDeadline(t *testing.T) {
	dir := shortSocketDir(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/identity" {
			http.NotFound(w, r)
			return
		}
		<-r.Context().Done()
	})}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	started := time.Now()
	err = newFsdControl(controlSock).requireCompatibleIdentityWithin(
		"test-version",
		strings.Repeat("a", 64),
		150*time.Millisecond,
	)
	if err == nil {
		t.Fatal("hung identity endpoint unexpectedly passed")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hung identity endpoint exceeded its lifecycle deadline: %v", elapsed)
	}
}

// TestEnsurePortablefsdAdoptsHealthyDaemon proves the fskit path adopts an
// already-listening control socket instead of spawning a second daemon: a
// fake control server answering the liveness and exact identity endpoints is
// "the daemon", and ensure returns a client bound to it without ever
// exec-ing a binary.
func TestEnsurePortablefsdAdoptsHealthyDaemon(t *testing.T) {
	dir := shortSocketDir(t)
	daemonPath, daemonSHA256 := fakePortablefsdBinary(t, dir, "test-version")
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
		if r.URL.Path == "/v1/identity" {
			_, _ = fmt.Fprintf(w, `{"schemaVersion":1,"controlProtocol":1,"daemonVersion":"test-version","executableSha256":%q,"pfslocalMajor":1,"pfslocalMinor":0}`, daemonSHA256)
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()

	cfg := fskitConfig{
		fsType:            "portablefs",
		frontendSock:      filepath.Join(dir, "pfs.sock"),
		controlSock:       controlSock,
		daemonPathForTest: daemonPath,
	}
	ctl, err := ensurePortablefsd(cfg, dir, "test-version")
	if err != nil {
		t.Fatalf("adopting a healthy daemon must not require the binary: %v", err)
	}
	if !ctl.healthy() {
		t.Fatal("adopted control client is not healthy")
	}
}

func TestEnsurePortablefsdFailsClosedOnIncompatibleHealthyDaemon(t *testing.T) {
	dir := shortSocketDir(t)
	daemonPath, _ := fakePortablefsdBinary(t, dir, "new-version")
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		case "/v1/identity":
			_, _ = w.Write([]byte(`{"schemaVersion":1,"controlProtocol":1,"daemonVersion":"old-version","executableSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pfslocalMajor":1,"pfslocalMinor":0}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()

	cfg := fskitConfig{
		frontendSock:      filepath.Join(dir, "pfs.sock"),
		controlSock:       controlSock,
		daemonPathForTest: daemonPath,
	}
	_, err = ensurePortablefsd(cfg, dir, "new-version")
	if err == nil {
		t.Fatal("incompatible healthy daemon must fail closed")
	}
	if !strings.Contains(err.Error(), `daemon "old-version", CLI "new-version"`) ||
		!strings.Contains(err.Error(), "will not replace a live daemon automatically") {
		t.Fatalf("incompatible daemon error = %v", err)
	}
}

// TestFsdControlAttachRoundTrip drives the exact control-protocol bytes the
// fskit mount path sends: ensureAttach posts the attach request and reads the
// attachRef, setCredential and unmountAttach address the ref path, and daemon
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
	var unmounted string
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
	mux.HandleFunc("/v1/attaches/att_test1/unmount", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if unmounted != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"unknown attach"}`))
				return
			}
			unmounted = "att_test1"
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
		Options:      fskitOptionsFromPerf(perfOptionsFromEnv(func(string) string { return "" }), []string{"node_modules"}, true),
	})
	if err != nil {
		t.Fatalf("ensureAttach: %v", err)
	}
	if ref != "att_test1" {
		t.Fatalf("attachRef = %q", ref)
	}
	if len(gotAttach.Options.LocalDirs) != 1 || !gotAttach.Options.VolumeLocalDirs {
		t.Fatalf("attach options did not travel: %+v", gotAttach.Options)
	}
	if err := ctl.setCredential(ref, "tok-rotated", 0); err != nil {
		t.Fatalf("setCredential: %v", err)
	}
	if credentialToken != "tok-rotated" {
		t.Fatalf("rotated credential did not reach the daemon: %q", credentialToken)
	}
	if err := ctl.unmountAttach(ref); err != nil {
		t.Fatalf("unmountAttach: %v", err)
	}
	if unmounted != "att_test1" {
		t.Fatal("unmount did not address the attach ref")
	}
	if err := ctl.unmountAttach(ref); err != nil {
		t.Fatalf("repeated exact unmount of an already-absent attach must converge: %v", err)
	}

	// A typed daemon refusal surfaces its envelope, bounded.
	if _, err := ctl.ensureAttach(fskitEnsureAttachRequest{VolumeID: "vol-refuse"}); err == nil ||
		!strings.Contains(err.Error(), "authority unreachable") {
		t.Fatalf("daemon refusal must surface the envelope, got: %v", err)
	}
}

// TestFastFlagRetired pins the --fast retirement: the flag is gone from the
// mount surface, and passing it fails with a pointer at the adaptive model
// instead of being silently ignored.
func TestFastFlagRetired(t *testing.T) {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o mountOpts
	addMountFlags(fs, &o)
	err := fs.Parse([]string{"--fast", "vol@main"})
	if err == nil || !strings.Contains(err.Error(), "adaptive") {
		t.Fatalf("--fast must fail with a pointer at the adaptive model, got: %v", err)
	}
}

// newManagedTestFS opens the file-backed PFJ3 entry log at walPath and builds
// the MANAGED workfs over it — the only generation a v5 server serves.
func newManagedTestFS(t testing.TB, blobs content.BlobReader, walPath string) *workfs.FS {
	t.Helper()
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	flog, err := pfj3.NewFileEntryLog(w)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.NewManaged(nil, blobs, flog)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}
