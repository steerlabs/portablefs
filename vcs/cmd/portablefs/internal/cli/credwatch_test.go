package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCredentialRejectedClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain 401", &httpError{Status: 401, Message: "Unauthorized."}, true},
		{"plain 403", &httpError{Status: 403, Message: "Forbidden."}, true},
		{"typed lease unauthorized", &httpError{Status: 409, Code: "ACCESS_LEASE_UNAUTHORIZED", Message: "rotated"}, true},
		{"wrapped 401", fmt.Errorf("create access lease for v@main: %w", &httpError{Status: 401}), true},
		{"outage 503", &httpError{Status: 503, Message: "store unavailable"}, false},
		{"lease expired", &httpError{Status: 410, Code: "ACCESS_LEASE_EXPIRED"}, false},
		{"transport", fmt.Errorf("dial tcp: connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialRejected(tc.err); got != tc.want {
				t.Fatalf("credentialRejected(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// watchHarness wires a credentialWatch to a log buffer and a real mount-state
// file, the exact production wiring of runMountForeground.
func watchHarness(t *testing.T) (*credentialWatch, *bytes.Buffer, string, string) {
	t.Helper()
	dir := t.TempDir()
	mountPath := "/tmp/watch-mount"
	if err := writeMountState(dir, mountState{MountPath: mountPath, VolumeID: "vol_1", Branch: "main", PID: os.Getpid(), Strategy: "fuse"}); err != nil {
		t.Fatal(err)
	}
	logBuf := &bytes.Buffer{}
	w := newCredentialWatch(
		func(format string, args ...any) { fmt.Fprintf(logBuf, format+"\n", args...) },
		func(status string, atMs int64) { setMountStatus(dir, mountPath, status, atMs) },
	)
	return w, logBuf, dir, mountPath
}

// TestLeaseKeeperMarksCredentialExpiredOnRevocation simulates a key
// revocation end-to-end at the keeper: the renew answers a typed terminal
// refusal AND the re-acquire answers unauthorized. The watch must log exactly
// once (renewals keep ticking — no spam), flip the persisted mount status,
// and clear everything if credentials later work again.
func TestLeaseKeeperMarksCredentialExpiredOnRevocation(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 401, `{"error":{"code":"ACCESS_LEASE_UNAUTHORIZED","message":"Access lease credentials rejected."}}`
	})
	revoked := true
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		if revoked {
			return 401, `{"error":{"code":"ACCESS_LEASE_UNAUTHORIZED","message":"Unauthorized."}}`
		}
		return 200, leaseCreateOK
	})

	w, logBuf, stateDir, mountPath := watchHarness(t)
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, "vol_1", "main", "", &sessionTokenSource{}, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "tok", ExpiresAtMs: 1, ControlSeq: "1",
	}, nil)
	k.credWatch = w

	k.renewOnce(context.Background())
	st, err := readMountState(stateDir, mountPath)
	if err != nil || st == nil {
		t.Fatalf("read state: %v %v", st, err)
	}
	if st.Status != mountStatusCredentialExpired || st.StatusChangedAtMs == 0 {
		t.Fatalf("state must record the credential expiry: %+v", st)
	}
	if got := strings.Count(logBuf.String(), "credentials revoked or expired"); got != 1 {
		t.Fatalf("revocation must log exactly once, got %d: %q", got, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "portablefs login") {
		t.Fatalf("the log line must say what to do: %q", logBuf.String())
	}

	// The renew cadence keeps ticking against the dead credential: no spam.
	k.renewOnce(context.Background())
	k.renewOnce(context.Background())
	if got := strings.Count(logBuf.String(), "credentials revoked or expired"); got != 1 {
		t.Fatalf("repeat rejections must not re-log, got %d: %q", got, logBuf.String())
	}

	// A later success (new key installed, manager accepts again) recovers.
	revoked = false
	k.renewOnce(context.Background())
	st, _ = readMountState(stateDir, mountPath)
	if st.Status != "" || st.StatusChangedAtMs != 0 {
		t.Fatalf("recovery must clear the persisted status: %+v", st)
	}
	if got := strings.Count(logBuf.String(), "credentials accepted again"); got != 1 {
		t.Fatalf("recovery must log exactly once: %q", logBuf.String())
	}
}

// TestLeaseKeeperOutageStaysLive: a definitive renew refusal followed by an
// OUTAGE on re-acquire (503) is not a credential rejection — the mount must
// not be branded credential-expired by a manager hiccup.
func TestLeaseKeeperOutageStaysLive(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 410, `{"error":{"code":"ACCESS_LEASE_EXPIRED","message":"lease expired"}}`
	})
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 503, `{"error":{"code":"ACCESS_LEASE_STORE_UNAVAILABLE","message":"store unavailable"}}`
	})
	w, logBuf, stateDir, mountPath := watchHarness(t)
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, "vol_1", "main", "", &sessionTokenSource{}, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "tok", ExpiresAtMs: 1, ControlSeq: "1",
	}, nil)
	k.credWatch = w

	k.renewOnce(context.Background())
	st, _ := readMountState(stateDir, mountPath)
	if st.Status != "" {
		t.Fatalf("an outage must not mark credentials expired: %+v", st)
	}
	if logBuf.Len() != 0 {
		t.Fatalf("an outage must not log a revocation line: %q", logBuf.String())
	}
}

// TestMountsShowsCredentialExpired pins the operator surface: a running
// daemon whose credentials were revoked renders credential-expired with the
// remediation, not "live"; JSON carries the same fields.
func TestMountsShowsCredentialExpired(t *testing.T) {
	e, stdout, _ := testEnv(t)
	stateHome := t.TempDir()
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return ""
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMountState(dir, mountState{
		MountPath: "/tmp/w1", VolumeID: "vol_revoked", Branch: "main", PID: os.Getpid(),
		Strategy: "fuse", Status: mountStatusCredentialExpired, StatusChangedAtMs: 1700000000000,
	}); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"mounts"}); rc != 0 {
		t.Fatalf("mounts rc = %d", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "credential-expired") || !strings.Contains(out, "portablefs login") {
		t.Fatalf("mounts must render the degraded status with remediation: %q", out)
	}
	if strings.Contains(out, "  live") {
		t.Fatalf("a credential-expired mount must not be reported live: %q", out)
	}

	stdout.Reset()
	if rc := e.run([]string{"mounts", "--json"}); rc != 0 {
		t.Fatal("mounts --json failed")
	}
	if !strings.Contains(stdout.String(), `"status": "credential-expired"`) || !strings.Contains(stdout.String(), `"health": "credential-expired"`) {
		t.Fatalf("mounts --json must carry the status fields: %q", stdout.String())
	}
}
