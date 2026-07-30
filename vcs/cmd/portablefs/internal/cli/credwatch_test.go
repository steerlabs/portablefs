package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// watchHarness wires a credentialWatch to a log buffer and a real mount-state
// file, the exact production wiring of runMountForeground.
func watchHarness(t *testing.T) (*credentialWatch, *bytes.Buffer, string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mountPath := "/tmp/watch-mount"
	if err := writeMountState(dir, validFuseMountState(t, mountPath)); err != nil {
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
// refusal. The watch must log exactly once, flip the persisted mount status,
// and the keeper must stop without any create/recovery path.
func TestLeaseKeeperMarksCredentialExpiredOnRevocation(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 401, `{"error":{"code":"ACCESS_LEASE_UNAUTHORIZED","message":"Access lease credentials rejected."}}`
	})
	w, logBuf, stateDir, mountPath := watchHarness(t)
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, &sessionTokenSource{}, leaseState{
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

	// A terminal keeper never ticks again.
	k.renewOnce(context.Background())
	k.renewOnce(context.Background())
	if got := strings.Count(logBuf.String(), "credentials revoked or expired"); got != 1 {
		t.Fatalf("repeat rejections must not re-log, got %d: %q", got, logBuf.String())
	}

}

// TestLeaseKeeperExpiredIsVisible verifies that terminal expiry is surfaced
// directly; there is no re-acquire whose outcome could hide it.
func TestLeaseKeeperExpiredIsVisible(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 410, `{"error":{"code":"ACCESS_LEASE_EXPIRED","message":"lease expired"}}`
	})
	w, logBuf, stateDir, mountPath := watchHarness(t)
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, &sessionTokenSource{}, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "tok", ExpiresAtMs: 1, ControlSeq: "1",
	}, nil)
	k.credWatch = w

	k.renewOnce(context.Background())
	st, _ := readMountState(stateDir, mountPath)
	if st.Status != mountStatusCredentialExpired {
		t.Fatalf("terminal expiry must be visible: %+v", st)
	}
	if !strings.Contains(logBuf.String(), "credentials revoked or expired") {
		t.Fatalf("terminal expiry must be logged: %q", logBuf.String())
	}
}

// TestMountsShowsCredentialExpired pins the operator surface: a running
// daemon whose credentials were revoked renders credential-expired with the
// remediation, not "live"; JSON carries the same fields.
func TestMountsShowsCredentialExpired(t *testing.T) {
	e, stdout, _ := testEnv(t)
	e.mountHealthFn = func(st *mountState) string {
		if st.Status == mountStatusCredentialExpired {
			return mountStatusCredentialExpired
		}
		return "live"
	}
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
	st := validFuseMountState(t, "/tmp/w1")
	st.VolumeID = "vol_revoked"
	st.Status = mountStatusCredentialExpired
	st.StatusChangedAtMs = 1700000000000
	if err := writeMountState(dir, st); err != nil {
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
