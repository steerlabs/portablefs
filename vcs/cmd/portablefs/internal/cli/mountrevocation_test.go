package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Revocation observability. These tests run on every platform on purpose: the
// whole point of the shared vocabulary is that a Linux fusev3 self-revocation
// and a macOS FSKit watchdog revocation produce the same record and the same
// `portablefs mounts --json` shape.

func revokedStateDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, "/tmp/revoked"
}

func TestSetMountRevokedPersistsReasonAndTimestamp(t *testing.T) {
	dir, mountPath := revokedStateDir(t)
	if err := writeMountState(dir, validFuseMountState(t, mountPath)); err != nil {
		t.Fatal(err)
	}
	if !setMountRevoked(dir, mountPath, mountRevokedRepairBudgetExceeded, "the mount could not repair in time", 1700000000000) {
		t.Fatal("revocation was not recorded")
	}
	got, err := readMountState(dir, mountPath)
	if err != nil || got == nil {
		t.Fatalf("readMountState: %v %v", got, err)
	}
	if got.Status != mountStatusRevoked {
		t.Fatalf("status = %q, want %q", got.Status, mountStatusRevoked)
	}
	if got.StatusReason != mountRevokedRepairBudgetExceeded {
		t.Fatalf("statusReason = %q", got.StatusReason)
	}
	if got.StatusDetail != "the mount could not repair in time" || got.StatusChangedAtMs != 1700000000000 {
		t.Fatalf("revocation record lost its detail or timestamp: %+v", got)
	}
}

func TestRevocationRecordIsTerminalAndCannotBeDowngraded(t *testing.T) {
	// A renewal owner that has not noticed the revocation must not be able to
	// relabel a mount that refuses to serve as one that merely needs a new
	// credential.
	dir, mountPath := revokedStateDir(t)
	if err := writeMountState(dir, validFuseMountState(t, mountPath)); err != nil {
		t.Fatal(err)
	}
	setMountRevoked(dir, mountPath, mountRevokedSessionTerminal, "session fenced", 1700000000000)
	setMountStatus(dir, mountPath, mountStatusCredentialExpired, 1700000900000)
	setMountRevoked(dir, mountPath, mountRevokedDaemonUnreachable, "later, weaker verdict", 1700000900000)

	got, err := readMountState(dir, mountPath)
	if err != nil || got == nil {
		t.Fatalf("readMountState: %v %v", got, err)
	}
	if got.Status != mountStatusRevoked || got.StatusReason != mountRevokedSessionTerminal {
		t.Fatalf("terminal revocation was overwritten: %+v", got)
	}
	if got.StatusChangedAtMs != 1700000000000 {
		t.Fatalf("revocation timestamp moved to a later observation: %d", got.StatusChangedAtMs)
	}
}

func TestUnknownRevocationReasonIsRecordedAsUnclassified(t *testing.T) {
	// An engine that grows a new reason must not be able to make a revocation
	// unrecordable, and must not be silently mislabelled as a known class.
	dir, mountPath := revokedStateDir(t)
	if err := writeMountState(dir, validFuseMountState(t, mountPath)); err != nil {
		t.Fatal(err)
	}
	if !setMountRevoked(dir, mountPath, "a-reason-from-the-future", "detail", 1700000000000) {
		t.Fatal("an unrecognized reason lost the whole revocation")
	}
	got, err := readMountState(dir, mountPath)
	if err != nil || got == nil {
		t.Fatalf("readMountState: %v %v", got, err)
	}
	if got.StatusReason != mountRevokedUnclassified {
		t.Fatalf("statusReason = %q, want %q", got.StatusReason, mountRevokedUnclassified)
	}
}

func TestMountRecordRefusesInconsistentRevocationFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*mountState)
	}{
		{"revoked without a reason", func(st *mountState) {
			st.Status, st.StatusChangedAtMs = mountStatusRevoked, 1
		}},
		{"revoked without a timestamp", func(st *mountState) {
			st.Status, st.StatusReason = mountStatusRevoked, mountRevokedSessionTerminal
		}},
		{"revoked with an invalid reason", func(st *mountState) {
			st.Status, st.StatusChangedAtMs, st.StatusReason = mountStatusRevoked, 1, "nonsense"
		}},
		{"classification without the verdict", func(st *mountState) {
			st.Status, st.StatusChangedAtMs = mountStatusCredentialExpired, 1
			st.StatusReason = mountRevokedSessionTerminal
		}},
		{"detail without any status", func(st *mountState) {
			st.StatusDetail = "orphaned prose"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := validFuseMountState(t, "/tmp/w")
			tc.mutate(&st)
			if err := validateMountStateRecord("/state/x.json", &st); err == nil {
				t.Fatal("an inconsistent revocation record was accepted")
			}
		})
	}
}

func TestMountHealthReportsRevokedAheadOfLiveness(t *testing.T) {
	// The defect this closes: a revoked mount whose MNT_DETACH failed still has
	// a running owner and an installed kernel mount, so every liveness check it
	// is subjected to passes and it reported itself LIVE.
	st := validFuseMountState(t, "/tmp/w")
	st.Status = mountStatusRevoked
	st.StatusReason = mountRevokedCoherenceViolation
	st.StatusChangedAtMs = 1700000000000
	if got := mountHealth(&st); got != mountStatusRevoked {
		t.Fatalf("mountHealth = %q, want %q", got, mountStatusRevoked)
	}

	// And a revoked record whose owner is long gone still reads as revoked
	// rather than as an ordinary leftover: the verdict says why.
	st.PID = 4194000
	st.ProcessStartIdentity = "1"
	if got := mountHealth(&st); got != mountStatusRevoked {
		t.Fatalf("mountHealth for a dead revoked owner = %q, want %q", got, mountStatusRevoked)
	}
}

func TestMountStatusWordNamesTheRevocationReason(t *testing.T) {
	word := mountStatusWord(mountStatusInput{
		health:            mountStatusRevoked,
		mountPath:         "/tmp/w",
		statusChangedAtMs: 1700000000000,
		statusReason:      mountRevokedSessionTerminal,
		statusDetail:      "the v3 authority session is terminal",
	})
	for _, want := range []string{"revoked", mountRevokedSessionTerminal, "the v3 authority session is terminal", "portablefs umount /tmp/w"} {
		if !strings.Contains(word, want) {
			t.Fatalf("status word %q missing %q", word, want)
		}
	}
	if strings.Contains(word, "live") {
		t.Fatalf("a revoked mount was described as live: %q", word)
	}
}

// mountsJSONRows runs `portablefs mounts --json` against a private state root
// and returns the decoded rows.
func mountsJSONRows(t *testing.T, states ...mountState) []map[string]any {
	t.Helper()
	e, stdout, _ := testEnv(t)
	stateHome := t.TempDir()
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return baseGetenv(k)
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range states {
		if err := writeMountState(dir, st); err != nil {
			t.Fatal(err)
		}
	}
	if rc := e.run([]string{"mounts", "--json"}); rc != 0 {
		t.Fatalf("mounts --json rc = %d: %s", rc, stdout.String())
	}
	var out struct {
		Mounts []map[string]any `json:"mounts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode mounts --json: %v\n%s", err, stdout.String())
	}
	return out.Mounts
}

func TestMountsJSONCarriesTheRevocationVerdict(t *testing.T) {
	st := validFuseMountState(t, "/tmp/revoked")
	st.Status = mountStatusRevoked
	st.StatusReason = mountRevokedRoutesChanged
	st.StatusDetail = "the volume's route declaration changed under this mount"
	st.StatusChangedAtMs = 1700000000000

	rows := mountsJSONRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	// An agent reading --json must be able to branch on the class without
	// parsing prose, and must never see this row as live.
	for field, want := range map[string]any{
		"status":       mountStatusRevoked,
		"statusReason": mountRevokedRoutesChanged,
		"health":       mountStatusRevoked,
	} {
		if row[field] != want {
			t.Fatalf("--json %s = %v, want %v (row: %v)", field, row[field], want, row)
		}
	}
	if row["statusDetail"] == "" || row["statusDetail"] == nil {
		t.Fatalf("--json dropped the revocation detail: %v", row)
	}
	if row["statusChangedAtMs"] == nil {
		t.Fatalf("--json dropped the revocation timestamp: %v", row)
	}
}

func TestMountsJSONDeclaresSessionTerminalField(t *testing.T) {
	// sessionTerminal is the daemon's own machine-readable verdict. It is
	// omitempty, so a healthy row must not carry it, and the mountRow type must
	// declare it at all — it did not, which is why an agent could see a mount
	// the supervisor was about to revoke and read it as healthy.
	rows := mountsJSONRows(t, validFuseMountState(t, "/tmp/plain"))
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if _, present := rows[0]["sessionTerminal"]; present {
		t.Fatalf("a healthy row carried sessionTerminal: %v", rows[0])
	}
	if _, present := rows[0]["statusReason"]; present {
		t.Fatalf("a healthy row carried a revocation classification: %v", rows[0])
	}
	// And the row type must actually declare the field, on every platform:
	// the daemon has reported sessionTerminal for a long time and the JSON
	// view simply dropped it.
	encoded, err := json.Marshal(mountInventoryRow{
		MountPath: "/tmp/w", SessionTerminal: true,
		StatusReason: mountRevokedSessionTerminal, StatusDetail: "fenced",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"sessionTerminal":true`, `"statusReason":"` + mountRevokedSessionTerminal + `"`, `"statusDetail":"fenced"`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("mounts row JSON missing %s: %s", want, encoded)
		}
	}
}

func TestMountsJSONRevocationShapeIsIdenticalForFSKitRecords(t *testing.T) {
	// One vocabulary, one shape: a macOS-recorded revocation must decode the
	// same way a Linux-recorded one does.
	st := validFSKitMountState(t, "/tmp/fskit-revoked")
	st.Status = mountStatusRevoked
	st.StatusReason = mountRevokedDaemonUnreachable
	st.StatusDetail = "portablefsd stopped answering"
	st.StatusChangedAtMs = 1700000000000

	rows := mountsJSONRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0]["health"] != mountStatusRevoked || rows[0]["statusReason"] != mountRevokedDaemonUnreachable {
		t.Fatalf("fskit revocation row: %v", rows[0])
	}
}
