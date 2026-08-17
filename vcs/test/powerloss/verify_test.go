package powerloss

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// contractLog carries one mark per sample-ledger checkpoint, so a cut can be
// placed before, between and after them.
func contractLog(t *testing.T) *Log {
	t.Helper()
	image := buildSynthLog(t, 512, []synthEntry{
		{sector: 0, sectors: 1, payload: []byte("a")},
		{flags: FlagMark, mark: "ckpt-0"},
		{sector: 1, sectors: 1, payload: []byte("b")},
		{flags: FlagMark, mark: "ckpt-1"},
	})
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	return log
}

func TestExpectationsDemandPresenceOnlyForFsyncedWritesBeforeTheCut(t *testing.T) {
	log := contractLog(t)
	ledger := sampleLedger(t)
	tests := []struct {
		name     string
		endEntry int
		want     []Requirement
	}{
		{
			name:     "cut before every mark",
			endEntry: 0,
			want:     []Requirement{RequireAbsentOrPermitted, RequirePermitted},
		},
		{
			name:     "cut at the fsynced checkpoint's mark",
			endEntry: 1,
			want:     []Requirement{RequirePresent, RequirePermitted},
		},
		{
			name: "cut at the acknowledged checkpoint's mark still demands nothing of it",
			// This is the assertion the whole harness turns on. The authority
			// acknowledged checkpoint 1 before this cut, and the contract still
			// permits it to be gone: an ack means applied to the page cache,
			// not durable.
			endEntry: 3,
			want:     []Requirement{RequirePresent, RequirePermitted},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectations, err := Expectations(log, ledger, test.endEntry)
			if err != nil {
				t.Fatalf("Expectations: %v", err)
			}
			if len(expectations) != len(test.want) {
				t.Fatalf("got %d expectations, want %d", len(expectations), len(test.want))
			}
			for index, expectation := range expectations {
				if expectation.Requirement != test.want[index] {
					t.Errorf("checkpoint %d requirement = %s, want %s", index, expectation.Requirement, test.want[index])
				}
				if expectation.Why == "" {
					t.Errorf("checkpoint %d carries no stated reason", index)
				}
			}
		})
	}
}

// TestExpectationsAfterRestartDemandNoMoreThanTheDeviceInstrument pins the
// claim the process instrument is allowed to make. A SIGKILL leaves the page
// cache intact, so an un-fsynced write will usually still be readable - and
// the harness still must not require it, or it would encode today's
// implementation as tomorrow's contract.
func TestExpectationsAfterRestartDemandNoMoreThanTheDeviceInstrument(t *testing.T) {
	ledger := &Ledger{Volume: "powerloss-volume", Instrument: InstrumentProcess, Label: "unit"}
	ledger.Add("data/file-0", GenerateContent(0, 64), "", Fsynced)
	ledger.Add("data/file-1", GenerateContent(1, 64), "", Acknowledged)
	expectations, err := ExpectationsAfterRestart(ledger)
	if err != nil {
		t.Fatalf("ExpectationsAfterRestart: %v", err)
	}
	want := []Requirement{RequirePresent, RequirePermitted}
	for index, expectation := range expectations {
		if expectation.Requirement != want[index] {
			t.Errorf("checkpoint %d requirement = %s, want %s", index, expectation.Requirement, want[index])
		}
	}
	if _, err := ExpectationsAfterRestart(sampleLedger(t)); err == nil {
		t.Fatal("ExpectationsAfterRestart accepted a device ledger, whose cuts it cannot reason about")
	}
}

// writeRecovered lays out a recovered volume tree.
func writeRecovered(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "powerloss-volume")
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestVerifyAcceptsAConformingRecovery(t *testing.T) {
	log := contractLog(t)
	ledger := sampleLedger(t)
	expectations, err := Expectations(log, ledger, 3)
	if err != nil {
		t.Fatalf("Expectations: %v", err)
	}
	// The fsynced file is complete; the acknowledged one is half applied,
	// which a power cut is entitled to leave.
	partial := GenerateContent(1, 64)
	partial = append(append([]byte(nil), partial[:32]...), make([]byte, 32)...)
	root := writeRecovered(t, map[string][]byte{
		"data/file-0": GenerateContent(0, 64),
		"data/file-1": partial,
	})
	report := Verify(root, expectations, 3)
	if err := report.Err(); err != nil {
		t.Fatalf("Verify rejected a conforming recovery: %v", err)
	}
	if report.Durable != 1 {
		t.Errorf("Durable = %d, want 1", report.Durable)
	}
	if got := report.Findings[1].Observed; !strings.Contains(got, "partial") {
		t.Errorf("acknowledged finding = %q, want it to report a partial application", got)
	}
}

func TestVerifyAcceptsAnAcknowledgedWriteVanishingEntirely(t *testing.T) {
	log := contractLog(t)
	ledger := sampleLedger(t)
	expectations, err := Expectations(log, ledger, 3)
	if err != nil {
		t.Fatalf("Expectations: %v", err)
	}
	root := writeRecovered(t, map[string][]byte{"data/file-0": GenerateContent(0, 64)})
	report := Verify(root, expectations, 3)
	if err := report.Err(); err != nil {
		t.Fatalf("Verify demanded an un-fsynced write survive a power cut: %v", err)
	}
	if report.Findings[1].Observed != "absent" {
		t.Errorf("acknowledged finding = %q, want absent", report.Findings[1].Observed)
	}
}

func TestVerifyReportsDurabilityDefects(t *testing.T) {
	log := contractLog(t)
	ledger := sampleLedger(t)
	expectations, err := Expectations(log, ledger, 3)
	if err != nil {
		t.Fatalf("Expectations: %v", err)
	}
	corrupted := GenerateContent(0, 64)
	corrupted[7] ^= 0x80
	stale := GenerateContent(1, 64)
	stale[3] = ^stale[3]
	if stale[3] == 0 {
		stale[3] = 0x5a
	}
	tests := []struct {
		name    string
		files   map[string][]byte
		wantSub string
	}{
		{
			name:    "an fsynced file did not survive",
			files:   map[string][]byte{},
			wantSub: "the file must exist after recovery",
		},
		{
			name:    "an fsynced file came back changed",
			files:   map[string][]byte{"data/file-0": corrupted},
			wantSub: "the content must be exactly",
		},
		{
			name:    "an fsynced file came back truncated",
			files:   map[string][]byte{"data/file-0": GenerateContent(0, 64)[:16]},
			wantSub: "the content must be exactly",
		},
		{
			name: "recovery exposed stale bytes in an un-fsynced file",
			files: map[string][]byte{
				"data/file-0": GenerateContent(0, 64),
				"data/file-1": stale,
			},
			wantSub: "stale data from a freed extent",
		},
		{
			name: "recovery left more of an un-fsynced file than was written",
			files: map[string][]byte{
				"data/file-0": GenerateContent(0, 64),
				"data/file-1": append(GenerateContent(1, 64), 0x11),
			},
			wantSub: "more bytes than the workload ever wrote",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := writeRecovered(t, test.files)
			report := Verify(root, expectations, 3)
			err := report.Err()
			if err == nil {
				t.Fatal("Verify passed a recovery that broke the contract")
			}
			if !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("Verify error = %v, want it to name %q", err, test.wantSub)
			}
		})
	}
}

// TestVerifyRefusesToSkipTheStaleDataCheck guards the one branch that could
// quietly reduce coverage: a ledger whose content is not reproducible cannot
// be checked for stale data, and the harness must say so rather than pass.
func TestVerifyRefusesToSkipTheStaleDataCheck(t *testing.T) {
	log := contractLog(t)
	ledger := sampleLedger(t)
	ledger.Checkpoints[1].SHA256 = Digest([]byte("content this harness did not generate"))
	ledger.Checkpoints[1].Size = int64(len("content this harness did not generate"))
	expectations, err := Expectations(log, ledger, 3)
	if err != nil {
		t.Fatalf("Expectations: %v", err)
	}
	root := writeRecovered(t, map[string][]byte{
		"data/file-0": GenerateContent(0, 64),
		"data/file-1": []byte("content"),
	})
	report := Verify(root, expectations, 3)
	err = report.Err()
	if err == nil || !strings.Contains(err.Error(), "not reproducible") {
		t.Fatalf("Verify error = %v, want a refusal to run without the stale-data check", err)
	}
}
