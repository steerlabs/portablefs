package powerloss

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleLedger(t *testing.T) *Ledger {
	t.Helper()
	ledger := &Ledger{Volume: "powerloss-volume", Instrument: InstrumentDevice, Label: "unit"}
	ledger.Add("data/file-0", GenerateContent(0, 64), "ckpt-0", Fsynced)
	ledger.Add("data/file-1", GenerateContent(1, 64), "ckpt-1", Acknowledged)
	return ledger
}

func TestLedgerRoundTrip(t *testing.T) {
	ledger := sampleLedger(t)
	pathname := filepath.Join(t.TempDir(), "ledger.json")
	if err := ledger.Save(pathname); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadLedger(pathname)
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if loaded.Volume != ledger.Volume || len(loaded.Checkpoints) != len(ledger.Checkpoints) {
		t.Fatalf("loaded = %+v, want %+v", loaded, ledger)
	}
	for index, checkpoint := range loaded.Checkpoints {
		if checkpoint != ledger.Checkpoints[index] {
			t.Errorf("checkpoint %d = %+v, want %+v", index, checkpoint, ledger.Checkpoints[index])
		}
	}
	if got := loaded.Marks(); len(got) != 2 || got[0] != "ckpt-0" {
		t.Fatalf("Marks = %v", got)
	}
	if _, err := os.Stat(pathname + ".pending"); !os.IsNotExist(err) {
		t.Fatal("Save left its pending file behind")
	}
}

func TestLedgerValidateRejectsUntrustworthyRecords(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Ledger)
		wantSub string
	}{
		{
			name:    "no checkpoints",
			mutate:  func(l *Ledger) { l.Checkpoints = nil },
			wantSub: "records no checkpoints",
		},
		{
			name:    "no volume",
			mutate:  func(l *Ledger) { l.Volume = "" },
			wantSub: "no volume name",
		},
		{
			name:    "volume is a path",
			mutate:  func(l *Ledger) { l.Volume = "cell/volume" },
			wantSub: "not a single directory name",
		},
		{
			name:    "escaping checkpoint path",
			mutate:  func(l *Ledger) { l.Checkpoints[0].Path = "../outside" },
			wantSub: "escapes the volume",
		},
		{
			name:    "uncleaned checkpoint path",
			mutate:  func(l *Ledger) { l.Checkpoints[0].Path = "data//file-0" },
			wantSub: "not in clean form",
		},
		{
			name:    "absolute checkpoint path",
			mutate:  func(l *Ledger) { l.Checkpoints[0].Path = "/etc/passwd" },
			wantSub: "is absolute",
		},
		{
			name:    "duplicate mark",
			mutate:  func(l *Ledger) { l.Checkpoints[1].Mark = l.Checkpoints[0].Mark },
			wantSub: "share mark",
		},
		{
			name:    "rewritten checkpoint file",
			mutate:  func(l *Ledger) { l.Checkpoints[1].Path = l.Checkpoints[0].Path },
			wantSub: "must be write-once",
		},
		{
			name:    "fsynced checkpoint with no mark",
			mutate:  func(l *Ledger) { l.Checkpoints[0].Mark = "" },
			wantSub: "no mark",
		},
		{
			name:    "shell-unsafe mark",
			mutate:  func(l *Ledger) { l.Checkpoints[0].Mark = "ckpt 0; rm -rf /" },
			wantSub: "not a safe mark name",
		},
		{
			name:    "unknown durability",
			mutate:  func(l *Ledger) { l.Checkpoints[0].Durability = Durability("probably") },
			wantSub: "unknown durability",
		},
		{
			name:    "malformed digest",
			mutate:  func(l *Ledger) { l.Checkpoints[0].SHA256 = "abc" },
			wantSub: "malformed digest",
		},
		{
			name:    "renumbered checkpoint",
			mutate:  func(l *Ledger) { l.Checkpoints[1].Index = 7 },
			wantSub: "declares index",
		},
		{
			name:    "no instrument",
			mutate:  func(l *Ledger) { l.Instrument = "" },
			wantSub: "names no known instrument",
		},
		{
			name:    "process ledger carrying device marks",
			mutate:  func(l *Ledger) { l.Instrument = InstrumentProcess },
			wantSub: "has no device log to resolve it against",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := sampleLedger(t)
			test.mutate(ledger)
			err := ledger.Validate()
			if err == nil {
				t.Fatal("Validate accepted a ledger the verifier could misread")
			}
			if !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("Validate error = %v, want it to name %q", err, test.wantSub)
			}
			// Save must fail on exactly the same rule; a ledger that is
			// invalid in memory must never reach the verifier on disk.
			if err := ledger.Save(filepath.Join(t.TempDir(), "ledger.json")); err == nil {
				t.Fatal("Save wrote a ledger Validate rejects")
			}
		})
	}
}

func TestLoadLedgerRejectsUnknownFields(t *testing.T) {
	pathname := filepath.Join(t.TempDir(), "ledger.json")
	raw := `{"volume":"v","instrument":"device","label":"l","checkpoints":[],"durable":true}`
	if err := os.WriteFile(pathname, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLedger(pathname); err == nil {
		t.Fatal("LoadLedger accepted a ledger with a field it does not understand")
	}
}

func TestGenerateContentIsDeterministicAndZeroFree(t *testing.T) {
	for index := range 8 {
		content := GenerateContent(index, 1024)
		if len(content) != 1024 {
			t.Fatalf("GenerateContent(%d) length = %d", index, len(content))
		}
		if Digest(content) != Digest(GenerateContent(index, 1024)) {
			t.Fatalf("GenerateContent(%d) is not deterministic", index)
		}
		for offset, value := range content {
			if value == 0 {
				t.Fatalf("GenerateContent(%d) has a zero byte at %d; a lost byte would be indistinguishable from a written one", index, offset)
			}
		}
		if index > 0 && Digest(content) == Digest(GenerateContent(0, 1024)) {
			t.Fatalf("GenerateContent(%d) matches checkpoint 0", index)
		}
	}
}
