package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/test/powerloss"
)

// newChannel builds the driver's half of the mark protocol with a canned
// answer, so a test can assert the request sequence the harness would have
// seen without a device mapper anywhere in sight.
func newChannel(t *testing.T, reply string, rounds int) (*markChannel, *bytes.Buffer) {
	t.Helper()
	requests := &bytes.Buffer{}
	acks := strings.Repeat(reply+"\n", rounds)
	return &markChannel{requests: requests, acks: bufio.NewReader(strings.NewReader(acks)), enabled: true}, requests
}

func driveInto(t *testing.T, mount string, channel *markChannel, instrument powerloss.Instrument, checkpoints int) (string, error) {
	t.Helper()
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	opts := options{
		mount:       mount,
		volume:      "powerloss-volume",
		ledger:      ledgerPath,
		label:       "unit",
		prefix:      "checkpoints",
		checkpoints: checkpoints,
		size:        4096,
		subdirs:     2,
	}
	return ledgerPath, drive(opts, instrument, channel, io.Discard)
}

// TestDriveMarksAfterEveryDurableWrite is the ordering the whole instrument
// depends on: the mark for a checkpoint must be requested after that
// checkpoint's fsync returned and before the next write starts. If the driver
// ever marked first, every replay would cut before the data it claims.
func TestDriveMarksAfterEveryDurableWrite(t *testing.T) {
	mount := t.TempDir()
	channel, requests := newChannel(t, "ok", 4)
	ledgerPath, err := driveInto(t, mount, channel, powerloss.InstrumentDevice, 3)
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	got := strings.Fields(strings.ReplaceAll(strings.TrimSpace(requests.String()), "\n", " "))
	want := []string{"mark", "ckpt-0000", "mark", "ckpt-0001", "mark", "ckpt-0002"}
	if len(got) != len(want) {
		t.Fatalf("mark requests = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("mark requests = %v, want %v", got, want)
		}
	}
	ledger, err := powerloss.LoadLedger(ledgerPath)
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if len(ledger.Checkpoints) != 6 {
		t.Fatalf("ledger has %d checkpoints, want one durable and one acknowledged per round", len(ledger.Checkpoints))
	}
	for index, checkpoint := range ledger.Checkpoints {
		wantDurability := powerloss.Fsynced
		if index%2 == 1 {
			wantDurability = powerloss.Acknowledged
		}
		if checkpoint.Durability != wantDurability {
			t.Errorf("checkpoint %d durability = %s, want %s", index, checkpoint.Durability, wantDurability)
		}
		// Only the fsynced half may carry a mark: an acknowledged write has no
		// durability boundary to mark.
		if (checkpoint.Mark != "") != (wantDurability == powerloss.Fsynced) {
			t.Errorf("checkpoint %d mark = %q with durability %s", index, checkpoint.Mark, checkpoint.Durability)
		}
		content, err := os.ReadFile(filepath.Join(mount, checkpoint.Path))
		if err != nil {
			t.Fatalf("checkpoint %d file: %v", index, err)
		}
		if powerloss.Digest(content) != checkpoint.SHA256 {
			t.Errorf("checkpoint %d records a digest the file it wrote does not have", index)
		}
	}
}

// TestDriveStopsWhenAMarkCannotBeTaken is the fail-closed rule on the mark
// channel. A run that kept writing after a mark was refused would record
// checkpoints no cut can ever assert.
func TestDriveStopsWhenAMarkCannotBeTaken(t *testing.T) {
	channel, _ := newChannel(t, "error: dmsetup is gone", 4)
	if _, err := driveInto(t, t.TempDir(), channel, powerloss.InstrumentDevice, 3); err == nil {
		t.Fatal("drive continued after the harness refused a mark")
	} else if !strings.Contains(err.Error(), "could not take mark") {
		t.Fatalf("drive error = %v, want it to name the refused mark", err)
	}
}

func TestDriveInProcessInstrumentTakesNoMarks(t *testing.T) {
	channel := &markChannel{requests: &bytes.Buffer{}, acks: bufio.NewReader(strings.NewReader("")), enabled: false}
	ledgerPath, err := driveInto(t, t.TempDir(), channel, powerloss.InstrumentProcess, 2)
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	ledger, err := powerloss.LoadLedger(ledgerPath)
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if ledger.Instrument != powerloss.InstrumentProcess {
		t.Fatalf("ledger instrument = %s", ledger.Instrument)
	}
}

func TestRunRejectsIncompleteInvocations(t *testing.T) {
	tests := [][]string{
		{},
		{"--mount", "/tmp"},
		{"--mount", "/tmp", "--volume", "v"},
		{"--mount", "/tmp", "--volume", "v", "--ledger", "/tmp/l", "--instrument", "guesswork"},
		{"--mount", "/tmp", "--volume", "v", "--ledger", "/tmp/l", "--checkpoints", "0"},
		{"--mount", "/tmp", "--volume", "v", "--ledger", "/tmp/l", "--prefix", "../escape"},
		{"--mount", "/tmp", "--volume", "v", "--ledger", "/tmp/l", "stray"},
	}
	for _, arguments := range tests {
		if err := run(arguments, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Errorf("run(%v) accepted an invocation it cannot honour", arguments)
		}
	}
}
