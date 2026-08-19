package mountlog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/mountrecord"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func testRenewalEvent() mountenrollment.RenewalEvent {
	now := time.Unix(1_700_000_000, 123_000_000).UTC()
	return mountenrollment.RenewalEvent{
		Kind:       mountenrollment.RenewalRetrying,
		ObservedAt: now,
		Status: mountenrollment.RenewalStatus{
			AuthorizationDeadline: now.Add(10 * time.Minute),
			LastSuccess:           now.Add(-5 * time.Minute),
			NextAttempt:           now.Add(time.Second),
			Sequence:              2,
			ConsecutiveFailures:   1,
			LastError:             "temporary failure\nwithout record injection",
		},
	}
}

func TestWriteRenewalProducesOneStructuredBoundedRecord(t *testing.T) {
	var output bytes.Buffer
	writer, err := New(&output, "linux-fuse", "mount0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteRenewal(testRenewalEvent()); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("log records = %d, want 1: %q", len(lines), output.String())
	}
	var record renewalRecord
	if err := json.Unmarshal(lines[0], &record); err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != 1 || record.Kind != "renewal.retrying" || record.Component != "linux-fuse" ||
		record.MountIdentity != "mount0123456789abcdef" || record.Sequence != 2 || record.ConsecutiveFailures != 1 ||
		!strings.Contains(record.Error, "without record injection") {
		t.Fatalf("renewal record = %+v", record)
	}
}

func TestOpenAppendUsesThePrivatePathDerivedMountLog(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "mounts")
	if err := privatepath.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	writer, err := OpenAppend(dir, "/Volumes/Work", "macos-fskit", "att0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteRenewal(testRenewalEvent()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := mountrecord.LogPath(dir, "/Volumes/Work")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log mode = %04o, want 0600", info.Mode().Perm())
	}
	if body, err := os.ReadFile(path); err != nil || !bytes.Contains(body, []byte(`"kind":"renewal.retrying"`)) {
		t.Fatalf("log body = %q, err = %v", body, err)
	}
}
