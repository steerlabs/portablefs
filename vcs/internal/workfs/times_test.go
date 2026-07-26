package workfs

import (
	"os"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
)

type fileTimes interface {
	ChangeTime() time.Time
	AccessTime() time.Time
}

func statTimes(t *testing.T, fs *FS, name string) (mtime, ctime, atime time.Time) {
	t.Helper()
	fi, err := fs.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	ti, ok := fi.Sys().(fileTimes)
	if !ok {
		t.Fatalf("stat %s: FileInfo does not expose ctime/atime", name)
	}
	return fi.ModTime(), ti.ChangeTime(), ti.AccessTime()
}

func waitAfterMs(t *testing.T, ts time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().UnixMilli() <= ts.UnixMilli() {
		if time.Now().After(deadline) {
			t.Fatalf("time did not advance past %v", ts)
		}
		time.Sleep(time.Millisecond)
	}
}

func requireAdvancedMs(t *testing.T, label string, got, prev time.Time) {
	t.Helper()
	if got.UnixMilli() <= prev.UnixMilli() {
		t.Fatalf("%s = %d, want > %d", label, got.UnixMilli(), prev.UnixMilli())
	}
}

func requireSameMs(t *testing.T, label string, got, want time.Time) {
	t.Helper()
	if got.UnixMilli() != want.UnixMilli() {
		t.Fatalf("%s = %d, want %d", label, got.UnixMilli(), want.UnixMilli())
	}
}

func TestCtimeAdvancesOnMetadataAndWriteNotRead(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	_, c0, _ := statTimes(t, fs, "f")
	waitAfterMs(t, c0)
	if err := fs.Chmod("f", 0o600); err != nil {
		t.Fatal(err)
	}
	_, c1, _ := statTimes(t, fs, "f")
	requireAdvancedMs(t, "ctime after chmod", c1, c0)

	waitAfterMs(t, c1)
	if err := fs.Chown("f", 1000, 2000); err != nil {
		t.Fatal(err)
	}
	_, c2, _ := statTimes(t, fs, "f")
	requireAdvancedMs(t, "ctime after chown", c2, c1)

	waitAfterMs(t, c2)
	wf, err := fs.OpenFile("f", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wf.Write([]byte("Z")); err != nil {
		t.Fatal(err)
	}
	_ = wf.Close()
	_, c3, _ := statTimes(t, fs, "f")
	requireAdvancedMs(t, "ctime after write", c3, c2)

	waitAfterMs(t, c3)
	if got := readFile(t, fs, "f"); got != "Zbc" {
		t.Fatalf("read = %q, want Zbc", got)
	}
	_, c4, _ := statTimes(t, fs, "f")
	requireSameMs(t, "ctime after pure read", c4, c3)
}

func TestAtimeRelatime(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	_, c0, a0 := statTimes(t, fs, "f")
	waitAfterMs(t, a0)
	if got := readFile(t, fs, "f"); got != "abc" {
		t.Fatalf("read = %q, want abc", got)
	}
	_, c1, a1 := statTimes(t, fs, "f")
	requireSameMs(t, "ctime after atime read", c1, c0)
	requireAdvancedMs(t, "atime after stale read", a1, a0)

	waitAfterMs(t, a1)
	if got := readFile(t, fs, "f"); got != "abc" {
		t.Fatalf("read = %q, want abc", got)
	}
	_, _, a2 := statTimes(t, fs, "f")
	requireSameMs(t, "atime after fresh relatime read", a2, a1)
}

func TestParentDirTimesBumpOnCreateRemoveRename(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	if err := fs.MkdirAll("d", 0o755); err != nil {
		t.Fatal(err)
	}
	pm0, pc0, _ := statTimes(t, fs, "d")
	waitAfterMs(t, pc0)
	f, err := fs.Create("d/a")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	pm1, pc1, _ := statTimes(t, fs, "d")
	requireAdvancedMs(t, "parent mtime after create", pm1, pm0)
	requireAdvancedMs(t, "parent ctime after create", pc1, pc0)

	waitAfterMs(t, pc1)
	if err := fs.Remove("d/a"); err != nil {
		t.Fatal(err)
	}
	pm2, pc2, _ := statTimes(t, fs, "d")
	requireAdvancedMs(t, "parent mtime after remove", pm2, pm1)
	requireAdvancedMs(t, "parent ctime after remove", pc2, pc1)

	if err := fs.MkdirAll("src", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("dst", 0o755); err != nil {
		t.Fatal(err)
	}
	rf, err := fs.Create("src/a")
	if err != nil {
		t.Fatal(err)
	}
	_ = rf.Close()
	srcM0, srcC0, _ := statTimes(t, fs, "src")
	dstM0, dstC0, _ := statTimes(t, fs, "dst")
	waitAfterMs(t, srcC0)
	waitAfterMs(t, dstC0)
	if err := fs.Rename("src/a", "dst/a"); err != nil {
		t.Fatal(err)
	}
	srcM1, srcC1, _ := statTimes(t, fs, "src")
	dstM1, dstC1, _ := statTimes(t, fs, "dst")
	requireAdvancedMs(t, "old parent mtime after rename", srcM1, srcM0)
	requireAdvancedMs(t, "old parent ctime after rename", srcC1, srcC0)
	requireAdvancedMs(t, "new parent mtime after rename", dstM1, dstM0)
	requireAdvancedMs(t, "new parent ctime after rename", dstC1, dstC0)
}

func TestCtimeAtimeSnapshotReconstructAndLegacyDefault(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("f")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	waitAfterMs(t, time.Now())
	if err := fs.Chmod("f", 0o600); err != nil {
		t.Fatal(err)
	}

	_, ctime, atime := statTimes(t, fs, "f")
	snap := fs.Snapshot()
	var entry SnapshotEntry
	var found bool
	for _, e := range snap.Entries {
		if e.Path == "f" {
			entry, found = e, true
			break
		}
	}
	if !found {
		t.Fatal("f missing from snapshot")
	}
	requireSameMs(t, "snapshot ctime", time.UnixMilli(entry.CtimeMs), ctime)
	requireSameMs(t, "snapshot atime", time.UnixMilli(entry.AtimeMs), atime)

	fs2, _ := newFS(t, backendEntriesFromSnapshot(snap), &fakeBlobs{data: map[string][]byte{}})
	_, c2, a2 := statTimes(t, fs2, "f")
	if c2.UnixMilli() != entry.CtimeMs || a2.UnixMilli() != entry.AtimeMs {
		t.Fatalf("reconstructed ctime/atime = %d/%d, want %d/%d", c2.UnixMilli(), a2.UnixMilli(), entry.CtimeMs, entry.AtimeMs)
	}

	const legacyMtimeMs = int64(1_700_000_000_123)
	fs3, _ := newFS(t, []backend.Entry{{Path: "legacy", Kind: "file", Mode: 0o644, MtimeMs: legacyMtimeMs}}, &fakeBlobs{data: map[string][]byte{}})
	m3, c3, a3 := statTimes(t, fs3, "legacy")
	if m3.UnixMilli() != legacyMtimeMs || c3.UnixMilli() != legacyMtimeMs || a3.UnixMilli() != legacyMtimeMs {
		t.Fatalf("legacy times = m:%d c:%d a:%d, want all %d", m3.UnixMilli(), c3.UnixMilli(), a3.UnixMilli(), legacyMtimeMs)
	}
}
