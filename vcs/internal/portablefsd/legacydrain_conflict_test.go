package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func TestLegacyCreateLikeReplayRejectsUnprovenExistingObjects(t *testing.T) {
	ctx, vol := legacyConflictTestVolume(t)

	dir, st := vol.Mkdir(ctx, "create-is-dir", 0o755)
	if st != fsproto.OK {
		t.Fatalf("seed directory: status %d", st)
	}
	file, st := vol.CreateExcl(ctx, "mkdir-is-file", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed file: status %d", st)
	}
	link, st := vol.Symlink(ctx, "actual-target", "wrong-target")
	if st != fsproto.OK {
		t.Fatalf("seed symlink: status %d", st)
	}
	unrelated, st := vol.CreateExcl(ctx, "unrelated-file", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed unrelated file: status %d", st)
	}
	unrelatedDir, st := vol.Mkdir(ctx, "unrelated-dir", 0o755)
	if st != fsproto.OK {
		t.Fatalf("seed unrelated directory: status %d", st)
	}
	_, st = vol.CreateExcl(ctx, "identityless-file", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed identityless file: status %d", st)
	}
	for name, ino := range map[string]uint64{
		"create-is-dir": dir.Ino, "mkdir-is-file": file.Ino, "wrong-target": link.Ino,
		"unrelated-file": unrelated.Ino, "unrelated-dir": unrelatedDir.Ino,
	} {
		if ino == 0 {
			t.Fatalf("seed %q has no stable authority inode", name)
		}
	}

	tests := []struct {
		name string
		rec  wal.Record
	}{
		{
			name: "create cannot adopt directory",
			rec:  wal.Record{Op: wal.OpCreate, Path: "create-is-dir", Mode: 0o644, Ino: dir.Ino},
		},
		{
			name: "mkdir cannot adopt file",
			rec: wal.Record{
				Op: wal.OpMkdir, Path: "mkdir-is-file", Mode: 0o755, Inos: []uint64{file.Ino},
			},
		},
		{
			name: "symlink target must match",
			rec: wal.Record{
				Op: wal.OpSymlink, Path: "wrong-target", Target: "wanted-target", Ino: link.Ino,
			},
		},
		{
			name: "same kind but unrelated inode",
			rec: wal.Record{
				Op: wal.OpCreate, Path: "unrelated-file", Mode: 0o644, Ino: unrelated.Ino + 1,
			},
		},
		{
			name: "same directory kind but unrelated inode",
			rec: wal.Record{
				Op: wal.OpMkdir, Path: "unrelated-dir", Mode: 0o755,
				Inos: []uint64{unrelatedDir.Ino + 1},
			},
		},
		{
			name: "existing object without recorded identity",
			rec: wal.Record{
				Op: wal.OpCreate, Path: "identityless-file", Mode: 0o644,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := applyLegacyRecord(ctx, vol, newLegacyDrainState(t), tt.rec)
			if !errors.Is(err, errLegacyAdoptionConflict) {
				t.Fatalf("error = %v, want legacy adoption conflict", err)
			}
			var conflict *legacyAdoptionConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("error type = %T, want *legacyAdoptionConflictError", err)
			}
			if conflict.Path != tt.rec.Path || conflict.Op != tt.rec.Op {
				t.Fatalf("conflict = %+v, want op=%d path=%q", conflict, tt.rec.Op, tt.rec.Path)
			}
		})
	}
}

func TestLegacyCreateLikeReplayAcceptsProvablyIdenticalObjects(t *testing.T) {
	ctx, vol := legacyConflictTestVolume(t)

	file, st := vol.CreateExcl(ctx, "same-file", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed file: status %d", st)
	}
	dir, st := vol.Mkdir(ctx, "same-dir", 0o755)
	if st != fsproto.OK {
		t.Fatalf("seed directory: status %d", st)
	}
	exactDir, st := vol.Mkdir(ctx, "same-exact-dir", 0o750)
	if st != fsproto.OK {
		t.Fatalf("seed exact directory: status %d", st)
	}
	link, st := vol.Symlink(ctx, "same-target", "same-link")
	if st != fsproto.OK {
		t.Fatalf("seed symlink: status %d", st)
	}
	for name, ino := range map[string]uint64{
		"same-file": file.Ino, "same-dir": dir.Ino, "same-exact-dir": exactDir.Ino, "same-link": link.Ino,
	} {
		if ino == 0 {
			t.Fatalf("seed %q has no stable authority inode", name)
		}
	}

	tests := []struct {
		name string
		rec  wal.Record
	}{
		{
			name: "file identity",
			rec:  wal.Record{Op: wal.OpCreate, Path: "same-file", Mode: 0o644, Ino: file.Ino},
		},
		{
			name: "mkdir-p leaf identity",
			rec: wal.Record{
				Op: wal.OpMkdir, Path: "same-dir", Mode: 0o755, Inos: []uint64{dir.Ino},
			},
		},
		{
			name: "exclusive mkdir leaf identity",
			rec: wal.Record{
				Op: wal.OpMkdir, Path: "same-exact-dir", Mode: 0o750, Excl: true, Ino: exactDir.Ino,
			},
		},
		{
			name: "symlink identity and target",
			rec: wal.Record{
				Op: wal.OpSymlink, Path: "same-link", Target: "same-target", Ino: link.Ino,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := applyLegacyRecord(ctx, vol, newLegacyDrainState(t), tt.rec); err != nil {
				t.Fatalf("apply: %v", err)
			}
		})
	}
}

func TestLegacyIdentitylessCreateLikeReplayCreatesAbsentNames(t *testing.T) {
	ctx, vol := legacyConflictTestVolume(t)

	records := []wal.Record{
		{Op: wal.OpCreate, Path: "fresh-file", Mode: 0o640},
		{Op: wal.OpMkdir, Path: "fresh-dir", Mode: 0o750},
		{Op: wal.OpSymlink, Path: "fresh-link", Target: "fresh-file"},
	}
	for _, rec := range records {
		if err := applyLegacyRecord(ctx, vol, newLegacyDrainState(t), rec); err != nil {
			t.Fatalf("%s %q: %v", opName(rec.Op), rec.Path, err)
		}
	}
	for path, kind := range map[string]string{
		"fresh-file": "file", "fresh-dir": "directory", "fresh-link": "symlink",
	} {
		attr, st := vol.Lookup(ctx, path)
		if st != fsproto.OK || attr.Kind != kind {
			t.Fatalf("lookup %q = (%+v, %d), want kind %q", path, attr, st, kind)
		}
	}
	if target, st := vol.Readlink(ctx, "fresh-link"); st != fsproto.OK || target != "fresh-file" {
		t.Fatalf("readlink = (%q, %d), want (%q, OK)", target, st, "fresh-file")
	}
}

func TestLegacyRecordedIdentityIsNotSilentlyReallocated(t *testing.T) {
	ctx, vol := legacyConflictTestVolume(t)

	records := []wal.Record{
		{Op: wal.OpCreate, Path: "stable-file", Mode: 0o640, Ino: 9001},
		{Op: wal.OpMkdir, Path: "stable-dir", Mode: 0o750, Inos: []uint64{9002}},
		{Op: wal.OpSymlink, Path: "stable-link", Target: "stable-file", Ino: 9003},
	}
	for _, rec := range records {
		err := applyLegacyRecord(ctx, vol, newLegacyDrainState(t), rec)
		if !errors.Is(err, errLegacyAdoptionConflict) {
			t.Fatalf("%s %q error = %v, want legacy adoption conflict", opName(rec.Op), rec.Path, err)
		}
		if _, st := vol.Lookup(ctx, rec.Path); st != fsproto.ENOENT {
			t.Fatalf("%s %q mutated namespace before conflict: status %d", opName(rec.Op), rec.Path, st)
		}
	}
}

func TestLegacyAdoptionConflictPreservesWALAndSidecar(t *testing.T) {
	ctx, vol := legacyConflictTestVolume(t)
	file, st := vol.CreateExcl(ctx, "wal-conflict", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed file: status %d", st)
	}
	if file.Ino == 0 {
		t.Fatal("seed file has no stable authority inode")
	}

	walPath := filepath.Join(t.TempDir(), "sess-conflict.wal")
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	rec := wal.Record{
		Op: wal.OpMkdir, Path: "wal-conflict", Mode: 0o755, Inos: []uint64{file.Ino},
	}
	seq, err := w.AppendBuffered(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.CommitThrough(seq); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	sidecarPath := walPath + ".drain.json"
	sidecar := []byte(`{"nextOffset":{"kept":17},"lastAppliedSeq":{"kept":9}}`)
	if err := os.WriteFile(sidecarPath, sidecar, 0o600); err != nil {
		t.Fatal(err)
	}

	err = (&attach{}).drainOneLegacyWAL(ctx, vol, walPath)
	if !errors.Is(err, errLegacyAdoptionConflict) {
		t.Fatalf("drain error = %v, want legacy adoption conflict", err)
	}

	w, err = wal.Open(walPath)
	if err != nil {
		t.Fatalf("conflicting WAL was removed: %v", err)
	}
	records, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Op != rec.Op || records[0].Path != rec.Path {
		t.Fatalf("surviving records = %+v, want original conflict record", records)
	}
	gotSidecar, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatalf("conflicting sidecar was removed: %v", err)
	}
	if !bytes.Equal(gotSidecar, sidecar) {
		t.Fatalf("sidecar changed on conflict: got %q, want %q", gotSidecar, sidecar)
	}
}

func legacyConflictTestVolume(t *testing.T) (context.Context, *clientcore.Volume) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr:     serveAuthority(t),
		Pool:     2,
		WALDir:   t.TempDir(),
		VolumeID: t.Name(),
		Branch:   "legacy-conflict",
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = vol.Close()
		cancel()
	})
	return ctx, vol
}

func newLegacyDrainState(t *testing.T) *legacyDrainState {
	t.Helper()
	return &legacyDrainState{
		path:           filepath.Join(t.TempDir(), "drain.json"),
		NextOffset:     map[string]int64{},
		LastAppliedSeq: map[string]uint64{},
	}
}
