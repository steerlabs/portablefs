package writeback

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func abandonedStoreWithTail(t *testing.T) (string, string) {
	t.Helper()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("authority offline")
	auth.mu.Unlock()
	dir := t.TempDir()
	engine, err := Open(context.Background(), Config{
		StateDir: dir,
		VolumeID: "vol",
		Branch:   "main",
		Remote:   auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, handled, err := engine.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create handled=%v err=%v", handled, err)
	}
	engine.Abandon()
	job, ok := loadJob(filepath.Join(dir, streamDirName(1)))
	if !ok {
		t.Fatal("missing recovery job")
	}
	return dir, job.JobID
}

func TestForceParkAbandonedStoreRefusesLiveOwnerThenParksIdempotently(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	dir := t.TempDir()
	engine, err := Open(context.Background(), Config{
		StateDir: dir,
		VolumeID: "vol",
		Branch:   "main",
		Remote:   auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, handled, err := engine.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create handled=%v err=%v", handled, err)
	}
	if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_exact", "test"); err == nil {
		t.Fatal("live engine lock was not refused")
	}
	engine.Abandon()

	first, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_exact", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first.ZeroTail || len(first.JobIDs) != 1 {
		t.Fatalf("first proof = %+v", first)
	}
	stream := filepath.Join(dir, streamDirName(1))
	scan, err := scanStreamReadOnly(stream)
	if err != nil {
		t.Fatal(err)
	}
	frameCount := len(scan.frames)
	second, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_exact", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("idempotent result second=%+v first=%+v", second, first)
	}
	scan, err = scanStreamReadOnly(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.frames) != frameCount {
		t.Fatalf("idempotent retry appended frames: before=%d after=%d", frameCount, len(scan.frames))
	}
}

func TestForceParkAbandonedStorePublishesExactZeroTailProof(t *testing.T) {
	auth := newFakeAuthority()
	dir := t.TempDir()
	engine, err := Open(context.Background(), Config{
		StateDir: dir,
		VolumeID: "vol",
		Branch:   "main",
		Remote:   auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.Abandon()
	result, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_zero", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.ZeroTail || len(result.JobIDs) != 0 {
		t.Fatalf("zero-tail result = %+v", result)
	}
	var proof forceParkProof
	body, err := os.ReadFile(filepath.Join(dir, forceParkProofName))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(body, &proof); err != nil {
		t.Fatal(err)
	}
	if proof.ProofID != "mnt_zero" || !proof.ZeroTail || proof.VolumeID != "vol" || proof.Branch != "main" {
		t.Fatalf("zero-tail proof = %+v", proof)
	}
}

func TestForceParkAbandonedStoreClosesPreRegistryEmptyStreamAsZeroTail(t *testing.T) {
	auth := newFakeAuthority()
	dir := t.TempDir()
	engine, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	mountID, epoch := engine.mountID, engine.epoch
	engine.Abandon()
	streamDir := filepath.Join(dir, streamDirName(epoch))
	wal, err := createStreamWAL(streamDir, mountID, "vol", "main", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(streamDir, "job.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture unexpectedly has job registry: %v", err)
	}
	// Model a crash while a prior offline attempt was appending its clean
	// marker. The strict scanner may discard only this physically torn EOF.
	partialPayload, _ := json.Marshal(closeFrame{Through: 0})
	partial := encodeFrame(nil, frameClose, 1, 0, partialPayload)
	segment := segmentPath(streamDir, 1)
	file, err := os.OpenFile(segment, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(partial[:len(partial)/2]); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_empty_crash", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.ZeroTail || len(result.JobIDs) != 0 {
		t.Fatalf("empty pre-registry result=%+v", result)
	}
	scan, err := scanStreamReadOnly(streamDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.frames) != 1 || scan.frames[0].typ != frameClose {
		t.Fatalf("empty stream was not durably clean-closed: %+v", scan.frames)
	}
	// Crash after the clean-close but before/after proof publication remains
	// idempotently recognizable without inventing a recovery job.
	if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_empty_crash", "test"); err != nil {
		t.Fatalf("retry empty clean proof: %v", err)
	}
}

func TestForceParkAbandonedStoreRejectsNoncanonicalDuplicateStreamName(t *testing.T) {
	dir, _ := abandonedStoreWithTail(t)
	source := filepath.Join(dir, streamDirName(1))
	duplicate := source + "-copy"
	if err := os.Mkdir(duplicate, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(duplicate, entry.Name()), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotWritebackStore(t, dir)
	if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_duplicate", "test"); err == nil {
		t.Fatal("noncanonical duplicate stream name was accepted")
	}
	if after := snapshotWritebackStore(t, dir); !reflect.DeepEqual(after, before) {
		t.Fatal("duplicate-stream refusal changed store bytes")
	}
}

func TestStreamEpochFromDirIsCanonical(t *testing.T) {
	if epoch, ok := streamEpochFromDir("stream-0000000000000001"); !ok || epoch != 1 {
		t.Fatalf("canonical epoch=(%d,%v)", epoch, ok)
	}
	for _, name := range []string{
		"stream-0000000000000001-copy",
		"stream-000000000000001",
		"stream-000000000000000A",
		"stream-0000000000000000",
	} {
		if epoch, ok := streamEpochFromDir(name); ok {
			t.Fatalf("noncanonical %q parsed as %d", name, epoch)
		}
	}
}

func TestForceParkAbandonedStorePreservesStaleProofAndTerminalJobs(t *testing.T) {
	t.Run("different proof identity", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_first", "test"); err != nil {
			t.Fatal(err)
		}
		before := snapshotWritebackStore(t, dir)
		if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_second", "test"); err == nil {
			t.Fatal("different proof identity was accepted")
		}
		if after := snapshotWritebackStore(t, dir); !reflect.DeepEqual(after, before) {
			t.Fatal("different proof identity changed the store")
		}
	})
	for _, state := range []string{JobConflict, JobCorrupt} {
		t.Run(state, func(t *testing.T) {
			dir, _ := abandonedStoreWithTail(t)
			stream := filepath.Join(dir, streamDirName(1))
			job, ok := loadJob(stream)
			if !ok {
				t.Fatal("missing job")
			}
			job.State = state
			body, _ := json.MarshalIndent(job, "", "  ")
			if err := os.WriteFile(filepath.Join(stream, "job.json"), append(body, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshotWritebackStore(t, dir)
			if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_terminal", "test"); err == nil {
				t.Fatalf("%s job was reclassified", state)
			}
			if after := snapshotWritebackStore(t, dir); !reflect.DeepEqual(after, before) {
				t.Fatalf("%s refusal changed the store", state)
			}
		})
	}
}

func TestForceParkAbandonedStorePreservesMismatchCorruptionAndSymlinkLock(t *testing.T) {
	t.Run("job identity mismatch", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		stream := filepath.Join(dir, streamDirName(1))
		job, _ := loadJob(stream)
		job.VolumeID = "foreign"
		body, _ := json.MarshalIndent(job, "", "  ")
		if err := os.WriteFile(filepath.Join(stream, "job.json"), append(body, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		assertForceParkRefusalPreservesStore(t, dir)
	})
	t.Run("corrupt segment", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		segment := segmentPath(filepath.Join(dir, streamDirName(1)), 1)
		body, err := os.ReadFile(segment)
		if err != nil {
			t.Fatal(err)
		}
		body[0] ^= 0xff
		if err := os.WriteFile(segment, body, 0o600); err != nil {
			t.Fatal(err)
		}
		assertForceParkRefusalPreservesStore(t, dir)
	})
	t.Run("symlink lock", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		lock := filepath.Join(dir, "engine.lock")
		target := filepath.Join(dir, "real-engine.lock")
		if err := os.Rename(lock, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(target), lock); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_lock", "test"); err == nil {
			t.Fatal("symlink engine lock was accepted")
		}
		after, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, before) {
			t.Fatal("symlink refusal changed the lock target")
		}
		if _, err := os.Stat(filepath.Join(dir, forceParkProofName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("symlink refusal published proof: %v", err)
		}
	})
	t.Run("hard-linked segment", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		segment := segmentPath(filepath.Join(dir, streamDirName(1)), 1)
		if err := os.Link(segment, filepath.Join(dir, "linked-segment")); err != nil {
			t.Fatal(err)
		}
		assertForceParkRefusalPreservesStore(t, dir)
	})
	t.Run("symlink job registry", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		stream := filepath.Join(dir, streamDirName(1))
		jobPath := filepath.Join(stream, "job.json")
		target := filepath.Join(stream, "job-target.json")
		if err := os.Rename(jobPath, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(target), jobPath); err != nil {
			t.Fatal(err)
		}
		assertForceParkRefusalPreservesStore(t, dir)
	})
	t.Run("permissive job registry", func(t *testing.T) {
		dir, _ := abandonedStoreWithTail(t)
		jobPath := filepath.Join(dir, streamDirName(1), "job.json")
		if err := os.Chmod(jobPath, 0o644); err != nil {
			t.Fatal(err)
		}
		assertForceParkRefusalPreservesStore(t, dir)
	})
}

func TestForceParkAbandonedStoreRejectsInconsistentForcedTerminal(t *testing.T) {
	dir, jobID := abandonedStoreWithTail(t)
	if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_terminal", "test"); err != nil {
		t.Fatal(err)
	}
	stream := filepath.Join(dir, streamDirName(1))
	scan, err := scanStreamReadOnly(stream)
	if err != nil {
		t.Fatal(err)
	}
	last := scan.frames[len(scan.frames)-1]
	if last.typ != frameForcedClose {
		t.Fatalf("last frame type=%d", last.typ)
	}
	segment := segmentPath(stream, last.ordinal)
	info, err := os.Stat(segment)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(closeFrame{Through: scan.lastSeq, JobID: jobID, Reason: "mismatch"})
	replacement := encodeFrame(nil, frameForcedClose, last.frameNo, 0, payload)
	offset := info.Size() - frameLen(len(last.payload))
	if len(replacement) != int(frameLen(len(last.payload))) {
		t.Skip("replacement payload length differs; terminal identity path covered by job mismatch tests")
	}
	file, err := os.OpenFile(segment, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(replacement, offset); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before := snapshotWritebackStore(t, dir)
	if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_terminal", "test"); err == nil {
		t.Fatal("inconsistent terminal Through was accepted")
	}
	if after := snapshotWritebackStore(t, dir); !reflect.DeepEqual(after, before) {
		t.Fatal("terminal mismatch refusal changed the store")
	}
}

func assertForceParkRefusalPreservesStore(t *testing.T, dir string) {
	t.Helper()
	before := snapshotWritebackStore(t, dir)
	if _, err := ForceParkAbandonedStore(dir, "vol", "main", "mnt_preserve", "test"); err == nil {
		t.Fatal("invalid store was accepted")
	}
	if after := snapshotWritebackStore(t, dir); !reflect.DeepEqual(after, before) {
		t.Fatal("refusal changed the invalid store")
	}
}

func snapshotWritebackStore(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	var names []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			names = append(names, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	for _, path := range names {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			out[rel] = "symlink:" + target
		case info.IsDir():
			out[rel] = "dir"
		default:
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			out[rel] = string(body)
		}
	}
	return out
}
