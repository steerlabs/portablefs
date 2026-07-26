package histstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newFSStore(t *testing.T) (*FSStore, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFSStore(FSConfig{Domain: "fs-a", RootDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, dir
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestFSPutGetHeadDelete(t *testing.T) {
	store, dir := newFSStore(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("durable!"), 512)
	key := "t/tenant/pft2/sha256/aa/" + strings.Repeat("aa", 32) + "/i1"

	if err := store.Put(ctx, key, int64(len(data)), digestOf(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	// No temp residue next to the published object.
	entries, err := os.ReadDir(filepath.Join(dir, filepath.Dir(filepath.FromSlash(key))))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q survived publish", e.Name())
		}
	}

	got, err := ReadVerified(ctx, store, key, int64(len(data)), digestOf(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("read bytes differ")
	}
	size, err := store.Head(ctx, key)
	if err != nil || size != int64(len(data)) {
		t.Fatalf("head = %d, %v", size, err)
	}

	// Idempotent re-put of identical content succeeds.
	if err := store.Put(ctx, key, int64(len(data)), digestOf(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Head(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete head: %v", err)
	}
	// Idempotent delete.
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestFSPutRefusesLies(t *testing.T) {
	store, _ := newFSStore(t)
	ctx := context.Background()
	data := []byte("content")
	key := "t/x/pft2/sha256/bb/" + strings.Repeat("bb", 32) + "/i1"

	// Wrong declared size (short body).
	if err := store.Put(ctx, key, int64(len(data))+5, digestOf(data), bytes.NewReader(data)); err == nil {
		t.Fatal("short body accepted")
	}
	// Oversized body.
	if err := store.Put(ctx, key, int64(len(data))-1, digestOf(data), bytes.NewReader(data)); err == nil {
		t.Fatal("oversized body accepted")
	}
	// Wrong digest.
	if err := store.Put(ctx, key, int64(len(data)), digestOf([]byte("other")), bytes.NewReader(data)); err == nil {
		t.Fatal("digest lie accepted")
	}
	// Nothing became visible at the exact key.
	if _, err := store.Head(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed put left state: %v", err)
	}
}

func TestFSRejectsPathAttacks(t *testing.T) {
	store, dir := newFSStore(t)
	ctx := context.Background()
	outside := filepath.Join(filepath.Dir(dir), "escape-target")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"../escape-target",
		"a/../../escape-target",
		"/etc/passwd",
		"a/./b",
		"a//b",
		"a/\x00/b",
	} {
		if _, _, err := store.open(key); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("key %q: want ErrInvalidKey, got %v", key, err)
		}
		if err := store.Put(ctx, key, 1, digestOf([]byte("x")), bytes.NewReader([]byte("x"))); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("put %q: want ErrInvalidKey, got %v", key, err)
		}
		if err := store.Delete(ctx, key); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("delete %q: want ErrInvalidKey, got %v", key, err)
		}
	}
}

func TestFSRefusesSymlinkEscape(t *testing.T) {
	store, dir := newFSStore(t)
	ctx := context.Background()

	// A symlink INSIDE the root pointing outside: valid key shape, so only
	// openat confinement can catch it.
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "leak"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(ctx, "link/leak"); err == nil {
		t.Fatal("symlink escape read succeeded")
	}
	if err := store.Put(ctx, "link/newfile", 1, digestOf([]byte("x")), bytes.NewReader([]byte("x"))); err == nil {
		if _, statErr := os.Stat(filepath.Join(outsideDir, "newfile")); statErr == nil {
			t.Fatal("symlink escape write landed outside the root")
		}
		t.Fatal("symlink escape put succeeded")
	}

	// A symlink AT the exact key (to a file inside the root) is refused:
	// exact keys must be regular files.
	if err := os.WriteFile(filepath.Join(dir, "real"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(ctx, "alias"); err == nil {
		t.Fatal("symlink at exact key served bytes")
	}
}

func TestFSReadVerifiedCatchesTamper(t *testing.T) {
	store, dir := newFSStore(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte{7}, 9000)
	key := "t/x/pft2/sha256/cc/" + strings.Repeat("cc", 32) + "/i1"
	if err := store.Put(ctx, key, int64(len(data)), digestOf(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.FromSlash(key))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[100] ^= 1
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerified(ctx, store, key, int64(len(data)), digestOf(data)); err == nil {
		t.Fatal("tampered bytes verified")
	}
	if err := VerifyStream(ctx, store, key, int64(len(data)), digestOf(data)); err == nil {
		t.Fatal("tampered bytes stream-verified")
	}
	// Size lies are caught before hashing completes.
	if err := VerifyStream(ctx, store, key, int64(len(data))-1, digestOf(data)); err == nil {
		t.Fatal("size lie verified")
	}
}

func TestFSPutHealsSameSizeCorruption(t *testing.T) {
	store, dir := newFSStore(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("healthy!"), 1024)
	key := "t/x/pft2/sha256/ee/" + strings.Repeat("ee", 32) + "/i1"
	if err := store.Put(ctx, key, int64(len(data)), digestOf(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Repeat([]byte("corrupt!"), 1024)
	if len(corrupt) != len(data) {
		t.Fatal("test fixture sizes differ")
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(key)), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, key, int64(len(data)), digestOf(data), bytes.NewReader(data)); err != nil {
		t.Fatalf("same-size repair put: %v", err)
	}
	if err := VerifyStream(ctx, store, key, int64(len(data)), digestOf(data)); err != nil {
		t.Fatalf("repaired object did not verify: %v", err)
	}
}

func TestFSPutHonoursContextCancel(t *testing.T) {
	store, dir := newFSStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	data := bytes.Repeat([]byte{1}, 1<<20)
	key := "t/x/pft2/sha256/dd/" + strings.Repeat("dd", 32) + "/i1"
	reader := &cancelAfterReader{data: data, cancel: cancel, after: 128 << 10}
	err := store.Put(ctx, key, int64(len(data)), digestOf(data), reader)
	if err == nil {
		t.Fatal("cancelled put succeeded")
	}
	if _, headErr := store.Head(context.Background(), key); !errors.Is(headErr, ErrNotFound) {
		t.Fatalf("cancelled put left state: %v", headErr)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(key)+".tmp-*")); err != nil || len(matches) != 0 {
		t.Fatalf("cancelled put left temporary uploads: %v (%v)", matches, err)
	}
}

func TestFSSweepTempsRemovesOnlyStaleWorkerTemps(t *testing.T) {
	store, dir := newFSStore(t)
	stale := filepath.Join(dir, "t", "x", "object.tmp-0123456789abcdef")
	fresh := filepath.Join(dir, "t", "x", "fresh.tmp-fedcba9876543210")
	nontemp := filepath.Join(dir, "t", "x", "object.tmp-not-a-worker-temp")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{stale, fresh, nontemp} {
		if err := os.WriteFile(name, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := store.SweepTemps(context.Background(), time.Hour)
	if err != nil || removed != 1 {
		t.Fatalf("sweep removed %d: %v", removed, err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale temp remains: %v", err)
	}
	for _, name := range []string{fresh, nontemp} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("sweep removed protected file %s: %v", name, err)
		}
	}
}

type cancelAfterReader struct {
	data   []byte
	offset int
	after  int
	cancel context.CancelFunc
}

func (r *cancelAfterReader) Read(p []byte) (int, error) {
	if r.offset >= r.after && r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
