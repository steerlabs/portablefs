package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/secure"
)

const (
	encKeyA = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	encKeyB = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

// addr returns the content address ("sha256:<hex>") of data — the cache verifies
// keys against contents on read, so tests must use real digests.
func addr(data string) string {
	sum := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fileFor(dir, digest string) string {
	return filepath.Join(dir, strings.TrimPrefix(digest, "sha256:"))
}

// TestTieredCachePromotesAndPersists: a value spilled to disk survives RAM
// eviction (served from disk + promoted back to RAM) and survives a process
// restart (warm cache).
func TestTieredCachePromotesAndPersists(t *testing.T) {
	dir := t.TempDir()
	// Tiny RAM (so it evicts), larger disk.
	c, err := NewTieredCache(8, dir, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}

	a, b := addr("11111"), addr("22222") // distinct 5-byte values
	c.Add(a, []byte("11111"))
	c.Add(b, []byte("22222")) // RAM (8B) evicts "a" to fit; both on disk

	// "a" is gone from RAM but still on disk -> Get serves it (and promotes it).
	if v, ok := c.Get(a); !ok || string(v) != "11111" {
		t.Fatalf("disk-tier get a = %q,%v; want 11111,true", v, ok)
	}

	// A fresh cache over the same dir is warm (survives restart).
	c2, err := NewTieredCache(8, dir, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := c2.Get(a); !ok || string(v) != "11111" {
		t.Fatalf("warm-start get a = %q,%v; want 11111,true", v, ok)
	}
	if v, ok := c2.Get(b); !ok || string(v) != "22222" {
		t.Fatalf("warm-start get b = %q,%v; want 22222,true", v, ok)
	}
}

// TestDiskCacheEvictsByBytes: the disk tier evicts least-recently-used files once
// total bytes exceed the budget.
func TestDiskCacheEvictsByBytes(t *testing.T) {
	dir := t.TempDir()
	c, err := NewTieredCache(0, dir, 10, nil) // RAM disabled, 10-byte disk
	if err != nil {
		t.Fatal(err)
	}
	a, b, cc := addr("aaaaa"), addr("bbbbb"), addr("ccccc") // distinct 5-byte values
	c.Add(a, []byte("aaaaa"))                               // 5
	c.Add(b, []byte("bbbbb"))                               // 5 -> total 10
	c.Get(a)                                                // a most-recently-used
	c.Add(cc, []byte("ccccc"))                              // 5 -> total 15 > 10 -> evict LRU (b)

	if _, ok := c.Get(b); ok {
		t.Fatal("b should have been evicted from disk")
	}
	if _, ok := c.Get(a); !ok {
		t.Fatal("a should still be on disk")
	}
	// The evicted file is actually deleted.
	if _, err := os.Stat(fileFor(dir, b)); !os.IsNotExist(err) {
		t.Fatalf("evicted file b still present (err=%v)", err)
	}
}

// TestDiskCacheDropsCorruptFile: a disk file whose bytes no longer match its
// content address (bit-rot / truncation) is treated as a miss and removed, never
// served as valid content.
func TestDiskCacheDropsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	c, err := NewTieredCache(0, dir, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := addr("hello world")
	c.Add(a, []byte("hello world"))
	if _, ok := c.Get(a); !ok {
		t.Fatal("value should be present before corruption")
	}
	// Corrupt the on-disk file.
	if err := os.WriteFile(fileFor(dir, a), []byte("tampered!!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(a); ok {
		t.Fatal("corrupt disk file was served as valid (digest not verified)")
	}
	if _, err := os.Stat(fileFor(dir, a)); !os.IsNotExist(err) {
		t.Fatalf("corrupt file should have been dropped (err=%v)", err)
	}
}

// TestDiskCacheConcurrentSameKeyAdd: many concurrent Add of the SAME key (the
// parallel-prefetch-plus-on-demand-fetch race) must not corrupt the published file
// or leave any temp behind — each Add uses its own uniquely named temp.
func TestDiskCacheConcurrentSameKeyAdd(t *testing.T) {
	dir := t.TempDir()
	c, err := newDiskCache(dir, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	val := []byte("the one true content for this digest")
	a := addr(string(val))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Add(a, val)
		}()
	}
	wg.Wait()
	got, ok := c.Get(a)
	if !ok || !bytes.Equal(got, val) {
		t.Fatalf("concurrent same-key Add corrupted the file: ok=%v got=%q", ok, got)
	}
	// No temp files may remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file after concurrent Add: %s", e.Name())
		}
	}
}

// TestDiskCacheSweepsStaleTemp: a leftover *.tmp from a crash between write and
// rename is reclaimed on warm-start, not leaked forever against the budget.
func TestDiskCacheSweepsStaleTemp(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "deadbeef.123456.tmp")
	if err := os.WriteFile(stale, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newDiskCache(dir, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temp should have been swept on warm-start (err=%v)", err)
	}
}

// TestDiskCacheEncryptedAtRest: an encrypted disk cache round-trips, never writes
// plaintext, and treats a file sealed under a different key as a miss.
func TestDiskCacheEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	enc, err := secure.NewAtRestFromKey(encKeyA)
	if err != nil || enc == nil {
		t.Fatalf("cipher: %v", err)
	}
	c, err := NewTieredCache(0, dir, 1<<20, enc) // disk-only, encrypted
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("plaintext blob content that must not hit the disk")
	a := addr(string(plain))
	c.Add(a, plain)

	if v, ok := c.Get(a); !ok || !bytes.Equal(v, plain) {
		t.Fatalf("encrypted round-trip get = %q,%v", v, ok)
	}
	raw, err := os.ReadFile(fileFor(dir, a))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, plain) {
		t.Fatal("plaintext found in the cache file — disk cache is not encrypted at rest")
	}

	// A cache with the wrong key cannot read the file (treats it as a miss).
	wrong, _ := secure.NewAtRestFromKey(encKeyB)
	c2, err := NewTieredCache(0, dir, 1<<20, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c2.Get(a); ok {
		t.Fatal("a file sealed under a different key must not decrypt")
	}
}
