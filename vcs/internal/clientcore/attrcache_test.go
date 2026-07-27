package clientcore

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func TestAttrCacheGenFencedEvictAndNegative(t *testing.T) {
	c := NewAttrCache()
	const g = 7

	c.PutAttr(g, 5, "p", fsproto.Attr{Kind: "file", Size: 10})
	if e, ok := c.Get(g, 5, "p"); !ok || !e.Exists || e.Attr.Size != 10 {
		t.Fatalf("expected a cached positive entry, got %+v ok=%v", e, ok)
	}
	if _, ok := c.Get(g+1, 5, "p"); ok {
		t.Fatal("an entry from another generation must not hit")
	}
	if _, ok := c.Get(g, 6, "p"); ok {
		t.Fatal("an entry whose version trails curVer must miss")
	}
	if _, ok := c.Get(g, 5, "p"); !ok {
		t.Fatal("entry at its own version must hit")
	}
	c.Evict("p")
	if _, ok := c.Get(g, 5, "p"); ok {
		t.Fatal("evicted entry must miss")
	}
	c.PutNegative(g, 3, "gone")
	if e, ok := c.Get(g, 3, "gone"); !ok || e.Exists {
		t.Fatalf("expected a cached negative, got %+v ok=%v", e, ok)
	}
	c.PutAttr(g, 1, "a", fsproto.Attr{Kind: "file"})
	c.Clear()
	if _, ok := c.Get(g, 1, "a"); ok {
		t.Fatal("clear must drop everything")
	}
}

func TestAttrCacheNegativeUsesParentVersionGate(t *testing.T) {
	c := NewAttrCache()
	const g = 11
	c.PutNegative(g, 3, "dir/.DS_Store")
	if e, ok := c.GetLookup(g, 0, 3, "dir/.DS_Store"); !ok || e.Exists {
		t.Fatalf("negative should hit at the parent version, got %+v ok=%v", e, ok)
	}
	if _, ok := c.GetLookup(g, 0, 4, "dir/.DS_Store"); ok {
		t.Fatal("negative must miss after parent directory version advances")
	}
	// A positive entry is gated by its own path version, not the parent directory version.
	c.PutAttr(g, 2, "dir/file", fsproto.Attr{Kind: "file"})
	if _, ok := c.GetLookup(g, 2, 99, "dir/file"); !ok {
		t.Fatal("positive entry should not be invalidated by an unrelated parent version")
	}
}
