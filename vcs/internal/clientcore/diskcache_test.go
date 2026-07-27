package clientcore

import "testing"

func TestDiskBlockCachePersistsAndVersionGates(t *testing.T) {
	dir := t.TempDir()
	c, err := NewDiskBlockCache(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	c.Put("vol", 1, 10, 2, 7, []byte("block-v7"))
	if got, ok := c.Get("vol", 1, 10, 2, 7); !ok || string(got) != "block-v7" {
		t.Fatalf("get v7 = %q,%v", got, ok)
	}
	if _, ok := c.Get("vol", 1, 10, 2, 8); ok {
		t.Fatal("different content version must miss")
	}

	reopened, err := NewDiskBlockCache(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.Get("vol", 1, 10, 2, 7); !ok || string(got) != "block-v7" {
		t.Fatalf("restart get = %q,%v", got, ok)
	}
}

func TestDiskBlockCacheEvictsLRU(t *testing.T) {
	c, err := NewDiskBlockCache(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	c.Put("vol", 1, 1, 0, 1, []byte("aaaa"))
	c.Put("vol", 1, 2, 0, 1, []byte("bbbb"))
	if _, ok := c.Get("vol", 1, 1, 0, 1); !ok {
		t.Fatal("first block should be cached")
	}
	c.Put("vol", 1, 3, 0, 1, []byte("cccc"))
	if _, ok := c.Get("vol", 1, 2, 0, 1); ok {
		t.Fatal("least-recently-used block should be evicted")
	}
	if _, ok := c.Get("vol", 1, 1, 0, 1); !ok {
		t.Fatal("recently used block should remain")
	}
	if _, ok := c.Get("vol", 1, 3, 0, 1); !ok {
		t.Fatal("new block should remain")
	}
}

func TestDiskBlockCacheRangeComposition(t *testing.T) {
	c, err := NewDiskBlockCache(t.TempDir(), int64(DiskBlockSize*3))
	if err != nil {
		t.Fatal(err)
	}
	block0 := make([]byte, DiskBlockSize)
	block1 := make([]byte, DiskBlockSize)
	for i := range block0 {
		block0[i] = 'a'
		block1[i] = 'b'
	}
	c.Put("vol", 1, 9, 0, 3, block0)
	c.Put("vol", 1, 9, 1, 3, block1)
	got, ok := c.GetRange("vol", 1, 9, int64(DiskBlockSize-3), 8, 3)
	if !ok {
		t.Fatal("range spanning cached blocks missed")
	}
	if string(got) != "aaabbbbb" {
		t.Fatalf("range = %q", got)
	}
	if _, ok := c.GetRange("vol", 1, 9, int64(DiskBlockSize-3), 8, 4); ok {
		t.Fatal("different version must miss")
	}
}

func TestDiskBlockCachePutRangeSkipsUnsafePartial(t *testing.T) {
	c, err := NewDiskBlockCache(t.TempDir(), int64(DiskBlockSize*2))
	if err != nil {
		t.Fatal(err)
	}
	c.PutRange("vol", 1, 1, 128, 1, []byte("partial"), 7)
	if _, ok := c.GetRange("vol", 1, 1, 128, 7, 1); ok {
		t.Fatal("mid-block partial read must not be cached as a block")
	}
	c.PutRange("vol", 1, 1, 0, 1, []byte("short-eof"), 1024)
	if got, ok := c.GetRange("vol", 1, 1, 0, 1024, 1); !ok || string(got) != "short-eof" {
		t.Fatalf("EOF-short block = %q,%v", got, ok)
	}
}
