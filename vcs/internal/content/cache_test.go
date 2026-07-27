package content

import "testing"

// TestCacheEvictsByBytes: the cache evicts the least-recently-used entry once the
// total bytes exceed the budget (not after a fixed entry count).
func TestCacheEvictsByBytes(t *testing.T) {
	c := NewCache(10)
	c.Add("a", []byte("12345")) // 5
	c.Add("b", []byte("12345")) // 5 -> total 10
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should still be cached")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("b should still be cached")
	}
	c.Get("a")                  // a is now most-recently-used
	c.Add("d", []byte("12345")) // total 15 > 10 -> evict LRU (b)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted (least recently used)")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should survive (recently used)")
	}
	if _, ok := c.Get("d"); !ok {
		t.Fatal("d should be cached")
	}
}

// TestCacheSkipsOversizedEntry: an entry larger than the whole budget is not
// cached (it would evict everything and still not fit).
func TestCacheSkipsOversizedEntry(t *testing.T) {
	c := NewCache(4)
	c.Add("big", []byte("123456")) // 6 > 4
	if _, ok := c.Get("big"); ok {
		t.Fatal("oversized entry should not be cached")
	}
}

// TestCacheDisabledWhenZeroBudget: a non-positive budget disables caching.
func TestCacheDisabledWhenZeroBudget(t *testing.T) {
	c := NewCache(0)
	c.Add("a", []byte("x"))
	if _, ok := c.Get("a"); ok {
		t.Fatal("zero-budget cache should not store")
	}
}
