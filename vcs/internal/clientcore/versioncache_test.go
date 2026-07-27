package clientcore

import "testing"

func TestVersionCacheApplyMonotonicAndGen(t *testing.T) {
	vc := NewVersionCache()
	const g = 42
	vc.RefreshAll(g)

	if !vc.FillOK(g, "p", 5) {
		t.Fatal("first fill must succeed")
	}
	if vc.Apply(g, "p", 5) {
		t.Fatal("an invalidation at an already-held version must not evict")
	}
	if !vc.Apply(g, "p", 6) {
		t.Fatal("an invalidation newer than held must evict")
	}
	if vc.FillOK(g, "p", 5) {
		t.Fatal("monotonic fill must reject installing a version older than held")
	}
	if !vc.FillOK(g, "p", 7) {
		t.Fatal("a newer fill must succeed")
	}
	if vc.Apply(99, "p", 1000) {
		t.Fatal("apply under a foreign generation must be a no-op")
	}
	if vc.FillOK(99, "p", 1000) {
		t.Fatal("fill under a foreign generation must be a no-op")
	}
	if !vc.SeenGen(g) || vc.SeenGen(99) {
		t.Fatal("generation tracking wrong before refresh")
	}
	vc.RefreshAll(99)
	if !vc.FillOK(99, "p", 1) {
		t.Fatal("after a generation change a low version installs")
	}
}
