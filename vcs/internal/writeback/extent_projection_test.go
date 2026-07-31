package writeback

import (
	"context"
	"errors"
	"testing"
)

// saturatedOverlay returns a fixture whose "d/f" overlay sits exactly at the
// extent bound: n contiguous one-byte extents (each write lands at EOF, so no
// hole extent is inserted, and separate WAL frames keep them separate extents).
// The bound is tightened onto the seeded set only after seeding, so every
// assertion below is about ONE admission decision made at a genuinely
// saturated overlay. The uplink is gated shut, so folding can never relieve it.
func saturatedOverlay(t *testing.T, n int) *saturationFixture {
	t.Helper()
	oldExtents := maxFileExtents
	t.Cleanup(func() { maxFileExtents = oldExtents })
	maxFileExtents = 4 * n // room to seed

	f := newSaturationFixture(t, 1<<30) // the WAL budget is not the constraint
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	for i := 0; i < n; i++ {
		if _, handled, err := f.e.WriteAt(ctx, "d/f", int64(i), []byte("x")); err != nil || !handled {
			t.Fatalf("seed write %d: handled=%v err=%v", i, handled, err)
		}
	}
	if got := overlayExtents(t, f.e, "d/f"); got != n {
		t.Fatalf("seeded overlay holds %d extents, want %d", got, n)
	}
	maxFileExtents = n
	return f
}

func overlayExtents(t *testing.T, e *Engine, path string) int {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	fv := e.files[path]
	if fv == nil {
		return 0
	}
	return len(fv.extents)
}

// TestProjectedExtentCountsMatchTheSplice is the projection's contract: for
// every shape, the projected cardinality equals what the real splice produces.
// The projection is what admission charges, so any gap between the two is
// either a false ENOSPC (projection too high) or an overlay that grows past its
// bound (too low).
func TestProjectedExtentCountsMatchTheSplice(t *testing.T) {
	ext := func(pairs ...uint64) []extent {
		var out []extent
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, extent{start: pairs[i], end: pairs[i+1]})
		}
		return out
	}
	rng := func(pairs ...uint64) []extentRange {
		var out []extentRange
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, extentRange{start: pairs[i], end: pairs[i+1]})
		}
		return out
	}

	writes := []struct {
		name     string
		existing []extent
		ranges   []extentRange
		want     int
	}{
		{"empty overlay, one range", nil, rng(0, 10), 1},
		{"disjoint range costs one slot", ext(0, 10), rng(20, 30), 2},
		{"two disjoint records cost two slots", ext(0, 10), rng(20, 30, 40, 50), 3},
		{"exact overwrite replaces in place", ext(0, 10), rng(0, 10), 1},
		{"overwrite covering three extents merges them", ext(0, 10, 10, 20, 20, 30), rng(0, 30), 1},
		{"overwrite covering a superset merges them", ext(10, 20, 30, 40), rng(0, 100), 1},
		{"partial overlap on the left keeps one fragment", ext(0, 10), rng(5, 20), 2},
		{"partial overlap on the right keeps one fragment", ext(10, 20), rng(0, 15), 2},
		{"range strictly inside splits into two fragments", ext(0, 100), rng(40, 50), 3},
		{"hole plus record past EOF costs two", ext(0, 10), rng(10, 20, 20, 30), 3},
		{"empty range is a no-op", ext(0, 10), rng(5, 5), 1},
		{"later record overwrites an earlier one", nil, rng(0, 10, 0, 10), 1},
	}
	for _, tc := range writes {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectedWriteExtents(tc.existing, tc.ranges); got != tc.want {
				t.Fatalf("projectedWriteExtents = %d, want %d", got, tc.want)
			}
			// The splice itself is the oracle.
			fv := &fileView{extents: append([]extent(nil), tc.existing...)}
			for _, r := range tc.ranges {
				fv.insertExtent(extent{start: r.start, end: r.end})
			}
			if len(fv.extents) != tc.want {
				t.Fatalf("insertExtent produced %d extents, projection promised %d", len(fv.extents), tc.want)
			}
		})
	}

	truncates := []struct {
		name             string
		existing         []extent
		oldSize, newSize uint64
		want             int
	}{
		{"shrink drops and clips", ext(0, 10, 10, 20, 20, 30), 30, 15, 2},
		{"shrink to zero clears the set", ext(0, 10, 10, 20), 20, 0, 0},
		{"shrink never needs a slot", ext(0, 1, 1, 2, 2, 3), 3, 2, 2},
		{"same size changes nothing", ext(0, 10), 10, 10, 1},
		{"extend adds one hole extent", ext(0, 10), 10, 100, 2},
		{"extend over a stale extent past EOF merges it", ext(0, 10, 50, 60), 10, 100, 2},
	}
	for _, tc := range truncates {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectedTruncateExtents(tc.existing, tc.oldSize, tc.newSize); got != tc.want {
				t.Fatalf("projectedTruncateExtents = %d, want %d", got, tc.want)
			}
			fv := &fileView{extents: append([]extent(nil), tc.existing...)}
			fv.truncateExtents(tc.oldSize, tc.newSize, 1)
			if len(fv.extents) != tc.want {
				t.Fatalf("truncateExtents produced %d extents, projection promised %d", len(fv.extents), tc.want)
			}
		})
	}
}

// TestSaturatedOverlayAdmitsMutationsThatDoNotGrowIt is the false-ENOSPC
// defect. The preflight charged every write records+1 extents and every
// truncate one, regardless of what the splice would actually do. At the bound
// that refuses operations which REDUCE the bounded resource: an overwrite that
// replaces existing extents, and any shrinking truncate. ENOSPC for freeing
// space is not backpressure, it is a bug — the only correct answer is the
// projected post-splice cardinality.
func TestSaturatedOverlayAdmitsMutationsThatDoNotGrowIt(t *testing.T) {
	ctx := context.Background()

	t.Run("in-place overwrite of an existing extent", func(t *testing.T) {
		const n = 8
		f := saturatedOverlay(t, n)
		// Exactly covers the extent at offset 3: the splice replaces it, so the
		// overlay cardinality is unchanged.
		if _, handled, err := f.e.WriteAt(ctx, "d/f", 3, []byte("y")); err != nil || !handled {
			t.Fatalf("in-place overwrite at the bound: handled=%v err=%v", handled, err)
		}
		if got := overlayExtents(t, f.e, "d/f"); got != n {
			t.Fatalf("in-place overwrite left %d extents, want %d", got, n)
		}
	})

	t.Run("overwrite merging several extents", func(t *testing.T) {
		const n = 8
		f := saturatedOverlay(t, n)
		// Covers the first four seeded extents outright: four extents become
		// one, so the overlay SHRINKS.
		if _, handled, err := f.e.WriteAt(ctx, "d/f", 0, make([]byte, 4)); err != nil || !handled {
			t.Fatalf("merging overwrite at the bound: handled=%v err=%v", handled, err)
		}
		if got := overlayExtents(t, f.e, "d/f"); got >= n {
			t.Fatalf("merging overwrite left %d extents, want fewer than %d", got, n)
		}
	})

	t.Run("disjoint write is still refused", func(t *testing.T) {
		const n = 8
		f := saturatedOverlay(t, n)
		_, handled, err := f.e.WriteAt(ctx, "d/f", int64(n)+8, []byte("z"))
		if !errors.Is(err, ErrNoSpace) {
			t.Fatalf("disjoint write at the bound surfaced %v, want %v", err, ErrNoSpace)
		}
		if !handled {
			t.Fatal("the refusal changed lanes; a definite ENOSPC must not hand off")
		}
	})

	t.Run("shrinking truncate", func(t *testing.T) {
		const n = 8
		f := saturatedOverlay(t, n)
		if _, handled, err := f.e.Truncate(ctx, "d/f", 4); err != nil || !handled {
			t.Fatalf("shrinking truncate at the bound: handled=%v err=%v", handled, err)
		}
		if got := overlayExtents(t, f.e, "d/f"); got > n {
			t.Fatalf("shrinking truncate left %d extents, want at most %d", got, n)
		}
	})

	t.Run("truncate to zero clears the overlay and re-admits writes", func(t *testing.T) {
		const n = 8
		f := saturatedOverlay(t, n)
		if _, handled, err := f.e.Truncate(ctx, "d/f", 0); err != nil || !handled {
			t.Fatalf("truncate to zero at the bound: handled=%v err=%v", handled, err)
		}
		if got := overlayExtents(t, f.e, "d/f"); got != 0 {
			t.Fatalf("truncate to zero left %d extents, want 0", got)
		}
		if _, handled, err := f.e.WriteAt(ctx, "d/f", 0, []byte("fresh")); err != nil || !handled {
			t.Fatalf("write after truncate to zero: handled=%v err=%v", handled, err)
		}
	})

	t.Run("growing truncate is still refused", func(t *testing.T) {
		const n = 8
		f := saturatedOverlay(t, n)
		_, handled, err := f.e.Truncate(ctx, "d/f", 1<<20)
		if !errors.Is(err, ErrNoSpace) {
			t.Fatalf("growing truncate at the bound surfaced %v, want %v", err, ErrNoSpace)
		}
		if !handled {
			t.Fatal("the refusal changed lanes; a definite ENOSPC must not hand off")
		}
	})
}
