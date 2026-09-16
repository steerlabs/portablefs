package writeback

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
)

func TestExtentMapSetAndSpans(t *testing.T) {
	tests := []struct {
		name string
		sets []span
		lo   int64
		hi   int64
		want []span
	}{
		{
			name: "disjoint sorted",
			sets: []span{{8, 10, []byte("ij")}, {0, 2, []byte("ab")}, {4, 6, []byte("ef")}},
			lo:   0,
			hi:   12,
			want: []span{{0, 2, []byte("ab")}, {4, 6, []byte("ef")}, {8, 10, []byte("ij")}},
		},
		{
			name: "overwrite middle splits old extent",
			sets: []span{{0, 10, []byte("abcdefghij")}, {3, 7, []byte("WXYZ")}},
			lo:   0,
			hi:   10,
			want: []span{{0, 3, []byte("abc")}, {3, 7, []byte("WXYZ")}, {7, 10, []byte("hij")}},
		},
		{
			name: "overwrite multiple extents and gaps",
			sets: []span{{0, 3, []byte("abc")}, {5, 8, []byte("fgh")}, {2, 7, []byte("23456")}},
			lo:   0,
			hi:   8,
			want: []span{{0, 2, []byte("ab")}, {2, 7, []byte("23456")}, {7, 8, []byte("h")}},
		},
		{
			name: "zero mask is retained and can be overwritten",
			sets: []span{{2, 9, nil}, {4, 6, []byte("xy")}},
			lo:   1,
			hi:   10,
			want: []span{{2, 4, nil}, {4, 6, []byte("xy")}, {6, 9, nil}},
		},
		{
			name: "query clips data",
			sets: []span{{2, 8, []byte("cdefgh")}},
			lo:   4,
			hi:   7,
			want: []span{{4, 7, []byte("efg")}},
		},
		{
			name: "same bounds replace",
			sets: []span{{1, 4, []byte("old")}, {1, 4, []byte("new")}},
			lo:   0,
			hi:   5,
			want: []span{{1, 4, []byte("new")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := newExtentPool(64)
			m := extentMap{pool: &pool}
			for _, s := range tt.sets {
				m.set(s.lo, s.hi, s.data)
				assertExtentInvariants(t, &m)
			}
			var got []span
			spans(m.root, tt.lo, tt.hi, &got)
			if !equalSpans(got, tt.want) {
				t.Fatalf("spans(%d, %d) = %s, want %s", tt.lo, tt.hi, formatSpans(got), formatSpans(tt.want))
			}

			m.clear()
			if m.root != nil {
				t.Fatal("clear left a root")
			}
			assertPoolAccounting(t, &pool, 0)
		})
	}
}

func TestExtentMapRandomizedAgainstByteModel(t *testing.T) {
	const (
		domain     = 128
		iterations = 2_000
	)
	for seed := int64(0); seed < 16; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			pool := newExtentPool(4 * domain)
			m := extentMap{pool: &pool}
			model := make([]byte, domain)
			covered := make([]bool, domain)

			for step := 0; step < iterations; step++ {
				lo := rng.Intn(domain)
				hi := lo + 1 + rng.Intn(domain-lo)
				var data []byte
				if rng.Intn(4) != 0 {
					data = make([]byte, hi-lo)
					rng.Read(data)
				}
				m.set(int64(lo), int64(hi), data)
				for i := lo; i < hi; i++ {
					covered[i] = true
					if data == nil {
						model[i] = 0
					} else {
						model[i] = data[i-lo]
					}
				}
				assertExtentInvariants(t, &m)

				qlo := rng.Intn(domain)
				qhi := qlo + 1 + rng.Intn(domain-qlo)
				assertSpansMatchModel(t, &m, int64(qlo), int64(qhi), model, covered)
			}
		})
	}
}

func FuzzExtentMapAgainstByteModel(f *testing.F) {
	f.Add([]byte{0, 8, 1, 'a', 4, 4, 0, 2, 10, 1, 'z'})
	f.Add([]byte{7, 17, 0, 1, 31, 1, 0xff})
	f.Fuzz(func(t *testing.T, operations []byte) {
		const domain = 64
		pool := newExtentPool(4 * domain)
		m := extentMap{pool: &pool}
		model := make([]byte, domain)
		covered := make([]bool, domain)
		for i := 0; i+3 < len(operations); i += 4 {
			lo := int(operations[i]) % domain
			width := 1 + int(operations[i+1])%(domain-lo)
			hi := lo + width
			zero := operations[i+2]&1 == 0
			var data []byte
			if !zero {
				data = make([]byte, width)
				for j := range data {
					data[j] = operations[i+3] + byte(j)
				}
			}
			m.set(int64(lo), int64(hi), data)
			for j := lo; j < hi; j++ {
				covered[j] = true
				if zero {
					model[j] = 0
				} else {
					model[j] = data[j-lo]
				}
			}
			assertExtentInvariants(t, &m)
		}
		for lo := 0; lo < domain; lo++ {
			for hi := lo + 1; hi <= domain; hi++ {
				assertSpansMatchModel(t, &m, int64(lo), int64(hi), model, covered)
			}
		}
	})
}

func assertSpansMatchModel(t *testing.T, m *extentMap, lo, hi int64, model []byte, covered []bool) {
	t.Helper()
	var got []span
	spans(m.root, lo, hi, &got)
	gotBytes := make([]byte, hi-lo)
	gotCovered := make([]bool, hi-lo)
	for _, s := range got {
		for pos := s.lo; pos < s.hi; pos++ {
			i := pos - lo
			if gotCovered[i] {
				t.Fatalf("overlapping returned spans at %d: %s", pos, formatSpans(got))
			}
			gotCovered[i] = true
			if s.data != nil {
				gotBytes[i] = s.data[pos-s.lo]
			}
		}
	}
	if !slices.Equal(gotBytes, model[lo:hi]) || !slices.Equal(gotCovered, covered[lo:hi]) {
		t.Fatalf("query [%d,%d) = bytes %v covered %v, want bytes %v covered %v; spans %s", lo, hi, gotBytes, gotCovered, model[lo:hi], covered[lo:hi], formatSpans(got))
	}
}

func assertExtentInvariants(t *testing.T, m *extentMap) {
	t.Helper()
	var previous *extent
	count := 0
	var walk func(*extent) int
	walk = func(n *extent) int {
		if n == nil {
			return 0
		}
		leftHeight := walk(n.left)
		if n.lo >= n.hi {
			t.Fatalf("invalid extent [%d,%d)", n.lo, n.hi)
		}
		if n.data != nil && int64(len(n.data)) != n.hi-n.lo {
			t.Fatalf("extent [%d,%d) has %d data bytes", n.lo, n.hi, len(n.data))
		}
		if previous != nil && previous.hi > n.lo {
			t.Fatalf("overlapping tree extents [%d,%d) and [%d,%d)", previous.lo, previous.hi, n.lo, n.hi)
		}
		previous = n
		count++
		rightHeight := walk(n.right)
		wantHeight := 1 + max(leftHeight, rightHeight)
		if n.height != wantHeight {
			t.Fatalf("extent [%d,%d) height = %d, want %d", n.lo, n.hi, n.height, wantHeight)
		}
		if d := leftHeight - rightHeight; d < -1 || d > 1 {
			t.Fatalf("extent [%d,%d) balance = %d", n.lo, n.hi, d)
		}
		return wantHeight
	}
	walk(m.root)
	assertPoolAccounting(t, m.pool, count)
}

func assertPoolAccounting(t *testing.T, pool *extentPool, used int) {
	t.Helper()
	seen := make(map[*extent]bool, len(pool.nodes))
	free := 0
	for n := pool.free; n != nil; n = n.left {
		if seen[n] {
			t.Fatal("cycle in extent free list")
		}
		seen[n] = true
		free++
	}
	if used+free != len(pool.nodes) {
		t.Fatalf("extent pool accounts for %d used + %d free, want %d", used, free, len(pool.nodes))
	}
}

func equalSpans(a, b []span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].lo != b[i].lo || a[i].hi != b[i].hi || !slices.Equal(a[i].data, b[i].data) {
			return false
		}
	}
	return true
}

func formatSpans(ss []span) string {
	return fmt.Sprintf("%v", ss)
}
