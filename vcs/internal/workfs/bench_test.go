package workfs

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Authority hot-path microbenchmarks. Run: go test -bench . -benchmem -cpu 1,4,8 ./internal/workfs/
// The -cpu sweep on the Concurrent* benchmarks exposes fs.mu contention (throughput that does not
// scale with cores = the single tree lock is the ceiling).

func benchFS(b *testing.B) *FS {
	b.Helper()
	w, err := wal.Open(filepath.Join(b.TempDir(), "wal.log"))
	if err != nil {
		b.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		b.Fatal(err)
	}
	return fs
}

func names(n int) []string {
	s := make([]string, n)
	for i := range s {
		s[i] = fmt.Sprintf("f%d", i)
	}
	return s
}

func BenchmarkWrite4K(b *testing.B) {
	fs := benchFS(b)
	f, _ := fs.Create("f")
	_ = f.Close()
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := fs.WriteAt("f", int64(i&1023)*4096, data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppend4K(b *testing.B) {
	fs := benchFS(b)
	f, _ := fs.Create("f")
	_ = f.Close()
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := fs.AppendAtHandleExistingAs("f", 0, data, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRead4K(b *testing.B) {
	fs := benchFS(b)
	f, _ := fs.Create("f")
	_ = f.Close()
	_, _, _ = fs.WriteAt("f", 0, make([]byte, 1<<20), 0o644) // 1 MiB
	rf, err := fs.Open("f")
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rf.ReadAt(buf, int64(i&255)*4096)
	}
}

func BenchmarkLstat(b *testing.B) {
	fs := benchFS(b)
	_ = fs.MkdirAll("a/b/c", 0o755)
	f, _ := fs.Create("a/b/c/file")
	_ = f.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fs.Lstat("a/b/c/file"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreate(b *testing.B) {
	ns := names(b.N)
	fs := benchFS(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, err := fs.Create(ns[i])
		if err != nil {
			b.Fatal(err)
		}
		_ = f.Close()
	}
}

func BenchmarkConcurrentWrite4K(b *testing.B) {
	const nf = 256
	fs := benchFS(b)
	ns := names(nf)
	for _, n := range ns {
		f, _ := fs.Create(n)
		_ = f.Close()
	}
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _, _ = fs.WriteAt(ns[i&(nf-1)], 0, data, 0o644)
			i++
		}
	})
}

func BenchmarkConcurrentLstat(b *testing.B) {
	const nf = 256
	fs := benchFS(b)
	ns := names(nf)
	for _, n := range ns {
		f, _ := fs.Create(n)
		_ = f.Close()
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = fs.Lstat(ns[i&(nf-1)])
			i++
		}
	})
}

// Mixed 90% reads (Lstat) + 10% writes — the realistic read-heavy mix; exposes whether writers
// (exclusive fs.mu) starve readers.
func BenchmarkConcurrentMixed(b *testing.B) {
	const nf = 256
	fs := benchFS(b)
	ns := names(nf)
	for _, n := range ns {
		f, _ := fs.Create(n)
		_ = f.Close()
	}
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%10 == 0 {
				_, _, _ = fs.WriteAt(ns[i&(nf-1)], 0, data, 0o644)
			} else {
				_, _ = fs.Lstat(ns[i&(nf-1)])
			}
			i++
		}
	})
}
