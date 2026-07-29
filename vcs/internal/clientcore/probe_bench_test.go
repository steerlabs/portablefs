package clientcore

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// BenchmarkProbeMissSteadyState replicates the pfsbench W2 probe shape: a
// 4-component missing path inside an existing directory the engine holds a
// delegation over, name formatting included.
func BenchmarkProbeMissSteadyState(b *testing.B) {
	fs := newManagedTestFS(b, testBlobs{}, filepath.Join(b.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ctx0, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	srv := fsproto.NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx0, ln) }()

	v, err := Dial(context.Background(), Options{Addr: ln.Addr().String(), Pool: 4, Owner: "probe-bench", WALDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	defer v.Close()
	ctx := context.Background()
	for _, d := range []string{"w2", "w2/src", "w2/probe"} {
		if _, st := v.Mkdir(ctx, d, 0o755); st != fsproto.OK {
			b.Fatal(st)
		}
	}
	const dirs = 100
	// Replicate the storm history the pfsbench probe phase runs after:
	// 5,000 delegated create+writes, drained.
	payload := make([]byte, 8<<10)
	for d := 0; d < dirs; d++ {
		if _, st := v.Mkdir(ctx, fmt.Sprintf("w2/src/pkg%03d", d), 0o755); st != fsproto.OK {
			b.Fatal(st)
		}
	}
	for i := 0; i < 5000; i++ {
		p := fmt.Sprintf("w2/src/pkg%03d/f%04d.js", i%dirs, i)
		if _, st := v.Create(ctx, p, 0o644); st != fsproto.OK {
			b.Fatal(st)
		}
		n := NewNodeState(InoOf(p), false)
		if _, st := v.Write(ctx, p, n, 0, payload[:1024+(i%15360)]); st != fsproto.OK {
			b.Fatal(st)
		}
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		b.Fatal(err)
	}
	for d := 0; d < dirs; d++ {
		if _, st := v.Mkdir(ctx, fmt.Sprintf("w2/probe/pkg%03d", d), 0o755); st != fsproto.OK {
			b.Fatal(st)
		}
	}
	// Fill round.
	for i := 0; i < 2000; i++ {
		path := fmt.Sprintf("w2/probe/pkg%03d/nope%04d.json", i%dirs, i)
		if _, st := v.Lookup(ctx, path); st != fsproto.ENOENT {
			b.Fatal(st)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("w2/probe/pkg%03d/nope%04d.json", i%dirs, i%2000)
		if _, st := v.Lookup(ctx, path); st != fsproto.ENOENT {
			b.Fatal(st)
		}
	}
}
