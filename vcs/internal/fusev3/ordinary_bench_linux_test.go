//go:build linux

package fusev3

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// Review-only microbenchmark: ordinary (non-workspace) cached LOOKUP/GETATTR and
// one slow callback, each followed by the go-fuse tracked-reply lifecycle.
func TestOrdinaryMountBenchmarks(t *testing.T) {
	if os.Getenv("PFS_ORDINARY_BENCH") != "1" {
		t.Skip("explicit baseline comparison benchmark")
	}
	if runtime.GOMAXPROCS(0) != 8 {
		t.Fatal("comparison requires GOMAXPROCS=8")
	}
	f := newStockFixture(t)
	f.mount.subscription.config.clock = &subscriptionTestClock{now: f.mount.subscription.config.clock.Now()}
	entry := f.lookup(t, 1, "cached")
	f.lookup(t, 1, "cached")
	node := entry.NodeId
	file := f.lookup(t, 1, "file")
	opened := openDelegatedWriter(t, f, file.NodeId)
	writeDelegated(t, f, file.NodeId, opened.Fh, 0, []byte("seed"))
	reply := func(unique uint64, opcode uint32) {
		if f.raw.ReplyWriteTracked(unique) {
			f.raw.PrepareReplyPayload(unique, node, opcode, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK)
		}
	}
	var unique atomic.Uint64
	unique.Store(1 << 40)
	ops := map[string]func(){
		"getattr-cached": func() {
			u := unique.Add(2)
			var out fuse.AttrOut
			if st := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}}, &out); st != fuse.OK {
				panic(st)
			}
			reply(u, 3)
		},
		"lookup-cached": func() {
			u := unique.Add(2)
			var out fuse.EntryOut
			if st := f.raw.Lookup(nil, &fuse.InHeader{Unique: u, NodeId: 1}, "cached", &out); st != fuse.OK {
				panic(st)
			}
			reply(u, 1)
			f.raw.Forget(node, 1)
		},
		"write-delegated": func() {
			u := unique.Add(2)
			if _, st := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: u, NodeId: file.NodeId}, Fh: opened.Fh, Offset: 0, Size: 4, Flags: uint32(syscall.O_RDWR)}, []byte("abcd")); st != fuse.OK {
				panic(st)
			}
			reply(u, 16)
			if u%32 == 0 {
				u := unique.Add(2)
				if st := f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: file.NodeId}, Fh: opened.Fh}); st != fuse.OK {
					panic(st)
				}
				reply(u, 20)
			}
		},
		"read-delegated": func() {
			u := unique.Add(2)
			buf := make([]byte, 4)
			if _, st := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u, NodeId: file.NodeId}, Fh: opened.Fh, Size: 4}, buf); st != fuse.OK {
				panic(st)
			}
			reply(u, 15)
		},
		"getxattr-slow": func() {
			u := unique.Add(2)
			f.raw.GetXAttr(nil, &fuse.InHeader{Unique: u, NodeId: node}, "user.x", make([]byte, 64))
			reply(u, 22)
		},
	}
	graft := newGraftFixture(t, mustRoutes(t, "node_modules/\n"), false)
	parent := graft.mkdir(t, 1, "node_modules")
	local := &fuse.CreateOut{}
	if st := graft.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: nextTestRequestUnique(), NodeId: parent.NodeId}, Flags: uint32(syscall.O_RDWR), Mode: 0o644}, "local", local); st != fuse.OK {
		t.Fatal(st)
	}
	ops["write-local"] = func() {
		u := unique.Add(2)
		if _, st := graft.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: u, NodeId: local.NodeId}, Fh: local.Fh, Size: 4}, []byte("abcd")); st != fuse.OK {
			panic(st)
		}
	}
	ops["read-local"] = func() {
		u := unique.Add(2)
		buf := make([]byte, 4)
		if _, st := graft.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u, NodeId: local.NodeId}, Fh: local.Fh, Size: 4}, buf); st != fuse.OK {
			panic(st)
		}
	}
	ops["getattr-cached"]()
	ops["lookup-cached"]()
	names := []string{"getattr-cached", "lookup-cached", "write-delegated", "read-delegated", "getxattr-slow", "write-local", "read-local"}
	if os.Getenv("PFS_ORDINARY_BENCH_CACHED_ONLY") == "1" {
		names = names[:2]
	}
	for _, name := range names {
		op := ops[name]
		calls := f.rpcCalls()
		serial := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				op()
			}
		})
		fastHit := f.rpcCalls() == calls
		cached := name == "getattr-cached" || name == "lookup-cached"
		if cached && !fastHit {
			t.Fatalf("%s serial issued an authority RPC", name)
		}
		calls = f.rpcCalls()
		par := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			b.SetParallelism(1)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					op()
				}
			})
		})
		parallelFastHit := f.rpcCalls() == calls
		if cached && !parallelFastHit {
			t.Fatalf("%s parallel issued an authority RPC", name)
		}
		fmt.Fprintf(os.Stdout, "ORDINARY %-15s procs=%d serial=%9.3f ns/op %.2f allocs/op %d B/op  parallel=%9.3f ns/op %.2f allocs/op %d B/op  noRPC=%v\n",
			name, runtime.GOMAXPROCS(0), float64(serial.T.Nanoseconds())/float64(serial.N), float64(serial.MemAllocs)/float64(serial.N), serial.AllocedBytesPerOp(), float64(par.T.Nanoseconds())/float64(par.N), float64(par.MemAllocs)/float64(par.N), par.AllocedBytesPerOp(), fastHit && parallelFastHit)
	}
}
