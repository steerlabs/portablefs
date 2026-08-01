package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// Wire round trips per syscall sequence, on the WRITE-THROUGH lane.
//
// These are the acceptance tests for attribute-returning mutations. Every
// mutation reply carries the post-op attributes of the names its version stamp
// covered, and the mount installs them in its version-gated caches instead of
// evicting them and re-reading (postattrs.go), so the metadata prologue and
// epilogue around a mutation cost NOTHING on the wire.
//
// Measured baseline on this harness before the change (the same shape the
// production trace showed, minus the kernel's own repetition):
//
//	create+write+close   6 RTT   lookup, create, getattr, getattr(parent), write, getattr
//	rename               3 RTT   lookup(dst), lookup(src)=0, rename, getattr
//	unlink               3 RTT   getattr(parent), lookup=0, remove, lookup(ENOENT)
//
// After: 3 / 2 / 1, and every one of those is a MUTATION or a genuinely cold
// first read of a name this mount has never seen. There is no round trip left
// that re-reads state this mount itself just wrote.

// wireCounter counts authority round trips across one syscall-shaped step.
type wireCounter struct {
	t    *testing.T
	v    *Volume
	base int64
}

func newWireCounter(t *testing.T, v *Volume) *wireCounter {
	t.Helper()
	return &wireCounter{t: t, v: v, base: opCount(v)}
}

// step runs fn, asserts the round trips it issued, and re-arms the counter.
func (w *wireCounter) step(name string, want int64, fn func()) int64 {
	w.t.Helper()
	fn()
	now := opCount(w.v)
	got := now - w.base
	w.base = now
	if got != want {
		w.t.Errorf("%s: %d authority round trips, want %d", name, got, want)
	}
	return got
}

func TestWriteThroughCreateWriteCloseCostsThreeRoundTrips(t *testing.T) {
	t.Setenv("PORTABLEFS_DEBUG_WRITE_THROUGH", "1")
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "rtt-create", WALDir: t.TempDir()})

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}

	w := newWireCounter(t, v)
	var total int64
	// The kernel's pre-create lookup of a name this mount has never seen: a
	// genuinely cold read, and the only one in the sequence.
	total += w.step("lookup d/f (ENOENT)", 1, func() {
		if _, st := v.Lookup(ctx, "d/f"); st != fsproto.ENOENT {
			t.Fatalf("pre-create lookup: %d", st)
		}
	})
	var n *NodeState
	total += w.step("create d/f", 1, func() {
		a, st := v.Create(ctx, "d/f", 0o644)
		if st != fsproto.OK {
			t.Fatalf("create: %d", st)
		}
		n = NewNodeState(a.Ino, a.Ino != 0)
	})
	// The create reply carried both the new file's attributes and the
	// parent's; neither needs re-reading.
	total += w.step("getattr d/f", 0, func() {
		if _, st := v.Getattr(ctx, "d/f", n); st != fsproto.OK {
			t.Fatalf("post-create getattr: %d", st)
		}
	})
	total += w.step("getattr d (parent)", 0, func() {
		if _, st := v.Getattr(ctx, "d", nil); st != fsproto.OK {
			t.Fatalf("parent getattr: %d", st)
		}
	})
	total += w.step("write d/f 4K", 1, func() {
		if _, st := v.Write(ctx, "d/f", n, 0, make([]byte, 4096)); st != fsproto.OK {
			t.Fatalf("write: %d", st)
		}
	})
	total += w.step("getattr d/f (post-write)", 0, func() {
		if _, st := v.Getattr(ctx, "d/f", n); st != fsproto.OK {
			t.Fatalf("post-write getattr: %d", st)
		}
	})
	if total != 3 {
		t.Errorf("create+write(4K)+close = %d round trips, want 3 (baseline 6)", total)
	}
}

// TestWriteThroughOpenHandleGetattrIsFreeAfterItsOwnWrite pins the read the
// daemon issues on EVERY write reply (attach.writeReply → GetattrOpenHandle).
// It is handle-addressed, so it used to bypass the attribute cache
// unconditionally and cost one authority round trip per write(2). The cached
// entry the write's own reply installed proves both coherence (version anchor)
// and identity (stable ino), which is exactly what the bypass was approximating.
func TestWriteThroughOpenHandleGetattrIsFreeAfterItsOwnWrite(t *testing.T) {
	t.Setenv("PORTABLEFS_DEBUG_WRITE_THROUGH", "1")
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "rtt-handle", WALDir: t.TempDir()})

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	if _, st := v.Lookup(ctx, "d/f"); st != fsproto.ENOENT {
		t.Fatalf("pre-create lookup: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(ctx, "d/f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}

	w := newWireCounter(t, v)
	payload := make([]byte, 4096)
	for i := 0; i < 4; i++ {
		w.step("write", 1, func() {
			if _, st := v.WriteOpenHandle(ctx, "d/f", n, int64(i)*4096, payload); st != fsproto.OK {
				t.Fatalf("write %d: %d", i, st)
			}
		})
		w.step("open-handle getattr", 0, func() {
			att, st := v.GetattrOpenHandle(ctx, "d/f", n)
			if st != fsproto.OK {
				t.Fatalf("open-handle getattr %d: %d", i, st)
			}
			if want := int64((i + 1) * 4096); att.Size != want {
				t.Fatalf("open-handle getattr %d size = %d, want %d", i, att.Size, want)
			}
		})
	}
}

func TestWriteThroughRenameAndUnlinkRoundTrips(t *testing.T) {
	t.Setenv("PORTABLEFS_DEBUG_WRITE_THROUGH", "1")
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "rtt-ns", WALDir: t.TempDir()})

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	// The kernel looks a name up before creating it; that first authority
	// response is also what anchors the mount's coherence generation, so this
	// mirrors the real syscall order rather than starting cold on a mutation.
	if _, st := v.Lookup(ctx, "d/f"); st != fsproto.ENOENT {
		t.Fatalf("pre-create lookup: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)

	w := newWireCounter(t, v)
	var rename int64
	// Cold: this mount has never seen the destination name.
	rename += w.step("lookup d/g (ENOENT)", 1, func() {
		if _, st := v.Lookup(ctx, "d/g"); st != fsproto.ENOENT {
			t.Fatalf("rename dst lookup: %d", st)
		}
	})
	rename += w.step("lookup d/f", 0, func() {
		if _, st := v.Lookup(ctx, "d/f"); st != fsproto.OK {
			t.Fatalf("rename src lookup: %d", st)
		}
	})
	rename += w.step("rename d/f -> d/g", 1, func() {
		if st := v.Rename(ctx, "d/f", "d/g", n, nil); st != fsproto.OK {
			t.Fatalf("rename: %d", st)
		}
	})
	// The rename reply carried the destination's attributes, the source's
	// proven absence, and the parent's new version.
	rename += w.step("getattr d/g", 0, func() {
		if _, st := v.Getattr(ctx, "d/g", n); st != fsproto.OK {
			t.Fatalf("post-rename getattr: %d", st)
		}
	})
	rename += w.step("lookup d/f (ENOENT)", 0, func() {
		if _, st := v.Lookup(ctx, "d/f"); st != fsproto.ENOENT {
			t.Fatalf("post-rename source lookup: %d", st)
		}
	})
	if rename != 2 {
		t.Errorf("rename sequence = %d round trips, want 2 (baseline 3)", rename)
	}

	w = newWireCounter(t, v)
	var unlink int64
	unlink += w.step("getattr d (parent)", 0, func() {
		if _, st := v.Getattr(ctx, "d", nil); st != fsproto.OK {
			t.Fatalf("unlink parent getattr: %d", st)
		}
	})
	unlink += w.step("lookup d/g", 0, func() {
		if _, st := v.Lookup(ctx, "d/g"); st != fsproto.OK {
			t.Fatalf("unlink target lookup: %d", st)
		}
	})
	unlink += w.step("remove d/g", 1, func() {
		if st := v.Remove(ctx, "d/g", n); st != fsproto.OK {
			t.Fatalf("remove: %d", st)
		}
	})
	unlink += w.step("lookup d/g (ENOENT)", 0, func() {
		if _, st := v.Lookup(ctx, "d/g"); st != fsproto.ENOENT {
			t.Fatalf("post-remove lookup: %d", st)
		}
	})
	if unlink != 1 {
		t.Errorf("unlink sequence = %d round trips, want 1 (baseline 3)", unlink)
	}
}

// TestMutationAttrInstallNeverOutrunsAPeerInvalidation is the coherence half of
// the change: an installed post-op attribute is subject to exactly the version
// rule a read fill is, so a peer's later mutation supersedes it and the next
// read goes back to the authority. Nothing installed here has a TTL.
func TestMutationAttrInstallNeverOutrunsAPeerInvalidation(t *testing.T) {
	t.Setenv("PORTABLEFS_DEBUG_WRITE_THROUGH", "1")
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "rtt-coherence", WALDir: t.TempDir()})
	watchInvalidationsForTest(t, v)
	peer := dialCore(t, addr, Options{Owner: "rtt-peer", WALDir: t.TempDir()})

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	// The create installed d/f; serving it costs nothing.
	if _, st := v.Getattr(ctx, "d/f", n); st != fsproto.OK {
		t.Fatalf("getattr: %d", st)
	}

	// A peer overwrites the file. Its invalidation carries a strictly greater
	// version for d/f, which must supersede the installed entry.
	pn := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := peer.Write(ctx, "d/f", pn, 0, []byte("peer bytes")); st != fsproto.OK {
		t.Fatalf("peer write: %d", st)
	}
	if err := peer.FlushToAuthority(ctx); err != nil {
		t.Fatalf("peer flush: %v", err)
	}
	waitFor(t, func() bool {
		att, st := v.Getattr(ctx, "d/f", n)
		return st == fsproto.OK && att.Size == int64(len("peer bytes"))
	}, "installed attributes were never superseded by the peer's invalidation")
}
