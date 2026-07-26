package workfs

import (
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// TestInvalidationInPlaceTagging guards the CWD-coherence fix: a content/metadata change must be
// tagged InPlace so the mount SKIPS the parent dentry drop (NotifyEntry) — dropping the dentry of a
// directory a process holds as its CWD disconnects it, so a concurrent getcwd() ENOENTs and the app
// sees SQLITE_CANTOPEN. A create/remove/rename must NOT be InPlace, so the dentry IS dropped and a
// removed/renamed name is seen gone for any entry-TTL. Guards both the classifier and changesFor.
func TestInvalidationInPlaceTagging(t *testing.T) {
	for _, op := range []wal.Op{wal.OpWrite, wal.OpTruncate, wal.OpChmod, wal.OpChtimes, wal.OpChown} {
		if !isInPlaceOp(op) {
			t.Errorf("op %d must be in-place (mount must skip NotifyEntry to keep an in-use CWD connected)", op)
		}
	}
	for _, op := range []wal.Op{wal.OpCreate, wal.OpMkdir, wal.OpRemove, wal.OpRename, wal.OpSymlink, wal.OpOrphan, wal.OpLink} {
		if isInPlaceOp(op) {
			t.Errorf("op %d must NOT be in-place (mount must NotifyEntry so a removed/renamed name is seen gone)", op)
		}
	}

	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	if chmod := fs.changesFor(wal.Record{Op: wal.OpChmod, Path: "d"}, "", 1, 0); len(chmod) != 1 || !chmod[0].InPlace {
		t.Fatalf("chmod invalidation must carry InPlace=true, got %+v", chmod)
	}
	if rm := fs.changesFor(wal.Record{Op: wal.OpRemove, Path: "d"}, "", 2, 0); len(rm) != 1 || rm[0].InPlace {
		t.Fatalf("remove invalidation must carry InPlace=false, got %+v", rm)
	}
	if link := fs.changesFor(wal.Record{Op: wal.OpLink, Path: "a", NewPath: "b"}, "", 3, 0); len(link) != 2 ||
		link[0].Path != "a" || link[1].Path != "b" || link[0].InPlace || link[1].InPlace {
		t.Fatalf("link invalidations must cover source+destination as namespace changes, got %+v", link)
	}
	if link := fs.changesFor(wal.Record{Op: wal.OpLink, Path: "a", NewPath: "b"}, "", 4, 0, 42); len(link) != 2 ||
		len(link[0].RelatedInos) != 1 || link[0].RelatedInos[0] != 42 ||
		len(link[1].RelatedInos) != 1 || link[1].RelatedInos[0] != 42 {
		t.Fatalf("link invalidations must carry related inode identity, got %+v", link)
	}
}

// TestRejectedRemoveDoesNotPublish guards that a remove which REJECTS (non-empty dir, or a missing
// path) changed nothing and therefore publishes NO invalidation — every op must return changed=false
// on a no-op/reject. A phantom name-change would make a peer drop a dentry it didn't need to, and if
// that name is an in-use CWD directory it re-opens the getcwd→ENOENT→SQLITE_CANTOPEN hazard.
func TestRejectedRemoveDoesNotPublish(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	_ = fs.MkdirAll("d", 0o755)
	f, _ := fs.Create("d/keep")
	_ = f.Close() // d is now non-empty -> a remove of d must reject (errNotEmpty)

	sub, unsub := fs.Subscribe() // subscribe AFTER setup: the channel only sees what follows
	defer unsub()
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpRemove, Path: "d"}}, ""); err != nil {
		t.Fatalf("ApplyBatch must tolerate a rejected remove: %v", err)
	}
	select {
	case got := <-sub:
		t.Fatalf("a rejected (non-empty) remove published %v, want nothing", got)
	case <-time.After(300 * time.Millisecond):
		// good: the no-op remove published nothing
	}
	if fs.resolve("d") == nil {
		t.Fatal("the rejected remove must have left d intact")
	}
}

// TestMutationPublishesInvalidations: every mutation notifies subscribers of the
// changed paths (rename notifies both), so clients can drop just those entries.
func TestMutationPublishesInvalidations(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	ch, cancel := fs.Subscribe()
	defer cancel()

	f, _ := fs.Create("a.txt")
	_, _ = f.Write([]byte("hi"))
	_ = f.Close()
	_ = fs.MkdirAll("d", 0o755)
	_ = fs.Rename("a.txt", "b.txt")

	got := map[string]bool{}
	timeout := time.After(2 * time.Second)
	for !(got["a.txt"] && got["b.txt"] && got["d"]) {
		select {
		case ps := <-ch:
			for _, p := range ps {
				got[p.Path] = true
			}
		case <-timeout:
			t.Fatalf("missing invalidations; got %v", got)
		}
	}
}
