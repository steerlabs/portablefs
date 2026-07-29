package fsproto

// Wire-level attribute semantics for handle-addressed stats, driven through
// the in-process dispatch path (no sockets): fstat of an open-unlinked
// (parked) inode reports st_nlink 0 on the wire — the POSIX truth for a file
// with no remaining directory entry — while named/handle stats of live inodes
// keep a non-zero count, and a reaped handle is a verified-absence ENOENT.

import (
	"testing"
	"time"
)

func TestGetattrOrphanReportsZeroNlink(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-NL", 1, "ONL", "tokNL", 4)

	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "victim", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	// A live named file reports nlink >= 1 (never "unlinked while open").
	named := s.dispatch(&Request{Op: OpGetattr, Path: "victim"})
	if named.Status != OK || named.Attr == nil || named.Attr.Nlink == 0 {
		t.Fatalf("named getattr = %+v, want live nlink >= 1", named)
	}
	ino := named.Attr.Ino
	if ino == 0 {
		t.Fatal("named getattr must carry the stable ino")
	}

	// Unlink-while-open parks the inode; fstat by orphan ino reports nlink 0.
	orph := exactDo(s, cs, &Request{Op: OpOrphan, Path: "victim"}, 0, 2)
	if orph.Status != OK || orph.OrphanIno != ino {
		t.Fatalf("orphan: %+v, want parked ino %d", orph, ino)
	}
	resp := s.dispatch(&Request{Op: OpGetattr, OrphanIno: ino})
	if resp.Status != OK || resp.Attr == nil {
		t.Fatalf("orphan getattr = %+v", resp)
	}
	if resp.Attr.Nlink != 0 {
		t.Fatalf("parked orphan wire nlink = %d, want 0", resp.Attr.Nlink)
	}
	if resp.Attr.Ino != ino {
		t.Fatalf("parked orphan wire ino = %d, want %d", resp.Attr.Ino, ino)
	}

	// The handle-addressed stat of the SAME parked inode agrees.
	handle := s.dispatch(&Request{Op: OpGetattr, Path: "victim", HandleIno: ino})
	if handle.Status != OK || handle.Attr == nil || handle.Attr.Nlink != 0 {
		t.Fatalf("parked handle getattr = %+v, want nlink 0", handle)
	}

	// Public reap is removed from the protocol: the rejection is a durable
	// exact outcome (EPERM) and its identical resend replays. Only the
	// authority reaps, once durable state proves no pins — this UNPINNED
	// park is destroyed by the sweep, and the handle becomes verified
	// absence (exactly ENOENT).
	if r := exactDo(s, cs, &Request{Op: OpReap, OrphanIno: ino}, 0, 3); r.Status != EPERM {
		t.Fatalf("reap: %+v, want durable EPERM", r)
	}
	if r := exactDo(s, cs, &Request{Op: OpReap, OrphanIno: ino}, 0, 3); r.Status != EPERM || !r.Duplicate {
		t.Fatalf("reap replay: %+v, want stored duplicate EPERM", r)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r := s.dispatch(&Request{Op: OpGetattr, OrphanIno: ino}); r.Status == ENOENT {
			break
		}
		if time.Now().After(deadline) {
			r := s.dispatch(&Request{Op: OpGetattr, OrphanIno: ino})
			t.Fatalf("unpinned orphan getattr status = %d, want ENOENT after the reap sweep", r.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHandleStatSurvivesRenameAndReportsLiveNlink(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-HR", 1, "OHR", "tokHR", 4)

	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "orig", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := exactDo(s, cs, &Request{Op: OpWrite, Path: "orig", Data: []byte("payload")}, 0, 2); r.Status != OK {
		t.Fatalf("write: %+v", r)
	}
	a := s.dispatch(&Request{Op: OpGetattr, Path: "orig"})
	if a.Status != OK || a.Attr == nil || a.Attr.Ino == 0 {
		t.Fatalf("getattr: %+v", a)
	}
	ino := a.Attr.Ino

	// Rename the file; the handle (by ino) keeps resolving, still live.
	if r := exactDo(s, cs, &Request{Op: OpRename, Path: "orig", NewPath: "moved"}, 0, 3); r.Status != OK {
		t.Fatalf("rename: %+v", r)
	}
	h := s.dispatch(&Request{Op: OpGetattr, Path: "orig", HandleIno: ino})
	if h.Status != OK || h.Attr == nil || h.Attr.Ino != ino {
		t.Fatalf("handle stat after rename = %+v, want ino %d", h, ino)
	}
	if h.Attr.Nlink == 0 {
		t.Fatalf("live renamed inode reports nlink 0 (would read as unlinked): %+v", h.Attr)
	}
	if h.Attr.Size != int64(len("payload")) {
		t.Fatalf("handle stat size = %d, want %d", h.Attr.Size, len("payload"))
	}

	// A handle ino the authority never allocated is verified absence.
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "", HandleIno: ino + 100000}); r.Status != ENOENT {
		t.Fatalf("unknown handle getattr status = %d, want ENOENT", r.Status)
	}
}
