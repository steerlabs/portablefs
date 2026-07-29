package fsproto

import (
	"path/filepath"
	"testing"
)

// TestReadStampsVersionAndGen: a read-family response carries the path's coherence
// Version and the authority Gen, so a client can do generation-aware, monotonic fills.
func TestReadStampsVersionAndGen(t *testing.T) {
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	s := NewServer(fs, fs)
	cs := openExactSession(t, s, "sess-VG", 1, "M", "tokVG", 8)
	if r := exactDo(s, cs, &Request{Op: OpMkdir, Path: "d", Mode: 0o755}, 0, 1); r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "d/a", Mode: 0o644}, 0, 2); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := exactDo(s, cs, &Request{Op: OpWrite, Path: "d/a", Data: []byte("hello")}, 0, 3); r.Status != OK {
		t.Fatalf("write: %+v", r)
	}

	g := s.dispatch(&Request{Op: OpGetattr, Path: "d/a"})
	if g.Status != OK || g.Version == 0 || g.Gen == 0 {
		t.Fatalf("getattr must stamp Version+Gen: %+v", g)
	}
	r := s.dispatch(&Request{Op: OpRead, Path: "d/a", Size: 5})
	if r.Status != OK || r.Version == 0 || r.Gen == 0 {
		t.Fatalf("read must stamp Version+Gen: %+v", r)
	}
}

func TestGetattrMissCarriesParentVersion(t *testing.T) {
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	s := NewServer(fs, fs)
	cs := openExactSession(t, s, "sess-PV", 1, "M", "tokPV", 8)
	if r := exactDo(s, cs, &Request{Op: OpMkdir, Path: "d", Mode: 0o755}, 0, 1); r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}

	miss := s.dispatch(&Request{Op: OpGetattr, Path: "d/.DS_Store"})
	if miss.Status != ENOENT || miss.Gen == 0 || miss.ParentVersion == 0 {
		t.Fatalf("miss must carry gen and parent version: %+v", miss)
	}
	before := miss.ParentVersion
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "d/file", Mode: 0o644}, 0, 2); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	miss = s.dispatch(&Request{Op: OpGetattr, Path: "d/.DS_Store"})
	if miss.Status != ENOENT || miss.ParentVersion <= before {
		t.Fatalf("parent version should advance after child create: before=%d after=%+v", before, miss)
	}
}
