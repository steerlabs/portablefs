package fsproto

import "testing"

// TestReadStampsVersionAndGen: a read-family response carries the path's coherence
// Version and the authority Gen, so a client can do generation-aware, monotonic fills.
func TestReadStampsVersionAndGen(t *testing.T) {
	s, deleg := newEnforceServer(t)
	deleg.Checkout("d", "M")
	s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755, Owner: "M"})
	s.dispatch(&Request{Op: OpCreate, Path: "d/a", Mode: 0o644, Owner: "M"})
	s.dispatch(&Request{Op: OpWrite, Path: "d/a", Data: []byte("hello"), Owner: "M"})

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
	s, deleg := newEnforceServer(t)
	deleg.Checkout("d", "M")
	s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755, Owner: "M"})

	miss := s.dispatch(&Request{Op: OpGetattr, Path: "d/.DS_Store"})
	if miss.Status != ENOENT || miss.Gen == 0 || miss.ParentVersion == 0 {
		t.Fatalf("miss must carry gen and parent version: %+v", miss)
	}
	before := miss.ParentVersion
	s.dispatch(&Request{Op: OpCreate, Path: "d/file", Mode: 0o644, Owner: "M"})
	miss = s.dispatch(&Request{Op: OpGetattr, Path: "d/.DS_Store"})
	if miss.Status != ENOENT || miss.ParentVersion <= before {
		t.Fatalf("parent version should advance after child create: before=%d after=%+v", before, miss)
	}
}
