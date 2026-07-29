package fsproto

// Wire-level edge sweeps over the managed authority: reserved-namespace
// hiding, sparse writes, and delete-then-recreate — every mutation riding the
// mandatory exact-session path exactly like a real mount. The flush ledger's
// gap/resend/epoch semantics are pinned in workfs/managed_coordination_test
// and writeback_managed_test; exact-identity replay is pinned in
// exact_test/coordinate_test.

import (
	"testing"
)

// TestReservedNamespaceFullyHidden: the reserved root namespace
// (".portablefs-*") is invisible to clients — reads answer ENOENT, mutations
// consume their identities with a durable ENOENT, and renames cannot land in
// it.
func TestReservedNamespaceFullyHidden(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Create("visible.txt", 0o644); st != OK {
		t.Fatalf("create visible.txt: status %d", st)
	}

	const wm = ".portablefs-evil"
	if _, st, _ := c.Getattr(wm); st != ENOENT {
		t.Fatalf("getattr %q: status=%d, want ENOENT", wm, st)
	}
	if _, st, _ := c.Create(wm, 0o644); st != ENOENT {
		t.Fatalf("create reserved %q: status=%d, want ENOENT", wm, st)
	}
	if _, st, _ := c.Read(wm, 0, 8); st != ENOENT {
		t.Fatalf("read reserved: status=%d, want ENOENT", st)
	}
	if st, _ := c.Remove(wm); st != ENOENT {
		t.Fatalf("remove reserved: status=%d, want ENOENT", st)
	}
	if st, _ := c.Truncate(wm, 1); st != ENOENT {
		t.Fatalf("truncate reserved: status=%d, want ENOENT", st)
	}
	if st, _ := c.Rename("visible.txt", wm); st != ENOENT {
		t.Fatalf("rename to reserved NewPath: status=%d, want ENOENT", st)
	}
	ents, _, st, _ := c.Readdir("")
	if st != OK {
		t.Fatalf("readdir root: status %d", st)
	}
	sawVisible := false
	for _, e := range ents {
		if isReserved(e.Name) {
			t.Fatalf("readdir leaked reserved entry %q", e.Name)
		}
		if e.Name == "visible.txt" {
			sawVisible = true
		}
	}
	if !sawVisible {
		t.Fatalf("readdir root hid a normal file visible.txt; entries=%v", ents)
	}
}

// TestIsReservedCanonicalizationMatrix is the focused canonicalization-vs-traversal
// table for isReserved (the guard's correctness crux): every spelling that path.Clean
// resolves to a ROOT ".portablefs-*" file is reserved, while a ".portablefs-*" basename inside a
// SUBDIR is a legitimate user file and must NOT be reserved. This is the audit-found
// CRITICAL (traversal past the guard) plus the HIGH (subdir false-positive) in one
// exhaustive matrix.
func TestIsReservedCanonicalizationMatrix(t *testing.T) {
	cases := map[string]bool{
		// Root reserved file (prefix is ".portablefs-", WITH the dash) in every traversal spelling.
		".portablefs-id":                       true,
		"./.portablefs-id":                     true,
		"/.portablefs-id":                      true,
		"x/../.portablefs-id":                  true,
		"a/b/../../.portablefs-id":             true,
		"a/b/c/../../../.portablefs-z":         true,
		"./x/../.portablefs-id":                true,
		"//.portablefs-id":                     true, // double slash collapses to /.portablefs-id
		".portablefs-":                         true, // bare prefix is reserved
		".portablefs-with/trailing":            true, // a ".portablefs-*" at root with children still starts with the prefix
		"x/../.portablefs-id/../.portablefs-z": true, // /x/.. -> /, /.portablefs-id/.. -> /, /.portablefs-z -> reserved
		// Legitimate: ".portablefs-*" as a basename inside a subdirectory (NOT a root watermark).
		"foo/.portablefs-bar":     false,
		"a/b/.portablefs-id":      false,
		"sub/.portablefs-id":      false,
		"x/y/../.portablefs-here": false, // cleans to x/.portablefs-here (still a subdir, not root)
		// The prefix REQUIRES the trailing dash: bare ".osw" (and ".osw" via any traversal) is
		// NOT reserved, nor is ".oswald" (".oswa..." never matches ".portablefs-").
		".osw":                  false,
		"./.osw":                false,
		"/.osw":                 false,
		"a/b/../../.osw":        false,
		".oswald":               false, // ".oswa..." never matches the ".portablefs-" prefix
		".portablefs-x.tmp":     true,  // a watermark-like name at root is reserved
		"notosw/.portablefs-no": false,
		// Plainly unreserved.
		"app.db":    false,
		"ws/app.db": false,
		"":          false,
		".":         false,
		"/":         false,
	}

	for p, want := range cases {
		if got := isReserved(p); got != want {
			t.Errorf("isReserved(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestReservedSubdirFileIsUsable end-to-ends the subdir exception through the
// wire: a ".portablefs-*" basename inside a subdirectory is an ordinary user
// file — creatable, listable, readable — while the genuine root namespace
// stays uncreatable.
func TestReservedSubdirFileIsUsable(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Mkdir("d", 0o755); st != OK {
		t.Fatalf("mkdir d: status %d", st)
	}
	if _, st, _ := c.Create("d/.portablefs-legit", 0o644); st != OK {
		t.Fatalf("create d/.portablefs-legit: status %d", st)
	}
	if _, st, _ := c.Write("d/.portablefs-legit", 0, []byte("payload"), 0o644); st != OK {
		t.Fatalf("write d/.portablefs-legit: status %d", st)
	}
	ents, _, st, _ := c.Readdir("d")
	if st != OK {
		t.Fatalf("readdir d: status %d", st)
	}
	found := false
	for _, e := range ents {
		if e.Name == ".portablefs-legit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("readdir d hid subdir file .portablefs-legit; entries=%v", ents)
	}
	if _, st, _ := c.Getattr("d/.portablefs-legit"); st != OK {
		t.Fatalf("getattr d/.portablefs-legit: status=%d, want OK", st)
	}
	if data, st, _ := c.Read("d/.portablefs-legit", 0, 64); st != OK || string(data) != "payload" {
		t.Fatalf("read d/.portablefs-legit=%q (st=%d), want payload", data, st)
	}
	if _, st, _ := c.Create(".portablefs-evil", 0o644); st != ENOENT {
		t.Fatalf("root .portablefs-evil create: status=%d, want ENOENT", st)
	}
}

// TestWriteSparseAndHoles: writes past EOF leave a zero-filled hole and size
// tracks the highest written offset — over the wire, through exact sessions.
func TestWriteSparseAndHoles(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Create("sp", 0o644); st != OK {
		t.Fatalf("create: %d", st)
	}
	if _, st, _ := c.Write("sp", 0, []byte("AB"), 0o644); st != OK {
		t.Fatalf("write @0: %d", st)
	}
	if _, st, _ := c.Write("sp", 100, []byte("YZ"), 0o644); st != OK {
		t.Fatalf("write @100: %d", st)
	}
	a, st, _ := c.Getattr("sp")
	if st != OK || a.Size != 102 {
		t.Fatalf("sparse size=%d (st=%d), want 102", a.Size, st)
	}
	data, st, _ := c.Read("sp", 0, 102)
	if st != OK || len(data) != 102 {
		t.Fatalf("sparse read: status=%d len=%d, want OK/102", st, len(data))
	}
	if data[0] != 'A' || data[1] != 'B' || data[100] != 'Y' || data[101] != 'Z' {
		t.Fatalf("sparse bytes wrong at endpoints: %q", data[:2])
	}
	for i := 2; i < 100; i++ {
		if data[i] != 0 {
			t.Fatalf("hole not zero at byte %d: %d", i, data[i])
		}
	}
	hole, st, _ := c.Read("sp", 10, 8)
	if st != OK || len(hole) != 8 {
		t.Fatalf("hole read: status=%d len=%d", st, len(hole))
	}
	for i, b := range hole {
		if b != 0 {
			t.Fatalf("hole read byte %d = %d, want 0", i, b)
		}
	}
}

// TestDeleteThenRecreate: a removed path recreates empty at the same name,
// with fresh content and no resurrection of the old bytes.
func TestDeleteThenRecreate(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Create("f", 0o644); st != OK {
		t.Fatalf("create: %d", st)
	}
	if _, st, _ := c.Write("f", 0, []byte("old"), 0o644); st != OK {
		t.Fatalf("write: %d", st)
	}
	if st, _ := c.Remove("f"); st != OK {
		t.Fatalf("remove: %d", st)
	}
	if _, st, _ := c.Getattr("f"); st != ENOENT {
		t.Fatalf("after remove getattr: status=%d, want ENOENT", st)
	}
	a, st, _ := c.Create("f", 0o644)
	if st != OK || a.Size != 0 {
		t.Fatalf("recreate: status=%d size=%d, want OK/0", st, a.Size)
	}
	if data, st, _ := c.Read("f", 0, 16); st != OK || len(data) != 0 {
		t.Fatalf("recreated file not empty: status=%d data=%q", st, data)
	}
	if _, st, _ := c.Write("f", 0, []byte("new"), 0o644); st != OK {
		t.Fatalf("write after recreate: %d", st)
	}
	if data, _, _ := c.Read("f", 0, 16); string(data) != "new" {
		t.Fatalf("recreated f=%q, want new", data)
	}
}
