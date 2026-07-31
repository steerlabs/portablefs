package fsproto

// Protocol-surface coverage for the two metadata facts the authority now
// PERSISTS rather than leaving to a client convention: a per-inode birth time
// and a per-inode BSD file-flag word (chflags(2)). The storage-format side is
// proven in internal/pft2 and internal/workfs; these tests pin what a mount
// actually observes on the wire.

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func getattr(t *testing.T, s *Server, path string) *Attr {
	t.Helper()
	r := s.dispatch(&Request{Op: OpGetattr, Path: path})
	if r.Status != OK || r.Attr == nil {
		t.Fatalf("getattr %s: status=%d attr=%v", path, r.Status, r.Attr)
	}
	return r.Attr
}

// TestGetattrServesAStoredBirthTime: a create is answered with a REAL birth
// time, and later mutations that move mtime leave it alone. The mtime is
// deliberately pushed far away before the final check so a birth time that was
// merely being derived from mtime (the convention clients used while the
// authority had nowhere to store one) would fail here.
func TestGetattrServesAStoredBirthTime(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "pfs-birth", 1, "owner", "tok", 4)

	created := exactDo(s, cs, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1)
	if created.Status != OK {
		t.Fatalf("create: status %d", created.Status)
	}
	attr := getattr(t, s, "f")
	if attr.BirthtimeMs == 0 {
		t.Fatal("getattr served birthtime 0 for a freshly created file")
	}
	if attr.Flags != 0 {
		t.Fatalf("getattr served flags %#x for a freshly created file, want 0", attr.Flags)
	}
	birth := attr.BirthtimeMs

	// Push mtime a decade past the creation instant.
	const farFuture = int64(2_000_000_000_000)
	setTime := exactDo(s, cs, &Request{
		Op: OpSetattr, Path: "f", MtimeMs: farFuture, SetTime: true,
	}, 1, 1)
	if setTime.Status != OK {
		t.Fatalf("setattr mtime: status %d", setTime.Status)
	}
	after := getattr(t, s, "f")
	if after.MtimeMs != farFuture {
		t.Fatalf("mtime = %d, want %d", after.MtimeMs, farFuture)
	}
	if after.BirthtimeMs != birth {
		t.Fatalf("birthtime moved to %d after an mtime change, want %d", after.BirthtimeMs, birth)
	}
	if after.BirthtimeMs == after.MtimeMs {
		t.Fatal("birthtime tracks mtime — it is being derived, not served from storage")
	}

	// readdir-plus must agree with getattr: a mount fills its attr cache from
	// the listing, so a birth time that only appeared on getattr would flip
	// under a client that listed first.
	listing := s.dispatch(&Request{Op: OpReaddir, Path: ""})
	if listing.Status != OK {
		t.Fatalf("readdir: status %d", listing.Status)
	}
	var seen bool
	for _, entry := range listing.Entries {
		if entry.Name != "f" {
			continue
		}
		seen = true
		if entry.Attr.BirthtimeMs != birth {
			t.Fatalf("readdir birthtime = %d, want %d", entry.Attr.BirthtimeMs, birth)
		}
	}
	if !seen {
		t.Fatal("readdir did not list the created file")
	}
}

// TestSetattrPersistsBsdFlags: the SetFlags group reaches the tree as an
// OpChflags, the FULL uint32 survives (policy masking is the client's job), and
// clearing back to zero is a real durable state.
func TestSetattrPersistsBsdFlags(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "pfs-flags", 1, "owner", "tok", 4)

	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: status %d", r.Status)
	}

	const stored = uint32(0x8000_8002)
	set := exactDo(s, cs, &Request{Op: OpSetattr, Path: "f", Flags: stored, SetFlags: true}, 1, 1)
	if set.Status != OK {
		t.Fatalf("setattr flags: status %d", set.Status)
	}
	if set.Attr == nil || set.Attr.Flags != stored {
		t.Fatalf("setattr reply attr = %+v, want flags %#x", set.Attr, stored)
	}
	if got := getattr(t, s, "f").Flags; got != stored {
		t.Fatalf("getattr flags = %#x, want %#x (no server-side masking)", got, stored)
	}

	cleared := exactDo(s, cs, &Request{Op: OpSetattr, Path: "f", Flags: 0, SetFlags: true}, 1, 2)
	if cleared.Status != OK {
		t.Fatalf("setattr clear flags: status %d", cleared.Status)
	}
	if got := getattr(t, s, "f").Flags; got != 0 {
		t.Fatalf("getattr flags after clear = %#x, want 0", got)
	}
}

// TestSetattrFlagsIsItsOwnExactGroup mirrors the existing multi-group rule: one
// exact identity maps to exactly one WAL record, so chflags may not ride along
// with chmod/chtimes/chown, and the value may not travel without its intent
// flag (zero is a legal flag word, so the flag is the only signal).
func TestSetattrFlagsIsItsOwnExactGroup(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "pfs-group", 1, "owner", "tok", 8)
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: status %d", r.Status)
	}

	for i, req := range []*Request{
		{Op: OpSetattr, Path: "f", Mode: 0o600, SetMode: true, Flags: 0x2, SetFlags: true},
		{Op: OpSetattr, Path: "f", UID: 7, SetUID: true, Flags: 0x2, SetFlags: true},
		{Op: OpSetattr, Path: "f", MtimeMs: 1, SetTime: true, Flags: 0x2, SetFlags: true},
		{Op: OpSetattr, Path: "f", Flags: 0x2}, // value without its intent flag
	} {
		if r := exactDo(s, cs, req, uint32(i+1), 1); r.Status != EINVAL {
			t.Fatalf("multi-group/flagless setattr %d: status %d, want EINVAL", i, r.Status)
		}
	}

	// The same two intents, split into separate identities the way the client
	// already splits chmod from chown, both apply.
	if r := exactDo(s, cs, &Request{Op: OpSetattr, Path: "f", Mode: 0o600, SetMode: true}, 5, 1); r.Status != OK {
		t.Fatalf("split chmod: status %d", r.Status)
	}
	if r := exactDo(s, cs, &Request{Op: OpSetattr, Path: "f", Flags: 0x2, SetFlags: true}, 6, 1); r.Status != OK {
		t.Fatalf("split chflags: status %d", r.Status)
	}
	attr := getattr(t, s, "f")
	if attr.Mode&0o777 != 0o600 || attr.Flags != 0x2 {
		t.Fatalf("after the split setattrs: mode=%o flags=%#x", attr.Mode&0o777, attr.Flags)
	}
}

// TestChflagsCanonicalHashLeavesOlderRecordsUntouched: the exact-once
// fingerprint folds the flag word in ONLY for a chflags record, so every
// pre-chflags record hashes exactly as it did before the op existed. Without
// that discipline a retry parked by an older authority would fence as a hash
// conflict after a rolling upgrade.
func TestChflagsCanonicalHashLeavesOlderRecordsUntouched(t *testing.T) {
	chmod := wal.Record{Op: wal.OpChmod, Path: "f", Mode: 0o600}
	before := string(canonicalRecordHash(chmod))
	chmod.Flags = 0x2 // a field a chmod can never legally carry
	if string(canonicalRecordHash(chmod)) != before {
		t.Fatal("a stray flag word changed a chmod's exact fingerprint")
	}

	a := wal.Record{Op: wal.OpChflags, Path: "f", Flags: 0x2}
	b := wal.Record{Op: wal.OpChflags, Path: "f", Flags: 0x4}
	if string(canonicalRecordHash(a)) == string(canonicalRecordHash(b)) {
		t.Fatal("two different flag words share one exact fingerprint")
	}
	zero := wal.Record{Op: wal.OpChflags, Path: "f"}
	if string(canonicalRecordHash(zero)) == string(canonicalRecordHash(a)) {
		t.Fatal("clearing flags and setting them share one exact fingerprint")
	}
}
