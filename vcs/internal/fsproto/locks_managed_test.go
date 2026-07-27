package fsproto

import "testing"

// TestManagedWireExclCreate proves wire-level O_EXCL at the client surface:
// a managed authority decides exclusivity atomically inside its ordered
// journal, so of two mounts racing CreateExcl on one path exactly one wins
// and the loser sees EEXIST — with no lookup pre-check round trip, and no
// cross-machine TOCTOU window (the pre-check this replaces let two machines
// both win O_EXCL on the same git lock file).
func TestManagedWireExclCreate(t *testing.T) {
	addr := serveManagedAuthority(t)
	dial := func(owner string) *Client {
		cli, err := Dial(addr, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		cli.SetOwner(owner)
		if _, err := cli.EnsureExactSession(); err != nil {
			t.Fatalf("exact session for %s: %v", owner, err)
		}
		return cli
	}
	a, b := dial("MA"), dial("MB")

	if _, st, err := a.CreateExcl("x.lock", 0o600); err != nil || st != OK {
		t.Fatalf("first excl create: st=%d err=%v", st, err)
	}
	if _, st, err := b.CreateExcl("x.lock", 0o600); err != nil || st != EEXIST {
		t.Fatalf("second excl create: st=%d err=%v, want EEXIST", st, err)
	}
	// The fused create+open form enforces the same exclusivity.
	if _, _, st, err := b.CreateExclRegisterOpen("x.lock", 0o600); err != nil || st != EEXIST {
		t.Fatalf("fused excl create over existing: st=%d err=%v, want EEXIST", st, err)
	}
}

// TestManagedAdvisoryLockClientSurface proves the advisory-lock routing fix at
// the client wire surface (what clientcore's lockRouter chooses between). A
// managed authority refuses the legacy envelope-less setlk with EPERM — the
// failure that broke flock/SQLite locking on production volumes — while the
// journaled LockManaged surface grants, excludes a second mount, reports the
// conflict through getlk, and releases so the blocked mount can acquire.
func TestManagedAdvisoryLockClientSurface(t *testing.T) {
	addr := serveManagedAuthority(t)
	dial := func(owner string) *Client {
		cli, err := Dial(addr, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		cli.SetOwner(owner)
		if _, err := cli.EnsureExactSession(); err != nil {
			t.Fatalf("exact session for %s: %v", owner, err)
		}
		return cli
	}
	a, b := dial("MA"), dial("MB")

	if _, st, err := a.Create("db", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	// Bug repro: the legacy envelope-less setlk clientcore used to send is
	// categorically refused by a managed authority.
	if res, err := a.Lock("db", LkSetlk, 7, 0, kernelOffsetEOF, true, false); err != nil || res.Status != EPERM {
		t.Fatalf("legacy setlk on managed: res=%+v err=%v, want EPERM", res, err)
	}

	// The fix: the journaled surface grants the write lock.
	if res, err := a.LockManaged("db", 0, LkSetlk, 7, 0, kernelOffsetEOF, true, false); err != nil || res.Status != OK {
		t.Fatalf("managed setlk: res=%+v err=%v", res, err)
	}
	// A second mount is excluded without blocking.
	if res, err := b.LockManaged("db", 0, LkSetlk, 9, 0, kernelOffsetEOF, true, false); err != nil || res.Status != EAGAIN {
		t.Fatalf("conflicting managed setlk: res=%+v err=%v, want EAGAIN", res, err)
	}
	// Getlk (pure read) reports the holder's write lock.
	if res, err := b.LockManaged("db", 0, LkGetlk, 9, 0, kernelOffsetEOF, false, false); err != nil || !res.Conflict || !res.CWrite {
		t.Fatalf("managed getlk: res=%+v err=%v, want a write-lock conflict", res, err)
	}
	// Release, then the second mount acquires.
	if res, err := a.LockManaged("db", 0, LkSetlk, 7, 0, kernelOffsetEOF, false, true); err != nil || res.Status != OK {
		t.Fatalf("managed unlock: res=%+v err=%v", res, err)
	}
	if res, err := b.LockManaged("db", 0, LkSetlk, 9, 0, kernelOffsetEOF, true, false); err != nil || res.Status != OK {
		t.Fatalf("managed setlk after release: res=%+v err=%v", res, err)
	}
}
