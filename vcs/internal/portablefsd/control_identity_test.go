package portablefsd

// ── FINDING 3 (ROUND 13): RESERVE ONE IDENTITY, MUTATE ANOTHER ──────────────
//
// Both arms of a control write sample the pathname's item BEFORE the namespace
// gate — which is where a frontend must take its reservation, holding nothing —
// and then never compare that sample with what the name actually resolves to
// under the lock. A concurrent create or rename-over between the two moves the
// name from A (or from absent) to B, and the handler opens B's mutation
// sequence while holding A's reservation, or none at all.
//
// The reservation is the ONLY thing that keeps a refresh from arming over a
// mutation that has not published yet. Held against the wrong identity it
// proves nothing about the one being mutated: B may be pinned, and this control
// mutation's whole bracket — begin, commit, publish, settle — can open and
// close inside the exact gap the pin protocol exists to close.
//
// The unwind for "the state I pre-resolved no longer holds under the lock"
// already exists: it is the ErrLaneChanged discipline — release every lock, the
// reservation and the lane token, and re-admit against the state that is
// actually there. Identity revalidation reuses it exactly.

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// bracketedWithoutAReservation names every item whose mutation sequence is open
// while nothing holds a size reservation for it. The set must always be empty
// inside a control write: the bracket and the reservation are two halves of one
// claim about one identity.
func bracketedWithoutAReservation(a *attach) []uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var out []uint64
	for itemID := range a.itemMutations {
		if a.itemMutationInFlightLocked(itemID) &&
			a.sizeMutationReservations[itemID] == 0 {
			out = append(out, itemID)
		}
	}
	return out
}

func newControlIdentityAttach(t *testing.T, name string) (*attach, *clientcore.Volume) {
	t.Helper()
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr: authority, Pool: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	a := newAttach("att-"+name, "key", ensureAttachRequest{
		VolumeID: "vol-" + name, Branch: "main",
		MountPath: "/Volumes/" + name, AuthorityURL: authority,
	}, privateTestDir(t))
	a.vol = vol
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }
	return a, vol
}

// rebindOnce replaces the frontend identity bound to p exactly once, standing in
// for the concurrent create or rename-over that lands between a control write's
// pre-lock sample and its namespace gate.
func rebindOnce(a *attach, p string, itemID uint64) func(context.Context) {
	var once sync.Once
	return func(context.Context) {
		once.Do(func() {
			a.mu.Lock()
			rec := &itemRecord{
				item: pfslocal.Item{ItemID: itemID, ItemGeneration: 1},
				path: p,
				// The unbound shape a name that has just been created or
				// renamed over carries before the daemon has recorded its
				// authority inode — the same state controlWriteLocked derives
				// for a name it has no record of at all.
				state: clientcore.NewNodeState(0, false),
				attr:  fsproto.Attr{Kind: "file", Mode: 0o644},
			}
			a.items[itemID] = rec
			a.paths[p] = rec
			a.addItemAliasLocked(rec)
			a.mu.Unlock()
		})
	}
}

func controlWrite(t *testing.T, a *attach, p, payload string) *httptest.ResponseRecorder {
	t.Helper()
	body := []byte(`{"path":"` + p + `","dataBase64":"` +
		base64.StdEncoding.EncodeToString([]byte(payload)) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/fs/write", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	(&Server{}).controlFSWrite(recorder, req, a)
	return recorder
}

// TestControlWriteRevalidatesTheIdentityItReserved is the authority arm with the
// name already bound: A at the sample, B under the lock.
func TestControlWriteRevalidatesTheIdentityItReserved(t *testing.T) {
	a, vol := newControlIdentityAttach(t, "ControlIdentityRebind")
	const p = "f.txt"
	attr, st := vol.Create(context.Background(), p, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create %s: %d", p, st)
	}
	a.mu.Lock()
	original := a.registerLocked(p, attr)
	a.mu.Unlock()
	if original == nil {
		t.Fatal("could not register the pre-existing item")
	}

	const replacement = uint64(0x51D3)
	a.testControlAdmissionProbe = rebindOnce(a, p, replacement)

	var unreserved []uint64
	var sampled bool
	a.testControlWriteRefreshFails = func() bool {
		if !sampled {
			sampled = true
			unreserved = bracketedWithoutAReservation(a)
		}
		return false
	}

	if rec := controlWrite(t, a, p, "control"); rec.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !sampled {
		t.Fatal("the control write never reached its locked mutation")
	}
	if len(unreserved) != 0 {
		t.Fatalf("the control write opened the mutation sequence of item(s) %v "+
			"while holding no size reservation for them: it sampled one pathname "+
			"identity before the lock and mutated another under it, so the whole "+
			"bracket can run inside a refresh pin on the item it really touched",
			unreserved)
	}
	if len(bracketedWithoutAReservation(a)) != 0 {
		t.Fatal("a mutation sequence outlived the control write that opened it")
	}
}

// TestControlWriteReservesANameThatAppearedUnderTheLock is the absent-to-present
// half. Sampling nothing means reserving nothing, which is correct only for a
// name that is still absent under the lock.
func TestControlWriteReservesANameThatAppearedUnderTheLock(t *testing.T) {
	a, _ := newControlIdentityAttach(t, "ControlIdentityAppear")
	const p = "appeared.txt"

	const appeared = uint64(0x51D4)
	a.testControlAdmissionProbe = rebindOnce(a, p, appeared)

	var unreserved []uint64
	var sampled bool
	a.testControlWriteRefreshFails = func() bool {
		if !sampled {
			sampled = true
			unreserved = bracketedWithoutAReservation(a)
		}
		return false
	}

	if rec := controlWrite(t, a, p, "control"); rec.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !sampled {
		t.Fatal("the control write never reached its locked mutation")
	}
	if len(unreserved) != 0 {
		t.Fatalf("the control write bracketed item(s) %v that appeared at the "+
			"pathname after it had already decided to reserve nothing", unreserved)
	}
}

// TestGraftControlWriteRevalidatesTheIdentityItReserved is the same finding on
// the graft arm, whose mutation is a host-inode replacement bracketed by the
// same per-item sequence.
func TestGraftControlWriteRevalidatesTheIdentityItReserved(t *testing.T) {
	a := newAttach("att-graft-identity", "key", ensureAttachRequest{
		VolumeID: "vol-graft-identity", Branch: "main",
		MountPath: "/Volumes/GraftIdentity",
		Options:   AttachOptions{LocalDirs: []string{"cache"}},
	}, graftTestDir(t))
	if _, err := a.addLocalDirs([]string{"cache"}); err != nil {
		t.Fatal(err)
	}
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }
	const p = "cache/file.txt"

	a.mu.Lock()
	sampledRec := &itemRecord{
		item:  pfslocal.Item{ItemID: 0x61A1, ItemGeneration: 1},
		path:  p,
		state: clientcore.NewNodeState(0x61A1, true),
		attr:  fsproto.Attr{Kind: "file", Mode: 0o644},
		graft: true,
	}
	a.items[sampledRec.item.ItemID] = sampledRec
	a.paths[p] = sampledRec
	a.addItemAliasLocked(sampledRec)
	a.mu.Unlock()

	a.testControlAdmissionProbe = rebindOnce(a, p, 0x61A2)

	var unreserved []uint64
	var sampled bool
	a.testAfterLocalFileWrite = func(string) {
		if !sampled {
			sampled = true
			unreserved = bracketedWithoutAReservation(a)
		}
	}

	if rec := controlWrite(t, a, p, "fresh"); rec.Code != http.StatusNoContent {
		t.Fatalf("graft control write status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !sampled {
		t.Fatal("the graft control write never committed its host inode")
	}
	if len(unreserved) != 0 {
		t.Fatalf("the graft control write opened the mutation sequence of item(s) "+
			"%v while holding no size reservation for them: the name it reserved "+
			"and the name it mutated are different identities", unreserved)
	}
}
