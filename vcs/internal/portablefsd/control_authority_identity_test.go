package portablefsd

// ── FINDING 2 (ROUND 14): THE REGISTRY IS NOT THE AUTHORITY ─────────────────
//
// Round 13 made a control write compare the identity it reserved before the
// namespace gate with the identity the name resolves to under it. Both readings
// come from the LOCAL registry, and the local registry is exactly the thing a
// remote namespace change makes wrong: nsMu and the name stripes fence this
// daemon's frontends, and nothing at all fences a peer's.
//
//	the registry binds p -> A, so admission reserves A and phase 3 sees A;
//	a peer renames B over p at the authority (or the registry is simply behind);
//	vol.Lookup(p) answers B.
//
// From there the handler adopted B's inode into A's NodeState when it had none
// — and asked nothing at all when it had one — then opened, wrote and truncated
// B while holding A's reservation and A's mutation sequence. B's mutation could
// therefore complete inside B's own outstanding refresh syscall: the exact
// linearization failure the size token exists to make impossible.
//
// The authority's answer is the FINAL target resolution, so it is proved
// against the reserved identity before anything is opened or mutated. A
// mismatch — an inode that differs, or an authority object where the reserved
// NodeState had no authority identity at all — is a legitimate coherence fact:
// REGISTER it, publish the namespace change it implies, and unwind to pre-lock
// admission so the item that is really there is the item that is really
// reserved. What may never happen is what did: binding an unproven pre-lock
// NodeState to the lookup's inode and mutating through it in the same attempt.

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// controlWriteAttempt records one admission-and-mutation attempt of a control
// write: what it RESERVED, and what it went on to MUTATE.
type controlWriteAttempt struct {
	// item and authority are the frontend item this attempt reserved and the
	// authority identity that item carried at the moment of the reservation.
	item      uint64
	authority uint64
	// mutated is the authority inode the handler actually reached, and reserved
	// is the reservation this daemon held for the frontend item naming it.
	mutated  uint64
	reserved int
}

// watchControlWriteIdentity records, per attempt, the identity reserved at
// pre-lock admission and the authority identity finally mutated under it.
func watchControlWriteIdentity(a *attach, p string, peer func()) *[]controlWriteAttempt {
	attempts := &[]controlWriteAttempt{}
	var once sync.Once
	a.testControlAdmissionProbe = func(context.Context) {
		a.mu.RLock()
		att := controlWriteAttempt{}
		if rec := a.paths[p]; rec != nil {
			att.item = rec.item.ItemID
			att.authority = rec.state.AuthorityIno()
		}
		a.mu.RUnlock()
		*attempts = append(*attempts, att)
		if peer != nil {
			once.Do(peer)
		}
	}
	a.testControlWriteAuthorityTarget = func(ino uint64) {
		if len(*attempts) == 0 {
			return
		}
		att := &(*attempts)[len(*attempts)-1]
		att.mutated = ino
		a.mu.RLock()
		att.reserved = a.sizeMutationReservations[att.item]
		a.mu.RUnlock()
	}
	return attempts
}

func requireProvenAuthorityTarget(t *testing.T, attempts []controlWriteAttempt) {
	t.Helper()
	var mutated []controlWriteAttempt
	for _, att := range attempts {
		if att.mutated != 0 {
			mutated = append(mutated, att)
		}
	}
	if len(mutated) == 0 {
		t.Fatal("the control write never reached its authority mutation")
	}
	for _, att := range mutated {
		if att.authority != att.mutated {
			t.Fatalf("a control write reserved frontend item %d — whose proven "+
				"authority identity was %d — and then mutated authority inode %d "+
				"under that reservation\n"+
				"the local registry cannot fence a remote namespace change, so the "+
				"lookup's identity has to be PROVED against the reserved item "+
				"before anything is opened or mutated; adopting it mid-handler "+
				"means this write's whole bracket can open and close inside a "+
				"refresh pin on the object it really touched",
				att.item, att.authority, att.mutated)
		}
		if att.reserved == 0 {
			t.Fatalf("a control write mutated authority inode %d while holding no "+
				"size reservation for the frontend item %d that names it",
				att.mutated, att.item)
		}
	}
}

// bindUnprovenItem binds p to a frontend item with no authority identity at
// all: the ordinary state of a locally-born item whose delegated create has not
// been reconciled with the authority yet, and the state controlWriteLocked
// derives for any name it has no record of.
func bindUnprovenItem(a *attach, p string, itemID uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := &itemRecord{
		item:  pfslocal.Item{ItemID: itemID, ItemGeneration: 1},
		path:  p,
		state: clientcore.NewNodeState(0, false),
		attr:  fsproto.Attr{Kind: "file", Mode: 0o644},
	}
	a.items[itemID] = rec
	a.paths[p] = rec
	a.addItemAliasLocked(rec)
}

// TestControlWriteProvesAnAuthorityTargetItHasNotBound is the finding's
// headline: the reserved item carries no authority identity, so the handler
// adopted whatever the lookup returned and mutated it in the same attempt.
func TestControlWriteProvesAnAuthorityTargetItHasNotBound(t *testing.T) {
	a, vol := newControlIdentityAttach(t, "AuthorityUnbound")
	ctx := context.Background()
	const p = "target.txt"
	const peer = "peer.txt"

	peerAttr, st := vol.Create(ctx, peer, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create %s: %d", peer, st)
	}
	// The registry names p; the authority does not, yet.
	const local = uint64(0x51E1)
	bindUnprovenItem(a, p, local)

	attempts := watchControlWriteIdentity(a, p, func() {
		if st := vol.Rename(ctx, peer, p, nil, nil); st != fsproto.OK {
			t.Errorf("peer rename %s -> %s: %d", peer, p, st)
		}
	})

	if rr := controlWrite(t, a, p, "control"); rr.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", rr.Code, rr.Body.String())
	}
	last := (*attempts)[len(*attempts)-1]
	if last.mutated != peerAttr.Ino {
		t.Fatalf("the control write mutated authority inode %d, not the peer's %d: "+
			"the interleaving this test exists to pin did not happen",
			last.mutated, peerAttr.Ino)
	}
	requireProvenAuthorityTarget(t, *attempts)
	if len(bracketedWithoutAReservation(a)) != 0 {
		t.Fatal("a mutation sequence outlived the control write that opened it")
	}
}

// TestControlWriteProvesAnAuthorityTargetThatReplacedTheOneItReserved is the
// other half of the same line: the reserved item DOES carry an authority
// identity, and the handler compared it with nothing.
func TestControlWriteProvesAnAuthorityTargetThatReplacedTheOneItReserved(t *testing.T) {
	a, vol := newControlIdentityAttach(t, "AuthorityReplaced")
	ctx := context.Background()
	const p = "target.txt"
	const peer = "peer.txt"
	const survivor = "survivor.txt"

	original, st := vol.Create(ctx, p, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create %s: %d", p, st)
	}
	peerAttr, st := vol.Create(ctx, peer, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create %s: %d", peer, st)
	}
	a.mu.Lock()
	rec := a.registerLocked(p, original)
	a.mu.Unlock()
	if rec == nil {
		t.Fatal("could not register the pre-existing item")
	}

	attempts := watchControlWriteIdentity(a, p, func() {
		// The reserved inode is still very much alive — it simply is not at
		// this pathname any more.
		if st := vol.Rename(ctx, p, survivor, nil, nil); st != fsproto.OK {
			t.Errorf("peer rename %s -> %s: %d", p, survivor, st)
		}
		if st := vol.Rename(ctx, peer, p, nil, nil); st != fsproto.OK {
			t.Errorf("peer rename %s -> %s: %d", peer, p, st)
		}
	})

	if rr := controlWrite(t, a, p, "control"); rr.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", rr.Code, rr.Body.String())
	}
	last := (*attempts)[len(*attempts)-1]
	if last.mutated != peerAttr.Ino {
		t.Fatalf("the control write mutated authority inode %d, not the peer's %d: "+
			"the interleaving this test exists to pin did not happen",
			last.mutated, peerAttr.Ino)
	}
	requireProvenAuthorityTarget(t, *attempts)
	if len(bracketedWithoutAReservation(a)) != 0 {
		t.Fatal("a mutation sequence outlived the control write that opened it")
	}
}

// TestControlWriteProvesTheAuthorityTargetItCreated is the second site with the
// same shape. The authority no longer has the name at all, so the handler's own
// Create mints a replacement and the registry rebinds the pathname to it — while
// the reservation and the bracket are still held against the identity that was
// displaced.
func TestControlWriteProvesTheAuthorityTargetItCreated(t *testing.T) {
	a, vol := newControlIdentityAttach(t, "AuthorityRecreated")
	ctx := context.Background()
	const p = "target.txt"
	const survivor = "survivor.txt"

	original, st := vol.Create(ctx, p, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create %s: %d", p, st)
	}
	a.mu.Lock()
	rec := a.registerLocked(p, original)
	a.mu.Unlock()
	if rec == nil {
		t.Fatal("could not register the pre-existing item")
	}

	attempts := watchControlWriteIdentity(a, p, func() {
		if st := vol.Rename(ctx, p, survivor, nil, nil); st != fsproto.OK {
			t.Errorf("peer rename %s -> %s: %d", p, survivor, st)
		}
	})

	if rr := controlWrite(t, a, p, "control"); rr.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", rr.Code, rr.Body.String())
	}
	last := (*attempts)[len(*attempts)-1]
	if last.mutated == 0 || last.mutated == original.Ino {
		t.Fatalf("the control write mutated authority inode %d rather than a "+
			"replacement it created: the interleaving this test exists to pin did "+
			"not happen", last.mutated)
	}
	requireProvenAuthorityTarget(t, *attempts)
	if len(bracketedWithoutAReservation(a)) != 0 {
		t.Fatal("a mutation sequence outlived the control write that opened it")
	}
}
