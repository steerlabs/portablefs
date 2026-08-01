package fsproto

import "testing"

// TestRequestFlagWireValuesArePinned pins every PFRQ request flag to its
// exact wire bit. These values are shared with every deployed peer: a
// renumbering is a total, symmetric wire break (an in-tree build shifts
// encoder and decoder together, so only an explicit pin can catch it —
// this regression shipped once, as an iota chain silently renumbered by an
// unrelated const added to the same block).
func TestRequestFlagWireValuesArePinned(t *testing.T) {
	pins := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"OrphanTarget", requestFlagOrphanTarget, 1 << 9},
		{"Append", requestFlagAppend, 1 << 10},
		{"SetMode", requestFlagSetMode, 1 << 11},
		{"SetTime", requestFlagSetTime, 1 << 12},
		{"SetUID", requestFlagSetUID, 1 << 13},
		{"SetGID", requestFlagSetGID, 1 << 14},
		{"LockWrite", requestFlagLockWrite, 1 << 15},
		{"LockUnlock", requestFlagLockUnlock, 1 << 16},
		{"OpenState", requestFlagOpenState, 1 << 17},
		{"RegisterOpen", requestFlagRegisterOpen, 1 << 18},
		{"Excl", requestFlagExcl, 1 << 19},
		{"Envelope", requestFlagEnvelope, 1 << 20},
		{"SetATime", requestFlagSetATime, 1 << 21},
		{"SetFlags", requestFlagSetFlags, 1 << 22},
	}
	for _, p := range pins {
		if p.got != p.want {
			t.Errorf("requestFlag%s = %#x, want %#x: request flag bits are wire values shared with deployed peers and must never renumber", p.name, p.got, p.want)
		}
	}
	// The known-flags mask must be exactly the union of the pinned bits: a
	// new flag must be added to both this test and the mask deliberately.
	var want uint32
	for _, p := range pins {
		want |= p.want
	}
	if requestKnownFlags != want {
		t.Errorf("requestKnownFlags = %#x, want %#x (the union of the pinned bits)", requestKnownFlags, want)
	}
}
