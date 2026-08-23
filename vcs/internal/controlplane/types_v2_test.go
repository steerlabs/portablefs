package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStateV2RejectsPlacementAndLifecycleCrossInvariantViolations(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	var base State
	if err := h.store.View(func(state State) error { base = state; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*State)
	}{
		{name: "ready without placement", mutate: func(state *State) { v := state.Volumes[volume.ID]; v.Placement = nil; state.Volumes[v.ID] = v }},
		{name: "sequence two legacy endpoint", mutate: func(state *State) {
			v := state.Volumes[volume.ID]
			v.PlacementSequence = 2
			v.Placement.Sequence = 2
			state.Volumes[v.ID] = v
		}},
		{name: "destroyed retains placement", mutate: func(state *State) {
			v := state.Volumes[volume.ID]
			v.State = VolumeDestroyed
			v.DeletionRequested = true
			v.DestroyedUnix = v.UpdatedUnix
			state.Volumes[v.ID] = v
		}},
		{name: "archiving missing attempt", mutate: func(state *State) {
			v := state.Volumes[volume.ID]
			v.State = VolumeArchiving
			v.ArchiveCycleStep = "quiescing"
			state.Volumes[v.ID] = v
		}},
		{name: "partial allocator bound", mutate: func(state *State) {
			cell := state.Cells[state.Volumes[volume.ID].Placement.CellID]
			cell.LastPort = 0
			state.Cells[cell.ID] = cell
		}},
		{name: "bounded allocator without declaration digest", mutate: func(state *State) {
			cell := state.Cells[state.Volumes[volume.ID].Placement.CellID]
			cell.RegistrationSHA256 = ""
			state.Cells[cell.ID] = cell
		}},
		{name: "placement outside allocator bound", mutate: func(state *State) {
			v := state.Volumes[volume.ID]
			cell := state.Cells[v.Placement.CellID]
			cell.LastPort = v.Placement.ListenPort - 1
			state.Cells[cell.ID] = cell
		}},
		// Archive capability is a relayed cell report, never an assumption a
		// never-observed cell gets for free.
		{name: "archive capability without observation", mutate: func(state *State) {
			unobserved := state.Cells[state.Volumes[volume.ID].Placement.CellID]
			unobserved.ID = "44444444-4444-4444-8444-444444444444"
			unobserved.LastObservedUnix = 0
			unobserved.LastManagerRelease, unobserved.LastAgentRelease, unobserved.LastHelperRelease = "", "", ""
			unobserved.Health = CellUnknown
			unobserved.ArchiveConfigured = true
			state.Cells[unobserved.ID] = unobserved
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, err := cloneState(base)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&state)
			if err := state.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
}

func TestArchiveRecordBoundsAreEnforced(t *testing.T) {
	record := ArchiveRecord{FormatVersion: 1, ChunkSizeBytes: 8 << 20, Attempt: "33333333-3333-4333-8333-333333333333", SealedEpoch: 1,
		SealedUnix: 1, Manifest: ObjectRef{Key: "manifest", SizeBytes: 1, SHA256: strings.Repeat("a", 64)},
		Packs: []ObjectRef{{Key: "pack", SizeBytes: 1, SHA256: strings.Repeat("b", 64)}}, RootDigest: strings.Repeat("c", 64),
		SealedAllocatedBytes: 4096, SealedInodes: 1, KeyVersion: "default"}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	tooMany := record
	tooMany.Packs = make([]ObjectRef, MaxArchivePacks+1)
	for i := range tooMany.Packs {
		tooMany.Packs[i] = record.Packs[0]
	}
	if err := tooMany.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pack bound = %v", err)
	}
	longKey := record
	longKey.Manifest.Key = strings.Repeat("k", MaxArchiveObjectKeyBytes+1)
	if err := longKey.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("key bound = %v", err)
	}
	// Seal-time measured usage is optional in both directions: absent (zero) for
	// records sealed before it existed, present for every new one.
	measured := record
	measured.SealedMeasuredBytes, measured.SealedMeasuredInodes = 1<<30, 4096
	if err := measured.Validate(); err != nil {
		t.Fatalf("measured record = %v", err)
	}
	if encoded, err := json.Marshal(record); err != nil || strings.Contains(string(encoded), "sealed_measured") {
		t.Fatalf("unmeasured record encoding = %s, %v", encoded, err)
	}
}
