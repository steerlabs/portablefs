package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

type fakeRemoteBaseBackend struct {
	proof         *backend.BaseProvenance
	proofErr      error
	manifest      []backend.Entry
	manifestCalls int
	objectCalls   int
}

func (f *fakeRemoteBaseBackend) BaseProvenance(_ context.Context, _ backend.BaseProvenanceRequest) (*backend.BaseProvenance, error) {
	return f.proof, f.proofErr
}

func (f *fakeRemoteBaseBackend) ManifestAt(_ context.Context, _ string) ([]backend.Entry, error) {
	f.manifestCalls++
	return f.manifest, nil
}

func (f *fakeRemoteBaseBackend) Blob(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("legacy blob route unexpectedly used")
}

func (f *fakeRemoteBaseBackend) HistoryObject(_ context.Context, _ string, _ uint64) ([]byte, error) {
	f.objectCalls++
	return nil, errors.New("history object route unexpectedly used")
}

func baseIdentity(record, control string) remoteBaseIdentity {
	return remoteBaseIdentity{
		TenantID: "tenant-a", CommitID: "commit-a", GenerationID: "generation-a",
		BaseSeq: 7, BaseDigest: strings.Repeat("a", 64),
		RecordCodec: record, ControlCodec: control,
	}
}

func TestResolveRemoteBaseNeverGuessesAcrossFamilies(t *testing.T) {
	t.Run("pft2 never calls manifest", func(t *testing.T) {
		fake := &fakeRemoteBaseBackend{proof: &backend.BaseProvenance{Kind: "pft2"}}
		resolved, err := resolveRemoteBase(context.Background(), fake, baseIdentity("pfj3", "pfc2"))
		if err != nil || resolved.proof.Kind != "pft2" {
			t.Fatalf("resolved %#v, %v", resolved, err)
		}
		if fake.manifestCalls != 0 || fake.objectCalls != 0 {
			t.Fatalf("manifest=%d object=%d", fake.manifestCalls, fake.objectCalls)
		}
	})

	t.Run("manifest never calls object serving", func(t *testing.T) {
		fake := &fakeRemoteBaseBackend{
			proof:    &backend.BaseProvenance{Kind: "manifest_v1"},
			manifest: []backend.Entry{{Path: "ok", Kind: "file"}},
		}
		resolved, err := resolveRemoteBase(context.Background(), fake, baseIdentity("pfj3", "pfc2"))
		if err != nil || len(resolved.entries) != 1 {
			t.Fatalf("resolved %#v, %v", resolved, err)
		}
		if fake.manifestCalls != 1 || fake.objectCalls != 0 {
			t.Fatalf("manifest=%d object=%d", fake.manifestCalls, fake.objectCalls)
		}
	})

	t.Run("unavailable proof is not manifest permission", func(t *testing.T) {
		fake := &fakeRemoteBaseBackend{proofErr: backend.ErrBaseProvenanceNotFound}
		if _, err := resolveRemoteBase(context.Background(), fake, baseIdentity("pfj3", "pfc2")); err == nil {
			t.Fatal("missing proof accepted")
		}
		if fake.manifestCalls != 0 {
			t.Fatalf("manifest called %d times", fake.manifestCalls)
		}
	})

	t.Run("pfr1 can never open pft2", func(t *testing.T) {
		fake := &fakeRemoteBaseBackend{proof: &backend.BaseProvenance{Kind: "pft2"}}
		if _, err := resolveRemoteBase(context.Background(), fake, baseIdentity("pfr1", "pfc1")); err == nil {
			t.Fatal("PFR1 PFT2 base accepted")
		}
		if fake.manifestCalls != 0 || fake.objectCalls != 0 {
			t.Fatalf("manifest=%d object=%d", fake.manifestCalls, fake.objectCalls)
		}
	})
}

func forkProof() *backend.BaseProvenance {
	return &backend.BaseProvenance{
		Kind: "pft2", BaseMode: "fork",
		Root: &backend.Pft2Root{
			Digest: strings.Repeat("b", 64), Size: "64",
			// A namespaced source root: high-water far beyond the flat cap.
			MaxInoSeen: "21474836481",
		},
		Allocator: &backend.Pft2Allocator{InodeNamespace: "6", NextLocal: "3", MaxInoSeen: "1"},
	}
}

func anchoredProof() *backend.BaseProvenance {
	return &backend.BaseProvenance{
		Kind: "pft2", BaseMode: "adopted",
		Root: &backend.Pft2Root{
			Digest: strings.Repeat("b", 64), Size: "64", MaxInoSeen: "21474836481",
		},
		Anchor: &backend.Pft2Anchor{
			AnchorID: "anchor-a", AsOfSeq: "7",
			RecoveryRootDigest: strings.Repeat("c", 64), RecoveryRootSize: "64",
			ControlRootDigest: strings.Repeat("d", 64), ControlRootSize: "64",
			InodeNamespace: "5", NextLocal: "9", MaxInoSeen: "21474836481",
		},
	}
}

// TestPft2BaseFromProofSeedsExactAllocator proves the WorkFS base contract
// is seeded from the PROVEN facts: a fork adopts the NEW branch's fresh
// namespace (never a flat allocator), an anchored base adopts the anchor's,
// and every internal contradiction fails closed.
func TestPft2BaseFromProofSeedsExactAllocator(t *testing.T) {
	t.Run("fork seeds the fresh branch namespace", func(t *testing.T) {
		base, err := pft2BaseFromProof(forkProof(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if base.RecoveryRoot != nil || base.AnchorAsOfSeq != 0 {
			t.Fatalf("fork base carries anchor state: %+v", base)
		}
		if base.InodeNamespace != 6 || base.NextLocal != 3 || base.AllocatorMaxInoSeen != 1 {
			t.Fatalf("fork allocator seeded wrongly: %+v", base)
		}
		if base.BaseSeq != 0 || base.RootMaxInoSeen != 21474836481 {
			t.Fatalf("fork base facts seeded wrongly: %+v", base)
		}
	})

	t.Run("fork without allocator fails closed", func(t *testing.T) {
		proof := forkProof()
		proof.Allocator = nil
		if _, err := pft2BaseFromProof(proof, 0); err == nil {
			t.Fatal("fork proof without allocator accepted")
		}
	})

	t.Run("adopted seeds the anchor allocator and as-of", func(t *testing.T) {
		base, err := pft2BaseFromProof(anchoredProof(), 7)
		if err != nil {
			t.Fatal(err)
		}
		if base.RecoveryRoot == nil || base.AnchorAsOfSeq != 7 || base.BaseSeq != 7 {
			t.Fatalf("adopted anchor state seeded wrongly: %+v", base)
		}
		if base.InodeNamespace != 5 || base.NextLocal != 9 || base.AllocatorMaxInoSeen != 21474836481 {
			t.Fatalf("adopted allocator seeded wrongly: %+v", base)
		}
	})

	t.Run("anchor high-water below the root fails closed", func(t *testing.T) {
		proof := anchoredProof()
		proof.Anchor.MaxInoSeen = "21474836480"
		if _, err := pft2BaseFromProof(proof, 7); err == nil ||
			!strings.Contains(err.Error(), "below root high-water") {
			t.Fatalf("undersized anchor accepted: %v", err)
		}
	})
}
