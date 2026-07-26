package backend

// Strict fork-allocator provenance validation (socket-free: these exercise
// the pure validator directly, so they run under network-restricted
// sandboxes too). A fork proof must carry the NEW branch's DB-issued
// allocator and no anchor; anchored modes must reject the fork-only arm;
// every value is canonical bounded decimal.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
)

func forkProofRequest() BaseProvenanceRequest {
	return BaseProvenanceRequest{
		TenantID: "tenant-a", CommitID: "commit-a", GenerationID: "generation-a",
		BaseSeq: 0, BaseDigest: strings.Repeat("0", 64),
		RecordCodec: "pfj3", ControlCodec: "pfc2",
	}
}

func validForkProof() *BaseProvenance {
	return &BaseProvenance{
		V: "1", Kind: "pft2", BaseMode: "fork",
		TenantID: "tenant-a", CommitID: "commit-a", VolumeID: "volume-a",
		BranchID: "branch-a", GenerationID: "generation-a", BaseSeq: "0",
		BaseDigest: strings.Repeat("0", 64), RecordCodec: "pfj3", ControlCodec: "pfc2",
		Root: &Pft2Root{
			Digest: strings.Repeat("b", 64), Size: "64",
			// A namespaced source root: high-water far beyond the flat cap.
			MaxInoSeen: "21474836481",
		},
		Allocator: &Pft2Allocator{InodeNamespace: "6", NextLocal: "1", MaxInoSeen: "1"},
	}
}

func TestForkProvenanceRequiresExactAllocator(t *testing.T) {
	if err := validateBaseProvenance(validForkProof(), forkProofRequest()); err != nil {
		t.Fatalf("valid fork proof rejected: %v", err)
	}
	maxIno, namespace, nextLocal, err := validForkProof().ForkAllocatorFacts()
	if err != nil || namespace != 6 || nextLocal != 1 || maxIno != 1 {
		t.Fatalf("fork allocator facts = (%d,%d,%d), %v", maxIno, namespace, nextLocal, err)
	}

	cases := []struct {
		name    string
		mutate  func(*BaseProvenance, *BaseProvenanceRequest)
		errPart string
	}{
		{"missing allocator", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator = nil },
			"missing the fresh branch allocator"},
		{"fork with anchor", func(p *BaseProvenance, _ *BaseProvenanceRequest) {
			p.Allocator = nil
			p.Anchor = &Pft2Anchor{
				AnchorID: "anchor-a", AsOfSeq: "0",
				RecoveryRootDigest: strings.Repeat("c", 64), RecoveryRootSize: "64",
				ControlRootDigest: strings.Repeat("d", 64), ControlRootSize: "64",
				InodeNamespace: "6", NextLocal: "1", MaxInoSeen: "1",
			}
		}, "unexpectedly contains a recovery anchor"},
		{"nonzero fork base seq", func(p *BaseProvenance, want *BaseProvenanceRequest) {
			want.BaseSeq = 7
			p.BaseSeq = "7"
		}, "seq-0 generation origin"},
		{"noncanonical namespace", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator.InodeNamespace = "06" },
			"not canonical decimal"},
		{"zero namespace", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator.InodeNamespace = "0" },
			"outside"},
		{"namespace beyond 31 bits", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator.InodeNamespace = "2147483648" },
			"outside"},
		{"zero next local", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator.NextLocal = "0" },
			"outside"},
		{"next local beyond exhaustion mark", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator.NextLocal = "4294967298" },
			"outside"},
		{"empty allocator max", func(p *BaseProvenance, _ *BaseProvenanceRequest) { p.Allocator.MaxInoSeen = "" },
			"not canonical decimal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := validForkProof()
			want := forkProofRequest()
			tc.mutate(proof, &want)
			err := validateBaseProvenance(proof, want)
			if err == nil {
				t.Fatal("contradictory fork proof accepted")
			}
			if !strings.Contains(err.Error(), tc.errPart) {
				t.Fatalf("rejection classified wrongly: %v (want %q)", err, tc.errPart)
			}
		})
	}
}

func TestAnchoredProvenanceRejectsForkAllocatorArm(t *testing.T) {
	raw, err := json.Marshal(validPft2Proof())
	if err != nil {
		t.Fatal(err)
	}
	var proof BaseProvenance
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	if err := validateBaseProvenance(&proof, proofRequest()); err != nil {
		t.Fatalf("valid adopted proof rejected: %v", err)
	}
	proof.Allocator = &Pft2Allocator{InodeNamespace: "6", NextLocal: "1", MaxInoSeen: "1"}
	if err := validateBaseProvenance(&proof, proofRequest()); err == nil ||
		!strings.Contains(err.Error(), "fork allocator") {
		t.Fatalf("anchored proof with fork allocator accepted: %v", err)
	}

	manifest := &BaseProvenance{
		V: "1", Kind: "manifest_v1",
		TenantID: "tenant-a", CommitID: "commit-a", VolumeID: "volume-a",
		BranchID: "branch-a", GenerationID: "generation-a", BaseSeq: "7",
		BaseDigest: strings.Repeat("a", 64), RecordCodec: "pfj3", ControlCodec: "pfc2",
		Allocator: &Pft2Allocator{InodeNamespace: "6", NextLocal: "1", MaxInoSeen: "1"},
	}
	if err := validateBaseProvenance(manifest, proofRequest()); err == nil ||
		!strings.Contains(err.Error(), "PFT2 fields") {
		t.Fatalf("manifest proof with allocator accepted: %v", err)
	}
}

func TestAnchorAsOfAccessorBounds(t *testing.T) {
	raw, err := json.Marshal(validPft2Proof())
	if err != nil {
		t.Fatal(err)
	}
	var proof BaseProvenance
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	asOf, err := proof.AnchorAsOf()
	if err != nil || asOf != 7 {
		t.Fatalf("anchor as-of = %d, %v", asOf, err)
	}
	proof.Anchor.AsOfSeq = "007"
	if _, err := proof.AnchorAsOf(); err == nil {
		t.Fatal("noncanonical as-of accepted")
	}
	var fork *BaseProvenance
	if _, err := fork.AnchorAsOf(); err == nil {
		t.Fatal("nil proof answered an anchor sequence")
	}
	if _, _, _, err := validForkProof().AnchorFacts(); err == nil {
		t.Fatal("fork proof answered anchor facts")
	}
	if _, err := validForkProof().RecoveryRootRef(); err == nil {
		t.Fatal("fork proof answered a recovery root")
	}
	if maxIno, err := validForkProof().RootMaxInoSeen(); err != nil || maxIno != 21474836481 {
		t.Fatalf("fork root high-water = %d, %v", maxIno, err)
	}
	if uint64(21474836481)>>32 < 1 || uint64(21474836481) <= uint64(pft2.MaxInodeLocalCounter) {
		t.Fatal("fixture root high-water no longer exceeds the flat allocator cap")
	}
}
