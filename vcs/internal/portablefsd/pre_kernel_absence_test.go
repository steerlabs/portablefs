package portablefsd

import (
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

func TestPlannedFSKitMountAbsenceUsesAttemptSourceAcrossWholeInventory(t *testing.T) {
	const (
		path = "/Volumes/PortableFSStartup"
		ref  = "att_AAAAAAAAAAAAAAAAAAAAAA"
	)
	observed := time.Unix(1_700_000_000, 123)
	proof, err := plannedFSKitMountAbsenceProof([]fskitKernelMount{
		{path: path, fsType: "apfs", source: "/dev/disk9s1"},
		{path: "/", fsType: "apfs", source: "/dev/disk3s1"},
	}, path, ref, observed)
	if err != nil {
		t.Fatal(err)
	}
	wantSource := fskitidentity.ResourcePrefix + ref
	if proof.GetObservedUnixNanos() != observed.UnixNano() || proof.GetComponent() != v3DetachProofComponent ||
		!strings.Contains(string(proof.GetObservation()), "mount-source="+wantSource) ||
		!strings.Contains(string(proof.GetObservation()), "records=2") {
		t.Fatalf("absence proof = %+v", proof)
	}
	// A foreign filesystem at the intended path is not this attach and must
	// not prevent releasing this attach's ACTIVE membership.
}

func TestPlannedFSKitMountAbsenceRefusesAttemptSourceAtAnyPath(t *testing.T) {
	const ref = "att_BBBBBBBBBBBBBBBBBBBBBB"
	_, err := plannedFSKitMountAbsenceProof([]fskitKernelMount{
		{path: "/Volumes/Unexpected", fsType: fskitidentity.FSType, source: fskitidentity.ResourcePrefix + ref},
	}, "/Volumes/Intended", ref, time.Now())
	if err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("installed attempt source verdict = %v", err)
	}
}

func TestPlannedFSKitMountAbsenceRefusesEmptyInventory(t *testing.T) {
	_, err := plannedFSKitMountAbsenceProof(nil, "/Volumes/Intended", "att_CCCCCCCCCCCCCCCCCCCCCC", time.Now())
	if err == nil || !strings.Contains(err.Error(), "no mount records") {
		t.Fatalf("empty getfsstat inventory verdict = %v", err)
	}
}
