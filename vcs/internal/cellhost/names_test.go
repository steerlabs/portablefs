package cellhost

import (
	"errors"
	"regexp"
	"testing"
)

const testVolumeID = "22222222-2222-4222-8222-222222222222"

// TestPlacementServiceAccountNameKeepsTheV1NameAtSequenceOne pins the
// compatibility half of the derivation: a migrated v1 placement must keep the
// account it already owns, or the helper would try to create a second account
// for a UID that is already taken and verifyServiceIdentity would refuse.
func TestPlacementServiceAccountNameKeepsTheV1NameAtSequenceOne(t *testing.T) {
	name, err := PlacementServiceAccountName(testVolumeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if name != "pfs-eirceircejbcfarceirceircei" {
		t.Fatalf("v1 placement name = %q, want the v1 base32 name", name)
	}
}

func TestPlacementServiceAccountNameIsDeterministicAndPerPlacement(t *testing.T) {
	first, err := PlacementServiceAccountName(testVolumeID, 3)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := PlacementServiceAccountName(testVolumeID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if first != repeated {
		t.Fatalf("placement account derivation is not deterministic: %q then %q", first, repeated)
	}
	if first != "pfs-ewsvk2ffwdkpxz3z2drzpdgjyu" {
		t.Fatalf("placement 3 name = %q, want the pinned SHA-256 derivation", first)
	}
	seen := map[string]uint64{}
	for _, sequence := range []uint64{1, 2, 3, 4, 5, 1 << 32, ^uint64(0)} {
		name, err := PlacementServiceAccountName(testVolumeID, sequence)
		if err != nil {
			t.Fatalf("sequence %d: %v", sequence, err)
		}
		if len(name) > accountNameLimit || !regexp.MustCompile(`^pfs-[a-z2-7]{26}$`).MatchString(name) {
			t.Fatalf("sequence %d produced an unusable account name %q", sequence, name)
		}
		if previous, duplicate := seen[name]; duplicate {
			t.Fatalf("placements %d and %d share the account name %q; identity tuples are never reused",
				previous, sequence, name)
		}
		seen[name] = sequence
	}
	other, err := PlacementServiceAccountName("22222222-2222-4222-8222-222222222223", 3)
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("distinct volumes produced the same per-placement account name")
	}
}

func TestPlacementServiceAccountNameRefusesUnusableInput(t *testing.T) {
	for _, input := range []struct {
		volumeID string
		sequence uint64
	}{
		{testVolumeID, 0},
		{"", 1},
		{"not-a-uuid", 1},
		{"22222222-2222-4222-8222-22222222222", 1},
		{"../../etc/passwd", 1},
	} {
		if name, err := PlacementServiceAccountName(input.volumeID, input.sequence); !errors.Is(err, ErrInvalid) {
			t.Fatalf("PlacementServiceAccountName(%q, %d) = %q, %v; want ErrInvalid",
				input.volumeID, input.sequence, name, err)
		}
	}
}
