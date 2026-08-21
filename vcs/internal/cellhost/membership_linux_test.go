//go:build linux

package cellhost

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// membershipDocument builds the record in the writer's exact format
// (volumeserver/visibility_membership.go persistLocked): header line, the hex
// of the volume ID's own bytes, then one hex session ID per active line. The
// helper's parser is tested against these bytes rather than against the
// authority's code, because the file - not the package - is the interface.
func membershipDocument(volumeID string, sessions ...[16]byte) string {
	var builder strings.Builder
	builder.WriteString(visibilityMembershipHeader + "\n")
	builder.WriteString(hex.EncodeToString([]byte(volumeID)) + "\n")
	for _, session := range sessions {
		builder.WriteString(hex.EncodeToString(session[:]) + "\n")
	}
	return builder.String()
}

func writeMembership(t *testing.T, fixture *placementFixture, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(fixture.stateRoot, testVolumeID, visibilityMembershipName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestStrictMembershipEmptyReadsTheDurableRecord covers the two answers the
// archive gate acts on. An empty record is the machine proof that replaces the
// operator strict-fence attestation, so "empty" has to mean exactly empty.
func TestStrictMembershipEmptyReadsTheDurableRecord(t *testing.T) {
	fixture := newPlacementFixture(t)
	path := writeMembership(t, fixture, membershipDocument(testVolumeID), 0o600)

	empty, err := fixture.host.StrictMembershipEmpty(testVolumeID)
	if err != nil || !empty {
		t.Fatalf("empty membership = %v, %v", empty, err)
	}

	writeMembership(t, fixture, membershipDocument(testVolumeID,
		[16]byte{1}, [16]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}), 0o600)
	empty, err = fixture.host.StrictMembershipEmpty(testVolumeID)
	if err != nil || empty {
		t.Fatalf("populated membership = %v, %v", empty, err)
	}

	// No record was ever written: no strict mount was ever admitted.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	empty, err = fixture.host.StrictMembershipEmpty(testVolumeID)
	if err != nil || !empty {
		t.Fatalf("absent membership = %v, %v", empty, err)
	}
	// The whole state directory can be absent for the same reason.
	if err := removeTreeBeneath(fixture.stateRoot, testVolumeID); err != nil {
		t.Fatal(err)
	}
	empty, err = fixture.host.StrictMembershipEmpty(testVolumeID)
	if err != nil || !empty {
		t.Fatalf("absent state directory = %v, %v", empty, err)
	}
}

// TestStrictMembershipEmptyFailsClosedOnAnythingUnreadable: this answer gates
// destroying a volume's data. Anything that is not an intact, private, own-
// volume record is an error, never an emptiness claim.
func TestStrictMembershipEmptyFailsClosedOnAnythingUnreadable(t *testing.T) {
	other := "22222222-2222-4222-8222-222222222223"
	session := hex.EncodeToString(make([]byte, 16))
	cases := map[string]string{
		"empty file":       "",
		"wrong header":     "PFS-VISIBILITY-2\n" + hex.EncodeToString([]byte(testVolumeID)) + "\n",
		"header only":      visibilityMembershipHeader + "\n",
		"another volume":   membershipDocument(other),
		"plaintext volume": visibilityMembershipHeader + "\n" + testVolumeID + "\n",
		"short session":    membershipDocument(testVolumeID) + hex.EncodeToString(make([]byte, 8)) + "\n",
		"non-hex session":  membershipDocument(testVolumeID) + "not-hex\n",
		"zero session":     membershipDocument(testVolumeID) + session + "\n",
		"duplicate":        membershipDocument(testVolumeID, [16]byte{9}, [16]byte{9}),
	}
	for name, contents := range cases {
		fixture := newPlacementFixture(t)
		writeMembership(t, fixture, contents, 0o600)
		empty, err := fixture.host.StrictMembershipEmpty(testVolumeID)
		if err == nil {
			t.Fatalf("%s: StrictMembershipEmpty = %v, nil; want an error", name, empty)
		}
		if empty {
			t.Fatalf("%s: a failed read reported the membership empty", name)
		}
	}

	loose := newPlacementFixture(t)
	writeMembership(t, loose, membershipDocument(testVolumeID), 0o644)
	if _, err := loose.host.StrictMembershipEmpty(testVolumeID); err == nil {
		t.Fatal("a world-readable membership record was accepted")
	}

	linked := newPlacementFixture(t)
	path := writeMembership(t, linked, membershipDocument(testVolumeID), 0o600)
	elsewhere := filepath.Join(linked.stateRoot, testVolumeID, "elsewhere")
	if err := os.Rename(path, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal(err)
	}
	if _, err := linked.host.StrictMembershipEmpty(testVolumeID); err == nil {
		t.Fatal("a symlinked membership path was followed")
	}

	if _, err := linked.host.StrictMembershipEmpty("not-a-uuid"); err == nil {
		t.Fatal("an invalid volume ID was accepted")
	}
}
