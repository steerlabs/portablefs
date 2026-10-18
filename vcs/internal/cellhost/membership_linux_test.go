//go:build linux

package cellhost

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountmembership"
	"golang.org/x/sys/unix"
)

// Use the authority writer's shared encoder, not a second format fixture.
func membershipDocument(volumeID string, sessions ...[16]byte) string {
	records := make([]mountmembership.Record, len(sessions))
	for i, session := range sessions {
		records[i] = mountmembership.Record{SessionID: session, Profile: mountmembership.ProfileFSKitExclusive}
	}
	data, err := mountmembership.Encode(volumeID, records)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func writeMembership(t *testing.T, fixture *placementFixture, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(fixture.stateRoot, testVolumeID, mountmembership.Filename)
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
		"wrong header":     "INVALID\n" + hex.EncodeToString([]byte(testVolumeID)) + "\n",
		"header only":      mountmembership.Header + "\n",
		"another volume":   membershipDocument(other),
		"plaintext volume": mountmembership.Header + "\n" + testVolumeID + "\n",
		"short session":    membershipDocument(testVolumeID) + hex.EncodeToString(make([]byte, 8)) + "\tfskit-exclusive\n",
		"non-hex session":  membershipDocument(testVolumeID) + strings.Repeat("z", 32) + "\tfskit-exclusive\n",
		"zero session":     membershipDocument(testVolumeID) + session + "\tfskit-exclusive\n",
		"duplicate":        membershipDocument(testVolumeID, [16]byte{9}) + strings.TrimPrefix(membershipDocument(testVolumeID, [16]byte{9}), membershipDocument(testVolumeID)),
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

func TestStrictMembershipReadsEveryCurrentProfile(t *testing.T) {
	for _, profile := range []mountmembership.Profile{mountmembership.ProfileLinux, mountmembership.ProfileFSKitExclusive, mountmembership.ProfileCacheless} {
		t.Run(string(profile), func(t *testing.T) {
			fixture := newPlacementFixture(t)
			data, err := mountmembership.Encode(testVolumeID, []mountmembership.Record{{SessionID: [16]byte{1}, Profile: profile}})
			if err != nil {
				t.Fatal(err)
			}
			writeMembership(t, fixture, string(data), 0o600)
			if empty, err := fixture.host.StrictMembershipEmpty(testVolumeID); err != nil || empty {
				t.Fatalf("membership = %v, %v", empty, err)
			}
		})
	}
}

func TestStrictMembershipRejectsUnsafeFilesAndParents(t *testing.T) {
	for _, kind := range []string{"directory", "fifo", "oversized", "volume symlink", "root symlink"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newPlacementFixture(t)
			path := writeMembership(t, fixture, membershipDocument(testVolumeID), 0o600)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", mountmembership.MaxBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				parent := filepath.Dir(path)
				if kind == "root symlink" {
					parent = fixture.stateRoot
				}
				if err := os.Rename(parent, parent+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-real", parent); err != nil {
					t.Fatal(err)
				}
			}
			if empty, err := fixture.host.StrictMembershipEmpty(testVolumeID); err == nil || empty {
				t.Fatalf("unsafe membership = %v, %v", empty, err)
			}
		})
	}
}
