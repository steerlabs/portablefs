package restoremode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestQuiesceProofIsWrittenOnlyUnderEmptyMembershipLock(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "config")
	stateRoot := filepath.Join(root, "state")
	for _, dir := range []string{configRoot, stateRoot} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	membership, _, err := volumeserver.OpenFileVisibilityMembership(filepath.Join(stateRoot, "visibility.membership"), "volume-a", false)
	if err != nil {
		t.Fatal(err)
	}
	defer membership.Close()
	id := volumeserver.SessionID{1}
	if err := membership.Activate(id); err != nil {
		t.Fatal(err)
	}
	nonce := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := writeAtomicJSON(filepath.Join(configRoot, QuiesceRequest), quiesceRequest{Nonce: nonce, RequestedUnix: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	watcher, err := NewQuiesceWatcher(context.Background(), QuiesceConfig{
		ConfigRoot: configRoot, StateRoot: stateRoot, VolumeID: "volume-a", AuthorityEpoch: 9,
		WireEpoch: volumeserver.Epoch{7}, Membership: membership, PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if _, err := os.Stat(filepath.Join(stateRoot, QuiesceProof)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proof while membership active: %v", err)
	}
	if err := membership.Activate(volumeserver.SessionID{2}); !errors.Is(err, volumeserver.ErrQuiescing) {
		t.Fatalf("strict attach during quiesce = %v", err)
	}
	if err := membership.Deactivate(id); err != nil {
		t.Fatal(err)
	}
	var proof quiesceProof
	if err := readStrictJSON(filepath.Join(stateRoot, QuiesceProof), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Nonce != nonce || !proof.MembershipEmpty || proof.AuthorityEpoch != 9 || proof.WireSessionEpochHex != "07000000000000000000000000000000" {
		t.Fatalf("proof = %+v", proof)
	}
	if err := os.Remove(filepath.Join(configRoot, QuiesceRequest)); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Check(); err != nil {
		t.Fatal(err)
	}
	if err := membership.Activate(volumeserver.SessionID{3}); err != nil {
		t.Fatalf("strict attach after cancellation = %v", err)
	}
}

func TestQuiesceWatcherRefusesMissingMembership(t *testing.T) {
	root := t.TempDir()
	if _, err := NewQuiesceWatcher(context.Background(), QuiesceConfig{ConfigRoot: root, StateRoot: root, VolumeID: "v"}); err == nil {
		t.Fatal("watcher accepted missing durable membership")
	}
}
