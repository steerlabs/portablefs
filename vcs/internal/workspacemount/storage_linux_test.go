//go:build linux

package workspacemount

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestRootStableBackingAndAcknowledgedMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root backing and UID 1000 ownership")
	}
	root := t.TempDir()
	m := &Manager{Inventory: inventory(t), Clients: filepath.Join(root, "clients"), Backing: filepath.Join(root, "backing")}
	for _, p := range []string{m.Clients, m.Backing} {
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	d := desired(1)
	if err := m.Inventory.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	first, err := m.backingRoot(d.Mount)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(first, "local-data")
	if err = os.WriteFile(data, []byte("survives replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	next := desired(2)
	again, err := m.backingRoot(next.Mount)
	if err != nil || first != again {
		t.Fatal("incarnation replaced local data", again, err)
	}
	other := desired(3)
	other.Mount.AuthorityId[0]++
	foreign, err := m.backingRoot(other.Mount)
	if err != nil || foreign == first {
		t.Fatal("authority aliased local backing", err)
	}
	client := filepath.Join(m.Clients, d.Witness.Intent)
	if err = os.Mkdir(client, 0700); err != nil {
		t.Fatal(err)
	}
	if err = m.Acknowledge([]*pb.MountID{d.Mount}); err == nil {
		t.Fatal("live metadata removed")
	}
	if _, err = os.Stat(client); err != nil {
		t.Fatal(err)
	}
	if err = m.Inventory.Reconcile(d.Mount, func(*Desired) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = m.Acknowledge([]*pb.MountID{d.Mount}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(client); !os.IsNotExist(err) {
		t.Fatal("ack retained incarnation metadata", err)
	}
	if value, err := os.ReadFile(data); err != nil || string(value) != "survives replacement" {
		t.Fatal("ack erased machine local data", err)
	}
	if len(m.Inventory.Snapshot()) != 0 {
		t.Fatal("ack retained root record")
	}
	if err = os.Chmod(first, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = m.backingRoot(d.Mount); err == nil {
		t.Fatal("adopted unequal local ownership")
	}
	if err = os.RemoveAll(first); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(foreign, first); err != nil {
		t.Fatal(err)
	}
	if _, err = m.backingRoot(d.Mount); err == nil {
		t.Fatal("followed foreign local backing symlink")
	}
}

func TestRootRecreatesOnlyProtectedColdTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root target pin boundary")
	}
	m := &Manager{Targets: t.TempDir()}
	id := desired(1).Mount
	target, old, err := m.protectedTarget(id)
	if err != nil {
		t.Fatal(err)
	}
	target.Close()
	path := filepath.Join(m.Targets, id.VolumeId)
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target, next, err := m.protectedTarget(id)
	if err != nil || next.Mode&0777 != 0 || next.Uid != 0 || next.Gid != 0 {
		t.Fatal("cold target was not protected", old, next, err)
	}
	target.Close()
	if err = os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.protectedTarget(id); err == nil {
		t.Fatal("adopted writable target")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(m.Targets, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.protectedTarget(id); err == nil {
		t.Fatal("followed replaced target")
	}
}
