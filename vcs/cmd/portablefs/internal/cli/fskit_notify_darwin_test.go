//go:build darwin

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFSKitNativeGlobalMountNotification(t *testing.T) {
	watcher, err := newFSKitMountWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.close()
	root := t.TempDir()
	image := filepath.Join(root, "events.dmg")
	mount := filepath.Join(root, "mounted")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("/usr/bin/hdiutil", args...).CombinedOutput(); err != nil {
			t.Fatalf("hdiutil %v: %v: %s", args, err, out)
		}
	}
	run("create", "-quiet", "-size", "64m", "-fs", "APFS", "-volname", "PFSNotificationTest", image)
	mounted := false
	t.Cleanup(func() {
		if mounted {
			run("detach", "-quiet", mount)
		}
	})
	wait := func(w fsKitMountWatcher) {
		t.Helper()
		select {
		case err, ok := <-w.events():
			if !ok || err != nil {
				t.Fatalf("native notification: %v (open %v)", err, ok)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no native EVFILT_FS mount notification")
		}
	}
	// The first watcher is registered before these real mount/unmount events.
	run("attach", "-quiet", "-nobrowse", "-mountpoint", mount, image)
	mounted = true
	wait(watcher)
	if mounts, err := darwinMountTable(); err != nil {
		t.Fatal(err)
	} else {
		found := false
		for _, entry := range mounts {
			if entry.path == mount {
				found = true
			}
		}
		if !found {
			t.Fatal("native mount notification did not correspond to current inventory")
		}
	}
	// Register a second watcher while present. Both observe the same global
	// coalescible unmount, and inventory (not flags) proves exact absence.
	second, err := newFSKitMountWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	run("detach", "-quiet", mount)
	mounted = false
	wait(watcher)
	wait(second)
	st := validFSKitMountState(t, mount)
	if present, err := recordedKernelMountPresent(&st); err != nil || present {
		t.Fatalf("exact absence after native unmount: %v %v", present, err)
	}
	// An unmount before registration is not expected to be replayed. The first
	// snapshot after successful registration must establish its absence.
	late, err := newFSKitMountWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer late.close()
	if present, err := recordedKernelMountPresent(&st); err != nil || present {
		t.Fatalf("absence preceding registration: %v %v", present, err)
	}
	// Queue unrelated mount-table changes without consuming either event. They
	// may coalesce; the wake is never a receipt for this attach's absence.
	run("attach", "-quiet", "-nobrowse", "-mountpoint", mount, image)
	mounted = true
	run("detach", "-quiet", mount)
	mounted = false
	wait(late)
	if present, err := recordedKernelMountPresent(&st); err != nil || present {
		t.Fatalf("coalesced events changed absence evidence: %v %v", present, err)
	}
	run("attach", "-quiet", "-nobrowse", "-mountpoint", mount, image)
	mounted = true
	if _, err := recordedKernelMountPresent(&st); err == nil {
		t.Fatal("reused mount coordinates did not produce identity refusal")
	}
}
