//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
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

	runTool := func(tool string, args ...string) []byte {
		t.Helper()
		out, err := exec.Command(tool, args...).Output()
		if err != nil {
			var stderr []byte
			if exit, ok := err.(*exec.ExitError); ok {
				stderr = exit.Stderr
			}
			t.Fatalf("%s %v: %v: %s%s", tool, args, err, out, stderr)
		}
		return out
	}
	run := func(args ...string) []byte { t.Helper(); return runTool("/usr/bin/hdiutil", args...) }
	run("create", "-quiet", "-size", "64m", "-fs", "APFS", "-volname", "PFSNotificationTest", image)
	device := ""
	t.Cleanup(func() {
		if device != "" {
			run("detach", "-force", device)
		}
	})
	attach := func() {
		t.Helper()
		out := run("attach", "-plist", "-nobrowse", "-mountpoint", mount, image)
		convert := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
		convert.Stdin = bytes.NewReader(out)
		converted, err := convert.CombinedOutput()
		if err != nil {
			t.Fatalf("decode attach plist: %v: %s", err, converted)
		}
		var result struct {
			Entities []struct {
				Device  string `json:"dev-entry"`
				Content string `json:"content-hint"`
				Mount   string `json:"mount-point"`
			} `json:"system-entities"`
		}
		if err := json.Unmarshal(converted, &result); err != nil {
			t.Fatal(err)
		}
		mounted := false
		for _, entity := range result.Entities {
			if entity.Content == "GUID_partition_scheme" {
				device = entity.Device
			}
			if entity.Mount == mount {
				mounted = true
			}
		}
		if device == "" || !mounted {
			t.Fatalf("attach did not identify its whole disk and mount: %s", out)
		}
	}
	detach := func() {
		t.Helper()
		// APFS volumes live on a synthesized disk, distinct from the attached
		// image's whole disk. Disk Arbitration must finish unmounting all of them
		// before image ejection. A partial detach can already have removed the
		// mount path, so retain the exact attach identity through both operations.
		runTool("/usr/sbin/diskutil", "unmountDisk", "force", device)
		run("detach", "-force", device)
		device = ""
	}
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
	attach()
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
	detach()
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
	attach()
	detach()
	wait(late)
	if present, err := recordedKernelMountPresent(&st); err != nil || present {
		t.Fatalf("coalesced events changed absence evidence: %v %v", present, err)
	}
	attach()
	if _, err := recordedKernelMountPresent(&st); err == nil {
		t.Fatal("reused mount coordinates did not produce identity refusal")
	}
}
