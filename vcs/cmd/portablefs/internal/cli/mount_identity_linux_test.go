//go:build linux

package cli

import (
	"strings"
	"testing"
)

func TestVerifyLinuxRecordedMountRequiresUniqueExactKernelObject(t *testing.T) {
	st := &mountState{
		MountPath:       "/mnt/work",
		Strategy:        "fuse",
		MountInstanceID: "mnt_AAAAAAAAAAAAAAAAAAAAAA",
		KernelMountID:   "42",
	}
	exact := linuxMountInfoEntry{
		id: "42", mountPoint: st.MountPath, fsType: "fuse.portablefs",
		source: "portablefs:" + st.MountInstanceID,
	}
	if err := verifyLinuxRecordedMountEntries(st, []linuxMountInfoEntry{exact}); err != nil {
		t.Fatal(err)
	}
	t.Run("stacked foreign top", func(t *testing.T) {
		foreign := linuxMountInfoEntry{id: "43", mountPoint: st.MountPath, fsType: "tmpfs", source: "tmpfs"}
		err := verifyLinuxRecordedMountEntries(st, []linuxMountInfoEntry{exact, foreign})
		if err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("path reused", func(t *testing.T) {
		reused := exact
		reused.id = "43"
		err := verifyLinuxRecordedMountEntries(st, []linuxMountInfoEntry{reused})
		if err == nil || !strings.Contains(err.Error(), "want exact id 42") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("foreign object", func(t *testing.T) {
		foreign := linuxMountInfoEntry{id: "42", mountPoint: st.MountPath, fsType: "fuse.sshfs", source: "host:/work"}
		if err := verifyLinuxRecordedMountEntries(st, []linuxMountInfoEntry{foreign}); err == nil {
			t.Fatal("foreign same-path mount accepted")
		}
	})
}

func TestRecoverFUSEMountingIdentityRequiresUniqueSourceMatch(t *testing.T) {
	const mountPath = "/mnt/work"
	const instance = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
	exact := linuxMountInfoEntry{
		id: "42", mountPoint: mountPath, fsType: "fuse.portablefs", source: "portablefs:" + instance,
	}
	id, present, err := recoverFUSEMountingIdentityFromEntries(mountPath, instance, []linuxMountInfoEntry{exact})
	if err != nil || !present || id != "42" {
		t.Fatalf("exact recovery = id %q present %v err %v", id, present, err)
	}
	if id, present, err := recoverFUSEMountingIdentityFromEntries(mountPath, instance, nil); err != nil || present || id != "" {
		t.Fatalf("absent recovery = id %q present %v err %v", id, present, err)
	}
	for name, entries := range map[string][]linuxMountInfoEntry{
		"stacked": {exact, {id: "43", mountPoint: mountPath, fsType: "tmpfs", source: "tmpfs"}},
		"foreign source": {{
			id: "42", mountPoint: mountPath, fsType: "fuse.portablefs",
			source: "portablefs:mnt_BBBBBBBBBBBBBBBBBBBBBB",
		}},
		"foreign type": {{id: "42", mountPoint: mountPath, fsType: "fuse.sshfs", source: exact.source}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := recoverFUSEMountingIdentityFromEntries(mountPath, instance, entries); err == nil {
				t.Fatal("ambiguous or foreign kernel object was accepted")
			}
		})
	}
}
