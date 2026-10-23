//go:build linux

package workspacemount

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIdentityPrivateToWorkspaceUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root supervisor and UID 1000")
	}
	s, r := store(t)
	// Make the fixture's ancestors traversable, so only production identity modes
	// protect this generated key, rather than testing t.TempDir's private mode.
	for p := filepath.Dir(s.directory); p != "/" && p != os.TempDir(); p = filepath.Dir(p) {
		if err := os.Chmod(p, 0755); err != nil {
			t.Fatal(err)
		}
		if p == os.TempDir() {
			break
		}
	}
	key := filepath.Join(s.directory, volumeKey(r.Mount.AuthorityId, r.Mount.VolumeId)+".json")
	cmd := exec.Command("/bin/sh", "-c", `test ! -r "$1" && test ! -x "$2"`, "identity-test", key, s.directory)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	if err := cmd.Run(); err != nil {
		t.Fatal("workspace UID could access supervisor identity", err)
	}
}
