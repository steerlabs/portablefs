//go:build darwin

package cli

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProcessStartIdentityRejectsZombie(t *testing.T) {
	child, err := os.StartProcess("/usr/bin/true", []string{"true"}, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		child.Kill()
		if _, err := child.Wait(); err != nil {
			t.Errorf("reap child: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info, err := unix.SysctlKinfoProc("kern.proc.pid", child.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if info.Proc.P_stat == 5 { // SZOMB in <sys/proc.h>.
			if identity, err := processStartIdentity(child.Pid); identity != "" || !errors.Is(err, unix.ESRCH) {
				t.Fatalf("zombie identity = %q, error = %v; want no identity and ESRCH", identity, err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child %d did not become a zombie", child.Pid)
}
