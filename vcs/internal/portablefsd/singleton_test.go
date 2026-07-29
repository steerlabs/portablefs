package portablefsd

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDaemonSingletonLockRefusesSecondOwner(t *testing.T) {
	controlSocket := filepath.Join(t.TempDir(), "control.sock")
	first, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatal(err)
	}

	if second, err := acquireSingleton(controlSocket); err == nil {
		_ = second.Close()
		t.Fatal("second daemon acquired the live socket ownership lock")
	}

	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatalf("lock did not become available after the owner exited: %v", err)
	}
	_ = syscall.Flock(int(third.Fd()), syscall.LOCK_UN)
	_ = third.Close()
}

func TestDaemonStateLockRefusesDifferentSocketsSharingState(t *testing.T) {
	stateDir := t.TempDir()
	first, err := acquireStateSingleton(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSingleton(first)

	if second, err := acquireStateSingleton(stateDir); err == nil {
		releaseSingleton(second)
		t.Fatal("second daemon acquired the live state-directory lock")
	}
}

func TestListenUnixSocketNeverUnlinksExistingOwner(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pfsd-socket-owner-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "frontend.sock")
	owner, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()

	if replacement, err := listenUnixSocket(path); err == nil {
		_ = replacement.Close()
		t.Fatal("listener replaced an existing Unix socket")
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := owner.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	client, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("original socket owner was no longer reachable: %v", err)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("original owner accept: %v", err)
	}
}
