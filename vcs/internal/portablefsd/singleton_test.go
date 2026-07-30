package portablefsd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDaemonSingletonLockRefusesSecondOwner(t *testing.T) {
	dir := privateTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	controlSocket := filepath.Join(dir, "control.sock")
	first, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatal(err)
	}

	if second, err := acquireSingleton(controlSocket); err == nil {
		releaseSingleton(second)
		t.Fatal("second daemon acquired the live socket ownership lock")
	}

	releaseSingleton(first)
	third, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatalf("lock did not become available after the owner exited: %v", err)
	}
	releaseSingleton(third)
}

func TestDaemonStateLockRefusesDifferentSocketsSharingState(t *testing.T) {
	stateDir := privateTestDir(t)
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
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

func TestDaemonSingletonRejectsUnsafeLockInodes(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, dir, lockPath string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, dir, lockPath string) {
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, lockPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong mode",
			setup: func(t *testing.T, _, lockPath string) {
				if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(lockPath, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, _, lockPath string) {
				if err := os.Mkdir(lockPath, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "multiple links",
			setup: func(t *testing.T, dir, lockPath string) {
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, lockPath); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := privateTestDir(t)
			lockPath := filepath.Join(dir, ".portablefsd.lock")
			test.setup(t, dir, lockPath)
			if lock, err := acquireSingleton(filepath.Join(dir, "control.sock")); err == nil {
				releaseSingleton(lock)
				t.Fatal("unsafe singleton lock inode was accepted")
			}
		})
	}
}

func TestDaemonSingletonDetectsLockReplacementAndSplitInode(t *testing.T) {
	dir := privateTestDir(t)
	controlSocket := filepath.Join(dir, "control.sock")
	first, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSingleton(first)

	lockPath := filepath.Join(dir, ".portablefsd.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatalf("replacement inode did not demonstrate split ownership: %v", err)
	}
	defer releaseSingleton(second)
	if err := first.validate(); err == nil || !strings.Contains(err.Error(), "private file") {
		t.Fatalf("original owner replacement validation = %v, want hard refusal", err)
	}
}

func TestDaemonSingletonDetectsPinnedDirectoryReplacement(t *testing.T) {
	root := privateTestDir(t)
	dir := filepath.Join(root, "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	controlSocket := filepath.Join(dir, "control.sock")
	first, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSingleton(first)

	oldDir := dir + ".old"
	if err := os.Rename(dir, oldDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := acquireSingleton(controlSocket)
	if err != nil {
		t.Fatalf("replacement directory did not demonstrate split ownership: %v", err)
	}
	defer releaseSingleton(second)
	if err := first.validate(); err == nil || !strings.Contains(err.Error(), "changed after it was pinned") {
		t.Fatalf("original directory validation = %v, want replacement refusal", err)
	}
}

func TestLosingDaemonDoesNotInitializeOrMutateRegistry(t *testing.T) {
	cfg, _, cancel := startDaemonNoAttach(t, "")
	defer cancel()
	before := snapshotPrivateState(t, cfg.StateDir)

	loser := NewServer(cfg)
	if loser.registry != nil {
		t.Fatal("NewServer initialized registry before singleton ownership")
	}
	if got := snapshotPrivateState(t, cfg.StateDir); !reflect.DeepEqual(got, before) {
		t.Fatalf("NewServer mutated shared state: before=%v after=%v", before, got)
	}
	err := loser.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "another portablefsd owns") {
		t.Fatalf("losing Run error = %v, want singleton refusal", err)
	}
	if loser.registry != nil {
		t.Fatal("losing daemon initialized a registry/persister before singleton refusal")
	}
	if got := snapshotPrivateState(t, cfg.StateDir); !reflect.DeepEqual(got, before) {
		t.Fatalf("losing daemon mutated shared state: before=%v after=%v", before, got)
	}
	conn, err := net.DialTimeout("unix", cfg.ControlSocket, time.Second)
	if err != nil {
		t.Fatalf("winning daemon was disturbed by loser: %v", err)
	}
	_ = conn.Close()
}

func snapshotPrivateState(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += ":" + string(data)
		}
		out[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestListenUnixSocketNeverUnlinksExistingOwner(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfsd-socket-owner-")
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
