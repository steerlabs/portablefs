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

func leaveStaleUnixSocket(t *testing.T, path string) os.FileInfo {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("closed test listener did not leave a stale socket: %v", err)
	}
	return info
}

func shortDaemonSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfsr-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestDaemonRestartReclaimsOnlyItsStaleCanonicalSockets(t *testing.T) {
	root := shortDaemonSocketDir(t)
	cfg := Config{
		FrontendSocket: filepath.Join(root, "run", "frontend.sock"),
		ControlSocket:  filepath.Join(root, "run", "control.sock"),
		StateDir:       filepath.Join(root, "state"),
		Version:        "restart-test",
	}
	oldFrontend := leaveStaleUnixSocket(t, cfg.FrontendSocket)
	oldControl := leaveStaleUnixSocket(t, cfg.ControlSocket)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewServer(cfg).Run(ctx)
	}()
	waitUnix(t, cfg.FrontendSocket)
	waitUnix(t, cfg.ControlSocket)

	for path, oldInfo := range map[string]os.FileInfo{
		cfg.FrontendSocket: oldFrontend,
		cfg.ControlSocket:  oldControl,
	} {
		current, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(oldInfo, current) {
			t.Fatalf("daemon reused stale socket inode at %s", path)
		}
		if current.Mode()&os.ModeSocket == 0 || current.Mode().Perm() != 0o600 {
			t.Fatalf("replacement socket %s has unsafe mode %s", path, current.Mode())
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("restarted daemon shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("restarted daemon did not stop")
	}
}

func TestStaleSocketReclamationRefusesLiveListener(t *testing.T) {
	dir := shortDaemonSocketDir(t)
	path := filepath.Join(dir, "control.sock")
	lock, err := acquireSingleton(path)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSingleton(lock)
	ln, err := listenUnixSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if err := reclaimStaleUnixSocket(lock, path); err == nil ||
		!strings.Contains(err.Error(), "listening Unix socket") {
		t.Fatalf("live socket reclamation verdict = %v", err)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("refused live listener was disturbed: %v", err)
	}
	_ = conn.Close()
}

func TestStaleSocketReclamationRestoresConcurrentReplacement(t *testing.T) {
	dir := shortDaemonSocketDir(t)
	path := filepath.Join(dir, "control.sock")
	displaced := filepath.Join(dir, "displaced-stale.sock")
	leaveStaleUnixSocket(t, path)
	lock, err := acquireSingleton(path)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSingleton(lock)

	var replacement net.Listener
	err = reclaimStaleUnixSocketWith(lock, path, func() {
		if err := os.Rename(path, displaced); err != nil {
			t.Fatal(err)
		}
		replacement, err = listenUnixSocket(path)
		if err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("concurrent replacement verdict = %v", err)
	}
	defer replacement.Close()
	if _, err := os.Lstat(displaced); err != nil {
		t.Fatalf("original stale socket was not preserved: %v", err)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("concurrent live replacement was not restored: %v", err)
	}
	_ = conn.Close()
}

func TestStaleSocketReclamationRefusesUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{
			name: "regular file",
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("owner"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				target := path + ".target"
				if err := os.WriteFile(target, []byte("owner"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "permissive socket",
			setup: func(t *testing.T, path string) {
				leaveStaleUnixSocket(t, path)
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard-linked socket",
			setup: func(t *testing.T, path string) {
				leaveStaleUnixSocket(t, path)
				if err := os.Link(path, path+".peer"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := shortDaemonSocketDir(t)
			path := filepath.Join(dir, "control.sock")
			test.setup(t, path)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := acquireSingleton(path)
			if err != nil {
				t.Fatal(err)
			}
			defer releaseSingleton(lock)

			if err := reclaimStaleUnixSocket(lock, path); err == nil ||
				!strings.Contains(err.Error(), "unsafe existing Unix socket") {
				t.Fatalf("unsafe entry reclamation verdict = %v", err)
			}
			after, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("unsafe entry was removed: %v", err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("unsafe entry was replaced")
			}
		})
	}
}

func TestDaemonRefusesNonCanonicalSocketPair(t *testing.T) {
	for _, test := range []struct {
		name     string
		frontend string
		control  string
	}{
		{name: "same entry", frontend: "run/control.sock", control: "run/control.sock"},
		{name: "different directories", frontend: "frontend/pfs.sock", control: "control/control.sock"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := privateTestDir(t)
			err := NewServer(Config{
				FrontendSocket: filepath.Join(root, test.frontend),
				ControlSocket:  filepath.Join(root, test.control),
				StateDir:       filepath.Join(root, "state"),
			}).Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), "distinct entries in the singleton socket directory") {
				t.Fatalf("socket-pair verdict = %v", err)
			}
		})
	}
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

func TestListenUnixSocketPublishesOnlyPrivateMode(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfsd-socket-mode-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "frontend.sock")
	for attempt := 0; attempt < 100; attempt++ {
		type result struct {
			ln  net.Listener
			err error
		}
		ready := make(chan result, 1)
		go func() {
			ln, err := listenUnixSocket(path)
			ready <- result{ln: ln, err: err}
		}()

		deadline := time.Now().Add(5 * time.Second)
		for {
			info, err := os.Lstat(path)
			if err == nil {
				if got := info.Mode().Perm(); got != 0o600 {
					t.Fatalf("published socket mode=%o, want 0600", got)
				}
				break
			}
			if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatal("socket was not published")
			}
		}
		out := <-ready
		if out.err != nil {
			t.Fatal(out.err)
		}
		if err := out.ln.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("closed listener left published socket: %v", err)
		}
	}
}

func TestPublishedUnixListenerNeverRemovesReplacement(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfsd-socket-replace-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "frontend.sock")
	ln, err := listenUnixSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	const replacement = "replacement-owner"
	if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err == nil || !strings.Contains(err.Error(), "refusing to remove replaced Unix socket") {
		t.Fatalf("close replacement verdict=%v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != replacement {
		t.Fatalf("replacement contents=%q", got)
	}
}
