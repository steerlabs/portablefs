//go:build darwin

package portablefsd

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRefreshKernelFileRejectsSymlinkEscapesAndRenameSwap(t *testing.T) {
	host := privateTestDir(t)
	mount := filepath.Join(host, "mount")
	outside := filepath.Join(host, "outside")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}

	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertContents := func(name, want string) {
		t.Helper()
		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	inode := func(name string) uint64 {
		t.Helper()
		var stat unix.Stat_t
		if err := unix.Stat(name, &stat); err != nil {
			t.Fatal(err)
		}
		return uint64(stat.Ino)
	}

	absoluteSentinel := filepath.Join(outside, "absolute")
	write(absoluteSentinel, "absolute-sentinel")
	if err := os.Symlink(absoluteSentinel, filepath.Join(mount, "absolute-link")); err != nil {
		t.Fatal(err)
	}
	if refreshKernelFile(mount, "absolute-link", inode(absoluteSentinel), 1) {
		t.Fatal("absolute symlink refresh unexpectedly succeeded")
	}
	assertContents(absoluteSentinel, "absolute-sentinel")

	relativeSentinel := filepath.Join(outside, "relative")
	write(relativeSentinel, "relative-sentinel")
	if err := os.Symlink("../outside/relative", filepath.Join(mount, "relative-link")); err != nil {
		t.Fatal(err)
	}
	if refreshKernelFile(mount, "relative-link", inode(relativeSentinel), 1) {
		t.Fatal("relative symlink refresh unexpectedly succeeded")
	}
	assertContents(relativeSentinel, "relative-sentinel")

	nestedSentinel := filepath.Join(outside, "nested")
	write(nestedSentinel, "nested-sentinel")
	if err := os.Symlink("../outside", filepath.Join(mount, "linked-directory")); err != nil {
		t.Fatal(err)
	}
	if refreshKernelFile(mount, "linked-directory/nested", inode(nestedSentinel), 1) {
		t.Fatal("intermediate symlink refresh unexpectedly succeeded")
	}
	assertContents(nestedSentinel, "nested-sentinel")

	victim := filepath.Join(mount, "victim")
	parked := filepath.Join(mount, "parked")
	replacement := filepath.Join(outside, "replacement")
	write(victim, "original")
	expectedItemID := inode(victim)
	write(replacement, "rename-swap-sentinel")
	if err := os.Rename(victim, parked); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, victim); err != nil {
		t.Fatal(err)
	}
	if refreshKernelFile(mount, "victim", expectedItemID, 1) {
		t.Fatal("regular-file rename-swap refresh unexpectedly succeeded")
	}
	assertContents(victim, "rename-swap-sentinel")
	assertContents(parked, "original")
}

func TestRefreshKernelFileTruncatesExpectedRegularFile(t *testing.T) {
	mount := privateTestDir(t)
	name := filepath.Join(mount, "regular")
	if err := os.WriteFile(name, []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(name, &stat); err != nil {
		t.Fatal(err)
	}
	if !refreshKernelFile(mount, "regular", uint64(stat.Ino), 3) {
		t.Fatal("regular-file refresh failed")
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "con" {
		t.Fatalf("regular file = %q, want %q", got, "con")
	}
}

func TestRefreshKernelFileResistsConcurrentSymlinkSwap(t *testing.T) {
	host := privateTestDir(t)
	mount := filepath.Join(host, "mount")
	outside := filepath.Join(host, "outside")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectedOutsideID := statInode(t, outside)
	victim := filepath.Join(mount, "victim")
	parked := filepath.Join(mount, "parked")
	if err := os.WriteFile(victim, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(victim, parked) != nil {
				runtime.Gosched()
				continue
			}
			_ = os.Symlink(outside, victim)
			runtime.Gosched()
			_ = os.Remove(victim)
			_ = os.Rename(parked, victim)
		}
	}()

	// Deliberately supply the outside target's inode. Without atomic
	// O_NOFOLLOW_ANY resolution this defeats the post-open inode check and
	// turns any successful symlink traversal into an outside truncation.
	for i := 0; i < 2_000; i++ {
		_ = refreshKernelFile(mount, "victim", expectedOutsideID, 1)
	}
	close(stop)
	wg.Wait()

	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "outside-sentinel" {
		t.Fatalf("outside file changed through concurrent symlink swap: %q", got)
	}
}

func TestRefreshKernelFileResistsConcurrentRegularFileSwap(t *testing.T) {
	host := privateTestDir(t)
	mount := filepath.Join(host, "mount")
	outsideDir := filepath.Join(host, "outside")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(mount, "victim")
	parked := filepath.Join(mount, "parked")
	replacement := filepath.Join(outsideDir, "replacement")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectedVictimID := statInode(t, victim)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(victim, parked) != nil {
				runtime.Gosched()
				continue
			}
			if os.Rename(replacement, victim) != nil {
				_ = os.Rename(parked, victim)
				continue
			}
			runtime.Gosched()
			_ = os.Rename(victim, replacement)
			_ = os.Rename(parked, victim)
		}
	}()

	for i := 0; i < 2_000; i++ {
		_ = refreshKernelFile(mount, "victim", expectedVictimID, 1)
	}
	close(stop)
	wg.Wait()

	got, err := os.ReadFile(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement-sentinel" {
		t.Fatalf("replacement changed through concurrent rename swap: %q", got)
	}
}

func statInode(t *testing.T, name string) uint64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(name, &stat); err != nil {
		t.Fatal(err)
	}
	return uint64(stat.Ino)
}
