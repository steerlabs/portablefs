package confinedfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestRootAllowsSafeRelativeSymlinkAndPreservesTarget(t *testing.T) {
	host := t.TempDir()
	root, err := Open(filepath.Join(host, "root"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := root.MkdirAll("graft/real", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("graft/real/value", []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("real", "graft/safe"); err != nil {
		t.Fatal(err)
	}
	gotTarget, err := root.Readlink("graft/safe")
	if err != nil || gotTarget != "real" {
		t.Fatalf("readlink = %q, %v", gotTarget, err)
	}
	got, err := root.ReadFile("graft/safe/value")
	if err != nil || string(got) != "inside" {
		t.Fatalf("safe relative traversal = %q, %v", got, err)
	}
}

func TestRootRejectsEveryServerSideSymlinkEscape(t *testing.T) {
	host := t.TempDir()
	backing := filepath.Join(host, "root")
	outside := filepath.Join(host, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := Open(backing, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.MkdirAll("graft", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("graft/source", []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		target string
	}{
		{name: "relative", target: "../../outside"},
		{name: "dotdot-chain", target: "missing/../../../../outside"},
		{name: "absolute", target: outside},
		{name: "absolute-root", target: "/etc"},
		{name: "proc-magic-link", target: "/proc/self/fd/1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link := "graft/escape-" + tc.name
			if err := root.Symlink(tc.target, link); err != nil {
				t.Fatal(err)
			}
			got, err := root.Readlink(link)
			if err != nil || got != tc.target {
				t.Fatalf("readlink did not preserve target: %q, %v", got, err)
			}
			assertRejected := func(op string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s unexpectedly traversed %q", op, tc.target)
				}
			}
			assertRejected("read", func() error {
				f, err := root.Open(link + "/secret")
				if err == nil {
					_ = f.Close()
				}
				return err
			}())
			assertRejected("create", root.WriteFile(link+"/created", []byte("bad"), 0o644))
			assertRejected("mkdir", root.Mkdir(link+"/created-dir", 0o755))
			assertRejected("rename destination", root.Rename("graft/source", link+"/renamed"))
			assertRejected("hardlink destination", root.Link("graft/source", link+"/linked"))
			assertRejected("symlink destination", root.Symlink("x", link+"/nested-link"))
			assertRejected("remove through link", root.Remove(link+"/secret"))
			if got, err := os.ReadFile(filepath.Join(outside, "secret")); err != nil || string(got) != "outside" {
				t.Fatalf("outside sentinel changed: %q, %v", got, err)
			}
			for _, name := range []string{"created", "created-dir", "renamed", "linked", "nested-link"} {
				if _, err := os.Lstat(filepath.Join(outside, name)); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("outside %s exists after rejected operation: %v", name, err)
				}
			}
			if err := root.WriteFile("graft/source", []byte("source"), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRootRejectsUntrustedPathSyntax(t *testing.T) {
	root, err := Open(filepath.Join(t.TempDir(), "root"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"/etc/passwd", "../outside", "a/../../outside", "bad\x00name"} {
		if _, err := root.Open(name); err == nil {
			t.Errorf("Open(%q) unexpectedly succeeded", name)
		}
	}
}

func TestRootResistsConcurrentDestinationParentSymlinkSwap(t *testing.T) {
	host := t.TempDir()
	backing := filepath.Join(host, "root")
	outside := filepath.Join(host, "outside")
	if err := os.MkdirAll(filepath.Join(backing, "graft", "parent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := Open(backing, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	parent := filepath.Join(backing, "graft", "parent")
	parked := filepath.Join(backing, "graft", "parked")
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
			if os.Rename(parent, parked) != nil {
				runtime.Gosched()
				continue
			}
			_ = os.Symlink(outside, parent)
			runtime.Gosched()
			_ = os.Remove(parent)
			_ = os.Rename(parked, parent)
		}
	}()

	for i := 0; i < 2_000; i++ {
		_ = root.WriteFile("graft/source", []byte("x"), 0o644)
		_ = root.WriteFile("graft/parent/created", []byte("x"), 0o644)
		_ = root.Rename("graft/source", "graft/parent/renamed")
		_ = root.WriteFile("graft/source", []byte("x"), 0o644)
		_ = root.Link("graft/source", "graft/parent/linked")
		_ = root.Remove("graft/parent/created")
		_ = root.Remove("graft/parent/renamed")
		_ = root.Remove("graft/parent/linked")
	}
	close(stop)
	wg.Wait()

	for _, name := range []string{"created", "renamed", "linked"} {
		if _, err := os.Lstat(filepath.Join(outside, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("race escaped through destination parent: outside/%s: %v", name, err)
		}
	}
}
