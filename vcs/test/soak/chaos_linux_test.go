//go:build linux

package soak

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A direct-XFS syscall oracle models aliases as inodes instead of unrelated
// byte strings. Every random action compares errno, then the final manifest
// compares every surviving name/content through A, B, and Authority storage.
func TestSoakChaos(t *testing.T) {
	if isolateSoak(t, 90*time.Second) {
		return
	}
	f := newFixture(t)
	oracle, err := os.MkdirTemp(filepath.Dir(f.root), "soak-model-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(oracle)
	for _, base := range []string{f.a, oracle} {
		if err := os.Mkdir(filepath.Join(base, "chaos"), 0700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 16; i++ {
			if err := os.WriteFile(filepath.Join(base, "chaos", fmt.Sprintf("f-%02d", i)), []byte("initial"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.measure(t, "chaos-seed-730021-200-random-operations", func() error {
		rng := rand.New(rand.NewSource(730021))
		counts := map[string]int{}
		for iteration := 0; iteration < 200; iteration++ {
			mount := f.a
			if rng.Intn(2) == 1 {
				mount = f.b
			}
			op := rng.Intn(8)
			src := fmt.Sprintf("chaos/f-%02d", rng.Intn(32))
			dst := fmt.Sprintf("chaos/f-%02d", rng.Intn(32))
			dir := fmt.Sprintf("chaos/d-%02d", rng.Intn(8))
			payload := []byte(fmt.Sprintf("step=%d random=%016x", iteration, rng.Uint64()))
			size := int64(rng.Intn(80))
			offset := int64(rng.Intn(16))
			name := []string{"create", "write", "rename", "unlink", "mkdir", "rmdir", "truncate", "link"}[op]
			counts[name]++
			action := func(root string) error {
				a, b := filepath.Join(root, src), filepath.Join(root, dst)
				switch op {
				case 0:
					h, e := os.OpenFile(a, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if e != nil {
						return e
					}
					_, e = h.Write(payload)
					return errors.Join(e, h.Close())
				case 1:
					h, e := os.OpenFile(a, os.O_WRONLY, 0)
					if e != nil {
						return e
					}
					_, e = h.WriteAt(payload, offset)
					return errors.Join(e, h.Close())
				case 2:
					return os.Rename(a, b)
				case 3:
					return syscall.Unlink(a)
				case 4:
					return os.Mkdir(filepath.Join(root, dir), 0700)
				case 5:
					return syscall.Rmdir(filepath.Join(root, dir))
				case 6:
					return os.Truncate(a, size)
				default:
					return os.Link(a, b)
				}
			}
			t.Logf("CHAOS step=%d mount=%s op=%s source=%s dest=%s size=%d offset=%d", iteration, filepath.Base(mount), name, src, dst, size, offset)
			var actual error
			if err := f.bounded(t, fmt.Sprintf("chaos step=%d op=%s", iteration, name), 15*time.Second, func() error { actual = action(mount); return nil }); err != nil {
				return err
			}
			expected := action(oracle)
			var actualErrno, expectedErrno syscall.Errno
			if actual != nil && !errors.As(actual, &actualErrno) {
				return fmt.Errorf("step=%d unexpected error: %w", iteration, actual)
			}
			if expected != nil && !errors.As(expected, &expectedErrno) {
				return fmt.Errorf("oracle: %w", expected)
			}
			if actualErrno != expectedErrno {
				return fmt.Errorf("seed=730021 step=%d op=%s mount=%v model=%v", iteration, name, actual, expected)
			}
		}
		for name, count := range counts {
			t.Logf("CHAOS coverage %s=%d", name, count)
		}
		if len(counts) != 8 {
			return fmt.Errorf("random seed covered %d operations, want8", len(counts))
		}
		f.barrier(t)
		want, err := treeHashes(filepath.Join(oracle, "chaos"))
		if err != nil {
			return err
		}
		for _, root := range []string{f.a, f.b, f.root} {
			got, err := treeHashes(filepath.Join(root, "chaos"))
			if err != nil {
				return err
			}
			if err = compareTrees(want, got); err != nil {
				return fmt.Errorf("%s: %w", root, err)
			}
		}
		return nil
	})
}
