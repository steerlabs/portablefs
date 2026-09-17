//go:build linux

package soak

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Retain the exact first-run seed and oracle interleaving. The smaller fixed
// A/B cycle in repro_linux_test.go is not sufficient to reproduce every run.
func TestSoakReproSeededAliasCycle(t *testing.T) {
	if isolateSoak(t, 5*time.Minute) {
		return
	}
	f := newFixture(t)
	oracle, err := os.MkdirTemp(filepath.Dir(f.root), "soak-alias-model-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(oracle)
	for _, base := range []string{f.a, oracle} {
		mustMkdir(t, filepath.Join(base, "chaos"))
	}
	rng := rand.New(rand.NewSource(730021))
	for iteration := 0; iteration < 200; iteration++ {
		mount := f.a
		if rng.Intn(2) == 1 {
			mount = f.b
		}
		dir := fmt.Sprintf("chaos/d-%03d", iteration)
		file := filepath.Join(dir, "file")
		alias := filepath.Join(dir, "alias")
		renamed := filepath.Join(dir, "renamed")
		payload := []byte(fmt.Sprintf("iteration=%d random=%016x", iteration, rng.Uint64()))
		ops := []struct {
			name string
			run  func(string) error
		}{
			{"mkdir", func(root string) error { return os.Mkdir(filepath.Join(root, dir), 0700) }},
			{"create/write", func(root string) error { return os.WriteFile(filepath.Join(root, file), payload, 0600) }},
			{"link", func(root string) error { return os.Link(filepath.Join(root, file), filepath.Join(root, alias)) }},
			{"truncate", func(root string) error { return os.Truncate(filepath.Join(root, alias), int64(len(payload)/2)) }},
			{"rename", func(root string) error { return os.Rename(filepath.Join(root, file), filepath.Join(root, renamed)) }},
			{"unlink", func(root string) error { return os.Remove(filepath.Join(root, alias)) }},
			{"mkdir-empty", func(root string) error { return os.Mkdir(filepath.Join(root, dir, "empty"), 0700) }},
			{"rmdir", func(root string) error { return os.Remove(filepath.Join(root, dir, "empty")) }},
		}
		for _, op := range ops {
			if rng.Intn(2) == 1 {
				if mount == f.a {
					mount = f.b
				} else {
					mount = f.a
				}
			}
			t.Logf("ALIAS seed=730021 iteration=%d op=%s mount=%s", iteration, op.name, filepath.Base(mount))
			if err := f.bounded(t, fmt.Sprintf("alias iteration=%d op=%s", iteration, op.name), 15*time.Second, func() error { return op.run(mount) }); err != nil {
				t.Fatal(err)
			}
			if err := op.run(oracle); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(filepath.Join(oracle, renamed))
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{f.a, f.b} {
			requireContent(t, filepath.Join(root, renamed), want, "seeded alias peer read")
		}
	}
	f.barrier(t)
}
