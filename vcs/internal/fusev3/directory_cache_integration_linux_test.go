//go:build linux

package fusev3

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestKernelReusableDirectoryReadPermissionAndRetainedRights(t *testing.T) {
	for _, routes := range []string{"", "node_modules\n"} {
		t.Run(map[bool]string{true: "mixed-route", false: "ordinary"}[routes != ""], func(t *testing.T) {
			f := newIntegrationFixture(t, integrationConfig{Mounts: 2, Routes: routes})
			directoryA, directoryB := f.join(0, "read-proof"), f.join(1, "read-proof")
			mustMkdir(t, directoryA)
			mustWrite(t, filepath.Join(directoryA, "kept"), []byte("kept"), 0600)
			var child publicationIdentity
			raw := f.mounts[0].raw
			raw.mu.RLock()
			for name, record := range raw.cachedStableNames {
				if name.name == "kept" {
					child = record.identity
					break
				}
			}
			raw.mu.RUnlock()
			if child == (publicationIdentity{}) {
				t.Fatal("source did not retain the created child identity")
			}
			waitUntil(t, 10*time.Second, "source close and delegation release", func() bool {
				return !f.mounts[0].delegations.Owns(child[:]) && pendingCloses(f.mounts[0].delegations) == 0
			})
			requireDirectoryNames(t, directoryB, []string{"kept"}, "prime reusable directory page")
			before := f.mounts[1].MetadataStats()
			requireDirectoryNames(t, directoryB, []string{"kept"}, "warm reusable directory page")
			after := f.mounts[1].MetadataStats()
			if after.OpenMisses != before.OpenMisses || after.PageMisses != before.PageMisses || after.OpenHits <= before.OpenHits {
				t.Fatalf("unchanged directory missed proof/page: before=%+v after=%+v", before, after)
			}
			old, err := os.Open(directoryB)
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			if err = os.Chmod(directoryA, 0); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(directoryA, 0700) }()
			if fresh, openErr := os.Open(directoryB); openErr == nil {
				fresh.Close()
				t.Fatal("new open survived revoked read/search access")
			} else if !errors.Is(openErr, syscall.EACCES) {
				t.Fatal(openErr)
			}
			names, err := old.Readdirnames(-1)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("old readable description lost rights: %v", err)
			}
			slices.Sort(names)
			if !slices.Equal(names, []string{"kept"}) {
				t.Fatalf("old names=%q", names)
			}
			if err = os.Chmod(directoryA, 0400); err != nil {
				t.Fatal(err)
			}
			readOnly, err := os.Open(directoryB)
			if err != nil {
				t.Fatalf("read without search regressed: %v", err)
			}
			names, err = readOnly.Readdirnames(-1)
			closeErr := readOnly.Close()
			if err != nil && !errors.Is(err, io.EOF) || closeErr != nil || !slices.Equal(names, []string{"kept"}) {
				t.Fatalf("read-only listing=%q read=%v close=%v", names, err, closeErr)
			}
		})
	}
}
