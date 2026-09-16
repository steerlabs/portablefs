package coherencebench

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A benchmark result is useful only if it performed the advertised work.
// Verify the complete small tree for both worker shapes outside timing gates.
func TestInstallCreatesAdvertisedTree(t *testing.T) {
	for _, workers := range []int{1, 8} {
		t.Run(fmt.Sprintf("workers-%d", workers), func(t *testing.T) {
			root := t.TempDir()
			result, err := Install(root, 83, 43, workers)
			if err != nil {
				t.Fatal(err)
			}
			if result.Operations != 126 || result.Files != 83 || result.Directories != 43 || result.Workers != workers || result.WallSeconds <= 0 {
				t.Fatalf("incorrect result: %+v", result)
			}
			want := make([]byte, FileBytes)
			for i := range want {
				want[i] = byte(31*i + 17)
			}
			files, directories := 0, 0
			err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if path == root {
					return nil
				}
				if entry.IsDir() {
					directories++
					return nil
				}
				files++
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if !bytes.Equal(data, want) {
					return fmt.Errorf("wrong payload in %s", path)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if files != result.Files || directories != result.Directories {
				t.Fatalf("created %d files/%d directories, advertised %+v", files, directories, result)
			}
		})
	}
}

func TestInstallRejectsInvalidSetup(t *testing.T) {
	root := t.TempDir()
	// Deny all file creation with a regular file as the parent; this fails
	// before spawning workers and must never emit a successful measurement.
	parent := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(parent, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, shape := range []struct{ files, dirs, workers int }{
		{0, 1, 1}, {1, 0, 1}, {1, 1, 0}, {83, 43, 8},
	} {
		t.Run(fmt.Sprintf("%d-%d-%d", shape.files, shape.dirs, shape.workers), func(t *testing.T) {
			if result, err := Install(parent, shape.files, shape.dirs, shape.workers); err == nil || result.WallSeconds != 0 {
				t.Fatalf("failed install reported success: %+v, %v", result, err)
			}
		})
	}
	got, err := os.ReadFile(parent)
	if err != nil || string(got) != "preserve" {
		t.Fatalf("existing file changed: %q %v", got, err)
	}
}

func TestPrepareGitRefusesNonemptyRoot(t *testing.T) {
	for _, existing := range []string{"notes.txt", ".git/config"} {
		t.Run(existing, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, existing)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("preserve existing content\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := PrepareGit(root, 1); err == nil {
				t.Fatal("preparation accepted a nonempty root")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "preserve existing content\n" {
				t.Fatalf("existing content changed: %q, %v", got, err)
			}
			files := 0
			err = filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() {
					files++
				}
				return nil
			})
			if err != nil || files != 1 {
				t.Fatalf("preparation changed existing tree: files=%d, error=%v", files, err)
			}
		})
	}
}

func TestPeerWorkloadChecksEveryFileAndStopsOnWriterFailure(t *testing.T) {
	root := t.TempDir()
	result, err := PeerWriteRead(root, root, 17)
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 17 || result.Operations != 34 || result.WallSeconds <= 0 || result.FilesObservedDuringWrite == 0 || result.DirectoryScans == 0 {
		t.Fatalf("incorrect peer result: %+v", result)
	}
	for index := range 17 {
		want := make([]byte, FileBytes)
		fillPayload(want, index)
		got, err := os.ReadFile(filepath.Join(root, fmt.Sprintf("file-%06d.dat", index)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("file %d: content matches=%t error=%v", index, bytes.Equal(got, want), err)
		}
	}
	// The first file already exists. The writer must cancel and join its
	// reader, even though that reader is waiting for a larger advertised set.
	done := make(chan error, 1)
	go func() { _, err := PeerWriteRead(root, root, 18); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("duplicate create unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer failure left the peer reader waiting")
	}
}

func TestPeerSingleFileDoesNotConsumeCompletionAtFirstObservation(t *testing.T) {
	for range 20 {
		root := t.TempDir()
		result, err := PeerWriteRead(root, root, 1)
		if err != nil || result.Files != 1 || result.Operations != 2 {
			t.Fatalf("single-file peer workload: result=%+v error=%v", result, err)
		}
	}
}
